// Windows Event IDs Database — Security monitoring reference
// Covers Security, System, Sysmon, PowerShell, and other critical event sources

export const WINDOWS_EVENT_IDS_DB = [
  // ═══════════════════════════════════════════════════════════════
  // SECURITY LOG — LOGON EVENTS (4624–4634)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 4624,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "An account was successfully logged on. Contains logon type, source network address, and authentication package used.",
    significance: "critical",
    mitreTechniques: ["T1078 - Valid Accounts", "T1021 - Remote Services", "T1550 - Use Alternate Authentication Material"],
    splunkQuery: 'index=wineventlog EventCode=4624 Logon_Type!=5 | stats count by Account_Name, Logon_Type, Source_Network_Address | sort -count',
    elkQuery: '{"query":{"bool":{"must":[{"term":{"event.code":"4624"}},{"bool":{"must_not":[{"term":{"winlog.event_data.LogonType":"5"}}]}}]}}}',
    falsePositives: "Service accounts with Logon Type 5 (Service), SYSTEM account logons, scheduled tasks triggering Type 2 (Interactive) on terminal servers",
    investigationSteps: [
      "Check the Logon Type field: 2=Interactive, 3=Network, 4=Batch, 5=Service, 7=Unlock, 8=NetworkCleartext, 9=NewCredentials, 10=RemoteInteractive, 11=CachedInteractive",
      "Correlate Source_Network_Address with known hosts",
      "Check for unusual logon times or from unexpected subnets",
      "Verify the Authentication Package (NTLM vs Kerberos)",
      "Look for Logon Type 10 from external IPs (RDP brute force)",
      "Check Elevated Token field for admin logons"
    ]
  },
  {
    id: 4625,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "An account failed to log on. Records the reason for failure, source address, and target account name.",
    significance: "high",
    mitreTechniques: ["T1110 - Brute Force", "T1110.001 - Password Guessing", "T1110.003 - Password Spraying"],
    splunkQuery: 'index=wineventlog EventCode=4625 | stats count by Target_User_Name, Source_Network_Address, Sub_Status | where count>5 | sort -count',
    elkQuery: '{"query":{"term":{"event.code":"4625"}},"aggs":{"by_user":{"terms":{"field":"winlog.event_data.TargetUserName"},"aggs":{"by_ip":{"terms":{"field":"winlog.event_data.IpAddress"}}}}}}',
    falsePositives: "Users mistyping passwords, expired passwords, service accounts with stale credentials, NLA authentication failures",
    investigationSteps: [
      "Check Sub_Status for failure reason: 0xC000006A=bad password, 0xC0000064=user doesn't exist, 0xC0000072=account disabled, 0xC0000234=account locked",
      "Aggregate by source IP to detect brute force (>10 failures in 10 minutes)",
      "Check if multiple accounts targeted from same IP (password spraying)",
      "Correlate with 4624 events to see if attacker eventually succeeded",
      "Check for failures against admin accounts or service accounts",
      "Look for Logon Type 3 failures from external IPs"
    ]
  },
  {
    id: 4626,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "User/device claims information. Contains claims assigned during logon for Dynamic Access Control.",
    significance: "low",
    mitreTechniques: ["T1078 - Valid Accounts"],
    splunkQuery: 'index=wineventlog EventCode=4626 | table _time, Subject_User_Name, Claims',
    elkQuery: '{"query":{"term":{"event.code":"4626"}}}',
    falsePositives: "Normal DAC operations in environments using claims-based access control",
    investigationSteps: [
      "Review claims assigned to the user session",
      "Check if claims match expected group memberships",
      "Correlate with the corresponding 4624 logon event"
    ]
  },
  {
    id: 4627,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "Group membership information during logon. Lists all groups the account belongs to at logon time.",
    significance: "medium",
    mitreTechniques: ["T1078 - Valid Accounts", "T1098 - Account Manipulation"],
    splunkQuery: 'index=wineventlog EventCode=4627 | table _time, Subject_User_Name, GroupMembership',
    elkQuery: '{"query":{"term":{"event.code":"4627"}}}',
    falsePositives: "Normal logon events, service accounts with many group memberships",
    investigationSteps: [
      "Check for unexpected privileged group memberships (Domain Admins, Enterprise Admins, Schema Admins)",
      "Compare current groups against baseline for the account",
      "Look for recently added groups via 4728/4732/4756 events",
      "Correlate with 4624 to link group info with logon details"
    ]
  },
  {
    id: 4634,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "An account was logged off. Records the logon ID that can be correlated with the corresponding 4624 logon event.",
    significance: "low",
    mitreTechniques: [],
    splunkQuery: 'index=wineventlog EventCode=4634 | stats count by Target_User_Name, Logon_Type',
    elkQuery: '{"query":{"term":{"event.code":"4634"}}}',
    falsePositives: "Normal user logoffs, service account session terminations",
    investigationSteps: [
      "Calculate session duration by correlating Logon_ID with 4624 event",
      "Check for very short sessions which may indicate automated activity",
      "Verify logoff aligns with expected user behavior patterns"
    ]
  },
  {
    id: 4647,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "User initiated logoff. Differs from 4634 in that this is an explicit user-initiated logoff action.",
    significance: "low",
    mitreTechniques: [],
    splunkQuery: 'index=wineventlog EventCode=4647 | table _time, Target_User_Name',
    elkQuery: '{"query":{"term":{"event.code":"4647"}}}',
    falsePositives: "Normal user sign-outs",
    investigationSteps: [
      "Correlate with 4624 to determine session length",
      "Check for logoffs at unusual times"
    ]
  },
  {
    id: 4648,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A logon was attempted using explicit credentials. Occurs when a process uses different credentials than the logged-on user (runas, mapped drives, scheduled tasks).",
    significance: "high",
    mitreTechniques: ["T1078 - Valid Accounts", "T1550.002 - Pass the Hash", "T1021.002 - SMB/Windows Admin Shares"],
    splunkQuery: 'index=wineventlog EventCode=4648 | stats count by Subject_User_Name, Target_User_Name, Target_Server_Name | where Subject_User_Name!=Target_User_Name',
    elkQuery: '{"query":{"term":{"event.code":"4648"}},"aggs":{"by_subject":{"terms":{"field":"winlog.event_data.SubjectUserName"}}}}',
    falsePositives: "Administrators using runas, mapped network drives to file shares, scheduled tasks running under different accounts",
    investigationSteps: [
      "Check if Subject_User_Name differs from Target_User_Name (credential switching)",
      "Identify the process requesting alternate credentials via Process_Name",
      "Check Target_Server_Name for lateral movement indicators",
      "Correlate with 4624 Type 3 events on the target server",
      "Look for runas.exe or similar credential tools in process auditing"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // SECURITY LOG — OBJECT ACCESS (4656, 4658, 4660, 4663)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 4656,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A handle to an object was requested. Records the object type, name, and access rights requested.",
    significance: "medium",
    mitreTechniques: ["T1003 - OS Credential Dumping", "T1005 - Data from Local System", "T1039 - Data from Network Shared Drive"],
    splunkQuery: 'index=wineventlog EventCode=4656 Object_Type=File | stats count by Object_Name, Process_Name, Access_Mask | sort -count',
    elkQuery: '{"query":{"bool":{"must":[{"term":{"event.code":"4656"}},{"term":{"winlog.event_data.ObjectType":"File"}}]}}}',
    falsePositives: "File system indexing services, antivirus scanning, backup software accessing files",
    investigationSteps: [
      "Decode the Access_Mask to determine requested permissions (0x1 = READ, 0x2 = WRITE, 0x10000 = DELETE)",
      "Check Object_Name for sensitive file paths (SAM, SYSTEM, NTDS.dit, password files)",
      "Identify the Process_Name making the request",
      "Correlate with 4663 to confirm actual access occurred",
      "Check for unusual processes accessing sensitive registry keys"
    ]
  },
  {
    id: 4658,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "The handle to an object was closed.",
    significance: "low",
    mitreTechniques: [],
    splunkQuery: 'index=wineventlog EventCode=4658 | stats count by Process_Name, Object_Name',
    elkQuery: '{"query":{"term":{"event.code":"4658"}}}',
    falsePositives: "Normal file handle operations by system processes",
    investigationSteps: [
      "Correlate Handle_ID with 4656/4663 events to track full object access lifecycle",
      "Calculate handle open duration for anomaly detection"
    ]
  },
  {
    id: 4660,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "An object was deleted. Only generated if delete auditing is enabled on the object.",
    significance: "high",
    mitreTechniques: ["T1070.004 - Indicator Removal: File Deletion", "T1485 - Data Destruction"],
    splunkQuery: 'index=wineventlog EventCode=4660 | stats count by Subject_User_Name, Object_Name | sort -count',
    elkQuery: '{"query":{"term":{"event.code":"4660"}}}',
    falsePositives: "Temp file cleanup, application cache clearing, legitimate file management",
    investigationSteps: [
      "Check what object was deleted via Handle_ID correlation with 4656",
      "Identify the user and process performing the deletion",
      "Look for mass deletion patterns (anti-forensics or ransomware)"
    ]
  },
  {
    id: 4663,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "An attempt was made to access an object. Confirms that access actually occurred (unlike 4656 which is just a request).",
    significance: "high",
    mitreTechniques: ["T1003.002 - Security Account Manager", "T1003.003 - NTDS", "T1005 - Data from Local System"],
    splunkQuery: 'index=wineventlog EventCode=4663 | stats count by Object_Name, Process_Name, Access_List | sort -count',
    elkQuery: '{"query":{"term":{"event.code":"4663"}}}',
    falsePositives: "Backup software, antivirus real-time scanning, Windows Search indexer",
    investigationSteps: [
      "Check Object_Name for sensitive files: \\Windows\\System32\\config\\SAM, NTDS.dit, *.kdbx, *.pfx",
      "Decode Access_List: %%4416=ReadData, %%4417=WriteData, %%4418=AppendData, %%1537=DELETE",
      "Identify Process_Name — look for unusual processes (mimikatz, procdump, ntdsutil)",
      "Check for processes reading the LSASS memory space",
      "Aggregate by user to detect data collection/staging"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // SECURITY LOG — SPECIAL PRIVILEGES (4672)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 4672,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "Special privileges assigned to new logon. Generated when an account with admin-level privileges logs on.",
    significance: "high",
    mitreTechniques: ["T1078.002 - Domain Accounts", "T1134 - Access Token Manipulation"],
    splunkQuery: 'index=wineventlog EventCode=4672 | stats count by Subject_User_Name, Privileges | where Subject_User_Name!="SYSTEM"',
    elkQuery: '{"query":{"bool":{"must":[{"term":{"event.code":"4672"}},{"bool":{"must_not":[{"term":{"winlog.event_data.SubjectUserName":"SYSTEM"}}]}}]}}}',
    falsePositives: "Domain admin logons, service accounts with SeBackupPrivilege, built-in Administrator account",
    investigationSteps: [
      "Check which privileges were assigned: SeDebugPrivilege (process debugging), SeTcbPrivilege (act as OS), SeAssignPrimaryTokenPrivilege (token manipulation)",
      "Verify the account should have these privileges",
      "Correlate with 4624 to determine logon source",
      "Alert on SeDebugPrivilege for non-admin accounts (credential dumping indicator)",
      "Check for SeImpersonatePrivilege on service accounts (potato attacks)"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // SECURITY LOG — PROCESS TRACKING (4688, 4689)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 4688,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A new process has been created. With command line auditing enabled, captures the full command line of every process.",
    significance: "critical",
    mitreTechniques: ["T1059 - Command and Scripting Interpreter", "T1053 - Scheduled Task/Job", "T1569.002 - Service Execution"],
    splunkQuery: 'index=wineventlog EventCode=4688 | eval cmdlen=len(Process_Command_Line) | where cmdlen>200 | table _time, Creator_Process_Name, New_Process_Name, Process_Command_Line, Subject_User_Name',
    elkQuery: '{"query":{"term":{"event.code":"4688"}},"sort":[{"@timestamp":"desc"}]}',
    falsePositives: "Normal system processes, svchost.exe child processes, Windows Update, scheduled maintenance tasks",
    investigationSteps: [
      "Check Process_Command_Line for encoded PowerShell (-enc/-e), suspicious downloads (certutil, bitsadmin, wget), or reconnaissance commands",
      "Examine parent-child process relationships: cmd.exe spawned by Word/Excel = macro execution",
      "Look for processes running from unusual paths (\\Temp, \\AppData, \\ProgramData, \\Users\\Public)",
      "Check Token_Elevation_Type: 1=Default (no UAC), 2=Elevated, 3=Limited",
      "Alert on: powershell.exe -enc, cmd.exe /c whoami, net user, nltest, dsquery, csvde",
      "Detect LOLBins: mshta, regsvr32, rundll32, certutil, msbuild, installutil"
    ]
  },
  {
    id: 4689,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A process has exited. Records the process name and exit status code.",
    significance: "low",
    mitreTechniques: [],
    splunkQuery: 'index=wineventlog EventCode=4689 | stats count by Process_Name, Exit_Status',
    elkQuery: '{"query":{"term":{"event.code":"4689"}}}',
    falsePositives: "Normal process termination",
    investigationSteps: [
      "Calculate process runtime by correlating with 4688 (same Process_ID)",
      "Check for processes with very short runtimes (data staging, reconnaissance)",
      "Check Exit_Status for abnormal termination codes"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // SECURITY LOG — SERVICE INSTALLATION (4697)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 4697,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A service was installed in the system. Records the service name, file path, type, and start type.",
    significance: "critical",
    mitreTechniques: ["T1543.003 - Create or Modify System Process: Windows Service", "T1569.002 - Service Execution"],
    splunkQuery: 'index=wineventlog EventCode=4697 | table _time, Subject_User_Name, Service_Name, Service_File_Name, Service_Start_Type | where Service_File_Name!="*system32*"',
    elkQuery: '{"query":{"term":{"event.code":"4697"}}}',
    falsePositives: "Software installations, Windows Update installing drivers, legitimate admin tools creating services",
    investigationSteps: [
      "Check Service_File_Name for unusual paths or suspicious binaries",
      "Verify Service_Start_Type: 2=Automatic, 3=Manual, 4=Disabled",
      "Look for services with cmd.exe or powershell.exe as the binary path",
      "Check for services pointing to writable directories",
      "Alert on services created outside of normal change windows",
      "Cross-reference with known-good service baselines"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // SECURITY LOG — SCHEDULED TASKS (4698–4702)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 4698,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A scheduled task was created. Contains the full XML task definition including triggers, actions, and the command to execute.",
    significance: "critical",
    mitreTechniques: ["T1053.005 - Scheduled Task", "T1547.001 - Registry Run Keys / Startup Folder"],
    splunkQuery: 'index=wineventlog EventCode=4698 | table _time, Subject_User_Name, Task_Name, Task_Content | search Task_Content="*powershell*" OR Task_Content="*cmd*" OR Task_Content="*mshta*"',
    elkQuery: '{"query":{"term":{"event.code":"4698"}}}',
    falsePositives: "Windows Update tasks, software update schedulers (Adobe, Chrome), Group Policy tasks, SCCM tasks",
    investigationSteps: [
      "Parse the Task_Content XML to extract the command/action being executed",
      "Check for encoded commands, script downloads, or beacon callbacks in the action",
      "Verify the creating user has legitimate reason to create scheduled tasks",
      "Check trigger times — tasks set to run at boot or logon are persistence mechanisms",
      "Look for tasks created in \\Microsoft\\Windows\\* that mimic legitimate task names",
      "Alert on tasks pointing to temp directories or user-writable paths"
    ]
  },
  {
    id: 4699,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A scheduled task was deleted.",
    significance: "medium",
    mitreTechniques: ["T1070 - Indicator Removal on Host"],
    splunkQuery: 'index=wineventlog EventCode=4699 | table _time, Subject_User_Name, Task_Name',
    elkQuery: '{"query":{"term":{"event.code":"4699"}}}',
    falsePositives: "Cleanup of completed one-time tasks, software uninstallation removing scheduled updates",
    investigationSteps: [
      "Check if the task was recently created (4698) then quickly deleted — indicator of one-shot persistence",
      "Correlate with 4698 to determine what the deleted task was doing",
      "Alert on deletion of tasks that were not created by the same user"
    ]
  },
  {
    id: 4700,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A scheduled task was enabled.",
    significance: "medium",
    mitreTechniques: ["T1053.005 - Scheduled Task"],
    splunkQuery: 'index=wineventlog EventCode=4700 | table _time, Subject_User_Name, Task_Name',
    elkQuery: '{"query":{"term":{"event.code":"4700"}}}',
    falsePositives: "Re-enabling maintenance tasks, Group Policy re-enabling tasks",
    investigationSteps: [
      "Check if the task was previously disabled for a reason",
      "Correlate with 4698 to review the task content"
    ]
  },
  {
    id: 4701,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A scheduled task was disabled.",
    significance: "medium",
    mitreTechniques: ["T1562 - Impair Defenses"],
    splunkQuery: 'index=wineventlog EventCode=4701 | table _time, Subject_User_Name, Task_Name',
    elkQuery: '{"query":{"term":{"event.code":"4701"}}}',
    falsePositives: "Temporarily disabling maintenance tasks, disabling tasks during troubleshooting",
    investigationSteps: [
      "Check if security-related tasks were disabled (Windows Defender scans, log collection)",
      "Verify the disabling user has appropriate authorization"
    ]
  },
  {
    id: 4702,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A scheduled task was updated.",
    significance: "high",
    mitreTechniques: ["T1053.005 - Scheduled Task"],
    splunkQuery: 'index=wineventlog EventCode=4702 | table _time, Subject_User_Name, Task_Name, Task_Content',
    elkQuery: '{"query":{"term":{"event.code":"4702"}}}',
    falsePositives: "Software updates changing task parameters, GPO refreshing task definitions",
    investigationSteps: [
      "Compare old and new Task_Content to identify what changed",
      "Check if the action/command was modified to point to a different binary",
      "Alert on modifications to legitimate system tasks (hijacking)"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // SECURITY LOG — ACCOUNT MANAGEMENT (4720–4740)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 4720,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A user account was created. Contains the new account name, who created it, and initial attributes.",
    significance: "critical",
    mitreTechniques: ["T1136.001 - Create Account: Local Account", "T1136.002 - Create Account: Domain Account"],
    splunkQuery: 'index=wineventlog EventCode=4720 | table _time, Subject_User_Name, Target_User_Name, Subject_Domain_Name | where Subject_User_Name!="SYSTEM"',
    elkQuery: '{"query":{"term":{"event.code":"4720"}}}',
    falsePositives: "HR onboarding processes, automated provisioning systems, application installers creating service accounts",
    investigationSteps: [
      "Verify the creation was part of an authorized change request",
      "Check if the creating account (Subject) is authorized for user creation",
      "Look for accounts created with names mimicking service accounts or admin accounts",
      "Check for immediate group additions (4728/4732/4756) to privileged groups",
      "Alert on user creation outside of business hours or from unusual workstations",
      "Check if the new account was immediately used (4624) — indicator of rogue account creation"
    ]
  },
  {
    id: 4722,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A user account was enabled.",
    significance: "high",
    mitreTechniques: ["T1098 - Account Manipulation", "T1078 - Valid Accounts"],
    splunkQuery: 'index=wineventlog EventCode=4722 | table _time, Subject_User_Name, Target_User_Name',
    elkQuery: '{"query":{"term":{"event.code":"4722"}}}',
    falsePositives: "Re-enabling accounts after password reset, HR re-onboarding returning employees",
    investigationSteps: [
      "Check if the account was previously disabled for security reasons",
      "Verify the enabling action was authorized",
      "Monitor the account for immediate usage after enabling"
    ]
  },
  {
    id: 4723,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "An attempt was made to change an account's password. The user changed their own password.",
    significance: "medium",
    mitreTechniques: ["T1098 - Account Manipulation"],
    splunkQuery: 'index=wineventlog EventCode=4723 | stats count by Target_User_Name | sort -count',
    elkQuery: '{"query":{"term":{"event.code":"4723"}}}',
    falsePositives: "Normal password change policies, user-initiated password changes",
    investigationSteps: [
      "Check for multiple failed attempts (attacker trying to change a compromised account's password)",
      "Verify the change aligns with password policy expiration"
    ]
  },
  {
    id: 4724,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "An attempt was made to reset an account's password. An administrator or help desk reset the password.",
    significance: "high",
    mitreTechniques: ["T1098 - Account Manipulation"],
    splunkQuery: 'index=wineventlog EventCode=4724 | table _time, Subject_User_Name, Target_User_Name | where Subject_User_Name!=Target_User_Name',
    elkQuery: '{"query":{"term":{"event.code":"4724"}}}',
    falsePositives: "Help desk password resets, automated password rotation for service accounts",
    investigationSteps: [
      "Verify the reset was requested through proper channels (ticket system)",
      "Check if an admin is resetting passwords for accounts they shouldn't manage",
      "Alert on password resets of high-privilege accounts",
      "Look for mass password resets from a single admin account (possible compromise)"
    ]
  },
  {
    id: 4725,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A user account was disabled.",
    significance: "medium",
    mitreTechniques: ["T1531 - Account Access Removal"],
    splunkQuery: 'index=wineventlog EventCode=4725 | table _time, Subject_User_Name, Target_User_Name',
    elkQuery: '{"query":{"term":{"event.code":"4725"}}}',
    falsePositives: "HR offboarding, automated account lifecycle management",
    investigationSteps: [
      "Verify alignment with HR termination/offboarding",
      "Check if active service accounts were disabled (potential sabotage)",
      "Alert if admin accounts are being disabled by non-authorized users"
    ]
  },
  {
    id: 4726,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A user account was deleted.",
    significance: "high",
    mitreTechniques: ["T1070 - Indicator Removal on Host", "T1531 - Account Access Removal"],
    splunkQuery: 'index=wineventlog EventCode=4726 | table _time, Subject_User_Name, Target_User_Name',
    elkQuery: '{"query":{"term":{"event.code":"4726"}}}',
    falsePositives: "Account cleanup during offboarding, removing temporary accounts",
    investigationSteps: [
      "Verify the deletion was authorized and follows change management",
      "Check if the deleted account was recently created (rogue account cleanup by attacker)",
      "Alert on deletion of service accounts or admin accounts"
    ]
  },
  {
    id: 4728,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A member was added to a security-enabled global group.",
    significance: "high",
    mitreTechniques: ["T1098 - Account Manipulation", "T1078.002 - Domain Accounts"],
    splunkQuery: 'index=wineventlog EventCode=4728 | table _time, Subject_User_Name, Member_Name, Group_Name | search Group_Name="Domain Admins" OR Group_Name="Enterprise Admins"',
    elkQuery: '{"query":{"bool":{"must":[{"term":{"event.code":"4728"}},{"terms":{"winlog.event_data.TargetUserName":["Domain Admins","Enterprise Admins"]}}]}}}',
    falsePositives: "Authorized role changes, onboarding users to appropriate groups",
    investigationSteps: [
      "Check the target group — Domain Admins, Enterprise Admins, Schema Admins additions are critical",
      "Verify the change was authorized via change management system",
      "Check if the added member is a new account (4720 recently)",
      "Alert on additions to privileged groups outside change windows"
    ]
  },
  {
    id: 4729,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A member was removed from a security-enabled global group.",
    significance: "medium",
    mitreTechniques: ["T1098 - Account Manipulation"],
    splunkQuery: 'index=wineventlog EventCode=4729 | table _time, Subject_User_Name, Member_Name, Group_Name',
    elkQuery: '{"query":{"term":{"event.code":"4729"}}}',
    falsePositives: "Role changes, offboarding, group membership cleanup",
    investigationSteps: [
      "Check if security group members are being removed to weaken access controls",
      "Correlate with 4728 to see if the member was added then removed quickly (covering tracks)"
    ]
  },
  {
    id: 4732,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A member was added to a security-enabled local group.",
    significance: "high",
    mitreTechniques: ["T1098 - Account Manipulation", "T1136.001 - Create Account: Local Account"],
    splunkQuery: 'index=wineventlog EventCode=4732 | table _time, Subject_User_Name, Member_Name, Group_Name | search Group_Name="Administrators"',
    elkQuery: '{"query":{"bool":{"must":[{"term":{"event.code":"4732"}},{"term":{"winlog.event_data.TargetUserName":"Administrators"}}]}}}',
    falsePositives: "Software installation requiring local admin, IT provisioning new machines",
    investigationSteps: [
      "Adding to local Administrators group is a major privilege escalation indicator",
      "Check if the added account is a domain account being added to local admins",
      "Verify through change management",
      "Alert on any addition to local Administrators group"
    ]
  },
  {
    id: 4733,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A member was removed from a security-enabled local group.",
    significance: "medium",
    mitreTechniques: ["T1098 - Account Manipulation"],
    splunkQuery: 'index=wineventlog EventCode=4733 | table _time, Subject_User_Name, Member_Name, Group_Name',
    elkQuery: '{"query":{"term":{"event.code":"4733"}}}',
    falsePositives: "Normal role changes, software uninstallation removing service accounts",
    investigationSteps: [
      "Check if security-critical accounts are being removed from groups",
      "Verify removal was authorized"
    ]
  },
  {
    id: 4735,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A security-enabled local group was changed (attributes modified).",
    significance: "medium",
    mitreTechniques: ["T1098 - Account Manipulation"],
    splunkQuery: 'index=wineventlog EventCode=4735 | table _time, Subject_User_Name, Group_Name, Group_Domain',
    elkQuery: '{"query":{"term":{"event.code":"4735"}}}',
    falsePositives: "Group description changes, authorized group attribute modifications",
    investigationSteps: [
      "Check what group attributes were changed",
      "Verify the change was authorized"
    ]
  },
  {
    id: 4737,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A security-enabled global group was changed.",
    significance: "medium",
    mitreTechniques: ["T1098 - Account Manipulation"],
    splunkQuery: 'index=wineventlog EventCode=4737 | table _time, Subject_User_Name, Group_Name',
    elkQuery: '{"query":{"term":{"event.code":"4737"}}}',
    falsePositives: "Authorized group modifications through AD management tools",
    investigationSteps: [
      "Check what changed on the group (name, description, scope)",
      "Verify through change management"
    ]
  },
  {
    id: 4738,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A user account was changed. Records which attributes were modified.",
    significance: "high",
    mitreTechniques: ["T1098 - Account Manipulation", "T1078 - Valid Accounts"],
    splunkQuery: 'index=wineventlog EventCode=4738 | table _time, Subject_User_Name, Target_User_Name, User_Account_Control | where User_Account_Control="*Enabled*" OR User_Account_Control="*Password Not Required*"',
    elkQuery: '{"query":{"term":{"event.code":"4738"}}}',
    falsePositives: "Password expiry policy changes, user profile updates, LDAP attribute synchronization",
    investigationSteps: [
      "Check User_Account_Control changes: Don't Require Preauth (AS-REP roasting setup), Password Not Required, Trusted For Delegation",
      "Alert on SPN changes (Kerberoasting setup via targeted SPN addition)",
      "Check for script path or home directory changes (malicious logon scripts)",
      "Look for changes to adminCount attribute or delegation settings"
    ]
  },
  {
    id: 4740,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A user account was locked out. Contains the account name and the computer from which the lockout originated.",
    significance: "high",
    mitreTechniques: ["T1110 - Brute Force"],
    splunkQuery: 'index=wineventlog EventCode=4740 | stats count by Target_User_Name, Caller_Computer_Name | sort -count',
    elkQuery: '{"query":{"term":{"event.code":"4740"}}}',
    falsePositives: "Users forgetting passwords, stale credentials in mapped drives or cached sessions, mobile devices with old passwords",
    investigationSteps: [
      "Check Caller_Computer_Name to identify the source of bad passwords",
      "Correlate with 4625 events from the same source to see what account was targeted",
      "Look for mass lockouts which may indicate a brute force or password spray attack",
      "Check if the lockout source is an external IP or unknown system",
      "Verify if the locked account is a service account (may cause service outage)"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // SECURITY LOG — KERBEROS (4768–4776)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 4768,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A Kerberos authentication ticket (TGT) was requested. The initial authentication step in Kerberos.",
    significance: "high",
    mitreTechniques: ["T1558.004 - AS-REP Roasting", "T1078.002 - Domain Accounts"],
    splunkQuery: 'index=wineventlog EventCode=4768 | stats count by Target_User_Name, Client_Address, Ticket_Encryption_Type | where Ticket_Encryption_Type="0x17"',
    elkQuery: '{"query":{"term":{"event.code":"4768"}}}',
    falsePositives: "Normal Kerberos authentication, machine account TGT requests every 10 hours",
    investigationSteps: [
      "Check Ticket_Encryption_Type: 0x17=RC4-HMAC (normal but weak), 0x12=AES256 (preferred), 0x23=RC4 (downgrade attack)",
      "Result_Code 0x6=principal unknown, 0x12=pre-auth required, 0x17=password expired, 0x18=pre-auth failed (wrong password)",
      "Alert on Result_Code 0x0 with encryption type RC4 for accounts without pre-auth (AS-REP roasting)",
      "Check for TGT requests from unexpected client addresses",
      "Monitor for high-frequency TGT requests from a single source (brute force)"
    ]
  },
  {
    id: 4769,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A Kerberos service ticket (TGS) was requested. Used when a user accesses a service.",
    significance: "high",
    mitreTechniques: ["T1558.003 - Kerberoasting", "T1021 - Remote Services"],
    splunkQuery: 'index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17 | stats count by Target_User_Name, Service_Name, Client_Address | where count>5 | sort -count',
    elkQuery: '{"query":{"bool":{"must":[{"term":{"event.code":"4769"}},{"term":{"winlog.event_data.TicketEncryptionType":"0x17"}}]}}}',
    falsePositives: "Normal service ticket requests, application servers requesting tickets on behalf of users",
    investigationSteps: [
      "Alert on RC4 encryption (0x17) TGS requests — Kerberoasting indicator",
      "Check for single user requesting tickets for many different SPNs in short time",
      "Look for Service_Name values that match high-value accounts (SQL admin, Exchange, etc.)",
      "Filter out machine accounts ($) and krbtgt from noise",
      "Correlate with 4688 to check if Rubeus.exe, Invoke-Kerberoast, or GetUserSPNs was run"
    ]
  },
  {
    id: 4770,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A Kerberos service ticket was renewed.",
    significance: "low",
    mitreTechniques: ["T1550.003 - Pass the Ticket"],
    splunkQuery: 'index=wineventlog EventCode=4770 | stats count by Target_User_Name, Service_Name',
    elkQuery: '{"query":{"term":{"event.code":"4770"}}}',
    falsePositives: "Normal ticket renewals for long-running sessions",
    investigationSteps: [
      "Check for unusual renewal patterns or renewals from unexpected IPs",
      "High volume of renewals may indicate ticket reuse (Pass the Ticket)"
    ]
  },
  {
    id: 4771,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "Kerberos pre-authentication failed. Equivalent to a failed logon attempt but specific to Kerberos.",
    significance: "high",
    mitreTechniques: ["T1110 - Brute Force", "T1110.003 - Password Spraying"],
    splunkQuery: 'index=wineventlog EventCode=4771 | stats count by Target_User_Name, Client_Address, Failure_Code | where count>5',
    elkQuery: '{"query":{"term":{"event.code":"4771"}}}',
    falsePositives: "Expired passwords, clock skew between client and DC, old cached credentials",
    investigationSteps: [
      "Failure_Code: 0x18=wrong password, 0x12=account disabled/expired, 0x17=password expired, 0x25=clock skew",
      "Multiple 0x18 failures from same IP = brute force attempt",
      "Multiple 0x18 failures against different accounts from same IP = password spray",
      "Correlate with 4768 success events to check if attacker eventually succeeded"
    ]
  },
  {
    id: 4772,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A Kerberos authentication ticket request failed.",
    significance: "medium",
    mitreTechniques: ["T1558 - Steal or Forge Kerberos Tickets"],
    splunkQuery: 'index=wineventlog EventCode=4772 | stats count by Target_User_Name, Failure_Code',
    elkQuery: '{"query":{"term":{"event.code":"4772"}}}',
    falsePositives: "Service accounts with expired passwords, misconfigured SPNs",
    investigationSteps: [
      "Check failure codes for patterns suggesting ticket forging attempts",
      "Correlate with other Kerberos events for the same account"
    ]
  },
  {
    id: 4773,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A Kerberos service ticket request failed.",
    significance: "medium",
    mitreTechniques: ["T1558 - Steal or Forge Kerberos Tickets"],
    splunkQuery: 'index=wineventlog EventCode=4773 | stats count by Target_User_Name, Service_Name, Failure_Code',
    elkQuery: '{"query":{"term":{"event.code":"4773"}}}',
    falsePositives: "Misconfigured SPNs, service accounts with wrong encryption types",
    investigationSteps: [
      "Check for forged ticket usage (Silver Ticket) causing service ticket failures",
      "Verify SPN configuration for the target service"
    ]
  },
  {
    id: 4776,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "The domain controller attempted to validate the credentials for an account (NTLM authentication).",
    significance: "high",
    mitreTechniques: ["T1110 - Brute Force", "T1550.002 - Pass the Hash"],
    splunkQuery: 'index=wineventlog EventCode=4776 | stats count by Target_User_Name, Workstation_Name, Status | where Status!="0x0"',
    elkQuery: '{"query":{"term":{"event.code":"4776"}}}',
    falsePositives: "Legacy applications using NTLM, workgroup computers authenticating against DC, some VPN solutions",
    investigationSteps: [
      "Status 0x0=success, 0xC000006A=wrong password, 0xC0000064=user doesn't exist, 0xC0000234=locked out",
      "NTLM authentication in a Kerberos environment is suspicious — check why Kerberos wasn't used",
      "Look for Pass the Hash: successful NTLM auth from unusual workstation names",
      "Alert on NTLM auth from external IPs or for privileged accounts",
      "Check if NTLM was used because the client couldn't reach the KDC"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // SECURITY LOG — FILE SHARE ACCESS (5140–5145)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 5140,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A network share object was accessed. Records the share name and source IP.",
    significance: "high",
    mitreTechniques: ["T1021.002 - SMB/Windows Admin Shares", "T1039 - Data from Network Shared Drive"],
    splunkQuery: 'index=wineventlog EventCode=5140 Share_Name IN ("\\\\*\\C$","\\\\*\\ADMIN$","\\\\*\\IPC$") | stats count by Source_Address, Share_Name, Subject_User_Name',
    elkQuery: '{"query":{"bool":{"must":[{"term":{"event.code":"5140"}},{"terms":{"winlog.event_data.ShareName":["\\\\\\\\*\\\\C$","\\\\\\\\*\\\\ADMIN$"]}}]}}}',
    falsePositives: "Admin tools (SCCM, SCOM) accessing admin shares, file server normal operations, backup agents",
    investigationSteps: [
      "Alert on access to administrative shares (C$, ADMIN$, IPC$) from non-admin workstations",
      "Check Source_Address — admin share access from unexpected subnets indicates lateral movement",
      "IPC$ access is needed for enumeration (net view, PsExec) — check correlated 4688 events",
      "Monitor for C$ access followed by file copy operations (staging for exfiltration)"
    ]
  },
  {
    id: 5142,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A network share object was added.",
    significance: "high",
    mitreTechniques: ["T1135 - Network Share Discovery", "T1021.002 - SMB/Windows Admin Shares"],
    splunkQuery: 'index=wineventlog EventCode=5142 | table _time, Subject_User_Name, Share_Name, Share_Path',
    elkQuery: '{"query":{"term":{"event.code":"5142"}}}',
    falsePositives: "Administrators creating new file shares for departments, application installations creating shares",
    investigationSteps: [
      "Check if the new share exposes sensitive data",
      "Verify the share creation was authorized",
      "Check share permissions — Everyone/Full Control is dangerous"
    ]
  },
  {
    id: 5143,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A network share object was modified.",
    significance: "medium",
    mitreTechniques: ["T1222 - File and Directory Permissions Modification"],
    splunkQuery: 'index=wineventlog EventCode=5143 | table _time, Subject_User_Name, Share_Name, Old_SDDL, New_SDDL',
    elkQuery: '{"query":{"term":{"event.code":"5143"}}}',
    falsePositives: "Authorized permission changes, GPO-driven share permission updates",
    investigationSteps: [
      "Compare Old_SDDL and New_SDDL to identify permission changes",
      "Alert on permissions being relaxed (adding Everyone or broadening access)"
    ]
  },
  {
    id: 5144,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A network share object was deleted.",
    significance: "medium",
    mitreTechniques: ["T1070 - Indicator Removal on Host"],
    splunkQuery: 'index=wineventlog EventCode=5144 | table _time, Subject_User_Name, Share_Name',
    elkQuery: '{"query":{"term":{"event.code":"5144"}}}',
    falsePositives: "Cleanup of temporary shares, decommissioning file servers",
    investigationSteps: [
      "Verify the share deletion was authorized",
      "Check if the share was recently created (rogue share cleanup by attacker)"
    ]
  },
  {
    id: 5145,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A network share object was checked to see if the client can be granted desired access. More detailed than 5140.",
    significance: "high",
    mitreTechniques: ["T1021.002 - SMB/Windows Admin Shares", "T1039 - Data from Network Shared Drive"],
    splunkQuery: 'index=wineventlog EventCode=5145 Relative_Target_Name="*.exe" OR Relative_Target_Name="*.dll" OR Relative_Target_Name="*.ps1" | table _time, Source_Address, Share_Name, Relative_Target_Name',
    elkQuery: '{"query":{"bool":{"must":[{"term":{"event.code":"5145"}}]}}}',
    falsePositives: "File server normal operations, DFS namespace resolution, printer driver distribution",
    investigationSteps: [
      "Check Relative_Target_Name for sensitive file access patterns",
      "Alert on executable access (*.exe, *.dll, *.ps1, *.bat) via shares — PsExec uses ADMIN$ + exe copy",
      "Monitor for access to srvsvc, samr, lsarpc named pipes (reconnaissance)",
      "Check Access_Mask for write access to executable locations"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // SECURITY LOG — AUDIT LOG MANAGEMENT (1102)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 1102,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "The audit log was cleared. Extremely suspicious — defenders almost never clear the security log.",
    significance: "critical",
    mitreTechniques: ["T1070.001 - Indicator Removal: Clear Windows Event Logs"],
    splunkQuery: 'index=wineventlog EventCode=1102 | table _time, Subject_User_Name, Subject_Domain_Name, Computer',
    elkQuery: '{"query":{"term":{"event.code":"1102"}}}',
    falsePositives: "Extremely rare in legitimate operations — some compliance procedures require periodic log rotation but should use archival, not clearing",
    investigationSteps: [
      "IMMEDIATE ALERT — security log clearing is a top indicator of compromise",
      "Identify who cleared the log (Subject_User_Name) and from which machine",
      "Check other log sources (Sysmon, PowerShell, EDR) for the same timeframe",
      "Look for other anti-forensic activity around the same time",
      "Check if the account that cleared logs was compromised",
      "Collect logs from SIEM (they should have a copy before clearing)"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // SECURITY LOG — POLICY CHANGES (4704, 4706, 4713, 4719)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 4704,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A user right was assigned.",
    significance: "high",
    mitreTechniques: ["T1134 - Access Token Manipulation", "T1098 - Account Manipulation"],
    splunkQuery: 'index=wineventlog EventCode=4704 | table _time, Subject_User_Name, Target_User_Name, Privilege_Name',
    elkQuery: '{"query":{"term":{"event.code":"4704"}}}',
    falsePositives: "Group Policy application, software installations requiring specific privileges",
    investigationSteps: [
      "Check which privilege was assigned: SeDebugPrivilege, SeImpersonatePrivilege, SeTcbPrivilege are critical",
      "Verify the assignment was through proper Group Policy or authorized change",
      "Alert on privileges that enable credential theft or token manipulation"
    ]
  },
  {
    id: 4706,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A new trust was created to a domain.",
    significance: "critical",
    mitreTechniques: ["T1482 - Domain Trust Discovery", "T1134.005 - SID-History Injection"],
    splunkQuery: 'index=wineventlog EventCode=4706 | table _time, Subject_User_Name, Domain_Name, Trust_Type, Trust_Direction',
    elkQuery: '{"query":{"term":{"event.code":"4706"}}}',
    falsePositives: "Authorized domain trust creation during mergers/acquisitions, lab environment setup",
    investigationSteps: [
      "Verify the trust creation was authorized through change management",
      "Check Trust_Direction: Inbound, Outbound, or Bidirectional",
      "Check Trust_Type: Forest, External, Realm — each has different security implications",
      "Alert on any unauthorized trust creation — this can give attackers access to the entire forest"
    ]
  },
  {
    id: 4713,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "Kerberos policy was changed.",
    significance: "critical",
    mitreTechniques: ["T1484 - Domain Policy Modification"],
    splunkQuery: 'index=wineventlog EventCode=4713 | table _time, Subject_User_Name, Changes',
    elkQuery: '{"query":{"term":{"event.code":"4713"}}}',
    falsePositives: "Authorized Kerberos policy changes during security hardening",
    investigationSteps: [
      "Check what policy was changed: maximum ticket lifetime, maximum renewal age, maximum clock skew",
      "Increasing ticket lifetimes makes stolen tickets usable for longer",
      "Decreasing clock skew tolerance can cause authentication issues",
      "Verify through Group Policy change management"
    ]
  },
  {
    id: 4719,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "System audit policy was changed.",
    significance: "critical",
    mitreTechniques: ["T1562.002 - Impair Defenses: Disable Windows Event Logging"],
    splunkQuery: 'index=wineventlog EventCode=4719 | table _time, Subject_User_Name, Category, Subcategory, Changes',
    elkQuery: '{"query":{"term":{"event.code":"4719"}}}',
    falsePositives: "Authorized audit policy changes via Group Policy, security hardening activities",
    investigationSteps: [
      "ALERT — changing audit policy may be an attempt to stop logging before malicious activity",
      "Check if Success or Failure auditing was disabled for critical categories",
      "Verify the change through Group Policy management console",
      "Look for other defense evasion techniques around the same time"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // SECURITY LOG — SPECIAL EVENTS (4756, 4757, 4764, 4767)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 4756,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A member was added to a security-enabled universal group.",
    significance: "high",
    mitreTechniques: ["T1098 - Account Manipulation"],
    splunkQuery: 'index=wineventlog EventCode=4756 | table _time, Subject_User_Name, Member_Name, Group_Name | search Group_Name="Enterprise Admins" OR Group_Name="Schema Admins"',
    elkQuery: '{"query":{"term":{"event.code":"4756"}}}',
    falsePositives: "Authorized group membership changes, provisioning systems",
    investigationSteps: [
      "Enterprise Admins and Schema Admins are universal groups — additions are critical alerts",
      "Verify through change management",
      "Check for unauthorized elevation of privileges"
    ]
  },
  {
    id: 4757,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A member was removed from a security-enabled universal group.",
    significance: "medium",
    mitreTechniques: ["T1098 - Account Manipulation"],
    splunkQuery: 'index=wineventlog EventCode=4757 | table _time, Subject_User_Name, Member_Name, Group_Name',
    elkQuery: '{"query":{"term":{"event.code":"4757"}}}',
    falsePositives: "Authorized group membership changes",
    investigationSteps: [
      "Check if member was added briefly then removed (covering tracks after privilege abuse)"
    ]
  },
  {
    id: 4764,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A group's type was changed (e.g., from security to distribution or vice versa).",
    significance: "high",
    mitreTechniques: ["T1098 - Account Manipulation"],
    splunkQuery: 'index=wineventlog EventCode=4764 | table _time, Subject_User_Name, Group_Name, Group_Type_Change',
    elkQuery: '{"query":{"term":{"event.code":"4764"}}}',
    falsePositives: "Authorized changes during AD restructuring",
    investigationSteps: [
      "Changing a security group to distribution removes access controls",
      "Check if the change was authorized",
      "Alert on conversion of privileged security groups"
    ]
  },
  {
    id: 4767,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A user account was unlocked.",
    significance: "medium",
    mitreTechniques: ["T1078 - Valid Accounts"],
    splunkQuery: 'index=wineventlog EventCode=4767 | table _time, Subject_User_Name, Target_User_Name | stats count by Subject_User_Name, Target_User_Name',
    elkQuery: '{"query":{"term":{"event.code":"4767"}}}',
    falsePositives: "Help desk unlocking accounts after password issues",
    investigationSteps: [
      "Check if the account was locked due to brute force (correlate with 4740)",
      "Verify unlock was requested through proper channels",
      "Monitor the account for suspicious activity after unlock"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // SYSTEM LOG — SERVICE EVENTS (7034–7045)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 7034,
    source: "Service Control Manager",
    channel: "System",
    description: "A service terminated unexpectedly. Records the service name and how many times it has terminated.",
    significance: "medium",
    mitreTechniques: ["T1489 - Service Stop"],
    splunkQuery: 'index=wineventlog source="System" EventCode=7034 | stats count by ServiceName | sort -count',
    elkQuery: '{"query":{"bool":{"must":[{"term":{"event.code":"7034"}},{"term":{"winlog.channel":"System"}}]}}}',
    falsePositives: "Unstable third-party services, memory leaks causing crashes, Windows Update service restarts",
    investigationSteps: [
      "Check if security services terminated (Windows Defender, EDR agents, SIEM collectors)",
      "High crash count may indicate exploitation attempts",
      "Check for memory dump files that could contain exploit artifacts"
    ]
  },
  {
    id: 7035,
    source: "Service Control Manager",
    channel: "System",
    description: "A service was sent a start or stop control. Records the service name and type of control sent.",
    significance: "medium",
    mitreTechniques: ["T1489 - Service Stop", "T1569.002 - Service Execution"],
    splunkQuery: 'index=wineventlog source="System" EventCode=7035 | stats count by ServiceName, Control | sort -count',
    elkQuery: '{"query":{"bool":{"must":[{"term":{"event.code":"7035"}},{"term":{"winlog.channel":"System"}}]}}}',
    falsePositives: "Normal service management, Windows Update, application installations",
    investigationSteps: [
      "Alert on security service stops (Defender, firewall, EDR, sysmon)",
      "Check for unknown or suspicious service names being started",
      "Correlate with 7045 for newly installed services"
    ]
  },
  {
    id: 7036,
    source: "Service Control Manager",
    channel: "System",
    description: "A service entered the running or stopped state.",
    significance: "low",
    mitreTechniques: ["T1489 - Service Stop"],
    splunkQuery: 'index=wineventlog source="System" EventCode=7036 | stats count by ServiceName, param1 | sort -count',
    elkQuery: '{"query":{"bool":{"must":[{"term":{"event.code":"7036"}},{"term":{"winlog.channel":"System"}}]}}}',
    falsePositives: "Normal service start/stop during system operation",
    investigationSteps: [
      "Monitor for security services entering stopped state",
      "Baseline normal service state changes and alert on deviations"
    ]
  },
  {
    id: 7040,
    source: "Service Control Manager",
    channel: "System",
    description: "The start type of a service was changed (e.g., from Manual to Disabled, or Auto to Manual).",
    significance: "high",
    mitreTechniques: ["T1562 - Impair Defenses", "T1543.003 - Windows Service"],
    splunkQuery: 'index=wineventlog source="System" EventCode=7040 | table _time, ServiceName, param1, param2',
    elkQuery: '{"query":{"bool":{"must":[{"term":{"event.code":"7040"}},{"term":{"winlog.channel":"System"}}]}}}',
    falsePositives: "Authorized service configuration changes, software installation changing service startup types",
    investigationSteps: [
      "Alert on security services being disabled (Windows Firewall, Windows Defender, EventLog)",
      "Check if persistence services are being changed to Auto start",
      "param1=old start type, param2=new start type"
    ]
  },
  {
    id: 7045,
    source: "Service Control Manager",
    channel: "System",
    description: "A new service was installed in the system. Critical for detecting persistence and lateral movement tools.",
    significance: "critical",
    mitreTechniques: ["T1543.003 - Create or Modify System Process: Windows Service", "T1569.002 - Service Execution", "T1021.002 - SMB/Windows Admin Shares"],
    splunkQuery: 'index=wineventlog source="System" EventCode=7045 | table _time, ServiceName, ImagePath, ServiceType, StartType | where ImagePath!="*system32*" AND ImagePath!="*SysWOW64*"',
    elkQuery: '{"query":{"bool":{"must":[{"term":{"event.code":"7045"}},{"term":{"winlog.channel":"System"}}]}}}',
    falsePositives: "Software installations, driver installations, Windows Update",
    investigationSteps: [
      "Check ImagePath for suspicious binaries: cmd.exe /c, powershell.exe, binaries in temp dirs",
      "PsExec creates PSEXESVC service — check for lateral movement",
      "Look for service names that mimic legitimate Windows services",
      "Check ServiceType: own process, share process, kernel driver",
      "Alert on services with ImagePath pointing to writable directories",
      "Cross-reference with known-good service baselines"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // SYSTEM LOG — LOG MANAGEMENT (104)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 104,
    source: "Microsoft-Windows-Eventlog",
    channel: "System",
    description: "The event log was cleared (System log version of event 1102). Records which log was cleared.",
    significance: "critical",
    mitreTechniques: ["T1070.001 - Indicator Removal: Clear Windows Event Logs"],
    splunkQuery: 'index=wineventlog source="System" EventCode=104 | table _time, Subject_User_Name, Channel',
    elkQuery: '{"query":{"bool":{"must":[{"term":{"event.code":"104"}},{"term":{"winlog.channel":"System"}}]}}}',
    falsePositives: "Extremely rare — almost always indicates malicious activity or misconfigured log rotation",
    investigationSteps: [
      "IMMEDIATE ALERT — same severity as 1102",
      "Check which log channel was cleared",
      "Identify the user who cleared it",
      "Check SIEM for copies of the cleared logs",
      "Look for wevtutil.exe cl or Clear-EventLog in process auditing"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // SYSMON — PROCESS EVENTS (1, 5, 6)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 1,
    source: "Microsoft-Windows-Sysmon",
    channel: "Microsoft-Windows-Sysmon/Operational",
    description: "Process creation. The most detailed process creation event — includes full command line, hashes, parent process, current directory, and user.",
    significance: "critical",
    mitreTechniques: ["T1059 - Command and Scripting Interpreter", "T1204 - User Execution", "T1106 - Native API"],
    splunkQuery: 'index=sysmon EventCode=1 | eval cmdlen=len(CommandLine) | where cmdlen>100 | table _time, ParentImage, Image, CommandLine, User, Hashes | sort -cmdlen',
    elkQuery: '{"query":{"term":{"event.code":"1"}},"sort":[{"@timestamp":"desc"}]}',
    falsePositives: "Normal system process creation, administrative tools, development tools",
    investigationSteps: [
      "Check parent-child process chains: winword.exe→cmd.exe→powershell.exe = malicious macro",
      "Look for encoded PowerShell: -enc, -e, -encodedcommand, FromBase64String",
      "Check Image hash against threat intel (VirusTotal, MISP)",
      "Alert on processes from: \\Users\\Public, \\Temp, \\AppData\\Local\\Temp, \\ProgramData",
      "Detect LOLBins: mshta.exe, wscript.exe, cscript.exe, regsvr32.exe, msbuild.exe, installutil.exe",
      "Check CurrentDirectory for unusual execution locations",
      "Look for LSASS access: procdump.exe, taskmgr.exe with -ma flag, comsvcs.dll MiniDump"
    ]
  },
  {
    id: 5,
    source: "Microsoft-Windows-Sysmon",
    channel: "Microsoft-Windows-Sysmon/Operational",
    description: "Process terminated. Records the process GUID and image name.",
    significance: "low",
    mitreTechniques: [],
    splunkQuery: 'index=sysmon EventCode=5 | stats count by Image | sort -count',
    elkQuery: '{"query":{"term":{"event.code":"5"}}}',
    falsePositives: "Normal process termination",
    investigationSteps: [
      "Calculate process lifetime by correlating with Sysmon Event 1",
      "Very short-lived processes may indicate fileless malware or one-shot tools"
    ]
  },
  {
    id: 6,
    source: "Microsoft-Windows-Sysmon",
    channel: "Microsoft-Windows-Sysmon/Operational",
    description: "Driver loaded. Records the driver image path, hash, and whether it's signed.",
    significance: "high",
    mitreTechniques: ["T1014 - Rootkit", "T1068 - Exploitation for Privilege Escalation", "T1543.003 - Windows Service"],
    splunkQuery: 'index=sysmon EventCode=6 Signed=false | table _time, ImageLoaded, Hashes, SignatureStatus',
    elkQuery: '{"query":{"bool":{"must":[{"term":{"event.code":"6"}},{"term":{"winlog.event_data.Signed":"false"}}]}}}',
    falsePositives: "Third-party drivers during installation, development drivers, virtual machine drivers",
    investigationSteps: [
      "Alert on unsigned drivers (Signed=false) — rootkit indicator",
      "Check driver hash against known vulnerable drivers (BYOVD attacks)",
      "Known BYOVD targets: RTCore64.sys, dbutil_2_3.sys, ene.sys, asio.sys",
      "Verify driver source and certificate validity"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // SYSMON — NETWORK (3)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 3,
    source: "Microsoft-Windows-Sysmon",
    channel: "Microsoft-Windows-Sysmon/Operational",
    description: "Network connection detected. Records source/destination IP and port, protocol, and the process making the connection.",
    significance: "high",
    mitreTechniques: ["T1071 - Application Layer Protocol", "T1041 - Exfiltration Over C2 Channel", "T1572 - Protocol Tunneling"],
    splunkQuery: 'index=sysmon EventCode=3 | stats count by Image, DestinationIp, DestinationPort | where Image!="*svchost*" AND Image!="*chrome*" AND Image!="*firefox*" | sort -count',
    elkQuery: '{"query":{"term":{"event.code":"3"}}}',
    falsePositives: "Web browsers, Windows Update, cloud sync clients, telemetry services",
    investigationSteps: [
      "Alert on unexpected processes making outbound connections (cmd.exe, powershell.exe, mshta.exe, regsvr32.exe)",
      "Check DestinationPort: 4444 (Metasploit), 8080 (common C2), 443 (HTTPS C2), 53 (DNS tunneling)",
      "Look for connections to known bad IPs/domains via threat intel feeds",
      "Check for beaconing patterns (regular interval connections)",
      "Monitor for connections from LOLBins that shouldn't need network access"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // SYSMON — IMAGE/DLL LOADING (7)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 7,
    source: "Microsoft-Windows-Sysmon",
    channel: "Microsoft-Windows-Sysmon/Operational",
    description: "Image loaded. Records when a DLL or module is loaded by a process, including the hash and signature status.",
    significance: "high",
    mitreTechniques: ["T1574.001 - DLL Search Order Hijacking", "T1574.002 - DLL Side-Loading", "T1055.001 - DLL Injection"],
    splunkQuery: 'index=sysmon EventCode=7 Signed=false | stats count by Image, ImageLoaded | sort -count',
    elkQuery: '{"query":{"bool":{"must":[{"term":{"event.code":"7"}},{"term":{"winlog.event_data.Signed":"false"}}]}}}',
    falsePositives: "Development libraries, custom application DLLs, some third-party software using unsigned DLLs",
    investigationSteps: [
      "Alert on unsigned DLLs loaded by system processes (DLL hijacking)",
      "Check for DLLs loaded from non-standard paths (user-writable directories)",
      "Look for clr.dll or mscoree.dll loaded by unexpected processes (.NET injection)",
      "Check for amsi.dll NOT being loaded by PowerShell (AMSI bypass indicator)",
      "Monitor for known malicious DLL names: mimilib.dll, PowerShdll.dll"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // SYSMON — REMOTE THREAD / PROCESS ACCESS (8, 10)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 8,
    source: "Microsoft-Windows-Sysmon",
    channel: "Microsoft-Windows-Sysmon/Operational",
    description: "CreateRemoteThread detected. A process created a thread in another process — common injection technique.",
    significance: "critical",
    mitreTechniques: ["T1055 - Process Injection", "T1055.003 - Thread Execution Hijacking"],
    splunkQuery: 'index=sysmon EventCode=8 | stats count by SourceImage, TargetImage | where SourceImage!=TargetImage',
    elkQuery: '{"query":{"term":{"event.code":"8"}}}',
    falsePositives: "Debuggers, some legitimate software using CreateRemoteThread for hooking (antivirus, accessibility tools)",
    investigationSteps: [
      "Alert on any CreateRemoteThread into lsass.exe (credential dumping)",
      "Check SourceImage — malware creates threads in legitimate processes to hide",
      "Look for thread creation from unusual locations (temp, appdata)",
      "Check StartAddress for shellcode indicators",
      "Correlate with Sysmon Event 10 for process access patterns"
    ]
  },
  {
    id: 10,
    source: "Microsoft-Windows-Sysmon",
    channel: "Microsoft-Windows-Sysmon/Operational",
    description: "Process accessed. Records when a process opens another process, critical for detecting credential dumping.",
    significance: "critical",
    mitreTechniques: ["T1003.001 - LSASS Memory", "T1055 - Process Injection"],
    splunkQuery: 'index=sysmon EventCode=10 TargetImage="*lsass.exe" GrantedAccess IN ("0x1010","0x1410","0x1438","0x143a","0x1fffff") | table _time, SourceImage, TargetImage, GrantedAccess, SourceUser',
    elkQuery: '{"query":{"bool":{"must":[{"term":{"event.code":"10"}},{"wildcard":{"winlog.event_data.TargetImage":"*lsass.exe"}}]}}}',
    falsePositives: "Antivirus/EDR scanning LSASS, Windows Error Reporting, csrss.exe, authorized security tools",
    investigationSteps: [
      "LSASS access with 0x1010 or 0x1FFFFF = credential dumping (mimikatz, procdump, comsvcs.dll)",
      "Known legitimate LSASS accessors: csrss.exe, smss.exe, wininit.exe, wmiprvse.exe (WMI only)",
      "GrantedAccess decode: 0x0010=VM_READ, 0x0400=QUERY_INFO, 0x1000=QUERY_LIMITED",
      "Alert on ANY non-standard process accessing LSASS",
      "Check SourceImage hash against known credential dumping tools",
      "Look for MiniDumpWriteDump calls via CallTrace field"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // SYSMON — FILE SYSTEM (11, 15, 23, 26)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 11,
    source: "Microsoft-Windows-Sysmon",
    channel: "Microsoft-Windows-Sysmon/Operational",
    description: "File created. Records the process creating the file, the file path, and creation time.",
    significance: "medium",
    mitreTechniques: ["T1105 - Ingress Tool Transfer", "T1059 - Command and Scripting Interpreter"],
    splunkQuery: 'index=sysmon EventCode=11 TargetFilename="*.exe" OR TargetFilename="*.dll" OR TargetFilename="*.ps1" OR TargetFilename="*.bat" | stats count by Image, TargetFilename | sort -count',
    elkQuery: '{"query":{"bool":{"must":[{"term":{"event.code":"11"}}]}}}',
    falsePositives: "Software installations, browser downloads, temp file creation, application updates",
    investigationSteps: [
      "Alert on executables created in temp directories, Downloads, or user-writable system paths",
      "Check for files dropped by Office applications (macro payload delivery)",
      "Monitor for .hta, .vbs, .js, .wsf file creation (script-based attacks)",
      "Look for files with double extensions (report.pdf.exe)",
      "Check Image field to see what process created the file"
    ]
  },
  {
    id: 15,
    source: "Microsoft-Windows-Sysmon",
    channel: "Microsoft-Windows-Sysmon/Operational",
    description: "FileCreateStreamHash. Logs when an alternate data stream (ADS) is created, including its hash.",
    significance: "high",
    mitreTechniques: ["T1564.004 - NTFS File Attributes", "T1105 - Ingress Tool Transfer"],
    splunkQuery: 'index=sysmon EventCode=15 | stats count by Image, TargetFilename | where TargetFilename="*:*" | sort -count',
    elkQuery: '{"query":{"term":{"event.code":"15"}}}',
    falsePositives: "Browser downloads creating Zone.Identifier ADS, some backup software",
    investigationSteps: [
      "ADS can hide executable content in legitimate files",
      "Filter out Zone.Identifier streams (normal browser behavior)",
      "Alert on executable content hidden in ADS of document files",
      "Check the stream hash against threat intel"
    ]
  },
  {
    id: 23,
    source: "Microsoft-Windows-Sysmon",
    channel: "Microsoft-Windows-Sysmon/Operational",
    description: "File delete archived. When configured, Sysmon archives deleted files for forensic analysis.",
    significance: "medium",
    mitreTechniques: ["T1070.004 - Indicator Removal: File Deletion", "T1485 - Data Destruction"],
    splunkQuery: 'index=sysmon EventCode=23 | stats count by Image, TargetFilename | sort -count',
    elkQuery: '{"query":{"term":{"event.code":"23"}}}',
    falsePositives: "Normal temp file cleanup, application cache management",
    investigationSteps: [
      "Check for deletion of security tools, logs, or evidence",
      "Look for mass file deletion patterns (ransomware or data destruction)",
      "Archived copy can be analyzed for malware"
    ]
  },
  {
    id: 26,
    source: "Microsoft-Windows-Sysmon",
    channel: "Microsoft-Windows-Sysmon/Operational",
    description: "File delete logged. Records file deletions without archiving the file content.",
    significance: "medium",
    mitreTechniques: ["T1070.004 - Indicator Removal: File Deletion"],
    splunkQuery: 'index=sysmon EventCode=26 | stats count by Image, TargetFilename | sort -count',
    elkQuery: '{"query":{"term":{"event.code":"26"}}}',
    falsePositives: "Normal file management, temp file cleanup",
    investigationSteps: [
      "Similar to Event 23 but without archival",
      "Monitor for deletion patterns indicating anti-forensics"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // SYSMON — REGISTRY (12, 13, 14)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 12,
    source: "Microsoft-Windows-Sysmon",
    channel: "Microsoft-Windows-Sysmon/Operational",
    description: "Registry object added or deleted. Records the registry key path and the process modifying it.",
    significance: "high",
    mitreTechniques: ["T1547.001 - Registry Run Keys / Startup Folder", "T1112 - Modify Registry", "T1546.001 - Change Default File Association"],
    splunkQuery: 'index=sysmon EventCode=12 TargetObject="*\\Run\\*" OR TargetObject="*\\RunOnce\\*" OR TargetObject="*\\Services\\*" | table _time, Image, EventType, TargetObject',
    elkQuery: '{"query":{"bool":{"must":[{"term":{"event.code":"12"}}]}}}',
    falsePositives: "Software installations modifying registry, Group Policy applying settings, Windows Update",
    investigationSteps: [
      "Alert on Run/RunOnce key modifications (persistence)",
      "Check for new services being registered in HKLM\\SYSTEM\\CurrentControlSet\\Services",
      "Monitor IFEO (Image File Execution Options) for debugger persistence",
      "Look for AppInit_DLLs modifications (DLL injection persistence)",
      "Check TargetObject for COM object hijacking (InprocServer32 modifications)"
    ]
  },
  {
    id: 13,
    source: "Microsoft-Windows-Sysmon",
    channel: "Microsoft-Windows-Sysmon/Operational",
    description: "Registry value set. Records the value name, type, and data being written.",
    significance: "high",
    mitreTechniques: ["T1547.001 - Registry Run Keys / Startup Folder", "T1112 - Modify Registry"],
    splunkQuery: 'index=sysmon EventCode=13 TargetObject="*\\Run\\*" | table _time, Image, TargetObject, Details',
    elkQuery: '{"query":{"bool":{"must":[{"term":{"event.code":"13"}}]}}}',
    falsePositives: "Normal registry value changes during software installation and configuration",
    investigationSteps: [
      "Check Details field for the value being written (command paths, DLL paths)",
      "Alert on encoded content being written to registry (PowerShell storage)",
      "Monitor for DisableAntiSpyware, DisableRealtimeMonitoring in Defender keys",
      "Check for AMSI provider removal in registry"
    ]
  },
  {
    id: 14,
    source: "Microsoft-Windows-Sysmon",
    channel: "Microsoft-Windows-Sysmon/Operational",
    description: "Registry object renamed. Records old and new names of registry keys/values.",
    significance: "medium",
    mitreTechniques: ["T1112 - Modify Registry"],
    splunkQuery: 'index=sysmon EventCode=14 | table _time, Image, TargetObject, NewName',
    elkQuery: '{"query":{"term":{"event.code":"14"}}}',
    falsePositives: "Software migrations renaming registry keys, profile migrations",
    investigationSteps: [
      "Check for renaming of security-related registry keys",
      "Look for keys being renamed to hide malicious entries"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // SYSMON — NAMED PIPES (17, 18)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 17,
    source: "Microsoft-Windows-Sysmon",
    channel: "Microsoft-Windows-Sysmon/Operational",
    description: "Pipe created. Named pipes are used for inter-process communication and by many C2 frameworks.",
    significance: "high",
    mitreTechniques: ["T1559 - Inter-Process Communication", "T1570 - Lateral Tool Transfer"],
    splunkQuery: 'index=sysmon EventCode=17 | stats count by Image, PipeName | where PipeName!="*\\\\wkssvc*" AND PipeName!="*\\\\srvsvc*" | sort -count',
    elkQuery: '{"query":{"term":{"event.code":"17"}}}',
    falsePositives: "Normal Windows IPC, SQL Server named pipes, print spooler",
    investigationSteps: [
      "Known malicious pipe names: \\\\msagent_*, \\\\MSSE-*, \\\\postex_*, \\\\status_*, \\\\mypipe-f*, \\\\win_svc",
      "Cobalt Strike default pipes: \\\\MSSE-*, \\\\postex_*, \\\\status_*",
      "PsExec uses: \\\\psexesvc",
      "Check for pipes with random alphanumeric names",
      "Correlate with network connections from the same process"
    ]
  },
  {
    id: 18,
    source: "Microsoft-Windows-Sysmon",
    channel: "Microsoft-Windows-Sysmon/Operational",
    description: "Pipe connected. Records when a process connects to a named pipe.",
    significance: "high",
    mitreTechniques: ["T1559 - Inter-Process Communication", "T1021.002 - SMB/Windows Admin Shares"],
    splunkQuery: 'index=sysmon EventCode=18 | stats count by Image, PipeName | sort -count',
    elkQuery: '{"query":{"term":{"event.code":"18"}}}',
    falsePositives: "Normal Windows service communication, application IPC",
    investigationSteps: [
      "Check for connections to known malicious pipes (see Event 17 list)",
      "Look for lateral movement: pipes connected from remote systems via SMB",
      "Correlate pipe names between Events 17 and 18 to map IPC patterns"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // SYSMON — DNS QUERY (22)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 22,
    source: "Microsoft-Windows-Sysmon",
    channel: "Microsoft-Windows-Sysmon/Operational",
    description: "DNS query. Records the process making the DNS query, the queried domain, and the result.",
    significance: "high",
    mitreTechniques: ["T1071.004 - DNS", "T1568 - Dynamic Resolution", "T1048.003 - Exfiltration Over Unencrypted Non-C2 Protocol"],
    splunkQuery: 'index=sysmon EventCode=22 | stats count by Image, QueryName | where Image!="*chrome*" AND Image!="*firefox*" AND Image!="*edge*" AND Image!="*svchost*" | sort -count',
    elkQuery: '{"query":{"term":{"event.code":"22"}}}',
    falsePositives: "Normal DNS resolution, CDN lookups, telemetry services, Windows Update",
    investigationSteps: [
      "Alert on DNS queries from unexpected processes (cmd.exe, powershell.exe, rundll32.exe)",
      "Check for DGA domains (long random-looking strings)",
      "Monitor for DNS tunneling indicators: high-entropy subdomains, TXT queries, high query volume to single domain",
      "Look for queries to known C2 domains via threat intel",
      "Check for base64-encoded data in subdomain labels (DNS exfiltration)"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // SYSMON — PROCESS TAMPERING (25)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 25,
    source: "Microsoft-Windows-Sysmon",
    channel: "Microsoft-Windows-Sysmon/Operational",
    description: "Process tampering. Detects process hollowing, process herpaderping, and other process image tampering techniques.",
    significance: "critical",
    mitreTechniques: ["T1055.012 - Process Hollowing", "T1055 - Process Injection"],
    splunkQuery: 'index=sysmon EventCode=25 | table _time, Image, Type, User',
    elkQuery: '{"query":{"term":{"event.code":"25"}}}',
    falsePositives: "Very few false positives — some packers and runtime protectors may trigger",
    investigationSteps: [
      "HIGH CONFIDENCE ALERT — process tampering is almost always malicious",
      "Type field indicates the technique: Image is locked, Image is replaced",
      "Process hollowing: legitimate process started in suspended state, code replaced, resumed",
      "Herpaderping: file content modified after mapping but before process creation completes",
      "Immediately isolate the system and begin incident response",
      "Collect memory dump of the affected process"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // SYSMON — WMI (19, 20, 21)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 19,
    source: "Microsoft-Windows-Sysmon",
    channel: "Microsoft-Windows-Sysmon/Operational",
    description: "WmiEventFilter activity detected. WMI event subscriptions are used for persistence.",
    significance: "critical",
    mitreTechniques: ["T1546.003 - WMI Event Subscription"],
    splunkQuery: 'index=sysmon EventCode=19 | table _time, EventType, Operation, User, Name, Query',
    elkQuery: '{"query":{"term":{"event.code":"19"}}}',
    falsePositives: "Legitimate monitoring tools using WMI (SCCM, SCOM), some PowerShell scripts",
    investigationSteps: [
      "WMI persistence is a favorite of advanced attackers — investigate thoroughly",
      "Check the WQL query in the filter — common triggers: process start, logon, timer",
      "Correlate with Event 20 (Consumer) and Event 21 (Binding) for the full subscription",
      "Look for CommandLineEventConsumer or ActiveScriptEventConsumer (execution capabilities)"
    ]
  },
  {
    id: 20,
    source: "Microsoft-Windows-Sysmon",
    channel: "Microsoft-Windows-Sysmon/Operational",
    description: "WmiEventConsumer activity detected. The consumer defines what action to take when the filter triggers.",
    significance: "critical",
    mitreTechniques: ["T1546.003 - WMI Event Subscription"],
    splunkQuery: 'index=sysmon EventCode=20 | table _time, EventType, Operation, User, Name, Destination',
    elkQuery: '{"query":{"term":{"event.code":"20"}}}',
    falsePositives: "Legitimate WMI consumers for monitoring",
    investigationSteps: [
      "Check Destination field for commands or scripts to be executed",
      "CommandLineEventConsumer runs arbitrary commands",
      "ActiveScriptEventConsumer runs VBScript/JScript",
      "LogFileEventConsumer can write to arbitrary files"
    ]
  },
  {
    id: 21,
    source: "Microsoft-Windows-Sysmon",
    channel: "Microsoft-Windows-Sysmon/Operational",
    description: "WmiEventConsumerToFilter activity detected. The binding connects a filter to a consumer, completing the subscription.",
    significance: "critical",
    mitreTechniques: ["T1546.003 - WMI Event Subscription"],
    splunkQuery: 'index=sysmon EventCode=21 | table _time, EventType, Operation, User, Consumer, Filter',
    elkQuery: '{"query":{"term":{"event.code":"21"}}}',
    falsePositives: "Legitimate WMI subscriptions by management tools",
    investigationSteps: [
      "This event completes the persistence chain (Filter→Consumer→Binding)",
      "Correlate with Events 19 and 20 to understand the full subscription",
      "Use wmic /namespace:\\\\root\\subscription PATH __EventFilter to enumerate existing subscriptions",
      "Remove with: Get-WMIObject -Namespace root/subscription -Class __EventFilter | Remove-WMIObject"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // SYSMON — CLIPBOARD (24) AND CONFIG (16)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 24,
    source: "Microsoft-Windows-Sysmon",
    channel: "Microsoft-Windows-Sysmon/Operational",
    description: "Clipboard change. Records when clipboard content changes and which process changed it.",
    significance: "medium",
    mitreTechniques: ["T1115 - Clipboard Data"],
    splunkQuery: 'index=sysmon EventCode=24 | stats count by Image | where Image!="*explorer.exe*" AND Image!="*rdpclip.exe*" | sort -count',
    elkQuery: '{"query":{"term":{"event.code":"24"}}}',
    falsePositives: "Normal copy/paste operations, clipboard managers, RDP clipboard sync",
    investigationSteps: [
      "Check which process is reading/modifying clipboard data",
      "Alert on unusual processes accessing clipboard (possible credential harvesting)",
      "Clipboard monitoring malware often captures passwords copied from password managers"
    ]
  },
  {
    id: 16,
    source: "Microsoft-Windows-Sysmon",
    channel: "Microsoft-Windows-Sysmon/Operational",
    description: "Sysmon config state changed. Records when the Sysmon configuration is updated.",
    significance: "critical",
    mitreTechniques: ["T1562 - Impair Defenses"],
    splunkQuery: 'index=sysmon EventCode=16 | table _time, Configuration, ConfigurationFileHash',
    elkQuery: '{"query":{"term":{"event.code":"16"}}}',
    falsePositives: "Authorized Sysmon configuration updates by security team",
    investigationSteps: [
      "Verify the configuration change was authorized",
      "Check if monitoring rules were weakened or removed",
      "Compare ConfigurationFileHash with known-good config hash",
      "Alert on any unexpected Sysmon configuration changes"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // POWERSHELL EVENTS (4103, 4104, 400, 403, 800)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 4103,
    source: "Microsoft-Windows-PowerShell",
    channel: "Microsoft-Windows-PowerShell/Operational",
    description: "Module logging. Records cmdlets and functions executed, including parameters and output.",
    significance: "high",
    mitreTechniques: ["T1059.001 - PowerShell", "T1106 - Native API"],
    splunkQuery: 'index=wineventlog source="Microsoft-Windows-PowerShell/Operational" EventCode=4103 | table _time, Payload, ContextInfo',
    elkQuery: '{"query":{"bool":{"must":[{"term":{"event.code":"4103"}},{"term":{"winlog.channel":"Microsoft-Windows-PowerShell/Operational"}}]}}}',
    falsePositives: "Normal PowerShell administration, DSC configurations, scheduled PowerShell tasks",
    investigationSteps: [
      "Check Payload for suspicious cmdlets: Invoke-Expression, Invoke-WebRequest, New-Object Net.WebClient",
      "Look for download cradles: IEX(IWR ...), IEX(New-Object Net.WebClient).DownloadString(...)",
      "Monitor for AD enumeration: Get-ADUser, Get-ADComputer, Get-ADGroup",
      "Check for execution policy bypass: Set-ExecutionPolicy, -ExecutionPolicy Bypass",
      "Look for AMSI bypass attempts: [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
    ]
  },
  {
    id: 4104,
    source: "Microsoft-Windows-PowerShell",
    channel: "Microsoft-Windows-PowerShell/Operational",
    description: "Script block logging. Records the full text of PowerShell scripts when they execute — the single most valuable PowerShell log.",
    significance: "critical",
    mitreTechniques: ["T1059.001 - PowerShell", "T1027 - Obfuscated Files or Information"],
    splunkQuery: 'index=wineventlog source="Microsoft-Windows-PowerShell/Operational" EventCode=4104 ScriptBlockText="*" | eval slen=len(ScriptBlockText) | where slen>500 | table _time, ScriptBlockText, Path',
    elkQuery: '{"query":{"bool":{"must":[{"term":{"event.code":"4104"}},{"term":{"winlog.channel":"Microsoft-Windows-PowerShell/Operational"}}]}}}',
    falsePositives: "Normal PowerShell scripts, DSC configurations, profile scripts, module loading",
    investigationSteps: [
      "Search ScriptBlockText for: Invoke-Mimikatz, Invoke-Kerberoast, Invoke-BloodHound, Invoke-PowerShellTcp",
      "Look for Base64 encoding: [Convert]::FromBase64String, -enc, -EncodedCommand",
      "Check for AMSI bypass strings: AmsiInitFailed, amsiContext, AmsiScanBuffer",
      "Monitor for reflective loading: [Reflection.Assembly]::Load",
      "Detect obfuscation: excessive backticks, string concatenation, variable substitution, -replace chains",
      "Check MessageNumber and MessageTotal for multi-part scripts (large scripts split across events)",
      "Warning level 3 = suspicious, 5 = normal"
    ]
  },
  {
    id: 400,
    source: "PowerShell",
    channel: "Windows PowerShell",
    description: "Engine state is changed from None to Available. Indicates a PowerShell session started.",
    significance: "medium",
    mitreTechniques: ["T1059.001 - PowerShell"],
    splunkQuery: 'index=wineventlog source="Windows PowerShell" EventCode=400 | table _time, HostName, HostApplication',
    elkQuery: '{"query":{"bool":{"must":[{"term":{"event.code":"400"}},{"term":{"winlog.channel":"Windows PowerShell"}}]}}}',
    falsePositives: "Normal PowerShell usage, scheduled scripts, DSC, SCCM scripts",
    investigationSteps: [
      "Check HostApplication for the command line that started PowerShell",
      "Look for PowerShell started with encoded commands (-enc) or unusual flags",
      "Monitor HostName for non-standard hosts (not ConsoleHost or ISE): ServerRemoteHost = remoting, Default Host = COM/WMI",
      "Correlate with parent process via 4688/Sysmon Event 1"
    ]
  },
  {
    id: 403,
    source: "PowerShell",
    channel: "Windows PowerShell",
    description: "Engine state is changed from Available to Stopped. Indicates a PowerShell session ended.",
    significance: "low",
    mitreTechniques: [],
    splunkQuery: 'index=wineventlog source="Windows PowerShell" EventCode=403 | table _time, HostName, HostApplication',
    elkQuery: '{"query":{"bool":{"must":[{"term":{"event.code":"403"}},{"term":{"winlog.channel":"Windows PowerShell"}}]}}}',
    falsePositives: "Normal PowerShell session termination",
    investigationSteps: [
      "Calculate session duration by correlating with Event 400",
      "Very short sessions may indicate automated malware using PowerShell"
    ]
  },
  {
    id: 800,
    source: "PowerShell",
    channel: "Windows PowerShell",
    description: "Pipeline execution details. Captures the commands executed in the PowerShell pipeline.",
    significance: "medium",
    mitreTechniques: ["T1059.001 - PowerShell"],
    splunkQuery: 'index=wineventlog source="Windows PowerShell" EventCode=800 | table _time, UserId, HostApplication, Pipeline',
    elkQuery: '{"query":{"bool":{"must":[{"term":{"event.code":"800"}},{"term":{"winlog.channel":"Windows PowerShell"}}]}}}',
    falsePositives: "Normal PowerShell command execution",
    investigationSteps: [
      "Check Pipeline details for suspicious commands",
      "Useful as a backup when Script Block Logging (4104) is not enabled",
      "Less detail than 4104 but captures command-level execution"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // WINDOWS DEFENDER / ANTIMALWARE (1006, 1007, 1008, 1116, 1117, 5001)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 1006,
    source: "Microsoft-Windows-Windows Defender",
    channel: "Microsoft-Windows-Windows Defender/Operational",
    description: "The antimalware engine found malware or other potentially unwanted software.",
    significance: "critical",
    mitreTechniques: ["T1204 - User Execution", "T1059 - Command and Scripting Interpreter"],
    splunkQuery: 'index=wineventlog source="Microsoft-Windows-Windows Defender/Operational" EventCode=1006 | table _time, Threat_Name, Path, Severity_Name, Action_Name',
    elkQuery: '{"query":{"term":{"event.code":"1006"}}}',
    falsePositives: "False positive detections on legitimate tools (PsExec, Mimikatz for authorized testing)",
    investigationSteps: [
      "Check Threat_Name for the malware family identified",
      "Review Path to determine what file was flagged",
      "Check Severity_Name: Severe, High, Medium, Low",
      "Verify Action_Name: Quarantine, Remove, Allow, NoAction",
      "If detection is on a known pentesting tool, verify it's authorized",
      "Check if the threat was successfully remediated (Event 1007)"
    ]
  },
  {
    id: 1007,
    source: "Microsoft-Windows-Windows Defender",
    channel: "Microsoft-Windows-Windows Defender/Operational",
    description: "The antimalware platform performed an action to protect your system from malware.",
    significance: "high",
    mitreTechniques: [],
    splunkQuery: 'index=wineventlog source="Microsoft-Windows-Windows Defender/Operational" EventCode=1007 | table _time, Threat_Name, Action_Name, Action_Status',
    elkQuery: '{"query":{"term":{"event.code":"1007"}}}',
    falsePositives: "Successful remediation of false positives",
    investigationSteps: [
      "Verify the threat was successfully quarantined or removed",
      "Check Action_Status for success/failure",
      "If action failed, manual remediation is needed"
    ]
  },
  {
    id: 1008,
    source: "Microsoft-Windows-Windows Defender",
    channel: "Microsoft-Windows-Windows Defender/Operational",
    description: "The antimalware platform attempted to perform an action but failed.",
    significance: "critical",
    mitreTechniques: ["T1562.001 - Disable or Modify Tools"],
    splunkQuery: 'index=wineventlog source="Microsoft-Windows-Windows Defender/Operational" EventCode=1008 | table _time, Threat_Name, Action_Name, Error_Code',
    elkQuery: '{"query":{"term":{"event.code":"1008"}}}',
    falsePositives: "File locked by another process, insufficient permissions on quarantine folder",
    investigationSteps: [
      "HIGH PRIORITY — malware detected but NOT remediated",
      "Check Error_Code for why remediation failed",
      "Manual intervention required — collect the file for analysis",
      "Check if the malware is actively running or has persisted"
    ]
  },
  {
    id: 1116,
    source: "Microsoft-Windows-Windows Defender",
    channel: "Microsoft-Windows-Windows Defender/Operational",
    description: "Windows Defender detected malware or potentially unwanted software (modern equivalent of 1006).",
    significance: "critical",
    mitreTechniques: ["T1204 - User Execution"],
    splunkQuery: 'index=wineventlog source="Microsoft-Windows-Windows Defender/Operational" EventCode=1116 | table _time, Threat_Name, Path, Severity_ID',
    elkQuery: '{"query":{"term":{"event.code":"1116"}}}',
    falsePositives: "PUA detections on bundleware, potentially unwanted browser extensions",
    investigationSteps: [
      "Check Threat_Name and Category_Name",
      "Review the detection path",
      "Severity_ID: 1=Low, 2=Medium, 4=High, 5=Severe",
      "Correlate with 1117 for action taken"
    ]
  },
  {
    id: 1117,
    source: "Microsoft-Windows-Windows Defender",
    channel: "Microsoft-Windows-Windows Defender/Operational",
    description: "Windows Defender took action against malware or potentially unwanted software.",
    significance: "high",
    mitreTechniques: [],
    splunkQuery: 'index=wineventlog source="Microsoft-Windows-Windows Defender/Operational" EventCode=1117 | table _time, Threat_Name, Action_ID, Action_Name',
    elkQuery: '{"query":{"term":{"event.code":"1117"}}}',
    falsePositives: "Quarantine of false positives",
    investigationSteps: [
      "Verify remediation was successful",
      "Action_ID: 1=Clean, 2=Quarantine, 3=Remove, 6=Allow, 8=NoAction, 9=Block",
      "If action was Allow or NoAction, check if an exclusion was recently added"
    ]
  },
  {
    id: 5001,
    source: "Microsoft-Windows-Windows Defender",
    channel: "Microsoft-Windows-Windows Defender/Operational",
    description: "Real-time protection is disabled. Extremely suspicious if not during authorized maintenance.",
    significance: "critical",
    mitreTechniques: ["T1562.001 - Disable or Modify Tools"],
    splunkQuery: 'index=wineventlog source="Microsoft-Windows-Windows Defender/Operational" EventCode=5001 | table _time, Computer',
    elkQuery: '{"query":{"term":{"event.code":"5001"}}}',
    falsePositives: "Authorized security testing, installing software that conflicts with real-time protection",
    investigationSteps: [
      "IMMEDIATE ALERT — real-time protection disabled is a top indicator of attack in progress",
      "Check who/what disabled it — correlate with recent logons and process execution",
      "Look for Set-MpPreference -DisableRealtimeMonitoring $true in PowerShell logs",
      "Check for registry modification of DisableAntiSpyware in Sysmon Event 13",
      "Often done immediately before deploying malware"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // WINDOWS FIREWALL (2003, 2004, 2005, 2006)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 2003,
    source: "Microsoft-Windows-Windows Firewall With Advanced Security",
    channel: "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
    description: "A Windows Defender Firewall setting has changed. Detects when firewall profiles are modified.",
    significance: "high",
    mitreTechniques: ["T1562.004 - Disable or Modify System Firewall"],
    splunkQuery: 'index=wineventlog EventCode=2003 | table _time, Profile, Setting_Type, Setting_Value',
    elkQuery: '{"query":{"term":{"event.code":"2003"}}}',
    falsePositives: "Authorized network configuration changes, VPN software adjusting firewall settings",
    investigationSteps: [
      "Check if a firewall profile was set to OFF",
      "Look for changes to DefaultInboundAction or DefaultOutboundAction",
      "Verify the change was authorized"
    ]
  },
  {
    id: 2004,
    source: "Microsoft-Windows-Windows Firewall With Advanced Security",
    channel: "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
    description: "A rule has been added to the Windows Defender Firewall exception list.",
    significance: "high",
    mitreTechniques: ["T1562.004 - Disable or Modify System Firewall"],
    splunkQuery: 'index=wineventlog EventCode=2004 | table _time, Rule_Name, Application_Path, Direction, Action, Protocol, Local_Port, Remote_Port',
    elkQuery: '{"query":{"term":{"event.code":"2004"}}}',
    falsePositives: "Software installations adding firewall rules, legitimate service configuration",
    investigationSteps: [
      "Check Application_Path for unusual or suspicious binaries",
      "Alert on rules allowing inbound connections (potential backdoor)",
      "Look for rules with broad scope (Any address, Any port)",
      "Correlate with process creation events around the same time"
    ]
  },
  {
    id: 2005,
    source: "Microsoft-Windows-Windows Firewall With Advanced Security",
    channel: "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
    description: "A rule has been modified in the Windows Defender Firewall exception list.",
    significance: "medium",
    mitreTechniques: ["T1562.004 - Disable or Modify System Firewall"],
    splunkQuery: 'index=wineventlog EventCode=2005 | table _time, Rule_Name, Application_Path, Direction, Action',
    elkQuery: '{"query":{"term":{"event.code":"2005"}}}',
    falsePositives: "Authorized rule modifications during maintenance",
    investigationSteps: [
      "Check if existing rules were modified to be more permissive",
      "Compare old and new rule parameters"
    ]
  },
  {
    id: 2006,
    source: "Microsoft-Windows-Windows Firewall With Advanced Security",
    channel: "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
    description: "A rule has been deleted from the Windows Defender Firewall exception list.",
    significance: "medium",
    mitreTechniques: ["T1562.004 - Disable or Modify System Firewall"],
    splunkQuery: 'index=wineventlog EventCode=2006 | table _time, Rule_Name',
    elkQuery: '{"query":{"term":{"event.code":"2006"}}}',
    falsePositives: "Software uninstallation removing rules, cleanup during hardening",
    investigationSteps: [
      "Check if protective rules were deleted",
      "Verify the deletion was authorized"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // REMOTE DESKTOP (21, 24, 25, 39, 40, 1149)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 21,
    source: "Microsoft-Windows-TerminalServices-LocalSessionManager",
    channel: "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    description: "Remote Desktop Services: Session logon succeeded.",
    significance: "high",
    mitreTechniques: ["T1021.001 - Remote Desktop Protocol"],
    splunkQuery: 'index=wineventlog source="Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" EventCode=21 | table _time, User, Source_Network_Address, Session_ID',
    elkQuery: '{"query":{"bool":{"must":[{"term":{"event.code":"21"}},{"term":{"winlog.channel":"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"}}]}}}',
    falsePositives: "Authorized RDP sessions by admins, help desk remote support",
    investigationSteps: [
      "Check Source_Network_Address for unexpected IPs or external connections",
      "Verify the user is authorized for RDP access",
      "Check for RDP connections outside business hours",
      "Correlate with 4624 Logon Type 10 for authentication details"
    ]
  },
  {
    id: 1149,
    source: "Microsoft-Windows-TerminalServices-RemoteConnectionManager",
    channel: "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
    description: "Remote Desktop Services: User authentication succeeded (network level authentication).",
    significance: "high",
    mitreTechniques: ["T1021.001 - Remote Desktop Protocol"],
    splunkQuery: 'index=wineventlog source="Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" EventCode=1149 | table _time, User, Source_Network_Address',
    elkQuery: '{"query":{"bool":{"must":[{"term":{"event.code":"1149"}}]}}}',
    falsePositives: "Normal RDP sessions, NLA authentication from authorized systems",
    investigationSteps: [
      "This event fires at NLA (before desktop access is granted)",
      "Check Source_Network_Address against allowed RDP sources",
      "Alert on external IP addresses attempting RDP",
      "Correlate with Session logon Event 21 and Security logon Event 4624"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // BITS CLIENT (59, 60, 61)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 59,
    source: "Microsoft-Windows-Bits-Client",
    channel: "Microsoft-Windows-Bits-Client/Operational",
    description: "BITS started a transfer job. BITS is commonly abused for downloading malware.",
    significance: "high",
    mitreTechniques: ["T1197 - BITS Jobs", "T1105 - Ingress Tool Transfer"],
    splunkQuery: 'index=wineventlog source="Microsoft-Windows-Bits-Client/Operational" EventCode=59 | table _time, jobTitle, url, User',
    elkQuery: '{"query":{"term":{"event.code":"59"}}}',
    falsePositives: "Windows Update, Microsoft Store updates, SCCM software distribution",
    investigationSteps: [
      "Check the URL being downloaded — look for suspicious domains or direct IP addresses",
      "BITS jobs persist across reboots and can be used for persistent downloads",
      "Check for BITS jobs created by unusual processes",
      "bitsadmin /list /allusers to enumerate current jobs"
    ]
  },
  {
    id: 60,
    source: "Microsoft-Windows-Bits-Client",
    channel: "Microsoft-Windows-Bits-Client/Operational",
    description: "BITS transfer job completed.",
    significance: "medium",
    mitreTechniques: ["T1197 - BITS Jobs"],
    splunkQuery: 'index=wineventlog source="Microsoft-Windows-Bits-Client/Operational" EventCode=60 | table _time, jobTitle, url, fileTime, fileLength',
    elkQuery: '{"query":{"term":{"event.code":"60"}}}',
    falsePositives: "Completed Windows Update downloads",
    investigationSteps: [
      "Check what file was downloaded and its size",
      "Verify the download was expected",
      "Check if the downloaded file was subsequently executed"
    ]
  },
  {
    id: 61,
    source: "Microsoft-Windows-Bits-Client",
    channel: "Microsoft-Windows-Bits-Client/Operational",
    description: "BITS transfer job failed or was cancelled.",
    significance: "low",
    mitreTechniques: ["T1197 - BITS Jobs"],
    splunkQuery: 'index=wineventlog source="Microsoft-Windows-Bits-Client/Operational" EventCode=61 | table _time, jobTitle, url, ErrorCode',
    elkQuery: '{"query":{"term":{"event.code":"61"}}}',
    falsePositives: "Network issues causing download failures, cancelled updates",
    investigationSteps: [
      "Check the URL that failed — it may reveal attempted malware downloads that were blocked",
      "Multiple failures may indicate C2 infrastructure that's been taken down"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // TASK SCHEDULER (106, 129, 140, 141, 200, 201)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 106,
    source: "Microsoft-Windows-TaskScheduler",
    channel: "Microsoft-Windows-TaskScheduler/Operational",
    description: "Task registered (created). Alternative to Security Event 4698 for environments without Security auditing.",
    significance: "high",
    mitreTechniques: ["T1053.005 - Scheduled Task"],
    splunkQuery: 'index=wineventlog source="Microsoft-Windows-TaskScheduler/Operational" EventCode=106 | table _time, TaskName, UserContext',
    elkQuery: '{"query":{"term":{"event.code":"106"}}}',
    falsePositives: "Software installations creating tasks, GPO applying scheduled tasks",
    investigationSteps: [
      "Check TaskName for suspicious or randomized names",
      "Correlate with Security Event 4698 for the task content",
      "Check UserContext for the account the task runs under"
    ]
  },
  {
    id: 129,
    source: "Microsoft-Windows-TaskScheduler",
    channel: "Microsoft-Windows-TaskScheduler/Operational",
    description: "Task Scheduler launched a task.",
    significance: "medium",
    mitreTechniques: ["T1053.005 - Scheduled Task"],
    splunkQuery: 'index=wineventlog source="Microsoft-Windows-TaskScheduler/Operational" EventCode=129 | table _time, TaskName, EnginePID',
    elkQuery: '{"query":{"term":{"event.code":"129"}}}',
    falsePositives: "Normal scheduled task execution",
    investigationSteps: [
      "Check which tasks are running and when",
      "Correlate EnginePID with process creation events"
    ]
  },
  {
    id: 140,
    source: "Microsoft-Windows-TaskScheduler",
    channel: "Microsoft-Windows-TaskScheduler/Operational",
    description: "Task Scheduler updated a task.",
    significance: "medium",
    mitreTechniques: ["T1053.005 - Scheduled Task"],
    splunkQuery: 'index=wineventlog source="Microsoft-Windows-TaskScheduler/Operational" EventCode=140 | table _time, TaskName, UserName',
    elkQuery: '{"query":{"term":{"event.code":"140"}}}',
    falsePositives: "GPO refreshing task definitions, authorized task modifications",
    investigationSteps: [
      "Check if the task action was modified (command hijacking)",
      "Compare with the original task registration (Event 106)"
    ]
  },
  {
    id: 141,
    source: "Microsoft-Windows-TaskScheduler",
    channel: "Microsoft-Windows-TaskScheduler/Operational",
    description: "Task Scheduler deleted a task.",
    significance: "medium",
    mitreTechniques: ["T1070 - Indicator Removal on Host"],
    splunkQuery: 'index=wineventlog source="Microsoft-Windows-TaskScheduler/Operational" EventCode=141 | table _time, TaskName, UserName',
    elkQuery: '{"query":{"term":{"event.code":"141"}}}',
    falsePositives: "Cleanup of completed one-time tasks, software uninstallation",
    investigationSteps: [
      "Check if a recently created task was quickly deleted (one-shot persistence)",
      "Correlate with Event 106 for the original task content"
    ]
  },
  {
    id: 200,
    source: "Microsoft-Windows-TaskScheduler",
    channel: "Microsoft-Windows-TaskScheduler/Operational",
    description: "Task Scheduler launched an action in a task.",
    significance: "medium",
    mitreTechniques: ["T1053.005 - Scheduled Task"],
    splunkQuery: 'index=wineventlog source="Microsoft-Windows-TaskScheduler/Operational" EventCode=200 | table _time, TaskName, ActionName',
    elkQuery: '{"query":{"term":{"event.code":"200"}}}',
    falsePositives: "Normal scheduled task execution",
    investigationSteps: [
      "Check ActionName for the command being executed",
      "Correlate with process creation events for detailed command line"
    ]
  },
  {
    id: 201,
    source: "Microsoft-Windows-TaskScheduler",
    channel: "Microsoft-Windows-TaskScheduler/Operational",
    description: "Task Scheduler completed a task action.",
    significance: "low",
    mitreTechniques: ["T1053.005 - Scheduled Task"],
    splunkQuery: 'index=wineventlog source="Microsoft-Windows-TaskScheduler/Operational" EventCode=201 | table _time, TaskName, ActionName, ResultCode',
    elkQuery: '{"query":{"term":{"event.code":"201"}}}',
    falsePositives: "Normal task completion",
    investigationSteps: [
      "Check ResultCode for the exit status",
      "Calculate task duration by correlating with Event 200"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // APPLOCKER (8003, 8004, 8006, 8007)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 8003,
    source: "Microsoft-Windows-AppLocker",
    channel: "Microsoft-Windows-AppLocker/EXE and DLL",
    description: "AppLocker allowed an .exe or .dll file to run.",
    significance: "low",
    mitreTechniques: [],
    splunkQuery: 'index=wineventlog source="Microsoft-Windows-AppLocker/EXE and DLL" EventCode=8003 | stats count by PolicyName, FilePath',
    elkQuery: '{"query":{"term":{"event.code":"8003"}}}',
    falsePositives: "Normal application execution within AppLocker policy",
    investigationSteps: [
      "Use for baselining allowed applications",
      "Check for unusual file paths being allowed"
    ]
  },
  {
    id: 8004,
    source: "Microsoft-Windows-AppLocker",
    channel: "Microsoft-Windows-AppLocker/EXE and DLL",
    description: "AppLocker blocked an .exe or .dll file from running.",
    significance: "high",
    mitreTechniques: ["T1204 - User Execution", "T1059 - Command and Scripting Interpreter"],
    splunkQuery: 'index=wineventlog source="Microsoft-Windows-AppLocker/EXE and DLL" EventCode=8004 | stats count by FilePath, User | sort -count',
    elkQuery: '{"query":{"term":{"event.code":"8004"}}}',
    falsePositives: "Users attempting to run unauthorized but legitimate software",
    investigationSteps: [
      "Check FilePath for known malware or pentest tools",
      "Multiple blocks from the same user may indicate compromise attempt",
      "Verify if the block was for a legitimate application needing a policy exception"
    ]
  },
  {
    id: 8006,
    source: "Microsoft-Windows-AppLocker",
    channel: "Microsoft-Windows-AppLocker/MSI and Script",
    description: "AppLocker allowed a script or MSI to run.",
    significance: "low",
    mitreTechniques: [],
    splunkQuery: 'index=wineventlog source="Microsoft-Windows-AppLocker/MSI and Script" EventCode=8006 | stats count by FilePath',
    elkQuery: '{"query":{"term":{"event.code":"8006"}}}',
    falsePositives: "Normal script execution within policy",
    investigationSteps: [
      "Use for baselining allowed scripts"
    ]
  },
  {
    id: 8007,
    source: "Microsoft-Windows-AppLocker",
    channel: "Microsoft-Windows-AppLocker/MSI and Script",
    description: "AppLocker blocked a script or MSI from running.",
    significance: "high",
    mitreTechniques: ["T1059 - Command and Scripting Interpreter"],
    splunkQuery: 'index=wineventlog source="Microsoft-Windows-AppLocker/MSI and Script" EventCode=8007 | stats count by FilePath, User | sort -count',
    elkQuery: '{"query":{"term":{"event.code":"8007"}}}',
    falsePositives: "Users attempting to run unauthorized scripts",
    investigationSteps: [
      "Check FilePath for malicious scripts",
      "Alert on blocked .ps1, .vbs, .js, .wsf files",
      "Verify if the block was expected or indicates an attack attempt"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // CERTIFICATE SERVICES (4886, 4887, 4899)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 4886,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "Certificate Services received a certificate request.",
    significance: "medium",
    mitreTechniques: ["T1649 - Steal or Forge Authentication Certificates"],
    splunkQuery: 'index=wineventlog EventCode=4886 | table _time, Requester, Request_ID, Attributes',
    elkQuery: '{"query":{"term":{"event.code":"4886"}}}',
    falsePositives: "Normal certificate enrollment, auto-enrollment, MDM certificate requests",
    investigationSteps: [
      "Check Requester for the account requesting the certificate",
      "Look for unusual certificate templates being requested (ESC1-ESC8 attacks)",
      "Monitor for requests from non-standard accounts"
    ]
  },
  {
    id: 4887,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "Certificate Services approved a certificate request and issued a certificate.",
    significance: "high",
    mitreTechniques: ["T1649 - Steal or Forge Authentication Certificates"],
    splunkQuery: 'index=wineventlog EventCode=4887 | table _time, Requester, Request_ID, Certificate_Template',
    elkQuery: '{"query":{"term":{"event.code":"4887"}}}',
    falsePositives: "Normal certificate issuance through auto-enrollment",
    investigationSteps: [
      "Check Certificate_Template for templates that allow authentication (User, SmartcardLogon, Machine)",
      "Alert on certificates issued to unexpected users via privileged templates",
      "Check for ESC1: template allows requester to specify SAN (Subject Alternative Name)",
      "Monitor for high volume of certificate requests (mass enrollment attack)"
    ]
  },
  {
    id: 4899,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A Certificate Services template was updated.",
    significance: "critical",
    mitreTechniques: ["T1649 - Steal or Forge Authentication Certificates"],
    splunkQuery: 'index=wineventlog EventCode=4899 | table _time, Subject_User_Name, Template_Name, Template_Change',
    elkQuery: '{"query":{"term":{"event.code":"4899"}}}',
    falsePositives: "Authorized template modifications by PKI administrators",
    investigationSteps: [
      "ALERT on template modifications — ESC4 attack (modify template to allow privilege escalation)",
      "Check if enrollment permissions were changed to include broader groups",
      "Check if the CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag was enabled (allows SAN specification)",
      "Verify through change management"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // DIRECTORY SERVICE / ACTIVE DIRECTORY (4662, 4742, 5136, 5137, 5141)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 4662,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "An operation was performed on an object in Active Directory. Critical for detecting DCSync and AD replication attacks.",
    significance: "critical",
    mitreTechniques: ["T1003.006 - DCSync", "T1207 - Rogue Domain Controller"],
    splunkQuery: 'index=wineventlog EventCode=4662 Properties="*1131f6ad*" OR Properties="*1131f6aa*" OR Properties="*89e95b76*" | table _time, Subject_User_Name, Object_Name, Properties',
    elkQuery: '{"query":{"bool":{"must":[{"term":{"event.code":"4662"}}]}}}',
    falsePositives: "Legitimate domain controller replication, Azure AD Connect synchronization",
    investigationSteps: [
      "DCSync detection: Properties containing GUIDs 1131f6ad-* (DS-Replication-Get-Changes-All) or 1131f6aa-* (DS-Replication-Get-Changes)",
      "If the Subject is NOT a domain controller or Azure AD Connect service account, it's DCSync",
      "Check for Property GUID 89e95b76-* (DS-Replication-Get-Changes-In-Filtered-Set)",
      "Correlate with network traffic to the DC (DCE/RPC replication traffic from non-DC)",
      "IMMEDIATE incident response if DCSync from non-authorized account"
    ]
  },
  {
    id: 4742,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A computer account was changed.",
    significance: "high",
    mitreTechniques: ["T1098 - Account Manipulation", "T1207 - Rogue Domain Controller"],
    splunkQuery: 'index=wineventlog EventCode=4742 | table _time, Subject_User_Name, Target_User_Name, User_Account_Control | where User_Account_Control="*SERVER_TRUST*"',
    elkQuery: '{"query":{"term":{"event.code":"4742"}}}',
    falsePositives: "Normal computer account maintenance, SCCM managing computer objects",
    investigationSteps: [
      "Check for User_Account_Control changes to SERVER_TRUST_ACCOUNT (promoting to DC)",
      "Alert on msDS-AllowedToDelegateTo changes (resource-based constrained delegation attack)",
      "Monitor for SPN changes on computer accounts"
    ]
  },
  {
    id: 5136,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A directory service object was modified. The most detailed AD change event.",
    significance: "high",
    mitreTechniques: ["T1484 - Domain Policy Modification", "T1098 - Account Manipulation"],
    splunkQuery: 'index=wineventlog EventCode=5136 | table _time, Subject_User_Name, Object_DN, Attribute_Name, Attribute_Value | search Attribute_Name IN ("msDS-AllowedToDelegateTo","servicePrincipalName","userAccountControl","adminCount","member")',
    elkQuery: '{"query":{"term":{"event.code":"5136"}}}',
    falsePositives: "Normal AD administration, GPO updates, user profile changes",
    investigationSteps: [
      "Critical attributes to monitor: member (group changes), servicePrincipalName (kerberoasting setup), msDS-AllowedToDelegateTo (delegation), userAccountControl (account flags), adminCount, dNSHostName",
      "Check Object_DN for the modified object",
      "Verify the modification was authorized",
      "Alert on SPN additions to user accounts (targeted kerberoasting)"
    ]
  },
  {
    id: 5137,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A directory service object was created.",
    significance: "high",
    mitreTechniques: ["T1136.002 - Create Account: Domain Account"],
    splunkQuery: 'index=wineventlog EventCode=5137 | table _time, Subject_User_Name, Object_DN, Object_Class',
    elkQuery: '{"query":{"term":{"event.code":"5137"}}}',
    falsePositives: "Normal object creation during provisioning, GPO creation",
    investigationSteps: [
      "Check Object_Class: user, computer, group, organizationalUnit, groupPolicyContainer",
      "Alert on unexpected computer objects (rogue DC, machine account manipulation)",
      "Verify the creation was authorized"
    ]
  },
  {
    id: 5141,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A directory service object was deleted.",
    significance: "high",
    mitreTechniques: ["T1070 - Indicator Removal on Host"],
    splunkQuery: 'index=wineventlog EventCode=5141 | table _time, Subject_User_Name, Object_DN, Object_Class',
    elkQuery: '{"query":{"term":{"event.code":"5141"}}}',
    falsePositives: "Normal AD object lifecycle management, OU cleanup",
    investigationSteps: [
      "Check if GPOs, OUs, or security groups were deleted",
      "Alert on deletion of security-critical objects",
      "Check if deleted objects had RecycleBin enabled (can be recovered)"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // GROUP POLICY (4739, 5136 with GPO)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 4739,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "Domain Policy was changed. Records changes to the default domain policy settings.",
    significance: "critical",
    mitreTechniques: ["T1484.001 - Group Policy Modification"],
    splunkQuery: 'index=wineventlog EventCode=4739 | table _time, Subject_User_Name, Domain_Policy_Changed',
    elkQuery: '{"query":{"term":{"event.code":"4739"}}}',
    falsePositives: "Authorized domain policy changes, security hardening activities",
    investigationSteps: [
      "Check what policy was changed: password policy, lockout policy, Kerberos policy",
      "Weakening password complexity or lockout thresholds = possible attack setup",
      "Verify through change management process"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // DPAPI (4692, 4693, 4694, 4695)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 4692,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "Backup of data protection master key was attempted.",
    significance: "high",
    mitreTechniques: ["T1555.004 - Windows Credential Manager", "T1003.004 - LSA Secrets"],
    splunkQuery: 'index=wineventlog EventCode=4692 | table _time, Subject_User_Name, Master_Key_ID',
    elkQuery: '{"query":{"term":{"event.code":"4692"}}}',
    falsePositives: "Normal DPAPI key backup during user profile operations",
    investigationSteps: [
      "DPAPI master key backups happen during key rotation",
      "Check if key backup was triggered by an unexpected process",
      "An attacker with domain admin can extract DPAPI backup keys to decrypt any user's secrets"
    ]
  },
  {
    id: 4693,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "Recovery of data protection master key was attempted.",
    significance: "critical",
    mitreTechniques: ["T1555.004 - Windows Credential Manager", "T1003.004 - LSA Secrets"],
    splunkQuery: 'index=wineventlog EventCode=4693 | table _time, Subject_User_Name, Master_Key_ID, Recovery_Reason',
    elkQuery: '{"query":{"term":{"event.code":"4693"}}}',
    falsePositives: "Profile migration, password reset requiring DPAPI key recovery",
    investigationSteps: [
      "HIGH ALERT — DPAPI master key recovery can decrypt all user secrets (Chrome passwords, RDP passwords, etc.)",
      "Check who initiated the recovery and verify authorization",
      "Mimikatz dpapi::masterkey uses this technique",
      "Correlate with other credential access techniques in the same timeframe"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // CREDENTIAL VALIDATION (4774, 4775, 4776 already covered)
  // ═══════════════════════════════════════════════════════════════
  {
    id: 4774,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "An account was mapped for logon. Indicates certificate-to-account mapping was used.",
    significance: "medium",
    mitreTechniques: ["T1649 - Steal or Forge Authentication Certificates"],
    splunkQuery: 'index=wineventlog EventCode=4774 | table _time, Subject_User_Name, Mapping_Method',
    elkQuery: '{"query":{"term":{"event.code":"4774"}}}',
    falsePositives: "Smart card logons, certificate-based authentication",
    investigationSteps: [
      "Check if certificate-based authentication is expected for this account",
      "Verify the certificate used is from a trusted CA",
      "Alert on unexpected certificate mappings (forged certificates)"
    ]
  },
  {
    id: 4775,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "An account could not be mapped for logon. Certificate mapping failed.",
    significance: "medium",
    mitreTechniques: ["T1649 - Steal or Forge Authentication Certificates"],
    splunkQuery: 'index=wineventlog EventCode=4775 | table _time, Subject_User_Name, Error_Code',
    elkQuery: '{"query":{"term":{"event.code":"4775"}}}',
    falsePositives: "Expired certificates, revoked certificates, misconfigured mapping",
    investigationSteps: [
      "Failed certificate mapping may indicate forged or stolen certificate attempt",
      "Check error reason and certificate details"
    ]
  },
  // ═══════════════════════════════════════════════════════════════
  // ADDITIONAL CRITICAL EVENTS
  // ═══════════════════════════════════════════════════════════════
  {
    id: 4964,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "Special groups have been assigned to a new logon. For monitoring when custom special groups log on.",
    significance: "high",
    mitreTechniques: ["T1078 - Valid Accounts"],
    splunkQuery: 'index=wineventlog EventCode=4964 | table _time, Subject_User_Name, Special_Groups',
    elkQuery: '{"query":{"term":{"event.code":"4964"}}}',
    falsePositives: "Normal logon of accounts in configured special groups",
    investigationSteps: [
      "Special Groups are configured in the HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Audit\\SpecialGroups registry key",
      "Check which special group triggered the alert",
      "Verify the logon is from an expected user in that group"
    ]
  },
  {
    id: 4985,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "The state of a transaction has changed. Related to transactional NTFS operations.",
    significance: "medium",
    mitreTechniques: ["T1055.012 - Process Hollowing", "T1564.004 - NTFS File Attributes"],
    splunkQuery: 'index=wineventlog EventCode=4985 | table _time, Resource_Manager, Transaction_ID',
    elkQuery: '{"query":{"term":{"event.code":"4985"}}}',
    falsePositives: "Application use of transactional NTFS",
    investigationSteps: [
      "Transactional NTFS can be abused for process hollowing (process doppelganging)",
      "Check for unusual transactional file operations"
    ]
  },
  {
    id: 1100,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "The event logging service has shut down. May indicate a system shutdown or deliberate logging disruption.",
    significance: "high",
    mitreTechniques: ["T1562.002 - Disable Windows Event Logging"],
    splunkQuery: 'index=wineventlog EventCode=1100 | table _time, Computer',
    elkQuery: '{"query":{"term":{"event.code":"1100"}}}',
    falsePositives: "Normal system shutdown, restart, or maintenance",
    investigationSteps: [
      "Check if this correlates with a system shutdown/restart (Event 1074 in System log)",
      "If the system was not being shut down, the event log service was stopped — investigate immediately",
      "This is the last event written before logging stops — check the timeline up to this point"
    ]
  },
  {
    id: 4616,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "The system time was changed.",
    significance: "high",
    mitreTechniques: ["T1070.006 - Timestomp"],
    splunkQuery: 'index=wineventlog EventCode=4616 | table _time, Subject_User_Name, Previous_Time, New_Time | eval diff=abs(strptime(New_Time,"%Y-%m-%dT%H:%M:%S")-strptime(Previous_Time,"%Y-%m-%dT%H:%M:%S")) | where diff>300',
    elkQuery: '{"query":{"term":{"event.code":"4616"}}}',
    falsePositives: "NTP synchronization (usually small adjustments), time zone changes, daylight saving time",
    investigationSteps: [
      "Large time changes may indicate an attempt to manipulate log timestamps",
      "Check the magnitude of the change — NTP adjustments are typically seconds, not minutes",
      "Verify the change aligns with authorized maintenance",
      "Timestomping can be used to make malicious events appear to have occurred at a different time"
    ]
  },
  {
    id: 4657,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "A registry value was modified. Requires auditing to be configured on specific registry keys.",
    significance: "high",
    mitreTechniques: ["T1547.001 - Registry Run Keys / Startup Folder", "T1112 - Modify Registry"],
    splunkQuery: 'index=wineventlog EventCode=4657 | table _time, Subject_User_Name, Object_Name, Object_Value_Name, New_Value, Process_Name',
    elkQuery: '{"query":{"term":{"event.code":"4657"}}}',
    falsePositives: "Software installation, Group Policy application, Windows Update",
    investigationSteps: [
      "Check Object_Name for persistence locations (Run, RunOnce, Services, IFEO)",
      "Check Process_Name for what modified the registry",
      "Compare Old_Value and New_Value to understand the change",
      "Alert on modifications by unexpected processes"
    ]
  },
  {
    id: 4670,
    source: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    description: "Permissions on an object were changed.",
    significance: "high",
    mitreTechniques: ["T1222 - File and Directory Permissions Modification"],
    splunkQuery: 'index=wineventlog EventCode=4670 | table _time, Subject_User_Name, Object_Name, Process_Name | search Object_Name="*\\System32\\*" OR Object_Name="*\\SysWOW64\\*"',
    elkQuery: '{"query":{"term":{"event.code":"4670"}}}',
    falsePositives: "Software installation, access control management, security hardening",
    investigationSteps: [
      "Check Object_Name for critical system files or directories",
      "Compare Old_SDDL and New_SDDL to identify what changed",
      "Alert on weakening of permissions on system binaries or security tools"
    ]
  }
];
