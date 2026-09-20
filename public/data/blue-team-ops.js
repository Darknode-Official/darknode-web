/* ==========================================================================
   Blue Team Operations Reference Data
   Comprehensive security monitoring, detection, and hardening reference
   ========================================================================== */

/* --------------------------------------------------------------------------
   1. WINDOWS EVENT IDS
   100+ security-relevant Windows Event IDs for detection and forensics
   -------------------------------------------------------------------------- */

const WINDOWS_EVENT_IDS = [
  {
    eventId: 1,
    channel: "Microsoft-Windows-Sysmon/Operational",
    provider: "Microsoft-Windows-Sysmon",
    description: "Process creation. Logs detailed information about newly created processes including full command line, hashes, parent process, and user context.",
    forensicSignificance: "Foundational telemetry for tracking process execution chains, identifying malicious binaries, and reconstructing attack timelines. The command line field is critical for detecting encoded PowerShell, LOLBin abuse, and living-off-the-land techniques.",
    detectionUse: "Detect suspicious process trees, unusual parent-child relationships (e.g., Word spawning cmd.exe), and known-bad command line patterns.",
    severity: "high"
  },
  {
    eventId: 2,
    channel: "Microsoft-Windows-Sysmon/Operational",
    provider: "Microsoft-Windows-Sysmon",
    description: "File creation time changed. Logs when a process modifies the creation timestamp of a file, a technique known as timestomping.",
    forensicSignificance: "Timestomping is a common anti-forensics technique used to blend malicious files with legitimate system files. Detection of this event directly indicates an attempt to tamper with forensic evidence.",
    detectionUse: "Detect timestomping attempts where attackers modify file creation times to evade timeline analysis and blend malware with legitimate files.",
    severity: "high"
  },
  {
    eventId: 3,
    channel: "Microsoft-Windows-Sysmon/Operational",
    provider: "Microsoft-Windows-Sysmon",
    description: "Network connection detected. Logs TCP/UDP connections made by processes, including source and destination IP addresses, ports, and the initiating process.",
    forensicSignificance: "Essential for identifying command-and-control communications, data exfiltration channels, and lateral movement. Correlating network connections with process creation events builds a complete picture of malicious activity.",
    detectionUse: "Detect processes making unexpected outbound connections, beaconing behavior, connections to known-bad IPs, and unusual port usage.",
    severity: "medium"
  },
  {
    eventId: 5,
    channel: "Microsoft-Windows-Sysmon/Operational",
    provider: "Microsoft-Windows-Sysmon",
    description: "Process terminated. Logs when a process ends, providing the process GUID and ID for correlation with the original creation event.",
    forensicSignificance: "Useful for determining process lifetimes and identifying short-lived processes that may indicate malicious tool execution followed by cleanup.",
    detectionUse: "Correlate with process creation events to identify unusually short-lived processes typical of staging tools, or detect when security tools are terminated.",
    severity: "low"
  },
  {
    eventId: 6,
    channel: "Microsoft-Windows-Sysmon/Operational",
    provider: "Microsoft-Windows-Sysmon",
    description: "Driver loaded. Logs when a driver is loaded into the kernel, including the driver file hash and signature status.",
    forensicSignificance: "Kernel drivers have unrestricted access to the system. Malicious drivers can rootkit the system, disable security tools, or enable persistent access. Unsigned or newly seen drivers are high-priority investigation targets.",
    detectionUse: "Detect loading of unsigned drivers, known-vulnerable drivers (BYOVD attacks), and rootkit installation attempts.",
    severity: "high"
  },
  {
    eventId: 7,
    channel: "Microsoft-Windows-Sysmon/Operational",
    provider: "Microsoft-Windows-Sysmon",
    description: "Image loaded. Logs when a module (DLL) is loaded into a process, including the image hash and signature information.",
    forensicSignificance: "DLL side-loading and DLL injection are common attack techniques. Tracking loaded images helps identify when legitimate processes load malicious libraries.",
    detectionUse: "Detect DLL side-loading, DLL injection, and unsigned modules loaded by trusted processes. Identify reflective DLL loading and CLR-based attacks.",
    severity: "medium"
  },
  {
    eventId: 8,
    channel: "Microsoft-Windows-Sysmon/Operational",
    provider: "Microsoft-Windows-Sysmon",
    description: "CreateRemoteThread detected. Logs when a process creates a thread in another process, a technique commonly used for process injection.",
    forensicSignificance: "CreateRemoteThread is a primary mechanism for process injection, allowing attackers to execute code within legitimate processes to evade detection. This is a high-fidelity indicator of compromise.",
    detectionUse: "Detect process injection attacks including classic DLL injection, shellcode injection, and process hollowing preparation steps.",
    severity: "critical"
  },
  {
    eventId: 10,
    channel: "Microsoft-Windows-Sysmon/Operational",
    provider: "Microsoft-Windows-Sysmon",
    description: "Process access. Logs when a process opens another process, capturing the access rights requested. Essential for detecting credential dumping and process injection.",
    forensicSignificance: "Opening lsass.exe with specific access rights is a hallmark of credential dumping tools like Mimikatz. Cross-process access patterns reveal injection and manipulation attempts.",
    detectionUse: "Detect credential dumping by monitoring access to lsass.exe, identify process injection preparation, and flag suspicious cross-process access patterns.",
    severity: "critical"
  },
  {
    eventId: 11,
    channel: "Microsoft-Windows-Sysmon/Operational",
    provider: "Microsoft-Windows-Sysmon",
    description: "File created. Logs file creation events including the creating process and the target filename with full path.",
    forensicSignificance: "Tracks malware dropping payloads to disk, creation of persistence mechanisms (scheduled tasks, startup items), and staging of tools for lateral movement.",
    detectionUse: "Detect payload drops in suspicious locations (temp directories, startup folders), creation of webshells, and writing of scripts to system directories.",
    severity: "medium"
  },
  {
    eventId: 12,
    channel: "Microsoft-Windows-Sysmon/Operational",
    provider: "Microsoft-Windows-Sysmon",
    description: "Registry object added or deleted. Logs creation and deletion of registry keys and values, identifying the process responsible.",
    forensicSignificance: "Registry modifications are central to many persistence mechanisms, configuration changes, and defense evasion techniques. Tracking these changes is critical for identifying unauthorized system modifications.",
    detectionUse: "Detect persistence via Run/RunOnce keys, service creation, COM object hijacking, and registry-based configuration changes that weaken security.",
    severity: "high"
  },
  {
    eventId: 13,
    channel: "Microsoft-Windows-Sysmon/Operational",
    provider: "Microsoft-Windows-Sysmon",
    description: "Registry value set. Logs when a registry value is modified, capturing the process, target registry path, and the new value details.",
    forensicSignificance: "Complements Event ID 12 by capturing the actual values written to the registry. Critical for understanding what persistence mechanisms or configuration changes were made.",
    detectionUse: "Detect modification of security-relevant registry values including AMSI bypass, UAC bypass, and credential caching configuration changes.",
    severity: "high"
  },
  {
    eventId: 15,
    channel: "Microsoft-Windows-Sysmon/Operational",
    provider: "Microsoft-Windows-Sysmon",
    description: "FileCreateStreamHash. Logs when a named file stream (ADS - Alternate Data Stream) is created, and logs the hash of the contents.",
    forensicSignificance: "Alternate Data Streams can hide malicious content within legitimate files. This event detects both ADS creation and the Mark-of-the-Web (Zone.Identifier) stream, which indicates file origin.",
    detectionUse: "Detect hiding of payloads in Alternate Data Streams and monitor Zone.Identifier streams to track downloaded file origins.",
    severity: "medium"
  },
  {
    eventId: 17,
    channel: "Microsoft-Windows-Sysmon/Operational",
    provider: "Microsoft-Windows-Sysmon",
    description: "Pipe created. Logs when a named pipe is created, identifying the creating process. Named pipes are used for inter-process communication.",
    forensicSignificance: "Many attack frameworks like Cobalt Strike, Metasploit, and PsExec use named pipes for communication. Known pipe name patterns can directly identify specific tools.",
    detectionUse: "Detect C2 frameworks by their characteristic pipe names (e.g., Cobalt Strike default pipes), PsExec lateral movement, and custom malware communication channels.",
    severity: "high"
  },
  {
    eventId: 18,
    channel: "Microsoft-Windows-Sysmon/Operational",
    provider: "Microsoft-Windows-Sysmon",
    description: "Pipe connected. Logs when a named pipe connection is made, identifying the connecting process and the pipe name.",
    forensicSignificance: "Complements pipe creation events to show the full communication chain. Useful for identifying which processes are communicating via named pipes.",
    detectionUse: "Detect lateral movement tools connecting to remote pipes, and identify processes communicating with known malicious pipe names.",
    severity: "medium"
  },
  {
    eventId: 22,
    channel: "Microsoft-Windows-Sysmon/Operational",
    provider: "Microsoft-Windows-Sysmon",
    description: "DNS query. Logs DNS queries made by processes, including the queried domain name and the query results.",
    forensicSignificance: "DNS queries reveal C2 domain lookups, DNS tunneling, and domain generation algorithm (DGA) activity. Process-to-DNS correlation is invaluable for attribution.",
    detectionUse: "Detect DNS tunneling via unusually long subdomain queries, DGA domains, lookups to known-bad domains, and DNS-based data exfiltration.",
    severity: "medium"
  },
  {
    eventId: 23,
    channel: "Microsoft-Windows-Sysmon/Operational",
    provider: "Microsoft-Windows-Sysmon",
    description: "File delete archived. Logs file deletion events and optionally archives the deleted file for forensic recovery.",
    forensicSignificance: "Captures anti-forensics activity where attackers delete their tools after use. The archive capability allows recovery of deleted malicious files for analysis.",
    detectionUse: "Detect cleanup activity by attackers removing their tools, scripts, or staging files. Recover deleted files for malware analysis.",
    severity: "medium"
  },
  {
    eventId: 25,
    channel: "Microsoft-Windows-Sysmon/Operational",
    provider: "Microsoft-Windows-Sysmon",
    description: "Process tampering. Detects process image tampering techniques such as process hollowing and process herpaderping.",
    forensicSignificance: "Process tampering techniques allow attackers to execute malicious code under the guise of legitimate processes. This is a high-confidence indicator of sophisticated attacks.",
    detectionUse: "Detect process hollowing, process doppelganging, process herpaderping, and other advanced process manipulation techniques used to evade security controls.",
    severity: "critical"
  },
  {
    eventId: 1100,
    channel: "Security",
    provider: "Microsoft-Windows-EventLog",
    description: "The event logging service has shut down. Indicates the Windows Event Log service was stopped.",
    forensicSignificance: "An unexpected shutdown of the event logging service could indicate an attacker attempting to prevent their activities from being logged. This should always be investigated unless during planned maintenance.",
    detectionUse: "Alert on unexpected event log service shutdowns that may indicate an attacker is attempting to blind security monitoring.",
    severity: "critical"
  },
  {
    eventId: 1102,
    channel: "Security",
    provider: "Microsoft-Windows-Eventlog",
    description: "The audit log was cleared. Records when a user clears the Security event log, capturing the account that performed the action.",
    forensicSignificance: "Clearing the security log is a strong indicator of an attacker covering their tracks. This event itself survives the clear operation and provides attribution to the responsible account.",
    detectionUse: "Immediately alert on security log clearing events. Cross-reference with the account performing the action and investigate all recent activity from that account.",
    severity: "critical"
  },
  {
    eventId: 4103,
    channel: "Microsoft-Windows-PowerShell/Operational",
    provider: "Microsoft-Windows-PowerShell",
    description: "PowerShell module logging. Records detailed information about PowerShell pipeline execution including cmdlet and function invocations with parameters.",
    forensicSignificance: "Module logging captures the actual PowerShell commands executed, providing visibility into attacker activity even when scripts are obfuscated at the source level.",
    detectionUse: "Detect malicious PowerShell usage including reconnaissance commands, credential access, download cradles, and lateral movement commands.",
    severity: "high"
  },
  {
    eventId: 4104,
    channel: "Microsoft-Windows-PowerShell/Operational",
    provider: "Microsoft-Windows-PowerShell",
    description: "PowerShell script block logging. Records the full content of PowerShell script blocks as they are executed, including deobfuscated content.",
    forensicSignificance: "Script block logging captures PowerShell code after deobfuscation, revealing the true intent of encoded or obfuscated commands. This is one of the most valuable telemetry sources for detecting PowerShell-based attacks.",
    detectionUse: "Detect obfuscated PowerShell attacks, AMSI bypasses, credential dumping scripts, download cradles, and encoded command execution.",
    severity: "high"
  },
  {
    eventId: 4616,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "The system time was changed. Records when the system clock is modified, capturing the old and new times and the responsible account.",
    forensicSignificance: "System time changes can be used to manipulate log timestamps, evade time-based security controls, or interfere with Kerberos authentication (which is time-sensitive).",
    detectionUse: "Detect potential timestomping at the system level, Kerberos attacks requiring time manipulation, and forensic timeline corruption attempts.",
    severity: "high"
  },
  {
    eventId: 4624,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "An account was successfully logged on. Records successful authentication events including the logon type, source network address, and authentication package used.",
    forensicSignificance: "The most fundamental authentication event. Logon Type field distinguishes between interactive (2), network (3), batch (4), service (5), unlock (7), network cleartext (8), new credentials (9), remote interactive (10), and cached interactive (11) logons.",
    detectionUse: "Detect unauthorized access, lateral movement (Type 3 logons from unexpected sources), remote desktop sessions (Type 10), and service account abuse.",
    severity: "medium"
  },
  {
    eventId: 4625,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "An account failed to log on. Records failed authentication attempts including the failure reason, source IP, and target account name.",
    forensicSignificance: "Failed logon events are primary indicators of brute force attacks, password spraying, and credential stuffing. The failure sub-status code provides specific reasons for the failure.",
    detectionUse: "Detect brute force attacks (high volume from single source), password spray attacks (single attempt against many accounts), and credential stuffing from known-breached credentials.",
    severity: "high"
  },
  {
    eventId: 4634,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "An account was logged off. Records when a logon session ends, providing the logon ID for correlation with the original 4624 event.",
    forensicSignificance: "Correlating logoff with logon events establishes session duration, which helps identify unusual session patterns such as extremely short automated sessions or unusually long interactive sessions.",
    detectionUse: "Calculate session durations to identify automated lateral movement (very short sessions) or persistent unauthorized access (very long sessions).",
    severity: "low"
  },
  {
    eventId: 4648,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A logon was attempted using explicit credentials. Records when a user provides different credentials than their current logon session, such as using runas or mapping a network drive with alternate credentials.",
    forensicSignificance: "Explicit credential logons indicate when users or processes authenticate with credentials different from the current session. This is commonly seen during lateral movement when attackers use stolen credentials.",
    detectionUse: "Detect credential hopping and lateral movement where attackers use stolen credentials to access other systems. Flag when service accounts use explicit credentials unexpectedly.",
    severity: "high"
  },
  {
    eventId: 4657,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A registry value was modified. Captures registry value changes including the old and new values when Object Access auditing is enabled.",
    forensicSignificance: "Provides native Windows auditing of registry changes without requiring Sysmon. Captures both old and new values for forensic comparison.",
    detectionUse: "Detect modifications to security-sensitive registry keys including Run keys, service configurations, and security policy settings.",
    severity: "medium"
  },
  {
    eventId: 4663,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "An attempt was made to access an object. Records when a process accesses a file, folder, registry key, or other securable object that has auditing configured.",
    forensicSignificance: "Object access auditing provides detailed tracking of file and folder access, which is critical for detecting data theft, unauthorized access to sensitive files, and ransomware activity.",
    detectionUse: "Detect unauthorized access to sensitive files, mass file access indicating data exfiltration, and ransomware encrypting files across file shares.",
    severity: "medium"
  },
  {
    eventId: 4670,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "Permissions on an object were changed. Records when the DACL (permissions) on a securable object are modified.",
    forensicSignificance: "Permission changes can indicate an attacker granting themselves access to protected resources or weakening security on critical system objects.",
    detectionUse: "Detect unauthorized permission changes on sensitive files, folders, and registry keys that could facilitate persistence or data access.",
    severity: "medium"
  },
  {
    eventId: 4672,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "Special privileges assigned to new logon. Records when a user logs on with administrative or other sensitive privileges such as SeDebugPrivilege, SeTakeOwnershipPrivilege, or SeLoadDriverPrivilege.",
    forensicSignificance: "Identifies sessions with elevated privileges that could be used for credential dumping (SeDebugPrivilege), taking ownership of protected objects, or loading kernel drivers. Essential for tracking privileged access.",
    detectionUse: "Monitor privileged logon sessions, detect unexpected privilege assignments, and identify accounts that should not have administrative access.",
    severity: "high"
  },
  {
    eventId: 4688,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A new process has been created. Records process creation events including the executable path, command line (when enabled via policy), parent process, and user context.",
    forensicSignificance: "Native Windows process creation logging. When command line auditing is enabled, provides similar visibility to Sysmon Event ID 1 but without hash values or additional metadata.",
    detectionUse: "Detect suspicious process execution, unusual parent-child process relationships, and command line parameters indicating malicious activity.",
    severity: "medium"
  },
  {
    eventId: 4689,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A process has exited. Records when a process terminates, including the process name and exit status code.",
    forensicSignificance: "Process exit events combined with creation events establish process lifetimes. Exit status codes can indicate abnormal termination or successful execution of attack tools.",
    detectionUse: "Correlate with process creation events to identify short-lived reconnaissance or attack tool execution, and detect processes terminated with unusual exit codes.",
    severity: "low"
  },
  {
    eventId: 4697,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A service was installed in the system. Records the installation of new Windows services including the service name, binary path, account, and start type.",
    forensicSignificance: "Service installation is a primary persistence and privilege escalation mechanism. Malicious services can run as SYSTEM and survive reboots. The binary path field reveals the actual executable.",
    detectionUse: "Detect installation of malicious services for persistence or privilege escalation. Flag services with binary paths pointing to temp directories, encoded commands, or unsigned executables.",
    severity: "critical"
  },
  {
    eventId: 4698,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A scheduled task was created. Records the creation of new scheduled tasks including the task name, XML definition with triggers and actions, and the creating user.",
    forensicSignificance: "Scheduled tasks are a common persistence mechanism. The task XML contains the exact command to be executed, trigger conditions, and execution account, providing full attack context.",
    detectionUse: "Detect scheduled task creation for persistence, especially tasks created by unexpected users, tasks executing from unusual paths, or tasks with suspicious command lines.",
    severity: "high"
  },
  {
    eventId: 4699,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A scheduled task was deleted. Records when a scheduled task is removed from the system.",
    forensicSignificance: "Attackers may delete scheduled tasks after execution to remove evidence of their persistence mechanisms. Deletion of legitimate monitoring tasks could indicate defense evasion.",
    detectionUse: "Detect cleanup activity where attackers remove their persistence mechanisms, or identify deletion of legitimate security monitoring tasks.",
    severity: "medium"
  },
  {
    eventId: 4700,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A scheduled task was enabled. Records when a previously disabled scheduled task is re-enabled.",
    forensicSignificance: "Enabling a dormant scheduled task could indicate an attacker activating a pre-staged persistence mechanism or re-enabling a task that was disabled during investigation.",
    detectionUse: "Monitor for re-enabling of suspicious scheduled tasks, especially those that were recently disabled during incident response.",
    severity: "medium"
  },
  {
    eventId: 4701,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A scheduled task was disabled. Records when a scheduled task is disabled without being deleted.",
    forensicSignificance: "Disabling legitimate scheduled tasks (antivirus updates, patch management) is a defense evasion technique. Disabling and later re-enabling a malicious task can be used as a staging technique.",
    detectionUse: "Detect disabling of security-related scheduled tasks, backup tasks, or monitoring tasks that could indicate defense evasion.",
    severity: "medium"
  },
  {
    eventId: 4702,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A scheduled task was updated. Records when an existing scheduled task is modified, including changes to triggers, actions, or conditions.",
    forensicSignificance: "Modifying existing scheduled tasks can be stealthier than creating new ones. Attackers may hijack legitimate tasks by changing their action to execute malicious commands.",
    detectionUse: "Detect scheduled task hijacking where attackers modify existing legitimate tasks to execute malicious payloads while maintaining the appearance of normality.",
    severity: "high"
  },
  {
    eventId: 4719,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "System audit policy was changed. Records modifications to the Windows audit policy configuration.",
    forensicSignificance: "Changing audit policy to reduce logging is a defense evasion technique. Attackers may disable auditing of specific categories to prevent their activities from being recorded.",
    detectionUse: "Alert on any audit policy changes, especially those that reduce logging coverage. This should be a high-priority alert in any environment.",
    severity: "critical"
  },
  {
    eventId: 4720,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A user account was created. Records the creation of new local or domain user accounts including the account name, SID, and the account that created it.",
    forensicSignificance: "Account creation can indicate an attacker establishing persistent access. Rogue accounts, especially those added to privileged groups, are a significant threat requiring immediate investigation.",
    detectionUse: "Detect unauthorized account creation, especially outside of normal IT operations windows. Correlate with subsequent group membership changes (4728, 4732) to identify privilege escalation.",
    severity: "high"
  },
  {
    eventId: 4722,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A user account was enabled. Records when a previously disabled user account is enabled.",
    forensicSignificance: "Enabling disabled accounts can indicate an attacker activating a dormant account for unauthorized access, or re-enabling an account that was disabled during incident response.",
    detectionUse: "Monitor for enabling of dormant or disabled accounts, especially service accounts or accounts disabled during previous security incidents.",
    severity: "high"
  },
  {
    eventId: 4723,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "An attempt was made to change an account's password. Records self-service password change attempts where the user provides both old and new passwords.",
    forensicSignificance: "Multiple failed password change attempts may indicate an attacker who has partial access to an account attempting to take full control by changing the password.",
    detectionUse: "Detect unauthorized password change attempts, especially on service accounts or privileged accounts that should use managed password solutions.",
    severity: "medium"
  },
  {
    eventId: 4724,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "An attempt was made to reset an account's password. Records administrative password resets where the old password is not required.",
    forensicSignificance: "Administrative password resets bypass the old password requirement. An attacker with sufficient privileges can reset passwords to gain access to other accounts, enabling lateral movement.",
    detectionUse: "Detect unauthorized administrative password resets, especially those performed outside of normal IT support processes or by unexpected accounts.",
    severity: "high"
  },
  {
    eventId: 4725,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A user account was disabled. Records when a user account is disabled, including the target account and the administrator who performed the action.",
    forensicSignificance: "Disabling accounts can be part of incident response, but it can also indicate an attacker disabling legitimate accounts to cause disruption or prevent administrators from logging in.",
    detectionUse: "Monitor for disabling of administrator accounts or service accounts that could indicate an attacker attempting to lock out defenders.",
    severity: "medium"
  },
  {
    eventId: 4726,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A user account was deleted. Records the deletion of user accounts from the local SAM database or Active Directory.",
    forensicSignificance: "Account deletion can indicate an attacker covering their tracks by removing rogue accounts, or can be part of a destructive attack aimed at disrupting operations.",
    detectionUse: "Alert on unexpected account deletions, especially of service accounts or recently created accounts that may have been used for unauthorized access.",
    severity: "high"
  },
  {
    eventId: 4728,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A member was added to a security-enabled global group. Records when a user or computer is added to an Active Directory global security group.",
    forensicSignificance: "Adding accounts to privileged global groups (Domain Admins, Enterprise Admins, Schema Admins) is a critical privilege escalation indicator. This is one of the most important events to monitor in Active Directory.",
    detectionUse: "Alert on additions to privileged groups including Domain Admins, Enterprise Admins, Schema Admins, and other sensitive groups defined in the environment.",
    severity: "critical"
  },
  {
    eventId: 4732,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A member was added to a security-enabled local group. Records when a user is added to a local security group such as Administrators, Remote Desktop Users, or Backup Operators.",
    forensicSignificance: "Adding members to the local Administrators group grants full control of the system. Monitoring local group changes is critical for detecting privilege escalation on individual endpoints.",
    detectionUse: "Detect privilege escalation via addition to local Administrators group, Remote Desktop Users group, or other security-sensitive local groups.",
    severity: "high"
  },
  {
    eventId: 4735,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A security-enabled local group was changed. Records modifications to local security group properties such as description or group type changes.",
    forensicSignificance: "Group property changes could be used to modify group behavior or permissions in subtle ways that are harder to detect than direct membership changes.",
    detectionUse: "Monitor for unexpected changes to security-sensitive local group properties that could indicate tampering with access control mechanisms.",
    severity: "medium"
  },
  {
    eventId: 4738,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A user account was changed. Records modifications to user account properties in Active Directory or the local SAM database.",
    forensicSignificance: "Account modifications can include changes to logon hours, account expiration, profile paths, and other properties. Attackers may modify accounts to maintain access or escalate privileges.",
    detectionUse: "Detect unauthorized modifications to user accounts, especially changes to adminCount, servicePrincipalName (Kerberoasting setup), or account delegation settings.",
    severity: "medium"
  },
  {
    eventId: 4740,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A user account was locked out. Records when an account is locked due to exceeding the failed logon attempt threshold defined in the account lockout policy.",
    forensicSignificance: "Account lockouts can indicate active brute force attacks, password spraying campaigns, or misconfigured services using stale credentials. Mass lockouts may indicate a targeted attack.",
    detectionUse: "Detect brute force attacks and password spray campaigns by monitoring lockout patterns. Mass lockouts across multiple accounts from a single source strongly indicate an attack.",
    severity: "high"
  },
  {
    eventId: 4742,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A computer account was changed. Records modifications to computer account properties in Active Directory.",
    forensicSignificance: "Computer account modifications can be part of attacks against Active Directory, including resource-based constrained delegation attacks and machine account quota abuse.",
    detectionUse: "Detect unauthorized computer account modifications, especially changes to delegation settings or ServicePrincipalName attributes that could enable Kerberos attacks.",
    severity: "medium"
  },
  {
    eventId: 4756,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A member was added to a security-enabled universal group. Records when a user or group is added to a universal security group in Active Directory.",
    forensicSignificance: "Universal groups are replicated across all domains in a forest. Adding members to privileged universal groups like Enterprise Admins grants forest-wide administrative access.",
    detectionUse: "Alert on additions to universal security groups, especially Enterprise Admins and other forest-wide administrative groups.",
    severity: "critical"
  },
  {
    eventId: 4757,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A member was removed from a security-enabled universal group. Records when a user or group is removed from a universal security group.",
    forensicSignificance: "Removing members from security groups can indicate an attacker modifying group memberships to deny access to legitimate administrators or covering tracks by removing themselves from groups they previously joined.",
    detectionUse: "Monitor for unexpected removals from security groups that could indicate an attacker removing evidence of their privilege escalation.",
    severity: "medium"
  },
  {
    eventId: 4768,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A Kerberos authentication ticket (TGT) was requested. Records TGT requests to the Key Distribution Center including the requesting account, source IP, and encryption type.",
    forensicSignificance: "TGT requests are the first step in Kerberos authentication. The encryption type field is critical: RC4 (0x17) requests for accounts that should use AES may indicate AS-REP roasting or Golden Ticket usage.",
    detectionUse: "Detect AS-REP roasting (RC4 TGT requests for accounts with pre-auth disabled), Golden Ticket usage (TGT anomalies), and unauthorized TGT requests from unexpected sources.",
    severity: "high"
  },
  {
    eventId: 4769,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A Kerberos service ticket was requested. Records TGS requests including the target service, requesting account, source IP, and encryption type used.",
    forensicSignificance: "Service ticket requests reveal what services users are accessing. RC4 encryption in service ticket requests (ticket encryption type 0x17) is the primary indicator of Kerberoasting attacks.",
    detectionUse: "Detect Kerberoasting attacks by monitoring for RC4-encrypted service ticket requests, especially in bulk targeting multiple SPNs. Also detect lateral movement via service ticket patterns.",
    severity: "high"
  },
  {
    eventId: 4770,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A Kerberos service ticket was renewed. Records renewal of existing Kerberos service tickets.",
    forensicSignificance: "Ticket renewals extend the lifetime of existing tickets. Abnormal renewal patterns can indicate ticket manipulation or replay attacks.",
    detectionUse: "Monitor for unusual ticket renewal patterns that may indicate ticket theft or replay, especially renewals for tickets that should have expired.",
    severity: "medium"
  },
  {
    eventId: 4771,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "Kerberos pre-authentication failed. Records when Kerberos pre-authentication fails, typically due to incorrect password, expired account, or time synchronization issues.",
    forensicSignificance: "Pre-authentication failures indicate incorrect passwords for Kerberos-based authentication. High volumes targeting a single account indicate brute force, while single attempts across many accounts indicate password spraying.",
    detectionUse: "Detect Kerberos-based brute force attacks and password spraying campaigns. Correlate with 4625 events for comprehensive authentication failure monitoring.",
    severity: "high"
  },
  {
    eventId: 4776,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "The domain controller attempted to validate the credentials for an account. Records NTLM authentication validation attempts at the domain controller level.",
    forensicSignificance: "NTLM authentication events reveal pass-the-hash attacks, NTLM relay attempts, and environments still relying on legacy NTLM authentication. The error code field distinguishes successful and failed attempts.",
    detectionUse: "Detect pass-the-hash attacks, NTLM relay attacks, and identify systems still using NTLM where Kerberos should be enforced. Monitor for NTLM authentication from unexpected sources.",
    severity: "high"
  },
  {
    eventId: 4946,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A change has been made to Windows Firewall exception list. A rule was added to the Windows Firewall exception list.",
    forensicSignificance: "Firewall rule additions can indicate an attacker opening ports for C2 communication, lateral movement, or data exfiltration. Unauthorized firewall changes weaken the security posture.",
    detectionUse: "Detect unauthorized firewall rule additions, especially rules allowing inbound connections on unusual ports or from any source address.",
    severity: "high"
  },
  {
    eventId: 4947,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A change has been made to Windows Firewall exception list. A rule was modified in the Windows Firewall exception list.",
    forensicSignificance: "Modifying existing firewall rules can be stealthier than adding new ones. Attackers may widen the scope of existing rules to gain network access while minimizing detection.",
    detectionUse: "Monitor for modifications to firewall rules that broaden access, change allowed ports, or modify the scope of existing exceptions.",
    severity: "medium"
  },
  {
    eventId: 4950,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A Windows Firewall setting has changed. Records when Windows Firewall profile settings are modified.",
    forensicSignificance: "Changes to firewall profile settings (e.g., disabling the firewall for a profile) significantly impact the security posture of the system and may indicate defense evasion.",
    detectionUse: "Alert on firewall being disabled or profile settings being weakened, which could indicate an attacker preparing for lateral movement or C2 establishment.",
    severity: "high"
  },
  {
    eventId: 5140,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A network share object was accessed. Records when a user accesses a network share, including the share name, source IP, and access type.",
    forensicSignificance: "Network share access is central to lateral movement and data exfiltration scenarios. Monitoring share access reveals attacker movement across the network.",
    detectionUse: "Detect lateral movement via administrative shares (C$, ADMIN$), unauthorized access to sensitive file shares, and data staging on network shares.",
    severity: "medium"
  },
  {
    eventId: 5142,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A network share object was added. Records when a new network share is created on the system.",
    forensicSignificance: "Creation of new network shares can indicate an attacker staging data for exfiltration or creating hidden shares for persistent access and tool distribution.",
    detectionUse: "Detect creation of unauthorized network shares, especially hidden shares (ending in $) or shares created outside normal IT operations.",
    severity: "medium"
  },
  {
    eventId: 5144,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A network share object was deleted. Records when a network share is removed from the system.",
    forensicSignificance: "Share deletion after use can indicate an attacker cleaning up staging areas used during data exfiltration or removing shares created for tool distribution.",
    detectionUse: "Monitor for deletion of shares that were recently created, which may indicate an attacker cleaning up after data staging or exfiltration.",
    severity: "medium"
  },
  {
    eventId: 5145,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A network share object was checked to see whether client can be granted desired access. Records detailed share access check results including the specific file or folder accessed within the share.",
    forensicSignificance: "Provides granular visibility into what files and folders are being accessed within network shares, including the specific access rights requested (read, write, delete).",
    detectionUse: "Detect ransomware activity (mass file access and modification across shares), data exfiltration (bulk read access), and unauthorized access to sensitive file share paths.",
    severity: "medium"
  },
  {
    eventId: 7034,
    channel: "System",
    provider: "Service Control Manager",
    description: "A service terminated unexpectedly. Records when a Windows service crashes or terminates abnormally, including the number of times this has occurred.",
    forensicSignificance: "Unexpected service termination can indicate an attacker crashing security services, exploitation of service vulnerabilities, or instability caused by malicious modifications.",
    detectionUse: "Detect termination of security-critical services (antivirus, EDR, event logging) that may indicate an attacker disabling defenses.",
    severity: "high"
  },
  {
    eventId: 7035,
    channel: "System",
    provider: "Service Control Manager",
    description: "A service control was sent to a service. Records when a start, stop, pause, or continue control is sent to a Windows service.",
    forensicSignificance: "Service control messages show when services are started or stopped. Stopping security services is a common defense evasion technique.",
    detectionUse: "Detect stopping of security services, unexpected service starts that may indicate persistence activation, and manipulation of critical system services.",
    severity: "medium"
  },
  {
    eventId: 7036,
    channel: "System",
    provider: "Service Control Manager",
    description: "A service entered a new state (running, stopped, paused). Records state transitions for Windows services.",
    forensicSignificance: "Service state changes provide a timeline of when services were active. Correlating with other events helps establish when malicious services were running.",
    detectionUse: "Monitor state changes for security-critical services and detect unexpected service activations or deactivations.",
    severity: "low"
  },
  {
    eventId: 7040,
    channel: "System",
    provider: "Service Control Manager",
    description: "The start type of a service was changed. Records when a service's start type is modified (auto, manual, disabled, boot).",
    forensicSignificance: "Changing a service to auto-start establishes persistence. Disabling security services removes protective controls. Both scenarios require investigation.",
    detectionUse: "Detect persistence establishment by changing malicious services to auto-start, and defense evasion by disabling security services.",
    severity: "high"
  },
  {
    eventId: 7045,
    channel: "System",
    provider: "Service Control Manager",
    description: "A new service was installed in the system. Records the installation of new services including the service name, binary path, service type, and start type.",
    forensicSignificance: "New service installation is one of the most important persistence and privilege escalation indicators. The System channel version provides different details than the Security channel 4697 event.",
    detectionUse: "Detect new service installation for persistence, especially services with suspicious binary paths (temp directories, encoded commands), running as SYSTEM, or set to auto-start.",
    severity: "critical"
  },
  {
    eventId: 4649,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A replay attack was detected. Indicates that a Kerberos replay attack was detected where the same ticket was used from a different source.",
    forensicSignificance: "Kerberos replay attacks indicate stolen tickets being used by an attacker. This is a direct indicator of pass-the-ticket or other Kerberos-based lateral movement.",
    detectionUse: "Alert immediately on Kerberos replay detections as they indicate active ticket theft and reuse.",
    severity: "critical"
  },
  {
    eventId: 4673,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A privileged service was called. Records when a process calls a system service that requires a specific privilege, such as acting as part of the operating system.",
    forensicSignificance: "Privileged service calls indicate processes exercising sensitive system privileges. Unusual privileged calls can indicate privilege abuse or exploitation.",
    detectionUse: "Detect processes calling privileged services that they normally would not, indicating potential privilege escalation or exploitation.",
    severity: "medium"
  },
  {
    eventId: 4674,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "An operation was attempted on a privileged object. Records attempts to perform operations on objects that require specific privileges.",
    forensicSignificance: "Operations on privileged objects leave traces of administrative actions and potential privilege abuse. Failed attempts may indicate an attacker testing access boundaries.",
    detectionUse: "Monitor for failed privileged operations that may indicate an attacker probing for exploitable privilege escalation paths.",
    severity: "medium"
  },
  {
    eventId: 4692,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "Backup of data protection master key was attempted. Records attempts to back up DPAPI master keys.",
    forensicSignificance: "DPAPI master key backup can indicate credential theft attempts. DPAPI protects various credentials stored on Windows systems, and backing up the master key enables offline decryption.",
    detectionUse: "Detect DPAPI master key extraction attempts that could enable decryption of saved browser passwords, Wi-Fi passwords, and other DPAPI-protected secrets.",
    severity: "high"
  },
  {
    eventId: 4693,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "Recovery of data protection master key was attempted. Records attempts to recover DPAPI master keys.",
    forensicSignificance: "DPAPI master key recovery is a technique used by credential theft tools to decrypt stored credentials. This is a strong indicator of credential harvesting activity.",
    detectionUse: "Alert on DPAPI master key recovery attempts as they strongly indicate credential theft in progress.",
    severity: "high"
  },
  {
    eventId: 4706,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A new trust was created to a domain. Records the creation of Active Directory trust relationships.",
    forensicSignificance: "Trust creation enables cross-domain authentication and access. Unauthorized trust creation can provide an attacker with persistent cross-domain access.",
    detectionUse: "Alert on creation of domain trusts that could indicate an attacker establishing persistent cross-domain access paths.",
    severity: "critical"
  },
  {
    eventId: 4707,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A trust to a domain was removed. Records the removal of Active Directory trust relationships.",
    forensicSignificance: "Trust removal can indicate cleanup after an attack or disruption of legitimate business relationships between domains.",
    detectionUse: "Monitor for unexpected trust removals that could indicate either post-attack cleanup or denial-of-service against cross-domain access.",
    severity: "high"
  },
  {
    eventId: 4713,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "Kerberos policy was changed. Records modifications to the Kerberos authentication policy including ticket lifetime and renewal settings.",
    forensicSignificance: "Modifying Kerberos policy settings can extend ticket lifetimes, enabling longer persistence via Golden Tickets or reducing security controls around Kerberos authentication.",
    detectionUse: "Alert on Kerberos policy changes, especially increases to ticket lifetime or reduction of security requirements.",
    severity: "high"
  },
  {
    eventId: 4716,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "Trusted domain information was modified. Records changes to existing domain trust configurations.",
    forensicSignificance: "Modifications to trust configurations can change the scope of trust, authentication methods, or SID filtering settings, potentially broadening attacker access.",
    detectionUse: "Monitor for trust configuration changes that weaken security, such as disabling SID filtering or enabling trust transitivity.",
    severity: "high"
  },
  {
    eventId: 4717,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "System security access was granted to an account. Records when specific system access rights (logon rights) are granted to an account.",
    forensicSignificance: "Granting logon rights like SeNetworkLogonRight or SeInteractiveLogonRight can expand an account's access capabilities beyond what was originally intended.",
    detectionUse: "Detect granting of sensitive logon rights to unauthorized accounts that could enable lateral movement or interactive access.",
    severity: "medium"
  },
  {
    eventId: 4718,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "System security access was removed from an account. Records when system access rights are removed from an account.",
    forensicSignificance: "Removal of logon rights from legitimate accounts could indicate an attacker restricting administrator access to maintain control of the environment.",
    detectionUse: "Monitor for removal of logon rights from administrator accounts that could indicate an attacker locking out defenders.",
    severity: "medium"
  },
  {
    eventId: 4739,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "Domain policy was changed. Records modifications to domain-level policy settings including password policy and account lockout policy.",
    forensicSignificance: "Domain policy changes affect all users in the domain. Weakening password or lockout policies reduces the overall security posture and can facilitate brute force attacks.",
    detectionUse: "Alert on domain policy changes that weaken security, such as reducing password complexity requirements, increasing account lockout thresholds, or shortening password history.",
    severity: "critical"
  },
  {
    eventId: 4741,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A computer account was created. Records the creation of new computer accounts in Active Directory.",
    forensicSignificance: "Unauthorized computer account creation can be part of resource-based constrained delegation attacks or used to establish persistent domain presence.",
    detectionUse: "Detect unauthorized computer account creation, especially by non-administrative users exploiting the default MachineAccountQuota allowing users to add up to 10 computer accounts.",
    severity: "high"
  },
  {
    eventId: 4743,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A computer account was deleted. Records the deletion of computer accounts from Active Directory.",
    forensicSignificance: "Computer account deletion may indicate cleanup of rogue machines or disruption of legitimate domain-joined systems.",
    detectionUse: "Monitor for unexpected computer account deletions that could indicate post-attack cleanup or service disruption.",
    severity: "medium"
  },
  {
    eventId: 4764,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A group's type was changed. Records when a group's type or scope is changed in Active Directory.",
    forensicSignificance: "Changing a group type (e.g., from Distribution to Security) can grant permissions to a previously unprivileged group, potentially affecting access control across the domain.",
    detectionUse: "Detect group type changes that could grant unintended permissions or indicate an attacker manipulating group properties for privilege escalation.",
    severity: "medium"
  },
  {
    eventId: 4765,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "SID History was added to an account. Records when the SID History attribute is added to an account.",
    forensicSignificance: "SID History injection is a persistence and privilege escalation technique where an attacker adds a privileged SID (such as Domain Admin) to a regular account's SID History, granting the account those privileges.",
    detectionUse: "Alert on SID History additions as they are a known persistence mechanism. Legitimate SID History use is limited to domain migrations.",
    severity: "critical"
  },
  {
    eventId: 4766,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "An attempt to add SID History to an account failed. Records failed attempts to inject SID History into an account.",
    forensicSignificance: "Failed SID History injection attempts indicate an attacker trying to escalate privileges via this technique but lacking sufficient permissions.",
    detectionUse: "Alert on failed SID History injection attempts as they indicate active attack attempts even though they were unsuccessful.",
    severity: "high"
  },
  {
    eventId: 4794,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "An attempt was made to set the Directory Services Restore Mode administrator password. Records DSRM password changes on domain controllers.",
    forensicSignificance: "The DSRM password provides a backdoor into the domain controller if the DsrmAdminLogonBehavior registry value is set to allow network logon. Setting this password can establish persistent domain controller access.",
    detectionUse: "Alert on DSRM password changes as they can establish a backdoor into the domain controller independent of Active Directory authentication.",
    severity: "critical"
  },
  {
    eventId: 4798,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A user's local group membership was enumerated. Records when a process queries the local group membership of a user account.",
    forensicSignificance: "Local group enumeration is common during reconnaissance. Attackers enumerate group memberships to identify privileged accounts and plan privilege escalation.",
    detectionUse: "Detect local reconnaissance activity, especially enumeration of Administrator group membership by non-administrative processes.",
    severity: "low"
  },
  {
    eventId: 4799,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A security-enabled local group membership was enumerated. Records when a process enumerates the members of a local security group.",
    forensicSignificance: "Enumerating security group members reveals which accounts have specific privileges. This is a common reconnaissance step in attack chains.",
    detectionUse: "Detect enumeration of local security group memberships, especially the Administrators group, as part of reconnaissance activity.",
    severity: "low"
  },
  {
    eventId: 5136,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A directory service object was modified. Records modifications to Active Directory objects including the attribute that was changed and its new value.",
    forensicSignificance: "AD object modifications reveal critical changes such as adding SPNs (Kerberoasting setup), modifying delegation settings, changing ACLs, and modifying group policy links.",
    detectionUse: "Detect AD attack preparation (SPN modifications for Kerberoasting), ACL abuse (DACL modifications on sensitive objects), and GPO manipulation.",
    severity: "high"
  },
  {
    eventId: 5137,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A directory service object was created. Records creation of new Active Directory objects.",
    forensicSignificance: "New AD object creation includes creation of Group Policy Objects, Organizational Units, and other directory objects that could be used for persistence or policy manipulation.",
    detectionUse: "Detect creation of rogue GPOs, OUs designed to bypass policies, and other AD objects used for persistence.",
    severity: "medium"
  },
  {
    eventId: 5138,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A directory service object was undeleted. Records when a deleted Active Directory object is restored from the AD Recycle Bin.",
    forensicSignificance: "Object restoration could indicate an attacker recovering previously deleted accounts or objects to regain access that was revoked during incident response.",
    detectionUse: "Monitor for restoration of deleted AD objects, especially user accounts or groups that were deleted during incident response.",
    severity: "medium"
  },
  {
    eventId: 5139,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A directory service object was moved. Records when an Active Directory object is moved between containers or OUs.",
    forensicSignificance: "Moving objects between OUs can change the Group Policies applied to them, potentially removing security controls or applying different configurations.",
    detectionUse: "Detect movement of computer or user accounts out of protected OUs to escape Group Policy restrictions.",
    severity: "medium"
  },
  {
    eventId: 5141,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A directory service object was deleted. Records deletion of Active Directory objects.",
    forensicSignificance: "Deletion of AD objects can cause operational disruption and may indicate destructive activity or cleanup of attack artifacts.",
    detectionUse: "Alert on deletion of critical AD objects including GPOs, OUs containing important accounts, and trust objects.",
    severity: "high"
  },
  {
    eventId: 4662,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "An operation was performed on an object. Records operations on Active Directory objects when DS Access auditing is enabled.",
    forensicSignificance: "Captures replication operations that can reveal DCSync attacks (when access rights include DS-Replication-Get-Changes and DS-Replication-Get-Changes-All).",
    detectionUse: "Detect DCSync attacks by monitoring for non-domain-controller accounts performing replication operations against domain controller objects.",
    severity: "critical"
  },
  {
    eventId: 4685,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "The state of a transaction has changed. Records state changes in COM+ transactions.",
    forensicSignificance: "Unusual transaction state changes can indicate exploitation of COM+ services or manipulation of distributed transactions.",
    detectionUse: "Monitor for unusual COM+ transaction patterns that may indicate exploitation or abuse of COM-based services.",
    severity: "low"
  },
  {
    eventId: 4696,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A primary token was assigned to process. Records when a process is assigned a different primary token, which changes its security context.",
    forensicSignificance: "Token manipulation is a key privilege escalation technique. Assigning a different token to a process allows it to operate under a different security context.",
    detectionUse: "Detect token manipulation attacks where processes acquire elevated tokens to gain higher privileges.",
    severity: "high"
  },
  {
    eventId: 4704,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A user right was assigned. Records when a user right (privilege) is assigned to a user or group.",
    forensicSignificance: "Assignment of sensitive user rights like SeDebugPrivilege, SeTakeOwnershipPrivilege, or SeImpersonatePrivilege can enable privilege escalation attacks.",
    detectionUse: "Alert on assignment of dangerous privileges, especially SeDebugPrivilege (enables credential dumping) and SeImpersonatePrivilege (enables token impersonation attacks).",
    severity: "high"
  },
  {
    eventId: 4705,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A user right was removed. Records when a user right is removed from a user or group.",
    forensicSignificance: "Removing user rights from security accounts could indicate an attacker weakening defensive capabilities or an authorized hardening action.",
    detectionUse: "Monitor for removal of user rights from security-critical service accounts that could indicate defense weakening.",
    severity: "medium"
  },
  {
    eventId: 4767,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A user account was unlocked. Records when an administrator unlocks a previously locked user account.",
    forensicSignificance: "Account unlocking after lockout events may indicate a social engineering attack where the attacker convinces IT staff to unlock an account they locked via brute force.",
    detectionUse: "Correlate account unlock events with lockout events to identify potential social engineering or unauthorized unlock of brute-forced accounts.",
    severity: "medium"
  },
  {
    eventId: 1116,
    channel: "Microsoft-Windows-Windows Defender/Operational",
    provider: "Microsoft-Windows-Windows Defender",
    description: "Windows Defender detected malware or potentially unwanted software. Records when Windows Defender identifies a threat.",
    forensicSignificance: "Malware detections provide direct evidence of threats on the system. Even if cleaned, the detection record helps reconstruct the attack timeline.",
    detectionUse: "Correlate Defender detections with other events to understand the full attack chain. Detections of hacking tools like Mimikatz indicate active compromise.",
    severity: "high"
  },
  {
    eventId: 1117,
    channel: "Microsoft-Windows-Windows Defender/Operational",
    provider: "Microsoft-Windows-Windows Defender",
    description: "Windows Defender took action against malware. Records the remediation action taken (quarantine, remove, allow) for a detected threat.",
    forensicSignificance: "Understanding the remediation action taken is critical. Allowed detections may indicate an attacker added exclusions, while quarantined items should be retrieved for analysis.",
    detectionUse: "Monitor for allowed or failed remediation actions that may indicate an attacker has added Defender exclusions or the malware evaded cleanup.",
    severity: "high"
  },
  {
    eventId: 5001,
    channel: "Microsoft-Windows-Windows Defender/Operational",
    provider: "Microsoft-Windows-Windows Defender",
    description: "Windows Defender real-time protection was disabled. Records when real-time protection is turned off.",
    forensicSignificance: "Disabling real-time protection is a common defense evasion technique that allows attackers to execute malware without detection.",
    detectionUse: "Alert immediately on Defender real-time protection being disabled, especially when not performed by IT staff during authorized maintenance.",
    severity: "critical"
  },
  {
    eventId: 5007,
    channel: "Microsoft-Windows-Windows Defender/Operational",
    provider: "Microsoft-Windows-Windows Defender",
    description: "Windows Defender configuration changed. Records changes to Defender settings including exclusion additions and scan configuration changes.",
    forensicSignificance: "Adding exclusions for specific paths or processes is a technique used by attackers to prevent their tools from being detected while leaving Defender otherwise functional.",
    detectionUse: "Monitor for addition of Defender exclusions, especially for paths like temp directories, user profile folders, or specific processes known to be used in attacks.",
    severity: "high"
  },
  {
    eventId: 4660,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "An object was deleted. Records when a securable object (file, registry key, etc.) is deleted.",
    forensicSignificance: "Object deletion tracking helps identify evidence destruction and cleanup activities. The handle ID can be correlated with preceding access events.",
    detectionUse: "Detect mass file deletion that may indicate ransomware, cleanup activity, or evidence destruction.",
    severity: "medium"
  },
  {
    eventId: 4656,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A handle to an object was requested. Records when a process requests a handle to a securable object, capturing the access rights requested.",
    forensicSignificance: "Handle requests reveal what access an attacker attempted to obtain on an object, even if the access was denied. The requested access mask provides detailed information about intent.",
    detectionUse: "Detect access attempts to sensitive files and registry keys, especially when combined with unusual access masks indicating malicious intent.",
    severity: "low"
  },
  {
    eventId: 4658,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "The handle to an object was closed. Records when a handle to a securable object is closed, completing the access tracking chain.",
    forensicSignificance: "Handle close events, when correlated with handle request events (4656), establish the complete duration of object access for timeline reconstruction.",
    detectionUse: "Correlate with 4656 events to determine access duration and identify long-running access to sensitive resources.",
    severity: "informational"
  },
  {
    eventId: 4778,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A session was reconnected to a Window Station. Records when a user reconnects to an existing RDP session.",
    forensicSignificance: "Session reconnection reveals when users or attackers reconnect to previously established RDP sessions, potentially from different source addresses.",
    detectionUse: "Detect RDP session hijacking where an attacker reconnects to an active or disconnected session belonging to another user.",
    severity: "medium"
  },
  {
    eventId: 4779,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "A session was disconnected from a Window Station. Records when a user disconnects from an RDP session without logging off.",
    forensicSignificance: "Session disconnections leave active sessions that can be hijacked. Monitoring disconnections helps identify sessions that may be targets for reconnection attacks.",
    detectionUse: "Track disconnected RDP sessions and alert when they are reconnected from different source addresses, indicating potential session hijacking.",
    severity: "low"
  },
  {
    eventId: 4964,
    channel: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
    description: "Special groups have been assigned to a new logon. Records when a logon session is assigned membership in a specially designated group defined in the Special Groups configuration.",
    forensicSignificance: "Special groups monitoring provides additional tracking for accounts in designated high-value groups beyond the standard privileged group monitoring.",
    detectionUse: "Track logon sessions that include membership in custom-defined special groups, providing targeted monitoring for environment-specific sensitive groups.",
    severity: "high"
  }
];

/* --------------------------------------------------------------------------
   2. SIEM QUERIES
   Splunk (SPL) and Elastic (KQL/EQL) detection queries
   -------------------------------------------------------------------------- */

const SIEM_QUERIES = {
  splunk: [
    {
      title: "Brute Force Login Detection",
      query: "index=wineventlog EventCode=4625 | stats count by src_ip, Account_Name | where count > 10 | sort -count",
      description: "Detects potential brute force attacks by identifying source IPs with more than 10 failed login attempts against specific accounts.",
      useCase: "Credential access detection",
      mitreTechnique: "T1110.001"
    },
    {
      title: "Password Spray Detection",
      query: "index=wineventlog EventCode=4625 | bin _time span=30m | stats dc(Account_Name) as unique_accounts count by src_ip, _time | where unique_accounts > 5 AND count < (unique_accounts * 3)",
      description: "Identifies password spray attacks where a single source IP attempts a small number of passwords against many accounts within a short time window.",
      useCase: "Credential access detection",
      mitreTechnique: "T1110.003"
    },
    {
      title: "Credential Stuffing via Multiple Failed Logons Across Accounts",
      query: "index=wineventlog EventCode=4625 Status=0xC000006D | bin _time span=1h | stats dc(Account_Name) as unique_users count by src_ip, _time | where unique_users > 20",
      description: "Detects credential stuffing by identifying source IPs with failed logon attempts against a large number of unique accounts with bad password status codes.",
      useCase: "Credential access detection",
      mitreTechnique: "T1110.004"
    },
    {
      title: "Lateral Movement via PsExec",
      query: "index=wineventlog (EventCode=7045 ServiceName=\"PSEXESVC\" OR ServiceName=\"psexec*\") OR (EventCode=5145 ShareName=\"\\\\*\\ADMIN$\" RelativeTargetName=\"PSEXESVC*\") | stats values(ServiceName) values(ComputerName) count by Account_Name, src_ip",
      description: "Detects PsExec usage by monitoring for the PSEXESVC service installation and file writes to the ADMIN$ share characteristic of PsExec lateral movement.",
      useCase: "Lateral movement detection",
      mitreTechnique: "T1570"
    },
    {
      title: "Lateral Movement via WMI",
      query: "index=wineventlog EventCode=4688 (New_Process_Name=\"*\\\\wmiprvse.exe\" OR New_Process_Name=\"*\\\\wmic.exe\") | search Creator_Process_Name!=\"*\\\\svchost.exe\" | stats count by ComputerName, Account_Name, Creator_Process_Name, Process_Command_Line",
      description: "Detects WMI-based lateral movement by identifying WMI process creation from unexpected parent processes.",
      useCase: "Lateral movement detection",
      mitreTechnique: "T1047"
    },
    {
      title: "Lateral Movement via WinRM",
      query: "index=wineventlog EventCode=4688 New_Process_Name=\"*\\\\wsmprovhost.exe\" | stats count by ComputerName, Account_Name, Creator_Process_Name, Process_Command_Line",
      description: "Detects WinRM-based lateral movement by monitoring for wsmprovhost.exe process creation, which is spawned when a remote PowerShell session is established.",
      useCase: "Lateral movement detection",
      mitreTechnique: "T1021.006"
    },
    {
      title: "Lateral Movement via SMB Admin Shares",
      query: "index=wineventlog EventCode=5140 ShareName IN (\"\\\\*\\C$\", \"\\\\*\\ADMIN$\", \"\\\\*\\IPC$\") | stats count values(ShareName) by SubjectUserName, IpAddress, ComputerName | where count > 3",
      description: "Detects lateral movement via administrative shares by monitoring access to C$, ADMIN$, and IPC$ shares from remote IPs.",
      useCase: "Lateral movement detection",
      mitreTechnique: "T1021.002"
    },
    {
      title: "Privilege Escalation via New Service Creation",
      query: "index=wineventlog (EventCode=7045 OR EventCode=4697) | eval suspicious=if(match(Service_File_Name, \"(?i)(cmd|powershell|mshta|rundll32|regsvr32|certutil|bitsadmin|wscript|cscript|temp|tmp|appdata)\"), \"yes\", \"no\") | where suspicious=\"yes\" | table _time ComputerName Account_Name ServiceName Service_File_Name Service_Start_Type",
      description: "Detects suspicious service installations that may indicate privilege escalation, focusing on services with command interpreters or temporary paths in the binary path.",
      useCase: "Privilege escalation detection",
      mitreTechnique: "T1543.003"
    },
    {
      title: "Privilege Escalation via Scheduled Task Creation",
      query: "index=wineventlog EventCode=4698 | spath input=TaskContent output=command path=Task.Actions.Exec.Command | spath input=TaskContent output=args path=Task.Actions.Exec.Arguments | eval full_cmd=command.\" \".args | search full_cmd=\"*powershell*\" OR full_cmd=\"*cmd*\" OR full_cmd=\"*certutil*\" OR full_cmd=\"*mshta*\" | table _time ComputerName SubjectUserName TaskName full_cmd",
      description: "Detects creation of scheduled tasks with suspicious command execution that may indicate persistence or privilege escalation.",
      useCase: "Privilege escalation and persistence detection",
      mitreTechnique: "T1053.005"
    },
    {
      title: "Token Manipulation Detection",
      query: "index=wineventlog EventCode=4696 | stats count by TargetUserName, SubjectUserName, ProcessName | where SubjectUserName!=TargetUserName",
      description: "Detects token manipulation by monitoring for primary token assignment where the subject user and target user differ, indicating privilege escalation via token theft.",
      useCase: "Privilege escalation detection",
      mitreTechnique: "T1134.001"
    },
    {
      title: "Persistence via Registry Run Keys",
      query: "index=sysmon EventCode=13 TargetObject=\"*\\\\CurrentVersion\\\\Run*\" OR TargetObject=\"*\\\\CurrentVersion\\\\RunOnce*\" | eval suspicious=if(match(Details, \"(?i)(powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|temp|tmp|appdata)\"), \"yes\", \"no\") | where suspicious=\"yes\" | table _time ComputerName Image User TargetObject Details",
      description: "Detects persistence establishment via registry Run and RunOnce keys with suspicious command references in the value data.",
      useCase: "Persistence detection",
      mitreTechnique: "T1547.001"
    },
    {
      title: "Persistence via Startup Folder",
      query: "index=sysmon EventCode=11 TargetFilename=\"*\\\\Start Menu\\\\Programs\\\\Startup\\\\*\" | eval file_ext=lower(mvindex(split(TargetFilename, \".\"), -1)) | where file_ext IN (\"exe\", \"bat\", \"cmd\", \"vbs\", \"js\", \"ps1\", \"lnk\", \"scr\") | table _time ComputerName Image User TargetFilename",
      description: "Detects dropping of executable files into the startup folder for persistence, filtering for common executable and script file extensions.",
      useCase: "Persistence detection",
      mitreTechnique: "T1547.001"
    },
    {
      title: "Persistence via WMI Event Subscription",
      query: "index=sysmon EventCode=1 (CommandLine=\"*__EventFilter*\" OR CommandLine=\"*CommandLineEventConsumer*\" OR CommandLine=\"*ActiveScriptEventConsumer*\" OR CommandLine=\"*__FilterToConsumerBinding*\") OR (Image=\"*\\\\scrcons.exe\" OR Image=\"*\\\\mofcomp.exe\") | table _time ComputerName User Image CommandLine ParentImage",
      description: "Detects WMI event subscription persistence by monitoring for creation of WMI filters, consumers, and bindings.",
      useCase: "Persistence detection",
      mitreTechnique: "T1546.003"
    },
    {
      title: "Defense Evasion via Log Clearing",
      query: "index=wineventlog (EventCode=1102 OR EventCode=1100) OR (EventCode=4688 New_Process_Name=\"*\\\\wevtutil.exe\" Process_Command_Line=\"*clear-log*\" OR Process_Command_Line=\"*cl *\") | table _time ComputerName Account_Name EventCode Message Process_Command_Line",
      description: "Detects security log clearing via direct log clearing events and wevtutil.exe command line execution.",
      useCase: "Defense evasion detection",
      mitreTechnique: "T1070.001"
    },
    {
      title: "Defense Evasion via Timestomping",
      query: "index=sysmon EventCode=2 | eval time_diff=abs(strptime(PreviousCreationUtcTime, \"%Y-%m-%d %H:%M:%S\") - strptime(CreationUtcTime, \"%Y-%m-%d %H:%M:%S\")) | where time_diff > 86400 | table _time ComputerName Image TargetFilename PreviousCreationUtcTime CreationUtcTime",
      description: "Detects timestomping by identifying file creation time changes where the modification exceeds 24 hours, indicating deliberate manipulation of file timestamps.",
      useCase: "Defense evasion detection",
      mitreTechnique: "T1070.006"
    },
    {
      title: "Defense Evasion via Process Injection (CreateRemoteThread)",
      query: "index=sysmon EventCode=8 | eval target_name=mvindex(split(TargetImage, \"\\\\\"), -1) | where SourceImage!=TargetImage | search target_name IN (\"lsass.exe\", \"svchost.exe\", \"explorer.exe\", \"winlogon.exe\", \"csrss.exe\") | table _time ComputerName SourceImage TargetImage SourceUser StartModule StartFunction",
      description: "Detects process injection via CreateRemoteThread by monitoring for remote thread creation targeting common injection targets like lsass.exe and svchost.exe.",
      useCase: "Defense evasion detection",
      mitreTechnique: "T1055.003"
    },
    {
      title: "Defense Evasion via AMSI Bypass Attempts",
      query: "index=wineventlog EventCode=4104 ScriptBlockText=\"*AmsiInitFailed*\" OR ScriptBlockText=\"*amsi.dll*\" OR ScriptBlockText=\"*AmsiUtils*\" OR ScriptBlockText=\"*amsiContext*\" OR ScriptBlockText=\"*SetField*NonPublic*amsi*\" | table _time ComputerName ScriptBlockText UserName",
      description: "Detects attempts to bypass the Antimalware Scan Interface by monitoring for known AMSI bypass patterns in PowerShell script block logging.",
      useCase: "Defense evasion detection",
      mitreTechnique: "T1562.001"
    },
    {
      title: "Data Exfiltration via Large Outbound Transfers",
      query: "index=network sourcetype=firewall action=allowed direction=outbound | stats sum(bytes_out) as total_bytes by src_ip, dest_ip, dest_port | eval total_mb=round(total_bytes/1024/1024, 2) | where total_mb > 100 | sort -total_mb | table src_ip dest_ip dest_port total_mb",
      description: "Identifies potential data exfiltration by detecting large outbound data transfers exceeding 100MB to single destinations.",
      useCase: "Data exfiltration detection",
      mitreTechnique: "T1048"
    },
    {
      title: "Exfiltration via DNS Tunneling",
      query: "index=dns | eval subdomain_len=len(mvindex(split(query, \".\"), 0)) | where subdomain_len > 40 | stats count avg(subdomain_len) as avg_len dc(query) as unique_queries by src_ip | where count > 50 AND avg_len > 40 | table src_ip count avg_len unique_queries",
      description: "Detects DNS tunneling by identifying queries with unusually long subdomain labels, which is characteristic of data encoded in DNS queries.",
      useCase: "Data exfiltration detection",
      mitreTechnique: "T1048.003"
    },
    {
      title: "Exfiltration via Unusual Port Usage",
      query: "index=network sourcetype=firewall action=allowed direction=outbound NOT dest_port IN (80, 443, 53, 25, 587, 993, 995, 8080, 8443) | stats sum(bytes_out) as total_bytes count by src_ip, dest_port | eval total_mb=round(total_bytes/1024/1024, 2) | where total_mb > 50 | sort -total_mb",
      description: "Detects data exfiltration over non-standard ports by monitoring for large outbound transfers on ports not typically used for legitimate traffic.",
      useCase: "Data exfiltration detection",
      mitreTechnique: "T1048.002"
    },
    {
      title: "Discovery via Net Commands",
      query: "index=sysmon EventCode=1 (Image=\"*\\\\net.exe\" OR Image=\"*\\\\net1.exe\") (CommandLine=\"*user*\" OR CommandLine=\"*group*\" OR CommandLine=\"*localgroup*\" OR CommandLine=\"*share*\" OR CommandLine=\"*view*\" OR CommandLine=\"*session*\" OR CommandLine=\"*accounts*\") | stats count values(CommandLine) by ComputerName, User, ParentImage | where count > 3",
      description: "Detects reconnaissance using net.exe commands to enumerate users, groups, shares, and sessions, especially when multiple discovery commands are run in succession.",
      useCase: "Discovery and reconnaissance detection",
      mitreTechnique: "T1087"
    },
    {
      title: "Discovery via Whoami and System Information Commands",
      query: "index=sysmon EventCode=1 (Image=\"*\\\\whoami.exe\" OR Image=\"*\\\\systeminfo.exe\" OR Image=\"*\\\\hostname.exe\" OR Image=\"*\\\\ipconfig.exe\" OR Image=\"*\\\\tasklist.exe\" OR Image=\"*\\\\qprocess.exe\") | bin _time span=5m | stats dc(Image) as unique_tools values(Image) as tools by ComputerName, User, _time | where unique_tools > 3",
      description: "Detects system enumeration by identifying execution of multiple discovery tools within a short time window, typical of automated reconnaissance scripts.",
      useCase: "Discovery and reconnaissance detection",
      mitreTechnique: "T1033"
    },
    {
      title: "Discovery via NLTest for Domain Trust Enumeration",
      query: "index=sysmon EventCode=1 Image=\"*\\\\nltest.exe\" (CommandLine=\"*/dclist*\" OR CommandLine=\"*/domain_trusts*\" OR CommandLine=\"*/trusted_domains*\" OR CommandLine=\"*/all_trusts*\" OR CommandLine=\"*/parentdomain*\" OR CommandLine=\"*/server*\") | table _time ComputerName User CommandLine ParentImage",
      description: "Detects Active Directory domain trust enumeration using nltest.exe, commonly used by attackers to map trust relationships for lateral movement planning.",
      useCase: "Discovery and reconnaissance detection",
      mitreTechnique: "T1482"
    },
    {
      title: "Discovery via AdFind",
      query: "index=sysmon EventCode=1 (Image=\"*\\\\AdFind.exe\" OR OriginalFileName=\"AdFind.exe\") OR (CommandLine=\"*objectcategory*\" AND CommandLine=\"*-f *\" AND (CommandLine=\"*person*\" OR CommandLine=\"*computer*\" OR CommandLine=\"*subnet*\" OR CommandLine=\"*trustdmp*\")) | table _time ComputerName User Image CommandLine ParentImage",
      description: "Detects AdFind.exe usage for Active Directory enumeration. AdFind is a legitimate AD query tool frequently abused by ransomware operators during reconnaissance.",
      useCase: "Discovery and reconnaissance detection",
      mitreTechnique: "T1018"
    },
    {
      title: "C2 Beaconing Pattern Detection",
      query: "index=network sourcetype=firewall action=allowed direction=outbound | bin _time span=1m | stats count by src_ip, dest_ip, _time | streamstats window=60 current=true stdev(count) as stdev_count avg(count) as avg_count by src_ip, dest_ip | where avg_count > 0 AND stdev_count/avg_count < 0.3 AND avg_count < 5 | stats count avg(avg_count) as beacon_rate by src_ip, dest_ip | where count > 30",
      description: "Detects C2 beaconing by identifying regular, low-volume network connections with low jitter (standard deviation relative to mean), characteristic of automated callback behavior.",
      useCase: "Command and control detection",
      mitreTechnique: "T1071"
    },
    {
      title: "C2 via Unusual User Agents",
      query: "index=proxy | stats count dc(dest) as unique_dests by http_user_agent, src_ip | where (match(http_user_agent, \"^(curl|wget|python|Go-http|Java)\") OR len(http_user_agent) < 10 OR http_user_agent=\"\") AND count > 5 | sort -count",
      description: "Detects potential C2 traffic by identifying HTTP requests with unusual, minimal, or missing user agent strings that are characteristic of scripted tools and implants.",
      useCase: "Command and control detection",
      mitreTechnique: "T1071.001"
    },
    {
      title: "C2 via Long DNS Queries (DGA Detection)",
      query: "index=dns | eval query_len=len(query) | eval label_count=mvcount(split(query, \".\")) | eval entropy=0 | foreach * [| eval <<FIELD>>=<<FIELD>>] | where query_len > 50 OR label_count > 5 | stats count by query, src_ip | where count < 3 | sort -count | head 100",
      description: "Detects domain generation algorithm activity and DNS-based C2 by identifying unusually long DNS queries with high entropy and many subdomain labels.",
      useCase: "Command and control detection",
      mitreTechnique: "T1568.002"
    },
    {
      title: "PowerShell Encoded Command Execution",
      query: "index=wineventlog (EventCode=4688 OR EventCode=4104) (Process_Command_Line=\"*-enc*\" OR Process_Command_Line=\"*-EncodedCommand*\" OR Process_Command_Line=\"*-ec *\" OR ScriptBlockText=\"*FromBase64String*\" OR ScriptBlockText=\"*[Convert]::*\") | table _time ComputerName Account_Name Process_Command_Line ScriptBlockText",
      description: "Detects execution of base64-encoded PowerShell commands, a common obfuscation technique used to evade command line-based detection.",
      useCase: "Execution and defense evasion detection",
      mitreTechnique: "T1059.001"
    },
    {
      title: "PowerShell Download Cradle Detection",
      query: "index=wineventlog EventCode=4104 (ScriptBlockText=\"*Net.WebClient*\" OR ScriptBlockText=\"*DownloadString*\" OR ScriptBlockText=\"*DownloadFile*\" OR ScriptBlockText=\"*Invoke-WebRequest*\" OR ScriptBlockText=\"*iwr *\" OR ScriptBlockText=\"*wget *\" OR ScriptBlockText=\"*curl *\" OR ScriptBlockText=\"*Start-BitsTransfer*\" OR ScriptBlockText=\"*Invoke-RestMethod*\") | table _time ComputerName ScriptBlockText UserName",
      description: "Detects PowerShell download cradles used to fetch and execute remote payloads from the internet, a common initial access and staging technique.",
      useCase: "Execution and initial access detection",
      mitreTechnique: "T1059.001"
    },
    {
      title: "Kerberoasting Detection",
      query: "index=wineventlog EventCode=4769 TicketEncryptionType=0x17 ServiceName!=\"krbtgt\" ServiceName!=\"*$\" | bin _time span=5m | stats dc(ServiceName) as unique_spns values(ServiceName) by Account_Name, Client_Address, _time | where unique_spns > 3 | sort -unique_spns",
      description: "Detects Kerberoasting attacks by monitoring for RC4-encrypted (type 0x17) Kerberos service ticket requests targeting multiple service principal names, excluding machine accounts.",
      useCase: "Credential access detection",
      mitreTechnique: "T1558.003"
    },
    {
      title: "AS-REP Roasting Detection",
      query: "index=wineventlog EventCode=4768 TicketEncryptionType=0x17 Result_Code=0x0 | stats count by Account_Name, Client_Address | where count > 1 | lookup ad_accounts username AS Account_Name OUTPUT preauth_required | where preauth_required=\"false\"",
      description: "Detects AS-REP roasting by identifying successful TGT requests using RC4 encryption for accounts with Kerberos pre-authentication disabled.",
      useCase: "Credential access detection",
      mitreTechnique: "T1558.004"
    },
    {
      title: "Golden Ticket Detection via Anomalous TGT",
      query: "index=wineventlog EventCode=4769 | transaction Account_Name maxspan=1h | where (EventCode=4769 AND NOT [search index=wineventlog EventCode=4768 | fields Account_Name]) | stats count by Account_Name, Client_Address, ServiceName",
      description: "Detects potential Golden Ticket usage by identifying service ticket requests without a corresponding TGT request, which occurs when a forged TGT is used.",
      useCase: "Credential access and persistence detection",
      mitreTechnique: "T1558.001"
    },
    {
      title: "Pass-the-Hash Detection",
      query: "index=wineventlog EventCode=4624 LogonType=3 AuthenticationPackageName=\"NTLM\" LogonProcessName=\"NtLmSsp\" | stats count dc(ComputerName) as unique_hosts values(ComputerName) by Account_Name, Source_Network_Address | where unique_hosts > 3",
      description: "Detects pass-the-hash attacks by monitoring for NTLM network logons from accounts accessing multiple hosts, characteristic of lateral movement with stolen NTLM hashes.",
      useCase: "Credential access and lateral movement detection",
      mitreTechnique: "T1550.002"
    },
    {
      title: "Ransomware Indicator - Mass File Encryption",
      query: "index=sysmon EventCode=11 | bin _time span=1m | stats dc(TargetFilename) as unique_files by ComputerName, Image, _time | where unique_files > 100 | eval files_per_second=unique_files/60 | sort -unique_files",
      description: "Detects potential ransomware activity by identifying processes creating an unusually high number of files in a short time, characteristic of encryption operations.",
      useCase: "Impact detection",
      mitreTechnique: "T1486"
    },
    {
      title: "Ransomware Indicator - Shadow Copy Deletion",
      query: "index=sysmon EventCode=1 (CommandLine=\"*vssadmin*delete*shadows*\" OR CommandLine=\"*wmic*shadowcopy*delete*\" OR CommandLine=\"*bcdedit*/set*recoveryenabled*no*\" OR CommandLine=\"*wbadmin*delete*catalog*\" OR CommandLine=\"*vssadmin*resize*shadowstorage*\") | table _time ComputerName User Image CommandLine ParentImage",
      description: "Detects shadow copy deletion and recovery disabling commands commonly executed by ransomware before encryption to prevent file recovery.",
      useCase: "Impact detection and ransomware response",
      mitreTechnique: "T1490"
    },
    {
      title: "DCSync Attack Detection",
      query: "index=wineventlog EventCode=4662 AccessMask=0x100 (Properties=\"*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*\" OR Properties=\"*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*\" OR Properties=\"*89e95b76-444d-4c62-991a-0facbeda640c*\") | where SubjectUserName!=\"*$\" | table _time SubjectUserName SubjectDomainName ComputerName",
      description: "Detects DCSync attacks by monitoring for replication requests (DS-Replication-Get-Changes-All) from non-machine accounts, indicating credential extraction from Active Directory.",
      useCase: "Credential access detection",
      mitreTechnique: "T1003.006"
    },
    {
      title: "Credential Dumping via LSASS Access",
      query: "index=sysmon EventCode=10 TargetImage=\"*\\\\lsass.exe\" (GrantedAccess=0x1010 OR GrantedAccess=0x1038 OR GrantedAccess=0x1FFFFF OR GrantedAccess=0x143A) | where SourceImage!=\"*\\\\csrss.exe\" AND SourceImage!=\"*\\\\lsm.exe\" AND SourceImage!=\"*\\\\wmiprvse.exe\" AND SourceImage!=\"*\\\\svchost.exe\" | table _time ComputerName SourceImage SourceUser GrantedAccess CallTrace",
      description: "Detects credential dumping tools accessing LSASS process memory by monitoring for suspicious access patterns, filtering out legitimate system processes.",
      useCase: "Credential access detection",
      mitreTechnique: "T1003.001"
    },
    {
      title: "Suspicious Parent-Child Process Relationships",
      query: "index=sysmon EventCode=1 ((ParentImage=\"*\\\\winword.exe\" OR ParentImage=\"*\\\\excel.exe\" OR ParentImage=\"*\\\\powerpnt.exe\" OR ParentImage=\"*\\\\outlook.exe\") AND (Image=\"*\\\\cmd.exe\" OR Image=\"*\\\\powershell.exe\" OR Image=\"*\\\\wscript.exe\" OR Image=\"*\\\\cscript.exe\" OR Image=\"*\\\\certutil.exe\" OR Image=\"*\\\\mshta.exe\")) | table _time ComputerName User ParentImage Image CommandLine",
      description: "Detects suspicious child processes spawned by Office applications, indicating potential macro-based malware execution or document exploitation.",
      useCase: "Initial access and execution detection",
      mitreTechnique: "T1204.002"
    },
    {
      title: "Windows Defender Exclusion Added",
      query: "index=wineventlog source=\"WinEventLog:Microsoft-Windows-Windows Defender/Operational\" EventCode=5007 | search \"HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows Defender\\\\Exclusions\" | rex field=New_Value \"(?<exclusion_path>[A-Z]:\\\\[^\\\"]+)\" | table _time ComputerName exclusion_path",
      description: "Detects when Windows Defender exclusions are added, which attackers use to prevent detection of their tools and payloads.",
      useCase: "Defense evasion detection",
      mitreTechnique: "T1562.001"
    }
  ],
  elastic: [
    {
      title: "Brute Force Login Detection",
      query: "event.code:\"4625\" | stats count(*) by source.ip, user.name | where count > 10",
      description: "Identifies source IPs generating excessive failed login events, indicating potential brute force activity.",
      useCase: "Credential access detection",
      mitreTechnique: "T1110.001"
    },
    {
      title: "Password Spray Detection",
      query: "event.code:\"4625\" AND winlog.event_data.Status:\"0xC000006D\" | stats count(*), cardinality(user.name) as unique_users by source.ip | where unique_users > 5",
      description: "Detects password spray attacks by identifying source IPs with single failed attempts against many unique accounts.",
      useCase: "Credential access detection",
      mitreTechnique: "T1110.003"
    },
    {
      title: "Credential Stuffing Detection",
      query: "event.code:\"4625\" AND winlog.event_data.SubStatus:\"0xC000006A\" | stats count(*), cardinality(user.name) as unique_accounts by source.ip | where unique_accounts > 20",
      description: "Identifies credential stuffing by detecting a high number of failed logons with bad password status targeting many unique accounts from a single source.",
      useCase: "Credential access detection",
      mitreTechnique: "T1110.004"
    },
    {
      title: "Lateral Movement via PsExec",
      query: "event.code:\"7045\" AND winlog.event_data.ServiceName:(\"PSEXESVC\" OR \"psexec*\") OR (event.code:\"5145\" AND winlog.event_data.ShareName:\"\\\\\\\\*\\\\ADMIN$\" AND winlog.event_data.RelativeTargetName:PSEXESVC*)",
      description: "Detects PsExec lateral movement by monitoring for PSEXESVC service installation and ADMIN$ share access patterns.",
      useCase: "Lateral movement detection",
      mitreTechnique: "T1570"
    },
    {
      title: "Lateral Movement via WMI Remote Execution",
      query: "process.name:\"wmiprvse.exe\" AND event.code:\"1\" AND NOT process.parent.name:\"svchost.exe\" | stats count(*) by host.name, user.name, process.command_line",
      description: "Detects WMI-based remote execution by identifying WMI provider host processes spawned from unexpected parent processes.",
      useCase: "Lateral movement detection",
      mitreTechnique: "T1047"
    },
    {
      title: "Lateral Movement via WinRM",
      query: "event.code:\"1\" AND process.name:\"wsmprovhost.exe\" | stats count(*) by host.name, user.name, process.parent.name, process.command_line",
      description: "Identifies WinRM lateral movement by monitoring for wsmprovhost.exe creation, indicating remote PowerShell session establishment.",
      useCase: "Lateral movement detection",
      mitreTechnique: "T1021.006"
    },
    {
      title: "Lateral Movement via SMB Admin Shares",
      query: "event.code:\"5140\" AND winlog.event_data.ShareName:(\"\\\\\\\\*\\\\C$\" OR \"\\\\\\\\*\\\\ADMIN$\" OR \"\\\\\\\\*\\\\IPC$\") | stats count(*), cardinality(host.name) as unique_hosts by user.name, source.ip",
      description: "Detects access to administrative shares from remote systems, indicating potential lateral movement via SMB.",
      useCase: "Lateral movement detection",
      mitreTechnique: "T1021.002"
    },
    {
      title: "Privilege Escalation via Service Installation",
      query: "(event.code:\"7045\" OR event.code:\"4697\") AND winlog.event_data.ServiceFileName:(*cmd* OR *powershell* OR *mshta* OR *rundll32* OR *temp* OR *tmp* OR *appdata*)",
      description: "Detects suspicious service installations with command interpreters or temporary directory paths in the binary path, indicating privilege escalation attempts.",
      useCase: "Privilege escalation detection",
      mitreTechnique: "T1543.003"
    },
    {
      title: "Scheduled Task Persistence Detection",
      query: "event.code:\"4698\" AND winlog.event_data.TaskContent:(*powershell* OR *cmd.exe* OR *certutil* OR *mshta* OR *wscript* OR *cscript*)",
      description: "Detects creation of scheduled tasks containing suspicious commands that may indicate persistence or privilege escalation.",
      useCase: "Persistence and privilege escalation detection",
      mitreTechnique: "T1053.005"
    },
    {
      title: "Token Manipulation Detection",
      query: "event.code:\"4696\" AND NOT (winlog.event_data.SubjectUserName: winlog.event_data.TargetUserName)",
      description: "Detects token manipulation by identifying primary token assignments where subject and target users differ.",
      useCase: "Privilege escalation detection",
      mitreTechnique: "T1134.001"
    },
    {
      title: "Registry Run Key Persistence",
      query: "event.code:\"13\" AND registry.path:(*CurrentVersion\\\\Run* OR *CurrentVersion\\\\RunOnce*) AND registry.data.strings:(*powershell* OR *cmd* OR *wscript* OR *mshta* OR *temp* OR *appdata*)",
      description: "Detects persistence via registry Run and RunOnce keys with suspicious values referencing script interpreters or temporary directories.",
      useCase: "Persistence detection",
      mitreTechnique: "T1547.001"
    },
    {
      title: "Startup Folder Persistence",
      query: "event.code:\"11\" AND file.path:*Start?Menu\\\\Programs\\\\Startup* AND file.extension:(\"exe\" OR \"bat\" OR \"cmd\" OR \"vbs\" OR \"js\" OR \"ps1\" OR \"lnk\" OR \"scr\")",
      description: "Detects files dropped into the startup folder for persistence, focusing on executable and script file types.",
      useCase: "Persistence detection",
      mitreTechnique: "T1547.001"
    },
    {
      title: "WMI Event Subscription Persistence",
      query: "event.code:\"1\" AND (process.command_line:(*__EventFilter* OR *CommandLineEventConsumer* OR *ActiveScriptEventConsumer* OR *__FilterToConsumerBinding*) OR process.name:(\"scrcons.exe\" OR \"mofcomp.exe\"))",
      description: "Detects WMI event subscription persistence by monitoring for WMI filter and consumer creation commands.",
      useCase: "Persistence detection",
      mitreTechnique: "T1546.003"
    },
    {
      title: "Security Log Clearing Detection",
      query: "event.code:(\"1102\" OR \"1100\") OR (event.code:\"1\" AND process.name:\"wevtutil.exe\" AND process.command_line:(*clear-log* OR *cl*))",
      description: "Detects security log clearing via event log cleared events and wevtutil.exe command line monitoring.",
      useCase: "Defense evasion detection",
      mitreTechnique: "T1070.001"
    },
    {
      title: "Timestomping Detection via File Time Modification",
      query: "event.code:\"2\" AND event.provider:\"Microsoft-Windows-Sysmon\"",
      description: "Detects timestomping by monitoring Sysmon file creation time change events, indicating deliberate manipulation of file metadata.",
      useCase: "Defense evasion detection",
      mitreTechnique: "T1070.006"
    },
    {
      title: "Process Injection via CreateRemoteThread",
      query: "event.code:\"8\" AND NOT (process.executable:*csrss.exe OR process.executable:*lsm.exe) AND process.pe.original_file_name:(*lsass.exe OR *svchost.exe OR *explorer.exe)",
      description: "Detects process injection via CreateRemoteThread targeting common system processes, filtering out legitimate OS operations.",
      useCase: "Defense evasion detection",
      mitreTechnique: "T1055.003"
    },
    {
      title: "AMSI Bypass Detection in PowerShell",
      query: "event.code:\"4104\" AND powershell.file.script_block_text:(*AmsiInitFailed* OR *amsi.dll* OR *AmsiUtils* OR *amsiContext* OR *SetField*NonPublic*amsi*)",
      description: "Detects AMSI bypass attempts in PowerShell script blocks by monitoring for known bypass patterns and AMSI-related string manipulation.",
      useCase: "Defense evasion detection",
      mitreTechnique: "T1562.001"
    },
    {
      title: "Large Outbound Data Transfer Detection",
      query: "network.direction:\"outbound\" AND event.action:\"allowed\" | stats sum(network.bytes) as total_bytes by source.ip, destination.ip, destination.port | where total_bytes > 104857600",
      description: "Identifies potential data exfiltration by detecting outbound transfers exceeding 100MB to individual destinations.",
      useCase: "Data exfiltration detection",
      mitreTechnique: "T1048"
    },
    {
      title: "DNS Tunneling Detection",
      query: "dns.question.name:* AND length(dns.question.name) > 50 | stats count(*), avg(length(dns.question.name)) as avg_len by source.ip | where count > 50 AND avg_len > 40",
      description: "Detects DNS tunneling by identifying queries with unusually long domain names, characteristic of data encoded in DNS queries.",
      useCase: "Data exfiltration detection",
      mitreTechnique: "T1048.003"
    },
    {
      title: "Discovery Commands - Net Enumeration",
      query: "event.code:\"1\" AND process.name:(\"net.exe\" OR \"net1.exe\") AND process.command_line:(*user* OR *group* OR *localgroup* OR *share* OR *view* OR *session*) | stats count(*), cardinality(process.command_line) as unique_cmds by host.name, user.name | where unique_cmds > 3",
      description: "Detects reconnaissance activity using net.exe commands to enumerate domain users, groups, shares, and sessions.",
      useCase: "Discovery and reconnaissance detection",
      mitreTechnique: "T1087"
    },
    {
      title: "System Enumeration via Multiple Discovery Tools",
      query: "event.code:\"1\" AND process.name:(\"whoami.exe\" OR \"systeminfo.exe\" OR \"hostname.exe\" OR \"ipconfig.exe\" OR \"tasklist.exe\" OR \"qprocess.exe\") | stats cardinality(process.name) as unique_tools by host.name, user.name | where unique_tools > 3",
      description: "Detects automated reconnaissance by identifying execution of multiple discovery tools within a short time frame.",
      useCase: "Discovery and reconnaissance detection",
      mitreTechnique: "T1033"
    },
    {
      title: "Domain Trust Enumeration via NLTest",
      query: "event.code:\"1\" AND process.name:\"nltest.exe\" AND process.command_line:(*dclist* OR *domain_trusts* OR *trusted_domains* OR *all_trusts* OR *parentdomain*)",
      description: "Detects domain trust enumeration using nltest.exe, commonly abused during Active Directory reconnaissance.",
      useCase: "Discovery and reconnaissance detection",
      mitreTechnique: "T1482"
    },
    {
      title: "AdFind Active Directory Reconnaissance",
      query: "(process.name:\"AdFind.exe\" OR process.pe.original_file_name:\"AdFind.exe\") OR (process.command_line:*objectcategory* AND process.command_line:(*person* OR *computer* OR *subnet* OR *trustdmp*))",
      description: "Detects AdFind.exe usage for AD enumeration, a tool frequently leveraged by ransomware operators.",
      useCase: "Discovery and reconnaissance detection",
      mitreTechnique: "T1018"
    },
    {
      title: "C2 Beaconing Detection via Regular Intervals",
      query: "network.direction:\"outbound\" AND event.action:\"allowed\" | stats count(*) by source.ip, destination.ip, @timestamp | where count > 30",
      description: "Identifies potential C2 beaconing by detecting regular, low-volume outbound connections to the same destination over extended periods.",
      useCase: "Command and control detection",
      mitreTechnique: "T1071"
    },
    {
      title: "Suspicious HTTP User Agents",
      query: "http.request.method:* AND (user_agent.original:(/^(curl|wget|python|Go-http|Java)/) OR length(user_agent.original) < 10)",
      description: "Detects HTTP traffic with unusual user agent strings characteristic of scripted tools, implants, or C2 frameworks.",
      useCase: "Command and control detection",
      mitreTechnique: "T1071.001"
    },
    {
      title: "DGA Domain Detection via Long DNS Queries",
      query: "dns.question.type:\"A\" AND length(dns.question.name) > 50 | stats count(*), cardinality(dns.question.name) as unique_queries by source.ip | where unique_queries > 100",
      description: "Detects domain generation algorithm activity by identifying hosts making many unique long DNS queries.",
      useCase: "Command and control detection",
      mitreTechnique: "T1568.002"
    },
    {
      title: "Encoded PowerShell Command Execution",
      query: "event.code:\"1\" AND process.name:\"powershell.exe\" AND process.command_line:(*-enc* OR *-EncodedCommand* OR *-ec *) OR (event.code:\"4104\" AND powershell.file.script_block_text:*FromBase64String*)",
      description: "Detects base64-encoded PowerShell commands used for obfuscation and defense evasion.",
      useCase: "Execution and defense evasion detection",
      mitreTechnique: "T1059.001"
    },
    {
      title: "PowerShell Download Cradle Detection",
      query: "event.code:\"4104\" AND powershell.file.script_block_text:(*Net.WebClient* OR *DownloadString* OR *DownloadFile* OR *Invoke-WebRequest* OR *Start-BitsTransfer* OR *Invoke-RestMethod*)",
      description: "Detects PowerShell download cradles used to fetch and execute remote payloads.",
      useCase: "Execution and initial access detection",
      mitreTechnique: "T1059.001"
    },
    {
      title: "Kerberoasting Detection",
      query: "event.code:\"4769\" AND winlog.event_data.TicketEncryptionType:\"0x17\" AND NOT winlog.event_data.ServiceName:\"krbtgt\" AND NOT winlog.event_data.ServiceName:*$ | stats cardinality(winlog.event_data.ServiceName) as unique_spns by user.name, source.ip | where unique_spns > 3",
      description: "Detects Kerberoasting by monitoring for RC4-encrypted service ticket requests targeting multiple SPNs from a single user.",
      useCase: "Credential access detection",
      mitreTechnique: "T1558.003"
    },
    {
      title: "AS-REP Roasting Detection",
      query: "event.code:\"4768\" AND winlog.event_data.TicketEncryptionType:\"0x17\" AND winlog.event_data.Status:\"0x0\"",
      description: "Detects AS-REP roasting by identifying successful TGT requests using RC4 encryption for accounts with pre-authentication disabled.",
      useCase: "Credential access detection",
      mitreTechnique: "T1558.004"
    },
    {
      title: "Pass-the-Hash Detection via NTLM Network Logon",
      query: "event.code:\"4624\" AND winlog.event_data.LogonType:\"3\" AND winlog.event_data.AuthenticationPackageName:\"NTLM\" | stats cardinality(host.name) as unique_hosts by user.name, source.ip | where unique_hosts > 3",
      description: "Detects pass-the-hash by monitoring NTLM network logons accessing multiple hosts from a single source.",
      useCase: "Credential access and lateral movement detection",
      mitreTechnique: "T1550.002"
    },
    {
      title: "Ransomware - Mass File Creation Activity",
      query: "event.code:\"11\" | stats cardinality(file.path) as unique_files by host.name, process.name | where unique_files > 100",
      description: "Detects potential ransomware by identifying processes creating a very high number of unique files in a short period.",
      useCase: "Impact detection",
      mitreTechnique: "T1486"
    },
    {
      title: "Ransomware - Shadow Copy Deletion",
      query: "event.code:\"1\" AND process.command_line:(*vssadmin*delete*shadows* OR *wmic*shadowcopy*delete* OR *bcdedit*recoveryenabled*no* OR *wbadmin*delete*catalog*)",
      description: "Detects shadow copy deletion and recovery disabling commands commonly executed before ransomware encryption.",
      useCase: "Impact detection and ransomware response",
      mitreTechnique: "T1490"
    },
    {
      title: "DCSync Attack Detection",
      query: "event.code:\"4662\" AND winlog.event_data.AccessMask:\"0x100\" AND winlog.event_data.Properties:(*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2* OR *1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*) AND NOT user.name:*$",
      description: "Detects DCSync attacks by monitoring for directory replication requests from non-machine accounts.",
      useCase: "Credential access detection",
      mitreTechnique: "T1003.006"
    },
    {
      title: "LSASS Memory Access for Credential Dumping",
      query: "event.code:\"10\" AND winlog.event_data.TargetImage:*lsass.exe AND winlog.event_data.GrantedAccess:(\"0x1010\" OR \"0x1038\" OR \"0x1FFFFF\" OR \"0x143A\") AND NOT process.executable:(*csrss.exe OR *lsm.exe OR *svchost.exe)",
      description: "Detects credential dumping via LSASS memory access with suspicious access masks, filtering out legitimate system processes.",
      useCase: "Credential access detection",
      mitreTechnique: "T1003.001"
    },
    {
      title: "Suspicious Office Application Child Process",
      query: "event.code:\"1\" AND process.parent.name:(\"winword.exe\" OR \"excel.exe\" OR \"powerpnt.exe\" OR \"outlook.exe\") AND process.name:(\"cmd.exe\" OR \"powershell.exe\" OR \"wscript.exe\" OR \"cscript.exe\" OR \"certutil.exe\" OR \"mshta.exe\")",
      description: "Detects suspicious child processes spawned by Office applications indicating macro execution or document exploitation.",
      useCase: "Initial access and execution detection",
      mitreTechnique: "T1204.002"
    },
    {
      title: "Windows Defender Exclusion Addition",
      query: "event.code:\"5007\" AND winlog.event_data.New_Value:*Exclusions*",
      description: "Detects the addition of Windows Defender exclusions that attackers use to prevent detection of their tools.",
      useCase: "Defense evasion detection",
      mitreTechnique: "T1562.001"
    }
  ]
};

/* --------------------------------------------------------------------------
   3. THREAT HUNTING HYPOTHESES
   Structured hunting scenarios for proactive threat detection
   -------------------------------------------------------------------------- */

const THREAT_HUNTING_HYPOTHESES = [
  {
    hypothesis: "An adversary is using LOLBins to download and execute malicious payloads while evading application whitelisting.",
    dataSources: [
      "Sysmon Event ID 1 (Process Create)",
      "Sysmon Event ID 3 (Network Connection)",
      "Proxy logs",
      "EDR telemetry"
    ],
    analysisSteps: [
      "Query for executions of known LOLBins: certutil.exe, mshta.exe, regsvr32.exe, rundll32.exe, msiexec.exe, bitsadmin.exe",
      "Filter for command lines containing URLs, UNC paths, or download-related flags such as -urlcache, -decode, /i:http, /transfer",
      "Correlate with outbound network connections from these processes using Sysmon Event ID 3",
      "Check if downloaded files are subsequently executed by examining child process creation events",
      "Baseline normal usage of these tools by IT administration to reduce false positives"
    ],
    expectedFindings: "LOLBin processes making network connections to external IPs or executing downloaded content, especially outside of IT administration windows.",
    mitreTechnique: "T1218",
    difficulty: "intermediate"
  },
  {
    hypothesis: "An adversary has compromised valid credentials and is conducting lateral movement using NTLM pass-the-hash across multiple systems.",
    dataSources: [
      "Windows Event ID 4624 (Logon Type 3 with NTLM)",
      "Windows Event ID 4776 (NTLM Credential Validation)",
      "Network flow data",
      "EDR telemetry"
    ],
    analysisSteps: [
      "Identify accounts with Type 3 NTLM logons across multiple systems within a short time window",
      "Filter out machine accounts and known service accounts that legitimately authenticate to multiple hosts",
      "Correlate the source IPs of NTLM logons to identify the originating workstation",
      "Check if the originating workstation shows signs of compromise such as malware detections or suspicious process execution",
      "Examine the accessed systems for evidence of data access, tool execution, or persistence establishment"
    ],
    expectedFindings: "A single user account or source IP performing NTLM network logons to many systems in rapid succession, especially accessing administrative shares or executing remote commands.",
    mitreTechnique: "T1550.002",
    difficulty: "intermediate"
  },
  {
    hypothesis: "An adversary is using WMI for persistent remote command execution across the network for lateral movement.",
    dataSources: [
      "Sysmon Event ID 1 (Process Create)",
      "Windows Event ID 4688 (Process Creation)",
      "Sysmon Event ID 3 (Network Connection)",
      "WMI-Activity/Operational event log"
    ],
    analysisSteps: [
      "Search for wmiprvse.exe child processes, which indicate remote WMI command execution",
      "Filter for suspicious child processes like cmd.exe, powershell.exe, or custom binaries spawned by wmiprvse.exe",
      "Identify the source system by examining WMI network connections on port 135 and subsequent DCOM high ports",
      "Check for WMI event subscription creation that could indicate persistent WMI-based backdoors",
      "Correlate WMI activity with authentication events to identify the accounts being used"
    ],
    expectedFindings: "WMI provider host process spawning suspicious child processes like command interpreters or unknown binaries, combined with network connections from a single source to multiple targets.",
    mitreTechnique: "T1047",
    difficulty: "intermediate"
  },
  {
    hypothesis: "An adversary has established persistence through scheduled tasks that execute malicious payloads at regular intervals.",
    dataSources: [
      "Windows Event ID 4698 (Scheduled Task Created)",
      "Windows Event ID 4702 (Scheduled Task Updated)",
      "Sysmon Event ID 1 (Process Create)",
      "Task Scheduler Operational log"
    ],
    analysisSteps: [
      "Query for all scheduled task creation events (4698) and extract the task XML to identify the action commands",
      "Filter for tasks executing from unusual locations like temp directories, user profiles, or ProgramData",
      "Look for tasks with encoded commands, download cradles, or references to script interpreters",
      "Identify scheduled tasks created by non-administrative accounts or outside of change management windows",
      "Cross-reference task names with known legitimate tasks to identify masquerading attempts"
    ],
    expectedFindings: "Scheduled tasks executing binaries from temp directories, using encoded PowerShell commands, or created by unexpected user accounts outside normal change windows.",
    mitreTechnique: "T1053.005",
    difficulty: "beginner"
  },
  {
    hypothesis: "An adversary is conducting Kerberoasting attacks to extract service account credentials from Active Directory.",
    dataSources: [
      "Windows Event ID 4769 (Kerberos Service Ticket Request)",
      "Windows Event ID 4768 (Kerberos TGT Request)",
      "Active Directory service account inventory",
      "Network flow data"
    ],
    analysisSteps: [
      "Query for 4769 events with RC4 ticket encryption (type 0x17) which is the legacy encryption type targeted by Kerberoasting",
      "Exclude machine accounts (ending in $) and the krbtgt service from the analysis",
      "Identify accounts requesting service tickets for multiple SPNs in a short time window, indicating automated enumeration",
      "Cross-reference targeted SPNs with service accounts that have weak or old passwords",
      "Check the source workstations for signs of compromise or unauthorized tool usage"
    ],
    expectedFindings: "A single account requesting RC4-encrypted service tickets for many different SPNs within minutes, especially targeting service accounts with SPNs that have not been recently audited.",
    mitreTechnique: "T1558.003",
    difficulty: "intermediate"
  },
  {
    hypothesis: "An adversary is exfiltrating data through DNS tunneling by encoding stolen data in DNS query subdomains.",
    dataSources: [
      "DNS query logs",
      "Sysmon Event ID 22 (DNS Query)",
      "Network flow data",
      "Proxy logs"
    ],
    analysisSteps: [
      "Calculate the average subdomain length and entropy for all DNS queries per source host",
      "Identify hosts generating DNS queries with subdomain labels exceeding 40 characters or total query lengths exceeding 60 characters",
      "Analyze the character distribution of long subdomains for base32 or base64 encoding patterns",
      "Check for high volumes of queries to single domains with many unique subdomains",
      "Correlate suspicious DNS activity with process execution on the source host to identify the responsible application"
    ],
    expectedFindings: "A single host generating thousands of DNS queries to the same domain with long, high-entropy subdomain labels, especially using TXT or NULL query types, from a non-browser process.",
    mitreTechnique: "T1048.003",
    difficulty: "advanced"
  },
  {
    hypothesis: "An adversary has gained initial access via a phishing email and is using macro-enabled Office documents to establish a foothold.",
    dataSources: [
      "Sysmon Event ID 1 (Process Create)",
      "Email gateway logs",
      "Sysmon Event ID 11 (File Create)",
      "Sysmon Event ID 3 (Network Connection)"
    ],
    analysisSteps: [
      "Search for Office applications (winword.exe, excel.exe, powerpnt.exe) spawning child processes like cmd.exe, powershell.exe, wscript.exe, or mshta.exe",
      "Identify Office processes making outbound network connections to external IP addresses",
      "Look for file creation events where Office applications write executables or scripts to temp directories",
      "Correlate with email logs to identify the original email, sender, and attachment",
      "Check for persistence establishment following the initial Office document execution"
    ],
    expectedFindings: "Office applications spawning command interpreters or script engines, making outbound connections to external hosts, or dropping executable files to disk.",
    mitreTechnique: "T1566.001",
    difficulty: "beginner"
  },
  {
    hypothesis: "An adversary is performing credential dumping by accessing LSASS process memory using tools like Mimikatz or comsvcs.dll.",
    dataSources: [
      "Sysmon Event ID 10 (Process Access)",
      "Sysmon Event ID 1 (Process Create)",
      "Windows Event ID 4688 (Process Creation)",
      "EDR telemetry"
    ],
    analysisSteps: [
      "Monitor for processes accessing lsass.exe with suspicious access masks (0x1010, 0x1038, 0x1FFFFF, 0x143A)",
      "Filter out legitimate system processes that access LSASS (csrss.exe, lsm.exe, svchost.exe)",
      "Search for procdump.exe, comsvcs.dll MiniDump, or Out-Minidump being used to create LSASS memory dumps",
      "Look for suspicious processes loading dbghelp.dll or dbgcore.dll which are used for memory dumping",
      "Check for creation of .dmp files in temp directories or other staging locations"
    ],
    expectedFindings: "Non-system processes accessing LSASS with read access, processes using the MiniDump API, or dump files being written to disk containing LSASS memory.",
    mitreTechnique: "T1003.001",
    difficulty: "intermediate"
  },
  {
    hypothesis: "An adversary is staging data in a central location before exfiltrating it from the network.",
    dataSources: [
      "Sysmon Event ID 11 (File Create)",
      "Windows Event ID 5145 (Network Share Access)",
      "Network flow data",
      "File integrity monitoring"
    ],
    analysisSteps: [
      "Identify directories with sudden increases in file creation volume, especially in temp, ProgramData, or user profile locations",
      "Search for archive creation tools (7z.exe, winrar.exe, tar.exe, compress) being used to create large archives",
      "Monitor for file renaming operations that change extensions to benign types (e.g., .txt, .log, .jpg)",
      "Track large file copies to network shares, especially hidden shares or newly created shares",
      "Correlate staging activity with subsequent large outbound network transfers"
    ],
    expectedFindings: "Large volumes of files being copied to a single directory, compressed into archives, and then transferred to external destinations or removable media.",
    mitreTechnique: "T1074.001",
    difficulty: "intermediate"
  },
  {
    hypothesis: "An adversary is using PowerShell for reconnaissance and payload execution while bypassing AMSI and script block logging.",
    dataSources: [
      "Windows Event ID 4104 (PowerShell Script Block Logging)",
      "Windows Event ID 4103 (PowerShell Module Logging)",
      "Sysmon Event ID 1 (Process Create)",
      "EDR telemetry"
    ],
    analysisSteps: [
      "Search for AMSI bypass patterns in script block logs: AmsiInitFailed, AmsiUtils, SetField NonPublic",
      "Identify PowerShell processes launched with encoded commands (-enc, -EncodedCommand) and decode the base64 content",
      "Look for download cradle patterns: Net.WebClient, DownloadString, DownloadFile, Invoke-WebRequest, IEX",
      "Monitor for PowerShell loading .NET assemblies via reflection or Add-Type with suspicious namespaces",
      "Track PowerShell version downgrade attacks using powershell -version 2 to bypass logging"
    ],
    expectedFindings: "PowerShell sessions with AMSI bypass code, encoded commands that decode to malicious payloads, download cradles fetching remote scripts, or version downgrade to evade script block logging.",
    mitreTechnique: "T1059.001",
    difficulty: "intermediate"
  },
  {
    hypothesis: "An insider threat actor is accessing sensitive files outside of their normal work pattern and potentially exfiltrating confidential data.",
    dataSources: [
      "Windows Event ID 4663 (Object Access)",
      "Windows Event ID 5145 (Network Share Access)",
      "DLP logs",
      "Cloud storage access logs",
      "USB device connection logs"
    ],
    analysisSteps: [
      "Establish baseline file access patterns per user including typical directories, file types, and access volumes",
      "Identify deviations from baseline such as accessing new sensitive directories, increased access volume, or access during unusual hours",
      "Monitor for bulk file downloads, copy operations to removable media, or uploads to personal cloud storage",
      "Track email attachments containing sensitive file types sent to external recipients",
      "Correlate with HR data including employees under investigation, on notice period, or with known grievances"
    ],
    expectedFindings: "Users accessing sensitive file shares they have not previously accessed, bulk downloading files outside normal work hours, or transferring data to personal devices or cloud services.",
    mitreTechnique: "T1048",
    difficulty: "advanced"
  },
  {
    hypothesis: "An adversary has compromised a supply chain component and is using trusted software updates to deliver malicious payloads.",
    dataSources: [
      "Sysmon Event ID 1 (Process Create)",
      "Sysmon Event ID 3 (Network Connection)",
      "Sysmon Event ID 7 (Image Loaded)",
      "Software inventory logs",
      "Code signing certificate logs"
    ],
    analysisSteps: [
      "Inventory all software update mechanisms and their expected behaviors including update servers, binary paths, and scheduling",
      "Monitor for signed binaries making unexpected network connections or spawning unusual child processes",
      "Check for DLLs loaded by trusted applications that are unsigned or have recently changed hashes",
      "Identify software updates that deviate from their expected download sources or distribution patterns",
      "Look for trusted applications exhibiting behaviors inconsistent with their documented functionality"
    ],
    expectedFindings: "Trusted, signed software exhibiting unexpected behaviors such as connecting to non-vendor infrastructure, loading unsigned modules, or spawning command interpreters after updates.",
    mitreTechnique: "T1195.002",
    difficulty: "advanced"
  },
  {
    hypothesis: "An adversary is abusing cloud compute resources to mine cryptocurrency or conduct further attacks using compromised cloud credentials.",
    dataSources: [
      "Cloud provider audit logs (AWS CloudTrail, Azure Activity Log, GCP Audit Log)",
      "Cloud billing alerts",
      "IAM access logs",
      "Network flow logs"
    ],
    analysisSteps: [
      "Monitor for creation of new compute instances (EC2, Azure VM, GCE) especially GPU or high-CPU instances in unusual regions",
      "Track API calls creating new IAM users, roles, or access keys that may indicate persistence establishment",
      "Identify unusual API activity patterns such as calls at odd hours or from new IP addresses and geolocations",
      "Monitor for changes to security group rules or network ACLs that open inbound access",
      "Check billing dashboards for unexpected cost increases that may indicate cryptomining"
    ],
    expectedFindings: "New compute instances launched in unusual regions, especially GPU instances, new IAM credentials created, security groups opened, or billing spikes from unauthorized resource consumption.",
    mitreTechnique: "T1578",
    difficulty: "intermediate"
  },
  {
    hypothesis: "An adversary is attempting to escape a container environment to gain access to the underlying host system.",
    dataSources: [
      "Container runtime logs (Docker daemon, containerd)",
      "Linux auditd logs on container hosts",
      "Kubernetes audit logs",
      "Syslog from container hosts",
      "Falco or similar container security tool alerts"
    ],
    analysisSteps: [
      "Monitor for containers running with privileged mode or excessive Linux capabilities (SYS_ADMIN, SYS_PTRACE, DAC_READ_SEARCH)",
      "Search for processes within containers accessing host file systems via mounted volumes, procfs, or sysfs",
      "Detect attempts to create cgroups, modify kernel parameters, or load kernel modules from within containers",
      "Identify containers running with host PID, network, or IPC namespaces that break isolation boundaries",
      "Look for exploitation of known container escape vulnerabilities such as CVE-2019-5736 (runc) or CVE-2020-15257 (containerd)"
    ],
    expectedFindings: "Containers running in privileged mode accessing host resources, processes within containers interacting with the host kernel, or exploitation of container runtime vulnerabilities leading to host-level access.",
    mitreTechnique: "T1611",
    difficulty: "advanced"
  },
  {
    hypothesis: "An adversary is using DNS for command and control by leveraging DNS query types and response codes to communicate with compromised hosts.",
    dataSources: [
      "DNS query logs",
      "Sysmon Event ID 22 (DNS Query)",
      "Network flow data",
      "Passive DNS databases"
    ],
    analysisSteps: [
      "Identify hosts making an unusually high volume of DNS queries compared to their baseline",
      "Monitor for TXT, NULL, CNAME, and MX query types to unusual domains, as these are commonly used for C2 data channels",
      "Detect queries to newly registered domains or domains with low reputation scores",
      "Analyze the timing pattern of DNS queries for regularity that may indicate automated beaconing",
      "Check for DNS responses with unusually large payloads, especially in TXT records, which can carry encoded commands"
    ],
    expectedFindings: "Regular DNS queries to suspicious domains using TXT or NULL record types, with responses containing encoded data, from non-DNS-server processes on endpoint systems.",
    mitreTechnique: "T1071.004",
    difficulty: "advanced"
  },
  {
    hypothesis: "An adversary is performing Active Directory reconnaissance using BloodHound or similar tools to map attack paths to domain dominance.",
    dataSources: [
      "Windows Event ID 4662 (Directory Service Access)",
      "Windows Event ID 4624 (Logon Events)",
      "Sysmon Event ID 3 (Network Connection)",
      "LDAP query logs on domain controllers"
    ],
    analysisSteps: [
      "Monitor for LDAP queries requesting objectClass=group, objectClass=user, objectClass=computer, and objectClass=trusteddomain in rapid succession",
      "Detect high-volume LDAP queries from a single source that enumerate all user objects, group memberships, and ACLs",
      "Identify SharpHound or similar collection binaries by process name, hash, or command line patterns",
      "Look for SMB session enumeration (NetSessionEnum) and local admin enumeration against multiple hosts",
      "Monitor for connection patterns to port 389/636 (LDAP/LDAPS) from workstations to domain controllers with unusually high query volumes"
    ],
    expectedFindings: "A single workstation performing thousands of LDAP queries enumerating users, groups, ACLs, and trust relationships in a short time frame, combined with SMB session enumeration across the network.",
    mitreTechnique: "T1087.002",
    difficulty: "intermediate"
  },
  {
    hypothesis: "An adversary has established persistence through COM object hijacking by modifying CLSID registry entries to load malicious DLLs.",
    dataSources: [
      "Sysmon Event ID 12/13 (Registry Create/Modify)",
      "Sysmon Event ID 7 (Image Loaded)",
      "Sysmon Event ID 1 (Process Create)",
      "Windows Event ID 4657 (Registry Value Modified)"
    ],
    analysisSteps: [
      "Monitor registry modifications under HKCU\\Software\\Classes\\CLSID and HKLM\\Software\\Classes\\CLSID for new or changed InprocServer32 and LocalServer32 values",
      "Identify when user-level CLSID entries shadow system-level entries, which is the core COM hijacking mechanism",
      "Cross-reference modified CLSIDs with a known-good baseline to identify unauthorized changes",
      "Track DLL loading events to see when the hijacked COM objects are instantiated and load the attacker DLL",
      "Correlate COM hijacking with the application that triggers the hijacked COM object to understand the activation mechanism"
    ],
    expectedFindings: "New HKCU CLSID registry entries that shadow legitimate HKLM entries, pointing to DLLs in unusual locations like temp directories or user profile folders.",
    mitreTechnique: "T1546.015",
    difficulty: "advanced"
  },
  {
    hypothesis: "An adversary is using living-off-the-land techniques to perform process injection via legitimate Windows utilities.",
    dataSources: [
      "Sysmon Event ID 1 (Process Create)",
      "Sysmon Event ID 8 (CreateRemoteThread)",
      "Sysmon Event ID 10 (Process Access)",
      "EDR telemetry"
    ],
    analysisSteps: [
      "Search for mavinject.exe being used to inject DLLs into running processes via the /INJECTRUNNING flag",
      "Monitor for Microsoft.Workflow.Compiler.exe being used to compile and execute arbitrary C# code",
      "Detect msbuild.exe executing inline tasks containing arbitrary code that is compiled and run in memory",
      "Look for installutil.exe or regsvcs.exe being used to execute uninstall handlers that contain malicious code",
      "Track rundll32.exe executing DLLs from unusual locations or with suspicious export function names"
    ],
    expectedFindings: "Legitimate Windows utilities being used in unusual ways, such as mavinject.exe injecting into sensitive processes or msbuild.exe executing inline task code from temporary locations.",
    mitreTechnique: "T1218",
    difficulty: "intermediate"
  },
  {
    hypothesis: "An adversary has compromised a privileged account and is performing DCSync to extract all domain credentials from Active Directory.",
    dataSources: [
      "Windows Event ID 4662 (Directory Service Access)",
      "Windows Event ID 4624 (Logon Events)",
      "Network flow data on domain controller ports",
      "Active Directory replication logs"
    ],
    analysisSteps: [
      "Monitor Event ID 4662 for access to directory replication GUIDs: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 and 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
      "Filter for non-machine accounts (not ending in $) performing replication operations",
      "Identify replication requests from non-domain-controller IP addresses",
      "Check if the requesting account has been recently granted replication permissions (Replicating Directory Changes All)",
      "Correlate with authentication events to trace the source of the DCSync attack"
    ],
    expectedFindings: "A non-domain-controller system performing directory replication requests, especially from a user account rather than a machine account, indicating Mimikatz DCSync or similar credential extraction.",
    mitreTechnique: "T1003.006",
    difficulty: "advanced"
  },
  {
    hypothesis: "An adversary is using stolen certificates or self-signed certificates to sign malicious code and bypass code signing requirements.",
    dataSources: [
      "Sysmon Event ID 6 (Driver Loaded)",
      "Sysmon Event ID 7 (Image Loaded)",
      "Certificate Authority logs",
      "Code signing audit logs",
      "EDR telemetry"
    ],
    analysisSteps: [
      "Monitor for executables and drivers signed with certificates not in the organization's approved certificate inventory",
      "Detect drivers loaded with signatures from certificates that have been recently revoked",
      "Identify code signing certificates issued to unexpected organization names or from unexpected certificate authorities",
      "Search for self-signed certificates being used to sign executables, especially in non-development contexts",
      "Track certificate enrollment and export events from internal certificate authorities for unauthorized issuance"
    ],
    expectedFindings: "Executables or drivers signed with certificates from unknown issuers, revoked certificates, or recently created self-signed certificates, especially when loaded by system services or security-critical processes.",
    mitreTechnique: "T1553.002",
    difficulty: "advanced"
  },
  {
    hypothesis: "An adversary is establishing covert persistent access through a web shell deployed on an internet-facing web server.",
    dataSources: [
      "Web server access logs",
      "Sysmon Event ID 11 (File Create)",
      "Sysmon Event ID 1 (Process Create)",
      "File integrity monitoring on web roots"
    ],
    analysisSteps: [
      "Monitor for new file creation in web root directories and their subdirectories, especially .aspx, .php, .jsp, .jspx files",
      "Detect web server processes (w3wp.exe, httpd, nginx, tomcat) spawning command interpreters like cmd.exe or powershell.exe",
      "Analyze web server access logs for POST requests to newly created or rarely accessed pages",
      "Look for anomalous request patterns such as single-IP repeated access to specific pages with varying parameters",
      "Check for obfuscated code in web-accessible files that may indicate web shell functionality"
    ],
    expectedFindings: "New or modified files in web root directories with server-side scripting extensions, web server processes spawning system commands, and unusual POST request patterns to specific endpoints.",
    mitreTechnique: "T1505.003",
    difficulty: "intermediate"
  },
  {
    hypothesis: "An adversary is abusing Windows Remote Desktop Protocol for lateral movement and has potentially hijacked existing RDP sessions.",
    dataSources: [
      "Windows Event ID 4624 (Logon Type 10)",
      "Windows Event ID 4778/4779 (Session Reconnect/Disconnect)",
      "Windows Event ID 1149 (TerminalServices-RemoteConnectionManager)",
      "Network flow data on port 3389"
    ],
    analysisSteps: [
      "Identify RDP sessions (Type 10 logons) originating from internal hosts that are not designated jump servers or admin workstations",
      "Detect RDP session reconnection (4778) where the source address differs from the original session source",
      "Monitor for tscon.exe usage which can be used to hijack disconnected RDP sessions without credentials",
      "Check for RDP connections using non-standard ports that may indicate tunneled RDP",
      "Correlate RDP activity with the time of day and typical user behavior to identify anomalous sessions"
    ],
    expectedFindings: "RDP sessions from unexpected source systems, session hijacking via tscon.exe or reconnection from different IPs, and RDP traffic on non-standard ports indicating tunneling.",
    mitreTechnique: "T1021.001",
    difficulty: "beginner"
  },
  {
    hypothesis: "An adversary is using email forwarding rules or mailbox delegation to maintain persistent access to sensitive communications.",
    dataSources: [
      "Exchange/Microsoft 365 audit logs",
      "Unified Audit Log (Set-Mailbox, New-InboxRule)",
      "Mail flow logs",
      "Azure AD sign-in logs"
    ],
    analysisSteps: [
      "Search for creation of inbox rules that forward or redirect emails to external addresses using New-InboxRule or Set-InboxRule",
      "Monitor for mailbox delegation changes (Add-MailboxPermission) granting FullAccess or SendAs to unexpected users",
      "Detect transport rules that BCC or redirect specific emails to unauthorized recipients",
      "Check for OAuth application grants that allow third-party applications to read email",
      "Identify rules that automatically delete emails matching certain criteria to hide evidence of compromise"
    ],
    expectedFindings: "Inbox rules forwarding email externally, mailbox permissions granted to unauthorized users, or OAuth applications with Mail.Read or Mail.ReadWrite permissions.",
    mitreTechnique: "T1114.003",
    difficulty: "beginner"
  },
  {
    hypothesis: "An adversary has deployed a rootkit or bootkit that manipulates the boot process to load malicious code before the operating system.",
    dataSources: [
      "Sysmon Event ID 6 (Driver Loaded)",
      "Secure Boot logs",
      "UEFI integrity measurements",
      "EDR telemetry",
      "Windows Event ID 12 (System boot)"
    ],
    analysisSteps: [
      "Monitor for unsigned kernel drivers being loaded during or after boot using Sysmon Event ID 6",
      "Check for modifications to the Boot Configuration Data (BCD) store using bcdedit commands",
      "Verify Master Boot Record (MBR) and Volume Boot Record (VBR) integrity against known-good baselines",
      "Detect disabling of Secure Boot, code integrity, or driver signature enforcement via registry or policy changes",
      "Scan for known BYOVD (Bring Your Own Vulnerable Driver) drivers used to disable kernel protections"
    ],
    expectedFindings: "Unsigned kernel drivers loaded during boot, modifications to BCD disabling security features, MBR/VBR changes, or known vulnerable drivers loaded to disable kernel security controls.",
    mitreTechnique: "T1542",
    difficulty: "advanced"
  },
  {
    hypothesis: "An adversary is exploiting misconfigured Active Directory Certificate Services to obtain unauthorized certificates for authentication.",
    dataSources: [
      "Windows Event ID 4886/4887 (Certificate Services received/approved request)",
      "Certificate Authority audit logs",
      "Active Directory Event ID 4768 (TGT with certificate)",
      "LDAP query logs"
    ],
    analysisSteps: [
      "Enumerate certificate templates with dangerous configurations: client authentication EKU, enrollee supplies subject, low authorization requirements",
      "Monitor for certificate enrollment requests from unexpected users or for unexpected templates",
      "Detect certificates issued with Subject Alternative Names (SANs) that differ from the requesting user",
      "Look for authentication events (4768) using certificate-based authentication from accounts that typically use password authentication",
      "Check for ESC1-ESC8 misconfigurations as documented in the SpecterOps Certified Pre-Owned research"
    ],
    expectedFindings: "Certificate enrollment requests for templates with enrollee-supplies-subject enabled, certificates with SANs for high-privilege accounts, or certificate-based authentication for accounts that normally use passwords.",
    mitreTechnique: "T1649",
    difficulty: "advanced"
  },
  {
    hypothesis: "An adversary is tunneling command and control traffic through legitimate cloud services to evade network-based detection.",
    dataSources: [
      "Proxy logs with SSL inspection",
      "Cloud application access logs",
      "DNS query logs",
      "Network flow data",
      "EDR telemetry"
    ],
    analysisSteps: [
      "Identify processes making persistent connections to cloud storage services (OneDrive, Google Drive, Dropbox, AWS S3) that are not standard sync clients",
      "Detect unusual API call patterns to cloud services such as high-frequency small file uploads and downloads",
      "Monitor for use of cloud-based C2 frameworks that leverage services like Azure Functions, AWS Lambda, or Google Cloud Functions",
      "Look for DNS queries to cloud service API endpoints from non-browser processes",
      "Analyze the data transfer patterns to cloud services for regularity indicating automated C2 communication"
    ],
    expectedFindings: "Non-standard processes connecting to cloud service APIs, regular small data transfers to cloud storage indicative of beaconing, or use of serverless cloud functions for command relay.",
    mitreTechnique: "T1102",
    difficulty: "advanced"
  },
  {
    hypothesis: "An adversary is manipulating Group Policy Objects to push malicious configurations or software across the domain.",
    dataSources: [
      "Windows Event ID 5136 (Directory Service Object Modified)",
      "Windows Event ID 5137 (Directory Service Object Created)",
      "Group Policy Operational logs",
      "SYSVOL file monitoring",
      "Active Directory replication logs"
    ],
    analysisSteps: [
      "Monitor for creation of new GPOs or modification of existing GPOs, especially high-impact policies linked to the domain root or Domain Controllers OU",
      "Detect changes to GPO file contents in SYSVOL, particularly scripts, MSI packages, and registry policies",
      "Identify GPOs configured with scheduled tasks, logon scripts, or software installation policies",
      "Track which accounts modify GPOs and verify they are authorized GPO administrators",
      "Check for GPOs that configure security settings to weaken protections such as disabling Windows Firewall or reducing audit policy"
    ],
    expectedFindings: "New or modified GPOs containing scheduled tasks, logon scripts, or software deployment that were not created through the normal change management process.",
    mitreTechnique: "T1484.001",
    difficulty: "intermediate"
  },
  {
    hypothesis: "An adversary is using SSH tunneling or SOCKS proxying to establish covert network channels through compromised Linux servers.",
    dataSources: [
      "SSH authentication logs (auth.log/secure)",
      "Linux auditd logs",
      "Network flow data",
      "Process monitoring"
    ],
    analysisSteps: [
      "Search for SSH connections with port forwarding options (-L, -R, -D) in command line arguments or SSH configuration",
      "Detect SSH sessions with dynamic port forwarding (-D) which creates a SOCKS proxy for traffic tunneling",
      "Monitor for unusual network connections originating from sshd child processes to internal systems",
      "Identify SSH sessions from unexpected source IPs or at unusual times, especially to bastion hosts",
      "Look for persistent SSH connections with keepalive settings that maintain long-lived tunnels"
    ],
    expectedFindings: "SSH sessions with port forwarding flags, persistent SSH connections used as tunnels, or sshd processes generating network connections to internal systems not directly accessible from the SSH source.",
    mitreTechnique: "T1572",
    difficulty: "intermediate"
  },
  {
    hypothesis: "An adversary is performing password spraying against cloud identity providers (Azure AD, Okta) while staying below lockout thresholds.",
    dataSources: [
      "Azure AD Sign-in logs",
      "Okta System Log",
      "ADFS audit logs",
      "Cloud application access logs",
      "Conditional Access policy logs"
    ],
    analysisSteps: [
      "Identify single IP addresses or small IP ranges attempting authentication against many unique user accounts",
      "Detect authentication attempts that are evenly spaced in time, indicating automated tooling with built-in delays",
      "Monitor for failed authentications using legacy protocols (SMTP, IMAP, POP3) which may bypass MFA",
      "Look for authentication attempts from anonymizing infrastructure (VPN services, Tor exit nodes, cloud provider IPs)",
      "Analyze user agent strings in authentication requests for non-standard or automated tool signatures"
    ],
    expectedFindings: "Distributed authentication failures from cloud-hosted IP addresses targeting many accounts with uniform timing patterns, especially using legacy authentication protocols that bypass conditional access policies.",
    mitreTechnique: "T1110.003",
    difficulty: "intermediate"
  },
  {
    hypothesis: "An adversary is leveraging legitimate remote monitoring and management (RMM) tools as command-and-control infrastructure to blend with normal IT operations.",
    dataSources: [
      "Sysmon Event ID 1 (Process Create)",
      "Sysmon Event ID 3 (Network Connection)",
      "Software inventory",
      "EDR telemetry",
      "Proxy logs"
    ],
    analysisSteps: [
      "Inventory all authorized RMM tools in the environment (ConnectWise, TeamViewer, AnyDesk, Splashtop, etc.)",
      "Detect installation or execution of RMM tools not in the authorized inventory",
      "Monitor for RMM tools running from unusual directory paths or under unexpected user contexts",
      "Track network connections from RMM tools to identify non-standard relay servers",
      "Identify multiple RMM tools on a single system, which is unusual and may indicate an attacker deploying backup C2 channels"
    ],
    expectedFindings: "RMM tools installed or executed that are not on the organization's authorized software list, running from temporary directories, or connecting to unrecognized relay infrastructure.",
    mitreTechnique: "T1219",
    difficulty: "beginner"
  },
  {
    hypothesis: "An adversary is performing privilege escalation on Linux systems through exploitation of SUID/SGID binaries or sudo misconfigurations.",
    dataSources: [
      "Linux auditd logs (execve syscall)",
      "Syslog/auth.log",
      "File integrity monitoring",
      "Process execution logs"
    ],
    analysisSteps: [
      "Enumerate all SUID and SGID binaries on the system and compare against a known-good baseline",
      "Monitor for new SUID/SGID binaries appearing on the system or permission changes to existing binaries",
      "Detect sudo command execution patterns, especially privilege escalation via GTFOBins-style techniques (sudo vim, sudo find, sudo python)",
      "Search for exploitation of sudo vulnerabilities such as CVE-2021-3156 (Baron Samedit) in command history and process logs",
      "Check for modifications to /etc/sudoers or sudoers.d files that expand privilege access"
    ],
    expectedFindings: "New SUID binaries in unusual locations, sudo commands using known privilege escalation techniques via text editors or scripting languages, or unauthorized modifications to sudoers configuration.",
    mitreTechnique: "T1548.001",
    difficulty: "intermediate"
  },
  {
    hypothesis: "An adversary is using legitimate cloud synchronization tools to exfiltrate data by syncing sensitive directories to personal cloud accounts.",
    dataSources: [
      "DLP logs",
      "Endpoint process monitoring",
      "Cloud application access logs",
      "Proxy logs",
      "USB device logs"
    ],
    analysisSteps: [
      "Detect installation of personal cloud sync clients (Dropbox, Google Drive, OneDrive personal) on corporate endpoints",
      "Monitor for synchronization of directories containing sensitive file types (source code, documents, databases) to cloud storage",
      "Identify large upload volumes to cloud storage services, especially from endpoints not typically generating such traffic",
      "Check for use of personal email accounts to send large attachments or share links to cloud-stored files",
      "Track rclone or similar command-line cloud sync tools that can be used for rapid bulk data transfer"
    ],
    expectedFindings: "Cloud sync tools synchronizing sensitive directories, rclone or similar tools transferring large volumes to external cloud storage, or personal cloud accounts receiving corporate data.",
    mitreTechnique: "T1567.002",
    difficulty: "beginner"
  }
];

/* --------------------------------------------------------------------------
   4. HARDENING BASELINES
   System hardening checks and remediation for Windows and Linux
   -------------------------------------------------------------------------- */

const HARDENING_BASELINES = {
  windows: [
    {
      id: "WIN-001",
      title: "Enforce Minimum Password Length",
      description: "Ensure the minimum password length is set to at least 14 characters to resist offline brute force attacks. Modern password guidance from NIST 800-63B recommends longer passwords to increase the keyspace significantly.",
      auditCommand: "net accounts | findstr /i \"Minimum password length\"",
      remediationCommand: "net accounts /minpwlen:14"
    },
    {
      id: "WIN-002",
      title: "Configure Account Lockout Threshold",
      description: "Set the account lockout threshold to lock accounts after a defined number of failed login attempts. This mitigates brute force attacks while balancing availability. A value of 5 attempts is recommended with a 30-minute lockout duration.",
      auditCommand: "net accounts | findstr /i \"Lockout threshold\"",
      remediationCommand: "net accounts /lockoutthreshold:5"
    },
    {
      id: "WIN-003",
      title: "Enable Advanced Audit Policy for Logon Events",
      description: "Configure the advanced audit policy to log both successful and failed logon events. This provides visibility into authentication activity critical for detecting brute force, credential stuffing, and lateral movement.",
      auditCommand: "auditpol /get /subcategory:\"Logon\"",
      remediationCommand: "auditpol /set /subcategory:\"Logon\" /success:enable /failure:enable"
    },
    {
      id: "WIN-004",
      title: "Enable Audit Policy for Process Creation",
      description: "Enable process creation auditing to log all new processes including their command line arguments. This is foundational telemetry for detecting malicious execution and tracking attack chains.",
      auditCommand: "auditpol /get /subcategory:\"Process Creation\"",
      remediationCommand: "auditpol /set /subcategory:\"Process Creation\" /success:enable /failure:enable && reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit\" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f"
    },
    {
      id: "WIN-005",
      title: "Enforce SMB Signing",
      description: "Enable and require SMB signing on all connections to prevent man-in-the-middle attacks and NTLM relay. SMB signing ensures the integrity and authenticity of SMB traffic, mitigating relay attacks like those used by Responder and ntlmrelayx.",
      auditCommand: "Get-SmbServerConfiguration | Select-Object RequireSecuritySignature, EnableSecuritySignature | Format-List",
      remediationCommand: "Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force"
    },
    {
      id: "WIN-006",
      title: "Deploy LAPS (Local Administrator Password Solution)",
      description: "Deploy Microsoft LAPS to automatically manage and rotate unique local administrator passwords on each domain-joined computer. This prevents lateral movement using shared local admin credentials.",
      auditCommand: "Get-AdmPwdPassword -ComputerName $env:COMPUTERNAME -ErrorAction SilentlyContinue; if ($?) { Write-Host 'LAPS is configured' } else { Write-Host 'LAPS is NOT configured' }",
      remediationCommand: "Install-Module -Name AdmPwd.PS -Force; Import-Module AdmPwd.PS; Update-AdmPwdADSchema; Set-AdmPwdComputerSelfPermission -OrgUnit \"OU=Workstations,DC=domain,DC=com\""
    },
    {
      id: "WIN-007",
      title: "Enable Credential Guard",
      description: "Enable Windows Credential Guard to isolate LSASS process credentials using virtualization-based security. This prevents credential dumping tools like Mimikatz from extracting plaintext passwords and NTLM hashes from memory.",
      auditCommand: "Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard | Select-Object -ExpandProperty SecurityServicesRunning",
      remediationCommand: "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v LsaCfgFlags /t REG_DWORD /d 1 /f && reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f && reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\" /v RequirePlatformSecurityFeatures /t REG_DWORD /d 3 /f"
    },
    {
      id: "WIN-008",
      title: "Enable LSA Protection (RunAsPPL)",
      description: "Configure LSASS to run as a Protected Process Light (PPL), preventing non-protected processes from opening LSASS or injecting code into it. This mitigates credential dumping even without full Credential Guard.",
      auditCommand: "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RunAsPPL",
      remediationCommand: "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RunAsPPL /t REG_DWORD /d 1 /f"
    },
    {
      id: "WIN-009",
      title: "Enable PowerShell Script Block Logging",
      description: "Enable PowerShell script block logging to capture the full content of all executed PowerShell scripts, including deobfuscated versions of encoded commands. This is critical for detecting PowerShell-based attacks.",
      auditCommand: "reg query \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\" /v EnableScriptBlockLogging",
      remediationCommand: "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f"
    },
    {
      id: "WIN-010",
      title: "Enable PowerShell Module Logging",
      description: "Enable PowerShell module logging to record detailed pipeline execution information for all PowerShell modules, providing complementary visibility to script block logging.",
      auditCommand: "reg query \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging\" /v EnableModuleLogging",
      remediationCommand: "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging\" /v EnableModuleLogging /t REG_DWORD /d 1 /f && reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging\\ModuleNames\" /v * /t REG_SZ /d * /f"
    },
    {
      id: "WIN-011",
      title: "Configure AppLocker or WDAC Application Control",
      description: "Deploy application control using AppLocker or Windows Defender Application Control (WDAC) to restrict executable, script, and DLL execution to approved applications. This is the most effective defense against arbitrary code execution.",
      auditCommand: "Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections | Format-Table",
      remediationCommand: "Set-AppLockerPolicy -XMLPolicy \"C:\\AppLockerPolicy.xml\" -Merge"
    },
    {
      id: "WIN-012",
      title: "Configure Windows Firewall Profiles",
      description: "Ensure the Windows Firewall is enabled on all profiles (Domain, Private, Public) with default deny inbound rules. The firewall should block all inbound connections except those explicitly required.",
      auditCommand: "Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Format-Table",
      remediationCommand: "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow"
    },
    {
      id: "WIN-013",
      title: "Restrict RDP Access and Enable NLA",
      description: "Restrict Remote Desktop access to authorized users and require Network Level Authentication (NLA) to prevent unauthenticated session establishment. NLA requires authentication before the full RDP connection is established.",
      auditCommand: "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections && reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v UserAuthentication",
      remediationCommand: "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v UserAuthentication /t REG_DWORD /d 1 /f"
    },
    {
      id: "WIN-014",
      title: "Configure UAC to Maximum Level",
      description: "Configure User Account Control to the highest level to prompt for consent on the secure desktop for all elevation requests. This mitigates UAC bypass techniques and ensures administrators are aware of privilege escalation.",
      auditCommand: "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v ConsentPromptBehaviorAdmin && reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v EnableLUA",
      remediationCommand: "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f && reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v EnableLUA /t REG_DWORD /d 1 /f && reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f"
    },
    {
      id: "WIN-015",
      title: "Disable LLMNR",
      description: "Disable Link-Local Multicast Name Resolution (LLMNR) to prevent LLMNR poisoning attacks that capture NTLMv2 hashes. Attackers use tools like Responder to poison LLMNR responses and capture credentials.",
      auditCommand: "reg query \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\" /v EnableMulticast",
      remediationCommand: "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\" /v EnableMulticast /t REG_DWORD /d 0 /f"
    },
    {
      id: "WIN-016",
      title: "Disable NBT-NS (NetBIOS Name Service)",
      description: "Disable NetBIOS over TCP/IP to prevent NBT-NS poisoning attacks. Like LLMNR, NBT-NS can be poisoned by attackers to intercept authentication attempts and capture NTLMv2 hashes.",
      auditCommand: "Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true } | Select-Object Description, @{Name='NBT-NS';Expression={if($_.TcpipNetbiosOptions -eq 2){'Disabled'}else{'Enabled'}}}",
      remediationCommand: "Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true } | ForEach-Object { $_.SetTcpipNetbios(2) }"
    },
    {
      id: "WIN-017",
      title: "Disable WDigest Authentication Caching",
      description: "Disable WDigest authentication to prevent storage of plaintext credentials in LSASS memory. On older Windows versions, WDigest stores credentials in cleartext, making them trivially extractable by Mimikatz.",
      auditCommand: "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\" /v UseLogonCredential",
      remediationCommand: "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\" /v UseLogonCredential /t REG_DWORD /d 0 /f"
    },
    {
      id: "WIN-018",
      title: "Enable Audit Policy for Object Access",
      description: "Enable auditing of object access attempts for sensitive files, folders, and registry keys. This provides visibility into data access patterns needed for detecting exfiltration and unauthorized access.",
      auditCommand: "auditpol /get /subcategory:\"File System\" && auditpol /get /subcategory:\"Registry\"",
      remediationCommand: "auditpol /set /subcategory:\"File System\" /success:enable /failure:enable && auditpol /set /subcategory:\"Registry\" /success:enable /failure:enable"
    },
    {
      id: "WIN-019",
      title: "Restrict Anonymous Enumeration of SAM and Shares",
      description: "Prevent anonymous enumeration of SAM accounts and network shares, which attackers use during reconnaissance to discover user accounts and accessible file shares.",
      auditCommand: "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RestrictAnonymousSAM && reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RestrictAnonymous",
      remediationCommand: "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f && reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RestrictAnonymous /t REG_DWORD /d 1 /f"
    },
    {
      id: "WIN-020",
      title: "Disable Remote Registry Service",
      description: "Disable the Remote Registry service to prevent remote access to the Windows registry. This reduces the attack surface by preventing remote registry enumeration and modification.",
      auditCommand: "Get-Service RemoteRegistry | Select-Object Status, StartType",
      remediationCommand: "Stop-Service RemoteRegistry -Force; Set-Service RemoteRegistry -StartupType Disabled"
    },
    {
      id: "WIN-021",
      title: "Configure Password History and Maximum Age",
      description: "Enforce password history of at least 24 previous passwords and a maximum password age of 60 days to ensure credentials are rotated regularly and cannot be reused.",
      auditCommand: "net accounts | findstr /i \"password\"",
      remediationCommand: "net accounts /uniquepw:24 /maxpwage:60"
    },
    {
      id: "WIN-022",
      title: "Enable Controlled Folder Access",
      description: "Enable Windows Defender Controlled Folder Access to protect sensitive directories from unauthorized modifications by untrusted processes. This provides ransomware protection for documents and data directories.",
      auditCommand: "Get-MpPreference | Select-Object EnableControlledFolderAccess",
      remediationCommand: "Set-MpPreference -EnableControlledFolderAccess Enabled"
    },
    {
      id: "WIN-023",
      title: "Disable Autorun and Autoplay",
      description: "Disable AutoRun and AutoPlay for all drive types to prevent automatic execution of malware from removable media. This is a fundamental defense against USB-based attacks.",
      auditCommand: "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v NoDriveTypeAutoRun",
      remediationCommand: "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f && reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v NoAutorun /t REG_DWORD /d 1 /f"
    },
    {
      id: "WIN-024",
      title: "Configure Event Log Maximum Size",
      description: "Increase the maximum size of Security, System, and Application event logs to ensure adequate log retention for forensic investigation. Default sizes are often insufficient for detecting low-and-slow attacks.",
      auditCommand: "wevtutil gl Security | findstr /i \"maxSize\" && wevtutil gl System | findstr /i \"maxSize\"",
      remediationCommand: "wevtutil sl Security /ms:1073741824 && wevtutil sl System /ms:268435456 && wevtutil sl Application /ms:268435456"
    }
  ],
  linux: [
    {
      id: "LNX-001",
      title: "Harden SSH Configuration - Disable Root Login",
      description: "Disable direct root login over SSH to prevent brute force attacks against the root account. All administrative access should use named user accounts with sudo for accountability.",
      auditCommand: "grep -i '^PermitRootLogin' /etc/ssh/sshd_config",
      remediationCommand: "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl restart sshd"
    },
    {
      id: "LNX-002",
      title: "Harden SSH Configuration - Disable Password Authentication",
      description: "Disable password-based SSH authentication and enforce key-based authentication only. SSH keys provide significantly stronger authentication than passwords and are not susceptible to brute force attacks.",
      auditCommand: "grep -i '^PasswordAuthentication' /etc/ssh/sshd_config",
      remediationCommand: "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && systemctl restart sshd"
    },
    {
      id: "LNX-003",
      title: "Harden SSH Configuration - Use Strong Ciphers and MACs",
      description: "Configure SSH to use only strong ciphers, MACs, and key exchange algorithms. Remove deprecated and weak algorithms to prevent downgrade attacks and ensure confidentiality.",
      auditCommand: "sshd -T | grep -E '^(ciphers|macs|kexalgorithms)'",
      remediationCommand: "echo 'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr' >> /etc/ssh/sshd_config && echo 'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256' >> /etc/ssh/sshd_config && echo 'KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512' >> /etc/ssh/sshd_config && systemctl restart sshd"
    },
    {
      id: "LNX-004",
      title: "Configure Password Aging Policy",
      description: "Set password aging parameters to enforce regular password rotation. Configure maximum password age, minimum age, and warning period to ensure users change passwords before expiration.",
      auditCommand: "grep -E '^PASS_MAX_DAYS|^PASS_MIN_DAYS|^PASS_WARN_AGE' /etc/login.defs",
      remediationCommand: "sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs && sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs && sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs"
    },
    {
      id: "LNX-005",
      title: "Configure PAM Password Complexity",
      description: "Configure PAM password quality requirements using pam_pwquality to enforce minimum length, character class requirements, and complexity. This prevents users from setting weak passwords.",
      auditCommand: "grep -E 'pam_pwquality|pam_cracklib' /etc/pam.d/common-password /etc/pam.d/system-auth 2>/dev/null",
      remediationCommand: "apt-get install -y libpam-pwquality 2>/dev/null || yum install -y libpwquality 2>/dev/null; echo 'password requisite pam_pwquality.so retry=3 minlen=14 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 difok=4' >> /etc/pam.d/common-password"
    },
    {
      id: "LNX-006",
      title: "Set Secure Permissions on /etc/passwd",
      description: "Ensure /etc/passwd is owned by root with permissions 644. This file must be world-readable for system operation but should not be writable by non-root users.",
      auditCommand: "stat -c '%a %U:%G' /etc/passwd",
      remediationCommand: "chown root:root /etc/passwd && chmod 644 /etc/passwd"
    },
    {
      id: "LNX-007",
      title: "Set Secure Permissions on /etc/shadow",
      description: "Ensure /etc/shadow is owned by root with permissions 640 or more restrictive. This file contains password hashes and must not be readable by unprivileged users.",
      auditCommand: "stat -c '%a %U:%G' /etc/shadow",
      remediationCommand: "chown root:shadow /etc/shadow && chmod 640 /etc/shadow"
    },
    {
      id: "LNX-008",
      title: "Set Secure Permissions on /etc/sudoers",
      description: "Ensure /etc/sudoers is owned by root with permissions 440. The sudoers file controls privilege escalation and must be tightly protected from unauthorized modification.",
      auditCommand: "stat -c '%a %U:%G' /etc/sudoers",
      remediationCommand: "chown root:root /etc/sudoers && chmod 440 /etc/sudoers"
    },
    {
      id: "LNX-009",
      title: "Harden Kernel Parameters via sysctl - Network Security",
      description: "Configure kernel network parameters to prevent IP spoofing, ICMP redirect acceptance, and source routing. These settings harden the network stack against common network-layer attacks.",
      auditCommand: "sysctl net.ipv4.conf.all.rp_filter net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.accept_source_route net.ipv4.icmp_echo_ignore_broadcasts",
      remediationCommand: "echo 'net.ipv4.conf.all.rp_filter = 1' >> /etc/sysctl.d/99-security.conf && echo 'net.ipv4.conf.all.accept_redirects = 0' >> /etc/sysctl.d/99-security.conf && echo 'net.ipv4.conf.all.accept_source_route = 0' >> /etc/sysctl.d/99-security.conf && echo 'net.ipv4.icmp_echo_ignore_broadcasts = 1' >> /etc/sysctl.d/99-security.conf && echo 'net.ipv4.conf.default.rp_filter = 1' >> /etc/sysctl.d/99-security.conf && echo 'net.ipv4.conf.default.accept_redirects = 0' >> /etc/sysctl.d/99-security.conf && sysctl --system"
    },
    {
      id: "LNX-010",
      title: "Configure iptables/nftables Firewall Rules",
      description: "Implement a default-deny firewall policy using iptables or nftables. Only explicitly required inbound ports should be allowed, with all other traffic dropped by default.",
      auditCommand: "iptables -L -n --line-numbers 2>/dev/null || nft list ruleset 2>/dev/null",
      remediationCommand: "iptables -P INPUT DROP && iptables -P FORWARD DROP && iptables -P OUTPUT ACCEPT && iptables -A INPUT -i lo -j ACCEPT && iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT && iptables -A INPUT -p tcp --dport 22 -j ACCEPT && iptables-save > /etc/iptables/rules.v4"
    },
    {
      id: "LNX-011",
      title: "Install and Configure AIDE File Integrity Monitoring",
      description: "Deploy AIDE (Advanced Intrusion Detection Environment) to monitor critical system files for unauthorized modifications. File integrity monitoring detects rootkits, backdoors, and unauthorized configuration changes.",
      auditCommand: "which aide && aide --version 2>/dev/null; ls /var/lib/aide/aide.db* 2>/dev/null",
      remediationCommand: "apt-get install -y aide 2>/dev/null || yum install -y aide 2>/dev/null; aideinit 2>/dev/null || aide --init; cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db; echo '0 5 * * * /usr/bin/aide --check' | crontab -"
    },
    {
      id: "LNX-012",
      title: "Enable Automatic Security Updates",
      description: "Configure automatic installation of security updates to ensure critical patches are applied promptly. Unpatched vulnerabilities are a primary initial access vector for attackers.",
      auditCommand: "dpkg -l unattended-upgrades 2>/dev/null | grep '^ii' || rpm -q yum-cron 2>/dev/null",
      remediationCommand: "apt-get install -y unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades 2>/dev/null || yum install -y yum-cron && systemctl enable --now yum-cron 2>/dev/null"
    },
    {
      id: "LNX-013",
      title: "Restrict Cron Access",
      description: "Restrict cron job creation to authorized users only by configuring cron.allow. Unauthorized cron jobs are a common persistence mechanism used by attackers.",
      auditCommand: "ls -la /etc/cron.allow /etc/cron.deny 2>/dev/null; cat /etc/cron.allow 2>/dev/null",
      remediationCommand: "echo root > /etc/cron.allow && chmod 600 /etc/cron.allow && chown root:root /etc/cron.allow && rm -f /etc/cron.deny"
    },
    {
      id: "LNX-014",
      title: "Audit SUID and SGID Binaries",
      description: "Regularly audit SUID and SGID binaries on the system and remove unnecessary setuid/setgid permissions. These binaries run with elevated privileges and are common targets for privilege escalation.",
      auditCommand: "find / -type f \\( -perm -4000 -o -perm -2000 \\) -exec ls -la {} \\; 2>/dev/null",
      remediationCommand: "find / -type f -perm -4000 -not -path '/usr/bin/passwd' -not -path '/usr/bin/sudo' -not -path '/usr/bin/su' -not -path '/usr/bin/newgrp' -not -path '/usr/bin/chsh' -not -path '/usr/bin/chfn' -not -path '/usr/bin/gpasswd' -not -path '/usr/bin/mount' -not -path '/usr/bin/umount' -not -path '/usr/bin/pkexec' 2>/dev/null | while read f; do echo \"Review: $f\"; done"
    },
    {
      id: "LNX-015",
      title: "Set Restrictive Default umask",
      description: "Configure a restrictive default umask of 027 or 077 to ensure newly created files and directories have appropriate permissions. A permissive umask can lead to sensitive files being readable by all users.",
      auditCommand: "grep -E 'umask|UMASK' /etc/login.defs /etc/profile /etc/bashrc 2>/dev/null",
      remediationCommand: "sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs && echo 'umask 027' >> /etc/profile.d/umask.sh"
    },
    {
      id: "LNX-016",
      title: "Disable USB Storage",
      description: "Disable USB storage device support to prevent unauthorized data exfiltration via removable media and protect against USB-based attacks such as BadUSB.",
      auditCommand: "modprobe -n -v usb-storage 2>&1; lsmod | grep usb_storage",
      remediationCommand: "echo 'install usb-storage /bin/true' > /etc/modprobe.d/disable-usb-storage.conf && echo 'blacklist usb-storage' >> /etc/modprobe.d/disable-usb-storage.conf && rmmod usb_storage 2>/dev/null"
    },
    {
      id: "LNX-017",
      title: "Configure auditd for Security Monitoring",
      description: "Deploy and configure the Linux Audit daemon to log security-relevant events including file access, process execution, user authentication, and privilege escalation attempts.",
      auditCommand: "systemctl status auditd; auditctl -l",
      remediationCommand: "apt-get install -y auditd 2>/dev/null || yum install -y audit 2>/dev/null; systemctl enable --now auditd && cat >> /etc/audit/rules.d/security.rules << 'RULES'\n-w /etc/passwd -p wa -k identity\n-w /etc/shadow -p wa -k identity\n-w /etc/group -p wa -k identity\n-w /etc/sudoers -p wa -k sudoers\n-w /etc/sudoers.d/ -p wa -k sudoers\n-a always,exit -F arch=b64 -S execve -k exec\n-w /var/log/auth.log -p wa -k auth_log\n-w /var/log/secure -p wa -k auth_log\n-w /sbin/insmod -p x -k kernel_modules\n-w /sbin/modprobe -p x -k kernel_modules\n-w /sbin/rmmod -p x -k kernel_modules\nRULES\nauditctl -R /etc/audit/rules.d/security.rules"
    },
    {
      id: "LNX-018",
      title: "Enable and Configure SELinux or AppArmor",
      description: "Enable mandatory access control using SELinux (enforcing mode) or AppArmor to confine processes and limit the damage from exploited services. MAC provides defense in depth beyond traditional discretionary access controls.",
      auditCommand: "getenforce 2>/dev/null || aa-status 2>/dev/null || echo 'No MAC framework detected'",
      remediationCommand: "sestatus 2>/dev/null && sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config && setenforce 1 2>/dev/null || (apt-get install -y apparmor apparmor-utils 2>/dev/null && systemctl enable --now apparmor && aa-enforce /etc/apparmor.d/*)"
    },
    {
      id: "LNX-019",
      title: "Disable Core Dumps",
      description: "Disable core dumps to prevent sensitive data from being written to disk when processes crash. Core dumps can contain credentials, encryption keys, and other sensitive information from process memory.",
      auditCommand: "ulimit -c; grep -E 'core|hard.*core' /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null; sysctl fs.suid_dumpable",
      remediationCommand: "echo '* hard core 0' >> /etc/security/limits.conf && echo 'fs.suid_dumpable = 0' >> /etc/sysctl.d/99-security.conf && sysctl -w fs.suid_dumpable=0"
    },
    {
      id: "LNX-020",
      title: "Configure NTP Time Synchronization",
      description: "Configure accurate time synchronization using NTP or chrony to ensure log timestamps are consistent across systems. Accurate timestamps are critical for forensic analysis and log correlation.",
      auditCommand: "timedatectl status; systemctl status chronyd 2>/dev/null || systemctl status ntpd 2>/dev/null || systemctl status systemd-timesyncd 2>/dev/null",
      remediationCommand: "apt-get install -y chrony 2>/dev/null || yum install -y chrony 2>/dev/null; systemctl enable --now chronyd"
    },
    {
      id: "LNX-021",
      title: "Disable IPv6 if Not Required",
      description: "Disable IPv6 if it is not required in the environment to reduce the attack surface. IPv6 introduces additional complexity and potential attack vectors if not properly managed.",
      auditCommand: "sysctl net.ipv6.conf.all.disable_ipv6 net.ipv6.conf.default.disable_ipv6",
      remediationCommand: "echo 'net.ipv6.conf.all.disable_ipv6 = 1' >> /etc/sysctl.d/99-security.conf && echo 'net.ipv6.conf.default.disable_ipv6 = 1' >> /etc/sysctl.d/99-security.conf && sysctl --system"
    },
    {
      id: "LNX-022",
      title: "Restrict su Command Access",
      description: "Restrict the use of the su command to members of the wheel or sudo group to limit which users can switch to root. This adds an additional layer of access control beyond sudo.",
      auditCommand: "grep 'pam_wheel' /etc/pam.d/su",
      remediationCommand: "sed -i 's/^#.*pam_wheel.so.*/auth required pam_wheel.so use_uid/' /etc/pam.d/su"
    },
    {
      id: "LNX-023",
      title: "Configure Login Banner Warning",
      description: "Configure legal warning banners for SSH and console login to establish legal standing for monitoring and prosecution. The banner should warn that the system is monitored and unauthorized access is prohibited.",
      auditCommand: "cat /etc/issue; cat /etc/issue.net; grep -i 'Banner' /etc/ssh/sshd_config",
      remediationCommand: "echo 'Authorized users only. All activity is monitored and recorded. Unauthorized access is prohibited and subject to prosecution.' > /etc/issue && cp /etc/issue /etc/issue.net && sed -i 's/^#*Banner.*/Banner \\/etc\\/issue.net/' /etc/ssh/sshd_config && systemctl restart sshd"
    },
    {
      id: "LNX-024",
      title: "Harden Kernel Parameters - Address Space Layout Randomization",
      description: "Enable Address Space Layout Randomization (ASLR) at the maximum level to randomize the memory layout of processes. ASLR makes exploitation of memory corruption vulnerabilities significantly more difficult.",
      auditCommand: "sysctl kernel.randomize_va_space",
      remediationCommand: "echo 'kernel.randomize_va_space = 2' >> /etc/sysctl.d/99-security.conf && sysctl -w kernel.randomize_va_space=2"
    },
    {
      id: "LNX-025",
      title: "Configure Fail2Ban for SSH Protection",
      description: "Deploy and configure Fail2Ban to automatically ban IP addresses that exhibit brute force behavior against SSH and other services. This provides automated response to credential attacks.",
      auditCommand: "systemctl status fail2ban 2>/dev/null; fail2ban-client status sshd 2>/dev/null",
      remediationCommand: "apt-get install -y fail2ban 2>/dev/null || yum install -y fail2ban 2>/dev/null; cat > /etc/fail2ban/jail.local << 'EOF'\n[sshd]\nenabled = true\nport = ssh\nfilter = sshd\nlogpath = /var/log/auth.log\nmaxretry = 3\nbantime = 3600\nfindtime = 600\nEOF\nsystemctl enable --now fail2ban"
    }
  ]
};
