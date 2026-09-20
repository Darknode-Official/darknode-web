// Copyright (c) 2026 SpartanKing18. All rights reserved.
// YARA Rules Database — Malware detection signatures for security education
// Categories: ransomware, trojans/RATs, droppers/loaders, webshells, cryptominers,
// wipers, rootkits, exploit kits, packers/crypters, APT toolkits, generic suspicious

export const YARA_RULES = [
  // ============================================================
  // RANSOMWARE (50 rules)
  // ============================================================
  {
    id: "YARA-RW-001", name: "WannaCry_Ransomware", description: "Detects WannaCry/WannaCrypt ransomware by its kill switch domain check and encryption routine markers",
    author: "Darknode Research", date: "2024-01-15", tags: ["ransomware", "wannacry", "apt"],
    rule_text: `rule WannaCry_Ransomware {
    meta:
        description = "Detects WannaCry ransomware"
        author = "Darknode Research"
        date = "2024-01-15"
        hash = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
    strings:
        $killswitch = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii wide
        $bitcoin = "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn" ascii
        $mutex = "MsWinZonesCacheCounterMutexA0" ascii
        $enc1 = { 68 00 00 00 00 68 00 10 00 00 }
        $svc = "cmd.exe /c \"%s\"" ascii
        $ext = ".WNCRY" ascii wide
        $note = "@Please_Read_Me@.txt" ascii
    condition:
        uint16(0) == 0x5A4D and ($killswitch or $bitcoin) and 2 of ($mutex, $enc1, $svc, $ext, $note)
}`,
    references: ["https://www.microsoft.com/en-us/security/blog/2017/05/12/wannacrypt-ransomware-worm-targets-out-of-date-systems/"],
    malware_family: "WannaCry", confidence: "high"
  },
  {
    id: "YARA-RW-002", name: "REvil_Sodinokibi", description: "Detects REvil/Sodinokibi ransomware via configuration decryption routine and ransom note patterns",
    author: "Darknode Research", date: "2024-01-15", tags: ["ransomware", "revil", "sodinokibi"],
    rule_text: `rule REvil_Sodinokibi {
    meta:
        description = "Detects REvil/Sodinokibi ransomware"
        author = "Darknode Research"
        date = "2024-01-15"
    strings:
        $cfg_key = { 8B 45 ?? 33 45 ?? 89 45 ?? 8B 4D ?? 03 4D ?? }
        $note1 = "-readme.txt" ascii nocase
        $note2 = "Every important files" ascii
        $ext_marker = { 2E ?? ?? ?? ?? ?? 00 }
        $api1 = "BCryptGenRandom" ascii
        $api2 = "BCryptEncrypt" ascii
        $pdb = "sodin" ascii nocase
        $mutex_pat = "Global\\\\" ascii
    condition:
        uint16(0) == 0x5A4D and $cfg_key and ($api1 or $api2) and 1 of ($note1, $note2, $pdb)
}`,
    references: ["https://www.secureworks.com/research/revil-sodinokibi-ransomware"],
    malware_family: "REvil", confidence: "high"
  },
  {
    id: "YARA-RW-003", name: "LockBit_Ransomware", description: "Detects LockBit ransomware variants by self-spreading mechanism and wallpaper modification",
    author: "Darknode Research", date: "2024-02-10", tags: ["ransomware", "lockbit"],
    rule_text: `rule LockBit_Ransomware {
    meta:
        description = "Detects LockBit ransomware family"
        author = "Darknode Research"
        date = "2024-02-10"
    strings:
        $note = "Restore-My-Files.txt" ascii wide
        $ext1 = ".lockbit" ascii
        $ext2 = ".abcd" ascii
        $wallpaper = "SystemParametersInfoW" ascii
        $spread1 = "ADMIN$" ascii wide
        $spread2 = "IPC$" ascii wide
        $mutex = "Global\\{" ascii
        $anti_dbg = { 64 A1 30 00 00 00 0F B6 40 02 }
        $shadow_del = "vssadmin delete shadows" ascii nocase
    condition:
        uint16(0) == 0x5A4D and 3 of them
}`,
    references: ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-075a"],
    malware_family: "LockBit", confidence: "high"
  },
  {
    id: "YARA-RW-004", name: "Conti_Ransomware", description: "Detects Conti ransomware by its multi-threaded encryption and network enumeration routines",
    author: "Darknode Research", date: "2024-01-20", tags: ["ransomware", "conti"],
    rule_text: `rule Conti_Ransomware {
    meta:
        description = "Detects Conti ransomware"
    strings:
        $note = "readme.txt" ascii wide
        $ext = ".CONTI" ascii
        $thread = "CreateIoCompletionPort" ascii
        $net1 = "NetShareEnum" ascii
        $net2 = "GetIpNetTable" ascii
        $enc = { 0F 11 44 24 ?? 0F 11 4C 24 ?? }
        $cmd1 = "vssadmin" ascii nocase
        $cmd2 = "bcdedit" ascii nocase
        $str1 = "YOURNETWORKHASBEENENCRYPTED" ascii nocase
    condition:
        uint16(0) == 0x5A4D and filesize < 1MB and 4 of them
}`,
    references: ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-265a"],
    malware_family: "Conti", confidence: "high"
  },
  {
    id: "YARA-RW-005", name: "BlackCat_ALPHV", description: "Detects BlackCat/ALPHV ransomware written in Rust with cross-platform capabilities",
    author: "Darknode Research", date: "2024-03-01", tags: ["ransomware", "blackcat", "alphv", "rust"],
    rule_text: `rule BlackCat_ALPHV {
    meta:
        description = "Detects BlackCat/ALPHV ransomware (Rust-based)"
    strings:
        $rust1 = "core::panicking::panic" ascii
        $rust2 = "std::rt::lang_start" ascii
        $cfg = "--access-token" ascii
        $note = "RECOVER-" ascii
        $ext = "uhwuvzu" ascii
        $json_cfg = "\"extension\":" ascii
        $esxi1 = "esxcli" ascii
        $esxi2 = "vm process kill" ascii
        $win_svc = "sc.exe stop" ascii
    condition:
        ($rust1 or $rust2) and 2 of ($cfg, $note, $ext, $json_cfg) and 1 of ($esxi1, $esxi2, $win_svc)
}`,
    references: ["https://www.varonis.com/blog/blackcat-ransomware"],
    malware_family: "BlackCat", confidence: "high"
  },
  {
    id: "YARA-RW-006", name: "Ryuk_Ransomware", description: "Detects Ryuk ransomware used in targeted attacks against enterprise networks",
    author: "Darknode Research", date: "2024-01-18", tags: ["ransomware", "ryuk"],
    rule_text: `rule Ryuk_Ransomware {
    meta:
        description = "Detects Ryuk ransomware"
    strings:
        $note = "RyukReadMe" ascii wide
        $ext = ".RYK" ascii
        $hermes = "HERMES" ascii wide
        $inject = "VirtualAllocEx" ascii
        $anti1 = "IsDebuggerPresent" ascii
        $cmd1 = "net stop" ascii
        $cmd2 = "icacls" ascii
        $btc = "bitcoin" ascii nocase
        $marker = { DE AD BE EF }
    condition:
        uint16(0) == 0x5A4D and 4 of them
}`,
    references: ["https://www.crowdstrike.com/blog/big-game-hunting-with-ryuk-another-lucrative-targeted-ransomware/"],
    malware_family: "Ryuk", confidence: "high"
  },
  {
    id: "YARA-RW-007", name: "DarkSide_Ransomware", description: "Detects DarkSide ransomware responsible for Colonial Pipeline attack",
    author: "Darknode Research", date: "2024-02-05", tags: ["ransomware", "darkside"],
    rule_text: `rule DarkSide_Ransomware {
    meta:
        description = "Detects DarkSide ransomware"
    strings:
        $note = "README" ascii
        $cfg_marker = { 52 61 6E 73 6F 6D }
        $lang_check = "GetUserDefaultUILanguage" ascii
        $shadow = "vssadmin.exe Delete Shadows /All /Quiet" ascii
        $svc_stop = "sc  config" ascii
        $wallpaper = "SystemParametersInfoW" ascii
        $cis_check = { 81 F9 19 04 00 00 }
        $api_hash = { E8 ?? ?? ?? ?? 8B D8 85 DB 74 }
    condition:
        uint16(0) == 0x5A4D and filesize < 2MB and 4 of them
}`,
    references: ["https://www.mandiant.com/resources/blog/shining-a-light-on-darkside-ransomware-operations"],
    malware_family: "DarkSide", confidence: "high"
  },
  {
    id: "YARA-RW-008", name: "Maze_Ransomware", description: "Detects Maze ransomware known for double extortion tactics",
    author: "Darknode Research", date: "2024-01-22", tags: ["ransomware", "maze"],
    rule_text: `rule Maze_Ransomware {
    meta:
        description = "Detects Maze ransomware"
    strings:
        $note = "DECRYPT-FILES.txt" ascii
        $pdb = "sss.pdb" ascii
        $mutex = "Global\\x" ascii
        $api1 = "CryptImportKey" ascii
        $api2 = "CryptEncrypt" ascii
        $anti = { 0F 31 2B C1 3D 00 10 00 00 }
        $shadow = "wmic shadowcopy delete" ascii nocase
        $ext = { 2E [4-8] 00 }
    condition:
        uint16(0) == 0x5A4D and ($pdb or $note) and 2 of ($api1, $api2, $anti, $shadow, $mutex)
}`,
    references: ["https://www.mcafee.com/blogs/other-blogs/mcafee-labs/ransomware-maze/"],
    malware_family: "Maze", confidence: "high"
  },
  {
    id: "YARA-RW-009", name: "Hive_Ransomware", description: "Detects Hive ransomware which was disrupted by FBI in 2023",
    author: "Darknode Research", date: "2024-02-12", tags: ["ransomware", "hive"],
    rule_text: `rule Hive_Ransomware {
    meta:
        description = "Detects Hive ransomware variants"
    strings:
        $go1 = "main.main" ascii
        $go2 = "runtime.goexit" ascii
        $note = "HOW_TO_DECRYPT" ascii
        $ext = ".hive" ascii
        $key_marker = "-----BEGIN PUBLIC KEY-----" ascii
        $export = "export-" ascii
        $bat = ".bat" ascii
        $login = "hive" ascii nocase
    condition:
        ($go1 and $go2) and 2 of ($note, $ext, $key_marker, $export)
}`,
    references: ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-321a"],
    malware_family: "Hive", confidence: "high"
  },
  {
    id: "YARA-RW-010", name: "Phobos_Ransomware", description: "Detects Phobos ransomware targeting SMBs via exposed RDP",
    author: "Darknode Research", date: "2024-01-25", tags: ["ransomware", "phobos"],
    rule_text: `rule Phobos_Ransomware {
    meta:
        description = "Detects Phobos ransomware family"
    strings:
        $note1 = "info.hta" ascii
        $note2 = "info.txt" ascii
        $ext1 = ".phobos" ascii
        $ext2 = ".eking" ascii
        $ext3 = ".eight" ascii
        $mutex = "Global\\{" ascii
        $cmd = "bcdedit /set {default} recoveryenabled No" ascii
        $shadow = "vssadmin delete shadows /all /quiet" ascii nocase
        $wbadmin = "wbadmin delete catalog -quiet" ascii nocase
    condition:
        uint16(0) == 0x5A4D and 3 of them
}`,
    references: ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-060a"],
    malware_family: "Phobos", confidence: "high"
  },
  {
    id: "YARA-RW-011", name: "GandCrab_Ransomware", description: "Detects GandCrab ransomware which operated as RaaS before shutting down",
    author: "Darknode Research", date: "2024-01-28", tags: ["ransomware", "gandcrab"],
    rule_text: `rule GandCrab_Ransomware {
    meta:
        description = "Detects GandCrab ransomware"
    strings:
        $note = "GDCB-DECRYPT.txt" ascii wide
        $ext1 = ".GDCB" ascii
        $ext2 = ".CRAB" ascii
        $ext3 = ".KRAB" ascii
        $mutex = "Global\\pc_group=" ascii
        $url = ".onion" ascii
        $salsa = { 65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 20 6B }
        $c2_path = "/curl.php" ascii
    condition:
        uint16(0) == 0x5A4D and 3 of them
}`,
    references: ["https://www.europol.europa.eu/media-press/newsroom/news/no-more-ransom-decrypts-gandcrab"],
    malware_family: "GandCrab", confidence: "high"
  },
  {
    id: "YARA-RW-012", name: "RansomEXX", description: "Detects RansomEXX/Defray777 ransomware targeting enterprises",
    author: "Darknode Research", date: "2024-02-15", tags: ["ransomware", "ransomexx"],
    rule_text: `rule RansomEXX {
    meta:
        description = "Detects RansomEXX ransomware"
    strings:
        $note = "!NEWS_FOR_" ascii
        $elf_magic = { 7F 45 4C 46 }
        $aes = "EVP_EncryptInit_ex" ascii
        $rsa = "RSA_public_encrypt" ascii
        $mutex = "/tmp/.locker" ascii
        $esxi = "esxcli" ascii
        $linux = "/proc/self/exe" ascii
    condition:
        ($elf_magic at 0 or uint16(0) == 0x5A4D) and 3 of ($note, $aes, $rsa, $mutex, $esxi, $linux)
}`,
    references: ["https://securelist.com/ransomexx-trojan-attacks-linux-systems/99279/"],
    malware_family: "RansomEXX", confidence: "high"
  },
  {
    id: "YARA-RW-013", name: "BlackBasta_Ransomware", description: "Detects Black Basta ransomware emerging from Conti operators",
    author: "Darknode Research", date: "2024-03-05", tags: ["ransomware", "blackbasta"],
    rule_text: `rule BlackBasta_Ransomware {
    meta:
        description = "Detects Black Basta ransomware"
    strings:
        $note = "readme.txt" ascii wide
        $ext = ".basta" ascii
        $ico_drop = "fkdjsadasd.ico" ascii
        $wallpaper = "SystemParametersInfoW" ascii
        $thread_enc = "CreateThread" ascii
        $chacha = { 65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 20 6B }
        $shadow = "vssadmin delete shadows" ascii nocase
        $svc = "sc config" ascii
    condition:
        uint16(0) == 0x5A4D and 4 of them
}`,
    references: ["https://unit42.paloaltonetworks.com/threat-assessment-black-basta-ransomware/"],
    malware_family: "BlackBasta", confidence: "high"
  },
  {
    id: "YARA-RW-014", name: "Clop_Ransomware", description: "Detects Clop/Cl0p ransomware known for MOVEit exploitation",
    author: "Darknode Research", date: "2024-02-20", tags: ["ransomware", "clop"],
    rule_text: `rule Clop_Ransomware {
    meta:
        description = "Detects Clop ransomware"
    strings:
        $note = "ClopReadMe.txt" ascii wide
        $ext = ".Clop" ascii
        $note2 = "!!!READ_HERE!!!.RTF" ascii
        $mutex = "BestChangeT0p^" ascii
        $sig = { 43 6C 6F 70 }
        $anti_cis = "GetKeyboardLayoutList" ascii
        $proc_kill = "taskkill" ascii nocase
        $svc_stop = "net stop" ascii nocase
    condition:
        uint16(0) == 0x5A4D and 3 of them
}`,
    references: ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a"],
    malware_family: "Clop", confidence: "high"
  },
  {
    id: "YARA-RW-015", name: "Babuk_Ransomware", description: "Detects Babuk ransomware with leaked source code enabling many variants",
    author: "Darknode Research", date: "2024-01-30", tags: ["ransomware", "babuk"],
    rule_text: `rule Babuk_Ransomware {
    meta:
        description = "Detects Babuk ransomware and variants from leaked builder"
    strings:
        $note = "How To Restore Your Files.txt" ascii
        $ext = ".babyk" ascii
        $ecdh = "curve25519" ascii nocase
        $sosemanuk = { 8B 44 24 ?? 33 44 24 ?? 89 44 24 }
        $esxi_arg = "--path" ascii
        $shares = "NetShareEnum" ascii
        $shadow = "vssadmin" ascii nocase
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and 3 of them
}`,
    references: ["https://www.mcafee.com/blogs/other-blogs/mcafee-labs/babuk-ransomware/"],
    malware_family: "Babuk", confidence: "high"
  },
  {
    id: "YARA-RW-016", name: "Royal_Ransomware", description: "Detects Royal ransomware operated by former Conti Team One members",
    author: "Darknode Research", date: "2024-02-25", tags: ["ransomware", "royal"],
    rule_text: `rule Royal_Ransomware {
    meta:
        description = "Detects Royal ransomware"
    strings:
        $note = "README.TXT" ascii
        $ext = ".royal" ascii
        $partial_enc = { 83 F8 10 7C ?? 8B }
        $openssl = "OpenSSL" ascii
        $aes_ni = { 66 0F 38 DC }
        $shadow = "vssadmin delete" ascii
        $svc = "sc.exe config" ascii
        $network = "GetAdaptersInfo" ascii
    condition:
        uint16(0) == 0x5A4D and 4 of them
}`,
    references: ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-061a"],
    malware_family: "Royal", confidence: "high"
  },
  {
    id: "YARA-RW-017", name: "Akira_Ransomware", description: "Detects Akira ransomware targeting enterprise Linux and Windows systems",
    author: "Darknode Research", date: "2024-03-10", tags: ["ransomware", "akira"],
    rule_text: `rule Akira_Ransomware {
    meta:
        description = "Detects Akira ransomware"
    strings:
        $note = "akira_readme.txt" ascii
        $ext = ".akira" ascii
        $onion = ".onion" ascii
        $rust = "core::panicking" ascii
        $chacha = "ChaCha20" ascii nocase
        $exclude = "winnt" ascii nocase
        $exclude2 = "recycle" ascii nocase
        $power = "powershell" ascii nocase
    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and 3 of ($note, $ext, $onion, $rust, $chacha)
}`,
    references: ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a"],
    malware_family: "Akira", confidence: "high"
  },
  {
    id: "YARA-RW-018", name: "Play_Ransomware", description: "Detects Play ransomware known for intermittent encryption",
    author: "Darknode Research", date: "2024-02-28", tags: ["ransomware", "play"],
    rule_text: `rule Play_Ransomware {
    meta:
        description = "Detects Play ransomware"
    strings:
        $note = "ReadMe" ascii
        $ext = ".play" ascii
        $aes = "CryptEncrypt" ascii
        $rsa = "CryptImportKey" ascii
        $marker = { 50 4C 41 59 }
        $shadow = "wmic shadowcopy delete" ascii nocase
        $disable_av = "Set-MpPreference" ascii
    condition:
        uint16(0) == 0x5A4D and $marker and 2 of ($aes, $rsa, $shadow, $disable_av)
}`,
    references: ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a"],
    malware_family: "Play", confidence: "high"
  },
  {
    id: "YARA-RW-019", name: "Medusa_Ransomware", description: "Detects Medusa ransomware operating as a RaaS",
    author: "Darknode Research", date: "2024-03-15", tags: ["ransomware", "medusa"],
    rule_text: `rule Medusa_Ransomware {
    meta:
        description = "Detects Medusa ransomware"
    strings:
        $note = "!!!READ_ME_MEDUSA!!!.txt" ascii
        $ext = ".MEDUSA" ascii
        $gaze = "gaze.exe" ascii
        $pdb = "medusa" ascii nocase
        $enc = "CryptGenKey" ascii
        $bcdedit = "bcdedit" ascii nocase
        $wbadmin = "wbadmin" ascii nocase
    condition:
        uint16(0) == 0x5A4D and 3 of them
}`,
    references: ["https://unit42.paloaltonetworks.com/medusa-ransomware-escalation-new-leak-site/"],
    malware_family: "Medusa", confidence: "high"
  },
  {
    id: "YARA-RW-020", name: "NoEscape_Ransomware", description: "Detects NoEscape ransomware (Avaddon rebrand)",
    author: "Darknode Research", date: "2024-03-20", tags: ["ransomware", "noescape", "avaddon"],
    rule_text: `rule NoEscape_Ransomware {
    meta:
        description = "Detects NoEscape/Avaddon rebrand ransomware"
    strings:
        $note = "HOW_TO_RECOVER_FILES" ascii
        $salsa = { 65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 20 6B }
        $cis_check = "GetUserDefaultUILanguage" ascii
        $shadow = "vssadmin" ascii
        $safe_boot = "bcdedit" ascii
        $config_json = "\"extension\"" ascii
    condition:
        uint16(0) == 0x5A4D and $salsa and 2 of ($note, $cis_check, $shadow, $safe_boot, $config_json)
}`,
    references: [], malware_family: "NoEscape", confidence: "medium"
  },
  {
    id: "YARA-RW-021", name: "AvosLocker_Ransomware", description: "Detects AvosLocker ransomware targeting Windows and Linux",
    author: "Darknode Research", date: "2024-02-01", tags: ["ransomware", "avoslocker"],
    rule_text: `rule AvosLocker_Ransomware {
    meta:
        description = "Detects AvosLocker ransomware"
    strings:
        $note = "GET_YOUR_FILES_BACK.txt" ascii
        $ext = ".avos" ascii
        $ext2 = ".avos2" ascii
        $mutex = "AvosLocker" ascii
        $safe_mode = "bcdedit /set safeboot network" ascii
        $aes = "CryptEncrypt" ascii
    condition:
        uint16(0) == 0x5A4D and 3 of them
}`,
    references: ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-352a"],
    malware_family: "AvosLocker", confidence: "high"
  },
  {
    id: "YARA-RW-022", name: "MedusaLocker_Ransomware", description: "Detects MedusaLocker ransomware (distinct from Medusa RaaS)",
    author: "Darknode Research", date: "2024-01-30", tags: ["ransomware", "medusalocker"],
    rule_text: `rule MedusaLocker_Ransomware {
    meta:
        description = "Detects MedusaLocker ransomware"
    strings:
        $note = "HOW_TO_RECOVER_DATA" ascii
        $ext1 = ".encrypted" ascii
        $ext2 = ".ReadInstructions" ascii
        $task = "schtasks" ascii
        $rsa_import = "CryptImportPublicKeyInfo" ascii
        $aes = "CryptEncrypt" ascii
        $persist = "\\Microsoft\\Windows\\Task" ascii
    condition:
        uint16(0) == 0x5A4D and 3 of them
}`,
    references: ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-181a"],
    malware_family: "MedusaLocker", confidence: "high"
  },
  {
    id: "YARA-RW-023", name: "Vice_Society_Ransomware", description: "Detects Vice Society ransomware targeting education sector",
    author: "Darknode Research", date: "2024-02-08", tags: ["ransomware", "vicesociety"],
    rule_text: `rule Vice_Society_Ransomware {
    meta:
        description = "Detects Vice Society ransomware"
    strings:
        $note = "AllYFilesAE" ascii
        $ext = ".v-society" ascii
        $ntdll = "NtQueryInformationProcess" ascii
        $aes = { 0F 11 44 24 ?? 66 0F 38 DC }
        $shadow = "vssadmin" ascii
        $svc = "net stop" ascii
    condition:
        uint16(0) == 0x5A4D and 3 of them
}`,
    references: ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-249a"],
    malware_family: "ViceSociety", confidence: "medium"
  },
  {
    id: "YARA-RW-024", name: "Cuba_Ransomware", description: "Detects Cuba ransomware used in attacks on critical infrastructure",
    author: "Darknode Research", date: "2024-02-10", tags: ["ransomware", "cuba"],
    rule_text: `rule Cuba_Ransomware {
    meta:
        description = "Detects Cuba ransomware"
    strings:
        $note = "!! READ ME !!.txt" ascii
        $ext = ".cuba" ascii
        $marker = "FIDEL" ascii
        $aes = "CryptEncrypt" ascii
        $rsa = "CryptImportKey" ascii
        $shadow = "vssadmin" ascii
    condition:
        uint16(0) == 0x5A4D and $marker and 2 of ($note, $ext, $aes, $rsa)
}`,
    references: ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-335a"],
    malware_family: "Cuba", confidence: "high"
  },
  {
    id: "YARA-RW-025", name: "Qilin_Ransomware", description: "Detects Qilin/Agenda ransomware written in Go and Rust",
    author: "Darknode Research", date: "2024-03-25", tags: ["ransomware", "qilin", "agenda"],
    rule_text: `rule Qilin_Ransomware {
    meta:
        description = "Detects Qilin/Agenda ransomware"
    strings:
        $go = "main.main" ascii
        $rust = "core::panicking" ascii
        $note = "-RECOVER-" ascii
        $cfg = "--config" ascii
        $esxi = "esxcli" ascii
        $ext_cfg = "\"extension\":" ascii
    condition:
        ($go or $rust) and 2 of ($note, $cfg, $esxi, $ext_cfg)
}`,
    references: ["https://www.group-ib.com/blog/qilin-ransomware/"],
    malware_family: "Qilin", confidence: "medium"
  },
  // Additional ransomware 026-050
  {
    id: "YARA-RW-026", name: "Dharma_CrySiS", description: "Detects Dharma/CrySiS ransomware family",
    author: "Darknode Research", date: "2024-01-15", tags: ["ransomware", "dharma", "crysis"],
    rule_text: `rule Dharma_CrySiS { meta: description = "Detects Dharma/CrySiS ransomware" strings: $note = "FILES ENCRYPTED.txt" ascii $ext1 = ".dharma" ascii $ext2 = ".cezar" ascii $ext3 = ".cmb" ascii $email = "[" ascii $mutex = "Global\\\\" ascii $shadow = "vssadmin" ascii condition: uint16(0) == 0x5A4D and 3 of them }`,
    references: [], malware_family: "Dharma", confidence: "high"
  },
  { id: "YARA-RW-027", name: "Cerber_Ransomware", description: "Detects Cerber ransomware with audio ransom demands", author: "Darknode Research", date: "2024-01-15", tags: ["ransomware", "cerber"], rule_text: `rule Cerber_Ransomware { meta: description = "Detects Cerber ransomware" strings: $note = "# DECRYPT MY FILES #" ascii $ext = ".cerber" ascii $audio = ".vbs" ascii $json = "{\"BLOCKEDIPS\":" ascii $udp_flood = { 68 00 00 FF FF } condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "Cerber", confidence: "high" },
  { id: "YARA-RW-028", name: "SamSam_Ransomware", description: "Detects SamSam ransomware targeting healthcare and municipalities", author: "Darknode Research", date: "2024-01-18", tags: ["ransomware", "samsam"], rule_text: `rule SamSam_Ransomware { meta: description = "Detects SamSam ransomware" strings: $note = "HELP_DECRYPT_YOUR_FILES" ascii $dotnet = "_CorExeMain" ascii $runner = "runner1.exe" ascii $pass = "password123" ascii $enc = "RijndaelManaged" ascii condition: uint16(0) == 0x5A4D and $dotnet and 2 of ($note, $runner, $pass, $enc) }`, references: [], malware_family: "SamSam", confidence: "high" },
  { id: "YARA-RW-029", name: "TeslaCrypt_Ransomware", description: "Detects TeslaCrypt ransomware targeting gamers", author: "Darknode Research", date: "2024-01-20", tags: ["ransomware", "teslacrypt"], rule_text: `rule TeslaCrypt { meta: description = "Detects TeslaCrypt" strings: $note = "HELP_RESTORE_FILES" ascii $ext1 = ".vvv" ascii $ext2 = ".micro" ascii $storage = "key.dat" ascii $btc = "bitcoin" ascii nocase condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "TeslaCrypt", confidence: "high" },
  { id: "YARA-RW-030", name: "Petya_NotPetya", description: "Detects Petya/NotPetya MBR-encrypting ransomware", author: "Darknode Research", date: "2024-01-22", tags: ["ransomware", "petya", "notpetya", "wiper"], rule_text: `rule Petya_NotPetya { meta: description = "Detects Petya/NotPetya" strings: $mbr_overwrite = { B8 00 80 8E D0 BC 00 7C } $salsa = { 65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 20 6B } $psexec = "psexec" ascii nocase $wmic = "wmic" ascii nocase $eternalblue = { 17 00 00 00 00 00 00 00 } $note = "Ooops, your important files are encrypted" ascii condition: 3 of them }`, references: ["https://www.us-cert.gov/ncas/alerts/TA17-181A"], malware_family: "NotPetya", confidence: "high" },
  { id: "YARA-RW-031", name: "LockerGoga_Ransomware", description: "Detects LockerGoga ransomware targeting industrial companies", author: "Darknode Research", date: "2024-01-25", tags: ["ransomware", "lockergoga"], rule_text: `rule LockerGoga { meta: description = "Detects LockerGoga" strings: $note = "README_LOCKED.txt" ascii $ext = ".locked" ascii $boost = "boost::" ascii $openssl = "OpenSSL" ascii $logoff = "logoff.exe" ascii condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "LockerGoga", confidence: "high" },
  { id: "YARA-RW-032", name: "Ragnar_Locker", description: "Detects Ragnar Locker ransomware using VM-based evasion", author: "Darknode Research", date: "2024-01-28", tags: ["ransomware", "ragnarlocker"], rule_text: `rule Ragnar_Locker { meta: description = "Detects Ragnar Locker" strings: $note = "RGNR_" ascii $vbox = "VirtualBox" ascii $vm_deploy = "va.exe" ascii $salsa = { 65 78 70 61 6E 64 20 33 32 } $shadow = "vssadmin" ascii condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "RagnarLocker", confidence: "high" },
  { id: "YARA-RW-033", name: "Egregor_Ransomware", description: "Detects Egregor ransomware (Maze successor)", author: "Darknode Research", date: "2024-02-01", tags: ["ransomware", "egregor"], rule_text: `rule Egregor { meta: description = "Detects Egregor ransomware" strings: $note = "RECOVER-FILES.txt" ascii $dll = "DllRegisterServer" ascii $pass = "--password" ascii $printer = "winspool" ascii $anti = "IsDebuggerPresent" ascii condition: uint16(0) == 0x5A4D and $dll and 2 of ($note, $pass, $printer) }`, references: [], malware_family: "Egregor", confidence: "high" },
  { id: "YARA-RW-034", name: "Ragnarok_Ransomware", description: "Detects Ragnarok ransomware", author: "Darknode Research", date: "2024-02-05", tags: ["ransomware", "ragnarok"], rule_text: `rule Ragnarok { meta: description = "Detects Ragnarok ransomware" strings: $note = "How_To_Decrypt_My_Files" ascii $ext = ".ragnarok_cry" ascii $enc = "CryptEncrypt" ascii $shadow = "vssadmin" ascii condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "Ragnarok", confidence: "medium" },
  { id: "YARA-RW-035", name: "Netwalker_Ransomware", description: "Detects Netwalker/Mailto ransomware", author: "Darknode Research", date: "2024-02-08", tags: ["ransomware", "netwalker", "mailto"], rule_text: `rule Netwalker { meta: description = "Detects Netwalker ransomware" strings: $ps_loader = "IEX" ascii $reflective = "[System.Reflection.Assembly]" ascii $note = "Readme.txt" ascii $ext = ".mailto" ascii $powershell = "powershell" ascii nocase condition: 3 of them }`, references: [], malware_family: "Netwalker", confidence: "high" },
  { id: "YARA-RW-036", name: "Zeppelin_Ransomware", description: "Detects Zeppelin ransomware (Buran variant)", author: "Darknode Research", date: "2024-02-10", tags: ["ransomware", "zeppelin"], rule_text: `rule Zeppelin { meta: description = "Detects Zeppelin/Buran" strings: $note = "!!! ALL YOUR FILES ARE ENCRYPTED !!!" ascii $delphi = "Borland" ascii $config = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" ascii $shadow = "vssadmin" ascii condition: uint16(0) == 0x5A4D and 3 of them }`, references: ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-223a"], malware_family: "Zeppelin", confidence: "high" },
  { id: "YARA-RW-037", name: "BlackMatter_Ransomware", description: "Detects BlackMatter ransomware (DarkSide successor)", author: "Darknode Research", date: "2024-02-12", tags: ["ransomware", "blackmatter"], rule_text: `rule BlackMatter { meta: description = "Detects BlackMatter ransomware" strings: $api_hash_routine = { 8B 45 ?? 6A 0D 5A F7 E2 } $note = "readme" ascii $cis = "GetUserDefaultUILanguage" ascii $shadow = "vssadmin" ascii $svc = "sc stop" ascii condition: uint16(0) == 0x5A4D and $api_hash_routine and 2 of ($note, $cis, $shadow, $svc) }`, references: ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-291a"], malware_family: "BlackMatter", confidence: "high" },
  { id: "YARA-RW-038", name: "Yanluowang_Ransomware", description: "Detects Yanluowang ransomware targeting enterprises", author: "Darknode Research", date: "2024-02-15", tags: ["ransomware", "yanluowang"], rule_text: `rule Yanluowang { meta: description = "Detects Yanluowang" strings: $note = "README.txt" ascii $ext = ".yanluowang" ascii $sql_stop = "sqlservr" ascii $exchange = "MSExchange" ascii condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "Yanluowang", confidence: "medium" },
  { id: "YARA-RW-039", name: "Diavol_Ransomware", description: "Detects Diavol ransomware linked to TrickBot operators", author: "Darknode Research", date: "2024-02-18", tags: ["ransomware", "diavol"], rule_text: `rule Diavol { meta: description = "Detects Diavol ransomware" strings: $note = "README_FOR_DECRYPT" ascii $ext = ".lock64" ascii $gdi = "GdipSaveImageToFile" ascii $bmp_note = "locker.bmp" ascii $rsa = "CryptImportKey" ascii condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "Diavol", confidence: "high" },
  { id: "YARA-RW-040", name: "Trigona_Ransomware", description: "Detects Trigona ransomware targeting MSSQL servers", author: "Darknode Research", date: "2024-02-20", tags: ["ransomware", "trigona"], rule_text: `rule Trigona { meta: description = "Detects Trigona ransomware" strings: $note = "how_to_decrypt" ascii $ext = "._locked" ascii $delphi = "Borland" ascii $aes = "CryptEncrypt" ascii $mssql = "sqlservr" ascii condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "Trigona", confidence: "medium" },
  { id: "YARA-RW-041", name: "INC_Ransom", description: "Detects INC ransomware", author: "Darknode Research", date: "2024-03-01", tags: ["ransomware", "inc"], rule_text: `rule INC_Ransom { meta: description = "Detects INC ransomware" strings: $note = "INC-README.txt" ascii $ext = ".INC" ascii $html_note = "INC-README.html" ascii $mplog = "MpCmdRun" ascii condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "INC", confidence: "medium" },
  { id: "YARA-RW-042", name: "8Base_Ransomware", description: "Detects 8Base ransomware (Phobos variant)", author: "Darknode Research", date: "2024-03-05", tags: ["ransomware", "8base"], rule_text: `rule EightBase { meta: description = "Detects 8Base ransomware" strings: $note = "info.hta" ascii $ext = ".8base" ascii $mutex = "Global\\{" ascii $shadow = "vssadmin" ascii $persist = "schtasks" ascii condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "8Base", confidence: "medium" },
  { id: "YARA-RW-043", name: "Rhysida_Ransomware", description: "Detects Rhysida ransomware targeting healthcare", author: "Darknode Research", date: "2024-03-10", tags: ["ransomware", "rhysida"], rule_text: `rule Rhysida { meta: description = "Detects Rhysida ransomware" strings: $note = "CriticalBreachDetected.pdf" ascii $ext = ".rhysida" ascii $chacha = "ChaCha20" ascii nocase $rsa_key = "-----BEGIN PUBLIC KEY-----" ascii $ps = "powershell" ascii nocase condition: (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F) and 3 of them }`, references: ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-319a"], malware_family: "Rhysida", confidence: "high" },
  { id: "YARA-RW-044", name: "Cactus_Ransomware", description: "Detects Cactus ransomware using self-encryption", author: "Darknode Research", date: "2024-03-12", tags: ["ransomware", "cactus"], rule_text: `rule Cactus_Ransomware { meta: description = "Detects Cactus ransomware" strings: $note = "cAcTuS.readme.txt" ascii $ext = ".cts" ascii $self_decrypt = "7za.exe" ascii $openssl = "OpenSSL" ascii condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "Cactus", confidence: "medium" },
  { id: "YARA-RW-045", name: "BianLian_Ransomware", description: "Detects BianLian ransomware (Go-based)", author: "Darknode Research", date: "2024-03-15", tags: ["ransomware", "bianlian", "go"], rule_text: `rule BianLian { meta: description = "Detects BianLian ransomware" strings: $go = "main.main" ascii $note = "Look at this instruction.txt" ascii $ext = ".bianlian" ascii $enc_routine = "encryptFile" ascii condition: $go and 2 of ($note, $ext, $enc_routine) }`, references: ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-136a"], malware_family: "BianLian", confidence: "high" },
  { id: "YARA-RW-046", name: "STOP_Djvu_Ransomware", description: "Detects STOP/Djvu ransomware (most common consumer ransomware)", author: "Darknode Research", date: "2024-01-15", tags: ["ransomware", "stop", "djvu"], rule_text: `rule STOP_Djvu { meta: description = "Detects STOP/Djvu ransomware" strings: $note = "_readme.txt" ascii $marker = { 36 A6 98 D1 } $personal_id = "PERSONAL ID" ascii $salsa = { 65 78 70 61 6E 64 20 33 32 } $api = "api.2ip.ua" ascii condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "STOP/Djvu", confidence: "high" },
  { id: "YARA-RW-047", name: "Magniber_Ransomware", description: "Detects Magniber ransomware targeting South Korea", author: "Darknode Research", date: "2024-02-01", tags: ["ransomware", "magniber"], rule_text: `rule Magniber { meta: description = "Detects Magniber" strings: $note = "READ_ME" ascii $msi = "WindowsInstaller" ascii $js_loader = "WScript.Shell" ascii $cab = { 4D 53 43 46 } condition: 2 of them }`, references: [], malware_family: "Magniber", confidence: "medium" },
  { id: "YARA-RW-048", name: "Snatch_Ransomware", description: "Detects Snatch ransomware rebooting into safe mode", author: "Darknode Research", date: "2024-02-05", tags: ["ransomware", "snatch"], rule_text: `rule Snatch { meta: description = "Detects Snatch ransomware" strings: $go = "main.main" ascii $safe_mode = "bcdedit /set {current} safeboot minimal" ascii $note = "HOW TO RESTORE YOUR FILES" ascii $svc = "SuperBackupMan" ascii condition: ($go or uint16(0) == 0x5A4D) and 2 of ($safe_mode, $note, $svc) }`, references: ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-263a"], malware_family: "Snatch", confidence: "high" },
  { id: "YARA-RW-049", name: "LockBit3_Builder", description: "Detects LockBit 3.0 samples from leaked builder", author: "Darknode Research", date: "2024-03-01", tags: ["ransomware", "lockbit3", "builder"], rule_text: `rule LockBit3_Builder { meta: description = "Detects LockBit 3.0 builder output" strings: $cfg = { 00 00 00 00 [4] 00 00 00 00 [4] 00 00 00 00 } $api_resolve = { 48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC } $note = ".README.txt" ascii $anti = "NtQueryInformationProcess" ascii condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "LockBit3", confidence: "medium" },
  { id: "YARA-RW-050", name: "Ransomware_Generic_Indicators", description: "Generic ransomware behavior indicators", author: "Darknode Research", date: "2024-01-15", tags: ["ransomware", "generic"], rule_text: `rule Ransomware_Generic { meta: description = "Generic ransomware indicators" strings: $s1 = "vssadmin delete shadows" ascii nocase $s2 = "bcdedit /set {default} recoveryenabled no" ascii nocase $s3 = "wbadmin delete catalog" ascii nocase $s4 = "wmic shadowcopy delete" ascii nocase $s5 = "CryptEncrypt" ascii $s6 = "CryptGenKey" ascii $s7 = "YOUR FILES" ascii nocase $s8 = "bitcoin" ascii nocase $s9 = ".onion" ascii condition: uint16(0) == 0x5A4D and 4 of them }`, references: [], malware_family: "Generic", confidence: "medium" },

  // ============================================================
  // TROJANS / RATs (50 rules)
  // ============================================================
  {
    id: "YARA-TR-001", name: "Cobalt_Strike_Beacon", description: "Detects Cobalt Strike Beacon payload in memory or on disk",
    author: "Darknode Research", date: "2024-01-15", tags: ["trojan", "cobaltstrike", "c2", "apt"],
    rule_text: `rule Cobalt_Strike_Beacon {
    meta:
        description = "Detects Cobalt Strike Beacon"
    strings:
        $pipe = "\\\\\\\\.\\\\pipe\\\\" ascii
        $config = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? }
        $xor_key = { 69 68 69 68 }
        $named_pipe = "MSSE-" ascii
        $watermark = { 00 00 BE EF }
        $sleep_mask = { 48 8B 44 24 ?? 48 89 44 24 ?? 48 83 C4 }
        $beacon_str = "%d.%d.%d.%d" ascii
    condition:
        2 of them
}`,
    references: ["https://www.mandiant.com/resources/blog/defining-cobalt-strike-components"],
    malware_family: "CobaltStrike", confidence: "high"
  },
  {
    id: "YARA-TR-002", name: "Emotet_Loader", description: "Detects Emotet banking trojan and loader",
    author: "Darknode Research", date: "2024-01-18", tags: ["trojan", "emotet", "loader", "banking"],
    rule_text: `rule Emotet_Loader {
    meta:
        description = "Detects Emotet trojan/loader"
    strings:
        $s1 = "CreateTimerQueueTimer" ascii
        $s2 = "BCryptGenerateSymmetricKey" ascii
        $reg = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $mutex = "PEM%x" ascii
        $heavens_gate = { 6A 33 E8 ?? ?? ?? ?? 83 C4 04 }
        $epoch_check = { 81 FE ?? ?? ?? ?? 7? }
    condition:
        uint16(0) == 0x5A4D and 3 of them
}`,
    references: ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-110a"],
    malware_family: "Emotet", confidence: "high"
  },
  {
    id: "YARA-TR-003", name: "AsyncRAT_Trojan", description: "Detects AsyncRAT open-source remote access trojan",
    author: "Darknode Research", date: "2024-01-20", tags: ["trojan", "rat", "asyncrat"],
    rule_text: `rule AsyncRAT {
    meta:
        description = "Detects AsyncRAT"
    strings:
        $dotnet = "_CorExeMain" ascii
        $class1 = "AsyncClient" ascii
        $class2 = "HandlePacket" ascii
        $aes = "RijndaelManaged" ascii
        $mutex = "AsyncMutex_" ascii
        $install = "\\AppData\\Roaming\\\\" ascii
        $anti_vm = "vmware" ascii nocase
        $anti_dbg = "CheckRemoteDebuggerPresent" ascii
    condition:
        uint16(0) == 0x5A4D and $dotnet and 3 of ($class1, $class2, $aes, $mutex, $install)
}`,
    references: ["https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp"],
    malware_family: "AsyncRAT", confidence: "high"
  },
  { id: "YARA-TR-004", name: "Remcos_RAT", description: "Detects Remcos RAT (Remote Control & Surveillance)", author: "Darknode Research", date: "2024-01-22", tags: ["trojan", "rat", "remcos"], rule_text: `rule Remcos_RAT { meta: description = "Detects Remcos RAT" strings: $s1 = "Remcos" ascii wide $s2 = "Breaking-Security" ascii $rc4 = { 8A 04 ?? 03 C1 99 F7 } $settings = "SETTINGS" ascii wide $mutex = "Remcos_Mutex" ascii $keylog = "keylog" ascii nocase condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "Remcos", confidence: "high" },
  { id: "YARA-TR-005", name: "QuasarRAT", description: "Detects Quasar RAT open-source trojan", author: "Darknode Research", date: "2024-01-25", tags: ["trojan", "rat", "quasar"], rule_text: `rule QuasarRAT { meta: description = "Detects Quasar RAT" strings: $dotnet = "_CorExeMain" ascii $s1 = "QuasarClient" ascii $s2 = "ClientSocket" ascii $s3 = "GetKeyloggerLogs" ascii $s4 = "HandleGetProcesses" ascii $aes = "AesCryptoServiceProvider" ascii condition: uint16(0) == 0x5A4D and $dotnet and 2 of ($s1, $s2, $s3, $s4) }`, references: ["https://github.com/quasar/Quasar"], malware_family: "QuasarRAT", confidence: "high" },
  { id: "YARA-TR-006", name: "NjRAT", description: "Detects njRAT/Bladabindi trojan", author: "Darknode Research", date: "2024-01-28", tags: ["trojan", "rat", "njrat"], rule_text: `rule NjRAT { meta: description = "Detects njRAT" strings: $dotnet = "_CorExeMain" ascii $s1 = "njRAT" ascii nocase $s2 = "kl.dat" ascii $s3 = "netsh firewall" ascii $s4 = "cmd.exe /k ping" ascii $s5 = "SEE_MASK_NOZONECHECKS" ascii $b64_split = "|'|'" ascii condition: uint16(0) == 0x5A4D and $dotnet and 3 of ($s1, $s2, $s3, $s4, $s5, $b64_split) }`, references: [], malware_family: "njRAT", confidence: "high" },
  { id: "YARA-TR-007", name: "Agent_Tesla", description: "Detects Agent Tesla infostealer/keylogger", author: "Darknode Research", date: "2024-02-01", tags: ["trojan", "infostealer", "agenttesla"], rule_text: `rule Agent_Tesla { meta: description = "Detects Agent Tesla" strings: $dotnet = "_CorExeMain" ascii $s1 = "smtp" ascii nocase $s2 = "keylog" ascii nocase $s3 = "Screenshot" ascii $s4 = "\\passwords.txt" ascii $s5 = "logins" ascii $browser = "\\Mozilla\\Firefox\\Profiles" ascii $chrome = "\\Google\\Chrome\\User Data" ascii condition: uint16(0) == 0x5A4D and $dotnet and 3 of ($s1, $s2, $s3, $s4, $s5, $browser, $chrome) }`, references: [], malware_family: "AgentTesla", confidence: "high" },
  { id: "YARA-TR-008", name: "DarkComet_RAT", description: "Detects DarkComet RAT", author: "Darknode Research", date: "2024-02-05", tags: ["trojan", "rat", "darkcomet"], rule_text: `rule DarkComet_RAT { meta: description = "Detects DarkComet RAT" strings: $s1 = "DarkComet" ascii $s2 = "DC_MUTEX-" ascii $s3 = "#BOT#" ascii $s4 = "YOURINFOMATION" ascii $s5 = "EditSERVER" ascii $pdb = "DarkComet" ascii condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "DarkComet", confidence: "high" },
  { id: "YARA-TR-009", name: "Sliver_C2", description: "Detects Sliver C2 framework implant", author: "Darknode Research", date: "2024-02-08", tags: ["trojan", "c2", "sliver"], rule_text: `rule Sliver_C2 { meta: description = "Detects Sliver C2 implant" strings: $go = "main.main" ascii $s1 = "sliverpb" ascii $s2 = "github.com/bishopfox/sliver" ascii $mtls = "grpc" ascii $wg = "WireGuard" ascii nocase $dns = "dnsclient" ascii condition: ($go) and 2 of ($s1, $s2, $mtls, $wg, $dns) }`, references: ["https://github.com/BishopFox/sliver"], malware_family: "Sliver", confidence: "high" },
  { id: "YARA-TR-010", name: "Meterpreter_Reverse_TCP", description: "Detects Metasploit Meterpreter reverse TCP payload", author: "Darknode Research", date: "2024-01-15", tags: ["trojan", "meterpreter", "metasploit"], rule_text: `rule Meterpreter_Reverse_TCP { meta: description = "Detects Meterpreter reverse TCP" strings: $api1 = "WSASocketA" ascii $api2 = "InternetOpenA" ascii $stage = { 6A 10 56 57 68 99 A5 74 61 } $recv_loop = { 8B 4E 08 89 0E 6A 40 68 00 10 00 00 } condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "Meterpreter", confidence: "high" },
  { id: "YARA-TR-011", name: "TrickBot_Trojan", description: "Detects TrickBot modular banking trojan", author: "Darknode Research", date: "2024-02-10", tags: ["trojan", "trickbot", "banking"], rule_text: `rule TrickBot { meta: description = "Detects TrickBot" strings: $s1 = "moduleconfig" ascii $s2 = "injectDll" ascii $s3 = "mailsearcher" ascii $s4 = "networkDll" ascii $s5 = "tab_browser" ascii $bot_id = "group_tag" ascii $cfg = "<mcconf>" ascii condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "TrickBot", confidence: "high" },
  { id: "YARA-TR-012", name: "QakBot_Trojan", description: "Detects QakBot/Qbot banking trojan", author: "Darknode Research", date: "2024-02-12", tags: ["trojan", "qakbot", "qbot"], rule_text: `rule QakBot { meta: description = "Detects QakBot" strings: $dll = "DllRegisterServer" ascii $anti = "IsDebuggerPresent" ascii $env = "SELF_TEST_ID" ascii $cfg_rc4 = { 8B 45 ?? 33 45 ?? 89 45 ?? } $inject = "explorer.exe" ascii wide $xor_cfg = { 31 ?? 83 ?? 04 3B ?? 72 } condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "QakBot", confidence: "high" },
  { id: "YARA-TR-013", name: "BumbleBee_Loader", description: "Detects BumbleBee loader used by initial access brokers", author: "Darknode Research", date: "2024-02-15", tags: ["trojan", "loader", "bumblebee"], rule_text: `rule BumbleBee { meta: description = "Detects BumbleBee loader" strings: $s1 = "bomberlib" ascii $s2 = "GetUserNameA" ascii $s3 = "\\System32\\wab.exe" ascii $uuid = "SELECT * FROM Win32_ComputerSystemProduct" ascii $anti_sandbox = "GetTickCount" ascii condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "BumbleBee", confidence: "high" },
  { id: "YARA-TR-014", name: "IcedID_BokBot", description: "Detects IcedID/BokBot banking trojan", author: "Darknode Research", date: "2024-02-18", tags: ["trojan", "icedid", "bokbot"], rule_text: `rule IcedID { meta: description = "Detects IcedID/BokBot" strings: $dll_export = "DllRegisterServer" ascii $gzip = { 1F 8B 08 } $cfg_marker = { 00 00 [2] 00 00 00 00 [4] 00 00 } $ua = "Mozilla/5.0" ascii $cookie_exfil = "Cookie:" ascii condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "IcedID", confidence: "medium" },
  { id: "YARA-TR-015", name: "Havoc_C2", description: "Detects Havoc C2 framework demon agent", author: "Darknode Research", date: "2024-02-20", tags: ["trojan", "c2", "havoc"], rule_text: `rule Havoc_C2 { meta: description = "Detects Havoc C2 implant" strings: $s1 = "HavocFramework" ascii $s2 = "github.com/HavocFramework" ascii $demon = "demon" ascii $config_flag = { 44 45 41 44 42 45 45 46 } condition: 2 of them }`, references: ["https://github.com/HavocFramework/Havoc"], malware_family: "Havoc", confidence: "high" },
  { id: "YARA-TR-016", name: "Brute_Ratel_C4", description: "Detects Brute Ratel C4 adversary simulation framework", author: "Darknode Research", date: "2024-02-22", tags: ["trojan", "c2", "bruteratel"], rule_text: `rule Brute_Ratel_C4 { meta: description = "Detects Brute Ratel C4 Badger" strings: $s1 = "bruteratel" ascii nocase $s2 = "badger" ascii $cfg = { 42 52 43 34 } $syscall = "NtAllocateVirtualMemory" ascii $indirect = "SystemFunction032" ascii condition: 2 of them }`, references: [], malware_family: "BruteRatel", confidence: "high" },
  { id: "YARA-TR-017", name: "Mythic_Agent", description: "Detects Mythic C2 framework agents", author: "Darknode Research", date: "2024-02-25", tags: ["trojan", "c2", "mythic"], rule_text: `rule Mythic_Agent { meta: description = "Detects Mythic C2 agents" strings: $go = "main.main" ascii $s1 = "mythic" ascii nocase $s2 = "apfell" ascii nocase $s3 = "poseidon" ascii nocase $uuid = "UUID" ascii $callback = "callback_host" ascii condition: ($go or uint16(0) == 0x5A4D) and 2 of ($s1, $s2, $s3, $uuid, $callback) }`, references: ["https://github.com/its-a-feature/Mythic"], malware_family: "Mythic", confidence: "medium" },
  { id: "YARA-TR-018", name: "RedLine_Stealer", description: "Detects RedLine infostealer", author: "Darknode Research", date: "2024-03-01", tags: ["trojan", "stealer", "redline"], rule_text: `rule RedLine_Stealer { meta: description = "Detects RedLine" strings: $dotnet = "_CorExeMain" ascii $s1 = "StringDecrypt" ascii $s2 = "ScanningArgs" ascii $s3 = "SystemHardware" ascii $browser = "Login Data" ascii $wallet = "wallet.dat" ascii condition: uint16(0) == 0x5A4D and $dotnet and 3 of ($s1, $s2, $s3, $browser, $wallet) }`, references: [], malware_family: "RedLine", confidence: "high" },
  { id: "YARA-TR-019", name: "Raccoon_Stealer", description: "Detects Raccoon Stealer infostealer", author: "Darknode Research", date: "2024-03-05", tags: ["trojan", "stealer", "raccoon"], rule_text: `rule Raccoon_Stealer { meta: description = "Detects Raccoon Stealer v2" strings: $cfg_url = "/aN7jD0qO6kT5bK5bQ4eR8fE1xP7hL2" ascii $machineId = "MachineGuid" ascii $steal1 = "passwords.txt" ascii $steal2 = "cookies.txt" ascii $steal3 = "autofill.txt" ascii condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "Raccoon", confidence: "high" },
  { id: "YARA-TR-020", name: "Vidar_Stealer", description: "Detects Vidar infostealer", author: "Darknode Research", date: "2024-03-08", tags: ["trojan", "stealer", "vidar"], rule_text: `rule Vidar_Stealer { meta: description = "Detects Vidar stealer" strings: $dep1 = "freebl3.dll" ascii $dep2 = "mozglue.dll" ascii $dep3 = "nss3.dll" ascii $dep4 = "softokn3.dll" ascii $profile = "\\steam\\config" ascii nocase condition: uint16(0) == 0x5A4D and 3 of ($dep1, $dep2, $dep3, $dep4) }`, references: [], malware_family: "Vidar", confidence: "high" },
  { id: "YARA-TR-021", name: "Lumma_Stealer", description: "Detects LummaC2/Lumma Stealer", author: "Darknode Research", date: "2024-03-10", tags: ["trojan", "stealer", "lumma"], rule_text: `rule Lumma_Stealer { meta: description = "Detects Lumma Stealer" strings: $s1 = "LummaC" ascii $ua = "Mozilla/5.0" ascii $grab = "autofill" ascii $crypto = "Electrum" ascii $browser = "\\Local Storage\\leveldb" ascii condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "Lumma", confidence: "medium" },
  { id: "YARA-TR-022", name: "Formbook_XLoader", description: "Detects Formbook/XLoader form grabber", author: "Darknode Research", date: "2024-03-12", tags: ["trojan", "formbook", "xloader"], rule_text: `rule Formbook_XLoader { meta: description = "Detects Formbook/XLoader" strings: $sha1 = { 8B 45 ?? 33 45 ?? C1 C0 05 03 C6 } $inject = "ntdll.dll" ascii $hashing = { C1 ?? 0D 03 }  $anti = "sbiedll.dll" ascii $config_decrypt = { 8A 04 ?? 34 ?? 88 04 ?? } condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "Formbook", confidence: "high" },
  { id: "YARA-TR-023", name: "ShadowPad_Backdoor", description: "Detects ShadowPad modular backdoor (Chinese APT)", author: "Darknode Research", date: "2024-02-01", tags: ["trojan", "backdoor", "shadowpad", "apt"], rule_text: `rule ShadowPad { meta: description = "Detects ShadowPad backdoor" strings: $decrypt = { 8B 45 ?? 33 45 ?? 89 45 ?? 8B 45 ?? 33 45 ?? } $plugin = "PluginBase" ascii $c2_config = { 00 [4] FF FF FF FF 00 00 [2] } $module_mgr = "ModuleManager" ascii condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "ShadowPad", confidence: "high" },
  { id: "YARA-TR-024", name: "PlugX_Backdoor", description: "Detects PlugX/Korplug backdoor (Chinese APT)", author: "Darknode Research", date: "2024-02-05", tags: ["trojan", "backdoor", "plugx", "apt"], rule_text: `rule PlugX { meta: description = "Detects PlugX/Korplug" strings: $xor_decode = { 8A 04 ?? 34 ?? 88 04 ?? 4? 3B ?? 72 } $sideload_dll = "DllMain" ascii $config_marker = { 58 58 58 58 58 58 58 58 } $persistence = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "PlugX", confidence: "medium" },
  { id: "YARA-TR-025", name: "Gh0st_RAT", description: "Detects Gh0st RAT and variants", author: "Darknode Research", date: "2024-02-08", tags: ["trojan", "rat", "gh0st"], rule_text: `rule Gh0st_RAT { meta: description = "Detects Gh0st RAT" strings: $header = "Gh0st" ascii $zlib = { 78 9C } $keylog = "keylog" ascii nocase $screen = "ScreenCapture" ascii $shell = "CmdShell" ascii condition: $header and 2 of ($keylog, $screen, $shell) }`, references: [], malware_family: "Gh0stRAT", confidence: "high" },
  // TR-026 through TR-050 — additional trojans/RATs
  { id: "YARA-TR-026", name: "PoisonIvy_RAT", description: "Detects Poison Ivy RAT", author: "Darknode Research", date: "2024-02-10", tags: ["trojan", "rat", "poisonivy"], rule_text: `rule PoisonIvy { meta: description = "Detects Poison Ivy" strings: $mutex = "())(!@#$" ascii $stub = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 04 C3 } $camellia = { 8B 44 24 04 53 55 56 57 } condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "PoisonIvy", confidence: "high" },
  { id: "YARA-TR-027", name: "AZORult_Stealer", description: "Detects AZORult infostealer", author: "Darknode Research", date: "2024-02-12", tags: ["trojan", "stealer", "azorult"], rule_text: `rule AZORult { meta: description = "Detects AZORult stealer" strings: $s1 = "passwords.txt" ascii $s2 = "cookies.txt" ascii $xor = { 30 ?? 4? 3B ?? 72 } $ua = "AZORult" ascii condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "AZORult", confidence: "high" },
  { id: "YARA-TR-028", name: "Ursnif_Gozi", description: "Detects Ursnif/Gozi banking trojan", author: "Darknode Research", date: "2024-02-15", tags: ["trojan", "banking", "ursnif"], rule_text: `rule Ursnif_Gozi { meta: description = "Detects Ursnif/Gozi" strings: $s1 = "client.dll" ascii $s2 = "serpent" ascii $join = "soft=%u&version=%u&user=%08x" ascii $tor = "torproject" ascii condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "Ursnif", confidence: "high" },
  { id: "YARA-TR-029", name: "Dridex_Trojan", description: "Detects Dridex/Cridex banking trojan", author: "Darknode Research", date: "2024-02-18", tags: ["trojan", "banking", "dridex"], rule_text: `rule Dridex { meta: description = "Detects Dridex" strings: $vba_drop = "Auto_Open" ascii $dll_export = "DllRegisterServer" ascii $rc4 = { 8A 04 ?? 03 C1 25 FF 00 00 00 } $inject = "NtCreateSection" ascii condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "Dridex", confidence: "medium" },
  { id: "YARA-TR-030", name: "SystemBC_Proxy", description: "Detects SystemBC proxy bot", author: "Darknode Research", date: "2024-02-20", tags: ["trojan", "proxy", "systembc"], rule_text: `rule SystemBC { meta: description = "Detects SystemBC" strings: $xor_key = { 48 ?? ?? ?? ?? 34 ?? 88 } $tor = ".onion" ascii $socks5 = { 05 01 00 } $config = "BEGIN_" ascii condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "SystemBC", confidence: "medium" },
  { id: "YARA-TR-031", name: "Amadey_Bot", description: "Detects Amadey dropper bot", author: "Darknode Research", date: "2024-02-22", tags: ["trojan", "loader", "amadey"], rule_text: `rule Amadey { meta: description = "Detects Amadey" strings: $ua = "Amadey" ascii $report = "id=%s&vs=%s&sd=%s&os=%s&bi=%s" ascii $cmd = "cmd /c timeout" ascii $persist = "schtasks" ascii condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "Amadey", confidence: "high" },
  { id: "YARA-TR-032", name: "SmokeLoader", description: "Detects SmokeLoader downloader/bot", author: "Darknode Research", date: "2024-02-25", tags: ["trojan", "loader", "smokeloader"], rule_text: `rule SmokeLoader { meta: description = "Detects SmokeLoader" strings: $anti1 = "SbieDll" ascii $anti2 = "dbghelp" ascii $inject = "NtWriteVirtualMemory" ascii $hollow = "NtUnmapViewOfSection" ascii $explorer = "explorer.exe" ascii wide condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "SmokeLoader", confidence: "medium" },
  { id: "YARA-TR-033", name: "Phemedrone_Stealer", description: "Detects Phemedrone infostealer", author: "Darknode Research", date: "2024-03-01", tags: ["trojan", "stealer", "phemedrone"], rule_text: `rule Phemedrone { meta: description = "Detects Phemedrone stealer" strings: $dotnet = "_CorExeMain" ascii $s1 = "Phemedrone" ascii $s2 = "GrabBrowserData" ascii $s3 = "GrabCryptoWallets" ascii $tg = "api.telegram.org" ascii condition: uint16(0) == 0x5A4D and $dotnet and 2 of ($s1, $s2, $s3, $tg) }`, references: [], malware_family: "Phemedrone", confidence: "high" },
  { id: "YARA-TR-034", name: "DanaBot_Trojan", description: "Detects DanaBot banking trojan", author: "Darknode Research", date: "2024-03-05", tags: ["trojan", "banking", "danabot"], rule_text: `rule DanaBot { meta: description = "Detects DanaBot" strings: $s1 = "zlib1.dll" ascii $s2 = "tor.dll" ascii $s3 = "vnc.dll" ascii $s4 = "stealer.dll" ascii $cfg = { 00 00 [4] 00 00 [4] FF FF FF FF } condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "DanaBot", confidence: "medium" },
  { id: "YARA-TR-035", name: "Warzone_RAT", description: "Detects Warzone/AveMaria RAT", author: "Darknode Research", date: "2024-03-08", tags: ["trojan", "rat", "warzone"], rule_text: `rule Warzone_RAT { meta: description = "Detects Warzone RAT" strings: $s1 = "AVE_MARIA" ascii $s2 = "warzone" ascii nocase $rdp = "RDPWrap" ascii $uac = "pkgmgr.exe" ascii $keylog = "keylog" ascii nocase condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "Warzone", confidence: "high" },
  { id: "YARA-TR-036", name: "XWorm_RAT", description: "Detects XWorm RAT", author: "Darknode Research", date: "2024-03-10", tags: ["trojan", "rat", "xworm"], rule_text: `rule XWorm { meta: description = "Detects XWorm RAT" strings: $dotnet = "_CorExeMain" ascii $s1 = "XWorm" ascii $s2 = "XClient" ascii $mutex = "XWorm_" ascii $tg = "api.telegram.org" ascii condition: uint16(0) == 0x5A4D and $dotnet and 2 of ($s1, $s2, $mutex, $tg) }`, references: [], malware_family: "XWorm", confidence: "high" },
  { id: "YARA-TR-037", name: "Raspberry_Robin", description: "Detects Raspberry Robin USB worm", author: "Darknode Research", date: "2024-03-12", tags: ["trojan", "worm", "raspberryrobin"], rule_text: `rule Raspberry_Robin { meta: description = "Detects Raspberry Robin" strings: $lnk_cmd = "cmd /R " ascii $msiexec = "msiexec" ascii nocase $q_param = "/q" ascii $usb = "removable" ascii nocase $obf = { 63 6D 64 20 2F [1-5] 20 } condition: 3 of them }`, references: [], malware_family: "RaspberryRobin", confidence: "medium" },
  { id: "YARA-TR-038", name: "Rhadamanthys_Stealer", description: "Detects Rhadamanthys stealer", author: "Darknode Research", date: "2024-03-15", tags: ["trojan", "stealer", "rhadamanthys"], rule_text: `rule Rhadamanthys { meta: description = "Detects Rhadamanthys" strings: $s1 = "Rhadamanthys" ascii nocase $shellcode = { E8 00 00 00 00 58 } $crypto = "\\wallets\\" ascii nocase $browser = "\\Login Data" ascii condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "Rhadamanthys", confidence: "medium" },
  { id: "YARA-TR-039", name: "Stealc_Stealer", description: "Detects Stealc infostealer", author: "Darknode Research", date: "2024-03-18", tags: ["trojan", "stealer", "stealc"], rule_text: `rule Stealc { meta: description = "Detects Stealc stealer" strings: $s1 = "Mozilla Firefox" ascii $s2 = "Google Chrome" ascii $s3 = "passwords.txt" ascii $s4 = "screenshot.jpg" ascii $hw = "SELECT * FROM Win32_Processor" ascii condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "Stealc", confidence: "medium" },
  { id: "YARA-TR-040", name: "PikaBot_Loader", description: "Detects PikaBot loader", author: "Darknode Research", date: "2024-03-20", tags: ["trojan", "loader", "pikabot"], rule_text: `rule PikaBot { meta: description = "Detects PikaBot" strings: $anti1 = "GetSystemFirmwareTable" ascii $anti2 = "EnumSystemLocalesA" ascii $inject = "NtCreateThreadEx" ascii $lang = "GetKeyboardLayoutList" ascii condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "PikaBot", confidence: "medium" },
  { id: "YARA-TR-041", name: "Latrodectus_Loader", description: "Detects Latrodectus/IceNova loader (IcedID successor)", author: "Darknode Research", date: "2024-03-22", tags: ["trojan", "loader", "latrodectus"], rule_text: `rule Latrodectus { meta: description = "Detects Latrodectus" strings: $dll = "DllRegisterServer" ascii $anti = "GetComputerNameW" ascii $wmi = "Win32_OperatingSystem" ascii $ua = "Mozilla/4.0" ascii $rc4 = { 8A 14 ?? 02 D1 88 14 ?? } condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "Latrodectus", confidence: "medium" },
  { id: "YARA-TR-042", name: "DarkGate_Loader", description: "Detects DarkGate MaaS loader", author: "Darknode Research", date: "2024-03-25", tags: ["trojan", "loader", "darkgate"], rule_text: `rule DarkGate { meta: description = "Detects DarkGate loader" strings: $autoit = "AutoIt" ascii $s1 = "DarkGate" ascii nocase $cfg = "0=" ascii $xor_loop = { 30 ?? 4? 3B ?? 72 } $hkcu = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide condition: 3 of them }`, references: [], malware_family: "DarkGate", confidence: "high" },
  { id: "YARA-TR-043", name: "NanoCore_RAT", description: "Detects NanoCore RAT", author: "Darknode Research", date: "2024-02-01", tags: ["trojan", "rat", "nanocore"], rule_text: `rule NanoCore { meta: description = "Detects NanoCore RAT" strings: $dotnet = "_CorExeMain" ascii $s1 = "NanoCore" ascii $s2 = "NanoCoreBase" ascii $s3 = "ClientPlugin" ascii $guid = "PluginCommand" ascii condition: uint16(0) == 0x5A4D and $dotnet and 2 of ($s1, $s2, $s3, $guid) }`, references: [], malware_family: "NanoCore", confidence: "high" },
  { id: "YARA-TR-044", name: "Netwire_RAT", description: "Detects NetWire RC RAT", author: "Darknode Research", date: "2024-02-05", tags: ["trojan", "rat", "netwire"], rule_text: `rule NetWire { meta: description = "Detects NetWire" strings: $s1 = "NetWire" ascii $s2 = "[Backspace]" ascii $s3 = "[Enter]" ascii $keylog = "Logs\\\\" ascii $mutex = "O49d" ascii condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "NetWire", confidence: "high" },
  { id: "YARA-TR-045", name: "Ramnit_Trojan", description: "Detects Ramnit file infector/banking trojan", author: "Darknode Research", date: "2024-02-08", tags: ["trojan", "banking", "ramnit"], rule_text: `rule Ramnit { meta: description = "Detects Ramnit" strings: $html_inject = "data_inject" ascii $vnc = "vnc_" ascii $ftp_grab = "ftp_grab" ascii $marker = { 52 6D 4E } condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "Ramnit", confidence: "high" },
  { id: "YARA-TR-046", name: "Zloader_Trojan", description: "Detects ZLoader/Zbot banking trojan", author: "Darknode Research", date: "2024-02-10", tags: ["trojan", "banking", "zloader"], rule_text: `rule ZLoader { meta: description = "Detects ZLoader" strings: $bot_id = "botid" ascii $rc4 = { 8A 04 ?? 03 C2 25 FF 00 00 00 } $inject = "NtWriteVirtualMemory" ascii $cfg = "config.bin" ascii condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "ZLoader", confidence: "medium" },
  { id: "YARA-TR-047", name: "Raccoon_v2_Stealer", description: "Detects Raccoon Stealer v2 (C/C++ rewrite)", author: "Darknode Research", date: "2024-02-12", tags: ["trojan", "stealer", "raccoonv2"], rule_text: `rule Raccoon_v2 { meta: description = "Detects Raccoon v2" strings: $s1 = "machineId=" ascii $s2 = "configId=" ascii $s3 = "ews_" ascii $libs = "nss3.dll" ascii $ua = "Mozilla/5.0" ascii condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "Raccoonv2", confidence: "medium" },
  { id: "YARA-TR-048", name: "Jupyter_Infostealer", description: "Detects Jupyter/SolarMarker infostealer", author: "Darknode Research", date: "2024-02-15", tags: ["trojan", "stealer", "jupyter"], rule_text: `rule Jupyter { meta: description = "Detects Jupyter infostealer" strings: $dotnet = "_CorExeMain" ascii $s1 = "SolarMarker" ascii nocase $s2 = "Jupyter" ascii nocase $ps_loader = "powershell" ascii nocase $persist = "\\AppData\\Roaming\\\\" ascii condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "Jupyter", confidence: "medium" },
  { id: "YARA-TR-049", name: "SilverRAT", description: "Detects Silver RAT (Arabic-origin)", author: "Darknode Research", date: "2024-02-18", tags: ["trojan", "rat", "silverrat"], rule_text: `rule SilverRAT { meta: description = "Detects Silver RAT" strings: $dotnet = "_CorExeMain" ascii $s1 = "SilverClient" ascii $s2 = "HandleCommand" ascii $keylog = "StartKeylogger" ascii $tg = "sendDocument" ascii condition: uint16(0) == 0x5A4D and $dotnet and 2 of ($s1, $s2, $keylog, $tg) }`, references: [], malware_family: "SilverRAT", confidence: "medium" },
  { id: "YARA-TR-050", name: "Generic_RAT_Behavior", description: "Generic RAT behavioral indicators", author: "Darknode Research", date: "2024-01-15", tags: ["trojan", "rat", "generic"], rule_text: `rule Generic_RAT { meta: description = "Generic RAT indicators" strings: $keylog = "GetAsyncKeyState" ascii $screen = "BitBlt" ascii $webcam = "capCreateCaptureWindow" ascii $shell = "cmd.exe /c" ascii $download = "URLDownloadToFile" ascii $persist = "CurrentVersion\\Run" ascii wide $inject = "WriteProcessMemory" ascii condition: uint16(0) == 0x5A4D and 4 of them }`, references: [], malware_family: "Generic", confidence: "low" },

  // ============================================================
  // DROPPERS / LOADERS (30 rules)
  // ============================================================
  { id: "YARA-DL-001", name: "ISFB_Dropper", description: "Detects ISFB/Gozi dropper", author: "Darknode Research", date: "2024-01-15", tags: ["dropper", "isfb"], rule_text: `rule ISFB_Dropper { meta: description = "Detects ISFB dropper" strings: $api_hash = { E8 ?? ?? ?? ?? 83 F8 ?? 74 } $persist = "schtasks /create" ascii $payload_xor = { 31 ?? 83 ?? 04 3B ?? 72 } condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "ISFB", confidence: "medium" },
  { id: "YARA-DL-002", name: "Hancitor_Dropper", description: "Detects Hancitor/Chanitor dropper", author: "Darknode Research", date: "2024-01-18", tags: ["dropper", "hancitor"], rule_text: `rule Hancitor { meta: description = "Detects Hancitor" strings: $ua = "Mozilla/5.0" ascii $post = "GUID=%I64u&BUILD=%s&INFO=%s" ascii $api = "VirtualAllocEx" ascii condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "Hancitor", confidence: "high" },
  { id: "YARA-DL-003", name: "GuLoader_Shellcode", description: "Detects GuLoader/CloudEyE shellcode loader", author: "Darknode Research", date: "2024-01-20", tags: ["dropper", "guloader"], rule_text: `rule GuLoader { meta: description = "Detects GuLoader" strings: $anti_dbg = { 64 8B 05 30 00 00 00 0F B6 40 02 } $xor_loop = { 8A 04 ?? 34 ?? 88 04 ?? 4? } $nop_sled = { 90 90 90 90 90 } $vb = "VB5!" ascii condition: 2 of them }`, references: [], malware_family: "GuLoader", confidence: "high" },
  { id: "YARA-DL-004", name: "Emotet_Epoch_Dropper", description: "Detects Emotet epoch-specific dropper", author: "Darknode Research", date: "2024-01-22", tags: ["dropper", "emotet"], rule_text: `rule Emotet_Dropper { meta: description = "Detects Emotet dropper" strings: $macro = "AutoOpen" ascii $ps = "powershell" ascii nocase $wmi = "Win32_Process" ascii $b64 = "FromBase64String" ascii condition: 2 of them }`, references: [], malware_family: "Emotet", confidence: "medium" },
  { id: "YARA-DL-005", name: "Bazar_Loader", description: "Detects BazarLoader/BazarBackdoor", author: "Darknode Research", date: "2024-01-25", tags: ["dropper", "bazarloader"], rule_text: `rule BazarLoader { meta: description = "Detects BazarLoader" strings: $dns_over_https = "dns.google" ascii $emercoin = ".bazar" ascii $inject = "NtCreateThreadEx" ascii $anti = "wine_get_version" ascii condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "BazarLoader", confidence: "high" },
  { id: "YARA-DL-006", name: "Gootloader_JS", description: "Detects Gootloader JavaScript downloader", author: "Darknode Research", date: "2024-01-28", tags: ["dropper", "gootloader", "javascript"], rule_text: `rule Gootloader { meta: description = "Detects Gootloader JS dropper" strings: $wscript = "WScript.Shell" ascii $obf1 = "replace(" ascii $obf2 = "split(" ascii $sched = "schtasks" ascii $ps = "powershell" ascii nocase condition: 3 of them }`, references: [], malware_family: "Gootloader", confidence: "medium" },
  { id: "YARA-DL-007", name: "BATLOADER", description: "Detects BATLOADER dropper using SEO poisoning", author: "Darknode Research", date: "2024-02-01", tags: ["dropper", "batloader"], rule_text: `rule BATLOADER { meta: description = "Detects BATLOADER" strings: $msi = "WindowsInstaller" ascii $bat = "@echo off" ascii nocase $ps_bypass = "-ExecutionPolicy Bypass" ascii nocase $dl = "Invoke-WebRequest" ascii condition: 3 of them }`, references: [], malware_family: "BATLOADER", confidence: "medium" },
  { id: "YARA-DL-008", name: "Qakbot_HTML_Smuggling", description: "Detects QakBot HTML smuggling dropper", author: "Darknode Research", date: "2024-02-05", tags: ["dropper", "qakbot", "htmlsmuggling"], rule_text: `rule Qakbot_HTML_Smuggling { meta: description = "Detects QakBot HTML smuggling" strings: $blob = "new Blob" ascii $atob = "atob(" ascii $createElement = "createElement" ascii $zip_magic = { 50 4B 03 04 } $onclick = "onclick" ascii condition: 3 of ($blob, $atob, $createElement, $onclick) }`, references: [], malware_family: "QakBot", confidence: "medium" },
  { id: "YARA-DL-009", name: "Chromeloader", description: "Detects ChromeLoader browser hijacker dropper", author: "Darknode Research", date: "2024-02-08", tags: ["dropper", "chromeloader"], rule_text: `rule Chromeloader { meta: description = "Detects ChromeLoader" strings: $ps = "powershell" ascii nocase $chrome = "chrome.exe" ascii $extension = "--load-extension" ascii $sched = "schtasks" ascii condition: 3 of them }`, references: [], malware_family: "ChromeLoader", confidence: "high" },
  { id: "YARA-DL-010", name: "OneNote_Malware_Dropper", description: "Detects malicious OneNote files dropping malware", author: "Darknode Research", date: "2024-02-10", tags: ["dropper", "onenote"], rule_text: `rule OneNote_Dropper { meta: description = "Detects malicious OneNote dropper" strings: $onenote = { E4 52 5C 7B 8C D8 A7 4D } $hta = ".hta" ascii $bat = ".bat" ascii $vbs = ".vbs" ascii $cmd = "cmd.exe" ascii $ps = "powershell" ascii nocase condition: $onenote and 2 of ($hta, $bat, $vbs, $cmd, $ps) }`, references: [], malware_family: "OneNote_Dropper", confidence: "medium" },
  { id: "YARA-DL-011", name: "ISO_LNK_Dropper", description: "Detects ISO/IMG files with LNK-based payload delivery", author: "Darknode Research", date: "2024-02-12", tags: ["dropper", "iso", "lnk"], rule_text: `rule ISO_LNK_Dropper { meta: description = "Detects ISO with malicious LNK" strings: $lnk = { 4C 00 00 00 01 14 02 00 } $cmd = "cmd.exe" ascii $rundll = "rundll32" ascii $regsvr = "regsvr32" ascii condition: $lnk and 1 of ($cmd, $rundll, $regsvr) }`, references: [], malware_family: "ISO_Dropper", confidence: "medium" },
  { id: "YARA-DL-012", name: "HTA_Dropper_Generic", description: "Detects generic HTA-based malware droppers", author: "Darknode Research", date: "2024-02-15", tags: ["dropper", "hta"], rule_text: `rule HTA_Dropper { meta: description = "Detects HTA dropper" strings: $hta = "<HTA:APPLICATION" ascii nocase $vbs = "CreateObject" ascii $shell = "WScript.Shell" ascii $ps = "powershell" ascii nocase $dl = "XMLHTTP" ascii condition: $hta and 2 of ($vbs, $shell, $ps, $dl) }`, references: [], malware_family: "HTA_Dropper", confidence: "medium" },
  { id: "YARA-DL-013", name: "VBA_Macro_Dropper", description: "Detects malicious VBA macro droppers in Office documents", author: "Darknode Research", date: "2024-02-18", tags: ["dropper", "vba", "macro"], rule_text: `rule VBA_Macro_Dropper { meta: description = "Detects VBA macro dropper" strings: $auto = "Auto_Open" ascii $auto2 = "Document_Open" ascii $shell = "Shell" ascii $ps = "powershell" ascii nocase $wscript = "WScript" ascii $certutil = "certutil" ascii condition: ($auto or $auto2) and 2 of ($shell, $ps, $wscript, $certutil) }`, references: [], malware_family: "VBA_Dropper", confidence: "medium" },
  // DL-014 through DL-030
  { id: "YARA-DL-014", name: "XLL_Dropper", description: "Detects malicious XLL Excel add-in droppers", author: "Darknode Research", date: "2024-02-20", tags: ["dropper", "xll"], rule_text: `rule XLL_Dropper { meta: description = "Detects XLL dropper" strings: $export = "xlAutoOpen" ascii $dl = "URLDownloadToFile" ascii $exec = "WinExec" ascii condition: uint16(0) == 0x5A4D and $export and ($dl or $exec) }`, references: [], malware_family: "XLL_Dropper", confidence: "high" },
  { id: "YARA-DL-015", name: "MSI_Dropper", description: "Detects malicious MSI installer droppers", author: "Darknode Research", date: "2024-02-22", tags: ["dropper", "msi"], rule_text: `rule MSI_Dropper { meta: description = "Detects malicious MSI dropper" strings: $msi = { D0 CF 11 E0 A1 B1 1A E1 } $custom_action = "CustomAction" ascii wide $cmd = "cmd.exe" ascii $ps = "powershell" ascii nocase condition: $msi at 0 and 2 of ($custom_action, $cmd, $ps) }`, references: [], malware_family: "MSI_Dropper", confidence: "medium" },
  { id: "YARA-DL-016", name: "LNK_Dropper_Powershell", description: "Detects LNK files launching PowerShell payloads", author: "Darknode Research", date: "2024-02-25", tags: ["dropper", "lnk", "powershell"], rule_text: `rule LNK_PS_Dropper { meta: description = "Detects LNK with PowerShell" strings: $lnk = { 4C 00 00 00 01 14 02 00 } $ps = "powershell" ascii nocase $enc = "-enc" ascii nocase $bypass = "-ep bypass" ascii nocase $iex = "IEX" ascii condition: $lnk at 0 and $ps and 1 of ($enc, $bypass, $iex) }`, references: [], malware_family: "LNK_Dropper", confidence: "high" },
  { id: "YARA-DL-017", name: "SVG_Smuggling", description: "Detects SVG-based HTML smuggling", author: "Darknode Research", date: "2024-03-01", tags: ["dropper", "svg", "smuggling"], rule_text: `rule SVG_Smuggling { meta: description = "Detects SVG smuggling" strings: $svg = "<svg" ascii nocase $script = "<script" ascii nocase $b64 = "atob(" ascii $blob = "Blob(" ascii condition: $svg and $script and ($b64 or $blob) }`, references: [], malware_family: "SVG_Smuggler", confidence: "medium" },
  { id: "YARA-DL-018", name: "PDF_JS_Dropper", description: "Detects PDF with embedded JavaScript dropper", author: "Darknode Research", date: "2024-03-05", tags: ["dropper", "pdf"], rule_text: `rule PDF_JS_Dropper { meta: description = "Detects PDF with JS" strings: $pdf = "%PDF-" ascii $js = "/JavaScript" ascii $launch = "/Launch" ascii $uri = "/URI" ascii $embedded = "/EmbeddedFile" ascii condition: $pdf at 0 and 2 of ($js, $launch, $uri, $embedded) }`, references: [], malware_family: "PDF_Dropper", confidence: "medium" },
  { id: "YARA-DL-019", name: "Shellcode_Loader_Generic", description: "Detects generic shellcode loader patterns", author: "Darknode Research", date: "2024-03-08", tags: ["dropper", "shellcode"], rule_text: `rule Shellcode_Loader { meta: description = "Detects shellcode loader" strings: $alloc = "VirtualAlloc" ascii $protect = "VirtualProtect" ascii $thread = "CreateThread" ascii $copy = { F3 A4 } $rwx = { 40 00 00 00 } condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "ShellcodeLoader", confidence: "medium" },
  { id: "YARA-DL-020", name: "Reflective_DLL_Loader", description: "Detects reflective DLL injection loader", author: "Darknode Research", date: "2024-03-10", tags: ["dropper", "reflective", "dll"], rule_text: `rule Reflective_DLL { meta: description = "Detects reflective DLL loader" strings: $mz = { 4D 5A } $pe_search = { 8B ?? 3C [0-2] 81 ?? 50 45 00 00 } $reloc = "IMAGE_BASE_RELOCATION" ascii $api_resolve = { FF 75 ?? E8 ?? ?? ?? ?? 89 45 } condition: $mz at 0 and 2 of ($pe_search, $reloc, $api_resolve) }`, references: [], malware_family: "ReflectiveDLL", confidence: "medium" },
  { id: "YARA-DL-021", name: "NSIS_Dropper", description: "Detects NSIS installer used as dropper", author: "Darknode Research", date: "2024-03-12", tags: ["dropper", "nsis"], rule_text: `rule NSIS_Dropper { meta: description = "Detects malicious NSIS installer" strings: $nsis = "Nullsoft" ascii $nsis2 = "NSIS" ascii $cmd = "cmd.exe" ascii $ps = "powershell" ascii nocase $hidden = "SW_HIDE" ascii condition: ($nsis or $nsis2) and 2 of ($cmd, $ps, $hidden) }`, references: [], malware_family: "NSIS_Dropper", confidence: "low" },
  { id: "YARA-DL-022", name: "SFX_RAR_Dropper", description: "Detects self-extracting RAR archives used as droppers", author: "Darknode Research", date: "2024-03-15", tags: ["dropper", "sfx", "rar"], rule_text: `rule SFX_RAR_Dropper { meta: description = "Detects SFX RAR dropper" strings: $mz = { 4D 5A } $rar = "Rar!" ascii $setup = "Setup=" ascii $silent = "Silent=1" ascii $overwrite = "Overwrite=" ascii condition: $mz at 0 and $rar and 2 of ($setup, $silent, $overwrite) }`, references: [], malware_family: "SFX_Dropper", confidence: "medium" },
  { id: "YARA-DL-023", name: "Donut_Shellcode", description: "Detects Donut shellcode generator output", author: "Darknode Research", date: "2024-03-18", tags: ["dropper", "donut", "shellcode"], rule_text: `rule Donut_Shellcode { meta: description = "Detects Donut-generated shellcode" strings: $amsi_patch = { B8 57 00 07 80 C3 } $clr = "CLRCreateInstance" ascii $amsi = "AmsiScanBuffer" ascii $etw = "EtwEventWrite" ascii condition: 2 of them }`, references: ["https://github.com/TheWover/donut"], malware_family: "Donut", confidence: "high" },
  { id: "YARA-DL-024", name: "SEO_Poisoning_Dropper", description: "Detects SEO poisoning fake installer droppers", author: "Darknode Research", date: "2024-03-20", tags: ["dropper", "seo"], rule_text: `rule SEO_Dropper { meta: description = "Detects SEO poisoning dropper" strings: $msi = "WindowsInstaller" ascii $fake_name = { 53 65 74 75 70 } $temp = "\\AppData\\Local\\Temp\\\\" ascii $run = "ShellExecute" ascii condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "SEO_Dropper", confidence: "low" },
  { id: "YARA-DL-025", name: "WSF_Dropper", description: "Detects Windows Script File droppers", author: "Darknode Research", date: "2024-03-22", tags: ["dropper", "wsf"], rule_text: `rule WSF_Dropper { meta: description = "Detects WSF dropper" strings: $wsf = "<job" ascii nocase $script = "<script" ascii nocase $vbs = "language=\"VBScript\"" ascii nocase $shell = "WScript.Shell" ascii $dl = "XMLHTTP" ascii condition: $wsf and $script and 1 of ($vbs, $shell, $dl) }`, references: [], malware_family: "WSF_Dropper", confidence: "medium" },
  { id: "YARA-DL-026", name: "Python_Dropper", description: "Detects Python-based malware droppers", author: "Darknode Research", date: "2024-03-25", tags: ["dropper", "python"], rule_text: `rule Python_Dropper { meta: description = "Detects Python dropper" strings: $shebang = "#!/usr/bin/python" ascii $import1 = "import subprocess" ascii $import2 = "import socket" ascii $import3 = "import base64" ascii $exec = "exec(" ascii $eval = "eval(" ascii condition: 3 of them }`, references: [], malware_family: "Python_Dropper", confidence: "low" },
  { id: "YARA-DL-027", name: "AutoIt_Dropper", description: "Detects AutoIt compiled malware droppers", author: "Darknode Research", date: "2024-03-01", tags: ["dropper", "autoit"], rule_text: `rule AutoIt_Dropper { meta: description = "Detects AutoIt dropper" strings: $au3 = "AU3!" ascii $compiled = "AutoIt" ascii $run = "Run(" ascii $exec = "Execute(" ascii $obf = "BinaryToString" ascii condition: ($au3 or $compiled) and 1 of ($run, $exec, $obf) }`, references: [], malware_family: "AutoIt_Dropper", confidence: "medium" },
  { id: "YARA-DL-028", name: "CHM_Dropper", description: "Detects compiled HTML help file droppers", author: "Darknode Research", date: "2024-03-05", tags: ["dropper", "chm"], rule_text: `rule CHM_Dropper { meta: description = "Detects CHM dropper" strings: $chm = "ITSF" ascii $script = "<script" ascii nocase $activex = "ActiveXObject" ascii $shell = "WScript.Shell" ascii condition: $chm at 0 and 2 of ($script, $activex, $shell) }`, references: [], malware_family: "CHM_Dropper", confidence: "medium" },
  { id: "YARA-DL-029", name: "Nim_Loader", description: "Detects Nim-compiled malware loaders", author: "Darknode Research", date: "2024-03-08", tags: ["dropper", "nim"], rule_text: `rule Nim_Loader { meta: description = "Detects Nim loader" strings: $nim1 = "NimMain" ascii $nim2 = "@mnim" ascii $http = "HttpOpenRequestW" ascii $alloc = "VirtualAlloc" ascii condition: uint16(0) == 0x5A4D and ($nim1 or $nim2) and ($http or $alloc) }`, references: [], malware_family: "Nim_Loader", confidence: "medium" },
  { id: "YARA-DL-030", name: "Rust_Loader", description: "Detects Rust-compiled malware loaders", author: "Darknode Research", date: "2024-03-10", tags: ["dropper", "rust"], rule_text: `rule Rust_Loader { meta: description = "Detects Rust loader" strings: $rust1 = "core::panicking" ascii $rust2 = "std::rt::lang_start" ascii $http = "reqwest" ascii $inject = "VirtualAllocEx" ascii condition: uint16(0) == 0x5A4D and ($rust1 or $rust2) and ($http or $inject) }`, references: [], malware_family: "Rust_Loader", confidence: "low" },

  // ============================================================
  // WEBSHELLS (30 rules)
  // ============================================================
  { id: "YARA-WS-001", name: "China_Chopper_Webshell", description: "Detects China Chopper one-line webshell", author: "Darknode Research", date: "2024-01-15", tags: ["webshell", "chinachopper"], rule_text: `rule China_Chopper { meta: description = "Detects China Chopper webshell" strings: $asp = "eval(Request" ascii nocase $aspx = "eval(Request.Item" ascii nocase $php = "eval($_POST[" ascii $jsp = "Runtime.getRuntime().exec" ascii condition: any of them }`, references: [], malware_family: "ChinaChopper", confidence: "high" },
  { id: "YARA-WS-002", name: "WSO_Webshell", description: "Detects WSO (Web Shell by oRb) webshell", author: "Darknode Research", date: "2024-01-18", tags: ["webshell", "wso"], rule_text: `rule WSO_Webshell { meta: description = "Detects WSO webshell" strings: $s1 = "WSO" ascii $s2 = "FilesMan" ascii $s3 = "Auth" ascii $s4 = "$auth_pass" ascii $func = "base64_decode" ascii condition: 3 of them }`, references: [], malware_family: "WSO", confidence: "high" },
  { id: "YARA-WS-003", name: "B374k_Webshell", description: "Detects b374k PHP webshell", author: "Darknode Research", date: "2024-01-20", tags: ["webshell", "b374k"], rule_text: `rule B374k { meta: description = "Detects b374k webshell" strings: $s1 = "b374k" ascii nocase $s2 = "eval(gzinflate" ascii $s3 = "$_POST" ascii $s4 = "passthru" ascii condition: 2 of them }`, references: [], malware_family: "b374k", confidence: "high" },
  { id: "YARA-WS-004", name: "C99_Webshell", description: "Detects c99 PHP webshell", author: "Darknode Research", date: "2024-01-22", tags: ["webshell", "c99"], rule_text: `rule C99_Webshell { meta: description = "Detects c99 webshell" strings: $s1 = "c99shell" ascii nocase $s2 = "c99sh" ascii $s3 = "Encoder" ascii $s4 = "FilesTools" ascii $func = "system(" ascii condition: 2 of them }`, references: [], malware_family: "c99", confidence: "high" },
  { id: "YARA-WS-005", name: "R57_Webshell", description: "Detects r57 webshell", author: "Darknode Research", date: "2024-01-25", tags: ["webshell", "r57"], rule_text: `rule R57 { meta: description = "Detects r57 webshell" strings: $s1 = "r57shell" ascii nocase $s2 = "r57" ascii $s3 = "Safe mode" ascii $s4 = "phpinfo()" ascii condition: 2 of them }`, references: [], malware_family: "r57", confidence: "high" },
  { id: "YARA-WS-006", name: "Weevely_Webshell", description: "Detects Weevely PHP webshell", author: "Darknode Research", date: "2024-01-28", tags: ["webshell", "weevely"], rule_text: `rule Weevely { meta: description = "Detects Weevely webshell" strings: $s1 = "$kh=" ascii $s2 = "$kf=" ascii $s3 = "eval(" ascii $s4 = "base64_decode" ascii $s5 = "$_COOKIE" ascii condition: 3 of them }`, references: [], malware_family: "Weevely", confidence: "high" },
  { id: "YARA-WS-007", name: "ASPXSpy_Webshell", description: "Detects ASPXSpy webshell", author: "Darknode Research", date: "2024-02-01", tags: ["webshell", "aspxspy"], rule_text: `rule ASPXSpy { meta: description = "Detects ASPXSpy" strings: $s1 = "ASPXSpy" ascii nocase $s2 = "Process.Start" ascii $s3 = "cmd.exe" ascii $aspx = "<%@ Page" ascii condition: $aspx and 2 of ($s1, $s2, $s3) }`, references: [], malware_family: "ASPXSpy", confidence: "high" },
  { id: "YARA-WS-008", name: "JspSpy_Webshell", description: "Detects JspSpy webshell", author: "Darknode Research", date: "2024-02-05", tags: ["webshell", "jspspy"], rule_text: `rule JspSpy { meta: description = "Detects JspSpy" strings: $s1 = "JspSpy" ascii nocase $s2 = "Runtime.getRuntime()" ascii $s3 = "ProcessBuilder" ascii $jsp = "<%@page" ascii condition: $jsp and 1 of ($s1, $s2, $s3) }`, references: [], malware_family: "JspSpy", confidence: "high" },
  { id: "YARA-WS-009", name: "Godzilla_Webshell", description: "Detects Godzilla Java webshell", author: "Darknode Research", date: "2024-02-08", tags: ["webshell", "godzilla"], rule_text: `rule Godzilla_Webshell { meta: description = "Detects Godzilla webshell" strings: $s1 = "javax.crypto.Cipher" ascii $s2 = "AES/ECB" ascii nocase $s3 = "defineClass" ascii $s4 = "newInstance" ascii $pass = "pass=" ascii condition: 3 of them }`, references: [], malware_family: "Godzilla", confidence: "high" },
  { id: "YARA-WS-010", name: "Behinder_Webshell", description: "Detects Behinder/Bingxie webshell", author: "Darknode Research", date: "2024-02-10", tags: ["webshell", "behinder"], rule_text: `rule Behinder { meta: description = "Detects Behinder" strings: $s1 = "AES" ascii $s2 = "javax.crypto" ascii $s3 = "ClassLoader" ascii $s4 = "defineClass" ascii $php_ver = "openssl_decrypt" ascii condition: 3 of ($s1, $s2, $s3, $s4) or ($php_ver and filesize < 5KB) }`, references: [], malware_family: "Behinder", confidence: "high" },
  { id: "YARA-WS-011", name: "AntSword_Webshell", description: "Detects AntSword webshell", author: "Darknode Research", date: "2024-02-12", tags: ["webshell", "antsword"], rule_text: `rule AntSword { meta: description = "Detects AntSword" strings: $php = "eval(" ascii $post = "$_POST" ascii $assert = "assert(" ascii $create = "create_function" ascii $b64 = "base64_decode" ascii condition: 3 of them and filesize < 10KB }`, references: [], malware_family: "AntSword", confidence: "medium" },
  { id: "YARA-WS-012", name: "PHP_Obfuscated_Webshell", description: "Detects obfuscated PHP webshells", author: "Darknode Research", date: "2024-02-15", tags: ["webshell", "obfuscated", "php"], rule_text: `rule PHP_Obfuscated_Webshell { meta: description = "Detects obfuscated PHP webshell" strings: $eval = "eval(" ascii $gzinf = "gzinflate(" ascii $b64 = "base64_decode(" ascii $rot = "str_rot13(" ascii $preg = "preg_replace" ascii $e_mod = "/e" ascii condition: $eval and 2 of ($gzinf, $b64, $rot) and filesize < 50KB }`, references: [], malware_family: "PHP_Webshell", confidence: "medium" },
  // WS-013 through WS-030
  { id: "YARA-WS-013", name: "PHP_System_Webshell", description: "Detects PHP webshells using system commands", author: "Darknode Research", date: "2024-02-18", tags: ["webshell", "php"], rule_text: `rule PHP_System_Shell { strings: $s1 = "system($_" ascii $s2 = "exec($_" ascii $s3 = "passthru($_" ascii $s4 = "shell_exec($_" ascii $s5 = "popen($_" ascii condition: any of them and filesize < 10KB }`, references: [], malware_family: "PHP_Webshell", confidence: "high" },
  { id: "YARA-WS-014", name: "PHP_Upload_Webshell", description: "Detects PHP webshells with file upload", author: "Darknode Research", date: "2024-02-20", tags: ["webshell", "php", "upload"], rule_text: `rule PHP_Upload_Shell { strings: $upload = "move_uploaded_file" ascii $files = "$_FILES" ascii $exec = "exec(" ascii $system = "system(" ascii condition: $upload and $files and ($exec or $system) }`, references: [], malware_family: "PHP_Webshell", confidence: "medium" },
  { id: "YARA-WS-015", name: "ASPX_Cmd_Webshell", description: "Detects ASPX command execution webshells", author: "Darknode Research", date: "2024-02-22", tags: ["webshell", "aspx"], rule_text: `rule ASPX_Cmd_Shell { strings: $page = "<%@ Page" ascii nocase $process = "Process.Start" ascii $cmd = "cmd.exe" ascii $response = "Response.Write" ascii condition: $page and $process and ($cmd or $response) }`, references: [], malware_family: "ASPX_Webshell", confidence: "high" },
  { id: "YARA-WS-016", name: "JSP_Cmd_Webshell", description: "Detects JSP command execution webshells", author: "Darknode Research", date: "2024-02-25", tags: ["webshell", "jsp"], rule_text: `rule JSP_Cmd_Shell { strings: $rt = "Runtime.getRuntime()" ascii $exec = ".exec(" ascii $reader = "BufferedReader" ascii $param = "request.getParameter" ascii condition: $rt and $exec and ($reader or $param) }`, references: [], malware_family: "JSP_Webshell", confidence: "high" },
  { id: "YARA-WS-017", name: "Python_Webshell", description: "Detects Python-based webshells", author: "Darknode Research", date: "2024-03-01", tags: ["webshell", "python"], rule_text: `rule Python_Webshell { strings: $import = "import subprocess" ascii $os = "import os" ascii $exec = "os.popen" ascii $flask = "Flask" ascii $cmd = "request.args" ascii condition: ($import or $os) and ($exec or $cmd) }`, references: [], malware_family: "Python_Webshell", confidence: "medium" },
  { id: "YARA-WS-018", name: "Perl_Webshell", description: "Detects Perl CGI webshells", author: "Darknode Research", date: "2024-03-05", tags: ["webshell", "perl"], rule_text: `rule Perl_Webshell { strings: $perl = "#!/usr/bin/perl" ascii $cgi = "use CGI" ascii $exec = "system(" ascii $bt = "\x60" $open = "open(" ascii condition: $perl and 2 of ($cgi, $exec, $bt, $open) }`, references: [], malware_family: "Perl_Webshell", confidence: "medium" },
  { id: "YARA-WS-019", name: "IIS_Webshell", description: "Detects IIS native module webshells", author: "Darknode Research", date: "2024-03-08", tags: ["webshell", "iis"], rule_text: `rule IIS_Webshell { strings: $mz = { 4D 5A } $iis = "IHttpModule" ascii $register = "RegisterModule" ascii $exec = "CreateProcessW" ascii condition: $mz at 0 and $iis and ($register or $exec) }`, references: [], malware_family: "IIS_Webshell", confidence: "high" },
  { id: "YARA-WS-020", name: "SharPyShell", description: "Detects SharPyShell ASPX webshell", author: "Darknode Research", date: "2024-03-10", tags: ["webshell", "sharpyshell", "aspx"], rule_text: `rule SharPyShell { strings: $s1 = "SharPyShell" ascii nocase $s2 = "CompileAssemblyFromSource" ascii $s3 = "CSharpCodeProvider" ascii $crypto = "RijndaelManaged" ascii condition: 2 of them }`, references: [], malware_family: "SharPyShell", confidence: "high" },
  { id: "YARA-WS-021", name: "P0wnyShell", description: "Detects p0wny PHP webshell", author: "Darknode Research", date: "2024-03-12", tags: ["webshell", "p0wny"], rule_text: `rule P0wnyShell { strings: $s1 = "p0wny" ascii nocase $s2 = "shell_exec" ascii $s3 = "proc_open" ascii $term = "xterm" ascii condition: 2 of them }`, references: ["https://github.com/flozz/p0wny-shell"], malware_family: "p0wny", confidence: "high" },
  { id: "YARA-WS-022", name: "ReGeorg_Webshell", description: "Detects reGeorg SOCKS proxy webshell", author: "Darknode Research", date: "2024-03-15", tags: ["webshell", "regeorg", "tunnel"], rule_text: `rule ReGeorg { strings: $s1 = "reGeorg" ascii nocase $s2 = "Georg says" ascii $s3 = "cmd=connect" ascii $socks = "SOCKS" ascii condition: 2 of them }`, references: ["https://github.com/sensepost/reGeorg"], malware_family: "reGeorg", confidence: "high" },
  { id: "YARA-WS-023", name: "Neo_Regeorg", description: "Detects Neo-reGeorg tunnel webshell", author: "Darknode Research", date: "2024-03-18", tags: ["webshell", "neoregeorg", "tunnel"], rule_text: `rule Neo_Regeorg { strings: $s1 = "neoreg" ascii nocase $aes = "AES" ascii $b64 = "base64" ascii $socket = "socket" ascii condition: $s1 and 1 of ($aes, $b64, $socket) }`, references: [], malware_family: "NeoReGeorg", confidence: "high" },
  { id: "YARA-WS-024", name: "ABPTTS_Webshell", description: "Detects ABPTTS HTTP tunnel webshell", author: "Darknode Research", date: "2024-03-20", tags: ["webshell", "abptts", "tunnel"], rule_text: `rule ABPTTS { strings: $s1 = "ABPTTS" ascii nocase $enc = "encrypt" ascii $tunnel = "forward" ascii condition: $s1 and ($enc or $tunnel) }`, references: [], malware_family: "ABPTTS", confidence: "high" },
  { id: "YARA-WS-025", name: "TinyShell_Webshell", description: "Detects tiny/minimal webshells", author: "Darknode Research", date: "2024-03-22", tags: ["webshell", "tiny"], rule_text: `rule TinyShell { strings: $php1 = "<?php eval($_" ascii $php2 = "<?=\x60$_GET" ascii $php3 = "<?php system($_" ascii condition: any of them and filesize < 200 }`, references: [], malware_family: "TinyShell", confidence: "high" },
  { id: "YARA-WS-026", name: "Chopper_ASPX", description: "Detects China Chopper ASPX variant", author: "Darknode Research", date: "2024-03-01", tags: ["webshell", "chopper", "aspx"], rule_text: `rule Chopper_ASPX { strings: $aspx = "<%@ Page" ascii nocase $eval = "eval(Request" ascii nocase $unsafe = "unsafe" ascii $compile = "CompileAssemblyFromSource" ascii condition: $aspx and ($eval or $compile) and filesize < 5KB }`, references: [], malware_family: "ChinaChopper", confidence: "high" },
  { id: "YARA-WS-027", name: "IceSword_Webshell", description: "Detects IceSword/IceScorpion webshell", author: "Darknode Research", date: "2024-03-05", tags: ["webshell", "icescorpion"], rule_text: `rule IceScorpion { strings: $aes = "AES" ascii $class_loader = "ClassLoader" ascii $define = "defineClass" ascii $key_len = { 10 00 00 00 } condition: 3 of them and filesize < 10KB }`, references: [], malware_family: "IceScorpion", confidence: "high" },
  { id: "YARA-WS-028", name: "Laudanum_Webshell", description: "Detects Laudanum webshell collection", author: "Darknode Research", date: "2024-03-08", tags: ["webshell", "laudanum"], rule_text: `rule Laudanum { strings: $s1 = "Laudanum" ascii $s2 = "Tim Medin" ascii $proxy = "proxy" ascii $shell = "shell" ascii condition: ($s1 or $s2) and ($proxy or $shell) }`, references: [], malware_family: "Laudanum", confidence: "high" },
  { id: "YARA-WS-029", name: "TunnelShell", description: "Detects webshells designed for network tunneling", author: "Darknode Research", date: "2024-03-10", tags: ["webshell", "tunnel"], rule_text: `rule TunnelShell { strings: $socket = "fsockopen" ascii $connect = "socket_connect" ascii $proxy = "CONNECT" ascii $socks = { 05 01 00 } condition: 2 of them and filesize < 50KB }`, references: [], malware_family: "TunnelShell", confidence: "medium" },
  { id: "YARA-WS-030", name: "Webshell_Generic_PHP", description: "Generic PHP webshell detection", author: "Darknode Research", date: "2024-01-15", tags: ["webshell", "generic", "php"], rule_text: `rule Webshell_Generic_PHP { meta: description = "Generic PHP webshell" strings: $php = "<?php" ascii nocase $eval = "eval(" ascii $b64 = "base64_decode(" ascii $post = "$_POST" ascii $get = "$_GET" ascii $request = "$_REQUEST" ascii $system = "system(" ascii $exec = "exec(" ascii $passthru = "passthru(" ascii condition: $php and 1 of ($eval, $b64) and 1 of ($post, $get, $request) and 1 of ($system, $exec, $passthru) and filesize < 100KB }`, references: [], malware_family: "Generic", confidence: "medium" },

  // ============================================================
  // CRYPTOMINERS (20 rules)
  // ============================================================
  { id: "YARA-CM-001", name: "XMRig_Cryptominer", description: "Detects XMRig Monero cryptocurrency miner", author: "Darknode Research", date: "2024-01-15", tags: ["cryptominer", "xmrig", "monero"], rule_text: `rule XMRig { meta: description = "Detects XMRig" strings: $s1 = "xmrig" ascii nocase $s2 = "stratum+tcp://" ascii $s3 = "randomx" ascii nocase $s4 = "cryptonight" ascii nocase $pool = "pool." ascii $wallet = { 34 [40-100] } condition: 2 of them }`, references: ["https://github.com/xmrig/xmrig"], malware_family: "XMRig", confidence: "high" },
  { id: "YARA-CM-002", name: "Coinhive_Miner", description: "Detects Coinhive JavaScript miner (discontinued)", author: "Darknode Research", date: "2024-01-18", tags: ["cryptominer", "coinhive", "javascript"], rule_text: `rule Coinhive { strings: $s1 = "CoinHive" ascii nocase $s2 = "coinhive.min.js" ascii $s3 = "CoinHive.Anonymous" ascii $s4 = "startMining" ascii condition: any of them }`, references: [], malware_family: "Coinhive", confidence: "high" },
  { id: "YARA-CM-003", name: "Cryptojacking_JS", description: "Detects generic JavaScript cryptojacking scripts", author: "Darknode Research", date: "2024-01-20", tags: ["cryptominer", "cryptojacking", "javascript"], rule_text: `rule Cryptojacking_JS { strings: $s1 = "CryptoNight" ascii nocase $s2 = "WebAssembly" ascii $s3 = "stratum" ascii $s4 = "miner.start" ascii $s5 = "hashrate" ascii condition: 3 of them }`, references: [], malware_family: "Cryptojacking", confidence: "medium" },
  { id: "YARA-CM-004", name: "WannaMine_Miner", description: "Detects WannaMine cryptominer using EternalBlue", author: "Darknode Research", date: "2024-01-22", tags: ["cryptominer", "wannamine"], rule_text: `rule WannaMine { strings: $eternal = "EternalBlue" ascii nocase $xmr = "xmrig" ascii nocase $ps = "powershell" ascii nocase $wmi = "Win32_Process" ascii $mimikatz = "sekurlsa" ascii condition: 3 of them }`, references: [], malware_family: "WannaMine", confidence: "high" },
  { id: "YARA-CM-005", name: "LemonDuck_Miner", description: "Detects LemonDuck cryptominer botnet", author: "Darknode Research", date: "2024-01-25", tags: ["cryptominer", "lemonduck", "botnet"], rule_text: `rule LemonDuck { strings: $ps = "powershell" ascii nocase $sched = "schtasks" ascii $xmr = "pool.mining" ascii $spread = "IPC$" ascii wide $eternal = "EternalBlue" ascii nocase condition: 3 of them }`, references: [], malware_family: "LemonDuck", confidence: "high" },
  { id: "YARA-CM-006", name: "Kinsing_Miner", description: "Detects Kinsing cryptominer targeting containers", author: "Darknode Research", date: "2024-01-28", tags: ["cryptominer", "kinsing", "container"], rule_text: `rule Kinsing { strings: $go = "main.main" ascii $s1 = "kinsing" ascii nocase $s2 = "kdevtmpfsi" ascii $cron = "crontab" ascii $xmr = "stratum" ascii condition: $go and 2 of ($s1, $s2, $cron, $xmr) }`, references: [], malware_family: "Kinsing", confidence: "high" },
  { id: "YARA-CM-007", name: "TeamTNT_Miner", description: "Detects TeamTNT cloud-focused cryptominer", author: "Darknode Research", date: "2024-02-01", tags: ["cryptominer", "teamtnt", "cloud"], rule_text: `rule TeamTNT { strings: $s1 = "TeamTNT" ascii nocase $aws = "/.aws/credentials" ascii $docker = "docker" ascii nocase $xmr = "xmrig" ascii nocase $cleanup = "iptables -F" ascii condition: 3 of them }`, references: [], malware_family: "TeamTNT", confidence: "high" },
  { id: "YARA-CM-008", name: "Outlaw_Miner", description: "Detects Outlaw/Dota cryptominer botnet", author: "Darknode Research", date: "2024-02-05", tags: ["cryptominer", "outlaw", "botnet"], rule_text: `rule Outlaw_Miner { strings: $s1 = ".dota" ascii $ssh = "authorized_keys" ascii $brute = "sshpass" ascii $xmr = "stratum+tcp" ascii condition: 3 of them }`, references: [], malware_family: "Outlaw", confidence: "high" },
  { id: "YARA-CM-009", name: "Perfctl_Miner", description: "Detects perfctl Linux cryptominer", author: "Darknode Research", date: "2024-02-08", tags: ["cryptominer", "perfctl", "linux"], rule_text: `rule Perfctl { strings: $elf = { 7F 45 4C 46 } $name = "perfctl" ascii $proc_hide = "/proc/self" ascii $rootkit = "ld.so.preload" ascii condition: $elf at 0 and 2 of ($name, $proc_hide, $rootkit) }`, references: [], malware_family: "Perfctl", confidence: "high" },
  { id: "YARA-CM-010", name: "Clipper_Crypto_Stealer", description: "Detects cryptocurrency address clipper/replacer malware", author: "Darknode Research", date: "2024-02-10", tags: ["cryptominer", "clipper", "stealer"], rule_text: `rule Crypto_Clipper { strings: $clipboard = "GetClipboardData" ascii $set_clip = "SetClipboardData" ascii $btc_regex = "^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$" ascii $eth_regex = "^0x[a-fA-F0-9]{40}$" ascii $monitor = "AddClipboardFormatListener" ascii condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "Clipper", confidence: "high" },
  { id: "YARA-CM-011", name: "Norman_Miner", description: "Detects Norman cryptominer", author: "Darknode Research", date: "2024-02-12", tags: ["cryptominer", "norman"], rule_text: `rule Norman_Miner { strings: $s1 = "svchost" ascii $inject = "NtCreateThreadEx" ascii $xmr = "cryptonight" ascii nocase $pool = "stratum" ascii condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "Norman", confidence: "medium" },
  { id: "YARA-CM-012", name: "Adylkuzz_Miner", description: "Detects Adylkuzz cryptominer using EternalBlue", author: "Darknode Research", date: "2024-02-15", tags: ["cryptominer", "adylkuzz"], rule_text: `rule Adylkuzz { strings: $smb = "SMB" ascii $payload = "DoublePulsar" ascii $xmr = "Monero" ascii nocase $svc = "adylkuzz" ascii nocase condition: 2 of them }`, references: [], malware_family: "Adylkuzz", confidence: "high" },
  { id: "YARA-CM-013", name: "Mimo_Miner", description: "Detects Mimo/MimiKatz-based cryptominer", author: "Darknode Research", date: "2024-02-18", tags: ["cryptominer", "mimo"], rule_text: `rule Mimo_Miner { strings: $mimi = "mimikatz" ascii nocase $xmr = "xmrig" ascii nocase $spread = "psexec" ascii nocase $wmi = "wmic" ascii condition: 3 of them }`, references: [], malware_family: "Mimo", confidence: "high" },
  { id: "YARA-CM-014", name: "CoinMiner_Generic_Linux", description: "Generic Linux cryptominer indicators", author: "Darknode Research", date: "2024-02-20", tags: ["cryptominer", "generic", "linux"], rule_text: `rule CoinMiner_Linux { strings: $elf = { 7F 45 4C 46 } $stratum = "stratum+tcp://" ascii $pool = "pool" ascii $xmr1 = "RandomX" ascii nocase $xmr2 = "CryptoNight" ascii nocase $cpu = "cpu-priority" ascii condition: $elf at 0 and 3 of ($stratum, $pool, $xmr1, $xmr2, $cpu) }`, references: [], malware_family: "Generic", confidence: "medium" },
  { id: "YARA-CM-015", name: "CoinMiner_Generic_Windows", description: "Generic Windows cryptominer indicators", author: "Darknode Research", date: "2024-02-22", tags: ["cryptominer", "generic", "windows"], rule_text: `rule CoinMiner_Windows { strings: $mz = { 4D 5A } $stratum = "stratum+tcp://" ascii $pool = "pool." ascii $xmr = "RandomX" ascii nocase $wallet = "wallet" ascii $gpu = "opencl" ascii nocase condition: $mz at 0 and 3 of ($stratum, $pool, $xmr, $wallet, $gpu) }`, references: [], malware_family: "Generic", confidence: "medium" },
  { id: "YARA-CM-016", name: "Browser_Miner_Injection", description: "Detects browser-based miner injection in web pages", author: "Darknode Research", date: "2024-02-25", tags: ["cryptominer", "browser", "injection"], rule_text: `rule Browser_Miner { strings: $wasm = "WebAssembly" ascii $worker = "new Worker" ascii $hash = "hashrate" ascii $throttle = "throttle" ascii $mine = "startMining" ascii condition: 3 of them }`, references: [], malware_family: "BrowserMiner", confidence: "medium" },
  { id: "YARA-CM-017", name: "SilentMiner", description: "Detects Silent/Hidden cryptocurrency miners", author: "Darknode Research", date: "2024-03-01", tags: ["cryptominer", "silent"], rule_text: `rule SilentMiner { strings: $svc = "sc create" ascii $hidden = "SW_HIDE" ascii $xmr = "xmrig" ascii nocase $startup = "\\Startup\\\\" ascii condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "SilentMiner", confidence: "medium" },
  { id: "YARA-CM-018", name: "CryptoNight_Algorithm", description: "Detects CryptoNight mining algorithm implementation", author: "Darknode Research", date: "2024-03-05", tags: ["cryptominer", "cryptonight"], rule_text: `rule CryptoNight_Algo { strings: $cn_slow_hash = { 8B 45 ?? 31 45 ?? 8B 45 ?? 31 45 ?? 81 45 } $aes_key_expand = { 66 0F 38 DC } $keccak = "Keccak" ascii nocase condition: 2 of them }`, references: [], malware_family: "CryptoNight", confidence: "medium" },
  { id: "YARA-CM-019", name: "Docker_Cryptojack", description: "Detects Docker container cryptojacking scripts", author: "Darknode Research", date: "2024-03-08", tags: ["cryptominer", "docker", "container"], rule_text: `rule Docker_Cryptojack { strings: $docker = "docker" ascii $pull = "docker pull" ascii $run = "docker run" ascii $xmr = "xmrig" ascii nocase $alpine = "alpine" ascii condition: 3 of them }`, references: [], malware_family: "DockerCryptojack", confidence: "medium" },
  { id: "YARA-CM-020", name: "Golang_Miner", description: "Detects Go-based cryptocurrency miners", author: "Darknode Research", date: "2024-03-10", tags: ["cryptominer", "golang"], rule_text: `rule Golang_Miner { strings: $go = "main.main" ascii $stratum = "stratum" ascii $randomx = "RandomX" ascii nocase $pool = "pool" ascii $goroutine = "runtime.goexit" ascii condition: $go and $goroutine and 2 of ($stratum, $randomx, $pool) }`, references: [], malware_family: "GoMiner", confidence: "medium" },

  // ============================================================
  // WIPERS (15 rules)
  // ============================================================
  { id: "YARA-WP-001", name: "WhisperGate_Wiper", description: "Detects WhisperGate wiper targeting Ukraine", author: "Darknode Research", date: "2024-01-15", tags: ["wiper", "whispergate", "ukraine"], rule_text: `rule WhisperGate { strings: $note = "Your hard drive has been corrupted" ascii $btc = "1AVNM68gj6PGPFcJuftKATa4WLnzg8fpfv" ascii $mbr = { 00 7C B4 0E AC 3C 00 74 } $dotnet = "_CorExeMain" ascii $discord = "discord" ascii condition: 3 of them }`, references: ["https://www.microsoft.com/en-us/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/"], malware_family: "WhisperGate", confidence: "high" },
  { id: "YARA-WP-002", name: "HermeticWiper", description: "Detects HermeticWiper used in Ukraine attacks", author: "Darknode Research", date: "2024-01-18", tags: ["wiper", "hermeticwiper", "ukraine"], rule_text: `rule HermeticWiper { strings: $driver = "epmntdrv" ascii $service = "PhysicalDrive" ascii wide $decomp = "LZDecompressFragment" ascii $cert = "Hermetica Digital" ascii condition: uint16(0) == 0x5A4D and 2 of them }`, references: ["https://www.welivesecurity.com/2022/03/01/isaacwiper-hermeticwizard-wiper-worm-targeting-ukraine/"], malware_family: "HermeticWiper", confidence: "high" },
  { id: "YARA-WP-003", name: "CaddyWiper", description: "Detects CaddyWiper targeting Ukraine", author: "Darknode Research", date: "2024-01-20", tags: ["wiper", "caddywiper", "ukraine"], rule_text: `rule CaddyWiper { strings: $dc_check = "DsGetDcNameW" ascii $zero_fill = { C6 04 01 00 41 3B C2 72 } $phys = "\\\\\\\\.\\\\PHYSICALDRIVE" ascii wide condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "CaddyWiper", confidence: "high" },
  { id: "YARA-WP-004", name: "Shamoon_Wiper", description: "Detects Shamoon/DistTrack wiper", author: "Darknode Research", date: "2024-01-22", tags: ["wiper", "shamoon", "disttrack"], rule_text: `rule Shamoon { strings: $driver = "RawDisk" ascii $eldos = "EldoS" ascii $overwrite = "DeviceIoControl" ascii $mbr_write = { B4 03 CD 13 } $image = "JPEG" ascii condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "Shamoon", confidence: "high" },
  { id: "YARA-WP-005", name: "ZeroCleare_Wiper", description: "Detects ZeroCleare wiper", author: "Darknode Research", date: "2024-01-25", tags: ["wiper", "zerocleare"], rule_text: `rule ZeroCleare { strings: $driver = "EldoS RawDisk" ascii $rawdisk = "rawdisk" ascii nocase $phys = "PhysicalDrive" ascii wide $svc = "sc.exe create" ascii condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "ZeroCleare", confidence: "high" },
  { id: "YARA-WP-006", name: "Meteor_Wiper", description: "Detects Meteor wiper targeting Iranian railways", author: "Darknode Research", date: "2024-01-28", tags: ["wiper", "meteor", "iran"], rule_text: `rule Meteor_Wiper { strings: $cfg = "setup.ini" ascii $batch = ".bat" ascii $lock = "screen.exe" ascii $wipe = "DeviceIoControl" ascii condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "Meteor", confidence: "medium" },
  { id: "YARA-WP-007", name: "IsaacWiper", description: "Detects IsaacWiper used in Ukraine", author: "Darknode Research", date: "2024-02-01", tags: ["wiper", "isaacwiper", "ukraine"], rule_text: `rule IsaacWiper { strings: $phys = "\\\\\\\\.\\\\PhysicalDrive" ascii wide $rand = "CryptGenRandom" ascii $overwrite = { C6 04 ?? 00 FF 44 24 } condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "IsaacWiper", confidence: "high" },
  { id: "YARA-WP-008", name: "AcidRain_Wiper", description: "Detects AcidRain wiper targeting Viasat modems", author: "Darknode Research", date: "2024-02-05", tags: ["wiper", "acidrain", "iot"], rule_text: `rule AcidRain { strings: $elf = { 7F 45 4C 46 } $dev = "/dev/" ascii $mtd = "mtd" ascii $mmc = "mmc" ascii $overwrite = { 00 00 00 00 FF FF FF FF } condition: $elf at 0 and 2 of ($dev, $mtd, $mmc) }`, references: [], malware_family: "AcidRain", confidence: "high" },
  { id: "YARA-WP-009", name: "DoubleZero_Wiper", description: "Detects DoubleZero wiper targeting Ukraine", author: "Darknode Research", date: "2024-02-08", tags: ["wiper", "doublezero", "ukraine"], rule_text: `rule DoubleZero { strings: $dotnet = "_CorExeMain" ascii $api = "NtFileOpen" ascii $zero = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 } $svc_stop = "sc stop" ascii condition: uint16(0) == 0x5A4D and $dotnet and 1 of ($api, $svc_stop) }`, references: [], malware_family: "DoubleZero", confidence: "medium" },
  { id: "YARA-WP-010", name: "SwiftSlicer_Wiper", description: "Detects SwiftSlicer wiper (Go-based)", author: "Darknode Research", date: "2024-02-10", tags: ["wiper", "swiftslicer", "ukraine"], rule_text: `rule SwiftSlicer { strings: $go = "main.main" ascii $ad = "Active Directory" ascii $gpo = "SYSVOL" ascii $wipe = { 00 00 00 00 [4096] 00 00 00 00 } condition: $go and ($ad or $gpo) }`, references: [], malware_family: "SwiftSlicer", confidence: "medium" },
  { id: "YARA-WP-011", name: "Dustman_Wiper", description: "Detects Dustman wiper (Iran-linked)", author: "Darknode Research", date: "2024-02-12", tags: ["wiper", "dustman", "iran"], rule_text: `rule Dustman { strings: $driver = "Eldos" ascii $rawdisk = "RawDisk3" ascii $agent = "agent.exe" ascii condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "Dustman", confidence: "high" },
  { id: "YARA-WP-012", name: "Olympic_Destroyer", description: "Detects Olympic Destroyer wiper from 2018 Olympics", author: "Darknode Research", date: "2024-02-15", tags: ["wiper", "olympicdestroyer"], rule_text: `rule Olympic_Destroyer { strings: $vss = "vssadmin delete shadows" ascii nocase $wbadmin = "wbadmin delete catalog" ascii nocase $bcdedit = "bcdedit /set {default} recoveryenabled no" ascii nocase $wmic_spread = "wmic" ascii $psexec = "psexec" ascii condition: 3 of them }`, references: [], malware_family: "OlympicDestroyer", confidence: "high" },
  { id: "YARA-WP-013", name: "StoneDrill_Wiper", description: "Detects StoneDrill wiper (APT33)", author: "Darknode Research", date: "2024-02-18", tags: ["wiper", "stonedrill", "apt33"], rule_text: `rule StoneDrill { strings: $injection = "VirtualAllocEx" ascii $write = "WriteProcessMemory" ascii $phys = "PhysicalDrive" ascii $overwrite = "DeviceIoControl" ascii condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "StoneDrill", confidence: "medium" },
  { id: "YARA-WP-014", name: "KillDisk_Wiper", description: "Detects KillDisk wiper (BlackEnergy)", author: "Darknode Research", date: "2024-02-20", tags: ["wiper", "killdisk", "blackenergy"], rule_text: `rule KillDisk { strings: $svc = "ntdsutil" ascii $phys = "\\\\\\\\.\\\\PhysicalDrive0" ascii wide $overwrite = { 00 00 00 00 00 00 00 00 } $boot = { EB 3C 90 } condition: uint16(0) == 0x5A4D and 2 of ($svc, $phys, $overwrite) }`, references: [], malware_family: "KillDisk", confidence: "high" },
  { id: "YARA-WP-015", name: "BiBi_Wiper", description: "Detects BiBi wiper targeting Israel", author: "Darknode Research", date: "2024-02-22", tags: ["wiper", "bibi", "israel"], rule_text: `rule BiBi_Wiper { strings: $bibi = "BiBi" ascii $elf = { 7F 45 4C 46 } $threads = "pthread_create" ascii $overwrite = "pwrite" ascii condition: ($elf at 0 or uint16(0) == 0x5A4D) and $bibi and ($threads or $overwrite) }`, references: [], malware_family: "BiBi", confidence: "high" },

  // ============================================================
  // ROOTKITS (15 rules)
  // ============================================================
  { id: "YARA-RK-001", name: "Azazel_Rootkit", description: "Detects Azazel Linux userland rootkit", author: "Darknode Research", date: "2024-01-15", tags: ["rootkit", "linux", "azazel"], rule_text: `rule Azazel { strings: $elf = { 7F 45 4C 46 } $hook1 = "accept" ascii $hook2 = "readdir" ascii $hook3 = "open" ascii $env_hide = "LD_PRELOAD" ascii $magic = "AZAZEL" ascii condition: $elf at 0 and $magic and 2 of ($hook1, $hook2, $hook3, $env_hide) }`, references: [], malware_family: "Azazel", confidence: "high" },
  { id: "YARA-RK-002", name: "Reptile_Rootkit", description: "Detects Reptile Linux kernel rootkit", author: "Darknode Research", date: "2024-01-18", tags: ["rootkit", "linux", "kernel", "reptile"], rule_text: `rule Reptile { strings: $s1 = "reptile" ascii nocase $lkm = "module_init" ascii $hide = "proc_dir_entry" ascii $hook = "sys_call_table" ascii condition: 2 of them }`, references: ["https://github.com/f0rb1dd3n/Reptile"], malware_family: "Reptile", confidence: "high" },
  { id: "YARA-RK-003", name: "Diamorphine_Rootkit", description: "Detects Diamorphine Linux kernel rootkit", author: "Darknode Research", date: "2024-01-20", tags: ["rootkit", "linux", "kernel", "diamorphine"], rule_text: `rule Diamorphine { strings: $s1 = "diamorphine" ascii nocase $lkm = "module_init" ascii $signal = "kill" ascii $hide_pid = "is_invisible" ascii condition: ($s1 or $hide_pid) and $lkm }`, references: ["https://github.com/m0nad/Diamorphine"], malware_family: "Diamorphine", confidence: "high" },
  { id: "YARA-RK-004", name: "Necurs_Rootkit", description: "Detects Necurs rootkit/bootkit", author: "Darknode Research", date: "2024-01-22", tags: ["rootkit", "windows", "necurs"], rule_text: `rule Necurs { strings: $driver = ".sys" ascii $hook = "IofCallDriver" ascii $ndis = "NdisRegisterProtocol" ascii $hide = "ZwQueryDirectoryFile" ascii condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "Necurs", confidence: "high" },
  { id: "YARA-RK-005", name: "TDL4_Bootkit", description: "Detects TDL4/TDSS bootkit rootkit", author: "Darknode Research", date: "2024-01-25", tags: ["rootkit", "bootkit", "tdl4"], rule_text: `rule TDL4 { strings: $tdl = "tdl" ascii nocase $mbr = { FA 33 C0 8E D0 } $vbr_hook = { EB ?? 90 4E 54 46 53 } $driver = "\\SystemRoot\\system32\\drivers" ascii wide condition: 2 of them }`, references: [], malware_family: "TDL4", confidence: "high" },
  { id: "YARA-RK-006", name: "ZeroAccess_Rootkit", description: "Detects ZeroAccess/Sirefef rootkit", author: "Darknode Research", date: "2024-01-28", tags: ["rootkit", "zeroaccess", "sirefef"], rule_text: `rule ZeroAccess { strings: $p2p = "\\\\?\\GLOBALROOT\\\\" ascii wide $max = "max++" ascii $junction = "\\$Recycle.Bin\\\\" ascii wide $driver = "B48DADF8" ascii condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "ZeroAccess", confidence: "high" },
  { id: "YARA-RK-007", name: "Sauron_Rootkit", description: "Detects ProjectSauron/Remsec rootkit (APT)", author: "Darknode Research", date: "2024-02-01", tags: ["rootkit", "apt", "sauron"], rule_text: `rule ProjectSauron { strings: $lua = "lua" ascii $module = "SAURON" ascii nocase $encrypt = "RC6" ascii $pipe = "\\pipe\\\\" ascii condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "ProjectSauron", confidence: "high" },
  { id: "YARA-RK-008", name: "Uroburos_Rootkit", description: "Detects Uroburos/Turla rootkit", author: "Darknode Research", date: "2024-02-05", tags: ["rootkit", "turla", "uroburos", "apt"], rule_text: `rule Uroburos { strings: $driver = "\\Device\\RawDisk" ascii wide $queue = "queue" ascii $encrypt = "CAST-128" ascii $hook = "SSDT" ascii $vfs = "virtual filesystem" ascii nocase condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "Uroburos", confidence: "high" },
  { id: "YARA-RK-009", name: "Scranos_Rootkit", description: "Detects Scranos rootkit/spyware", author: "Darknode Research", date: "2024-02-08", tags: ["rootkit", "scranos"], rule_text: `rule Scranos { strings: $driver = ".sys" ascii $cert = "Yun Yu Health" ascii $inject = "Chrome" ascii $youtube = "youtube" ascii nocase condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "Scranos", confidence: "medium" },
  { id: "YARA-RK-010", name: "MosaicRegressor_UEFI", description: "Detects MosaicRegressor UEFI rootkit", author: "Darknode Research", date: "2024-02-10", tags: ["rootkit", "uefi", "bootkit"], rule_text: `rule MosaicRegressor { strings: $uefi = "EFI" ascii $dxe = "DXE_DRIVER" ascii $smi = "SmmBase" ascii $payload_drop = "InfectedShell" ascii condition: 2 of them }`, references: [], malware_family: "MosaicRegressor", confidence: "high" },
  { id: "YARA-RK-011", name: "CosmicStrand_UEFI", description: "Detects CosmicStrand UEFI firmware rootkit", author: "Darknode Research", date: "2024-02-12", tags: ["rootkit", "uefi", "cosmicstrand"], rule_text: `rule CosmicStrand { strings: $uefi_marker = "AMI" ascii $hook_kernel = "ntoskrnl" ascii $shellcode = { E8 00 00 00 00 5B } $http = "HTTP/1.1" ascii condition: 3 of them }`, references: [], malware_family: "CosmicStrand", confidence: "high" },
  { id: "YARA-RK-012", name: "BlackLotus_Bootkit", description: "Detects BlackLotus UEFI bootkit", author: "Darknode Research", date: "2024-02-15", tags: ["rootkit", "uefi", "bootkit", "blacklotus"], rule_text: `rule BlackLotus { strings: $efi = ".efi" ascii $secureboot = "Secure Boot" ascii nocase $mokutil = "mokutil" ascii $bcd = "bcdedit" ascii $self_sign = "self-signed" ascii nocase condition: 3 of them }`, references: ["https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/"], malware_family: "BlackLotus", confidence: "high" },
  { id: "YARA-RK-013", name: "FiveSys_Rootkit", description: "Detects FiveSys rootkit with stolen Microsoft signature", author: "Darknode Research", date: "2024-02-18", tags: ["rootkit", "fivesys", "signed"], rule_text: `rule FiveSys { strings: $driver = "\\Registry\\Machine\\SYSTEM" ascii wide $proxy = "proxy" ascii $filter = "FilterManager" ascii $signed = "Microsoft Windows Hardware Compatibility" ascii condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "FiveSys", confidence: "medium" },
  { id: "YARA-RK-014", name: "FontOnLake_Rootkit", description: "Detects FontOnLake Linux rootkit", author: "Darknode Research", date: "2024-02-20", tags: ["rootkit", "linux", "fontonlake"], rule_text: `rule FontOnLake { strings: $elf = { 7F 45 4C 46 } $hook = "ld.so.preload" ascii $hide = "readdir" ascii $backdoor = "sshd" ascii $c2 = "connect" ascii condition: $elf at 0 and 3 of ($hook, $hide, $backdoor, $c2) }`, references: [], malware_family: "FontOnLake", confidence: "high" },
  { id: "YARA-RK-015", name: "LD_PRELOAD_Rootkit_Generic", description: "Detects generic LD_PRELOAD-based Linux rootkits", author: "Darknode Research", date: "2024-01-15", tags: ["rootkit", "linux", "ldpreload", "generic"], rule_text: `rule LD_PRELOAD_Rootkit { strings: $elf = { 7F 45 4C 46 } $preload = "ld.so.preload" ascii $readdir = "readdir" ascii $readdir64 = "readdir64" ascii $fopen = "fopen" ascii $stat = "__xstat" ascii $hide_pattern = "is_invisible" ascii condition: $elf at 0 and $preload and 2 of ($readdir, $readdir64, $fopen, $stat, $hide_pattern) }`, references: [], malware_family: "Generic", confidence: "medium" },

  // ============================================================
  // EXPLOIT KITS (15 rules)
  // ============================================================
  { id: "YARA-EK-001", name: "Angler_ExploitKit", description: "Detects Angler Exploit Kit landing pages", author: "Darknode Research", date: "2024-01-15", tags: ["exploitkit", "angler"], rule_text: `rule Angler_EK { strings: $obf1 = "eval(" ascii $obf2 = "String.fromCharCode" ascii $flash = ".swf" ascii $java = "java" ascii nocase $land = "landing" ascii condition: 3 of them }`, references: [], malware_family: "Angler", confidence: "medium" },
  { id: "YARA-EK-002", name: "RIG_ExploitKit", description: "Detects RIG Exploit Kit", author: "Darknode Research", date: "2024-01-18", tags: ["exploitkit", "rig"], rule_text: `rule RIG_EK { strings: $gate = "?data=" ascii $vbs = "VBScript.Encode" ascii $wscript = "WScript" ascii $ie_check = "navigator.userAgent" ascii condition: 3 of them }`, references: [], malware_family: "RIG", confidence: "medium" },
  { id: "YARA-EK-003", name: "Nuclear_ExploitKit", description: "Detects Nuclear Exploit Kit", author: "Darknode Research", date: "2024-01-20", tags: ["exploitkit", "nuclear"], rule_text: `rule Nuclear_EK { strings: $flash = "application/x-shockwave-flash" ascii $jar = ".jar" ascii $obf = "eval(function(p,a,c,k,e" ascii $redirect = "document.location" ascii condition: 3 of them }`, references: [], malware_family: "Nuclear", confidence: "medium" },
  { id: "YARA-EK-004", name: "Magnitude_ExploitKit", description: "Detects Magnitude Exploit Kit", author: "Darknode Research", date: "2024-01-22", tags: ["exploitkit", "magnitude"], rule_text: `rule Magnitude_EK { strings: $ie_vuln = "CVE-2018-8174" ascii $vbs = "VBScript" ascii $shellcode = "unescape" ascii $b64 = "atob(" ascii condition: 2 of them }`, references: [], malware_family: "Magnitude", confidence: "medium" },
  { id: "YARA-EK-005", name: "Fallout_ExploitKit", description: "Detects Fallout Exploit Kit", author: "Darknode Research", date: "2024-01-25", tags: ["exploitkit", "fallout"], rule_text: `rule Fallout_EK { strings: $redirect = "302" ascii $vbs = "VBScript" ascii $ps = "powershell" ascii nocase $cve = "CVE-2018" ascii condition: 3 of them }`, references: [], malware_family: "Fallout", confidence: "medium" },
  { id: "YARA-EK-006", name: "Sundown_ExploitKit", description: "Detects Sundown Exploit Kit", author: "Darknode Research", date: "2024-01-28", tags: ["exploitkit", "sundown"], rule_text: `rule Sundown_EK { strings: $flash = ".swf" ascii $silverlight = "Silverlight" ascii $ie = "ActiveXObject" ascii $eval = "eval(" ascii condition: 3 of them }`, references: [], malware_family: "Sundown", confidence: "medium" },
  { id: "YARA-EK-007", name: "Underminer_ExploitKit", description: "Detects Underminer Exploit Kit", author: "Darknode Research", date: "2024-02-01", tags: ["exploitkit", "underminer"], rule_text: `rule Underminer_EK { strings: $flash = "application/x-shockwave-flash" ascii $encrypt = "AES" ascii $bootkit = "MBR" ascii $hidden = "Hidden" ascii condition: 3 of them }`, references: [], malware_family: "Underminer", confidence: "medium" },
  { id: "YARA-EK-008", name: "Spelevo_ExploitKit", description: "Detects Spelevo Exploit Kit", author: "Darknode Research", date: "2024-02-05", tags: ["exploitkit", "spelevo"], rule_text: `rule Spelevo_EK { strings: $ie_vuln = "CVE-2018-15982" ascii $flash_vuln = "CVE-2018-4878" ascii $redirect = "iframe" ascii nocase $b64 = "base64" ascii condition: 2 of them }`, references: [], malware_family: "Spelevo", confidence: "medium" },
  { id: "YARA-EK-009", name: "Purple_Fox_EK", description: "Detects Purple Fox exploit kit and rootkit", author: "Darknode Research", date: "2024-02-08", tags: ["exploitkit", "purplefox", "rootkit"], rule_text: `rule Purple_Fox { strings: $msi = "msiexec" ascii nocase $ps = "powershell" ascii nocase $rootkit = ".sys" ascii $spread = "SMB" ascii $cve = "CVE-2020" ascii condition: 3 of them }`, references: [], malware_family: "PurpleFox", confidence: "medium" },
  { id: "YARA-EK-010", name: "Bottle_ExploitKit", description: "Detects Bottle EK (Asia-focused)", author: "Darknode Research", date: "2024-02-10", tags: ["exploitkit", "bottle"], rule_text: `rule Bottle_EK { strings: $cve = "CVE-2018-8174" ascii $vbs = "VBScript" ascii $ua_check = "navigator.userAgent" ascii $charset = "charset=" ascii condition: 3 of them }`, references: [], malware_family: "Bottle", confidence: "low" },
  { id: "YARA-EK-011", name: "Blackhole_ExploitKit", description: "Detects legacy Blackhole Exploit Kit artifacts", author: "Darknode Research", date: "2024-02-12", tags: ["exploitkit", "blackhole"], rule_text: `rule Blackhole_EK { strings: $java = "java.lang.Runtime" ascii $pdf = "%PDF-" ascii $obf = "eval(" ascii $pluginDetect = "PluginDetect" ascii condition: 3 of them }`, references: [], malware_family: "Blackhole", confidence: "medium" },
  { id: "YARA-EK-012", name: "Sweet_Orange_EK", description: "Detects Sweet Orange Exploit Kit", author: "Darknode Research", date: "2024-02-15", tags: ["exploitkit", "sweetorange"], rule_text: `rule Sweet_Orange { strings: $ie = "ActiveXObject" ascii $java = "deployJava" ascii $flash = "embed" ascii nocase $obf = "unescape(" ascii condition: 3 of them }`, references: [], malware_family: "SweetOrange", confidence: "medium" },
  { id: "YARA-EK-013", name: "Fiesta_ExploitKit", description: "Detects Fiesta Exploit Kit", author: "Darknode Research", date: "2024-02-18", tags: ["exploitkit", "fiesta"], rule_text: `rule Fiesta_EK { strings: $java = ".jar" ascii $silverlight = ".xap" ascii $pdf = "application/pdf" ascii $eval = "eval" ascii condition: 3 of them }`, references: [], malware_family: "Fiesta", confidence: "low" },
  { id: "YARA-EK-014", name: "Neutrino_ExploitKit", description: "Detects Neutrino Exploit Kit", author: "Darknode Research", date: "2024-02-20", tags: ["exploitkit", "neutrino"], rule_text: `rule Neutrino_EK { strings: $flash = "application/x-shockwave-flash" ascii $json = "JSON.parse" ascii $xor = "charCodeAt" ascii $gate = "gate.php" ascii condition: 3 of them }`, references: [], malware_family: "Neutrino", confidence: "medium" },
  { id: "YARA-EK-015", name: "ExploitKit_Generic_Landing", description: "Generic exploit kit landing page detection", author: "Darknode Research", date: "2024-01-15", tags: ["exploitkit", "generic"], rule_text: `rule EK_Generic_Landing { strings: $obf1 = "eval(function(" ascii $obf2 = "String.fromCharCode" ascii $obf3 = "unescape(" ascii $plugin = "navigator.plugins" ascii $ua = "navigator.userAgent" ascii $iframe = "iframe" ascii nocase $java = "application/java" ascii $flash = "application/x-shockwave-flash" ascii condition: 3 of ($obf1, $obf2, $obf3) and 2 of ($plugin, $ua, $iframe, $java, $flash) }`, references: [], malware_family: "Generic", confidence: "low" },

  // ============================================================
  // PACKERS / CRYPTERS (15 rules)
  // ============================================================
  { id: "YARA-PC-001", name: "UPX_Packed", description: "Detects UPX packed executables", author: "Darknode Research", date: "2024-01-15", tags: ["packer", "upx"], rule_text: `rule UPX_Packed { strings: $upx0 = "UPX0" ascii $upx1 = "UPX1" ascii $upx2 = "UPX!" ascii condition: uint16(0) == 0x5A4D and 2 of them }`, references: ["https://upx.github.io/"], malware_family: "UPX", confidence: "high" },
  { id: "YARA-PC-002", name: "Themida_Packed", description: "Detects Themida/WinLicense packed executables", author: "Darknode Research", date: "2024-01-18", tags: ["packer", "themida", "winlicense"], rule_text: `rule Themida { strings: $s1 = ".themida" ascii $s2 = "WinLicense" ascii $vm = { 68 ?? ?? ?? ?? E9 ?? ?? ?? ?? 00 00 00 } $anti = "IsDebuggerPresent" ascii condition: uint16(0) == 0x5A4D and 1 of ($s1, $s2) }`, references: [], malware_family: "Themida", confidence: "high" },
  { id: "YARA-PC-003", name: "VMProtect_Packed", description: "Detects VMProtect packed executables", author: "Darknode Research", date: "2024-01-20", tags: ["packer", "vmprotect"], rule_text: `rule VMProtect { strings: $vmp0 = ".vmp0" ascii $vmp1 = ".vmp1" ascii $s1 = "VMProtect" ascii condition: uint16(0) == 0x5A4D and any of them }`, references: [], malware_family: "VMProtect", confidence: "high" },
  { id: "YARA-PC-004", name: "ASPack_Packed", description: "Detects ASPack packed executables", author: "Darknode Research", date: "2024-01-22", tags: ["packer", "aspack"], rule_text: `rule ASPack { strings: $s1 = ".aspack" ascii $s2 = "ASPack" ascii $ep = { 60 E8 03 00 00 00 E9 EB } condition: uint16(0) == 0x5A4D and any of them }`, references: [], malware_family: "ASPack", confidence: "high" },
  { id: "YARA-PC-005", name: "MPRESS_Packed", description: "Detects MPRESS packed executables", author: "Darknode Research", date: "2024-01-25", tags: ["packer", "mpress"], rule_text: `rule MPRESS { strings: $s1 = "MPRESS1" ascii $s2 = "MPRESS2" ascii condition: uint16(0) == 0x5A4D and any of them }`, references: [], malware_family: "MPRESS", confidence: "high" },
  { id: "YARA-PC-006", name: "Enigma_Packed", description: "Detects Enigma Protector packed executables", author: "Darknode Research", date: "2024-01-28", tags: ["packer", "enigma"], rule_text: `rule Enigma { strings: $s1 = "Enigma protector" ascii nocase $s2 = ".enigma" ascii $vm = "ENIGMA" ascii condition: uint16(0) == 0x5A4D and any of them }`, references: [], malware_family: "Enigma", confidence: "high" },
  { id: "YARA-PC-007", name: "ConfuserEx_Packed", description: "Detects ConfuserEx .NET obfuscation", author: "Darknode Research", date: "2024-02-01", tags: ["packer", "confuserex", "dotnet"], rule_text: `rule ConfuserEx { strings: $dotnet = "_CorExeMain" ascii $s1 = "ConfuserEx" ascii nocase $s2 = "Confuser.Core" ascii $obf = { 01 00 01 28 ?? ?? ?? 06 } condition: uint16(0) == 0x5A4D and $dotnet and 1 of ($s1, $s2) }`, references: [], malware_family: "ConfuserEx", confidence: "high" },
  { id: "YARA-PC-008", name: "SmartAssembly_Packed", description: "Detects SmartAssembly .NET obfuscation", author: "Darknode Research", date: "2024-02-05", tags: ["packer", "smartassembly", "dotnet"], rule_text: `rule SmartAssembly { strings: $dotnet = "_CorExeMain" ascii $s1 = "SmartAssembly" ascii $s2 = "{SmartAssembly}" ascii $powered = "Powered by SmartAssembly" ascii condition: uint16(0) == 0x5A4D and $dotnet and any of ($s1, $s2, $powered) }`, references: [], malware_family: "SmartAssembly", confidence: "high" },
  { id: "YARA-PC-009", name: "Dotfuscator_Packed", description: "Detects Dotfuscator .NET obfuscation", author: "Darknode Research", date: "2024-02-08", tags: ["packer", "dotfuscator", "dotnet"], rule_text: `rule Dotfuscator { strings: $dotnet = "_CorExeMain" ascii $s1 = "Dotfuscator" ascii $s2 = "DotfuscatorAttribute" ascii condition: uint16(0) == 0x5A4D and $dotnet and ($s1 or $s2) }`, references: [], malware_family: "Dotfuscator", confidence: "high" },
  { id: "YARA-PC-010", name: "PyInstaller_Packed", description: "Detects PyInstaller packed Python executables", author: "Darknode Research", date: "2024-02-10", tags: ["packer", "pyinstaller", "python"], rule_text: `rule PyInstaller { strings: $s1 = "PyInstaller" ascii $s2 = "pyi-" ascii $s3 = "MEIPASS" ascii $python = "python" ascii nocase condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "PyInstaller", confidence: "high" },
  { id: "YARA-PC-011", name: "Nuitka_Packed", description: "Detects Nuitka compiled Python executables", author: "Darknode Research", date: "2024-02-12", tags: ["packer", "nuitka", "python"], rule_text: `rule Nuitka { strings: $s1 = "Nuitka" ascii $s2 = "onefile" ascii $python = "python" ascii nocase condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "Nuitka", confidence: "medium" },
  { id: "YARA-PC-012", name: "Exe2Aut_AutoIt", description: "Detects compiled AutoIt (decompilable)", author: "Darknode Research", date: "2024-02-15", tags: ["packer", "autoit"], rule_text: `rule AutoIt_Compiled { strings: $au3 = "AU3!" ascii $autoit = "AutoIt" ascii $script = ">>>AUTOIT SCRIPT<<<" ascii condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "AutoIt", confidence: "high" },
  { id: "YARA-PC-013", name: "Obsidium_Packed", description: "Detects Obsidium packed executables", author: "Darknode Research", date: "2024-02-18", tags: ["packer", "obsidium"], rule_text: `rule Obsidium { strings: $s1 = "Obsidium" ascii $anti_dump = { E8 ?? ?? ?? ?? EB 03 ?? ?? ?? E8 } condition: uint16(0) == 0x5A4D and any of them }`, references: [], malware_family: "Obsidium", confidence: "high" },
  { id: "YARA-PC-014", name: "Custom_XOR_Packer", description: "Detects custom single-byte XOR encoded payloads", author: "Darknode Research", date: "2024-02-20", tags: ["packer", "xor", "custom"], rule_text: `rule Custom_XOR_Packer { strings: $xor_loop = { 80 34 ?? ?? 4? 3B ?? 72 } $xor_loop2 = { 30 ?? 4? 3B ?? 72 } $mz_xored = { ?? ?? ?? ?? [8-16] ?? ?? ?? ?? } condition: uint16(0) == 0x5A4D and 1 of ($xor_loop, $xor_loop2) and filesize < 5MB }`, references: [], malware_family: "Custom_XOR", confidence: "low" },
  { id: "YARA-PC-015", name: "Packing_Indicators_Generic", description: "Generic indicators of packed/obfuscated executables", author: "Darknode Research", date: "2024-01-15", tags: ["packer", "generic"], rule_text: `rule Packing_Indicators { meta: description = "Generic packing indicators" strings: $high_entropy_section = { 55 50 58 } $few_imports = "kernel32.dll" ascii $load_library = "LoadLibraryA" ascii $get_proc = "GetProcAddress" ascii $virtual_alloc = "VirtualAlloc" ascii condition: uint16(0) == 0x5A4D and for any i in (0..pe.number_of_sections - 1) : (pe.sections[i].raw_data_size == 0 and pe.sections[i].virtual_size > 0) }`, references: [], malware_family: "Generic", confidence: "low" },

  // ============================================================
  // APT TOOLKITS (30 rules)
  // ============================================================
  { id: "YARA-APT-001", name: "APT28_XAgent", description: "Detects APT28/Fancy Bear XAgent backdoor", author: "Darknode Research", date: "2024-01-15", tags: ["apt", "apt28", "fancybear", "xagent"], rule_text: `rule APT28_XAgent { strings: $s1 = "Sofacy" ascii nocase $s2 = "GAMEFISH" ascii $s3 = "CompletionPort" ascii $mutex = "Mutex_" ascii $http = "POST" ascii $key_exchange = "RSA" ascii condition: uint16(0) == 0x5A4D and 3 of them }`, references: ["https://www.fireeye.com/blog/threat-research/2017/08/apt28-targets-hospitality-sector.html"], malware_family: "XAgent", confidence: "high" },
  { id: "YARA-APT-002", name: "APT29_WellMess", description: "Detects APT29/Cozy Bear WellMess implant", author: "Darknode Research", date: "2024-01-18", tags: ["apt", "apt29", "cozybear", "wellmess"], rule_text: `rule APT29_WellMess { strings: $go = "main.main" ascii $s1 = "WellMess" ascii nocase $s2 = "botlib" ascii $rc6 = "RC6" ascii $c2 = "Cookie:" ascii condition: $go and 2 of ($s1, $s2, $rc6, $c2) }`, references: [], malware_family: "WellMess", confidence: "high" },
  { id: "YARA-APT-003", name: "Lazarus_Manuscrypt", description: "Detects Lazarus Group Manuscrypt backdoor", author: "Darknode Research", date: "2024-01-20", tags: ["apt", "lazarus", "dprk", "manuscrypt"], rule_text: `rule Lazarus_Manuscrypt { strings: $s1 = "Manuscrypt" ascii nocase $fake_tls = { 16 03 01 00 } $rc4 = { 8A 04 ?? 03 C1 25 FF 00 00 00 } $c2_cfg = { 00 00 [4] 00 00 [4] FF } condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "Manuscrypt", confidence: "high" },
  { id: "YARA-APT-004", name: "APT41_ShadowPad", description: "Detects APT41 ShadowPad variant", author: "Darknode Research", date: "2024-01-22", tags: ["apt", "apt41", "shadowpad", "china"], rule_text: `rule APT41_ShadowPad { strings: $decrypt = { 8B 45 ?? 33 45 ?? 89 45 ?? } $plugin = "PluginBase" ascii $timestamp = { 00 00 [4] FF FF FF FF } $c2_encode = "base64" ascii condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "ShadowPad", confidence: "high" },
  { id: "YARA-APT-005", name: "Equation_Group_DoubleFantasy", description: "Detects Equation Group DoubleFantasy implant", author: "Darknode Research", date: "2024-01-25", tags: ["apt", "equation", "nsa", "doublefantasy"], rule_text: `rule DoubleFantasy { strings: $s1 = "DoubleFantasy" ascii nocase $rc5 = { 8B 45 ?? 03 45 ?? C1 C0 } $driver = "\\\\REGISTRY\\\\MACHINE" ascii wide $persist = "\\\\SystemRoot" ascii wide condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "DoubleFantasy", confidence: "high" },
  { id: "YARA-APT-006", name: "Turla_Carbon", description: "Detects Turla Carbon backdoor", author: "Darknode Research", date: "2024-01-28", tags: ["apt", "turla", "carbon", "russia"], rule_text: `rule Turla_Carbon { strings: $s1 = "carbon" ascii nocase $pipe = "\\\\.\\pipe\\\\" ascii $svc = "srservice" ascii $cfg = "carbon_system" ascii condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "Carbon", confidence: "high" },
  { id: "YARA-APT-007", name: "APT32_METALJACK", description: "Detects APT32/OceanLotus METALJACK backdoor", author: "Darknode Research", date: "2024-02-01", tags: ["apt", "apt32", "oceanlotus", "vietnam"], rule_text: `rule APT32_METALJACK { strings: $s1 = "OceanLotus" ascii nocase $side_load = "DllMain" ascii $decrypt = { 31 ?? 83 ?? 04 3B ?? 72 } $ua = "Mozilla" ascii condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "METALJACK", confidence: "medium" },
  { id: "YARA-APT-008", name: "Charming_Kitten_POWERSTAR", description: "Detects Charming Kitten/APT35 POWERSTAR backdoor", author: "Darknode Research", date: "2024-02-05", tags: ["apt", "apt35", "charmingkitten", "iran"], rule_text: `rule POWERSTAR { strings: $ps = "powershell" ascii nocase $b64 = "FromBase64String" ascii $keylog = "GetAsyncKeyState" ascii $c2 = "cloudflare" ascii nocase condition: 3 of them }`, references: [], malware_family: "POWERSTAR", confidence: "medium" },
  { id: "YARA-APT-009", name: "Kimsuky_AppleSeed", description: "Detects Kimsuky/APT43 AppleSeed backdoor", author: "Darknode Research", date: "2024-02-08", tags: ["apt", "kimsuky", "dprk", "appleseed"], rule_text: `rule AppleSeed { strings: $s1 = "AppleSeed" ascii nocase $keylog = "keylog" ascii nocase $screen = "screenshot" ascii nocase $usb = "removable" ascii nocase condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "AppleSeed", confidence: "medium" },
  { id: "YARA-APT-010", name: "MuddyWater_POWERSTATS", description: "Detects MuddyWater POWERSTATS backdoor", author: "Darknode Research", date: "2024-02-10", tags: ["apt", "muddywater", "iran", "powerstats"], rule_text: `rule POWERSTATS { strings: $ps = "powershell" ascii nocase $wmi = "Win32_OperatingSystem" ascii $b64 = "ToBase64String" ascii $screen = "[System.Drawing" ascii $keylog = "GetAsyncKeyState" ascii condition: 3 of them }`, references: [], malware_family: "POWERSTATS", confidence: "medium" },
  { id: "YARA-APT-011", name: "Winnti_Backdoor", description: "Detects Winnti Group backdoor", author: "Darknode Research", date: "2024-02-12", tags: ["apt", "winnti", "china"], rule_text: `rule Winnti { strings: $svc = "ServiceMain" ascii $driver = ".sys" ascii $xor = { 31 ?? 83 ?? 04 3B } $http = "HTTP/1.1" ascii condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "Winnti", confidence: "medium" },
  { id: "YARA-APT-012", name: "SideWinder_APT", description: "Detects SideWinder APT group tools", author: "Darknode Research", date: "2024-02-15", tags: ["apt", "sidewinder", "india"], rule_text: `rule SideWinder { strings: $lnk = { 4C 00 00 00 01 14 02 00 } $hta = "mshta" ascii $ps = "powershell" ascii nocase $dotnet = "_CorExeMain" ascii condition: 2 of them }`, references: [], malware_family: "SideWinder", confidence: "low" },
  { id: "YARA-APT-013", name: "Sandworm_Industroyer2", description: "Detects Sandworm Industroyer2 ICS malware", author: "Darknode Research", date: "2024-02-18", tags: ["apt", "sandworm", "ics", "industroyer"], rule_text: `rule Industroyer2 { strings: $iec104 = { 68 [1] 04 [2] 00 } $station = "station" ascii $iec_cmd = "ASDU" ascii $point = "IOA" ascii condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "Industroyer2", confidence: "high" },
  { id: "YARA-APT-014", name: "Mustang_Panda_PlugX", description: "Detects Mustang Panda customized PlugX", author: "Darknode Research", date: "2024-02-20", tags: ["apt", "mustangpanda", "china", "plugx"], rule_text: `rule Mustang_Panda_PlugX { strings: $side_load = "DllMain" ascii $xor = { 8A 04 ?? 34 ?? 88 04 ?? } $cfg = { 58 58 58 58 } $persist = "Run" ascii wide condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "PlugX", confidence: "medium" },
  { id: "YARA-APT-015", name: "Gamaredon_Pterodo", description: "Detects Gamaredon Pterodo/Pteranodon backdoor", author: "Darknode Research", date: "2024-02-22", tags: ["apt", "gamaredon", "russia", "ukraine"], rule_text: `rule Pterodo { strings: $vbs = "WScript.Shell" ascii $ps = "powershell" ascii nocase $sched = "schtasks" ascii $c2 = ".ddns." ascii condition: 3 of them }`, references: [], malware_family: "Pterodo", confidence: "medium" },
  { id: "YARA-APT-016", name: "DarkHotel_APT", description: "Detects DarkHotel APT espionage tools", author: "Darknode Research", date: "2024-02-25", tags: ["apt", "darkhotel", "southkorea"], rule_text: `rule DarkHotel { strings: $keylog = "GetAsyncKeyState" ascii $screen = "BitBlt" ascii $usb_spread = "autorun.inf" ascii $cert_steal = "CertOpenStore" ascii condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "DarkHotel", confidence: "medium" },
  { id: "YARA-APT-017", name: "Lotus_Panda_Tools", description: "Detects Lotus Panda/Spring Dragon espionage tools", author: "Darknode Research", date: "2024-03-01", tags: ["apt", "lotuspanda", "china"], rule_text: `rule Lotus_Panda { strings: $dll_side = "DllMain" ascii $reg_persist = "CurrentVersion\\Run" ascii wide $http_beacon = "POST /update" ascii $xor_cfg = { 31 ?? 83 ?? 01 3B } condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "LotusPanda", confidence: "low" },
  { id: "YARA-APT-018", name: "Transparent_Tribe", description: "Detects Transparent Tribe/APT36 tools (Pakistan)", author: "Darknode Research", date: "2024-03-05", tags: ["apt", "apt36", "transparenttribe", "pakistan"], rule_text: `rule Transparent_Tribe { strings: $dotnet = "_CorExeMain" ascii $crimson = "Crimson" ascii nocase $keylog = "keylog" ascii nocase $screen = "screenshot" ascii nocase $usb = "removable" ascii nocase condition: uint16(0) == 0x5A4D and $dotnet and 2 of ($crimson, $keylog, $screen, $usb) }`, references: [], malware_family: "CrimsonRAT", confidence: "high" },
  { id: "YARA-APT-019", name: "OilRig_RDAT", description: "Detects OilRig/APT34 RDAT backdoor", author: "Darknode Research", date: "2024-03-08", tags: ["apt", "oilrig", "apt34", "iran"], rule_text: `rule OilRig_RDAT { strings: $exchange = "EWS" ascii $email_c2 = "Exchange Web Services" ascii nocase $steganography = "bitmap" ascii nocase $dns_c2 = "dns" ascii condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "RDAT", confidence: "medium" },
  { id: "YARA-APT-020", name: "Patchwork_BadNews", description: "Detects Patchwork/Dropping Elephant BadNews backdoor", author: "Darknode Research", date: "2024-03-10", tags: ["apt", "patchwork", "india"], rule_text: `rule BadNews { strings: $dotnet = "_CorExeMain" ascii $s1 = "BadNews" ascii nocase $keylog = "GetKeyState" ascii $screen = "CopyFromScreen" ascii condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "BadNews", confidence: "medium" },
  // APT-021 through APT-030
  { id: "YARA-APT-021", name: "Hafnium_Exchange_Webshell", description: "Detects HAFNIUM Exchange exploitation webshells", author: "Darknode Research", date: "2024-03-12", tags: ["apt", "hafnium", "exchange", "china"], rule_text: `rule Hafnium_Shell { strings: $aspx = "<%@" ascii nocase $eval = "eval(Request" ascii nocase $jscript = "JScript" ascii $cmd = "cmd.exe" ascii condition: $aspx and 2 of ($eval, $jscript, $cmd) }`, references: [], malware_family: "HAFNIUM", confidence: "high" },
  { id: "YARA-APT-022", name: "Volt_Typhoon_LOTL", description: "Detects Volt Typhoon living-off-the-land patterns", author: "Darknode Research", date: "2024-03-15", tags: ["apt", "volttyphoon", "china", "lotl"], rule_text: `rule Volt_Typhoon { strings: $ntds = "ntdsutil" ascii $wmic = "wmic process" ascii $netsh = "netsh portproxy" ascii $ssh_tunnel = "ssh -L" ascii $impacket = "secretsdump" ascii condition: 3 of them }`, references: ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a"], malware_family: "VoltTyphoon", confidence: "medium" },
  { id: "YARA-APT-023", name: "Midnight_Blizzard_Tools", description: "Detects Midnight Blizzard/Nobelium post-compromise tools", author: "Darknode Research", date: "2024-03-18", tags: ["apt", "nobelium", "apt29", "russia"], rule_text: `rule Midnight_Blizzard { strings: $dll_side = "DllMain" ascii $cobalt = "beacon" ascii nocase $ad_recon = "ldap" ascii nocase $token = "TokenElevation" ascii condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "Nobelium", confidence: "low" },
  { id: "YARA-APT-024", name: "Scattered_Spider_Tools", description: "Detects Scattered Spider social engineering tools", author: "Darknode Research", date: "2024-03-20", tags: ["apt", "scatteredspider", "socialengineering"], rule_text: `rule Scattered_Spider { strings: $okta = "okta" ascii nocase $mfa_bypass = "MFA" ascii $sim_swap = "phone" ascii $ngrok = "ngrok" ascii $tunnel = "tunnel" ascii condition: 3 of them }`, references: [], malware_family: "ScatteredSpider", confidence: "low" },
  { id: "YARA-APT-025", name: "StormBamboo_Tools", description: "Detects Storm Bamboo/Evasive Panda tools", author: "Darknode Research", date: "2024-03-22", tags: ["apt", "stormbamboo", "china"], rule_text: `rule StormBamboo { strings: $side = "DllMain" ascii $dns_poison = "dns" ascii $isp = "ISP" ascii nocase $supply = "update" ascii condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "StormBamboo", confidence: "low" },
  { id: "YARA-APT-026", name: "Andariel_Tools", description: "Detects Andariel/Lazarus subgroup tools", author: "Darknode Research", date: "2024-03-25", tags: ["apt", "andariel", "lazarus", "dprk"], rule_text: `rule Andariel { strings: $dotnet = "_CorExeMain" ascii $keylog = "keylog" ascii nocase $rdp = "RDP" ascii $proxy = "socks" ascii nocase $crypto = "cryptocurrency" ascii nocase condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "Andariel", confidence: "medium" },
  { id: "YARA-APT-027", name: "APT1_WEBC2", description: "Detects APT1/Comment Crew WEBC2 backdoor", author: "Darknode Research", date: "2024-01-15", tags: ["apt", "apt1", "china", "webc2"], rule_text: `rule APT1_WEBC2 { strings: $s1 = "WEBC2" ascii $http = "GET" ascii $ie_com = "InternetExplorer.Application" ascii $html_parse = "InnerText" ascii condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "WEBC2", confidence: "high" },
  { id: "YARA-APT-028", name: "Scarab_Backdoor", description: "Detects Scarab backdoor (Turkey-linked APT)", author: "Darknode Research", date: "2024-02-01", tags: ["apt", "scarab", "turkey"], rule_text: `rule Scarab { strings: $delphi = "Borland" ascii $s1 = "Scarab" ascii nocase $http_c2 = "POST /cgi-bin" ascii $cmd = "cmd.exe" ascii condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "Scarab", confidence: "medium" },
  { id: "YARA-APT-029", name: "SUNBURST_SolarWinds", description: "Detects SUNBURST backdoor from SolarWinds supply chain attack", author: "Darknode Research", date: "2024-01-15", tags: ["apt", "sunburst", "solarwinds", "apt29"], rule_text: `rule SUNBURST { strings: $dotnet = "_CorExeMain" ascii $s1 = "OrionImprovementBusinessLayer" ascii $s2 = "SolarWinds.Orion.Core.BusinessLayer" ascii $dga = ".avsvmcloud.com" ascii $job_id = "JobEngine" ascii condition: uint16(0) == 0x5A4D and $dotnet and 2 of ($s1, $s2, $dga, $job_id) }`, references: ["https://www.mandiant.com/resources/blog/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor"], malware_family: "SUNBURST", confidence: "high" },
  { id: "YARA-APT-030", name: "XZ_Backdoor", description: "Detects XZ Utils backdoor (CVE-2024-3094)", author: "Darknode Research", date: "2024-04-01", tags: ["apt", "xz", "supply_chain", "backdoor"], rule_text: `rule XZ_Backdoor { strings: $xz = "XZ Utils" ascii $lzma = "liblzma" ascii $sshd = "sshd" ascii $ifunc = "IFUNC" ascii $rsa_key = "RSA_public_decrypt" ascii condition: 3 of them }`, references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-3094"], malware_family: "XZ_Backdoor", confidence: "high" },

  // ============================================================
  // GENERIC SUSPICIOUS INDICATORS (30 rules)
  // ============================================================
  { id: "YARA-GS-001", name: "Suspicious_PowerShell_Download", description: "Detects PowerShell download cradle patterns", author: "Darknode Research", date: "2024-01-15", tags: ["suspicious", "powershell", "download"], rule_text: `rule Suspicious_PS_Download { strings: $iex = "IEX" ascii $iwr = "Invoke-WebRequest" ascii $wc = "Net.WebClient" ascii $dl = "DownloadString" ascii $bypass = "-ExecutionPolicy Bypass" ascii nocase condition: 2 of them }`, references: [], malware_family: "Generic", confidence: "medium" },
  { id: "YARA-GS-002", name: "Suspicious_Process_Injection", description: "Detects common process injection API patterns", author: "Darknode Research", date: "2024-01-18", tags: ["suspicious", "injection"], rule_text: `rule Suspicious_Injection { strings: $alloc = "VirtualAllocEx" ascii $write = "WriteProcessMemory" ascii $thread = "CreateRemoteThread" ascii $open = "OpenProcess" ascii $nt_create = "NtCreateThreadEx" ascii condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "Generic", confidence: "medium" },
  { id: "YARA-GS-003", name: "Suspicious_Persistence_Registry", description: "Detects registry-based persistence mechanisms", author: "Darknode Research", date: "2024-01-20", tags: ["suspicious", "persistence", "registry"], rule_text: `rule Suspicious_Reg_Persist { strings: $run = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide $runonce = "CurrentVersion\\RunOnce" ascii wide $winlogon = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii wide $userinit = "Userinit" ascii wide condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "Generic", confidence: "low" },
  { id: "YARA-GS-004", name: "Suspicious_Credential_Access", description: "Detects credential harvesting indicators", author: "Darknode Research", date: "2024-01-22", tags: ["suspicious", "credentials"], rule_text: `rule Suspicious_Cred_Access { strings: $lsass = "lsass.exe" ascii wide $sam = "\\SAM" ascii wide $ntds = "ntds.dit" ascii $sekurlsa = "sekurlsa" ascii $dpapi = "CryptUnprotectData" ascii condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "Generic", confidence: "medium" },
  { id: "YARA-GS-005", name: "Suspicious_Keylogger", description: "Detects keylogger behavior patterns", author: "Darknode Research", date: "2024-01-25", tags: ["suspicious", "keylogger"], rule_text: `rule Suspicious_Keylogger { strings: $hook = "SetWindowsHookEx" ascii $key1 = "GetAsyncKeyState" ascii $key2 = "GetKeyState" ascii $key3 = "GetKeyboardState" ascii $log = "keylog" ascii nocase $file = "log.txt" ascii condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "Generic", confidence: "medium" },
  { id: "YARA-GS-006", name: "Suspicious_Screen_Capture", description: "Detects screen capture functionality", author: "Darknode Research", date: "2024-01-28", tags: ["suspicious", "screencapture"], rule_text: `rule Suspicious_Screen_Capture { strings: $bitblt = "BitBlt" ascii $getdc = "GetDC" ascii $compat = "CreateCompatibleBitmap" ascii $jpeg = "image/jpeg" ascii $screenshot = "screenshot" ascii nocase condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "Generic", confidence: "low" },
  { id: "YARA-GS-007", name: "Suspicious_AntiDebug", description: "Detects anti-debugging techniques", author: "Darknode Research", date: "2024-02-01", tags: ["suspicious", "antidebug", "evasion"], rule_text: `rule Suspicious_AntiDebug { strings: $s1 = "IsDebuggerPresent" ascii $s2 = "CheckRemoteDebuggerPresent" ascii $s3 = "NtQueryInformationProcess" ascii $s4 = "OutputDebugStringA" ascii $s5 = { 64 A1 30 00 00 00 0F B6 40 02 } condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "Generic", confidence: "low" },
  { id: "YARA-GS-008", name: "Suspicious_AntiVM", description: "Detects anti-VM/sandbox detection techniques", author: "Darknode Research", date: "2024-02-05", tags: ["suspicious", "antivm", "evasion"], rule_text: `rule Suspicious_AntiVM { strings: $vm1 = "VMware" ascii nocase $vm2 = "VirtualBox" ascii nocase $vm3 = "VBOX" ascii $vm4 = "QEMU" ascii $vm5 = "Xen" ascii $wmi = "Win32_ComputerSystem" ascii $cpuid = { 0F A2 } condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "Generic", confidence: "low" },
  { id: "YARA-GS-009", name: "Suspicious_Network_Exfil", description: "Detects data exfiltration patterns", author: "Darknode Research", date: "2024-02-08", tags: ["suspicious", "exfiltration"], rule_text: `rule Suspicious_Exfil { strings: $ftp = "STOR" ascii $smtp = "MAIL FROM:" ascii $http_post = "POST" ascii $dns = "TXT" ascii $b64 = "base64" ascii $zip = "CreateFile" ascii $compress = "compress" ascii nocase condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "Generic", confidence: "low" },
  { id: "YARA-GS-010", name: "Suspicious_Hardcoded_IP", description: "Detects hardcoded IP addresses (potential C2)", author: "Darknode Research", date: "2024-02-10", tags: ["suspicious", "c2", "hardcoded"], rule_text: `rule Suspicious_Hardcoded_IP { strings: $ip_pattern = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}/ ascii $not_local1 = "127.0.0.1" ascii $not_local2 = "0.0.0.0" ascii condition: uint16(0) == 0x5A4D and #ip_pattern > 2 and not $not_local1 and not $not_local2 }`, references: [], malware_family: "Generic", confidence: "low" },
  { id: "YARA-GS-011", name: "Suspicious_DLL_Sideloading", description: "Detects potential DLL sideloading", author: "Darknode Research", date: "2024-02-12", tags: ["suspicious", "sideloading"], rule_text: `rule Suspicious_Sideload { strings: $export = "DllMain" ascii $load = "LoadLibrary" ascii $path = "\\System32\\\\" ascii wide $hijack = "VERSION.dll" ascii nocase condition: uint16(0) == 0x5A4D and 2 of them }`, references: [], malware_family: "Generic", confidence: "low" },
  { id: "YARA-GS-012", name: "Suspicious_AMSI_Bypass", description: "Detects AMSI bypass attempts", author: "Darknode Research", date: "2024-02-15", tags: ["suspicious", "amsi", "bypass"], rule_text: `rule Suspicious_AMSI_Bypass { strings: $amsi = "AmsiScanBuffer" ascii $patch = { B8 57 00 07 80 } $amsi_init = "AmsiInitialize" ascii $disable = "amsiContext" ascii condition: 2 of them }`, references: [], malware_family: "Generic", confidence: "high" },
  { id: "YARA-GS-013", name: "Suspicious_ETW_Patch", description: "Detects ETW patching for evasion", author: "Darknode Research", date: "2024-02-18", tags: ["suspicious", "etw", "evasion"], rule_text: `rule Suspicious_ETW_Patch { strings: $etw = "EtwEventWrite" ascii $ntdll = "ntdll" ascii $patch = { C3 } $write = "WriteProcessMemory" ascii condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "Generic", confidence: "medium" },
  { id: "YARA-GS-014", name: "Suspicious_Syscall_Usage", description: "Detects direct syscall usage for API unhooking", author: "Darknode Research", date: "2024-02-20", tags: ["suspicious", "syscall", "evasion"], rule_text: `rule Suspicious_Syscall { strings: $syscall = { 0F 05 C3 } $nt_func = "Nt" ascii $zw_func = "Zw" ascii $ntdll_map = "ntdll.dll" ascii condition: uint16(0) == 0x5A4D and $syscall and 1 of ($nt_func, $zw_func, $ntdll_map) }`, references: [], malware_family: "Generic", confidence: "medium" },
  { id: "YARA-GS-015", name: "Suspicious_Token_Manipulation", description: "Detects access token manipulation", author: "Darknode Research", date: "2024-02-22", tags: ["suspicious", "token", "privilege"], rule_text: `rule Suspicious_Token { strings: $s1 = "AdjustTokenPrivileges" ascii $s2 = "ImpersonateLoggedOnUser" ascii $s3 = "DuplicateTokenEx" ascii $s4 = "SetThreadToken" ascii $s5 = "CreateProcessAsUser" ascii condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "Generic", confidence: "medium" },
  { id: "YARA-GS-016", name: "Suspicious_WMI_Execution", description: "Detects WMI-based code execution", author: "Darknode Research", date: "2024-02-25", tags: ["suspicious", "wmi", "execution"], rule_text: `rule Suspicious_WMI { strings: $wmi1 = "Win32_Process" ascii $wmi2 = "Win32_OperatingSystem" ascii $create = "Create" ascii $exec = "ExecMethod" ascii $ps = "powershell" ascii nocase condition: 3 of them }`, references: [], malware_family: "Generic", confidence: "low" },
  { id: "YARA-GS-017", name: "Suspicious_Named_Pipe", description: "Detects suspicious named pipe usage for C2", author: "Darknode Research", date: "2024-03-01", tags: ["suspicious", "namedpipe", "c2"], rule_text: `rule Suspicious_Named_Pipe { strings: $create = "CreateNamedPipeW" ascii $connect = "ConnectNamedPipe" ascii $pipe_name = "\\\\\\\\.\\\\pipe\\\\" ascii $impersonate = "ImpersonateNamedPipeClient" ascii condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "Generic", confidence: "low" },
  { id: "YARA-GS-018", name: "Suspicious_Scheduled_Task", description: "Detects scheduled task creation for persistence", author: "Darknode Research", date: "2024-03-05", tags: ["suspicious", "persistence", "scheduledtask"], rule_text: `rule Suspicious_Schtask { strings: $schtasks = "schtasks /create" ascii nocase $xml_task = "<Task" ascii $trigger = "<Triggers>" ascii $action = "<Actions>" ascii $exec = "<Exec>" ascii condition: 3 of them }`, references: [], malware_family: "Generic", confidence: "low" },
  { id: "YARA-GS-019", name: "Suspicious_Service_Creation", description: "Detects suspicious service installation", author: "Darknode Research", date: "2024-03-08", tags: ["suspicious", "persistence", "service"], rule_text: `rule Suspicious_Service { strings: $sc_create = "sc create" ascii nocase $binpath = "binPath=" ascii nocase $auto_start = "start= auto" ascii nocase $service_api = "CreateServiceW" ascii condition: 2 of them }`, references: [], malware_family: "Generic", confidence: "low" },
  { id: "YARA-GS-020", name: "Suspicious_COM_Hijack", description: "Detects COM object hijacking", author: "Darknode Research", date: "2024-03-10", tags: ["suspicious", "persistence", "com"], rule_text: `rule Suspicious_COM_Hijack { strings: $clsid = "CLSID" ascii wide $inproc = "InprocServer32" ascii wide $dll_path = ".dll" ascii $reg_write = "RegSetValueExW" ascii condition: uint16(0) == 0x5A4D and 3 of them }`, references: [], malware_family: "Generic", confidence: "low" },
  { id: "YARA-GS-021", name: "Suspicious_Certutil_Abuse", description: "Detects certutil abuse for download/decode", author: "Darknode Research", date: "2024-03-12", tags: ["suspicious", "certutil", "lolbin"], rule_text: `rule Suspicious_Certutil { strings: $certutil = "certutil" ascii nocase $decode = "-decode" ascii nocase $urlcache = "-urlcache" ascii nocase $split = "-split" ascii nocase condition: $certutil and 1 of ($decode, $urlcache, $split) }`, references: [], malware_family: "Generic", confidence: "high" },
  { id: "YARA-GS-022", name: "Suspicious_Mshta_Abuse", description: "Detects mshta.exe abuse for code execution", author: "Darknode Research", date: "2024-03-15", tags: ["suspicious", "mshta", "lolbin"], rule_text: `rule Suspicious_Mshta { strings: $mshta = "mshta" ascii nocase $vbscript = "vbscript:" ascii nocase $javascript = "javascript:" ascii nocase $http = "http" ascii nocase condition: $mshta and 1 of ($vbscript, $javascript, $http) }`, references: [], malware_family: "Generic", confidence: "high" },
  { id: "YARA-GS-023", name: "Suspicious_Rundll32_Abuse", description: "Detects rundll32.exe abuse", author: "Darknode Research", date: "2024-03-18", tags: ["suspicious", "rundll32", "lolbin"], rule_text: `rule Suspicious_Rundll32 { strings: $rundll = "rundll32" ascii nocase $javascript = "javascript:" ascii nocase $url = "http" ascii $shell32 = "shell32.dll,ShellExec_RunDLL" ascii condition: $rundll and 1 of ($javascript, $url, $shell32) }`, references: [], malware_family: "Generic", confidence: "medium" },
  { id: "YARA-GS-024", name: "Suspicious_Regsvr32_Abuse", description: "Detects regsvr32.exe abuse (Squiblydoo)", author: "Darknode Research", date: "2024-03-20", tags: ["suspicious", "regsvr32", "lolbin", "squiblydoo"], rule_text: `rule Suspicious_Regsvr32 { strings: $regsvr = "regsvr32" ascii nocase $scrobj = "scrobj.dll" ascii nocase $url = "http" ascii $i_flag = "/i:" ascii nocase $s_flag = "/s" ascii nocase condition: $regsvr and 2 of ($scrobj, $url, $i_flag, $s_flag) }`, references: [], malware_family: "Generic", confidence: "high" },
  { id: "YARA-GS-025", name: "Suspicious_WMIC_Abuse", description: "Detects WMIC abuse for code execution", author: "Darknode Research", date: "2024-03-22", tags: ["suspicious", "wmic", "lolbin"], rule_text: `rule Suspicious_WMIC { strings: $wmic = "wmic" ascii nocase $process = "process call create" ascii nocase $xsl = "/format:" ascii nocase $os_get = "os get" ascii nocase condition: $wmic and 1 of ($process, $xsl) }`, references: [], malware_family: "Generic", confidence: "medium" },
  { id: "YARA-GS-026", name: "Suspicious_BITSAdmin", description: "Detects BITSAdmin abuse for download", author: "Darknode Research", date: "2024-03-25", tags: ["suspicious", "bitsadmin", "lolbin"], rule_text: `rule Suspicious_BITSAdmin { strings: $bits = "bitsadmin" ascii nocase $transfer = "/transfer" ascii nocase $addfile = "/addfile" ascii nocase $http = "http" ascii condition: $bits and ($transfer or $addfile) and $http }`, references: [], malware_family: "Generic", confidence: "high" },
  { id: "YARA-GS-027", name: "Suspicious_MSBuild_Abuse", description: "Detects MSBuild abuse for code execution", author: "Darknode Research", date: "2024-03-01", tags: ["suspicious", "msbuild", "lolbin"], rule_text: `rule Suspicious_MSBuild { strings: $msbuild = "MSBuild" ascii nocase $task = "<Task>" ascii $code = "<Code" ascii $csharp = "CSharp" ascii condition: 3 of them }`, references: [], malware_family: "Generic", confidence: "high" },
  { id: "YARA-GS-028", name: "Suspicious_InstallUtil_Abuse", description: "Detects InstallUtil abuse for .NET execution", author: "Darknode Research", date: "2024-03-05", tags: ["suspicious", "installutil", "lolbin"], rule_text: `rule Suspicious_InstallUtil { strings: $installutil = "InstallUtil" ascii nocase $uninstall = "/U" ascii $dotnet = "_CorExeMain" ascii $system_config = "System.Configuration.Install" ascii condition: 2 of them }`, references: [], malware_family: "Generic", confidence: "medium" },
  { id: "YARA-GS-029", name: "Suspicious_Base64_Payload", description: "Detects large Base64 encoded payloads", author: "Darknode Research", date: "2024-03-08", tags: ["suspicious", "base64", "encoded"], rule_text: `rule Suspicious_B64_Payload { strings: $b64_pattern = /[A-Za-z0-9+\/]{200,}={0,2}/ ascii $ps = "powershell" ascii nocase $frombase = "FromBase64String" ascii $decode = "base64_decode" ascii condition: $b64_pattern and 1 of ($ps, $frombase, $decode) }`, references: [], malware_family: "Generic", confidence: "low" },
  { id: "YARA-GS-030", name: "Suspicious_Obfuscated_Script", description: "Detects heavily obfuscated scripts", author: "Darknode Research", date: "2024-01-15", tags: ["suspicious", "obfuscation", "script"], rule_text: `rule Suspicious_Obfuscated { strings: $replace_chain = ".replace(" ascii $split_join = ".split(" ascii $fromchar = "String.fromCharCode" ascii $eval = "eval(" ascii $chr_concat = "chr(" ascii $char_code = "charCodeAt" ascii condition: 4 of them }`, references: [], malware_family: "Generic", confidence: "low" }
];

export const YARA_CATEGORIES = [
  { id: "ransomware", name: "Ransomware", count: 50, description: "File-encrypting malware demanding payment for decryption" },
  { id: "trojan", name: "Trojans & RATs", count: 50, description: "Remote access trojans, infostealers, and banking trojans" },
  { id: "dropper", name: "Droppers & Loaders", count: 30, description: "First-stage malware that downloads and executes payloads" },
  { id: "webshell", name: "Webshells", count: 30, description: "Server-side backdoors for web server persistence" },
  { id: "cryptominer", name: "Cryptominers", count: 20, description: "Cryptocurrency mining malware" },
  { id: "wiper", name: "Wipers", count: 15, description: "Destructive malware that destroys data" },
  { id: "rootkit", name: "Rootkits", count: 15, description: "Kernel/userland rootkits for hiding malware" },
  { id: "exploitkit", name: "Exploit Kits", count: 15, description: "Web-based exploit delivery platforms" },
  { id: "packer", name: "Packers & Crypters", count: 15, description: "Executable packers and obfuscation tools" },
  { id: "apt", name: "APT Toolkits", count: 30, description: "Nation-state and advanced persistent threat tools" },
  { id: "suspicious", name: "Generic Suspicious", count: 30, description: "Generic behavioral indicators of compromise" }
];
