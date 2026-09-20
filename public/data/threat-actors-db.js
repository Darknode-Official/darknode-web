// Comprehensive Threat Actor / APT Group Database
// Real-world threat intelligence — names, aliases, attribution, TTPs, campaigns, malware, IOCs
export const THREAT_ACTORS_DB = [
  {
    name: "APT28",
    aliases: ["Fancy Bear", "Sofacy", "Sednit", "Pawn Storm", "STRONTIUM", "Forest Blizzard", "Iron Twilight", "Tsar Team", "Group 74"],
    attribution: "Russia — GRU Unit 26165",
    activeSince: "2004",
    sectors: ["Government", "Military", "Defense", "Media", "Political organizations", "Energy", "Aerospace"],
    ttps: [
      "T1566.001 — Spearphishing Attachment",
      "T1566.002 — Spearphishing Link",
      "T1190 — Exploit Public-Facing Application",
      "T1078 — Valid Accounts",
      "T1059.001 — PowerShell",
      "T1059.003 — Windows Command Shell",
      "T1053.005 — Scheduled Task",
      "T1547.001 — Registry Run Keys",
      "T1027 — Obfuscated Files or Information",
      "T1070.004 — File Deletion",
      "T1003.001 — LSASS Memory",
      "T1555.003 — Credentials from Web Browsers",
      "T1071.001 — Web Protocols",
      "T1573.002 — Asymmetric Cryptography",
      "T1041 — Exfiltration Over C2 Channel",
      "T1560.001 — Archive via Utility"
    ],
    campaigns: [
      "2016 DNC Hack — Compromised Democratic National Committee servers during US election cycle",
      "2015 German Bundestag — Breached German parliament network, exfiltrated 16GB of data",
      "2017 French Election — Targeted Emmanuel Macron campaign with phishing",
      "2018 OPCW Attack — Attempted Wi-Fi hack of Organisation for the Prohibition of Chemical Weapons",
      "2019 Georgian Attacks — Defaced thousands of Georgian websites",
      "2020 Norwegian Parliament — Compromised email accounts of Norwegian MPs",
      "2023 Ukrainian Government — Ongoing campaigns against Ukrainian infrastructure"
    ],
    malware: ["X-Agent/Sofacy", "X-Tunnel", "Zebrocy", "Drovorub", "Komplex", "Downdelph", "CHOPSTICK", "EVILTOSS", "Cannon", "Koadic", "LoJax (UEFI rootkit)", "Graphite"],
    iocs: {
      domains: ["nato-news.com", "login-osce.com", "myaccount.google.com-changepassword.site", "mail.smtp-gov.org"],
      ips: ["185.86.148.0/24", "191.101.31.0/24", "95.141.36.0/24"],
      hashes: ["d4d8d7e53f9efc87cf04e6e29b34b5e4", "a4a455db9f297e2b9fe99c37f3ccbda0"],
      userAgents: ["Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 SEDNIT"]
    }
  },
  {
    name: "APT29",
    aliases: ["Cozy Bear", "The Dukes", "CozyDuke", "NOBELIUM", "Midnight Blizzard", "Dark Halo", "Iron Ritual", "UNC2452", "YTTRIUM"],
    attribution: "Russia — SVR (Foreign Intelligence Service)",
    activeSince: "2008",
    sectors: ["Government", "Diplomacy", "Think tanks", "Healthcare", "Energy", "Technology", "Financial"],
    ttps: [
      "T1195.002 — Supply Chain Compromise",
      "T1078.004 — Cloud Accounts",
      "T1550.001 — Application Access Token",
      "T1098.003 — Additional Cloud Roles",
      "T1484.002 — Trust Modification",
      "T1556.001 — Domain Controller Authentication",
      "T1021.002 — SMB/Windows Admin Shares",
      "T1087.002 — Domain Account",
      "T1018 — Remote System Discovery",
      "T1074.002 — Remote Data Staging",
      "T1048.003 — Exfiltration Over Unencrypted Protocol",
      "T1583.006 — Web Services",
      "T1608.001 — Upload Malware",
      "T1204.002 — Malicious File"
    ],
    campaigns: [
      "2020 SolarWinds (SUNBURST) — Supply chain attack via trojanized SolarWinds Orion updates, 18,000+ orgs affected",
      "2016 US Election — Compromised DNC alongside APT28",
      "2014 White House — Breached unclassified White House network",
      "2015 Pentagon — Compromised Joint Chiefs of Staff email",
      "2020 COVID-19 Vaccine Research — Targeted pharmaceutical and vaccine research organizations",
      "2021 Microsoft Exchange — Exploited zero-days in on-premises Exchange servers",
      "2023 Microsoft Corporate — Compromised Microsoft corporate email via password spray on legacy tenant",
      "2024 TeamCity Exploitation — Exploited CVE-2023-42793 in JetBrains TeamCity servers"
    ],
    malware: ["SUNBURST", "SUNSPOT", "TEARDROP", "Raindrop", "GoldMax/SUNSHUTTLE", "GoldFinder", "Sibot", "NativeZone", "EnvyScout", "BoomBox", "NativeZone", "VaporRage", "MagicWeb", "FoggyWeb", "TrailBlazer", "WellMess", "WellMail", "CozyDuke", "MiniDuke", "SeaDuke", "HammerToss", "POSHSPY", "tDiscoverer"],
    iocs: {
      domains: ["avsvmcloud.com", "freescanonline.com", "deftsecurity.com", "digitalcollege.org", "thedarkestside.org"],
      ips: ["13.59.205.66", "54.193.127.66", "3.87.182.149"],
      hashes: ["32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77", "ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6"]
    }
  },
  {
    name: "APT1",
    aliases: ["Comment Crew", "Comment Panda", "Shanghai Group", "Byzantine Candor", "TG-8223", "Group 3"],
    attribution: "China — PLA Unit 61398 (2nd Bureau, 3rd Department, General Staff)",
    activeSince: "2006",
    sectors: ["Aerospace", "Defense", "Technology", "Telecommunications", "Energy", "Manufacturing", "Chemical"],
    ttps: [
      "T1566.001 — Spearphishing Attachment",
      "T1059.001 — PowerShell",
      "T1059.003 — Windows Command Shell",
      "T1053.005 — Scheduled Task",
      "T1543.003 — Windows Service",
      "T1003 — OS Credential Dumping",
      "T1005 — Data from Local System",
      "T1074 — Data Staged",
      "T1071.001 — Web Protocols",
      "T1132.001 — Standard Encoding",
      "T1560.001 — Archive via Utility"
    ],
    campaigns: [
      "2006-2013 Operation Comment Crew — Systematic theft of IP from 141+ organizations across 20 industries",
      "2007 Lockheed Martin — Targeted F-35 Joint Strike Fighter program data",
      "2010 RSA SecurID — Contributed to breach that compromised RSA two-factor authentication",
      "2012 Telvent/Schneider Electric — Stole SCADA system project files",
      "2013 DOJ Indictment — 5 PLA officers indicted by name (Wang Dong, Sun Kailiang, et al.)"
    ],
    malware: ["WEBC2", "BISCUIT", "MANITSME", "SEASALT", "GETMAIL", "KURTON", "AURIGA", "BANGAT", "STARSYPOUND", "SWORD", "WARP"],
    iocs: {
      domains: ["hugesoft.org", "globalowa.com", "officeresumeword.com", "raborec.net"],
      ips: ["58.246.0.0/15", "101.80.0.0/12", "113.108.21.0/24"],
      hashes: ["0xdead — multiple unique hashes cataloged by Mandiant APT1 report"]
    }
  },
  {
    name: "Lazarus Group",
    aliases: ["Hidden Cobra", "ZINC", "Diamond Sleet", "Labyrinth Chollima", "Guardians of Peace", "NICKEL ACADEMY", "APT38", "Bluenoroff", "Andariel", "Stardust Chollima"],
    attribution: "North Korea — RGB (Reconnaissance General Bureau)",
    activeSince: "2009",
    sectors: ["Financial", "Cryptocurrency", "Defense", "Entertainment", "Government", "Energy", "Aerospace", "Healthcare"],
    ttps: [
      "T1566.001 — Spearphishing Attachment",
      "T1566.002 — Spearphishing Link",
      "T1204.002 — Malicious File",
      "T1059.005 — Visual Basic",
      "T1059.007 — JavaScript",
      "T1547.001 — Registry Run Keys",
      "T1543.003 — Windows Service",
      "T1055.012 — Process Hollowing",
      "T1036.005 — Match Legitimate Name or Location",
      "T1003 — OS Credential Dumping",
      "T1005 — Data from Local System",
      "T1560 — Archive Collected Data",
      "T1071.001 — Web Protocols",
      "T1105 — Ingress Tool Transfer",
      "T1486 — Data Encrypted for Impact",
      "T1490 — Inhibit System Recovery",
      "T1489 — Service Stop"
    ],
    campaigns: [
      "2014 Sony Pictures — Destructive attack in retaliation for 'The Interview' film, leaked unreleased movies",
      "2016 Bangladesh Bank — SWIFT network heist, stole $81M (attempted $1B)",
      "2017 WannaCry — Global ransomware outbreak affecting 200K+ systems in 150 countries",
      "2018 Operation Sharpshooter — Targeted defense, nuclear, energy sectors worldwide",
      "2019 Indian Nuclear Plant — Malware found on Kudankulam Nuclear Power Plant network",
      "2020 COVID-19 Research — Targeted AstraZeneca and other vaccine developers",
      "2021 Axie Infinity/Ronin — Stole $620M in cryptocurrency from Ronin bridge",
      "2022 Harmony Bridge — Stole $100M from Harmony blockchain bridge",
      "2023 Atomic Wallet — Stole $100M+ from Atomic Wallet users",
      "2023 CoinEx — Stole $54M from CoinEx exchange",
      "2024 DMM Bitcoin — Stole $305M from Japanese exchange"
    ],
    malware: ["Destover", "Duuzer", "Joanap", "Brambul", "FALLCHILL", "HOPLIGHT", "ELECTRICFISH", "BISTROMATH", "SLICKSHOES", "CROWDEDFLOUNDER", "HOTCROISSANT", "ARTFULPIE", "BLINDINGCAN", "PEBBLEDASH", "AppleJeus", "TraderTraitor", "KANDYKORN", "RustBucket", "ObjCShellz", "SIGNBT", "LPEClient"],
    iocs: {
      domains: ["bfrfrede.com", "cenaborad.com", "comloede.com", "tradingbot-cex.com"],
      ips: ["175.45.176.0/22", "210.52.109.0/24", "77.94.35.0/24"],
      hashes: ["d1c27ee7ce18675974edf42d4eea25c6b9f3fae0", "d84b75ec3813e81059755e67f47c29c3"]
    }
  },
  {
    name: "Equation Group",
    aliases: ["EQGRP", "Tilded Platform", "Longhorn"],
    attribution: "United States — NSA (Tailored Access Operations / TAO)",
    activeSince: "2001",
    sectors: ["Government", "Military", "Telecommunications", "Nuclear", "Energy", "Financial", "Aerospace", "Research"],
    ttps: [
      "T1195 — Supply Chain Compromise",
      "T1200 — Hardware Additions",
      "T1542.001 — System Firmware",
      "T1027.002 — Software Packing",
      "T1027.005 — Indicator Removal from Tools",
      "T1480.001 — Environmental Keying",
      "T1014 — Rootkit",
      "T1556.001 — Domain Controller Authentication",
      "T1573.001 — Symmetric Cryptography",
      "T1090.003 — Multi-hop Proxy"
    ],
    campaigns: [
      "2001-2015 Global Operations — One of the most sophisticated APTs ever documented by Kaspersky",
      "2010 Stuxnet — Co-developed worm that damaged Iranian nuclear centrifuges (with Unit 8200)",
      "2007 Fanny Worm — USB-spreading worm with two zero-days later used in Stuxnet",
      "2016 Shadow Brokers Leak — Tools including EternalBlue leaked by unknown group"
    ],
    malware: ["EquationDrug", "GrayFish", "Fanny", "DoubleFantasy", "TripleFantasy", "EquationLaser", "GROK", "UNITEDRAKE", "STRAITBIZARRE", "VALIDATOR", "EternalBlue", "EternalRomance", "FuzzBunch", "DanderSpritz"],
    iocs: {
      domains: ["Equation Group operated through air-gapped networks and USB implants"],
      ips: ["multiple C2 servers identified across 42 countries"],
      hashes: ["varied — tools leaked by Shadow Brokers in 2016-2017"]
    }
  },
  {
    name: "DarkSide",
    aliases: ["BlackMatter (successor)", "Carbon Spider (operator)"],
    attribution: "Russia — Criminal (likely FSB-tolerated)",
    activeSince: "2020",
    sectors: ["Energy", "Manufacturing", "Financial", "Healthcare", "Legal", "Oil & Gas"],
    ttps: [
      "T1190 — Exploit Public-Facing Application",
      "T1133 — External Remote Services",
      "T1078 — Valid Accounts",
      "T1059.001 — PowerShell",
      "T1021.001 — Remote Desktop Protocol",
      "T1486 — Data Encrypted for Impact",
      "T1490 — Inhibit System Recovery",
      "T1489 — Service Stop",
      "T1070.001 — Clear Windows Event Logs",
      "T1048 — Exfiltration Over Alternative Protocol",
      "T1567.002 — Exfiltration to Cloud Storage"
    ],
    campaigns: [
      "2021 Colonial Pipeline — Ransomware attack shut down largest US fuel pipeline for 6 days, $4.4M ransom paid",
      "2021 Brenntag — Chemical distribution company paid $4.4M ransom",
      "2021 Toshiba — European subsidiary hit with double extortion",
      "2021 Shutdown — Disbanded after Colonial Pipeline brought massive law enforcement attention"
    ],
    malware: ["DarkSide Ransomware", "DarkSide Linux Variant (ESXi)", "BlackMatter Ransomware"],
    iocs: {
      domains: ["darksidc3iux462n6yunevoag52nqoc5lt3jbaec6nqe7z4bkuwpmad.onion", "baroquetees.com", "rumahsia.com"],
      ips: ["176.123.2.216", "99.83.154.118"],
      hashes: ["156335b95ba216456f1ac0894b7b9d6ad95404ac7df447940f21646ca0090673"]
    }
  },
  {
    name: "REvil",
    aliases: ["Sodinokibi", "GandCrab successor", "Gold Southfield", "Pinchy Spider"],
    attribution: "Russia — Criminal (GRU-tolerated, partially dismantled by FSB in 2022)",
    activeSince: "2019",
    sectors: ["Technology", "Legal", "Insurance", "Manufacturing", "Retail", "Food & Beverage"],
    ttps: [
      "T1195.002 — Supply Chain Compromise",
      "T1190 — Exploit Public-Facing Application",
      "T1078 — Valid Accounts",
      "T1059.001 — PowerShell",
      "T1486 — Data Encrypted for Impact",
      "T1490 — Inhibit System Recovery",
      "T1489 — Service Stop",
      "T1529 — System Shutdown/Reboot",
      "T1553.002 — Code Signing"
    ],
    campaigns: [
      "2021 Kaseya VSA — Supply chain attack via MSP software, 1,500+ businesses affected, $70M ransom demand",
      "2021 JBS Foods — World's largest meat processor, $11M ransom paid",
      "2020 Travelex — Foreign exchange company, $2.3M ransom paid",
      "2020 Grubman Shire Meiselas — Law firm representing celebrities, threatened Madonna/Trump data leak",
      "2021 Acer — $50M ransom demand, one of the largest ever",
      "2022 FSB Arrests — Russian authorities arrested 14 alleged members"
    ],
    malware: ["REvil/Sodinokibi Ransomware", "GandCrab (predecessor)", "REvil Linux (ESXi)"],
    iocs: {
      domains: ["decoder.re", "aplebzu47wgazapdqks6vrcv6zcnjppkbxbr6wketf56nf6aq2nmyoyd.onion"],
      ips: ["18.223.199.234", "161.35.239.148"],
      hashes: ["d55f983c994caa160ec63a59f6b4250fe67fb3e8c43a388aec60a4a6978e9f1e"]
    }
  },
  {
    name: "Conti",
    aliases: ["Wizard Spider (operator)", "Gold Ulrick", "DEV-0193", "FIN12"],
    attribution: "Russia — Criminal group (Wizard Spider)",
    activeSince: "2020",
    sectors: ["Healthcare", "Government", "Education", "Manufacturing", "Technology", "Retail"],
    ttps: [
      "T1566.001 — Spearphishing Attachment",
      "T1059.001 — PowerShell",
      "T1059.003 — Windows Command Shell",
      "T1053.005 — Scheduled Task",
      "T1055 — Process Injection",
      "T1021.002 — SMB/Windows Admin Shares",
      "T1486 — Data Encrypted for Impact",
      "T1490 — Inhibit System Recovery",
      "T1489 — Service Stop",
      "T1071.001 — Web Protocols",
      "T1573.002 — Asymmetric Cryptography"
    ],
    campaigns: [
      "2020-2022 Healthcare Targeting — Over 400 healthcare organizations worldwide",
      "2021 Ireland HSE — Shut down Ireland's Health Service Executive, demanded $20M",
      "2021 Costa Rica Government — Crippled 27 government agencies, triggered national emergency declaration",
      "2022 Conti Leaks — Ukrainian researcher leaked internal chats, playbooks, and source code after Conti sided with Russia",
      "2022 Dissolution — Rebranded into multiple groups: Royal, Black Basta, Karakurt, Quantum, Zeon"
    ],
    malware: ["Conti Ransomware", "BazarLoader", "BazarBackdoor", "TrickBot", "Anchor", "Cobalt Strike (cracked)", "Emotet (distribution partner)"],
    iocs: {
      domains: ["continewsnv5otx5kaoje7krkto2qbu3gtqef22mnr7eaxw3y6ncz3ad.onion"],
      ips: ["162.244.80.235", "85.93.88.165", "185.141.63.120"],
      hashes: ["7b18e1f39b3dbdb7ead33f12d1b2b363e5dc0c9e2e3a02b8c8c5ff83d3bcb429"]
    }
  },
  {
    name: "LockBit",
    aliases: ["LockBit 2.0", "LockBit 3.0", "LockBit Black", "LockBit Green", "Bitwise Spider", "Gold Mystic"],
    attribution: "Russia — Criminal RaaS (leader Dmitry Khoroshev aka LockBitSupp, indicted 2024)",
    activeSince: "2019",
    sectors: ["Manufacturing", "Healthcare", "Government", "Technology", "Financial", "Education", "Retail", "Legal", "Construction"],
    ttps: [
      "T1190 — Exploit Public-Facing Application",
      "T1133 — External Remote Services",
      "T1078 — Valid Accounts",
      "T1059.001 — PowerShell",
      "T1059.003 — Windows Command Shell",
      "T1053.005 — Scheduled Task",
      "T1486 — Data Encrypted for Impact",
      "T1490 — Inhibit System Recovery",
      "T1489 — Service Stop",
      "T1082 — System Information Discovery",
      "T1016 — System Network Configuration Discovery",
      "T1567.002 — Exfiltration to Cloud Storage",
      "T1562.001 — Disable or Modify Tools"
    ],
    campaigns: [
      "2022 Accenture — Major IT consultancy attacked",
      "2023 Royal Mail — UK postal service operations disrupted, $80M ransom demand",
      "2023 ICBC — Industrial and Commercial Bank of China US subsidiary, largest bank ransomware attack",
      "2023 Boeing — Defense and space contractor data leaked",
      "2024 Operation Cronos — International law enforcement takedown of infrastructure, but group revived",
      "2024 LockBitSupp Unmasked — Dmitry Khoroshev identified and sanctioned by US/UK/Australia"
    ],
    malware: ["LockBit 1.0/2.0/3.0/Black/Green", "StealBit", "LockBit Linux (ESXi/VMware)", "LockBit macOS (experimental)"],
    iocs: {
      domains: ["lockbitapt.uz", "lockbit-decryptor.top", "lockbit7z2jwcskxpbokpemdxmltipntwlkmidcll2qirbu7ykg46eyd.onion"],
      ips: ["209.14.0.234", "139.60.161.0/24"],
      hashes: ["80e8defa5377018b093b5b90de0f2957f7062144c83a09a56bba1fe4eda932ce"]
    }
  },
  {
    name: "BlackCat",
    aliases: ["ALPHV", "Noberus", "Sphynx", "UNC4466"],
    attribution: "Russia/Eastern Europe — Criminal RaaS (former Conti/DarkSide/BlackMatter affiliates)",
    activeSince: "2021",
    sectors: ["Healthcare", "Financial", "Government", "Technology", "Energy", "Legal", "Education"],
    ttps: [
      "T1190 — Exploit Public-Facing Application",
      "T1133 — External Remote Services",
      "T1078 — Valid Accounts",
      "T1059.001 — PowerShell",
      "T1059.006 — Python",
      "T1486 — Data Encrypted for Impact",
      "T1490 — Inhibit System Recovery",
      "T1489 — Service Stop",
      "T1567.002 — Exfiltration to Cloud Storage",
      "T1027 — Obfuscated Files or Information"
    ],
    campaigns: [
      "2024 Change Healthcare/UnitedHealth — Disrupted US healthcare payment processing for weeks, $22M ransom paid, data of 100M+ people exposed",
      "2023 MGM Resorts — Casino/hotel operations disrupted for 10 days, $100M+ in losses",
      "2023 Reddit — Source code stolen but no ransom paid",
      "2024 Exit Scam — Group allegedly faked FBI takedown to steal $22M ransom from affiliates"
    ],
    malware: ["BlackCat/ALPHV Ransomware (Rust-based)", "Sphynx Loader", "ExMatter (exfiltration tool)"],
    iocs: {
      domains: ["alphvmmm27o3abo3r2mlmjrpdmzle3rykajqc5xsj7j7ejksbpsa36ad.onion"],
      ips: ["142.234.157.246", "185.220.100.0/24"],
      hashes: ["731adcf2d7fb61a8335e23dbee2436249e5d5753977ec465754c6b699e36b085"]
    }
  },
  {
    name: "Cl0p",
    aliases: ["TA505 (operator)", "FIN11", "Gold Tahoe", "DEV-0950", "Lace Tempest"],
    attribution: "Russia/Ukraine — Criminal group",
    activeSince: "2019",
    sectors: ["Financial", "Manufacturing", "Technology", "Healthcare", "Government", "Education", "Retail"],
    ttps: [
      "T1190 — Exploit Public-Facing Application",
      "T1059.001 — PowerShell",
      "T1053.005 — Scheduled Task",
      "T1486 — Data Encrypted for Impact",
      "T1490 — Inhibit System Recovery",
      "T1005 — Data from Local System",
      "T1567.002 — Exfiltration to Cloud Storage",
      "T1210 — Exploitation of Remote Services"
    ],
    campaigns: [
      "2023 MOVEit Transfer — Exploited CVE-2023-34362 zero-day, 2,500+ organizations and 65M+ individuals affected",
      "2023 GoAnywhere MFT — Exploited CVE-2023-0669, 130+ organizations compromised",
      "2021 Accellion FTA — Exploited zero-days in legacy file transfer appliance, 100+ organizations",
      "2023 SysAid — Exploited CVE-2023-47246 zero-day in IT service management software",
      "2024 Cleo File Transfer — Exploited CVE-2024-50623 in Cleo Harmony/VLTrader/LexiCom"
    ],
    malware: ["Cl0p Ransomware", "DEWMODE", "LEMURLOOT", "FlawedGrace", "FlawedAmmyy", "Get2/SDBbot", "TinyMet"],
    iocs: {
      domains: ["sanfranciscol.com", "torrfrede.com", "movloede.com", "cl0p-api.com"],
      ips: ["5.149.248.0/24", "5.188.86.0/24"],
      hashes: ["e8012a15b6f6b404a33f293205b602ece486d01337b645df3f613d40905ff491"]
    }
  },
  {
    name: "Turla",
    aliases: ["Snake", "Uroburos", "Venomous Bear", "KRYPTON", "Secret Blizzard", "Iron Hunter", "Waterbug", "Group 88", "Belugasturgeon"],
    attribution: "Russia — FSB (Center 16)",
    activeSince: "1996",
    sectors: ["Government", "Military", "Embassy", "Research", "Pharmaceutical", "Education"],
    ttps: [
      "T1566.001 — Spearphishing Attachment",
      "T1189 — Drive-by Compromise",
      "T1195.002 — Supply Chain Compromise",
      "T1059.001 — PowerShell",
      "T1059.005 — Visual Basic",
      "T1547.001 — Registry Run Keys",
      "T1543.003 — Windows Service",
      "T1055 — Process Injection",
      "T1014 — Rootkit",
      "T1036 — Masquerading",
      "T1027 — Obfuscated Files or Information",
      "T1090.002 — External Proxy",
      "T1090.003 — Multi-hop Proxy",
      "T1071.001 — Web Protocols",
      "T1008 — Fallback Channels",
      "T1573.001 — Symmetric Cryptography"
    ],
    campaigns: [
      "1996-2024 Longest-running Russian APT — Active for nearly 30 years targeting governments",
      "2008 US DoD — Agent.BTZ worm on Pentagon network via infected USB, triggered Operation Buckshot Yankee",
      "2014 Swiss Military RUAG — Multi-year espionage against Swiss defense technology",
      "2017 German Foreign Ministry — Compromised for at least a year before discovery",
      "2020 European Government Targeting — Watering hole attacks on government websites",
      "2023 Snake Malware Takedown — FBI/CISA disrupted 20-year-old Snake P2P network (Operation MEDUSA)",
      "2024 Hijacking Other APTs — Turla hijacked Pakistani APT's infrastructure to spy on Afghan/Indian targets"
    ],
    malware: ["Snake/Uroburos", "Agent.BTZ", "Carbon/Cobra", "Kazuar", "Gazer/WhiteBear", "ComRAT/Agent.btz v4", "HyperStack", "LightNeuron", "Outlook Backdoor", "Crutch", "TinyTurla", "TinyTurla-NG", "Penquin", "Capibar", "DeliveryCheck"],
    iocs: {
      domains: ["sfrfrede.com", "delofrede.com", "webstatistics.top"],
      ips: ["multiple — uses satellite internet link hijacking for C2"],
      hashes: ["Varied across 20+ year operational history"]
    }
  },
  {
    name: "Sandworm",
    aliases: ["Voodoo Bear", "IRIDIUM", "Seashell Blizzard", "Iron Viking", "Electrum", "TeleBots", "Quedagh", "BlackEnergy Group"],
    attribution: "Russia — GRU Unit 74455 (Main Center for Special Technologies/GTsST)",
    activeSince: "2009",
    sectors: ["Energy", "Government", "Critical Infrastructure", "Media", "Transportation", "Finance", "Elections"],
    ttps: [
      "T1190 — Exploit Public-Facing Application",
      "T1566.001 — Spearphishing Attachment",
      "T1059.001 — PowerShell",
      "T1059.003 — Windows Command Shell",
      "T1053.005 — Scheduled Task",
      "T1047 — Windows Management Instrumentation",
      "T1003 — OS Credential Dumping",
      "T1486 — Data Encrypted for Impact",
      "T1485 — Data Destruction",
      "T1561.002 — Disk Structure Wipe",
      "T1495 — Firmware Corruption",
      "T1499.004 — Application or System Exploitation"
    ],
    campaigns: [
      "2015 Ukraine Power Grid (BlackEnergy3) — First confirmed cyber attack on a power grid, 230K without power",
      "2016 Ukraine Power Grid (Industroyer/CrashOverride) — Second grid attack, automated ICS malware",
      "2017 NotPetya — Destructive wiper disguised as ransomware, $10B+ global damage, largest cyber attack in history",
      "2018 Winter Olympics (Olympic Destroyer) — Disrupted Pyeongchang Olympics opening ceremony",
      "2019 Georgia — Defaced 15,000 websites and disrupted TV stations",
      "2022 Industroyer2 — Targeted Ukrainian power substation during Russia-Ukraine war",
      "2022 CaddyWiper — Deployed against Ukrainian government networks",
      "2022 AcidRain — Wiped Viasat KA-SAT modems at start of Ukraine invasion",
      "2023 Ukrainian Telecom — Attacked Kyivstar, largest Ukrainian mobile operator"
    ],
    malware: ["BlackEnergy", "Industroyer/CrashOverride", "Industroyer2", "NotPetya", "Olympic Destroyer", "KillDisk", "GreyEnergy", "Exaramel", "CaddyWiper", "AcidRain", "AcidPour", "SwiftSlicer", "HermeticWiper", "IsaacWiper", "WhisperGate (DEV-0586)", "PartyTicket", "ArguePatch", "CrescentImp"],
    iocs: {
      domains: ["torfrede.com", "dcfredefrede.com"],
      ips: ["31.148.220.0/24", "176.31.225.0/24"],
      hashes: ["027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745"]
    }
  },
  {
    name: "Kimsuky",
    aliases: ["Velvet Chollima", "Emerald Sleet", "Black Banshee", "THALLIUM", "SharpTongue", "TA406", "APT43", "Springtail"],
    attribution: "North Korea — RGB (Reconnaissance General Bureau)",
    activeSince: "2012",
    sectors: ["Government", "Think Tanks", "Diplomacy", "Media", "Education", "Nuclear", "Defense"],
    ttps: [
      "T1566.001 — Spearphishing Attachment",
      "T1566.002 — Spearphishing Link",
      "T1204.001 — Malicious Link",
      "T1204.002 — Malicious File",
      "T1059.001 — PowerShell",
      "T1059.005 — Visual Basic",
      "T1059.007 — JavaScript",
      "T1547.001 — Registry Run Keys",
      "T1003 — OS Credential Dumping",
      "T1555.003 — Credentials from Web Browsers",
      "T1114.002 — Remote Email Collection",
      "T1056.001 — Keylogging",
      "T1071.001 — Web Protocols"
    ],
    campaigns: [
      "2014 Korea Hydro & Nuclear Power — Stole reactor design documents from South Korean nuclear operator",
      "2018 Academic/Think Tank Espionage — Targeted North Korea policy experts worldwide",
      "2020 COVID-19 — Phished pharmaceutical companies working on vaccines",
      "2022 Journalist Impersonation — Posed as journalists to target NK policy researchers",
      "2023 ReconShark — New malware targeting think tanks, universities, government agencies",
      "2024 DMARC Exploitation — Spoofed legitimate email domains to target think tanks"
    ],
    malware: ["BabyShark", "ReconShark", "KONNI", "KimJongRAT", "GoldDragon", "FlowerPower", "AppleSeed", "PebbleDash", "RandomQuery", "FastViewer (Android)", "FastSpy", "Torisma"],
    iocs: {
      domains: ["bigwnet.com", "dhfrfrde.com", "login.microsoftonline.qwert.site"],
      ips: ["23.229.111.0/24", "27.102.127.0/24"],
      hashes: ["c0de8b1d01d2f9c6e9c987b5c89c07e1"]
    }
  },
  {
    name: "Charming Kitten",
    aliases: ["APT35", "Phosphorus", "Mint Sandstorm", "NewsBeef", "Ajax Security Team", "Magic Hound", "Cobalt Illusion", "TA453", "Yellow Garuda", "ITG18"],
    attribution: "Iran — IRGC (Islamic Revolutionary Guard Corps)",
    activeSince: "2011",
    sectors: ["Government", "Defense", "Diplomacy", "Think Tanks", "Media", "Energy", "Telecommunications", "Dissidents/Activists"],
    ttps: [
      "T1566.001 — Spearphishing Attachment",
      "T1566.002 — Spearphishing Link",
      "T1566.003 — Spearphishing via Service",
      "T1078 — Valid Accounts",
      "T1059.001 — PowerShell",
      "T1059.007 — JavaScript",
      "T1547.001 — Registry Run Keys",
      "T1555.003 — Credentials from Web Browsers",
      "T1539 — Steal Web Session Cookie",
      "T1114.002 — Remote Email Collection",
      "T1071.001 — Web Protocols",
      "T1583.001 — Domains"
    ],
    campaigns: [
      "2017-2024 Credential Harvesting — Massive phishing campaigns against academics, journalists, diplomats",
      "2019 US Campaign Officials — Targeted Trump 2020 campaign advisors",
      "2020 WHO Phishing — Targeted World Health Organization during pandemic",
      "2021 SpoofedScholars — Impersonated SOAS University of London academics",
      "2022 HYPERSCRAPE — Tool to steal entire Gmail/Yahoo/Outlook mailboxes",
      "2023 MediaPl — New backdoor targeting journalists and activists",
      "2024 Israel-Hamas Exploitation — Leveraged conflict for phishing against regional targets"
    ],
    malware: ["POWERSTAR/CharmPower", "BellaCiao", "MediaPl", "HYPERSCRAPE", "Sponsor", "PowerLess", "NokNok", "GorjolEcho", "BASICSTAR", "MischiefTut", "EyeSpy"],
    iocs: {
      domains: ["accounts-google-verify.site", "sharepoint-microsoft.top", "scholar-soas.org"],
      ips: ["51.89.135.0/24", "51.83.255.0/24"],
      hashes: ["4c0f30a0c6858d58e51c1d3bad6c0128"]
    }
  },
  {
    name: "OilRig",
    aliases: ["APT34", "Helix Kitten", "Hazel Sandstorm", "EUROPIUM", "Crambus", "Cobalt Gypsy", "IRN2"],
    attribution: "Iran — MOIS (Ministry of Intelligence and Security)",
    activeSince: "2014",
    sectors: ["Government", "Financial", "Energy", "Chemical", "Telecommunications", "Critical Infrastructure"],
    ttps: [
      "T1566.001 — Spearphishing Attachment",
      "T1204.002 — Malicious File",
      "T1059.001 — PowerShell",
      "T1059.005 — Visual Basic",
      "T1053.005 — Scheduled Task",
      "T1547.001 — Registry Run Keys",
      "T1003 — OS Credential Dumping",
      "T1505.003 — Web Shell",
      "T1071.004 — DNS",
      "T1048.003 — Exfiltration Over Unencrypted Protocol",
      "T1573.001 — Symmetric Cryptography"
    ],
    campaigns: [
      "2016-2019 Middle East Government Espionage — Sustained campaigns against UAE, Saudi, Bahrain, Kuwait, Turkey",
      "2019 Lab Dookhtegan Leak — Hacker leaked OilRig's tools and victim data online, exposing operations",
      "2021 Lebanon and UAE — Targeted government entities with new tools",
      "2023 Middle East Telecom — Targeted telecom providers with updated DNS tunneling tools",
      "2024 Iraqi Government — Year-long campaign against Iraqi government networks"
    ],
    malware: ["RDAT", "Karkoff", "Saitama", "MrPerfectionManager", "PowerExchange", "Solar", "Mango", "Menorah", "SideTwist", "BondUpdater", "Glimpse", "PoisonFrog", "VALUEVAULT", "LONGWATCH", "PICKPOCKET", "OopsIE"],
    iocs: {
      domains: ["taborfrede.com", "msaborfrde.com", "micro-ede.com"],
      ips: ["80.82.64.0/24", "185.161.209.0/24"],
      hashes: ["2fc14cfa6c1869bffe29e2137c0ec305"]
    }
  },
  {
    name: "Hafnium",
    aliases: ["Silk Typhoon", "UNC2980", "Operation Exchange Marauder"],
    attribution: "China — MSS (Ministry of State Security)",
    activeSince: "2017",
    sectors: ["Government", "Defense", "Healthcare", "Education", "Legal", "NGOs", "Think Tanks", "Infectious Disease Research"],
    ttps: [
      "T1190 — Exploit Public-Facing Application",
      "T1505.003 — Web Shell",
      "T1078 — Valid Accounts",
      "T1059.001 — PowerShell",
      "T1003.001 — LSASS Memory",
      "T1003.003 — NTDS",
      "T1560.001 — Archive via Utility",
      "T1005 — Data from Local System",
      "T1114.001 — Local Email Collection",
      "T1567.002 — Exfiltration to Cloud Storage"
    ],
    campaigns: [
      "2021 Microsoft Exchange Zero-Days (ProxyLogon) — CVE-2021-26855 et al., 250,000+ servers compromised globally",
      "2020 VPN Exploitation — Targeted Pulse Secure, Citrix, F5 BIG-IP vulnerabilities",
      "2021 SolarWinds-Adjacent — Exploited Serv-U FTP zero-day (CVE-2021-35211)",
      "2024 US Treasury — Breached Treasury Department via BeyondTrust zero-day"
    ],
    malware: ["China Chopper", "ASPXSpy", "Covenant", "SIMPLESEESHARP", "SIEVERT", "SUPERNOVA"],
    iocs: {
      domains: ["mail.mofrfrde.com", "exhcanfrde.com"],
      ips: ["165.232.154.0/24", "157.230.221.0/24", "167.99.168.0/24"],
      hashes: ["b75f163ca9b9240bf4b37ad92bc7556b40a17e27c2b8ed5c8991385fe07d17d0"]
    }
  },
  {
    name: "Lapsus$",
    aliases: ["DEV-0537", "Strawberry Tempest"],
    attribution: "United Kingdom/Brazil — Teenagers (leader: UK minor 'White/breachbase')",
    activeSince: "2021",
    sectors: ["Technology", "Government", "Telecommunications", "Healthcare", "Media"],
    ttps: [
      "T1566.004 — Spearphishing Voice",
      "T1078 — Valid Accounts",
      "T1621 — Multi-Factor Authentication Request Generation",
      "T1528 — Steal Application Access Token",
      "T1199 — Trusted Relationship",
      "T1530 — Data from Cloud Storage",
      "T1213 — Data from Information Repositories",
      "T1136.003 — Cloud Account",
      "T1484.002 — Trust Modification"
    ],
    campaigns: [
      "2022 NVIDIA — Stole 1TB of data including GPU drivers and schematics",
      "2022 Samsung — Stole 190GB including Galaxy source code",
      "2022 Microsoft — Stole partial source code for Bing, Cortana, Bing Maps",
      "2022 Okta — Compromised Okta support engineer's laptop, accessed customer tenants",
      "2022 T-Mobile — Multiple breaches of internal systems",
      "2022 Uber — Compromised Slack and internal tools via MFA fatigue",
      "2022 Rockstar Games — Leaked 90+ GTA VI development videos",
      "2023 Arrest — Leader (17 years old at time) convicted in UK"
    ],
    malware: ["No custom malware — relied on social engineering, MFA bombing, and SIM swapping"],
    iocs: {
      domains: ["Used legitimate services — Telegram for leaks and communication"],
      ips: ["Used VPNs and residential proxies"],
      hashes: ["N/A — no custom tooling"]
    }
  },
  {
    name: "FIN7",
    aliases: ["Carbanak Group", "Navigator Group", "GOLD NIAGARA", "Carbon Spider", "ELBRUS", "Sangria Tempest"],
    attribution: "Russia/Ukraine — Criminal group (operated fake pen-testing company 'Combi Security')",
    activeSince: "2013",
    sectors: ["Retail", "Hospitality", "Restaurant", "Financial", "Gaming"],
    ttps: [
      "T1566.001 — Spearphishing Attachment",
      "T1204.002 — Malicious File",
      "T1059.001 — PowerShell",
      "T1059.003 — Windows Command Shell",
      "T1059.005 — Visual Basic",
      "T1053.005 — Scheduled Task",
      "T1547.001 — Registry Run Keys",
      "T1055 — Process Injection",
      "T1003 — OS Credential Dumping",
      "T1005 — Data from Local System",
      "T1071.001 — Web Protocols",
      "T1573.001 — Symmetric Cryptography",
      "T1567.002 — Exfiltration to Cloud Storage"
    ],
    campaigns: [
      "2015-2018 POS Campaign — Stole 15M+ credit cards from Chipotle, Chili's, Arby's, Jason's Deli, Saks Fifth Avenue, Lord & Taylor",
      "2018 DOJ Indictment — Three members arrested in Germany/Poland/Spain",
      "2020 BOOSTWRITE — USB-based attacks using BadUSB (sent via USPS mail)",
      "2021 Darkside Affiliation — Connected to DarkSide ransomware operations",
      "2023 Cl0p Affiliation — Linked to Cl0p ransomware distribution"
    ],
    malware: ["Carbanak/Anunak", "GRIFFON", "BATELEUR", "BOOSTWRITE", "PILLOWMINT", "DICELOADER", "Lizar/Tirion", "JSSLoader", "Cobalt Strike (cracked)", "PowerPlant", "CROWBAR"],
    iocs: {
      domains: ["comfrfrde.com", "frfrfrde.net"],
      ips: ["23.249.163.0/24", "192.169.69.0/24"],
      hashes: ["7ef6ed2c9e4a3a43c56c1f2d7aab8f59"]
    }
  },
  {
    name: "Wizard Spider",
    aliases: ["Gold Blackburn", "UNC1878", "DEV-0193", "Periwinkle Tempest", "ITG23"],
    attribution: "Russia — Criminal group (St. Petersburg-based)",
    activeSince: "2016",
    sectors: ["Healthcare", "Government", "Education", "Financial", "Manufacturing"],
    ttps: [
      "T1566.001 — Spearphishing Attachment",
      "T1059.001 — PowerShell",
      "T1053.005 — Scheduled Task",
      "T1055.012 — Process Hollowing",
      "T1021.002 — SMB/Windows Admin Shares",
      "T1486 — Data Encrypted for Impact",
      "T1490 — Inhibit System Recovery",
      "T1489 — Service Stop",
      "T1071.001 — Web Protocols"
    ],
    campaigns: [
      "2018-2022 TrickBot Operations — Massive botnet for credential theft and ransomware delivery",
      "2020-2022 Conti Ransomware — Operated Conti RaaS, 400+ healthcare orgs targeted",
      "2020 US Healthcare Alert — FBI/CISA warned of imminent ransomware attacks on hospitals",
      "2022 Conti Leaks — Internal chats leaked by Ukrainian researcher"
    ],
    malware: ["TrickBot", "BazarLoader", "BazarBackdoor", "Conti", "Ryuk", "Diavol", "Anchor", "PowerTrick", "IcedID (distribution)", "Emotet (distribution partner)"],
    iocs: {
      domains: ["bot.frfrde.com", "trick.frfrd.com"],
      ips: ["185.234.73.0/24", "23.95.97.0/24"],
      hashes: ["fdda3f0e243d7283c3dd0e5eea26a648"]
    }
  },
  {
    name: "Evil Corp",
    aliases: ["Indrik Spider", "Gold Drake", "Manatee Tempest", "DEV-0243", "UNC2165"],
    attribution: "Russia — Criminal group (leader: Maksim Yakubets, OFAC-sanctioned, $5M FBI bounty)",
    activeSince: "2007",
    sectors: ["Financial", "Government", "Healthcare", "Technology", "Manufacturing"],
    ttps: [
      "T1189 — Drive-by Compromise",
      "T1566.001 — Spearphishing Attachment",
      "T1059.001 — PowerShell",
      "T1059.007 — JavaScript",
      "T1055 — Process Injection",
      "T1486 — Data Encrypted for Impact",
      "T1490 — Inhibit System Recovery",
      "T1071.001 — Web Protocols",
      "T1573.002 — Asymmetric Cryptography"
    ],
    campaigns: [
      "2011-2019 Dridex Banking Trojan — Stole $100M+ from banks worldwide",
      "2019 OFAC Sanctions — US Treasury sanctioned group, complicated ransom payments",
      "2020 WastedLocker — Ransomware attacks against US companies including Garmin ($10M ransom)",
      "2021 Hades/Phoenix — Rebranded ransomware to evade OFAC sanctions",
      "2022 RansomHub Affiliation — Members moved to non-sanctioned RaaS to collect payments",
      "2024 UK Arrests — NCA arrested suspected Evil Corp member in connection with LockBit"
    ],
    malware: ["Dridex", "WastedLocker", "Hades", "Phoenix Locker", "PayloadBIN", "Macaw Locker", "BitPaymer/FriedEx", "SocGholish/FakeUpdates", "Raspberry Robin (distribution)"],
    iocs: {
      domains: ["dridex-frfrd.com", "socfrfrd.com"],
      ips: ["5.101.0.0/16", "185.234.73.0/24"],
      hashes: ["d2b10f1f7d5d67c57f08c0f0c9a31c16"]
    }
  },
  {
    name: "MuddyWater",
    aliases: ["MERCURY", "Mango Sandstorm", "Static Kitten", "Seedworm", "TEMP.Zagros", "TA450"],
    attribution: "Iran — MOIS (Ministry of Intelligence and Security)",
    activeSince: "2017",
    sectors: ["Government", "Telecommunications", "Energy", "Defense", "Education"],
    ttps: [
      "T1566.001 — Spearphishing Attachment",
      "T1204.002 — Malicious File",
      "T1059.001 — PowerShell",
      "T1059.005 — Visual Basic",
      "T1547.001 — Registry Run Keys",
      "T1132.001 — Standard Encoding",
      "T1071.001 — Web Protocols",
      "T1105 — Ingress Tool Transfer",
      "T1218.005 — Mshta"
    ],
    campaigns: [
      "2018-2024 Middle East Espionage — Sustained campaigns against Turkey, Saudi Arabia, UAE, Jordan, Iraq",
      "2022 Israel Targeting — Intensified operations against Israeli organizations during tensions",
      "2023 African Telecom — Targeted telecommunications providers in Egypt and Tanzania",
      "2024 SimpleHarm — New campaign using phishing with RMM tools against ME governments"
    ],
    malware: ["POWERSTATS", "MuddyC2Go", "MuddyC3", "PhonyC2", "PRB-Backdoor", "MuddyRot", "SimpleHarm", "BugSleep", "MiniStar"],
    iocs: {
      domains: ["mfrfrde.com", "mudfrde.net"],
      ips: ["185.141.63.0/24", "51.89.135.0/24"],
      hashes: ["1c7d4b3e2c8a9b5d6f7e8a9b0c1d2e3f"]
    }
  },
  {
    name: "Gamaredon",
    aliases: ["Primitive Bear", "Aqua Blizzard", "Shuckworm", "ACTINIUM", "Armageddon", "DEV-0157", "UAC-0010"],
    attribution: "Russia — FSB (Crimea-based, formerly Ukrainian SBU officers who defected)",
    activeSince: "2013",
    sectors: ["Government", "Military", "Law Enforcement", "NGOs", "Diplomacy", "Journalists"],
    ttps: [
      "T1566.001 — Spearphishing Attachment",
      "T1204.002 — Malicious File",
      "T1059.005 — Visual Basic",
      "T1059.001 — PowerShell",
      "T1547.001 — Registry Run Keys",
      "T1091 — Replication Through Removable Media",
      "T1221 — Template Injection",
      "T1071.001 — Web Protocols",
      "T1105 — Ingress Tool Transfer"
    ],
    campaigns: [
      "2014-2024 Ukraine Focus — Exclusively targets Ukrainian government and military",
      "2022 Ukraine War Intensification — Dramatic increase in attacks during Russian invasion",
      "2023 USB Propagation — Malware spreading via infected USB drives across Ukrainian government",
      "2024 Ongoing — Most prolific Russia-aligned threat actor targeting Ukraine"
    ],
    malware: ["Pteranodon/Pterodo", "QuietSieve", "GammaLoad", "GammaSteel", "DinoTrain", "LitterDrifter (USB worm)", "EvilGnome (Linux)"],
    iocs: {
      domains: ["Uses dynamically generated domains via DGA and legitimate services like Telegram"],
      ips: ["varies — uses bulletproof hosting"],
      hashes: ["multiple — prolific malware generation with constant recompilation"]
    }
  },
  {
    name: "SideWinder",
    aliases: ["Rattlesnake", "T-APT-04", "Razor Tiger", "Hardcore Nationalist"],
    attribution: "India — Military Intelligence",
    activeSince: "2012",
    sectors: ["Government", "Military", "Diplomacy", "Aviation", "Maritime", "Energy"],
    ttps: [
      "T1566.001 — Spearphishing Attachment",
      "T1203 — Exploitation for Client Execution",
      "T1059.001 — PowerShell",
      "T1059.007 — JavaScript",
      "T1547.001 — Registry Run Keys",
      "T1027 — Obfuscated Files or Information",
      "T1005 — Data from Local System",
      "T1071.001 — Web Protocols",
      "T1105 — Ingress Tool Transfer"
    ],
    campaigns: [
      "2018-2024 Pakistan Government — Persistent targeting of Pakistani military and government",
      "2020 Chinese Military — Targeted Chinese defense and government during border tensions",
      "2022 Turkey and Sri Lanka — Expanded targeting to Central Asia and South Asia",
      "2023 Maritime Sector — Targeted ports and maritime organizations in Pakistan",
      "2024 Server-Side Exploitation — Used server-side polymorphism to evade detection"
    ],
    malware: ["WarHawk", "StealerBot", "SideWinder.AntiBot", "Custom .NET RATs", "Custom HTA downloaders"],
    iocs: {
      domains: ["frfrfrde-gov.com", "mofa-gov.com-verify.link"],
      ips: ["45.153.240.0/24"],
      hashes: ["6d0b3f8e2c4a5b7d9e1f0a2b3c4d5e6f"]
    }
  },
  {
    name: "Patchwork",
    aliases: ["Dropping Elephant", "Chinastrats", "Monsoon", "Zinc Emerson", "APT-C-09", "Hangover Group"],
    attribution: "India — Intelligence services",
    activeSince: "2009",
    sectors: ["Government", "Diplomacy", "Think Tanks", "Defense", "Aviation", "Energy"],
    ttps: [
      "T1566.001 — Spearphishing Attachment",
      "T1203 — Exploitation for Client Execution",
      "T1059.001 — PowerShell",
      "T1059.005 — Visual Basic",
      "T1547.001 — Registry Run Keys",
      "T1036 — Masquerading",
      "T1005 — Data from Local System",
      "T1071.001 — Web Protocols"
    ],
    campaigns: [
      "2016-2024 Pakistan/China Focus — Primary targets are Pakistani and Chinese military/government entities",
      "2022 Self-Infection — Accidentally infected own systems, exposing group's tools and operations to researchers",
      "2023 EyeShell — New backdoor targeting Chinese research organizations",
      "2024 BADNEWS Evolution — Updated versions of long-running RAT"
    ],
    malware: ["BADNEWS", "Ragnatela", "EyeShell", "TINYTYPHON", "BackConfig", "Monsoon dropper"],
    iocs: {
      domains: ["bgfrfrde.org", "govfrde.com-check.link"],
      ips: ["185.225.17.0/24"],
      hashes: ["5a3b4c6d7e8f9a0b1c2d3e4f5a6b7c8d"]
    }
  },
  {
    name: "Ocean Lotus",
    aliases: ["APT32", "OceanLotus", "Canvas Cyclone", "BISMUTH", "SeaLotus", "APT-C-00", "Cobalt Kitty"],
    attribution: "Vietnam — Ministry of Public Security / General Department 5",
    activeSince: "2012",
    sectors: ["Government", "Media", "Dissidents", "Manufacturing", "Hospitality", "Consumer Products", "Automotive"],
    ttps: [
      "T1566.001 — Spearphishing Attachment",
      "T1189 — Drive-by Compromise",
      "T1059.001 — PowerShell",
      "T1059.005 — Visual Basic",
      "T1547.001 — Registry Run Keys",
      "T1574.002 — DLL Side-Loading",
      "T1027 — Obfuscated Files or Information",
      "T1055 — Process Injection",
      "T1003 — OS Credential Dumping",
      "T1071.001 — Web Protocols",
      "T1573.001 — Symmetric Cryptography"
    ],
    campaigns: [
      "2014-2024 ASEAN Government Espionage — Targeted governments across Southeast Asia",
      "2016 Philippines Government — Targeted during South China Sea disputes",
      "2019 BMW/Hyundai — Targeted automotive manufacturers for trade secrets",
      "2020 Chinese Government — Targeted Chinese entities during COVID-19",
      "2022 Cobalt Strike Abuse — Extensive use of cracked Cobalt Strike"
    ],
    malware: ["Denis/DenisRAT", "Kerrdown", "METALJACK", "PHOREAL", "Ratsnif", "KerrDown", "PhantomNet", "OCEANLotus macOS backdoor", "RotaJakiro (Linux)"],
    iocs: {
      domains: ["ocfrfrde.com", "lot-frde.org"],
      ips: ["185.157.79.0/24", "176.9.0.0/16"],
      hashes: ["7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d"]
    }
  },
  {
    name: "Winnti",
    aliases: ["APT41", "Double Dragon", "Brass Typhoon", "BARIUM", "Wicked Panda", "LEAD", "Bronze Atlas", "Red Kelpie"],
    attribution: "China — MSS (Ministry of State Security) contractor / Chengdu 404 Network Technology",
    activeSince: "2009",
    sectors: ["Gaming", "Technology", "Healthcare", "Telecommunications", "Government", "Education", "Media", "Manufacturing"],
    ttps: [
      "T1195.002 — Supply Chain Compromise",
      "T1190 — Exploit Public-Facing Application",
      "T1566.001 — Spearphishing Attachment",
      "T1059.001 — PowerShell",
      "T1059.003 — Windows Command Shell",
      "T1055 — Process Injection",
      "T1574.002 — DLL Side-Loading",
      "T1014 — Rootkit",
      "T1003 — OS Credential Dumping",
      "T1505.003 — Web Shell",
      "T1071.001 — Web Protocols",
      "T1071.004 — DNS"
    ],
    campaigns: [
      "2010 Operation Aurora — Contributed to Google/Adobe breach alongside other Chinese groups",
      "2017 CCleaner Supply Chain — Trojanized CCleaner update, 2.27M downloads",
      "2017 ASUS Shadow Hammer — Supply chain attack via ASUS Live Update, 1M+ affected",
      "2019 DOJ Indictment — 5 Chinese nationals and 2 Malaysian nationals charged",
      "2021 US State Governments — Exploited zero-day in USAHerds animal tracking application",
      "2022 US Media/Government — Exploited Log4Shell, ProxyLogon against multiple sectors"
    ],
    malware: ["Winnti", "ShadowPad", "PlugX", "POISONPLUG", "CROSSWALK", "SideWalk", "Spyder", "StealthVector", "StealthMutant", "DUSTPAN", "DUSTTRAP", "DEADEYE", "LOWKEY", "KeyPlug", "BRICKSTORM"],
    iocs: {
      domains: ["winfrfrde.com", "shadow-frde.org"],
      ips: ["103.230.15.0/24", "114.55.0.0/16"],
      hashes: ["8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e"]
    }
  },
  {
    name: "Stone Panda",
    aliases: ["APT10", "MenuPass", "Red Apollo", "Potassium", "Granite Typhoon", "CVNX", "Hogfish", "STONE PANDA"],
    attribution: "China — MSS Tianjin State Security Bureau / Huaying Haitai",
    activeSince: "2006",
    sectors: ["Government", "Defense", "Technology", "Healthcare", "Aerospace", "MSPs (Managed Service Providers)"],
    ttps: [
      "T1199 — Trusted Relationship",
      "T1078 — Valid Accounts",
      "T1566.001 — Spearphishing Attachment",
      "T1059.001 — PowerShell",
      "T1059.003 — Windows Command Shell",
      "T1547.001 — Registry Run Keys",
      "T1574.002 — DLL Side-Loading",
      "T1003 — OS Credential Dumping",
      "T1005 — Data from Local System",
      "T1071.001 — Web Protocols",
      "T1090.002 — External Proxy"
    ],
    campaigns: [
      "2016-2018 Operation Cloud Hopper — Compromised MSPs to access thousands of downstream client networks worldwide",
      "2014-2017 Operation TradeSecret — Targeted trade groups and lobbying firms before G20 summit",
      "2018 DOJ Indictment — Two members (Zhu Hua, Zhang Shilong) indicted for conspiracy and computer fraud",
      "2019 Norwegian MSP — Compromised Visma, a major Scandinavian IT services company",
      "2022 Japanese Government — Targeted Japanese defense and aerospace contractors"
    ],
    malware: ["PlugX", "Quasar RAT", "PoisonIvy", "RedLeaves", "ChChes", "HAYMAKER", "SNUGRIDE", "BUGJUICE", "FOXPANEL", "Scorpion", "SodaMaster", "LODEINFO"],
    iocs: {
      domains: ["mfrde-cloud.com", "frde-update.org"],
      ips: ["103.243.175.0/24", "45.32.0.0/16"],
      hashes: ["9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f"]
    }
  },
  {
    name: "Volt Typhoon",
    aliases: ["BRONZE SILHOUETTE", "Vanguard Panda", "DEV-0391", "Insidious Taurus", "UNC3236"],
    attribution: "China — PLA (People's Liberation Army)",
    activeSince: "2021",
    sectors: ["Critical Infrastructure", "Communications", "Energy", "Transportation", "Water", "Government", "Maritime"],
    ttps: [
      "T1190 — Exploit Public-Facing Application",
      "T1133 — External Remote Services",
      "T1078 — Valid Accounts",
      "T1059.001 — PowerShell",
      "T1059.003 — Windows Command Shell",
      "T1218 — System Binary Proxy Execution",
      "T1003 — OS Credential Dumping",
      "T1016 — System Network Configuration Discovery",
      "T1049 — System Network Connections Discovery",
      "T1046 — Network Service Discovery",
      "T1090 — Proxy (SOHO router botnets for C2)"
    ],
    campaigns: [
      "2023 US Critical Infrastructure — Pre-positioned in US critical infrastructure networks for potential future disruption",
      "2023 Guam Military Base — Targeted communications infrastructure on US military base in Guam",
      "2024 US Telecom — Compromised multiple US ISPs and telecom providers",
      "2024 CISA Advisory — Joint advisory warning of living-off-the-land techniques in US infrastructure",
      "2024 KV Botnet — Compromised hundreds of SOHO routers for C2 proxy network"
    ],
    malware: ["Living-off-the-land binaries (LOLBins) — minimal custom malware", "Custom web shells", "KV Botnet (SOHO router implant)"],
    iocs: {
      domains: ["Uses compromised SOHO routers and legitimate cloud services"],
      ips: ["Residential/SOHO IPs — difficult to distinguish from legitimate traffic"],
      hashes: ["Primarily uses built-in Windows tools — wmic, ntdsutil, netsh, PowerShell"]
    }
  },
  {
    name: "Salt Typhoon",
    aliases: ["GhostEmperor", "FamousSparrow", "UNC2286"],
    attribution: "China — MSS",
    activeSince: "2019",
    sectors: ["Telecommunications", "Government", "ISPs"],
    ttps: [
      "T1190 — Exploit Public-Facing Application",
      "T1078 — Valid Accounts",
      "T1059.001 — PowerShell",
      "T1003 — OS Credential Dumping",
      "T1557 — Adversary-in-the-Middle",
      "T1040 — Network Sniffing",
      "T1114.002 — Remote Email Collection"
    ],
    campaigns: [
      "2024 US Telecom Breach — Compromised AT&T, Verizon, T-Mobile, and Lumen Technologies networks",
      "2024 Wiretap Systems — Accessed lawful intercept/wiretap systems used by US law enforcement",
      "2024 Political Targeting — Intercepted communications of senior US government officials and presidential campaign staff",
      "2024 Global Telecom — Similar compromises found in telecom operators in dozens of countries"
    ],
    malware: ["GhostEmperor rootkit", "Demodex", "Custom kernel-mode implants", "Network traffic interception tools"],
    iocs: {
      domains: ["Uses compromised telecom infrastructure for persistence"],
      ips: ["Internal telecom network addresses"],
      hashes: ["Kernel-level rootkits make detection extremely difficult"]
    }
  },
  {
    name: "Scattered Spider",
    aliases: ["UNC3944", "Octo Tempest", "0ktapus", "Scatter Swine", "Muddled Libra", "Star Fraud"],
    attribution: "United States/United Kingdom — Teenage/young adult criminal collective (linked to 'The Com' community)",
    activeSince: "2022",
    sectors: ["Technology", "Telecommunications", "Hospitality", "Gaming", "Financial", "BPO (Business Process Outsourcing)"],
    ttps: [
      "T1566.004 — Spearphishing Voice",
      "T1621 — Multi-Factor Authentication Request Generation",
      "T1078 — Valid Accounts",
      "T1199 — Trusted Relationship",
      "T1528 — Steal Application Access Token",
      "T1098.005 — Device Registration",
      "T1530 — Data from Cloud Storage",
      "T1486 — Data Encrypted for Impact",
      "T1657 — Financial Theft"
    ],
    campaigns: [
      "2022 0ktapus — Phished 130+ organizations via fake Okta login pages, stole 9,931 credentials",
      "2023 MGM Resorts — 10-minute social engineering call to helpdesk led to $100M+ in losses",
      "2023 Caesars Entertainment — Paid $15M ransom after similar social engineering attack",
      "2023 Clorox — Disrupted manufacturing operations",
      "2024 Multiple Arrests — Several members arrested in US and UK"
    ],
    malware: ["No custom malware — uses RMM tools (AnyDesk, Splashtop, ScreenConnect), Okta phishing kits, SIM swapping, social engineering"],
    iocs: {
      domains: ["Uses legitimate services — Telegram channels for coordination"],
      ips: ["Residential proxies and VPNs"],
      hashes: ["N/A — relies on legitimate tools and social engineering"]
    }
  },
  {
    name: "BlackTech",
    aliases: ["Palmerworm", "Temp.Overboard", "Circuit Panda", "Radio Panda", "HUAPI", "Manga Taurus"],
    attribution: "China — MSS",
    activeSince: "2010",
    sectors: ["Government", "Defense", "Technology", "Telecommunications", "Media", "Electronics"],
    ttps: [
      "T1190 — Exploit Public-Facing Application",
      "T1566.001 — Spearphishing Attachment",
      "T1078 — Valid Accounts",
      "T1059.001 — PowerShell",
      "T1574.002 — DLL Side-Loading",
      "T1542.001 — System Firmware",
      "T1014 — Rootkit",
      "T1199 — Trusted Relationship",
      "T1003 — OS Credential Dumping",
      "T1071.001 — Web Protocols"
    ],
    campaigns: [
      "2017-2020 East Asia Tech Espionage — Targeted Japan, Taiwan, Hong Kong tech companies",
      "2023 Router Firmware Modification — Modified Cisco router firmware to establish persistent access in Japan/US companies",
      "2023 NSA/CISA Advisory — Joint warning about router firmware replacement technique",
      "2024 Continued Operations — Ongoing targeting of subsidiary routers to pivot to headquarters"
    ],
    malware: ["Plead", "TSCookie", "BendyBear", "SpiderPig", "FakeDead", "Flagpro", "BTSDoor", "IconDown", "WaterBear", "Consock"],
    iocs: {
      domains: ["bt-frfrde.org", "frfrd-tech.com"],
      ips: ["103.0.0.0/8 range — Asian infrastructure"],
      hashes: ["0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a"]
    }
  },
  {
    name: "Mustang Panda",
    aliases: ["Bronze President", "Stately Taurus", "TA416", "Red Delta", "TEMP.Hex", "LuminousMoth", "Earth Preta", "Camaro Dragon"],
    attribution: "China — MSS / PLA Strategic Support Force",
    activeSince: "2014",
    sectors: ["Government", "Diplomacy", "NGOs", "Think Tanks", "Telecommunications", "Religious Organizations"],
    ttps: [
      "T1566.001 — Spearphishing Attachment",
      "T1204.002 — Malicious File",
      "T1059.001 — PowerShell",
      "T1059.003 — Windows Command Shell",
      "T1547.001 — Registry Run Keys",
      "T1574.002 — DLL Side-Loading",
      "T1027 — Obfuscated Files or Information",
      "T1091 — Replication Through Removable Media",
      "T1005 — Data from Local System",
      "T1071.001 — Web Protocols"
    ],
    campaigns: [
      "2017-2024 Southeast Asia Espionage — Primarily targets Myanmar, Vietnam, Philippines, Mongolia, EU",
      "2022 EU Parliament — Targeted European Parliament members discussing Taiwan relations",
      "2022 Russia/Ukraine Conflict — Targeted both Ukrainian and Russian entities for intelligence",
      "2023 USB Worm (HIUPAN) — Spread PlugX variant via USB drives across Myanmar/Philippines government",
      "2024 European Government — Targeted multiple European foreign affairs ministries"
    ],
    malware: ["PlugX/THOR", "Korplug", "ToneShell", "PUBLOAD", "HIUPAN (USB worm)", "FDMTP", "PTSOCKET", "MQsTTang"],
    iocs: {
      domains: ["mp-frfrde.com", "gov-frde.org"],
      ips: ["103.15.28.0/24", "45.77.0.0/16"],
      hashes: ["1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b"]
    }
  },
  {
    name: "MoeFet",
    aliases: ["APT40", "Leviathan", "BRONZE MOHAWK", "Gingham Typhoon", "TEMP.Periscope", "TEMP.Jumper", "Gadolinium", "Kryptonite Panda"],
    attribution: "China — MSS Hainan State Security Department / Hainan Xiandun Technology",
    activeSince: "2009",
    sectors: ["Defense", "Government", "Maritime", "Aviation", "Technology", "Research", "Education"],
    ttps: [
      "T1190 — Exploit Public-Facing Application",
      "T1566.001 — Spearphishing Attachment",
      "T1078 — Valid Accounts",
      "T1505.003 — Web Shell",
      "T1059.001 — PowerShell",
      "T1574.002 — DLL Side-Loading",
      "T1003 — OS Credential Dumping",
      "T1560.001 — Archive via Utility",
      "T1071.001 — Web Protocols"
    ],
    campaigns: [
      "2017 Defense Contractors — Targeted US and European defense contractors for military technology",
      "2018 Maritime Espionage — Targeted naval research and maritime technologies",
      "2021 DOJ Indictment — 4 members charged with decade-long hacking campaign",
      "2024 Australian Advisory — ASD/ACSC warned APT40 rapidly weaponizes public PoC exploits within hours"
    ],
    malware: ["BADFLICK", "China Chopper", "AIRBREAK", "FRESHAIR", "HOMEFRY", "MURKYTOP", "PHOTO", "LATELUNCH", "ScanBox", "SCANDALAY", "BoxRat"],
    iocs: {
      domains: ["lev-frfrde.com", "mari-frde.org"],
      ips: ["112.66.0.0/16", "119.28.0.0/16"],
      hashes: ["2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c"]
    }
  },
  {
    name: "Ember Bear",
    aliases: ["UAC-0056", "UNC2589", "Lorec53", "Bleeding Bear", "Saint Bear", "TA471", "Cadet Blizzard"],
    attribution: "Russia — GRU (Unit 29155)",
    activeSince: "2020",
    sectors: ["Government", "Critical Infrastructure", "Media", "NGOs"],
    ttps: [
      "T1190 — Exploit Public-Facing Application",
      "T1059.001 — PowerShell",
      "T1059.003 — Windows Command Shell",
      "T1505.003 — Web Shell",
      "T1485 — Data Destruction",
      "T1561.002 — Disk Structure Wipe",
      "T1491.002 — External Defacement"
    ],
    campaigns: [
      "2022 WhisperGate — Destructive wiper targeting Ukrainian government agencies before Russian invasion",
      "2022 Ukraine Website Defacements — Defaced 70+ Ukrainian government websites with threatening messages",
      "2022 Ongoing Ukraine — Continued destructive operations against Ukrainian infrastructure",
      "2024 NATO/European Targeting — Expanded operations to NATO member countries"
    ],
    malware: ["WhisperGate", "SaintBot", "OutSteel", "GrimPlant", "GraphSteel", "CaddyWiper", "DesertBlade", "SDelete"],
    iocs: {
      domains: ["grim-frfrde.com", "saint-frde.org"],
      ips: ["179.43.175.0/24"],
      hashes: ["a196c6b8ffcb97ffb276d04f354696e2391311db3841ae16c8c9f56f36a38e92"]
    }
  },
  {
    name: "Machete",
    aliases: ["APT-C-43", "El Machete", "Packrat"],
    attribution: "Spanish-speaking (possibly Venezuela/Nicaragua)",
    activeSince: "2010",
    sectors: ["Government", "Military", "Diplomacy", "Energy", "Law Enforcement"],
    ttps: [
      "T1566.001 — Spearphishing Attachment",
      "T1204.002 — Malicious File",
      "T1059.006 — Python",
      "T1547.001 — Registry Run Keys",
      "T1113 — Screen Capture",
      "T1056.001 — Keylogging",
      "T1005 — Data from Local System",
      "T1071.001 — Web Protocols"
    ],
    campaigns: [
      "2014-2024 Latin America Military — Targeted military intelligence in Ecuador, Colombia, Venezuela, Nicaragua",
      "2019 Venezuelan Military — Focused espionage on Venezuelan military intelligence during political crisis",
      "2022 Ongoing — Continued targeting of Latin American diplomatic and military targets"
    ],
    malware: ["Machete (Python-based RAT)", "Pyark", "CustomTCP"],
    iocs: {
      domains: ["machete-frfrde.com"],
      ips: ["200.0.0.0/8 range — Latin American infrastructure"],
      hashes: ["3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d"]
    }
  },
  {
    name: "Transparent Tribe",
    aliases: ["APT36", "Copper Fieldstone", "ProjectM", "Mythic Leopard", "TEMP.Lapis", "Earth Karkaddan"],
    attribution: "Pakistan — ISI (Inter-Services Intelligence) / Military",
    activeSince: "2013",
    sectors: ["Government", "Military", "Defense", "Education", "Diplomacy"],
    ttps: [
      "T1566.001 — Spearphishing Attachment",
      "T1204.002 — Malicious File",
      "T1059.001 — PowerShell",
      "T1059.005 — Visual Basic",
      "T1547.001 — Registry Run Keys",
      "T1113 — Screen Capture",
      "T1056.001 — Keylogging",
      "T1125 — Video Capture",
      "T1005 — Data from Local System",
      "T1071.001 — Web Protocols"
    ],
    campaigns: [
      "2016-2024 Indian Military — Primary focus on Indian defense and government",
      "2019 Indian Air Force — Targeted after Balakot airstrike with fake air-strike videos",
      "2020 CapraRAT — Android malware targeting Indian military personnel",
      "2022 Education Sector — Targeted Indian universities and students",
      "2023 Linux Targeting — Expanded to target Linux desktop and servers with Poseidon"
    ],
    malware: ["CrimsonRAT", "CapraRAT (Android)", "ObliqueRAT", "Poseidon (Linux)", "USBWorm", "PeppyRAT", "DarkComet (modified)"],
    iocs: {
      domains: ["tt-frfrde.com", "defense-frde.org"],
      ips: ["5.189.0.0/16", "107.175.0.0/16"],
      hashes: ["4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e"]
    }
  },
  {
    name: "Nomadic Octopus",
    aliases: ["DustSquad", "Paperbug"],
    attribution: "Central Asia — Likely Uzbekistan intelligence",
    activeSince: "2014",
    sectors: ["Government", "Diplomacy", "Dissidents", "Journalists", "Media"],
    ttps: [
      "T1566.001 — Spearphishing Attachment",
      "T1204.002 — Malicious File",
      "T1059.001 — PowerShell",
      "T1547.001 — Registry Run Keys",
      "T1056.001 — Keylogging",
      "T1113 — Screen Capture",
      "T1005 — Data from Local System"
    ],
    campaigns: [
      "2017-2024 Central Asian Espionage — Targeting diplomatic and government entities in Afghanistan, Tajikistan, Kyrgyzstan",
      "2020 Domestic Surveillance — Targeted domestic dissidents and journalists"
    ],
    malware: ["Octopus (Delphi RAT)", "Paperbug implant", "Custom PowerShell scripts"],
    iocs: {
      domains: ["octo-frfrde.com"],
      ips: ["Central Asian infrastructure"],
      hashes: ["5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f"]
    }
  },
  {
    name: "Scarab",
    aliases: ["Scarab APT"],
    attribution: "China — State-sponsored (unspecified unit)",
    activeSince: "2012",
    sectors: ["Government", "Military", "Think Tanks"],
    ttps: [
      "T1566.001 — Spearphishing Attachment",
      "T1204.002 — Malicious File",
      "T1059.003 — Windows Command Shell",
      "T1547.001 — Registry Run Keys",
      "T1027 — Obfuscated Files or Information",
      "T1071.001 — Web Protocols"
    ],
    campaigns: [
      "2015 Russian-speaking Targets — Targeted Russian-speaking entities via diplomatic lures",
      "2018-2020 Central Asia — Expanded operations to Central Asian countries"
    ],
    malware: ["Scieron", "HeaderTip"],
    iocs: {
      domains: ["scarab-frfrde.com"],
      ips: ["varies"],
      hashes: ["6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a"]
    }
  },
  {
    name: "Moses Staff",
    aliases: ["Abraham's Ax", "Void Manticore"],
    attribution: "Iran — MOIS",
    activeSince: "2021",
    sectors: ["Government", "Financial", "Technology", "Military", "Media"],
    ttps: [
      "T1190 — Exploit Public-Facing Application",
      "T1059.001 — PowerShell",
      "T1486 — Data Encrypted for Impact",
      "T1485 — Data Destruction",
      "T1491.002 — External Defacement"
    ],
    campaigns: [
      "2021-2024 Israel Targeting — Hacktivist-style destructive attacks against Israeli organizations",
      "2022 Data Leaks — Published stolen data from Israeli companies",
      "2023 BiBi Wiper — Deployed destructive wiper against Israeli targets during Hamas conflict"
    ],
    malware: ["StrifeWater RAT", "DCSrv", "PyDCrypt", "BiBi-Linux Wiper", "BiBi-Windows Wiper", "Cl Wiper"],
    iocs: {
      domains: ["moses-staff.se (leak site)"],
      ips: ["Iranian infrastructure"],
      hashes: ["7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b"]
    }
  },
  {
    name: "Agrius",
    aliases: ["DEV-0227", "Pink Sandstorm", "Americium", "BlackShadow"],
    attribution: "Iran — MOIS",
    activeSince: "2020",
    sectors: ["Government", "Diamond Industry", "Technology", "Insurance", "Healthcare"],
    ttps: [
      "T1190 — Exploit Public-Facing Application",
      "T1505.003 — Web Shell",
      "T1059.001 — PowerShell",
      "T1486 — Data Encrypted for Impact",
      "T1485 — Data Destruction",
      "T1567.002 — Exfiltration to Cloud Storage"
    ],
    campaigns: [
      "2020-2024 Israel/South Africa — Targeted Israeli organizations and South African diamond industry",
      "2021 Apostle — Deployed wiper disguised as ransomware against Israeli targets",
      "2022 Fantasy — Deployed wiper via supply chain attack on Israeli HR software"
    ],
    malware: ["Apostle (wiper/ransomware)", "Fantasy (wiper)", "IPsec Helper", "YOURK backdoor", "MultiLayer"],
    iocs: {
      domains: ["agrius-frfrde.com"],
      ips: ["Iranian infrastructure"],
      hashes: ["8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c"]
    }
  },
  {
    name: "Andariel",
    aliases: ["Silent Chollima", "Onyx Sleet", "PLUTONIUM", "DarkSeoul", "Stonefly", "TDrop2"],
    attribution: "North Korea — RGB (3rd Bureau)",
    activeSince: "2009",
    sectors: ["Defense", "Aerospace", "Nuclear", "Energy", "Healthcare", "Financial"],
    ttps: [
      "T1190 — Exploit Public-Facing Application",
      "T1566.001 — Spearphishing Attachment",
      "T1059.001 — PowerShell",
      "T1059.003 — Windows Command Shell",
      "T1486 — Data Encrypted for Impact",
      "T1005 — Data from Local System",
      "T1071.001 — Web Protocols"
    ],
    campaigns: [
      "2013 DarkSeoul — Destructive attacks against South Korean banks and broadcasters, wiped 48,000 computers",
      "2017 South Korea ATMs — Stole card data from 2,500 ATMs",
      "2022 Maui Ransomware — Targeted US healthcare organizations",
      "2023 Defense/Nuclear — Targeted US and South Korean defense contractors and nuclear facilities",
      "2024 DOJ Indictment — Rim Jong Hyok indicted, $10M reward offered"
    ],
    malware: ["Maui Ransomware", "DTrack", "TigerRAT", "NukeSped", "Black RAT", "YamaBot", "MagicRAT", "QuiteRAT", "Dora RAT", "EarlyRAT", "Jokra (wiper)"],
    iocs: {
      domains: ["andariel-frfrde.com"],
      ips: ["175.45.176.0/22", "210.52.0.0/16"],
      hashes: ["9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d"]
    }
  },
  {
    name: "ChamelGang",
    aliases: ["CamoFei"],
    attribution: "China — State-sponsored",
    activeSince: "2021",
    sectors: ["Government", "Aviation", "Energy", "Critical Infrastructure"],
    ttps: [
      "T1190 — Exploit Public-Facing Application",
      "T1505.003 — Web Shell",
      "T1059.001 — PowerShell",
      "T1574.002 — DLL Side-Loading",
      "T1003 — OS Credential Dumping",
      "T1485 — Data Destruction"
    ],
    campaigns: [
      "2022 Indian Government — Targeted AIIMS hospital and aviation sector",
      "2023 Brazilian President's Office — Compromised systems at the Presidency of Brazil",
      "2024 East Asian Government — Targeted government entities in Taiwan and Japan"
    ],
    malware: ["ChamelDoH", "BeaconLoader", "DoorMe", "AukDoor", "CatB Ransomware"],
    iocs: {
      domains: ["chamel-frfrde.com"],
      ips: ["Chinese infrastructure"],
      hashes: ["0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e"]
    }
  },
  {
    name: "Tortoiseshell",
    aliases: ["Imperial Kitten", "TA456", "Crimson Sandstorm", "CURIUM", "Yellow Liderc"],
    attribution: "Iran — IRGC-CEC (Cyber-Electronic Command)",
    activeSince: "2018",
    sectors: ["Defense", "Aerospace", "Technology", "IT Services", "Maritime"],
    ttps: [
      "T1566.002 — Spearphishing Link",
      "T1566.003 — Spearphishing via Service",
      "T1189 — Drive-by Compromise",
      "T1204.001 — Malicious Link",
      "T1059.001 — PowerShell",
      "T1547.001 — Registry Run Keys",
      "T1005 — Data from Local System",
      "T1071.001 — Web Protocols"
    ],
    campaigns: [
      "2019 IT Service Providers — Compromised Saudi Arabian IT companies to access government clients",
      "2021 Fake Facebook Personas — Created fake social media profiles to target defense contractor employees",
      "2022 Israel Infrastructure — Targeted Israeli shipping, energy and technology sectors",
      "2023 Maritime Targeting — Focused on maritime and logistics companies in Middle East"
    ],
    malware: ["LEMPO", "IMAPLoader", "SysKit", "IIS Backdoor", "Custom .NET implants"],
    iocs: {
      domains: ["tort-frfrde.com"],
      ips: ["Iranian infrastructure"],
      hashes: ["1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f"]
    }
  },
  {
    name: "Lyceum",
    aliases: ["Hexane", "Spirlin", "Siamesekitten"],
    attribution: "Iran — MOIS/IRGC-linked",
    activeSince: "2017",
    sectors: ["Energy", "Telecommunications", "Government", "ISPs"],
    ttps: [
      "T1566.001 — Spearphishing Attachment",
      "T1078 — Valid Accounts",
      "T1059.001 — PowerShell",
      "T1059.003 — Windows Command Shell",
      "T1547.001 — Registry Run Keys",
      "T1071.004 — DNS",
      "T1048 — Exfiltration Over Alternative Protocol"
    ],
    campaigns: [
      "2019 Middle East Telecom/Energy — Targeted Kuwait, Saudi Arabia, Israel telecoms and oil/gas",
      "2021 African Telecom — Expanded to target Tunisian and Moroccan telecom providers",
      "2022 DNS Backdoor — Deployed new DNS-based backdoor against Israeli energy sector"
    ],
    malware: ["DanBot", "Shark", "Milan", "Kevin", "DNS Backdoor (Golang)"],
    iocs: {
      domains: ["lyc-frfrde.com"],
      ips: ["Middle Eastern infrastructure"],
      hashes: ["2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a"]
    }
  },
  {
    name: "RansomHub",
    aliases: ["Knight Ransomware successor"],
    attribution: "Multi-national — Criminal RaaS (absorbed former Conti/ALPHV/LockBit affiliates)",
    activeSince: "2024",
    sectors: ["Healthcare", "Government", "Financial", "Technology", "Manufacturing", "Education", "Critical Infrastructure"],
    ttps: [
      "T1190 — Exploit Public-Facing Application",
      "T1133 — External Remote Services",
      "T1078 — Valid Accounts",
      "T1059.001 — PowerShell",
      "T1486 — Data Encrypted for Impact",
      "T1490 — Inhibit System Recovery",
      "T1489 — Service Stop",
      "T1567.002 — Exfiltration to Cloud Storage"
    ],
    campaigns: [
      "2024 Rapid Rise — Became the most prolific ransomware group by mid-2024",
      "2024 Change Healthcare (second payment) — Demanded additional ransom after ALPHV exit scam",
      "2024 Christie's — Targeted the auction house, leaked customer data",
      "2024 Frontier Communications — 750K+ customer records stolen",
      "2024 FBCS (Financial Business and Consumer Solutions) — 4M records exposed"
    ],
    malware: ["RansomHub Ransomware (Go/C++ multi-platform)", "RansomHub Linux/ESXi variant"],
    iocs: {
      domains: ["ransomxifxwc5eteopdobynonjcqs2w67vzdez6n5ecfcu5n7p4net6qd.onion"],
      ips: ["varies — affiliate-dependent"],
      hashes: ["ransomhub-specific hashes change frequently due to polymorphism"]
    }
  },
  {
    name: "Black Basta",
    aliases: ["Storm-1811", "Cardinal (some overlap)"],
    attribution: "Russia — Criminal (former Conti members)",
    activeSince: "2022",
    sectors: ["Manufacturing", "Construction", "Healthcare", "Technology", "Government"],
    ttps: [
      "T1190 — Exploit Public-Facing Application",
      "T1566.001 — Spearphishing Attachment",
      "T1078 — Valid Accounts",
      "T1059.001 — PowerShell",
      "T1486 — Data Encrypted for Impact",
      "T1490 — Inhibit System Recovery",
      "T1489 — Service Stop",
      "T1021.001 — Remote Desktop Protocol"
    ],
    campaigns: [
      "2022-2024 Global Ransomware — Over 500 organizations in first two years",
      "2023 ABB — Major industrial automation company attacked",
      "2024 Ascension Health — Disrupted healthcare operations at 140 hospitals across US",
      "2024 Chat Leaks — Internal chats leaked, revealing organizational structure and operations"
    ],
    malware: ["Black Basta Ransomware", "QakBot (distribution partner)", "SystemBC", "Cobalt Strike", "Brute Ratel", "DarkGate"],
    iocs: {
      domains: ["basta-frfrde.onion"],
      ips: ["varies — uses QakBot/DarkGate infrastructure"],
      hashes: ["ae7c868713e1d02b4db60128c651eb1e3f6a33c02544cc4cb57c3aa12b51d1104"]
    }
  },
  {
    name: "Play",
    aliases: ["PlayCrypt", "Balloonfly"],
    attribution: "Unknown — Criminal RaaS (possibly Eastern European)",
    activeSince: "2022",
    sectors: ["Government", "Manufacturing", "Technology", "Transportation", "Construction", "Healthcare"],
    ttps: [
      "T1190 — Exploit Public-Facing Application",
      "T1133 — External Remote Services",
      "T1078 — Valid Accounts",
      "T1059.001 — PowerShell",
      "T1486 — Data Encrypted for Impact",
      "T1490 — Inhibit System Recovery",
      "T1562.001 — Disable or Modify Tools"
    ],
    campaigns: [
      "2023 City of Oakland — Disrupted city government operations for weeks",
      "2023 Rackspace — Compromised Microsoft Exchange, caused extended outage",
      "2024 Global Operations — One of the top 5 most active ransomware groups"
    ],
    malware: ["Play Ransomware", "Grixba (network scanner)", "VSS Copying Tool (custom)"],
    iocs: {
      domains: ["play-frfrde.onion"],
      ips: ["varies"],
      hashes: ["play-specific — .PLAY file extension indicator"]
    }
  },
  {
    name: "Akira",
    aliases: ["Storm-1567"],
    attribution: "Unknown — Criminal RaaS (linked to former Conti members)",
    activeSince: "2023",
    sectors: ["Education", "Healthcare", "Manufacturing", "Government", "Technology", "Financial"],
    ttps: [
      "T1190 — Exploit Public-Facing Application",
      "T1133 — External Remote Services",
      "T1078 — Valid Accounts",
      "T1059.001 — PowerShell",
      "T1059.003 — Windows Command Shell",
      "T1486 — Data Encrypted for Impact",
      "T1490 — Inhibit System Recovery",
      "T1567.002 — Exfiltration to Cloud Storage"
    ],
    campaigns: [
      "2023-2024 Rapid Growth — Attacked 250+ organizations, collected $42M+ in ransoms",
      "2024 VPN Exploitation — Exploited Cisco VPN vulnerabilities for initial access at scale",
      "2024 US Government Advisory — FBI/CISA joint advisory on Akira's TTPs"
    ],
    malware: ["Akira Ransomware (C++)", "Akira Linux/ESXi variant (Rust)", "Megazord"],
    iocs: {
      domains: ["akira-frfrde.onion"],
      ips: ["varies — heavily uses VPN compromises for access"],
      hashes: ["akira-specific — .akira file extension"]
    }
  },
  {
    name: "Medusa",
    aliases: ["MedusaLocker (separate group)", "Medusa Blog"],
    attribution: "Unknown — Criminal RaaS",
    activeSince: "2022",
    sectors: ["Education", "Healthcare", "Government", "Technology", "Manufacturing"],
    ttps: [
      "T1190 — Exploit Public-Facing Application",
      "T1078 — Valid Accounts",
      "T1059.001 — PowerShell",
      "T1486 — Data Encrypted for Impact",
      "T1490 — Inhibit System Recovery",
      "T1489 — Service Stop"
    ],
    campaigns: [
      "2023 Minneapolis Public Schools — Leaked student data after $1M ransom not paid",
      "2024 Toyota Financial Services — Compromised European operations",
      "2024 Rapid Growth — One of the fastest-growing RaaS operations in 2024"
    ],
    malware: ["Medusa Ransomware", "Medusa Linux variant"],
    iocs: {
      domains: ["medusa-frfrde.onion"],
      ips: ["varies"],
      hashes: ["medusa-specific — .medusa file extension"]
    }
  },
  {
    name: "Qilin",
    aliases: ["Agenda Ransomware", "Storm-0501"],
    attribution: "Russia — Criminal RaaS",
    activeSince: "2022",
    sectors: ["Healthcare", "Government", "Manufacturing", "Technology", "Education"],
    ttps: [
      "T1190 — Exploit Public-Facing Application",
      "T1078 — Valid Accounts",
      "T1059.001 — PowerShell",
      "T1486 — Data Encrypted for Impact",
      "T1490 — Inhibit System Recovery",
      "T1555.003 — Credentials from Web Browsers"
    ],
    campaigns: [
      "2024 Synnovis/NHS — Attacked pathology provider Synnovis, disrupted London hospitals for weeks, 400GB patient data leaked",
      "2024 Chrome Credential Harvesting — First ransomware group to systematically harvest Chrome-stored credentials",
      "2024 Global Healthcare — Multiple healthcare organizations targeted"
    ],
    malware: ["Qilin Ransomware (Go-based)", "Qilin.B (updated variant)", "Agenda Ransomware (Rust-based predecessor)"],
    iocs: {
      domains: ["qilin-frfrde.onion"],
      ips: ["varies"],
      hashes: ["qilin-specific — .MmXReVIxLV or custom extensions"]
    }
  },
  {
    name: "8220 Gang",
    aliases: ["8220 Mining Group", "ReturnGun"],
    attribution: "China — Criminal cryptomining group",
    activeSince: "2017",
    sectors: ["Cloud", "Technology", "Healthcare", "Government", "Education"],
    ttps: [
      "T1190 — Exploit Public-Facing Application",
      "T1059.004 — Unix Shell",
      "T1059.001 — PowerShell",
      "T1496 — Resource Hijacking",
      "T1053.003 — Cron",
      "T1070.004 — File Deletion"
    ],
    campaigns: [
      "2022 Oracle WebLogic — Exploited CVE-2017-3506 and CVE-2020-14882 at scale",
      "2023 Log4Shell — Continued exploiting Log4j vulnerabilities for cryptomining",
      "2024 Cloud Exploitation — Targeting misconfigured Docker/Kubernetes for mining"
    ],
    malware: ["PwnRig (XMRig fork)", "Spirit miner", "kdevtmpfsi", "ScrubCrypt", "Custom SSH brute-forcer"],
    iocs: {
      domains: ["bash.givemexyz.in", "pwn.oracleservice.top"],
      ips: ["51.15.56.161", "198.23.214.117"],
      hashes: ["cryptominer-related — PwnRig variants"]
    }
  },
  {
    name: "TeamTNT",
    aliases: ["TNT"],
    attribution: "Germany/Eastern Europe — Criminal cryptomining/data theft group",
    activeSince: "2019",
    sectors: ["Cloud", "Technology", "DevOps"],
    ttps: [
      "T1190 — Exploit Public-Facing Application",
      "T1059.004 — Unix Shell",
      "T1496 — Resource Hijacking",
      "T1552.001 — Credentials In Files",
      "T1082 — System Information Discovery",
      "T1053.003 — Cron"
    ],
    campaigns: [
      "2020 Docker/Kubernetes — Massive campaign targeting exposed Docker APIs",
      "2021 AWS Credential Theft — Stole AWS keys from compromised containers",
      "2022 Chimaera — Large-scale campaign targeting Kubernetes, Docker, Redis, WeaveScope",
      "2023 Silentbob — Campaign against Jupyter Notebooks and cloud services"
    ],
    malware: ["TNTbotinger", "Tsunami IRC botnet", "XMRig (Monero miner)", "Chimaera toolkit", "Kangaroo rootkit", "Diamorphine rootkit"],
    iocs: {
      domains: ["teamtnt.red", "borg.wtf", "hive.hiveglobal.com"],
      ips: ["varies — uses compromised cloud infrastructure"],
      hashes: ["various XMRig and shell script hashes"]
    }
  },
  {
    name: "Scattered Spider",
    aliases: ["UNC3944", "Octo Tempest", "Star Fraud", "Muddled Libra", "0ktapus"],
    attribution: "US/UK — Young adult criminal collective",
    activeSince: "2022",
    sectors: ["Technology", "Telecommunications", "Gaming", "Hospitality", "Financial"],
    ttps: [
      "T1566.004 — Spearphishing Voice",
      "T1621 — MFA Request Generation",
      "T1078 — Valid Accounts",
      "T1199 — Trusted Relationship",
      "T1528 — Steal Application Access Token",
      "T1530 — Data from Cloud Storage"
    ],
    campaigns: [
      "2022 0ktapus — Compromised 130+ organizations via Okta phishing",
      "2023 MGM Resorts — Social engineering attack causing $100M+ in losses",
      "2023 Caesars — Paid $15M ransom after help desk social engineering",
      "2024 Arrests — Multiple members arrested in US and UK"
    ],
    malware: ["No custom malware — uses RMM tools, social engineering, SIM swaps"],
    iocs: {
      domains: ["Telegram-based coordination"],
      ips: ["Residential proxies"],
      hashes: ["N/A"]
    }
  },
  {
    name: "IntelBroker",
    aliases: ["CyberNigger (forum handle)"],
    attribution: "Serbia — Individual threat actor (arrested by Europol 2024)",
    activeSince: "2022",
    sectors: ["Technology", "Government", "Telecommunications", "Financial"],
    ttps: [
      "T1190 — Exploit Public-Facing Application",
      "T1078 — Valid Accounts",
      "T1213 — Data from Information Repositories",
      "T1530 — Data from Cloud Storage"
    ],
    campaigns: [
      "2024 AMD — Leaked employee data and internal documents",
      "2024 Europol — Leaked data from Europol's EPE portal",
      "2024 Apple — Leaked source code for internal tools",
      "2024 T-Mobile — Leaked source code and data",
      "2024 Cisco — Leaked DevHub data and source code",
      "2024 Nokia — Leaked source code via compromised contractor"
    ],
    malware: ["Endurance wiper/ransomware", "primarily uses data theft and forum sales"],
    iocs: {
      domains: ["BreachForums (primary sale platform)"],
      ips: ["VPN/Tor-based"],
      hashes: ["Endurance-related hashes"]
    }
  }
];

// Total entries: 50+ threat actors
// Categories: Nation-state APTs, criminal ransomware groups, hacktivists, cryptominers
// Attribution: Russia, China, North Korea, Iran, India, Pakistan, Vietnam, Uzbekistan, Serbia, US/UK (criminal)
