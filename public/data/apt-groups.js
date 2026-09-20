// Copyright (c) 2026 SpartanKing18. All rights reserved.
// Source-available for learning only. Redistribution prohibited. See LICENSE.
//
// Advanced Persistent Threat (APT) Groups Database
// Comprehensive reference for threat intelligence education
// Covers state-sponsored and financially motivated APT groups with
// attribution, targets, campaigns, tools, and MITRE ATT&CK mappings.

export const APT_GROUPS = [
  // ==================== RUSSIA ====================
  {
    name: "APT28",
    aliases: ["Fancy Bear", "Sofacy", "Sednit", "Pawn Storm", "STRONTIUM", "Forest Blizzard", "Group 74", "Tsar Team"],
    attribution: "Russia — GRU (Main Intelligence Directorate), Unit 26165",
    active_since: 2004,
    status: "Active",
    targets: {
      industries: ["Government", "Military", "Defense contractors", "Media", "Political organizations", "International organizations (NATO, OSCE, OPCW)"],
      countries: ["United States", "Ukraine", "Georgia", "NATO members", "European Union members", "Middle East"]
    },
    notable_campaigns: [
      { year: 2016, name: "DNC Hack", description: "Breached Democratic National Committee and released emails via WikiLeaks to influence the 2016 US presidential election" },
      { year: 2018, name: "OPCW Attack", description: "GRU officers caught attempting close-access WiFi attack on OPCW headquarters in The Hague, Netherlands" },
      { year: 2015, name: "Bundestag Hack", description: "Compromised German parliament network, requiring complete rebuild of IT infrastructure" },
      { year: 2017, name: "French Elections", description: "Targeted Emmanuel Macron's En Marche! campaign with phishing and data leaks" },
      { year: 2019, name: "Georgian Infrastructure", description: "Conducted large-scale cyberattack against Georgian government, media, and businesses" }
    ],
    tools: ["X-Agent (Sofacy)", "X-Tunnel", "Zebrocy", "Drovorub (Linux malware)", "Skinnyboy", "CompuTrace LoJack abuse", "Koadic", "Responder", "Mimikatz"],
    ttps: [
      "T1566 — Spearphishing (credential harvesting and malicious attachments)",
      "T1078 — Valid Accounts (compromised credentials)",
      "T1003 — OS Credential Dumping",
      "T1071 — Application Layer Protocol (HTTP/HTTPS C2)",
      "T1114 — Email Collection",
      "T1583.001 — Acquire Infrastructure: Domains (typosquatting)",
      "T1588.002 — Obtain Capabilities: Tool (open-source tools)",
      "T1190 — Exploit Public-Facing Application (zero-days in Outlook, WinRAR)"
    ],
    iocs: {
      domains: ["login-microsoftonline[.]com", "mylogin-microsoftonline[.]com"],
      techniques: ["OAuth token phishing", "Close-access WiFi attacks", "Zero-day exploitation"]
    }
  },
  {
    name: "APT29",
    aliases: ["Cozy Bear", "The Dukes", "Nobelium", "Midnight Blizzard", "YTTRIUM", "UNC2452", "Dark Halo", "StellarParticle"],
    attribution: "Russia — SVR (Foreign Intelligence Service)",
    active_since: 2008,
    status: "Active",
    targets: {
      industries: ["Government", "Diplomatic missions", "Think tanks", "Healthcare (COVID-19 vaccine research)", "Technology", "Cloud service providers"],
      countries: ["United States", "European Union", "NATO members", "Ukraine"]
    },
    notable_campaigns: [
      { year: 2020, name: "SolarWinds (SUNBURST)", description: "Supply chain attack compromising SolarWinds Orion, affecting ~18,000 organizations including US government agencies (Treasury, Commerce, DHS)" },
      { year: 2020, name: "COVID-19 Vaccine Research", description: "Targeted pharmaceutical companies and research institutions developing COVID-19 vaccines (UK NCSC/NSA/CISA advisory)" },
      { year: 2014, name: "White House and State Department", description: "Compromised unclassified networks of the White House, State Department, and Joint Chiefs of Staff" },
      { year: 2016, name: "DNC Breach", description: "Alongside APT28, compromised Democratic National Committee (APT29 had been in the network since 2015)" },
      { year: 2024, name: "Microsoft Corporate Email", description: "Compromised Microsoft corporate email using password spray against legacy test tenant, accessed senior leadership mailboxes" }
    ],
    tools: ["SUNBURST", "TEARDROP", "RAINDROP", "GoldMax/SUNSHUTTLE", "EnvyScout", "FoggyWeb", "MagicWeb", "WellMess", "WellMail", "TrailBlazer", "NativeZone", "BoomBox"],
    ttps: [
      "T1195.002 — Supply Chain Compromise",
      "T1078 — Valid Accounts (password spraying, stolen credentials)",
      "T1550.001 — Application Access Token (SAML token forging / Golden SAML)",
      "T1114.002 — Remote Email Collection (Microsoft 365)",
      "T1071.001 — Web Protocols (HTTPS C2)",
      "T1071.004 — DNS (DNS-based C2 in SUNBURST)",
      "T1001.002 — Steganography (C2 data in HTTP responses)",
      "T1556.006 — Modify Authentication Process (FoggyWeb, MagicWeb)",
      "T1199 — Trusted Relationship (cloud service provider access)"
    ],
    iocs: {
      domains: ["avsvmcloud[.]com (SUNBURST DNS C2)"],
      techniques: ["Golden SAML attacks", "Residential proxy networks for credential spraying", "OAuth application abuse in cloud environments"]
    }
  },
  {
    name: "Sandworm",
    aliases: ["Voodoo Bear", "IRIDIUM", "Seashell Blizzard", "Telebots", "Electrum", "Iron Viking", "TEMP.Noble", "UAC-0082"],
    attribution: "Russia — GRU Unit 74455 (Main Centre for Special Technologies, GTsST)",
    active_since: 2009,
    status: "Active",
    targets: {
      industries: ["Energy/utilities", "Government", "Media", "Transportation", "Financial", "Elections infrastructure"],
      countries: ["Ukraine", "Georgia", "United States", "France", "South Korea", "Global (NotPetya)"]
    },
    notable_campaigns: [
      { year: 2015, name: "Ukraine Power Grid Attack #1", description: "BlackEnergy/KillDisk attack on 3 Ukrainian power distribution companies, cutting power to ~230,000 customers — first confirmed cyber-caused power outage" },
      { year: 2016, name: "Ukraine Power Grid Attack #2", description: "Industroyer/CrashOverride malware attacked Ukrenergo transmission substation, causing another blackout" },
      { year: 2017, name: "NotPetya", description: "Destructive wiper disguised as ransomware, spread globally via compromised M.E.Doc software, caused $10+ billion in damages" },
      { year: 2018, name: "Olympic Destroyer", description: "Disrupted Pyeongchang Winter Olympics opening ceremony IT systems, used false flag attribution to North Korea and China" },
      { year: 2022, name: "Ukraine Cyber Campaign", description: "Multiple wiper attacks (HermeticWiper, CaddyWiper, Industroyer2) coordinated with Russia's military invasion of Ukraine" }
    ],
    tools: ["BlackEnergy", "Industroyer/CrashOverride", "Industroyer2", "NotPetya", "Olympic Destroyer", "HermeticWiper", "CaddyWiper", "AcidRain", "Cyclops Blink", "VPNFilter", "GreyEnergy"],
    ttps: [
      "T1190 — Exploit Public-Facing Application",
      "T1195.002 — Supply Chain Compromise (M.E.Doc for NotPetya)",
      "T1561 — Disk Wipe (multiple wiper malware families)",
      "T1495 — Firmware Corruption (AcidRain targeting Viasat modems)",
      "T1562 — Impair Defenses",
      "T1210 — Exploitation of Remote Services (EternalBlue in NotPetya)",
      "T1106 — Native API (ICS protocol abuse in Industroyer)",
      "T1036 — Masquerading (false flag in Olympic Destroyer)"
    ],
    iocs: {
      techniques: ["ICS/SCADA attacks targeting power grid infrastructure", "Wiper attacks disguised as ransomware", "False flag operations to misdirect attribution"]
    }
  },
  {
    name: "Turla",
    aliases: ["Snake", "Venomous Bear", "Uroburos", "Waterbug", "Krypton", "Secret Blizzard", "IRON HUNTER", "Group 88"],
    attribution: "Russia — FSB (Federal Security Service), Center 16",
    active_since: 2004,
    status: "Active",
    targets: {
      industries: ["Government", "Military", "Diplomatic missions", "Research", "Aerospace"],
      countries: ["NATO members", "Central Asia", "Middle East", "European Union"]
    },
    notable_campaigns: [
      { year: 2008, name: "Agent.BTZ / Pentagon Breach", description: "Compromised US military classified networks via infected USB drive in Middle Eastern parking lot, led to creation of US Cyber Command" },
      { year: 2014, name: "Epic Turla", description: "Massive cyber-espionage campaign targeting 45+ countries using watering hole attacks and spearphishing" },
      { year: 2017, name: "Carbon Framework", description: "Sophisticated modular backdoor framework targeting government institutions with P2P C2" },
      { year: 2019, name: "Hijacking APT34 Infrastructure", description: "Turla hijacked Iranian APT34 (OilRig) C2 infrastructure to conduct operations under a false flag" },
      { year: 2023, name: "Snake Takedown", description: "FBI and Five Eyes partners dismantled the Snake/Uroburos malware network (Operation MEDUSA) after 20 years of operations" }
    ],
    tools: ["Snake/Uroburos", "Carbon", "ComRAT (Agent.BTZ successor)", "Kazuar", "Gazer", "LightNeuron", "Crutch", "TinyTurla", "Capibar", "DeliveryCheck"],
    ttps: [
      "T1071.004 — DNS (DNS-over-HTTPS for C2)",
      "T1102 — Web Service (satellite internet hijacking for C2)",
      "T1584.004 — Compromise Infrastructure (hijacking other APT's C2)",
      "T1091 — Replication Through Removable Media (Agent.BTZ USB)",
      "T1505.003 — Web Shell",
      "T1027 — Obfuscated Files or Information",
      "T1090 — Proxy (complex multi-hop proxy chains)",
      "T1562 — Impair Defenses"
    ],
    iocs: {
      techniques: ["Satellite internet hijacking for C2 communication", "Hijacking rival APT infrastructure", "20+ year operational continuity with evolving toolsets"]
    }
  },
  // ==================== CHINA ====================
  {
    name: "APT1",
    aliases: ["Comment Crew", "Comment Panda", "PLA Unit 61398", "Byzantine Candor", "Shanghai Group"],
    attribution: "China — PLA Unit 61398, 3rd Department of the General Staff (3PLA), based in Pudong, Shanghai",
    active_since: 2006,
    status: "Active (reorganized)",
    targets: {
      industries: ["Aerospace", "Defense", "Technology", "Energy", "Telecommunications", "Manufacturing", "Financial", "Media"],
      countries: ["United States", "Canada", "United Kingdom", "European Union", "Japan", "Taiwan"]
    },
    notable_campaigns: [
      { year: 2013, name: "Mandiant APT1 Report", description: "Mandiant publicly attributed the group to PLA Unit 61398, documenting 141 victims across 20 major industries over 7 years" },
      { year: 2014, name: "US DOJ Indictment", description: "5 PLA officers indicted by name for computer hacking and economic espionage — first time the US charged state-sponsored hackers" },
      { year: 2011, name: "RSA SecurID Breach", description: "Compromised RSA SecurID two-factor authentication system, then used stolen seeds to attack defense contractors including Lockheed Martin" }
    ],
    tools: ["WEBC2", "BISCUIT", "CALENDAR", "GLOOXMAIL", "MANITSME", "GETMAIL", "HACKSFASE", "SEASALT", "KURTON"],
    ttps: [
      "T1566.001 — Spearphishing Attachment",
      "T1059.001 — PowerShell",
      "T1003 — OS Credential Dumping",
      "T1005 — Data from Local System",
      "T1114 — Email Collection",
      "T1070 — Indicator Removal on Host",
      "T1021.001 — Remote Services: RDP",
      "T1074 — Data Staged (for exfiltration)"
    ],
    iocs: {
      techniques: ["Sustained multi-year access campaigns", "Large-scale intellectual property theft", "Pivoting from initial compromises to high-value targets"]
    }
  },
  {
    name: "APT10",
    aliases: ["Stone Panda", "MenuPass", "Cicada", "POTASSIUM", "Red Apollo", "CVNX"],
    attribution: "China — MSS (Ministry of State Security), Tianjin State Security Bureau",
    active_since: 2009,
    status: "Active",
    targets: {
      industries: ["Managed Service Providers (MSPs)", "Technology", "Healthcare", "Aerospace", "Government", "Telecommunications"],
      countries: ["United States", "Japan", "United Kingdom", "India", "Australia", "Canada", "Brazil", "France"]
    },
    notable_campaigns: [
      { year: 2017, name: "Operation Cloud Hopper", description: "Massive campaign targeting MSPs to gain access to their clients' networks — compromised MSPs in 12+ countries, affecting hundreds of downstream organizations" },
      { year: 2018, name: "US DOJ Indictment", description: "Two Chinese nationals (Zhu Hua and Zhang Shilong) indicted for computer hacking conspiracy" },
      { year: 2020, name: "Cicada Campaign", description: "Targeted Japanese organizations with A41APT campaign using sophisticated multi-layer obfuscation" }
    ],
    tools: ["PlugX/Destroy RAT", "QuasarRAT", "Poison Ivy", "RedLeaves", "ChChes", "UPPERCUT", "SodaMaster", "P8RAT", "Ecipekac"],
    ttps: [
      "T1199 — Trusted Relationship (targeting MSPs to reach clients)",
      "T1078 — Valid Accounts (stolen MSP credentials)",
      "T1021.001 — RDP",
      "T1027.002 — Software Packing (multi-layer obfuscation)",
      "T1055 — Process Injection",
      "T1053.005 — Scheduled Task",
      "T1071.001 — Web Protocols (HTTPS C2)",
      "T1041 — Exfiltration Over C2 Channel"
    ],
    iocs: {
      techniques: ["MSP compromise for supply chain access to hundreds of clients", "Long-term persistent access (years)", "Multi-layer malware obfuscation (Ecipekac loader)"]
    }
  },
  {
    name: "APT41",
    aliases: ["Double Dragon", "Wicked Panda", "Winnti", "Barium", "Bronze Atlas", "LEAD"],
    attribution: "China — MSS-linked, dual espionage and financially motivated operations",
    active_since: 2012,
    status: "Active",
    targets: {
      industries: ["Technology", "Gaming", "Healthcare", "Telecommunications", "Government", "Education", "Travel", "Media"],
      countries: ["United States", "Japan", "South Korea", "India", "France", "United Kingdom", "Netherlands", "Singapore"]
    },
    notable_campaigns: [
      { year: 2020, name: "US State Government Breaches", description: "Exploited zero-days in Zoho ManageEngine and Citrix to breach at least 6 US state government networks" },
      { year: 2019, name: "Video Game Supply Chain", description: "Compromised video game supply chains to distribute ShadowPad backdoor through legitimate game updates, also conducted in-game currency theft" },
      { year: 2020, name: "US DOJ Indictment", description: "5 Chinese nationals and 2 Malaysian nationals charged; attacks against 100+ companies worldwide" },
      { year: 2021, name: "Log4Shell Exploitation", description: "Among the first APT groups to exploit Log4Shell (CVE-2021-44228) within hours of public disclosure" }
    ],
    tools: ["ShadowPad", "Winnti", "CROSSWALK", "PlugX", "KEYPLUG", "DUSTPAN", "DUSTTRAP", "LOWKEY", "Cobalt Strike", "Metasploit"],
    ttps: [
      "T1195.002 — Supply Chain Compromise (gaming software, Codecov)",
      "T1190 — Exploit Public-Facing Application (zero-days in Citrix, Zoho, Log4j)",
      "T1059.001 — PowerShell",
      "T1505.003 — Web Shell",
      "T1553.002 — Code Signing (stolen game studio certificates)",
      "T1592 — Gather Victim Host Information",
      "T1057 — Process Discovery",
      "T1018 — Remote System Discovery"
    ],
    iocs: {
      techniques: ["Dual-purpose operations (state espionage + financial crime)", "Supply chain attacks through gaming industry", "Rapid zero-day exploitation (hours after disclosure)"]
    }
  },
  {
    name: "Volt Typhoon",
    aliases: ["Vanguard Panda", "Bronze Silhouette", "DEV-0391", "Insidious Taurus", "UNC3236"],
    attribution: "China — PLA or MSS-affiliated (contested by China, confirmed by Five Eyes)",
    active_since: 2021,
    status: "Active",
    targets: {
      industries: ["Critical infrastructure (energy, water, transportation, communications)", "Government", "Military (Guam)", "Maritime"],
      countries: ["United States", "Guam", "Australia"]
    },
    notable_campaigns: [
      { year: 2023, name: "Critical Infrastructure Pre-positioning", description: "Microsoft and Five Eyes disclosed Volt Typhoon's systematic compromise of US critical infrastructure — assessed as pre-positioning for potential disruption during a conflict (e.g., Taiwan crisis)" },
      { year: 2024, name: "KV Botnet", description: "Operated botnet of compromised SOHO routers (Cisco, Netgear, etc.) as operational relay network — disrupted by FBI court-ordered operation in Jan 2024" },
      { year: 2023, name: "Guam Communications", description: "Targeted telecommunications and maritime organizations in Guam, a strategic US military outpost in the Pacific" }
    ],
    tools: ["Living-off-the-land binaries (LOLBins) — minimal custom malware", "ntdsutil", "netsh", "PowerShell", "certutil", "FRP (Fast Reverse Proxy)", "Impacket", "China Chopper web shell"],
    ttps: [
      "T1078 — Valid Accounts (compromised VPN/administrator credentials)",
      "T1133 — External Remote Services (VPN/Fortinet/Citrix/Ivanti exploitation)",
      "T1059.001 — PowerShell",
      "T1003.003 — NTDS (ntdsutil domain credential extraction)",
      "T1021 — Remote Services (RDP, SMB, WinRM using legitimate credentials)",
      "T1218 — System Binary Proxy Execution (living-off-the-land)",
      "T1584 — Compromise Infrastructure (SOHO router botnet as C2 relay)",
      "T1070 — Indicator Removal (extensive log clearing)"
    ],
    iocs: {
      techniques: [
        "Exclusively living-off-the-land (no custom malware — makes detection extremely difficult)",
        "Pre-positioning in critical infrastructure for potential future disruption",
        "Using compromised SOHO routers as operational relay boxes (KV-botnet)",
        "Years-long persistent access without triggering alerts"
      ]
    }
  },
  {
    name: "Salt Typhoon",
    aliases: ["GhostEmperor", "FamousSparrow", "UNC2286"],
    attribution: "China — MSS-affiliated",
    active_since: 2019,
    status: "Active",
    targets: {
      industries: ["Telecommunications", "Internet Service Providers", "Government communications"],
      countries: ["United States", "European Union", "Southeast Asia"]
    },
    notable_campaigns: [
      { year: 2024, name: "US Telecom Breaches", description: "Compromised at least 9 major US telecommunications providers (AT&T, Verizon, T-Mobile, Lumen) — accessed lawful intercept systems and communications metadata of US government officials including presidential campaign staff" },
      { year: 2024, name: "CALEA System Access", description: "Gained access to systems used for court-ordered wiretapping (CALEA), potentially compromising active law enforcement investigations" }
    ],
    tools: ["Demodex rootkit", "GhostRAT", "Custom implants targeting telecom infrastructure", "Exploitation of telecom-specific protocols"],
    ttps: [
      "T1190 — Exploit Public-Facing Application (Cisco IOS XE, Fortinet)",
      "T1078 — Valid Accounts",
      "T1557 — Adversary-in-the-Middle (telecom network interception)",
      "T1119 — Automated Collection (communications metadata)",
      "T1005 — Data from Local System (lawful intercept data)",
      "T1041 — Exfiltration Over C2 Channel"
    ],
    iocs: {
      techniques: [
        "Targeting telecom lawful intercept (CALEA) infrastructure",
        "Communications metadata collection at scale",
        "Multi-carrier compromise for comprehensive surveillance capability"
      ]
    }
  },
  // ==================== NORTH KOREA ====================
  {
    name: "Lazarus Group",
    aliases: ["Hidden Cobra", "ZINC", "Diamond Sleet", "Labyrinth Chollima", "APT38 (financial operations)", "BlueNoroff (crypto operations)", "Andariel (South Korea operations)"],
    attribution: "North Korea — Reconnaissance General Bureau (RGB)",
    active_since: 2009,
    status: "Active",
    targets: {
      industries: ["Cryptocurrency/DeFi", "Financial institutions (SWIFT)", "Defense", "Aerospace", "Technology", "Media/Entertainment", "Government"],
      countries: ["United States", "South Korea", "Japan", "Global (cryptocurrency theft)"]
    },
    notable_campaigns: [
      { year: 2014, name: "Sony Pictures Hack", description: "Destructive attack on Sony Pictures in retaliation for 'The Interview' movie, leaked unreleased films, executive emails, and employee data" },
      { year: 2016, name: "Bangladesh Bank SWIFT Heist", description: "Stole $81 million from Bangladesh Bank via fraudulent SWIFT messages (attempted $951 million, stopped by typo in routing)" },
      { year: 2017, name: "WannaCry", description: "Global ransomware attack using EternalBlue, attributed to Lazarus — infected 230,000+ systems in 150 countries" },
      { year: 2022, name: "Ronin Bridge ($625M)", description: "Stole $625 million from the Ronin Bridge (Axie Infinity) by compromising validator nodes via fake job offer phishing" },
      { year: 2023, name: "Cryptocurrency Theft Spree", description: "Stole $1.7+ billion in cryptocurrency across multiple attacks (Atomic Wallet, CoinEx, Stake.com, etc.)" },
      { year: 2025, name: "Bybit ($1.5B)", description: "Largest cryptocurrency theft in history — $1.5 billion stolen from Bybit exchange" }
    ],
    tools: ["BLINDINGCAN", "COPPERHEDGE", "DTrack", "AppleJeus (fake crypto trading apps)", "ThreatNeedle", "ELECTRICFISH", "FASTCash", "TraderTraitor", "KANDYKORN", "RustBucket"],
    ttps: [
      "T1566 — Spearphishing (fake job offers via LinkedIn targeting crypto/tech employees)",
      "T1195.002 — Supply Chain Compromise (trojanized crypto trading applications)",
      "T1059.006 — Python (cross-platform malware)",
      "T1059.007 — JavaScript (AppleJeus and TraderTraitor Electron apps)",
      "T1565.001 — Stored Data Manipulation (SWIFT transaction fraud)",
      "T1657 — Financial Theft (cryptocurrency)",
      "T1204.002 — Malicious File (weaponized documents with job offers)",
      "T1027 — Obfuscated Files"
    ],
    iocs: {
      techniques: [
        "Fake job recruitment campaigns targeting crypto developers via LinkedIn",
        "Trojanized cryptocurrency trading applications (AppleJeus)",
        "SWIFT banking system exploitation for wire fraud",
        "Cryptocurrency bridge and DeFi protocol exploitation",
        "IT worker infiltration schemes (North Korean IT workers employed under false identities)"
      ]
    }
  },
  {
    name: "Kimsuky",
    aliases: ["Velvet Chollima", "Thallium", "Emerald Sleet", "Black Banshee", "APT43", "ARCHIPELAGO"],
    attribution: "North Korea — RGB (Reconnaissance General Bureau), focused on intelligence collection",
    active_since: 2012,
    status: "Active",
    targets: {
      industries: ["Government", "Think tanks", "Academia", "Nuclear policy experts", "Journalists", "Human rights organizations"],
      countries: ["South Korea", "United States", "Japan", "European Union"]
    },
    notable_campaigns: [
      { year: 2014, name: "Korea Hydro & Nuclear Power", description: "Breached South Korean nuclear power operator, stole reactor blueprints and employee data" },
      { year: 2023, name: "ReconShark", description: "Targeted think tank experts and academics researching North Korea policy with spearphishing" },
      { year: 2023, name: "Credential Harvesting", description: "Massive Google/Yahoo credential phishing campaigns targeting North Korea policy experts, journalists, and NGO workers" }
    ],
    tools: ["BabyShark", "ReconShark", "GoldDragon", "AppleSeed", "FlowerPower", "RandomQuery", "FastViewer (Android)", "custom Chrome extensions for email theft"],
    ttps: [
      "T1566.001 — Spearphishing Attachment",
      "T1566.002 — Spearphishing Link (credential harvesting)",
      "T1598.003 — Spearphishing for Information (impersonating journalists/academics)",
      "T1114 — Email Collection (custom browser extensions, BEC)",
      "T1059.001 — PowerShell",
      "T1204.002 — Malicious File (weaponized documents)",
      "T1176 — Browser Extensions (malicious Chrome extensions for email theft)",
      "T1583.001 — Acquire Infrastructure: Domains (lookalike domains)"
    ],
    iocs: {
      techniques: [
        "Extensive social engineering before technical exploitation",
        "Impersonating journalists and think tank researchers in prolonged email exchanges",
        "Custom browser extensions for Gmail/Yahoo email collection",
        "Credential harvesting via realistic phishing pages"
      ]
    }
  },
  // ==================== IRAN ====================
  {
    name: "APT33",
    aliases: ["Elfin", "Magnallium", "Refined Kitten", "Peach Sandstorm", "HOLMIUM"],
    attribution: "Iran — IRGC (Islamic Revolutionary Guard Corps)",
    active_since: 2013,
    status: "Active",
    targets: {
      industries: ["Aviation", "Energy (petrochemical)", "Defense", "Government"],
      countries: ["Saudi Arabia", "United States", "South Korea", "United Arab Emirates"]
    },
    notable_campaigns: [
      { year: 2012, name: "Shamoon Attacks (associated)", description: "Destructive wiper attacks on Saudi Aramco (35,000 workstations) and RasGas — though direct APT33 involvement is debated vs. other Iranian groups" },
      { year: 2017, name: "Aviation Targeting", description: "Targeted US and Saudi Arabian aviation and petrochemical companies with spearphishing" },
      { year: 2023, name: "Password Spray Campaign", description: "Large-scale password spray attacks against thousands of organizations globally, with focus on defense and satellite sectors" }
    ],
    tools: ["Shamoon/Disttrack (associated)", "Turnedup", "DROPSHOT", "ShapeShift", "STONEDRILL", "PoshC2", "FalseFont"],
    ttps: [
      "T1566 — Spearphishing (job recruitment themed)",
      "T1110.003 — Password Spraying",
      "T1078 — Valid Accounts",
      "T1190 — Exploit Public-Facing Application",
      "T1561 — Disk Wipe (Shamoon association)",
      "T1059.001 — PowerShell",
      "T1588.002 — Obtain Capabilities: Tool (open-source RATs)"
    ],
    iocs: {
      techniques: [
        "Job recruitment themed spearphishing (fake Boeing, Lockheed Martin recruiters)",
        "Large-scale password spray campaigns",
        "Destructive wiper deployment against energy sector"
      ]
    }
  },
  {
    name: "APT34",
    aliases: ["OilRig", "Helix Kitten", "IRN2", "Hazel Sandstorm", "COBALT GYPSY", "Crambus"],
    attribution: "Iran — MOIS (Ministry of Intelligence and Security)",
    active_since: 2014,
    status: "Active",
    targets: {
      industries: ["Government", "Financial", "Energy", "Telecommunications", "Chemical"],
      countries: ["Middle East (Saudi Arabia, UAE, Qatar, Kuwait, Bahrain, Lebanon, Jordan)", "United States"]
    },
    notable_campaigns: [
      { year: 2019, name: "Tools Leaked on Telegram", description: "OilRig tools (Glimpse, PoisonFrog, HyperShell, Fox Panel) leaked on Telegram by entity 'Lab Dookhtegan', exposing operational details and victim data" },
      { year: 2017, name: "DNS Hijacking Campaign", description: "Compromised DNS registrars and telecommunications providers to redirect DNS for government and private organizations" },
      { year: 2020, name: "Middle East Government Targeting", description: "Continued campaigns against government entities using web shells and custom backdoors" }
    ],
    tools: ["Helminth", "ISMAgent", "OopsIE", "QUADAGENT", "VALUEVAULT", "LONGWATCH", "Glimpse", "PoisonFrog", "Karkoff", "SideTwist", "Saitama"],
    ttps: [
      "T1566.001 — Spearphishing Attachment (macro documents)",
      "T1583.001 — Acquire Infrastructure: Domains",
      "T1071.004 — DNS (DNS tunneling for C2)",
      "T1505.003 — Web Shell (TwoFace, HyperShell)",
      "T1003 — OS Credential Dumping (Mimikatz, LaZagne)",
      "T1087 — Account Discovery",
      "T1016 — System Network Configuration Discovery",
      "T1053.005 — Scheduled Task"
    ],
    iocs: {
      techniques: [
        "DNS tunneling for C2 communication",
        "DNS hijacking at registrar level",
        "Extensive web shell deployment",
        "Social engineering via LinkedIn"
      ]
    }
  },
  {
    name: "APT35",
    aliases: ["Charming Kitten", "Phosphorus", "Mint Sandstorm", "TA453", "Yellow Garuda", "ITG18", "Newscaster"],
    attribution: "Iran — IRGC Intelligence Organization (IRGC-IO)",
    active_since: 2014,
    status: "Active",
    targets: {
      industries: ["Think tanks", "Government", "Media/Journalism", "Academia", "Human rights", "Nuclear policy"],
      countries: ["United States", "Israel", "United Kingdom", "European Union"]
    },
    notable_campaigns: [
      { year: 2019, name: "HBO Hack", description: "Breached HBO, stealing unaired Game of Thrones episodes and internal data, demanding $6 million ransom" },
      { year: 2020, name: "COVID-19 Research Targeting", description: "Targeted pharmaceutical companies and WHO personnel during COVID-19 pandemic" },
      { year: 2023, name: "MediaPl Backdoor", description: "Deployed novel backdoor targeting Middle East affairs specialists at think tanks and universities" },
      { year: 2024, name: "US Election Campaign Targeting", description: "Targeted US presidential campaigns with spearphishing and credential harvesting" }
    ],
    tools: ["HYPERSCRAPE (email extraction)", "CharmPower", "BellaCiao", "MediaPl", "POWERSTAR", "NokNok (macOS)", "KORG", "DownPaper", "Sponsor"],
    ttps: [
      "T1598 — Phishing for Information (extended social engineering before technical exploitation)",
      "T1566.002 — Spearphishing Link (credential harvesting pages)",
      "T1114 — Email Collection (HYPERSCRAPE bulk email extraction)",
      "T1078 — Valid Accounts (compromised academic/journalist accounts)",
      "T1204 — User Execution (multi-persona impersonation to build trust)",
      "T1583.001 — Acquire Infrastructure: Domains (typosquatting academic/media sites)"
    ],
    iocs: {
      techniques: [
        "Multi-persona social engineering (impersonating journalists, academics, think tank staff)",
        "Extended rapport building over weeks/months before delivering payload",
        "HYPERSCRAPE tool for bulk email collection from webmail providers",
        "Targeting dual-national diaspora communities"
      ]
    }
  },
  // ==================== FINANCIALLY MOTIVATED ====================
  {
    name: "FIN7",
    aliases: ["Carbanak Group", "Carbon Spider", "Navigator Group", "Sangria Tempest", "ELBRUS"],
    attribution: "Eastern European cybercrime organization",
    active_since: 2013,
    status: "Active",
    targets: {
      industries: ["Retail (point-of-sale)", "Hospitality", "Restaurant chains", "Financial services"],
      countries: ["United States", "United Kingdom", "European Union", "Australia"]
    },
    notable_campaigns: [
      { year: 2018, name: "Point-of-Sale Campaigns", description: "Compromised over 6,500 POS terminals across thousands of retail locations (Chipotle, Arby's, Red Robin, Chili's), stealing millions of credit card numbers" },
      { year: 2020, name: "Fake Cybersecurity Company", description: "Created a fake company called 'Combi Security' to recruit legitimate penetration testers who unknowingly helped FIN7 develop attack tools" },
      { year: 2022, name: "BlackBasta Partnership", description: "Transitioned from POS fraud to ransomware, working with BlackBasta RaaS operation" }
    ],
    tools: ["Carbanak/Anunak", "GRIFFON", "HALFBAKED", "BOOSTWRITE", "JSSLoader", "Lizar/Tirion", "PowerPlant", "BlackBasta ransomware (partnership)"],
    ttps: [
      "T1566.001 — Spearphishing Attachment (macro documents, LNK files in ZIP)",
      "T1204.002 — Malicious File",
      "T1059.001 — PowerShell",
      "T1055 — Process Injection",
      "T1005 — Data from Local System (POS memory scraping)",
      "T1486 — Data Encrypted for Impact (ransomware pivot)",
      "T1657 — Financial Theft (credit card data)",
      "T1585 — Establish Accounts (fake company for recruitment)"
    ],
    iocs: {
      techniques: [
        "POS malware for credit card data theft",
        "Created fake cybersecurity companies for operational cover and recruitment",
        "Transitioned from financial fraud to ransomware operations",
        "Highly structured criminal organization with specialized roles"
      ]
    }
  },
  {
    name: "FIN11",
    aliases: ["TA505", "Evil Corp (disputed)", "Graceful Spider", "Gold Tahoe"],
    attribution: "Eastern European (Russia-based) cybercrime group",
    active_since: 2014,
    status: "Active",
    targets: {
      industries: ["Financial", "Retail", "Healthcare", "Technology", "Government"],
      countries: ["Global — over 40 countries"]
    },
    notable_campaigns: [
      { year: 2019, name: "Cl0p Ransomware", description: "Deployed Cl0p ransomware against enterprise targets, pioneering double extortion with data leak site" },
      { year: 2021, name: "Accellion FTA Exploitation", description: "Mass exploited zero-days in Accellion FTA file transfer appliance, stealing data from 100+ organizations including Shell, Qualys, Jones Day" },
      { year: 2023, name: "MOVEit Transfer (CVE-2023-34362)", description: "Mass exploited MOVEit Transfer zero-day, affecting 2,500+ organizations — largest data theft campaign of 2023" }
    ],
    tools: ["Cl0p ransomware", "FlawedAmmyy RAT", "SDBbot", "Get2 loader", "FlawedGrace", "DEWMODE (Accellion web shell)", "LEMURLOOT (MOVEit web shell)"],
    ttps: [
      "T1190 — Exploit Public-Facing Application (zero-days in file transfer platforms)",
      "T1505.003 — Web Shell (DEWMODE, LEMURLOOT)",
      "T1566.001 — Spearphishing Attachment (malicious Excel/Word documents)",
      "T1486 — Data Encrypted for Impact (Cl0p)",
      "T1657 — Financial Theft (extortion without encryption)",
      "T1048 — Exfiltration Over Alternative Protocol"
    ],
    iocs: {
      techniques: [
        "Mass exploitation of file transfer platform zero-days (Accellion, GoAnywhere, MOVEit)",
        "Encryption-less extortion (data theft without deploying ransomware)",
        "High-volume spam campaigns (historically millions of emails per campaign)"
      ]
    }
  },
  {
    name: "Scattered Spider",
    aliases: ["Octo Tempest", "UNC3944", "Star Fraud", "Scatter Swine", "Muddled Libra", "0ktapus"],
    attribution: "English-speaking cybercrime collective (US, UK, primarily young adults/teenagers)",
    active_since: 2022,
    status: "Active",
    targets: {
      industries: ["Telecommunications", "Technology", "Hospitality/Gaming (MGM, Caesars)", "Financial", "Retail", "Business Process Outsourcing"],
      countries: ["United States", "United Kingdom", "Canada"]
    },
    notable_campaigns: [
      { year: 2022, name: "0ktapus Campaign", description: "Phished Okta credentials from 130+ organizations (Twilio, Cloudflare, Mailchimp, DoorDash) using fake Okta login pages sent via SMS" },
      { year: 2023, name: "MGM Resorts ($100M impact)", description: "Brought down MGM Resorts operations for 10+ days via social engineering of IT help desk, causing ~$100 million in losses" },
      { year: 2023, name: "Caesars Entertainment ($15M ransom)", description: "Social engineered Caesars Entertainment and collected $15 million ransom payment" }
    ],
    tools: ["Phishing kits (Evilginx2, Modlishka)", "ALPHV/BlackCat ransomware (partnership)", "Mimikatz", "Cobalt Strike", "AnyDesk", "FleetDeck", "Splashtop", "ScreenConnect"],
    ttps: [
      "T1566.002 — Spearphishing Link (SMS phishing / smishing with fake Okta pages)",
      "T1598.004 — Spearphishing Voice (vishing IT help desks to reset MFA)",
      "T1621 — Multi-Factor Authentication Request Generation (MFA fatigue/bombing)",
      "T1078 — Valid Accounts (SIM swapping to intercept SMS MFA)",
      "T1199 — Trusted Relationship (compromising identity providers)",
      "T1219 — Remote Access Software (AnyDesk, ScreenConnect)",
      "T1486 — Data Encrypted for Impact (ALPHV/BlackCat partnership)"
    ],
    iocs: {
      techniques: [
        "Social engineering IT help desks via phone (extremely convincing, native English speakers)",
        "SMS phishing with real-time Okta credential relay (AiTM)",
        "SIM swapping for MFA bypass",
        "MFA fatigue attacks (push notification bombing)",
        "Targeting identity providers (Okta, Azure AD) as pivot point"
      ]
    }
  },
  // ==================== EQUATION GROUP / FIVE EYES ====================
  {
    name: "Equation Group",
    aliases: ["EQGRP", "Longhorn (CIA)", "Lamberts"],
    attribution: "United States — NSA (National Security Agency), Tailored Access Operations (TAO)",
    active_since: 1996,
    status: "Active (presumed)",
    targets: {
      industries: ["Government", "Military", "Telecommunications", "Energy", "Aerospace", "Nuclear research", "Islamic institutions"],
      countries: ["Iran", "Russia", "China", "Pakistan", "Afghanistan", "India", "Syria", "Mali", "Global"]
    },
    notable_campaigns: [
      { year: 2010, name: "Stuxnet (associated)", description: "Co-developed Stuxnet with Israel's Unit 8200 targeting Iranian nuclear centrifuges (Olympic Games)" },
      { year: 2016, name: "Shadow Brokers Leak", description: "Shadow Brokers group leaked NSA/Equation Group tools including EternalBlue, EternalRomance, DoublePulsar, and FUZZBUNCH framework" },
      { year: 2013, name: "Snowden Revelations", description: "Edward Snowden disclosed NSA global surveillance programs (PRISM, XKeyscore, BULLRUN) and TAO capabilities" }
    ],
    tools: ["EQUATIONDRUG", "EQUATIONLASER", "FANNY (USB worm)", "GRAYFISH", "EternalBlue", "EternalRomance", "DoublePulsar", "FUZZBUNCH", "DanderSpritz", "UNITEDRAKE"],
    ttps: [
      "T1542 — Pre-OS Boot (hard drive firmware implants — survives OS reinstallation and disk formatting)",
      "T1091 — Replication Through Removable Media (FANNY USB worm using 2 zero-days)",
      "T1190 — Exploit Public-Facing Application (multiple zero-days)",
      "T1210 — Exploitation of Remote Services (EternalBlue, EternalRomance)",
      "T1556 — Modify Authentication Process",
      "T1027 — Obfuscated Files (multi-layer encryption with unique keys per victim)",
      "T1557 — Adversary-in-the-Middle"
    ],
    iocs: {
      techniques: [
        "Hard drive firmware reprogramming (persists through OS reinstall and disk format)",
        "Air-gap jumping via USB malware (FANNY worm)",
        "Stockpile of zero-day exploits for major platforms",
        "Most sophisticated publicly known threat actor toolset",
        "Operational security practices spanning decades"
      ]
    }
  },
  // ==================== ADDITIONAL GROUPS ====================
  {
    name: "APT32",
    aliases: ["OceanLotus", "Canvas Cyclone", "SeaLotus", "APT-C-00", "Ocean Buffalo"],
    attribution: "Vietnam — Ministry of Public Security or intelligence services",
    active_since: 2012,
    status: "Active",
    targets: {
      industries: ["Government", "Media/Journalism", "Dissidents/Human rights", "Manufacturing", "Technology", "Hospitality"],
      countries: ["Vietnam (domestic surveillance)", "Cambodia", "Philippines", "Laos", "China", "Germany"]
    },
    notable_campaigns: [
      { year: 2017, name: "Vietnamese Domestic Surveillance", description: "Targeted Vietnamese bloggers, journalists, and human rights activists with spyware" },
      { year: 2018, name: "Southeast Asian Automotive", description: "Targeted automotive companies including Toyota, Lexus, and BMW in Southeast Asia" },
      { year: 2020, name: "COVID-19 Espionage", description: "Targeted Chinese government organizations for COVID-19 intelligence during the early pandemic" }
    ],
    tools: ["Denis", "Cobalt Kitty", "Windshield", "KOMPROGO", "SOUNDBITE", "PHOREAL", "BEACON (Cobalt Strike)", "Kerrdown", "RotaJakiro (Linux)"],
    ttps: [
      "T1189 — Drive-by Compromise (watering hole attacks with custom exploits)",
      "T1566.001 — Spearphishing Attachment (weaponized documents)",
      "T1059.005 — Visual Basic (macro-based execution)",
      "T1574.002 — DLL Side-Loading",
      "T1055 — Process Injection",
      "T1071.001 — Web Protocols (Cobalt Strike HTTPS)",
      "T1140 — Deobfuscate/Decode Files"
    ],
    iocs: {
      techniques: [
        "Watering hole attacks targeting specific communities",
        "macOS malware targeting Vietnamese diaspora",
        "Strategic web compromise of Vietnamese-language news sites"
      ]
    }
  },
  {
    name: "APT37",
    aliases: ["Reaper", "ScarCruft", "Ricochet Chollima", "StarCruft", "Group123", "Red Eyes", "InkySquid"],
    attribution: "North Korea — MSS (Ministry of State Security)",
    active_since: 2012,
    status: "Active",
    targets: {
      industries: ["Government", "Military", "Defense", "Media", "Human rights/Defectors"],
      countries: ["South Korea", "Japan", "Vietnam", "Middle East"]
    },
    notable_campaigns: [
      { year: 2018, name: "Adobe Flash Zero-Day", description: "Exploited Adobe Flash zero-day (CVE-2018-4878) in targeted attacks against South Korean organizations" },
      { year: 2022, name: "Internet Explorer Zero-Day", description: "Exploited Internet Explorer zero-day (CVE-2022-41128) via weaponized documents" },
      { year: 2023, name: "Defector Targeting", description: "Targeted North Korean defectors and human rights organizations in South Korea with mobile spyware" }
    ],
    tools: ["RokRAT", "BLUELIGHT", "GOLDBACKDOOR", "DOLPHIN", "M2RAT", "Chinotto (Android/Windows)", "NavRAT", "POORWEB"],
    ttps: [
      "T1190 — Exploit Public-Facing Application (zero-days in Flash, IE)",
      "T1566.001 — Spearphishing Attachment",
      "T1059.005 — Visual Basic (macros)",
      "T1102 — Web Service (cloud storage for C2: Dropbox, Yandex, pCloud)",
      "T1113 — Screen Capture",
      "T1056.001 — Keylogging",
      "T1005 — Data from Local System"
    ],
    iocs: {
      techniques: [
        "Zero-day exploitation capability (Flash, IE, Windows)",
        "Cloud storage services for C2 (harder to block/detect)",
        "Cross-platform targeting (Windows, Android, macOS)"
      ]
    }
  },
  {
    name: "Gamaredon",
    aliases: ["Primitive Bear", "Aqua Blizzard", "Armageddon", "Shuckworm", "Actinium", "DEV-0157", "UAC-0010"],
    attribution: "Russia — FSB (Federal Security Service), based in occupied Crimea",
    active_since: 2013,
    status: "Active",
    targets: {
      industries: ["Government", "Military", "Law enforcement", "NGOs", "Judiciary"],
      countries: ["Ukraine (primary target)", "NATO members (secondary)"]
    },
    notable_campaigns: [
      { year: 2022, name: "Ukraine War Cyber Operations", description: "Massively increased operations alongside Russia's invasion, targeting Ukrainian government and military organizations with hundreds of spearphishing attacks daily" },
      { year: 2023, name: "USB Propagation Campaign", description: "Deployed malware with USB worm capability to spread through Ukrainian government networks via infected flash drives" }
    ],
    tools: ["Pterodo/Pteranodon", "GammaLoad", "GammaSteel", "QuietSieve", "DinoTrain", "DessertDown", "custom VBS/PowerShell scripts"],
    ttps: [
      "T1566.001 — Spearphishing Attachment (weaponized documents from compromised contacts)",
      "T1059.005 — Visual Basic",
      "T1059.001 — PowerShell",
      "T1091 — Replication Through Removable Media (USB propagation)",
      "T1071.004 — DNS (Telegram, Telegraph for C2 domain resolution)",
      "T1105 — Ingress Tool Transfer",
      "T1113 — Screen Capture"
    ],
    iocs: {
      techniques: [
        "Extremely high operational tempo (hundreds of attacks per day during wartime)",
        "Uses compromised Ukrainian government email accounts for credible spearphishing",
        "Dynamic C2 infrastructure via Telegram/Telegraph channels",
        "Volume-based approach rather than sophisticated tooling"
      ]
    }
  },
  {
    name: "MuddyWater",
    aliases: ["Mercury", "Mango Sandstorm", "TEMP.Zagros", "Static Kitten", "Seedworm", "TA450"],
    attribution: "Iran — MOIS (Ministry of Intelligence and Security)",
    active_since: 2017,
    status: "Active",
    targets: {
      industries: ["Government", "Telecommunications", "Energy", "Defense"],
      countries: ["Middle East (Saudi Arabia, Iraq, Jordan, Turkey)", "South Asia (Pakistan, India)", "Central Asia", "Africa"]
    },
    notable_campaigns: [
      { year: 2022, name: "Log4Shell Exploitation", description: "Exploited Log4Shell vulnerability in SysAid servers targeting Israeli organizations" },
      { year: 2023, name: "Phishing-as-a-Service", description: "Developed and shared phishing infrastructure and tools with other Iranian threat groups" }
    ],
    tools: ["POWERSTATS (PowerShell backdoor)", "MuddyC3", "MuddyC2Go", "PhonyC2", "SimpleHarm", "SHARPSTATS", "Atera Agent (legitimate RMM tool abuse)", "ScreenConnect"],
    ttps: [
      "T1566 — Spearphishing (document with macros, direct links)",
      "T1059.001 — PowerShell (primary execution mechanism)",
      "T1219 — Remote Access Software (Atera, ScreenConnect abuse)",
      "T1071.001 — Web Protocols (HTTPS)",
      "T1053.005 — Scheduled Task",
      "T1003 — OS Credential Dumping",
      "T1105 — Ingress Tool Transfer"
    ],
    iocs: {
      techniques: [
        "Heavy reliance on PowerShell for all stages of operations",
        "Abuse of legitimate RMM tools (Atera, ScreenConnect) for persistence and access",
        "Shared infrastructure and tools with other Iranian APT groups"
      ]
    }
  },
  {
    name: "Lapsus$",
    aliases: ["DEV-0537", "Strawberry Tempest"],
    attribution: "International — teenagers/young adults (UK-based leader arrested at age 16)",
    active_since: 2021,
    status: "Inactive (key members arrested)",
    targets: {
      industries: ["Technology", "Telecommunications", "Gaming", "Government"],
      countries: ["Global (primarily targeting large technology companies)"]
    },
    notable_campaigns: [
      { year: 2022, name: "Microsoft Source Code", description: "Gained access to Microsoft internal systems and leaked source code for Bing, Cortana, and other products" },
      { year: 2022, name: "NVIDIA ($1M GPUs)", description: "Stole proprietary data including DLSS source code, GPU schematics, and employee credentials" },
      { year: 2022, name: "Samsung 190GB", description: "Leaked 190GB of Samsung source code including Galaxy device bootloader and Knox security framework" },
      { year: 2022, name: "Okta Breach", description: "Compromised an Okta support contractor (Sitel/Sykes), potentially affecting up to 366 Okta customers" },
      { year: 2022, name: "Uber Internal Systems", description: "Compromised Uber's internal systems including Slack, AWS, and vulnerability reports via social engineering" },
      { year: 2023, name: "Rockstar Games (GTA VI)", description: "Leaked 90+ pre-release GTA VI development videos, one of the biggest gaming leaks ever" }
    ],
    tools: ["SIM swapping", "MFA fatigue", "Social engineering", "Insider recruitment (paying employees for access)", "Redline Stealer logs", "Genesis marketplace credentials"],
    ttps: [
      "T1078 — Valid Accounts (purchased from dark web credential markets)",
      "T1566.004 — Spearphishing Voice (calling IT help desks)",
      "T1621 — MFA Request Generation (MFA fatigue/bombing — spam push notifications)",
      "T1136 — Create Account",
      "T1098 — Account Manipulation",
      "T1530 — Data from Cloud Storage Object",
      "T1567 — Exfiltration Over Web Service (Telegram for data leaks)"
    ],
    iocs: {
      techniques: [
        "SIM swapping to bypass SMS-based MFA",
        "MFA fatigue attacks (flooding targets with push notifications at 1 AM)",
        "Paying company employees/contractors for insider access (openly advertised on Telegram)",
        "Social engineering via phone (native English speakers, highly convincing)",
        "Purchasing credential stealer logs from Genesis marketplace/dark web",
        "Leaking stolen data on Telegram for notoriety rather than financial gain"
      ]
    }
  }
];

export const APT_ATTRIBUTION_METHODS = [
  {
    method: "Technical indicators",
    description: "Analyzing malware code, infrastructure, and TTPs for patterns linked to known groups",
    examples: [
      "Code reuse and shared codebases between malware families",
      "Compilation timestamps and language settings in binaries",
      "Infrastructure overlaps (shared C2 servers, registrars, hosting)",
      "Distinctive encryption implementations or protocols"
    ],
    reliability: "Medium — can be spoofed or shared between groups"
  },
  {
    method: "Operational patterns",
    description: "Analyzing working hours, targeting patterns, and operational tempo",
    examples: [
      "Activity aligned with specific timezone working hours (e.g., UTC+8 for Chinese groups)",
      "Consistent targeting of specific industries or countries aligned with nation-state interests",
      "Campaign timing correlating with geopolitical events",
      "Language artifacts in malware strings, comments, or phishing lures"
    ],
    reliability: "Medium-High — harder to fake consistently over time"
  },
  {
    method: "Intelligence collection",
    description: "HUMINT, SIGINT, and law enforcement information",
    examples: [
      "SIGINT intercepts correlating cyber operations with government directives",
      "Law enforcement investigations and indictments",
      "Informant intelligence from within threat actor organizations",
      "Physical surveillance of suspected operators"
    ],
    reliability: "High — but rarely publicly available"
  },
  {
    method: "Victim and targeting analysis",
    description: "Analyzing who is targeted and what data is stolen to infer motivation",
    examples: [
      "Intellectual property theft aligned with national economic priorities (e.g., China's Made in China 2025)",
      "Targeting of dissidents, journalists, and human rights groups aligned with regime interests",
      "Financial theft aligned with sanctions evasion (North Korea)",
      "Critical infrastructure targeting aligned with military contingency planning"
    ],
    reliability: "Medium — provides motivation context but not definitive attribution"
  },
  {
    method: "False flag detection",
    description: "Identifying deliberate misdirection in attack attribution",
    examples: [
      "Olympic Destroyer (Sandworm) used code overlaps with Lazarus and APT3 to create false flags",
      "Language strings and compilation artifacts can be intentionally planted",
      "Infrastructure registered with stolen identities from target countries",
      "Turla hijacking APT34 infrastructure to conduct operations under Iran's name"
    ],
    reliability: "Critical awareness — any single indicator can be faked; attribution requires convergence of multiple independent evidence streams"
  }
];

export const THREAT_ACTOR_MOTIVATIONS = [
  {
    motivation: "Espionage (state-sponsored intelligence collection)",
    description: "Collecting strategic, political, military, or economic intelligence for national advantage",
    typical_actors: ["APT28", "APT29", "APT1", "APT10", "Turla", "Kimsuky", "APT35"],
    targets: ["Government agencies", "Military/defense", "Diplomatic missions", "Think tanks", "Academic researchers"],
    indicators: ["Long-term persistent access (months/years)", "Data exfiltration without disruption", "Targeting of classified or sensitive information"]
  },
  {
    motivation: "Financial gain (cybercrime)",
    description: "Generating revenue through fraud, ransomware, extortion, or theft",
    typical_actors: ["FIN7", "FIN11", "Scattered Spider", "REvil operators", "LockBit affiliates"],
    targets: ["Financial institutions", "Retail (POS)", "Healthcare", "Any organization with valuable data or willingness to pay ransom"],
    indicators: ["Ransomware deployment", "Credit card data theft", "Business email compromise", "Cryptocurrency theft"]
  },
  {
    motivation: "Disruption/Destruction (state-sponsored or hacktivist)",
    description: "Disrupting or destroying target infrastructure for political or military objectives",
    typical_actors: ["Sandworm", "APT33 (Shamoon)", "Lazarus (WannaCry)"],
    targets: ["Critical infrastructure (energy, water, transportation)", "Government systems", "Military targets", "Media"],
    indicators: ["Wiper malware deployment", "ICS/SCADA targeting", "Timed attacks during geopolitical events", "Irreversible damage"]
  },
  {
    motivation: "Revenue generation for sanctioned regimes",
    description: "State-directed financial theft to fund government programs and circumvent sanctions",
    typical_actors: ["Lazarus Group", "APT38", "BlueNoroff"],
    targets: ["Banks (SWIFT)", "Cryptocurrency exchanges", "DeFi protocols", "Blockchain bridges"],
    indicators: ["SWIFT fraud", "Cryptocurrency theft at scale", "IT worker infiltration schemes", "Revenue estimated to fund weapons programs"]
  },
  {
    motivation: "Hacktivism / Notoriety",
    description: "Political activism, ideological motivation, or desire for fame/notoriety",
    typical_actors: ["Lapsus$", "Anonymous (collective)", "Various hacktivist groups"],
    targets: ["Corporations perceived as adversaries", "Government agencies", "High-profile technology companies"],
    indicators: ["Public data leaks", "Website defacement", "Social media announcements", "No financial demands (or demands for notoriety/political change)"]
  }
];
