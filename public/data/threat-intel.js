// =============================================================================
// THREAT INTELLIGENCE REFERENCE
// Comprehensive threat actor, MITRE ATT&CK, malware, IOC, and feed data
// =============================================================================

// -----------------------------------------------------------------------------
// 1. THREAT ACTORS -- Known threat groups (APTs, cybercrime, hacktivism)
// -----------------------------------------------------------------------------

export const THREAT_ACTORS = [
  // --- Nation-State: Russia ---
  {
    name: "APT28",
    aliases: ["Fancy Bear", "Sofacy", "Sednit", "Pawn Storm", "STRONTIUM", "Forest Blizzard"],
    origin: "Russia",
    type: "nation-state",
    targets: ["government", "military", "defense", "media", "energy"],
    ttps: ["T1566 Phishing", "T1059 Command and Scripting Interpreter", "T1071 Application Layer Protocol", "T1078 Valid Accounts", "T1203 Exploitation for Client Execution"],
    activeSince: 2004,
    notableCampaigns: ["DNC hack 2016", "Bundestag attack 2015", "WADA breach 2016", "NotPetya attribution overlap", "Ubiquiti EdgeRouter campaign 2024"]
  },
  {
    name: "APT29",
    aliases: ["Cozy Bear", "The Dukes", "NOBELIUM", "Midnight Blizzard", "YTTRIUM"],
    origin: "Russia",
    type: "nation-state",
    targets: ["government", "think tanks", "healthcare", "technology", "diplomatic"],
    ttps: ["T1195 Supply Chain Compromise", "T1059 Command and Scripting Interpreter", "T1071 Application Layer Protocol", "T1055 Process Injection", "T1027 Obfuscated Files"],
    activeSince: 2008,
    notableCampaigns: ["SolarWinds Orion supply chain attack 2020", "COVID-19 vaccine research targeting 2020", "Microsoft OAuth abuse 2023", "TeamCity exploitation 2024"]
  },
  {
    name: "Sandworm",
    aliases: ["Voodoo Bear", "IRIDIUM", "Seashell Blizzard", "Telebots", "Iron Viking"],
    origin: "Russia",
    type: "nation-state",
    targets: ["energy", "government", "critical infrastructure", "telecommunications", "financial"],
    ttps: ["T1485 Data Destruction", "T1499 Endpoint Denial of Service", "T1059 Command and Scripting Interpreter", "T1053 Scheduled Task", "T1562 Impair Defenses"],
    activeSince: 2009,
    notableCampaigns: ["Ukraine power grid attacks 2015/2016", "NotPetya 2017", "Olympic Destroyer 2018", "Cyclops Blink 2022", "AcidRain Viasat attack 2022"]
  },
  {
    name: "Turla",
    aliases: ["Snake", "Uroburos", "Venomous Bear", "KRYPTON", "Secret Blizzard", "Waterbug"],
    origin: "Russia",
    type: "nation-state",
    targets: ["government", "military", "education", "research", "pharmaceutical"],
    ttps: ["T1071 Application Layer Protocol", "T1027 Obfuscated Files", "T1055 Process Injection", "T1059 Command and Scripting Interpreter", "T1102 Web Service"],
    activeSince: 1996,
    notableCampaigns: ["Agent.BTZ 2008", "Epic Turla 2014", "Satellite communication hijacking", "Crutch backdoor 2020", "Snake malware takedown 2023"]
  },
  {
    name: "Gamaredon",
    aliases: ["Primitive Bear", "Shuckworm", "Actinium", "Aqua Blizzard", "Armageddon"],
    origin: "Russia",
    type: "nation-state",
    targets: ["government", "military", "NGOs", "judiciary", "law enforcement"],
    ttps: ["T1566 Phishing", "T1059 Command and Scripting Interpreter", "T1547 Boot or Logon Autostart Execution", "T1071 Application Layer Protocol", "T1105 Ingress Tool Transfer"],
    activeSince: 2013,
    notableCampaigns: ["Continuous Ukraine targeting since 2014", "USB spreading campaigns 2022", "Telegram-based C2 infrastructure 2023"]
  },
  {
    name: "Star Blizzard",
    aliases: ["SEABORGIUM", "Callisto Group", "ColdRiver", "TA446"],
    origin: "Russia",
    type: "nation-state",
    targets: ["defense", "government", "NGOs", "think tanks", "academia"],
    ttps: ["T1566 Phishing", "T1078 Valid Accounts", "T1114 Email Collection", "T1598 Phishing for Information", "T1534 Internal Spearphishing"],
    activeSince: 2017,
    notableCampaigns: ["UK government targeting 2022", "US nuclear research lab phishing 2023", "Evilginx credential harvesting 2023"]
  },

  // --- Nation-State: China ---
  {
    name: "APT41",
    aliases: ["Double Dragon", "Winnti", "Barium", "Wicked Panda", "Brass Typhoon"],
    origin: "China",
    type: "nation-state / cybercrime",
    targets: ["technology", "healthcare", "telecommunications", "gaming", "government"],
    ttps: ["T1195 Supply Chain Compromise", "T1059 Command and Scripting Interpreter", "T1055 Process Injection", "T1003 OS Credential Dumping", "T1071 Application Layer Protocol"],
    activeSince: 2012,
    notableCampaigns: ["CCleaner supply chain attack 2017", "ShadowPad backdoor deployment", "US state government compromise 2021-2022", "Citrix and Cisco zero-day exploitation 2023"]
  },
  {
    name: "APT1",
    aliases: ["Comment Crew", "Comment Panda", "PLA Unit 61398"],
    origin: "China",
    type: "nation-state",
    targets: ["technology", "aerospace", "energy", "manufacturing", "government"],
    ttps: ["T1566 Phishing", "T1059 Command and Scripting Interpreter", "T1003 OS Credential Dumping", "T1005 Data from Local System", "T1074 Data Staged"],
    activeSince: 2006,
    notableCampaigns: ["Mandiant APT1 report exposure 2013", "Operation Shady RAT", "Systematic US corporate espionage"]
  },
  {
    name: "APT10",
    aliases: ["Stone Panda", "MenuPass", "Red Apollo", "POTASSIUM"],
    origin: "China",
    type: "nation-state",
    targets: ["MSPs", "technology", "aerospace", "government", "healthcare"],
    ttps: ["T1199 Trusted Relationship", "T1059 Command and Scripting Interpreter", "T1003 OS Credential Dumping", "T1071 Application Layer Protocol", "T1041 Exfiltration Over C2 Channel"],
    activeSince: 2006,
    notableCampaigns: ["Operation Cloud Hopper (MSP targeting)", "Japanese government targeting 2020", "Managed service provider compromise campaigns"]
  },
  {
    name: "Hafnium",
    aliases: ["Silk Typhoon", "HAFNIUM"],
    origin: "China",
    type: "nation-state",
    targets: ["defense", "higher education", "legal", "infectious disease research", "policy"],
    ttps: ["T1190 Exploit Public-Facing Application", "T1003 OS Credential Dumping", "T1059 Command and Scripting Interpreter", "T1505 Server Software Component", "T1560 Archive Collected Data"],
    activeSince: 2017,
    notableCampaigns: ["Microsoft Exchange ProxyLogon zero-day exploitation 2021", "ProxyShell follow-on attacks"]
  },
  {
    name: "Volt Typhoon",
    aliases: ["BRONZE SILHOUETTE", "Vanguard Panda", "DEV-0391", "Insidious Taurus"],
    origin: "China",
    type: "nation-state",
    targets: ["critical infrastructure", "telecommunications", "energy", "water", "transportation"],
    ttps: ["T1078 Valid Accounts", "T1059 Command and Scripting Interpreter", "T1218 System Binary Proxy Execution", "T1003 OS Credential Dumping", "T1090 Proxy"],
    activeSince: 2021,
    notableCampaigns: ["US critical infrastructure pre-positioning 2023", "Guam military base targeting", "SOHO router botnet (KV-Botnet) 2024", "Telecom infrastructure compromise 2024"]
  },
  {
    name: "Salt Typhoon",
    aliases: ["GhostEmperor", "FamousSparrow", "UNC2286"],
    origin: "China",
    type: "nation-state",
    targets: ["telecommunications", "ISPs", "government", "technology"],
    ttps: ["T1190 Exploit Public-Facing Application", "T1059 Command and Scripting Interpreter", "T1005 Data from Local System", "T1071 Application Layer Protocol", "T1048 Exfiltration Over Alternative Protocol"],
    activeSince: 2019,
    notableCampaigns: ["US telecom provider compromise 2024 (AT&T, Verizon, T-Mobile)", "Wiretap system access", "Metadata collection operations"]
  },
  {
    name: "APT3",
    aliases: ["Gothic Panda", "Buckeye", "UPS Team", "TG-0110"],
    origin: "China",
    type: "nation-state",
    targets: ["aerospace", "defense", "technology", "telecommunications", "transportation"],
    ttps: ["T1190 Exploit Public-Facing Application", "T1059 Command and Scripting Interpreter", "T1003 OS Credential Dumping", "T1055 Process Injection", "T1071 Application Layer Protocol"],
    activeSince: 2007,
    notableCampaigns: ["Operation Clandestine Fox 2014", "Operation Double Tap 2014", "Pirpi RAT campaigns"]
  },
  {
    name: "Mustang Panda",
    aliases: ["Bronze President", "TA416", "RedDelta", "Stately Taurus"],
    origin: "China",
    type: "nation-state",
    targets: ["government", "NGOs", "religious organizations", "telecommunications"],
    ttps: ["T1566 Phishing", "T1059 Command and Scripting Interpreter", "T1547 Boot or Logon Autostart Execution", "T1105 Ingress Tool Transfer", "T1071 Application Layer Protocol"],
    activeSince: 2014,
    notableCampaigns: ["Southeast Asian government targeting", "European diplomatic missions 2022", "PlugX USB spreading campaign 2023"]
  },
  {
    name: "APT31",
    aliases: ["Zirconium", "Judgment Panda", "Violet Typhoon"],
    origin: "China",
    type: "nation-state",
    targets: ["government", "finance", "aerospace", "defense", "technology"],
    ttps: ["T1566 Phishing", "T1059 Command and Scripting Interpreter", "T1090 Proxy", "T1071 Application Layer Protocol", "T1005 Data from Local System"],
    activeSince: 2010,
    notableCampaigns: ["Finnish parliament attack 2020", "Norwegian parliament attack 2021", "US DOJ indictment 2024 for widespread espionage"]
  },

  // --- Nation-State: North Korea ---
  {
    name: "Lazarus Group",
    aliases: ["HIDDEN COBRA", "Labyrinth Chollima", "ZINC", "Diamond Sleet", "APT38"],
    origin: "North Korea",
    type: "nation-state",
    targets: ["financial", "cryptocurrency", "defense", "entertainment", "technology"],
    ttps: ["T1566 Phishing", "T1059 Command and Scripting Interpreter", "T1055 Process Injection", "T1027 Obfuscated Files", "T1486 Data Encrypted for Impact"],
    activeSince: 2009,
    notableCampaigns: ["Sony Pictures hack 2014", "Bangladesh Bank heist 2016", "WannaCry ransomware 2017", "Ronin Network $620M theft 2022", "3CX supply chain attack 2023"]
  },
  {
    name: "Kimsuky",
    aliases: ["Velvet Chollima", "THALLIUM", "Emerald Sleet", "Black Banshee", "APT43"],
    origin: "North Korea",
    type: "nation-state",
    targets: ["government", "think tanks", "academia", "nuclear", "media"],
    ttps: ["T1566 Phishing", "T1059 Command and Scripting Interpreter", "T1114 Email Collection", "T1056 Input Capture", "T1078 Valid Accounts"],
    activeSince: 2012,
    notableCampaigns: ["KHNP nuclear plant attack 2014", "AppleSeed backdoor campaigns", "ReconShark malware 2023", "Social engineering of NK policy experts"]
  },
  {
    name: "Andariel",
    aliases: ["Silent Chollima", "Stonefly", "Onyx Sleet", "DarkSeoul"],
    origin: "North Korea",
    type: "nation-state",
    targets: ["defense", "aerospace", "nuclear", "engineering", "healthcare"],
    ttps: ["T1190 Exploit Public-Facing Application", "T1059 Command and Scripting Interpreter", "T1486 Data Encrypted for Impact", "T1003 OS Credential Dumping", "T1071 Application Layer Protocol"],
    activeSince: 2009,
    notableCampaigns: ["DarkSeoul attacks 2013", "Defense sector espionage", "Maui ransomware healthcare targeting 2022", "EarlyRat malware 2023"]
  },
  {
    name: "BlueNoroff",
    aliases: ["APT38", "Sapphire Sleet", "CryptoCore", "SnatchCrypto"],
    origin: "North Korea",
    type: "nation-state / financial",
    targets: ["banks", "cryptocurrency", "venture capital", "DeFi platforms", "fintech"],
    ttps: ["T1566 Phishing", "T1059 Command and Scripting Interpreter", "T1204 User Execution", "T1071 Application Layer Protocol", "T1027 Obfuscated Files"],
    activeSince: 2014,
    notableCampaigns: ["SWIFT banking attacks 2016-2018", "AppleJeus cryptocurrency campaigns", "DangerousPassword campaign 2023", "RustBucket macOS malware 2023"]
  },
  {
    name: "ScarCruft",
    aliases: ["APT37", "Reaper", "Group123", "Ricochet Chollima", "Ruby Sleet"],
    origin: "North Korea",
    type: "nation-state",
    targets: ["government", "military", "media", "defectors", "human rights"],
    ttps: ["T1566 Phishing", "T1059 Command and Scripting Interpreter", "T1203 Exploitation for Client Execution", "T1056 Input Capture", "T1113 Screen Capture"],
    activeSince: 2012,
    notableCampaigns: ["Operation Daybreak 2016", "Operation Erebus 2017", "RokRAT campaigns", "M2RAT malware 2023"]
  },

  // --- Nation-State: Iran ---
  {
    name: "APT33",
    aliases: ["Elfin", "Refined Kitten", "Magnallium", "Peach Sandstorm", "Holmium"],
    origin: "Iran",
    type: "nation-state",
    targets: ["aerospace", "defense", "petrochemical", "energy", "government"],
    ttps: ["T1566 Phishing", "T1059 Command and Scripting Interpreter", "T1003 OS Credential Dumping", "T1110 Brute Force", "T1078 Valid Accounts"],
    activeSince: 2013,
    notableCampaigns: ["Shamoon-related activity", "Aerospace and energy sector targeting", "Password spray campaigns against defense sector 2023"]
  },
  {
    name: "APT34",
    aliases: ["OilRig", "Helix Kitten", "EUROPIUM", "Hazel Sandstorm", "Crambus"],
    origin: "Iran",
    type: "nation-state",
    targets: ["government", "financial", "energy", "telecommunications", "chemical"],
    ttps: ["T1566 Phishing", "T1059 Command and Scripting Interpreter", "T1003 OS Credential Dumping", "T1071 Application Layer Protocol", "T1053 Scheduled Task"],
    activeSince: 2014,
    notableCampaigns: ["DNSpionage campaign 2018", "Karkoff campaign 2019", "SideTwist backdoor 2021", "Middle East government targeting 2023"]
  },
  {
    name: "APT35",
    aliases: ["Charming Kitten", "Phosphorus", "Mint Sandstorm", "NewsBeef", "TA453"],
    origin: "Iran",
    type: "nation-state",
    targets: ["government", "defense", "academia", "media", "dissidents"],
    ttps: ["T1566 Phishing", "T1078 Valid Accounts", "T1059 Command and Scripting Interpreter", "T1071 Application Layer Protocol", "T1056 Input Capture"],
    activeSince: 2014,
    notableCampaigns: ["HBO data breach 2017", "US presidential campaign targeting 2019", "HYPERSCRAPE email tool 2022", "MediaPl backdoor 2024"]
  },
  {
    name: "MuddyWater",
    aliases: ["MERCURY", "Mango Sandstorm", "Static Kitten", "Seedworm", "TEMP.Zagros"],
    origin: "Iran",
    type: "nation-state",
    targets: ["government", "telecommunications", "energy", "defense", "education"],
    ttps: ["T1566 Phishing", "T1059 Command and Scripting Interpreter", "T1218 System Binary Proxy Execution", "T1053 Scheduled Task", "T1105 Ingress Tool Transfer"],
    activeSince: 2017,
    notableCampaigns: ["Middle East government targeting", "PhonyC2 framework 2023", "DarkBeatC2 framework 2024", "Atera RMM abuse campaigns"]
  },
  {
    name: "Agrius",
    aliases: ["DEV-0227", "Pink Sandstorm", "Americium"],
    origin: "Iran",
    type: "nation-state",
    targets: ["Israel", "diamond industry", "technology", "education", "aerospace"],
    ttps: ["T1486 Data Encrypted for Impact", "T1485 Data Destruction", "T1059 Command and Scripting Interpreter", "T1078 Valid Accounts", "T1190 Exploit Public-Facing Application"],
    activeSince: 2020,
    notableCampaigns: ["Apostle wiper/ransomware 2021", "Fantasy wiper 2022", "Israeli targets attacks", "Diamond industry supply chain targeting"]
  },
  {
    name: "CyberAv3ngers",
    aliases: ["IRGC-CEC"],
    origin: "Iran",
    type: "nation-state",
    targets: ["water", "energy", "critical infrastructure", "ICS/SCADA"],
    ttps: ["T1190 Exploit Public-Facing Application", "T1078 Valid Accounts", "T1059 Command and Scripting Interpreter", "T1485 Data Destruction"],
    activeSince: 2020,
    notableCampaigns: ["Unitronics PLC attacks on US water systems 2023", "IRGC-linked ICS targeting"]
  },

  // --- Nation-State: Others ---
  {
    name: "Equation Group",
    aliases: ["EQGRP", "Tilded Team"],
    origin: "United States (attributed)",
    type: "nation-state",
    targets: ["government", "military", "telecommunications", "energy", "research"],
    ttps: ["T1195 Supply Chain Compromise", "T1542 Pre-OS Boot", "T1027 Obfuscated Files", "T1059 Command and Scripting Interpreter", "T1055 Process Injection"],
    activeSince: 2001,
    notableCampaigns: ["Stuxnet (attributed)", "Flame malware", "DoubleFantasy / GrayFish implants", "Shadow Brokers leak 2016-2017"]
  },
  {
    name: "DarkHotel",
    aliases: ["DUBNIUM", "Fallout Team", "Luder", "Shadow Crane"],
    origin: "South Korea (attributed)",
    type: "nation-state",
    targets: ["government", "defense", "technology", "automotive", "chemical"],
    ttps: ["T1566 Phishing", "T1189 Drive-by Compromise", "T1059 Command and Scripting Interpreter", "T1056 Input Capture", "T1113 Screen Capture"],
    activeSince: 2007,
    notableCampaigns: ["Hotel Wi-Fi targeting of executives 2014", "Zero-day exploitation campaigns", "IE and Firefox zero-day chains 2020"]
  },
  {
    name: "Patchwork",
    aliases: ["Dropping Elephant", "Chinastrats", "QUILTED TIGER", "Monsoon"],
    origin: "India (attributed)",
    type: "nation-state",
    targets: ["government", "diplomatic", "defense", "think tanks", "academia"],
    ttps: ["T1566 Phishing", "T1203 Exploitation for Client Execution", "T1059 Command and Scripting Interpreter", "T1105 Ingress Tool Transfer", "T1071 Application Layer Protocol"],
    activeSince: 2015,
    notableCampaigns: ["Pakistan military targeting", "BADNEWS RAT campaigns", "Self-infection revealing Ragnatela RAT 2022"]
  },
  {
    name: "Ocean Lotus",
    aliases: ["APT32", "Canvas Cyclone", "SeaLotus", "OceanBuffalo"],
    origin: "Vietnam",
    type: "nation-state",
    targets: ["government", "media", "manufacturing", "human rights", "hospitality"],
    ttps: ["T1566 Phishing", "T1059 Command and Scripting Interpreter", "T1189 Drive-by Compromise", "T1027 Obfuscated Files", "T1055 Process Injection"],
    activeSince: 2012,
    notableCampaigns: ["ASEAN targeting", "Automotive sector espionage", "COVID-19 themed phishing 2020", "Vietnamese dissident targeting"]
  },

  // --- Cybercrime: Ransomware ---
  {
    name: "LockBit",
    aliases: ["LockBit 3.0", "LockBit Black", "LockBit Green"],
    origin: "Russia (attributed)",
    type: "cybercrime / ransomware",
    targets: ["all sectors", "healthcare", "government", "manufacturing", "financial"],
    ttps: ["T1486 Data Encrypted for Impact", "T1078 Valid Accounts", "T1059 Command and Scripting Interpreter", "T1003 OS Credential Dumping", "T1021 Remote Services"],
    activeSince: 2019,
    notableCampaigns: ["Most prolific ransomware group 2022-2023", "Royal Mail UK attack 2023", "Boeing breach 2023", "Operation Cronos takedown 2024"]
  },
  {
    name: "BlackCat",
    aliases: ["ALPHV", "Noberus", "Sphynx"],
    origin: "Russia (attributed)",
    type: "cybercrime / ransomware",
    targets: ["healthcare", "technology", "government", "financial", "legal"],
    ttps: ["T1486 Data Encrypted for Impact", "T1078 Valid Accounts", "T1059 Command and Scripting Interpreter", "T1021 Remote Services", "T1490 Inhibit System Recovery"],
    activeSince: 2021,
    notableCampaigns: ["First Rust-based ransomware", "Reddit breach 2023", "Change Healthcare attack 2024", "MGM Resorts attack 2023"]
  },
  {
    name: "Cl0p",
    aliases: ["TA505", "FIN11", "Lace Tempest"],
    origin: "Russia (attributed)",
    type: "cybercrime / ransomware",
    targets: ["technology", "financial", "healthcare", "government", "education"],
    ttps: ["T1190 Exploit Public-Facing Application", "T1486 Data Encrypted for Impact", "T1059 Command and Scripting Interpreter", "T1005 Data from Local System", "T1567 Exfiltration Over Web Service"],
    activeSince: 2019,
    notableCampaigns: ["Accellion FTA exploitation 2021", "GoAnywhere MFT mass exploitation 2023", "MOVEit Transfer mass exploitation 2023"]
  },
  {
    name: "Conti",
    aliases: ["Wizard Spider", "GOLD ULRICK", "DEV-0193"],
    origin: "Russia",
    type: "cybercrime / ransomware",
    targets: ["healthcare", "government", "manufacturing", "technology", "education"],
    ttps: ["T1486 Data Encrypted for Impact", "T1059 Command and Scripting Interpreter", "T1021 Remote Services", "T1003 OS Credential Dumping", "T1562 Impair Defenses"],
    activeSince: 2020,
    notableCampaigns: ["HSE Ireland attack 2021", "Costa Rica government attack 2022", "Conti leaks 2022", "Rebranded into multiple groups post-dissolution"]
  },
  {
    name: "REvil",
    aliases: ["Sodinokibi", "GOLD SOUTHFIELD", "PINCHY SPIDER"],
    origin: "Russia",
    type: "cybercrime / ransomware",
    targets: ["technology", "legal", "insurance", "manufacturing", "food"],
    ttps: ["T1486 Data Encrypted for Impact", "T1195 Supply Chain Compromise", "T1078 Valid Accounts", "T1059 Command and Scripting Interpreter", "T1041 Exfiltration Over C2 Channel"],
    activeSince: 2019,
    notableCampaigns: ["Kaseya VSA supply chain attack 2021", "JBS Foods attack 2021", "Acer $50M ransom demand 2021", "FSB arrests 2022"]
  },
  {
    name: "Black Basta",
    aliases: ["Storm-1811"],
    origin: "Russia (attributed)",
    type: "cybercrime / ransomware",
    targets: ["manufacturing", "construction", "technology", "healthcare", "financial"],
    ttps: ["T1486 Data Encrypted for Impact", "T1566 Phishing", "T1059 Command and Scripting Interpreter", "T1021 Remote Services", "T1003 OS Credential Dumping"],
    activeSince: 2022,
    notableCampaigns: ["Ex-Conti members regrouping", "500+ victims by 2024", "Ascension Health attack 2024", "Chat logs leaked 2025"]
  },
  {
    name: "Royal",
    aliases: ["DEV-0569", "Storm-0569"],
    origin: "Russia (attributed)",
    type: "cybercrime / ransomware",
    targets: ["healthcare", "education", "manufacturing", "government", "technology"],
    ttps: ["T1486 Data Encrypted for Impact", "T1566 Phishing", "T1059 Command and Scripting Interpreter", "T1078 Valid Accounts", "T1490 Inhibit System Recovery"],
    activeSince: 2022,
    notableCampaigns: ["City of Dallas attack 2023", "Rebranded to BlackSuit 2023", "Multi-million dollar ransom demands"]
  },
  {
    name: "Play",
    aliases: ["PlayCrypt", "Balloonfly"],
    origin: "Unknown",
    type: "cybercrime / ransomware",
    targets: ["government", "technology", "telecommunications", "manufacturing", "financial"],
    ttps: ["T1486 Data Encrypted for Impact", "T1190 Exploit Public-Facing Application", "T1078 Valid Accounts", "T1059 Command and Scripting Interpreter", "T1003 OS Credential Dumping"],
    activeSince: 2022,
    notableCampaigns: ["City of Oakland attack 2023", "ProxyNotShell exploitation", "Rackspace attack 2022"]
  },
  {
    name: "Akira",
    aliases: ["Storm-1567"],
    origin: "Unknown",
    type: "cybercrime / ransomware",
    targets: ["education", "healthcare", "manufacturing", "technology", "financial"],
    ttps: ["T1486 Data Encrypted for Impact", "T1078 Valid Accounts", "T1133 External Remote Services", "T1059 Command and Scripting Interpreter", "T1490 Inhibit System Recovery"],
    activeSince: 2023,
    notableCampaigns: ["VPN exploitation campaigns", "Cisco VPN zero-day abuse", "Stanford University attack 2023", "250+ victims by 2024"]
  },
  {
    name: "Rhysida",
    aliases: ["Vice Society successor"],
    origin: "Unknown",
    type: "cybercrime / ransomware",
    targets: ["healthcare", "education", "government", "manufacturing", "technology"],
    ttps: ["T1486 Data Encrypted for Impact", "T1566 Phishing", "T1059 Command and Scripting Interpreter", "T1078 Valid Accounts", "T1490 Inhibit System Recovery"],
    activeSince: 2023,
    notableCampaigns: ["British Library attack 2023", "Chilean Army data breach 2023", "Healthcare sector targeting", "Insomniac Games breach 2023"]
  },

  // --- Cybercrime: Other ---
  {
    name: "Lapsus$",
    aliases: ["DEV-0537", "Strawberry Tempest"],
    origin: "United Kingdom / Brazil",
    type: "cybercrime / extortion",
    targets: ["technology", "gaming", "telecommunications", "government", "healthcare"],
    ttps: ["T1078 Valid Accounts", "T1199 Trusted Relationship", "T1566 Phishing", "T1621 Multi-Factor Authentication Request Generation", "T1530 Data from Cloud Storage Object"],
    activeSince: 2021,
    notableCampaigns: ["NVIDIA breach 2022", "Samsung source code leak 2022", "Microsoft source code access 2022", "Uber breach 2022", "Okta breach 2022"]
  },
  {
    name: "FIN7",
    aliases: ["Carbon Spider", "GOLD NIAGARA", "Sangria Tempest", "Carbanak"],
    origin: "Russia (attributed)",
    type: "cybercrime / financial",
    targets: ["retail", "hospitality", "financial", "technology", "food service"],
    ttps: ["T1566 Phishing", "T1059 Command and Scripting Interpreter", "T1055 Process Injection", "T1071 Application Layer Protocol", "T1005 Data from Local System"],
    activeSince: 2013,
    notableCampaigns: ["Carbanak banking attacks", "Point-of-sale malware campaigns", "Fake security company Combi Security", "POWERTRASH loader 2023"]
  },
  {
    name: "FIN8",
    aliases: ["Syssphinx", "White Rabbit"],
    origin: "Unknown",
    type: "cybercrime / financial",
    targets: ["retail", "hospitality", "financial", "insurance", "technology"],
    ttps: ["T1566 Phishing", "T1059 Command and Scripting Interpreter", "T1055 Process Injection", "T1005 Data from Local System", "T1486 Data Encrypted for Impact"],
    activeSince: 2016,
    notableCampaigns: ["Sardonic backdoor campaigns", "White Rabbit ransomware deployment", "POS malware campaigns"]
  },
  {
    name: "Scattered Spider",
    aliases: ["Octo Tempest", "Star Fraud", "UNC3944", "Muddled Libra", "0ktapus"],
    origin: "United States / United Kingdom",
    type: "cybercrime / extortion",
    targets: ["telecommunications", "technology", "financial", "gaming", "hospitality"],
    ttps: ["T1566 Phishing", "T1621 Multi-Factor Authentication Request Generation", "T1078 Valid Accounts", "T1199 Trusted Relationship", "T1530 Data from Cloud Storage Object"],
    activeSince: 2022,
    notableCampaigns: ["Twilio breach 2022", "130+ organizations in 0ktapus campaign", "MGM Resorts attack 2023", "Caesars Entertainment attack 2023"]
  },
  {
    name: "Magecart",
    aliases: ["Multiple subgroups", "Web skimming collective"],
    origin: "Various",
    type: "cybercrime / financial",
    targets: ["e-commerce", "retail", "hospitality", "ticketing", "payment processors"],
    ttps: ["T1059 Command and Scripting Interpreter", "T1189 Drive-by Compromise", "T1195 Supply Chain Compromise", "T1185 Browser Session Hijacking", "T1005 Data from Local System"],
    activeSince: 2015,
    notableCampaigns: ["British Airways breach 2018", "Ticketmaster breach 2018", "Hundreds of thousands of compromised stores", "Kritec skimmer 2023"]
  },
  {
    name: "Vice Society",
    aliases: ["DEV-0832", "Vanilla Tempest"],
    origin: "Russia (attributed)",
    type: "cybercrime / ransomware",
    targets: ["education", "healthcare", "government", "manufacturing"],
    ttps: ["T1486 Data Encrypted for Impact", "T1078 Valid Accounts", "T1059 Command and Scripting Interpreter", "T1021 Remote Services", "T1490 Inhibit System Recovery"],
    activeSince: 2021,
    notableCampaigns: ["LAUSD attack 2022", "UK school targeting", "Healthcare data exfiltration", "Rebranded to Rhysida"]
  },
  {
    name: "BianLian",
    aliases: ["Storm-0764"],
    origin: "Unknown",
    type: "cybercrime / ransomware",
    targets: ["healthcare", "financial", "manufacturing", "professional services", "education"],
    ttps: ["T1078 Valid Accounts", "T1059 Command and Scripting Interpreter", "T1021 Remote Services", "T1005 Data from Local System", "T1567 Exfiltration Over Web Service"],
    activeSince: 2022,
    notableCampaigns: ["Shifted to pure data exfiltration 2023", "Healthcare targeting", "Save the Children breach 2023"]
  },

  // --- Hacktivism ---
  {
    name: "Anonymous Sudan",
    aliases: ["Storm-1359"],
    origin: "Sudan (disputed, possible Russian ties)",
    type: "hacktivist / DDoS",
    targets: ["government", "technology", "healthcare", "financial", "airlines"],
    ttps: ["T1498 Network Denial of Service", "T1499 Endpoint Denial of Service"],
    activeSince: 2023,
    notableCampaigns: ["Microsoft Azure DDoS 2023", "Scandinavian Airlines attacks", "US hospital DDoS 2023", "FBI takedown 2024"]
  },
  {
    name: "KillNet",
    aliases: ["Killnet"],
    origin: "Russia",
    type: "hacktivist / DDoS",
    targets: ["government", "critical infrastructure", "healthcare", "financial", "aviation"],
    ttps: ["T1498 Network Denial of Service", "T1499 Endpoint Denial of Service", "T1078 Valid Accounts"],
    activeSince: 2022,
    notableCampaigns: ["US airport website DDoS 2022", "European government targeting", "NATO country attacks", "Rebranded to BlackSkills 2024"]
  },
  {
    name: "NoName057(16)",
    aliases: ["NoName"],
    origin: "Russia",
    type: "hacktivist / DDoS",
    targets: ["government", "financial", "transportation", "media"],
    ttps: ["T1498 Network Denial of Service", "T1499 Endpoint Denial of Service"],
    activeSince: 2022,
    notableCampaigns: ["DDoSia crowdsourced DDoS tool", "European government targeting", "Ukrainian infrastructure attacks"]
  },
  {
    name: "IT Army of Ukraine",
    aliases: ["IT Army"],
    origin: "Ukraine",
    type: "hacktivist",
    targets: ["Russian government", "Russian financial", "Russian media", "Russian infrastructure"],
    ttps: ["T1498 Network Denial of Service", "T1499 Endpoint Denial of Service", "T1190 Exploit Public-Facing Application"],
    activeSince: 2022,
    notableCampaigns: ["Russian government website DDoS", "Russian banking disruptions", "Coordinated volunteer cyber operations"]
  },
  {
    name: "GhostSec",
    aliases: ["Ghost Security"],
    origin: "Various",
    type: "hacktivist",
    targets: ["government", "critical infrastructure", "ICS/SCADA"],
    ttps: ["T1190 Exploit Public-Facing Application", "T1498 Network Denial of Service", "T1059 Command and Scripting Interpreter"],
    activeSince: 2015,
    notableCampaigns: ["Anti-ISIS operations (original)", "Israeli ICS targeting 2023", "Collaboration with Stormous ransomware"]
  }
];


// -----------------------------------------------------------------------------
// 2. MITRE ATT&CK MATRIX -- All 14 tactics with top techniques
// -----------------------------------------------------------------------------

export const MITRE_ATTACK = [
  {
    tactic: "Reconnaissance",
    id: "TA0043",
    techniques: [
      {
        id: "T1595",
        name: "Active Scanning",
        description: "Adversaries scan victim IP blocks to gather information for targeting. This includes vulnerability scanning, port scanning, and banner grabbing to identify services and potential entry points.",
        detection: "Monitor for suspicious network scanning activity from external sources. Analyze firewall and IDS logs for sequential port probes or high-volume connection attempts.",
        platforms: ["PRE"]
      },
      {
        id: "T1592",
        name: "Gather Victim Host Information",
        description: "Adversaries gather information about victim hosts including hardware, software, configurations, and patch levels to inform targeting and exploit selection.",
        detection: "Monitor for anomalous access to system information pages. Track unusual user-agent strings or automated enumeration behavior.",
        platforms: ["PRE"]
      },
      {
        id: "T1589",
        name: "Gather Victim Identity Information",
        description: "Adversaries collect victim identity data such as credentials, email addresses, and employee names through social media, data breaches, or OSINT to support social engineering and credential attacks.",
        detection: "Monitor for credential stuffing attempts. Track exposure of organizational data in paste sites and breach databases.",
        platforms: ["PRE"]
      },
      {
        id: "T1590",
        name: "Gather Victim Network Information",
        description: "Adversaries collect network topology, IP ranges, DNS records, and domain registration data to map the target environment before launching attacks.",
        detection: "Monitor DNS query logs for zone transfer attempts. Track WHOIS lookups and certificate transparency log queries.",
        platforms: ["PRE"]
      },
      {
        id: "T1591",
        name: "Gather Victim Org Information",
        description: "Adversaries collect information about victim organizations including business relationships, org structure, and physical locations to enable further targeting.",
        detection: "Difficult to detect directly. Monitor for scraping of corporate websites and social media reconnaissance.",
        platforms: ["PRE"]
      },
      {
        id: "T1598",
        name: "Phishing for Information",
        description: "Adversaries send phishing messages to gather actionable information such as credentials or system details rather than to deliver malware directly.",
        detection: "Monitor email for messages containing links to credential harvesting pages. Analyze email headers for spoofed sender domains.",
        platforms: ["PRE"]
      },
      {
        id: "T1597",
        name: "Search Closed Sources",
        description: "Adversaries search closed or private sources such as threat intelligence feeds, dark web forums, and paid databases for information about the victim.",
        detection: "Largely undetectable from victim's perspective. Monitor for leaked data on dark web markets.",
        platforms: ["PRE"]
      },
      {
        id: "T1596",
        name: "Search Open Technical Databases",
        description: "Adversaries search public technical databases like Shodan, Censys, and certificate transparency logs to discover exposed assets and services.",
        detection: "Monitor for connections from known scanning service IP ranges. Track unusual certificate transparency log queries.",
        platforms: ["PRE"]
      },
      {
        id: "T1593",
        name: "Search Open Websites/Domains",
        description: "Adversaries search publicly accessible websites and domains for information about victims including social media, job postings, and company websites.",
        detection: "Monitor for automated scraping of organizational web properties. Track suspicious access patterns to career pages.",
        platforms: ["PRE"]
      },
      {
        id: "T1594",
        name: "Search Victim-Owned Websites",
        description: "Adversaries search victim-owned websites to gather information for targeting, including employee directories, technology stacks, and organizational structure.",
        detection: "Monitor web server logs for enumeration patterns and crawler activity from suspicious IPs.",
        platforms: ["PRE"]
      }
    ]
  },
  {
    tactic: "Resource Development",
    id: "TA0042",
    techniques: [
      {
        id: "T1583",
        name: "Acquire Infrastructure",
        description: "Adversaries purchase or rent infrastructure including domains, servers, and cloud services for use in targeting. This may include VPS providers, bulletproof hosting, and domain registrars.",
        detection: "Monitor for newly registered domains that typosquat organizational domains. Track certificate issuance for suspicious domains.",
        platforms: ["PRE"]
      },
      {
        id: "T1586",
        name: "Compromise Accounts",
        description: "Adversaries compromise existing accounts with services to support operations including social media, email, and cloud service accounts.",
        detection: "Monitor for account takeover indicators. Track unusual login patterns on organizational accounts.",
        platforms: ["PRE"]
      },
      {
        id: "T1584",
        name: "Compromise Infrastructure",
        description: "Adversaries compromise third-party infrastructure to support operations, including web servers for hosting malware, C2, or phishing pages.",
        detection: "Monitor for compromised legitimate websites serving malicious content. Track infrastructure changes in known-good domains.",
        platforms: ["PRE"]
      },
      {
        id: "T1587",
        name: "Develop Capabilities",
        description: "Adversaries build custom malware, exploits, and tools rather than purchasing or stealing them, including custom packers, loaders, and C2 frameworks.",
        detection: "Analyze malware samples for unique signatures. Track malware family evolution through threat intelligence.",
        platforms: ["PRE"]
      },
      {
        id: "T1585",
        name: "Establish Accounts",
        description: "Adversaries create accounts on various services to support operations including email providers, social media platforms, and code repositories.",
        detection: "Monitor for fake accounts impersonating organizational personnel. Track suspicious account creation patterns.",
        platforms: ["PRE"]
      },
      {
        id: "T1588",
        name: "Obtain Capabilities",
        description: "Adversaries purchase or download tools, malware, exploits, and digital certificates for use in operations from underground markets or public repositories.",
        detection: "Monitor for use of known offensive tools. Track purchases on underground forums through threat intelligence.",
        platforms: ["PRE"]
      },
      {
        id: "T1608",
        name: "Stage Capabilities",
        description: "Adversaries upload malware, tools, or exploits to staging infrastructure to make them available during an operation, including drive-by download sites and C2 servers.",
        detection: "Monitor for known malware hosted on new infrastructure. Scan for suspicious file uploads to cloud storage.",
        platforms: ["PRE"]
      }
    ]
  },
  {
    tactic: "Initial Access",
    id: "TA0001",
    techniques: [
      {
        id: "T1189",
        name: "Drive-by Compromise",
        description: "Adversaries gain access through users visiting compromised websites during normal browsing. The website exploits browser or plugin vulnerabilities to install malware without user interaction beyond visiting the page.",
        detection: "Monitor browser process creation for unexpected child processes. Implement browser isolation and keep browsers patched. Analyze web proxy logs for known exploit kit patterns.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1190",
        name: "Exploit Public-Facing Application",
        description: "Adversaries exploit vulnerabilities in internet-facing applications such as web servers, VPN appliances, firewalls, and mail servers to gain initial access to the network.",
        detection: "Monitor application logs for exploitation attempts. Implement WAF rules. Conduct regular vulnerability scanning of exposed services. Track CVE exploitation in the wild.",
        platforms: ["Windows", "Linux", "macOS", "Network", "Containers"]
      },
      {
        id: "T1133",
        name: "External Remote Services",
        description: "Adversaries leverage external-facing remote services like VPNs, Citrix, RDP, and SSH to gain initial access using legitimate credentials obtained through other means.",
        detection: "Monitor remote access logs for unusual login times, locations, or failed attempts. Enforce MFA on all remote access services. Track concurrent sessions from different geographies.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1200",
        name: "Hardware Additions",
        description: "Adversaries introduce malicious hardware components such as USB devices, network implants, or rogue wireless access points to gain access to networks.",
        detection: "Monitor for new USB device connections. Implement port security on network switches. Conduct regular physical security assessments. Use endpoint device control policies.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1566",
        name: "Phishing",
        description: "Adversaries send phishing messages with malicious attachments or links to gain access to victim systems. Spearphishing targets specific individuals or organizations with customized lures.",
        detection: "Implement email filtering and sandboxing. Monitor for suspicious email attachments and URLs. Train users on phishing identification. Analyze email headers for spoofing indicators.",
        platforms: ["Windows", "Linux", "macOS", "SaaS", "Office 365", "Google Workspace"]
      },
      {
        id: "T1091",
        name: "Replication Through Removable Media",
        description: "Adversaries move onto systems by copying malware to removable media and leveraging autorun features or social engineering to gain execution when the media is connected.",
        detection: "Disable autorun/autoplay. Monitor for executable files on removable media. Implement device control policies restricting USB usage.",
        platforms: ["Windows"]
      },
      {
        id: "T1195",
        name: "Supply Chain Compromise",
        description: "Adversaries compromise the supply chain of software or hardware to insert malicious code before delivery to end users, affecting all downstream customers of the compromised vendor.",
        detection: "Verify software integrity through code signing and checksums. Monitor for unexpected changes in vendor software. Implement software composition analysis for dependencies.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1199",
        name: "Trusted Relationship",
        description: "Adversaries abuse trusted relationships with third-party organizations that have access to the target environment, such as MSPs, IT vendors, or partner organizations.",
        detection: "Monitor third-party access patterns. Implement least-privilege access for vendor accounts. Review and audit trusted relationship access regularly.",
        platforms: ["Windows", "Linux", "macOS", "SaaS", "IaaS"]
      },
      {
        id: "T1078",
        name: "Valid Accounts",
        description: "Adversaries use legitimate credentials to gain initial access, persist, escalate privileges, or evade detection. Credentials may be obtained through credential dumping, phishing, or purchasing from brokers.",
        detection: "Monitor for anomalous account usage patterns. Implement impossible travel detection. Track service account usage. Enable MFA across all access points.",
        platforms: ["Windows", "Linux", "macOS", "SaaS", "IaaS", "Azure AD", "Office 365", "Google Workspace"]
      }
    ]
  },
  {
    tactic: "Execution",
    id: "TA0002",
    techniques: [
      {
        id: "T1059",
        name: "Command and Scripting Interpreter",
        description: "Adversaries abuse command and script interpreters (PowerShell, cmd, Bash, Python, JavaScript, VBScript) to execute commands, scripts, and binaries on victim systems.",
        detection: "Enable PowerShell script block logging and module logging. Monitor process creation for scripting engines. Implement application whitelisting. Log command-line arguments.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1609",
        name: "Container Administration Command",
        description: "Adversaries abuse container administration tools such as kubectl or docker exec to execute commands within containers in a compromised environment.",
        detection: "Monitor container runtime logs for exec commands. Implement RBAC for container orchestration. Track kubectl audit logs.",
        platforms: ["Containers"]
      },
      {
        id: "T1610",
        name: "Deploy Container",
        description: "Adversaries deploy malicious containers within a victim environment to execute malicious code, establish persistence, or move laterally within container orchestration systems.",
        detection: "Monitor for unexpected container deployments. Implement image scanning and admission controllers. Track container registry pulls.",
        platforms: ["Containers"]
      },
      {
        id: "T1203",
        name: "Exploitation for Client Execution",
        description: "Adversaries exploit vulnerabilities in client applications such as browsers, Office suite, PDF readers, and media players to execute malicious code on the victim system.",
        detection: "Monitor for abnormal process creation from client applications. Keep client software patched. Implement exploit protection mechanisms.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1559",
        name: "Inter-Process Communication",
        description: "Adversaries abuse inter-process communication mechanisms such as COM, DDE, and XPC to execute arbitrary commands, often bypassing security controls.",
        detection: "Monitor for unusual DDE/COM object creation. Track inter-process communication events. Disable DDE in Office applications if not needed.",
        platforms: ["Windows", "macOS"]
      },
      {
        id: "T1106",
        name: "Native API",
        description: "Adversaries interact directly with native OS APIs to execute behaviors, bypassing higher-level monitoring of command interpreters and scripting engines.",
        detection: "Monitor API calls through ETW or syscall tracing. Track unusual sequences of API calls. Implement behavioral detection for common API abuse patterns.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1053",
        name: "Scheduled Task/Job",
        description: "Adversaries abuse task scheduling functionality (Windows Task Scheduler, cron, at, systemd timers) to execute malicious code at system startup or on a scheduled basis.",
        detection: "Monitor for new scheduled task creation. Audit existing scheduled tasks regularly. Track changes to cron files and systemd timers.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1129",
        name: "Shared Modules",
        description: "Adversaries execute malicious payloads via loading shared modules (DLLs, shared objects) into processes, potentially using legitimate applications to load malicious libraries.",
        detection: "Monitor DLL loading events for unsigned or unexpected modules. Implement DLL search order hardening. Track shared library loading on Linux/macOS.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1072",
        name: "Software Deployment Tools",
        description: "Adversaries abuse trusted software deployment tools (SCCM, Ansible, Puppet, Chef) to execute malicious code across many systems simultaneously.",
        detection: "Monitor software deployment tool logs for unauthorized deployments. Restrict access to deployment infrastructure. Track unusual package deployments.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1569",
        name: "System Services",
        description: "Adversaries abuse system services (Windows Service Control Manager, systemd, launchd) to execute malicious payloads as part of system service operations.",
        detection: "Monitor service creation and modification events. Track service binary paths for changes. Implement service integrity monitoring.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1204",
        name: "User Execution",
        description: "Adversaries rely on user interaction to execute malicious payloads, such as opening a malicious attachment, clicking a link, or running a program disguised as legitimate software.",
        detection: "Train users to recognize social engineering. Monitor for execution of downloaded files. Implement mark-of-the-web restrictions.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1047",
        name: "Windows Management Instrumentation",
        description: "Adversaries abuse WMI to execute commands and payloads on local and remote systems, leveraging its deep integration with Windows for lateral movement and execution.",
        detection: "Monitor WMI event subscriptions and process creation via WMI. Enable WMI activity logging. Track wmic.exe and WMI provider host activity.",
        platforms: ["Windows"]
      }
    ]
  },
  {
    tactic: "Persistence",
    id: "TA0003",
    techniques: [
      {
        id: "T1098",
        name: "Account Manipulation",
        description: "Adversaries manipulate accounts to maintain access, including modifying credentials, adding SSH keys, modifying permissions, or adding accounts to privileged groups.",
        detection: "Monitor for account modification events. Track changes to user group memberships. Alert on SSH authorized_keys modifications.",
        platforms: ["Windows", "Linux", "macOS", "Azure AD", "Office 365", "Google Workspace"]
      },
      {
        id: "T1197",
        name: "BITS Jobs",
        description: "Adversaries abuse Windows Background Intelligent Transfer Service (BITS) to download, execute, and clean up malware while evading detection through legitimate system functionality.",
        detection: "Monitor BITS job creation and execution. Track bitsadmin.exe and PowerShell BITS cmdlet usage. Analyze BITS transfer logs.",
        platforms: ["Windows"]
      },
      {
        id: "T1547",
        name: "Boot or Logon Autostart Execution",
        description: "Adversaries configure malware to execute during system boot or user logon by modifying registry run keys, startup folders, login items, or init scripts.",
        detection: "Monitor registry run key modifications. Track startup folder changes. Audit login items on macOS. Monitor systemd and init.d changes on Linux.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1176",
        name: "Browser Extensions",
        description: "Adversaries install malicious browser extensions to maintain persistence, intercept credentials, modify web pages, and surveil user browsing activity.",
        detection: "Monitor for new browser extension installations. Implement extension whitelisting. Track extension permissions and updates.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1136",
        name: "Create Account",
        description: "Adversaries create new accounts (local, domain, cloud) to maintain access independent of existing credentials that may be discovered and reset.",
        detection: "Monitor for new account creation events. Track unexpected user additions. Alert on service account creation outside change management processes.",
        platforms: ["Windows", "Linux", "macOS", "Azure AD", "Office 365", "Google Workspace"]
      },
      {
        id: "T1543",
        name: "Create or Modify System Process",
        description: "Adversaries create or modify system-level processes (Windows services, systemd services, launch daemons) to repeatedly execute malicious payloads.",
        detection: "Monitor service creation and modification events. Track changes to systemd unit files. Audit launchd plist modifications on macOS.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1546",
        name: "Event Triggered Execution",
        description: "Adversaries establish persistence by configuring malware to execute in response to specific events such as WMI subscriptions, application shimming, or accessibility features.",
        detection: "Monitor WMI event subscriptions. Track application compatibility shim installations. Audit accessibility feature binary modifications.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1574",
        name: "Hijack Execution Flow",
        description: "Adversaries hijack the way operating systems run programs by placing malicious content in locations searched before legitimate libraries (DLL search order hijacking, PATH interception).",
        detection: "Monitor for DLL loading from unusual paths. Track PATH environment variable modifications. Implement binary integrity checking.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1525",
        name: "Implant Internal Image",
        description: "Adversaries implant malicious code in cloud or container images to establish persistence that activates when new instances are launched from the compromised image.",
        detection: "Scan container and VM images for malware. Implement image signing and verification. Monitor for unauthorized image modifications.",
        platforms: ["IaaS", "Containers"]
      },
      {
        id: "T1556",
        name: "Modify Authentication Process",
        description: "Adversaries modify authentication mechanisms (password filters, PAM modules, SSP DLLs) to capture credentials or bypass authentication entirely.",
        detection: "Monitor for changes to authentication-related files and registry keys. Track PAM configuration modifications. Audit SSP DLL registrations.",
        platforms: ["Windows", "Linux", "macOS", "Azure AD"]
      },
      {
        id: "T1137",
        name: "Office Application Startup",
        description: "Adversaries leverage Office application startup features (macros, add-ins, templates) to execute malicious code when Office applications are opened.",
        detection: "Monitor Office startup locations for new files. Track macro-enabled documents. Audit Office add-in installations.",
        platforms: ["Windows", "macOS"]
      },
      {
        id: "T1542",
        name: "Pre-OS Boot",
        description: "Adversaries modify system firmware, bootloaders, or boot records (bootkits, UEFI implants) to persist below the operating system, surviving reimaging and reinstallation.",
        detection: "Enable Secure Boot. Monitor firmware integrity through TPM measurements. Implement UEFI firmware scanning.",
        platforms: ["Windows", "Linux"]
      },
      {
        id: "T1505",
        name: "Server Software Component",
        description: "Adversaries install malicious server software components (web shells, SQL stored procedures, transport agents) to maintain persistent access to server infrastructure.",
        detection: "Monitor web server directories for new or modified files. Implement file integrity monitoring. Track SQL stored procedure creation.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1205",
        name: "Traffic Signaling",
        description: "Adversaries use traffic signaling techniques (port knocking, magic packets) to open backdoor access that remains hidden until activated by specific network traffic patterns.",
        detection: "Monitor for port-knocking patterns. Analyze network traffic for unusual packet sequences. Track firewall rule changes.",
        platforms: ["Windows", "Linux", "macOS", "Network"]
      }
    ]
  },
  {
    tactic: "Privilege Escalation",
    id: "TA0004",
    techniques: [
      {
        id: "T1548",
        name: "Abuse Elevation Control Mechanism",
        description: "Adversaries bypass elevation controls such as UAC on Windows, sudo on Linux/macOS, or setuid/setgid binaries to gain elevated privileges without proper authorization.",
        detection: "Monitor for UAC bypass attempts. Track sudo usage anomalies. Audit setuid/setgid binary usage. Monitor for privilege escalation exploit indicators.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1134",
        name: "Access Token Manipulation",
        description: "Adversaries modify access tokens to operate under a different user or system security context, enabling privilege escalation through token impersonation, theft, or creation.",
        detection: "Monitor for token manipulation API calls. Track impersonation events. Audit security token creation and modification.",
        platforms: ["Windows"]
      },
      {
        id: "T1068",
        name: "Exploitation for Privilege Escalation",
        description: "Adversaries exploit software vulnerabilities in the operating system or applications to gain elevated privileges, including kernel exploits and application-level privilege escalation bugs.",
        detection: "Keep systems patched. Monitor for known exploit signatures. Implement exploit protection technologies. Track unexpected privilege changes.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1484",
        name: "Domain Policy Modification",
        description: "Adversaries modify domain-level policies (Group Policy, trust relationships) to escalate privileges across the domain or weaken security controls.",
        detection: "Monitor GPO modifications. Track domain trust changes. Audit Active Directory replication events. Alert on policy modifications outside change windows.",
        platforms: ["Windows", "Azure AD"]
      },
      {
        id: "T1611",
        name: "Escape to Host",
        description: "Adversaries break out of container or virtualization boundaries to gain access to the underlying host system, escalating from container-level to host-level access.",
        detection: "Monitor for container escape indicators. Implement container runtime security. Track unusual host access from container contexts.",
        platforms: ["Containers", "Windows", "Linux"]
      },
      {
        id: "T1055",
        name: "Process Injection",
        description: "Adversaries inject code into running processes to escalate privileges, evade detection, or gain access to the process's resources and memory, including DLL injection, process hollowing, and thread execution hijacking.",
        detection: "Monitor for cross-process memory access. Track process injection API calls. Implement memory protection mechanisms. Audit unexpected DLL loading.",
        platforms: ["Windows", "Linux", "macOS"]
      }
    ]
  },
  {
    tactic: "Defense Evasion",
    id: "TA0005",
    techniques: [
      {
        id: "T1548",
        name: "Abuse Elevation Control Mechanism",
        description: "Adversaries bypass elevation controls to execute code with elevated privileges while evading monitoring of standard privilege escalation paths.",
        detection: "Monitor UAC bypass techniques. Track elevation prompts and their outcomes. Audit privileged operations initiated without standard elevation.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1134",
        name: "Access Token Manipulation",
        description: "Adversaries manipulate access tokens to evade detection by appearing to operate under legitimate user contexts, hiding malicious activity within normal-appearing sessions.",
        detection: "Monitor for token manipulation API calls. Track unusual token usage patterns. Correlate process tokens with user sessions.",
        platforms: ["Windows"]
      },
      {
        id: "T1197",
        name: "BITS Jobs",
        description: "Adversaries use BITS to transfer and execute malware while blending with legitimate Windows update traffic, evading network-based detection.",
        detection: "Monitor BITS job creation. Track unusual BITS transfer destinations. Correlate BITS activity with known-good update patterns.",
        platforms: ["Windows"]
      },
      {
        id: "T1140",
        name: "Deobfuscate/Decode Files or Information",
        description: "Adversaries decode or deobfuscate encrypted/encoded payloads after delivery to reveal malicious content that evaded initial security scanning.",
        detection: "Monitor for decoding utilities (certutil, base64). Track file creation following decode operations. Analyze process command lines for encoding indicators.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1006",
        name: "Direct Volume Access",
        description: "Adversaries directly access logical drives or volumes to read/write data, bypassing file system access controls and monitoring tools.",
        detection: "Monitor for direct volume access API calls. Track raw disk read/write operations. Implement kernel-level monitoring of volume access.",
        platforms: ["Windows"]
      },
      {
        id: "T1484",
        name: "Domain Policy Modification",
        description: "Adversaries modify domain policies to weaken security controls, disable logging, or create exceptions that allow malicious activity to proceed undetected.",
        detection: "Monitor GPO modifications. Track changes to domain security policies. Audit policy application events.",
        platforms: ["Windows", "Azure AD"]
      },
      {
        id: "T1480",
        name: "Execution Guardrails",
        description: "Adversaries implement environmental checks (hostname, IP, domain, language) to restrict execution to intended targets, preventing analysis in sandbox or researcher environments.",
        detection: "Analyze malware for environmental checks. Monitor for system reconnaissance preceding execution. Implement diverse sandbox configurations.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1211",
        name: "Exploitation for Defense Evasion",
        description: "Adversaries exploit vulnerabilities in security software or OS components to disable or bypass security controls including AV, EDR, and application whitelisting.",
        detection: "Monitor security tool health and functionality. Track security software crashes or restarts. Implement tamper protection for security tools.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1222",
        name: "File and Directory Permissions Modification",
        description: "Adversaries modify file and directory permissions or ACLs to weaken security controls, enable access to restricted resources, or hide malicious files.",
        detection: "Monitor for permission changes on critical files and directories. Track ACL modifications. Audit icacls, chmod, and chown usage.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1564",
        name: "Hide Artifacts",
        description: "Adversaries hide files, directories, users, and other artifacts to evade detection, using techniques like hidden files, NTFS alternate data streams, or hidden user accounts.",
        detection: "Monitor for hidden file creation. Scan for NTFS alternate data streams. Track hidden user account creation. Audit file attribute changes.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1562",
        name: "Impair Defenses",
        description: "Adversaries disable or modify security tools and logging to prevent detection, including disabling Windows Defender, stopping logging services, or modifying firewall rules.",
        detection: "Monitor security tool status. Track logging service health. Alert on firewall rule changes. Implement tamper-proof logging.",
        platforms: ["Windows", "Linux", "macOS", "IaaS"]
      },
      {
        id: "T1070",
        name: "Indicator Removal",
        description: "Adversaries delete or modify artifacts (logs, files, timestamps) to remove indicators of compromise and cover their tracks in the victim environment.",
        detection: "Implement centralized logging with forward-only writes. Monitor for log deletion attempts. Track timestomping indicators.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1036",
        name: "Masquerading",
        description: "Adversaries disguise malicious artifacts as legitimate by manipulating names, locations, or metadata to evade detection and blend with normal system activity.",
        detection: "Verify binary signatures and file hashes. Monitor for processes running from unusual locations. Track file name mismatches with binary metadata.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1112",
        name: "Modify Registry",
        description: "Adversaries modify the Windows Registry to hide configuration data, persist malware, or disable security features without creating obvious filesystem artifacts.",
        detection: "Monitor registry modifications to sensitive keys. Track reg.exe and regedit.exe usage. Implement registry auditing for critical keys.",
        platforms: ["Windows"]
      },
      {
        id: "T1027",
        name: "Obfuscated Files or Information",
        description: "Adversaries encrypt, encode, or obfuscate malware and data to evade detection by security tools, including binary padding, steganography, and custom encryption.",
        detection: "Implement multi-engine AV scanning. Use behavioral analysis alongside signature detection. Monitor for obfuscation tools and encoding utilities.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1055",
        name: "Process Injection",
        description: "Adversaries inject code into legitimate processes to evade process-based defenses and blend malicious activity with normal system operations.",
        detection: "Monitor for cross-process memory operations. Track unusual DLL loading. Implement memory integrity checks on critical processes.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1207",
        name: "Rogue Domain Controller",
        description: "Adversaries register rogue domain controllers (DCShadow) to push malicious changes to Active Directory via replication, bypassing standard audit logging.",
        detection: "Monitor for new domain controller registrations. Track AD replication events from unexpected sources. Audit nTDSDSA object creation.",
        platforms: ["Windows"]
      },
      {
        id: "T1014",
        name: "Rootkit",
        description: "Adversaries install rootkits to hide malware presence by intercepting and modifying OS API calls, hiding processes, files, network connections, and registry entries.",
        detection: "Implement kernel integrity checking. Use anti-rootkit scanning tools. Compare live system state with offline forensic analysis.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1218",
        name: "System Binary Proxy Execution",
        description: "Adversaries abuse signed system binaries (rundll32, mshta, certutil, regsvr32) to proxy execution of malicious code, bypassing application whitelisting.",
        detection: "Monitor LOLBin usage with suspicious arguments. Track system binary execution with unusual parent processes. Implement command-line logging.",
        platforms: ["Windows"]
      },
      {
        id: "T1221",
        name: "Template Injection",
        description: "Adversaries abuse document template functionality to load malicious code from remote locations when documents are opened, bypassing email attachment scanning.",
        detection: "Monitor for documents loading remote templates. Track Office network connections. Analyze document metadata for remote template references.",
        platforms: ["Windows"]
      },
      {
        id: "T1127",
        name: "Trusted Developer Utilities Proxy Execution",
        description: "Adversaries abuse trusted developer tools (MSBuild, dnx, rcsi) to proxy execution of malicious code, bypassing application control policies.",
        detection: "Monitor developer tool execution in non-development environments. Track MSBuild project file creation and execution.",
        platforms: ["Windows"]
      },
      {
        id: "T1535",
        name: "Unused/Unsupported Cloud Regions",
        description: "Adversaries deploy resources in cloud regions not typically used by the organization to evade monitoring that may only cover primary operational regions.",
        detection: "Monitor for resource deployment in unused cloud regions. Implement cloud governance policies restricting available regions.",
        platforms: ["IaaS"]
      },
      {
        id: "T1550",
        name: "Use Alternate Authentication Material",
        description: "Adversaries use alternate authentication material (pass-the-hash, pass-the-ticket, web session cookies) to move laterally without needing plaintext credentials.",
        detection: "Monitor for NTLM hash usage. Track Kerberos ticket anomalies. Correlate authentication events across systems.",
        platforms: ["Windows", "Azure AD", "Office 365", "SaaS"]
      },
      {
        id: "T1078",
        name: "Valid Accounts",
        description: "Adversaries use legitimate credentials to blend with normal user activity, making detection challenging since authentication appears genuine.",
        detection: "Implement UEBA for anomalous account behavior. Track impossible travel scenarios. Monitor for credential reuse across environments.",
        platforms: ["Windows", "Linux", "macOS", "SaaS", "IaaS"]
      },
      {
        id: "T1497",
        name: "Virtualization/Sandbox Evasion",
        description: "Adversaries check for virtualization or sandbox environments to avoid analysis, using techniques like timing checks, registry lookups, and hardware fingerprinting.",
        detection: "Implement sandbox environment variety. Monitor for VM-detection system calls. Use bare-metal analysis for suspicious samples.",
        platforms: ["Windows", "Linux", "macOS"]
      }
    ]
  },
  {
    tactic: "Credential Access",
    id: "TA0006",
    techniques: [
      {
        id: "T1557",
        name: "Adversary-in-the-Middle",
        description: "Adversaries position themselves between two communication endpoints to intercept and potentially modify traffic, capturing credentials, tokens, and sensitive data in transit.",
        detection: "Monitor for ARP spoofing and LLMNR/NBT-NS poisoning. Implement 802.1X network access control. Track DNS response anomalies.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1110",
        name: "Brute Force",
        description: "Adversaries attempt to gain access by systematically trying passwords through guessing, credential stuffing, or password spraying against authentication services.",
        detection: "Monitor for multiple failed login attempts. Implement account lockout policies. Track password spray patterns across multiple accounts.",
        platforms: ["Windows", "Linux", "macOS", "Azure AD", "Office 365", "SaaS"]
      },
      {
        id: "T1555",
        name: "Credentials from Password Stores",
        description: "Adversaries extract credentials from password managers, browser credential stores, and OS credential vaults to access additional systems and services.",
        detection: "Monitor access to credential store files. Track browser credential store access. Audit password manager API usage.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1212",
        name: "Exploitation for Credential Access",
        description: "Adversaries exploit software vulnerabilities to extract credentials, such as exploiting authentication bypass bugs or memory corruption to read credential data.",
        detection: "Keep authentication systems patched. Monitor for exploit indicators against credential services. Implement credential isolation.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1187",
        name: "Forced Authentication",
        description: "Adversaries force authentication attempts by crafting files or links that trigger automatic credential exchange (e.g., UNC paths forcing SMB authentication).",
        detection: "Monitor for outbound SMB authentication to external addresses. Block NTLM relay to external networks. Track forced authentication triggers.",
        platforms: ["Windows"]
      },
      {
        id: "T1056",
        name: "Input Capture",
        description: "Adversaries capture user input through keylogging, credential interception portals, or API hooking to collect credentials and other sensitive information.",
        detection: "Monitor for keylogger indicators. Track input hooking API calls. Implement keystroke encryption for credential entry.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1556",
        name: "Modify Authentication Process",
        description: "Adversaries modify authentication mechanisms to capture credentials during the authentication process or to bypass authentication entirely for persistent access.",
        detection: "Monitor authentication-related file integrity. Track changes to PAM modules and SSP DLLs. Audit authentication flow modifications.",
        platforms: ["Windows", "Linux", "macOS", "Azure AD"]
      },
      {
        id: "T1111",
        name: "Multi-Factor Authentication Interception",
        description: "Adversaries intercept MFA tokens or bypass MFA through real-time phishing proxies (EvilGinx), SIM swapping, or exploiting MFA implementation weaknesses.",
        detection: "Monitor for MFA bypass indicators. Track SIM swap attempts. Implement phishing-resistant MFA (FIDO2). Audit MFA enrollment changes.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1621",
        name: "Multi-Factor Authentication Request Generation",
        description: "Adversaries bombard users with MFA push notifications (MFA fatigue) hoping the user will approve a request to stop the notifications, granting access.",
        detection: "Monitor for excessive MFA push requests. Implement number-matching MFA. Track and alert on repeated MFA denials followed by an approval.",
        platforms: ["Windows", "Linux", "macOS", "SaaS", "Azure AD"]
      },
      {
        id: "T1040",
        name: "Network Sniffing",
        description: "Adversaries capture network traffic using packet sniffing tools to extract credentials, tokens, and other sensitive data transmitted over the network.",
        detection: "Monitor for promiscuous mode on network interfaces. Detect packet capture tool execution. Enforce encryption for all sensitive traffic.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1003",
        name: "OS Credential Dumping",
        description: "Adversaries dump credentials from OS credential stores including LSASS memory, SAM database, NTDS.dit, /etc/shadow, and credential cache files.",
        detection: "Protect LSASS with PPL or Credential Guard. Monitor for credential dumping tools (Mimikatz). Track access to credential store files.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1528",
        name: "Steal Application Access Token",
        description: "Adversaries steal application access tokens (OAuth, API keys, session tokens) to access resources and services without needing the user's credentials.",
        detection: "Monitor for unusual OAuth token grants. Track API key usage anomalies. Implement token rotation and revocation policies.",
        platforms: ["SaaS", "Office 365", "Azure AD", "Google Workspace"]
      },
      {
        id: "T1649",
        name: "Steal or Forge Authentication Certificates",
        description: "Adversaries steal or forge authentication certificates to authenticate as users or machines, enabling persistent access through certificate-based authentication.",
        detection: "Monitor certificate enrollment and issuance. Track certificate-based authentication events. Audit CA server access and template modifications.",
        platforms: ["Windows", "Azure AD"]
      },
      {
        id: "T1558",
        name: "Steal or Forge Kerberos Tickets",
        description: "Adversaries steal or forge Kerberos tickets (Golden Ticket, Silver Ticket, Kerberoasting) for authentication without knowing actual passwords.",
        detection: "Monitor for anomalous Kerberos ticket requests. Track TGS requests for service accounts. Implement Kerberos event logging.",
        platforms: ["Windows"]
      },
      {
        id: "T1539",
        name: "Steal Web Session Cookie",
        description: "Adversaries steal web session cookies to authenticate to web applications as the victim user, bypassing MFA and other authentication mechanisms.",
        detection: "Monitor for cookie theft indicators. Implement session binding to IP/device. Track unusual session usage patterns.",
        platforms: ["Windows", "Linux", "macOS", "SaaS"]
      },
      {
        id: "T1552",
        name: "Unsecured Credentials",
        description: "Adversaries search for unsecured credentials in files, scripts, configuration files, environment variables, and cloud metadata services.",
        detection: "Scan repositories for exposed credentials. Monitor access to credential files. Implement secret management solutions.",
        platforms: ["Windows", "Linux", "macOS", "IaaS", "Containers"]
      }
    ]
  },
  {
    tactic: "Discovery",
    id: "TA0007",
    techniques: [
      {
        id: "T1087",
        name: "Account Discovery",
        description: "Adversaries enumerate user accounts on local systems, domain controllers, email servers, and cloud environments to identify potential targets for lateral movement.",
        detection: "Monitor for account enumeration commands (net user, Get-ADUser). Track LDAP queries for user objects. Audit cloud IAM API calls.",
        platforms: ["Windows", "Linux", "macOS", "Azure AD", "Office 365"]
      },
      {
        id: "T1010",
        name: "Application Window Discovery",
        description: "Adversaries enumerate open application windows to gather information about user activity, running applications, and potential data of interest.",
        detection: "Monitor for window enumeration API calls. Track unusual application discovery patterns.",
        platforms: ["Windows", "macOS"]
      },
      {
        id: "T1217",
        name: "Browser Information Discovery",
        description: "Adversaries enumerate browser bookmarks, history, and settings to discover internal URLs, credentials, and organizational information.",
        detection: "Monitor access to browser data files. Track reading of browser databases and configuration files.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1580",
        name: "Cloud Infrastructure Discovery",
        description: "Adversaries enumerate cloud infrastructure components including VMs, storage, databases, and networking to understand the cloud environment for further operations.",
        detection: "Monitor cloud API calls for resource enumeration. Track unusual cloud discovery patterns. Audit cloud resource listing commands.",
        platforms: ["IaaS"]
      },
      {
        id: "T1538",
        name: "Cloud Service Dashboard",
        description: "Adversaries access cloud management dashboards to discover resources, configurations, and permissions available in the cloud environment.",
        detection: "Monitor for unusual cloud console access. Track dashboard access from new IPs or devices.",
        platforms: ["IaaS", "Azure AD", "Office 365"]
      },
      {
        id: "T1526",
        name: "Cloud Service Discovery",
        description: "Adversaries enumerate cloud services available in the victim environment to identify potential targets and understand the cloud infrastructure.",
        detection: "Monitor cloud service enumeration API calls. Track unusual service discovery patterns.",
        platforms: ["IaaS", "SaaS", "Azure AD", "Office 365"]
      },
      {
        id: "T1613",
        name: "Container and Resource Discovery",
        description: "Adversaries enumerate containers, pods, and container orchestration resources to understand the container environment for further operations.",
        detection: "Monitor kubectl and docker commands for resource enumeration. Track Kubernetes API calls for listing operations.",
        platforms: ["Containers"]
      },
      {
        id: "T1482",
        name: "Domain Trust Discovery",
        description: "Adversaries enumerate Active Directory domain trusts to identify potential paths for lateral movement to trusted domains and forests.",
        detection: "Monitor for nltest and similar trust enumeration tools. Track LDAP queries for trust objects. Audit domain trust enumeration commands.",
        platforms: ["Windows"]
      },
      {
        id: "T1083",
        name: "File and Directory Discovery",
        description: "Adversaries enumerate files and directories to find data of interest, discover system configurations, and identify security controls in place.",
        detection: "Monitor for extensive file system enumeration. Track unusual directory traversal patterns. Audit automated file search activities.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1046",
        name: "Network Service Discovery",
        description: "Adversaries scan for services running on remote hosts to identify potential targets for exploitation or lateral movement within the network.",
        detection: "Monitor for internal port scanning activity. Track service enumeration tools. Detect unusual network probing patterns.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1135",
        name: "Network Share Discovery",
        description: "Adversaries enumerate network shares to identify shared resources containing sensitive data or that may be used for lateral movement.",
        detection: "Monitor for net share and net view commands. Track SMB share enumeration. Audit share access patterns.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1057",
        name: "Process Discovery",
        description: "Adversaries enumerate running processes to identify security software, installed applications, and potential targets for process injection.",
        detection: "Monitor for process enumeration commands and API calls. Track unusual process listing activity.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1012",
        name: "Query Registry",
        description: "Adversaries query the Windows Registry to gather information about the system configuration, installed software, and security settings.",
        detection: "Monitor for registry query commands. Track reg.exe queries to sensitive registry keys.",
        platforms: ["Windows"]
      },
      {
        id: "T1018",
        name: "Remote System Discovery",
        description: "Adversaries discover remote systems through DNS queries, network scanning, ARP tables, and Active Directory enumeration to identify lateral movement targets.",
        detection: "Monitor for remote system discovery commands (net view, ping sweeps). Track ARP table queries. Audit LDAP computer object queries.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1518",
        name: "Software Discovery",
        description: "Adversaries enumerate installed software to identify security tools, vulnerable applications, and useful utilities for post-exploitation activities.",
        detection: "Monitor for software enumeration commands and WMI queries. Track application listing activities.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1082",
        name: "System Information Discovery",
        description: "Adversaries gather system information including OS version, hostname, architecture, and hardware details to aid in targeting and exploit selection.",
        detection: "Monitor for system information gathering commands. Track unusual systeminfo, uname, or sw_vers execution.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1016",
        name: "System Network Configuration Discovery",
        description: "Adversaries enumerate network configuration including IP addresses, routing tables, DNS settings, and proxy configurations to understand the network environment.",
        detection: "Monitor for network configuration commands (ipconfig, ifconfig, route). Track unusual network enumeration activity.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1049",
        name: "System Network Connections Discovery",
        description: "Adversaries enumerate active network connections to discover communication channels, identify connected systems, and find potential pivot points.",
        detection: "Monitor for netstat and similar commands. Track network connection enumeration API calls.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1033",
        name: "System Owner/User Discovery",
        description: "Adversaries identify the primary user, currently logged on users, and user privileges to understand the context of their access and potential escalation paths.",
        detection: "Monitor for user enumeration commands (whoami, id). Track unusual user discovery patterns.",
        platforms: ["Windows", "Linux", "macOS"]
      }
    ]
  },
  {
    tactic: "Lateral Movement",
    id: "TA0008",
    techniques: [
      {
        id: "T1210",
        name: "Exploitation of Remote Services",
        description: "Adversaries exploit vulnerabilities in remote services (SMB, RDP, SSH, databases) to move laterally to other systems on the network.",
        detection: "Monitor for exploit attempts against internal services. Track unusual remote service connections. Implement network segmentation.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1534",
        name: "Internal Spearphishing",
        description: "Adversaries send spearphishing messages from compromised internal accounts to other users within the organization to move laterally or gain additional access.",
        detection: "Monitor internal email for phishing indicators. Track email forwarding rules. Analyze internal email patterns for anomalies.",
        platforms: ["Windows", "Linux", "macOS", "Office 365", "SaaS"]
      },
      {
        id: "T1570",
        name: "Lateral Tool Transfer",
        description: "Adversaries transfer tools and malware between systems using protocols like SMB, FTP, or cloud storage to stage capabilities for further operations.",
        detection: "Monitor for file transfers between internal systems. Track SMB write operations. Audit tool deployment across systems.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1563",
        name: "Remote Service Session Hijacking",
        description: "Adversaries hijack existing remote service sessions (RDP, SSH) to move laterally without generating new authentication events or requiring credentials.",
        detection: "Monitor for session hijacking indicators. Track RDP session disconnections followed by reconnections. Audit SSH session management.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1021",
        name: "Remote Services",
        description: "Adversaries use legitimate remote services (RDP, SSH, SMB, WinRM, VNC) with valid credentials to move laterally between systems on the network.",
        detection: "Monitor for unusual remote service connections. Track lateral authentication events. Implement jump server requirements for remote access.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1091",
        name: "Replication Through Removable Media",
        description: "Adversaries move laterally by copying malware to removable media (USB drives) and relying on autorun or user interaction to execute on connected systems.",
        detection: "Disable autorun. Monitor USB device connections. Track file copies to removable media.",
        platforms: ["Windows"]
      },
      {
        id: "T1080",
        name: "Taint Shared Content",
        description: "Adversaries modify content on network shares by adding malicious files or replacing legitimate files with trojanized versions to compromise users who access the share.",
        detection: "Monitor for modifications to files on network shares. Implement file integrity monitoring for shared resources.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1550",
        name: "Use Alternate Authentication Material",
        description: "Adversaries use alternate authentication material (pass-the-hash, pass-the-ticket, stolen tokens) to move laterally without needing plaintext credentials.",
        detection: "Monitor for NTLM relay attacks. Track Kerberos ticket anomalies. Correlate authentication events across systems.",
        platforms: ["Windows", "Azure AD", "Office 365", "SaaS"]
      }
    ]
  },
  {
    tactic: "Collection",
    id: "TA0009",
    techniques: [
      {
        id: "T1557",
        name: "Adversary-in-the-Middle",
        description: "Adversaries position between endpoints to collect data in transit, including credentials, emails, and sensitive communications without altering the data flow.",
        detection: "Monitor for ARP spoofing and LLMNR poisoning. Implement encryption for internal traffic. Track unusual network proxy behavior.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1560",
        name: "Archive Collected Data",
        description: "Adversaries compress and/or encrypt collected data using tools like 7-Zip, WinRAR, tar, or custom packers before exfiltration to reduce transfer size and avoid content inspection.",
        detection: "Monitor for archive creation tools. Track large archive file creation. Detect encryption of staging directories.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1123",
        name: "Audio Capture",
        description: "Adversaries capture audio through the victim's microphone to record conversations and gather intelligence from the physical environment.",
        detection: "Monitor for microphone access by unexpected applications. Track audio recording API calls. Implement microphone access controls.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1119",
        name: "Automated Collection",
        description: "Adversaries automate data collection using scripts or tools that systematically gather files, databases, and other data matching specific criteria.",
        detection: "Monitor for automated file enumeration and collection. Track bulk file access patterns. Detect data staging activities.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1185",
        name: "Browser Session Hijacking",
        description: "Adversaries inject into browser processes to collect data from web sessions, including credentials, financial data, and session tokens.",
        detection: "Monitor for browser process injection. Track unusual browser extension activity. Implement browser isolation.",
        platforms: ["Windows"]
      },
      {
        id: "T1115",
        name: "Clipboard Data",
        description: "Adversaries collect data stored in the clipboard to capture passwords, cryptocurrency addresses, and other sensitive information copied by users.",
        detection: "Monitor for clipboard monitoring API calls. Track clipboard access by unexpected processes.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1530",
        name: "Data from Cloud Storage",
        description: "Adversaries collect data from cloud storage services (S3, Azure Blob, GCS) that may be publicly accessible or accessible with compromised credentials.",
        detection: "Monitor cloud storage access logs. Track unusual data downloads from cloud storage. Implement cloud DLP policies.",
        platforms: ["IaaS", "SaaS"]
      },
      {
        id: "T1602",
        name: "Data from Configuration Repository",
        description: "Adversaries collect configuration files from network devices, management platforms, and infrastructure to extract credentials and map network topology.",
        detection: "Monitor for SNMP queries and TFTP transfers. Track access to network device configurations. Audit configuration management systems.",
        platforms: ["Network"]
      },
      {
        id: "T1213",
        name: "Data from Information Repositories",
        description: "Adversaries collect data from information repositories such as SharePoint, Confluence, internal wikis, and code repositories that contain sensitive organizational data.",
        detection: "Monitor for bulk data access in collaboration platforms. Track unusual repository access patterns. Implement DLP for information repositories.",
        platforms: ["Windows", "Linux", "macOS", "SaaS"]
      },
      {
        id: "T1005",
        name: "Data from Local System",
        description: "Adversaries collect data from the local file system including documents, databases, and configuration files containing sensitive information.",
        detection: "Monitor for bulk file access and reading. Track file access to sensitive directories. Implement endpoint DLP.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1039",
        name: "Data from Network Shared Drive",
        description: "Adversaries collect data from network shared drives that may contain sensitive documents, databases, and other files accessible across the network.",
        detection: "Monitor for bulk file access on network shares. Track unusual share access patterns. Implement file access auditing.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1025",
        name: "Data from Removable Media",
        description: "Adversaries collect data from removable media connected to compromised systems, including USB drives and external hard drives.",
        detection: "Monitor for file access on removable media. Track removable media connections. Implement device control policies.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1074",
        name: "Data Staged",
        description: "Adversaries stage collected data in a central location before exfiltration, often in temporary directories, hidden folders, or cloud storage.",
        detection: "Monitor for data staging in temporary directories. Track large file creation in unusual locations. Detect compression of staged data.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1114",
        name: "Email Collection",
        description: "Adversaries collect email from local email clients, mail servers, or cloud email services to gather intelligence, credentials, and sensitive communications.",
        detection: "Monitor for email export activities. Track Exchange/O365 API calls for email access. Audit email forwarding rule creation.",
        platforms: ["Windows", "Office 365", "Google Workspace"]
      },
      {
        id: "T1056",
        name: "Input Capture",
        description: "Adversaries capture user input through keyloggers, credential interception hooks, or web portal mimicry to collect credentials and sensitive data.",
        detection: "Monitor for keylogging indicators. Track input hook API calls. Detect credential capture portal deployment.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1113",
        name: "Screen Capture",
        description: "Adversaries capture screenshots of the victim's desktop to gather information about user activities, displayed data, and the working environment.",
        detection: "Monitor for screen capture API calls. Track screenshot file creation. Detect screen recording software.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1125",
        name: "Video Capture",
        description: "Adversaries capture video through the victim's webcam to conduct surveillance and gather visual intelligence from the physical environment.",
        detection: "Monitor for webcam access by unexpected applications. Track video recording API calls. Implement camera access controls.",
        platforms: ["Windows", "Linux", "macOS"]
      }
    ]
  },
  {
    tactic: "Command and Control",
    id: "TA0011",
    techniques: [
      {
        id: "T1071",
        name: "Application Layer Protocol",
        description: "Adversaries communicate using standard application layer protocols (HTTP, HTTPS, DNS, SMTP) to blend C2 traffic with normal network activity and evade detection.",
        detection: "Analyze network traffic for unusual patterns within allowed protocols. Implement SSL/TLS inspection. Monitor DNS query patterns for anomalies.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1092",
        name: "Communication Through Removable Media",
        description: "Adversaries use removable media to establish C2 channels in air-gapped networks, transferring commands and data via USB drives between connected and disconnected systems.",
        detection: "Monitor for suspicious files on removable media. Track USB device connections in air-gapped environments. Implement strict removable media policies.",
        platforms: ["Windows", "Linux"]
      },
      {
        id: "T1132",
        name: "Data Encoding",
        description: "Adversaries encode C2 data using standard or custom encoding schemes (Base64, XOR, custom algorithms) to obfuscate the content of communications.",
        detection: "Analyze network traffic for encoding patterns. Monitor for Base64-encoded data in HTTP traffic. Implement deep packet inspection.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1001",
        name: "Data Obfuscation",
        description: "Adversaries obfuscate C2 communications using techniques like steganography, protocol impersonation, and junk data insertion to evade detection.",
        detection: "Monitor for unusual data patterns in network traffic. Implement traffic analysis for hidden channels. Track protocol anomalies.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1568",
        name: "Dynamic Resolution",
        description: "Adversaries use dynamic resolution techniques (DGA, DNS calculation, fast flux) to dynamically establish C2 connections, making infrastructure harder to block.",
        detection: "Monitor DNS queries for DGA patterns. Track rapid DNS changes. Implement DNS sinkholing for known DGA families.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1573",
        name: "Encrypted Channel",
        description: "Adversaries encrypt C2 communications using symmetric or asymmetric encryption to prevent detection of communication content by network monitoring tools.",
        detection: "Monitor for encrypted traffic to unusual destinations. Implement JA3/JA3S fingerprinting. Track certificate anomalies in TLS connections.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1008",
        name: "Fallback Channels",
        description: "Adversaries configure multiple C2 channels as fallbacks in case primary channels are discovered and blocked, ensuring continued access to compromised systems.",
        detection: "Monitor for multiple C2 channel indicators. Track beacon pattern changes. Analyze malware configurations for fallback addresses.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1105",
        name: "Ingress Tool Transfer",
        description: "Adversaries transfer tools and files from external systems into the compromised environment using C2 channels, HTTP downloads, or legitimate file transfer services.",
        detection: "Monitor for file downloads from unusual sources. Track tool deployment across systems. Analyze network transfers for known tool signatures.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1104",
        name: "Multi-Stage Channels",
        description: "Adversaries create separate C2 channels for different stages of an operation, using lightweight first-stage beacons to download more capable second-stage implants.",
        detection: "Monitor for sequential C2 channel establishment. Track download-and-execute patterns. Analyze beacon behavior changes.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1095",
        name: "Non-Application Layer Protocol",
        description: "Adversaries use non-application layer protocols (ICMP, UDP, raw sockets) for C2 communications to bypass security controls focused on higher-level protocols.",
        detection: "Monitor for unusual ICMP traffic patterns. Track raw socket creation. Analyze non-standard protocol usage.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1571",
        name: "Non-Standard Port",
        description: "Adversaries use non-standard ports for C2 communications to bypass firewall rules and network monitoring that focus on standard service ports.",
        detection: "Monitor for protocol-port mismatches. Track connections to unusual ports. Implement strict egress firewall policies.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1572",
        name: "Protocol Tunneling",
        description: "Adversaries tunnel C2 communications within legitimate protocols (DNS tunneling, HTTP tunneling, SSH tunneling) to bypass network filtering and monitoring.",
        detection: "Monitor for DNS tunneling indicators (high query volume, long subdomain names). Track unusual protocol payload sizes. Implement protocol-aware inspection.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1090",
        name: "Proxy",
        description: "Adversaries route C2 traffic through proxy servers, compromised systems, or anonymization networks (Tor) to obscure the true source and destination of communications.",
        detection: "Monitor for Tor and proxy tool usage. Track connections through known proxy services. Analyze multi-hop connection patterns.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1219",
        name: "Remote Access Software",
        description: "Adversaries use legitimate remote access software (TeamViewer, AnyDesk, ConnectWise) for C2, leveraging trusted applications to evade security controls.",
        detection: "Monitor for unauthorized remote access tool installations. Track remote access tool connections. Implement application control policies.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1205",
        name: "Traffic Signaling",
        description: "Adversaries use traffic signaling (port knocking, magic packets) to activate dormant backdoors, keeping them hidden until triggered by specific network patterns.",
        detection: "Monitor for port-knocking patterns. Analyze network traffic for unusual packet sequences. Track firewall rule activations.",
        platforms: ["Windows", "Linux", "macOS", "Network"]
      },
      {
        id: "T1102",
        name: "Web Service",
        description: "Adversaries use legitimate web services (social media, cloud storage, paste sites, code repositories) as C2 channels, hiding traffic within trusted platforms.",
        detection: "Monitor for unusual traffic to social media APIs. Track cloud storage API usage patterns. Analyze paste site access for C2 patterns.",
        platforms: ["Windows", "Linux", "macOS"]
      }
    ]
  },
  {
    tactic: "Exfiltration",
    id: "TA0010",
    techniques: [
      {
        id: "T1020",
        name: "Automated Exfiltration",
        description: "Adversaries automate exfiltration of collected data using scripts or tools that continuously or periodically transfer data to attacker-controlled infrastructure.",
        detection: "Monitor for automated data transfer patterns. Track periodic large data transfers. Implement DLP policies for data egress.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1030",
        name: "Data Transfer Size Limits",
        description: "Adversaries limit the size of data transfers to avoid triggering volume-based alerting, breaking exfiltration into smaller chunks over time.",
        detection: "Monitor for sustained low-volume data transfers to unusual destinations. Track cumulative data transfers over time.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1048",
        name: "Exfiltration Over Alternative Protocol",
        description: "Adversaries exfiltrate data using different protocols than the C2 channel, such as DNS, ICMP, FTP, or SMTP, to avoid detection on the primary C2 channel.",
        detection: "Monitor for data in DNS queries. Track unusual ICMP payload sizes. Analyze SMTP traffic for embedded data.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1041",
        name: "Exfiltration Over C2 Channel",
        description: "Adversaries exfiltrate data over the existing C2 channel, leveraging the already-established communication path to transfer stolen data.",
        detection: "Monitor C2 channels for increased data volume. Track changes in beacon traffic patterns. Implement network flow analysis.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1011",
        name: "Exfiltration Over Other Network Medium",
        description: "Adversaries exfiltrate data over alternative network mediums such as Bluetooth, cellular, Wi-Fi, or satellite to bypass network monitoring on primary connections.",
        detection: "Monitor for unusual wireless connections. Track Bluetooth data transfers. Detect unauthorized cellular modem usage.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1052",
        name: "Exfiltration Over Physical Medium",
        description: "Adversaries exfiltrate data by physically moving it out of the environment using removable media, printed documents, or other physical means.",
        detection: "Monitor for data copies to removable media. Implement device control policies. Track printer activity for sensitive documents.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1567",
        name: "Exfiltration Over Web Service",
        description: "Adversaries exfiltrate data to cloud storage services, paste sites, or other web services, blending exfiltration with normal web traffic to cloud services.",
        detection: "Monitor for large uploads to cloud storage services. Track API calls to file sharing platforms. Implement CASB policies for data egress.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1029",
        name: "Scheduled Transfer",
        description: "Adversaries schedule data exfiltration at specific times (off-hours, weekends) to blend with expected traffic patterns and avoid detection during active monitoring.",
        detection: "Monitor for after-hours data transfers. Track scheduled file transfer tasks. Analyze network traffic timing patterns.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1537",
        name: "Transfer Data to Cloud Account",
        description: "Adversaries transfer data to cloud accounts they control, using the organization's own cloud egress to avoid triggering network-based detection.",
        detection: "Monitor for data transfers to unknown cloud accounts. Track cloud storage API calls. Implement cloud DLP policies.",
        platforms: ["IaaS"]
      }
    ]
  },
  {
    tactic: "Impact",
    id: "TA0040",
    techniques: [
      {
        id: "T1531",
        name: "Account Access Removal",
        description: "Adversaries remove or lock accounts, delete credentials, or change passwords to prevent legitimate users from accessing systems, causing operational disruption.",
        detection: "Monitor for bulk account modifications. Track password resets across multiple accounts. Alert on account lockout patterns.",
        platforms: ["Windows", "Linux", "macOS", "Azure AD", "Office 365"]
      },
      {
        id: "T1485",
        name: "Data Destruction",
        description: "Adversaries destroy data and files on victim systems using wipers or deletion tools to cause operational disruption and inhibit recovery efforts.",
        detection: "Monitor for mass file deletion. Track wiper malware signatures. Implement file integrity monitoring for critical data.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1486",
        name: "Data Encrypted for Impact",
        description: "Adversaries encrypt data on victim systems using ransomware to extort payment, rendering files and systems inaccessible until a ransom is paid or backups are restored.",
        detection: "Monitor for mass file encryption indicators. Track file extension changes. Implement ransomware-specific behavioral detection.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1565",
        name: "Data Manipulation",
        description: "Adversaries modify data at rest or in transit to undermine data integrity, influence business decisions, or cause operational disruption.",
        detection: "Implement data integrity checking. Monitor for unauthorized data modifications. Track database transaction anomalies.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1491",
        name: "Defacement",
        description: "Adversaries deface websites or systems with messages to deliver propaganda, claim credit for intrusions, or intimidate victims and their users.",
        detection: "Implement website integrity monitoring. Track unauthorized file changes on web servers. Monitor for content modifications.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1561",
        name: "Disk Wipe",
        description: "Adversaries wipe disk structures or content to render systems unbootable and data unrecoverable, causing maximum destructive impact to the victim organization.",
        detection: "Monitor for disk write operations to MBR/GPT structures. Track wiper malware indicators. Implement boot record integrity monitoring.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1499",
        name: "Endpoint Denial of Service",
        description: "Adversaries exhaust system resources (CPU, memory, disk, network) on endpoints to deny service to legitimate users and disrupt business operations.",
        detection: "Monitor system resource utilization for anomalies. Track process resource consumption. Implement resource usage alerting.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1657",
        name: "Financial Theft",
        description: "Adversaries directly steal financial assets through fraudulent wire transfers, cryptocurrency theft, or manipulation of financial systems and transactions.",
        detection: "Monitor for unusual financial transactions. Implement multi-person authorization for wire transfers. Track cryptocurrency wallet interactions.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1495",
        name: "Firmware Corruption",
        description: "Adversaries corrupt firmware on devices to render them inoperable or to create persistent backdoors that survive OS reinstallation and disk replacement.",
        detection: "Monitor firmware update processes. Implement firmware integrity checking. Track BIOS/UEFI modification attempts.",
        platforms: ["Windows", "Linux", "macOS", "Network"]
      },
      {
        id: "T1490",
        name: "Inhibit System Recovery",
        description: "Adversaries delete or disable system recovery features (shadow copies, backups, recovery partitions) to prevent victims from restoring systems after an attack.",
        detection: "Monitor for shadow copy deletion (vssadmin, wmic). Track backup service modifications. Alert on recovery partition access.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1498",
        name: "Network Denial of Service",
        description: "Adversaries launch DDoS attacks to overwhelm network capacity, making services unavailable to legitimate users through volumetric, protocol, or application-layer floods.",
        detection: "Implement DDoS mitigation services. Monitor for unusual traffic volume spikes. Track protocol anomalies in network traffic.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1496",
        name: "Resource Hijacking",
        description: "Adversaries hijack victim system resources for their own purposes, commonly cryptocurrency mining, but also for proxy networks or distributed computing.",
        detection: "Monitor for cryptocurrency mining indicators. Track unusual CPU/GPU utilization. Detect mining pool connections.",
        platforms: ["Windows", "Linux", "macOS", "IaaS"]
      },
      {
        id: "T1489",
        name: "Service Stop",
        description: "Adversaries stop critical services to disrupt business operations, often as a precursor to ransomware deployment to ensure databases and applications release file locks.",
        detection: "Monitor for unexpected service stops. Track bulk service termination. Alert on stopping of security and backup services.",
        platforms: ["Windows", "Linux", "macOS"]
      },
      {
        id: "T1529",
        name: "System Shutdown/Reboot",
        description: "Adversaries shut down or reboot systems to complete destructive actions, trigger boot-level malware, or disrupt operations by forcing systems offline.",
        detection: "Monitor for unexpected system shutdown or reboot commands. Track shutdown events outside maintenance windows.",
        platforms: ["Windows", "Linux", "macOS"]
      }
    ]
  }
];


// -----------------------------------------------------------------------------
// 3. MALWARE FAMILIES -- Ransomware, RATs, botnets, rootkits, wipers, stealers
// -----------------------------------------------------------------------------

export const MALWARE_FAMILIES = [
  // --- Ransomware ---
  {
    name: "LockBit 3.0",
    type: "ransomware",
    description: "Highly prolific RaaS (Ransomware-as-a-Service) operation using double extortion. Written partly in C, uses AES+RSA encryption. Features a bug bounty program and automated deployment tooling. Dominates ransomware landscape by victim count.",
    iocs: ["lockbit file extension", ".lockbit ransom note", "Restore-My-Files.txt", "LBB file marker in encrypted files", "C2 on Tor hidden services"],
    ttps: ["T1486 Data Encrypted for Impact", "T1490 Inhibit System Recovery", "T1059 Command and Scripting Interpreter", "T1078 Valid Accounts", "T1489 Service Stop"],
    detection: "Monitor for mass file encryption activity. Track shadow copy deletion (vssadmin delete shadows). Detect GPO modification for network-wide deployment. Watch for StealBit exfiltration tool."
  },
  {
    name: "BlackCat (ALPHV)",
    type: "ransomware",
    description: "First major ransomware written in Rust for cross-platform capability (Windows, Linux, VMware ESXi). Uses AES encryption. Operates RaaS model with sophisticated affiliate program. Known for data leak site and aggressive extortion.",
    iocs: [".ALPHV file extension", "RECOVER-[random]-FILES.txt", "ExMatter exfiltration tool", "Eamfo credential stealer", "Rust-compiled PE binaries"],
    ttps: ["T1486 Data Encrypted for Impact", "T1059 Command and Scripting Interpreter", "T1078 Valid Accounts", "T1021 Remote Services", "T1562 Impair Defenses"],
    detection: "Monitor for Rust-compiled executables with encryption behavior. Track ESXi VM shutdown commands. Detect Eamfo Veeam credential theft. Watch for ExMatter data exfiltration."
  },
  {
    name: "Cl0p",
    type: "ransomware",
    description: "Ransomware known for mass exploitation of file transfer vulnerabilities (MOVEit, GoAnywhere, Accellion). Shifted from traditional encryption to pure data theft and extortion. Linked to TA505/FIN11.",
    iocs: [".Cl0p file extension", "ClopReadMe.txt", "DEWMODE web shell", "LEMURLOOT web shell", "flawed.zip staging archives"],
    ttps: ["T1190 Exploit Public-Facing Application", "T1486 Data Encrypted for Impact", "T1005 Data from Local System", "T1567 Exfiltration Over Web Service", "T1059 Command and Scripting Interpreter"],
    detection: "Monitor file transfer applications for exploitation indicators. Track web shell deployment on MFT servers. Detect SQL injection against MOVEit Transfer. Watch for mass file download activity."
  },
  {
    name: "Conti",
    type: "ransomware",
    description: "Former top-tier RaaS operation that splintered after internal leaks in 2022. Used fast multi-threaded encryption. Linked to Wizard Spider/TrickBot ecosystem. Descendants include Royal, Black Basta, and Akira.",
    iocs: [".CONTI file extension", "readme.txt ransom note", "Cobalt Strike beacons", "BazarLoader/BazarBackdoor", "Anchor malware"],
    ttps: ["T1486 Data Encrypted for Impact", "T1021 Remote Services", "T1059 Command and Scripting Interpreter", "T1003 OS Credential Dumping", "T1490 Inhibit System Recovery"],
    detection: "Monitor for multi-threaded file encryption. Track Cobalt Strike beacon patterns. Detect TrickBot/BazarLoader infections as precursors. Watch for Rclone data exfiltration."
  },
  {
    name: "REvil (Sodinokibi)",
    type: "ransomware",
    description: "Prolific RaaS operation active 2019-2022, known for high-profile attacks and supply chain compromises. Successor to GandCrab. Used Salsa20 + Elliptic Curve Diffie-Hellman encryption.",
    iocs: [".[random] file extension", "[random]-readme.txt", "Sodinokibi mutex", "HKEY_LOCAL_MACHINE\\SOFTWARE\\recfg registry key", "C2 domains in config"],
    ttps: ["T1486 Data Encrypted for Impact", "T1195 Supply Chain Compromise", "T1190 Exploit Public-Facing Application", "T1059 Command and Scripting Interpreter", "T1490 Inhibit System Recovery"],
    detection: "Monitor for Kaseya VSA exploitation indicators. Track REvil registry artifacts. Detect Salsa20 encryption patterns. Watch for supply chain compromise indicators."
  },
  {
    name: "Black Basta",
    type: "ransomware",
    description: "RaaS operation emerging from former Conti members. Targets Windows and VMware ESXi. Uses ChaCha20 encryption with RSA-4096. Known for rapid initial access through QakBot and social engineering.",
    iocs: [".basta file extension", "instructions_read_me.txt", "readme.txt with .onion links", "QakBot/Qbot precursor infections", "SystemBC proxy tool"],
    ttps: ["T1486 Data Encrypted for Impact", "T1566 Phishing", "T1059 Command and Scripting Interpreter", "T1021 Remote Services", "T1003 OS Credential Dumping"],
    detection: "Monitor for QakBot infections as ransomware precursors. Track ChaCha20 encryption activity. Detect ESXi encryption commands. Watch for Cobalt Strike lateral movement."
  },
  {
    name: "Akira",
    type: "ransomware",
    description: "Ransomware targeting SMBs primarily through VPN credential exploitation, especially Cisco VPN vulnerabilities. Written in C++, uses ChaCha20/RSA encryption. Retro-themed leak site.",
    iocs: [".akira file extension", "akira_readme.txt", "Megazord variant (.powerranges extension)", "w.exe / win.exe encryptor names", "Tor-based leak site"],
    ttps: ["T1486 Data Encrypted for Impact", "T1078 Valid Accounts", "T1133 External Remote Services", "T1059 Command and Scripting Interpreter", "T1490 Inhibit System Recovery"],
    detection: "Monitor for VPN credential brute forcing. Track Cisco VPN exploitation attempts. Detect WinSCP and Rclone for data exfiltration. Watch for VMware ESXi targeting."
  },
  {
    name: "Rhysida",
    type: "ransomware",
    description: "Emerging RaaS targeting healthcare and education. Uses ChaCha20 encryption. Positions itself as a penetration testing team. Suspected links to Vice Society operators.",
    iocs: [".rhysida file extension", "CriticalBreachDetected.pdf", "cmd.exe /c PowerShell execution chains", "PsExec lateral movement", "Tor C2 infrastructure"],
    ttps: ["T1486 Data Encrypted for Impact", "T1566 Phishing", "T1059 Command and Scripting Interpreter", "T1078 Valid Accounts", "T1490 Inhibit System Recovery"],
    detection: "Monitor for ChaCha20 encryption patterns. Track PsExec deployment for ransomware distribution. Detect PowerShell-based reconnaissance. Watch for healthcare sector targeting patterns."
  },
  {
    name: "WannaCry",
    type: "ransomware / worm",
    description: "Self-propagating ransomware that leveraged EternalBlue (MS17-010) SMB exploit to spread globally in May 2017. Attributed to Lazarus Group. Kill switch discovered by researcher. Infected 200,000+ systems in 150 countries.",
    iocs: [".WNCRY file extension", "@WanaDecryptor@.exe", "mssecsvc.exe service creation", "EternalBlue exploitation (MS17-010)", "tasksche.exe"],
    ttps: ["T1486 Data Encrypted for Impact", "T1210 Exploitation of Remote Services", "T1059 Command and Scripting Interpreter", "T1569 System Services", "T1490 Inhibit System Recovery"],
    detection: "Detect EternalBlue exploitation attempts. Monitor for SMBv1 exploitation. Track wannacry-related file indicators. Patch MS17-010 and disable SMBv1."
  },
  {
    name: "Ryuk",
    type: "ransomware",
    description: "Targeted ransomware used against enterprise environments, often deployed after TrickBot or Emotet infection. Linked to Wizard Spider. Predecessor to Conti. Uses RSA+AES encryption.",
    iocs: [".RYK file extension", "RyukReadMe.html", "hermes.exe dropper", "UNIQUE_ID_DO_NOT_REMOVE marker", "TrickBot precursor infections"],
    ttps: ["T1486 Data Encrypted for Impact", "T1059 Command and Scripting Interpreter", "T1021 Remote Services", "T1490 Inhibit System Recovery", "T1489 Service Stop"],
    detection: "Monitor for TrickBot/Emotet infections as precursors. Track Ryuk-specific file markers. Detect service stop sequences before encryption. Watch for lateral movement via RDP."
  },

  // --- Remote Access Trojans (RATs) ---
  {
    name: "Cobalt Strike",
    type: "RAT / C2 framework",
    description: "Commercial adversary simulation and red team tool widely abused by threat actors. Provides sophisticated post-exploitation capabilities including process injection, lateral movement, and flexible C2. Beacon payloads support HTTP, HTTPS, DNS, and SMB channels.",
    iocs: ["Malleable C2 profiles", "Named pipes (MSSE-[0-9]+-server)", "Default SSL certificate (serial 146473198)", "Beacon process injection patterns", "Watermarked payloads"],
    ttps: ["T1059 Command and Scripting Interpreter", "T1055 Process Injection", "T1071 Application Layer Protocol", "T1021 Remote Services", "T1105 Ingress Tool Transfer"],
    detection: "Monitor for Cobalt Strike beacon patterns. Track named pipe creation. Detect default or known Cobalt Strike SSL certificates. Analyze HTTPS traffic for malleable C2 profiles. Hunt for in-memory beacon artifacts."
  },
  {
    name: "Mimikatz",
    type: "credential dumping tool",
    description: "Post-exploitation tool for extracting credentials from Windows systems. Dumps LSASS memory, performs Kerberos attacks (Golden Ticket, Silver Ticket, Pass-the-Hash), and manipulates Windows security tokens.",
    iocs: ["mimikatz.exe", "sekurlsa::logonpasswords command", "lsadump::dcsync command", "Process access to lsass.exe", "Token manipulation events"],
    ttps: ["T1003 OS Credential Dumping", "T1558 Steal or Forge Kerberos Tickets", "T1134 Access Token Manipulation", "T1550 Use Alternate Authentication Material"],
    detection: "Protect LSASS with PPL or Credential Guard. Monitor for LSASS process access. Track DCSync replication requests. Detect known Mimikatz binary signatures and command patterns."
  },
  {
    name: "PlugX",
    type: "RAT",
    description: "Modular RAT used extensively by Chinese APT groups. Features DLL side-loading for execution, encrypted C2 communications, and extensible plugin architecture. Recent variants spread via USB drives. Decades of continuous development.",
    iocs: ["DLL side-loading patterns (legitimate exe + malicious DLL)", "USB spreading component", "Encrypted C2 traffic patterns", "Registry persistence keys", "Hidden directories on USB drives"],
    ttps: ["T1574 Hijack Execution Flow", "T1071 Application Layer Protocol", "T1055 Process Injection", "T1547 Boot or Logon Autostart Execution", "T1091 Replication Through Removable Media"],
    detection: "Monitor for DLL side-loading patterns. Track USB drive hidden directory creation. Detect encrypted C2 traffic to known PlugX infrastructure. Watch for legitimate application loading unsigned DLLs."
  },
  {
    name: "ShadowPad",
    type: "RAT / backdoor",
    description: "Sophisticated modular backdoor used as the successor to PlugX, associated with multiple Chinese APT groups. Features encrypted communications, modular plugin system, and supply chain compromise delivery. First discovered in the CCleaner supply chain attack.",
    iocs: ["Encrypted plugin modules", "DNS-based C2 communications", "Custom DNS TXT record protocol", "Registry-stored encrypted payload", "Time-delayed activation"],
    ttps: ["T1195 Supply Chain Compromise", "T1071 Application Layer Protocol", "T1059 Command and Scripting Interpreter", "T1027 Obfuscated Files", "T1055 Process Injection"],
    detection: "Monitor for supply chain compromise indicators. Track unusual DNS TXT queries. Detect encrypted payload storage in registry. Analyze for modular malware loading patterns."
  },
  {
    name: "Quasar RAT",
    type: "RAT",
    description: "Open-source .NET RAT available on GitHub. Provides remote desktop, keylogging, file management, and reverse proxy capabilities. Widely used by both APT groups and cybercriminals due to free availability and ease of modification.",
    iocs: ["Quasar.Common namespace strings", ".NET compiled binary indicators", "Registry persistence (CurrentVersion\\Run)", "Mutex patterns (QSR_MUTEX_*)", "Default C2 port 4782"],
    ttps: ["T1059 Command and Scripting Interpreter", "T1056 Input Capture", "T1113 Screen Capture", "T1547 Boot or Logon Autostart Execution", "T1071 Application Layer Protocol"],
    detection: "Monitor for .NET binaries with Quasar namespace strings. Track registry persistence indicators. Detect default C2 port connections. Watch for keylogger and screen capture behavior."
  },
  {
    name: "AsyncRAT",
    type: "RAT",
    description: "Open-source .NET RAT with keylogging, screen capture, file transfer, and remote shell capabilities. Highly popular in phishing campaigns due to its free availability and active development. Supports plugin extensions.",
    iocs: ["AsyncClient namespace strings", ".NET compiled binary indicators", "Registry persistence (CurrentVersion\\Run)", "Mutex patterns (AsyncMutex_*)", "AES-encrypted C2 communications"],
    ttps: ["T1059 Command and Scripting Interpreter", "T1056 Input Capture", "T1113 Screen Capture", "T1547 Boot or Logon Autostart Execution", "T1071 Application Layer Protocol"],
    detection: "Monitor for .NET binaries with AsyncClient namespaces. Track scheduled task creation for persistence. Detect AES-encrypted C2 traffic. Watch for phishing delivery campaigns."
  },
  {
    name: "Remcos RAT",
    type: "RAT",
    description: "Commercial surveillance tool marketed as Remote Control and Surveillance software. Frequently abused by threat actors. Features include keylogging, screen/webcam capture, audio recording, and credential harvesting.",
    iocs: ["Remcos mutex patterns", "remcos.exe or remcos_agent.exe", "Registry entries under HKCU\\Software\\Remcos-*", "Encrypted log files", "C2 traffic on configurable ports"],
    ttps: ["T1059 Command and Scripting Interpreter", "T1056 Input Capture", "T1113 Screen Capture", "T1125 Video Capture", "T1123 Audio Capture"],
    detection: "Monitor for Remcos-specific registry artifacts. Track execution of known Remcos binaries. Detect encrypted log file creation. Watch for audio/video capture API usage."
  },
  {
    name: "njRAT",
    type: "RAT",
    description: "Widely used RAT originating from the Middle East. Written in .NET, provides keylogging, webcam access, file management, and remote shell capabilities. Extremely prevalent due to its simplicity and wide availability.",
    iocs: [".NET compiled binary with im523 namespace", "Registry persistence entries", "USB spreading module", "Keylog files in %TEMP%", "C2 traffic using custom protocol"],
    ttps: ["T1059 Command and Scripting Interpreter", "T1056 Input Capture", "T1113 Screen Capture", "T1547 Boot or Logon Autostart Execution", "T1091 Replication Through Removable Media"],
    detection: "Monitor for .NET binaries with njRAT namespace strings. Track USB autorun modifications. Detect keylog file creation in temp directories. Watch for C2 traffic patterns."
  },
  {
    name: "DarkComet",
    type: "RAT",
    description: "Legacy RAT that was widely used in the early 2010s, notably by the Syrian regime for surveillance of dissidents. Features include remote desktop, keylogging, webcam capture, and system manipulation.",
    iocs: ["DarkComet mutex patterns (DC_MUTEX-*)", "Registry persistence entries", "Process names (darkcomet.exe)", "Keylog files", "Password dumping modules"],
    ttps: ["T1059 Command and Scripting Interpreter", "T1056 Input Capture", "T1113 Screen Capture", "T1547 Boot or Logon Autostart Execution", "T1071 Application Layer Protocol"],
    detection: "Monitor for DarkComet-specific mutex names. Track legacy RAT indicators. Detect characteristic process injection patterns."
  },
  {
    name: "Brute Ratel C4",
    type: "RAT / C2 framework",
    description: "Commercial red team tool designed to evade EDR detection. Uses syscall-level API calls instead of higher-level APIs. Supports DOH (DNS-over-HTTPS) and other evasive C2 channels. Cracked versions widely used by threat actors.",
    iocs: ["Badger payloads (shellcode-based)", "DOH C2 communications", "SMB named pipe C2", "syscall-based NTAPI invocations", "Memory-only execution patterns"],
    ttps: ["T1059 Command and Scripting Interpreter", "T1055 Process Injection", "T1071 Application Layer Protocol", "T1572 Protocol Tunneling", "T1027 Obfuscated Files"],
    detection: "Monitor for DOH-based C2 patterns. Track syscall-level operations for anomalous patterns. Detect memory-only payload execution. Watch for SMB named pipe C2 communication."
  },
  {
    name: "Sliver",
    type: "RAT / C2 framework",
    description: "Open-source adversary emulation framework increasingly used as a Cobalt Strike alternative. Written in Go. Supports HTTP(S), mTLS, WireGuard, and DNS C2 channels. Cross-platform implants for Windows, macOS, and Linux.",
    iocs: ["Go-compiled binaries", "mTLS C2 communications", "WireGuard tunnel C2", "DNS canary domain queries", "Cross-platform implant indicators"],
    ttps: ["T1059 Command and Scripting Interpreter", "T1055 Process Injection", "T1071 Application Layer Protocol", "T1573 Encrypted Channel", "T1572 Protocol Tunneling"],
    detection: "Monitor for Go-compiled C2 implants. Track mTLS connections to unknown servers. Detect WireGuard tunnel establishment to unusual endpoints. Watch for DNS-based C2 patterns."
  },

  // --- Botnets ---
  {
    name: "Emotet",
    type: "botnet / loader",
    description: "Highly sophisticated modular botnet that evolved from a banking Trojan to become a primary initial access broker. Delivered via spam campaigns with malicious documents. Serves as a loader for follow-on payloads including TrickBot and ransomware.",
    iocs: ["Epoch infrastructure (Epoch 1-5)", "Malicious Office documents with macros", "Registry persistence entries", "Encrypted C2 HTTP POST traffic", "Process injection into legitimate processes"],
    ttps: ["T1566 Phishing", "T1059 Command and Scripting Interpreter", "T1055 Process Injection", "T1547 Boot or Logon Autostart Execution", "T1071 Application Layer Protocol"],
    detection: "Monitor for Emotet spam campaign indicators. Track malicious macro execution. Detect Emotet C2 traffic patterns. Watch for follow-on payload delivery."
  },
  {
    name: "TrickBot",
    type: "botnet / banking trojan",
    description: "Modular banking Trojan and botnet that evolved into a comprehensive crimeware platform. Used for credential theft, network reconnaissance, and as a loader for ransomware (Ryuk, Conti). Linked to Wizard Spider.",
    iocs: ["gtag campaign identifiers", "Encrypted C2 communications", "Signed module downloads", "EternalBlue spreading module", "Anchor DNS C2 variant"],
    ttps: ["T1059 Command and Scripting Interpreter", "T1055 Process Injection", "T1003 OS Credential Dumping", "T1210 Exploitation of Remote Services", "T1071 Application Layer Protocol"],
    detection: "Monitor for TrickBot gtag campaign indicators. Track module download and loading patterns. Detect web injection configurations. Watch for network spreading attempts."
  },
  {
    name: "QakBot (QBot)",
    type: "botnet / banking trojan",
    description: "Long-running banking Trojan and botnet active since 2007. Functions as initial access broker for ransomware operations (Black Basta, REvil). Distributed through phishing with malicious documents and HTML smuggling.",
    iocs: ["Campaign ID tags (obama, biden, etc.)", "DLL loading from %TEMP%", "Scheduled task persistence", "Encrypted C2 HTTP traffic", "Thread hijacking for email spreading"],
    ttps: ["T1566 Phishing", "T1059 Command and Scripting Interpreter", "T1055 Process Injection", "T1053 Scheduled Task", "T1071 Application Layer Protocol"],
    detection: "Monitor for QakBot DLL loading patterns. Track scheduled task creation for persistence. Detect thread hijacking in email clients. Watch for C2 traffic to known QakBot infrastructure. Note: Partially disrupted by FBI operation Aug 2023."
  },
  {
    name: "Mirai",
    type: "botnet / IoT malware",
    description: "IoT botnet that infects Linux-based devices using default credentials. Used primarily for DDoS attacks. Source code release in 2016 spawned numerous variants. Continues to be one of the most prevalent IoT threats.",
    iocs: ["Telnet brute force using default credentials", "Self-propagating worm behavior", "SYN/ACK/UDP/DNS flood capabilities", "Architecture-specific binaries (MIPS, ARM, x86)", "Killing competing malware processes"],
    ttps: ["T1110 Brute Force", "T1498 Network Denial of Service", "T1059 Command and Scripting Interpreter", "T1496 Resource Hijacking"],
    detection: "Monitor for Telnet brute force activity. Track IoT device anomalous behavior. Detect DDoS traffic generation. Watch for default credential login attempts. Segment IoT networks."
  },
  {
    name: "BotenaGo",
    type: "botnet / IoT malware",
    description: "Go-based IoT botnet exploiting over 30 vulnerabilities in routers, modems, and NAS devices. Relatively small binary size. Creates backdoors for follow-on payloads including Mirai variants.",
    iocs: ["Go-compiled Linux binaries", "Exploitation of 30+ CVEs", "Backdoor listener on multiple ports", "Router and NAS targeting", "Small binary footprint"],
    ttps: ["T1190 Exploit Public-Facing Application", "T1059 Command and Scripting Interpreter", "T1496 Resource Hijacking"],
    detection: "Monitor IoT devices for unusual outbound connections. Track exploitation attempts against known router CVEs. Detect Go-compiled malware on IoT devices."
  },

  // --- Rootkits ---
  {
    name: "Demodex",
    type: "rootkit",
    description: "Windows rootkit associated with Chinese APT group GhostEmperor (Salt Typhoon). Operates in kernel mode to hide malicious activity. Uses a multi-stage loading process to evade detection.",
    iocs: ["Kernel-mode driver loading", "Multi-stage loader chain", "Cheat Engine anti-cheat bypass driver abuse", "Registry-stored encrypted payloads", "Process and file hiding"],
    ttps: ["T1014 Rootkit", "T1542 Pre-OS Boot", "T1055 Process Injection", "T1564 Hide Artifacts", "T1562 Impair Defenses"],
    detection: "Monitor for suspicious kernel driver loading. Track driver signing certificate anomalies. Implement kernel integrity checking. Detect rootkit indicators through cross-view analysis."
  },
  {
    name: "Uroburos (Snake)",
    type: "rootkit / RAT",
    description: "Sophisticated rootkit and espionage platform attributed to Turla (FSB). Features peer-to-peer C2 networking, custom encrypted virtual file system, and advanced anti-forensics. Operated for nearly 20 years before takedown in 2023.",
    iocs: ["Custom encrypted virtual file system", "Named pipe C2 (\\\\pipe\\...)", "Kernel-mode rootkit component", "P2P network between infected nodes", "Anti-forensics and log cleaning"],
    ttps: ["T1014 Rootkit", "T1071 Application Layer Protocol", "T1027 Obfuscated Files", "T1070 Indicator Removal", "T1564 Hide Artifacts"],
    detection: "Monitor for Snake-specific named pipe patterns. Track kernel driver anomalies. Detect P2P communication between internal hosts. Watch for virtual file system artifacts. FBI Perseus tool available for remediation."
  },
  {
    name: "BlackLotus",
    type: "bootkit / rootkit",
    description: "First UEFI bootkit to bypass Secure Boot on fully patched Windows 11 systems. Sold on underground forums for $5000. Exploits CVE-2022-21894 (Baton Drop) to bypass Secure Boot and persist below the OS.",
    iocs: ["UEFI boot partition modification", "Secure Boot bypass indicators", "Boot configuration changes", "HTTP downloader component", "Kernel driver loading during boot"],
    ttps: ["T1542 Pre-OS Boot", "T1014 Rootkit", "T1562 Impair Defenses", "T1553 Subvert Trust Controls"],
    detection: "Monitor UEFI boot partition integrity. Track Secure Boot configuration changes. Implement firmware scanning. Detect boot sequence modifications. Apply CVE-2022-21894 mitigations."
  },
  {
    name: "CosmicStrand",
    type: "rootkit / UEFI implant",
    description: "UEFI firmware rootkit attributed to Chinese-speaking threat actor. Modifies UEFI firmware to deploy kernel-level implant that survives OS reinstallation. Targets specific ASUS and Gigabyte motherboards.",
    iocs: ["Modified UEFI firmware images", "Kernel-level shellcode execution", "Specific motherboard model targeting (ASUS, Gigabyte)", "HTTP-based C2 in kernel mode", "Firmware image hash mismatches"],
    ttps: ["T1542 Pre-OS Boot", "T1014 Rootkit", "T1027 Obfuscated Files", "T1071 Application Layer Protocol"],
    detection: "Implement firmware integrity verification. Track UEFI firmware updates. Compare firmware hashes against known-good baselines. Monitor for unauthorized firmware modifications."
  },

  // --- Wipers ---
  {
    name: "NotPetya",
    type: "wiper / fake ransomware",
    description: "Destructive wiper disguised as Petya ransomware. Attributed to Sandworm (GRU). Spread through compromised MeDoc accounting software update mechanism in Ukraine, causing $10B+ in global damages. Uses EternalBlue and Mimikatz for lateral movement.",
    iocs: ["MeDoc update mechanism compromise", "EternalBlue exploitation (MS17-010)", "Mimikatz credential harvesting", "MBR/MFT overwrite", "Fake Petya ransom demand"],
    ttps: ["T1195 Supply Chain Compromise", "T1210 Exploitation of Remote Services", "T1561 Disk Wipe", "T1486 Data Encrypted for Impact", "T1003 OS Credential Dumping"],
    detection: "Monitor for MeDoc-related IoCs. Detect EternalBlue exploitation. Track MBR/MFT modification attempts. Watch for Mimikatz credential dumping. Verify ransomware payment mechanisms (NotPetya had no recovery)."
  },
  {
    name: "WhisperGate",
    type: "wiper",
    description: "Multi-stage destructive wiper deployed against Ukrainian organizations in January 2022, prior to the Russian invasion. Disguised as ransomware but had no recovery mechanism. Overwrites MBR and corrupts files.",
    iocs: ["MBR overwrite with fake ransom note", "Stage1.exe MBR corruptor", "stage2.exe file corruptor", "Discord CDN for payload download", "WhisperKill file corruptor component"],
    ttps: ["T1561 Disk Wipe", "T1485 Data Destruction", "T1486 Data Encrypted for Impact", "T1059 Command and Scripting Interpreter"],
    detection: "Monitor for MBR write operations. Track Discord CDN downloads of executables. Detect mass file corruption patterns. Watch for fake ransomware with no viable payment mechanism."
  },
  {
    name: "HermeticWiper",
    type: "wiper",
    description: "Destructive wiper deployed against Ukrainian organizations on February 23, 2022, one day before the Russian invasion. Abuses signed EaseUS Partition Master driver to corrupt disk partitions. Accompanied by HermeticWizard spreading worm.",
    iocs: ["Signed EaseUS Partition Master driver abuse", "MBR and partition table corruption", "HermeticWizard WMI/SMB spreading", "HermeticRansom Go-based decoy ransomware", "Timestomped compilation dates"],
    ttps: ["T1561 Disk Wipe", "T1485 Data Destruction", "T1210 Exploitation of Remote Services", "T1036 Masquerading"],
    detection: "Monitor for abuse of signed partition management drivers. Track disk partition modifications. Detect WMI and SMB-based lateral movement. Watch for Go-based ransomware deployed alongside wiper."
  },
  {
    name: "AcidRain",
    type: "wiper",
    description: "ELF wiper targeting modems and routers, deployed against Viasat KA-SAT satellite modems on February 24, 2022 during the Ukraine invasion. Wiped flash memory and rendered devices inoperable. Attributed to Sandworm.",
    iocs: ["ELF binary targeting MIPS architecture", "Flash memory wiping (MTD/eMMC)", "Recursive device file overwriting", "/dev/* pattern overwrite", "Satellite modem targeting"],
    ttps: ["T1561 Disk Wipe", "T1485 Data Destruction", "T1495 Firmware Corruption"],
    detection: "Monitor for unusual flash memory operations on embedded devices. Track satellite communication disruptions. Detect ELF malware targeting MIPS/ARM architectures."
  },
  {
    name: "CaddyWiper",
    type: "wiper",
    description: "Destructive wiper deployed against Ukrainian organizations in March 2022. Erases user data, partition information, and overwrites files. Deployed through Group Policy in targeted environments.",
    iocs: ["File content overwrite with zeros", "Partition table destruction", "GPO-based deployment", "Small binary size (~9KB)", "No spreading capability (requires AD deployment)"],
    ttps: ["T1561 Disk Wipe", "T1485 Data Destruction", "T1484 Domain Policy Modification"],
    detection: "Monitor for GPO-based malware deployment. Track mass file overwriting with null bytes. Detect partition table modification attempts."
  },
  {
    name: "Shamoon (Disttrack)",
    type: "wiper",
    description: "Destructive wiper first used against Saudi Aramco in 2012, wiping 35,000 systems. Attributed to Iran (APT33). Uses legitimate RawDisk driver for direct disk access. Reappeared in 2016 and 2018 campaigns.",
    iocs: ["RawDisk driver abuse (EldoS)", "MBR overwrite with burning US flag image", "Scheduled execution via named task", "Credential harvesting module", "Spreading via network shares"],
    ttps: ["T1561 Disk Wipe", "T1485 Data Destruction", "T1053 Scheduled Task", "T1003 OS Credential Dumping", "T1021 Remote Services"],
    detection: "Monitor for EldoS RawDisk driver loading. Track MBR write operations. Detect scheduled task creation for delayed execution. Watch for mass SMB-based file deployment."
  },

  // --- Information Stealers ---
  {
    name: "Raccoon Stealer",
    type: "infostealer",
    description: "MaaS (Malware-as-a-Service) information stealer targeting browser credentials, cryptocurrency wallets, and system information. Sold on underground forums. Version 2.0 rewritten in C/C++ with improved evasion.",
    iocs: ["Browser credential extraction", "Cryptocurrency wallet file theft", "Screenshot capture", "Telegram C2 bot communication", "machineinfo.txt reconnaissance file"],
    ttps: ["T1555 Credentials from Password Stores", "T1005 Data from Local System", "T1113 Screen Capture", "T1041 Exfiltration Over C2 Channel", "T1082 System Information Discovery"],
    detection: "Monitor for browser credential store access. Track cryptocurrency wallet file access. Detect Telegram API C2 communications. Watch for system reconnaissance data collection."
  },
  {
    name: "RedLine Stealer",
    type: "infostealer",
    description: "Widely distributed information stealer targeting browser data, cryptocurrency wallets, VPN credentials, and system information. Sold as MaaS on underground forums. Major initial access vector for ransomware operations.",
    iocs: ["Browser credential and cookie extraction", "Cryptocurrency wallet targeting", "VPN credential theft (NordVPN, OpenVPN)", "FTP credential harvesting", "Telegram or dedicated panel C2"],
    ttps: ["T1555 Credentials from Password Stores", "T1539 Steal Web Session Cookie", "T1005 Data from Local System", "T1082 System Information Discovery", "T1041 Exfiltration Over C2 Channel"],
    detection: "Monitor for browser credential database access. Track cryptocurrency wallet file reads. Detect VPN configuration file access. Watch for bulk credential exfiltration."
  },
  {
    name: "Vidar Stealer",
    type: "infostealer",
    description: "Information stealer forked from Arkei stealer. Targets browser data, cryptocurrency wallets, 2FA applications, and Telegram session data. Uses dead drop resolvers on social media for C2 configuration.",
    iocs: ["Social media dead drop resolvers", "Browser data extraction", "2FA application data theft", "Telegram session hijacking", "C2 configuration embedded in social media profiles"],
    ttps: ["T1555 Credentials from Password Stores", "T1539 Steal Web Session Cookie", "T1102 Web Service", "T1005 Data from Local System", "T1082 System Information Discovery"],
    detection: "Monitor for social media API queries from malware. Track 2FA application data file access. Detect Telegram session file theft. Watch for dead drop resolver patterns."
  },
  {
    name: "Lumma Stealer",
    type: "infostealer",
    description: "Rapidly growing MaaS information stealer written in C. Targets browser credentials, cryptocurrency wallets, and 2FA extensions. Uses advanced evasion techniques including sandbox detection and encrypted C2.",
    iocs: ["Browser credential and cookie theft", "Cryptocurrency wallet extraction", "2FA browser extension targeting", "Encrypted C2 HTTP traffic", "Sandbox detection routines"],
    ttps: ["T1555 Credentials from Password Stores", "T1539 Steal Web Session Cookie", "T1497 Virtualization/Sandbox Evasion", "T1005 Data from Local System", "T1573 Encrypted Channel"],
    detection: "Monitor for browser credential store access. Track cryptocurrency wallet file reads. Detect sandbox detection behavior. Watch for encrypted HTTP C2 patterns."
  },
  {
    name: "FormBook / XLoader",
    type: "infostealer",
    description: "Form-grabbing and keylogging malware targeting Windows and macOS (as XLoader). Captures form data from browsers, logs keystrokes, and steals clipboard data. Sold as MaaS since 2016.",
    iocs: ["Browser form data interception", "Keylogger functionality", "Screenshot capture", "Process hollowing into legitimate processes", "RC4 encrypted C2 traffic with decoy URLs"],
    ttps: ["T1056 Input Capture", "T1185 Browser Session Hijacking", "T1055 Process Injection", "T1113 Screen Capture", "T1071 Application Layer Protocol"],
    detection: "Monitor for process hollowing into explorer.exe or other legitimate processes. Track browser API hooking. Detect RC4 encrypted HTTP POST traffic with decoy URL patterns."
  },
  {
    name: "Agent Tesla",
    type: "infostealer / RAT",
    description: "Popular .NET-based infostealer and RAT active since 2014. Features keylogging, screen capture, browser credential theft, and clipboard monitoring. Delivered primarily through phishing. Exfiltrates via SMTP, FTP, or HTTP.",
    iocs: [".NET compiled binary indicators", "SMTP-based data exfiltration", "Keylog file creation", "Registry persistence", "Browser credential database extraction"],
    ttps: ["T1056 Input Capture", "T1555 Credentials from Password Stores", "T1113 Screen Capture", "T1115 Clipboard Data", "T1048 Exfiltration Over Alternative Protocol"],
    detection: "Monitor for .NET binaries with Agent Tesla signatures. Track SMTP traffic for data exfiltration. Detect browser credential store access. Watch for keylogger indicators."
  },

  // --- Loaders / Droppers ---
  {
    name: "BazarLoader",
    type: "loader",
    description: "Backdoor/loader linked to the TrickBot/Conti ecosystem (Wizard Spider). Used as initial access for enterprise ransomware deployments. Written in C++, uses EmerDNS (.bazar domains) for resilient C2.",
    iocs: [".bazar domain C2", "Signed binary delivery via email", "Scheduled task persistence", "Encrypted C2 communications", "Process injection into svchost.exe"],
    ttps: ["T1566 Phishing", "T1059 Command and Scripting Interpreter", "T1055 Process Injection", "T1053 Scheduled Task", "T1071 Application Layer Protocol"],
    detection: "Monitor for .bazar domain resolution. Track signed binary execution from email attachments. Detect process injection into system processes. Watch for follow-on Cobalt Strike deployment."
  },
  {
    name: "IcedID (BokBot)",
    type: "loader / banking trojan",
    description: "Banking trojan evolved into a major loader for ransomware operations. Delivered through phishing with malicious documents or ISO files. Serves as initial access for Conti, Quantum, and other ransomware groups.",
    iocs: ["ISO/IMG file delivery containing DLL", "Scheduled task persistence", "Encrypted C2 HTTPS traffic", "Browser injection for banking fraud", "Cobalt Strike follow-on payload"],
    ttps: ["T1566 Phishing", "T1059 Command and Scripting Interpreter", "T1055 Process Injection", "T1053 Scheduled Task", "T1185 Browser Session Hijacking"],
    detection: "Monitor for ISO file delivery via phishing. Track DLL execution from mounted images. Detect browser injection for credential theft. Watch for Cobalt Strike beacon deployment."
  },
  {
    name: "Gootloader",
    type: "loader",
    description: "JavaScript-based loader distributed through SEO poisoning of WordPress sites. Targets users searching for business documents (contracts, agreements). Delivers follow-on payloads including Cobalt Strike, REvil, and SystemBC.",
    iocs: ["SEO-poisoned WordPress sites", "ZIP files containing .js payloads", "Staged payload download via compromised sites", "Registry-stored payloads", "Obfuscated JavaScript execution"],
    ttps: ["T1189 Drive-by Compromise", "T1059 Command and Scripting Interpreter", "T1112 Modify Registry", "T1027 Obfuscated Files", "T1105 Ingress Tool Transfer"],
    detection: "Monitor for JavaScript execution from downloaded ZIP files. Track registry-based payload storage. Detect SEO poisoning campaign indicators. Watch for staged download patterns."
  },
  {
    name: "SystemBC",
    type: "proxy / loader",
    description: "Proxy bot used as a persistence mechanism and C2 proxy in ransomware operations. Creates SOCKS5 proxy tunnels through victim networks. Used by multiple ransomware affiliates as infrastructure tooling.",
    iocs: ["SOCKS5 proxy functionality", "Tor hidden service C2", "Scheduled task persistence", "Small binary size", "XOR-encrypted C2 traffic"],
    ttps: ["T1090 Proxy", "T1059 Command and Scripting Interpreter", "T1053 Scheduled Task", "T1573 Encrypted Channel", "T1105 Ingress Tool Transfer"],
    detection: "Monitor for SOCKS5 proxy establishment. Track Tor traffic from non-browser processes. Detect scheduled task persistence. Watch for XOR-encrypted C2 communications."
  },

  // --- Additional Notable Malware ---
  {
    name: "Stuxnet",
    type: "cyberweapon / worm",
    description: "Sophisticated cyberweapon targeting Iranian nuclear centrifuges (Siemens S7-300 PLCs). First known cyberweapon to cause physical destruction. Used four zero-day exploits. Attributed to US/Israel (Equation Group).",
    iocs: ["Siemens WinCC/Step 7 targeting", "USB spreading via LNK vulnerability", "Rootkit driver signed with stolen certificates", "PLC code manipulation", "Four zero-day exploit chain"],
    ttps: ["T1091 Replication Through Removable Media", "T1203 Exploitation for Client Execution", "T1014 Rootkit", "T1195 Supply Chain Compromise"],
    detection: "Historical significance -- monitoring for variants and descendants. Track ICS/SCADA system anomalies. Monitor PLC program modifications. Implement network segmentation for OT."
  },
  {
    name: "Pegasus",
    type: "spyware",
    description: "Commercial spyware developed by NSO Group for mobile device surveillance. Targets iOS and Android using zero-click exploits. Capable of extracting messages, calls, photos, and activating camera/microphone remotely.",
    iocs: ["Zero-click iMessage exploits", "FORCEDENTRY / BLASTPASS exploit chains", "Unique process names on iOS", "Anomalous network traffic from mobile devices", "Lookout/Amnesty forensic indicators"],
    ttps: ["T1203 Exploitation for Client Execution", "T1056 Input Capture", "T1113 Screen Capture", "T1123 Audio Capture", "T1125 Video Capture"],
    detection: "Use Mobile Verification Toolkit (MVT) for iOS forensics. Track anomalous iMessage processing. Detect unusual mobile data exfiltration. Monitor for zero-click exploit indicators."
  },
  {
    name: "Predator",
    type: "spyware",
    description: "Commercial spyware developed by Cytrox/Intellexa. Targets Android and iOS devices using one-click and zero-click exploits. Provides full device access including messages, calls, camera, and microphone.",
    iocs: ["Exploit chain delivery via SMS/WhatsApp links", "Alien loader component", "Python-based implant modules", "Encrypted C2 communications", "Mobile device jailbreak/root indicators"],
    ttps: ["T1203 Exploitation for Client Execution", "T1056 Input Capture", "T1113 Screen Capture", "T1123 Audio Capture", "T1573 Encrypted Channel"],
    detection: "Monitor for suspicious SMS links on managed devices. Track mobile device compromise indicators. Use forensic tools to detect spyware artifacts."
  }
];


// -----------------------------------------------------------------------------
// 4. IOC PATTERNS -- Indicator of Compromise patterns and signatures
// -----------------------------------------------------------------------------

export const IOC_PATTERNS = [
  // --- Network Indicators: Suspicious Domains ---
  {
    type: "domain",
    pattern: "/^[a-z0-9]{12,}\\.(top|xyz|club|buzz|icu|tk|ml|ga|cf|gq)$/",
    description: "DGA-generated domains using cheap/free TLDs. Random alphanumeric strings with high entropy typical of domain generation algorithms.",
    falsePositiveNotes: "Some legitimate short domains use these TLDs. Check domain age and registration patterns."
  },
  {
    type: "domain",
    pattern: "/^[a-z]{4,8}\\d{1,4}\\.(com|net|org)$/",
    description: "Common C2 domain pattern: short word + numbers on mainstream TLDs. Used by commodity malware families.",
    falsePositiveNotes: "May match legitimate short domains. Verify with threat intelligence feeds and domain reputation."
  },
  {
    type: "domain",
    pattern: "/^(update|secure|login|verify|account|support|service|portal)[-.].*\\.(com|net|org|info)$/",
    description: "Phishing/C2 domains using trust-implying prefixes. Common in credential harvesting and social engineering campaigns.",
    falsePositiveNotes: "Legitimate services may use similar patterns. Check SSL certificate details and WHOIS data."
  },
  {
    type: "domain",
    pattern: "/^[a-z]{1,3}\\.[a-z]{1,3}\\.[a-z0-9-]+\\.(com|net|org)$/",
    description: "Multi-level subdomain pattern common in DNS tunneling and phishing infrastructure.",
    falsePositiveNotes: "CDN and cloud services use deep subdomains. Verify subdomain entropy and query volume."
  },
  {
    type: "domain",
    pattern: "/\\.(onion|i2p|bit|lib|emc)$/",
    description: "Dark web and alternative DNS domains (Tor hidden services, I2P, Namecoin). Common C2 fallback channels.",
    falsePositiveNotes: "Some privacy-focused legitimate services use these. Context of access matters."
  },
  {
    type: "domain",
    pattern: "/^[a-z0-9]+\\.duckdns\\.org$/",
    description: "DuckDNS dynamic DNS domains frequently abused by malware for resilient C2 infrastructure.",
    falsePositiveNotes: "DuckDNS has legitimate users. Correlate with other indicators and traffic patterns."
  },
  {
    type: "domain",
    pattern: "/^[a-z0-9]+\\.(no-ip|ddns|hopto|zapto|sytes|serveftp|servehttp)\\.(com|net|org|biz)$/",
    description: "Dynamic DNS domains commonly abused by RATs and botnets for C2 infrastructure.",
    falsePositiveNotes: "Dynamic DNS has many legitimate use cases (home servers, IoT). Verify with traffic analysis."
  },
  {
    type: "domain",
    pattern: "/^[a-z0-9-]+\\.(workers\\.dev|pages\\.dev|r2\\.dev)$/",
    description: "Cloudflare serverless and CDN domains abused for phishing, C2 proxying, and payload hosting.",
    falsePositiveNotes: "Cloudflare services have millions of legitimate users. Analyze content and request patterns."
  },

  // --- Network Indicators: IP Patterns ---
  {
    type: "ip",
    pattern: "/^(185\\.(220|234|243)|91\\.(215|234)|45\\.(133|142|155)|193\\.(56|106|142|239))\\./",
    description: "IP ranges commonly associated with bulletproof hosting providers used by threat actors for C2 and malware hosting.",
    falsePositiveNotes: "Some legitimate services may be hosted in these ranges. Validate against current threat intelligence."
  },
  {
    type: "ip",
    pattern: "/^(10|172\\.(1[6-9]|2[0-9]|3[01])|192\\.168)\\./",
    description: "RFC 1918 private IP addresses. In external traffic, indicates misconfiguration, NAT leakage, or tunneled traffic.",
    falsePositiveNotes: "Normal in internal network traffic. Suspicious only when seen in external communication logs."
  },
  {
    type: "ip",
    pattern: "Tor exit node IP addresses",
    description: "Known Tor exit node addresses. Inbound connections may indicate anonymized attack traffic. Outbound connections may indicate data exfiltration or C2.",
    falsePositiveNotes: "Some users legitimately use Tor for privacy. Check organizational policy and correlate with user activity."
  },
  {
    type: "ip",
    pattern: "VPN provider IP ranges (NordVPN, ExpressVPN, ProtonVPN, Mullvad)",
    description: "Commercial VPN provider IP ranges used by threat actors to anonymize attack traffic and evade geolocation-based detection.",
    falsePositiveNotes: "Employees may use personal VPNs. Organizational VPN policy determines whether this is a concern."
  },
  {
    type: "ip",
    pattern: "/^(198\\.51\\.100|203\\.0\\.113|233\\.252\\.0)\\./",
    description: "Documentation and test IP ranges (RFC 5737, RFC 6890). Should not appear in production traffic, may indicate test/debug code in production.",
    falsePositiveNotes: "May appear in log examples or documentation. Flag only in actual network traffic."
  },

  // --- Network Indicators: URL Patterns ---
  {
    type: "url",
    pattern: "/https?:\\/\\/[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+[\\/:].*\\.(exe|dll|ps1|bat|vbs|hta|js|wsf)$/",
    description: "Direct IP-based downloads of executable content. Bypasses domain-based reputation and is common in malware delivery.",
    falsePositiveNotes: "Internal tools may use IP-based URLs. Check if IP is internal and file type is expected."
  },
  {
    type: "url",
    pattern: "/https?:\\/\\/.*\\/(wp-content|wp-includes|wp-admin)\\/.*\\.(php|js)\\?[a-z]=[a-f0-9]{32}/",
    description: "Compromised WordPress sites used for malware hosting or C2. Suspicious PHP/JS files in WordPress directories with encoded parameters.",
    falsePositiveNotes: "Legitimate WordPress plugins may have similar URL patterns. Check file hash and content."
  },
  {
    type: "url",
    pattern: "/https?:\\/\\/discord(app)?\\.com\\/api\\/webhooks\\/[0-9]+\\//",
    description: "Discord webhook URLs abused by malware for C2 communication and data exfiltration through Discord's CDN infrastructure.",
    falsePositiveNotes: "Legitimate Discord integrations use webhooks. Verify the webhook belongs to an authorized integration."
  },
  {
    type: "url",
    pattern: "/https?:\\/\\/cdn\\.discordapp\\.com\\/attachments\\/[0-9]+\\/[0-9]+\\/.*\\.(exe|dll|zip|rar|7z)$/",
    description: "Discord CDN used for malware payload hosting. Threat actors upload payloads as attachments and distribute download URLs.",
    falsePositiveNotes: "Legitimate file sharing occurs on Discord. Focus on executable and archive downloads from unknown sources."
  },
  {
    type: "url",
    pattern: "/https?:\\/\\/paste(bin)?\\.com\\/raw\\/[A-Za-z0-9]+/",
    description: "Pastebin raw URLs used for hosting encoded payloads, C2 configurations, and dead drop resolvers by commodity malware.",
    falsePositiveNotes: "Developers and sysadmins legitimately use Pastebin. Analyze downloaded content for malicious indicators."
  },
  {
    type: "url",
    pattern: "/https?:\\/\\/transfer\\.sh\\/[A-Za-z0-9]+\\//",
    description: "Transfer.sh file sharing service abused for malware payload delivery and data exfiltration due to its anonymous upload capability.",
    falsePositiveNotes: "Legitimate file sharing service. Check file types and correlate with other suspicious activity."
  },
  {
    type: "url",
    pattern: "/https?:\\/\\/raw\\.githubusercontent\\.com\\/[A-Za-z0-9_-]+\\/[A-Za-z0-9_-]+\\//",
    description: "GitHub raw content URLs used for hosting payloads, C2 scripts, and configuration files. Leverages GitHub's trusted reputation.",
    falsePositiveNotes: "Very common in legitimate software. Investigate the repository and content being downloaded."
  },

  // --- File Indicators: Hashes ---
  {
    type: "hash_pattern",
    pattern: "/^[a-fA-F0-9]{32}$/ (MD5)",
    description: "MD5 hash format. Used for file integrity checking and IOC matching. Collision-vulnerable but still widely used in threat intelligence.",
    falsePositiveNotes: "Always cross-reference with multiple hash types. MD5 collisions are feasible for motivated attackers."
  },
  {
    type: "hash_pattern",
    pattern: "/^[a-fA-F0-9]{40}$/ (SHA-1)",
    description: "SHA-1 hash format. More collision-resistant than MD5 but considered deprecated for security purposes.",
    falsePositiveNotes: "Cross-reference with SHA-256 when possible. SHA-1 collision attacks are practical but expensive."
  },
  {
    type: "hash_pattern",
    pattern: "/^[a-fA-F0-9]{64}$/ (SHA-256)",
    description: "SHA-256 hash format. Current standard for file integrity verification and IOC sharing in threat intelligence.",
    falsePositiveNotes: "Preferred hash type for IOC matching. Verify hash source and recency of intelligence."
  },
  {
    type: "hash_pattern",
    pattern: "Imphash (Import Hash)",
    description: "PE import table hash for identifying malware families regardless of file modifications. Same imphash indicates similar functionality.",
    falsePositiveNotes: "Different malware families may share imphashes if they use similar libraries. Combine with other indicators."
  },
  {
    type: "hash_pattern",
    pattern: "SSDEEP / Fuzzy Hash",
    description: "Context-triggered piecewise hash for finding similar files. Useful for identifying malware variants with minor modifications.",
    falsePositiveNotes: "Similarity threshold must be tuned. High false positive rate if threshold is too low."
  },
  {
    type: "hash_pattern",
    pattern: "TLSH (Trend Micro Locality Sensitive Hash)",
    description: "Locality sensitive hash for finding similar files. More robust than SSDEEP for identifying malware variants across polymorphic samples.",
    falsePositiveNotes: "Better than SSDEEP for polymorphic malware but still requires tuned thresholds."
  },

  // --- File Indicators: Extensions and Names ---
  {
    type: "file_extension",
    pattern: "/\\.(hta|vbs|wsf|wsh|js|jse|vbe|sct|scr)$/i",
    description: "Windows script and executable extensions commonly used in malware delivery. These file types can execute code when opened.",
    falsePositiveNotes: "Legitimate administrative scripts may use these extensions. Investigate context and source."
  },
  {
    type: "file_extension",
    pattern: "/\\.(iso|img|vhd|vhdx)$/i",
    description: "Disk image formats used to deliver malware while bypassing Mark-of-the-Web (MOTW) protections in Windows.",
    falsePositiveNotes: "IT departments use disk images for legitimate purposes. Check delivery mechanism and contents."
  },
  {
    type: "file_extension",
    pattern: "/\\.(lnk|url|library-ms|settingcontent-ms)$/i",
    description: "Windows shortcut and settings files abused for malware execution. LNK files can execute arbitrary commands.",
    falsePositiveNotes: "LNK files are normal in Windows. Check for unexpected command-line arguments in LNK targets."
  },
  {
    type: "file_name",
    pattern: "/^(svchost|csrss|lsass|services|smss|wininit|winlogon)\\.(exe)$/i (in non-system directories)",
    description: "Legitimate Windows system process names used by malware in non-standard locations to evade detection through name masquerading.",
    falsePositiveNotes: "These process names are legitimate when running from C:\\Windows\\System32. Flag only when found elsewhere."
  },
  {
    type: "file_name",
    pattern: "/^[a-z0-9]{8}\\.(exe|dll|tmp)$/i",
    description: "Random 8-character alphanumeric filenames typical of malware droppers and temporary payloads.",
    falsePositiveNotes: "Some legitimate software generates random temporary filenames. Check file location and creation context."
  },
  {
    type: "file_name",
    pattern: "web shells: cmd.aspx, shell.php, r57.php, c99.php, b374k.php, China Chopper patterns",
    description: "Known web shell filenames and patterns commonly deployed by threat actors for persistent web server access.",
    falsePositiveNotes: "Legitimate PHP/ASP files may have generic names. Analyze file content for shell functionality."
  },
  {
    type: "file_path",
    pattern: "/^C:\\\\(Users\\\\[^\\\\]+\\\\AppData\\\\(Local|Roaming)\\\\Temp|ProgramData|Windows\\\\Temp)\\\\[^\\\\]+\\.(exe|dll|bat|ps1|vbs)$/",
    description: "Executables in temporary and AppData directories, common staging locations for malware droppers and payloads.",
    falsePositiveNotes: "Legitimate installers and updaters use temp directories. Check digital signatures and parent process."
  },
  {
    type: "file_path",
    pattern: "/^C:\\\\Users\\\\Public\\\\.*\\.(exe|dll|bat|ps1)$/",
    description: "Executables in the Public user directory, frequently used by malware as a world-writable staging location.",
    falsePositiveNotes: "Some legitimate software installs to Public directories. Verify file origin and digital signature."
  },

  // --- Registry Indicators ---
  {
    type: "registry",
    pattern: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run (unexpected entries)",
    description: "Autostart registry key used by malware for persistence. Entries here execute on every user logon.",
    falsePositiveNotes: "Many legitimate applications add Run key entries. Verify publisher and binary path."
  },
  {
    type: "registry",
    pattern: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run (unexpected entries)",
    description: "Per-user autostart registry key commonly abused by malware for user-level persistence.",
    falsePositiveNotes: "User applications commonly set Run keys. Check against known software inventory."
  },
  {
    type: "registry",
    pattern: "HKLM\\SYSTEM\\CurrentControlSet\\Services (suspicious service entries)",
    description: "Windows service registry entries. Malware creates services for persistence and privilege escalation.",
    falsePositiveNotes: "Windows has many legitimate services. Focus on recently created services with unusual binary paths."
  },
  {
    type: "registry",
    pattern: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options (debugger entries)",
    description: "IFEO debugger entries used for persistence and defense evasion by redirecting execution of targeted binaries.",
    falsePositiveNotes: "Development tools may set IFEO entries for debugging. Check for unexpected debugger values."
  },
  {
    type: "registry",
    pattern: "HKCU\\SOFTWARE\\Classes\\CLSID\\{...}\\InProcServer32 (COM hijacking)",
    description: "COM object hijacking through CLSID registry modification for persistence and defense evasion.",
    falsePositiveNotes: "Legitimate COM registration is common. Focus on recently modified entries pointing to unusual DLLs."
  },
  {
    type: "registry",
    pattern: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders (modified paths)",
    description: "Shell folder path redirection for persistence or data collection by modifying where Windows looks for special folders.",
    falsePositiveNotes: "Folder redirection is used legitimately in enterprise environments. Verify changes are authorized."
  },
  {
    type: "registry",
    pattern: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SecurityProviders (SSP injection)",
    description: "Security Support Provider registration used by credential-stealing malware to intercept authentication.",
    falsePositiveNotes: "Additional SSPs are rare in most environments. Any new entry warrants investigation."
  },
  {
    type: "registry",
    pattern: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell (shell replacement)",
    description: "Winlogon shell replacement for persistence. Malware replaces or augments the default explorer.exe shell.",
    falsePositiveNotes: "Custom shells are used in kiosk environments. Any unexpected change is highly suspicious."
  },
  {
    type: "registry",
    pattern: "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware",
    description: "Registry key to disable Windows Defender. Commonly set by ransomware and other malware to evade endpoint protection.",
    falsePositiveNotes: "May be set by GPO when using third-party AV. Verify against organizational security policy."
  },
  {
    type: "registry",
    pattern: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA (UAC disabled)",
    description: "Registry key to disable User Account Control. Malware disables UAC to execute with elevated privileges without prompts.",
    falsePositiveNotes: "Extremely suspicious if changed without authorization. Some legacy applications require UAC disabled."
  },

  // --- Process/Behavior Indicators ---
  {
    type: "process",
    pattern: "powershell.exe -enc [base64] / -encodedcommand / -e [base64]",
    description: "Base64-encoded PowerShell commands. Heavily used by malware and attack tools to obfuscate malicious PowerShell execution.",
    falsePositiveNotes: "Some legitimate automation uses encoded commands. Decode and analyze the actual command content."
  },
  {
    type: "process",
    pattern: "powershell.exe with -nop -w hidden -exec bypass",
    description: "PowerShell execution with no profile, hidden window, and execution policy bypass. Classic malware and post-exploitation pattern.",
    falsePositiveNotes: "Some legitimate admin scripts use these flags. Investigate the full command line and parent process."
  },
  {
    type: "process",
    pattern: "cmd.exe /c wmic shadowcopy delete",
    description: "Shadow copy deletion via WMIC. Pre-ransomware encryption step to prevent file recovery from Volume Shadow Copies.",
    falsePositiveNotes: "Extremely suspicious in almost all contexts. May be part of legitimate backup rotation in rare cases."
  },
  {
    type: "process",
    pattern: "vssadmin.exe delete shadows /all /quiet",
    description: "Volume Shadow Copy deletion via vssadmin. Critical ransomware precursor activity to prevent recovery.",
    falsePositiveNotes: "Legitimate shadow copy management is typically done through backup software, not command-line deletion."
  },
  {
    type: "process",
    pattern: "bcdedit.exe /set {default} recoveryenabled No",
    description: "Disabling Windows Recovery Environment. Ransomware technique to prevent booting into recovery mode.",
    falsePositiveNotes: "Very rarely done legitimately. Investigate immediately upon detection."
  },
  {
    type: "process",
    pattern: "wbadmin.exe delete catalog -quiet",
    description: "Deleting Windows backup catalog. Another ransomware anti-recovery technique to prevent restoration from backups.",
    falsePositiveNotes: "Almost never legitimate. Flag with high confidence."
  },
  {
    type: "process",
    pattern: "certutil.exe -urlcache -split -f http://",
    description: "Using certutil for file download (LOLBin abuse). Certutil is a legitimate Windows tool abused as an alternative downloader.",
    falsePositiveNotes: "Certutil is legitimately used for certificate operations. Downloading files via URL cache is suspicious."
  },
  {
    type: "process",
    pattern: "mshta.exe http:// or mshta.exe vbscript:",
    description: "MSHTA execution of remote HTA files or inline scripts. Classic living-off-the-land technique for initial execution.",
    falsePositiveNotes: "HTA is rarely used legitimately in modern environments. Any execution warrants investigation."
  },
  {
    type: "process",
    pattern: "rundll32.exe executing from non-standard paths or with suspicious exports",
    description: "Rundll32 LOLBin abuse. Loading DLLs from temp directories or with uncommon export functions indicates malicious activity.",
    falsePositiveNotes: "Rundll32 is used legitimately by Windows. Check DLL path, export function name, and parent process."
  },
  {
    type: "process",
    pattern: "regsvr32.exe /s /n /u /i:http:// scrobj.dll (Squiblydoo)",
    description: "Regsvr32 COM scriptlet execution (Squiblydoo technique). Abuses regsvr32 to download and execute remote SCT files.",
    falsePositiveNotes: "Regsvr32 with /i: flag pointing to URLs is almost always malicious."
  },
  {
    type: "process",
    pattern: "bitsadmin.exe /transfer",
    description: "BITS transfer abuse for file downloads. Uses Windows Background Intelligent Transfer Service as a LOLBin downloader.",
    falsePositiveNotes: "BITS is used legitimately by Windows Update and SCCM. Check download URLs and destination paths."
  },
  {
    type: "process",
    pattern: "wmic.exe process call create",
    description: "Remote process creation via WMIC. Used for lateral movement by executing commands on remote systems.",
    falsePositiveNotes: "WMIC is used by system administrators. Check target systems and command content."
  },
  {
    type: "process",
    pattern: "schtasks.exe /create /sc onlogon|onstart|minute",
    description: "Scheduled task creation for persistence. Creating tasks that run at logon, startup, or frequent intervals.",
    falsePositiveNotes: "Legitimate software creates scheduled tasks. Investigate the task action, path, and creation context."
  },
  {
    type: "process",
    pattern: "nltest.exe /dclist: /domain_trusts /all_trusts",
    description: "Domain trust enumeration via nltest. Used in Active Directory reconnaissance to map trust relationships for lateral movement.",
    falsePositiveNotes: "IT administrators use nltest for AD troubleshooting. Check who is running it and from which system."
  },
  {
    type: "process",
    pattern: "net.exe user /add or net.exe localgroup administrators /add",
    description: "Local account creation and privilege escalation via net commands. Creating new admin accounts for persistent access.",
    falsePositiveNotes: "Legitimate account management occurs. Verify against change management and authorized personnel."
  },
  {
    type: "process",
    pattern: "psexec.exe or psexesvc.exe service creation",
    description: "PsExec remote execution tool. Creates a service on remote systems for command execution. Used for both admin tasks and lateral movement.",
    falsePositiveNotes: "PsExec is a legitimate admin tool. Monitor for unauthorized usage and unexpected source/destination pairs."
  },

  // --- Mutex/Named Object Indicators ---
  {
    type: "mutex",
    pattern: "Global\\\\[A-F0-9]{32}",
    description: "MD5-like mutex names used by malware to prevent multiple instances from running simultaneously.",
    falsePositiveNotes: "Some legitimate software uses hash-based mutex names. Cross-reference with known malware families."
  },
  {
    type: "mutex",
    pattern: "Specific known mutexes: QSR_MUTEX, DC_MUTEX, AsyncMutex, RasPPPoE, sadfhuhf",
    description: "Known malware family mutex names. Quasar RAT (QSR_MUTEX), DarkComet (DC_MUTEX), AsyncRAT (AsyncMutex).",
    falsePositiveNotes: "Definitive indicator when combined with other IOCs. Some may conflict with unusual legitimate software."
  },
  {
    type: "mutex",
    pattern: "/^[A-Z]{3,5}_MUTEX_[a-zA-Z0-9]+$/",
    description: "Common RAT mutex naming convention using uppercase prefix followed by _MUTEX_ and identifier.",
    falsePositiveNotes: "Pattern match only. Verify against known malware mutex databases."
  },

  // --- C2 Communication Patterns ---
  {
    type: "c2_pattern",
    pattern: "HTTP POST with fixed-interval beaconing (60s, 300s, 600s, 900s, 3600s)",
    description: "Regular-interval HTTP POST requests indicating C2 beacon communication. Consistent timing is a hallmark of automated malware C2.",
    falsePositiveNotes: "Health checks, telemetry, and update mechanisms may beacon regularly. Analyze beacon content and jitter."
  },
  {
    type: "c2_pattern",
    pattern: "DNS TXT queries with high entropy subdomains",
    description: "DNS tunneling indicator. High-entropy subdomain queries with TXT record responses used to encode data in DNS traffic.",
    falsePositiveNotes: "DKIM, SPF, and DMARC use DNS TXT records. Check query volume, subdomain length, and entropy."
  },
  {
    type: "c2_pattern",
    pattern: "HTTPS with self-signed certificates or certificates with unusual subject fields",
    description: "C2 encrypted communications using self-signed or anomalous TLS certificates to avoid content inspection.",
    falsePositiveNotes: "Development and internal services may use self-signed certificates. Check certificate details and endpoint."
  },
  {
    type: "c2_pattern",
    pattern: "HTTP requests with user-agent strings: 'Mozilla/4.0' or 'Mozilla/5.0' with outdated/inconsistent components",
    description: "Malware using outdated or inconsistent user-agent strings. Many malware families hardcode specific user-agent strings.",
    falsePositiveNotes: "Some legacy software uses old user-agent strings. Analyze the full user-agent for consistency."
  },
  {
    type: "c2_pattern",
    pattern: "ICMP packets with payloads exceeding normal size (>64 bytes data)",
    description: "ICMP tunneling indicator. Oversized ICMP echo payloads used to tunnel data through networks that allow ICMP traffic.",
    falsePositiveNotes: "Network testing tools (ping with size options) may generate large ICMP packets. Check frequency and destinations."
  },
  {
    type: "c2_pattern",
    pattern: "HTTP headers with unusual or custom fields (X-Custom-*, Cookie with encoded data)",
    description: "Custom HTTP headers used for C2 data encoding. Malleable C2 profiles can embed commands in HTTP headers.",
    falsePositiveNotes: "Web applications use custom headers. Analyze header values for encoding patterns (Base64, hex)."
  },
  {
    type: "c2_pattern",
    pattern: "SMB named pipes: \\\\pipe\\\\MSSE-[0-9]+-server, \\\\pipe\\\\msagent_[0-9a-f]+",
    description: "Cobalt Strike default named pipe patterns used for inter-process and lateral C2 communication.",
    falsePositiveNotes: "Cobalt Strike-specific indicators. Named pipes with these patterns are strong C2 indicators."
  },
  {
    type: "c2_pattern",
    pattern: "JA3/JA3S TLS fingerprints matching known malware families",
    description: "TLS client/server fingerprints (JA3 hashes) that match known malware C2 implementations.",
    falsePositiveNotes: "JA3 fingerprints may collide between malware and legitimate applications using similar TLS libraries."
  },
  {
    type: "c2_pattern",
    pattern: "Connections to cloud API endpoints (api.telegram.org, hooks.slack.com) from non-browser processes",
    description: "Abuse of legitimate messaging APIs for C2 communication. Malware sends commands/receives data through messaging platforms.",
    falsePositiveNotes: "Legitimate integrations use these APIs. Focus on processes that should not be making API calls."
  },

  // --- Email Indicators ---
  {
    type: "email",
    pattern: "Office documents with macros requesting EnableContent",
    description: "Macro-enabled Office documents delivered via email. Primary initial access vector for many malware families.",
    falsePositiveNotes: "Some legitimate business documents use macros. Verify sender and document origin."
  },
  {
    type: "email",
    pattern: "HTML attachments with JavaScript (HTML smuggling)",
    description: "HTML smuggling technique embedding malicious JavaScript in HTML email attachments to construct and deliver payloads client-side.",
    falsePositiveNotes: "Some legitimate email campaigns use HTML with JavaScript. Analyze JavaScript content for decoding/downloading behavior."
  },
  {
    type: "email",
    pattern: "ZIP/RAR attachments containing ISO, IMG, LNK, or directly executable files",
    description: "Multi-layered archive delivery to bypass email security scanning and MOTW protections.",
    falsePositiveNotes: "Legitimate archives may contain these file types. Check archive nesting depth and executable presence."
  },
  {
    type: "email",
    pattern: "Password-protected archives with password in email body",
    description: "Password-protected archive delivery bypassing email scanning. Password provided in email body allows recipient to extract.",
    falsePositiveNotes: "Some legitimate file transfers use password-protected archives. Verify sender and business context."
  },
  {
    type: "email",
    pattern: "Reply-chain hijacking (RE: FW: on threads the attacker intercepted)",
    description: "Thread hijacking where attackers insert malicious messages into existing legitimate email threads to increase trust.",
    falsePositiveNotes: "Verify the actual sender matches the expected participant. Check for subtle email address variations."
  },
  {
    type: "email",
    pattern: "QR code phishing (quishing) in email body or attachments",
    description: "QR codes in emails directing to phishing or malware download pages, bypassing URL scanning that does not decode QR codes.",
    falsePositiveNotes: "Legitimate organizations use QR codes in communications. Decode and verify the destination URL."
  },

  // --- Cloud/SaaS Indicators ---
  {
    type: "cloud",
    pattern: "OAuth application consent with broad permissions (Mail.Read, Files.ReadWrite.All)",
    description: "Malicious OAuth application requesting broad permissions for persistent access to email, files, and organizational data.",
    falsePositiveNotes: "Legitimate SaaS applications request broad permissions. Review application publisher and necessity of permissions."
  },
  {
    type: "cloud",
    pattern: "Impossible travel: authentication from geographically distant locations in short time",
    description: "Login events from geographically distant locations within an implausibly short timeframe, indicating credential compromise.",
    falsePositiveNotes: "VPN usage may cause false impossible travel alerts. Correlate with VPN logs and user confirmation."
  },
  {
    type: "cloud",
    pattern: "Bulk mail rule creation (forwarding all mail externally)",
    description: "Inbox rules forwarding all email to external addresses, indicating email compromise and data exfiltration.",
    falsePositiveNotes: "Users may create forwarding rules for legitimate purposes. Verify with the user and check destination."
  },
  {
    type: "cloud",
    pattern: "Service principal or application credential creation by non-admin users",
    description: "Unauthorized creation of service principals or application credentials for persistent cloud access.",
    falsePositiveNotes: "Developers may create service principals. Verify against authorized cloud administration processes."
  },
  {
    type: "cloud",
    pattern: "S3 bucket policy changes allowing public access or cross-account access",
    description: "S3 bucket policy modifications enabling unauthorized data access, common in cloud data exposure incidents.",
    falsePositiveNotes: "Some applications require public S3 access (static websites). Verify against cloud security policies."
  },

  // --- Encryption/Encoding Indicators ---
  {
    type: "encoding",
    pattern: "Base64-encoded PowerShell commands in process arguments",
    description: "PowerShell commands encoded in Base64 to evade command-line logging and basic detection signatures.",
    falsePositiveNotes: "Some deployment tools use Base64-encoded commands. Always decode and analyze the actual content."
  },
  {
    type: "encoding",
    pattern: "XOR-encoded payloads with single-byte keys (0x35, 0x3C, 0x55, 0xFF common)",
    description: "Simple XOR encoding used by malware to obfuscate payloads and evade static signatures.",
    falsePositiveNotes: "XOR encoding is trivial and may appear in legitimate data. Look for embedded PE headers after decoding."
  },
  {
    type: "encoding",
    pattern: "Hex-encoded strings in script variables or registry values",
    description: "Hexadecimal encoding of strings and payloads to obfuscate malicious content in scripts and persistence mechanisms.",
    falsePositiveNotes: "Hex encoding is common in programming. Analyze decoded content for malicious functionality."
  },
  {
    type: "encoding",
    pattern: "ROT13/ROT47 encoded strings in scripts",
    description: "Simple substitution cipher encoding used for light obfuscation of malicious strings in scripts.",
    falsePositiveNotes: "ROT13 is occasionally used in legitimate software for trivial obfuscation. Decode and analyze."
  },

  // --- Behavioral Indicators ---
  {
    type: "behavior",
    pattern: "Mass file extension changes (.encrypted, .locked, .crypt, etc.)",
    description: "Ransomware encryption indicator. Rapid file extension changes across multiple files and directories.",
    falsePositiveNotes: "Legitimate encryption tools may change extensions. Check the scale, speed, and associated processes."
  },
  {
    type: "behavior",
    pattern: "Rapid enumeration of network shares followed by file access across shares",
    description: "Network share enumeration and access pattern indicating automated data collection or ransomware spread.",
    falsePositiveNotes: "Backup software and inventory tools access multiple shares. Verify the process and authorization."
  },
  {
    type: "behavior",
    pattern: "Multiple failed authentication attempts across many accounts from single source",
    description: "Password spraying attack pattern. Low-and-slow credential guessing across many accounts to avoid lockout.",
    falsePositiveNotes: "Misconfigured service accounts may cause multiple auth failures. Check source and target accounts."
  },
  {
    type: "behavior",
    pattern: "Large data transfers to cloud storage services outside normal business hours",
    description: "Potential data exfiltration. Unusual uploads to cloud storage (Mega, Dropbox, Google Drive) outside normal working hours.",
    falsePositiveNotes: "Remote workers may transfer data at unusual hours. Correlate with user activity and file types."
  },
  {
    type: "behavior",
    pattern: "Process spawning from Office applications (WINWORD.EXE -> cmd.exe/powershell.exe)",
    description: "Macro or exploit execution in Office. Word, Excel, or PowerPoint spawning command interpreters indicates malicious document execution.",
    falsePositiveNotes: "Some legitimate Office macros spawn cmd.exe. Investigate the macro content and document origin."
  },
  {
    type: "behavior",
    pattern: "Service accounts authenticating interactively or from unexpected systems",
    description: "Service account misuse. Interactive logon or authentication from non-standard systems may indicate credential theft.",
    falsePositiveNotes: "Service account troubleshooting may involve interactive logins. Verify with operations team."
  },
  {
    type: "behavior",
    pattern: "Execution of reconnaissance commands in rapid succession (whoami, ipconfig, systeminfo, net user, nltest)",
    description: "Automated system reconnaissance. Rapid execution of discovery commands indicates post-exploitation automated enumeration.",
    falsePositiveNotes: "System administrators run these commands. Check the user context and preceding activity."
  },
  {
    type: "behavior",
    pattern: "LSASS process memory access by non-system processes",
    description: "Credential dumping attempt. Accessing LSASS memory to extract credentials using tools like Mimikatz, comsvcs.dll, or ProcDump.",
    falsePositiveNotes: "Antivirus and security tools may legitimately access LSASS. Verify the accessing process."
  }
];


// -----------------------------------------------------------------------------
// 5. THREAT FEEDS -- OSINT threat intelligence sources
// -----------------------------------------------------------------------------

export const THREAT_FEEDS = [
  // --- Government / CERT Feeds ---
  {
    name: "CISA Known Exploited Vulnerabilities (KEV)",
    url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    type: "vulnerability",
    format: "JSON, CSV",
    description: "CISA catalog of vulnerabilities confirmed to be actively exploited in the wild. Mandated for US federal agencies. Essential for prioritizing patching."
  },
  {
    name: "CISA Alerts and Advisories",
    url: "https://www.cisa.gov/news-events/cybersecurity-advisories",
    type: "advisory",
    format: "HTML, STIX",
    description: "US Cybersecurity and Infrastructure Security Agency alerts on current threats, vulnerabilities, and recommended mitigations."
  },
  {
    name: "US-CERT / ICS-CERT Advisories",
    url: "https://www.cisa.gov/uscert/ics/advisories",
    type: "advisory",
    format: "HTML, PDF",
    description: "ICS-specific security advisories for industrial control systems and operational technology environments."
  },
  {
    name: "NCSC UK Threat Reports",
    url: "https://www.ncsc.gov.uk/section/keep-up-to-date/threat-reports",
    type: "advisory",
    format: "HTML, PDF",
    description: "UK National Cyber Security Centre threat reports covering current cyber threats to UK organizations."
  },
  {
    name: "CERT-FR Advisories",
    url: "https://www.cert.ssi.gouv.fr/",
    type: "advisory",
    format: "HTML",
    description: "French national CERT advisories covering vulnerabilities, incidents, and threat intelligence for French organizations."
  },
  {
    name: "JPCERT/CC",
    url: "https://www.jpcert.or.jp/english/",
    type: "advisory",
    format: "HTML",
    description: "Japan Computer Emergency Response Team coordination center providing threat analysis and incident coordination."
  },

  // --- Open Source IOC Feeds ---
  {
    name: "AlienVault OTX (Open Threat Exchange)",
    url: "https://otx.alienvault.com/",
    type: "IOC",
    format: "STIX, JSON, CSV",
    description: "Collaborative threat intelligence community with millions of indicators including IPs, domains, URLs, file hashes, and YARA rules."
  },
  {
    name: "Abuse.ch URLhaus",
    url: "https://urlhaus.abuse.ch/",
    type: "IOC",
    format: "CSV, JSON, API",
    description: "Database of malware distribution URLs. Updated in real-time by security researchers. Provides blocklists for URL filtering."
  },
  {
    name: "Abuse.ch MalwareBazaar",
    url: "https://bazaar.abuse.ch/",
    type: "IOC",
    format: "CSV, JSON, API",
    description: "Malware sample sharing platform with rich metadata, YARA rules, and integration with other Abuse.ch services."
  },
  {
    name: "Abuse.ch ThreatFox",
    url: "https://threatfox.abuse.ch/",
    type: "IOC",
    format: "CSV, JSON, API",
    description: "IOC sharing platform focusing on malware C2 infrastructure. Links indicators to specific malware families and campaigns."
  },
  {
    name: "Abuse.ch Feodo Tracker",
    url: "https://feodotracker.abuse.ch/",
    type: "IOC",
    format: "CSV, JSON",
    description: "Tracks botnet C2 servers for banking trojans and loaders (Dridex, Emotet, TrickBot, QakBot). Provides IP blocklists."
  },
  {
    name: "Abuse.ch SSL Blacklist (SSLBL)",
    url: "https://sslbl.abuse.ch/",
    type: "IOC",
    format: "CSV",
    description: "Blacklist of SSL certificates associated with malware and botnet C2 servers. JA3 fingerprint tracking."
  },
  {
    name: "PhishTank",
    url: "https://phishtank.org/",
    type: "IOC",
    format: "CSV, JSON, XML",
    description: "Community-driven phishing URL verification and database. Collaborative platform for reporting and validating phishing sites."
  },
  {
    name: "OpenPhish",
    url: "https://openphish.com/",
    type: "IOC",
    format: "text, JSON",
    description: "Automated phishing intelligence platform providing curated lists of active phishing URLs with brand targeting information."
  },
  {
    name: "Blocklist.de",
    url: "https://www.blocklist.de/en/index.html",
    type: "IOC",
    format: "text",
    description: "Free service tracking IP addresses involved in attacks (brute force, DDoS, spam) reported by server operators."
  },
  {
    name: "Spamhaus DROP/EDROP",
    url: "https://www.spamhaus.org/drop/",
    type: "IOC",
    format: "text",
    description: "Dont Route Or Peer lists of hijacked or leased IP space used for spam, malware, and cybercrime. Essential network-level blocklist."
  },
  {
    name: "CIRCL MISP Default Feeds",
    url: "https://www.circl.lu/services/misp-malware-information-sharing-platform/",
    type: "IOC",
    format: "MISP JSON, STIX",
    description: "Default threat intelligence feeds for MISP platform including CIRCL OSINT feed, botnet trackers, and vulnerability data."
  },
  {
    name: "Emerging Threats Rules (Proofpoint)",
    url: "https://rules.emergingthreats.net/",
    type: "detection rules",
    format: "Snort/Suricata rules",
    description: "Open source IDS/IPS rules for detecting current threats. Includes rules for malware, exploits, and policy violations."
  },

  // --- Threat Intelligence Platforms ---
  {
    name: "VirusTotal",
    url: "https://www.virustotal.com/",
    type: "analysis",
    format: "JSON API",
    description: "Multi-engine malware scanning and analysis platform. Provides file, URL, domain, and IP reputation data from 70+ security vendors."
  },
  {
    name: "Shodan",
    url: "https://www.shodan.io/",
    type: "exposure",
    format: "JSON API",
    description: "Internet-wide scanning platform indexing exposed services, devices, and vulnerabilities. Essential for attack surface management."
  },
  {
    name: "Censys",
    url: "https://censys.io/",
    type: "exposure",
    format: "JSON API",
    description: "Internet scanning platform focused on certificate and host discovery. Provides detailed infrastructure visibility for threat hunting."
  },
  {
    name: "GreyNoise",
    url: "https://www.greynoise.io/",
    type: "context",
    format: "JSON API",
    description: "Internet background noise analysis. Distinguishes between targeted attacks and opportunistic scanning to reduce false positives."
  },
  {
    name: "MITRE ATT&CK",
    url: "https://attack.mitre.org/",
    type: "framework",
    format: "STIX 2.0, JSON",
    description: "Comprehensive knowledge base of adversary tactics and techniques based on real-world observations. Foundation for threat-informed defense."
  },
  {
    name: "MISP Threat Sharing",
    url: "https://www.misp-project.org/",
    type: "platform",
    format: "MISP JSON, STIX",
    description: "Open-source threat intelligence platform for sharing, storing, and correlating indicators of compromise and threat intelligence."
  },
  {
    name: "OpenCTI",
    url: "https://www.opencti.io/",
    type: "platform",
    format: "STIX 2.1",
    description: "Open-source cyber threat intelligence platform for managing and visualizing threat data. Built on STIX 2.1 and supports connectors."
  },
  {
    name: "IntelOwl",
    url: "https://github.com/intelowlproject/IntelOwl",
    type: "analysis",
    format: "JSON API",
    description: "Open-source intelligence analysis tool that aggregates data from multiple analyzers and enrichment services for indicator analysis."
  },

  // --- Vulnerability Data ---
  {
    name: "NVD (National Vulnerability Database)",
    url: "https://nvd.nist.gov/",
    type: "vulnerability",
    format: "JSON, XML",
    description: "NIST maintained repository of vulnerability data using CVE identifiers with CVSS scoring, CWE classification, and CPE matching."
  },
  {
    name: "CVE Program (MITRE)",
    url: "https://www.cve.org/",
    type: "vulnerability",
    format: "JSON 5.0",
    description: "Common Vulnerabilities and Exposures identification system. Foundation for vulnerability management worldwide."
  },
  {
    name: "Exploit-DB",
    url: "https://www.exploit-db.com/",
    type: "exploit",
    format: "text, binary",
    description: "Archive of public exploits and vulnerable software. Maintained by OffSec. Includes Google Hacking Database (GHDB)."
  },
  {
    name: "VulnCheck KEV",
    url: "https://vulncheck.com/kev",
    type: "vulnerability",
    format: "JSON API",
    description: "Enhanced known exploited vulnerability tracking that extends CISA KEV with additional context, earlier detection, and broader coverage."
  },

  // --- Security Research and Blogs ---
  {
    name: "Unit 42 (Palo Alto Networks)",
    url: "https://unit42.paloaltonetworks.com/",
    type: "research",
    format: "HTML, STIX",
    description: "Threat research from Palo Alto Networks covering APT groups, malware analysis, and emerging threats with detailed IOCs."
  },
  {
    name: "Mandiant Threat Intelligence",
    url: "https://www.mandiant.com/resources/blog",
    type: "research",
    format: "HTML",
    description: "Google/Mandiant threat research covering advanced persistent threats, incident response findings, and attribution analysis."
  },
  {
    name: "Microsoft Threat Intelligence",
    url: "https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/",
    type: "research",
    format: "HTML",
    description: "Microsoft threat intelligence blog covering threat actors, campaigns, and security features with detailed analysis."
  },
  {
    name: "Talos Intelligence (Cisco)",
    url: "https://blog.talosintelligence.com/",
    type: "research",
    format: "HTML, Snort rules",
    description: "Cisco Talos research covering malware, vulnerabilities, and threat campaigns with associated detection content."
  },
  {
    name: "Securelist (Kaspersky)",
    url: "https://securelist.com/",
    type: "research",
    format: "HTML, YARA",
    description: "Kaspersky GReAT team research covering APT campaigns, malware analysis, and threat landscape reports."
  },
  {
    name: "WeLiveSecurity (ESET)",
    url: "https://www.welivesecurity.com/",
    type: "research",
    format: "HTML",
    description: "ESET research covering malware campaigns, APT analysis, and security trends with detailed technical analysis."
  },
  {
    name: "SentinelLabs (SentinelOne)",
    url: "https://www.sentinelone.com/labs/",
    type: "research",
    format: "HTML",
    description: "SentinelOne research covering advanced threats, malware analysis, and vulnerability research."
  },
  {
    name: "The DFIR Report",
    url: "https://thedfirreport.com/",
    type: "research",
    format: "HTML",
    description: "Detailed intrusion analysis reports documenting real-world attack chains from initial access to impact with full TTPs."
  },
  {
    name: "Recorded Future",
    url: "https://www.recordedfuture.com/blog",
    type: "research",
    format: "HTML, API",
    description: "Threat intelligence research covering geopolitical threats, cybercrime, and vulnerability intelligence."
  }
];
