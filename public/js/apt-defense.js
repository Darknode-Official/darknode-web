// APT Defense Engine — Advanced Persistent Threat defense toolkit
// Real threat actor data, threat modeling, kill chain analysis, and detection heuristics

// ═══════════════════════════════════════════════════════════════════════════════
// APT GROUP DATABASE — 80+ real threat actor groups
// ═══════════════════════════════════════════════════════════════════════════════

export const APT_GROUPS = [
  {
    name: "APT28", aliases: ["Fancy Bear", "Sofacy", "Pawn Storm", "Sednit", "STRONTIUM", "Forest Blizzard"],
    origin: "Russia", attribution: "GRU Unit 26165",
    targets: ["Government", "Military", "Defense", "Media", "Political organizations"],
    ttps: ["T1566.001", "T1059.001", "T1053.005", "T1078", "T1003.001", "T1071.001", "T1027", "T1547.001"],
    malware: ["X-Agent", "Zebrocy", "Seduploader", "Downdelph", "Komplex"],
    campaigns: ["DNC hack 2016", "Bundestag hack 2015", "WADA breach 2016", "NotPetya support operations"],
    description: "Russian military intelligence cyber unit focused on political espionage, election interference, and information operations against NATO countries."
  },
  {
    name: "APT29", aliases: ["Cozy Bear", "The Dukes", "NOBELIUM", "Midnight Blizzard", "YTTRIUM"],
    origin: "Russia", attribution: "SVR (Foreign Intelligence Service)",
    targets: ["Government", "Diplomatic", "Think tanks", "Healthcare", "Technology"],
    ttps: ["T1195.002", "T1059.001", "T1053.005", "T1078.004", "T1550.001", "T1071.001", "T1027.005", "T1548.002"],
    malware: ["SUNBURST", "TEARDROP", "Raindrop", "WellMess", "WellMail", "EnvyScout", "BoomBox", "NativeZone"],
    campaigns: ["SolarWinds supply chain 2020", "COVID-19 vaccine research targeting 2020", "Microsoft/SolarWinds follow-on 2021"],
    description: "Russia's foreign intelligence service cyber operations, known for sophisticated supply chain attacks and long-term persistent access to high-value targets."
  },
  {
    name: "APT41", aliases: ["Double Dragon", "Winnti Group", "BARIUM", "Brass Typhoon"],
    origin: "China", attribution: "MSS-affiliated / dual-purpose",
    targets: ["Technology", "Healthcare", "Telecom", "Gaming", "Finance", "Government"],
    ttps: ["T1190", "T1059.001", "T1053.005", "T1078", "T1003", "T1071.001", "T1027", "T1055"],
    malware: ["ShadowPad", "Winnti", "POISONPLUG", "Crosswalk", "DUSTPAN", "DUSTTRAP"],
    campaigns: ["Operation CuckooBees", "Supply chain attacks on gaming companies", "COVID-era healthcare targeting"],
    description: "Chinese state-sponsored group unique for conducting both espionage and financially motivated operations, including supply chain compromises and ransomware."
  },
  {
    name: "Lazarus Group", aliases: ["HIDDEN COBRA", "Zinc", "Diamond Sleet", "Labyrinth Chollima", "APT38"],
    origin: "North Korea", attribution: "RGB (Reconnaissance General Bureau)",
    targets: ["Finance", "Cryptocurrency", "Aerospace", "Defense", "Media", "Government"],
    ttps: ["T1566.001", "T1059", "T1053.005", "T1078", "T1003", "T1071.001", "T1486", "T1565.001"],
    malware: ["FALLCHILL", "Bankshot", "AppleJeus", "ELECTRICFISH", "ThreatNeedle", "BLINDINGCAN", "DTrack"],
    campaigns: ["Sony Pictures 2014", "Bangladesh Bank heist 2016", "WannaCry 2017", "Ronin Network $620M theft 2022", "Atomic Wallet hack 2023"],
    description: "North Korean state-sponsored group conducting espionage, destructive attacks, and massive cryptocurrency theft to fund the DPRK regime."
  },
  {
    name: "Equation Group", aliases: ["EQGRP", "Longhorn"],
    origin: "United States", attribution: "NSA TAO (Tailored Access Operations)",
    targets: ["Government", "Military", "Telecom", "Energy", "Research", "Diplomatic"],
    ttps: ["T1195.002", "T1542.001", "T1027.002", "T1055", "T1071", "T1573", "T1014"],
    malware: ["DoubleFantasy", "EquationDrug", "GrayFish", "Fanny", "TripleFantasy", "FOXACID"],
    campaigns: ["Stuxnet support", "Hard drive firmware implants", "SWIFT banking system targeting"],
    description: "Widely considered the most sophisticated cyber threat actor, known for firmware-level persistence, air-gap crossing, and decade-long stealth operations."
  },
  {
    name: "Turla", aliases: ["Snake", "Venomous Bear", "Waterbug", "KRYPTON", "Secret Blizzard"],
    origin: "Russia", attribution: "FSB Center 16",
    targets: ["Government", "Diplomatic", "Military", "Research", "Media"],
    ttps: ["T1059.001", "T1071.001", "T1573.002", "T1090.003", "T1027", "T1055", "T1036"],
    malware: ["Snake", "Carbon", "Kazuar", "ComRAT", "Gazer", "LightNeuron", "TinyTurla", "Capibar"],
    campaigns: ["Agent.BTZ USB campaign", "Satellite C2 hijacking", "Iranian APT infrastructure hijacking 2019"],
    description: "One of Russia's oldest and most sophisticated cyber espionage groups, known for satellite-based C2, supply chain attacks, and hijacking other APT groups' infrastructure."
  },
  {
    name: "Sandworm", aliases: ["Voodoo Bear", "IRIDIUM", "Seashell Blizzard", "Telebots", "BlackEnergy Group"],
    origin: "Russia", attribution: "GRU Unit 74455",
    targets: ["Energy", "Government", "Critical infrastructure", "Media", "Elections"],
    ttps: ["T1190", "T1059", "T1053.005", "T1489", "T1485", "T1561.002", "T1486", "T1498"],
    malware: ["BlackEnergy", "Industroyer", "NotPetya", "Olympic Destroyer", "VPNFilter", "CaddyWiper", "Prestige"],
    campaigns: ["Ukraine power grid attack 2015-2016", "NotPetya global wiper 2017", "PyeongChang Olympics 2018", "Ukraine 2022 wiper campaigns"],
    description: "Russia's most destructive cyber unit, responsible for the world's most damaging cyberattack (NotPetya, $10B+ damage) and attacks on critical infrastructure."
  },
  {
    name: "Charming Kitten", aliases: ["APT35", "Phosphorus", "Mint Sandstorm", "NewsBeef", "Ajax Security Team"],
    origin: "Iran", attribution: "IRGC (Islamic Revolutionary Guard Corps)",
    targets: ["Government", "Defense", "Telecom", "Academia", "Dissidents", "Journalists"],
    ttps: ["T1566.001", "T1566.002", "T1078", "T1059.001", "T1003", "T1071.001", "T1114"],
    malware: ["DownPaper", "POWERSTAR", "BellaCiao", "CharmPower", "HYPERSCRAPE", "MediaPl"],
    campaigns: ["2020 US election targeting", "WHO impersonation 2020", "Think tank compromise campaigns"],
    description: "Iranian state-sponsored group conducting espionage against dissidents, journalists, and foreign government officials through sophisticated social engineering."
  },
  {
    name: "OceanLotus", aliases: ["APT32", "Canvas Cyclone", "SeaLotus", "Cobalt Kitty"],
    origin: "Vietnam", attribution: "Vietnamese government-affiliated",
    targets: ["Government", "Journalists", "Dissidents", "Private sector", "Manufacturing"],
    ttps: ["T1566.001", "T1059", "T1055", "T1027", "T1071", "T1036", "T1218"],
    malware: ["Denis", "Cobalt Kitty RAT", "KerrDown", "PhantomNet", "Ratsnif"],
    campaigns: ["Southeast Asian government targeting", "Automotive industry espionage", "Dissident surveillance campaigns"],
    description: "Vietnamese state-aligned group conducting espionage against neighboring countries, political dissidents, and foreign corporations with operations in Vietnam."
  },
  {
    name: "Kimsuky", aliases: ["Velvet Chollima", "Emerald Sleet", "Black Banshee", "Thallium", "APT43"],
    origin: "North Korea", attribution: "RGB",
    targets: ["Government", "Think tanks", "Academia", "Nuclear/defense policy", "Cryptocurrency"],
    ttps: ["T1566.001", "T1566.002", "T1059", "T1078", "T1003", "T1114", "T1071.001"],
    malware: ["BabyShark", "AppleSeed", "FlowerPower", "RandomQuery", "GoldDragon", "ReconShark"],
    campaigns: ["Korean peninsula intelligence collection", "Nuclear policy researcher targeting", "Cryptocurrency researcher targeting"],
    description: "North Korean espionage group focused on intelligence collection related to foreign policy, nuclear issues, and sanctions evasion."
  },
  {
    name: "MuddyWater", aliases: ["Mercury", "Mango Sandstorm", "Static Kitten", "TEMP.Zagros", "Seedworm"],
    origin: "Iran", attribution: "MOIS (Ministry of Intelligence and Security)",
    targets: ["Government", "Telecom", "Energy", "Defense", "Education"],
    ttps: ["T1566.001", "T1059.001", "T1059.005", "T1027", "T1071.001", "T1105", "T1036"],
    malware: ["POWERSTATS", "MuddyC2Go", "PhonyC2", "DarkBit ransomware", "SimpleHarm"],
    campaigns: ["Middle East government targeting", "Turkish government espionage 2019", "Israel targeting 2022-2023"],
    description: "Iranian intelligence group conducting espionage against Middle Eastern and Western targets, known for rapid tool development and living-off-the-land techniques."
  },
  {
    name: "FIN7", aliases: ["Carbanak", "Navigator Group", "Sangria Tempest", "Carbon Spider"],
    origin: "Russia", attribution: "Cybercriminal (some members arrested)",
    targets: ["Retail", "Hospitality", "Restaurant", "Finance", "Technology"],
    ttps: ["T1566.001", "T1059.001", "T1059.005", "T1055", "T1003", "T1071.001", "T1027"],
    malware: ["Carbanak", "GRIFFON", "HALFBAKED", "DICELOADER", "Lizar", "POWERPLANT", "BIRDWATCH"],
    campaigns: ["Point-of-sale malware campaign ($1B+ stolen)", "Supply chain attacks via Kaseya-like vectors"],
    description: "Prolific financially motivated threat group responsible for over $1 billion in theft from banks and retailers worldwide."
  },
  {
    name: "FIN11", aliases: ["TA505", "Lace Tempest", "DEV-0950"],
    origin: "Russia", attribution: "Cybercriminal",
    targets: ["Finance", "Retail", "Healthcare", "Manufacturing", "Technology"],
    ttps: ["T1190", "T1059.001", "T1486", "T1027", "T1071.001", "T1105", "T1036"],
    malware: ["Clop ransomware", "FlawedAmmyy", "SDBbot", "Get2", "FlawedGrace"],
    campaigns: ["Accellion FTA exploitation 2021", "MOVEit Transfer exploitation 2023", "GoAnywhere MFT exploitation 2023"],
    description: "Major ransomware and extortion operator known for mass exploitation of file transfer appliance zero-days and data theft for extortion."
  },
  {
    name: "Volt Typhoon", aliases: ["VANGUARD PANDA", "Bronze Silhouette", "DEV-0391"],
    origin: "China", attribution: "PLA / MSS",
    targets: ["Critical infrastructure", "Telecom", "Energy", "Water", "Transportation", "Military"],
    ttps: ["T1190", "T1078", "T1059.001", "T1003", "T1071.001", "T1218", "T1036", "T1562.001"],
    malware: ["Living-off-the-land (LOTL) — minimal custom malware"],
    campaigns: ["US critical infrastructure pre-positioning 2023-2024", "Guam military infrastructure targeting"],
    description: "Chinese state-sponsored group pre-positioning on US critical infrastructure for potential disruption during a Taiwan conflict, using exclusively living-off-the-land techniques."
  },
  {
    name: "Salt Typhoon", aliases: ["GhostEmperor", "FamousSparrow"],
    origin: "China", attribution: "MSS-affiliated",
    targets: ["Telecom", "ISP", "Government communications"],
    ttps: ["T1190", "T1078", "T1059", "T1003", "T1557", "T1040", "T1114"],
    malware: ["Demodex rootkit", "Custom implants"],
    campaigns: ["US telecom provider compromise 2024 (AT&T, Verizon, T-Mobile)", "Lawful intercept system access"],
    description: "Chinese espionage group that penetrated major US telecom providers to access lawful intercept systems and surveil targeted individuals' communications."
  },
  {
    name: "Scattered Spider", aliases: ["UNC3944", "Octo Tempest", "0ktapus", "Star Fraud"],
    origin: "US/UK", attribution: "Cybercriminal collective",
    targets: ["Telecom", "Technology", "Finance", "Hospitality", "Retail"],
    ttps: ["T1566.004", "T1078", "T1199", "T1059", "T1003", "T1486", "T1657"],
    malware: ["ALPHV/BlackCat ransomware (affiliate)", "Custom tools"],
    campaigns: ["MGM Resorts attack 2023 ($100M+ impact)", "Caesars Entertainment breach 2023", "Okta compromise"],
    description: "Young English-speaking threat actors using social engineering and SIM swapping to breach major enterprises, now affiliated with ALPHV ransomware."
  },
  {
    name: "LockBit", aliases: ["LockBit Gang", "ABCD ransomware"],
    origin: "Russia", attribution: "Cybercriminal (RaaS operator)",
    targets: ["All sectors — indiscriminate"],
    ttps: ["T1190", "T1133", "T1078", "T1486", "T1490", "T1027", "T1059"],
    malware: ["LockBit 2.0", "LockBit 3.0 (LockBit Black)", "LockBit Green", "StealBit"],
    campaigns: ["Most prolific ransomware operation 2022-2023", "ICBC Financial Services attack 2023"],
    description: "Most prolific ransomware-as-a-service operation globally, responsible for thousands of attacks. Disrupted by Operation Cronos (Feb 2024) but attempted resurgence."
  },
  {
    name: "BlackCat", aliases: ["ALPHV", "Noberus"],
    origin: "Russia", attribution: "Cybercriminal (former DarkSide/BlackMatter members)",
    targets: ["Healthcare", "Finance", "Government", "Critical infrastructure"],
    ttps: ["T1190", "T1078", "T1486", "T1490", "T1027", "T1059", "T1657"],
    malware: ["ALPHV/BlackCat ransomware (Rust-based)", "Sphynx", "ExMatter"],
    campaigns: ["Change Healthcare attack 2024 ($22M ransom paid)", "Reddit breach 2023", "MGM Resorts (via Scattered Spider)"],
    description: "First major ransomware written in Rust, with advanced features including cross-platform encryption. Conducted exit scam after Change Healthcare payment."
  },
  {
    name: "Cl0p", aliases: ["TA505 affiliate", "FIN11 affiliate"],
    origin: "Russia/Ukraine", attribution: "Cybercriminal",
    targets: ["File transfer appliance users — mass exploitation"],
    ttps: ["T1190", "T1486", "T1567", "T1071.001", "T1059"],
    malware: ["Cl0p ransomware", "DEWMODE", "LEMURLOOT", "FlawedAmmyy"],
    campaigns: ["MOVEit Transfer zero-day (2,500+ orgs)", "Accellion FTA exploitation", "GoAnywhere MFT exploitation"],
    description: "Ransomware group specializing in mass exploitation of file transfer zero-days for data theft and extortion without deploying ransomware encryption."
  },
  {
    name: "Hafnium", aliases: ["Silk Typhoon", "CHROMIUM"],
    origin: "China", attribution: "MSS-affiliated",
    targets: ["Government", "Defense", "Think tanks", "Healthcare", "Higher education"],
    ttps: ["T1190", "T1059", "T1003", "T1071.001", "T1505.003", "T1078"],
    malware: ["China Chopper", "Covenant", "Custom web shells"],
    campaigns: ["Microsoft Exchange ProxyLogon mass exploitation 2021 (30,000+ servers)"],
    description: "Chinese espionage group that mass-exploited Microsoft Exchange zero-days affecting hundreds of thousands of servers worldwide."
  },
  {
    name: "DarkSide", aliases: ["UNC2465"],
    origin: "Russia", attribution: "Cybercriminal (rebranded as BlackMatter, then BlackCat)",
    targets: ["Energy", "Finance", "Manufacturing", "Critical infrastructure"],
    ttps: ["T1190", "T1078", "T1486", "T1490", "T1059", "T1071.001"],
    malware: ["DarkSide ransomware"],
    campaigns: ["Colonial Pipeline attack May 2021 ($4.4M ransom, fuel shortage across US East Coast)"],
    description: "Ransomware group behind the Colonial Pipeline attack, one of the most impactful cyberattacks on US critical infrastructure."
  },
  {
    name: "Conti", aliases: ["Wizard Spider", "DEV-0193", "Storm-0193"],
    origin: "Russia", attribution: "Cybercriminal (disbanded 2022, members scattered)",
    targets: ["Healthcare", "Government", "Education", "Manufacturing"],
    ttps: ["T1190", "T1133", "T1078", "T1486", "T1490", "T1059.001", "T1055", "T1003"],
    malware: ["Conti ransomware", "BazarLoader", "TrickBot", "Anchor", "Diavol"],
    campaigns: ["Irish Health Service attack 2021", "Costa Rica government attack 2022", "700+ healthcare organizations targeted"],
    description: "Major ransomware operation that generated over $180M in ransom payments before disbanding after internal chats leaked following pro-Russia stance."
  },
  {
    name: "REvil", aliases: ["Sodinokibi", "Gold Southfield", "Pinchy Spider"],
    origin: "Russia", attribution: "Cybercriminal (members arrested)",
    targets: ["Technology", "MSPs", "Legal", "Insurance", "Manufacturing"],
    ttps: ["T1195.002", "T1190", "T1486", "T1490", "T1059", "T1071.001"],
    malware: ["REvil/Sodinokibi ransomware"],
    campaigns: ["Kaseya VSA supply chain attack July 2021 (1,500+ orgs)", "JBS Foods $11M ransom 2021"],
    description: "Ransomware-as-a-service operation behind major supply chain attacks and high-profile extortion, disrupted by FBI/FSB joint operation."
  },
  {
    name: "Gamaredon", aliases: ["Primitive Bear", "Shuckworm", "Aqua Blizzard", "Armageddon"],
    origin: "Russia", attribution: "FSB (Crimea-based unit)",
    targets: ["Ukrainian government", "Military", "Law enforcement", "Diplomats"],
    ttps: ["T1566.001", "T1059.005", "T1059.001", "T1547.001", "T1071.001", "T1027", "T1105"],
    malware: ["Pterodo/Pteranodon", "GammaSteel", "GammaLoad", "EvilGnome"],
    campaigns: ["Continuous targeting of Ukrainian government since 2014", "Intensified operations post-2022 invasion"],
    description: "Russia's most active group targeting Ukraine, conducting high-volume but lower-sophistication espionage operations with rapid malware iteration."
  },
  {
    name: "Mustang Panda", aliases: ["Bronze President", "Camaro Dragon", "RedDelta", "Earth Preta"],
    origin: "China", attribution: "PLA-affiliated",
    targets: ["Government", "NGOs", "Think tanks", "Telecom", "Religious organizations"],
    ttps: ["T1566.001", "T1059", "T1547.001", "T1071.001", "T1027", "T1055", "T1105"],
    malware: ["PlugX", "Korplug", "TONESHELL", "PUBLOAD", "MQsTTang"],
    campaigns: ["Southeast Asian government targeting", "European diplomatic targeting", "USB-based PlugX spreading"],
    description: "Chinese espionage group targeting governments and NGOs in Southeast Asia and Europe, known for USB-propagating malware and PlugX variants."
  },
  {
    name: "Agrius", aliases: ["DEV-0227", "Pink Sandstorm", "BlackShadow"],
    origin: "Iran", attribution: "MOIS-affiliated",
    targets: ["Israel", "South Africa", "Technology", "Diamond industry"],
    ttps: ["T1190", "T1078", "T1486", "T1485", "T1561.001", "T1059"],
    malware: ["Apostle (wiper disguised as ransomware)", "Fantasy", "Moneybird"],
    campaigns: ["Israeli targets destruction campaigns", "South African diamond industry targeting"],
    description: "Iranian destructive threat group that deploys wiper malware disguised as ransomware to cause maximum damage to Israeli and allied targets."
  },
  {
    name: "Moses Staff", aliases: ["Marigold Sandstorm", "Abraham's Ax"],
    origin: "Iran", attribution: "IRGC-affiliated",
    targets: ["Israel", "Government", "Military", "Engineering"],
    ttps: ["T1190", "T1078", "T1486", "T1485", "T1561", "T1059"],
    malware: ["StrifeWater", "DCSrv", "PyDCrypt"],
    campaigns: ["Israeli corporate data theft and leaks", "Destructive attacks on Israeli infrastructure"],
    description: "Iranian influence and destruction group focused on leaking stolen Israeli data and deploying destructive malware as part of information warfare."
  },
  {
    name: "Patchwork", aliases: ["Dropping Elephant", "Monsoon", "Chinastrats", "APT-C-09"],
    origin: "India", attribution: "Indian government-affiliated",
    targets: ["Pakistan government", "Chinese diplomatic", "Think tanks", "Defense"],
    ttps: ["T1566.001", "T1203", "T1059", "T1547.001", "T1071.001", "T1027"],
    malware: ["BADNEWS", "Ragnatela", "SPYDER", "Brute Ratel C4"],
    campaigns: ["Pakistani military targeting", "Chinese diplomatic targeting", "COVID-themed phishing"],
    description: "Indian-attributed espionage group known for borrowing code from public exploit databases and targeting regional adversaries."
  },
  {
    name: "SideWinder", aliases: ["Rattlesnake", "T-APT-04", "Razor Tiger"],
    origin: "India", attribution: "Indian military/intelligence",
    targets: ["Pakistan", "China", "Nepal", "Sri Lanka", "Military", "Government"],
    ttps: ["T1566.001", "T1203", "T1059.001", "T1547.001", "T1071.001", "T1027"],
    malware: ["SideWinder.AntiBot", "Custom .NET RATs", "StealerBot"],
    campaigns: ["Pakistan military personnel targeting", "Chinese government entity targeting"],
    description: "Prolific Indian-attributed group with one of the highest attack frequencies, primarily targeting South Asian military and government entities."
  },
  {
    name: "Andariel", aliases: ["Silent Chollima", "Onyx Sleet", "Plutonium", "DarkSeoul"],
    origin: "North Korea", attribution: "RGB Bureau 121",
    targets: ["Defense", "Aerospace", "Nuclear", "Healthcare", "Cryptocurrency"],
    ttps: ["T1190", "T1059", "T1078", "T1003", "T1486", "T1071.001", "T1027"],
    malware: ["Maui ransomware", "DTrack", "EarlyRat", "NukeSped", "TigerRAT"],
    campaigns: ["US healthcare ransomware attacks 2022", "Defense sector espionage", "Nuclear energy sector targeting"],
    description: "North Korean group conducting both espionage and ransomware operations, notably targeting US healthcare with Maui ransomware."
  },
  {
    name: "BlackTech", aliases: ["Palmerworm", "Temp.Overboard", "Circuit Panda", "Manga Taurus"],
    origin: "China", attribution: "PLA/MSS",
    targets: ["Technology", "Government", "Defense", "Telecom", "Media"],
    ttps: ["T1190", "T1059", "T1078", "T1542.001", "T1071.001", "T1027", "T1036"],
    malware: ["BendyBear", "FlagPro", "SpiderPig", "Waterbear", "Plead"],
    campaigns: ["Router firmware modification campaigns", "Asian telecom and government targeting"],
    description: "Chinese group known for modifying router firmware to maintain persistent access and pivot through trusted network devices."
  },
  {
    name: "Lyceum", aliases: ["Hexane", "Spirlin", "Siamesekitten"],
    origin: "Iran", attribution: "MOIS",
    targets: ["Telecom", "Energy", "Oil & gas", "Government"],
    ttps: ["T1566.001", "T1059", "T1078", "T1003", "T1071.001", "T1027"],
    malware: ["DanBot", "Milan", "Shark", "DanDrop"],
    campaigns: ["Middle Eastern telecom targeting", "African telecom providers", "Oil & gas sector espionage"],
    description: "Iranian espionage group focused on telecommunications and energy sectors in the Middle East and Africa."
  },
  {
    name: "Ember Bear", aliases: ["UNC2589", "Cadet Blizzard", "DEV-0586"],
    origin: "Russia", attribution: "GRU (assessed)",
    targets: ["Ukraine", "NATO countries", "Government", "IT sector"],
    ttps: ["T1190", "T1059", "T1485", "T1561", "T1486", "T1078"],
    malware: ["WhisperGate", "PartyTicket", "SaintBot", "OutSteel"],
    campaigns: ["WhisperGate destructive attacks Jan 2022 (pre-invasion)", "Ukrainian government website defacements"],
    description: "Russian group that launched destructive WhisperGate wiper attacks against Ukraine weeks before the 2022 invasion."
  },
  {
    name: "Earth Lusca", aliases: ["TAG-22", "Charcoal Typhoon"],
    origin: "China", attribution: "Winnti cluster / MSS contractor",
    targets: ["Government", "Education", "Religious movements", "Democracy activists", "Telecom"],
    ttps: ["T1190", "T1059", "T1078", "T1003", "T1071.001", "T1027", "T1055"],
    malware: ["ShadowPad", "Cobalt Strike", "SprySOCKS", "Winnti"],
    campaigns: ["Asian government espionage", "Cryptocurrency platform attacks", "Human rights activist targeting"],
    description: "Chinese group conducting both espionage and financially motivated attacks, part of the broader Winnti umbrella."
  },
  {
    name: "Bitter", aliases: ["APT-C-08", "T-APT-17"],
    origin: "India/South Asia", attribution: "Suspected Indian state-sponsored",
    targets: ["Pakistan", "Bangladesh", "China", "Saudi Arabia", "Government", "Military", "Energy"],
    ttps: ["T1566.001", "T1203", "T1059", "T1547.001", "T1071.001", "T1027"],
    malware: ["BitterRAT", "ArtraDownloader", "ZxxZ", "Almond RAT"],
    campaigns: ["Bangladesh government targeting", "Chinese energy sector espionage"],
    description: "South Asian espionage group targeting regional government and military entities with custom remote access tools."
  },
  {
    name: "Tortoiseshell", aliases: ["Imperial Kitten", "Crimson Sandstorm", "TA456"],
    origin: "Iran", attribution: "IRGC",
    targets: ["Defense", "IT", "Aerospace", "Military contractors"],
    ttps: ["T1566.001", "T1566.003", "T1059", "T1078", "T1003", "T1071.001"],
    malware: ["LEMPO", "IMAPLoader", "Syskit"],
    campaigns: ["US defense contractor social engineering", "Israeli technology sector targeting"],
    description: "Iranian group using elaborate fake social media personas and job-themed lures to compromise defense and aerospace sector employees."
  },
  {
    name: "ChamelGang", aliases: ["CamoFei"],
    origin: "China", attribution: "Chinese state-affiliated",
    targets: ["Government", "Aviation", "Energy", "Critical infrastructure"],
    ttps: ["T1190", "T1059", "T1078", "T1003", "T1071.001", "T1027"],
    malware: ["ChamelDoH", "BeaconLoader", "DoorMe"],
    campaigns: ["Indian government targeting", "AIIMS hospital attack", "Brazilian presidency targeting"],
    description: "Chinese espionage group targeting government and critical infrastructure across Asia and South America, using DNS-over-HTTPS for covert C2."
  },
  {
    name: "Storm-0558", aliases: ["No formal APT name yet"],
    origin: "China", attribution: "MSS-affiliated",
    targets: ["US Government", "State Department", "Commerce Department", "Email systems"],
    ttps: ["T1199", "T1078.004", "T1114", "T1071.001", "T1550"],
    malware: ["Forged Azure AD tokens using stolen MSA signing key"],
    campaigns: ["Microsoft cloud email compromise July 2023 (senior US officials' email accessed)"],
    description: "Chinese group that stole a Microsoft signing key and forged authentication tokens to access senior US government officials' email accounts."
  },
  {
    name: "Rhysida", aliases: ["Vice Society successor (assessed)"],
    origin: "Unknown", attribution: "Cybercriminal",
    targets: ["Healthcare", "Education", "Government", "Manufacturing"],
    ttps: ["T1190", "T1078", "T1486", "T1490", "T1059"],
    malware: ["Rhysida ransomware"],
    campaigns: ["British Library attack 2023", "Chilean Army breach", "Multiple US hospital attacks"],
    description: "Ransomware group targeting healthcare and education sectors, linked to the former Vice Society operation."
  },
  {
    name: "Play", aliases: ["PlayCrypt", "Balloonfly"],
    origin: "Unknown", attribution: "Cybercriminal",
    targets: ["Government", "Technology", "Telecom", "Manufacturing"],
    ttps: ["T1190", "T1078", "T1486", "T1490", "T1059", "T1003"],
    malware: ["Play ransomware"],
    campaigns: ["City of Oakland attack 2023", "Rackspace breach 2022", "Multiple government attacks"],
    description: "Ransomware group known for exploiting known vulnerabilities in Microsoft Exchange and FortiOS for initial access."
  },
  {
    name: "8Base", aliases: ["Phobos affiliate"],
    origin: "Unknown", attribution: "Cybercriminal (linked to RansomHouse)",
    targets: ["SMBs", "Professional services", "Manufacturing", "Construction"],
    ttps: ["T1190", "T1078", "T1486", "T1490", "T1059"],
    malware: ["Phobos ransomware variant"],
    campaigns: ["Mass targeting of small-to-medium businesses 2023-2024"],
    description: "Prolific ransomware group targeting SMBs, using a Phobos ransomware variant with custom modifications."
  },
  {
    name: "BianLian", aliases: ["BianDuck"],
    origin: "Unknown", attribution: "Cybercriminal",
    targets: ["Healthcare", "Professional services", "Manufacturing", "Financial"],
    ttps: ["T1190", "T1078", "T1567", "T1486", "T1059", "T1003"],
    malware: ["BianLian ransomware (Go-based)", "Custom Go backdoors"],
    campaigns: ["Shifted from encryption to pure data extortion 2023", "Save the Children breach"],
    description: "Ransomware group that pivoted from encryption to pure data theft and extortion after a free decryptor was released."
  },
  {
    name: "Akira", aliases: ["Storm-1567"],
    origin: "Unknown", attribution: "Cybercriminal (former Conti members assessed)",
    targets: ["SMBs", "Education", "Finance", "Healthcare", "Manufacturing"],
    ttps: ["T1133", "T1078", "T1486", "T1490", "T1059.001", "T1003"],
    malware: ["Akira ransomware (C++, later Rust)", "Megazord (Rust rewrite)"],
    campaigns: ["Cisco VPN exploitation campaign", "VMware ESXi Linux encryptor deployment"],
    description: "Fast-growing ransomware operation with links to former Conti members, known for targeting Cisco VPN appliances."
  },
  {
    name: "Medusa", aliases: ["MedusaLocker (different group)"],
    origin: "Unknown", attribution: "Cybercriminal",
    targets: ["Education", "Healthcare", "Government", "Technology"],
    ttps: ["T1190", "T1133", "T1078", "T1486", "T1490", "T1059"],
    malware: ["Medusa ransomware"],
    campaigns: ["Minneapolis Public Schools attack 2023", "Multiple US school district attacks"],
    description: "Ransomware group notably targeting school districts and healthcare organizations, using Telegram for data leak negotiations."
  },
  {
    name: "Storm-0978", aliases: ["RomCom", "Tropical Scorpius", "UNC2596", "Void Rabisu"],
    origin: "Russia", attribution: "Cybercriminal with GRU ties (assessed)",
    targets: ["Government", "Military", "Defense", "Political entities", "IT"],
    ttps: ["T1566.001", "T1203", "T1059", "T1078", "T1071.001", "T1486"],
    malware: ["RomCom RAT", "Industrial Spy ransomware", "Underground ransomware"],
    campaigns: ["Ukrainian government targeting 2022-2023", "NATO Summit targeting 2023", "Office zero-day exploitation"],
    description: "Russian group blending espionage and ransomware operations, targeting Ukrainian military and NATO allies."
  },
  {
    name: "Lapsus$", aliases: ["DEV-0537"],
    origin: "UK/Brazil", attribution: "Teenage hacker collective (members arrested)",
    targets: ["Technology", "Telecom", "Healthcare", "Government"],
    ttps: ["T1566.004", "T1078", "T1199", "T1657", "T1003", "T1567"],
    malware: ["No custom malware — used social engineering and insider recruitment"],
    campaigns: ["NVIDIA breach 2022", "Samsung breach 2022", "Microsoft breach 2022", "Okta breach 2022", "Uber breach 2022"],
    description: "Notorious teenage hacking group that breached major tech companies through social engineering, SIM swapping, and insider recruitment."
  },
  {
    name: "UNC1151", aliases: ["Ghostwriter", "Storm-0257"],
    origin: "Belarus", attribution: "Belarusian military intelligence (GRU cooperation)",
    targets: ["Poland", "Lithuania", "Latvia", "Ukraine", "NATO", "Media"],
    ttps: ["T1566.001", "T1566.002", "T1078", "T1584.001", "T1059", "T1027"],
    malware: ["SunSeed", "MicroBackdoor", "Cobalt Strike"],
    campaigns: ["Ghostwriter influence operations", "Credential phishing against NATO countries", "Anti-NATO disinformation campaigns"],
    description: "Belarusian group conducting espionage and influence operations against NATO countries, particularly Poland and the Baltic states."
  },
  {
    name: "SpacePirates", aliases: ["Unknown"],
    origin: "China", attribution: "Chinese state-affiliated",
    targets: ["Aerospace", "IT", "Defense", "Government"],
    ttps: ["T1566.001", "T1059", "T1055", "T1071.001", "T1027", "T1105"],
    malware: ["Deed RAT", "ShadowPad", "PlugX", "Zupdax"],
    campaigns: ["Russian aerospace targeting", "Georgian government targeting"],
    description: "Chinese espionage group targeting aerospace and defense sectors, uniquely including Russian entities."
  },
  {
    name: "ToddyCat", aliases: ["Unknown"],
    origin: "China", attribution: "Chinese state-affiliated",
    targets: ["Government", "Military", "Telecom", "Southeast Asia", "Europe"],
    ttps: ["T1190", "T1059", "T1505.003", "T1071.001", "T1027", "T1055"],
    malware: ["Samurai", "Ninja", "Custom loaders"],
    campaigns: ["Microsoft Exchange exploitation 2021", "Southeast Asian government targeting"],
    description: "Sophisticated Chinese group that exploited Exchange vulnerabilities in parallel with Hafnium, maintaining separate infrastructure and custom tooling."
  },
  {
    name: "Asylum Ambuscade", aliases: ["TA473"],
    origin: "Unknown", attribution: "Cybercriminal with possible state ties",
    targets: ["Government", "Finance", "Cryptocurrency", "SMBs"],
    ttps: ["T1566.001", "T1190", "T1059", "T1078", "T1071.001"],
    malware: ["SunSeed", "AHKBOT", "Node.js-based RATs"],
    campaigns: ["European government officials targeting 2022", "Cryptocurrency theft operations"],
    description: "Unusual group conducting both espionage against government officials and financially motivated cybercrime."
  },
  {
    name: "Daggerfly", aliases: ["Evasive Panda", "Bronze Highland", "StormBamboo"],
    origin: "China", attribution: "MSS-affiliated",
    targets: ["Telecom", "Government", "NGOs", "Education", "Democracy activists"],
    ttps: ["T1195.002", "T1059", "T1078", "T1071.001", "T1027", "T1055"],
    malware: ["MgBot", "Nightdoor", "MACMA (macOS)", "Suzafk"],
    campaigns: ["ISP-level DNS poisoning for supply chain attacks", "Tibetan activist targeting", "Hong Kong democracy movement targeting"],
    description: "Chinese group with ISP-level access capability, using DNS poisoning to deliver malware through legitimate software update mechanisms."
  },
  {
    name: "GoldenJackal", aliases: ["Unknown"],
    origin: "Unknown", attribution: "Suspected nation-state",
    targets: ["Government", "Diplomatic", "Air-gapped systems"],
    ttps: ["T1091", "T1052", "T1059", "T1078", "T1027", "T1001"],
    malware: ["GoldenDealer", "GoldenHowl", "GoldenRobo", "JackalControl", "JackalSteal"],
    campaigns: ["European government air-gapped network compromise", "South Asian embassy targeting"],
    description: "Sophisticated group specializing in compromising air-gapped government networks using USB-based malware propagation."
  },
  {
    name: "CloudAtlas", aliases: ["Inception", "Red October successor"],
    origin: "Russia (assessed)", attribution: "Unknown affiliation",
    targets: ["Government", "Diplomatic", "Aerospace", "Research", "Central Asia", "Russia"],
    ttps: ["T1566.001", "T1203", "T1059", "T1071.001", "T1027", "T1036"],
    malware: ["PowerShower", "VBShower", "VBCloud"],
    campaigns: ["Post-Soviet state government targeting", "Russian government entity targeting"],
    description: "Espionage group uniquely targeting both Western and Russian government entities, using cloud services for C2."
  },
  {
    name: "Donot Team", aliases: ["APT-C-35", "SectorE02"],
    origin: "India", attribution: "Indian state-affiliated (assessed)",
    targets: ["Pakistan", "Sri Lanka", "Bangladesh", "Government", "Military", "Diplomatic"],
    ttps: ["T1566.001", "T1203", "T1059", "T1547.001", "T1071.001", "T1027"],
    malware: ["yty framework", "DarkMusical", "Gedit"],
    campaigns: ["Pakistani military targeting", "Sri Lankan government targeting"],
    description: "Indian-attributed group primarily targeting South Asian military and diplomatic targets."
  },
  {
    name: "ScarCruft", aliases: ["APT37", "Reaper", "Group123", "Ricochet Chollima", "InkySquid"],
    origin: "North Korea", attribution: "MSS (Ministry of State Security)",
    targets: ["South Korea", "Japan", "Vietnam", "Middle East", "Defectors", "Journalists"],
    ttps: ["T1566.001", "T1059", "T1203", "T1547.001", "T1071.001", "T1027", "T1055"],
    malware: ["RokRAT", "Bluelight", "Dolphin", "GOLDBACKDOOR", "M2RAT"],
    campaigns: ["South Korean government targeting", "North Korean defector surveillance", "Internet Explorer zero-day exploitation"],
    description: "North Korean espionage group focused on South Korean targets and North Korean defectors, with developing mobile malware capabilities."
  },
  {
    name: "Transparent Tribe", aliases: ["APT36", "Mythic Leopard", "ProjectM", "C-Major"],
    origin: "Pakistan", attribution: "Pakistani military intelligence (ISI-linked)",
    targets: ["India", "Afghanistan", "Military", "Government", "Education", "Diplomatic"],
    ttps: ["T1566.001", "T1204", "T1059", "T1547.001", "T1071.001", "T1027", "T1113"],
    malware: ["CrimsonRAT", "ObliqueRAT", "CapraRAT (Android)", "Poseidon"],
    campaigns: ["Indian military personnel targeting", "Afghan government targeting", "Android spyware campaigns against Indian military"],
    description: "Pakistani state-linked group conducting espionage against Indian military and government using custom RATs and mobile malware."
  },
  {
    name: "Tonto Team", aliases: ["Earth Akhlut", "CactusPete", "Karma Panda"],
    origin: "China", attribution: "PLA (assessed)",
    targets: ["Government", "Military", "Technology", "Russia", "South Korea", "Japan"],
    ttps: ["T1566.001", "T1190", "T1059", "T1078", "T1071.001", "T1027"],
    malware: ["Bisonal", "Delf", "ShadowPad light"],
    campaigns: ["Russian government targeting", "Japanese defense sector targeting"],
    description: "Chinese military-linked group primarily targeting Northeast Asian countries and uniquely including Russian government entities."
  },
  {
    name: "TA410", aliases: ["FlowingFrog", "LookingFrog", "JollyFrog"],
    origin: "China", attribution: "MSS-affiliated",
    targets: ["Utilities", "Government", "Diplomatic", "Manufacturing", "Education"],
    ttps: ["T1190", "T1059", "T1078", "T1003", "T1071.001", "T1027"],
    malware: ["FlowCloud", "LookBack", "X4", "ShadowPad"],
    campaigns: ["US utilities sector targeting", "Diplomatic targeting in Middle East"],
    description: "Chinese espionage group with three subgroups, notably targeting US utility companies."
  },
  {
    name: "UNC3886", aliases: ["Unknown"],
    origin: "China", attribution: "Chinese state-affiliated",
    targets: ["Defense", "Government", "Telecom", "Technology"],
    ttps: ["T1190", "T1059", "T1078", "T1542", "T1027", "T1055", "T1014"],
    malware: ["REPTILE rootkit", "MEDUSA", "Custom hypervisor implants"],
    campaigns: ["VMware ESXi zero-day exploitation 2023", "Fortinet zero-day exploitation", "Juniper router compromise"],
    description: "Sophisticated Chinese group targeting network edge devices and hypervisors with zero-days, achieving firmware-level persistence."
  },
  {
    name: "UNC4841", aliases: ["Unknown"],
    origin: "China", attribution: "Chinese state-affiliated",
    targets: ["Government", "Academic", "Defense", "Technology"],
    ttps: ["T1190", "T1059", "T1505.003", "T1078", "T1071.001", "T1027"],
    malware: ["SEASPY", "SALTWATER", "SEASIDE", "WHIRLPOOL", "SUBMARINE"],
    campaigns: ["Barracuda ESG zero-day (CVE-2023-2868) mass exploitation"],
    description: "Chinese group that exploited a Barracuda email gateway zero-day to compromise government and defense organizations worldwide."
  },
  {
    name: "Pioneer Kitten", aliases: ["Fox Kitten", "Parisite", "UNC757", "Lemon Sandstorm"],
    origin: "Iran", attribution: "MOIS contractor",
    targets: ["Government", "Defense", "Technology", "Healthcare"],
    ttps: ["T1190", "T1078", "T1133", "T1003", "T1071.001", "T1486"],
    malware: ["Pay2Key ransomware", "Custom SSH tunneling tools"],
    campaigns: ["VPN appliance exploitation (Pulse Secure, F5, Citrix)", "Selling access to ransomware affiliates"],
    description: "Iranian group that exploits VPN appliances for initial access and monetizes access by selling it to ransomware operators."
  },
  {
    name: "Vice Society", aliases: ["DEV-0832", "Vanilla Tempest"],
    origin: "Russia (assessed)", attribution: "Cybercriminal",
    targets: ["Education", "Healthcare", "Manufacturing"],
    ttps: ["T1190", "T1078", "T1486", "T1490", "T1059"],
    malware: ["Multiple third-party ransomware (HelloKitty, Zeppelin, own PolyVice)"],
    campaigns: ["Los Angeles Unified School District attack 2022", "Multiple UK school attacks"],
    description: "Ransomware group heavily targeting the education sector, known for using multiple different ransomware families."
  },
  {
    name: "Night Dragon", aliases: ["Unknown"],
    origin: "China", attribution: "Chinese individuals",
    targets: ["Energy", "Oil & gas", "Petrochemical"],
    ttps: ["T1566.002", "T1059", "T1078", "T1003", "T1071.001"],
    malware: ["zwShell", "Custom RATs", "Poison Ivy"],
    campaigns: ["Global energy company espionage 2009-2011"],
    description: "Early Chinese cyber espionage operation targeting global energy companies for competitive intelligence on oil and gas deals."
  },
  {
    name: "IronHusky", aliases: ["Unknown"],
    origin: "China", attribution: "Chinese state-affiliated",
    targets: ["Government", "Military", "Mongolia", "Russia", "Belarus"],
    ttps: ["T1190", "T1059", "T1078", "T1071.001", "T1027"],
    malware: ["MysterySnail", "IronHusky RAT"],
    campaigns: ["Mongolian government targeting", "Russian military targeting"],
    description: "Chinese espionage group targeting Mongolian and Russian entities using Windows zero-day vulnerabilities."
  },
  {
    name: "Winnti", aliases: ["APT41 subgroup", "Axiom", "Barium", "Wicked Panda"],
    origin: "China", attribution: "MSS contractors",
    targets: ["Gaming", "Technology", "Software", "Telecom", "Pharmaceutical"],
    ttps: ["T1195.002", "T1059", "T1078", "T1003", "T1071.001", "T1027", "T1055"],
    malware: ["Winnti backdoor", "ShadowPad", "PlugX", "Spyder"],
    campaigns: ["Gaming industry supply chain 2011-2015", "CCleaner supply chain 2017", "ASUS Live Update supply chain 2019"],
    description: "Umbrella group name for Chinese operations conducting supply chain attacks and IP theft from technology companies."
  },
  {
    name: "Stone Panda", aliases: ["APT10", "MenuPass", "Red Apollo", "POTASSIUM", "Cicada"],
    origin: "China", attribution: "MSS Tianjin Bureau (indicted operatives)",
    targets: ["MSPs", "Technology", "Defense", "Government", "Healthcare", "Mining"],
    ttps: ["T1199", "T1059", "T1078", "T1003", "T1071.001", "T1027", "T1055"],
    malware: ["QuasarRAT", "PlugX", "Haymaker", "SodaMaster", "LODEINFO"],
    campaigns: ["Cloud Hopper (MSP compromise for downstream access to hundreds of companies)", "Japanese defense contractor targeting"],
    description: "Chinese group that pioneered the MSP compromise strategy, gaining access to hundreds of downstream companies through a handful of managed service providers."
  },
  {
    name: "Tick", aliases: ["Bronze Butler", "REDBALDKNIGHT", "Stalker Panda"],
    origin: "China", attribution: "PLA-affiliated",
    targets: ["Japan", "South Korea", "Defense", "Technology", "Aerospace"],
    ttps: ["T1566.001", "T1059", "T1547.001", "T1071.001", "T1027", "T1055"],
    malware: ["Daserf", "xxmm", "Datper", "ShadowPad variant"],
    campaigns: ["Japanese defense industry targeting", "South Korean technology sector"],
    description: "Chinese espionage group focused on Japanese and South Korean defense and technology sectors."
  },
  {
    name: "Nomadic Octopus", aliases: ["DustSquad"],
    origin: "Russia (assessed)", attribution: "Unknown affiliation",
    targets: ["Central Asian governments", "Diplomatic", "Political"],
    ttps: ["T1566.001", "T1059", "T1547.001", "T1071.001", "T1027"],
    malware: ["Octopus", "Paperbug"],
    campaigns: ["Central Asian political targeting", "Tajikistan telecom compromise"],
    description: "Espionage group targeting Central Asian government and political entities."
  },
  {
    name: "Machete", aliases: ["APT-C-43", "El Machete"],
    origin: "Latin America (assessed)", attribution: "Unknown, possibly Venezuelan",
    targets: ["Military", "Government", "Diplomatic", "Latin America"],
    ttps: ["T1566.001", "T1059.006", "T1547.001", "T1071.001", "T1113", "T1056.001"],
    malware: ["Machete (Python-based)", "Pyark"],
    campaigns: ["Venezuelan military targeting", "Ecuadorian government espionage", "Colombian military targeting"],
    description: "Spanish-speaking espionage group targeting Latin American military and government entities with Python-based malware."
  },
  {
    name: "Poseidon Group", aliases: ["Unknown"],
    origin: "Brazil", attribution: "Brazilian cybercriminal/espionage",
    targets: ["Finance", "Telecom", "Energy", "Media", "Government", "Brazil/Latin America"],
    ttps: ["T1566.001", "T1059", "T1078", "T1003", "T1071.001"],
    malware: ["Custom IGT (Information Gathering Toolkit)"],
    campaigns: ["Brazilian corporate espionage", "Latin American government targeting"],
    description: "Brazilian group conducting corporate espionage and blackmail operations, using stolen data to win security consulting contracts."
  },
  {
    name: "SandCat", aliases: ["Unknown"],
    origin: "Uzbekistan", attribution: "Uzbek intelligence service (SNB)",
    targets: ["Journalists", "Dissidents", "Activists", "Diplomats"],
    ttps: ["T1566.001", "T1203", "T1059", "T1547.001", "T1071.001"],
    malware: ["Custom Delphi RATs", "Commercial spyware"],
    campaigns: ["Journalist and activist surveillance"],
    description: "Uzbek intelligence-linked group conducting surveillance of journalists and dissidents using commercial and custom spyware."
  },
  {
    name: "Bahamut", aliases: ["The White Company"],
    origin: "Unknown (mercenary)", attribution: "Hack-for-hire / private sector",
    targets: ["Government", "Defense", "Diplomatic", "Activists", "Middle East", "South Asia"],
    ttps: ["T1566.001", "T1204", "T1059", "T1071.001", "T1027", "T1437"],
    malware: ["Bahamut Android spyware", "Custom Windows RATs", "Fake VPN apps"],
    campaigns: ["Middle Eastern government targeting", "South Asian activist surveillance"],
    description: "Sophisticated hack-for-hire group conducting espionage for multiple clients, operating fake news websites and mobile spyware."
  },
  {
    name: "Gallium", aliases: ["Alloy Taurus", "Granite Typhoon"],
    origin: "China", attribution: "MSS-affiliated",
    targets: ["Telecom", "Finance", "Government", "Southeast Asia", "Africa"],
    ttps: ["T1190", "T1059", "T1078", "T1003", "T1071.001", "T1027"],
    malware: ["PingPull", "Sword2033", "China Chopper", "SoftEther VPN"],
    campaigns: ["African telecom provider targeting", "Southeast Asian government targeting"],
    description: "Chinese group targeting telecom providers in Southeast Asia and Africa for signals intelligence collection."
  },
  {
    name: "Flax Typhoon", aliases: ["Ethereal Panda"],
    origin: "China", attribution: "MSS contractor",
    targets: ["Taiwan", "Government", "Education", "Technology", "Critical infrastructure"],
    ttps: ["T1190", "T1078", "T1059", "T1218", "T1036", "T1562.001"],
    malware: ["Living-off-the-land (China Chopper, SoftEther VPN)"],
    campaigns: ["Taiwanese organization targeting 2023", "IoT botnet for proxy network 2024"],
    description: "Chinese group targeting Taiwanese entities using minimal malware and extensive living-off-the-land techniques, later found operating a massive IoT botnet."
  },
];

// ═══════════════════════════════════════════════════════════════════════════════
// CAMPAIGN TRACKER
// ═══════════════════════════════════════════════════════════════════════════════

export class CampaignTracker {
  constructor() { this.campaigns = []; }

  addCampaign({ name, actor, startDate, endDate, targets, infrastructure, iocs, ttps, description, confidenceLevel }) {
    this.campaigns.push({
      id: `CAMP-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      name, actor, startDate, endDate: endDate || null,
      targets: targets || [], infrastructure: infrastructure || [],
      iocs: iocs || [], ttps: ttps || [],
      description: description || "",
      confidenceLevel: confidenceLevel || "medium",
      created: new Date().toISOString(), updated: new Date().toISOString(),
    });
    return this.campaigns[this.campaigns.length - 1];
  }

  findByActor(actorName) {
    const n = actorName.toLowerCase();
    return this.campaigns.filter(c =>
      c.actor.toLowerCase().includes(n) ||
      APT_GROUPS.some(g => g.name.toLowerCase() === c.actor.toLowerCase() && g.aliases.some(a => a.toLowerCase().includes(n)))
    );
  }

  findByTTP(ttpId) { return this.campaigns.filter(c => c.ttps.includes(ttpId)); }
  findByTarget(sector) { const s = sector.toLowerCase(); return this.campaigns.filter(c => c.targets.some(t => t.toLowerCase().includes(s))); }
  findByIOC(ioc) { const v = ioc.toLowerCase(); return this.campaigns.filter(c => c.iocs.some(i => i.toLowerCase().includes(v))); }

  timeline() {
    return [...this.campaigns]
      .filter(c => c.startDate)
      .sort((a, b) => new Date(a.startDate) - new Date(b.startDate));
  }

  getOverlapping(startDate, endDate) {
    const s = new Date(startDate), e = new Date(endDate);
    return this.campaigns.filter(c => {
      const cs = new Date(c.startDate);
      const ce = c.endDate ? new Date(c.endDate) : new Date();
      return cs <= e && ce >= s;
    });
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// DIAMOND MODEL ANALYZER
// ═══════════════════════════════════════════════════════════════════════════════

export function diamondModel({ adversary, capability, infrastructure, victim }) {
  const score = { adversary: 0, capability: 0, infrastructure: 0, victim: 0 };
  const findings = [];

  if (adversary) {
    const group = APT_GROUPS.find(g => g.name.toLowerCase() === adversary.toLowerCase() || g.aliases.some(a => a.toLowerCase() === adversary.toLowerCase()));
    if (group) {
      score.adversary = 90;
      findings.push({ vertex: "adversary", detail: `Identified: ${group.name} (${group.origin})`, confidence: "high" });
    } else {
      score.adversary = 30;
      findings.push({ vertex: "adversary", detail: `Unknown actor: ${adversary}`, confidence: "low" });
    }
  }

  if (capability && capability.length > 0) {
    const sophistication = capability.filter(c => /zero.?day|firmware|supply.?chain|rootkit|kernel/i.test(c)).length;
    score.capability = Math.min(100, 40 + sophistication * 20);
    findings.push({ vertex: "capability", detail: `${capability.length} capabilities identified, sophistication: ${sophistication > 2 ? "high" : sophistication > 0 ? "medium" : "low"}`, confidence: sophistication > 0 ? "high" : "medium" });
  }

  if (infrastructure && infrastructure.length > 0) {
    const dedicated = infrastructure.filter(i => /dedicated|owned|bulletproof/i.test(i.type || "")).length;
    const shared = infrastructure.filter(i => /shared|cloud|compromised/i.test(i.type || "")).length;
    score.infrastructure = Math.min(100, 30 + dedicated * 15 + shared * 5);
    findings.push({ vertex: "infrastructure", detail: `${infrastructure.length} nodes (${dedicated} dedicated, ${shared} shared)`, confidence: dedicated > 0 ? "high" : "medium" });
  }

  if (victim) {
    score.victim = 50;
    findings.push({ vertex: "victim", detail: `Target: ${victim.name || "unknown"}, Sector: ${victim.sector || "unknown"}`, confidence: "medium" });
  }

  const overall = (score.adversary + score.capability + score.infrastructure + score.victim) / 4;
  return { scores: score, overall, findings, attributionConfidence: overall > 70 ? "high" : overall > 40 ? "medium" : "low" };
}

// ═══════════════════════════════════════════════════════════════════════════════
// KILL CHAIN COVERAGE ANALYZER
// ═══════════════════════════════════════════════════════════════════════════════

const KILL_CHAIN_PHASES = [
  { id: "recon", name: "Reconnaissance", description: "Adversary gathers information about the target" },
  { id: "weaponize", name: "Weaponization", description: "Adversary creates a deliverable payload" },
  { id: "deliver", name: "Delivery", description: "Adversary transmits the weapon to the target" },
  { id: "exploit", name: "Exploitation", description: "Adversary exploits a vulnerability to execute code" },
  { id: "install", name: "Installation", description: "Adversary installs persistent access" },
  { id: "c2", name: "Command & Control", description: "Adversary establishes remote control channel" },
  { id: "actions", name: "Actions on Objectives", description: "Adversary achieves their goal" },
];

const CONTROL_TO_PHASE_MAP = {
  "email_filter": ["deliver"], "web_proxy": ["deliver", "c2"], "firewall": ["deliver", "c2"],
  "endpoint_protection": ["exploit", "install", "actions"], "ids_ips": ["deliver", "exploit", "c2"],
  "siem": ["recon", "deliver", "exploit", "install", "c2", "actions"],
  "dlp": ["actions"], "network_segmentation": ["install", "c2", "actions"],
  "mfa": ["exploit", "install"], "patch_management": ["exploit"],
  "threat_intel": ["recon", "weaponize"], "user_training": ["deliver"],
  "sandbox": ["deliver", "exploit"], "edr": ["exploit", "install", "c2", "actions"],
  "dns_filter": ["deliver", "c2"], "application_whitelist": ["exploit", "install"],
  "backup": ["actions"], "encryption": ["actions"],
  "vuln_scanner": ["recon", "exploit"], "pen_testing": ["recon", "exploit", "install", "c2"],
  "log_monitoring": ["recon", "deliver", "exploit", "install", "c2", "actions"],
  "honeypot": ["recon", "install", "c2"], "deception": ["recon", "install", "c2"],
};

export function analyzeKillChainCoverage(controls) {
  const coverage = {};
  KILL_CHAIN_PHASES.forEach(p => { coverage[p.id] = { phase: p.name, controls: [], covered: false, strength: 0 }; });

  controls.forEach(control => {
    const phases = CONTROL_TO_PHASE_MAP[control.toLowerCase().replace(/\s+/g, "_")] || [];
    phases.forEach(phaseId => {
      if (coverage[phaseId]) {
        coverage[phaseId].controls.push(control);
        coverage[phaseId].covered = true;
        coverage[phaseId].strength = Math.min(100, coverage[phaseId].strength + 25);
      }
    });
  });

  const gaps = KILL_CHAIN_PHASES.filter(p => !coverage[p.id].covered).map(p => p.name);
  const weakPhases = KILL_CHAIN_PHASES.filter(p => coverage[p.id].strength > 0 && coverage[p.id].strength < 50).map(p => p.name);
  const overallScore = KILL_CHAIN_PHASES.reduce((s, p) => s + coverage[p.id].strength, 0) / KILL_CHAIN_PHASES.length;

  return {
    coverage, gaps, weakPhases, overallScore,
    recommendations: gaps.map(g => `No controls covering "${g}" phase — add detection/prevention for this stage`),
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// ATTACK TREE BUILDER
// ═══════════════════════════════════════════════════════════════════════════════

export class AttackTreeNode {
  constructor(name, { type = "AND", probability = 0.5, cost = "medium", difficulty = "medium", description = "" } = {}) {
    this.name = name;
    this.type = type; // AND = all children must succeed, OR = any child succeeds
    this.probability = probability;
    this.cost = cost;
    this.difficulty = difficulty;
    this.description = description;
    this.children = [];
    this.mitigations = [];
  }

  addChild(node) { this.children.push(node); return node; }
  addMitigation(name, effectiveness) { this.mitigations.push({ name, effectiveness: effectiveness || 0.5 }); }

  calculateRisk() {
    if (this.children.length === 0) {
      const mitigationFactor = this.mitigations.reduce((f, m) => f * (1 - m.effectiveness), 1);
      return this.probability * mitigationFactor;
    }

    const childRisks = this.children.map(c => c.calculateRisk());
    if (this.type === "AND") {
      return childRisks.reduce((a, b) => a * b, 1);
    } else {
      return 1 - childRisks.reduce((a, b) => a * (1 - b), 1);
    }
  }

  toJSON() {
    return {
      name: this.name, type: this.type, probability: this.probability,
      cost: this.cost, difficulty: this.difficulty, description: this.description,
      risk: this.calculateRisk(), mitigations: this.mitigations,
      children: this.children.map(c => c.toJSON()),
    };
  }
}

export function buildAttackTree(goal) {
  const root = new AttackTreeNode(goal, { type: "OR" });
  return root;
}

// ═══════════════════════════════════════════════════════════════════════════════
// STRIDE THREAT MODELING
// ═══════════════════════════════════════════════════════════════════════════════

const STRIDE_CATEGORIES = {
  S: {
    name: "Spoofing", description: "Pretending to be something or someone else",
    questions: [
      "Can an attacker impersonate another user?",
      "Can authentication tokens be stolen or forged?",
      "Can the source of data be falsified?",
      "Can an attacker impersonate the system to users?",
      "Are there default or weak credentials?"
    ],
    mitigations: ["Strong authentication (MFA)", "Certificate pinning", "Digital signatures", "Session management"],
  },
  T: {
    name: "Tampering", description: "Modifying data or code without authorization",
    questions: [
      "Can data in transit be modified?",
      "Can stored data be modified without detection?",
      "Can configuration files be altered?",
      "Can audit logs be tampered with?",
      "Can code or binaries be modified?"
    ],
    mitigations: ["Integrity checks (HMAC/signatures)", "Access controls", "Tamper-evident logging", "Code signing"],
  },
  R: {
    name: "Repudiation", description: "Claiming to not have performed an action",
    questions: [
      "Can a user deny performing a transaction?",
      "Are actions logged with sufficient detail?",
      "Can logs be modified to hide activity?",
      "Are timestamps reliable and tamper-proof?",
      "Is there non-repudiation for critical operations?"
    ],
    mitigations: ["Comprehensive audit logging", "Digital signatures", "Timestamps from trusted sources", "Immutable log storage"],
  },
  I: {
    name: "Information Disclosure", description: "Exposing data to unauthorized parties",
    questions: [
      "Can sensitive data be intercepted in transit?",
      "Are error messages revealing internal details?",
      "Can backup data be accessed without authorization?",
      "Are secrets (keys, passwords) stored securely?",
      "Can side channels leak information?"
    ],
    mitigations: ["Encryption in transit (TLS)", "Encryption at rest", "Access controls", "Data classification", "Minimal error messages"],
  },
  D: {
    name: "Denial of Service", description: "Making the system unavailable",
    questions: [
      "Can the system be overwhelmed by requests?",
      "Are there resource exhaustion vulnerabilities?",
      "Can critical services be disrupted?",
      "Are there single points of failure?",
      "Can an attacker cause data corruption that halts the system?"
    ],
    mitigations: ["Rate limiting", "Load balancing", "Resource quotas", "Redundancy", "Input validation"],
  },
  E: {
    name: "Elevation of Privilege", description: "Gaining capabilities beyond what is authorized",
    questions: [
      "Can a normal user gain admin privileges?",
      "Are there privilege escalation paths?",
      "Can input validation be bypassed?",
      "Are there insecure default configurations?",
      "Can a guest gain authenticated access?"
    ],
    mitigations: ["Least privilege principle", "Input validation", "Secure defaults", "Privilege separation", "Regular access reviews"],
  },
};

export function strideAnalysis(component) {
  const results = {};
  for (const [key, cat] of Object.entries(STRIDE_CATEGORIES)) {
    results[key] = {
      category: cat.name, description: cat.description,
      component: component.name || component,
      threats: cat.questions.map((q, i) => ({
        id: `${key}-${i + 1}`, question: q,
        applicable: true, // Default to applicable, user should review
        severity: "medium", notes: "",
      })),
      mitigations: cat.mitigations,
    };
  }
  return results;
}

// ═══════════════════════════════════════════════════════════════════════════════
// DREAD RISK CALCULATOR
// ═══════════════════════════════════════════════════════════════════════════════

export function dreadScore({ damage, reproducibility, exploitability, affectedUsers, discoverability }) {
  const clamp = v => Math.max(0, Math.min(10, v || 0));
  const d = clamp(damage), r = clamp(reproducibility), e = clamp(exploitability);
  const a = clamp(affectedUsers), disc = clamp(discoverability);
  const total = (d + r + e + a + disc) / 5;

  let rating;
  if (total >= 8) rating = "critical";
  else if (total >= 6) rating = "high";
  else if (total >= 4) rating = "medium";
  else if (total >= 2) rating = "low";
  else rating = "informational";

  return {
    scores: { damage: d, reproducibility: r, exploitability: e, affectedUsers: a, discoverability: disc },
    total: Math.round(total * 10) / 10, rating,
    recommendation: rating === "critical" ? "Immediate remediation required" :
      rating === "high" ? "Remediate within 30 days" :
      rating === "medium" ? "Remediate within 90 days" :
      rating === "low" ? "Remediate in next release cycle" :
      "Accept risk or remediate at convenience",
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// ZERO-DAY DETECTION HEURISTICS
// ═══════════════════════════════════════════════════════════════════════════════

export const ZERO_DAY_INDICATORS = {
  processAnomalies: [
    { pattern: "Unusual parent-child process relationships", examples: ["winword.exe -> cmd.exe -> powershell.exe", "excel.exe -> rundll32.exe", "outlook.exe -> mshta.exe"], score: 85 },
    { pattern: "Legitimate process spawning shell", examples: ["svchost.exe -> cmd.exe", "spoolsv.exe -> powershell.exe", "w3wp.exe -> cmd.exe"], score: 90 },
    { pattern: "Process running from unusual location", examples: ["C:\\Users\\Public\\*.exe", "C:\\ProgramData\\*.exe", "C:\\Windows\\Temp\\*.exe"], score: 75 },
    { pattern: "Process with anomalous command line length", examples: ["Encoded PowerShell > 500 chars", "Base64 strings in command line"], score: 80 },
    { pattern: "Unsigned process loading into signed process", examples: ["DLL injection into explorer.exe", "DLL sideloading in legitimate apps"], score: 85 },
    { pattern: "Process making direct syscalls (bypassing API)", examples: ["Nt* syscall stubs", "Heaven's Gate technique (32->64 bit)"], score: 95 },
  ],
  networkAnomalies: [
    { pattern: "DNS requests to newly registered domains (< 30 days)", score: 70 },
    { pattern: "HTTPS connections with self-signed certificates", score: 60 },
    { pattern: "Beaconing pattern (periodic callbacks at regular intervals)", score: 85 },
    { pattern: "DNS-over-HTTPS to non-standard resolvers", score: 75 },
    { pattern: "Large data transfers to cloud storage during off-hours", score: 80 },
    { pattern: "Connections to TOR exit nodes or known anonymization services", score: 70 },
    { pattern: "SMB traffic to external IPs", score: 90 },
    { pattern: "RDP from unusual source IPs or at unusual times", score: 75 },
  ],
  fileAnomalies: [
    { pattern: "Modification of system binaries", examples: ["svchost.exe", "lsass.exe", "csrss.exe modified"], score: 95 },
    { pattern: "New files in system directories with recent timestamps", score: 70 },
    { pattern: "Files with double extensions", examples: ["document.pdf.exe", "image.jpg.scr"], score: 65 },
    { pattern: "Encrypted/compressed files created in temp directories", score: 75 },
    { pattern: "Scheduled task or service creation from unusual paths", score: 80 },
    { pattern: "Registry modification for persistence (Run keys, services)", score: 75 },
    { pattern: "WMI subscription creation for persistence", score: 85 },
    { pattern: "Boot record or firmware modification", score: 98 },
  ],
  memoryAnomalies: [
    { pattern: "Code injection into running processes", score: 90 },
    { pattern: "Reflective DLL loading (no file on disk)", score: 95 },
    { pattern: "Process hollowing (legitimate process with replaced code)", score: 95 },
    { pattern: "RWX memory regions in unexpected processes", score: 85 },
    { pattern: "Unlinked DLLs in process memory", score: 90 },
    { pattern: "Shellcode patterns in memory (NOP sleds, egg hunters)", score: 85 },
  ],
};

export function assessZeroDayRisk(indicators) {
  let totalScore = 0;
  let maxScore = 0;
  const triggered = [];

  for (const [category, patterns] of Object.entries(ZERO_DAY_INDICATORS)) {
    for (const pattern of patterns) {
      maxScore += pattern.score;
      if (indicators.some(ind => ind.toLowerCase().includes(pattern.pattern.toLowerCase().slice(0, 20)))) {
        totalScore += pattern.score;
        triggered.push({ category, pattern: pattern.pattern, score: pattern.score });
      }
    }
  }

  const riskPct = maxScore > 0 ? (totalScore / maxScore) * 100 : 0;
  return {
    riskScore: Math.round(riskPct),
    riskLevel: riskPct > 60 ? "critical" : riskPct > 40 ? "high" : riskPct > 20 ? "medium" : "low",
    triggeredIndicators: triggered,
    recommendation: riskPct > 60 ? "Isolate affected systems immediately, initiate incident response" :
      riskPct > 40 ? "Escalate to incident response team, begin forensic analysis" :
      riskPct > 20 ? "Investigate further, increase monitoring" :
      "Continue monitoring, no immediate action required",
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// SUPPLY CHAIN ATTACK DETECTOR
// ═══════════════════════════════════════════════════════════════════════════════

export const SUPPLY_CHAIN_PATTERNS = {
  dependencyConfusion: {
    description: "Internal package name registered on public registry",
    indicators: [
      "Package with internal naming convention appears on npmjs/PyPI/RubyGems",
      "Package has no README or minimal description",
      "Package was recently published (< 30 days)",
      "Package name closely matches an internal package",
      "Package has preinstall/postinstall scripts that execute network requests",
    ],
    detection: ["Monitor public registries for packages matching internal naming patterns", "Use package lock files to pin versions", "Configure private registry priority"],
  },
  typosquatting: {
    description: "Package name is a misspelling of a popular package",
    indicators: [
      "Package name is 1-2 characters different from popular package",
      "Package has significantly fewer downloads than the legitimate package",
      "Package contains obfuscated install scripts",
      "Author has no other packages",
      "Package was published very recently",
    ],
    detection: ["Use package verification tools", "Compare package hashes against known-good", "Review package source before install"],
  },
  buildPipeline: {
    description: "Compromised CI/CD pipeline or build system",
    indicators: [
      "Build output differs from source compilation",
      "Build system accessed unusual network resources",
      "Build timestamps don't match expected CI schedule",
      "Build artifacts contain unexpected dependencies",
      "Build environment variables modified unexpectedly",
    ],
    detection: ["Reproducible builds", "Build artifact signing", "Build environment isolation", "SLSA framework compliance"],
  },
  compromisedUpdate: {
    description: "Legitimate software update mechanism delivering malware",
    indicators: [
      "Update server TLS certificate changed unexpectedly",
      "Update binary hash doesn't match vendor-published hash",
      "Update payload significantly larger than previous updates",
      "Update triggers unusual system behaviors post-install",
      "Update delivered outside normal release schedule",
    ],
    detection: ["Pin update server certificates", "Verify update signatures", "Monitor update sizes", "Sandbox updates before deployment"],
    examples: ["SolarWinds Orion (2020)", "Kaseya VSA (2021)", "3CX Desktop App (2023)", "Codecov Bash Uploader (2021)"],
  },
};

export function assessSupplyChainRisk(packageInfo) {
  const risks = [];
  const { name, version, publishDate, author, downloads, scripts, dependencies } = packageInfo;

  if (publishDate) {
    const age = (Date.now() - new Date(publishDate).getTime()) / (1000 * 60 * 60 * 24);
    if (age < 30) risks.push({ type: "new_package", severity: "medium", detail: `Package published ${Math.round(age)} days ago` });
    if (age < 7) risks.push({ type: "very_new_package", severity: "high", detail: `Package published ${Math.round(age)} days ago — very recent` });
  }

  if (scripts) {
    const suspicious = ["preinstall", "postinstall", "preuninstall"];
    suspicious.forEach(s => {
      if (scripts[s]) {
        const cmd = scripts[s].toLowerCase();
        if (/curl|wget|http|net|socket|eval|exec/i.test(cmd)) {
          risks.push({ type: "suspicious_script", severity: "high", detail: `${s} script contains network/exec calls: ${scripts[s].slice(0, 100)}` });
        }
      }
    });
  }

  if (downloads !== undefined && downloads < 100) {
    risks.push({ type: "low_downloads", severity: "low", detail: `Only ${downloads} downloads — possibly typosquatting` });
  }

  if (dependencies && Object.keys(dependencies).length > 50) {
    risks.push({ type: "excessive_deps", severity: "medium", detail: `${Object.keys(dependencies).length} dependencies — large attack surface` });
  }

  const overallRisk = risks.reduce((max, r) => {
    const sev = { critical: 4, high: 3, medium: 2, low: 1 };
    return Math.max(max, sev[r.severity] || 0);
  }, 0);

  return {
    package: name, version,
    risks,
    overallRisk: ["none", "low", "medium", "high", "critical"][overallRisk],
    recommendation: overallRisk >= 3 ? "Do not install — review source code manually" :
      overallRisk >= 2 ? "Review package source before installing" :
      "Package appears low-risk, standard precautions apply",
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// FIRMWARE ANALYSIS CHECKLIST
// ═══════════════════════════════════════════════════════════════════════════════

export const FIRMWARE_ANALYSIS_CHECKLIST = {
  uefi: [
    { check: "Secure Boot enabled and enforcing", severity: "critical", description: "Ensures only signed bootloaders and kernel modules load" },
    { check: "UEFI firmware version up to date", severity: "high", description: "Outdated firmware may contain known vulnerabilities" },
    { check: "SPI flash write protection enabled", severity: "critical", description: "Prevents unauthorized firmware modification" },
    { check: "Platform Secure Boot keys validated", severity: "high", description: "Ensure no unauthorized keys in db/dbx" },
    { check: "SMM (System Management Mode) protection", severity: "critical", description: "Prevent SMM-based rootkits" },
    { check: "Intel Boot Guard or AMD PSB enabled", severity: "high", description: "Hardware root of trust for boot process" },
    { check: "TPM present and enabled (2.0 recommended)", severity: "high", description: "Hardware-based integrity measurement" },
    { check: "Measured Boot / Trusted Boot configured", severity: "medium", description: "Record boot measurements in TPM PCRs" },
    { check: "DMA protection (IOMMU/VT-d) enabled", severity: "medium", description: "Prevent DMA-based attacks from peripherals" },
    { check: "Firmware password/admin password set", severity: "medium", description: "Prevent unauthorized BIOS configuration changes" },
  ],
  router: [
    { check: "Firmware hash matches vendor-published hash", severity: "critical" },
    { check: "Default credentials changed", severity: "critical" },
    { check: "Remote administration disabled or restricted", severity: "high" },
    { check: "Firmware update mechanism uses TLS + signature verification", severity: "high" },
    { check: "Unused services disabled (UPnP, WPS, Telnet)", severity: "medium" },
    { check: "DNS settings not modified (no DNS hijacking)", severity: "high" },
    { check: "VPN filter/config not tampered", severity: "high" },
    { check: "No unknown cron jobs or startup scripts", severity: "critical" },
  ],
  iot: [
    { check: "Firmware extracted and analyzed for hardcoded credentials", severity: "critical" },
    { check: "Debug interfaces disabled (JTAG, UART)", severity: "high" },
    { check: "Encrypted firmware update mechanism", severity: "high" },
    { check: "No unnecessary open ports", severity: "medium" },
    { check: "Certificate validation implemented correctly", severity: "high" },
    { check: "No known CVEs in embedded libraries", severity: "high" },
  ],
};

// ═══════════════════════════════════════════════════════════════════════════════
// NATION-STATE ATTACK PATTERNS
// ═══════════════════════════════════════════════════════════════════════════════

export const NATION_STATE_PATTERNS = {
  russia: {
    name: "Russia",
    agencies: ["GRU (Units 26165, 74455)", "SVR", "FSB (Centers 16, 18)"],
    characteristics: [
      "Destructive operations (wipers, infrastructure disruption)",
      "Information operations and election interference",
      "Living-off-the-land techniques for persistence",
      "Supply chain compromises",
      "Critical infrastructure targeting (energy, water)",
    ],
    typicalTTPs: ["T1566.001", "T1190", "T1059.001", "T1485", "T1561", "T1486", "T1078", "T1003"],
    primaryTargets: ["NATO governments", "Ukraine", "Critical infrastructure", "Elections", "Media"],
    notableOperations: ["NotPetya ($10B+ damage)", "SolarWinds", "Ukraine power grid attacks", "DNC hack"],
    indicators: ["Use of wipers alongside espionage tools", "Targeting of OT/ICS systems", "Political timing of operations"],
  },
  china: {
    name: "China",
    agencies: ["MSS (Ministry of State Security)", "PLA (Strategic Support Force)", "MSS Contractors"],
    characteristics: [
      "Intellectual property theft at massive scale",
      "Long-term persistent access (years)",
      "Supply chain compromise via hardware and software",
      "Targeting of telecommunications for SIGINT",
      "Living-off-the-land and edge device exploitation",
    ],
    typicalTTPs: ["T1190", "T1195.002", "T1078", "T1003", "T1071.001", "T1027", "T1055", "T1036"],
    primaryTargets: ["Technology", "Defense", "Telecom", "Government", "Healthcare", "Research"],
    notableOperations: ["Operation Cloud Hopper", "SolarWinds-adjacent operations", "US telecom penetration (Salt Typhoon)", "Exchange ProxyLogon mass exploitation"],
    indicators: ["Targeting of R&D and IP", "Pre-positioning on critical infrastructure", "Use of ShadowPad/PlugX families", "Working hours aligned to UTC+8"],
  },
  northKorea: {
    name: "North Korea",
    agencies: ["RGB (Reconnaissance General Bureau)", "Bureau 121", "Lab 110"],
    characteristics: [
      "Cryptocurrency theft for regime funding",
      "Destructive attacks for political signaling",
      "Financial institution targeting (SWIFT, banks)",
      "IT worker infiltration of Western companies",
      "Social engineering via fake job opportunities",
    ],
    typicalTTPs: ["T1566.001", "T1059", "T1486", "T1565.001", "T1078", "T1003", "T1071.001"],
    primaryTargets: ["Cryptocurrency/DeFi", "Finance", "Defense", "Media", "Government"],
    notableOperations: ["Sony Pictures destruction", "Bangladesh Bank $81M theft", "WannaCry ransomware", "Ronin Network $620M theft", "Atomic Wallet $35M theft"],
    indicators: ["Financial motivation alongside espionage", "Targeting crypto/DeFi platforms", "Use of fake job lures", "Working hours aligned to UTC+9"],
  },
  iran: {
    name: "Iran",
    agencies: ["IRGC (Islamic Revolutionary Guard Corps)", "MOIS (Ministry of Intelligence)"],
    characteristics: [
      "Destructive attacks disguised as ransomware",
      "Influence operations and hack-and-leak",
      "VPN appliance exploitation for initial access",
      "Targeting of dissidents and journalists",
      "Retaliatory attacks following geopolitical events",
    ],
    typicalTTPs: ["T1190", "T1566.001", "T1059", "T1486", "T1485", "T1078", "T1003"],
    primaryTargets: ["Israel", "Saudi Arabia", "US", "Dissidents", "Energy", "Telecom"],
    notableOperations: ["Shamoon wiper attacks", "Albanian government attacks 2022", "Israeli infrastructure targeting"],
    indicators: ["Wiper deployment disguised as ransomware", "Targeting aligned with geopolitical tensions", "VPN exploit chains", "Persona-based social engineering"],
  },
};

// ═══════════════════════════════════════════════════════════════════════════════
// UTILITY: SEARCH AND ATTRIBUTION
// ═══════════════════════════════════════════════════════════════════════════════

export function searchAPTGroups(query) {
  const q = query.toLowerCase();
  return APT_GROUPS.filter(g =>
    g.name.toLowerCase().includes(q) ||
    g.aliases.some(a => a.toLowerCase().includes(q)) ||
    g.origin.toLowerCase().includes(q) ||
    g.targets.some(t => t.toLowerCase().includes(q)) ||
    g.malware.some(m => m.toLowerCase().includes(q)) ||
    g.description.toLowerCase().includes(q)
  );
}

export function attributeByTTPs(observedTTPs) {
  const scores = APT_GROUPS.map(group => {
    const overlap = observedTTPs.filter(t => group.ttps.includes(t));
    return {
      group: group.name, origin: group.origin,
      matchedTTPs: overlap, matchCount: overlap.length,
      totalTTPs: group.ttps.length,
      matchPercentage: group.ttps.length > 0 ? Math.round((overlap.length / group.ttps.length) * 100) : 0,
    };
  });
  return scores.filter(s => s.matchCount > 0).sort((a, b) => b.matchPercentage - a.matchPercentage);
}

export function attributeByMalware(malwareName) {
  const n = malwareName.toLowerCase();
  return APT_GROUPS.filter(g => g.malware.some(m => m.toLowerCase().includes(n)));
}

export function getGroupsByOrigin(country) {
  const c = country.toLowerCase();
  return APT_GROUPS.filter(g => g.origin.toLowerCase().includes(c));
}

export function getGroupsByTarget(sector) {
  const s = sector.toLowerCase();
  return APT_GROUPS.filter(g => g.targets.some(t => t.toLowerCase().includes(s)));
}
