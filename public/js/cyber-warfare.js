// Darknode Cyber Warfare Defense & Critical Infrastructure Protection Engine
// Educational / authorized-defense content for cyber security operations
// All data is public-domain knowledge compiled for training and defense purposes.

// ── Nation-State Cyber Threat Actor Database ──────────────────────────────

export const THREAT_ACTORS = [
  {
    nation: "Russia",
    groups: [
      {
        name: "APT28 / Fancy Bear",
        org: "GRU Unit 26165 (85th Main Special Service Center)",
        aliases: ["Sofacy", "Pawn Storm", "Sednit", "Strontium", "IRON TWILIGHT", "Forest Blizzard"],
        type: "military_intelligence",
        active_since: 2004,
        targets: ["government", "military", "defense", "media", "political_organizations", "energy"],
        regions: ["NATO", "Ukraine", "Georgia", "EU", "Middle East"],
        capabilities: ["spear_phishing", "zero_day_exploits", "credential_harvesting", "watering_hole", "supply_chain", "wiper_malware"],
        known_tools: ["X-Agent", "X-Tunnel", "Zebrocy", "Seduploader", "Koadic", "Responder"],
        notable_ops: [
          { name: "DNC Hack", year: 2016, desc: "Breach of Democratic National Committee networks, exfiltration and public release of emails" },
          { name: "Bundestag Attack", year: 2015, desc: "Compromise of German parliament network, 16GB data exfiltrated" },
          { name: "Olympic Destroyer", year: 2018, desc: "Destructive attack on 2018 Pyeongchang Winter Olympics infrastructure, designed as false flag" },
          { name: "NotPetya Attribution", year: 2017, desc: "Global destructive ransomware causing $10B+ damage, initially targeted Ukraine via MEDoc update" }
        ],
        mitre_techniques: ["T1566.001", "T1190", "T1078", "T1027", "T1059.001", "T1053.005", "T1071.001", "T1567"]
      },
      {
        name: "APT29 / Cozy Bear",
        org: "SVR (Foreign Intelligence Service)",
        aliases: ["The Dukes", "CozyDuke", "YTTRIUM", "Midnight Blizzard", "IRON RITUAL", "Nobelium"],
        type: "foreign_intelligence",
        active_since: 2008,
        targets: ["government", "diplomatic", "think_tanks", "healthcare", "technology", "energy"],
        regions: ["US", "EU", "NATO", "Five Eyes"],
        capabilities: ["supply_chain_attacks", "cloud_exploitation", "stealth_persistence", "zero_day", "custom_malware"],
        known_tools: ["WellMess", "WellMail", "EnvyScout", "BoomBox", "NativeZone", "MagicWeb", "FoggyWeb"],
        notable_ops: [
          { name: "SolarWinds (SUNBURST)", year: 2020, desc: "Supply chain compromise of SolarWinds Orion, access to 18,000+ organizations including US government agencies" },
          { name: "COVID-19 Vaccine Research", year: 2020, desc: "Targeted vaccine research institutions in US, UK, Canada" },
          { name: "White House / State Dept", year: 2014, desc: "Breach of unclassified networks at White House, State Department, Joint Chiefs of Staff" },
          { name: "Microsoft 365 Attacks", year: 2023, desc: "Targeted Microsoft 365 tenants of government and diplomatic organizations via token theft" }
        ],
        mitre_techniques: ["T1195.002", "T1078.004", "T1550.001", "T1098.002", "T1114.002", "T1069.003"]
      },
      {
        name: "Sandworm",
        org: "GRU Unit 74455 (Main Center for Special Technologies)",
        aliases: ["Voodoo Bear", "IRIDIUM", "Seashell Blizzard", "IRON VIKING", "TeleBots"],
        type: "military_cyber_operations",
        active_since: 2009,
        targets: ["critical_infrastructure", "energy", "government", "media", "elections", "olympics"],
        regions: ["Ukraine", "EU", "US", "South Korea", "Georgia"],
        capabilities: ["ics_attacks", "wiper_malware", "destructive_operations", "supply_chain", "power_grid_attacks"],
        known_tools: ["BlackEnergy", "Industroyer", "Industroyer2", "NotPetya", "Olympic Destroyer", "CaddyWiper", "SwiftSlicer", "AcidRain", "WhisperGate"],
        notable_ops: [
          { name: "Ukraine Power Grid 2015", year: 2015, desc: "First confirmed cyber attack on a power grid, 230,000 customers lost power using BlackEnergy" },
          { name: "Ukraine Power Grid 2016", year: 2016, desc: "Second power grid attack using Industroyer/CrashOverride, automated ICS attack" },
          { name: "NotPetya", year: 2017, desc: "Most destructive cyberattack in history, $10B+ global damage, spread via Ukrainian tax software MEDoc" },
          { name: "Viasat Attack", year: 2022, desc: "AcidRain wiper attack on KA-SAT modems at start of Ukraine invasion, disrupted satellite communications across Europe" }
        ],
        mitre_techniques: ["T1059.001", "T1485", "T1561.001", "T1495", "T1529", "T1565.001"]
      },
      {
        name: "Turla",
        org: "FSB Center 16 (Signals Intelligence)",
        aliases: ["Snake", "Venomous Bear", "KRYPTON", "Secret Blizzard", "IRON HUNTER", "Waterbug"],
        type: "signals_intelligence",
        active_since: 1996,
        targets: ["government", "diplomatic", "military", "research", "pharmaceutical"],
        regions: ["Global", "Middle East", "EU", "Central Asia"],
        capabilities: ["satellite_hijacking", "custom_rootkits", "watering_hole", "supply_chain_via_other_apt"],
        known_tools: ["Snake", "Carbon", "Kazuar", "ComRAT", "LightNeuron", "Crutch", "TinyTurla", "Capibar"],
        notable_ops: [
          { name: "Snake/Uroburos", year: 2014, desc: "20-year espionage operation discovered, rootkit with satellite-based C2" },
          { name: "Hijacking APT34 Infrastructure", year: 2019, desc: "Unique operation hijacking Iranian APT34's C2 to conduct own operations" },
          { name: "Pentagon Breach", year: 2008, desc: "Breach of classified US military networks via infected USB drive (Agent.BTZ)" }
        ],
        mitre_techniques: ["T1071.004", "T1102", "T1036.005", "T1027.002", "T1055.001", "T1090.003"]
      }
    ]
  },
  {
    nation: "China",
    groups: [
      {
        name: "APT1 / Comment Crew",
        org: "PLA Unit 61398 (2nd Bureau, 3rd Department, General Staff)",
        aliases: ["Comment Crew", "Comment Panda", "BRONZE BUTLER"],
        type: "military_intelligence",
        active_since: 2006,
        targets: ["aerospace", "defense", "energy", "technology", "manufacturing", "media"],
        regions: ["US", "EU", "Japan", "South Korea", "Taiwan"],
        capabilities: ["spear_phishing", "custom_backdoors", "long_term_persistence", "data_exfiltration"],
        known_tools: ["WEBC2", "BISCUIT", "CALENDAR", "GLOOXMAIL", "MANITSME"],
        notable_ops: [
          { name: "Mandiant APT1 Report", year: 2013, desc: "First public attribution of state-sponsored hacking to a military unit, 141+ organizations compromised" }
        ],
        mitre_techniques: ["T1566.001", "T1059.003", "T1053.005", "T1071.001", "T1005", "T1560.001"]
      },
      {
        name: "APT10 / Stone Panda",
        org: "MSS Tianjin Bureau (Ministry of State Security)",
        aliases: ["MenuPass", "Red Apollo", "CVNX", "POTASSIUM", "Cicada"],
        type: "civilian_intelligence",
        active_since: 2009,
        targets: ["managed_service_providers", "cloud_providers", "technology", "aerospace", "telecom", "government"],
        regions: ["Global", "Japan", "US", "EU"],
        capabilities: ["cloud_hopper", "msp_targeting", "supply_chain", "island_hopping"],
        known_tools: ["PlugX", "Quasar RAT", "SodaMaster", "LODEINFO", "Ecipekac"],
        notable_ops: [
          { name: "Cloud Hopper", year: 2017, desc: "Massive campaign targeting managed service providers to access their customers, affecting companies across 12+ countries" },
          { name: "Operation SoftCell", year: 2019, desc: "Targeting telecommunications providers to access call detail records for intelligence collection" }
        ],
        mitre_techniques: ["T1199", "T1078.004", "T1059.001", "T1071.001", "T1550.002", "T1074.002"]
      },
      {
        name: "Volt Typhoon",
        org: "PRC State-Sponsored (attributed)",
        aliases: ["BRONZE SILHOUETTE", "Vanguard Panda", "DEV-0391"],
        type: "pre_positioning",
        active_since: 2021,
        targets: ["critical_infrastructure", "communications", "energy", "transportation", "water", "military"],
        regions: ["US", "Guam", "Pacific"],
        capabilities: ["living_off_the_land", "lotl_binaries", "zero_day", "router_compromise", "long_dwell_time"],
        known_tools: ["LOTL (native tools only)", "SOHO router botnets", "KV Botnet", "custom web shells"],
        notable_ops: [
          { name: "Critical Infrastructure Pre-Positioning", year: 2023, desc: "Discovered pre-positioned in US critical infrastructure for potential disruption during conflict, targets include Guam military facilities" },
          { name: "KV Botnet", year: 2024, desc: "Botnet of compromised SOHO routers used as operational relay infrastructure" }
        ],
        mitre_techniques: ["T1059.001", "T1059.003", "T1053.005", "T1078", "T1021.001", "T1018"]
      },
      {
        name: "APT41 / Double Dragon",
        org: "MSS / Chengdu 404 Network Technology",
        aliases: ["Winnti", "BARIUM", "Brass Typhoon", "WICKED PANDA"],
        type: "dual_espionage_and_criminal",
        active_since: 2012,
        targets: ["gaming", "healthcare", "telecom", "technology", "education", "media", "government"],
        regions: ["Global"],
        capabilities: ["supply_chain", "ransomware", "cryptomining", "zero_day", "dual_motivation"],
        known_tools: ["ShadowPad", "Winnti", "CROSSWALK", "SideWalk", "DUSTPAN", "DUSTTRAP", "Cobalt Strike"],
        notable_ops: [
          { name: "CCleaner Supply Chain", year: 2017, desc: "Backdoored CCleaner software update, distributed to 2.27 million users, secondary payload targeting tech companies" },
          { name: "ShadowPad Supply Chain", year: 2017, desc: "Backdoored NetSarang server management software, potentially millions of servers affected" },
          { name: "US Indictments", year: 2020, desc: "5 members indicted by US DOJ for computer intrusions affecting 100+ companies worldwide" }
        ],
        mitre_techniques: ["T1195.002", "T1059.001", "T1543.003", "T1055.001", "T1027.002", "T1070.004"]
      }
    ]
  },
  {
    nation: "North Korea",
    groups: [
      {
        name: "Lazarus Group",
        org: "RGB Bureau 121 (Reconnaissance General Bureau)",
        aliases: ["HIDDEN COBRA", "Zinc", "Diamond Sleet", "NICKEL ACADEMY", "Labyrinth Chollima"],
        type: "cyber_operations",
        active_since: 2009,
        targets: ["financial", "cryptocurrency", "defense", "energy", "media", "government"],
        regions: ["Global", "South Korea", "US", "Japan", "Southeast Asia"],
        capabilities: ["destructive_attacks", "financial_theft", "cryptocurrency_theft", "supply_chain", "zero_day"],
        known_tools: ["FALLCHILL", "Bankshot", "DRATzarus", "ELECTRICFISH", "AppleJeus", "BLINDINGCAN", "DTrack"],
        notable_ops: [
          { name: "Sony Pictures Hack", year: 2014, desc: "Destructive attack against Sony Pictures, data theft and release, retaliation for film 'The Interview'" },
          { name: "Bangladesh Bank Heist", year: 2016, desc: "Attempted theft of $951M from Bangladesh Central Bank via SWIFT network, $81M successfully stolen" },
          { name: "WannaCry", year: 2017, desc: "Global ransomware outbreak affecting 200,000+ computers in 150 countries, used EternalBlue exploit" },
          { name: "Ronin Bridge Theft", year: 2022, desc: "$620M cryptocurrency theft from Axie Infinity's Ronin Bridge, largest crypto theft at the time" },
          { name: "3CX Supply Chain", year: 2023, desc: "Supply chain attack on 3CX VoIP software, distributed trojanized installer to 600,000+ organizations" }
        ],
        mitre_techniques: ["T1566.001", "T1195.002", "T1486", "T1565.001", "T1059.006", "T1055"]
      },
      {
        name: "APT38 / BlueNoroff",
        org: "RGB (financially-focused unit)",
        aliases: ["Stardust Chollima", "Sapphire Sleet", "NICKEL GLADSTONE"],
        type: "financial_cyber_operations",
        active_since: 2014,
        targets: ["banks", "swift_network", "cryptocurrency_exchanges", "defi_platforms", "fintech"],
        regions: ["Global", "Southeast Asia", "Latin America", "Africa"],
        capabilities: ["swift_fraud", "atm_cashout", "cryptocurrency_theft", "defi_exploitation", "social_engineering"],
        known_tools: ["DYEPACK", "HERMES", "FASTCash", "AppleJeus", "TraderTraitor"],
        notable_ops: [
          { name: "FASTCash ATM Attacks", year: 2018, desc: "Simultaneous ATM cashout attacks across 30+ countries, intercepting ATM transaction verification" },
          { name: "Harmony Bridge", year: 2022, desc: "$100M stolen from Harmony blockchain bridge" },
          { name: "Crypto Social Engineering", year: 2023, desc: "Targeted crypto developers via fake job offers on LinkedIn, delivering malware via coding challenges" }
        ],
        mitre_techniques: ["T1566.003", "T1204.002", "T1059.007", "T1539", "T1565.001", "T1020"]
      },
      {
        name: "Kimsuky / Velvet Chollima",
        org: "RGB (intelligence collection unit)",
        aliases: ["Thallium", "ARCHIPELAGO", "Emerald Sleet", "Black Banshee", "STOLEN PENCIL"],
        type: "intelligence_collection",
        active_since: 2012,
        targets: ["think_tanks", "academia", "government", "media", "defectors", "nuclear_policy"],
        regions: ["South Korea", "US", "Japan", "EU"],
        capabilities: ["spear_phishing", "credential_theft", "information_collection", "social_engineering"],
        known_tools: ["BabyShark", "KGH_SPY", "KONNI", "RandomQuery", "FlowerPower", "FastViewer"],
        notable_ops: [
          { name: "Korea Hydro & Nuclear Power", year: 2014, desc: "Attack on South Korean nuclear plant operator, leaked reactor designs" },
          { name: "Academic Targeting", year: 2023, desc: "Impersonating journalists and academics to collect intelligence on North Korea policy positions" }
        ],
        mitre_techniques: ["T1566.001", "T1598.003", "T1204.001", "T1059.005", "T1114.002", "T1056.001"]
      }
    ]
  },
  {
    nation: "Iran",
    groups: [
      {
        name: "APT33 / Elfin",
        org: "IRGC (Islamic Revolutionary Guard Corps)",
        aliases: ["Refined Kitten", "MAGNALLIUM", "Peach Sandstorm", "HOLMIUM"],
        type: "military_cyber",
        active_since: 2013,
        targets: ["aviation", "energy", "petrochemical", "defense", "government"],
        regions: ["Saudi Arabia", "US", "South Korea", "Japan", "Middle East"],
        capabilities: ["destructive_malware", "spear_phishing", "password_spraying", "wiper_attacks"],
        known_tools: ["Shamoon", "StoneDrill", "DROPSHOT", "TURNEDUP", "Tickler"],
        notable_ops: [
          { name: "Shamoon Attacks", year: 2012, desc: "Wiper malware destroyed 35,000 workstations at Saudi Aramco" },
          { name: "Shamoon 2.0", year: 2016, desc: "Return of Shamoon targeting Saudi government and private sector" },
          { name: "Password Spraying Campaign", year: 2023, desc: "Large-scale password spraying against defense, satellite, pharmaceutical organizations globally" }
        ],
        mitre_techniques: ["T1110.003", "T1566.002", "T1485", "T1561.002", "T1059.001", "T1021.001"]
      },
      {
        name: "APT34 / OilRig",
        org: "MOIS (Ministry of Intelligence and Security)",
        aliases: ["Helix Kitten", "CRAMBUS", "Hazel Sandstorm", "CHRYSENE"],
        type: "intelligence_espionage",
        active_since: 2014,
        targets: ["government", "energy", "chemical", "telecom", "financial"],
        regions: ["Middle East", "US", "EU"],
        capabilities: ["dns_tunneling", "web_shells", "credential_harvesting", "supply_chain"],
        known_tools: ["BONDUPDATER", "QUADAGENT", "OopsIE", "VALUEVAULT", "Karkoff", "SideTwist"],
        notable_ops: [
          { name: "DNS Hijacking Campaign", year: 2019, desc: "Large-scale DNS hijacking campaign redirecting government and telecom domains to capture credentials" },
          { name: "Tool Leak", year: 2019, desc: "APT34 tools and victim data leaked publicly on Telegram by Lab Dookhtegan" }
        ],
        mitre_techniques: ["T1071.004", "T1505.003", "T1003.001", "T1087.002", "T1059.001", "T1041"]
      },
      {
        name: "MuddyWater",
        org: "MOIS subordinate element",
        aliases: ["Mango Sandstorm", "MERCURY", "Static Kitten", "Seedworm", "TEMP.Zagros"],
        type: "intelligence_operations",
        active_since: 2017,
        targets: ["government", "telecom", "defense", "oil_gas", "academia"],
        regions: ["Middle East", "South Asia", "Central Asia", "Turkey"],
        capabilities: ["spear_phishing", "living_off_the_land", "macro_documents", "tunneling"],
        known_tools: ["POWERSTATS", "MuddyC2Go", "PhonyC2", "MiniDump", "Atera Agent abuse"],
        notable_ops: [
          { name: "Exchange Server Exploitation", year: 2021, desc: "Exploiting ProxyShell and Log4j vulnerabilities for initial access across Middle Eastern targets" }
        ],
        mitre_techniques: ["T1566.001", "T1059.001", "T1059.005", "T1105", "T1572", "T1090"]
      }
    ]
  },
  {
    nation: "Israel",
    groups: [
      {
        name: "Unit 8200",
        org: "IDF Intelligence Corps, Central Collection Unit",
        aliases: [],
        type: "signals_intelligence",
        active_since: 1952,
        targets: ["adversary_military", "nuclear_programs", "terrorism", "regional_threats"],
        regions: ["Middle East", "Iran"],
        capabilities: ["sigint", "zero_day_development", "offensive_cyber", "surveillance_technology"],
        known_tools: ["Stuxnet (co-developed)", "Duqu", "Flame"],
        notable_ops: [
          { name: "Stuxnet", year: 2010, desc: "Co-developed with US (Olympic Games), destroyed ~1,000 uranium enrichment centrifuges at Natanz, Iran — first known cyber weapon causing physical destruction" },
          { name: "Duqu", year: 2011, desc: "Espionage platform related to Stuxnet, targeting industrial control system manufacturers" },
          { name: "Flame", year: 2012, desc: "Massive espionage tool, 20MB, modular architecture, Bluetooth mapping, screen capture, audio recording" }
        ],
        mitre_techniques: ["T1091", "T1495", "T1059", "T1036", "T1027.002", "T1071.001"]
      }
    ]
  },
  {
    nation: "United States",
    groups: [
      {
        name: "Equation Group",
        org: "NSA TAO (Tailored Access Operations / Computer Network Operations)",
        aliases: ["PLATINUM COLONY"],
        type: "signals_intelligence_offensive",
        active_since: 1996,
        targets: ["adversary_government", "military", "telecom", "research", "nuclear"],
        regions: ["Global"],
        capabilities: ["firmware_implants", "zero_day_stockpile", "hard_drive_firmware", "air_gap_crossing", "satellite_interception"],
        known_tools: ["DOUBLEPULSAR", "ETERNALBLUE", "ETERNALROMANCE", "FANNY", "GrayFish", "EquationDrug", "UNITEDRECIPE"],
        notable_ops: [
          { name: "Shadow Brokers Leak", year: 2016, desc: "NSA tools leaked publicly, including EternalBlue which was later used in WannaCry and NotPetya" },
          { name: "Stuxnet", year: 2010, desc: "Co-developed with Israel, first cyber weapon causing physical destruction of infrastructure" },
          { name: "PRISM Program", year: 2013, desc: "Mass surveillance program collecting data from major tech companies (disclosed by Snowden)" }
        ],
        mitre_techniques: ["T1542.001", "T1495", "T1091", "T1027.009", "T1059", "T1190"]
      },
      {
        name: "US Cyber Command (USCYBERCOM)",
        org: "Department of Defense, Unified Combatant Command",
        aliases: [],
        type: "military_cyber_operations",
        active_since: 2009,
        targets: ["adversary_military", "terrorist_organizations", "critical_infrastructure_defense"],
        regions: ["Global"],
        capabilities: ["offensive_operations", "defensive_operations", "hunt_forward", "persistent_engagement"],
        known_tools: ["Classified"],
        notable_ops: [
          { name: "Operation Glowing Symphony", year: 2016, desc: "Offensive operation against ISIS online propaganda and communication infrastructure" },
          { name: "Hunt Forward Operations", year: 2022, desc: "Deployed teams to Ukraine, Albania, Latvia, Lithuania and others to find adversary activity in partner networks" },
          { name: "Iran Election Interference Defense", year: 2020, desc: "Operations to defend 2020 US elections from Iranian and Russian interference" }
        ],
        mitre_techniques: []
      }
    ]
  },
  {
    nation: "United Kingdom",
    groups: [
      {
        name: "GCHQ / NCSC",
        org: "Government Communications Headquarters / National Cyber Security Centre",
        aliases: [],
        type: "signals_intelligence_defensive",
        active_since: 1919,
        targets: ["adversary_intelligence", "critical_infrastructure_defense", "cyber_threats"],
        regions: ["Global", "Five Eyes"],
        capabilities: ["sigint", "defensive_cyber", "active_cyber_defense", "vulnerability_research"],
        known_tools: ["Active Cyber Defence tools", "NCSC scanning tools"],
        notable_ops: [
          { name: "Active Cyber Defence Program", year: 2016, desc: "National-scale defensive program: takedown services, DMARC enforcement, protective DNS, vulnerability scanning" },
          { name: "Tempora", year: 2013, desc: "Cable-tapping program for bulk data interception (disclosed by Snowden)" },
          { name: "WannaCry Attribution", year: 2017, desc: "Led attribution of WannaCry ransomware to North Korea" }
        ],
        mitre_techniques: []
      }
    ]
  }
];


// ── Critical Infrastructure Sectors ──────────────────────────────────────

export const CRITICAL_INFRASTRUCTURE_SECTORS = [
  {
    id: "energy",
    name: "Energy",
    sector_specific_agency: "Department of Energy (DOE)",
    sub_sectors: ["electricity", "oil", "natural_gas"],
    attack_surfaces: [
      "SCADA/EMS systems controlling grid operations",
      "Distributed Energy Resources (DER) management",
      "Smart meter infrastructure (AMI)",
      "Pipeline control systems (OT/ICS)",
      "Nuclear plant digital instrumentation (Safety systems, DCS)",
      "Renewable energy inverter controls",
      "Substation automation (IEC 61850)",
      "Energy trading platforms",
      "Physical security systems at generation facilities"
    ],
    known_threats: [
      { actor: "Sandworm", technique: "ICS-specific malware (Industroyer)", impact: "Power grid disruption" },
      { actor: "Volt Typhoon", technique: "LOTL pre-positioning", impact: "Potential future disruption" },
      { actor: "XENOTIME/TRITON", technique: "Safety system manipulation", impact: "Potential physical harm" },
      { actor: "Dragonfly/Energetic Bear", technique: "OT network reconnaissance", impact: "Intelligence collection" }
    ],
    frameworks: ["NERC CIP v7", "NIST SP 800-82", "IEC 62443", "DOE C2M2"],
    key_regulations: [
      { name: "NERC CIP", desc: "Mandatory cybersecurity standards for bulk electric system", standards: ["CIP-002 through CIP-014"] },
      { name: "CFATS", desc: "Chemical Facility Anti-Terrorism Standards for petrochemical" },
      { name: "NRC 10 CFR 73.54", desc: "Nuclear facility cyber security requirements" }
    ]
  },
  {
    id: "water",
    name: "Water and Wastewater Systems",
    sector_specific_agency: "Environmental Protection Agency (EPA)",
    sub_sectors: ["drinking_water", "wastewater_treatment", "dams"],
    attack_surfaces: [
      "SCADA systems controlling water treatment processes",
      "Chemical dosing systems (chlorine, fluoride, sodium hydroxide, lye)",
      "Pump station controls and telemetry (RTU/PLC)",
      "Remote access for operators (VPN, RDP)",
      "Water quality monitoring sensors",
      "Supervisory workstations (HMI)",
      "Historian databases storing process data",
      "Dam control and spillway automation"
    ],
    known_threats: [
      { actor: "Unknown", technique: "HMI manipulation", impact: "Oldsmar FL water treatment — attempted sodium hydroxide increase to dangerous levels (2021)" },
      { actor: "CyberAv3ngers (Iran-affiliated)", technique: "PLC exploitation", impact: "Targeting Unitronics PLCs at US water utilities (2023)" },
      { actor: "Insider threat", technique: "Credential abuse", impact: "Multiple incidents of disgruntled employees manipulating treatment processes" }
    ],
    frameworks: ["AWWA Cybersecurity Guidance", "NIST Cybersecurity Framework", "EPA Water Security"],
    key_regulations: [
      { name: "SDWA Section 1433", desc: "Risk and resilience assessments and emergency response plans for community water systems serving 3,300+" },
      { name: "AWIA 2018", desc: "America's Water Infrastructure Act requiring cybersecurity assessments" }
    ]
  },
  {
    id: "transportation",
    name: "Transportation Systems",
    sector_specific_agency: "Department of Transportation (DOT) / TSA",
    sub_sectors: ["aviation", "maritime", "highways", "rail", "pipeline", "postal"],
    attack_surfaces: [
      "Air traffic control systems (NextGen/SWIM)",
      "Airport operational technology (baggage, access control, CCTV)",
      "Airline reservation and crew management systems",
      "Maritime vessel navigation (GPS, AIS, ECDIS)",
      "Port terminal management systems",
      "Railroad positive train control (PTC) systems",
      "Traffic management systems and smart signals",
      "Pipeline SCADA and leak detection",
      "Connected and autonomous vehicle systems (V2X)",
      "Transit fare collection and passenger information"
    ],
    known_threats: [
      { actor: "APT groups (multiple)", technique: "IT system compromise", impact: "Airline reservation data theft for intelligence" },
      { actor: "Ransomware groups", technique: "Ransomware deployment", impact: "Colonial Pipeline (DarkSide, 2021) — largest US pipeline shutdown" },
      { actor: "Unknown", technique: "GPS spoofing", impact: "Maritime navigation manipulation, aircraft approach interference" }
    ],
    frameworks: ["TSA Security Directives", "NIST SP 800-82", "ICAO Annex 17"],
    key_regulations: [
      { name: "TSA Security Directive Pipeline-2021-02", desc: "Mandatory cybersecurity measures for pipeline operators" },
      { name: "TSA Emergency Amendment", desc: "Requirements for aviation and surface transportation operators" }
    ]
  },
  {
    id: "communications",
    name: "Communications",
    sector_specific_agency: "Department of Homeland Security (DHS) / CISA",
    sub_sectors: ["wireline", "wireless", "satellite", "cable", "broadcasting"],
    attack_surfaces: [
      "Telecommunications infrastructure (core network, edge, access)",
      "5G core network and RAN",
      "SS7/Diameter signaling networks",
      "BGP routing infrastructure",
      "DNS root and TLD servers",
      "Submarine cable landing stations",
      "Satellite ground stations and transponders",
      "Internet Exchange Points (IXPs)",
      "Software-defined networking controllers",
      "Lawful intercept systems"
    ],
    known_threats: [
      { actor: "Salt Typhoon (China)", technique: "Telecom network infiltration", impact: "Access to wiretap systems and call metadata at major US carriers (2024)" },
      { actor: "APT10", technique: "Operation SoftCell", impact: "Targeted telecom providers for call detail records" },
      { actor: "Multiple actors", technique: "SS7 exploitation", impact: "Call interception, location tracking, SMS interception" },
      { actor: "Multiple actors", technique: "BGP hijacking", impact: "Traffic interception and rerouting" }
    ],
    frameworks: ["NIST CSF", "FCC CSRIC Best Practices", "3GPP Security Specifications"],
    key_regulations: [
      { name: "FCC CALEA", desc: "Communications Assistance for Law Enforcement Act compliance" },
      { name: "Section 889 NDAA", desc: "Prohibition on certain telecommunications equipment (Huawei, ZTE)" }
    ]
  },
  {
    id: "financial",
    name: "Financial Services",
    sector_specific_agency: "Department of the Treasury",
    sub_sectors: ["banking", "insurance", "securities", "payment_processing"],
    attack_surfaces: [
      "SWIFT messaging network",
      "Core banking systems",
      "ATM networks and controllers",
      "Online/mobile banking platforms",
      "Payment card processing (PCI infrastructure)",
      "Stock exchange trading systems",
      "Clearinghouse and settlement systems",
      "Cryptocurrency exchange infrastructure",
      "Open banking APIs (PSD2/FDX)",
      "Fraud detection systems"
    ],
    known_threats: [
      { actor: "Lazarus/APT38", technique: "SWIFT fraud", impact: "Bangladesh Bank $81M theft, FASTCash ATM attacks" },
      { actor: "Carbanak/FIN7", technique: "POS malware", impact: "Hundreds of millions in payment card theft" },
      { actor: "Lazarus", technique: "DeFi exploitation", impact: "$1.7B+ in cryptocurrency stolen (cumulative)" },
      { actor: "Multiple", technique: "Ransomware", impact: "ION Trading Platform ransomware disrupting derivatives markets (2023)" }
    ],
    frameworks: ["FFIEC CAT", "PCI DSS v4.0", "SWIFT CSP", "SOX"],
    key_regulations: [
      { name: "GLBA", desc: "Gramm-Leach-Bliley Act financial data protection" },
      { name: "NYDFS Cybersecurity Regulation (23 NYCRR 500)", desc: "Cybersecurity requirements for financial services companies" },
      { name: "SEC Cybersecurity Rules", desc: "Incident disclosure and risk management disclosure requirements" }
    ]
  },
  {
    id: "healthcare",
    name: "Healthcare and Public Health",
    sector_specific_agency: "Department of Health and Human Services (HHS)",
    sub_sectors: ["hospitals", "pharmaceuticals", "medical_devices", "health_insurance", "public_health"],
    attack_surfaces: [
      "Electronic Health Record (EHR) systems",
      "Medical devices (infusion pumps, pacemakers, imaging systems)",
      "Hospital OT (HVAC, building management, pneumatic tube)",
      "Pharmaceutical manufacturing (GxP systems)",
      "Clinical trial data systems",
      "Telehealth platforms",
      "Health information exchanges (HIE)",
      "Medical imaging (PACS/DICOM)",
      "Laboratory information systems (LIS)",
      "Insurance claims processing"
    ],
    known_threats: [
      { actor: "Multiple ransomware groups", technique: "Ransomware", impact: "UHS ($67M), Universal Health Services, Scripps Health, CommonSpirit Health, Change Healthcare ($872M)" },
      { actor: "APT29", technique: "Espionage", impact: "COVID-19 vaccine research targeting" },
      { actor: "APT10", technique: "Data theft", impact: "Anthem Inc. 78.8M patient records breached" }
    ],
    frameworks: ["HIPAA Security Rule", "NIST CSF Healthcare Profile", "FDA Premarket Cybersecurity Guidance"],
    key_regulations: [
      { name: "HIPAA", desc: "Health Insurance Portability and Accountability Act — security and privacy of protected health information" },
      { name: "HITECH Act", desc: "Health Information Technology for Economic and Clinical Health Act — breach notification" },
      { name: "FDA 524B", desc: "Medical device cybersecurity requirements" }
    ]
  },
  {
    id: "government",
    name: "Government Facilities",
    sector_specific_agency: "DHS / GSA",
    sub_sectors: ["federal", "state_local_tribal", "education", "national_monuments"],
    attack_surfaces: [
      "Federal agency networks (.gov, .mil)",
      "Classified networks (SIPRNet, JWICS)",
      "Voting systems and election infrastructure",
      "Court record management systems",
      "Law enforcement databases (NCIC, NLETS)",
      "Federal building access control (HSPD-12/PIV)",
      "Government cloud (FedRAMP authorized)",
      "Interagency communications systems"
    ],
    known_threats: [
      { actor: "APT29", technique: "SolarWinds supply chain", impact: "Access to Treasury, Commerce, DHS, State Department networks" },
      { actor: "APT28", technique: "Credential harvesting", impact: "OPM breach, 21.5M personnel records stolen (attributed)" },
      { actor: "Multiple", technique: "Ransomware", impact: "City of Atlanta, Baltimore, New Orleans, Costa Rica government" }
    ],
    frameworks: ["FISMA", "FedRAMP", "NIST SP 800-53", "CDM Program", "Zero Trust Architecture (EO 14028)"],
    key_regulations: [
      { name: "FISMA", desc: "Federal Information Security Modernization Act" },
      { name: "EO 14028", desc: "Executive Order on Improving the Nation's Cybersecurity — zero trust mandate" },
      { name: "FedRAMP", desc: "Federal Risk and Authorization Management Program for cloud" }
    ]
  },
  {
    id: "defense",
    name: "Defense Industrial Base",
    sector_specific_agency: "Department of Defense (DoD)",
    sub_sectors: ["weapons_systems", "defense_contractors", "cleared_facilities"],
    attack_surfaces: [
      "Controlled Unclassified Information (CUI) in contractor networks",
      "Weapons system design and engineering data",
      "Defense supply chain management",
      "Cleared defense contractor networks",
      "Test range and simulation systems",
      "Satellite command and control",
      "Embedded systems in weapons platforms",
      "Defense logistics information systems"
    ],
    known_threats: [
      { actor: "APT1/PLA", technique: "Long-term espionage", impact: "Theft of F-35, C-17, missile defense technology designs" },
      { actor: "APT10", technique: "MSP targeting", impact: "Access to defense contractor data through managed service providers" },
      { actor: "Lazarus", technique: "Defense sector targeting", impact: "Targeting defense and aerospace engineers with fake job offers" }
    ],
    frameworks: ["CMMC 2.0", "NIST SP 800-171", "DFARS 252.204-7012", "ITAR"],
    key_regulations: [
      { name: "CMMC", desc: "Cybersecurity Maturity Model Certification — required for DoD contracts" },
      { name: "DFARS 252.204-7012", desc: "Safeguarding Covered Defense Information" },
      { name: "ITAR", desc: "International Traffic in Arms Regulations — defense article export controls" }
    ]
  },
  {
    id: "it",
    name: "Information Technology",
    sector_specific_agency: "CISA",
    sub_sectors: ["hardware", "software", "it_services", "cloud", "internet_infrastructure"],
    attack_surfaces: [
      "Software supply chain (build systems, package managers, code repositories)",
      "Cloud service provider infrastructure (AWS, Azure, GCP control plane)",
      "Domain registrar and DNS infrastructure",
      "Certificate authorities (CA) and PKI",
      "Content delivery networks (CDN)",
      "Managed service providers (MSP/MSSP)",
      "Open source software dependencies",
      "Hardware supply chain (chip fabrication, firmware)"
    ],
    known_threats: [
      { actor: "APT29", technique: "Supply chain (SolarWinds)", impact: "18,000+ organizations compromised" },
      { actor: "APT41", technique: "Supply chain (CCleaner, ShadowPad)", impact: "Millions of users affected" },
      { actor: "Multiple", technique: "Open source compromise", impact: "event-stream, ua-parser-js, colors.js, xz-utils backdoor" }
    ],
    frameworks: ["SSDF (NIST SP 800-218)", "SLSA Framework", "OpenSSF Scorecard"],
    key_regulations: [
      { name: "EO 14028 Software Supply Chain", desc: "SBOM requirements, secure development attestation" },
      { name: "EU Cyber Resilience Act", desc: "Cybersecurity requirements for products with digital elements" }
    ]
  },
  {
    id: "nuclear",
    name: "Nuclear Reactors, Materials, and Waste",
    sector_specific_agency: "Nuclear Regulatory Commission (NRC) / DOE",
    sub_sectors: ["power_reactors", "research_reactors", "nuclear_materials", "waste_management"],
    attack_surfaces: [
      "Digital instrumentation and control (DI&C) systems",
      "Safety-related systems (reactor protection, ESFAS)",
      "Non-safety systems that can impact safety",
      "Spent fuel pool monitoring",
      "Physical protection and security systems",
      "Emergency preparedness communication systems",
      "Nuclear material tracking (MC&A)",
      "Dosimetry and radiation monitoring networks"
    ],
    known_threats: [
      { actor: "Stuxnet (US/Israel)", technique: "PLC manipulation", impact: "Destroyed centrifuges at Natanz — demonstrated vulnerability of nuclear infrastructure" },
      { actor: "Kimsuky", technique: "Spear phishing", impact: "Korea Hydro & Nuclear Power breach — reactor design data stolen" },
      { actor: "Unknown", technique: "Insider threat", impact: "Multiple incidents of authorized personnel abusing access" }
    ],
    frameworks: ["NRC 10 CFR 73.54", "NRC RG 5.71", "IAEA NSS No. 17-T", "NEI 08-09"],
    key_regulations: [
      { name: "10 CFR 73.54", desc: "Protection of digital computer and communication systems and networks" },
      { name: "NRC RG 5.71", desc: "Cyber Security Programs for Nuclear Facilities" }
    ]
  },
  {
    id: "chemical",
    name: "Chemical",
    sector_specific_agency: "CISA / DHS",
    sub_sectors: ["basic_chemicals", "specialty_chemicals", "agricultural_chemicals", "pharmaceuticals", "consumer_products"],
    attack_surfaces: [
      "Distributed Control Systems (DCS) for process control",
      "Safety Instrumented Systems (SIS — Triconex, HIMA, Yokogawa)",
      "Laboratory information management systems (LIMS)",
      "Environmental monitoring and compliance reporting",
      "Supply chain and logistics management",
      "Physical access control to hazardous areas"
    ],
    known_threats: [
      { actor: "XENOTIME/TRITON", technique: "SIS manipulation", impact: "TRITON/TRISIS malware targeting Schneider Triconex safety controllers at Saudi petrochemical facility (2017) — first malware designed to cause physical harm" },
      { actor: "Ransomware groups", technique: "IT/OT ransomware", impact: "Norsk Hydro (LockerGoga, 2019) — aluminum production disrupted globally" }
    ],
    frameworks: ["CFATS", "RBPS", "ISA/IEC 62443", "NIST SP 800-82"],
    key_regulations: [
      { name: "CFATS", desc: "Chemical Facility Anti-Terrorism Standards" },
      { name: "PSM/RMP", desc: "OSHA Process Safety Management / EPA Risk Management Program" }
    ]
  },
  {
    id: "commercial",
    name: "Commercial Facilities",
    sector_specific_agency: "DHS",
    sub_sectors: ["entertainment", "gaming", "lodging", "outdoor_events", "retail", "real_estate"],
    attack_surfaces: ["POS systems", "building management", "guest WiFi", "loyalty programs", "physical security"],
    known_threats: [
      { actor: "FIN7/Carbanak", technique: "POS malware", impact: "Massive payment card theft from retail/hospitality" },
      { actor: "Multiple", technique: "Ransomware", impact: "MGM Resorts, Caesars Entertainment ($15M ransom, 2023)" }
    ],
    frameworks: ["PCI DSS", "NIST CSF"],
    key_regulations: [{ name: "PCI DSS v4.0", desc: "Payment Card Industry Data Security Standard" }]
  },
  {
    id: "dams",
    name: "Dams",
    sector_specific_agency: "DHS / Army Corps of Engineers / Bureau of Reclamation",
    sub_sectors: ["hydroelectric", "flood_control", "navigation", "irrigation"],
    attack_surfaces: ["SCADA systems for dam and spillway control", "flood gate automation", "water level monitoring", "seismic monitoring", "power generation controls"],
    known_threats: [
      { actor: "IRGC-affiliated", technique: "SCADA probing", impact: "Bowman Avenue Dam NY — Iranian hackers gained access to dam control system (2013)" }
    ],
    frameworks: ["FERC Dam Safety", "NIST SP 800-82"],
    key_regulations: [{ name: "FERC Dam Safety Regulations", desc: "Federal Energy Regulatory Commission dam safety and security" }]
  },
  {
    id: "emergency",
    name: "Emergency Services",
    sector_specific_agency: "DHS / FEMA",
    sub_sectors: ["law_enforcement", "fire", "ems", "emergency_management", "public_works"],
    attack_surfaces: ["911/PSAP systems (NG911)", "Computer-Aided Dispatch (CAD)", "records management", "mobile data terminals", "body cameras", "alert systems (IPAWS)"],
    known_threats: [
      { actor: "Multiple", technique: "Ransomware", impact: "Baltimore 911 CAD system ransomware, Atlanta PD systems" },
      { actor: "Swatting actors", technique: "TDoS/Swatting", impact: "Telephony denial of service against 911 systems" }
    ],
    frameworks: ["NIST CSF", "NENA NG911 Security Standards"],
    key_regulations: [{ name: "Kari's Law / RAY BAUM's Act", desc: "911 access and location requirements" }]
  },
  {
    id: "food",
    name: "Food and Agriculture",
    sector_specific_agency: "USDA / FDA",
    sub_sectors: ["farms", "food_processing", "food_distribution", "restaurants"],
    attack_surfaces: ["Precision agriculture systems (GPS, IoT sensors)", "food processing control systems", "cold chain monitoring", "supply chain/traceability systems", "livestock management systems"],
    known_threats: [
      { actor: "REvil", technique: "Ransomware", impact: "JBS Foods — world's largest meat processor shut down (2021), $11M ransom paid" },
      { actor: "Multiple", technique: "Ransomware", impact: "New Cooperative, Crystal Valley Cooperative grain and feed disruptions" }
    ],
    frameworks: ["FDA FSMA", "NIST CSF"],
    key_regulations: [{ name: "FSMA", desc: "FDA Food Safety Modernization Act — intentional adulteration rule" }]
  },
  {
    id: "manufacturing",
    name: "Critical Manufacturing",
    sector_specific_agency: "DHS / CISA",
    sub_sectors: ["primary_metals", "machinery", "electrical_equipment", "transportation_equipment"],
    attack_surfaces: ["Industrial control systems (PLC/DCS/SCADA)", "industrial IoT sensors", "robotics and CNC machines", "MES (Manufacturing Execution Systems)", "ERP/supply chain systems", "CAD/CAM design systems"],
    known_threats: [
      { actor: "Multiple APTs", technique: "IP theft", impact: "Systematic theft of manufacturing processes and designs" },
      { actor: "Ransomware groups", technique: "Ransomware", impact: "Honda, Nissan, Toyota supplier (Kojima Industries), semiconductor firms" }
    ],
    frameworks: ["ISA/IEC 62443", "NIST SP 800-82", "NIST Manufacturing Profile"],
    key_regulations: [{ name: "CHIPS Act", desc: "Semiconductor manufacturing security requirements" }]
  }
];


// ── NIST Cybersecurity Framework v2.0 ────────────────────────────────────

export const NIST_CSF = {
  version: "2.0",
  functions: [
    {
      id: "GV",
      name: "Govern",
      desc: "Establish and monitor the organization's cybersecurity risk management strategy, expectations, and policy",
      categories: [
        { id: "GV.OC", name: "Organizational Context", subcategories: [
          { id: "GV.OC-01", desc: "The organizational mission is understood and informs cybersecurity risk management" },
          { id: "GV.OC-02", desc: "Internal and external stakeholders are understood, and their needs and expectations regarding cybersecurity risk management are understood and considered" },
          { id: "GV.OC-03", desc: "Legal, regulatory, and contractual requirements regarding cybersecurity — including privacy and civil liberties obligations — are understood and managed" },
          { id: "GV.OC-04", desc: "Critical objectives, capabilities, and services that stakeholders depend on or expect from the organization are understood and communicated" },
          { id: "GV.OC-05", desc: "Outcomes, capabilities, and services that the organization depends on are understood and communicated" }
        ]},
        { id: "GV.RM", name: "Risk Management Strategy", subcategories: [
          { id: "GV.RM-01", desc: "Risk management objectives are established and agreed to by organizational stakeholders" },
          { id: "GV.RM-02", desc: "Risk appetite and risk tolerance statements are established, communicated, and maintained" },
          { id: "GV.RM-03", desc: "Cybersecurity risk management activities and outcomes are included in enterprise risk management processes" },
          { id: "GV.RM-04", desc: "Strategic direction that describes appropriate risk response options is established and communicated" },
          { id: "GV.RM-05", desc: "Lines of communication across the organization are established for cybersecurity risks, including risks from suppliers and other third parties" },
          { id: "GV.RM-06", desc: "A standardized method for calculating, documenting, categorizing, and prioritizing cybersecurity risks is established and communicated" },
          { id: "GV.RM-07", desc: "Strategic opportunities (i.e., positive risks) are characterized and are included in organizational cybersecurity risk discussions" }
        ]},
        { id: "GV.RR", name: "Roles, Responsibilities, and Authorities", subcategories: [
          { id: "GV.RR-01", desc: "Organizational leadership is responsible and accountable for cybersecurity risk and fosters a culture that is risk-aware, ethical, and continually improving" },
          { id: "GV.RR-02", desc: "Roles, responsibilities, and authorities related to cybersecurity risk management are established, communicated, understood, and enforced" },
          { id: "GV.RR-03", desc: "Adequate resources are allocated commensurate with the cybersecurity risk strategy, roles, responsibilities, and policies" },
          { id: "GV.RR-04", desc: "Cybersecurity is included in human resources practices" }
        ]},
        { id: "GV.PO", name: "Policy", subcategories: [
          { id: "GV.PO-01", desc: "Policy for managing cybersecurity risks is established based on organizational context, cybersecurity strategy, and priorities and is communicated and enforced" },
          { id: "GV.PO-02", desc: "Policy for managing cybersecurity risks is reviewed, updated, communicated, and enforced to reflect changes in requirements, threats, technology, and organizational mission" }
        ]},
        { id: "GV.SC", name: "Cybersecurity Supply Chain Risk Management", subcategories: [
          { id: "GV.SC-01", desc: "A cybersecurity supply chain risk management program, strategy, objectives, policies, and processes are established and agreed to by organizational stakeholders" },
          { id: "GV.SC-02", desc: "Cybersecurity roles and responsibilities for suppliers, customers, and partners are established, communicated, and coordinated internally and externally" },
          { id: "GV.SC-03", desc: "Cybersecurity supply chain risk management is integrated into cybersecurity and enterprise risk management, risk assessment, and improvement processes" },
          { id: "GV.SC-04", desc: "Suppliers are known and prioritized by criticality" },
          { id: "GV.SC-05", desc: "Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts and other agreements with suppliers and other relevant third parties" },
          { id: "GV.SC-06", desc: "Planning and due diligence are performed to reduce risks before entering into formal supplier or other third-party relationships" },
          { id: "GV.SC-07", desc: "The risks posed by a supplier, their products and services, and other third parties are understood, recorded, prioritized, assessed, responded to, and monitored over the course of the relationship" },
          { id: "GV.SC-08", desc: "Relevant suppliers and other third parties are included in incident planning, response, and recovery activities" },
          { id: "GV.SC-09", desc: "Supply chain security practices are integrated into cybersecurity and enterprise risk management programs, and their performance is monitored throughout the technology product and service life cycle" },
          { id: "GV.SC-10", desc: "Cybersecurity supply chain risk management plans include provisions for activities that occur after the conclusion of a partnership or service agreement" }
        ]}
      ]
    },
    {
      id: "ID",
      name: "Identify",
      desc: "Help determine the current cybersecurity risk to the organization",
      categories: [
        { id: "ID.AM", name: "Asset Management", subcategories: [
          { id: "ID.AM-01", desc: "Inventories of hardware managed by the organization are maintained" },
          { id: "ID.AM-02", desc: "Inventories of software, services, and systems managed by the organization are maintained" },
          { id: "ID.AM-03", desc: "Representations of the organization's authorized network communication and internal and external network data flows are maintained" },
          { id: "ID.AM-04", desc: "Inventories of services provided by suppliers are maintained" },
          { id: "ID.AM-05", desc: "Assets are prioritized based on classification, criticality, resources, and impact on the mission" },
          { id: "ID.AM-07", desc: "Inventories of data and corresponding metadata for designated data types are maintained" },
          { id: "ID.AM-08", desc: "Systems, hardware, software, services, and data are managed throughout their life cycles" }
        ]},
        { id: "ID.RA", name: "Risk Assessment", subcategories: [
          { id: "ID.RA-01", desc: "Vulnerabilities in assets are identified, validated, and recorded" },
          { id: "ID.RA-02", desc: "Cyber threat intelligence is received from information sharing forums and sources" },
          { id: "ID.RA-03", desc: "Internal and external threats to the organization are identified and recorded" },
          { id: "ID.RA-04", desc: "Potential impacts and likelihoods of threats exploiting vulnerabilities are identified and recorded" },
          { id: "ID.RA-05", desc: "Threats, vulnerabilities, likelihoods, and impacts are used to understand inherent risk and inform risk response prioritization" },
          { id: "ID.RA-06", desc: "Risk responses are chosen, prioritized, planned, tracked, and communicated" },
          { id: "ID.RA-07", desc: "Changes and exceptions are managed, assessed for risk impact, recorded, and tracked" },
          { id: "ID.RA-08", desc: "Processes for receiving, analyzing, and responding to vulnerability disclosures are established" },
          { id: "ID.RA-09", desc: "The authenticity and integrity of hardware and software are assessed prior to acquisition and use" },
          { id: "ID.RA-10", desc: "Critical suppliers are assessed prior to acquisition" }
        ]},
        { id: "ID.IM", name: "Improvement", subcategories: [
          { id: "ID.IM-01", desc: "Improvements are identified from evaluations" },
          { id: "ID.IM-02", desc: "Improvements are identified from security tests and exercises, including those done in coordination with suppliers and relevant third parties" },
          { id: "ID.IM-03", desc: "Improvements are identified from execution of operational processes, procedures, and activities" },
          { id: "ID.IM-04", desc: "Incident response plans and other cybersecurity plans that affect operations are established, communicated, maintained, and improved" }
        ]}
      ]
    },
    {
      id: "PR",
      name: "Protect",
      desc: "Use safeguards to prevent or reduce cybersecurity risk",
      categories: [
        { id: "PR.AA", name: "Identity Management, Authentication, and Access Control", subcategories: [
          { id: "PR.AA-01", desc: "Identities and credentials for authorized users, services, and hardware are managed by the organization" },
          { id: "PR.AA-02", desc: "Identities are proofed and bound to credentials based on the context of interactions" },
          { id: "PR.AA-03", desc: "Users, services, and hardware are authenticated" },
          { id: "PR.AA-04", desc: "Identity assertions are protected, conveyed, and verified" },
          { id: "PR.AA-05", desc: "Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed, and incorporate the principles of least privilege and separation of duties" },
          { id: "PR.AA-06", desc: "Physical access to assets is managed, monitored, and enforced commensurate with risk" }
        ]},
        { id: "PR.AT", name: "Awareness and Training", subcategories: [
          { id: "PR.AT-01", desc: "Personnel are provided with awareness and training so that they possess the knowledge and skills to perform general tasks with cybersecurity risks in mind" },
          { id: "PR.AT-02", desc: "Individuals in specialized roles are provided with awareness and training so that they possess the knowledge and skills to perform relevant tasks with cybersecurity risks in mind" }
        ]},
        { id: "PR.DS", name: "Data Security", subcategories: [
          { id: "PR.DS-01", desc: "The confidentiality, integrity, and availability of data-at-rest are protected" },
          { id: "PR.DS-02", desc: "The confidentiality, integrity, and availability of data-in-transit are protected" },
          { id: "PR.DS-10", desc: "The confidentiality, integrity, and availability of data-in-use are protected" },
          { id: "PR.DS-11", desc: "Backups of data are created, protected, maintained, and tested" }
        ]},
        { id: "PR.PS", name: "Platform Security", subcategories: [
          { id: "PR.PS-01", desc: "The configuration of IT/OT/IoT assets is managed through secure configuration management processes" },
          { id: "PR.PS-02", desc: "Software is maintained, replaced, and removed commensurate with risk" },
          { id: "PR.PS-03", desc: "Hardware is maintained, replaced, and removed commensurate with risk" },
          { id: "PR.PS-04", desc: "Log records are generated and made available for continuous monitoring" },
          { id: "PR.PS-05", desc: "Installation and execution of unauthorized software is prevented" },
          { id: "PR.PS-06", desc: "Secure software development practices are integrated, and their performance is monitored throughout the software development life cycle" }
        ]},
        { id: "PR.IR", name: "Technology Infrastructure Resilience", subcategories: [
          { id: "PR.IR-01", desc: "Networks and environments are protected from unauthorized logical access and usage" },
          { id: "PR.IR-02", desc: "The organization's technology assets are protected from environmental threats" },
          { id: "PR.IR-03", desc: "Mechanisms are implemented to achieve resilience requirements in normal and adverse situations" },
          { id: "PR.IR-04", desc: "Adequate resource capacity to ensure availability is maintained" }
        ]}
      ]
    },
    {
      id: "DE",
      name: "Detect",
      desc: "Find and analyze possible cybersecurity attacks and compromises",
      categories: [
        { id: "DE.CM", name: "Continuous Monitoring", subcategories: [
          { id: "DE.CM-01", desc: "Networks and network services are monitored to find potentially adverse events" },
          { id: "DE.CM-02", desc: "The physical environment is monitored to find potentially adverse events" },
          { id: "DE.CM-03", desc: "Personnel activity and technology usage are monitored to find potentially adverse events" },
          { id: "DE.CM-06", desc: "External service provider activities and services are monitored to find potentially adverse events" },
          { id: "DE.CM-09", desc: "Computing hardware and software, runtime environments, and their data are monitored to find potentially adverse events" }
        ]},
        { id: "DE.AE", name: "Adverse Event Analysis", subcategories: [
          { id: "DE.AE-02", desc: "Potentially adverse events are analyzed to better understand associated activities" },
          { id: "DE.AE-03", desc: "Information is correlated from multiple sources" },
          { id: "DE.AE-04", desc: "The estimated impact and scope of adverse events are understood" },
          { id: "DE.AE-06", desc: "Information on adverse events is provided to authorized staff and tools" },
          { id: "DE.AE-07", desc: "Cyber threat intelligence and other contextual information are integrated into the analysis" },
          { id: "DE.AE-08", desc: "Incidents are declared when adverse events meet the defined incident criteria" }
        ]}
      ]
    },
    {
      id: "RS",
      name: "Respond",
      desc: "Take action regarding a detected cybersecurity incident",
      categories: [
        { id: "RS.MA", name: "Incident Management", subcategories: [
          { id: "RS.MA-01", desc: "The incident response plan is executed in coordination with relevant third parties once an incident is declared" },
          { id: "RS.MA-02", desc: "Incident reports are triaged and validated" },
          { id: "RS.MA-03", desc: "Incidents are categorized and prioritized" },
          { id: "RS.MA-04", desc: "Incidents are escalated or elevated as needed" },
          { id: "RS.MA-05", desc: "The criteria for initiating incident recovery are applied" }
        ]},
        { id: "RS.AN", name: "Incident Analysis", subcategories: [
          { id: "RS.AN-03", desc: "Analysis is performed to establish what has taken place during an incident and the root cause of the incident" },
          { id: "RS.AN-06", desc: "Actions performed during an investigation are recorded, and the integrity of the investigation is preserved" },
          { id: "RS.AN-07", desc: "Incident data and metadata are collected, and their integrity and provenance are preserved" },
          { id: "RS.AN-08", desc: "An incident's magnitude is estimated and validated" }
        ]},
        { id: "RS.CO", name: "Incident Response Reporting and Communication", subcategories: [
          { id: "RS.CO-02", desc: "Internal and external stakeholders are notified of incidents" },
          { id: "RS.CO-03", desc: "Information is shared with designated internal and external stakeholders" }
        ]},
        { id: "RS.MI", name: "Incident Mitigation", subcategories: [
          { id: "RS.MI-01", desc: "Incidents are contained" },
          { id: "RS.MI-02", desc: "Incidents are eradicated" }
        ]}
      ]
    },
    {
      id: "RC",
      name: "Recover",
      desc: "Restore assets and operations that were impacted by a cybersecurity incident",
      categories: [
        { id: "RC.RP", name: "Incident Recovery Plan Execution", subcategories: [
          { id: "RC.RP-01", desc: "The recovery portion of the incident response plan is executed once initiated from the incident response process" },
          { id: "RC.RP-02", desc: "Recovery actions are selected, scoped, prioritized, and performed" },
          { id: "RC.RP-03", desc: "The integrity of backups and other restoration assets is verified before using them for restoration" },
          { id: "RC.RP-04", desc: "Critical mission functions and cybersecurity risk management are considered to establish post-incident operational norms" },
          { id: "RC.RP-05", desc: "The integrity of restored assets is verified, systems and services are restored, and normal operating status is confirmed" },
          { id: "RC.RP-06", desc: "The end of incident recovery is declared based on criteria, and incident-related documentation is completed" }
        ]},
        { id: "RC.CO", name: "Incident Recovery Communication", subcategories: [
          { id: "RC.CO-03", desc: "Recovery activities and progress in restoring operational capabilities are communicated to designated internal and external stakeholders" },
          { id: "RC.CO-04", desc: "Public updates on incident recovery are shared using approved methods and messaging" }
        ]}
      ]
    }
  ]
};


// ── CISA KEV Parser & Severity Ranker ────────────────────────────────────

export function parseKEV(jsonData) {
  if (!jsonData || !jsonData.vulnerabilities) return [];
  return jsonData.vulnerabilities.map(v => ({
    cveID: v.cveID,
    vendor: v.vendorProject,
    product: v.product,
    name: v.vulnerabilityName,
    description: v.shortDescription,
    dateAdded: v.dateAdded,
    dueDate: v.dueDate,
    required_action: v.requiredAction,
    known_ransomware: v.knownRansomwareCampaignUse === "Known",
    notes: v.notes || "",
    severity: rankKEVSeverity(v)
  }));
}

export function rankKEVSeverity(entry) {
  let score = 50;
  if (entry.knownRansomwareCampaignUse === "Known") score += 30;
  const added = new Date(entry.dateAdded);
  const due = new Date(entry.dueDate);
  const urgencyDays = (due - added) / (1000 * 60 * 60 * 24);
  if (urgencyDays <= 7) score += 20;
  else if (urgencyDays <= 14) score += 15;
  else if (urgencyDays <= 21) score += 10;
  const desc = (entry.shortDescription || "").toLowerCase();
  if (desc.includes("remote code execution") || desc.includes("rce")) score += 15;
  if (desc.includes("authentication bypass") || desc.includes("auth bypass")) score += 12;
  if (desc.includes("privilege escalation")) score += 10;
  if (desc.includes("zero-day") || desc.includes("0-day")) score += 10;
  if (desc.includes("active exploitation")) score += 10;
  return Math.min(100, score);
}

export function filterKEVByVendor(entries, vendor) {
  const v = vendor.toLowerCase();
  return entries.filter(e => (e.vendor || "").toLowerCase().includes(v));
}

export function filterKEVByDate(entries, startDate, endDate) {
  const start = new Date(startDate).getTime();
  const end = new Date(endDate).getTime();
  return entries.filter(e => {
    const d = new Date(e.dateAdded).getTime();
    return d >= start && d <= end;
  });
}

export function sortKEVBySeverity(entries) {
  return [...entries].sort((a, b) => b.severity - a.severity);
}


// ── Critical Infrastructure Attack Simulation Framework ──────────────────

export const SCADA_ATTACK_VECTORS = [
  {
    name: "Man-in-the-Middle on Modbus TCP",
    protocol: "Modbus TCP",
    ports: [502],
    description: "Intercept and modify Modbus TCP packets between HMI and PLC. Modbus has no authentication or encryption — all commands are plaintext.",
    impact: "Read/write any register or coil, change setpoints, disable alarms, mask true process state from operators",
    detection: [
      "Monitor for unexpected Modbus function codes (especially FC 5: Write Single Coil, FC 6: Write Single Register, FC 15: Write Multiple Coils, FC 16: Write Multiple Registers)",
      "Track source IPs communicating with PLCs — new sources indicate compromise",
      "Compare Modbus register values at network layer vs. historian values for discrepancies",
      "Deploy deep packet inspection (DPI) for Modbus protocol anomalies"
    ],
    mitigation: [
      "Segment OT network from IT network with industrial DMZ",
      "Deploy Modbus-aware firewalls (e.g., Tofino, Waterfall)",
      "Use encrypted tunnels (VPN/TLS) for Modbus communication where possible",
      "Implement allowlisting of Modbus function codes per device"
    ],
    mitre_ics: ["T0830", "T0831", "T0855"]
  },
  {
    name: "DNP3 Protocol Exploitation",
    protocol: "DNP3",
    ports: [20000],
    description: "Exploit the Distributed Network Protocol used in SCADA for electric utilities. DNP3 Secure Authentication (SA) is optional and rarely deployed.",
    impact: "Issue unauthorized control commands to RTUs, disable outstation reporting, inject false measurements",
    detection: [
      "Monitor for DNP3 unsolicited responses from unexpected sources",
      "Track changes to DNP3 data link layer addresses",
      "Alert on DNP3 cold restart or warm restart commands",
      "Monitor for DNP3 broadcast messages"
    ],
    mitigation: [
      "Enable DNP3 Secure Authentication (SA v5)",
      "Use bump-in-the-wire encryption for DNP3 links",
      "Implement egress filtering on DNP3 ports",
      "Deploy ICS-specific IDS (Claroty, Dragos, Nozomi Networks)"
    ],
    mitre_ics: ["T0855", "T0856", "T0869"]
  },
  {
    name: "OPC UA Server Exploitation",
    protocol: "OPC UA",
    ports: [4840, 4843],
    description: "Exploit OPC Unified Architecture servers that aggregate data from PLCs. Misconfigured OPC UA servers may allow anonymous access or have known CVEs.",
    impact: "Read all process data, write setpoints, discover entire OT network topology through OPC UA browsing",
    detection: [
      "Monitor OPC UA session establishment for anonymous or unexpected users",
      "Alert on OPC UA Browse requests that enumerate entire address space",
      "Track Write requests to OPC UA nodes",
      "Monitor for OPC UA server discovery multicast"
    ],
    mitigation: [
      "Disable anonymous access on all OPC UA servers",
      "Enforce certificate-based authentication for OPC UA",
      "Use OPC UA Security Mode: SignAndEncrypt",
      "Restrict OPC UA access to authorized applications via application allowlisting"
    ],
    mitre_ics: ["T0846", "T0855", "T0868"]
  },
  {
    name: "PLC Firmware Manipulation",
    protocol: "Vendor-Specific Engineering Protocols",
    ports: [],
    description: "Upload malicious firmware or logic to PLCs using vendor engineering software (TIA Portal, RSLogix, CoDeSys). Often these protocols lack authentication.",
    impact: "Persistent control manipulation surviving PLC reboots, hidden logic execution, safety system bypass",
    detection: [
      "Monitor for PLC firmware download operations (unusual outside maintenance windows)",
      "Hash all PLC programs and compare against known-good baselines",
      "Alert on PLC mode changes (RUN -> PROGRAM -> RUN)",
      "Track engineering workstation connections to PLCs"
    ],
    mitigation: [
      "Restrict engineering workstation access with jump servers",
      "Implement PLC firmware signing where supported",
      "Maintain offline backups of all PLC programs with version control",
      "Use PLC access control features (e.g., Siemens know-how protection, Rockwell source key)"
    ],
    mitre_ics: ["T0839", "T0845", "T0873"]
  },
  {
    name: "Safety Instrumented System (SIS) Manipulation",
    protocol: "TriStation (Triconex), proprietary safety protocols",
    ports: [1502],
    description: "Target safety systems designed to prevent catastrophic failures. The TRITON/TRISIS malware (2017) demonstrated this attack against Schneider Triconex controllers.",
    impact: "Disable safety shutdown mechanisms, allow unsafe process conditions, potential physical destruction and loss of life",
    detection: [
      "Monitor TriStation protocol traffic (should be rare outside maintenance)",
      "Alert on any writes to SIS controllers",
      "Track SIS controller mode changes",
      "Compare SIS logic against golden baseline",
      "Monitor for unusual SIS key switch position changes"
    ],
    mitigation: [
      "Air-gap SIS from DCS and IT networks (dedicated SIS network)",
      "Physical key switch in RUN position (prevents remote programming)",
      "Implement SIS-specific firewall rules",
      "Follow IEC 61511 lifecycle security requirements",
      "Conduct SIS logic reviews with independent safety engineers"
    ],
    mitre_ics: ["T0800", "T0836", "T0857"]
  },
  {
    name: "Historian Database Manipulation",
    protocol: "SQL, OPC, vendor APIs",
    ports: [1433, 3306, 5432],
    description: "Manipulate process historian databases to hide evidence of attacks or inject false historical data used for compliance and safety decisions.",
    impact: "Hide evidence of process manipulation, corrupt regulatory compliance data, mislead forensic analysis",
    detection: [
      "Implement database activity monitoring on historian servers",
      "Compare real-time process values with historian records",
      "Alert on direct SQL access to historian databases (should use application APIs)",
      "Monitor historian backup integrity"
    ],
    mitigation: [
      "Restrict direct database access — use application APIs only",
      "Implement write-once audit logging for historian data",
      "Deploy database activity monitoring",
      "Segment historian servers in the industrial DMZ"
    ],
    mitre_ics: ["T0811", "T0832", "T0882"]
  }
];


// ── Election Security Assessment ─────────────────────────────────────────

export const ELECTION_SECURITY = {
  voting_system_threats: [
    { threat: "Voting machine firmware tampering", risk: "critical", vector: "supply_chain", detection: "Hash verification of firmware before deployment, chain of custody logging" },
    { threat: "Election management system compromise", risk: "critical", vector: "network", detection: "Air-gap verification, pre-election logic and accuracy testing" },
    { threat: "Voter registration database manipulation", risk: "high", vector: "network", detection: "Database integrity monitoring, voter roll audits, comparison with motor vehicle records" },
    { threat: "E-pollbook manipulation", risk: "high", vector: "network_physical", detection: "Redundant paper pollbooks, network monitoring of e-pollbook connections" },
    { threat: "Results transmission interception", risk: "high", vector: "network", detection: "Encrypted transmission, out-of-band verification, paper ballot audit trail" },
    { threat: "DDoS on election night reporting websites", risk: "medium", vector: "network", detection: "CDN/DDoS protection, redundant reporting channels" },
    { threat: "Disinformation about voting procedures", risk: "high", vector: "social", detection: "Social media monitoring, rumor tracking, official channel amplification" },
    { threat: "Insider threat — poll worker manipulation", risk: "medium", vector: "physical", detection: "Bipartisan observation, chain of custody procedures, video monitoring" }
  ],
  infrastructure_hardening: [
    "Implement .gov domain for all election-related websites (DotGov program)",
    "Deploy DMARC at p=reject on all election office domains to prevent email impersonation",
    "Enable multi-factor authentication on all election system administrator accounts",
    "Conduct pre-election vulnerability scanning and penetration testing (CISA offers free)",
    "Implement network segmentation isolating election systems from general government networks",
    "Deploy endpoint detection and response (EDR) on all election infrastructure endpoints",
    "Establish and test incident response plan specific to election scenarios",
    "Conduct tabletop exercises simulating cyber and physical threats to election process",
    "Implement risk-limiting audits (RLAs) for post-election verification",
    "Maintain paper ballot backups for all electronic voting systems",
    "Join EI-ISAC (Elections Infrastructure Information Sharing and Analysis Center)",
    "Deploy Albert sensors (CISA network monitoring) on election networks",
    "Implement DNSSEC on all election-related domains",
    "Use HTTPS with HSTS on all public-facing election websites"
  ],
  disinformation_indicators: [
    { pattern: "Coordinated inauthentic behavior — multiple new accounts posting same content simultaneously", source: "social_media" },
    { pattern: "Foreign language artifacts in English-language content (character encoding, grammar patterns)", source: "content_analysis" },
    { pattern: "Geolocation inconsistencies — accounts claiming US location but posting during non-US hours", source: "metadata" },
    { pattern: "Amplification networks — small number of accounts generating disproportionate engagement", source: "network_analysis" },
    { pattern: "Narrative seeding — planting false stories in fringe outlets for mainstream pickup", source: "media_monitoring" },
    { pattern: "Deepfake or manipulated media of candidates or officials", source: "content_analysis" },
    { pattern: "Hack-and-leak operations timed to election cycle", source: "threat_intel" },
    { pattern: "False claims about voting procedures, locations, dates, or eligibility", source: "social_media" }
  ]
};


// ── Power Grid Security ──────────────────────────────────────────────────

export const POWER_GRID_SECURITY = {
  nerc_cip_checklist: [
    { standard: "CIP-002-5.1a", name: "BES Cyber System Categorization", checks: [
      "Identify all BES Cyber Systems and their impact ratings (High, Medium, Low)",
      "Document all Electronic Access Points (EAPs)",
      "Identify all Protected Cyber Assets (PCAs)",
      "Review and update asset inventories at least every 15 months"
    ]},
    { standard: "CIP-003-8", name: "Security Management Controls", checks: [
      "Documented cybersecurity policies approved by CIP Senior Manager",
      "CIP Senior Manager identified and documented",
      "Delegation of authority documented where applicable",
      "Policies reviewed and approved at least every 15 months"
    ]},
    { standard: "CIP-004-7", name: "Personnel & Training", checks: [
      "Security awareness training for all personnel with access",
      "Role-specific cybersecurity training before granting access",
      "Personnel risk assessments (background checks) completed",
      "Access revocation within 24 hours for termination, within 30 days for transfer"
    ]},
    { standard: "CIP-005-7", name: "Electronic Security Perimeters", checks: [
      "Electronic Security Perimeters (ESPs) defined for all High/Medium BCS",
      "All external routable connectivity through identified EAPs",
      "Inbound and outbound access permissions documented and restricted",
      "Interactive Remote Access (IRA) uses encryption and MFA",
      "Dial-up connectivity identified and protected"
    ]},
    { standard: "CIP-006-6", name: "Physical Security", checks: [
      "Physical Security Plans for all High/Medium impact BCS",
      "Physical Access Point (PAP) monitoring with alarming",
      "Visitor escort program and logging",
      "Physical access control systems regularly tested"
    ]},
    { standard: "CIP-007-6", name: "System Security Management", checks: [
      "Physical and logical ports restricted to necessary services",
      "Patch management process with 35-day assessment timeline",
      "Malicious code prevention (AV/endpoint protection)",
      "Security event monitoring with alerts for detected events",
      "System access controls with password complexity and change requirements"
    ]},
    { standard: "CIP-008-6", name: "Incident Reporting and Response Planning", checks: [
      "Cyber Security Incident Response Plan documented",
      "Reporting to ES-ISAC within required timelines",
      "Incident response plan tested at least annually",
      "Incident response plan updated within 180 days of test"
    ]},
    { standard: "CIP-009-6", name: "Recovery Plans", checks: [
      "Recovery plans for High/Medium impact BCS",
      "Backup and storage of information for recovery",
      "Recovery plan testing at least every 15 months",
      "Data preservation for post-event analysis"
    ]},
    { standard: "CIP-010-4", name: "Configuration Change Management and Vulnerability Assessments", checks: [
      "Baseline configurations documented for all High/Medium BCS",
      "Change management process with security impact assessment",
      "Active vulnerability assessments at least every 15 months",
      "Transient Cyber Assets and Removable Media managed"
    ]},
    { standard: "CIP-011-3", name: "Information Protection", checks: [
      "BES Cyber System Information (BCSI) identified and protected",
      "BCSI access authorization documented",
      "BCSI disposal or reuse procedures prevent unauthorized retrieval"
    ]},
    { standard: "CIP-013-2", name: "Supply Chain Risk Management", checks: [
      "Supply chain cybersecurity risk management plan developed",
      "Vendor risk assessments performed",
      "Software integrity and authenticity verification",
      "Vendor remote access controls"
    ]},
    { standard: "CIP-014-3", name: "Physical Security (Transmission)", checks: [
      "Risk assessment of transmission stations and substations",
      "Third-party verification of risk assessment",
      "Physical security plan for identified critical facilities",
      "Evaluation of physical security threats and vulnerabilities"
    ]}
  ],
  cascading_failure_analysis: {
    description: "Analysis framework for understanding cascading failures in interconnected power grids",
    phases: [
      { phase: 1, name: "Initiating Event", desc: "A disturbance triggers the cascade — cyber attack, equipment failure, natural disaster", examples: ["Targeted disconnection of transmission lines via SCADA manipulation", "Protection relay settings modification causing unnecessary trips", "False data injection in state estimation"] },
      { phase: 2, name: "Redistributed Power Flow", desc: "Remaining lines carry additional load, potentially exceeding thermal limits", analysis: "Run power flow simulation (DC/AC load flow) to identify overloaded lines" },
      { phase: 3, name: "Protection System Operation", desc: "Overloaded lines trip on thermal protection, further redistributing load", risk: "Protection system misoperation due to cyber manipulation can accelerate cascade" },
      { phase: 4, name: "Voltage Collapse", desc: "Reactive power deficiency causes voltage drop, generators trip on undervoltage", indicators: ["Voltage declining below 0.90 pu at load buses", "Reactive power reserves depleted", "Generator Q limits reached"] },
      { phase: 5, name: "Frequency Instability", desc: "Generation-load imbalance causes frequency deviation, triggering under-frequency load shedding (UFLS)", thresholds: ["59.95 Hz: First UFLS step (US)", "59.5 Hz: Additional UFLS steps", "57.0 Hz: Generator trip settings"] },
      { phase: 6, name: "System Separation / Blackout", desc: "Grid separates into islands, some with generation-load imbalance leading to blackout", recovery: "Black start procedures required — can take hours to days" }
    ]
  }
};


// ── Information Warfare & Disinformation ─────────────────────────────────

export const INFORMATION_WARFARE = {
  influence_operation_ttps: [
    {
      phase: "Preparation",
      techniques: [
        { name: "Persona Creation", desc: "Create fake social media accounts that build credibility over months before activation", indicators: ["Accounts created in bulk", "Generic profile photos (AI-generated)", "Follow pattern mimicking real users"] },
        { name: "Infrastructure Setup", desc: "Register domains, create fake news websites, establish social media pages", indicators: ["Recently registered domains with privacy protection", "Content scraped from legitimate news sites", "Hosting in bulletproof jurisdictions"] },
        { name: "Narrative Development", desc: "Identify divisive issues and develop messaging to exploit them", indicators: ["A/B testing of messages on small audiences", "Messaging aligned with known geopolitical objectives", "Exploitation of real domestic grievances"] }
      ]
    },
    {
      phase: "Seeding",
      techniques: [
        { name: "Hack and Leak", desc: "Steal genuine documents and release them, sometimes mixed with fabrications", indicators: ["Timing aligned with election cycles or diplomatic events", "Release through cut-out platforms (WikiLeaks, anonymous blogs)", "Selective release of damaging material"] },
        { name: "Fringe Media Placement", desc: "Plant stories in low-credibility outlets to establish a citable source", indicators: ["Story appears in multiple fringe outlets simultaneously", "No original sourcing or verification", "Claims designed to provoke outrage"] },
        { name: "Synthetic Media", desc: "Create deepfakes, manipulated images, or AI-generated text to fabricate evidence", indicators: ["Metadata inconsistencies", "Facial artifacts under forensic analysis", "No independent verification from claimed source"] }
      ]
    },
    {
      phase: "Amplification",
      techniques: [
        { name: "Bot Networks", desc: "Use automated accounts to amplify seeded content, making it appear organically popular", indicators: ["Unnaturally high engagement velocity", "Coordinated posting patterns", "Similar account creation dates and naming conventions"] },
        { name: "Hashtag Hijacking", desc: "Inject divisive content into trending hashtags to reach wider audiences", indicators: ["Topic drift within trending conversations", "Polarizing content injected into neutral hashtags"] },
        { name: "Influencer Co-option", desc: "Recruit real influencers (knowingly or unknowingly) to spread content", indicators: ["Influencers sharing content from unknown sources", "Payment trails from front organizations", "Content inconsistent with influencer's normal posting"] },
        { name: "Cross-Platform Relay", desc: "Move content between platforms to exploit different moderation policies", indicators: ["Same content appearing across 5+ platforms within hours", "Screenshots used to share banned content on other platforms"] }
      ]
    },
    {
      phase: "Exploitation",
      techniques: [
        { name: "Mainstream Media Pickup", desc: "Pressure legitimate media to cover the story, legitimizing it", indicators: ["Journalists citing social media volume as evidence of importance", "Media covering the story with disclaimers about unverified claims"] },
        { name: "Policy Influence", desc: "Use public opinion shift to influence policy decisions", indicators: ["Elected officials citing influenced narratives", "Policy proposals aligned with foreign adversary objectives"] },
        { name: "Social Division", desc: "Amplify both sides of divisive issues to deepen polarization", indicators: ["Same operation running accounts on multiple sides of an issue", "Protest and counter-protest organization by linked accounts"] }
      ]
    }
  ],
  bot_detection_indicators: [
    { indicator: "Account age < 30 days with high activity volume", weight: 0.7 },
    { indicator: "Profile photo matches AI-generated face databases", weight: 0.9 },
    { indicator: "Posting frequency > 50 posts/day", weight: 0.6 },
    { indicator: "Content is exclusively reshares with no original posts", weight: 0.5 },
    { indicator: "Posting times suggest non-human scheduling (exactly on the hour)", weight: 0.7 },
    { indicator: "Follows/followers ratio heavily skewed (1000 following, 2 followers)", weight: 0.6 },
    { indicator: "Username matches pattern: [FirstName][LastName][4digits]", weight: 0.4 },
    { indicator: "Engagement only with politically divisive content", weight: 0.5 },
    { indicator: "Identical content posted across multiple accounts simultaneously", weight: 0.9 },
    { indicator: "Geographic inconsistency (claims US but timezone analysis shows otherwise)", weight: 0.8 },
    { indicator: "Language model perplexity score indicates AI-generated text", weight: 0.7 },
    { indicator: "Network analysis shows account is part of a cluster with similar creation dates and behavior", weight: 0.9 }
  ]
};


// ── Diplomatic Cyber Norms ───────────────────────────────────────────────

export const CYBER_NORMS = {
  un_gge_norms: [
    { year: 2015, norm: "States should not knowingly allow their territory to be used for internationally wrongful acts using ICTs" },
    { year: 2015, norm: "States should not conduct or support ICT activity that intentionally damages critical infrastructure" },
    { year: 2015, norm: "States should take reasonable steps to ensure the integrity of the supply chain for ICT products" },
    { year: 2015, norm: "States should not conduct or support activity to harm information systems of another State's emergency response teams (CERTs/CSIRTs)" },
    { year: 2015, norm: "States should cooperate to increase stability and security in the use of ICTs and prevent harmful practices" },
    { year: 2015, norm: "States should consider all relevant information in attributing ICT incidents" },
    { year: 2015, norm: "States should not use proxies to commit internationally wrongful acts using ICTs" },
    { year: 2021, norm: "States should protect their own critical infrastructure from ICT threats" },
    { year: 2021, norm: "States should report ICT vulnerabilities to vendors rather than stockpile them" },
    { year: 2021, norm: "States should encourage responsible reporting of ICT vulnerabilities" },
    { year: 2021, norm: "States should take action to ensure that non-State actors do not exploit ICTs for illegal purposes from their territory" }
  ],
  paris_call: {
    name: "Paris Call for Trust and Security in Cyberspace",
    year: 2018,
    principles: [
      "Prevent and recover from malicious cyber activities that threaten or cause significant, indiscriminate or systemic harm to individuals and critical infrastructure",
      "Prevent activity that intentionally and substantially damages the general availability or integrity of the public core of the Internet",
      "Strengthen our capacity to prevent malign interference by foreign actors aimed at undermining electoral processes through malicious cyber activities",
      "Prevent ICT-enabled theft of intellectual property, including trade secrets or other confidential business information, with the intent of providing competitive advantages to companies or commercial sector",
      "Develop ways to prevent the proliferation of malicious ICT tools and practices intended to cause harm",
      "Strengthen the security of digital processes, products and services, throughout their lifecycle and supply chain",
      "Support efforts to strengthen an advanced cyber hygiene for all actors",
      "Take steps to prevent non-State actors, including the private sector, from hacking-back, for their own purposes or those of other non-State actors",
      "Promote the widespread acceptance and implementation of international norms of responsible behavior as well as confidence-building measures in cyberspace"
    ],
    signatories_count: 1200,
    notable_non_signatories: ["United States (joined 2021)", "Russia", "China", "North Korea", "Iran"]
  },
  budapest_convention: {
    name: "Budapest Convention on Cybercrime",
    organization: "Council of Europe",
    year: 2001,
    articles_count: 48,
    key_provisions: [
      "Criminalize offenses against the confidentiality, integrity and availability of computer data and systems",
      "Criminalize computer-related forgery and fraud",
      "Criminalize content-related offenses (child exploitation)",
      "Criminalize copyright infringement via computer",
      "Establish procedural law powers for investigation (search, seizure, interception)",
      "Establish 24/7 points of contact for international cooperation",
      "Mutual legal assistance for cross-border investigations"
    ],
    parties_count: 68,
    protocols: [
      { name: "Additional Protocol on Xenophobia and Racism", year: 2003 },
      { name: "Second Additional Protocol on Enhanced Cooperation and Disclosure", year: 2022 }
    ]
  },
  tallinn_manual: {
    name: "Tallinn Manual 2.0 on the International Law Applicable to Cyber Operations",
    organization: "NATO Cooperative Cyber Defence Centre of Excellence (CCDCOE)",
    year: 2017,
    key_rules: [
      { rule: 1, topic: "Sovereignty", principle: "The principle of sovereignty applies to cyberspace" },
      { rule: 4, topic: "Violation of Sovereignty", principle: "A State must not conduct cyber operations that violate the sovereignty of another State" },
      { rule: 6, topic: "Due Diligence", principle: "A State must not knowingly allow cyber infrastructure in its territory to be used for acts that adversely affect other States" },
      { rule: 20, topic: "Prohibition of Intervention", principle: "A State may not intervene, including by cyber means, in the internal or external affairs of another State" },
      { rule: 30, topic: "Countermeasures", principle: "An injured State may resort to proportionate countermeasures, including cyber countermeasures, against a responsible State" },
      { rule: 32, topic: "Necessity", principle: "Cyber operations amounting to a use of force may only be conducted when necessary" },
      { rule: 51, topic: "Objects", principle: "Cyber attacks shall not be directed at civilian objects" },
      { rule: 69, topic: "Use of Force", principle: "A cyber operation constitutes a use of force when its scale and effects are comparable to non-cyber operations rising to the level of a use of force" },
      { rule: 71, topic: "Armed Attack", principle: "A cyber operation constitutes an armed attack if it results in death, injury, or significant destruction" },
      { rule: 80, topic: "Distinction", principle: "The parties to an armed conflict must distinguish between civilian objects and military objectives in cyber operations" }
    ]
  }
};


// ── Supply Chain Integrity ───────────────────────────────────────────────

export const SUPPLY_CHAIN_SECURITY = {
  sbom_format: {
    spdx: {
      name: "SPDX (Software Package Data Exchange)",
      standard: "ISO/IEC 5962:2021",
      fields: [
        { field: "SPDXVersion", required: true, desc: "SPDX specification version" },
        { field: "DataLicense", required: true, desc: "License for the SPDX data (CC0-1.0)" },
        { field: "SPDXID", required: true, desc: "Unique identifier for the document element" },
        { field: "DocumentName", required: true, desc: "Name of this SPDX document" },
        { field: "DocumentNamespace", required: true, desc: "Unique URI for this document" },
        { field: "Creator", required: true, desc: "Tool/person/organization that created the SPDX" },
        { field: "PackageName", required: true, desc: "Full name of the package" },
        { field: "PackageVersion", required: true, desc: "Version of the package" },
        { field: "PackageSupplier", required: false, desc: "Actual distributor of the package" },
        { field: "PackageDownloadLocation", required: true, desc: "Download URL for the package" },
        { field: "PackageChecksum", required: false, desc: "Checksum value (SHA256 recommended)" },
        { field: "PackageLicenseConcluded", required: true, desc: "License the creator concluded governs the package" },
        { field: "PackageLicenseDeclared", required: true, desc: "License the package creator declared" },
        { field: "PackageCopyrightText", required: true, desc: "Copyright holder of the package" },
        { field: "ExternalRef", required: false, desc: "External references (CPE, PURL, CVE)" },
        { field: "Relationship", required: true, desc: "Dependency relationships between packages" }
      ]
    },
    cyclonedx: {
      name: "CycloneDX",
      standard: "OWASP CycloneDX",
      fields: [
        { field: "bomFormat", required: true, desc: "Must be 'CycloneDX'" },
        { field: "specVersion", required: true, desc: "Specification version (e.g., 1.5)" },
        { field: "serialNumber", required: false, desc: "Unique BOM identifier (URN UUID)" },
        { field: "version", required: true, desc: "BOM version number" },
        { field: "metadata", required: false, desc: "BOM metadata (timestamp, tools, component)" },
        { field: "components", required: true, desc: "Array of software components" },
        { field: "components[].type", required: true, desc: "Component type (library, framework, application, container, device, firmware, file, operating-system)" },
        { field: "components[].name", required: true, desc: "Component name" },
        { field: "components[].version", required: true, desc: "Component version" },
        { field: "components[].purl", required: false, desc: "Package URL identifier" },
        { field: "components[].hashes", required: false, desc: "Cryptographic hashes (SHA-256, SHA-512)" },
        { field: "components[].licenses", required: false, desc: "Declared licenses" },
        { field: "components[].supplier", required: false, desc: "Supplier information" },
        { field: "dependencies", required: false, desc: "Dependency tree" },
        { field: "vulnerabilities", required: false, desc: "Known vulnerabilities (VEX)" }
      ]
    }
  },
  verification_checks: [
    { check: "Code Signing Verification", desc: "Verify digital signatures on all software artifacts using publisher's public key", tools: ["sigcheck (Sysinternals)", "codesign (macOS)", "gpg --verify", "Sigstore/cosign"] },
    { check: "Hash Verification", desc: "Compare SHA-256 hashes of downloaded artifacts against published checksums", tools: ["sha256sum", "Get-FileHash (PowerShell)", "openssl dgst -sha256"] },
    { check: "Dependency Pinning", desc: "Pin all dependencies to exact versions with integrity hashes", tools: ["npm package-lock.json (integrity field)", "pip --require-hashes", "go.sum", "cargo.lock"] },
    { check: "Reproducible Builds", desc: "Verify that building from source produces identical binary output", tools: ["reprotest", "diffoscope", "in-toto"] },
    { check: "SBOM Generation", desc: "Generate Software Bill of Materials for all released software", tools: ["syft", "trivy", "cdxgen", "spdx-sbom-generator"] },
    { check: "Vulnerability Scanning", desc: "Scan SBOM against known vulnerability databases", tools: ["grype", "trivy", "osv-scanner", "snyk"] },
    { check: "License Compliance", desc: "Verify all component licenses are compatible with distribution requirements", tools: ["license-checker", "fossology", "scancode-toolkit"] },
    { check: "Provenance Verification", desc: "Verify the build provenance (who built it, from what source, with what tools)", tools: ["SLSA framework", "in-toto", "Sigstore"] }
  ],
  build_pipeline_security: [
    { control: "Source Code Integrity", measures: ["Require signed commits", "Branch protection rules", "Code review requirements", "Two-person rule for sensitive changes"] },
    { control: "Build Environment", measures: ["Hermetic builds (no network access during build)", "Ephemeral build environments", "Build system hardening", "Minimal build dependencies"] },
    { control: "Artifact Integrity", measures: ["Sign all build artifacts", "Generate SBOM during build", "Publish checksums alongside artifacts", "Immutable artifact storage"] },
    { control: "Distribution Security", measures: ["Package signing (GPG, Sigstore)", "Secure package registry", "Content delivery integrity (SRI hashes)", "Version pinning recommendations"] },
    { control: "Pipeline Access Control", measures: ["Least privilege for CI/CD systems", "Separate credentials per pipeline stage", "Audit logging of all pipeline actions", "MFA for pipeline configuration changes"] }
  ]
};


// ── Sanctions & Export Control Reference ─────────────────────────────────

export const EXPORT_CONTROLS = {
  restricted_cyber_technologies: [
    { category: "Intrusion Software", wassenaar: "4.A.5 / 4.D.4", desc: "Software specially designed to avoid detection by monitoring tools, or to defeat protective countermeasures, and extract data or modify system execution path" },
    { category: "IP Network Surveillance", wassenaar: "5.A.1.j", desc: "IP network communications surveillance systems capable of inspecting content and intercepting communications" },
    { category: "Cryptanalysis Items", wassenaar: "5.A.2.a.3", desc: "Items designed or modified for cryptanalysis" },
    { category: "Zero-Day Exploits", note: "No specific control number — covered under Intrusion Software and Wassenaar Arrangement debate" },
    { category: "Lawful Intercept Equipment", wassenaar: "5.A.1.f", desc: "Telecommunications interception equipment" },
    { category: "Location Tracking Systems", wassenaar: "5.A.1.g", desc: "Radio direction finding equipment capable of tracking mobile devices" }
  ],
  entity_lists: [
    { list: "OFAC SDN List", agency: "Treasury", desc: "Specially Designated Nationals and Blocked Persons — cannot transact with US persons or use US financial system" },
    { list: "BIS Entity List", agency: "Commerce", desc: "Entities subject to specific export license requirements due to activities contrary to US national security/foreign policy" },
    { list: "BIS Denied Persons List", agency: "Commerce", desc: "Individuals/entities denied export privileges" },
    { list: "State Department Debarred List", agency: "State", desc: "Parties debarred from participating in defense trade" },
    { list: "EU Consolidated List", agency: "EU", desc: "EU financial sanctions — asset freezes and travel bans" },
    { list: "UK OFSI Consolidated List", agency: "HM Treasury", desc: "UK financial sanctions targets" }
  ],
  notable_sanctioned_cyber_entities: [
    { entity: "GRU Unit 26165 / Unit 74455", nation: "Russia", reason: "Cyber operations against US elections, NotPetya, Olympics" },
    { entity: "Lazarus Group / RGB", nation: "North Korea", reason: "WannaCry, SWIFT thefts, cryptocurrency heists" },
    { entity: "Evil Corp / Maksim Yakubets", nation: "Russia", reason: "Dridex banking trojan, BitPaymer/WastedLocker ransomware" },
    { entity: "NSO Group", nation: "Israel", reason: "Pegasus spyware used against journalists, activists, diplomats" },
    { entity: "Positive Technologies", nation: "Russia", reason: "Providing cyber tools and services to Russian intelligence" },
    { entity: "Integrity Technology Group (Flax Typhoon)", nation: "China", reason: "State-sponsored botnet operations targeting critical infrastructure" },
    { entity: "CyberSprint (CyberAv3ngers)", nation: "Iran", reason: "IRGC-affiliated attacks on US water treatment facilities" }
  ]
};


// ── Utility Functions ────────────────────────────────────────────────────

export function lookupThreatActor(name) {
  const q = name.toLowerCase();
  for (const nation of THREAT_ACTORS) {
    for (const group of nation.groups) {
      if (group.name.toLowerCase().includes(q)) return { nation: nation.nation, ...group };
      if (group.aliases.some(a => a.toLowerCase().includes(q))) return { nation: nation.nation, ...group };
    }
  }
  return null;
}

export function lookupSector(id) {
  return CRITICAL_INFRASTRUCTURE_SECTORS.find(s => s.id === id) || null;
}

export function lookupNISTSubcategory(id) {
  for (const fn of NIST_CSF.functions) {
    for (const cat of fn.categories) {
      for (const sub of cat.subcategories) {
        if (sub.id === id) return { function: fn.name, category: cat.name, ...sub };
      }
    }
  }
  return null;
}

export function getNISTSubcategoryCount() {
  let count = 0;
  for (const fn of NIST_CSF.functions) {
    for (const cat of fn.categories) {
      count += cat.subcategories.length;
    }
  }
  return count;
}

export function getThreatActorsByTarget(target) {
  const q = target.toLowerCase();
  const results = [];
  for (const nation of THREAT_ACTORS) {
    for (const group of nation.groups) {
      if (group.targets.some(t => t.toLowerCase().includes(q))) {
        results.push({ nation: nation.nation, name: group.name, org: group.org });
      }
    }
  }
  return results;
}

export function getSectorThreats(sectorId) {
  const sector = lookupSector(sectorId);
  if (!sector) return [];
  return sector.known_threats;
}

export function assessCriticalInfrastructureRisk(sectorId, hasOTNetwork, hasInternetFacing, hasRemoteAccess, patchAge) {
  let risk = 30;
  const sector = lookupSector(sectorId);
  if (!sector) return { risk, label: "Unknown" };

  if (hasOTNetwork) risk += 15;
  if (hasInternetFacing) risk += 20;
  if (hasRemoteAccess) risk += 10;
  if (patchAge > 90) risk += 15;
  else if (patchAge > 30) risk += 8;

  risk += sector.known_threats.length * 3;

  risk = Math.min(100, risk);
  let label;
  if (risk >= 80) label = "Critical";
  else if (risk >= 60) label = "High";
  else if (risk >= 40) label = "Medium";
  else label = "Low";

  return { risk, label, sector: sector.name, threats: sector.known_threats.length, frameworks: sector.frameworks };
}
