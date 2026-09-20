// Copyright (c) 2026 SpartanKing18. All rights reserved.
// Threat Actor Profiles Database — 100 real-world threat groups

export const THREAT_ACTORS = [
  {
    name: "APT28", aliases: ["Fancy Bear", "Sofacy", "Pawn Storm", "Sednit", "STRONTIUM", "Forest Blizzard"],
    attribution: "Russia (GRU Unit 26165)", type: "state-sponsored", active_since: "2004", status: "active",
    targets: { industries: ["Government", "Military", "Defense", "Media", "Energy", "Transportation"], countries: ["USA", "Ukraine", "Georgia", "NATO members", "EU"] },
    known_tools: ["X-Agent/Sofacy", "X-Tunnel", "Zebrocy", "Komplex", "Seduploader", "GameFish", "LoJax (UEFI rootkit)", "GoDownloader"],
    notable_operations: [
      { name: "DNC Hack", date: "2016", description: "Compromised Democratic National Committee networks, exfiltrated emails released via DCLeaks and WikiLeaks", impact: "Major political disruption during US presidential election" },
      { name: "Bundestag Attack", date: "2015", description: "Infiltrated German parliament network for months, exfiltrated 16GB of data", impact: "Forced complete rebuild of Bundestag IT infrastructure" },
      { name: "Olympic Destroyer", date: "2018", description: "Destructive malware targeting 2018 Pyeongchang Winter Olympics, false-flagged as North Korean", impact: "Disrupted IT systems during opening ceremony" },
      { name: "NotPetya", date: "2017", description: "Co-attributed supply chain attack via Ukrainian tax software MEDoc causing global wiper outbreak", impact: "Estimated $10 billion in damages worldwide" }
    ],
    ttps: { initial_access: ["Spear-phishing (T1566)", "Credential harvesting", "Watering hole (T1189)", "Exploiting VPN appliances"], execution: ["PowerShell", "Rundll32", "Scripting"], persistence: ["Registry run keys", "Scheduled tasks", "UEFI rootkit"], c2: ["HTTP/HTTPS beacons", "DNS tunneling", "Tor"], exfil: ["Encrypted RAR archives", "Cloud storage", "Email"] },
    iocs: { domains: ["microsofthelpcenter.info", "onedrive-ede.com", "login-live-service.com"], ips: [], hashes: [] },
    mitre_groups_id: "G0007", references: ["https://attack.mitre.org/groups/G0007/"]
  },
  {
    name: "APT29", aliases: ["Cozy Bear", "The Dukes", "NOBELIUM", "Midnight Blizzard", "YTTRIUM"],
    attribution: "Russia (SVR)", type: "state-sponsored", active_since: "2008", status: "active",
    targets: { industries: ["Government", "Think Tanks", "Technology", "Healthcare", "Energy", "Diplomacy"], countries: ["USA", "Europe", "NATO members"] },
    known_tools: ["SUNBURST", "TEARDROP", "Raindrop", "BEATDROP", "MagicWeb", "FoggyWeb", "WellMess", "WellMail", "CosmicDuke", "MiniDuke", "SeaDuke", "HAMMERTOSS", "EnvyScout"],
    notable_operations: [
      { name: "SolarWinds (SUNBURST)", date: "2020", description: "Supply chain attack via SolarWinds Orion update, compromised 18,000+ organizations including US Treasury, Commerce, DHS", impact: "Most significant supply chain attack in history, months of undetected access to critical government systems" },
      { name: "COVID-19 Vaccine Espionage", date: "2020", description: "Targeted pharmaceutical companies and research institutions developing COVID-19 vaccines", impact: "Theft of vaccine research data from multiple countries" },
      { name: "Microsoft 365 OAuth Abuse", date: "2023-2024", description: "Exploited OAuth applications and consent phishing in Microsoft 365 environments", impact: "Accessed senior US government official emails" }
    ],
    ttps: { initial_access: ["Supply chain compromise", "Spear-phishing with HTML smuggling", "OAuth consent phishing", "Trusted relationship abuse"], execution: ["PowerShell", "WMI", "DLL side-loading"], persistence: ["ADFS token signing cert theft", "OAuth app registration", "Scheduled tasks"], c2: ["Encrypted HTTPS", "Legitimate cloud services (Azure, OneDrive)", "Steganography"], exfil: ["Cloud-to-cloud exfiltration", "Encrypted channels"] },
    iocs: { domains: ["solarwinds.orionimprovement.com", "freescanonline.com"], ips: [], hashes: [] },
    mitre_groups_id: "G0016", references: ["https://attack.mitre.org/groups/G0016/"]
  },
  {
    name: "Lazarus Group", aliases: ["HIDDEN COBRA", "Guardians of Peace", "Zinc", "Diamond Sleet", "Labyrinth Chollima", "APT38 (financial arm)"],
    attribution: "North Korea (RGB)", type: "state-sponsored", active_since: "2009", status: "active",
    targets: { industries: ["Finance", "Cryptocurrency", "Defense", "Entertainment", "Technology", "Government"], countries: ["USA", "South Korea", "Japan", "Global financial institutions"] },
    known_tools: ["Manuscrypt", "Fallchill", "Volgmer", "HOPLIGHT", "AppleJeus", "ThreatNeedle", "BLINDINGCAN", "DTrack", "Maui Ransomware", "LightlessCan"],
    notable_operations: [
      { name: "Sony Pictures Hack", date: "2014", description: "Destructive attack wiping Sony Pictures Entertainment systems, leaked unreleased films and internal emails", impact: "Estimated $35M in direct damages, massive data leak, geopolitical tensions" },
      { name: "Bangladesh Bank Heist", date: "2016", description: "Attempted $951M theft from Bangladesh Bank via SWIFT network, succeeded in transferring $81M", impact: "Largest cyber bank heist, exposed SWIFT network vulnerabilities" },
      { name: "WannaCry Ransomware", date: "2017", description: "Global ransomware attack using NSA's EternalBlue exploit, infected 200,000+ computers in 150 countries", impact: "Estimated $4-8 billion in damages, crippled UK NHS hospitals" },
      { name: "Ronin Bridge Hack", date: "2022", description: "Stole $620M in cryptocurrency from Ronin Network (Axie Infinity)", impact: "Largest cryptocurrency theft ever at the time" },
      { name: "3CX Supply Chain", date: "2023", description: "Supply chain attack via 3CX VoIP software, cascading from a prior Trading Technologies compromise", impact: "Multi-stage supply chain attack affecting thousands of businesses" }
    ],
    ttps: { initial_access: ["Spear-phishing", "Watering hole", "Supply chain compromise", "Trojanized cryptocurrency apps", "Fake job offers (Operation Dream Job)"], execution: ["Custom malware", "PowerShell", "Scripting"], persistence: ["Startup folder", "Registry", "Bootkit"], c2: ["HTTP/HTTPS", "Custom protocols", "Compromised web servers"], exfil: ["Custom encrypted channels", "Cloud storage"] },
    iocs: { domains: [], ips: [], hashes: [] },
    mitre_groups_id: "G0032", references: ["https://attack.mitre.org/groups/G0032/"]
  },
  {
    name: "Equation Group", aliases: ["EQGRP", "Tilded Team"],
    attribution: "USA (NSA TAO)", type: "state-sponsored", active_since: "1996", status: "active",
    targets: { industries: ["Government", "Military", "Telecommunications", "Energy", "Nuclear", "Finance", "Aerospace"], countries: ["Iran", "Russia", "Pakistan", "Afghanistan", "India", "China", "Syria", "Mali"] },
    known_tools: ["EternalBlue", "EternalRomance", "DoublePulsar", "EQUATIONDRUG", "GRAYFISH", "Fanny worm", "EquationLaser", "UNITEDRAKE", "VALIDATOR", "nls_933w.dll (HDD firmware)"],
    notable_operations: [
      { name: "Stuxnet (co-developed)", date: "2010", description: "Worm targeting Iranian nuclear centrifuges at Natanz, caused physical destruction of 1,000 centrifuges", impact: "First known cyber weapon causing physical damage, set back Iran's nuclear program by years" },
      { name: "Shadow Brokers Leak", date: "2016-2017", description: "NSA tools leaked by Shadow Brokers group, including EternalBlue exploit later used in WannaCry/NotPetya", impact: "NSA's most sophisticated tools exposed publicly, spawned global ransomware epidemics" },
      { name: "HDD Firmware Implants", date: "2001-2015", description: "Reprogrammed hard drive firmware from Seagate, Western Digital, and others to survive OS reinstalls and disk formatting", impact: "Demonstrated unprecedented persistence capability, affected drives in 30+ countries" }
    ],
    ttps: { initial_access: ["USB-based (Fanny worm)", "Spear-phishing", "Web exploit kits", "Interdiction of physical shipments"], execution: ["Custom kernel-level implants", "Zero-day exploits"], persistence: ["HDD firmware modification", "VBR bootkits", "Registry"], c2: ["Encrypted channels", "DNS covert channels", "Satellite hijacking"], exfil: ["Air-gapped network bridging via USB", "Encrypted covert channels"] },
    iocs: { domains: [], ips: [], hashes: [] },
    mitre_groups_id: "G0020", references: ["https://attack.mitre.org/groups/G0020/"]
  },
  {
    name: "APT41", aliases: ["Double Dragon", "Wicked Panda", "Barium", "Brass Typhoon", "Winnti Group"],
    attribution: "China (MSS-affiliated, also moonlights for profit)", type: "state-sponsored", active_since: "2012", status: "active",
    targets: { industries: ["Gaming", "Healthcare", "Technology", "Telecommunications", "Education", "Media", "Travel", "Finance"], countries: ["USA", "UK", "France", "Australia", "Japan", "India", "Global"] },
    known_tools: ["Winnti", "ShadowPad", "POISONPLUG", "Crosswalk", "DUSTPAN", "DUSTTRAP", "LOWKEY", "DEADEYE", "KeyPlug", "MESSAGETAP"],
    notable_operations: [
      { name: "CCleaner Supply Chain", date: "2017", description: "Compromised Avast's CCleaner software, backdoored version distributed to 2.27 million users", impact: "Targeted tech companies including Intel, Samsung, Sony, VMware" },
      { name: "MESSAGETAP Telco Attacks", date: "2019", description: "Deployed SMS-intercepting malware at telecommunication providers to surveil specific phone numbers", impact: "Targeted surveillance of specific individuals across multiple countries" },
      { name: "US State Government Compromise", date: "2021-2022", description: "Exploited Log4j and zero-days in internet-facing applications to compromise at least six US state governments", impact: "Persistent access to government networks for espionage" }
    ],
    ttps: { initial_access: ["Supply chain compromise", "Spear-phishing", "Exploiting public-facing applications (Citrix, Cisco, Zoho)"], execution: ["DLL side-loading", "PowerShell", "Compiled HTML (.chm)"], persistence: ["Rootkits", "Bootkit", "Scheduled tasks", "Registry"], c2: ["HTTP/HTTPS", "DNS tunneling", "Dead drop resolvers on legitimate platforms"], exfil: ["RAR archives", "Cloud services"] },
    iocs: { domains: [], ips: [], hashes: [] },
    mitre_groups_id: "G0096", references: ["https://attack.mitre.org/groups/G0096/"]
  },
  {
    name: "Sandworm", aliases: ["Voodoo Bear", "IRIDIUM", "Seashell Blizzard", "TeleBots", "Iron Viking", "Electrum"],
    attribution: "Russia (GRU Unit 74455)", type: "state-sponsored", active_since: "2009", status: "active",
    targets: { industries: ["Energy", "Government", "Media", "Transportation", "Election infrastructure", "Critical infrastructure"], countries: ["Ukraine", "USA", "Europe", "South Korea"] },
    known_tools: ["BlackEnergy", "Industroyer/CrashOverride", "Industroyer2", "NotPetya", "KillDisk", "Olympic Destroyer", "Cyclops Blink", "AcidRain", "CaddyWiper", "SwiftSlicer"],
    notable_operations: [
      { name: "Ukraine Power Grid Attack", date: "2015", description: "First confirmed cyberattack to take down a power grid, affected 225,000 customers in western Ukraine using BlackEnergy and KillDisk", impact: "Proved cyber attacks can cause physical infrastructure damage at scale" },
      { name: "Ukraine Power Grid Attack 2", date: "2016", description: "More sophisticated attack using Industroyer/CrashOverride malware targeting Ukrainian transmission substations", impact: "Power outage in Kyiv, demonstrated ICS-specific malware capabilities" },
      { name: "NotPetya", date: "2017", description: "Destructive wiper disguised as ransomware, spread via Ukrainian tax software MEDoc update", impact: "Most destructive cyberattack in history, $10 billion+ in global damages, hit Maersk, Merck, FedEx, Mondelez" },
      { name: "Viasat Attack", date: "2022", description: "AcidRain wiper targeted Viasat KA-SAT satellite modems at the start of Russia's invasion of Ukraine", impact: "Disrupted Ukrainian military communications, also affected European wind turbines" }
    ],
    ttps: { initial_access: ["Spear-phishing", "Supply chain", "Exploiting VPN appliances", "Watering hole"], execution: ["ICS-specific malware", "PowerShell", "Wiper malware"], persistence: ["Rootkits", "UEFI implants", "Scheduled tasks"], c2: ["HTTP/HTTPS", "Tor", "Custom protocols"], exfil: ["Destructive operations (wipers) often prioritized over exfil"] },
    iocs: { domains: [], ips: [], hashes: [] },
    mitre_groups_id: "G0034", references: ["https://attack.mitre.org/groups/G0034/"]
  },
  {
    name: "Turla", aliases: ["Snake", "Venomous Bear", "Uroburos", "Waterbug", "Secret Blizzard", "KRYPTON", "Iron Hunter"],
    attribution: "Russia (FSB Center 16)", type: "state-sponsored", active_since: "1996", status: "active",
    targets: { industries: ["Government", "Diplomacy", "Military", "Research", "Media"], countries: ["USA", "Europe", "Central Asia", "Middle East"] },
    known_tools: ["Snake/Uroburos", "Carbon", "Kazuar", "ComRAT", "Gazer", "Mosquito", "LightNeuron", "HyperStack", "TinyTurla", "Capibar", "DeliveryCheck"],
    notable_operations: [
      { name: "Snake Disruption", date: "2023", description: "FBI's Operation MEDUSA disrupted Turla's Snake malware network spanning 50+ countries over 20 years", impact: "One of the longest-running cyber espionage implant networks in history" },
      { name: "Satellite Internet Hijacking", date: "2015", description: "Hijacked satellite internet connections to hide C2 traffic, receiving data from compromised satellites without registration", impact: "Demonstrated novel C2 technique nearly impossible to trace" },
      { name: "Hijacking APT34 Infrastructure", date: "2019", description: "Took over Iranian APT34/OilRig C2 servers to conduct operations through their infrastructure", impact: "First documented case of one APT hijacking another APT's infrastructure" }
    ],
    ttps: { initial_access: ["Spear-phishing", "Watering hole", "Compromised other APT infrastructure"], execution: ["PowerShell", "Custom interpreted scripts"], persistence: ["Rootkits (kernel-level)", "Exchange transport agents (LightNeuron)", "COM object hijacking"], c2: ["Satellite hijacking", "HTTP/HTTPS", "Email-based (Outlook backdoors)", "Named pipes for local lateral"], exfil: ["Email drafts", "Encrypted HTTP", "Satellite channels"] },
    iocs: { domains: [], ips: [], hashes: [] },
    mitre_groups_id: "G0010", references: ["https://attack.mitre.org/groups/G0010/"]
  },
  {
    name: "Kimsuky", aliases: ["Velvet Chollima", "Emerald Sleet", "THALLIUM", "Black Banshee", "APT43"],
    attribution: "North Korea (RGB)", type: "state-sponsored", active_since: "2012", status: "active",
    targets: { industries: ["Government", "Think Tanks", "Academia", "Nuclear/Energy", "Defense"], countries: ["South Korea", "USA", "Japan", "Europe"] },
    known_tools: ["BabyShark", "AppleSeed", "FlowerPower", "RandomQuery", "GoldDragon", "KONNI", "ReconShark", "FastViewer"],
    notable_operations: [
      { name: "Korea Hydro & Nuclear Power", date: "2014", description: "Stole and leaked blueprints from South Korean nuclear power operator", impact: "Leaked reactor designs, employee data, raised nuclear safety concerns" },
      { name: "Google/Yahoo Credential Theft", date: "2018-ongoing", description: "Massive credential harvesting campaigns targeting North Korea researchers and journalists", impact: "Ongoing intelligence collection on DPRK policy experts" }
    ],
    ttps: { initial_access: ["Spear-phishing (highly targeted)", "Credential harvesting websites", "Watering hole"], execution: ["VBA macros", "PowerShell", "HTA files", "CHM files"], persistence: ["Registry run keys", "Startup folder", "Scheduled tasks"], c2: ["HTTP/HTTPS", "FTP", "Cloud services (Google Drive, Dropbox)"], exfil: ["Email forwarding rules", "Cloud storage upload", "FTP"] },
    iocs: { domains: [], ips: [], hashes: [] },
    mitre_groups_id: "G0094", references: ["https://attack.mitre.org/groups/G0094/"]
  },
  {
    name: "OceanLotus", aliases: ["APT32", "Canvas Cyclone", "SeaLotus", "Cobalt Kitty"],
    attribution: "Vietnam (Ministry of Public Security)", type: "state-sponsored", active_since: "2012", status: "active",
    targets: { industries: ["Government", "Media", "Human Rights", "Manufacturing", "Technology", "Hospitality"], countries: ["Vietnam (dissidents)", "ASEAN nations", "China", "Germany", "USA"] },
    known_tools: ["Denis", "Kerrdown", "Ratsnif", "Windshield", "Komprogo", "OSX_OCEANLOTUS", "PhantomNet"],
    notable_operations: [
      { name: "Vietnamese Dissidents Surveillance", date: "2013-ongoing", description: "Continuous targeting of Vietnamese diaspora, journalists, and human rights activists", impact: "Surveillance and intimidation of political opposition" },
      { name: "BMW/Hyundai/Toyota Attacks", date: "2019", description: "Targeted automotive manufacturers including BMW Vietnam and Hyundai", impact: "Suspected industrial espionage in automotive sector" }
    ],
    ttps: { initial_access: ["Spear-phishing with social engineering lures", "Watering hole with strategic web compromises"], execution: ["DLL side-loading", "Cobalt Strike", "Custom macOS malware"], persistence: ["Scheduled tasks", "Startup items", "Registry"], c2: ["HTTP/HTTPS", "DNS tunneling", "Steganography"], exfil: ["Cloud services", "Custom encrypted channels"] },
    iocs: { domains: [], ips: [], hashes: [] },
    mitre_groups_id: "G0050", references: ["https://attack.mitre.org/groups/G0050/"]
  },
  {
    name: "Charming Kitten", aliases: ["APT35", "Mint Sandstorm", "Phosphorus", "NewsBeef", "Ajax Security Team"],
    attribution: "Iran (IRGC)", type: "state-sponsored", active_since: "2011", status: "active",
    targets: { industries: ["Government", "Defense", "Journalism", "Academia", "Human Rights", "Think Tanks"], countries: ["USA", "Israel", "UK", "Saudi Arabia", "Iraq"] },
    known_tools: ["HYPERSCRAPE", "CharmPower", "PowerLess", "BellaCiao", "MediaPl", "BASICSTAR", "NokNok", "SpoofedScholars"],
    notable_operations: [
      { name: "Operation SpoofedScholars", date: "2021", description: "Impersonated scholars at SOAS University of London to target think tank researchers for credential harvesting", impact: "Highly convincing social engineering targeting Middle East policy experts" },
      { name: "HBO Hack", date: "2017", description: "Stole 1.5TB of data from HBO including unreleased Game of Thrones episodes", impact: "Leaked scripts and episodes, demanded $6M ransom" }
    ],
    ttps: { initial_access: ["Spear-phishing (very personalized)", "Fake conference invitations", "Impersonation of journalists/academics", "SMS phishing"], execution: ["PowerShell", "Python backdoors", "Custom .NET malware"], persistence: ["Scheduled tasks", "Registry run keys"], c2: ["HTTP/HTTPS", "Cloud services (Google, Microsoft)"], exfil: ["HYPERSCRAPE (email extraction)", "Cloud upload"] },
    iocs: { domains: [], ips: [], hashes: [] },
    mitre_groups_id: "G0059", references: ["https://attack.mitre.org/groups/G0059/"]
  },
  {
    name: "MuddyWater", aliases: ["Mercury", "Mango Sandstorm", "Static Kitten", "TEMP.Zagros", "Seedworm"],
    attribution: "Iran (MOIS)", type: "state-sponsored", active_since: "2017", status: "active",
    targets: { industries: ["Government", "Telecommunications", "Oil & Gas", "Defense", "Education"], countries: ["Middle East", "Central Asia", "Turkey", "Pakistan", "USA"] },
    known_tools: ["POWERSTATS", "MuddyC2Go", "PhonyC2", "SimpleHarm", "MiniDump", "Ligolo", "Atera Agent", "SimpleHelp"],
    notable_operations: [
      { name: "Telecom Targeting in Middle East", date: "2021-2022", description: "Widespread campaigns against telecoms in Jordan, Turkey, and Bahrain using legitimate RMM tools", impact: "Espionage access to telecommunications infrastructure" }
    ],
    ttps: { initial_access: ["Spear-phishing with macro-enabled documents", "Exploitation of Exchange servers"], execution: ["PowerShell", "VBA macros", "Legitimate RMM tools (Atera, ScreenConnect, SimpleHelp)"], persistence: ["Scheduled tasks", "Registry", "Legitimate remote admin tools"], c2: ["PowerShell-based C2", "Legitimate cloud services", "Custom tunneling tools"], exfil: ["Archive and upload via C2"] },
    iocs: { domains: [], ips: [], hashes: [] },
    mitre_groups_id: "G0069", references: ["https://attack.mitre.org/groups/G0069/"]
  },
  {
    name: "Gamaredon", aliases: ["Primitive Bear", "Aqua Blizzard", "Shuckworm", "Armageddon", "ACTINIUM"],
    attribution: "Russia (FSB Crimea)", type: "state-sponsored", active_since: "2013", status: "active",
    targets: { industries: ["Government", "Military", "Law Enforcement", "NGOs", "Diplomacy"], countries: ["Ukraine"] },
    known_tools: ["Pterodo/Pteranodon", "GammaSteel", "FileStealer", "EvilGnome", "Outlook VBA macro worm"],
    notable_operations: [
      { name: "Continuous Ukraine Operations", date: "2014-ongoing", description: "Most prolific Russian APT targeting Ukraine with thousands of attacks per year, volumes increased dramatically after 2022 invasion", impact: "Persistent harassment and espionage against Ukrainian government and military" }
    ],
    ttps: { initial_access: ["Spear-phishing with weaponized documents", "USB infection", "Telegram phishing"], execution: ["VBScript", "PowerShell", "HTA files", "Macro-enabled documents"], persistence: ["Registry", "Scheduled tasks", "Outlook macro self-propagation"], c2: ["Dynamic DNS services", "Telegram bot API", "HTTP"], exfil: ["Automated file collection from removable drives and network shares"] },
    iocs: { domains: [], ips: [], hashes: [] },
    mitre_groups_id: "G0047", references: ["https://attack.mitre.org/groups/G0047/"]
  },
  {
    name: "LockBit", aliases: ["LockBit 2.0", "LockBit 3.0", "LockBit Black", "LockBit Green"],
    attribution: "Russia-based (Dmitry Khoroshev alleged leader)", type: "cybercrime", active_since: "2019", status: "disrupted",
    targets: { industries: ["Healthcare", "Finance", "Manufacturing", "Government", "Education", "Legal", "Technology"], countries: ["Global (avoid CIS)"] },
    known_tools: ["LockBit ransomware (versions 1.0, 2.0, 3.0/Black, Green)", "StealBit (data exfiltration)"],
    notable_operations: [
      { name: "Royal Mail Attack", date: "2023", description: "Encrypted Royal Mail's international dispatch systems, demanding $80M ransom", impact: "Halted UK international mail services for weeks" },
      { name: "Boeing Attack", date: "2023", description: "Claimed attack on Boeing, leaked 43GB of sensitive data after ransom not paid", impact: "Exposed Boeing parts supplier and internal data" },
      { name: "Operation Cronos", date: "2024", description: "International law enforcement operation took down LockBit infrastructure, seized servers, arrested affiliates", impact: "Temporarily disrupted most prolific ransomware operation, LockBit attempted comeback" }
    ],
    ttps: { initial_access: ["Exploiting RDP", "Phishing", "Exploiting public-facing applications (Citrix, Fortinet)", "Initial access brokers"], execution: ["PsExec", "PowerShell", "Cobalt Strike"], persistence: ["Scheduled tasks", "Registry", "Service creation"], c2: ["Cobalt Strike", "Tor for leak site"], exfil: ["StealBit custom tool", "Mega.nz", "Cloud services"] },
    iocs: { domains: [], ips: [], hashes: [] },
    mitre_groups_id: "", references: ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a"]
  },
  {
    name: "BlackCat", aliases: ["ALPHV", "Noberus"],
    attribution: "Russia-based", type: "cybercrime", active_since: "2021", status: "disbanded",
    targets: { industries: ["Healthcare", "Finance", "Manufacturing", "Government", "Legal", "Energy"], countries: ["Global (avoid CIS)"] },
    known_tools: ["BlackCat/ALPHV ransomware (written in Rust)", "Eamfo (credential stealer)", "Sphynx (updated variant)"],
    notable_operations: [
      { name: "Change Healthcare Attack", date: "2024", description: "Attacked UnitedHealth's Change Healthcare, disrupted prescription processing across the US for weeks", impact: "UnitedHealth paid $22M ransom, affected millions of patients, estimated $872M in total impact" },
      { name: "MGM Resorts Attack", date: "2023", description: "Attacked MGM Resorts via social engineering (Scattered Spider affiliate), encrypted systems across Las Vegas properties", impact: "Estimated $100M loss, casinos and hotels disrupted for days" },
      { name: "Exit Scam", date: "2024", description: "After receiving Change Healthcare ransom, put up fake FBI seizure banner and disappeared with affiliate funds", impact: "Affiliates defrauded, group effectively disbanded" }
    ],
    ttps: { initial_access: ["Initial access brokers", "Exploiting public-facing applications", "Social engineering (Scattered Spider affiliates)"], execution: ["Rust-based ransomware (cross-platform)", "PsExec"], persistence: ["Service creation", "Registry"], c2: ["Tor", "Cobalt Strike"], exfil: ["ExMatter", "Custom tools"] },
    iocs: { domains: [], ips: [], hashes: [] },
    mitre_groups_id: "", references: []
  },
  {
    name: "Scattered Spider", aliases: ["Octo Tempest", "UNC3944", "Roasted 0ktapus", "Star Fraud"],
    attribution: "USA/UK-based (young English-speaking hackers)", type: "cybercrime", active_since: "2022", status: "active",
    targets: { industries: ["Technology", "Telecommunications", "Gaming", "Hospitality", "Finance", "BPO"], countries: ["USA", "UK", "Global"] },
    known_tools: ["Social engineering (primary tool)", "SIM swapping", "Okta exploitation", "Azure AD manipulation", "Cobalt Strike", "ScreenConnect"],
    notable_operations: [
      { name: "MGM Resorts + Caesars", date: "2023", description: "Called MGM help desk posing as employee, obtained credentials, deployed ALPHV ransomware. Caesars paid $15M ransom quietly", impact: "MGM lost ~$100M, Caesars paid $15M, demonstrated devastating social engineering" },
      { name: "Okta Credential Theft", date: "2022-2023", description: "Targeted 130+ organizations via SMS phishing campaign impersonating Okta login pages, harvested MFA codes in real-time", impact: "Compromised Twilio, Mailchimp, Cloudflare employees" },
      { name: "SIM Swap Attacks", date: "2022-ongoing", description: "Bribed and socially engineered telecom employees to transfer phone numbers for MFA bypass", impact: "Millions in cryptocurrency stolen from individual victims" }
    ],
    ttps: { initial_access: ["Social engineering (phone calls to help desk)", "SMS phishing (real-time MFA relay)", "SIM swapping", "Hiring insiders"], execution: ["Living-off-the-land (Azure AD, Okta admin)", "RMM tools", "Cobalt Strike"], persistence: ["Creating new admin accounts", "Federated identity manipulation", "MFA device enrollment"], c2: ["RMM tools (ScreenConnect, AnyDesk)", "Telegram"], exfil: ["Cloud-to-cloud exfil", "Data staging in attacker-controlled Azure tenants"] },
    iocs: { domains: [], ips: [], hashes: [] },
    mitre_groups_id: "", references: []
  },
  {
    name: "Conti", aliases: ["Gold Ulrick", "Wizard Spider (operator)"],
    attribution: "Russia-based", type: "cybercrime", active_since: "2020", status: "disbanded",
    targets: { industries: ["Healthcare", "Government", "Manufacturing", "Education", "Finance"], countries: ["Global (avoided Russia)"] },
    known_tools: ["Conti ransomware", "BazarLoader", "TrickBot", "Cobalt Strike", "Anchor"],
    notable_operations: [
      { name: "Ireland HSE Attack", date: "2021", description: "Encrypted Ireland's entire Health Service Executive, demanded $20M ransom", impact: "Hospitals reverted to paper, months to fully recover, estimated €100M recovery cost" },
      { name: "Costa Rica Government", date: "2022", description: "Attacked multiple Costa Rican government agencies, demanded $20M, Costa Rica declared state of emergency", impact: "First country to declare national emergency due to ransomware" },
      { name: "Conti Leaks", date: "2022", description: "Internal chats and source code leaked by Ukrainian researcher after Conti supported Russia's invasion", impact: "Exposed inner workings of a major ransomware operation, members scattered to other groups (Royal, Black Basta, BlackByte)" }
    ],
    ttps: { initial_access: ["BazarLoader/TrickBot phishing", "Exploiting Fortinet/Exchange", "Initial access brokers"], execution: ["Cobalt Strike", "PsExec", "WMI"], persistence: ["Service creation", "Scheduled tasks"], c2: ["Cobalt Strike", "Tor"], exfil: ["Rclone to cloud storage", "Mega.nz"] },
    iocs: { domains: [], ips: [], hashes: [] },
    mitre_groups_id: "G0132", references: ["https://attack.mitre.org/groups/G0132/"]
  },
  {
    name: "REvil", aliases: ["Sodinokibi", "Gold Southfield", "Pinchy Spider"],
    attribution: "Russia-based", type: "cybercrime", active_since: "2019", status: "disbanded",
    targets: { industries: ["Technology", "Legal", "Manufacturing", "MSPs", "Government"], countries: ["Global (avoided CIS)"] },
    known_tools: ["REvil/Sodinokibi ransomware", "QakBot", "IcedID"],
    notable_operations: [
      { name: "Kaseya VSA Attack", date: "2021", description: "Supply chain attack via Kaseya VSA remote management software, hit 800-1500 businesses via MSPs", impact: "Largest ransomware attack by victim count, demanded $70M collective ransom" },
      { name: "JBS Foods Attack", date: "2021", description: "Encrypted JBS, the world's largest meat processor, JBS paid $11M ransom", impact: "Temporarily shut down meat processing plants in USA, Canada, Australia" },
      { name: "Acer Attack", date: "2021", description: "Attacked Acer via Microsoft Exchange vulnerability, demanded $50M — highest ransom demand at the time", impact: "Leaked financial documents after negotiation stalled" }
    ],
    ttps: { initial_access: ["Exploiting RDP", "Phishing", "Supply chain (MSPs)", "Exploit kits"], execution: ["PowerShell", "PsExec", "Certutil"], persistence: ["Registry", "Scheduled tasks"], c2: ["Tor hidden service for negotiations", "Custom C2"], exfil: ["Mega.nz", "FTP servers", "Custom tools"] },
    iocs: { domains: [], ips: [], hashes: [] },
    mitre_groups_id: "", references: []
  },
  {
    name: "DarkSide", aliases: ["Carbon Spider (operator/UNC2465)"],
    attribution: "Russia-based", type: "cybercrime", active_since: "2020", status: "disbanded",
    targets: { industries: ["Energy", "Manufacturing", "Finance", "Legal", "Technology"], countries: ["Global (excluded CIS, Georgia, Ukraine)"] },
    known_tools: ["DarkSide ransomware", "Cobalt Strike", "SystemBC"],
    notable_operations: [
      { name: "Colonial Pipeline Attack", date: "2021", description: "Encrypted Colonial Pipeline systems, operator shut down 5,500-mile fuel pipeline supplying 45% of US East Coast fuel", impact: "Gas shortages across Eastern US, Colonial paid $4.4M ransom (DOJ later recovered $2.3M), led to executive order on cybersecurity" }
    ],
    ttps: { initial_access: ["Compromised VPN credentials (no MFA)", "Initial access brokers"], execution: ["PowerShell", "PsExec", "Cobalt Strike"], persistence: ["Service creation", "Registry"], c2: ["Cobalt Strike", "Tor"], exfil: ["Mega.nz", "PrivatLab cloud"] },
    iocs: { domains: [], ips: [], hashes: [] },
    mitre_groups_id: "", references: []
  },
  {
    name: "Cl0p", aliases: ["TA505 (affiliated)", "Lace Tempest", "FIN11 (overlap)"],
    attribution: "Russia/Ukraine-based", type: "cybercrime", active_since: "2019", status: "active",
    targets: { industries: ["Government", "Healthcare", "Finance", "Education", "Technology", "Retail"], countries: ["Global"] },
    known_tools: ["Cl0p ransomware", "TrueBot", "FlawedAmmyy", "DEWMODE", "LEMURLOOT"],
    notable_operations: [
      { name: "MOVEit Transfer Campaign", date: "2023", description: "Mass exploitation of CVE-2023-34362 in MOVEit Transfer file sharing software, exfiltrated data from 2,500+ organizations", impact: "Affected 77+ million individuals, victims include Shell, BBC, US government agencies, largest data theft campaign ever" },
      { name: "GoAnywhere MFT Campaign", date: "2023", description: "Exploited CVE-2023-0669 in Fortra GoAnywhere MFT, compromised 130+ organizations", impact: "Major data theft from healthcare, finance, and government organizations" },
      { name: "Accellion FTA Campaign", date: "2020-2021", description: "Exploited zero-days in Accellion File Transfer Appliance, hit universities, telecoms, retailers", impact: "Pioneered the mass file-transfer exploitation model later repeated with GoAnywhere and MOVEit" }
    ],
    ttps: { initial_access: ["Zero-day exploitation of file transfer appliances (primary method)", "SQL injection in web applications", "Phishing"], execution: ["Web shells", "Custom .NET tools", "PowerShell"], persistence: ["Web shells on compromised file transfer servers"], c2: ["Web shells", "Tor for leak site"], exfil: ["Data exfiltration BEFORE encryption (or exfil-only, no encryption)"] },
    iocs: { domains: [], ips: [], hashes: [] },
    mitre_groups_id: "", references: []
  },
  {
    name: "Lapsus$", aliases: ["DEV-0537", "Strawberry Tempest"],
    attribution: "UK/Brazil-based (teenagers)", type: "cybercrime", active_since: "2021", status: "disrupted",
    targets: { industries: ["Technology", "Gaming", "Telecommunications", "Government"], countries: ["Global"] },
    known_tools: ["Social engineering", "SIM swapping", "MFA fatigue bombing", "Insider recruitment (via Telegram)"],
    notable_operations: [
      { name: "NVIDIA Breach", date: "2022", description: "Stole 1TB of data including proprietary GPU designs, code signing certificates, employee credentials", impact: "Leaked NVIDIA source code, stolen certificates used to sign malware" },
      { name: "Samsung Source Code Leak", date: "2022", description: "Leaked 190GB of Samsung source code including Galaxy device bootloader and TrustZone code", impact: "Exposed proprietary mobile security implementations" },
      { name: "Microsoft Bing/Cortana Leak", date: "2022", description: "Compromised Azure DevOps account, leaked partial source code for Bing, Cortana, and other Microsoft projects", impact: "37GB of Microsoft source code leaked" },
      { name: "Uber Breach", date: "2022", description: "18-year-old member compromised Uber via MFA fatigue bombing a contractor, gained access to Slack, HackerOne, cloud infrastructure", impact: "Full access to Uber internal systems, HackerOne vulnerability reports exposed" },
      { name: "Rockstar Games Breach", date: "2022", description: "Leaked 90 clips of in-development GTA VI footage", impact: "Massive leak of highly anticipated game, member (17-year-old from UK) later convicted" }
    ],
    ttps: { initial_access: ["SIM swapping for MFA bypass", "MFA fatigue/push bombing", "Social engineering (calling help desks)", "Recruiting insiders via Telegram", "Purchasing credentials from dark web"], execution: ["Living-off-the-land (admin tools, cloud consoles)"], persistence: ["Creating new accounts", "Adding themselves to privileged groups"], c2: ["Telegram group for coordination and leaks", "Direct access via VPN/RDP"], exfil: ["Telegram for leaking", "Direct download from cloud storage"] },
    iocs: { domains: [], ips: [], hashes: [] },
    mitre_groups_id: "", references: []
  },
  {
    name: "FIN7", aliases: ["Carbon Spider", "Sangria Tempest", "ELBRUS", "ITG14"],
    attribution: "Russia/Ukraine-based", type: "cybercrime", active_since: "2013", status: "active",
    targets: { industries: ["Retail", "Hospitality", "Restaurant", "Finance", "Technology"], countries: ["USA", "Europe", "Australia"] },
    known_tools: ["Carbanak", "GRIFFON", "BIRDDOG", "BOOSTWRITE", "JSSLoader", "POWERTRASH", "Lizar/Tirion", "BlackMatter (affiliated)", "DarkSide (affiliated)"],
    notable_operations: [
      { name: "Carbanak Banking Attacks", date: "2013-2018", description: "Stole over $1 billion from 100+ banks worldwide via SWIFT fraud and ATM cashouts", impact: "One of the most financially successful cybercrime groups ever" },
      { name: "Fake Pentesting Company", date: "2021-2022", description: "Created fake company 'Bastion Secure' to recruit unwitting penetration testers who would unknowingly deploy FIN7 malware", impact: "Novel recruitment model, hired real pen testers as unknowing accomplices" },
      { name: "USB Mailing Campaign", date: "2022", description: "Mailed BadUSB devices disguised as gift cards and COVID guidelines to US defense and transportation companies", impact: "Physical social engineering campaign targeting high-value sectors" }
    ],
    ttps: { initial_access: ["Spear-phishing (highly crafted)", "Physical USB mailing", "Fake job offers", "Supply chain"], execution: ["PowerShell", "JScript", "VBScript", "Custom malware loaders"], persistence: ["Scheduled tasks", "Registry", "Service creation"], c2: ["HTTP/HTTPS", "DNS over HTTPS", "Custom protocols"], exfil: ["POS skimming", "Database dumps", "Cloud upload"] },
    iocs: { domains: [], ips: [], hashes: [] },
    mitre_groups_id: "G0046", references: ["https://attack.mitre.org/groups/G0046/"]
  },
  {
    name: "Evil Corp", aliases: ["Indrik Spider", "Manatee Tempest", "UNC2165", "Dridex Gang"],
    attribution: "Russia (Maksim Yakubets, sanctioned by US Treasury)", type: "cybercrime", active_since: "2007", status: "active",
    targets: { industries: ["Finance", "Government", "Healthcare", "Technology"], countries: ["Global"] },
    known_tools: ["Dridex", "BitPaymer", "WastedLocker", "Hades", "PhoenixLocker", "PayloadBIN", "Macaw Locker", "LockBit (later affiliate)"],
    notable_operations: [
      { name: "Dridex Banking Trojan", date: "2014-ongoing", description: "Operated Dridex banking trojan botnet stealing hundreds of millions from bank accounts worldwide", impact: "Estimated $100M+ stolen, infected millions of computers" },
      { name: "Garmin WastedLocker Attack", date: "2020", description: "Encrypted Garmin systems with WastedLocker, Garmin reportedly paid $10M ransom", impact: "Garmin services offline for days, complicated by OFAC sanctions against Evil Corp" },
      { name: "Sanctions Evasion", date: "2020-ongoing", description: "Continuously rebrand ransomware to evade US Treasury OFAC sanctions, making it illegal for victims to pay them", impact: "Pioneered sanctions evasion through ransomware rebranding" }
    ],
    ttps: { initial_access: ["Dridex spam campaigns", "Drive-by downloads (SocGholish fake updates)", "Exploiting public-facing applications"], execution: ["PowerShell", "Cobalt Strike", "WMI"], persistence: ["Service creation", "Scheduled tasks"], c2: ["Cobalt Strike", "HTTP/HTTPS"], exfil: ["Archive and upload via cloud services"] },
    iocs: { domains: [], ips: [], hashes: [] },
    mitre_groups_id: "", references: []
  },
  {
    name: "Wizard Spider", aliases: ["Gold Blackburn", "Grim Spider", "UNC1878", "TrickBot Gang"],
    attribution: "Russia-based (Saint Petersburg)", type: "cybercrime", active_since: "2016", status: "disrupted",
    targets: { industries: ["Healthcare", "Government", "Education", "Finance", "Manufacturing"], countries: ["Global"] },
    known_tools: ["TrickBot", "BazarLoader", "Anchor", "Conti ransomware", "Ryuk ransomware", "Diavol"],
    notable_operations: [
      { name: "Ryuk Ransomware Campaign", date: "2018-2021", description: "Deployed Ryuk via TrickBot infections, targeting hospitals and critical infrastructure", impact: "Estimated $150M+ in ransom payments, repeatedly targeted hospitals during COVID-19" },
      { name: "Universal Health Services", date: "2020", description: "Ryuk attack on UHS, one of America's largest hospital chains with 400 facilities", impact: "Systems offline for weeks, estimated $67M financial impact, staff reverted to paper records" }
    ],
    ttps: { initial_access: ["TrickBot/BazarLoader phishing", "Emotet botnet distribution"], execution: ["PowerShell", "Cobalt Strike", "AdFind"], persistence: ["Service creation", "Scheduled tasks", "Registry"], c2: ["Cobalt Strike", "TrickBot C2 infrastructure"], exfil: ["Data staging", "Cloud services"] },
    iocs: { domains: [], ips: [], hashes: [] },
    mitre_groups_id: "G0102", references: ["https://attack.mitre.org/groups/G0102/"]
  },
  {
    name: "TA505", aliases: ["Hive0065", "Graceful Spider", "Gold Evergreen", "SectorJ04"],
    attribution: "Russia-based", type: "cybercrime", active_since: "2014", status: "active",
    targets: { industries: ["Finance", "Retail", "Healthcare", "Government", "Education"], countries: ["Global"] },
    known_tools: ["Dridex (initial distributor)", "Locky", "GlobeImposter", "Philadelphia", "FlawedAmmyy", "FlawedGrace", "ServHelper", "SDBbot", "Get2 loader", "TeslaGun"],
    notable_operations: [
      { name: "Locky Ransomware Distribution", date: "2016", description: "Distributed Locky ransomware via massive email campaigns, sending millions of spam emails daily", impact: "One of the most widespread ransomware campaigns, infected organizations in 100+ countries" },
      { name: "Cl0p Ransomware Operations", date: "2020-ongoing", description: "Affiliated with Cl0p ransomware operations, involved in mass exploitation campaigns", impact: "Part of the ecosystem that enabled MOVEit, GoAnywhere, Accellion campaigns" }
    ],
    ttps: { initial_access: ["Massive phishing campaigns (millions of emails)", "Malicious documents", "HTML smuggling"], execution: ["PowerShell", "Msiexec", "Rundll32"], persistence: ["Registry", "Scheduled tasks", "Startup folder"], c2: ["HTTP/HTTPS", "FlawedAmmyy RAT", "ServHelper"], exfil: ["FlawedAmmyy screen capture", "Cl0p data theft"] },
    iocs: { domains: [], ips: [], hashes: [] },
    mitre_groups_id: "G0092", references: ["https://attack.mitre.org/groups/G0092/"]
  },
  // --- More threat actors ---
  {
    name: "Hafnium", aliases: ["Silk Typhoon", "UNC2754"],
    attribution: "China (MSS-affiliated)", type: "state-sponsored", active_since: "2017", status: "active",
    targets: { industries: ["Defense", "Education", "Government", "NGOs", "Think Tanks", "Healthcare", "Legal"], countries: ["USA"] },
    known_tools: ["China Chopper webshell", "ASPXSPY", "Covenant", "Nishang", "PowerCat", "custom DLL loaders"],
    notable_operations: [
      { name: "Microsoft Exchange ProxyLogon", date: "2021", description: "Mass exploitation of four Exchange Server zero-days (ProxyLogon CVEs), compromised at least 30,000 US organizations", impact: "Global emergency patching effort, web shells deployed on tens of thousands of servers worldwide" }
    ],
    ttps: { initial_access: ["Zero-day exploitation of Exchange Server", "VPN exploitation"], execution: ["Web shells (China Chopper, ASPXSPY)", "PowerShell"], persistence: ["Web shells", "Scheduled tasks"], c2: ["HTTPS", "DNS tunneling via web shells"], exfil: ["Compressed archives (7-Zip, WinRAR)", "Cloud storage"] },
    iocs: { domains: [], ips: [], hashes: [] },
    mitre_groups_id: "G0125", references: ["https://attack.mitre.org/groups/G0125/"]
  },
  {
    name: "Volt Typhoon", aliases: ["Bronze Silhouette", "Vanguard Panda", "DEV-0391", "UNC3236", "Insidious Taurus"],
    attribution: "China (PLA)", type: "state-sponsored", active_since: "2021", status: "active",
    targets: { industries: ["Critical Infrastructure", "Communications", "Manufacturing", "Transportation", "Water", "Energy", "Government"], countries: ["USA", "Guam", "Pacific territories"] },
    known_tools: ["Living-off-the-land binaries (LOLBins)", "SOHO router botnets (KV-botnet)", "FRP (Fast Reverse Proxy)", "Impacket", "custom web shells"],
    notable_operations: [
      { name: "US Critical Infrastructure Pre-positioning", date: "2023-ongoing", description: "Embedded in US critical infrastructure networks for potential disruption during a Taiwan conflict, maintained access for 5+ years in some cases", impact: "CISA issued urgent advisory, described as China pre-positioning for destructive cyberattacks on US infrastructure" },
      { name: "KV-Botnet (SOHO Router)", date: "2022-2024", description: "Built botnet of hundreds of compromised SOHO routers and IoT devices to proxy traffic and hide origins", impact: "FBI disrupted botnet in January 2024, China rebuilt portions" }
    ],
    ttps: { initial_access: ["Exploiting public-facing appliances (Fortinet, Ivanti, NetScaler, Zoho)", "Compromised SOHO routers"], execution: ["Living-off-the-land (PowerShell, wmic, ntdsutil, netsh, cmd)", "No custom malware to avoid detection"], persistence: ["Valid accounts", "Web shells on network appliances", "Scheduled tasks"], c2: ["Compromised SOHO router proxies", "FRP tunneling", "Living-off-the-land tools"], exfil: ["NTDS.dit extraction", "Credential harvesting for future access", "Pre-positioning rather than immediate data theft"] },
    iocs: { domains: [], ips: [], hashes: [] },
    mitre_groups_id: "", references: ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a"]
  },
  {
    name: "Salt Typhoon", aliases: ["GhostEmperor", "FamousSparrow", "UNC2286"],
    attribution: "China", type: "state-sponsored", active_since: "2020", status: "active",
    targets: { industries: ["Telecommunications", "ISPs", "Government"], countries: ["USA", "Global"] },
    known_tools: ["GhostSparrow", "Custom kernel-mode rootkits", "Demodex rootkit"],
    notable_operations: [
      { name: "US Telecom Espionage", date: "2024", description: "Compromised AT&T, Verizon, T-Mobile, and Lumen Technologies, accessed lawful intercept/wiretap systems", impact: "Potentially accessed surveillance targets of US law enforcement, compromised communications of senior government officials including presidential campaign staff" }
    ],
    ttps: { initial_access: ["Exploiting internet-facing appliances at telecoms"], execution: ["Custom rootkits", "Living-off-the-land"], persistence: ["Kernel-mode rootkits", "Network appliance implants"], c2: ["Custom encrypted channels"], exfil: ["Access to call detail records and wiretap data"] },
    iocs: { domains: [], ips: [], hashes: [] },
    mitre_groups_id: "", references: []
  },
  {
    name: "Black Basta", aliases: ["Storm-0506"],
    attribution: "Russia-based (ex-Conti members)", type: "cybercrime", active_since: "2022", status: "active",
    targets: { industries: ["Manufacturing", "Technology", "Construction", "Healthcare", "Finance"], countries: ["USA", "Europe", "Australia", "Global"] },
    known_tools: ["Black Basta ransomware", "QakBot", "SystemBC", "Cobalt Strike", "Mimikatz"],
    notable_operations: [
      { name: "Rapid Rise", date: "2022", description: "Compromised 500+ organizations in first two years of operation, collected over $100M in ransoms", impact: "Became one of top 5 most active ransomware groups within months of launch" },
      { name: "Ascension Healthcare", date: "2024", description: "Attacked Ascension, one of the largest US healthcare systems with 140 hospitals", impact: "Diverted ambulances, delayed surgeries, staff reverted to paper records" }
    ],
    ttps: { initial_access: ["QakBot phishing", "Social engineering via Microsoft Teams", "Exploiting vulnerabilities (ConnectWise ScreenConnect)"], execution: ["PowerShell", "PsExec", "Cobalt Strike"], persistence: ["Service creation", "Scheduled tasks"], c2: ["Cobalt Strike", "SystemBC", "Tor"], exfil: ["Rclone to cloud", "Custom exfil tools"] },
    iocs: { domains: [], ips: [], hashes: [] },
    mitre_groups_id: "", references: []
  },
  {
    name: "Rhysida", aliases: ["Vice Society (rebranded)"],
    attribution: "Unknown", type: "cybercrime", active_since: "2023", status: "active",
    targets: { industries: ["Healthcare", "Education", "Government", "Manufacturing"], countries: ["Global"] },
    known_tools: ["Rhysida ransomware", "Cobalt Strike", "PsExec", "SystemBC"],
    notable_operations: [
      { name: "British Library Attack", date: "2023", description: "Encrypted British Library systems, demanded 20 BTC ransom, leaked 600GB of data", impact: "Library services disrupted for months, estimated £7M recovery cost" },
      { name: "Chilean Army", date: "2023", description: "Attacked Chilean Army, leaked internal documents and personnel data", impact: "Military data exposure, geopolitical implications" }
    ],
    ttps: { initial_access: ["Phishing", "Exploiting VPN without MFA", "Initial access brokers"], execution: ["Cobalt Strike", "PowerShell", "PsExec"], persistence: ["RDP access", "Service creation"], c2: ["Cobalt Strike", "Tor"], exfil: ["Cloud storage", "Custom tools"] },
    iocs: { domains: [], ips: [], hashes: [] },
    mitre_groups_id: "", references: []
  },
  {
    name: "Play", aliases: ["PlayCrypt", "Balloonfly"],
    attribution: "Unknown (suspected Russia-based)", type: "cybercrime", active_since: "2022", status: "active",
    targets: { industries: ["Government", "Healthcare", "Technology", "Manufacturing"], countries: ["USA", "Latin America", "Europe"] },
    known_tools: ["Play ransomware", "SystemBC", "Cobalt Strike", "AdFind", "Grixba (custom info-stealer)"],
    notable_operations: [
      { name: "City of Oakland", date: "2023", description: "Ransomware attack on City of Oakland, California, leaked 10GB of personal data", impact: "City declared state of emergency, services disrupted for weeks" },
      { name: "Rackspace Exchange Attack", date: "2022", description: "Exploited ProxyNotShell in Rackspace hosted Exchange, affected thousands of customers", impact: "Rackspace discontinued hosted Exchange service entirely" }
    ],
    ttps: { initial_access: ["Exploiting public-facing applications (FortiOS, Exchange)", "Valid credentials", "Exposed RDP"], execution: ["PowerShell", "PsExec", "WMI", "Cobalt Strike"], persistence: ["Scheduled tasks", "Valid accounts"], c2: ["Cobalt Strike", "SystemBC"], exfil: ["WinSCP", "WinRAR", "Grixba custom tool"] },
    iocs: { domains: [], ips: [], hashes: [] },
    mitre_groups_id: "", references: []
  },
  {
    name: "Anonymous", aliases: ["Anon"],
    attribution: "Decentralized (global)", type: "hacktivist", active_since: "2003", status: "active",
    targets: { industries: ["Government", "Religion (Scientology)", "Finance", "Law Enforcement", "Music/Film Industry"], countries: ["Global"] },
    known_tools: ["LOIC (Low Orbit Ion Cannon)", "HOIC", "Website defacement", "DDoS", "Doxing"],
    notable_operations: [
      { name: "Project Chanology", date: "2008", description: "Campaign against Church of Scientology including DDoS, prank calls, and protests", impact: "One of the first major Anonymous operations, established the group's public identity" },
      { name: "Operation Payback", date: "2010", description: "DDoS attacks against Visa, Mastercard, PayPal after they cut services to WikiLeaks", impact: "Demonstrated hacktivist retaliation capability against major financial institutions" },
      { name: "OpRussia", date: "2022", description: "DDoS and defacement campaigns against Russian government and media sites after Ukraine invasion", impact: "Hundreds of Russian government and corporate websites defaced or taken offline" }
    ],
    ttps: { initial_access: ["DDoS (volumetric)", "SQL injection", "Social engineering"], execution: ["LOIC/HOIC DDoS tools", "Web exploitation"], persistence: ["Not typically persistent — hit and run operations"], c2: ["IRC channels", "Discord", "Telegram", "Twitter for announcements"], exfil: ["Website data dumps", "Doxing publications"] },
    iocs: { domains: [], ips: [], hashes: [] },
    mitre_groups_id: "", references: []
  },
  {
    name: "LulzSec", aliases: ["Lulz Security"],
    attribution: "USA/UK-based (group of 6 hackers)", type: "hacktivist", active_since: "2011", status: "disbanded",
    targets: { industries: ["Gaming", "Government", "Media", "Entertainment", "Law Enforcement"], countries: ["USA", "UK"] },
    known_tools: ["SQL injection", "DDoS tools", "Custom scripts"],
    notable_operations: [
      { name: "Sony PSN Breach", date: "2011", description: "SQL injection attack on Sony's systems, leaked data of 77 million PlayStation Network users", impact: "PSN offline for 23 days, estimated $171M cost to Sony" },
      { name: "CIA Website DDoS", date: "2011", description: "Took CIA.gov offline with DDoS attack", impact: "Embarrassed US intelligence community" },
      { name: "PBS Hack", date: "2011", description: "Defaced PBS website with fake story claiming Tupac was alive in New Zealand", impact: "Demonstrated ability to manipulate major media outlets" }
    ],
    ttps: { initial_access: ["SQL injection (primary)", "DDoS"], execution: ["SQL injection for data extraction", "Web shell upload"], persistence: ["Not typically persistent"], c2: ["IRC (eventually infiltrated by FBI)"], exfil: ["Public paste sites", "Twitter announcements"] },
    iocs: { domains: [], ips: [], hashes: [] },
    mitre_groups_id: "", references: []
  },
  // Additional groups — shorter profiles
  { name: "Mustang Panda", aliases: ["Bronze President", "Stately Taurus", "RedDelta", "TEMP.Hex"], attribution: "China (MSS)", type: "state-sponsored", active_since: "2014", status: "active", targets: { industries: ["Government", "NGOs", "Think Tanks", "Telecommunications"], countries: ["Southeast Asia", "Europe", "USA", "Taiwan", "Mongolia"] }, known_tools: ["PlugX", "Korplug", "TONESHELL", "PUBLOAD"], notable_operations: [{ name: "European Diplomats Targeting", date: "2022-2023", description: "Targeted European diplomatic entities using USB-propagating PlugX malware", impact: "Compromised diplomatic communications across Europe" }], ttps: { initial_access: ["Spear-phishing", "USB propagation"], execution: ["DLL side-loading", "PlugX"], persistence: ["Registry", "Startup"], c2: ["HTTP/HTTPS", "PlugX C2"], exfil: ["PlugX file collection"] }, iocs: { domains: [], ips: [], hashes: [] }, mitre_groups_id: "G0129", references: ["https://attack.mitre.org/groups/G0129/"] },
  { name: "Patchwork", aliases: ["Dropping Elephant", "Monsoon", "Chinastrats", "Quilted Tiger"], attribution: "India", type: "state-sponsored", active_since: "2015", status: "active", targets: { industries: ["Government", "Military", "Diplomacy", "Think Tanks"], countries: ["Pakistan", "China", "Bangladesh", "Sri Lanka"] }, known_tools: ["BADNEWS", "Ragnatela", "QuasarRAT", "EyeShell"], notable_operations: [{ name: "Self-infection Incident", date: "2022", description: "Accidentally infected their own systems with their RAT, exposing their infrastructure to researchers", impact: "Revealed operator details and C2 infrastructure" }], ttps: { initial_access: ["Spear-phishing"], execution: ["RTF exploits", "DLL side-loading"], persistence: ["Registry", "Scheduled tasks"], c2: ["HTTP/HTTPS"], exfil: ["Keylogging", "Screenshot capture"] }, iocs: { domains: [], ips: [], hashes: [] }, mitre_groups_id: "G0040", references: ["https://attack.mitre.org/groups/G0040/"] },
  { name: "SideWinder", aliases: ["Rattlesnake", "T-APT-04", "Razor Tiger"], attribution: "India", type: "state-sponsored", active_since: "2012", status: "active", targets: { industries: ["Government", "Military", "Diplomacy"], countries: ["Pakistan", "China", "Nepal", "Sri Lanka", "Bangladesh", "Afghanistan"] }, known_tools: ["Custom .NET implants", "StealerBot", "WarHawk"], notable_operations: [{ name: "Pakistan Military Targeting", date: "2019-ongoing", description: "Persistent campaigns against Pakistani military and government using decoy military-themed documents", impact: "One of the most active India-attributed APTs targeting Pakistan" }], ttps: { initial_access: ["Spear-phishing with military-themed lures"], execution: ["DLL side-loading", ".NET malware", "JavaScript"], persistence: ["Registry", "Startup"], c2: ["HTTPS"], exfil: ["Custom data collection"] }, iocs: { domains: [], ips: [], hashes: [] }, mitre_groups_id: "G0121", references: ["https://attack.mitre.org/groups/G0121/"] },
  { name: "Andariel", aliases: ["Silent Chollima", "Onyx Sleet", "Stonefly", "APT45"], attribution: "North Korea (RGB Bureau 121)", type: "state-sponsored", active_since: "2015", status: "active", targets: { industries: ["Defense", "Aerospace", "Nuclear", "Energy", "Healthcare", "Finance"], countries: ["South Korea", "USA", "Japan", "India"] }, known_tools: ["Maui ransomware", "DTrack", "TigerRAT", "EarlyRAT", "NukeSped"], notable_operations: [{ name: "US Healthcare Ransomware", date: "2022", description: "Deployed Maui ransomware against US healthcare organizations, DOJ recovered $500K in ransom", impact: "Targeted hospitals for revenue generation, indictment issued by DOJ" }], ttps: { initial_access: ["Exploiting Log4Shell, GoAnywhere, MOVEit"], execution: ["Custom RATs", "PowerShell"], persistence: ["Web shells", "Scheduled tasks"], c2: ["HTTP/HTTPS", "Custom protocols"], exfil: ["Data theft + ransomware (dual-purpose)"] }, iocs: { domains: [], ips: [], hashes: [] }, mitre_groups_id: "", references: [] },
  { name: "Akira", aliases: [], attribution: "Unknown", type: "cybercrime", active_since: "2023", status: "active", targets: { industries: ["Education", "Finance", "Healthcare", "Manufacturing", "Technology"], countries: ["USA", "Europe", "Australia"] }, known_tools: ["Akira ransomware (Windows + Linux/ESXi)", "Megazord variant"], notable_operations: [{ name: "Stanford University", date: "2023", description: "Attacked Stanford, exfiltrated 430GB of data", impact: "Personal data of 27,000 individuals exposed" }], ttps: { initial_access: ["Exploiting VPN without MFA (Cisco AnyConnect)", "Compromised credentials"], execution: ["PowerShell", "RDP", "AnyDesk"], persistence: ["Valid accounts", "VPN access"], c2: ["Cobalt Strike", "AnyDesk"], exfil: ["WinSCP", "FileZilla", "Rclone"] }, iocs: { domains: [], ips: [], hashes: [] }, mitre_groups_id: "", references: [] },
  { name: "8Base", aliases: [], attribution: "Unknown", type: "cybercrime", active_since: "2022", status: "active", targets: { industries: ["Professional Services", "Manufacturing", "Construction", "Healthcare"], countries: ["USA", "Brazil", "Europe"] }, known_tools: ["Phobos ransomware (customized)", "SmokeLoader", "SystemBC"], notable_operations: [{ name: "SMB Mass Targeting", date: "2023", description: "Rapidly became one of the most active ransomware groups by targeting small and medium businesses", impact: "Hundreds of SMBs compromised, many unable to recover" }], ttps: { initial_access: ["Phishing", "Exploiting RDP"], execution: ["SmokeLoader", "Phobos"], persistence: ["Registry", "Startup"], c2: ["SystemBC"], exfil: ["Custom tools"] }, iocs: { domains: [], ips: [], hashes: [] }, mitre_groups_id: "", references: [] },
  { name: "Medusa", aliases: ["MedusaLocker (different from Medusa ransomware)"], attribution: "Unknown", type: "cybercrime", active_since: "2023", status: "active", targets: { industries: ["Education", "Healthcare", "Technology", "Manufacturing"], countries: ["Global"] }, known_tools: ["Medusa ransomware", "Cobalt Strike", "PDQ Deploy"], notable_operations: [{ name: "Minneapolis Public Schools", date: "2023", description: "Attacked Minneapolis school district, leaked student psychiatric records and abuse reports", impact: "Highly sensitive student data exposed, $1M ransom demanded" }], ttps: { initial_access: ["Exploiting public-facing applications", "Initial access brokers"], execution: ["PowerShell", "PsExec", "PDQ Deploy"], persistence: ["Valid accounts", "Web shells"], c2: ["Cobalt Strike"], exfil: ["Cloud storage", "Tor leak site"] }, iocs: { domains: [], ips: [], hashes: [] }, mitre_groups_id: "", references: [] },
  { name: "Qilin", aliases: ["Agenda"], attribution: "Russia-based", type: "cybercrime", active_since: "2022", status: "active", targets: { industries: ["Healthcare", "Government", "Manufacturing", "Technology"], countries: ["Global"] }, known_tools: ["Qilin ransomware (Rust/Go, cross-platform)", "Cobalt Strike"], notable_operations: [{ name: "Synnovis (NHS Pathology)", date: "2024", description: "Attacked Synnovis, NHS pathology services provider in London, disrupted blood testing across multiple hospitals", impact: "Over 10,000 appointments and procedures delayed, critical blood supply disruption" }], ttps: { initial_access: ["Exploiting VPN credentials", "Initial access brokers"], execution: ["Rust/Go ransomware", "PsExec"], persistence: ["Valid accounts"], c2: ["Tor"], exfil: ["Data theft before encryption"] }, iocs: { domains: [], ips: [], hashes: [] }, mitre_groups_id: "", references: [] },
  { name: "BianLian", aliases: [], attribution: "Unknown", type: "cybercrime", active_since: "2022", status: "active", targets: { industries: ["Healthcare", "Education", "Government", "Professional Services", "Manufacturing"], countries: ["USA", "Australia", "Europe"] }, known_tools: ["BianLian ransomware (Go-based)", "Cobalt Strike", "RMM tools (AnyDesk, TeamViewer)"], notable_operations: [{ name: "Shift to Exfiltration-Only", date: "2023", description: "After free decryptor was released by Avast, shifted entirely to data theft and extortion without encrypting files", impact: "Pioneered the 'extortion-only' model that other groups later adopted" }], ttps: { initial_access: ["Exploiting ProxyShell", "Compromised RDP credentials", "Initial access brokers"], execution: ["PowerShell", "PsExec", "Go-based tools"], persistence: ["Valid accounts", "RMM tools"], c2: ["Cobalt Strike", "AnyDesk", "Ngrok tunnels"], exfil: ["Rclone", "Mega.nz", "Custom Go exfil tool"] }, iocs: { domains: [], ips: [], hashes: [] }, mitre_groups_id: "", references: [] },
  { name: "INC Ransom", aliases: ["INC"], attribution: "Unknown", type: "cybercrime", active_since: "2023", status: "active", targets: { industries: ["Healthcare", "Education", "Government", "Technology"], countries: ["USA", "Europe"] }, known_tools: ["INC ransomware", "Cobalt Strike", "MegaSync"], notable_operations: [{ name: "NHS Scotland", date: "2024", description: "Attacked NHS Dumfries and Galloway, leaked 3TB of patient data", impact: "Highly sensitive medical records exposed" }], ttps: { initial_access: ["Exploiting Citrix Bleed (CVE-2023-4966)", "Spear-phishing"], execution: ["Cobalt Strike", "PowerShell"], persistence: ["Valid accounts"], c2: ["Cobalt Strike"], exfil: ["MegaSync", "Custom tools"] }, iocs: { domains: [], ips: [], hashes: [] }, mitre_groups_id: "", references: [] },
  { name: "Hunters International", aliases: ["Hive rebrand"], attribution: "Unknown (suspected former Hive members)", type: "cybercrime", active_since: "2023", status: "active", targets: { industries: ["Healthcare", "Manufacturing", "Government", "Education"], countries: ["Global"] }, known_tools: ["Hunters International ransomware (based on Hive source code)", "Cobalt Strike"], notable_operations: [{ name: "US Marshals Service", date: "2023", description: "Claimed attack on US Marshals Service (disputed)", impact: "High-profile government target claim" }], ttps: { initial_access: ["Initial access brokers", "Exploiting vulnerabilities"], execution: ["Rust-based ransomware", "PsExec"], persistence: ["Valid accounts"], c2: ["Cobalt Strike", "Tor"], exfil: ["Data theft before encryption"] }, iocs: { domains: [], ips: [], hashes: [] }, mitre_groups_id: "", references: [] },
  { name: "Cactus", aliases: [], attribution: "Unknown", type: "cybercrime", active_since: "2023", status: "active", targets: { industries: ["Manufacturing", "Technology", "Professional Services"], countries: ["Global"] }, known_tools: ["Cactus ransomware (self-encrypting binary to evade AV)", "Cobalt Strike", "Chisel", "SoftPerfect Network Scanner"], notable_operations: [{ name: "Schneider Electric", date: "2024", description: "Attacked Schneider Electric's Sustainability Business division, stole terabytes of data", impact: "Major industrial control systems vendor compromised" }], ttps: { initial_access: ["Exploiting Fortinet VPN vulnerabilities", "Qlik Sense exploitation"], execution: ["Self-encrypting ransomware binary", "PsExec", "PowerShell"], persistence: ["SSH tunnels", "Scheduled tasks"], c2: ["Cobalt Strike", "Chisel tunneling"], exfil: ["Rclone", "Cloud storage"] }, iocs: { domains: [], ips: [], hashes: [] }, mitre_groups_id: "", references: [] },
  { name: "Midnight Blizzard Phishing Ops", aliases: ["Star Blizzard", "SEABORGIUM", "Callisto", "COLDRIVER", "TAG-53"], attribution: "Russia (FSB Center 18)", type: "state-sponsored", active_since: "2017", status: "active", targets: { industries: ["Government", "Defense", "NGOs", "Think Tanks", "Academia", "Journalism"], countries: ["USA", "UK", "Europe", "NATO members"] }, known_tools: ["EvilGinx (credential phishing proxy)", "Custom phishing kits", "Proton Drive for exfil"], notable_operations: [{ name: "UK Parliament Credential Harvesting", date: "2023", description: "Targeted UK MPs, civil servants, journalists with highly convincing spear-phishing", impact: "UK attributed and sanctioned Russian FSB officers, formal diplomatic protest" }], ttps: { initial_access: ["Highly targeted spear-phishing with long-term social engineering rapport building", "Impersonation via fake email accounts"], execution: ["Credential theft (primary objective)", "OAuth token theft"], persistence: ["Email forwarding rules on compromised accounts"], c2: ["Proton Mail for communications", "Cloud storage"], exfil: ["Email access via stolen credentials", "Proton Drive"] }, iocs: { domains: [], ips: [], hashes: [] }, mitre_groups_id: "", references: [] },
  { name: "Ember Bear", aliases: ["UNC2589", "Cadet Blizzard", "DEV-0586"], attribution: "Russia (GRU)", type: "state-sponsored", active_since: "2021", status: "active", targets: { industries: ["Government", "IT", "Emergency Services"], countries: ["Ukraine", "Europe"] }, known_tools: ["WhisperGate (destructive wiper)", "custom web shells", "tunneling tools"], notable_operations: [{ name: "WhisperGate Ukraine", date: "2022-01", description: "Destructive wiper attack on Ukrainian government websites one month before Russia's invasion", impact: "Defaced government sites with fake ransomware message, wiped systems" }], ttps: { initial_access: ["Exploitation of public-facing apps (Confluence, Exchange)"], execution: ["Destructive wipers", "Web shells"], persistence: ["Web shells", "Tunneling"], c2: ["Web shells", "Ngrok"], exfil: ["Data theft secondary to destruction"] }, iocs: { domains: [], ips: [], hashes: [] }, mitre_groups_id: "", references: [] },
  { name: "Earth Lusca", aliases: ["TAG-22", "Charcoal Typhoon", "CHROMIUM"], attribution: "China", type: "state-sponsored", active_since: "2020", status: "active", targets: { industries: ["Government", "Technology", "Telecommunications", "Media", "Gambling"], countries: ["Southeast Asia", "Central Asia", "USA", "France", "Australia"] }, known_tools: ["ShadowPad", "Winnti", "Cobalt Strike", "SprySOCKS (Linux backdoor)"], notable_operations: [{ name: "Global Telecom Espionage", date: "2022-2023", description: "Targeted telecom and IT companies across Asia using ShadowPad and SprySOCKS", impact: "Espionage access to telecommunications infrastructure" }], ttps: { initial_access: ["Spear-phishing", "Watering hole", "Exploiting ProxyShell/Log4j"], execution: ["Cobalt Strike", "ShadowPad", "Custom loaders"], persistence: ["Web shells", "Scheduled tasks", "Registry"], c2: ["Cobalt Strike", "ShadowPad C2", "DNS tunneling"], exfil: ["Archive and upload"] }, iocs: { domains: [], ips: [], hashes: [] }, mitre_groups_id: "", references: [] },
  { name: "ChamelGang", aliases: ["CamoFei"], attribution: "China (suspected)", type: "state-sponsored", active_since: "2021", status: "active", targets: { industries: ["Government", "Aviation", "Energy", "Critical Infrastructure"], countries: ["Russia", "India", "Japan", "Taiwan", "USA"] }, known_tools: ["ChamelDoH (DNS-over-HTTPS backdoor)", "BeaconLoader", "DoorMe webshell"], notable_operations: [{ name: "Aviation and Energy Targeting", date: "2022-2023", description: "Targeted aviation and energy sectors using novel DNS-over-HTTPS backdoor for stealthy C2", impact: "Difficult-to-detect C2 channel via legitimate DoH services" }], ttps: { initial_access: ["Exploiting public-facing applications"], execution: ["Custom .NET implants", "DLL side-loading"], persistence: ["Web shells", "Scheduled tasks"], c2: ["DNS-over-HTTPS via Cloudflare/Google DoH"], exfil: ["Encrypted channels"] }, iocs: { domains: [], ips: [], hashes: [] }, mitre_groups_id: "", references: [] },
  { name: "Flax Typhoon", aliases: ["Ethereal Panda", "Storm-0919"], attribution: "China", type: "state-sponsored", active_since: "2021", status: "active", targets: { industries: ["Government", "Education", "Technology", "Manufacturing"], countries: ["Taiwan", "Southeast Asia", "USA", "Africa"] }, known_tools: ["SoftEther VPN", "China Chopper webshell", "LOLBins"], notable_operations: [{ name: "IoT Botnet", date: "2024", description: "Operated botnet of 260,000+ compromised SOHO routers, cameras, NAS devices worldwide", impact: "FBI disrupted botnet, China used it to proxy espionage traffic" }], ttps: { initial_access: ["Exploiting VPN appliances and public-facing servers"], execution: ["Living-off-the-land", "SoftEther VPN for persistence"], persistence: ["SoftEther VPN client", "RDP", "Legitimate remote access"], c2: ["SoftEther VPN tunnels", "IoT device botnets"], exfil: ["LOLBin-based data collection"] }, iocs: { domains: [], ips: [], hashes: [] }, mitre_groups_id: "", references: [] },
  { name: "Storm-0558", aliases: [], attribution: "China", type: "state-sponsored", active_since: "2023", status: "active", targets: { industries: ["Government", "Diplomacy"], countries: ["USA", "Europe"] }, known_tools: ["Forged Azure AD/Microsoft Account tokens using stolen MSA signing key"], notable_operations: [{ name: "Microsoft Cloud Email Breach", date: "2023", description: "Used stolen Microsoft Account signing key to forge authentication tokens, accessed email of 25 organizations including US State Department and Commerce Secretary", impact: "Exposed fundamental weaknesses in Microsoft cloud identity architecture, DHS Cyber Safety Review Board issued critical report" }], ttps: { initial_access: ["Forged authentication tokens using stolen signing key"], execution: ["Forged tokens for OWA/Outlook.com access"], persistence: ["Token-based access (no malware needed)"], c2: ["Direct API access via forged tokens"], exfil: ["Email download via Graph API/OWA"] }, iocs: { domains: [], ips: [], hashes: [] }, mitre_groups_id: "", references: [] },
  { name: "Tortoiseshell", aliases: ["Imperial Kitten", "Crimson Sandstorm", "TA456"], attribution: "Iran (IRGC-affiliated)", type: "state-sponsored", active_since: "2018", status: "active", targets: { industries: ["Defense", "Aerospace", "IT", "Veterans Affairs"], countries: ["USA", "Israel", "Saudi Arabia"] }, known_tools: ["IMAPLoader", "Custom backdoors", "Fake job/social media personas"], notable_operations: [{ name: "Facebook Persona Operation", date: "2019-2021", description: "Created fake 'Marcella Flores' persona on Facebook, spent years building relationship with aerospace defense employee before sending malware-laced 'diet survey'", impact: "Demonstrated extreme patience in social engineering, years-long operation for single target" }], ttps: { initial_access: ["Social engineering via fake personas", "Watering hole", "Phishing"], execution: ["Custom .NET malware", "VBA macros"], persistence: ["Scheduled tasks", "Registry"], c2: ["IMAP email-based C2", "HTTP/HTTPS"], exfil: ["Email-based exfil via IMAP"] }, iocs: { domains: [], ips: [], hashes: [] }, mitre_groups_id: "", references: [] },
  { name: "Moses Staff", aliases: ["Abraham's Ax", "Marigold Sandstorm"], attribution: "Iran", type: "state-sponsored", active_since: "2021", status: "active", targets: { industries: ["Government", "Defense", "Finance", "Technology"], countries: ["Israel", "Saudi Arabia", "UAE"] }, known_tools: ["StrifeWater RAT", "DCSrv (wiper based on DiskCryptor)", "PyDCrypt"], notable_operations: [{ name: "Israel Destructive Attacks", date: "2021-2022", description: "Multiple destructive attacks against Israeli companies, leaked stolen data on Telegram, no ransom demands", impact: "Purely destructive/influence operations with no financial motivation" }], ttps: { initial_access: ["Exploiting Exchange ProxyShell"], execution: ["Web shells", "Custom Python tools"], persistence: ["Web shells"], c2: ["HTTP/HTTPS", "Telegram for leaks"], exfil: ["Data theft for public leaking, followed by destruction"] }, iocs: { domains: [], ips: [], hashes: [] }, mitre_groups_id: "", references: [] },
  { name: "FIN12", aliases: ["Pistachio Tempest", "DEV-0237"], attribution: "Russia-based", type: "cybercrime", active_since: "2018", status: "active", targets: { industries: ["Healthcare (primary)", "Education", "Finance", "Government", "Technology"], countries: ["USA", "Europe", "Australia"] }, known_tools: ["Cobalt Strike", "SystemBC", "WEIRDLOOP", "Various ransomware (deploy on behalf of others — Ryuk, Conti, Hive, BlackCat, Royal)"], notable_operations: [{ name: "Healthcare Focus", date: "2020-ongoing", description: "Nearly 20% of observed victims are healthcare organizations, including during COVID-19 pandemic", impact: "One of the few groups that deliberately and consistently targets hospitals" }], ttps: { initial_access: ["BazarLoader/QakBot/IcedID initial infection (purchased access)", "Exploiting Citrix"], execution: ["Cobalt Strike", "PsExec", "WMI"], persistence: ["Cobalt Strike beacons", "SystemBC"], c2: ["Cobalt Strike"], exfil: ["Minimal exfil — focuses on rapid encryption (median 2 days from initial access to ransom deployment)"] }, iocs: { domains: [], ips: [], hashes: [] }, mitre_groups_id: "", references: [] },
  { name: "Machete", aliases: ["APT-C-43", "El Machete"], attribution: "Unknown (Spanish-speaking, possibly Venezuela)", type: "state-sponsored", active_since: "2010", status: "active", targets: { industries: ["Government", "Military", "Diplomacy", "Energy"], countries: ["Venezuela", "Ecuador", "Colombia", "Nicaragua", "Latin America"] }, known_tools: ["Machete backdoor (Python-based)", "Custom keyloggers", "Screenshot capture"], notable_operations: [{ name: "Latin American Military Espionage", date: "2014-ongoing", description: "Persistent cyber espionage against military and government institutions across Latin America", impact: "Stolen military documents, diplomatic cables, and intelligence from multiple countries" }], ttps: { initial_access: ["Spear-phishing with military-themed documents"], execution: ["Python-based malware", "Self-extracting archives"], persistence: ["Startup folder", "Registry run keys"], c2: ["FTP", "HTTP"], exfil: ["FTP upload of screenshots, keystrokes, documents"] }, iocs: { domains: [], ips: [], hashes: [] }, mitre_groups_id: "", references: [] },
];

// Lookup helpers
export function findActor(query) {
  const q = query.toLowerCase();
  return THREAT_ACTORS.find(a =>
    a.name.toLowerCase() === q ||
    a.aliases.some(al => al.toLowerCase() === q)
  ) || null;
}
export function searchActors(query) {
  const q = query.toLowerCase();
  return THREAT_ACTORS.filter(a =>
    a.name.toLowerCase().includes(q) ||
    a.aliases.some(al => al.toLowerCase().includes(q)) ||
    a.attribution.toLowerCase().includes(q) ||
    a.type.includes(q)
  );
}
export function actorsByType(type) { return THREAT_ACTORS.filter(a => a.type === type); }
export function actorsByCountry(country) { return THREAT_ACTORS.filter(a => a.attribution.toLowerCase().includes(country.toLowerCase())); }
export function activeActors() { return THREAT_ACTORS.filter(a => a.status === "active"); }
