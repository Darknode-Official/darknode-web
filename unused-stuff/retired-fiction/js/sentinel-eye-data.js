// Sentinel Eye data — extracted for faster page load
export var NATION_STATE_PROFILES = [
  {
    id: 'us', name: 'United States', flag: '[US]', tier: 1,
    cyberCommand: 'US Cyber Command / NSA TAO',
    aptGroups: ['Equation Group', 'TAO', 'Longhorn'],
    knownOps: ['Stuxnet (joint w/ Israel)', 'Olympic Games', 'PRISM', 'Tailored Access Operations', 'Shadow Brokers leak tools'],
    capabilities: { offense: 10, defense: 9, intel: 10 },
    primaryTargets: ['Russia', 'China', 'Iran', 'North Korea', 'Counter-terrorism']
  },
  {
    id: 'ru', name: 'Russia', flag: '[RU]', tier: 1,
    cyberCommand: 'GRU Unit 74455 / SVR / FSB Center 16',
    aptGroups: ['APT28 (Fancy Bear)', 'APT29 (Cozy Bear)', 'Sandworm', 'Turla', 'Gamaredon'],
    knownOps: ['NotPetya', 'SolarWinds', 'Ukraine grid attacks (2015/2016)', 'US election interference (2016)', 'Viasat hack (2022)', 'WhisperGate'],
    capabilities: { offense: 9, defense: 7, intel: 9 },
    primaryTargets: ['Ukraine', 'NATO members', 'US critical infrastructure', 'EU government networks', 'Energy sector']
  },
  {
    id: 'cn', name: 'China', flag: '[CN]', tier: 1,
    cyberCommand: 'PLA Strategic Support Force / MSS',
    aptGroups: ['APT41', 'Volt Typhoon', 'Salt Typhoon', 'APT1 (Unit 61398)', 'Hafnium', 'Winnti', 'Stone Panda'],
    knownOps: ['OPM breach (22M records)', 'Volt Typhoon critical infrastructure pre-positioning', 'Salt Typhoon telecom infiltration', 'IP theft campaigns', 'Microsoft Exchange exploitation'],
    capabilities: { offense: 9, defense: 8, intel: 10 },
    primaryTargets: ['US critical infrastructure', 'Taiwan', 'Defense industrial base', 'Semiconductor industry', 'Telecom providers']
  },
  {
    id: 'kp', name: 'North Korea', flag: '[KP]', tier: 2,
    cyberCommand: 'RGB Bureau 121',
    aptGroups: ['Lazarus Group', 'Kimsuky', 'Andariel', 'BlueNoroff', 'ScarCruft'],
    knownOps: ['Sony Pictures hack (2014)', 'WannaCry (2017)', 'Bangladesh Bank heist ($81M)', 'Crypto theft ($2B+ total)', 'Ronin Bridge ($625M)', 'Harmony Bridge ($100M)'],
    capabilities: { offense: 7, defense: 3, intel: 6 },
    primaryTargets: ['Cryptocurrency exchanges', 'Financial institutions', 'South Korea', 'Defense contractors', 'DeFi protocols']
  },
  {
    id: 'ir', name: 'Iran', flag: '[IR]', tier: 2,
    cyberCommand: 'IRGC Cyber Command / MOIS',
    aptGroups: ['APT33 (Elfin)', 'APT34 (OilRig)', 'APT35 (Charming Kitten)', 'MuddyWater', 'Moses Staff'],
    knownOps: ['Shamoon (Saudi Aramco)', 'Albanian government attacks (2022)', 'US dam access (2013)', 'Israeli water system attacks', 'Predatory Sparrow retaliation'],
    capabilities: { offense: 7, defense: 5, intel: 6 },
    primaryTargets: ['Israel', 'Saudi Arabia', 'US government', 'Oil & gas sector', 'Middle East rivals']
  },
  {
    id: 'il', name: 'Israel', flag: '[IL]', tier: 1,
    cyberCommand: 'Unit 8200 / Israel National Cyber Directorate',
    aptGroups: ['Unit 8200 Operations', 'Candiru', 'NSO Group (private)'],
    knownOps: ['Stuxnet (joint w/ US)', 'Duqu', 'Flame', 'Pegasus spyware platform', 'Iranian nuclear facility sabotage'],
    capabilities: { offense: 9, defense: 8, intel: 9 },
    primaryTargets: ['Iran', 'Hezbollah', 'Hamas', 'Regional adversaries', 'Counter-terrorism']
  },
  {
    id: 'gb', name: 'United Kingdom', flag: '[UK]', tier: 1,
    cyberCommand: 'GCHQ / National Cyber Security Centre (NCSC)',
    aptGroups: ['GCHQ Operations'],
    knownOps: ['Joint operations with NSA (Five Eyes)', 'Belgacom hack', 'Counter-ISIS cyber operations', 'Russian election interference disruption'],
    capabilities: { offense: 8, defense: 8, intel: 9 },
    primaryTargets: ['Russia', 'China', 'Counter-terrorism', 'Organized cybercrime']
  },
  {
    id: 'fr', name: 'France', flag: '[FR]', tier: 2,
    cyberCommand: 'ANSSI / DGSE',
    aptGroups: ['Animal Farm (attributed)'],
    knownOps: ['Babar malware', 'Dino/Casper operations', 'Counter-terrorism cyber ops in Sahel', 'Olympic Games 2024 cyber defense'],
    capabilities: { offense: 7, defense: 8, intel: 7 },
    primaryTargets: ['Counter-terrorism', 'Russian influence operations', 'Chinese espionage', 'Economic espionage defense']
  },
  {
    id: 'in', name: 'India', flag: '[IN]', tier: 2,
    cyberCommand: 'NTRO / Defence Cyber Agency',
    aptGroups: ['SideWinder', 'Patchwork', 'Dropping Elephant'],
    knownOps: ['SideWinder campaigns against Pakistan/China', 'Patchwork espionage operations', 'Cyber operations during border tensions'],
    capabilities: { offense: 6, defense: 5, intel: 6 },
    primaryTargets: ['Pakistan', 'China', 'Counter-terrorism', 'Regional intelligence']
  },
  {
    id: 'pk', name: 'Pakistan', flag: '[PK]', tier: 3,
    cyberCommand: 'ISI Cyber Wing / Pakistan Cyber Force',
    aptGroups: ['Transparent Tribe', 'SideCopy'],
    knownOps: ['Transparent Tribe campaigns against India', 'Operation C-Major', 'Kashmir-themed phishing operations'],
    capabilities: { offense: 4, defense: 3, intel: 5 },
    primaryTargets: ['India', 'Afghan government', 'Regional intelligence', 'Kashmir-related targets']
  },
  {
    id: 'tr', name: 'Turkey', flag: '[TR]', tier: 3,
    cyberCommand: 'MIT Cyber Operations',
    aptGroups: ['StrongPity', 'Sea Turtle'],
    knownOps: ['StrongPity watering hole attacks', 'Sea Turtle DNS hijacking campaign', 'Regional espionage operations'],
    capabilities: { offense: 5, defense: 4, intel: 5 },
    primaryTargets: ['Kurdish organizations', 'Regional rivals', 'EU diplomatic networks', 'Opposition figures']
  },
  {
    id: 'vn', name: 'Vietnam', flag: '[VN]', tier: 3,
    cyberCommand: 'Ministry of Public Security / APT32 Operations',
    aptGroups: ['APT32 (OceanLotus)', 'Lotus Blossom'],
    knownOps: ['OceanLotus espionage campaigns', 'COVID-19 research theft', 'South China Sea-related espionage', 'Targeting of foreign corporations in Vietnam'],
    capabilities: { offense: 5, defense: 3, intel: 5 },
    primaryTargets: ['ASEAN rivals', 'Foreign corporations in Vietnam', 'Dissident groups', 'South China Sea disputants']
  },
  {
    id: 'au', name: 'Australia', flag: '[AU]', tier: 2,
    cyberCommand: 'Australian Signals Directorate (ASD) / ACSC',
    aptGroups: ['Five Eyes partner operations'],
    knownOps: ['Joint counter-ISIS ops', 'Offensive cyber against ransomware gangs (2022)', 'South Pacific SIGINT', 'Operation Hurricane (2020)'],
    capabilities: { offense: 7, defense: 7, intel: 8 },
    primaryTargets: ['Counter-ransomware', 'South Pacific intelligence', 'China-linked espionage defense', 'Counter-terrorism']
  },
  {
    id: 'jp', name: 'Japan', flag: '[JP]', tier: 2,
    cyberCommand: 'National Center of Incident Readiness (NISC) / Self-Defense Forces Cyber Command',
    aptGroups: ['Defensive posture — no known offensive groups'],
    knownOps: ['Active cyber defense legislation (2024)', 'Counter-APT10 operations', 'Olympic Games 2020 cyber defense (40B attack attempts blocked)'],
    capabilities: { offense: 4, defense: 7, intel: 6 },
    primaryTargets: ['Defense against China/Russia/DPRK', 'Critical infrastructure protection', 'Supply chain security']
  },
  {
    id: 'kr', name: 'South Korea', flag: '[KR]', tier: 2,
    cyberCommand: 'National Intelligence Service (NIS) / Cyber Operations Command',
    aptGroups: ['DarkHotel (attributed)', 'Reaper (attributed)'],
    knownOps: ['Counter-DPRK cyber operations', 'DarkHotel hotel WiFi espionage', 'Cyber defense against 1.5M daily attacks from DPRK'],
    capabilities: { offense: 6, defense: 7, intel: 7 },
    primaryTargets: ['North Korea', 'Counter-espionage', 'Critical infrastructure defense', 'Cryptocurrency theft prevention']
  },
  {
    id: 'de', name: 'Germany', flag: '[DE]', tier: 2,
    cyberCommand: 'BND / BSI / Bundeswehr Cyber-Informationsraum (CIR)',
    aptGroups: ['BND cyber operations'],
    knownOps: ['Bundestag hack response (2015)', 'Joint Five Eyes adjacent SIGINT', 'Counter-APT28 operations', 'Operation Avalanche (botnet takedown)'],
    capabilities: { offense: 6, defense: 8, intel: 7 },
    primaryTargets: ['Counter-Russian espionage', 'Counter-Chinese IP theft', 'Critical infrastructure defense', 'Counter-terrorism']
  },
  {
    id: 'nl', name: 'Netherlands', flag: '[NL]', tier: 2,
    cyberCommand: 'AIVD / MIVD / Defence Cyber Command',
    aptGroups: ['MIVD operations'],
    knownOps: ['Caught APT29 red-handed at OPCW (2018)', 'GRU officer arrests at The Hague', 'Joint AIVD/NSA operations', 'Counter-Russian intelligence'],
    capabilities: { offense: 7, defense: 7, intel: 8 },
    primaryTargets: ['Russian intelligence services', 'Counter-espionage', 'Critical infrastructure', 'International organizations (OPCW, ICC)']
  },
  {
    id: 'sg', name: 'Singapore', flag: '[SG]', tier: 3,
    cyberCommand: 'Cyber Security Agency (CSA) / Digital and Intelligence Service (DIS)',
    aptGroups: ['Classified'],
    knownOps: ['SingHealth breach response (2018, 1.5M records)', 'ASEAN cyber security hub', 'Smart Nation cybersecurity framework'],
    capabilities: { offense: 5, defense: 8, intel: 6 },
    primaryTargets: ['Critical infrastructure defense', 'Financial sector protection', 'Counter-espionage', 'Smart city security']
  },
  {
    id: 'ee', name: 'Estonia', flag: '[EE]', tier: 3,
    cyberCommand: 'Estonian Information System Authority (RIA) / NATO CCDCOE',
    aptGroups: ['NATO cyber defense operations'],
    knownOps: ['Survived 2007 Russian cyber attacks', 'Hosts NATO Cooperative Cyber Defence Centre of Excellence', 'Locked Shields exercise organizer', 'E-governance cyber defense pioneer'],
    capabilities: { offense: 4, defense: 9, intel: 5 },
    primaryTargets: ['Defense against Russian cyber operations', 'E-governance protection', 'NATO cyber defense training', 'Critical infrastructure resilience']
  },
  {
    id: 'br', name: 'Brazil', flag: '[BR]', tier: 3,
    cyberCommand: 'Brazilian Army Cyber Defense Command (ComDCiber)',
    aptGroups: ['Blind Eagle (attributed to South America)', 'Machete'],
    knownOps: ['World Cup 2014 cyber defense', 'Olympics 2016 cyber defense', 'Counter-ransomware operations', 'Regional cyber exercises'],
    capabilities: { offense: 4, defense: 5, intel: 4 },
    primaryTargets: ['Cybercrime defense', 'Critical infrastructure protection', 'Financial sector defense', 'Counter-espionage']
  }
];

export var APT_GROUPS = [
  {
    id: 'apt28', name: 'APT28', aliases: ['Fancy Bear', 'Sofacy', 'Pawn Storm', 'Sednit', 'STRONTIUM'],
    nationState: 'Russia (GRU Unit 26165)', active: true,
    campaigns: [
      { name: 'Operation Pawn Storm', startDate: '2014-01', targets: 'NATO, EU governments, media', status: 'ongoing' },
      { name: 'DNC Breach', startDate: '2016-03', targets: 'US Democratic National Committee', status: 'completed' },
      { name: 'Bundestag Hack', startDate: '2015-04', targets: 'German Parliament', status: 'completed' },
      { name: 'EU Diplomatic Campaign 2026', startDate: '2026-06', targets: 'EU foreign ministries', status: 'active' }
    ],
    tools: ['X-Tunnel', 'Seduploader', 'Zebrocy', 'GoDownloader', 'X-Agent', 'Komplex'],
    mitreAttack: ['T1566.001', 'T1190', 'T1078', 'T1059.001', 'T1053.005', 'T1071.001', 'T1027', 'T1003'],
    infrastructure: { domains: 847, ips: 312, hostingPrefs: 'Eastern European bullet-proof hosting, compromised legitimate servers' },
    activityPattern: { peakHours: '06:00-14:00 UTC', peakDays: 'Mon-Fri' },
    currentTargets: ['EU diplomatic networks', 'NATO logistics systems', 'Defense contractors']
  },
  {
    id: 'apt29', name: 'APT29', aliases: ['Cozy Bear', 'The Dukes', 'NOBELIUM', 'Midnight Blizzard', 'YTTRIUM'],
    nationState: 'Russia (SVR)', active: true,
    campaigns: [
      { name: 'SolarWinds (SUNBURST)', startDate: '2020-03', targets: 'US government agencies, Fortune 500', status: 'completed' },
      { name: 'COVID-19 vaccine research theft', startDate: '2020-07', targets: 'Pharmaceutical companies', status: 'completed' },
      { name: 'Microsoft 365 campaign', startDate: '2023-11', targets: 'Microsoft corporate, US government email', status: 'completed' },
      { name: 'Diplomatic Phishing 2026', startDate: '2026-04', targets: 'EU/NATO diplomatic staff', status: 'active' }
    ],
    tools: ['SUNBURST', 'TEARDROP', 'Raindrop', 'WellMess', 'WellMail', 'EnvyScout', 'FoggyWeb', 'MagicWeb'],
    mitreAttack: ['T1195.002', 'T1199', 'T1078.004', 'T1556', 'T1550.001', 'T1059.001', 'T1071.001', 'T1027.002'],
    infrastructure: { domains: 1253, ips: 487, hostingPrefs: 'Compromised legitimate infrastructure, cloud services (Azure, AWS)' },
    activityPattern: { peakHours: '07:00-16:00 UTC', peakDays: 'Mon-Fri' },
    currentTargets: ['Government cloud environments', 'Diplomatic communications', 'Technology companies']
  },
  {
    id: 'sandworm', name: 'Sandworm', aliases: ['Voodoo Bear', 'IRIDIUM', 'Seashell Blizzard', 'TeleBots', 'BlackEnergy Group'],
    nationState: 'Russia (GRU Unit 74455)', active: true,
    campaigns: [
      { name: 'Ukraine Power Grid Attack', startDate: '2015-12', targets: 'Ukrainian power companies', status: 'completed' },
      { name: 'NotPetya', startDate: '2017-06', targets: 'Ukraine (global collateral)', status: 'completed' },
      { name: 'Olympic Destroyer', startDate: '2018-02', targets: 'PyeongChang Winter Olympics', status: 'completed' },
      { name: 'Industroyer2', startDate: '2022-04', targets: 'Ukrainian power grid', status: 'completed' },
      { name: 'Critical Infrastructure Campaign 2026', startDate: '2026-07', targets: 'NATO member SCADA/ICS', status: 'active' }
    ],
    tools: ['BlackEnergy', 'Industroyer', 'Industroyer2', 'NotPetya', 'Olympic Destroyer', 'CaddyWiper', 'ArguePatch'],
    mitreAttack: ['T1190', 'T1059', 'T1485', 'T1498', 'T1565', 'T1070', 'T1021', 'T1105'],
    infrastructure: { domains: 623, ips: 198, hostingPrefs: 'Compromised ISP infrastructure, Tor hidden services' },
    activityPattern: { peakHours: '05:00-15:00 UTC', peakDays: 'Mon-Sat' },
    currentTargets: ['NATO critical infrastructure', 'Ukrainian systems', 'Energy sector ICS/SCADA']
  },
  {
    id: 'turla', name: 'Turla', aliases: ['Snake', 'Venomous Bear', 'Uroburos', 'KRYPTON', 'Waterbug'],
    nationState: 'Russia (FSB Center 16)', active: true,
    campaigns: [
      { name: 'Snake malware campaign', startDate: '2003-01', targets: 'Government networks worldwide', status: 'disrupted' },
      { name: 'Satellite C2 operations', startDate: '2015-09', targets: 'Diplomatic targets via satellite hijacking', status: 'completed' },
      { name: 'Government Espionage 2026', startDate: '2026-02', targets: 'European government networks', status: 'active' }
    ],
    tools: ['Snake', 'Carbon', 'Kazuar', 'Crutch', 'TinyTurla', 'Capibar', 'DeliveryCheck'],
    mitreAttack: ['T1071.001', 'T1573', 'T1008', 'T1036', 'T1055', 'T1560', 'T1041', 'T1090.003'],
    infrastructure: { domains: 412, ips: 156, hostingPrefs: 'Hijacked satellite downlinks, compromised embassy networks' },
    activityPattern: { peakHours: '06:00-14:00 UTC', peakDays: 'Mon-Fri' },
    currentTargets: ['EU government networks', 'Diplomatic missions', 'Defense ministries']
  },
  {
    id: 'apt41', name: 'APT41', aliases: ['Double Dragon', 'BARIUM', 'Winnti Group', 'Wicked Panda'],
    nationState: 'China (MSS)', active: true,
    campaigns: [
      { name: 'Global supply chain attacks', startDate: '2017-01', targets: 'Software companies, gaming', status: 'ongoing' },
      { name: 'State government compromise', startDate: '2021-05', targets: 'US state governments', status: 'completed' },
      { name: 'Cloud Provider Campaign', startDate: '2026-03', targets: 'Major cloud service providers', status: 'active' }
    ],
    tools: ['ShadowPad', 'Winnti', 'POISONPLUG', 'CROSSWALK', 'LOWKEY', 'Cobalt Strike (modified)', 'DUSTPAN'],
    mitreAttack: ['T1195.002', 'T1059.001', 'T1053', 'T1078', 'T1190', 'T1003', 'T1071', 'T1560'],
    infrastructure: { domains: 1567, ips: 723, hostingPrefs: 'Chinese hosting providers, compromised cloud infrastructure' },
    activityPattern: { peakHours: '00:00-08:00 UTC', peakDays: 'Mon-Sat' },
    currentTargets: ['Cloud providers', 'Semiconductor companies', 'Healthcare data', 'Gaming companies']
  },
  {
    id: 'volt_typhoon', name: 'Volt Typhoon', aliases: ['BRONZE SILHOUETTE', 'Vanguard Panda', 'DEV-0391', 'Insidious Taurus'],
    nationState: 'China (PLA)', active: true,
    campaigns: [
      { name: 'US Critical Infrastructure Pre-positioning', startDate: '2021-06', targets: 'US power, water, telecom, ports', status: 'active' },
      { name: 'Guam military base targeting', startDate: '2023-01', targets: 'US Pacific military installations', status: 'active' },
      { name: 'Water Utility Infiltration', startDate: '2026-01', targets: 'US municipal water systems', status: 'active' }
    ],
    tools: ['Living-off-the-land binaries (LOLBins)', 'SOHO router botnets (KV-botnet)', 'Custom web shells', 'ntdsutil', 'netsh'],
    mitreAttack: ['T1078', 'T1133', 'T1059.001', 'T1003.003', 'T1018', 'T1046', 'T1090', 'T1572'],
    infrastructure: { domains: 234, ips: 1847, hostingPrefs: 'Compromised SOHO routers, ASUS/Cisco/Netgear edge devices' },
    activityPattern: { peakHours: '01:00-09:00 UTC', peakDays: 'Mon-Sun' },
    currentTargets: ['US water utilities', 'US power grid', 'US telecom backbone', 'Pacific military logistics']
  },
  {
    id: 'salt_typhoon', name: 'Salt Typhoon', aliases: ['GhostEmperor', 'FamousSparrow', 'UNC2286'],
    nationState: 'China (MSS)', active: true,
    campaigns: [
      { name: 'US Telecom Infiltration', startDate: '2023-06', targets: 'AT&T, Verizon, T-Mobile, Lumen', status: 'active' },
      { name: 'Lawful Intercept Compromise', startDate: '2024-01', targets: 'CALEA wiretap systems', status: 'active' },
      { name: 'Global Telecom Expansion', startDate: '2026-04', targets: 'European and Asian telecom providers', status: 'active' }
    ],
    tools: ['Demodex rootkit', 'GhostEmperor implant', 'Custom kernel drivers', 'Modified Mimikatz'],
    mitreAttack: ['T1190', 'T1014', 'T1078', 'T1557', 'T1040', 'T1565', 'T1573', 'T1048'],
    infrastructure: { domains: 178, ips: 423, hostingPrefs: 'Compromised telecom infrastructure, cloud VPS in multiple countries' },
    activityPattern: { peakHours: '00:00-10:00 UTC', peakDays: 'Mon-Sun' },
    currentTargets: ['Major US telecom providers', 'Lawful intercept systems', 'European 5G networks']
  },
  {
    id: 'apt1', name: 'APT1', aliases: ['Comment Crew', 'Comment Panda', 'PLA Unit 61398'],
    nationState: 'China (PLA Unit 61398)', active: true,
    campaigns: [
      { name: 'Economic espionage campaign', startDate: '2006-01', targets: '141+ organizations across 20 industries', status: 'completed' },
      { name: 'Industrial IP Theft 2026', startDate: '2026-01', targets: 'Advanced manufacturing, aerospace', status: 'active' }
    ],
    tools: ['WEBC2', 'BISCUIT', 'CALENDAR', 'GLOOXMAIL', 'GETMAIL', 'MANITSME'],
    mitreAttack: ['T1566.001', 'T1059', 'T1071.001', 'T1560', 'T1005', 'T1041', 'T1078', 'T1003'],
    infrastructure: { domains: 937, ips: 849, hostingPrefs: 'Shanghai-based infrastructure, compromised hosting worldwide' },
    activityPattern: { peakHours: '00:00-08:00 UTC', peakDays: 'Mon-Fri' },
    currentTargets: ['Aerospace industry', 'Advanced manufacturing', 'Energy technology']
  },
  {
    id: 'lazarus', name: 'Lazarus Group', aliases: ['HIDDEN COBRA', 'Zinc', 'Diamond Sleet', 'Labyrinth Chollima'],
    nationState: 'North Korea (RGB)', active: true,
    campaigns: [
      { name: 'Sony Pictures', startDate: '2014-11', targets: 'Sony Pictures Entertainment', status: 'completed' },
      { name: 'WannaCry', startDate: '2017-05', targets: 'Global (200K+ systems)', status: 'completed' },
      { name: 'Crypto heist campaign', startDate: '2018-01', targets: 'Cryptocurrency exchanges and DeFi', status: 'ongoing' },
      { name: 'DeFi Bridge Exploits 2026', startDate: '2026-05', targets: 'Cross-chain bridge protocols', status: 'active' }
    ],
    tools: ['FALLCHILL', 'Manuscrypt', 'HOPLIGHT', 'AppleJeus', 'TraderTraitor', 'BLINDINGCAN', 'DTrack'],
    mitreAttack: ['T1566.001', 'T1189', 'T1059', 'T1105', 'T1027', 'T1486', 'T1565', 'T1048'],
    infrastructure: { domains: 567, ips: 234, hostingPrefs: 'Compromised servers worldwide, mixing services for crypto' },
    activityPattern: { peakHours: '00:00-09:00 UTC', peakDays: 'Mon-Sat' },
    currentTargets: ['DeFi protocols', 'Cryptocurrency exchanges', 'Blockchain bridges', 'Crypto venture capital']
  },
  {
    id: 'kimsuky', name: 'Kimsuky', aliases: ['Velvet Chollima', 'Thallium', 'Black Banshee', 'Emerald Sleet'],
    nationState: 'North Korea (RGB)', active: true,
    campaigns: [
      { name: 'South Korean government espionage', startDate: '2012-01', targets: 'South Korean government, think tanks', status: 'ongoing' },
      { name: 'Defense Research Theft 2026', startDate: '2026-03', targets: 'South Korean defense researchers', status: 'active' }
    ],
    tools: ['BabyShark', 'AppleSeed', 'FlowerPower', 'GoldDragon', 'RandomQuery', 'ReconShark'],
    mitreAttack: ['T1566.001', 'T1204', 'T1059.005', 'T1547', 'T1003', 'T1005', 'T1041', 'T1071'],
    infrastructure: { domains: 389, ips: 145, hostingPrefs: 'Free hosting services, compromised Korean web servers' },
    activityPattern: { peakHours: '23:00-08:00 UTC', peakDays: 'Mon-Sat' },
    currentTargets: ['South Korean defense sector', 'Nuclear policy researchers', 'Defector organizations']
  },
  {
    id: 'andariel', name: 'Andariel', aliases: ['Silent Chollima', 'Stonefly', 'Onyx Sleet', 'Plutonium'],
    nationState: 'North Korea (RGB)', active: true,
    campaigns: [
      { name: 'South Korean defense targeting', startDate: '2015-01', targets: 'South Korean defense, aerospace', status: 'ongoing' },
      { name: 'Enterprise Ransomware 2026', startDate: '2026-06', targets: 'South Korean enterprises', status: 'active' }
    ],
    tools: ['Maui ransomware', 'DTrack', 'YamaBot', 'MagicRAT', 'EarlyRat', 'NukeSped'],
    mitreAttack: ['T1190', 'T1059', 'T1486', 'T1082', 'T1005', 'T1071', 'T1027', 'T1047'],
    infrastructure: { domains: 201, ips: 98, hostingPrefs: 'Compromised South Korean servers, VPS providers' },
    activityPattern: { peakHours: '23:00-07:00 UTC', peakDays: 'Mon-Fri' },
    currentTargets: ['South Korean defense industry', 'Healthcare organizations', 'Nuclear energy sector']
  },
  {
    id: 'apt33', name: 'APT33', aliases: ['Elfin', 'Magnallium', 'Refined Kitten', 'Peach Sandstorm'],
    nationState: 'Iran (IRGC)', active: true,
    campaigns: [
      { name: 'Shamoon operations', startDate: '2012-08', targets: 'Saudi Aramco, RasGas', status: 'completed' },
      { name: 'Gulf Oil Infrastructure 2026', startDate: '2026-05', targets: 'Gulf state oil and gas SCADA', status: 'active' }
    ],
    tools: ['Shamoon', 'StoneDrill', 'Tickler', 'POWERTON', 'TURNEDUP', 'ShapeShift'],
    mitreAttack: ['T1566.002', 'T1059', 'T1485', 'T1561', 'T1003', 'T1021', 'T1071', 'T1110'],
    infrastructure: { domains: 312, ips: 134, hostingPrefs: 'Iranian hosting, compromised Middle Eastern servers' },
    activityPattern: { peakHours: '04:30-12:30 UTC', peakDays: 'Sat-Thu' },
    currentTargets: ['Gulf state energy sector', 'Aviation industry', 'Petrochemical companies']
  },
  {
    id: 'apt34', name: 'APT34', aliases: ['OilRig', 'Helix Kitten', 'IRN2', 'Hazel Sandstorm'],
    nationState: 'Iran (MOIS)', active: true,
    campaigns: [
      { name: 'Middle East government espionage', startDate: '2014-01', targets: 'Gulf state governments', status: 'ongoing' },
      { name: 'Diplomatic Intelligence 2026', startDate: '2026-02', targets: 'Gulf diplomatic networks', status: 'active' }
    ],
    tools: ['BONDUPDATER', 'QUADAGENT', 'RDAT', 'Karkoff', 'DNSpionage', 'SideTwist', 'Menorah'],
    mitreAttack: ['T1566.001', 'T1059.005', 'T1071.004', 'T1053', 'T1078', 'T1560', 'T1041', 'T1003'],
    infrastructure: { domains: 445, ips: 167, hostingPrefs: 'DNS tunneling infrastructure, compromised web servers' },
    activityPattern: { peakHours: '04:30-12:30 UTC', peakDays: 'Sat-Thu' },
    currentTargets: ['Gulf state governments', 'Financial sector', 'Telecom companies']
  },
  {
    id: 'apt35', name: 'APT35', aliases: ['Charming Kitten', 'Phosphorus', 'Mint Sandstorm', 'NewsBeef', 'TA453'],
    nationState: 'Iran (IRGC)', active: true,
    campaigns: [
      { name: 'Academic credential harvesting', startDate: '2014-01', targets: 'US/UK universities, think tanks', status: 'ongoing' },
      { name: 'Israel Tech Espionage 2026', startDate: '2026-04', targets: 'Israeli tech and defense sector', status: 'active' }
    ],
    tools: ['HYPERSCRAPE', 'PowerLess', 'BellaCiao', 'MediaPl', 'KORG', 'CharmPower'],
    mitreAttack: ['T1566.001', 'T1204', 'T1059.001', 'T1078', 'T1003', 'T1005', 'T1041', 'T1071.001'],
    infrastructure: { domains: 523, ips: 198, hostingPrefs: 'Typosquatted domains, compromised university infrastructure' },
    activityPattern: { peakHours: '04:00-12:00 UTC', peakDays: 'Sat-Thu' },
    currentTargets: ['Israeli technology sector', 'Nuclear policy experts', 'Journalists and activists']
  },
  {
    id: 'muddywater', name: 'MuddyWater', aliases: ['Mercury', 'Mango Sandstorm', 'Static Kitten', 'TEMP.Zagros'],
    nationState: 'Iran (MOIS)', active: true,
    campaigns: [
      { name: 'Middle East government targeting', startDate: '2017-01', targets: 'Regional government agencies', status: 'ongoing' },
      { name: 'US Defense Phishing 2026', startDate: '2026-06', targets: 'US defense contractors', status: 'active' }
    ],
    tools: ['POWERSTATS', 'MuddyC2Go', 'PhonyC2', 'SHARPSTATS', 'Atera Agent (abused)', 'SimpleHelp (abused)'],
    mitreAttack: ['T1566.001', 'T1059.001', 'T1204', 'T1053', 'T1219', 'T1071', 'T1003', 'T1027'],
    infrastructure: { domains: 289, ips: 112, hostingPrefs: 'Abused legitimate remote access tools, cloud hosting' },
    activityPattern: { peakHours: '05:00-13:00 UTC', peakDays: 'Sat-Wed' },
    currentTargets: ['US defense contractors', 'Middle East governments', 'Telecom providers']
  },
  {
    id: 'unit8200', name: 'Unit 8200 Operations', aliases: ['Duqu developers', 'Flame operators'],
    nationState: 'Israel (Unit 8200)', active: true,
    campaigns: [
      { name: 'Stuxnet (joint w/ US)', startDate: '2007-01', targets: 'Iranian nuclear program', status: 'completed' },
      { name: 'Regional Counter-threat Ops', startDate: '2026-01', targets: 'Iranian and proxy threat infrastructure', status: 'active' }
    ],
    tools: ['Stuxnet', 'Duqu', 'Flame', 'Gauss', 'Custom zero-day exploits'],
    mitreAttack: ['T1190', 'T1091', 'T1195', 'T1059', 'T1027', 'T1014', 'T1573', 'T1485'],
    infrastructure: { domains: 156, ips: 89, hostingPrefs: 'Highly compartmentalized, zero-day dependent' },
    activityPattern: { peakHours: '05:00-15:00 UTC', peakDays: 'Sun-Thu' },
    currentTargets: ['Iranian nuclear program', 'Hezbollah networks', 'Regional threat actors']
  },
  {
    id: 'equation', name: 'Equation Group', aliases: ['EQGRP', 'Tilded Platform'],
    nationState: 'United States (NSA TAO)', active: true,
    campaigns: [
      { name: 'Global surveillance infrastructure', startDate: '2001-01', targets: 'Worldwide targets of interest', status: 'ongoing' },
      { name: 'Post-Shadow Brokers operations', startDate: '2017-06', targets: 'Nation-state targets', status: 'active' }
    ],
    tools: ['EquationDrug', 'GrayFish', 'DoubleFantasy', 'TripleFantasy', 'EQUATIONLASER', 'Fanny worm'],
    mitreAttack: ['T1195', 'T1542', 'T1014', 'T1027', 'T1573', 'T1071', 'T1059', 'T1005'],
    infrastructure: { domains: 300, ips: 500, hostingPrefs: 'Global relay network, firmware-level persistence' },
    activityPattern: { peakHours: '13:00-22:00 UTC', peakDays: 'Mon-Fri' },
    currentTargets: ['Nation-state intelligence targets', 'Counter-proliferation', 'Counter-terrorism']
  },
  {
    id: 'tao', name: 'TAO', aliases: ['Tailored Access Operations', 'NSA TAO'],
    nationState: 'United States (NSA)', active: true,
    campaigns: [
      { name: 'QUANTUM/FOXACID web exploitation', startDate: '2008-01', targets: 'Global intelligence targets', status: 'ongoing' },
      { name: 'Hunt Forward Operations 2026', startDate: '2026-01', targets: 'Allied network defense', status: 'active' }
    ],
    tools: ['QUANTUM', 'FOXACID', 'UNITEDRAKE', 'VALIDATOR', 'OLYMPUSFIRE', 'IRATEMONK'],
    mitreAttack: ['T1195.002', 'T1190', 'T1189', 'T1557', 'T1059', 'T1014', 'T1542', 'T1573'],
    infrastructure: { domains: 200, ips: 800, hostingPrefs: 'Classified infrastructure, global relay points' },
    activityPattern: { peakHours: '12:00-23:00 UTC', peakDays: 'Mon-Fri' },
    currentTargets: ['Counter-intelligence', 'Counter-proliferation', 'Hunt-forward mission support']
  },
  {
    id: 'oceanlotus', name: 'OceanLotus', aliases: ['APT32', 'Canvas Cyclone', 'SeaLotus', 'Cobalt Kitty'],
    nationState: 'Vietnam (MPS)', active: true,
    campaigns: [
      { name: 'Regional espionage', startDate: '2014-01', targets: 'ASEAN countries, dissidents', status: 'ongoing' },
      { name: 'ASEAN Diplomatic 2026', startDate: '2026-03', targets: 'ASEAN diplomatic communications', status: 'active' }
    ],
    tools: ['METALJACK', 'Kerrdown', 'Cobalt Strike (modified)', 'PhantomNet', 'Ratsnif'],
    mitreAttack: ['T1566.001', 'T1204', 'T1059', 'T1055', 'T1003', 'T1005', 'T1041', 'T1071'],
    infrastructure: { domains: 678, ips: 234, hostingPrefs: 'Southeast Asian hosting, compromised legitimate websites' },
    activityPattern: { peakHours: '01:00-09:00 UTC', peakDays: 'Mon-Fri' },
    currentTargets: ['Foreign auto manufacturers in Vietnam', 'ASEAN diplomatic staff', 'Dissident groups']
  },
  {
    id: 'sidewinder', name: 'SideWinder', aliases: ['Rattlesnake', 'T-APT-04', 'Razor Tiger'],
    nationState: 'India (NTRO)', active: true,
    campaigns: [
      { name: 'Pakistan military targeting', startDate: '2012-01', targets: 'Pakistan military and government', status: 'ongoing' },
      { name: 'Pakistan Defense Ops 2026', startDate: '2026-04', targets: 'Pakistani military networks', status: 'active' }
    ],
    tools: ['SideWinder implant', 'StealerBot', 'Custom .NET backdoors', 'HTA downloader'],
    mitreAttack: ['T1566.001', 'T1204', 'T1059.005', 'T1547', 'T1003', 'T1005', 'T1071', 'T1027'],
    infrastructure: { domains: 456, ips: 123, hostingPrefs: 'Indian hosting providers, typosquatted domains' },
    activityPattern: { peakHours: '03:00-11:00 UTC', peakDays: 'Mon-Fri' },
    currentTargets: ['Pakistani military', 'Chinese government agencies', 'Sri Lankan government']
  },
  {
    id: 'gamaredon', name: 'Gamaredon', aliases: ['Primitive Bear', 'Shuckworm', 'Actinium', 'Aqua Blizzard'],
    nationState: 'Russia (FSB Crimea)', active: true,
    campaigns: [
      { name: 'Ukraine government targeting', startDate: '2014-01', targets: 'Ukrainian government agencies', status: 'ongoing' },
      { name: 'Ukraine Persistent Ops 2026', startDate: '2026-01', targets: 'Ukrainian government and military', status: 'active' }
    ],
    tools: ['Pterodo', 'QuietSieve', 'ObfuBerry', 'GammaLoad', 'GammaSteel', 'Armageddon'],
    mitreAttack: ['T1566.001', 'T1204', 'T1059.005', 'T1547.001', 'T1003', 'T1071', 'T1005', 'T1041'],
    infrastructure: { domains: 2345, ips: 876, hostingPrefs: 'High-volume domain registration, Crimean/Russian hosting' },
    activityPattern: { peakHours: '05:00-15:00 UTC', peakDays: 'Mon-Fri' },
    currentTargets: ['Ukrainian government', 'Ukrainian military', 'Ukrainian critical infrastructure']
  },
  {
    id: 'hafnium', name: 'Hafnium', aliases: ['Silk Typhoon', 'HAFNIUM'],
    nationState: 'China (MSS)', active: true,
    campaigns: [
      { name: 'Microsoft Exchange exploitation', startDate: '2021-01', targets: 'Global Exchange servers (250K+)', status: 'completed' },
      { name: 'Zero-Day Exploitation 2026', startDate: '2026-05', targets: 'Enterprise collaboration platforms', status: 'active' }
    ],
    tools: ['China Chopper', 'ASPXSpy', 'Covenant', 'Nishang', 'PowerCat', 'Custom web shells'],
    mitreAttack: ['T1190', 'T1505.003', 'T1059.001', 'T1003', 'T1560', 'T1041', 'T1078', 'T1071'],
    infrastructure: { domains: 312, ips: 567, hostingPrefs: 'Leased VPS in United States, compromised servers' },
    activityPattern: { peakHours: '00:00-08:00 UTC', peakDays: 'Mon-Sat' },
    currentTargets: ['Enterprise collaboration platforms', 'US defense contractors', 'Research institutions']
  },
  {
    id: 'darkhotel', name: 'DarkHotel', aliases: ['Luder', 'Shadow Crane', 'Dubnium'],
    nationState: 'South Korea (NIS - attributed)', active: true,
    campaigns: [
      { name: 'Hotel WiFi exploitation', startDate: '2007-01', targets: 'Business executives in luxury hotels', status: 'ongoing' },
      { name: 'Executive Targeting 2026', startDate: '2026-02', targets: 'Foreign executives visiting Asia', status: 'active' }
    ],
    tools: ['DarkHotel implant', 'Inexsmar', 'Tapaoux', 'Pioneer', 'Karba'],
    mitreAttack: ['T1189', 'T1566.001', 'T1204', 'T1059', 'T1547', 'T1056', 'T1003', 'T1071'],
    infrastructure: { domains: 234, ips: 89, hostingPrefs: 'Compromised hotel networks, premium hosting' },
    activityPattern: { peakHours: '23:00-07:00 UTC', peakDays: 'Mon-Fri' },
    currentTargets: ['Business executives', 'Diplomats', 'Government officials traveling in Asia']
  },
  {
    id: 'winnti', name: 'Winnti', aliases: ['APT41 subset', 'Barium', 'Wicked Spider'],
    nationState: 'China (MSS/PLA)', active: true,
    campaigns: [
      { name: 'Gaming industry supply chain', startDate: '2012-01', targets: 'Online gaming companies', status: 'ongoing' },
      { name: 'Tech Supply Chain 2026', startDate: '2026-01', targets: 'Technology supply chains', status: 'active' }
    ],
    tools: ['Winnti RAT', 'ShadowPad', 'PlugX', 'CROSSWALK', 'Spyder'],
    mitreAttack: ['T1195.002', 'T1059', 'T1055', 'T1014', 'T1027', 'T1071', 'T1003', 'T1041'],
    infrastructure: { domains: 789, ips: 345, hostingPrefs: 'Chinese cloud, compromised gaming infrastructure' },
    activityPattern: { peakHours: '00:00-09:00 UTC', peakDays: 'Mon-Sat' },
    currentTargets: ['Gaming companies', 'Semiconductor firms', 'Cloud service providers']
  },
  {
    id: 'stonepanda', name: 'Stone Panda', aliases: ['APT10', 'MenuPass', 'Red Apollo', 'POTASSIUM'],
    nationState: 'China (MSS Tianjin)', active: true,
    campaigns: [
      { name: 'Cloud Hopper', startDate: '2016-01', targets: 'Managed service providers globally', status: 'completed' },
      { name: 'MSP Exploitation 2026', startDate: '2026-03', targets: 'Global managed service providers', status: 'active' }
    ],
    tools: ['QuasarRAT', 'PlugX', 'Poison Ivy', 'ChChes', 'RedLeaves', 'ANEL'],
    mitreAttack: ['T1199', 'T1078', 'T1059', 'T1053', 'T1003', 'T1041', 'T1071', 'T1560'],
    infrastructure: { domains: 567, ips: 234, hostingPrefs: 'Compromised MSP infrastructure, Chinese hosting' },
    activityPattern: { peakHours: '00:00-09:00 UTC', peakDays: 'Mon-Fri' },
    currentTargets: ['Managed service providers', 'Japanese defense sector', 'Pharmaceutical companies']
  },
  {
    id: 'machete', name: 'Machete', aliases: ['El Machete', 'APT-C-43'],
    nationState: 'Unknown (Latin America)', active: true,
    campaigns: [
      { name: 'Latin American military espionage', startDate: '2010-01', targets: 'Latin American military organizations', status: 'ongoing' },
      { name: 'Regional Military Intel 2026', startDate: '2026-04', targets: 'Colombian and Ecuadorian military', status: 'active' }
    ],
    tools: ['Machete malware', 'Pythy', 'Custom Python backdoors'],
    mitreAttack: ['T1566.001', 'T1204', 'T1059.006', 'T1005', 'T1113', 'T1056', 'T1041', 'T1071'],
    infrastructure: { domains: 123, ips: 56, hostingPrefs: 'Latin American hosting providers, free dynamic DNS' },
    activityPattern: { peakHours: '12:00-22:00 UTC', peakDays: 'Mon-Fri' },
    currentTargets: ['Latin American military', 'Diplomatic missions', 'Government agencies']
  },
  {
    id: 'darkside', name: 'DarkSide', aliases: ['Carbon Spider (overlap)'],
    nationState: 'Russia (Cybercriminal - state-tolerated)', active: false,
    campaigns: [
      { name: 'Colonial Pipeline attack', startDate: '2021-05', targets: 'Colonial Pipeline (US fuel supply)', status: 'completed' },
      { name: 'Ransomware-as-a-Service operations', startDate: '2020-08', targets: 'US and EU enterprises', status: 'shutdown' }
    ],
    tools: ['DarkSide ransomware', 'Custom data exfiltration tools', 'Cobalt Strike'],
    mitreAttack: ['T1486', 'T1078', 'T1059', 'T1560', 'T1041', 'T1071', 'T1027', 'T1003'],
    infrastructure: { domains: 89, ips: 45, hostingPrefs: 'Bullet-proof Russian hosting, Tor hidden services' },
    activityPattern: { peakHours: '08:00-18:00 UTC', peakDays: 'Mon-Fri' },
    currentTargets: []
  },
  {
    id: 'revil', name: 'REvil', aliases: ['Sodinokibi', 'Gold Southfield', 'Pinchy Spider'],
    nationState: 'Russia (Cybercriminal - state-tolerated)', active: false,
    campaigns: [
      { name: 'Kaseya supply chain attack', startDate: '2021-07', targets: '1,500+ organizations via Kaseya VSA', status: 'completed' },
      { name: 'JBS Foods attack', startDate: '2021-05', targets: 'JBS Foods ($11M ransom)', status: 'completed' }
    ],
    tools: ['REvil/Sodinokibi ransomware', 'Custom exfiltration tools', 'Cobalt Strike'],
    mitreAttack: ['T1486', 'T1195.002', 'T1059', 'T1078', 'T1560', 'T1041', 'T1071', 'T1490'],
    infrastructure: { domains: 123, ips: 67, hostingPrefs: 'Tor hidden services, Russian bullet-proof hosting' },
    activityPattern: { peakHours: '07:00-17:00 UTC', peakDays: 'Mon-Sat' },
    currentTargets: []
  },
  {
    id: 'conti', name: 'Conti', aliases: ['Wizard Spider', 'Gold Ulrick', 'DEV-0193'],
    nationState: 'Russia (Cybercriminal - state-tolerated)', active: false,
    campaigns: [
      { name: 'Global ransomware operations', startDate: '2020-05', targets: '1,000+ organizations globally', status: 'shutdown' },
      { name: 'Costa Rica government attack', startDate: '2022-04', targets: 'Costa Rica government', status: 'completed' }
    ],
    tools: ['Conti ransomware', 'BazarLoader', 'TrickBot', 'Anchor', 'Cobalt Strike'],
    mitreAttack: ['T1486', 'T1059', 'T1078', 'T1003', 'T1021', 'T1560', 'T1041', 'T1490'],
    infrastructure: { domains: 234, ips: 156, hostingPrefs: 'Russian hosting, Tor services' },
    activityPattern: { peakHours: '07:00-19:00 UTC', peakDays: 'Mon-Sat' },
    currentTargets: []
  },
  {
    id: 'lockbit', name: 'LockBit', aliases: ['Gold Mystic', 'LockBit Gang', 'Bitwise Spider'],
    nationState: 'Russia (Cybercriminal)', active: true,
    campaigns: [
      { name: 'LockBit 3.0 RaaS operations', startDate: '2022-06', targets: 'Global enterprises', status: 'disrupted' },
      { name: 'ICBC Financial Services attack', startDate: '2023-11', targets: 'ICBC', status: 'completed' },
      { name: 'LockBit 4.0 Resurgence', startDate: '2026-06', targets: 'Global manufacturing and healthcare', status: 'active' }
    ],
    tools: ['LockBit 3.0/4.0 ransomware', 'StealBit', 'Cobalt Strike', 'Metasploit'],
    mitreAttack: ['T1486', 'T1078', 'T1190', 'T1059', 'T1003', 'T1560', 'T1041', 'T1490'],
    infrastructure: { domains: 345, ips: 234, hostingPrefs: 'Tor hidden services, bullet-proof hosting globally' },
    activityPattern: { peakHours: '06:00-20:00 UTC', peakDays: 'Mon-Sun' },
    currentTargets: ['Healthcare organizations', 'Manufacturing sector', 'Financial services']
  },
  {
    id: 'blackcat', name: 'BlackCat', aliases: ['ALPHV', 'Sphynx', 'Noberus'],
    nationState: 'Russia (Cybercriminal)', active: true,
    campaigns: [
      { name: 'Change Healthcare attack', startDate: '2024-02', targets: 'Change Healthcare', status: 'completed' },
      { name: 'Healthcare Sector Campaign', startDate: '2026-07', targets: 'US hospital networks', status: 'active' }
    ],
    tools: ['ALPHV/BlackCat ransomware (Rust)', 'ExMatter', 'Eamfo', 'Cobalt Strike'],
    mitreAttack: ['T1486', 'T1078', 'T1059', 'T1190', 'T1003', 'T1560', 'T1041', 'T1490'],
    infrastructure: { domains: 189, ips: 123, hostingPrefs: 'Tor hidden services, compromised cloud accounts' },
    activityPattern: { peakHours: '08:00-22:00 UTC', peakDays: 'Mon-Sun' },
    currentTargets: ['US healthcare organizations', 'Financial services', 'Legal firms']
  },
  {
    id: 'clop', name: 'Cl0p', aliases: ['TA505 (affiliate)', 'FIN11 (overlap)', 'Lace Tempest'],
    nationState: 'Russia (Cybercriminal)', active: true,
    campaigns: [
      { name: 'MOVEit Transfer exploitation', startDate: '2023-05', targets: '2,500+ organizations', status: 'completed' },
      { name: 'File Transfer Zero-Day Campaign', startDate: '2026-08', targets: 'Enterprise file transfer solutions', status: 'active' }
    ],
    tools: ['Cl0p ransomware', 'DEWMODE', 'LEMURLOOT', 'TrueBot', 'FlawedAmmyy'],
    mitreAttack: ['T1190', 'T1486', 'T1059', 'T1505.003', 'T1078', 'T1560', 'T1041', 'T1071'],
    infrastructure: { domains: 267, ips: 178, hostingPrefs: 'Tor leak sites, exploited file transfer infrastructure' },
    activityPattern: { peakHours: '06:00-16:00 UTC', peakDays: 'Mon-Fri' },
    currentTargets: ['Enterprise file transfer platforms', 'Managed file transfer services']
  },
  {
    id: 'transparent_tribe', name: 'Transparent Tribe', aliases: ['APT36', 'Mythic Leopard', 'ProjectM'],
    nationState: 'Pakistan (ISI)', active: true,
    campaigns: [
      { name: 'Indian military targeting', startDate: '2013-01', targets: 'Indian military and government', status: 'ongoing' },
      { name: 'Indian Defense RAT Campaign', startDate: '2026-05', targets: 'Indian defense officials', status: 'active' }
    ],
    tools: ['CrimsonRAT', 'ObliqueRAT', 'Peppy RAT', 'Custom Android spyware'],
    mitreAttack: ['T1566.001', 'T1204', 'T1059', 'T1547', 'T1005', 'T1113', 'T1041', 'T1071'],
    infrastructure: { domains: 234, ips: 89, hostingPrefs: 'Pakistani hosting, free hosting services' },
    activityPattern: { peakHours: '03:00-11:00 UTC', peakDays: 'Mon-Sat' },
    currentTargets: ['Indian military personnel', 'Indian government officials']
  },
  {
    id: 'strongpity', name: 'StrongPity', aliases: ['Promethium', 'APT-C-41'],
    nationState: 'Turkey (MIT)', active: true,
    campaigns: [
      { name: 'Watering hole attacks', startDate: '2016-01', targets: 'Kurdish organizations', status: 'ongoing' },
      { name: 'Trojanized Apps Campaign', startDate: '2026-02', targets: 'Kurdish diaspora in Europe', status: 'active' }
    ],
    tools: ['StrongPity implant', 'Trojanized WinRAR/TrueCrypt', 'Custom Android spyware'],
    mitreAttack: ['T1189', 'T1195.002', 'T1204', 'T1059', 'T1547', 'T1005', 'T1056', 'T1041'],
    infrastructure: { domains: 156, ips: 67, hostingPrefs: 'Turkish and European hosting' },
    activityPattern: { peakHours: '06:00-16:00 UTC', peakDays: 'Mon-Fri' },
    currentTargets: ['Kurdish organizations', 'Political opposition']
  },
  {
    id: 'scarcruft', name: 'ScarCruft', aliases: ['APT37', 'Reaper', 'Group123', 'Ricochet Chollima'],
    nationState: 'North Korea (MSS)', active: true,
    campaigns: [
      { name: 'South Korean targeting', startDate: '2012-01', targets: 'South Korean government and military', status: 'ongoing' },
      { name: 'Defector Surveillance 2026', startDate: '2026-03', targets: 'North Korean defectors', status: 'active' }
    ],
    tools: ['RokRAT', 'BLUELIGHT', 'Goldbackdoor', 'Dolphin', 'M2RAT'],
    mitreAttack: ['T1566.001', 'T1204', 'T1059', 'T1547', 'T1113', 'T1005', 'T1041', 'T1071'],
    infrastructure: { domains: 178, ips: 67, hostingPrefs: 'Cloud services (pCloud, Yandex, OneDrive)' },
    activityPattern: { peakHours: '23:00-08:00 UTC', peakDays: 'Mon-Sat' },
    currentTargets: ['North Korean defectors', 'South Korean government', 'Journalists']
  },
  {
    id: 'bluenoroff', name: 'BlueNoroff', aliases: ['APT38', 'Stardust Chollima', 'Sapphire Sleet'],
    nationState: 'North Korea (RGB)', active: true,
    campaigns: [
      { name: 'Bangladesh Bank heist', startDate: '2016-02', targets: 'Bangladesh Bank ($81M)', status: 'completed' },
      { name: 'Crypto VC Social Engineering', startDate: '2026-06', targets: 'Crypto venture capital firms', status: 'active' }
    ],
    tools: ['SWIFT malware', 'TraderTraitor', 'AppleJeus', 'COPPERHEDGE', 'Custom macOS malware'],
    mitreAttack: ['T1566.001', 'T1204', 'T1059', 'T1078', 'T1005', 'T1565', 'T1041', 'T1071'],
    infrastructure: { domains: 345, ips: 112, hostingPrefs: 'Compromised fintech infrastructure' },
    activityPattern: { peakHours: '23:00-09:00 UTC', peakDays: 'Mon-Sat' },
    currentTargets: ['Cryptocurrency exchanges', 'DeFi platforms', 'Crypto venture capital']
  },
  {
    id: 'mosesstaff', name: 'Moses Staff', aliases: ['Abraham Ax (linked)', 'Marigold Sandstorm'],
    nationState: 'Iran (IRGC)', active: true,
    campaigns: [
      { name: 'Israeli organization attacks', startDate: '2021-09', targets: 'Israeli companies and government', status: 'ongoing' },
      { name: 'Wiper Operations 2026', startDate: '2026-04', targets: 'Israeli technology companies', status: 'active' }
    ],
    tools: ['StrifeWater RAT', 'DCSrv (wiper)', 'PyDCrypt', 'Custom disk encryptors'],
    mitreAttack: ['T1190', 'T1059', 'T1485', 'T1561', 'T1078', 'T1003', 'T1071', 'T1027'],
    infrastructure: { domains: 89, ips: 34, hostingPrefs: 'Compromised servers, Tor hidden services' },
    activityPattern: { peakHours: '04:00-12:00 UTC', peakDays: 'Sat-Thu' },
    currentTargets: ['Israeli technology sector', 'Israeli government agencies']
  },
  {
    id: 'apt32', name: 'APT32', aliases: ['OceanLotus', 'Canvas Cyclone', 'SeaLotus', 'APT-C-00'],
    nationState: 'Vietnam (Ministry of Public Security)', active: true,
    campaigns: [
      { name: 'ASEAN espionage campaign', startDate: '2017-01', targets: 'ASEAN governments, foreign companies in Vietnam', status: 'ongoing' },
      { name: 'COVID-19 intelligence gathering', startDate: '2020-04', targets: 'Chinese government agencies, Wuhan organizations', status: 'completed' },
      { name: 'Automotive sector targeting', startDate: '2019-02', targets: 'Toyota, Hyundai, BMW subsidiaries in Vietnam', status: 'completed' },
      { name: 'SE Asia media surveillance', startDate: '2026-01', targets: 'Journalists, activists, political dissidents', status: 'active' }
    ],
    tools: ['METALJACK', 'Denis', 'Cobalt Kitty tools', 'Kerrdown', 'KerrDown', 'Windshield', 'Komprogo'],
    mitreAttack: ['T1566.001', 'T1059.005', 'T1059.001', 'T1071.001', 'T1036', 'T1027', 'T1204.002', 'T1055'],
    infrastructure: { domains: 412, ips: 156, hostingPrefs: 'Cloud hosting (GCP, AWS, Azure), compromised WordPress sites' },
    activityPattern: { peakHours: '01:00-09:00 UTC', peakDays: 'Mon-Sat' },
    currentTargets: ['ASEAN government agencies', 'Foreign companies operating in Vietnam', 'Human rights activists']
  },
  {
    id: 'gamaredon', name: 'Gamaredon', aliases: ['Primitive Bear', 'Shuckworm', 'Actinium', 'Aqua Blizzard', 'Armageddon'],
    nationState: 'Russia (FSB, Crimea-based)', active: true,
    campaigns: [
      { name: 'Ukraine government targeting', startDate: '2014-01', targets: 'Ukrainian government, military, law enforcement', status: 'ongoing' },
      { name: 'Pre-invasion reconnaissance', startDate: '2021-11', targets: 'Ukrainian military and government networks', status: 'completed' },
      { name: 'Wartime espionage 2022-2026', startDate: '2022-02', targets: 'Ukrainian military, NATO supporters', status: 'active' }
    ],
    tools: ['Pterodo/Pteranodon', 'GammaLoad', 'GammaSteel', 'QuietSieve', 'ObfuMerry', 'DinoTrain', 'DessertDown'],
    mitreAttack: ['T1566.001', 'T1204.002', 'T1059.005', 'T1059.001', 'T1547.001', 'T1071.001', 'T1105', 'T1083'],
    infrastructure: { domains: 3200, ips: 1800, hostingPrefs: 'Fast-flux DNS, Telegram for C2, compromised Ukrainian infrastructure' },
    activityPattern: { peakHours: '05:00-15:00 UTC', peakDays: 'Mon-Fri' },
    currentTargets: ['Ukrainian military command networks', 'Ukrainian government email systems', 'NATO member diplomatic staff in Ukraine']
  },
  {
    id: 'fin7', name: 'FIN7', aliases: ['Carbanak', 'Carbon Spider', 'Sangria Tempest', 'ELBRUS', 'ITG14'],
    nationState: 'Russia (cybercriminal, some state links)', active: true,
    campaigns: [
      { name: 'Carbanak banking campaign', startDate: '2013-01', targets: 'Banks worldwide, $1B+ stolen', status: 'completed' },
      { name: 'US retail POS attacks', startDate: '2015-01', targets: 'Chipotle, Arby\'s, Saks Fifth Avenue, Lord & Taylor', status: 'completed' },
      { name: 'Fake cybersecurity company (Bastion Secure)', startDate: '2021-10', targets: 'Recruited pentesters unknowingly for ransomware ops', status: 'completed' },
      { name: 'Cl0p/BlackBasta partnership', startDate: '2024-01', targets: 'Fortune 500 initial access brokering', status: 'active' }
    ],
    tools: ['Carbanak backdoor', 'GRIFFON', 'BIRDDOG', 'BOOSTWRITE', 'HALFBAKED', 'PILLOWMINT', 'Lizar/Tirion'],
    mitreAttack: ['T1566.001', 'T1204.002', 'T1059.001', 'T1059.005', 'T1055', 'T1027', 'T1071.001', 'T1486'],
    infrastructure: { domains: 890, ips: 430, hostingPrefs: 'Bullet-proof hosting, front companies, compromised infrastructure' },
    activityPattern: { peakHours: '06:00-18:00 UTC', peakDays: 'Mon-Sat' },
    currentTargets: ['Enterprise initial access brokering', 'Ransomware affiliate operations', 'US and European corporate targets']
  },
  {
    id: 'fin12', name: 'FIN12', aliases: ['Pistol Tempest', 'DEV-0237'],
    nationState: 'Russia (cybercriminal)', active: true,
    campaigns: [
      { name: 'Healthcare ransomware blitz', startDate: '2020-10', targets: 'US hospitals and healthcare systems', status: 'ongoing' },
      { name: 'Ryuk/Conti deployment', startDate: '2019-01', targets: 'High-revenue organizations for ransomware', status: 'completed' },
      { name: 'Multi-ransomware affiliate', startDate: '2023-01', targets: 'Healthcare, manufacturing, government', status: 'active' }
    ],
    tools: ['Cobalt Strike', 'SystemBC', 'BazarLoader', 'WEIRDLOOP', 'Ryuk', 'Conti', 'Hive', 'BlackCat deployer'],
    mitreAttack: ['T1566.001', 'T1078', 'T1059.001', 'T1486', 'T1490', 'T1021.002', 'T1047', 'T1003.001'],
    infrastructure: { domains: 210, ips: 145, hostingPrefs: 'TrickBot/BazarLoader infrastructure, initial access broker purchases' },
    activityPattern: { peakHours: '10:00-22:00 UTC', peakDays: 'Any day' },
    currentTargets: ['US healthcare organizations', 'Manufacturing companies >$300M revenue', 'Government contractors']
  },
  {
    id: 'scattered_spider', name: 'Scattered Spider', aliases: ['Roasted 0ktapus', 'UNC3944', 'Octo Tempest', 'Star Fraud', '0ktapus'],
    nationState: 'US/UK (cybercriminal, young adults)', active: true,
    campaigns: [
      { name: '0ktapus phishing campaign', startDate: '2022-03', targets: 'Twilio, Cloudflare, 130+ organizations', status: 'completed' },
      { name: 'MGM Resorts attack', startDate: '2023-09', targets: 'MGM Resorts International ($100M+ losses)', status: 'completed' },
      { name: 'Caesars Entertainment', startDate: '2023-08', targets: 'Caesars Entertainment ($15M ransom paid)', status: 'completed' },
      { name: 'Enterprise SaaS targeting 2026', startDate: '2026-01', targets: 'Major SaaS providers, telecom, finance', status: 'active' }
    ],
    tools: ['Custom phishing kits', 'SIM swapping', 'Social engineering (IT helpdesk impersonation)', 'ALPHV/BlackCat ransomware', 'Mimikatz', 'AnyDesk'],
    mitreAttack: ['T1566.001', 'T1078', 'T1621', 'T1556.006', 'T1199', 'T1059.001', 'T1486', 'T1657'],
    infrastructure: { domains: 340, ips: 120, hostingPrefs: 'Telegram coordination, residential proxies, compromised employee devices' },
    activityPattern: { peakHours: '15:00-06:00 UTC', peakDays: 'Any day (24/7 operations)' },
    currentTargets: ['Large enterprises with Okta/Azure AD', 'Telecom companies for SIM swapping', 'Hospitality and entertainment']
  },
  {
    id: 'lapsus', name: 'Lapsus$', aliases: ['DEV-0537', 'Strawberry Tempest'],
    nationState: 'International (teen hackers, Brazil/UK)', active: false,
    campaigns: [
      { name: 'NVIDIA breach', startDate: '2022-02', targets: 'NVIDIA — stole 1TB including code signing certs', status: 'completed' },
      { name: 'Samsung source code theft', startDate: '2022-03', targets: 'Samsung — 190GB Galaxy source code', status: 'completed' },
      { name: 'Microsoft source code', startDate: '2022-03', targets: 'Microsoft — Bing, Cortana partial source code', status: 'completed' },
      { name: 'Okta breach', startDate: '2022-01', targets: 'Okta via Sitel subcontractor — 366 customer tenants accessed', status: 'completed' }
    ],
    tools: ['SIM swapping', 'MFA fatigue attacks', 'Insider recruitment (bribing employees)', 'Social engineering', 'RedLine stealer logs'],
    mitreAttack: ['T1078', 'T1621', 'T1566', 'T1530', 'T1213', 'T1059', 'T1657', 'T1199'],
    infrastructure: { domains: 45, ips: 20, hostingPrefs: 'Telegram for coordination, residential IPs, stolen VPN credentials' },
    activityPattern: { peakHours: 'Variable (teen schedules)', peakDays: 'Any day' },
    currentTargets: ['Largely dormant after arrests. Copycat groups active.']
  },
  {
    id: 'darkangels', name: 'Dark Angels', aliases: ['Dunghill Leak'],
    nationState: 'Unknown (Russian-speaking)', active: true,
    campaigns: [
      { name: 'Johnson Controls attack', startDate: '2023-09', targets: 'Johnson Controls ($51M ransom demand, 27TB stolen)', status: 'completed' },
      { name: 'Cencora/AmerisourceBergen', startDate: '2024-02', targets: 'Cencora — $75M ransom paid (largest known)', status: 'completed' },
      { name: 'Single-target big game hunting 2026', startDate: '2026-01', targets: 'Fortune 100 companies, one at a time', status: 'active' }
    ],
    tools: ['Babuk-derived encryptor', 'RagnarLocker-derived Linux variant', 'Custom exfiltration tools', 'Rclone'],
    mitreAttack: ['T1190', 'T1078', 'T1486', 'T1567', 'T1048', 'T1070', 'T1059.001', 'T1021.002'],
    infrastructure: { domains: 15, ips: 8, hostingPrefs: 'Tor hidden services, minimal infrastructure' },
    activityPattern: { peakHours: '08:00-20:00 UTC', peakDays: 'Mon-Fri' },
    currentTargets: ['Fortune 100 companies with high revenue', 'Healthcare and pharma conglomerates']
  },
  {
    id: 'blacktech', name: 'BlackTech', aliases: ['Palmerworm', 'Temp.Overboard', 'Circuit Panda', 'Radio Panda', 'Manga Taurus'],
    nationState: 'China (MSS-linked)', active: true,
    campaigns: [
      { name: 'Router firmware manipulation', startDate: '2023-01', targets: 'Cisco routers in US/Japan subsidiaries for persistent access', status: 'ongoing' },
      { name: 'Japan-Taiwan supply chain', startDate: '2020-01', targets: 'Japanese and Taiwanese technology companies', status: 'ongoing' },
      { name: 'Semiconductor IP theft', startDate: '2024-06', targets: 'Taiwan semiconductor firms', status: 'active' }
    ],
    tools: ['Waterbear', 'Plead', 'TSCookie', 'BendyBear', 'FlagPro', 'SpiderPig', 'custom router implants'],
    mitreAttack: ['T1195.002', 'T1542.004', 'T1600', 'T1556', 'T1059', 'T1071', 'T1027', 'T1020'],
    infrastructure: { domains: 520, ips: 215, hostingPrefs: 'Compromised routers as C2 proxies, legitimate cloud services' },
    activityPattern: { peakHours: '00:00-08:00 UTC', peakDays: 'Mon-Fri' },
    currentTargets: ['Cisco/Juniper routers in target networks', 'Japanese government contractors', 'Taiwan TSMC supply chain']
  },
  {
    id: 'mustangpanda', name: 'Mustang Panda', aliases: ['Bronze President', 'Stately Taurus', 'RedDelta', 'TA416', 'Earth Preta'],
    nationState: 'China (MSS)', active: true,
    campaigns: [
      { name: 'SE Asian government espionage', startDate: '2017-01', targets: 'Myanmar, Vietnam, Philippines, Mongolia governments', status: 'ongoing' },
      { name: 'European diplomatic targeting', startDate: '2022-03', targets: 'EU diplomats handling Indo-Pacific policy', status: 'ongoing' },
      { name: 'USB propagation campaigns', startDate: '2023-01', targets: 'Air-gapped government networks via USB', status: 'active' }
    ],
    tools: ['PlugX', 'TONESHELL', 'PUBLOAD', 'Korplug', 'custom USB propagators', 'Cobalt Strike'],
    mitreAttack: ['T1566.001', 'T1204.002', 'T1091', 'T1059.001', 'T1547.001', 'T1071.001', 'T1027', 'T1055'],
    infrastructure: { domains: 680, ips: 290, hostingPrefs: 'SmartHoster, compromised government infrastructure, Google Drive C2' },
    activityPattern: { peakHours: '01:00-10:00 UTC', peakDays: 'Mon-Fri' },
    currentTargets: ['ASEAN government ministries', 'European foreign affairs agencies', 'NGOs and think tanks']
  },
  {
    id: 'sidewinder', name: 'SideWinder', aliases: ['Rattlesnake', 'T-APT-04', 'Razor Tiger', 'Hardcore Nationalist'],
    nationState: 'India (suspected state-sponsored)', active: true,
    campaigns: [
      { name: 'Pakistan military espionage', startDate: '2012-01', targets: 'Pakistan military, government, nuclear program', status: 'ongoing' },
      { name: 'China government targeting', startDate: '2020-01', targets: 'Chinese military and government entities', status: 'ongoing' },
      { name: 'Sri Lanka, Nepal, Bangladesh', startDate: '2023-01', targets: 'South Asian government entities', status: 'active' }
    ],
    tools: ['WarHawk', 'SideWinder.AntiBot', 'StealerBot', 'Custom HTA downloaders', 'RTF exploits (CVE-2017-11882)'],
    mitreAttack: ['T1566.001', 'T1203', 'T1059.005', 'T1204.002', 'T1027', 'T1071.001', 'T1105', 'T1041'],
    infrastructure: { domains: 950, ips: 380, hostingPrefs: 'Dynamic DNS services, compromised websites, cloud hosting' },
    activityPattern: { peakHours: '03:00-12:00 UTC', peakDays: 'Mon-Sat' },
    currentTargets: ['Pakistan armed forces', 'Chinese government and military', 'South Asian diplomats']
  },
  {
    id: 'transparenttribe', name: 'Transparent Tribe', aliases: ['APT36', 'Mythic Leopard', 'ProjectM', 'Copper Fieldstone'],
    nationState: 'Pakistan (ISI-linked)', active: true,
    campaigns: [
      { name: 'Indian military targeting', startDate: '2013-01', targets: 'Indian military personnel, defense contractors', status: 'ongoing' },
      { name: 'Indian education sector', startDate: '2022-01', targets: 'Indian universities with defense research', status: 'ongoing' },
      { name: 'Android spyware campaigns', startDate: '2023-06', targets: 'Indian military personnel via trojanized apps', status: 'active' }
    ],
    tools: ['CrimsonRAT', 'ObliqueRAT', 'CapraRAT (Android)', 'PeppyRAT', 'USBWorm', 'custom spear-phishing generators'],
    mitreAttack: ['T1566.001', 'T1204.002', 'T1059', 'T1547.001', 'T1113', 'T1056.001', 'T1071.001', 'T1091'],
    infrastructure: { domains: 340, ips: 120, hostingPrefs: 'Pakistan-based hosting, compromised Indian educational sites' },
    activityPattern: { peakHours: '03:00-13:00 UTC', peakDays: 'Mon-Fri' },
    currentTargets: ['Indian Army and Air Force personnel', 'Indian defense research organizations', 'Kashmir-related activists']
  },
  {
    id: 'agrius', name: 'Agrius', aliases: ['Pink Sandstorm', 'DEV-0gone', 'BlackShadow'],
    nationState: 'Iran (MOIS)', active: true,
    campaigns: [
      { name: 'Israeli organizations wiper attacks', startDate: '2020-12', targets: 'Israeli insurance, logistics, HR companies', status: 'ongoing' },
      { name: 'Diamond industry targeting', startDate: '2022-03', targets: 'Israeli diamond industry, South Africa, Hong Kong', status: 'completed' },
      { name: 'Fantasy wiper campaign', startDate: '2022-12', targets: 'Israeli HR and IT companies', status: 'completed' },
      { name: 'Expanded targeting 2026', startDate: '2026-02', targets: 'Israeli technology and defense supply chain', status: 'active' }
    ],
    tools: ['Apostle (wiper/ransomware)', 'Fantasy (wiper)', 'IPsec Helper', 'ASPXSpy webshell', 'Moneybird ransomware'],
    mitreAttack: ['T1190', 'T1505.003', 'T1059', 'T1485', 'T1486', 'T1078', 'T1003', 'T1027'],
    infrastructure: { domains: 65, ips: 28, hostingPrefs: 'Compromised servers, VPN services, Tor' },
    activityPattern: { peakHours: '04:00-14:00 UTC', peakDays: 'Sun-Thu' },
    currentTargets: ['Israeli technology companies', 'Israeli defense supply chain', 'Diamond and jewelry industry']
  },
  {
    id: 'predatorysparrow', name: 'Predatory Sparrow', aliases: ['Gonjeshke Darande'],
    nationState: 'Unknown (suspected Israel/allied, anti-Iran)', active: true,
    campaigns: [
      { name: 'Iran railway attack', startDate: '2021-07', targets: 'Iran national railway — displayed Khamenei office phone number on departure boards', status: 'completed' },
      { name: 'Khuzestan steel mills', startDate: '2022-06', targets: 'Three Iranian steel companies — caused physical fire in mill', status: 'completed' },
      { name: 'Iran gas station payment systems', startDate: '2023-12', targets: '70% of Iran gas stations — payment systems disabled', status: 'completed' },
      { name: 'Continued Iranian infrastructure targeting', startDate: '2026-01', targets: 'Iranian industrial and transportation systems', status: 'active' }
    ],
    tools: ['Custom ICS/SCADA exploitation tools', 'PLC manipulation code', 'Payment system malware', 'Supply chain implants'],
    mitreAttack: ['T1190', 'T0831', 'T0836', 'T0882', 'T1059', 'T1071', 'T1027', 'T1485'],
    infrastructure: { domains: 12, ips: 8, hostingPrefs: 'Extremely sophisticated OPSEC, minimal infrastructure' },
    activityPattern: { peakHours: 'Variable — timed for maximum impact', peakDays: 'Variable' },
    currentTargets: ['Iranian critical infrastructure', 'Iranian industrial control systems', 'Iranian financial systems']
  },
  {
    id: 'storm0558', name: 'Storm-0558', aliases: ['China-based threat actor (Microsoft designation)'],
    nationState: 'China (MSS)', active: true,
    campaigns: [
      { name: 'Microsoft cloud email compromise', startDate: '2023-05', targets: 'US State Dept, Commerce Dept, 25+ organizations, Ambassador email', status: 'completed' },
      { name: 'Forged Azure AD token campaign', startDate: '2023-06', targets: 'US government agencies via forged authentication tokens', status: 'completed' },
      { name: 'Continued cloud targeting', startDate: '2025-01', targets: 'Government cloud email systems', status: 'active' }
    ],
    tools: ['Forged Azure AD/MSA tokens', 'Stolen Microsoft signing key (MSA consumer key)', 'China Chopper webshell', 'Custom cloud exploitation tools'],
    mitreAttack: ['T1078.004', 'T1550.001', 'T1199', 'T1114.002', 'T1530', 'T1087.004', 'T1071.001', 'T1213'],
    infrastructure: { domains: 180, ips: 75, hostingPrefs: 'Compromised cloud infrastructure, legitimate Azure services' },
    activityPattern: { peakHours: '00:00-10:00 UTC', peakDays: 'Mon-Fri' },
    currentTargets: ['US government cloud email', 'Allied government Microsoft 365 tenants', 'Think tanks and policy organizations']
  }
];

export var HISTORICAL_OPS = [
  { id: 'op-001', name: 'Stuxnet', year: 2010, attribution: 'US/Israel (NSA TAO + Unit 8200)', type: 'destruction', targets: 'Iranian nuclear centrifuges (Natanz)', impact: 'Destroyed ~1,000 centrifuges, delayed Iranian nuclear program 1-2 years', description: 'First known cyber weapon targeting ICS. Used 4 zero-day exploits.' },
  { id: 'op-002', name: 'NotPetya', year: 2017, attribution: 'Russia (GRU/Sandworm)', type: 'destruction', targets: 'Ukraine (global collateral)', impact: '$10B+ global damages, Maersk, Merck, FedEx affected', description: 'Destructive wiper disguised as ransomware, spread via M.E.Doc.' },
  { id: 'op-003', name: 'SolarWinds (SUNBURST)', year: 2020, attribution: 'Russia (SVR/APT29)', type: 'espionage', targets: 'US government agencies, Fortune 500', impact: '18,000 orgs received trojanized update, ~100 confirmed compromised', description: 'Supply chain attack via SolarWinds Orion update mechanism.' },
  { id: 'op-004', name: 'WannaCry', year: 2017, attribution: 'North Korea (Lazarus)', type: 'financial', targets: 'Global (200K+ systems in 150 countries)', impact: 'NHS hospitals shut down, $4B+ damages, exploited EternalBlue', description: 'Ransomware worm using stolen NSA exploit.' },
  { id: 'op-005', name: 'OPM Breach', year: 2015, attribution: 'China (PLA/MSS)', type: 'espionage', targets: 'US Office of Personnel Management', impact: '22.1M personnel records including SF-86 clearance forms stolen', description: 'Massive theft of government employee data including biometrics.' },
  { id: 'op-006', name: 'Sony Pictures Hack', year: 2014, attribution: 'North Korea (Lazarus)', type: 'destruction', targets: 'Sony Pictures Entertainment', impact: 'Data leak, unreleased films, $100M+ damages', description: 'Retaliation for The Interview movie.' },
  { id: 'op-007', name: 'Shamoon', year: 2012, attribution: 'Iran (APT33)', type: 'destruction', targets: 'Saudi Aramco', impact: '35,000 computers wiped with MBR-overwriting malware', description: 'First major destructive cyber attack by Iran.' },
  { id: 'op-008', name: 'Ukraine Power Grid Attack', year: 2015, attribution: 'Russia (Sandworm)', type: 'disruption', targets: 'Ukrainian power companies', impact: '230,000 customers lost power, first confirmed grid cyber attack', description: 'Used BlackEnergy and manual SCADA manipulation.' },
  { id: 'op-009', name: 'Ukraine Grid Attack II (Industroyer)', year: 2016, attribution: 'Russia (Sandworm)', type: 'disruption', targets: 'Ukrenergo transmission station', impact: 'Power outage in Kyiv using purpose-built ICS malware', description: 'More sophisticated attack using Industroyer/CrashOverride.' },
  { id: 'op-010', name: 'Colonial Pipeline', year: 2021, attribution: 'Russia (DarkSide)', type: 'disruption', targets: 'Colonial Pipeline Company', impact: 'Largest US fuel pipeline shut 6 days, $4.4M ransom paid', description: 'Ransomware disrupting fuel supply to eastern US.' },
  { id: 'op-011', name: 'Moonlight Maze', year: 1996, attribution: 'Russia (Turla attributed)', type: 'espionage', targets: 'US DOD, NASA, DOE', impact: 'Years-long espionage, massive data exfiltration', description: 'One of the first documented nation-state cyber espionage campaigns.' },
  { id: 'op-012', name: 'Titan Rain', year: 2003, attribution: 'China (PLA)', type: 'espionage', targets: 'US defense contractors, Sandia, Lockheed, NASA', impact: 'Systematic theft of defense data over years', description: 'Early Chinese cyber espionage against US defense.' },
  { id: 'op-013', name: 'GhostNet', year: 2009, attribution: 'China (attributed)', type: 'espionage', targets: 'Dalai Lama offices, embassies, foreign ministries', impact: '1,295 computers in 103 countries compromised', description: 'Large-scale espionage targeting diplomatic organizations.' },
  { id: 'op-014', name: 'Operation Aurora', year: 2009, attribution: 'China (PLA)', type: 'espionage', targets: 'Google, Adobe, Juniper, 30+ companies', impact: 'Source code theft, dissident Gmail accounts compromised', description: 'Targeted attack on tech companies using IE zero-day.' },
  { id: 'op-015', name: 'Duqu', year: 2011, attribution: 'Israel (Unit 8200)', type: 'espionage', targets: 'Iranian nuclear supply chain', impact: 'Intel collection for follow-on operations', description: 'Stuxnet-related espionage malware.' },
  { id: 'op-016', name: 'Flame', year: 2012, attribution: 'US/Israel', type: 'espionage', targets: 'Iranian government and private sector', impact: 'Massive data collection: audio, screenshots, keylogging', description: 'Highly sophisticated 20MB modular espionage platform.' },
  { id: 'op-017', name: 'Shadow Brokers Leak', year: 2016, attribution: 'Shadow Brokers (leaked NSA tools)', type: 'hybrid', targets: 'NSA Equation Group tool repository', impact: 'EternalBlue, DoublePulsar leaked, enabled WannaCry and NotPetya', description: 'Theft and public release of NSA offensive tools.' },
  { id: 'op-018', name: 'Bangladesh Bank Heist', year: 2016, attribution: 'North Korea (Lazarus)', type: 'financial', targets: 'Bangladesh Bank via SWIFT', impact: '$81M stolen ($951M attempted)', description: 'Lazarus manipulated SWIFT messages to steal from central bank.' },
  { id: 'op-019', name: 'DNC Hack', year: 2016, attribution: 'Russia (GRU APT28/APT29)', type: 'hybrid', targets: 'Democratic National Committee', impact: 'Email theft and strategic leaks affecting 2016 US election', description: 'Combined espionage with information operations.' },
  { id: 'op-020', name: 'Olympic Destroyer', year: 2018, attribution: 'Russia (Sandworm)', type: 'disruption', targets: 'PyeongChang Winter Olympics', impact: 'Opening ceremony IT disrupted, false-flag attribution', description: 'Retaliation for Russian Olympic ban.' },
  { id: 'op-021', name: 'Triton/TRISIS', year: 2017, attribution: 'Russia (CNIIHM)', type: 'destruction', targets: 'Saudi petrochemical safety systems', impact: 'First malware targeting safety instrumented systems', description: 'Targeted SIS that prevent catastrophic failures.' },
  { id: 'op-022', name: 'Cloud Hopper', year: 2016, attribution: 'China (APT10)', type: 'espionage', targets: 'Managed service providers globally', impact: 'Access to MSP clients across industries', description: 'Targeted MSPs for downstream access to thousands of orgs.' },
  { id: 'op-023', name: 'Kaseya VSA Attack', year: 2021, attribution: 'Russia (REvil)', type: 'financial', targets: '1,500+ organizations via Kaseya', impact: '$70M ransom demanded', description: 'Supply chain attack via IT management software.' },
  { id: 'op-024', name: 'ProxyLogon', year: 2021, attribution: 'China (Hafnium)', type: 'espionage', targets: '250,000+ Exchange servers', impact: 'Mass exploitation, web shells deployed globally', description: 'Hafnium exploited 4 Exchange zero-days.' },
  { id: 'op-025', name: 'Viasat KA-SAT Attack', year: 2022, attribution: 'Russia (Sandworm)', type: 'disruption', targets: 'Viasat satellite network', impact: 'Ukrainian military comms disrupted, 5,800 German wind turbines affected', description: 'AcidRain wiper on satellite modems at invasion start.' },
  { id: 'op-026', name: 'Ronin Bridge Heist', year: 2022, attribution: 'North Korea (Lazarus)', type: 'financial', targets: 'Ronin Network (Axie Infinity)', impact: '$625M cryptocurrency stolen', description: 'Lazarus compromised validator nodes via social engineering.' },
  { id: 'op-027', name: 'Costa Rica Government Attack', year: 2022, attribution: 'Russia (Conti)', type: 'disruption', targets: 'Costa Rica government', impact: 'National emergency declared, Treasury and healthcare shut down', description: 'First country to declare cyber emergency.' },
  { id: 'op-028', name: 'MOVEit Exploitation', year: 2023, attribution: 'Russia (Cl0p)', type: 'financial', targets: '2,500+ organizations via MOVEit zero-day', impact: '90M+ individuals affected, $10B+ estimated damages', description: 'Mass data exfiltration without ransomware deployment.' },
  { id: 'op-029', name: 'Change Healthcare Attack', year: 2024, attribution: 'Russia (BlackCat/ALPHV)', type: 'disruption', targets: 'Change Healthcare', impact: 'US healthcare payments disrupted weeks, $22M ransom, 100M+ records', description: 'Ransomware on healthcare payment clearinghouse.' },
  { id: 'op-030', name: 'Salt Typhoon Telecom Infiltration', year: 2023, attribution: 'China (Salt Typhoon)', type: 'espionage', targets: 'AT&T, Verizon, T-Mobile, Lumen', impact: 'CALEA wiretap systems compromised, official call records collected', description: 'Deep penetration compromising lawful intercept systems.' },
  { id: 'op-031', name: 'Volt Typhoon Pre-positioning', year: 2021, attribution: 'China (Volt Typhoon)', type: 'espionage', targets: 'US critical infrastructure', impact: 'Pre-positioned access for potential wartime disruption', description: 'Living-off-the-land pre-positioning in US infrastructure.' },
  { id: 'op-032', name: 'Industroyer2', year: 2022, attribution: 'Russia (Sandworm)', type: 'disruption', targets: 'Ukrainian electrical substations', impact: 'Disrupted by CERT-UA before full activation', description: 'Updated Industroyer targeting Ukrainian grid during invasion.' },
  { id: 'op-033', name: 'Shamoon 2', year: 2016, attribution: 'Iran (APT33)', type: 'destruction', targets: 'Saudi government agencies', impact: 'Thousands of computers wiped', description: 'Return of Shamoon with new anti-analysis.' },
  { id: 'op-034', name: 'Shamoon 3', year: 2018, attribution: 'Iran (APT33)', type: 'destruction', targets: 'Italian oil company Saipem', impact: '300-400 servers wiped', description: 'Third iteration targeting oil and gas.' },
  { id: 'op-035', name: 'WhisperGate', year: 2022, attribution: 'Russia', type: 'destruction', targets: 'Ukrainian government agencies', impact: 'Government websites defaced, wiper deployed', description: 'Destructive wiper before Russian invasion.' },
  { id: 'op-036', name: 'HermeticWiper', year: 2022, attribution: 'Russia (Sandworm)', type: 'destruction', targets: 'Ukrainian government and financial', impact: 'Hundreds of computers wiped before invasion', description: 'Wiper deployed hours before kinetic invasion.' },
  { id: 'op-037', name: 'Albanian Government Attack', year: 2022, attribution: 'Iran (MOIS)', type: 'disruption', targets: 'Albanian government', impact: 'Services disrupted, diplomatic crisis, relations severed', description: 'Iran attacked NATO member Albania over MEK hosting.' },
  { id: 'op-038', name: 'PRISM', year: 2007, attribution: 'United States (NSA)', type: 'espionage', targets: 'Global communications via US tech companies', impact: 'Massive surveillance collecting from Google, Facebook, Apple, Microsoft', description: 'NSA program for foreign intelligence from US internet companies.' },
  { id: 'op-039', name: 'Belgacom Hack', year: 2013, attribution: 'UK (GCHQ)', type: 'espionage', targets: 'Belgian telecom', impact: 'Access to telecom used by EU institutions', description: 'GCHQ operation to intercept EU official communications.' },
  { id: 'op-040', name: 'Predatory Sparrow', year: 2022, attribution: 'Israel (attributed)', type: 'disruption', targets: 'Iranian steel companies', impact: 'Steel mill equipment damaged, fire in facility', description: 'Cyber-physical attack causing real-world fire.' },
  { id: 'op-041', name: 'Harmony Bridge Heist', year: 2022, attribution: 'North Korea (Lazarus)', type: 'financial', targets: 'Harmony blockchain bridge', impact: '$100M cryptocurrency stolen', description: 'Lazarus exploited cross-chain bridge vulnerabilities.' },
  { id: 'op-042', name: 'JBS Foods Attack', year: 2021, attribution: 'Russia (REvil)', type: 'financial', targets: 'JBS Foods', impact: 'Production halted globally, $11M ransom paid', description: 'Ransomware on critical food supply chain.' },
  { id: 'op-043', name: 'SolarWinds Serv-U', year: 2021, attribution: 'China (DEV-0322)', type: 'espionage', targets: 'US defense industrial base', impact: 'Zero-day exploitation targeting defense orgs', description: 'Chinese exploitation of different SolarWinds product.' },
  { id: 'op-044', name: 'Pegasus Operations', year: 2016, attribution: 'Israel (NSO Group)', type: 'espionage', targets: 'Journalists, activists, politicians', impact: '50,000+ numbers targeted by 40+ governments', description: 'Commercial spyware used against journalists and dissidents.' },
  { id: 'op-045', name: 'CCleaner Supply Chain', year: 2017, attribution: 'China (APT41)', type: 'espionage', targets: '2.27M CCleaner users', impact: 'Backdoored CCleaner, second-stage targeted tech companies', description: 'Supply chain compromise of popular utility.' },
  { id: 'op-046', name: 'ASUS Shadow Hammer', year: 2019, attribution: 'China (APT41)', type: 'espionage', targets: '1M+ ASUS users', impact: 'Backdoored updates targeting 600 specific MAC addresses', description: 'Supply chain attack through ASUS update mechanism.' },
  { id: 'op-047', name: 'Norsk Hydro Attack', year: 2019, attribution: 'Russia (LockerGoga)', type: 'disruption', targets: 'Norsk Hydro aluminum manufacturer', impact: '$71M losses, forced manual operations for weeks', description: 'Ransomware causing major industrial disruption.' },
  { id: 'op-048', name: 'Iranian Water Attack', year: 2020, attribution: 'Israel (attributed)', type: 'disruption', targets: 'Iranian water treatment', impact: 'Attempted chlorine level manipulation', description: 'Cyber attack on Iranian water infrastructure.' },
  { id: 'op-049', name: 'Israeli Water Targeting', year: 2020, attribution: 'Iran', type: 'disruption', targets: 'Israeli water and sewage', impact: 'Multiple attacks prevented before causing damage', description: 'Iran retaliated against Israeli water systems.' },
  { id: 'op-050', name: 'Oldsmar Water Plant', year: 2021, attribution: 'Unknown', type: 'disruption', targets: 'Oldsmar, Florida water plant', impact: 'Attempted increase of sodium hydroxide to dangerous levels', description: 'Remote access attempt to poison water supply.' },
  { id: 'op-051', name: 'SingHealth Breach', year: 2018, attribution: 'China (attributed)', type: 'espionage', targets: 'Singapore healthcare', impact: '1.5M patient records including PM medical data stolen', description: 'Targeted espionage against Singapore healthcare.' },
  { id: 'op-052', name: 'Marriott Breach', year: 2014, attribution: 'China (MSS attributed)', type: 'espionage', targets: 'Marriott/Starwood Hotels', impact: '500M guest records compromised over 4 years', description: 'Long-running espionage harvesting traveler data.' },
  { id: 'op-053', name: 'Equifax Breach', year: 2017, attribution: 'China (PLA)', type: 'espionage', targets: 'Equifax credit bureau', impact: '147M Americans PII exposed, 4 PLA members indicted', description: 'Chinese military hackers stole credit data.' },
  { id: 'op-054', name: 'Anthem Breach', year: 2015, attribution: 'China (Deep Panda)', type: 'espionage', targets: 'Anthem health insurance', impact: '78.8M records stolen including SSNs', description: 'Chinese espionage targeting health insurance data.' },
  { id: 'op-055', name: 'Yahoo Breaches', year: 2013, attribution: 'Russia (FSB)', type: 'espionage', targets: 'Yahoo email accounts', impact: '3B accounts compromised across two breaches', description: 'FSB officers directed hackers to compromise Yahoo.' },
  { id: 'op-056', name: 'TV5Monde Attack', year: 2015, attribution: 'Russia (APT28)', type: 'disruption', targets: 'French TV network', impact: '12 channels taken off air, ISIS false flag', description: 'APT28 disrupted French TV while planting false attribution.' },
  { id: 'op-057', name: 'Bundestag Hack', year: 2015, attribution: 'Russia (APT28)', type: 'espionage', targets: 'German Parliament', impact: '16GB data exfiltrated, GRU officer warrant issued', description: 'APT28 compromised German parliamentary network.' },
  { id: 'op-058', name: 'SWIFT Banking Attacks', year: 2015, attribution: 'North Korea (Lazarus)', type: 'financial', targets: 'Banks in Vietnam, Ecuador, Philippines, Bangladesh', impact: '$2B+ in theft attempts', description: 'Systematic exploitation of SWIFT banking network.' },
  { id: 'op-059', name: 'WannaCry NHS Impact', year: 2017, attribution: 'North Korea (Lazarus)', type: 'disruption', targets: 'UK National Health Service', impact: '80 trusts affected, 19,000 appointments cancelled', description: 'WannaCry devastated UK healthcare on unpatched XP.' },
  { id: 'op-060', name: 'Dragonfly/Energetic Bear', year: 2014, attribution: 'Russia (FSB)', type: 'espionage', targets: 'US and European energy sector', impact: 'Persistent access to energy ICS', description: 'Russian espionage in Western energy infrastructure.' },
  { id: 'op-061', name: 'Carbanak/FIN7', year: 2013, attribution: 'Russia (Cybercriminal)', type: 'financial', targets: '100+ financial institutions worldwide', impact: '$1B+ stolen via ATM cash-out and wire transfers', description: 'Sophisticated banking malware campaign.' },
  { id: 'op-062', name: 'BlackEnergy', year: 2014, attribution: 'Russia (Sandworm)', type: 'espionage', targets: 'Ukrainian government and energy', impact: 'Pre-positioning for future destructive operations', description: 'Reconnaissance preceding 2015 grid attack.' },
  { id: 'op-063', name: 'CaddyWiper', year: 2022, attribution: 'Russia (Sandworm)', type: 'destruction', targets: 'Ukrainian organizations', impact: 'Data destruction during invasion', description: 'One of numerous wipers during Ukraine invasion.' },
  { id: 'op-064', name: 'FEIB Taiwan SWIFT Attack', year: 2017, attribution: 'North Korea (Lazarus)', type: 'financial', targets: 'Far Eastern International Bank', impact: '$60M attempted, $500K recovered', description: 'Lazarus continued SWIFT attacks against Asian banks.' },
  { id: 'op-065', name: 'Operation Cleaver', year: 2012, attribution: 'Iran (IRGC)', type: 'espionage', targets: 'US military, airlines, energy in 16 countries', impact: 'Access to critical infrastructure networks', description: 'Iranian campaign targeting infrastructure in 16 nations.' },
  { id: 'op-066', name: 'FASTCash ATM Attacks', year: 2018, attribution: 'North Korea (Lazarus)', type: 'financial', targets: 'Banks in Asia and Africa', impact: 'Tens of millions stolen in simultaneous ATM cash-outs', description: 'Lazarus deployed FASTCash on ATM switches.' },
  { id: 'op-067', name: 'ProxyShell', year: 2021, attribution: 'Multiple', type: 'espionage', targets: 'Exchange servers globally', impact: 'Continued mass exploitation after ProxyLogon patches', description: 'Follow-on Exchange exploitation campaign.' },
  { id: 'op-068', name: 'Irish HSE Attack', year: 2021, attribution: 'Russia (Conti)', type: 'disruption', targets: 'Ireland Health Service', impact: 'Entire health system shut down, $600M+ recovery', description: 'Conti crippled Irish healthcare for months.' },
  { id: 'op-069', name: 'US Infrastructure Ransomware Wave', year: 2021, attribution: 'Multiple Russian groups', type: 'disruption', targets: 'US critical infrastructure', impact: 'Multiple pipeline and utility companies hit', description: 'Wave of attacks after Colonial Pipeline.' },
  { id: 'op-070', name: 'SolarWinds SUPERNOVA', year: 2020, attribution: 'China (Spiral)', type: 'espionage', targets: 'SolarWinds Orion users', impact: 'Additional supply chain compromise found during SUNBURST investigation', description: 'Chinese group exploited SolarWinds separately from Russia.' },
  { id: 'op-071', name: 'Turla Hijacks Iranian APT', year: 2019, attribution: 'Russia (Turla)', type: 'espionage', targets: 'Iranian APT34 targets', impact: 'Turla hijacked Iranian C2 for 4th-party collection', description: 'FSB compromised Iranian APT infrastructure.' },
  { id: 'op-072', name: 'Operation Ghostwriter', year: 2020, attribution: 'Russia/Belarus', type: 'hybrid', targets: 'Lithuania, Latvia, Poland', impact: 'Hack-and-leak plus disinformation targeting NATO support', description: 'Combined cyber intrusion with information warfare.' },
  { id: 'op-073', name: 'Sandworm Election Targeting', year: 2020, attribution: 'Russia (Sandworm)', type: 'hybrid', targets: 'US state election infrastructure', impact: 'Scanning and probing of election systems', description: 'GRU Unit 74455 recon against US election infrastructure.' },
  { id: 'op-074', name: 'ICBC Ransomware', year: 2023, attribution: 'Russia (LockBit)', type: 'disruption', targets: 'ICBC Financial Services', impact: 'Worlds largest bank disrupted, US Treasury market affected', description: 'LockBit disrupted ICBC Treasury clearing.' },
  { id: 'op-075', name: 'Boeing Data Leak', year: 2023, attribution: 'Russia (LockBit)', type: 'financial', targets: 'Boeing Corporation', impact: '43GB sensitive data leaked', description: 'LockBit exfiltrated Boeing proprietary data.' },
  { id: 'op-076', name: 'MGM Resorts Attack', year: 2023, attribution: 'Scattered Spider/BlackCat', type: 'disruption', targets: 'MGM Resorts International', impact: 'Operations disrupted 10 days, $100M+ losses', description: 'Social engineering plus ransomware against casino.' },
  { id: 'op-077', name: 'Caesars Attack', year: 2023, attribution: 'Scattered Spider/BlackCat', type: 'financial', targets: 'Caesars Entertainment', impact: '$15M ransom paid, customer data stolen', description: 'Social engineering attack, ransom paid.' },
  { id: 'op-078', name: 'GoAnywhere MFT Exploitation', year: 2023, attribution: 'Russia (Cl0p)', type: 'financial', targets: '130+ organizations', impact: '130+ orgs compromised via zero-day', description: 'Cl0p exploited file transfer zero-day.' },
  { id: 'op-079', name: 'Barracuda ESG Zero-Day', year: 2023, attribution: 'China (UNC4841)', type: 'espionage', targets: 'Government and critical infrastructure', impact: 'Persistent backdoors, some required hardware replacement', description: 'Chinese espionage via Barracuda ESG zero-day.' },
  { id: 'op-080', name: 'Citrix Bleed', year: 2023, attribution: 'Multiple (LockBit primary)', type: 'hybrid', targets: 'Citrix NetScaler/ADC users', impact: 'Mass exploitation enabling ransomware across thousands', description: 'Critical Citrix vulnerability widely exploited.' },
  { id: 'op-081', name: 'Okta Support Breach', year: 2023, attribution: 'Scattered Spider', type: 'espionage', targets: 'Okta customers', impact: '134 customers affected via support portal', description: 'Identity provider support system compromised.' },
  { id: 'op-082', name: 'Microsoft Executive Email Hack', year: 2023, attribution: 'Russia (APT29)', type: 'espionage', targets: 'Microsoft leadership and security', impact: 'Executive emails compromised, source code accessed', description: 'APT29 password-sprayed test tenant for leadership email.' },
  { id: 'op-083', name: 'Ivanti VPN Zero-Day Campaign', year: 2024, attribution: 'China (UNC5221)', type: 'espionage', targets: 'Government and defense worldwide', impact: 'CISA ordered emergency Ivanti disconnect from federal networks', description: 'Chinese exploitation of Ivanti Connect Secure zero-days.' },
  { id: 'op-084', name: 'XZ Utils Backdoor', year: 2024, attribution: 'Unknown nation-state', type: 'hybrid', targets: 'Linux SSH authentication', impact: 'Backdoor would have compromised SSH on major distros', description: 'Multi-year social engineering to insert SSH backdoor.' },
  { id: 'op-085', name: 'CrowdStrike Update Incident', year: 2024, attribution: 'Accidental', type: 'disruption', targets: 'Global Windows systems', impact: '8.5M systems crashed, airlines, hospitals, banks disrupted', description: 'Faulty CrowdStrike update caused global BSOD.' },
  { id: 'op-086', name: 'Pager Device Explosions', year: 2024, attribution: 'Israel (Mossad/Unit 8200)', type: 'destruction', targets: 'Hezbollah communication devices', impact: 'Thousands of devices exploded, 37 killed, 3,000+ wounded', description: 'Physical supply chain compromise with explosives.' },
  { id: 'op-087', name: 'APT29 Teams Phishing', year: 2024, attribution: 'Russia (APT29)', type: 'espionage', targets: 'Government and NGO via Microsoft Teams', impact: 'MFA bypass via compromised M365 tenants', description: 'APT29 abused small business tenants for Teams phishing.' },
  { id: 'op-088', name: 'Volt Typhoon Botnet Disruption', year: 2024, attribution: 'US (FBI)', type: 'disruption', targets: 'Volt Typhoon KV-botnet', impact: 'Court-authorized disruption of Chinese botnet', description: 'FBI remotely removed malware from SOHO routers.' },
  { id: 'op-089', name: 'LockBit Operation Cronos', year: 2024, attribution: 'International Law Enforcement', type: 'disruption', targets: 'LockBit infrastructure', impact: 'Infrastructure seized, affiliates identified, leader doxxed', description: 'International operation disrupted LockBit.' },
  { id: 'op-090', name: 'Snowflake Customer Attacks', year: 2024, attribution: 'UNC5537', type: 'financial', targets: 'AT&T, Ticketmaster, 160+ Snowflake customers', impact: 'Massive data theft using stolen credentials without MFA', description: 'Credential-based attacks on cloud data warehouses.' },
  { id: 'op-091', name: 'Iran Albania Attack II', year: 2024, attribution: 'Iran (MOIS)', type: 'disruption', targets: 'Albanian Institute of Statistics', impact: 'Continued Iranian attacks despite diplomatic severance', description: 'Iran continued attacks on Albania.' },
  { id: 'op-092', name: 'MSS LinkedIn Recruitment', year: 2024, attribution: 'China (MSS)', type: 'espionage', targets: 'Western government employees', impact: 'Thousands of officials approached for recruitment', description: 'Large-scale intelligence recruitment via social media.' },
  { id: 'op-093', name: 'NK IT Worker Infiltration', year: 2024, attribution: 'North Korea (RGB)', type: 'financial', targets: 'US/EU tech companies', impact: 'Thousands of NK workers fraudulently employed', description: 'North Korean workers using stolen identities for tech jobs.' },
  { id: 'op-094', name: 'APT29 HPE Attack', year: 2024, attribution: 'Russia (APT29)', type: 'espionage', targets: 'Hewlett Packard Enterprise', impact: 'HPE cloud email compromised', description: 'APT29 compromised HPE before Microsoft breach.' },
  { id: 'op-095', name: 'IRGC Persona Operations', year: 2024, attribution: 'Iran (IRGC)', type: 'hybrid', targets: 'US election campaigns', impact: 'Hack-and-leak attempts against presidential campaigns', description: 'IRGC attempted to influence US election.' },
  { id: 'op-096', name: 'Typhoon Flax', year: 2025, attribution: 'China (PLA)', type: 'espionage', targets: 'US defense satellite comms', impact: 'Access to military satellite ground station management', description: 'Chinese APT targeting satellite C2 infrastructure.' },
  { id: 'op-097', name: 'Operation Dark Winter', year: 2025, attribution: 'Russia (GRU)', type: 'disruption', targets: 'European gas distribution SCADA', impact: 'Attempted gas supply disruption during winter', description: 'Sandworm targeted European gas during cold snap.' },
  { id: 'op-098', name: 'Lazarus NFT Marketplace Exploit', year: 2025, attribution: 'North Korea (Lazarus)', type: 'financial', targets: 'Major NFT marketplace', impact: '$340M in digital assets stolen', description: 'Lazarus exploited logic flaw in NFT marketplace.' },
  { id: 'op-099', name: 'Iranian Hospital Wiper', year: 2025, attribution: 'Iran (APT33)', type: 'destruction', targets: 'Gulf state hospital networks', impact: 'Hospital systems wiped during medical procedures', description: 'Destructive wiper targeting healthcare.' },
  { id: 'op-100', name: 'Cascade Zero', year: 2026, attribution: 'Multiple nation-states', type: 'disruption', targets: 'Global internet infrastructure', impact: 'Coordinated BGP hijacking and DNS root server targeting', description: 'Multi-nation internet infrastructure attack.' },
  { id: 'op-101', name: 'Dragon Storm', year: 2026, attribution: 'China (PLA/MSS)', type: 'disruption', targets: 'US critical infrastructure during Taiwan crisis', impact: 'Simultaneous activation of pre-positioned access', description: 'Volt Typhoon activates all pre-positioned access.' },
  { id: 'op-102', name: 'APT29 Cloud Identity Attack', year: 2025, attribution: 'Russia (SVR)', type: 'espionage', targets: 'US/EU cloud identity federation', impact: 'Cross-tenant government cloud access via federation compromise', description: 'SVR exploitation of Azure AD federation.' },
  { id: 'op-103', name: 'Healthcare Ransomware Wave', year: 2026, attribution: 'Multiple Russian groups', type: 'financial', targets: 'US healthcare sector', impact: 'Coordinated ransomware hitting 30+ hospitals', description: 'Multiple groups targeting healthcare after Change Healthcare.' },
  { id: 'op-104', name: 'Silent EU Parliament Breach', year: 2025, attribution: 'China (APT41)', type: 'espionage', targets: 'European Parliament email/docs', impact: 'Multi-year undetected access to China policy communications', description: 'APT41 maintained persistent access to EU legislative comms.' }
];

export var WARGAME_SCENARIOS = [
  { id: 'ws-001', codename: 'DRAGON STORM', description: 'China activates Volt Typhoon pre-positioned access across US critical infrastructure during Taiwan Strait crisis', adversary: 'China (PLA/MSS)', difficulty: 5, estimatedDuration: '4 hours', phases: [
    { name: 'Phase 1: Geopolitical Trigger', description: 'PLA announces naval blockade of Taiwan. Volt Typhoon implants receiving activation signals.', blueTeamOptions: ['Activate CISA Shields Up', 'Deploy hunt teams to critical infrastructure', 'Elevate DEFCON level', 'Brief White House NSC'] },
    { name: 'Phase 2: Initial Activation', description: 'Water treatment in 3 states reports SCADA anomalies. Power grid operators detect unauthorized access.', blueTeamOptions: ['Isolate affected OT networks', 'Activate ICS incident response', 'Implement manual operations fallback', 'Deploy National Guard cyber units'] },
    { name: 'Phase 3: Escalation', description: 'Telecom backbone routing anomalies. Port management unauthorized commands. Military logistics affected.', blueTeamOptions: ['Activate military PACE plan', 'Deploy CYBERCOM teams', 'Coordinate with Five Eyes', 'Consider proportional response'] },
    { name: 'Phase 4: Full Crisis', description: 'Multiple sectors simultaneously affected. Public panic. Military C2 degraded.', blueTeamOptions: ['Activate continuity of government', 'Deploy emergency restoration', 'Authorize CYBERCOM offensive', 'Coordinate coalition response'] }
  ] },
  { id: 'ws-002', codename: 'BEARS CLAW', description: 'Russia launches coordinated attack on NATO member: power grid, telecom, financial', adversary: 'Russia (GRU/Sandworm)', difficulty: 5, estimatedDuration: '3.5 hours', phases: [
    { name: 'Phase 1: Prelude', description: 'Russian exercises near borders. Sandworm recon of critical infrastructure intensifies.', blueTeamOptions: ['Elevate national cyber posture', 'Deploy monitoring to critical infrastructure', 'Brief NATO allies', 'Activate mutual defense consultations'] },
    { name: 'Phase 2: First Strike', description: 'Industroyer2 variant activates in power grid. Substations trip. Backup generators fail.', blueTeamOptions: ['Activate grid isolation', 'Deploy ICS emergency response', 'Implement islanding', 'Request NATO cyber rapid reaction'] },
    { name: 'Phase 3: Multi-vector', description: 'SWIFT disrupted. Telecom base stations losing connectivity. Government email encrypted.', blueTeamOptions: ['Activate backup SWIFT channels', 'Deploy satellite comms fallback', 'Restore from offline backups', 'Invoke Article 5 consultations'] },
    { name: 'Phase 4: Recovery', description: 'Effects spreading to neighboring countries. Public services severely degraded.', blueTeamOptions: ['Coordinate international response', 'Deploy allied cyber defense', 'Authorize proportional response', 'Implement long-term hardening'] }
  ] },
  { id: 'ws-003', codename: 'HERMITS FURY', description: 'North Korea deploys WannaCry-scale worm targeting financial sector for crypto theft', adversary: 'North Korea (RGB/Lazarus)', difficulty: 4, estimatedDuration: '3 hours', phases: [
    { name: 'Phase 1: Setup', description: 'Lazarus compiling worm with banking trojan and crypto-stealing capabilities.', blueTeamOptions: ['Alert FS-ISAC members', 'Deploy emergency patches', 'Activate financial threat sharing', 'Brief Treasury and Fed'] },
    { name: 'Phase 2: Outbreak', description: 'Worm spreading through banking networks. Crypto hot wallets being drained.', blueTeamOptions: ['Network quarantine for affected institutions', 'Freeze suspicious crypto transactions', 'Activate financial incident response', 'Coordinate with international banking'] },
    { name: 'Phase 3: Peak', description: 'Worm reaches 50,000+ endpoints. $500M+ crypto stolen. $200M+ wire transfers initiated.', blueTeamOptions: ['Emergency SWIFT halt', 'Coordinate crypto exchange wallet freezing', 'Deploy FBI cyber for tracing', 'Brief Congressional leadership'] },
    { name: 'Phase 4: Containment', description: 'Kill switch identified. Crypto being laundered. Banking systems need restoration.', blueTeamOptions: ['Activate kill switch', 'Trace and freeze stolen crypto', 'Deploy banking recovery', 'Coordinate law enforcement'] }
  ] },
  { id: 'ws-004', codename: 'PERSIAN FIRE', description: 'Iran retaliates against sanctions with Shamoon-variant wiper targeting Gulf oil/gas', adversary: 'Iran (IRGC/APT33)', difficulty: 4, estimatedDuration: '3 hours', phases: [
    { name: 'Phase 1: Trigger', description: 'Expanded sanctions announced. Iranian rhetoric escalates. APT33 staging detected.', blueTeamOptions: ['Elevate Gulf defense posture', 'Deploy Shamoon detection', 'Brief Gulf oil companies', 'Coordinate with CENTCOM'] },
    { name: 'Phase 2: Strike', description: 'Shamoon deployed to Saudi, UAE, Kuwait oil companies. SCADA targeted simultaneously.', blueTeamOptions: ['Isolate affected networks', 'Manual oil production operations', 'Activate oil sector IR', 'Request CYBERCOM assistance'] },
    { name: 'Phase 3: Impact', description: 'Oil production reduced 30%. Global prices spiking. Proxy groups launching cyber attacks.', blueTeamOptions: ['Activate strategic petroleum reserves', 'Deploy international assistance', 'Coordinate energy market stabilization', 'Assess response options'] },
    { name: 'Phase 4: Response', description: 'Decision on counter-operations. Diplomatic pressure mounting.', blueTeamOptions: ['Authorize defensive ops against Iranian C2', 'Coordinate diplomatic response', 'Deploy long-term recovery', 'Implement follow-on monitoring'] }
  ] },
  { id: 'ws-005', codename: 'CASCADE ZERO', description: 'Coordinated multi-nation attack on internet infrastructure: BGP, DNS root, undersea cables', adversary: 'Coalition (Russia + China + Iran)', difficulty: 5, estimatedDuration: '5 hours', phases: [
    { name: 'Phase 1: Signals', description: 'BGP anomalies affecting 5% of global routing. DNS roots under DDoS. Cable anomalies in 3 oceans.', blueTeamOptions: ['Alert ICANN and root operators', 'Activate emergency BGP filtering', 'Deploy cable monitoring', 'Brief international partners'] },
    { name: 'Phase 2: Fragmentation', description: 'Internet degrading globally. Cloud providers losing inter-region connectivity.', blueTeamOptions: ['Activate internet resilience protocols', 'Deploy satellite alternative routing', 'Coordinate ISP emergency peering', 'Activate national internet plans'] },
    { name: 'Phase 3: Isolation', description: 'Countries losing connectivity. Markets halted. Military falling back to classified nets.', blueTeamOptions: ['Implement military PACE', 'Deploy emergency broadcast', 'Coordinate physical cable restoration', 'Activate continuity plans'] },
    { name: 'Phase 4: Restoration', description: 'Partial connectivity restoring. Attribution becoming clearer.', blueTeamOptions: ['Coordinate cable repair', 'Deploy clean DNS infrastructure', 'Implement RPKI enforcement', 'Plan diplomatic response'] }
  ] },
  { id: 'ws-006', codename: 'DARK HARVEST', description: 'Supply chain attack through major cloud provider affecting thousands of organizations', adversary: 'China (APT41)', difficulty: 4, estimatedDuration: '3.5 hours', phases: [
    { name: 'Phase 1: Discovery', description: 'Anomalous update pushed to 50,000+ cloud VMs. Backdoor detected by single analyst.', blueTeamOptions: ['Verify cloud agent integrity', 'Isolate compromised workloads', 'Alert cloud provider security', 'Begin forensic analysis'] },
    { name: 'Phase 2: Scope', description: 'Backdoor in 3 major cloud providers. Government workloads potentially compromised.', blueTeamOptions: ['Emergency cloud migration', 'Deploy exfiltration monitoring', 'Coordinate CISA emergency directive', 'Brief affected agencies'] },
    { name: 'Phase 3: Response', description: 'Clean agent deploying. Attacker activating second-stage before losing access.', blueTeamOptions: ['Accelerate clean deployment', 'Network-level C2 blocking', 'Deploy damage assessment', 'Coordinate with intel community'] },
    { name: 'Phase 4: Recovery', description: 'Hundreds of orgs still compromised. Cloud trust severely damaged.', blueTeamOptions: ['Mandatory agent verification', 'Zero-trust for cloud management', 'Industry-wide supply chain review', 'Establish new cloud security standards'] }
  ] },
  { id: 'ws-007', codename: 'SILENT FALL', description: 'Insider threat plus nation-state APT accessing classified military networks', adversary: 'Russia (SVR) + insider', difficulty: 4, estimatedDuration: '3 hours', phases: [
    { name: 'Phase 1: Recruitment', description: 'SVR-recruited insider provides VPN credentials to classified enclave.', blueTeamOptions: ['Activate insider threat program', 'Deploy user behavior analytics', 'Review privileged access logs', 'Implement continuous vetting'] },
    { name: 'Phase 2: Lateral Movement', description: 'APT29 moving through classified networks. JWICS and SIPRNet accessed.', blueTeamOptions: ['Emergency credential rotation', 'Network segmentation enforcement', 'Activate counterintelligence', 'Brief DNI'] },
    { name: 'Phase 3: Exfiltration', description: 'Classified documents being staged. Insider providing physical media.', blueTeamOptions: ['Emergency access revocation', 'Physical security measures', 'Coordinate with FBI CI', 'Activate damage assessment'] },
    { name: 'Phase 4: Damage Assessment', description: 'Multiple SAPs potentially affected. Insider arrested.', blueTeamOptions: ['Full damage assessment', 'Remediation across programs', 'Brief Congressional intel committees', 'Deploy enhanced monitoring'] }
  ] },
  { id: 'ws-008', codename: 'LIGHTNING STRIKE', description: 'Simultaneous ransomware on US hospitals during pandemic surge', adversary: 'Russian ransomware groups (coordinated)', difficulty: 4, estimatedDuration: '3 hours', phases: [
    { name: 'Phase 1: Warning', description: 'Intel indicates LockBit, BlackCat, and Cl0p coordinating hospital targeting.', blueTeamOptions: ['Alert HHS and H-ISAC', 'Emergency hospital patching', 'Activate healthcare cyber response', 'Brief hospitals on threat'] },
    { name: 'Phase 2: Impact', description: '35 hospitals across 12 states hit simultaneously. EHR encrypted. Patients diverted.', blueTeamOptions: ['Activate HHS emergency response', 'Deploy patient diversion plans', 'Paper-based records fallback', 'Request National Guard support'] },
    { name: 'Phase 3: Crisis', description: 'Patient deaths attributed to delays. More hospitals being hit.', blueTeamOptions: ['Deploy emergency medical teams', 'Activate FEMA health protocols', 'Coordinate national response', 'Consider ransom for life-threatening cases'] },
    { name: 'Phase 4: Resolution', description: 'Decryption keys obtained. Recovery beginning.', blueTeamOptions: ['Deploy decryption', 'Authorize CYBERCOM offensive', 'Long-term healthcare resilience plan', 'Brief Congress on cyber gaps'] }
  ] },
  { id: 'ws-009', codename: 'POLAR VORTEX', description: 'Russian attack on European gas distribution during extreme winter', adversary: 'Russia (Sandworm)', difficulty: 4, estimatedDuration: '3 hours', phases: [
    { name: 'Phase 1: Setup', description: 'Record cold. Russian gas restrictions. Sandworm probing gas distribution SCADA.', blueTeamOptions: ['Alert European energy CERTs', 'Deploy ICS monitoring to gas', 'Verify backup heating', 'Coordinate EU energy plans'] },
    { name: 'Phase 2: Attack', description: 'Gas SCADA in 4 EU countries compromised. Pressure regulation manipulated.', blueTeamOptions: ['Manual gas operations', 'Emergency heating for vulnerable populations', 'ICS emergency shutdown', 'Coordinate with EU energy ministers'] },
    { name: 'Phase 3: Humanitarian Crisis', description: 'Heating failures across cities. Hospitals and elderly care losing heat.', blueTeamOptions: ['Military emergency heating', 'Civil emergency shelters', 'International energy assistance', 'Brief NATO on Article 5'] },
    { name: 'Phase 4: Stabilization', description: 'Manual operations restoring service. Attribution confirmed.', blueTeamOptions: ['Complete restoration', 'Long-term SCADA upgrades', 'NATO unified response', 'Enhanced follow-on monitoring'] }
  ] },
  { id: 'ws-010', codename: 'RED HAND', description: 'Iran and proxies launch coordinated cyber campaign against Israel', adversary: 'Iran (IRGC + proxies)', difficulty: 4, estimatedDuration: '3 hours', phases: [
    { name: 'Phase 1: Escalation', description: 'Military tensions spike. Multiple Iranian APTs activating. Hezbollah cyber coordinating.', blueTeamOptions: ['Activate Israel Cyber Directorate', 'Deploy Unit 8200 defensive teams', 'Brief infrastructure operators', 'Coordinate with CYBERCOM'] },
    { name: 'Phase 2: Multi-APT Strike', description: 'APT33 wipers against utilities. APT35 harvesting defense credentials. Moses Staff leaking data.', blueTeamOptions: ['Sector-specific defenses', 'Wiper containment', 'Military network isolation', 'Intelligence sharing with allies'] },
    { name: 'Phase 3: Critical Impact', description: 'Power grid fluctuations. Water SCADA compromised. Iron Dome systems targeted.', blueTeamOptions: ['Backup military systems', 'Manual critical infrastructure ops', 'Emergency cyber defense measures', 'Authorize offensive operations'] },
    { name: 'Phase 4: Counter-Operations', description: 'Decision to launch counter-cyber ops against Iranian infrastructure.', blueTeamOptions: ['Execute counter-operations', 'Coordinate allied support', 'Long-term defensive hardening', 'Pursue diplomatic de-escalation'] }
  ] },
  { id: 'ws-011', codename: 'GHOST PROTOCOL', description: 'Zero-day in critical open source crypto library affecting 90% of web servers', adversary: 'Unknown nation-state', difficulty: 5, estimatedDuration: '4 hours', phases: [
    { name: 'Phase 1: Discovery', description: 'Backdoor found in crypto library used by 90% of web servers. Present for 6 months.', blueTeamOptions: ['Verify backdoor scope', 'Assess affected systems', 'Coordinate disclosure', 'Prepare emergency advisory'] },
    { name: 'Phase 2: Assessment', description: 'Every major organization affected. Mass exploitation may have occurred.', blueTeamOptions: ['Issue CISA emergency advisory', 'Coordinate global patching', 'Deploy compromise assessment', 'Brief international CERTs'] },
    { name: 'Phase 3: Exploitation Evidence', description: 'Selective exploitation against intel targets. Attribution emerging. Second backdoor found.', blueTeamOptions: ['Expand forensic investigation', 'Complete library replacement', 'Coordinate intel assessment', 'Monitor second backdoor'] },
    { name: 'Phase 4: Long-term', description: 'Full scope uncertain. Open source trust model questioned.', blueTeamOptions: ['SBOM requirements', 'Automated dependency verification', 'Funded open source security', 'International supply chain standards'] }
  ] },
  { id: 'ws-012', codename: 'STEEL RAIN', description: 'Coordinated attack on SWIFT, stock exchanges, and central banks', adversary: 'Multiple threat actors', difficulty: 5, estimatedDuration: '4 hours', phases: [
    { name: 'Phase 1: Indicators', description: 'SWIFT delays. Stock exchange order matching erratic. Multiple anomalies simultaneously.', blueTeamOptions: ['Alert FS-ISAC and Treasury', 'Deploy financial IR', 'Activate circuit breakers', 'Brief Fed and SEC'] },
    { name: 'Phase 2: Market Impact', description: 'NYSE/NASDAQ flash crash. SWIFT halted. Major banks compromised.', blueTeamOptions: ['Halt electronic trading', 'SWIFT contingency procedures', 'Deploy FBI Financial Crimes', 'Coordinate international regulators'] },
    { name: 'Phase 3: Cascade', description: 'Asian/European markets in chaos. Central banks compromised. Lazarus hitting crypto simultaneously.', blueTeamOptions: ['Global market halt', 'Deploy international cyber response', 'Emergency financial communications', 'Brief G7 finance ministers'] },
    { name: 'Phase 4: Stabilization', description: 'Financial integrity being verified. Public confidence severely damaged.', blueTeamOptions: ['Verify integrity before restart', 'Emergency liquidity provisions', 'Enhanced follow-on monitoring', 'International recovery plan'] }
  ] },
  { id: 'ws-013', codename: 'SAND SPIDER', description: 'AI-generated deepfakes combined with zero-day for government infiltration', adversary: 'Advanced nation-state', difficulty: 5, estimatedDuration: '3.5 hours', phases: [
    { name: 'Phase 1: Social Engineering', description: 'Deepfake video calls impersonate senior officials. Video platform zero-day exploited.', blueTeamOptions: ['Deploy deepfake detection', 'Out-of-band identity verification', 'Audit video platform security', 'Alert all agencies'] },
    { name: 'Phase 2: Access', description: 'Harvested credentials used across agencies. AI-powered lateral movement evading EDR.', blueTeamOptions: ['Emergency credential rotation', 'AI-aware detection systems', 'Activate threat hunting', 'Network micro-segmentation'] },
    { name: 'Phase 3: Collection', description: 'Classified material exfiltrated. AI prioritizing highest-value documents.', blueTeamOptions: ['Emergency DLP', 'Deploy deception technology', 'Coordinate multi-agency response', 'Brief oversight committees'] },
    { name: 'Phase 4: Attribution', description: 'Novel TTPs making attribution difficult. AI-generated false flags embedded.', blueTeamOptions: ['Advanced attribution analysis', 'Five Eyes sharing', 'Long-term re-entry monitoring', 'AI-specific defensive capabilities'] }
  ] },
  { id: 'ws-014', codename: 'BLACK TIDE', description: 'Attack on port management and maritime navigation causing shipping disruptions', adversary: 'China (PLA Navy Cyber)', difficulty: 3, estimatedDuration: '2.5 hours', phases: [
    { name: 'Phase 1: Reconnaissance', description: 'Scanning of US West Coast port management. AIS anomalies. Container tracking probed.', blueTeamOptions: ['Alert Maritime Transportation ISAC', 'Deploy port OT monitoring', 'Verify AIS integrity', 'Brief Coast Guard Cyber'] },
    { name: 'Phase 2: Attack', description: 'Crane management locked at 3 ports. Container tracking corrupted. Ship scheduling offline.', blueTeamOptions: ['Manual port operations', 'Deploy Coast Guard cyber', 'Activate port backups', 'Coordinate with CBP and DOT'] },
    { name: 'Phase 3: Supply Chain Impact', description: 'Major shipping delays. Just-in-time manufacturing affected. Military logistics disrupted.', blueTeamOptions: ['Alternative port facilities', 'Military logistics support', 'Coordinate international shipping', 'Assess military readiness impact'] },
    { name: 'Phase 4: Restoration', description: 'Port systems being restored. Maritime OT security lessons learned.', blueTeamOptions: ['Restore with enhanced security', 'Maritime OT security standards', 'International port cooperation', 'Deploy permanent OT monitoring'] }
  ] },
  { id: 'ws-015', codename: 'PHANTOM PULSE', description: 'EMP weapon combined with cyber attack on backup systems creating cascading failure', adversary: 'Advanced nation-state (hybrid)', difficulty: 5, estimatedDuration: '4.5 hours', phases: [
    { name: 'Phase 1: EMP Event', description: 'High-altitude EMP over mid-Atlantic. Electronics in 500-mile radius disrupted.', blueTeamOptions: ['Activate FEMA emergency', 'Assess electronics damage scope', 'Deploy military communications', 'Brief National Command Authority'] },
    { name: 'Phase 2: Cyber Compound', description: 'Surviving backup systems targeted by pre-positioned cyber implants.', blueTeamOptions: ['Isolate backups from network', 'Manual backup procedures', 'Faraday-protected communications', 'Military cyber defense'] },
    { name: 'Phase 3: Cascading Failure', description: 'No electronic backup. Nuclear cooling on emergency diesel. Hospital generators failing.', blueTeamOptions: ['Military emergency response', 'Nuclear emergency protocols', 'Manual hospital operations', 'Mass evacuation if needed'] },
    { name: 'Phase 4: National Response', description: 'Federal emergency declared. Military deploying for restoration.', blueTeamOptions: ['Army Corps of Engineers', 'National grid restoration plan', 'International assistance', 'Strategic response assessment'] }
  ] },
  { id: 'ws-016', codename: 'OPERATION BLACKOUT', description: 'China-linked APT pre-positioned in US power grid activates during Taiwan Strait crisis. Living-off-the-land tactics make detection extremely difficult. Power outages cascade across interconnected grids.', adversary: 'China (Volt Typhoon)', difficulty: 5, estimatedDuration: '5 hours', phases: [
    { name: 'Phase 1: Geopolitical Crisis', description: 'PLA naval exercises intensify around Taiwan. Volt Typhoon LOTL implants receive encrypted activation beacon via compromised SOHO routers.', blueTeamOptions: ['Activate CISA Shields Up directive', 'Deploy LOTL hunt teams to ICS/SCADA', 'Audit all SOHO router firmware in critical infrastructure', 'Elevate CYBERCOM readiness'] },
    { name: 'Phase 2: Silent Activation', description: 'No malware detected — adversary using native OS tools (PowerShell, WMI, ntdsutil). Subtle SCADA parameter changes in 6 utilities. Grid operators report "instrument drift."', blueTeamOptions: ['Deploy behavioral analytics on admin tools', 'Cross-reference SCADA anomalies across utilities', 'Implement emergency manual verification protocols', 'Activate DOE CESER rapid response'] },
    { name: 'Phase 3: Cascading Outage', description: 'Three interconnected grids experience simultaneous protection relay manipulation. 12 million customers lose power. Natural gas compressor stations disrupted.', blueTeamOptions: ['Execute grid islanding procedures', 'Deploy National Guard for civil order', 'Activate FEMA emergency shelters', 'Authorize CYBERCOM hunt-forward to identify C2'] },
    { name: 'Phase 4: Escalation Decision', description: 'Water treatment affected. Hospitals on generator backup (48hr fuel). Military logistics degrading. President briefed on proportional response options.', blueTeamOptions: ['Authorize offensive cyber against Volt Typhoon C2', 'Deploy military mobile power generation', 'Coordinate Five Eyes intelligence sharing', 'Brief Congress and prepare public communication'] },
    { name: 'Phase 5: Strategic Response', description: 'Attribution confirmed. International coalition forming. China denying involvement. Military contingency plans activated.', blueTeamOptions: ['Execute proportional cyber response', 'Coordinate allied diplomatic pressure', 'Implement long-term grid hardening plan', 'Establish new critical infrastructure cyber requirements'] }
  ] },
  { id: 'ws-017', codename: 'CASCADE FAILURE', description: 'Supply chain attack through a top-5 MSP compromises 1,200+ downstream organizations simultaneously. Attackers deployed RMM tool backdoor that persists through the MSP\'s own patch cycle.', adversary: 'Russia (APT41-linked criminal group)', difficulty: 4, estimatedDuration: '4 hours', phases: [
    { name: 'Phase 1: Discovery', description: 'Single SOC analyst notices anomalous outbound connections from MSP-managed agent. Investigation reveals trojanized update pushed 72 hours ago.', blueTeamOptions: ['Isolate MSP agent communication channels', 'Alert CISA and FBI immediately', 'Begin identifying all downstream customers', 'Deploy memory forensics on affected endpoints'] },
    { name: 'Phase 2: Scope Explosion', description: '1,200+ organizations confirmed affected — including 3 federal agencies, 47 hospitals, and 12 defense contractors. Media begins reporting.', blueTeamOptions: ['Issue CISA Emergency Directive', 'Coordinate MSP to push kill-switch update', 'Deploy mass IOC sharing through ISACs', 'Establish multi-victim coordination center'] },
    { name: 'Phase 3: Second Stage', description: 'Attackers deploying ransomware to high-value targets before losing access. Data exfiltration detected from defense contractors. Some victims discovering data already on dark web.', blueTeamOptions: ['Priority containment for defense/gov/healthcare', 'Activate FBI Cyber Division multi-victim response', 'Coordinate ransom payment policy across victims', 'Deploy emergency backup restoration'] },
    { name: 'Phase 4: Recovery Coordination', description: 'MSP issues clean agent. 600+ organizations still recovering. Congressional hearings announced. MSP facing collapse.', blueTeamOptions: ['Coordinated clean agent deployment', 'Establish victim financial support program', 'Draft MSP security regulation proposal', 'Implement mandatory SBOM and build verification requirements'] }
  ] },
  { id: 'ws-018', codename: 'DIGITAL PEARL HARBOR', description: 'Simultaneous multi-domain cyber attack: SWIFT financial messaging disrupted, GPS constellation spoofed over Pacific theater, and 4 undersea cables physically severed. Full-spectrum cyber warfare scenario.', adversary: 'Coalition (Russia + China coordinated)', difficulty: 5, estimatedDuration: '6 hours', phases: [
    { name: 'Phase 1: First Strikes', description: 'SWIFT reports processing failures in Asian and European corridors. GPS accuracy degrades across Western Pacific. Cable monitoring detects breaks on 4 Pacific cables simultaneously.', blueTeamOptions: ['Activate SWIFT contingency messaging', 'Deploy military GPS anti-spoofing (SAASM/M-code)', 'Reroute internet traffic via surviving cables', 'Brief National Security Council immediately'] },
    { name: 'Phase 2: Financial Chaos', description: 'Stock exchanges halting globally. $40T in daily transactions frozen. Cryptocurrency markets collapse 60% as automated trading fails. Central bank digital infrastructure targeted.', blueTeamOptions: ['Invoke emergency market halt procedures', 'Activate Federal Reserve emergency liquidity', 'Deploy backup financial communication channels', 'Coordinate G7 finance minister emergency call'] },
    { name: 'Phase 3: Military Degradation', description: 'INDOPACOM loses 40% satellite bandwidth. GPS-guided munitions unreliable. Military logistics management systems compromised. Inertial navigation fallback activated.', blueTeamOptions: ['Activate military PACE communication plan', 'Deploy SATCOM contingency constellation', 'Switch to inertial/celestial navigation', 'Invoke NATO Article 5 cyber provisions'] },
    { name: 'Phase 4: Attribution and Response', description: 'Intelligence confirms coordinated Russia-China operation. Cable ships deployed for repair (6-8 weeks). Financial system integrity verification required before restart.', blueTeamOptions: ['Authorize proportional offensive cyber operations', 'Coordinate international diplomatic response', 'Deploy naval protection for cable repair ships', 'Establish new resilience requirements for critical systems'] },
    { name: 'Phase 5: New Equilibrium', description: 'Markets partially restored after 96 hours. GPS restored with authentication. Cables under repair. Geopolitical landscape fundamentally altered.', blueTeamOptions: ['Implement financial system redundancy', 'Deploy sovereign cable monitoring', 'Mandate GPS authentication nationwide', 'Establish new deterrence doctrine'] }
  ] },
  { id: 'ws-019', codename: 'GHOST PROTOCOL', description: 'Discovery that a trusted allied nation\'s intelligence service planted backdoors in security products your organization relies on. Your firewalls, EDR, and PKI infrastructure may be compromised by an ally conducting espionage on your programs.', adversary: 'Allied nation intelligence service', difficulty: 5, estimatedDuration: '4.5 hours', phases: [
    { name: 'Phase 1: Whistleblower Alert', description: 'Contractor discloses evidence of firmware-level implants in ally-manufactured firewall appliances deployed across your classified networks. Initial verification confirms anomalous behavior.', blueTeamOptions: ['Restrict knowledge to minimal cleared team', 'Begin silent firmware analysis in isolated lab', 'Verify disclosure authenticity without alerting ally', 'Brief agency director under compartmented channels'] },
    { name: 'Phase 2: Scope Assessment', description: 'Implants confirmed in 3 security product lines from allied vendor. Affects firewalls, EDR agents, and HSMs. 5 classified programs potentially exposed over 2+ years.', blueTeamOptions: ['Map all affected products across enterprise', 'Assess which classified programs are exposed', 'Deploy alternative monitoring bypassing compromised tools', 'Begin damage assessment of accessed intelligence'] },
    { name: 'Phase 3: Diplomatic Crisis', description: 'Decision on whether to confront ally. Other agencies using same products. Risk of intelligence relationship collapse if public. Ally may have access to nuclear program data.', blueTeamOptions: ['Coordinate interagency assessment', 'Begin quiet replacement of compromised products', 'Develop diplomatic engagement strategy', 'Assess counterintelligence implications'] },
    { name: 'Phase 4: Remediation', description: 'Full product replacement underway. Intelligence damage assessment ongoing. Diplomatic channel opened. Trust framework for security products questioned.', blueTeamOptions: ['Complete product replacement with domestic alternatives', 'Implement hardware root-of-trust verification', 'Establish new allied technology trust framework', 'Reform security product supply chain requirements'] }
  ] },
  { id: 'ws-020', codename: 'RANSOMWARE PANDEMIC', description: 'LockBit 4.0 affiliates deploy ransomware to 50+ hospitals simultaneously via a compromised healthcare SaaS platform. Mass casualty threat as EHR, imaging, and pharmacy systems go offline.', adversary: 'LockBit affiliates (Russian-speaking)', difficulty: 4, estimatedDuration: '4 hours', phases: [
    { name: 'Phase 1: Mass Deployment', description: 'Emergency calls from 50+ hospitals across 22 states. EHR encrypted. Pharmacy dispensing offline. Imaging systems dark. Ventilator monitoring degraded. Multiple hospitals declaring internal disasters.', blueTeamOptions: ['Activate HHS ASPR emergency response', 'Deploy paper-based clinical workflows', 'Issue nationwide hospital alert via H-ISAC', 'Request CISA emergency support teams'] },
    { name: 'Phase 2: Patient Safety Crisis', description: 'Patient diversions overwhelming neighboring hospitals. 3 patients in critical condition due to medication errors from paper-based systems. Media coverage escalating. $50M collective ransom demand.', blueTeamOptions: ['Deploy military medical teams to hardest-hit hospitals', 'Activate NDMS (National Disaster Medical System)', 'Coordinate patient transfer logistics', 'Establish FBI negotiation channel with threat actor'] },
    { name: 'Phase 3: Response Decision', description: 'President briefed. Debate on federal response — pay ransom for life-threatening cases vs. no-concessions policy. More hospitals hit. LockBit offering "hospital discount."', blueTeamOptions: ['Authorize emergency decryption key purchase for critical care', 'Deploy CYBERCOM offensive against LockBit infrastructure', 'Activate FEMA for mass casualty logistics', 'Coordinate international law enforcement takedown'] },
    { name: 'Phase 4: Recovery and Reform', description: 'Decryption keys obtained through combination of payment and law enforcement action. 2 weeks to full recovery. 7 patient deaths attributed to delays.', blueTeamOptions: ['Coordinate national hospital recovery', 'Mandatory healthcare cybersecurity standards', 'Ban ransom payments with government waiver process', 'Establish healthcare cyber reserve fund'] }
  ] },
  { id: 'ws-021', codename: 'ZERO TRUST ZERO DAY', description: 'Zero-day RCE in a ubiquitous identity provider (think Okta/Azure AD scale) gives attackers bypass access to every organization using it — 100,000+ tenants, including most of the Fortune 500 and US government.', adversary: 'China (Storm-0558 evolution)', difficulty: 5, estimatedDuration: '5 hours', phases: [
    { name: 'Phase 1: Silent Exploitation', description: 'Threat actor has been exploiting the zero-day for 3 weeks. Token forging allows access to any tenant without credentials. Discovery happens when a CISO notices impossible travel alert that clears MFA.', blueTeamOptions: ['Emergency coordination with identity provider', 'Audit all authentication logs for token anomalies', 'Deploy out-of-band authentication for critical systems', 'Issue CISA Emergency Directive'] },
    { name: 'Phase 2: Scale Revealed', description: 'Analysis reveals 15,000+ tenants accessed. Attackers prioritized government, defense, energy, financial. Selective data exfiltration confirmed. Identity provider unable to determine full scope.', blueTeamOptions: ['Force global token revocation and re-authentication', 'Deploy temporary SSO bypass for critical operations', 'Coordinate multi-sector compromise assessment', 'Brief Congressional intelligence committees'] },
    { name: 'Phase 3: Authentication Collapse', description: 'Mass credential rotation causes service outages. Organizations cannot verify which sessions are legitimate. Shadow IT and bypass credentials emerge. Productivity halted across millions of workers.', blueTeamOptions: ['Phased re-enrollment with identity verification', 'Deploy hardware token requirements for privileged access', 'Establish emergency authentication alternatives', 'Coordinate with cloud providers for tenant verification'] },
    { name: 'Phase 4: Trust Architecture', description: 'Zero-day patched. Forensics ongoing. Identity provider trust model questioned. Debate on identity monoculture risk.', blueTeamOptions: ['Mandate multi-provider identity architecture', 'Require phishing-resistant MFA for all government', 'Establish identity provider security audit requirements', 'Fund development of decentralized identity alternatives'] },
    { name: 'Phase 5: Post-Mortem', description: 'Full scope: 3,200 organizations compromised, 800 with confirmed data theft. Identity provider stock down 60%. Class action lawsuits filed.', blueTeamOptions: ['Establish identity provider liability framework', 'Implement continuous identity provider security monitoring', 'Reform cloud security shared responsibility model', 'Create national identity resilience strategy'] }
  ] }
];
