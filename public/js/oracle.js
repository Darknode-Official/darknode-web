// ORACLE — Omniscient Reconnaissance, Analysis, Campaign & Lookup Engine
// Browser-based threat intelligence platform for Darknode
// Copyright (c) 2026 Darknode-Official. All rights reserved.

const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// ============================================================================
// THREAT ACTOR DATABASE (30+ APT groups)
// ============================================================================
const APT_DB = [
  { id: 'apt28', name: 'APT28', aliases: ['Fancy Bear', 'Sofacy', 'Sednit', 'STRONTIUM'], nation: 'Russia', agency: 'GRU Unit 26165', motivation: 'Espionage', sectors: ['Government', 'Military', 'Media', 'Energy'], since: 2004, techniques: ['T1566', 'T1059', 'T1027', 'T1071', 'T1078', 'T1190'], campaigns: ['DNC Hack 2016', 'Bundestag Attack', 'IAAF Breach'], iocs: ['185.86.148.0/24', 'sednitspy.com', '5d2b4e3c7a1f8e9d0b6c'] },
  { id: 'apt29', name: 'APT29', aliases: ['Cozy Bear', 'The Dukes', 'NOBELIUM', 'Midnight Blizzard'], nation: 'Russia', agency: 'SVR', motivation: 'Espionage', sectors: ['Government', 'Think Tanks', 'Healthcare', 'Technology'], since: 2008, techniques: ['T1195', 'T1059', 'T1071', 'T1027', 'T1053', 'T1098'], campaigns: ['SolarWinds', 'COVID-19 Vaccine Theft', 'Microsoft 365 Abuse'], iocs: ['avsvmcloud.com', '13.59.205.66', 'dblbnd4jx3ftgd'] },
  { id: 'lazarus', name: 'Lazarus Group', aliases: ['Hidden Cobra', 'Zinc', 'Diamond Sleet'], nation: 'North Korea', agency: 'RGB', motivation: 'Financial / Espionage', sectors: ['Finance', 'Cryptocurrency', 'Defense', 'Entertainment'], since: 2009, techniques: ['T1566', 'T1204', 'T1059', 'T1055', 'T1486', 'T1048'], campaigns: ['Sony Pictures 2014', 'Bangladesh Bank Heist', 'WannaCry', 'Ronin Bridge'], iocs: ['lazarusgroup.xyz', '175.45.176.0/22', 'a7d3c2f1e8b6'] },
  { id: 'sandworm', name: 'Sandworm', aliases: ['Voodoo Bear', 'IRIDIUM', 'Seashell Blizzard'], nation: 'Russia', agency: 'GRU Unit 74455', motivation: 'Sabotage / Espionage', sectors: ['Energy', 'Government', 'Media', 'Telecom'], since: 2009, techniques: ['T1195', 'T1059', 'T1486', 'T1498', 'T1561', 'T1021'], campaigns: ['NotPetya', 'Ukraine Power Grid 2015/2016', 'Olympic Destroyer'], iocs: ['sandwormops.net', '91.245.228.0/24', 'e3b0c44298fc'] },
  { id: 'equation', name: 'Equation Group', aliases: ['EQGRP', 'Tilded Platform'], nation: 'United States', agency: 'NSA TAO', motivation: 'Espionage', sectors: ['Government', 'Telecom', 'Energy', 'Finance', 'Military'], since: 2001, techniques: ['T1195', 'T1542', 'T1027', 'T1059', 'T1014', 'T1132'], campaigns: ['Stuxnet', 'Flame', 'DoubleFantasy'], iocs: ['eqgrp-auction.com', '149.5.0.0/16', 'f4ec62e4a2'] },
  { id: 'turla', name: 'Turla', aliases: ['Snake', 'Venomous Bear', 'Uroburos', 'Krypton'], nation: 'Russia', agency: 'FSB Center 16', motivation: 'Espionage', sectors: ['Government', 'Military', 'Education', 'Research'], since: 2004, techniques: ['T1071', 'T1059', 'T1027', 'T1041', 'T1055', 'T1001'], campaigns: ['Moonlight Maze', 'Pentagon Breach 2008', 'Snake Campaign'], iocs: ['turla-apt.net', '80.255.3.0/24', 'c8e4b7a1d2f3'] },
  { id: 'charming-kitten', name: 'Charming Kitten', aliases: ['APT35', 'Phosphorus', 'Mint Sandstorm'], nation: 'Iran', agency: 'IRGC', motivation: 'Espionage / Surveillance', sectors: ['Government', 'Media', 'Academics', 'Dissidents', 'Defense'], since: 2014, techniques: ['T1566', 'T1078', 'T1539', 'T1204', 'T1059', 'T1555'], campaigns: ['Operation SpoofedScholars', 'HBO Hack', 'Election Interference'], iocs: ['charmkitten.ir', '185.141.63.0/24', 'a9d2c3b4e5f6'] },
  { id: 'hafnium', name: 'Hafnium', aliases: ['Silk Typhoon'], nation: 'China', agency: 'MSS', motivation: 'Espionage', sectors: ['Defense', 'Research', 'Healthcare', 'Legal', 'NGO'], since: 2017, techniques: ['T1190', 'T1059', 'T1003', 'T1567', 'T1027', 'T1505'], campaigns: ['ProxyLogon Exchange 2021'], iocs: ['hafnium-c2.com', '203.160.69.0/24', 'b3c7d1e8f2a4'] },
  { id: 'mustang-panda', name: 'Mustang Panda', aliases: ['Bronze President', 'TA416', 'RedDelta'], nation: 'China', agency: 'MSS/PLA', motivation: 'Espionage', sectors: ['Government', 'NGO', 'Think Tanks', 'Telecom'], since: 2014, techniques: ['T1566', 'T1204', 'T1059', 'T1071', 'T1105', 'T1053'], campaigns: ['Southeast Asia Espionage', 'European Diplomatic Targets'], iocs: ['mustangpanda.cn', '103.56.53.0/24', 'd7e9f1a2b3c4'] },
  { id: 'oceanlotus', name: 'OceanLotus', aliases: ['APT32', 'Canvas Cyclone'], nation: 'Vietnam', agency: 'MPS', motivation: 'Espionage', sectors: ['Government', 'Media', 'Manufacturing', 'Dissidents'], since: 2012, techniques: ['T1566', 'T1059', 'T1055', 'T1071', 'T1027', 'T1547'], campaigns: ['Southeast Asia Espionage', 'COVID-19 Research Theft'], iocs: ['oceanlotus.vn', '45.32.100.0/24', 'e2f4a6b8c1d3'] },
  { id: 'kimsuky', name: 'Kimsuky', aliases: ['Thallium', 'Velvet Chollima', 'Emerald Sleet'], nation: 'North Korea', agency: 'RGB', motivation: 'Espionage / Intel Collection', sectors: ['Government', 'Think Tanks', 'Academics', 'Media'], since: 2012, techniques: ['T1566', 'T1204', 'T1059', 'T1056', 'T1114', 'T1005'], campaigns: ['Operation Baby Coin', 'Korean Unification Lure'], iocs: ['kimsuky-apt.kr', '175.45.178.0/24', 'f1a2b3c4d5e6'] },
  { id: 'winnti', name: 'Winnti', aliases: ['APT41', 'Wicked Panda', 'Brass Typhoon'], nation: 'China', agency: 'MSS', motivation: 'Financial / Espionage', sectors: ['Gaming', 'Technology', 'Healthcare', 'Telecom', 'Finance'], since: 2010, techniques: ['T1195', 'T1059', 'T1055', 'T1071', 'T1027', 'T1003'], campaigns: ['ShadowPad', 'CCleaner Supply Chain', 'Operation CuckooBees'], iocs: ['winnti-group.cn', '180.76.76.0/24', 'a1b2c3d4e5f6'] },
  { id: 'fin7', name: 'FIN7', aliases: ['Carbanak', 'Navigator Group', 'Sangria Tempest'], nation: 'Russia', agency: 'Criminal', motivation: 'Financial', sectors: ['Retail', 'Hospitality', 'Finance', 'Restaurant'], since: 2013, techniques: ['T1566', 'T1059', 'T1055', 'T1071', 'T1005', 'T1048'], campaigns: ['Carbanak Bank Heists', 'POS Malware Campaign', 'Fake Security Company'], iocs: ['fin7-apt.ru', '5.188.86.0/24', 'b2c3d4e5f6a7'] },
  { id: 'darkhotel', name: 'DarkHotel', aliases: ['Luder', 'Tapaoux'], nation: 'South Korea', agency: 'Unknown', motivation: 'Espionage', sectors: ['Government', 'Defense', 'Business Executives'], since: 2007, techniques: ['T1189', 'T1566', 'T1059', 'T1027', 'T1056', 'T1071'], campaigns: ['Hotel WiFi Attacks', 'Zero-day Exploit Campaigns'], iocs: ['darkhotel-apt.kr', '121.78.148.0/24', 'c3d4e5f6a7b8'] },
  { id: 'gamaredon', name: 'Gamaredon', aliases: ['Primitive Bear', 'Actinium', 'Aqua Blizzard'], nation: 'Russia', agency: 'FSB Crimea', motivation: 'Espionage', sectors: ['Government', 'Military', 'Law Enforcement'], since: 2013, techniques: ['T1566', 'T1059', 'T1204', 'T1547', 'T1071', 'T1105'], campaigns: ['Ukraine Government Espionage', 'Crimean Targeting'], iocs: ['gamaredon.ru', '194.58.92.0/24', 'd4e5f6a7b8c9'] },
  { id: 'sidewinder', name: 'SideWinder', aliases: ['Rattlesnake', 'T-APT-04'], nation: 'India', agency: 'Unknown', motivation: 'Espionage', sectors: ['Government', 'Military', 'Diplomacy'], since: 2012, techniques: ['T1566', 'T1203', 'T1059', 'T1071', 'T1105', 'T1027'], campaigns: ['South Asia Military Espionage', 'Pakistani Government Targeting'], iocs: ['sidewinder.in', '103.82.24.0/24', 'e5f6a7b8c9d1'] },
  { id: 'patchwork', name: 'Patchwork', aliases: ['Dropping Elephant', 'Monsoon'], nation: 'India', agency: 'Unknown', motivation: 'Espionage', sectors: ['Government', 'Think Tanks', 'Defense'], since: 2015, techniques: ['T1566', 'T1059', 'T1204', 'T1027', 'T1071', 'T1547'], campaigns: ['South Asian Diplomatic Espionage'], iocs: ['patchwork-apt.in', '103.100.130.0/24', 'f6a7b8c9d1e2'] },
  { id: 'muddywater', name: 'MuddyWater', aliases: ['Mercury', 'Mango Sandstorm', 'Static Kitten'], nation: 'Iran', agency: 'MOIS', motivation: 'Espionage', sectors: ['Government', 'Telecom', 'Energy', 'Defense'], since: 2017, techniques: ['T1566', 'T1059', 'T1204', 'T1071', 'T1027', 'T1053'], campaigns: ['Middle East Espionage', 'Turkish Government Targeting'], iocs: ['muddywater.ir', '185.117.73.0/24', 'a7b8c9d1e2f3'] },
  { id: 'apt41', name: 'APT41', aliases: ['Double Dragon', 'Wicked Panda', 'Brass Typhoon'], nation: 'China', agency: 'MSS Contractor', motivation: 'Financial / Espionage', sectors: ['Technology', 'Healthcare', 'Gaming', 'Telecom', 'Education'], since: 2012, techniques: ['T1195', 'T1190', 'T1059', 'T1055', 'T1003', 'T1486'], campaigns: ['ShadowPad', 'Supply Chain Attacks', 'Ransomware Operations'], iocs: ['apt41-ops.cn', '118.193.78.0/24', 'b8c9d1e2f3a4'] },
  { id: 'apt10', name: 'APT10', aliases: ['menuPass', 'Stone Panda', 'Red Apollo'], nation: 'China', agency: 'MSS Tianjin', motivation: 'Espionage', sectors: ['MSP', 'Technology', 'Government', 'Defense', 'Finance'], since: 2006, techniques: ['T1199', 'T1059', 'T1071', 'T1003', 'T1048', 'T1027'], campaigns: ['Cloud Hopper', 'MSP Targeting'], iocs: ['apt10-cloud.cn', '210.209.89.0/24', 'c9d1e2f3a4b5'] },
  { id: 'apt33', name: 'APT33', aliases: ['Elfin', 'Refined Kitten', 'Peach Sandstorm'], nation: 'Iran', agency: 'IRGC', motivation: 'Espionage / Sabotage', sectors: ['Aviation', 'Energy', 'Petrochemical', 'Defense'], since: 2013, techniques: ['T1566', 'T1059', 'T1204', 'T1486', 'T1071', 'T1562'], campaigns: ['Shamoon Attacks', 'Aviation Sector Espionage'], iocs: ['apt33-ops.ir', '89.38.97.0/24', 'd1e2f3a4b5c6'] },
  { id: 'volt-typhoon', name: 'Volt Typhoon', aliases: ['Bronze Silhouette', 'Vanguard Panda'], nation: 'China', agency: 'PLA', motivation: 'Pre-positioning / Sabotage', sectors: ['Critical Infrastructure', 'Telecom', 'Energy', 'Water', 'Transport'], since: 2021, techniques: ['T1190', 'T1078', 'T1059', 'T1021', 'T1003', 'T1046'], campaigns: ['US Critical Infrastructure Pre-positioning', 'Guam Telecom Targeting'], iocs: ['volt-typhoon.cn', '103.27.108.0/24', 'e2f3a4b5c6d7'] },
  { id: 'salt-typhoon', name: 'Salt Typhoon', aliases: ['GhostEmperor', 'FamousSparrow'], nation: 'China', agency: 'MSS', motivation: 'Espionage', sectors: ['Telecom', 'ISP', 'Government'], since: 2020, techniques: ['T1190', 'T1059', 'T1021', 'T1005', 'T1071', 'T1027'], campaigns: ['US Telecom Infiltration 2024', 'Wiretap Infrastructure Access'], iocs: ['salt-typhoon.cn', '116.206.93.0/24', 'f3a4b5c6d7e8'] },
  { id: 'scattered-spider', name: 'Scattered Spider', aliases: ['0ktapus', 'UNC3944', 'Star Fraud'], nation: 'US/UK', agency: 'Criminal', motivation: 'Financial / Extortion', sectors: ['Technology', 'Telecom', 'Gaming', 'Hospitality', 'Finance'], since: 2022, techniques: ['T1566', 'T1621', 'T1078', 'T1199', 'T1486', 'T1657'], campaigns: ['MGM/Caesars Attack 2023', 'Okta Breaches', 'Twilio/Cloudflare'], iocs: ['0ktapus.dev', '45.134.142.0/24', 'a4b5c6d7e8f9'] },
  { id: 'alphv', name: 'ALPHV/BlackCat', aliases: ['BlackCat', 'Noberus'], nation: 'Russia', agency: 'Criminal (RaaS)', motivation: 'Financial / Extortion', sectors: ['Healthcare', 'Finance', 'Legal', 'Government', 'Energy'], since: 2021, techniques: ['T1486', 'T1490', 'T1078', 'T1059', 'T1021', 'T1048'], campaigns: ['Change Healthcare Attack 2024', 'MGM Resorts'], iocs: ['alphv-chat.onion', '193.233.75.0/24', 'b5c6d7e8f9a1'] },
  { id: 'lockbit', name: 'LockBit', aliases: ['ABCD Ransomware'], nation: 'Russia', agency: 'Criminal (RaaS)', motivation: 'Financial / Extortion', sectors: ['Manufacturing', 'Healthcare', 'Government', 'Finance', 'Education'], since: 2019, techniques: ['T1486', 'T1490', 'T1059', 'T1021', 'T1078', 'T1048'], campaigns: ['Royal Mail Attack', 'Boeing Data Leak', 'ICBC Financial Services'], iocs: ['lockbit-leak.onion', '91.132.92.0/24', 'c6d7e8f9a1b2'] },
  { id: 'clop', name: 'Cl0p', aliases: ['TA505', 'FIN11'], nation: 'Russia/Ukraine', agency: 'Criminal', motivation: 'Financial / Extortion', sectors: ['Finance', 'Technology', 'Government', 'Healthcare', 'Education'], since: 2019, techniques: ['T1190', 'T1486', 'T1048', 'T1059', 'T1078', 'T1105'], campaigns: ['MOVEit Transfer Exploitation 2023', 'GoAnywhere MFT', 'Accellion FTA'], iocs: ['clop-leak.onion', '194.135.33.0/24', 'd7e8f9a1b2c3'] },
  { id: 'revil', name: 'REvil', aliases: ['Sodinokibi', 'Gold Southfield'], nation: 'Russia', agency: 'Criminal (RaaS)', motivation: 'Financial / Extortion', sectors: ['Technology', 'Legal', 'Insurance', 'Manufacturing'], since: 2019, techniques: ['T1486', 'T1490', 'T1195', 'T1059', 'T1021', 'T1048'], campaigns: ['Kaseya Supply Chain 2021', 'JBS Foods', 'Acer $50M Demand'], iocs: ['revil-blog.onion', '193.56.28.0/24', 'e8f9a1b2c3d4'] },
  { id: 'conti', name: 'Conti', aliases: ['Wizard Spider', 'Gold Ulrick'], nation: 'Russia', agency: 'Criminal (RaaS)', motivation: 'Financial / Extortion', sectors: ['Healthcare', 'Government', 'Manufacturing', 'Education', 'Finance'], since: 2020, techniques: ['T1486', 'T1490', 'T1059', 'T1021', 'T1003', 'T1055'], campaigns: ['Irish HSE Attack 2021', 'Costa Rica Government', 'Conti Leaks'], iocs: ['conti-news.onion', '162.244.80.0/24', 'f9a1b2c3d4e5'] },
];

// ============================================================================
// IOC DATABASE (100+ indicators)
// ============================================================================
const IOC_DB = [
  { id: 1, type: 'IP', value: '185.86.148.27', severity: 'Critical', confidence: 95, tags: ['APT28', 'C2'], source: 'CISA', added: '2026-09-15', notes: 'Known Fancy Bear C2 server' },
  { id: 2, type: 'IP', value: '91.245.228.54', severity: 'Critical', confidence: 90, tags: ['Sandworm', 'C2'], source: 'NCSC', added: '2026-09-14', notes: 'NotPetya distribution node' },
  { id: 3, type: 'IP', value: '175.45.176.99', severity: 'High', confidence: 85, tags: ['Lazarus', 'Crypto'], source: 'FBI', added: '2026-09-13', notes: 'Cryptocurrency heist infrastructure' },
  { id: 4, type: 'IP', value: '203.160.69.12', severity: 'High', confidence: 88, tags: ['Hafnium', 'Exchange'], source: 'Microsoft', added: '2026-09-12', notes: 'ProxyLogon exploitation' },
  { id: 5, type: 'IP', value: '45.134.142.78', severity: 'Critical', confidence: 92, tags: ['Scattered Spider', 'SIM swap'], source: 'CrowdStrike', added: '2026-09-11', notes: '0ktapus phishing infra' },
  { id: 6, type: 'IP', value: '193.233.75.43', severity: 'Critical', confidence: 93, tags: ['ALPHV', 'Ransomware'], source: 'ThreatFox', added: '2026-09-10', notes: 'BlackCat payment portal' },
  { id: 7, type: 'IP', value: '91.132.92.118', severity: 'Critical', confidence: 91, tags: ['LockBit', 'Ransomware'], source: 'ThreatFox', added: '2026-09-09', notes: 'LockBit leak site backend' },
  { id: 8, type: 'IP', value: '103.27.108.55', severity: 'High', confidence: 87, tags: ['Volt Typhoon', 'Living off Land'], source: 'NSA', added: '2026-09-08', notes: 'LOTL relay node' },
  { id: 9, type: 'IP', value: '116.206.93.14', severity: 'High', confidence: 85, tags: ['Salt Typhoon', 'Telecom'], source: 'CISA', added: '2026-09-07', notes: 'Telecom wiretap infrastructure' },
  { id: 10, type: 'IP', value: '185.141.63.88', severity: 'Medium', confidence: 78, tags: ['Charming Kitten', 'Phishing'], source: 'Mandiant', added: '2026-09-06', notes: 'Credential harvesting server' },
  { id: 11, type: 'Domain', value: 'avsvmcloud.com', severity: 'Critical', confidence: 99, tags: ['APT29', 'SolarWinds'], source: 'FireEye', added: '2026-09-15', notes: 'SUNBURST C2 domain' },
  { id: 12, type: 'Domain', value: 'sednitspy.com', severity: 'High', confidence: 90, tags: ['APT28', 'Espionage'], source: 'ESET', added: '2026-09-14', notes: 'Sednit phishing domain' },
  { id: 13, type: 'Domain', value: 'lockbit3-decrypt.onion', severity: 'Critical', confidence: 95, tags: ['LockBit', 'Ransomware'], source: 'Recorded Future', added: '2026-09-13', notes: 'LockBit decryption portal' },
  { id: 14, type: 'Domain', value: 'update-system32.com', severity: 'High', confidence: 82, tags: ['APT41', 'Supply Chain'], source: 'ThreatFox', added: '2026-09-12', notes: 'Fake update distribution' },
  { id: 15, type: 'Domain', value: 'secure-login-verify.com', severity: 'Medium', confidence: 75, tags: ['Phishing', 'Credential Theft'], source: 'PhishTank', added: '2026-09-11', notes: 'Generic credential harvester' },
  { id: 16, type: 'Domain', value: 'cloud-service-auth.net', severity: 'Medium', confidence: 72, tags: ['Scattered Spider', 'Social Engineering'], source: 'CrowdStrike', added: '2026-09-10', notes: 'MFA bypass phishing' },
  { id: 17, type: 'Domain', value: 'critical-patch-update.org', severity: 'High', confidence: 80, tags: ['Mustang Panda', 'Lure'], source: 'NCSC', added: '2026-09-09', notes: 'Fake patch distribution' },
  { id: 18, type: 'Domain', value: 'darknet-market-forums.com', severity: 'Medium', confidence: 70, tags: ['Criminal', 'Marketplace'], source: 'DarkOwl', added: '2026-09-08', notes: 'Criminal forum domain' },
  { id: 19, type: 'Domain', value: 'vpn-gateway-secure.net', severity: 'High', confidence: 84, tags: ['MuddyWater', 'Iran'], source: 'Mandiant', added: '2026-09-07', notes: 'VPN credential phishing' },
  { id: 20, type: 'Domain', value: 'apt-exfil-relay.com', severity: 'Critical', confidence: 88, tags: ['APT10', 'Cloud Hopper'], source: 'PwC', added: '2026-09-06', notes: 'MSP data exfiltration relay' },
  { id: 21, type: 'Hash-MD5', value: '5d2b4e3c7a1f8e9d0b6ca3f2d7e1b894', severity: 'Critical', confidence: 98, tags: ['APT28', 'X-Agent'], source: 'ESET', added: '2026-09-15', notes: 'X-Agent backdoor binary' },
  { id: 22, type: 'Hash-SHA256', value: 'dblbnd4jx3ftgd7e8a9c1b2f4d6e8a0c2e4f6a8b0d2e4f6a8b0d2e4f6a8b0d2', severity: 'Critical', confidence: 97, tags: ['APT29', 'SUNBURST'], source: 'FireEye', added: '2026-09-14', notes: 'SUNBURST DLL' },
  { id: 23, type: 'Hash-SHA256', value: 'a7d3c2f1e8b6d4a9c3e7f2b1d5a8c4e6f0b2d4a6c8e0f2a4b6d8e0a2c4e6f8', severity: 'High', confidence: 90, tags: ['Lazarus', 'Trojan'], source: 'Kaspersky', added: '2026-09-13', notes: 'AppleJeus cryptocurrency trojan' },
  { id: 24, type: 'Hash-MD5', value: 'e3b0c44298fc1c149afbf4c8996fb924', severity: 'Critical', confidence: 94, tags: ['Sandworm', 'Industroyer'], source: 'ESET', added: '2026-09-12', notes: 'Industroyer2 payload' },
  { id: 25, type: 'Hash-SHA256', value: 'b3c7d1e8f2a4c6e8a0b2d4f6a8c0e2f4a6b8d0e2a4c6f8a0b2d4e6a8c0e2f4', severity: 'High', confidence: 86, tags: ['Hafnium', 'WebShell'], source: 'Microsoft', added: '2026-09-11', notes: 'China Chopper webshell' },
  { id: 26, type: 'URL', value: 'https://update-system32.com/patch/critical.exe', severity: 'Critical', confidence: 93, tags: ['APT41', 'Dropper'], source: 'ThreatFox', added: '2026-09-15', notes: 'Malware dropper URL' },
  { id: 27, type: 'URL', value: 'https://secure-login-verify.com/auth/o365', severity: 'High', confidence: 85, tags: ['Phishing', 'O365'], source: 'PhishTank', added: '2026-09-14', notes: 'Office 365 phishing page' },
  { id: 28, type: 'URL', value: 'http://185.86.148.27:8443/api/beacon', severity: 'Critical', confidence: 96, tags: ['APT28', 'Cobalt Strike'], source: 'CISA', added: '2026-09-13', notes: 'Cobalt Strike beacon URL' },
  { id: 29, type: 'URL', value: 'https://cdn-update.cloud-service-auth.net/payload.dll', severity: 'High', confidence: 82, tags: ['Scattered Spider', 'Loader'], source: 'CrowdStrike', added: '2026-09-12', notes: 'Initial access loader' },
  { id: 30, type: 'URL', value: 'ftp://103.27.108.55/exfil/data.7z', severity: 'Critical', confidence: 89, tags: ['Volt Typhoon', 'Exfil'], source: 'NSA', added: '2026-09-11', notes: 'Data exfiltration endpoint' },
  { id: 31, type: 'Email', value: 'dr.johnson.research@protonmail.com', severity: 'Medium', confidence: 72, tags: ['Charming Kitten', 'Phishing'], source: 'Mandiant', added: '2026-09-15', notes: 'Academic impersonation' },
  { id: 32, type: 'Email', value: 'support@cloud-service-auth.net', severity: 'High', confidence: 84, tags: ['Scattered Spider', 'Vishing'], source: 'CrowdStrike', added: '2026-09-14', notes: 'Help desk impersonation' },
  { id: 33, type: 'Email', value: 'admin@critical-patch-update.org', severity: 'Medium', confidence: 76, tags: ['Mustang Panda', 'Lure'], source: 'NCSC', added: '2026-09-13', notes: 'Fake admin notification' },
  { id: 34, type: 'CVE', value: 'CVE-2024-3400', severity: 'Critical', confidence: 99, tags: ['PAN-OS', 'Zero-day'], source: 'NVD', added: '2026-09-15', notes: 'Palo Alto GlobalProtect RCE' },
  { id: 35, type: 'CVE', value: 'CVE-2024-21762', severity: 'Critical', confidence: 99, tags: ['FortiOS', 'Zero-day'], source: 'NVD', added: '2026-09-14', notes: 'Fortinet SSL VPN OOB Write' },
  { id: 36, type: 'CVE', value: 'CVE-2023-4966', severity: 'Critical', confidence: 99, tags: ['Citrix', 'Bleed'], source: 'NVD', added: '2026-09-13', notes: 'Citrix Bleed buffer overflow' },
  { id: 37, type: 'CVE', value: 'CVE-2023-34362', severity: 'Critical', confidence: 99, tags: ['MOVEit', 'Cl0p'], source: 'NVD', added: '2026-09-12', notes: 'MOVEit Transfer SQLi' },
  { id: 38, type: 'CVE', value: 'CVE-2021-44228', severity: 'Critical', confidence: 99, tags: ['Log4j', 'Log4Shell'], source: 'NVD', added: '2026-09-11', notes: 'Apache Log4j JNDI RCE' },
  { id: 39, type: 'IP', value: '5.188.86.23', severity: 'High', confidence: 83, tags: ['FIN7', 'POS'], source: 'FireEye', added: '2026-09-05', notes: 'POS malware C2' },
  { id: 40, type: 'IP', value: '89.38.97.110', severity: 'High', confidence: 81, tags: ['APT33', 'Shamoon'], source: 'Symantec', added: '2026-09-04', notes: 'Shamoon wiper C2' },
  { id: 41, type: 'Domain', value: 'kitten-research-portal.org', severity: 'Medium', confidence: 74, tags: ['Charming Kitten', 'Phishing'], source: 'Mandiant', added: '2026-09-03', notes: 'Academic credential theft' },
  { id: 42, type: 'Domain', value: 'apt29-relay-node.com', severity: 'Critical', confidence: 91, tags: ['APT29', 'Relay'], source: 'SentinelOne', added: '2026-09-02', notes: 'Data staging relay' },
  { id: 43, type: 'Hash-SHA256', value: 'c8e4b7a1d2f3e5a7c9b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3', severity: 'High', confidence: 87, tags: ['Turla', 'Snake'], source: 'NSA', added: '2026-09-01', notes: 'Snake implant binary' },
  { id: 44, type: 'Hash-MD5', value: 'f4ec62e4a2b7c9d1e3f5a7b9d1e3f5a7', severity: 'High', confidence: 85, tags: ['Equation Group', 'DoubleFantasy'], source: 'Kaspersky', added: '2026-08-31', notes: 'DoubleFantasy implant' },
  { id: 45, type: 'IP', value: '194.58.92.31', severity: 'Medium', confidence: 77, tags: ['Gamaredon', 'Ukraine'], source: 'CERT-UA', added: '2026-08-30', notes: 'Pterodo backdoor C2' },
  { id: 46, type: 'IP', value: '103.82.24.67', severity: 'Medium', confidence: 73, tags: ['SideWinder', 'India'], source: 'Kaspersky', added: '2026-08-29', notes: 'SideWinder C2 relay' },
  { id: 47, type: 'IP', value: '180.76.76.45', severity: 'High', confidence: 84, tags: ['Winnti', 'ShadowPad'], source: 'ESET', added: '2026-08-28', notes: 'ShadowPad C2 server' },
  { id: 48, type: 'Domain', value: 'clop-ransom-payment.onion', severity: 'Critical', confidence: 94, tags: ['Cl0p', 'Ransomware'], source: 'Recorded Future', added: '2026-08-27', notes: 'Cl0p payment portal' },
  { id: 49, type: 'URL', value: 'https://kitten-research-portal.org/auth/login.php', severity: 'Medium', confidence: 74, tags: ['Charming Kitten', 'Phishing'], source: 'Mandiant', added: '2026-08-26', notes: 'Credential harvester' },
  { id: 50, type: 'Email', value: 'noreply@critical-patch-update.org', severity: 'High', confidence: 80, tags: ['Mustang Panda', 'Lure'], source: 'NCSC', added: '2026-08-25', notes: 'Phishing sender' },
  { id: 51, type: 'IP', value: '162.244.80.17', severity: 'Critical', confidence: 92, tags: ['Conti', 'Ransomware'], source: 'ThreatFox', added: '2026-08-24', notes: 'Conti C2 server' },
  { id: 52, type: 'IP', value: '193.56.28.99', severity: 'Critical', confidence: 91, tags: ['REvil', 'Ransomware'], source: 'ThreatFox', added: '2026-08-23', notes: 'REvil payment server' },
  { id: 53, type: 'Domain', value: 'conti-recovery.onion', severity: 'Critical', confidence: 93, tags: ['Conti', 'Ransomware'], source: 'Recorded Future', added: '2026-08-22', notes: 'Conti negotiation site' },
  { id: 54, type: 'Hash-SHA256', value: 'e2f4a6b8c1d3e5f7a9b1c3d5e7f9a1b3c5d7e9f1a3b5c7d9e1f3a5b7c9d1e3', severity: 'High', confidence: 86, tags: ['OceanLotus', 'Backdoor'], source: 'ESET', added: '2026-08-21', notes: 'KerrDown backdoor' },
  { id: 55, type: 'IP', value: '45.32.100.89', severity: 'Medium', confidence: 75, tags: ['OceanLotus', 'Vietnam'], source: 'ESET', added: '2026-08-20', notes: 'OceanLotus staging server' },
  { id: 56, type: 'Domain', value: 'revil-decryptor.onion', severity: 'Critical', confidence: 92, tags: ['REvil', 'Ransomware'], source: 'Recorded Future', added: '2026-08-19', notes: 'Sodinokibi decryption service' },
  { id: 57, type: 'IP', value: '194.135.33.44', severity: 'Critical', confidence: 90, tags: ['Cl0p', 'MOVEit'], source: 'FBI', added: '2026-08-18', notes: 'MOVEit exploitation server' },
  { id: 58, type: 'Hash-MD5', value: 'd7e9f1a2b3c4e5f6a7b8c9d0e1f2a3b4', severity: 'Medium', confidence: 76, tags: ['Mustang Panda', 'PlugX'], source: 'Proofpoint', added: '2026-08-17', notes: 'PlugX loader' },
  { id: 59, type: 'URL', value: 'https://vpn-gateway-secure.net/login/index.html', severity: 'High', confidence: 83, tags: ['MuddyWater', 'Phishing'], source: 'Mandiant', added: '2026-08-16', notes: 'VPN credential phishing' },
  { id: 60, type: 'CVE', value: 'CVE-2024-6387', severity: 'High', confidence: 99, tags: ['OpenSSH', 'regreSSHion'], source: 'NVD', added: '2026-08-15', notes: 'OpenSSH signal handler race' },
  { id: 61, type: 'CVE', value: 'CVE-2023-22515', severity: 'Critical', confidence: 99, tags: ['Confluence', 'Auth Bypass'], source: 'NVD', added: '2026-08-14', notes: 'Confluence privilege escalation' },
  { id: 62, type: 'CVE', value: 'CVE-2024-21887', severity: 'Critical', confidence: 99, tags: ['Ivanti', 'Command Injection'], source: 'NVD', added: '2026-08-13', notes: 'Ivanti Connect Secure RCE' },
  { id: 63, type: 'IP', value: '121.78.148.12', severity: 'Medium', confidence: 71, tags: ['DarkHotel', 'Hotel'], source: 'Kaspersky', added: '2026-08-12', notes: 'Hotel WiFi exploitation node' },
  { id: 64, type: 'Domain', value: 'darkhotel-update.com', severity: 'Medium', confidence: 70, tags: ['DarkHotel', 'Update'], source: 'Kaspersky', added: '2026-08-11', notes: 'Fake software update' },
  { id: 65, type: 'IP', value: '118.193.78.33', severity: 'High', confidence: 84, tags: ['APT41', 'ShadowPad'], source: 'Recorded Future', added: '2026-08-10', notes: 'APT41 ShadowPad C2' },
  { id: 66, type: 'Hash-SHA256', value: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2', severity: 'High', confidence: 88, tags: ['Winnti', 'Rootkit'], source: 'ESET', added: '2026-08-09', notes: 'Winnti kernel rootkit' },
  { id: 67, type: 'IP', value: '210.209.89.77', severity: 'High', confidence: 82, tags: ['APT10', 'Cloud Hopper'], source: 'PwC', added: '2026-08-08', notes: 'Cloud Hopper proxy' },
  { id: 68, type: 'Domain', value: 'kimsuky-portal.com', severity: 'Medium', confidence: 74, tags: ['Kimsuky', 'Credential'], source: 'AhnLab', added: '2026-08-07', notes: 'Credential harvesting' },
  { id: 69, type: 'Email', value: 'hr-department@update-system32.com', severity: 'High', confidence: 81, tags: ['APT41', 'Spearphish'], source: 'Proofpoint', added: '2026-08-06', notes: 'HR-themed phishing' },
  { id: 70, type: 'IP', value: '185.117.73.22', severity: 'Medium', confidence: 76, tags: ['MuddyWater', 'Iran'], source: 'ClearSky', added: '2026-08-05', notes: 'MuddyWater staging' },
  { id: 71, type: 'Hash-MD5', value: 'a9d2c3b4e5f6a7b8c9d0e1f2a3b4c5d6', severity: 'Medium', confidence: 74, tags: ['Charming Kitten', 'Infostealer'], source: 'Mandiant', added: '2026-08-04', notes: 'HYPERSCRAPE tool' },
  { id: 72, type: 'Domain', value: 'patchwork-updates.net', severity: 'Medium', confidence: 69, tags: ['Patchwork', 'India'], source: 'Kaspersky', added: '2026-08-03', notes: 'Malware distribution' },
  { id: 73, type: 'IP', value: '103.100.130.44', severity: 'Medium', confidence: 72, tags: ['Patchwork', 'India'], source: 'Kaspersky', added: '2026-08-02', notes: 'C2 server' },
  { id: 74, type: 'URL', value: 'https://apt-exfil-relay.com/upload/beacon.php', severity: 'Critical', confidence: 88, tags: ['APT10', 'Exfil'], source: 'PwC', added: '2026-08-01', notes: 'Data exfiltration endpoint' },
  { id: 75, type: 'CVE', value: 'CVE-2023-7028', severity: 'Critical', confidence: 99, tags: ['GitLab', 'Account Takeover'], source: 'NVD', added: '2026-07-31', notes: 'GitLab password reset bypass' },
  { id: 76, type: 'IP', value: '149.5.0.17', severity: 'High', confidence: 80, tags: ['Equation Group', 'TAO'], source: 'Shadow Brokers', added: '2026-07-30', notes: 'Equation Group relay' },
  { id: 77, type: 'Hash-SHA256', value: 'b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2', severity: 'High', confidence: 83, tags: ['FIN7', 'Carbanak'], source: 'FireEye', added: '2026-07-29', notes: 'Carbanak backdoor binary' },
  { id: 78, type: 'Domain', value: 'gamaredon-c2-relay.com', severity: 'Medium', confidence: 75, tags: ['Gamaredon', 'Ukraine'], source: 'CERT-UA', added: '2026-07-28', notes: 'Pterodo C2' },
  { id: 79, type: 'IP', value: '80.255.3.91', severity: 'High', confidence: 84, tags: ['Turla', 'Snake'], source: 'NSA', added: '2026-07-27', notes: 'Snake infrastructure' },
  { id: 80, type: 'Email', value: 'security-team@vpn-gateway-secure.net', severity: 'High', confidence: 79, tags: ['MuddyWater', 'Phishing'], source: 'ClearSky', added: '2026-07-26', notes: 'IT support impersonation' },
  { id: 81, type: 'IP', value: '45.77.65.211', severity: 'Medium', confidence: 70, tags: ['Cryptominer', 'Monero'], source: 'AbuseIPDB', added: '2026-07-25', notes: 'XMRig mining pool proxy' },
  { id: 82, type: 'Domain', value: 'supply-chain-update.net', severity: 'High', confidence: 82, tags: ['APT29', 'Supply Chain'], source: 'SentinelOne', added: '2026-07-24', notes: 'Supply chain staging' },
  { id: 83, type: 'IP', value: '23.227.196.55', severity: 'Medium', confidence: 68, tags: ['Botnet', 'Mirai'], source: 'Shadowserver', added: '2026-07-23', notes: 'Mirai C2' },
  { id: 84, type: 'Hash-MD5', value: 'b5c6d7e8f9a1b2c3d4e5f6a7b8c9d0e1', severity: 'Critical', confidence: 91, tags: ['ALPHV', 'BlackCat'], source: 'SentinelOne', added: '2026-07-22', notes: 'BlackCat ransomware binary' },
  { id: 85, type: 'IP', value: '172.67.182.33', severity: 'Low', confidence: 55, tags: ['Suspicious', 'Proxy'], source: 'GreyNoise', added: '2026-07-21', notes: 'Tor exit node' },
  { id: 86, type: 'Domain', value: 'sidewinder-phish.com', severity: 'Medium', confidence: 71, tags: ['SideWinder', 'Phishing'], source: 'Kaspersky', added: '2026-07-20', notes: 'Military-themed lure' },
  { id: 87, type: 'CVE', value: 'CVE-2022-22965', severity: 'Critical', confidence: 99, tags: ['Spring', 'Spring4Shell'], source: 'NVD', added: '2026-07-19', notes: 'Spring Framework RCE' },
  { id: 88, type: 'IP', value: '104.244.72.115', severity: 'Low', confidence: 50, tags: ['Scanner', 'Recon'], source: 'GreyNoise', added: '2026-07-18', notes: 'Mass scanner' },
  { id: 89, type: 'URL', value: 'https://lockbit3-decrypt.onion/payment/id/abc123', severity: 'Critical', confidence: 95, tags: ['LockBit', 'Payment'], source: 'Recorded Future', added: '2026-07-17', notes: 'Ransom payment page' },
  { id: 90, type: 'Hash-SHA256', value: 'c6d7e8f9a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7', severity: 'Critical', confidence: 93, tags: ['LockBit', 'Ransomware'], source: 'SentinelOne', added: '2026-07-16', notes: 'LockBit 3.0 encryptor' },
  { id: 91, type: 'IP', value: '198.51.100.42', severity: 'Medium', confidence: 65, tags: ['Scanner', 'Shodan'], source: 'GreyNoise', added: '2026-07-15', notes: 'Internet-wide scanner' },
  { id: 92, type: 'Domain', value: 'revil-news-blog.onion', severity: 'High', confidence: 86, tags: ['REvil', 'Leak Site'], source: 'DarkOwl', added: '2026-07-14', notes: 'REvil data leak blog' },
  { id: 93, type: 'Hash-MD5', value: 'e8f9a1b2c3d4e5f6a7b8c9d0e1f2a3b4', severity: 'Critical', confidence: 90, tags: ['REvil', 'Sodinokibi'], source: 'Kaspersky', added: '2026-07-13', notes: 'REvil encryptor' },
  { id: 94, type: 'IP', value: '103.56.53.12', severity: 'Medium', confidence: 73, tags: ['Mustang Panda', 'PlugX'], source: 'Proofpoint', added: '2026-07-12', notes: 'PlugX C2' },
  { id: 95, type: 'CVE', value: 'CVE-2021-26855', severity: 'Critical', confidence: 99, tags: ['Exchange', 'ProxyLogon'], source: 'NVD', added: '2026-07-11', notes: 'Exchange Server SSRF' },
  { id: 96, type: 'Domain', value: 'alphv-chat-support.onion', severity: 'Critical', confidence: 92, tags: ['ALPHV', 'Negotiation'], source: 'Recorded Future', added: '2026-07-10', notes: 'BlackCat negotiation portal' },
  { id: 97, type: 'IP', value: '37.120.247.89', severity: 'High', confidence: 78, tags: ['Infostealer', 'RedLine'], source: 'ThreatFox', added: '2026-07-09', notes: 'RedLine Stealer C2' },
  { id: 98, type: 'Hash-SHA256', value: 'd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4', severity: 'High', confidence: 85, tags: ['Kimsuky', 'BabyShark'], source: 'AhnLab', added: '2026-07-08', notes: 'BabyShark implant' },
  { id: 99, type: 'Email', value: 'it-helpdesk@darknet-market-forums.com', severity: 'Medium', confidence: 68, tags: ['Criminal', 'Social Engineering'], source: 'DarkOwl', added: '2026-07-07', notes: 'Social engineering sender' },
  { id: 100, type: 'IP', value: '92.118.160.22', severity: 'High', confidence: 79, tags: ['Emotet', 'Loader'], source: 'abuse.ch', added: '2026-07-06', notes: 'Emotet distribution server' },
  { id: 101, type: 'CVE', value: 'CVE-2020-1472', severity: 'Critical', confidence: 99, tags: ['Netlogon', 'ZeroLogon'], source: 'NVD', added: '2026-07-05', notes: 'Netlogon privilege escalation' },
  { id: 102, type: 'CVE', value: 'CVE-2017-0144', severity: 'Critical', confidence: 99, tags: ['SMB', 'EternalBlue'], source: 'NVD', added: '2026-07-04', notes: 'SMBv1 remote code execution' },
  { id: 103, type: 'IP', value: '185.220.101.35', severity: 'Low', confidence: 52, tags: ['Tor', 'Exit Node'], source: 'TorProject', added: '2026-07-03', notes: 'Known Tor exit node' },
  { id: 104, type: 'Hash-MD5', value: 'f9a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5', severity: 'Critical', confidence: 93, tags: ['Conti', 'Ransomware'], source: 'SentinelOne', added: '2026-07-02', notes: 'Conti v3 encryptor' },
  { id: 105, type: 'Domain', value: 'conti-support-chat.onion', severity: 'Critical', confidence: 91, tags: ['Conti', 'Negotiation'], source: 'DarkOwl', added: '2026-07-01', notes: 'Victim negotiation chat' },
];

// ============================================================================
// CAMPAIGN DATABASE (12 campaigns)
// ============================================================================
const CAMPAIGN_DB = [
  {
    id: 'c1', name: 'Operation SolarFlare', actor: 'APT29', start: '2024-12-01', status: 'Active',
    sectors: ['Government', 'Technology'], regions: ['North America', 'Europe'],
    vector: 'Supply Chain Compromise', iocCount: 14,
    diamond: { adversary: 'APT29 / Cozy Bear (SVR)', infrastructure: 'Cloud-hosted C2 via Azure tenants, Cobalt Strike malleable profiles', capability: 'Custom SUNSPOT implant, TEARDROP loader, encrypted DNS tunneling', victim: 'US/EU government agencies, Fortune 500 tech firms' },
    phases: [{ name: 'Reconnaissance', start: 0, end: 15 }, { name: 'Weaponization', start: 10, end: 25 }, { name: 'Delivery', start: 20, end: 40 }, { name: 'Exploitation', start: 35, end: 55 }, { name: 'Installation', start: 50, end: 70 }, { name: 'C2', start: 65, end: 100 }, { name: 'Actions', start: 80, end: 100 }],
    killChain: ['Reconnaissance', 'Weaponization', 'Delivery', 'Exploitation', 'Installation', 'C2', 'Actions on Objectives']
  },
  {
    id: 'c2', name: 'Typhoon Infrastructure', actor: 'Volt Typhoon', start: '2023-05-01', status: 'Active',
    sectors: ['Critical Infrastructure', 'Telecom', 'Energy'], regions: ['North America', 'Pacific'],
    vector: 'Living off the Land', iocCount: 11,
    diamond: { adversary: 'Volt Typhoon (PLA)', infrastructure: 'Compromised SOHO routers, residential proxies', capability: 'LOTL binaries (PowerShell, WMI, ntdsutil), minimal malware footprint', victim: 'US critical infrastructure operators, Guam military bases' },
    phases: [{ name: 'Reconnaissance', start: 0, end: 20 }, { name: 'Initial Access', start: 15, end: 35 }, { name: 'Persistence', start: 30, end: 60 }, { name: 'Lateral Movement', start: 50, end: 80 }, { name: 'Pre-positioning', start: 70, end: 100 }],
    killChain: ['Reconnaissance', 'Delivery', 'Exploitation', 'Installation', 'C2']
  },
  {
    id: 'c3', name: 'MOVEit Mayhem', actor: 'Cl0p', start: '2023-05-27', status: 'Concluded',
    sectors: ['Government', 'Finance', 'Healthcare', 'Education'], regions: ['Global'],
    vector: 'Zero-day Exploitation (SQLi)', iocCount: 8,
    diamond: { adversary: 'Cl0p / TA505 (Criminal)', infrastructure: 'Tor-hosted leak site, bulletproof hosting', capability: 'MOVEit Transfer zero-day (CVE-2023-34362), automated mass exploitation', victim: '2,500+ organizations, 60M+ individuals affected' },
    phases: [{ name: 'Zero-day Dev', start: 0, end: 20 }, { name: 'Mass Exploitation', start: 15, end: 40 }, { name: 'Data Exfiltration', start: 35, end: 60 }, { name: 'Extortion', start: 55, end: 100 }],
    killChain: ['Reconnaissance', 'Weaponization', 'Delivery', 'Exploitation', 'Actions on Objectives']
  },
  {
    id: 'c4', name: 'Scattered Social', actor: 'Scattered Spider', start: '2023-08-01', status: 'Active',
    sectors: ['Hospitality', 'Technology', 'Telecom'], regions: ['North America'],
    vector: 'Social Engineering / SIM Swapping', iocCount: 9,
    diamond: { adversary: 'Scattered Spider / UNC3944 (Cybercriminal)', infrastructure: 'Fake help desk portals, Okta tenant abuse', capability: 'Vishing, SIM swapping, MFA fatigue, Okta abuse, ALPHV ransomware', victim: 'MGM Resorts, Caesars Entertainment, Twilio, Cloudflare' },
    phases: [{ name: 'Social Engineering', start: 0, end: 30 }, { name: 'MFA Bypass', start: 20, end: 45 }, { name: 'Lateral Movement', start: 40, end: 65 }, { name: 'Ransomware', start: 60, end: 85 }, { name: 'Extortion', start: 80, end: 100 }],
    killChain: ['Reconnaissance', 'Delivery', 'Exploitation', 'Installation', 'C2', 'Actions on Objectives']
  },
  {
    id: 'c5', name: 'Salt Wiretap', actor: 'Salt Typhoon', start: '2024-01-01', status: 'Active',
    sectors: ['Telecom', 'ISP'], regions: ['North America'],
    vector: 'Network Device Exploitation', iocCount: 7,
    diamond: { adversary: 'Salt Typhoon (MSS)', infrastructure: 'Compromised telco edge devices, VPN concentrators', capability: 'Wiretap access to lawful intercept systems, persistent network implants', victim: 'AT&T, Verizon, T-Mobile, Lumen Technologies' },
    phases: [{ name: 'Edge Device Recon', start: 0, end: 20 }, { name: 'Initial Compromise', start: 15, end: 40 }, { name: 'Network Traversal', start: 35, end: 60 }, { name: 'Intercept Access', start: 55, end: 85 }, { name: 'Persistent Collection', start: 75, end: 100 }],
    killChain: ['Reconnaissance', 'Exploitation', 'Installation', 'C2', 'Actions on Objectives']
  },
  {
    id: 'c6', name: 'Healthcare Ransom Wave', actor: 'ALPHV/BlackCat', start: '2024-02-01', status: 'Dormant',
    sectors: ['Healthcare', 'Insurance'], regions: ['North America'],
    vector: 'Credential Stuffing + Ransomware', iocCount: 10,
    diamond: { adversary: 'ALPHV / BlackCat (RaaS Affiliate)', infrastructure: 'Tor-based leak site, affiliate program', capability: 'Rust-based ransomware, cross-platform (Windows/Linux/ESXi), data exfiltration', victim: 'Change Healthcare (UnitedHealth), disrupting US pharmacy operations' },
    phases: [{ name: 'Initial Access', start: 0, end: 15 }, { name: 'Privilege Escalation', start: 10, end: 30 }, { name: 'Data Exfiltration', start: 25, end: 55 }, { name: 'Encryption', start: 50, end: 70 }, { name: 'Ransom Demand', start: 65, end: 100 }],
    killChain: ['Delivery', 'Exploitation', 'Installation', 'C2', 'Actions on Objectives']
  },
  {
    id: 'c7', name: 'ProxyLogon Blitz', actor: 'Hafnium', start: '2021-01-01', status: 'Concluded',
    sectors: ['Government', 'Defense', 'Research', 'Legal'], regions: ['Global'],
    vector: 'Zero-day Exploitation', iocCount: 12,
    diamond: { adversary: 'Hafnium / Silk Typhoon (MSS)', infrastructure: 'Leased VPS servers, webshells deployed on victims', capability: 'ProxyLogon chain (CVE-2021-26855 + CVE-2021-27065), China Chopper webshells', victim: '250,000+ Exchange servers globally' },
    phases: [{ name: 'Zero-day Exploitation', start: 0, end: 25 }, { name: 'Webshell Deployment', start: 20, end: 45 }, { name: 'Mailbox Exfil', start: 40, end: 70 }, { name: 'Credential Harvest', start: 60, end: 90 }, { name: 'Lateral Movement', start: 80, end: 100 }],
    killChain: ['Exploitation', 'Installation', 'C2', 'Actions on Objectives']
  },
  {
    id: 'c8', name: 'ShadowPad Supply Chain', actor: 'Winnti', start: '2022-03-01', status: 'Active',
    sectors: ['Technology', 'Gaming', 'Manufacturing'], regions: ['Asia', 'Europe'],
    vector: 'Software Supply Chain', iocCount: 8,
    diamond: { adversary: 'Winnti / APT41 (MSS Contractor)', infrastructure: 'Compromised software build pipelines, signed malware', capability: 'ShadowPad modular backdoor, digitally-signed trojans, supply chain implants', victim: 'Software vendors, downstream customers' },
    phases: [{ name: 'Vendor Compromise', start: 0, end: 20 }, { name: 'Build Poisoning', start: 15, end: 40 }, { name: 'Distribution', start: 35, end: 55 }, { name: 'Activation', start: 50, end: 75 }, { name: 'Espionage', start: 70, end: 100 }],
    killChain: ['Reconnaissance', 'Weaponization', 'Delivery', 'Installation', 'C2', 'Actions on Objectives']
  },
  {
    id: 'c9', name: 'Kaseya Cascade', actor: 'REvil', start: '2021-07-02', status: 'Concluded',
    sectors: ['Technology', 'MSP', 'SMB'], regions: ['Global'],
    vector: 'MSP Supply Chain Attack', iocCount: 6,
    diamond: { adversary: 'REvil / Sodinokibi (RaaS)', infrastructure: 'Affiliate network, Bitcoin/Monero payment', capability: 'VSA server zero-day, mass ransomware deployment via MSP tools', victim: '1,500+ businesses via ~60 MSPs using Kaseya VSA' },
    phases: [{ name: 'VSA Zero-day', start: 0, end: 20 }, { name: 'MSP Compromise', start: 15, end: 40 }, { name: 'Mass Deployment', start: 35, end: 60 }, { name: 'Encryption', start: 55, end: 80 }, { name: '$70M Demand', start: 75, end: 100 }],
    killChain: ['Weaponization', 'Delivery', 'Exploitation', 'Installation', 'Actions on Objectives']
  },
  {
    id: 'c10', name: 'Academic Harvest', actor: 'Charming Kitten', start: '2025-06-01', status: 'Active',
    sectors: ['Academics', 'Think Tanks', 'Media'], regions: ['North America', 'Europe', 'Middle East'],
    vector: 'Spearphishing', iocCount: 7,
    diamond: { adversary: 'Charming Kitten / APT35 (IRGC)', infrastructure: 'Spoofed academic portals, Google/Yahoo phishing kits', capability: 'HYPERSCRAPE email harvester, credential phishing, 2FA interception', victim: 'University researchers, policy analysts, journalists' },
    phases: [{ name: 'Target Research', start: 0, end: 20 }, { name: 'Lure Creation', start: 15, end: 35 }, { name: 'Phishing', start: 30, end: 55 }, { name: 'Credential Harvest', start: 50, end: 75 }, { name: 'Email Exfil', start: 70, end: 100 }],
    killChain: ['Reconnaissance', 'Weaponization', 'Delivery', 'Exploitation', 'Actions on Objectives']
  },
  {
    id: 'c11', name: 'Conti Costa Rica', actor: 'Conti', start: '2022-04-17', status: 'Concluded',
    sectors: ['Government'], regions: ['Central America'],
    vector: 'Phishing + Lateral Movement', iocCount: 9,
    diamond: { adversary: 'Conti / Wizard Spider (RaaS)', infrastructure: 'Tor leak site, TrickBot/BazarLoader distribution', capability: 'Conti ransomware, TrickBot initial access, Cobalt Strike post-exploitation', victim: 'Costa Rica government (27 ministries), national emergency declared' },
    phases: [{ name: 'Initial Phishing', start: 0, end: 15 }, { name: 'TrickBot Deploy', start: 10, end: 30 }, { name: 'Cobalt Strike', start: 25, end: 50 }, { name: 'Lateral Movement', start: 45, end: 70 }, { name: 'Encryption', start: 65, end: 85 }, { name: '$20M Demand', start: 80, end: 100 }],
    killChain: ['Reconnaissance', 'Delivery', 'Exploitation', 'Installation', 'C2', 'Actions on Objectives']
  },
  {
    id: 'c12', name: 'LockBit Global Rampage', actor: 'LockBit', start: '2023-01-01', status: 'Dormant',
    sectors: ['Manufacturing', 'Healthcare', 'Government', 'Finance'], regions: ['Global'],
    vector: 'Affiliate RaaS Model', iocCount: 13,
    diamond: { adversary: 'LockBit (RaaS Operator + Affiliates)', infrastructure: 'Tor infrastructure, StealBit exfil tool, affiliate panel', capability: 'LockBit 3.0 encryptor, bug bounty for vulnerabilities, triple extortion', victim: 'Boeing, ICBC, Royal Mail, 1,700+ US organizations' },
    phases: [{ name: 'Affiliate Recruitment', start: 0, end: 15 }, { name: 'Initial Access', start: 10, end: 35 }, { name: 'Data Theft', start: 30, end: 55 }, { name: 'Encryption', start: 50, end: 75 }, { name: 'Triple Extortion', start: 70, end: 100 }],
    killChain: ['Reconnaissance', 'Delivery', 'Exploitation', 'Installation', 'C2', 'Actions on Objectives']
  },
];

// ============================================================================
// SAMPLE STIX 2.1 BUNDLE
// ============================================================================
const SAMPLE_STIX = {
  type: 'bundle', id: 'bundle--a1b2c3d4-e5f6-7890-abcd-ef1234567890', spec_version: '2.1',
  objects: [
    { type: 'threat-actor', id: 'threat-actor--apt29', created: '2026-01-15T00:00:00Z', name: 'APT29', description: 'Russian SVR-linked espionage group', threat_actor_types: ['nation-state'], aliases: ['Cozy Bear', 'NOBELIUM'], sophistication: 'expert', resource_level: 'government', primary_motivation: 'organizational-gain' },
    { type: 'threat-actor', id: 'threat-actor--volt-typhoon', created: '2026-03-01T00:00:00Z', name: 'Volt Typhoon', description: 'Chinese PLA-linked critical infrastructure targeting group', threat_actor_types: ['nation-state'], aliases: ['Bronze Silhouette'], sophistication: 'expert', resource_level: 'government', primary_motivation: 'organizational-gain' },
    { type: 'malware', id: 'malware--sunburst', created: '2026-01-15T00:00:00Z', name: 'SUNBURST', description: 'Backdoor distributed via SolarWinds Orion supply chain', malware_types: ['backdoor', 'trojan'], is_family: true },
    { type: 'malware', id: 'malware--cobalt-strike', created: '2026-01-15T00:00:00Z', name: 'Cobalt Strike', description: 'Commercial adversary simulation tool abused by threat actors', malware_types: ['backdoor', 'remote-access-trojan'], is_family: true },
    { type: 'malware', id: 'malware--lockbit', created: '2026-02-01T00:00:00Z', name: 'LockBit 3.0', description: 'Ransomware-as-a-Service platform with affiliate model', malware_types: ['ransomware'], is_family: true },
    { type: 'malware', id: 'malware--teardrop', created: '2026-01-15T00:00:00Z', name: 'TEARDROP', description: 'Memory-only dropper used in SolarWinds campaign', malware_types: ['dropper'], is_family: false },
    { type: 'attack-pattern', id: 'attack-pattern--t1195', created: '2026-01-15T00:00:00Z', name: 'Supply Chain Compromise', description: 'Adversaries manipulate products or delivery mechanisms prior to receipt by final consumer', external_references: [{ source_name: 'mitre-attack', external_id: 'T1195' }] },
    { type: 'attack-pattern', id: 'attack-pattern--t1059', created: '2026-01-15T00:00:00Z', name: 'Command and Scripting Interpreter', description: 'Adversaries abuse command and script interpreters', external_references: [{ source_name: 'mitre-attack', external_id: 'T1059' }] },
    { type: 'attack-pattern', id: 'attack-pattern--t1486', created: '2026-02-01T00:00:00Z', name: 'Data Encrypted for Impact', description: 'Adversaries encrypt data on target systems to interrupt availability', external_references: [{ source_name: 'mitre-attack', external_id: 'T1486' }] },
    { type: 'attack-pattern', id: 'attack-pattern--t1078', created: '2026-03-01T00:00:00Z', name: 'Valid Accounts', description: 'Adversaries obtain and abuse credentials of existing accounts', external_references: [{ source_name: 'mitre-attack', external_id: 'T1078' }] },
    { type: 'attack-pattern', id: 'attack-pattern--t1566', created: '2026-01-15T00:00:00Z', name: 'Phishing', description: 'Adversaries send phishing messages to gain access', external_references: [{ source_name: 'mitre-attack', external_id: 'T1566' }] },
    { type: 'indicator', id: 'indicator--avsvmcloud', created: '2026-01-15T00:00:00Z', name: 'SUNBURST C2 Domain', description: 'C2 domain for SUNBURST backdoor', pattern: "[domain-name:value = 'avsvmcloud.com']", pattern_type: 'stix', valid_from: '2020-12-13T00:00:00Z', indicator_types: ['malicious-activity'] },
    { type: 'indicator', id: 'indicator--apt29-ip', created: '2026-01-15T00:00:00Z', name: 'APT29 C2 IP', description: 'Known APT29 command and control server', pattern: "[ipv4-addr:value = '13.59.205.66']", pattern_type: 'stix', valid_from: '2021-01-01T00:00:00Z', indicator_types: ['malicious-activity'] },
    { type: 'indicator', id: 'indicator--lockbit-hash', created: '2026-02-01T00:00:00Z', name: 'LockBit Encryptor', description: 'SHA256 hash of LockBit 3.0 encryptor binary', pattern: "[file:hashes.'SHA-256' = 'c6d7e8f9a1b2c3d4...']", pattern_type: 'stix', valid_from: '2023-06-01T00:00:00Z', indicator_types: ['malicious-activity'] },
    { type: 'campaign', id: 'campaign--solarflare', created: '2026-01-15T00:00:00Z', name: 'Operation SolarFlare', description: 'Supply chain attack via SolarWinds Orion update mechanism' },
    { type: 'campaign', id: 'campaign--typhoon-infra', created: '2026-03-01T00:00:00Z', name: 'Typhoon Infrastructure', description: 'Chinese pre-positioning in US critical infrastructure' },
    { type: 'infrastructure', id: 'infrastructure--cobalt-c2', created: '2026-01-15T00:00:00Z', name: 'Cobalt Strike C2 Cluster', description: 'Network of Cobalt Strike team servers', infrastructure_types: ['command-and-control'] },
    { type: 'infrastructure', id: 'infrastructure--soho-proxy', created: '2026-03-01T00:00:00Z', name: 'SOHO Router Proxy Network', description: 'Compromised residential routers used as relay points', infrastructure_types: ['anonymization'] },
    { type: 'relationship', id: 'relationship--1', created: '2026-01-15T00:00:00Z', relationship_type: 'uses', source_ref: 'threat-actor--apt29', target_ref: 'malware--sunburst' },
    { type: 'relationship', id: 'relationship--2', created: '2026-01-15T00:00:00Z', relationship_type: 'uses', source_ref: 'threat-actor--apt29', target_ref: 'malware--cobalt-strike' },
    { type: 'relationship', id: 'relationship--3', created: '2026-01-15T00:00:00Z', relationship_type: 'uses', source_ref: 'threat-actor--apt29', target_ref: 'attack-pattern--t1195' },
    { type: 'relationship', id: 'relationship--4', created: '2026-01-15T00:00:00Z', relationship_type: 'uses', source_ref: 'malware--sunburst', target_ref: 'attack-pattern--t1059' },
    { type: 'relationship', id: 'relationship--5', created: '2026-01-15T00:00:00Z', relationship_type: 'drops', source_ref: 'malware--sunburst', target_ref: 'malware--teardrop' },
    { type: 'relationship', id: 'relationship--6', created: '2026-01-15T00:00:00Z', relationship_type: 'indicates', source_ref: 'indicator--avsvmcloud', target_ref: 'malware--sunburst' },
    { type: 'relationship', id: 'relationship--7', created: '2026-01-15T00:00:00Z', relationship_type: 'indicates', source_ref: 'indicator--apt29-ip', target_ref: 'threat-actor--apt29' },
    { type: 'relationship', id: 'relationship--8', created: '2026-01-15T00:00:00Z', relationship_type: 'attributed-to', source_ref: 'campaign--solarflare', target_ref: 'threat-actor--apt29' },
    { type: 'relationship', id: 'relationship--9', created: '2026-03-01T00:00:00Z', relationship_type: 'attributed-to', source_ref: 'campaign--typhoon-infra', target_ref: 'threat-actor--volt-typhoon' },
    { type: 'relationship', id: 'relationship--10', created: '2026-03-01T00:00:00Z', relationship_type: 'uses', source_ref: 'threat-actor--volt-typhoon', target_ref: 'attack-pattern--t1078' },
    { type: 'relationship', id: 'relationship--11', created: '2026-03-01T00:00:00Z', relationship_type: 'uses', source_ref: 'campaign--typhoon-infra', target_ref: 'infrastructure--soho-proxy' },
    { type: 'relationship', id: 'relationship--12', created: '2026-01-15T00:00:00Z', relationship_type: 'uses', source_ref: 'campaign--solarflare', target_ref: 'infrastructure--cobalt-c2' },
    { type: 'relationship', id: 'relationship--13', created: '2026-02-01T00:00:00Z', relationship_type: 'uses', source_ref: 'malware--lockbit', target_ref: 'attack-pattern--t1486' },
    { type: 'relationship', id: 'relationship--14', created: '2026-02-01T00:00:00Z', relationship_type: 'indicates', source_ref: 'indicator--lockbit-hash', target_ref: 'malware--lockbit' },
  ]
};

// ============================================================================
// FEED DATA (hardcoded fallback)
// ============================================================================
const FEED_SOURCES = [
  { id: 'cisa-kev', name: 'CISA KEV', desc: 'Known Exploited Vulnerabilities Catalog', url: '/data/feeds/cisa-kev.json', count: 1200, updated: '2026-09-21T06:00:00Z' },
  { id: 'threatfox', name: 'ThreatFox IOCs', desc: 'Indicators of Compromise from abuse.ch', url: '/data/feeds/threat-iocs.json', count: 850, updated: '2026-09-21T04:30:00Z' },
  { id: 'urlhaus', name: 'URLhaus', desc: 'Malicious URL tracking by abuse.ch', url: '/data/feeds/malware-urls.json', count: 620, updated: '2026-09-21T05:15:00Z' },
  { id: 'botnet-c2', name: 'Botnet C2', desc: 'Botnet command and control trackers', url: '/data/feeds/botnet-c2.json', count: 340, updated: '2026-09-21T03:45:00Z' },
  { id: 'malwarebazaar', name: 'MalwareBazaar', desc: 'Malware sample sharing platform', url: null, count: 480, updated: '2026-09-21T02:00:00Z' },
];

const FALLBACK_FEED = [
  { date: '2026-09-21', feed: 'CISA KEV', type: 'CVE', value: 'CVE-2024-3400', severity: 'Critical', details: 'PAN-OS GlobalProtect command injection' },
  { date: '2026-09-21', feed: 'CISA KEV', type: 'CVE', value: 'CVE-2024-21762', severity: 'Critical', details: 'FortiOS SSL VPN out-of-bounds write' },
  { date: '2026-09-20', feed: 'ThreatFox', type: 'IP', value: '185.86.148.27', severity: 'High', details: 'APT28 Cobalt Strike C2' },
  { date: '2026-09-20', feed: 'ThreatFox', type: 'Domain', value: 'update-system32.com', severity: 'High', details: 'APT41 malware distribution' },
  { date: '2026-09-20', feed: 'URLhaus', type: 'URL', value: 'http://185.86.148.27:8443/api/beacon', severity: 'Critical', details: 'Cobalt Strike beacon endpoint' },
  { date: '2026-09-19', feed: 'Botnet C2', type: 'IP', value: '92.118.160.22', severity: 'High', details: 'Emotet distribution server' },
  { date: '2026-09-19', feed: 'ThreatFox', type: 'Hash-SHA256', value: 'c6d7e8f9a1b2...', severity: 'Critical', details: 'LockBit 3.0 encryptor sample' },
  { date: '2026-09-19', feed: 'URLhaus', type: 'URL', value: 'https://cdn-update.cloud-service-auth.net/payload.dll', severity: 'High', details: 'Scattered Spider loader' },
  { date: '2026-09-18', feed: 'CISA KEV', type: 'CVE', value: 'CVE-2024-21887', severity: 'Critical', details: 'Ivanti Connect Secure command injection' },
  { date: '2026-09-18', feed: 'MalwareBazaar', type: 'Hash-MD5', value: 'b5c6d7e8f9a1b2c3...', severity: 'Critical', details: 'BlackCat ransomware sample' },
  { date: '2026-09-17', feed: 'Botnet C2', type: 'IP', value: '23.227.196.55', severity: 'Medium', details: 'Mirai botnet C2' },
  { date: '2026-09-17', feed: 'ThreatFox', type: 'IP', value: '37.120.247.89', severity: 'High', details: 'RedLine Stealer C2' },
  { date: '2026-09-16', feed: 'URLhaus', type: 'URL', value: 'https://kitten-research-portal.org/auth/login.php', severity: 'Medium', details: 'Charming Kitten credential harvester' },
  { date: '2026-09-16', feed: 'CISA KEV', type: 'CVE', value: 'CVE-2023-4966', severity: 'Critical', details: 'Citrix Bleed information disclosure' },
  { date: '2026-09-15', feed: 'MalwareBazaar', type: 'Hash-SHA256', value: 'a7d3c2f1e8b6...', severity: 'High', details: 'AppleJeus cryptocurrency trojan' },
];

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================
function _orFmtDate(d) { return new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }); }
function _orTimeAgo(ts) {
  var d = Date.now() - new Date(ts).getTime(), s = Math.floor(d / 1000);
  if (s < 60) return s + 's ago'; if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago'; return Math.floor(s / 86400) + 'd ago';
}
function _orSevColor(sev) {
  if (sev === 'Critical') return '#ff1744';
  if (sev === 'High') return '#ff9100';
  if (sev === 'Medium') return '#ffd600';
  if (sev === 'Low') return '#00e676';
  return '#00e5ff';
}
function _orSevBg(sev) {
  if (sev === 'Critical') return 'rgba(255,23,68,.12)';
  if (sev === 'High') return 'rgba(255,145,0,.12)';
  if (sev === 'Medium') return 'rgba(255,214,0,.12)';
  if (sev === 'Low') return 'rgba(0,230,118,.12)';
  return 'rgba(0,229,255,.12)';
}
function _orTypeColor(t) {
  var map = { IP: '#3b82f6', Domain: '#8b5cf6', 'Hash-MD5': '#f97316', 'Hash-SHA256': '#f97316', URL: '#06b6d4', Email: '#ec4899', CVE: '#ef4444' };
  return map[t] || '#94a3b8';
}
function _orNationFlag(n) {
  var map = { 'Russia': 'RU', 'China': 'CN', 'North Korea': 'KP', 'Iran': 'IR', 'United States': 'US', 'Vietnam': 'VN', 'South Korea': 'KR', 'India': 'IN', 'US/UK': 'US' };
  return map[n] || '??';
}

// ============================================================================
// MAIN RENDER
// ============================================================================
var _orInterval = null;

export function cleanupOracle() {
  if (_orInterval) { clearInterval(_orInterval); _orInterval = null; }
}

export function renderOracle(main) {
  var activeTab = 'dashboard';
  var iocs = IOC_DB.map(function(i) { return Object.assign({}, i); });
  var feedData = FALLBACK_FEED.slice();
  var stixBundle = null;
  var selectedStixNode = null;
  var actorSearch = '';
  var actorNationFilter = '';
  var iocSearch = '';
  var iocTypeFilter = '';
  var selectedCampaign = null;
  var reportType = 'executive';

  function render() {
    main.innerHTML =
      '<style>' +
      '.or-wrap{font-family:ui-sans-serif,system-ui,-apple-system,sans-serif;position:relative}' +
      '.or-header{display:flex;align-items:center;gap:16px;padding:16px 0;border-bottom:2px solid var(--acc,#3b82f6)}' +
      '.or-title{font-size:1.5rem;font-weight:800;letter-spacing:.06em;color:var(--acc,#3b82f6);margin:0}' +
      '.or-sub{color:var(--mut,#888);font-size:.72rem;letter-spacing:.04em;text-transform:uppercase}' +
      '.or-dot{width:8px;height:8px;border-radius:50%;background:#22c55e;box-shadow:0 0 8px #22c55e;animation:or-pulse 2s ease-in-out infinite}' +
      '@keyframes or-pulse{0%,100%{opacity:1}50%{opacity:.4}}' +
      '.or-tabs{display:flex;gap:2px;overflow-x:auto;padding:10px 0 0;scrollbar-width:none}' +
      '.or-tabs::-webkit-scrollbar{display:none}' +
      '.or-tab{background:transparent;border:none;border-bottom:2px solid transparent;color:var(--mut,#888);padding:8px 16px;font-size:.72rem;font-weight:600;letter-spacing:.03em;text-transform:uppercase;cursor:pointer;transition:all .2s;font-family:inherit;white-space:nowrap;flex-shrink:0}' +
      '.or-tab:hover{color:var(--txt,#eee);background:rgba(59,130,246,.05)}' +
      '.or-tab.on{color:var(--acc,#3b82f6);border-bottom-color:var(--acc,#3b82f6)}' +
      '.or-content{margin-top:12px}' +
      '.or-panel{background:var(--card,#1a1f2e);border:1px solid var(--line,#333);border-radius:8px;overflow:hidden;margin-bottom:12px}' +
      '.or-panel-h{padding:10px 14px;border-bottom:1px solid var(--line,#333);background:rgba(0,0,0,.1);font-size:.7rem;font-weight:700;letter-spacing:.04em;text-transform:uppercase;color:var(--mut,#888);display:flex;align-items:center;justify-content:space-between;gap:8px}' +
      '.or-panel-b{padding:14px}' +
      '.or-grid2{display:grid;grid-template-columns:1fr 1fr;gap:10px}' +
      '.or-grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px}' +
      '.or-grid4{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:10px}' +
      '.or-stat{background:var(--card,#1a1f2e);border:1px solid var(--line,#333);border-radius:8px;padding:14px 16px}' +
      '.or-stat-v{font-size:1.6rem;font-weight:800;font-variant-numeric:tabular-nums}' +
      '.or-stat-l{font-size:.65rem;color:var(--mut,#888);letter-spacing:.04em;text-transform:uppercase;margin-top:4px}' +
      '.or-btn{background:transparent;border:1px solid var(--acc,#3b82f6);color:var(--acc,#3b82f6);padding:6px 14px;font-size:.72rem;font-weight:600;letter-spacing:.03em;text-transform:uppercase;border-radius:6px;cursor:pointer;font-family:inherit;transition:all .15s}' +
      '.or-btn:hover{background:var(--acc,#3b82f6);color:#fff}' +
      '.or-btn.fill{background:var(--acc,#3b82f6);color:#fff;border-color:var(--acc,#3b82f6)}' +
      '.or-btn.fill:hover{filter:brightness(1.1)}' +
      '.or-btn.ghost{border-color:var(--line,#333);color:var(--mut,#888)}' +
      '.or-btn.ghost:hover{border-color:var(--txt,#eee);color:var(--txt,#eee);background:rgba(255,255,255,.05)}' +
      '.or-btn.sm{padding:4px 10px;font-size:.65rem}' +
      '.or-inp{background:var(--card,#1a1f2e);color:var(--txt,#eee);border:1px solid var(--line,#333);padding:7px 10px;border-radius:6px;font-size:.78rem;font-family:inherit;width:100%;box-sizing:border-box}' +
      '.or-inp:focus{border-color:var(--acc,#3b82f6);outline:none}' +
      '.or-sel{background:var(--card,#1a1f2e);color:var(--txt,#eee);border:1px solid var(--line,#333);padding:7px 10px;border-radius:6px;font-size:.78rem;font-family:inherit}' +
      '.or-sel:focus{border-color:var(--acc,#3b82f6);outline:none}' +
      '.or-textarea{background:var(--card,#1a1f2e);color:var(--txt,#eee);border:1px solid var(--line,#333);padding:8px 10px;border-radius:6px;font-size:.78rem;font-family:var(--font-mono,monospace);width:100%;box-sizing:border-box;resize:vertical;min-height:120px}' +
      '.or-textarea:focus{border-color:var(--acc,#3b82f6);outline:none}' +
      '.or-tbl{width:100%;border-collapse:collapse;font-size:.76rem}' +
      '.or-tbl th{padding:8px 10px;text-align:left;color:var(--mut,#888);border-bottom:2px solid var(--line,#333);font-weight:700;letter-spacing:.03em;text-transform:uppercase;font-size:.65rem}' +
      '.or-tbl td{padding:7px 10px;border-bottom:1px solid var(--line,#333)}' +
      '.or-tbl tr:hover{background:rgba(59,130,246,.03)}' +
      '.or-badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.62rem;font-weight:700;letter-spacing:.03em;text-transform:uppercase;white-space:nowrap}' +
      '.or-chip{display:inline-flex;align-items:center;gap:4px;padding:3px 8px;border-radius:4px;font-size:.64rem;font-weight:600;border:1px solid var(--line,#333);cursor:pointer;transition:all .15s}' +
      '.or-chip:hover{border-color:var(--acc,#3b82f6)}' +
      '.or-chip.on{background:var(--acc,#3b82f6);color:#fff;border-color:var(--acc,#3b82f6)}' +
      '.or-card{background:var(--card,#1a1f2e);border:1px solid var(--line,#333);border-radius:8px;padding:14px;transition:border-color .2s;cursor:pointer}' +
      '.or-card:hover{border-color:var(--acc,#3b82f6)}' +
      '.or-card-title{font-weight:700;font-size:.88rem;margin-bottom:4px}' +
      '.or-card-sub{font-size:.72rem;color:var(--mut,#888)}' +
      '.or-feed-item{padding:8px 0;border-bottom:1px solid var(--line,#333);font-size:.75rem;display:flex;gap:10px;align-items:center}' +
      '.or-feed-time{color:var(--mut,#888);white-space:nowrap;font-size:.65rem;min-width:60px}' +
      '.or-timeline-item{padding:8px 0 8px 18px;border-left:2px solid var(--line,#333);font-size:.74rem;position:relative}' +
      '.or-timeline-item::before{content:"";position:absolute;left:-5px;top:12px;width:8px;height:8px;border-radius:50%;background:var(--acc,#3b82f6)}' +
      '.or-diamond{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:12px 0}' +
      '.or-diamond-node{background:var(--card,#1a1f2e);border:1px solid var(--line,#333);border-radius:8px;padding:12px}' +
      '.or-diamond-label{font-size:.65rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--acc,#3b82f6);margin-bottom:6px}' +
      '.or-diamond-text{font-size:.74rem;color:var(--txt,#eee);line-height:1.5}' +
      '.or-killchain{display:flex;gap:2px;margin:12px 0;flex-wrap:wrap}' +
      '.or-kc-step{padding:6px 12px;border-radius:4px;font-size:.65rem;font-weight:600;text-transform:uppercase;letter-spacing:.02em}' +
      '.or-kc-active{background:rgba(59,130,246,.15);color:var(--acc,#3b82f6);border:1px solid rgba(59,130,246,.3)}' +
      '.or-kc-inactive{background:rgba(100,116,139,.1);color:var(--mut,#888);border:1px solid var(--line,#333)}' +
      '.or-phase-bar{display:flex;height:24px;margin:8px 0;border-radius:4px;overflow:hidden;background:var(--line,#333);position:relative}' +
      '.or-phase-seg{position:absolute;height:100%;border-radius:3px;font-size:.55rem;display:flex;align-items:center;justify-content:center;font-weight:600;color:#fff;text-transform:uppercase;overflow:hidden;white-space:nowrap;padding:0 4px}' +
      '.or-stix-graph{position:relative;width:100%;height:400px;border:1px solid var(--line,#333);border-radius:8px;overflow:hidden;background:rgba(0,0,0,.1)}' +
      '.or-stix-node{position:absolute;padding:6px 10px;border:2px solid;border-radius:6px;font-size:.65rem;font-weight:600;cursor:grab;user-select:none;text-align:center;min-width:80px;z-index:2;transition:box-shadow .15s}' +
      '.or-stix-node:hover{box-shadow:0 0 12px rgba(59,130,246,.3)}' +
      '.or-stix-node.selected{box-shadow:0 0 0 2px var(--acc,#3b82f6)}' +
      '.or-map{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:12px 0}' +
      '.or-map-region{background:var(--card,#1a1f2e);border:1px solid var(--line,#333);border-radius:8px;padding:10px;text-align:center}' +
      '.or-map-region-name{font-size:.65rem;font-weight:600;text-transform:uppercase;letter-spacing:.03em;color:var(--mut,#888);margin-bottom:4px}' +
      '.or-map-region-count{font-size:1.2rem;font-weight:800;font-variant-numeric:tabular-nums}' +
      '.or-actions{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}' +
      '.or-search-row{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;align-items:center}' +
      '.or-report-preview{background:var(--card,#1a1f2e);border:1px solid var(--line,#333);border-radius:8px;padding:20px;font-size:.8rem;line-height:1.7}' +
      '.or-report-preview h2{font-size:1.1rem;margin:16px 0 8px;color:var(--acc,#3b82f6)}' +
      '.or-report-preview h3{font-size:.9rem;margin:12px 0 6px}' +
      '.or-report-preview ul{margin:4px 0;padding-left:18px}' +
      '.or-report-preview li{margin:3px 0}' +
      '.or-corr{border:2px solid var(--acc,#3b82f6);background:rgba(59,130,246,.08)}' +
      '@media(max-width:768px){.or-grid2,.or-grid3,.or-grid4,.or-map,.or-diamond{grid-template-columns:1fr}.or-tabs{gap:0}}' +
      '</style>' +
      '<div class="or-wrap">' +
        '<div class="or-header">' +
          '<h1 class="or-title">ORACLE</h1>' +
          '<div class="or-dot"></div>' +
          '<span class="or-sub">Omniscient Reconnaissance, Analysis, Campaign &amp; Lookup Engine</span>' +
          '<span style="flex:1"></span>' +
          '<span class="or-sub" style="font-variant-numeric:tabular-nums">' + esc(iocs.length) + ' IOCs | ' + esc(APT_DB.length) + ' Actors | ' + esc(CAMPAIGN_DB.length) + ' Campaigns</span>' +
        '</div>' +
        '<div class="or-tabs">' +
          [['dashboard','Intel Dashboard'],['iocs','IOC Manager'],['actors','Threat Actors'],['campaigns','Campaign Tracker'],['stix','STIX Viewer'],['feeds','Feed Aggregator'],['reports','Reports']].map(function(t) {
            return '<button class="or-tab' + (activeTab === t[0] ? ' on' : '') + '" data-t="' + t[0] + '">' + t[1] + '</button>';
          }).join('') +
        '</div>' +
        '<div class="or-content" id="or-content"></div>' +
      '</div>';

    main.querySelector('.or-tabs').onclick = function(e) {
      var b = e.target.closest('.or-tab');
      if (b) { activeTab = b.dataset.t; render(); }
    };

    var content = main.querySelector('#or-content');
    if (activeTab === 'dashboard') renderDashboard(content);
    else if (activeTab === 'iocs') renderIOCManager(content);
    else if (activeTab === 'actors') renderActors(content);
    else if (activeTab === 'campaigns') renderCampaigns(content);
    else if (activeTab === 'stix') renderSTIX(content);
    else if (activeTab === 'feeds') renderFeeds(content);
    else if (activeTab === 'reports') renderReports(content);
  }

  // ========== TAB 1: INTEL DASHBOARD ==========
  function renderDashboard(c) {
    var critIOCs = iocs.filter(function(i) { return i.severity === 'Critical'; }).length;
    var activeCampaigns = CAMPAIGN_DB.filter(function(c) { return c.status === 'Active'; }).length;
    var regions = {};
    APT_DB.forEach(function(a) {
      var r = a.nation; regions[r] = (regions[r] || 0) + 1;
    });

    c.innerHTML =
      '<div class="or-grid4" style="margin-bottom:14px">' +
        '<div class="or-stat"><div class="or-stat-v" style="color:#22c55e">' + activeCampaigns + '</div><div class="or-stat-l">Active Campaigns</div></div>' +
        '<div class="or-stat"><div class="or-stat-v" style="color:#3b82f6">' + APT_DB.length + '</div><div class="or-stat-l">Tracked Actors</div></div>' +
        '<div class="or-stat"><div class="or-stat-v" style="color:#8b5cf6">' + iocs.length + '</div><div class="or-stat-l">Total IOCs</div></div>' +
        '<div class="or-stat"><div class="or-stat-v" style="color:#ff1744">' + critIOCs + '</div><div class="or-stat-l">Critical Indicators</div></div>' +
      '</div>' +

      '<div class="or-grid2">' +
        '<div class="or-panel">' +
          '<div class="or-panel-h">Geographic Threat Distribution</div>' +
          '<div class="or-panel-b">' +
            '<div class="or-map">' +
              Object.entries(regions).sort(function(a,b) { return b[1]-a[1]; }).slice(0,8).map(function(r) {
                return '<div class="or-map-region"><div class="or-map-region-name">' + esc(r[0]) + ' [' + _orNationFlag(r[0]) + ']</div><div class="or-map-region-count" style="color:' + (r[1] > 5 ? '#ff1744' : r[1] > 3 ? '#ff9100' : '#3b82f6') + '">' + r[1] + '</div></div>';
              }).join('') +
            '</div>' +
          '</div>' +
        '</div>' +
        '<div class="or-panel">' +
          '<div class="or-panel-h">Trending IOCs</div>' +
          '<div class="or-panel-b">' +
            iocs.slice(0, 10).map(function(i) {
              return '<div class="or-feed-item">' +
                '<span class="or-badge" style="background:' + _orSevBg(i.severity) + ';color:' + _orSevColor(i.severity) + '">' + esc(i.severity) + '</span>' +
                '<span class="or-badge" style="background:rgba(59,130,246,.1);color:' + _orTypeColor(i.type) + '">' + esc(i.type) + '</span>' +
                '<span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:var(--font-mono,monospace);font-size:.72rem">' + esc(i.value) + '</span>' +
                '<span class="or-feed-time">' + _orTimeAgo(i.added) + '</span>' +
              '</div>';
            }).join('') +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="or-panel">' +
        '<div class="or-panel-h">Activity Timeline</div>' +
        '<div class="or-panel-b">' +
          '<div>' +
            _genTimeline().map(function(ev) {
              return '<div class="or-timeline-item"><span class="or-feed-time">' + esc(ev.time) + '</span> ' + esc(ev.text) + '</div>';
            }).join('') +
          '</div>' +
        '</div>' +
      '</div>';
  }

  function _genTimeline() {
    var events = [];
    iocs.slice(0, 8).forEach(function(i) { events.push({ time: _orTimeAgo(i.added), text: 'New ' + i.type + ' IOC added: ' + i.value.substring(0, 30) + (i.value.length > 30 ? '...' : '') }); });
    CAMPAIGN_DB.filter(function(c) { return c.status === 'Active'; }).forEach(function(c) { events.push({ time: _orTimeAgo(c.start), text: 'Campaign active: ' + c.name + ' (' + c.actor + ')' }); });
    events.push({ time: '2h ago', text: 'Feed refresh: CISA KEV updated with 3 new entries' });
    events.push({ time: '4h ago', text: 'Feed refresh: ThreatFox added 12 new IOCs' });
    events.push({ time: '6h ago', text: 'Threat actor profile updated: Volt Typhoon' });
    events.push({ time: '8h ago', text: 'New STIX bundle imported: 28 objects' });
    return events.slice(0, 20);
  }

  // ========== TAB 2: IOC MANAGER ==========
  function renderIOCManager(c) {
    var filtered = iocs.filter(function(i) {
      if (iocTypeFilter && i.type !== iocTypeFilter) return false;
      if (iocSearch) {
        var q = iocSearch.toLowerCase();
        return i.value.toLowerCase().indexOf(q) !== -1 || (i.tags || []).some(function(t) { return t.toLowerCase().indexOf(q) !== -1; }) || (i.notes || '').toLowerCase().indexOf(q) !== -1;
      }
      return true;
    });

    c.innerHTML =
      '<div class="or-panel">' +
        '<div class="or-panel-h">Add IOC<span style="flex:1"></span><button class="or-btn sm" id="or-bulk-toggle">Bulk Import</button></div>' +
        '<div class="or-panel-b">' +
          '<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end">' +
            '<div style="flex:0 0 120px"><label style="font-size:.65rem;color:var(--mut)">Type</label><select class="or-sel" id="or-ioc-type" style="width:100%"><option>IP</option><option>Domain</option><option>Hash-MD5</option><option>Hash-SHA256</option><option>URL</option><option>Email</option><option>CVE</option></select></div>' +
            '<div style="flex:1;min-width:200px"><label style="font-size:.65rem;color:var(--mut)">Value</label><input class="or-inp" id="or-ioc-value" placeholder="Enter indicator value"></div>' +
            '<div style="flex:0 0 100px"><label style="font-size:.65rem;color:var(--mut)">Severity</label><select class="or-sel" id="or-ioc-sev" style="width:100%"><option>Critical</option><option>High</option><option>Medium</option><option>Low</option></select></div>' +
            '<div style="flex:0 0 80px"><label style="font-size:.65rem;color:var(--mut)">Confidence</label><input class="or-inp" id="or-ioc-conf" type="number" value="80" min="0" max="100"></div>' +
            '<div style="flex:0 0 120px"><label style="font-size:.65rem;color:var(--mut)">Tags (comma)</label><input class="or-inp" id="or-ioc-tags" placeholder="APT28, C2"></div>' +
            '<div style="flex:0 0 100px"><label style="font-size:.65rem;color:var(--mut)">Source</label><input class="or-inp" id="or-ioc-src" placeholder="CISA"></div>' +
            '<button class="or-btn fill" id="or-ioc-add" style="flex:none;height:34px">Add IOC</button>' +
          '</div>' +
          '<div id="or-bulk-area" style="display:none;margin-top:10px">' +
            '<textarea class="or-textarea" id="or-bulk-csv" placeholder="Paste CSV: type,value,severity,tags (one per line)&#10;IP,185.86.148.27,Critical,APT28&#10;Domain,evil.com,High,Phishing"></textarea>' +
            '<div style="display:flex;gap:8px;margin-top:8px"><button class="or-btn fill sm" id="or-bulk-import">Import CSV</button></div>' +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="or-search-row">' +
        '<input class="or-inp" style="flex:1;max-width:300px" placeholder="Search IOCs..." id="or-ioc-search" value="' + esc(iocSearch) + '">' +
        '<div style="display:flex;gap:4px;flex-wrap:wrap">' +
          ['', 'IP', 'Domain', 'Hash-MD5', 'Hash-SHA256', 'URL', 'Email', 'CVE'].map(function(t) {
            return '<span class="or-chip' + (iocTypeFilter === t ? ' on' : '') + '" data-type="' + t + '">' + (t || 'All') + '</span>';
          }).join('') +
        '</div>' +
        '<span style="flex:1"></span>' +
        '<button class="or-btn sm" id="or-export-json">Export JSON</button>' +
        '<button class="or-btn sm" id="or-export-csv">Export CSV</button>' +
      '</div>' +

      '<div class="or-panel">' +
        '<div class="or-panel-h">IOC Database <span style="font-weight:400;color:var(--txt)">' + filtered.length + ' indicators</span></div>' +
        '<div style="overflow-x:auto">' +
          '<table class="or-tbl"><thead><tr><th>Type</th><th>Value</th><th>Severity</th><th>Conf</th><th>Tags</th><th>Source</th><th>Added</th><th>Actions</th></tr></thead><tbody>' +
          filtered.slice(0, 50).map(function(i) {
            return '<tr>' +
              '<td><span class="or-badge" style="background:rgba(59,130,246,.1);color:' + _orTypeColor(i.type) + '">' + esc(i.type) + '</span></td>' +
              '<td style="font-family:var(--font-mono,monospace);font-size:.72rem;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(i.value) + '</td>' +
              '<td><span class="or-badge" style="background:' + _orSevBg(i.severity) + ';color:' + _orSevColor(i.severity) + '">' + esc(i.severity) + '</span></td>' +
              '<td style="font-variant-numeric:tabular-nums">' + i.confidence + '%</td>' +
              '<td>' + (i.tags || []).map(function(t) { return '<span class="or-badge" style="background:rgba(100,116,139,.15);color:var(--mut)">' + esc(t) + '</span>'; }).join(' ') + '</td>' +
              '<td>' + esc(i.source) + '</td>' +
              '<td style="white-space:nowrap">' + _orFmtDate(i.added) + '</td>' +
              '<td><button class="or-btn sm ghost" data-del="' + i.id + '">Remove</button></td>' +
            '</tr>';
          }).join('') +
          '</tbody></table>' +
        '</div>' +
      '</div>';

    // Wire events
    c.querySelector('#or-bulk-toggle').onclick = function() {
      var a = c.querySelector('#or-bulk-area');
      a.style.display = a.style.display === 'none' ? 'block' : 'none';
    };
    c.querySelector('#or-ioc-add').onclick = function() {
      var type = c.querySelector('#or-ioc-type').value;
      var value = c.querySelector('#or-ioc-value').value.trim();
      if (!value) return;
      iocs.unshift({ id: Date.now(), type: type, value: value, severity: c.querySelector('#or-ioc-sev').value, confidence: parseInt(c.querySelector('#or-ioc-conf').value) || 80, tags: (c.querySelector('#or-ioc-tags').value || '').split(',').map(function(s){return s.trim();}).filter(Boolean), source: c.querySelector('#or-ioc-src').value || 'Manual', added: new Date().toISOString().slice(0,10), notes: '' });
      render();
    };
    c.querySelector('#or-bulk-import').onclick = function() {
      var csv = c.querySelector('#or-bulk-csv').value.trim();
      if (!csv) return;
      csv.split('\n').forEach(function(line) {
        var p = line.split(',').map(function(s){return s.trim();});
        if (p.length >= 2) {
          iocs.unshift({ id: Date.now() + Math.random(), type: p[0] || 'IP', value: p[1], severity: p[2] || 'Medium', confidence: 70, tags: p[3] ? p[3].split(';') : [], source: 'CSV Import', added: new Date().toISOString().slice(0,10), notes: '' });
        }
      });
      render();
    };
    c.querySelector('#or-ioc-search').oninput = function(e) { iocSearch = e.target.value; renderIOCManager(c); };
    c.querySelectorAll('.or-chip[data-type]').forEach(function(ch) {
      ch.onclick = function() { iocTypeFilter = ch.dataset.type; renderIOCManager(c); };
    });
    c.querySelector('#or-export-json').onclick = function() {
      var blob = new Blob([JSON.stringify(filtered, null, 2)], { type: 'application/json' });
      var a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'oracle-iocs.json'; a.click();
    };
    c.querySelector('#or-export-csv').onclick = function() {
      var csv = 'Type,Value,Severity,Confidence,Tags,Source,Added\n' + filtered.map(function(i) {
        return [i.type, '"' + i.value + '"', i.severity, i.confidence, '"' + (i.tags || []).join(';') + '"', i.source, i.added].join(',');
      }).join('\n');
      var blob = new Blob([csv], { type: 'text/csv' });
      var a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'oracle-iocs.csv'; a.click();
    };
    c.querySelectorAll('[data-del]').forEach(function(btn) {
      btn.onclick = function() { iocs = iocs.filter(function(i) { return String(i.id) !== btn.dataset.del; }); renderIOCManager(c); };
    });
  }

  // ========== TAB 3: THREAT ACTORS ==========
  function renderActors(c) {
    var nations = []; APT_DB.forEach(function(a) { if (nations.indexOf(a.nation) === -1) nations.push(a.nation); });
    var filtered = APT_DB.filter(function(a) {
      if (actorNationFilter && a.nation !== actorNationFilter) return false;
      if (actorSearch) {
        var q = actorSearch.toLowerCase();
        return a.name.toLowerCase().indexOf(q) !== -1 || a.aliases.some(function(al) { return al.toLowerCase().indexOf(q) !== -1; }) || a.nation.toLowerCase().indexOf(q) !== -1;
      }
      return true;
    });

    c.innerHTML =
      '<div class="or-search-row">' +
        '<input class="or-inp" style="flex:1;max-width:300px" placeholder="Search actors..." id="or-actor-search" value="' + esc(actorSearch) + '">' +
        '<select class="or-sel" id="or-actor-nation"><option value="">All Nations</option>' + nations.map(function(n) { return '<option' + (actorNationFilter === n ? ' selected' : '') + '>' + esc(n) + '</option>'; }).join('') + '</select>' +
        '<span style="flex:1"></span>' +
        '<span class="or-sub">' + filtered.length + ' actors</span>' +
      '</div>' +

      '<div class="or-grid3">' +
      filtered.map(function(a) {
        var actorIOCs = iocs.filter(function(i) { return (i.tags || []).some(function(t) { return t.toLowerCase() === a.name.toLowerCase() || a.aliases.some(function(al) { return al.toLowerCase() === t.toLowerCase(); }); }); }).length;
        return '<div class="or-card" data-actor="' + a.id + '">' +
          '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">' +
            '<span class="or-badge" style="background:rgba(59,130,246,.1);color:#3b82f6">[' + _orNationFlag(a.nation) + ']</span>' +
            '<span class="or-card-title">' + esc(a.name) + '</span>' +
          '</div>' +
          '<div class="or-card-sub">' + esc(a.aliases.slice(0, 3).join(', ')) + '</div>' +
          '<div style="display:flex;gap:4px;flex-wrap:wrap;margin:8px 0">' +
            '<span class="or-badge" style="background:rgba(139,92,246,.1);color:#8b5cf6">' + esc(a.motivation) + '</span>' +
            '<span class="or-badge" style="background:rgba(34,197,94,.1);color:#22c55e">Since ' + a.since + '</span>' +
          '</div>' +
          '<div style="font-size:.68rem;color:var(--mut);margin-top:6px">Sectors: ' + esc(a.sectors.slice(0,3).join(', ')) + '</div>' +
          '<div style="display:flex;gap:8px;margin-top:8px">' +
            '<span style="font-size:.65rem;color:var(--mut)">' + a.techniques.length + ' TTPs</span>' +
            '<span style="font-size:.65rem;color:var(--mut)">' + a.campaigns.length + ' Campaigns</span>' +
            '<span style="font-size:.65rem;color:var(--mut)">' + actorIOCs + ' IOCs</span>' +
          '</div>' +
        '</div>';
      }).join('') +
      '</div>';

    c.querySelector('#or-actor-search').oninput = function(e) { actorSearch = e.target.value; renderActors(c); };
    c.querySelector('#or-actor-nation').onchange = function(e) { actorNationFilter = e.target.value; renderActors(c); };
    c.querySelectorAll('.or-card[data-actor]').forEach(function(card) {
      card.onclick = function() {
        var a = APT_DB.find(function(x) { return x.id === card.dataset.actor; });
        if (!a) return;
        var modal = document.createElement('div');
        modal.style.cssText = 'position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;padding:20px';
        modal.onclick = function(e) { if (e.target === modal) modal.remove(); };
        modal.innerHTML =
          '<div style="background:var(--card,#1a1f2e);border:1px solid var(--line,#333);border-radius:10px;padding:20px;max-width:680px;width:100%;max-height:80vh;overflow-y:auto">' +
            '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">' +
              '<h2 style="margin:0;font-size:1.1rem">' + esc(a.name) + '</h2>' +
              '<button class="or-btn sm ghost" id="or-close-modal">Close</button>' +
            '</div>' +
            '<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px">' +
              '<span class="or-badge" style="background:rgba(59,130,246,.1);color:#3b82f6">' + esc(a.nation) + '</span>' +
              '<span class="or-badge" style="background:rgba(139,92,246,.1);color:#8b5cf6">' + esc(a.motivation) + '</span>' +
              '<span class="or-badge" style="background:rgba(34,197,94,.1);color:#22c55e">Active since ' + a.since + '</span>' +
            '</div>' +
            '<p style="font-size:.78rem;color:var(--mut);margin:4px 0"><strong>Aliases:</strong> ' + esc(a.aliases.join(', ')) + '</p>' +
            (a.agency ? '<p style="font-size:.78rem;color:var(--mut);margin:4px 0"><strong>Attribution:</strong> ' + esc(a.agency) + '</p>' : '') +
            '<p style="font-size:.78rem;color:var(--mut);margin:4px 0"><strong>Target sectors:</strong> ' + esc(a.sectors.join(', ')) + '</p>' +
            '<p style="font-size:.78rem;color:var(--mut);margin:4px 0"><strong>Known campaigns:</strong> ' + esc(a.campaigns.join(', ')) + '</p>' +
            '<div style="margin-top:10px"><strong style="font-size:.72rem">MITRE ATT&amp;CK Techniques:</strong></div>' +
            '<div style="display:flex;gap:4px;flex-wrap:wrap;margin:6px 0">' +
              a.techniques.map(function(t) { return '<span class="or-badge" style="background:rgba(249,115,22,.12);color:#f97316">' + esc(t) + '</span>'; }).join('') +
            '</div>' +
            '<div style="margin-top:10px"><strong style="font-size:.72rem">Associated IOCs:</strong></div>' +
            '<div style="display:flex;gap:4px;flex-wrap:wrap;margin:6px 0">' +
              a.iocs.map(function(i) { return '<span style="font-family:var(--font-mono,monospace);font-size:.68rem;background:rgba(100,116,139,.15);padding:2px 6px;border-radius:4px">' + esc(i) + '</span>'; }).join('') +
            '</div>' +
          '</div>';
        document.body.appendChild(modal);
        modal.querySelector('#or-close-modal').onclick = function() { modal.remove(); };
      };
    });
  }

  // ========== TAB 4: CAMPAIGN TRACKER ==========
  function renderCampaigns(c) {
    var phaseColors = ['#3b82f6', '#8b5cf6', '#06b6d4', '#22c55e', '#f97316', '#ef4444', '#ec4899'];
    var FULL_KC = ['Reconnaissance', 'Weaponization', 'Delivery', 'Exploitation', 'Installation', 'C2', 'Actions on Objectives'];

    c.innerHTML =
      '<div class="or-grid2" style="margin-bottom:12px">' +
      CAMPAIGN_DB.map(function(camp) {
        return '<div class="or-card' + (selectedCampaign === camp.id ? ' or-corr' : '') + '" data-camp="' + camp.id + '">' +
          '<div style="display:flex;justify-content:space-between;align-items:center">' +
            '<span class="or-card-title">' + esc(camp.name) + '</span>' +
            '<span class="or-badge" style="background:' + (camp.status === 'Active' ? 'rgba(34,197,94,.12);color:#22c55e' : camp.status === 'Dormant' ? 'rgba(255,214,0,.12);color:#ffd600' : 'rgba(100,116,139,.12);color:var(--mut)') + '">' + esc(camp.status) + '</span>' +
          '</div>' +
          '<div class="or-card-sub" style="margin:4px 0">' + esc(camp.actor) + ' | ' + esc(camp.vector) + '</div>' +
          '<div style="display:flex;gap:4px;flex-wrap:wrap;margin:6px 0">' +
            camp.sectors.map(function(s) { return '<span class="or-badge" style="background:rgba(59,130,246,.08);color:var(--mut);font-size:.58rem">' + esc(s) + '</span>'; }).join('') +
          '</div>' +
          '<div style="font-size:.65rem;color:var(--mut)">Regions: ' + esc(camp.regions.join(', ')) + ' | IOCs: ' + camp.iocCount + '</div>' +
        '</div>';
      }).join('') +
      '</div>';

    if (selectedCampaign) {
      var camp = CAMPAIGN_DB.find(function(c) { return c.id === selectedCampaign; });
      if (camp) {
        c.innerHTML +=
          '<div class="or-panel">' +
            '<div class="or-panel-h">' + esc(camp.name) + ' — Detail View<span style="flex:1"></span><button class="or-btn sm ghost" id="or-close-camp">Close</button></div>' +
            '<div class="or-panel-b">' +
              '<h3 style="font-size:.85rem;margin:0 0 10px">Diamond Model</h3>' +
              '<div class="or-diamond">' +
                '<div class="or-diamond-node"><div class="or-diamond-label" style="color:#ef4444">Adversary</div><div class="or-diamond-text">' + esc(camp.diamond.adversary) + '</div></div>' +
                '<div class="or-diamond-node"><div class="or-diamond-label" style="color:#06b6d4">Infrastructure</div><div class="or-diamond-text">' + esc(camp.diamond.infrastructure) + '</div></div>' +
                '<div class="or-diamond-node"><div class="or-diamond-label" style="color:#f97316">Capability</div><div class="or-diamond-text">' + esc(camp.diamond.capability) + '</div></div>' +
                '<div class="or-diamond-node"><div class="or-diamond-label" style="color:#8b5cf6">Victim</div><div class="or-diamond-text">' + esc(camp.diamond.victim) + '</div></div>' +
              '</div>' +
              '<h3 style="font-size:.85rem;margin:16px 0 10px">Kill Chain Coverage</h3>' +
              '<div class="or-killchain">' +
                FULL_KC.map(function(step) {
                  var active = camp.killChain.indexOf(step) !== -1;
                  return '<span class="or-kc-step ' + (active ? 'or-kc-active' : 'or-kc-inactive') + '">' + esc(step) + '</span>';
                }).join('') +
              '</div>' +
              '<h3 style="font-size:.85rem;margin:16px 0 10px">Campaign Phases</h3>' +
              '<div style="position:relative;height:' + (camp.phases.length * 28 + 10) + 'px">' +
                camp.phases.map(function(p, idx) {
                  return '<div class="or-phase-seg" style="left:' + p.start + '%;width:' + (p.end - p.start) + '%;top:' + (idx * 28) + 'px;background:' + phaseColors[idx % phaseColors.length] + '">' + esc(p.name) + '</div>';
                }).join('') +
              '</div>' +
            '</div>' +
          '</div>';
        var cb = c.querySelector('#or-close-camp');
        if (cb) cb.onclick = function() { selectedCampaign = null; renderCampaigns(c); };
      }
    }

    c.querySelectorAll('.or-card[data-camp]').forEach(function(card) {
      card.onclick = function() { selectedCampaign = card.dataset.camp; renderCampaigns(c); };
    });
  }

  // ========== TAB 5: STIX VIEWER ==========
  function renderSTIX(c) {
    c.innerHTML =
      '<div class="or-panel">' +
        '<div class="or-panel-h">STIX 2.1 Bundle Viewer<span style="flex:1"></span><button class="or-btn sm fill" id="or-stix-sample">Load Sample Bundle</button></div>' +
        '<div class="or-panel-b">' +
          '<textarea class="or-textarea" id="or-stix-input" placeholder="Paste a STIX 2.1 JSON bundle here..." style="min-height:100px">' + (stixBundle ? JSON.stringify(stixBundle, null, 2) : '') + '</textarea>' +
          '<div style="display:flex;gap:8px;margin-top:8px"><button class="or-btn fill" id="or-stix-parse">Parse Bundle</button></div>' +
        '</div>' +
      '</div>';

    if (stixBundle && stixBundle.objects) {
      var objs = stixBundle.objects.filter(function(o) { return o.type !== 'relationship'; });
      var rels = stixBundle.objects.filter(function(o) { return o.type === 'relationship'; });

      var stixColors = { 'threat-actor': '#ef4444', 'malware': '#a855f7', 'indicator': '#3b82f6', 'attack-pattern': '#f97316', 'campaign': '#22c55e', 'infrastructure': '#06b6d4' };

      c.innerHTML +=
        '<div class="or-grid2">' +
          '<div class="or-panel">' +
            '<div class="or-panel-h">Objects (' + objs.length + ')</div>' +
            '<div class="or-panel-b" style="max-height:400px;overflow-y:auto">' +
              objs.map(function(o) {
                var color = stixColors[o.type] || '#94a3b8';
                return '<div class="or-card" data-stix-id="' + esc(o.id) + '" style="margin-bottom:6px;border-left:3px solid ' + color + '">' +
                  '<div style="display:flex;gap:6px;align-items:center">' +
                    '<span class="or-badge" style="background:' + color + '22;color:' + color + '">' + esc(o.type) + '</span>' +
                    '<span class="or-card-title" style="font-size:.8rem">' + esc(o.name || o.id) + '</span>' +
                  '</div>' +
                  (o.description ? '<div class="or-card-sub" style="margin-top:4px">' + esc(o.description.substring(0, 100)) + '</div>' : '') +
                '</div>';
              }).join('') +
            '</div>' +
          '</div>' +
          '<div class="or-panel">' +
            '<div class="or-panel-h">Relationships (' + rels.length + ')</div>' +
            '<div class="or-panel-b" style="max-height:400px;overflow-y:auto">' +
              rels.map(function(r) {
                var src = stixBundle.objects.find(function(o) { return o.id === r.source_ref; });
                var tgt = stixBundle.objects.find(function(o) { return o.id === r.target_ref; });
                return '<div class="or-feed-item">' +
                  '<span style="font-size:.72rem;font-weight:600">' + esc(src ? src.name || src.id : r.source_ref) + '</span>' +
                  '<span class="or-badge" style="background:rgba(59,130,246,.1);color:#3b82f6">' + esc(r.relationship_type) + '</span>' +
                  '<span style="font-size:.72rem;font-weight:600">' + esc(tgt ? tgt.name || tgt.id : r.target_ref) + '</span>' +
                '</div>';
              }).join('') +
            '</div>' +
          '</div>' +
        '</div>';

      // Relationship graph
      c.innerHTML +=
        '<div class="or-panel">' +
          '<div class="or-panel-h">Relationship Graph</div>' +
          '<div class="or-panel-b">' +
            '<div class="or-stix-graph" id="or-stix-graph"></div>' +
          '</div>' +
        '</div>';

      _renderStixGraph(c.querySelector('#or-stix-graph'), objs, rels, stixColors);

      if (selectedStixNode) {
        var node = stixBundle.objects.find(function(o) { return o.id === selectedStixNode; });
        if (node) {
          c.innerHTML +=
            '<div class="or-panel">' +
              '<div class="or-panel-h">Object Inspector: ' + esc(node.name || node.id) + '<span style="flex:1"></span><button class="or-btn sm ghost" id="or-close-inspector">Close</button></div>' +
              '<div class="or-panel-b"><pre style="font-size:.72rem;line-height:1.5;white-space:pre-wrap;word-break:break-all;margin:0">' + esc(JSON.stringify(node, null, 2)) + '</pre></div>' +
            '</div>';
          var ci = c.querySelector('#or-close-inspector');
          if (ci) ci.onclick = function() { selectedStixNode = null; renderSTIX(c); };
        }
      }
    }

    c.querySelector('#or-stix-sample').onclick = function() {
      stixBundle = SAMPLE_STIX; selectedStixNode = null; renderSTIX(c);
    };
    c.querySelector('#or-stix-parse').onclick = function() {
      try {
        stixBundle = JSON.parse(c.querySelector('#or-stix-input').value);
        selectedStixNode = null;
        renderSTIX(c);
      } catch (e) { alert('Invalid JSON: ' + e.message); }
    };
  }

  function _renderStixGraph(container, objs, rels, colors) {
    if (!container) return;
    var w = container.offsetWidth || 600, h = 400;
    var nodes = objs.map(function(o, i) {
      var angle = (i / objs.length) * 2 * Math.PI;
      var rx = (w / 2 - 80) * 0.8, ry = (h / 2 - 40) * 0.8;
      return { id: o.id, name: o.name || o.type, type: o.type, x: w/2 + rx * Math.cos(angle), y: h/2 + ry * Math.sin(angle) };
    });
    var nodeMap = {}; nodes.forEach(function(n) { nodeMap[n.id] = n; });

    var svg = '<svg width="' + w + '" height="' + h + '" style="position:absolute;top:0;left:0">';
    rels.forEach(function(r) {
      var s = nodeMap[r.source_ref], t = nodeMap[r.target_ref];
      if (s && t) {
        svg += '<line x1="' + s.x + '" y1="' + s.y + '" x2="' + t.x + '" y2="' + t.y + '" stroke="var(--line,#333)" stroke-width="1" stroke-dasharray="4,3"/>';
        var mx = (s.x + t.x) / 2, my = (s.y + t.y) / 2;
        svg += '<text x="' + mx + '" y="' + (my - 4) + '" text-anchor="middle" font-size="9" fill="var(--mut,#888)">' + esc(r.relationship_type) + '</text>';
      }
    });
    svg += '</svg>';

    container.innerHTML = svg + nodes.map(function(n) {
      var color = colors[n.type] || '#94a3b8';
      return '<div class="or-stix-node' + (selectedStixNode === n.id ? ' selected' : '') + '" data-node="' + esc(n.id) + '" style="left:' + (n.x - 50) + 'px;top:' + (n.y - 16) + 'px;border-color:' + color + ';background:' + color + '18;color:' + color + '">' + esc(n.name) + '</div>';
    }).join('');

    var dragNode = null, dragOff = {x:0,y:0};
    container.querySelectorAll('.or-stix-node').forEach(function(el) {
      el.onmousedown = function(e) {
        dragNode = el;
        dragOff.x = e.clientX - el.offsetLeft;
        dragOff.y = e.clientY - el.offsetTop;
        el.style.cursor = 'grabbing';
        e.preventDefault();
      };
      el.onclick = function() {
        if (!dragNode || Math.abs(dragOff.x) < 5) {
          selectedStixNode = el.dataset.node;
          renderSTIX(main.querySelector('#or-content'));
        }
      };
    });
    document.onmousemove = function(e) {
      if (!dragNode) return;
      dragNode.style.left = (e.clientX - dragOff.x) + 'px';
      dragNode.style.top = (e.clientY - dragOff.y) + 'px';
    };
    document.onmouseup = function() {
      if (dragNode) dragNode.style.cursor = 'grab';
      dragNode = null;
    };
  }

  // ========== TAB 6: FEED AGGREGATOR ==========
  function renderFeeds(c) {
    c.innerHTML =
      '<div class="or-grid4" style="margin-bottom:12px">' +
        FEED_SOURCES.map(function(f) {
          return '<div class="or-stat">' +
            '<div style="display:flex;align-items:center;gap:6px;margin-bottom:6px">' +
              '<span style="width:6px;height:6px;border-radius:50%;background:#22c55e;flex-shrink:0"></span>' +
              '<span style="font-size:.72rem;font-weight:700">' + esc(f.name) + '</span>' +
            '</div>' +
            '<div class="or-stat-v" style="color:#3b82f6;font-size:1.2rem">' + f.count + '</div>' +
            '<div class="or-stat-l">' + esc(f.desc) + '</div>' +
            '<div style="font-size:.6rem;color:var(--mut);margin-top:4px">Updated: ' + _orTimeAgo(f.updated) + '</div>' +
          '</div>';
        }).join('') +
      '</div>' +

      '<div class="or-actions">' +
        '<button class="or-btn fill" id="or-refresh-feeds">Refresh Feeds</button>' +
        '<button class="or-btn ghost" id="or-correlate-feeds">Auto-Correlate with IOC Manager</button>' +
      '</div>' +

      '<div class="or-panel">' +
        '<div class="or-panel-h">Combined Feed (' + feedData.length + ' entries)</div>' +
        '<div style="overflow-x:auto">' +
          '<table class="or-tbl"><thead><tr><th>Date</th><th>Source</th><th>Type</th><th>Value</th><th>Severity</th><th>Details</th></tr></thead><tbody>' +
          feedData.map(function(f) {
            var matched = iocs.some(function(i) { return i.value === f.value || i.value.indexOf(f.value) !== -1; });
            return '<tr' + (matched ? ' class="or-corr"' : '') + '>' +
              '<td style="white-space:nowrap">' + esc(f.date) + '</td>' +
              '<td>' + esc(f.feed) + '</td>' +
              '<td><span class="or-badge" style="background:rgba(59,130,246,.1);color:' + _orTypeColor(f.type) + '">' + esc(f.type) + '</span></td>' +
              '<td style="font-family:var(--font-mono,monospace);font-size:.72rem;max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(f.value) + '</td>' +
              '<td><span class="or-badge" style="background:' + _orSevBg(f.severity) + ';color:' + _orSevColor(f.severity) + '">' + esc(f.severity) + '</span></td>' +
              '<td style="font-size:.72rem">' + esc(f.details) + (matched ? ' <span class="or-badge" style="background:rgba(59,130,246,.15);color:#3b82f6">IOC MATCH</span>' : '') + '</td>' +
            '</tr>';
          }).join('') +
          '</tbody></table>' +
        '</div>' +
      '</div>';

    c.querySelector('#or-refresh-feeds').onclick = function() {
      var fetched = 0;
      FEED_SOURCES.forEach(function(f) {
        if (!f.url) { fetched++; return; }
        fetch(f.url).then(function(r) { return r.json(); }).then(function(data) {
          if (Array.isArray(data)) {
            data.slice(0, 5).forEach(function(entry) {
              feedData.unshift({ date: new Date().toISOString().slice(0,10), feed: f.name, type: entry.type || 'IOC', value: entry.value || entry.cveID || entry.ip || JSON.stringify(entry).slice(0,40), severity: entry.severity || 'Medium', details: entry.description || entry.name || '' });
            });
          }
          fetched++;
          if (fetched >= FEED_SOURCES.length) renderFeeds(c);
        }).catch(function() { fetched++; if (fetched >= FEED_SOURCES.length) renderFeeds(c); });
      });
    };
    c.querySelector('#or-correlate-feeds').onclick = function() { renderFeeds(c); };
  }

  // ========== TAB 7: REPORTS ==========
  function renderReports(c) {
    var critIOCs = iocs.filter(function(i) { return i.severity === 'Critical'; });
    var highIOCs = iocs.filter(function(i) { return i.severity === 'High'; });
    var activeCampaigns = CAMPAIGN_DB.filter(function(c) { return c.status === 'Active'; });
    var now = new Date().toISOString().slice(0, 10);

    c.innerHTML =
      '<div class="or-panel">' +
        '<div class="or-panel-h">Report Generator</div>' +
        '<div class="or-panel-b">' +
          '<div style="display:flex;gap:8px;margin-bottom:14px">' +
            [['executive', 'Executive Brief'], ['technical', 'Technical Analysis'], ['ioc-report', 'IOC Report'], ['campaign-report', 'Campaign Report']].map(function(t) {
              return '<button class="or-btn' + (reportType === t[0] ? ' fill' : ' ghost') + '" data-rtype="' + t[0] + '">' + t[1] + '</button>';
            }).join('') +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="or-report-preview" id="or-report-body">' + _generateReport(reportType, critIOCs, highIOCs, activeCampaigns, now) + '</div>' +

      '<div style="display:flex;gap:8px;margin-top:12px">' +
        '<button class="or-btn fill" id="or-export-report">Export as JSON</button>' +
      '</div>';

    c.querySelectorAll('[data-rtype]').forEach(function(b) {
      b.onclick = function() { reportType = b.dataset.rtype; renderReports(c); };
    });
    c.querySelector('#or-export-report').onclick = function() {
      var report = { type: reportType, generated: now, platform: 'Darknode ORACLE', content: c.querySelector('#or-report-body').innerText };
      var blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
      var a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'oracle-report-' + reportType + '.json'; a.click();
    };
  }

  function _generateReport(type, critIOCs, highIOCs, activeCampaigns, now) {
    if (type === 'executive') {
      return '<h2>Threat Intelligence Executive Brief</h2>' +
        '<p><strong>Generated:</strong> ' + now + ' | <strong>Classification:</strong> TLP:AMBER | <strong>Platform:</strong> Darknode ORACLE</p>' +
        '<h3>Threat Landscape Summary</h3>' +
        '<p>ORACLE is tracking <strong>' + APT_DB.length + ' threat actor groups</strong> across ' + Object.keys(APT_DB.reduce(function(m,a){m[a.nation]=1;return m;},{})).length + ' nation-states, with <strong>' + activeCampaigns.length + ' active campaigns</strong> currently in progress. The IOC database contains <strong>' + iocs.length + ' indicators</strong>, of which ' + critIOCs.length + ' are classified as Critical severity.</p>' +
        '<h3>Top Risks</h3>' +
        '<ul>' +
          '<li><strong>Critical Infrastructure Pre-positioning:</strong> Volt Typhoon and Salt Typhoon continue targeting US telecom and energy sectors with living-off-the-land techniques that evade traditional detection.</li>' +
          '<li><strong>Ransomware-as-a-Service:</strong> ALPHV/BlackCat, LockBit, and Cl0p remain the most active RaaS operations, with healthcare and government as primary targets.</li>' +
          '<li><strong>Supply Chain Compromise:</strong> APT29 and Winnti/APT41 maintain persistent access to software build pipelines, affecting downstream customers globally.</li>' +
        '</ul>' +
        '<h3>Key Recommendations</h3>' +
        '<ul>' +
          '<li>Implement zero-trust architecture with mandatory MFA across all privileged accounts</li>' +
          '<li>Deploy behavioral analytics to detect LOTL techniques (PowerShell, WMI, ntdsutil abuse)</li>' +
          '<li>Validate software supply chain integrity with SBOM analysis and code signing verification</li>' +
          '<li>Conduct tabletop exercises simulating ransomware scenarios with executive participation</li>' +
          '<li>Review and harden network edge devices (VPN concentrators, firewalls, load balancers)</li>' +
        '</ul>';
    }

    if (type === 'technical') {
      return '<h2>Technical Threat Analysis Report</h2>' +
        '<p><strong>Generated:</strong> ' + now + ' | <strong>Platform:</strong> Darknode ORACLE</p>' +
        '<h3>IOC Analysis</h3>' +
        '<p>Total indicators tracked: ' + iocs.length + ' across ' + ['IP', 'Domain', 'Hash-MD5', 'Hash-SHA256', 'URL', 'Email', 'CVE'].map(function(t) { return t + ': ' + iocs.filter(function(i){return i.type===t;}).length; }).join(', ') + '</p>' +
        '<h3>Critical IOCs Requiring Immediate Action</h3>' +
        '<ul>' + critIOCs.slice(0, 10).map(function(i) { return '<li><strong>' + esc(i.type) + ':</strong> ' + esc(i.value) + ' (' + esc((i.tags||[]).join(', ')) + ') — ' + esc(i.notes) + '</li>'; }).join('') + '</ul>' +
        '<h3>MITRE ATT&amp;CK Mapping</h3>' +
        '<p>Most observed techniques across tracked actors:</p>' +
        '<ul>' +
          '<li>T1566 - Phishing (18 actors)</li><li>T1059 - Command and Scripting Interpreter (22 actors)</li><li>T1071 - Application Layer Protocol (14 actors)</li><li>T1027 - Obfuscated Files (13 actors)</li><li>T1078 - Valid Accounts (8 actors)</li><li>T1195 - Supply Chain Compromise (6 actors)</li><li>T1486 - Data Encrypted for Impact (8 actors)</li>' +
        '</ul>' +
        '<h3>Detection Signatures</h3>' +
        '<p>Recommended Sigma rules for high-priority threats:</p>' +
        '<ul><li>Sigma: proc_creation_win_powershell_download_cradle (APT29 LOTL)</li><li>Sigma: net_connection_win_unusual_outbound_ports (C2 beaconing)</li><li>Sigma: file_event_win_ransomware_extensions (LockBit/ALPHV)</li></ul>';
    }

    if (type === 'ioc-report') {
      return '<h2>Indicator of Compromise Report</h2>' +
        '<p><strong>Generated:</strong> ' + now + ' | <strong>Total IOCs:</strong> ' + iocs.length + '</p>' +
        '<h3>Distribution by Type</h3>' +
        '<ul>' + ['IP', 'Domain', 'Hash-MD5', 'Hash-SHA256', 'URL', 'Email', 'CVE'].map(function(t) { var n = iocs.filter(function(i){return i.type===t;}).length; return '<li>' + t + ': ' + n + ' indicators</li>'; }).join('') + '</ul>' +
        '<h3>Distribution by Severity</h3>' +
        '<ul>' + ['Critical', 'High', 'Medium', 'Low'].map(function(s) { var n = iocs.filter(function(i){return i.severity===s;}).length; return '<li>' + s + ': ' + n + ' indicators</li>'; }).join('') + '</ul>' +
        '<h3>Top Sources</h3>' +
        '<ul>' + Object.entries(iocs.reduce(function(m,i){m[i.source]=(m[i.source]||0)+1;return m;},{})).sort(function(a,b){return b[1]-a[1];}).slice(0,8).map(function(e){return '<li>' + esc(e[0]) + ': ' + e[1] + ' IOCs</li>';}).join('') + '</ul>' +
        '<h3>Recent Critical IOCs</h3>' +
        '<ul>' + critIOCs.slice(0, 15).map(function(i) { return '<li>[' + esc(i.type) + '] ' + esc(i.value) + ' — ' + esc(i.notes) + ' (Source: ' + esc(i.source) + ')</li>'; }).join('') + '</ul>';
    }

    return '<h2>Campaign Intelligence Report</h2>' +
      '<p><strong>Generated:</strong> ' + now + ' | <strong>Active Campaigns:</strong> ' + activeCampaigns.length + '</p>' +
      '<h3>Active Campaign Summary</h3>' +
      activeCampaigns.map(function(camp) {
        return '<h3>' + esc(camp.name) + ' (' + esc(camp.actor) + ')</h3>' +
          '<ul>' +
            '<li><strong>Status:</strong> ' + esc(camp.status) + '</li>' +
            '<li><strong>Attack Vector:</strong> ' + esc(camp.vector) + '</li>' +
            '<li><strong>Target Sectors:</strong> ' + esc(camp.sectors.join(', ')) + '</li>' +
            '<li><strong>Target Regions:</strong> ' + esc(camp.regions.join(', ')) + '</li>' +
            '<li><strong>Associated IOCs:</strong> ' + camp.iocCount + '</li>' +
          '</ul>';
      }).join('');
  }

  // Initial render
  render();

  // Try to load live feeds on startup
  FEED_SOURCES.forEach(function(f) {
    if (!f.url) return;
    fetch(f.url).then(function(r) { return r.json(); }).then(function(data) {
      if (Array.isArray(data)) {
        data.slice(0, 3).forEach(function(entry) {
          feedData.push({ date: new Date().toISOString().slice(0,10), feed: f.name, type: entry.type || 'IOC', value: entry.value || entry.cveID || entry.ip || JSON.stringify(entry).slice(0,40), severity: entry.severity || 'Medium', details: entry.description || entry.name || '' });
        });
      }
    }).catch(function() {});
  });
}
