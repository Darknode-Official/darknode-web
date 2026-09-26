// Executive Cyber Briefing — training / tabletop exercise briefing generator.
// Everything in this module is a FICTIONAL training scenario: the findings, incident
// counts, IOCs and decisions are invented for practice and are not real intelligence.
// No content is sourced from, or attributable to, any government agency.
const esc = (s) => String(s != null ? s : "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

// ═══════════════════════════════════════════════════════════════════════════════
// EXERCISE MARKINGS (not security classifications)
// ═══════════════════════════════════════════════════════════════════════════════
const CLASSIFICATIONS = [
  { id: 'training', label: 'TRAINING SCENARIO - FICTIONAL', color: '#fbbf24', bg: '#2a1a00' },
  { id: 'tabletop', label: 'TABLETOP EXERCISE - FICTIONAL', color: '#16a34a', bg: '#052e16' },
  { id: 'wargame', label: 'WARGAME INJECT - FICTIONAL', color: '#7c3aed', bg: '#1e1040' },
  { id: 'redteam', label: 'RED TEAM EXERCISE - FICTIONAL', color: '#dc2626', bg: '#2a0a0a' }
];

// ═══════════════════════════════════════════════════════════════════════════════
// AUDIENCE PROFILES
// ═══════════════════════════════════════════════════════════════════════════════
const AUDIENCES = [
  { id: 'potus', label: 'POTUS / National Security Council', abbr: 'NSC', detail: 'Strategic-level, policy-focused, minimal technical jargon' },
  { id: 'secdef', label: 'SECDEF / DoD Leadership', abbr: 'DoD', detail: 'Military cyber operations focus, force readiness implications' },
  { id: 'ciso', label: 'CISO / CTO', abbr: 'CISO', detail: 'Technical depth, actionable intelligence, defensive priorities' },
  { id: 'board', label: 'Board of Directors', abbr: 'BOARD', detail: 'Business impact, risk quantification, fiduciary responsibility' },
  { id: 'isac', label: 'Sector ISAC', abbr: 'ISAC', detail: 'Sector-specific threats, peer benchmarking, collective defense' }
];

// ═══════════════════════════════════════════════════════════════════════════════
// THREAT ACTOR DATABASE
// ═══════════════════════════════════════════════════════════════════════════════
const THREAT_ACTORS = [
  { name: 'APT28', alias: 'Fancy Bear', nation: 'Russia', flag: 'RU', sponsor: 'GRU Unit 26165', sectors: ['Government', 'Defense', 'Media'], activity: 92, confidence: 'HIGH', lastSeen: '2026-09-19', campaign: 'FOREST BLIZZARD', status: 'active', ttps: ['T1566 Phishing', 'T1078 Valid Accounts', 'T1003 Credential Dumping'], summary: 'Sustained credential harvesting campaign targeting NATO diplomatic communications. New custom implant "SilentForge" deployed via spearphishing. Exfiltrating policy documents related to Eastern European defense cooperation.' },
  { name: 'APT29', alias: 'Cozy Bear', nation: 'Russia', flag: 'RU', sponsor: 'SVR', sectors: ['Government', 'Think Tanks', 'Healthcare'], activity: 78, confidence: 'HIGH', lastSeen: '2026-09-18', campaign: 'MIDNIGHT BLIZZARD', status: 'active', ttps: ['T1195 Supply Chain', 'T1059 Command & Scripting', 'T1071 Application Layer Protocol'], summary: 'Supply chain compromise targeting cloud service providers serving government agencies. Leveraging OAuth tokens for persistent access. Two confirmed compromises at federal contractors with TS clearance data access.' },
  { name: 'Volt Typhoon', alias: 'BRONZE SILHOUETTE', nation: 'China', flag: 'CN', sponsor: 'PLA SSF', sectors: ['Energy', 'Telecom', 'Water', 'Transportation'], activity: 95, confidence: 'HIGH', lastSeen: '2026-09-20', campaign: 'LIVING OFF THE LAND', status: 'active', ttps: ['T1190 Exploit Public-Facing App', 'T1218 System Binary Proxy', 'T1071 Application Layer Protocol'], summary: 'Pre-positioning in US critical infrastructure continues to expand. New compromises identified in 3 additional water treatment facilities and 2 natural gas pipeline operators. Using only built-in OS tools to evade detection. Assessed as preparation for potential disruption during Taiwan contingency.' },
  { name: 'Salt Typhoon', alias: 'GhostEmperor', nation: 'China', flag: 'CN', sponsor: 'MSS', sectors: ['Telecom', 'ISP'], activity: 88, confidence: 'HIGH', lastSeen: '2026-09-19', campaign: 'TELECOM INFILTRATION', status: 'active', ttps: ['T1190 Exploit Public-Facing App', 'T1556 Modify Auth Process', 'T1557 Adversary-in-the-Middle'], summary: 'Persistent access in major US telecommunications providers confirmed. Intercepting lawful-intercept systems and senior government communications. Expanded to 2 additional regional ISPs in the past 30 days.' },
  { name: 'Lazarus Group', alias: 'HIDDEN COBRA', nation: 'North Korea', flag: 'KP', sponsor: 'RGB', sectors: ['Finance', 'Cryptocurrency', 'Defense'], activity: 85, confidence: 'HIGH', lastSeen: '2026-09-18', campaign: 'OPERATION DREAM JOB 3.0', status: 'active', ttps: ['T1566 Phishing', 'T1204 User Execution', 'T1055 Process Injection'], summary: 'Cryptocurrency theft campaign targeting DeFi platforms and centralized exchanges. $340M stolen in Q3 2026 alone. New approach uses AI-generated fake recruiter profiles on LinkedIn to deliver trojanized coding challenges to blockchain developers.' },
  { name: 'APT33', alias: 'Elfin', nation: 'Iran', flag: 'IR', sponsor: 'IRGC', sectors: ['Energy', 'Aerospace', 'Defense'], activity: 65, confidence: 'MODERATE', lastSeen: '2026-09-15', campaign: 'SHAMOON RESURGENCE', status: 'monitoring', ttps: ['T1190 Exploit Public-Facing App', 'T1486 Data Encrypted for Impact', 'T1485 Data Destruction'], summary: 'Staging destructive capabilities against Gulf state energy infrastructure. New wiper variant identified but not yet deployed. Increased reconnaissance of US energy sector SCADA systems in the past 60 days.' },
  { name: 'APT41', alias: 'Winnti', nation: 'China', flag: 'CN', sponsor: 'MSS / Criminal', sectors: ['Technology', 'Healthcare', 'Manufacturing'], activity: 72, confidence: 'HIGH', lastSeen: '2026-09-17', campaign: 'DUAL OPERATION', status: 'active', ttps: ['T1195 Supply Chain', 'T1059 Command & Scripting', 'T1105 Ingress Tool Transfer'], summary: 'Dual espionage/financial motivation continues. Compromised 3 SaaS providers serving federal healthcare systems. Separately conducting financially motivated ransomware operations under "Bronze Starlight" persona for misdirection.' },
  { name: 'Sandworm', alias: 'Voodoo Bear', nation: 'Russia', flag: 'RU', sponsor: 'GRU Unit 74455', sectors: ['Energy', 'Government', 'Telecom'], activity: 70, confidence: 'HIGH', lastSeen: '2026-09-16', campaign: 'PRESTIGE WIPER', status: 'monitoring', ttps: ['T1486 Data Encrypted for Impact', 'T1485 Data Destruction', 'T1562 Impair Defenses'], summary: 'Destructive capability development continues targeting European energy infrastructure. New variant of Industroyer tailored for North American grid protocols detected in sandboxed analysis. Currently in staging phase — no active deployment confirmed.' },
  { name: 'Kimsuky', alias: 'Velvet Chollima', nation: 'North Korea', flag: 'KP', sponsor: 'RGB', sectors: ['Government', 'Think Tanks', 'Academia'], activity: 58, confidence: 'MODERATE', lastSeen: '2026-09-14', campaign: 'STOLEN PENCIL', status: 'monitoring', ttps: ['T1566 Phishing', 'T1114 Email Collection', 'T1005 Data from Local System'], summary: 'Credential harvesting campaign against Korean Peninsula policy experts at US think tanks. Using compromised university email accounts as phishing infrastructure. Targeting individuals with access to classified nuclear policy discussions.' },
  { name: 'Turla', alias: 'Venomous Bear', nation: 'Russia', flag: 'RU', sponsor: 'FSB Center 16', sectors: ['Government', 'Diplomatic', 'Military'], activity: 45, confidence: 'MODERATE', lastSeen: '2026-09-10', campaign: 'SNAKE REVIVAL', status: 'monitoring', ttps: ['T1071 Application Layer Protocol', 'T1001 Data Obfuscation', 'T1587 Develop Capabilities'], summary: 'Rebuilding C2 infrastructure after FBI disruption of SNAKE malware. New satellite-based C2 communication method detected. Lower activity but increased sophistication in tradecraft suggests development of next-generation implant.' }
];

// ═══════════════════════════════════════════════════════════════════════════════
// CIKR SECTOR THREAT MATRIX
// ═══════════════════════════════════════════════════════════════════════════════
const SECTOR_THREATS = [
  { sector: 'Energy', level: 'HIGH', score: 82, actors: ['Volt Typhoon', 'Sandworm', 'APT33'], trend: 'rising', incidents30d: 14, description: 'Pre-positioning by Volt Typhoon in grid SCADA. Sandworm developing Industroyer variant for NA protocols.' },
  { sector: 'Financial Services', level: 'ELEVATED', score: 68, actors: ['Lazarus Group', 'APT41'], trend: 'stable', incidents30d: 8, description: 'DPRK crypto theft campaign intensifying. $340M Q3 losses. SWIFT system probing detected from new infrastructure.' },
  { sector: 'Healthcare', level: 'ELEVATED', score: 65, actors: ['APT41', 'Criminal Groups'], trend: 'rising', incidents30d: 11, description: 'SaaS provider compromises affecting federal healthcare data. Ransomware groups specifically targeting hospitals during holiday periods.' },
  { sector: 'Telecommunications', level: 'CRITICAL', score: 91, actors: ['Salt Typhoon', 'Volt Typhoon'], trend: 'rising', incidents30d: 6, description: 'Lawful-intercept compromise confirmed at major carriers. Expanding to regional ISPs. Government communications at risk.' },
  { sector: 'Transportation', level: 'MODERATE', score: 48, actors: ['Volt Typhoon'], trend: 'stable', incidents30d: 3, description: 'Reconnaissance against port management systems and air traffic control networks. No confirmed compromises.' },
  { sector: 'Water Systems', level: 'HIGH', score: 75, actors: ['Volt Typhoon', 'Criminal Groups'], trend: 'rising', incidents30d: 5, description: 'Three new water treatment facility compromises. Legacy SCADA systems with known vulnerabilities. CyberAv3ngers (Iran-affiliated) targeting PLC controllers.' },
  { sector: 'Government', level: 'HIGH', score: 79, actors: ['APT28', 'APT29', 'Kimsuky'], trend: 'stable', incidents30d: 19, description: 'Sustained espionage campaigns against diplomatic communications. Two contractor compromises with clearance data exposure.' },
  { sector: 'Defense Industrial Base', level: 'ELEVATED', score: 70, actors: ['APT29', 'APT41', 'Turla'], trend: 'rising', incidents30d: 7, description: 'Supply chain targeting of cleared defense contractors. Focus on hypersonic weapon programs and satellite communications.' }
];

// ═══════════════════════════════════════════════════════════════════════════════
// INTELLIGENCE FINDINGS
// ═══════════════════════════════════════════════════════════════════════════════
const INTEL_FINDINGS = [
  { id: 'IF-2026-0917', title: 'Volt Typhoon Expands Critical Infrastructure Pre-Positioning', source: 'Exercise intel cell (fictional)', classification: 'EXERCISE', confidence: 95, relevance: 98, date: '2026-09-17', summary: 'SIGINT and network forensics confirm Volt Typhoon has expanded pre-positioned access to 47 critical infrastructure entities across energy, water, and transportation sectors — up from 31 in previous reporting. New access achieved via compromised SOHO routers and VPN appliances. Assessment: preparation for disruptive/destructive operations during potential Taiwan Strait crisis. Recommend immediate hunting operations across all CIKR entities using published IOCs and behavioral analytics.', actionRequired: true },
  { id: 'IF-2026-0918', title: 'Salt Typhoon Intercept Capability Assessment', source: 'Exercise intel cell (fictional)', classification: 'EXERCISE', confidence: 90, relevance: 95, date: '2026-09-18', summary: 'Investigation confirms Salt Typhoon has achieved persistent access to lawful-intercept systems at 4 major US telecommunications providers, potentially enabling real-time surveillance of government communications. Compromise includes ability to modify intercept target lists. Impact assessment ongoing. POTUS and senior national security officials\' communications may have been exposed.', actionRequired: true },
  { id: 'IF-2026-0915', title: 'DPRK Cryptocurrency Operations Funding Analysis', source: 'Exercise intel cell (fictional)', classification: 'EXERCISE', confidence: 85, relevance: 72, date: '2026-09-15', summary: 'Analysis of blockchain movements confirms $1.2B in cryptocurrency stolen by DPRK-linked actors in 2026 YTD, representing approximately 40% of North Korea\'s weapons program funding. New laundering techniques using cross-chain bridges and mixing protocols are reducing recovery rates. Recommend coordinated sanctions action against 14 identified wallet clusters.', actionRequired: false },
  { id: 'IF-2026-0916', title: 'Russian Pre-Election Influence Operations Detected', source: 'Exercise intel cell (fictional)', classification: 'EXERCISE', confidence: 80, relevance: 88, date: '2026-09-16', summary: 'Multiple Russian information operations identified targeting US midterm election integrity. GRU-linked entities operating fabricated local news websites in 12 swing states. AI-generated deepfake content of election officials making false statements has been detected on 3 major social media platforms. Content amplification network of 2,400+ inauthentic accounts identified.', actionRequired: true },
  { id: 'IF-2026-0914', title: 'Sandworm Industroyer Variant for North American Grid', source: 'Exercise intel cell (fictional)', classification: 'EXERCISE', confidence: 75, relevance: 85, date: '2026-09-14', summary: 'Sandboxed analysis of malware sample recovered from compromised European energy sector entity reveals a new Industroyer variant specifically tailored for IEC 61850 and DNP3 protocols used in North American power grid. While no active deployment detected, the capability represents a significant escalation in destructive potential targeting the US energy sector. NERC CIP alert recommended.', actionRequired: true }
];

// ═══════════════════════════════════════════════════════════════════════════════
// RECOMMENDED ACTIONS
// ═══════════════════════════════════════════════════════════════════════════════
const RECOMMENDED_ACTIONS = [
  { priority: 'IMMEDIATE', action: 'Deploy Volt Typhoon hunting playbook across all CIKR entities', owner: 'SOC lead', deadline: '48 hours', status: 'IN PROGRESS', risk: 'CRITICAL', rationale: '16 new compromises identified in past 30 days. SOHO router and VPN appliance IOCs must be swept immediately.' },
  { priority: 'IMMEDIATE', action: 'Issue Emergency Directive for telecom lawful-intercept system audit', owner: 'Regulatory liaison', deadline: '72 hours', status: 'PENDING APPROVAL', risk: 'CRITICAL', rationale: 'Salt Typhoon access to intercept systems poses immediate national security risk. All major carriers must verify intercept system integrity.' },
  { priority: 'URGENT', action: 'Rotate all senior government communication cryptographic keys', owner: 'IT Ops / Crypto team', deadline: '7 days', status: 'PLANNING', risk: 'HIGH', rationale: 'Potential compromise of government communications via telecom infiltration requires key rotation as precautionary measure.' },
  { priority: 'URGENT', action: 'Issue NERC CIP alert for Industroyer variant targeting NA grid protocols', owner: 'OT security lead', deadline: '5 days', status: 'DRAFT', risk: 'HIGH', rationale: 'New destructive capability targeting IEC 61850 / DNP3 requires immediate awareness across energy sector.' },
  { priority: 'HIGH', action: 'Coordinate OFAC sanctions package for 14 DPRK cryptocurrency wallet clusters', owner: 'Legal / Compliance', deadline: '14 days', status: 'IN REVIEW', risk: 'MODERATE', rationale: '$1.2B YTD theft directly funding weapons programs. Sanctions can disrupt laundering chain at identified chokepoints.' },
  { priority: 'HIGH', action: 'Deploy AI-generated content detection at social media platform level', owner: 'Comms / Executive', deadline: '21 days', status: 'COORDINATING', risk: 'MODERATE', rationale: 'Pre-election deepfake detection requires platform cooperation. 2,400+ inauthentic account network must be disrupted before election cycle intensifies.' },
  { priority: 'MODERATE', action: 'Update cleared defense contractor cybersecurity requirements under CMMC 2.0', owner: 'Supplier risk lead', deadline: '30 days', status: 'POLICY REVIEW', risk: 'MODERATE', rationale: 'Two contractor compromises with TS data access highlight gaps in current CMMC implementation.' },
  { priority: 'MODERATE', action: 'Establish water sector cyber mutual aid program pilot', owner: 'Sector partnership lead', deadline: '45 days', status: 'PLANNING', risk: 'MODERATE', rationale: 'Small water utilities lack security resources. Mutual aid framework enables shared defense capabilities.' }
];

// ═══════════════════════════════════════════════════════════════════════════════
// DECISION POINTS
// ═══════════════════════════════════════════════════════════════════════════════
const DECISION_POINTS = [
  { id: 'DP-001', title: 'Authorization of Offensive Counter-Cyber Operation Against Volt Typhoon Infrastructure', deadline: '2026-09-22 1800Z', urgency: 'IMMEDIATE', background: 'Volt Typhoon pre-positioning in US critical infrastructure represents the most significant cyber threat to national security since SolarWinds. Passive defense alone is insufficient to remove pre-positioned access across 47 entities.',
    options: [
      { label: 'Authorize CYBERCOM offensive operation (OP PACIFIC SHIELD)', risk: 'MODERATE', pros: 'Directly degrades adversary capability. Sends deterrence signal.', cons: 'Risk of escalation. Potential attribution debate. May reveal intelligence sources.' },
      { label: 'Elevate to active defense only — hunt-forward teams + enhanced monitoring', risk: 'LOW', pros: 'Lower escalation risk. Preserves intelligence sources.', cons: 'Does not remove pre-positioned access. Adversary may activate before removal.' },
      { label: 'Pursue diplomatic channel with explicit warning', risk: 'LOW', pros: 'Avoids military escalation. International law compliance.', cons: 'Historically ineffective with PRC. Delays action while threat persists.' },
      { label: 'Combined approach — diplomatic warning + defensive hunt + authorized offensive contingency', risk: 'MODERATE', pros: 'Balanced response. Escalation ladder preserved.', cons: 'Complexity of coordination. Potential mixed signals.' }
    ]
  },
  { id: 'DP-002', title: 'Emergency Directive for Telecom Sector Lawful-Intercept Security Audit', deadline: '2026-09-24 0000Z', urgency: 'URGENT', background: 'Salt Typhoon access to lawful-intercept systems at 4 major carriers represents unprecedented counterintelligence risk. Government communications and intelligence operations may be compromised.',
    options: [
      { label: 'Issue an emergency directive under existing regulatory authority', risk: 'LOW', pros: 'Fastest path to action. Clear legal authority.', cons: 'Carrier pushback on operational disruption. Resource-intensive audits.' },
      { label: 'Request voluntary compliance via FCC coordination', risk: 'LOW', pros: 'Cooperative approach. Less regulatory friction.', cons: 'No enforcement mechanism. Slower implementation.' },
      { label: 'Classify as national security emergency — invoke Title 50 authorities', risk: 'MODERATE', pros: 'Maximum authority and resources. IC engagement.', cons: 'Political sensitivity. Public disclosure risk.' }
    ]
  },
  { id: 'DP-003', title: 'Pre-Election Cyber Threat Public Attribution', deadline: '2026-10-01 0000Z', urgency: 'HIGH', background: 'Russian influence operations targeting midterm elections require a decision on public attribution timing and content. Attribution can deter and educate, but can also amplify the narrative the adversary seeks.',
    options: [
      { label: 'Joint government public attribution statement', risk: 'LOW', pros: 'Public awareness. Deterrence effect. Platform takedown authority.', cons: 'May amplify adversary narratives. Political sensitivities.' },
      { label: 'Classified briefing to Congressional leadership only', risk: 'LOW', pros: 'Maintains intelligence equities. Avoids public attention.', cons: 'No public awareness. No platform action. Leak risk.' },
      { label: 'Coordinated attribution with Five Eyes allies', risk: 'LOW', pros: 'Stronger deterrent. Shared burden. International legitimacy.', cons: 'Slower coordination. Alliance equities to manage.' }
    ]
  }
];

// ═══════════════════════════════════════════════════════════════════════════════
// IOC DATABASE
// ═══════════════════════════════════════════════════════════════════════════════
const IOCS = [
  { type: 'IP', value: '192.0.2.34', actor: 'APT28', context: 'SilentForge C2 server', firstSeen: '2026-08-22', confidence: 'HIGH' },
  { type: 'IP', value: '198.51.100.19', actor: 'Volt Typhoon', context: 'Compromised SOHO router relay', firstSeen: '2026-07-15', confidence: 'HIGH' },
  { type: 'IP', value: '203.0.113.88', actor: 'Sandworm', context: 'Industroyer staging infrastructure', firstSeen: '2026-09-01', confidence: 'MODERATE' },
  { type: 'IP', value: '192.0.2.211', actor: 'Lazarus Group', context: 'Crypto theft exfiltration endpoint', firstSeen: '2026-08-10', confidence: 'HIGH' },
  { type: 'Domain', value: 'update-service.cloud-cdn[.]example', actor: 'APT29', context: 'OAuth token phishing domain', firstSeen: '2026-09-05', confidence: 'HIGH' },
  { type: 'Domain', value: 'login.office-auth[.]example', actor: 'APT28', context: 'Credential harvesting infrastructure', firstSeen: '2026-08-28', confidence: 'HIGH' },
  { type: 'Domain', value: 'api.blockchain-verify[.]test', actor: 'Lazarus Group', context: 'Fake recruitment / trojanized app server', firstSeen: '2026-09-08', confidence: 'MODERATE' },
  { type: 'Domain', value: 'news-daily-report[.]example', actor: 'GRU IO', context: 'Fabricated local news site (influence op)', firstSeen: '2026-08-15', confidence: 'HIGH' },
  { type: 'Hash (SHA-256)', value: 'a3f5d8c2e4b6a1d9c3f7e5b8a2d4c6f8e1b3a5d7c9f2e4b6a8d1c3f5e7b9a2d4', actor: 'Sandworm', context: 'Industroyer v3 (IEC 61850 module)', firstSeen: '2026-09-12', confidence: 'HIGH' },
  { type: 'Hash (SHA-256)', value: 'b7e2f4a6c8d1e3b5a7c9d2f4e6b8a1c3d5e7f9b2a4c6d8e1f3a5b7c9d2e4f6a8', actor: 'APT28', context: 'SilentForge implant (x64)', firstSeen: '2026-08-25', confidence: 'HIGH' },
  { type: 'Hash (SHA-256)', value: 'c9d1e3f5a7b2c4d6e8f1a3b5c7d9e2f4a6b8c1d3e5f7a9b2c4d6e8f1a3b5c7d9', actor: 'APT41', context: 'SaaS backdoor module (Node.js)', firstSeen: '2026-09-10', confidence: 'MODERATE' },
  { type: 'Hash (SHA-256)', value: 'd2e4f6a8b1c3d5e7f9a2b4c6d8e1f3a5b7c9d2e4f6a8b1c3d5e7f9a2b4c6d8e1', actor: 'Lazarus Group', context: 'Dream Job 3.0 payload dropper', firstSeen: '2026-09-06', confidence: 'HIGH' },
  { type: 'CVE', value: 'EXERCISE-VULN-01', actor: 'Volt Typhoon', context: 'Fictional VPN appliance auth bypass', firstSeen: '2026-09-03', confidence: 'HIGH' },
  { type: 'CVE', value: 'EXERCISE-VULN-02', actor: 'APT41', context: 'SaaS platform SSRF to RCE', firstSeen: '2026-09-09', confidence: 'MODERATE' }
];

// ═══════════════════════════════════════════════════════════════════════════════
// BLUF TEMPLATES (per audience)
// ═══════════════════════════════════════════════════════════════════════════════
const BLUF = {
  potus: 'Three concurrent nation-state cyber campaigns pose immediate risk to US national security and critical infrastructure:\n\n1. CHINA (Volt Typhoon): Pre-positioned destructive access confirmed in 47 US critical infrastructure entities across energy, water, and transportation — assessed as preparation for Taiwan contingency. DECISION REQUIRED: authorize counter-operation.\n\n2. CHINA (Salt Typhoon): Persistent access to lawful-intercept systems at 4 major US telecom carriers confirmed. Senior government communications potentially compromised. EMERGENCY DIRECTIVE recommended.\n\n3. RUSSIA (GRU): Coordinated influence operations targeting midterm elections detected across 12 states. AI-generated deepfake content of election officials in circulation. PUBLIC ATTRIBUTION decision required by Oct 1.',
  secdef: 'BOTTOM LINE: Three active cyber campaigns require DoD attention and potential CYBERCOM action.\n\n1. Volt Typhoon pre-positioning in 47 CIKR entities represents the most significant CNE threat since SolarWinds. CYBERCOM counter-operation (OP PACIFIC SHIELD) awaiting SECDEF authorization. Risk: adversary activation during Taiwan crisis could degrade force projection capability.\n\n2. Salt Typhoon telecom compromise includes interception of DoD communications transiting commercial carriers. Immediate assessment of operational security impact required.\n\n3. Sandworm developing Industroyer variant targeting North American grid protocols. Capability assessment indicates potential for cascading power disruption affecting military installations dependent on commercial grid.',
  ciso: 'BOTTOM LINE: Three threat vectors require immediate defensive action.\n\n1. HUNT IMMEDIATELY: Volt Typhoon IOCs (EXERCISE-VULN-01, SOHO router compromise indicators). Sweep all internet-facing VPN appliances and SOHO routers. 16 new compromises in 30 days.\n\n2. AUDIT NOW: If using any of the 4 affected telecom carriers for government communications, assume compromise. Rotate encryption keys. Transition sensitive comms to classified systems.\n\n3. PATCH/DETECT: Sandworm Industroyer v3 signatures released — deploy to all OT monitoring systems. APT28 SilentForge IOCs appended to this briefing.\n\nCritical patches: EXERCISE-VULN-01 (VPN appliance, CVSS 9.8), EXERCISE-VULN-02 (SaaS SSRF, CVSS 8.6).',
  board: 'BOTTOM LINE: Three nation-state campaigns create material cyber risk requiring board awareness.\n\n1. BUSINESS CONTINUITY RISK: Chinese state actors have pre-positioned destructive access in US energy, water, and telecom infrastructure. A geopolitical trigger event could cause cascading service disruptions. Estimated economic impact: $2.4B–$8.7B per day of disruption.\n\n2. DATA BREACH RISK: Telecom provider compromise may have exposed executive communications. If your organization uses affected carriers (names classified), assume compromise of unencrypted communications.\n\n3. REGULATORY RISK: Updated CMMC requirements, SEC cyber disclosure rules, and potential emergency directives will increase compliance obligations. Recommend pre-positioning additional cybersecurity budget.',
  isac: 'BOTTOM LINE: Three campaigns require sector-specific collective defense actions.\n\n1. ENERGY/WATER SECTOR: Volt Typhoon IOCs must be hunted across all SCADA/ICS environments within 48 hours. Shared indicators attached. Three new water utility compromises this month.\n\n2. TELECOM SECTOR: Salt Typhoon lawful-intercept compromise requires immediate audit of all carrier-grade interception systems. Coordinate through your sector ISAC.\n\n3. ALL SECTORS: APT28 credential harvesting campaign using domain typosquatting. Block attached domain list at email gateway. Sandworm Industroyer v3 YARA rules attached for OT monitoring.'
};

// ═══════════════════════════════════════════════════════════════════════════════
// STYLE BLOCK
// ═══════════════════════════════════════════════════════════════════════════════
function injectStyles() {
  if (document.getElementById('cb-styles')) return;
  const style = document.createElement('style');
  style.id = 'cb-styles';
  style.textContent = `
/* ── Cyber Briefing Generator ── */
.cb-wrap { font-family: ui-sans-serif, system-ui, -apple-system, sans-serif; color: #c8d6e5; max-width: 1200px; margin: 0 auto; }
.cb-fiction-badge { display: inline-block; vertical-align: middle; margin-left: 10px; padding: 3px 9px; border-radius: 4px; background: #f59e0b; color: #1a1200; font-size: 11px; font-weight: 700; letter-spacing: .04em; text-transform: uppercase; font-family: ui-sans-serif, system-ui, sans-serif; }
.cb-fiction-note { background: #2a1a00; border: 1px solid #f59e0b; color: #fde68a; border-radius: 6px; padding: 10px 14px; font-size: 12px; line-height: 1.55; margin-bottom: 16px; }
[data-style=pro] .cb-fiction-note { background: #fffbeb; color: #92400e; }
.cb-classification-banner { text-align: center; font-family: 'JetBrains Mono', monospace; font-size: 13px; font-weight: 700; letter-spacing: 3px; padding: 8px 16px; border-radius: 4px; margin-bottom: 20px; }
.cb-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 20px; margin-bottom: 24px; flex-wrap: wrap; }
.cb-header-left h1 { margin: 0 0 4px; font-size: 24px; font-family: 'JetBrains Mono', monospace; color: #fff; letter-spacing: 1px; }
.cb-header-left .cb-subtitle { color: #667788; font-size: 13px; font-family: 'JetBrains Mono', monospace; }
.cb-controls { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.cb-select { background: #0d1420; border: 1px solid #1e2d44; color: #c8d6e5; padding: 7px 12px; border-radius: 6px; font-size: 12px; font-family: 'JetBrains Mono', monospace; cursor: pointer; appearance: none; -webkit-appearance: none; padding-right: 28px; background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6'%3E%3Cpath d='M0 0l5 6 5-6z' fill='%23667788'/%3E%3C/svg%3E"); background-repeat: no-repeat; background-position: right 10px center; }
.cb-select:focus { outline: none; border-color: #3b82f6; }
.cb-btn { background: #1e293b; border: 1px solid #334155; color: #c8d6e5; padding: 7px 16px; border-radius: 6px; font-size: 12px; font-family: 'JetBrains Mono', monospace; cursor: pointer; transition: all 0.15s ease; display: inline-flex; align-items: center; gap: 6px; }
.cb-btn:hover { background: #334155; border-color: #475569; }
.cb-btn-primary { background: #1e40af; border-color: #2563eb; color: #fff; }
.cb-btn-primary:hover { background: #2563eb; }
.cb-section { background: linear-gradient(135deg, #0c1220, #0a0f1c); border: 1px solid #1a2540; border-radius: 8px; padding: 20px; margin-bottom: 16px; }
.cb-section-title { color: #3b82f6; font-size: 13px; font-family: 'JetBrains Mono', monospace; letter-spacing: 2px; text-transform: uppercase; margin: 0 0 16px; padding-bottom: 10px; border-bottom: 1px solid #1a2540; display: flex; align-items: center; gap: 8px; }
.cb-section-title .cb-icon { color: #60a5fa; }
.cb-bluf { background: #0a1628; border: 1px solid #1e3a5f; border-left: 4px solid #3b82f6; border-radius: 0 8px 8px 0; padding: 16px 20px; margin-bottom: 16px; }
.cb-bluf-label { color: #3b82f6; font-size: 11px; font-family: 'JetBrains Mono', monospace; font-weight: 700; letter-spacing: 2px; margin-bottom: 8px; }
.cb-bluf-text { font-size: 13px; line-height: 1.7; color: #d1dbe8; white-space: pre-line; }

/* Actor Table */
.cb-table { width: 100%; border-collapse: collapse; font-size: 12px; font-family: 'JetBrains Mono', monospace; }
.cb-table th { text-align: left; padding: 10px 12px; color: #60a5fa; font-size: 10px; letter-spacing: 1.5px; text-transform: uppercase; border-bottom: 2px solid #1a2540; font-weight: 600; white-space: nowrap; }
.cb-table td { padding: 10px 12px; border-bottom: 1px solid #111d30; vertical-align: middle; }
.cb-table tbody tr { transition: background 0.15s ease; }
.cb-table tbody tr:hover { background: rgba(59, 130, 246, 0.06); }
.cb-actor-name { color: #fff; font-weight: 600; }
.cb-actor-alias { color: #667788; font-size: 10px; display: block; margin-top: 2px; }
.cb-flag { display: inline-block; width: 18px; text-align: center; font-size: 11px; }
.cb-nation { color: #a0aec0; }
.cb-sectors { display: flex; flex-wrap: wrap; gap: 4px; }
.cb-sector-tag { background: #111d30; color: #8899aa; padding: 2px 7px; border-radius: 3px; font-size: 9px; white-space: nowrap; }
.cb-activity-bar-wrap { width: 100px; height: 6px; background: #111d30; border-radius: 3px; overflow: hidden; }
.cb-activity-bar { height: 100%; border-radius: 3px; transition: width 0.5s ease; }
.cb-confidence { font-size: 10px; font-weight: 600; letter-spacing: 0.5px; }
.cb-confidence-high { color: #22c55e; }
.cb-confidence-moderate { color: #eab308; }
.cb-confidence-low { color: #ef4444; }
.cb-last-seen { color: #667788; font-size: 11px; }
.cb-status-active { color: #22c55e; }
.cb-status-monitoring { color: #eab308; }

/* Sector Threat Matrix */
.cb-sector-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 12px; }
.cb-sector-card { background: #0a1220; border: 1px solid #1a2540; border-radius: 6px; padding: 14px; transition: border-color 0.15s ease; }
.cb-sector-card:hover { border-color: #2a3a5a; }
.cb-sector-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; }
.cb-sector-name { color: #e2e8f0; font-size: 13px; font-weight: 600; }
.cb-threat-badge { font-size: 9px; font-family: 'JetBrains Mono', monospace; font-weight: 700; letter-spacing: 1px; padding: 3px 10px; border-radius: 3px; }
.cb-threat-critical { background: #7f1d1d; color: #fca5a5; border: 1px solid #dc2626; }
.cb-threat-high { background: #7c2d12; color: #fdba74; border: 1px solid #ea580c; }
.cb-threat-elevated { background: #713f12; color: #fde68a; border: 1px solid #ca8a04; }
.cb-threat-moderate { background: #1e3a5f; color: #93c5fd; border: 1px solid #3b82f6; }
.cb-threat-low { background: #14532d; color: #86efac; border: 1px solid #22c55e; }
.cb-sector-score-bar { height: 4px; background: #111d30; border-radius: 2px; overflow: hidden; margin: 8px 0; }
.cb-sector-score-fill { height: 100%; border-radius: 2px; }
.cb-sector-actors { color: #8899aa; font-size: 10px; font-family: 'JetBrains Mono', monospace; margin-bottom: 6px; }
.cb-sector-desc { color: #667788; font-size: 11px; line-height: 1.5; }
.cb-sector-meta { display: flex; justify-content: space-between; align-items: center; margin-top: 8px; padding-top: 8px; border-top: 1px solid #111d30; }
.cb-sector-incidents { color: #8899aa; font-size: 10px; }
.cb-sector-trend { font-size: 10px; font-weight: 600; }
.cb-trend-rising { color: #ef4444; }
.cb-trend-stable { color: #eab308; }
.cb-trend-declining { color: #22c55e; }

/* Intel Findings */
.cb-intel-item { background: #0a1220; border: 1px solid #1a2540; border-radius: 6px; padding: 16px; margin-bottom: 10px; }
.cb-intel-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; margin-bottom: 10px; }
.cb-intel-id { color: #3b82f6; font-size: 10px; font-family: 'JetBrains Mono', monospace; }
.cb-intel-title { color: #e2e8f0; font-size: 13px; font-weight: 600; margin: 4px 0 8px; }
.cb-intel-meta { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 10px; }
.cb-intel-meta-item { font-size: 10px; color: #667788; font-family: 'JetBrains Mono', monospace; }
.cb-intel-meta-item span { color: #a0aec0; }
.cb-intel-summary { color: #a0b4c8; font-size: 12px; line-height: 1.6; }
.cb-intel-action { margin-top: 10px; padding: 8px 12px; background: #1e293b; border-radius: 4px; border-left: 3px solid #f59e0b; color: #fde68a; font-size: 11px; font-family: 'JetBrains Mono', monospace; }
.cb-score-bar { display: inline-flex; align-items: center; gap: 6px; }
.cb-score-track { width: 60px; height: 4px; background: #111d30; border-radius: 2px; overflow: hidden; display: inline-block; }
.cb-score-fill { height: 100%; border-radius: 2px; }
.cb-score-val { font-size: 10px; font-family: 'JetBrains Mono', monospace; font-weight: 600; }

/* Recommended Actions */
.cb-action-item { display: grid; grid-template-columns: 90px 1fr 100px 100px 80px; gap: 12px; align-items: center; padding: 12px; border-bottom: 1px solid #111d30; font-size: 12px; }
.cb-action-item:last-child { border-bottom: none; }
.cb-priority { font-size: 9px; font-family: 'JetBrains Mono', monospace; font-weight: 700; letter-spacing: 1px; padding: 4px 8px; border-radius: 3px; text-align: center; }
.cb-priority-immediate { background: #7f1d1d; color: #fca5a5; }
.cb-priority-urgent { background: #7c2d12; color: #fdba74; }
.cb-priority-high { background: #713f12; color: #fde68a; }
.cb-priority-moderate { background: #1e3a5f; color: #93c5fd; }
.cb-action-text { color: #d1dbe8; }
.cb-action-owner { color: #8899aa; font-size: 11px; font-family: 'JetBrains Mono', monospace; }
.cb-action-deadline { color: #667788; font-size: 11px; font-family: 'JetBrains Mono', monospace; }
.cb-action-status { font-size: 10px; font-family: 'JetBrains Mono', monospace; }

/* Decision Points */
.cb-decision { background: #0a1220; border: 1px solid #1e3a5f; border-radius: 8px; padding: 18px; margin-bottom: 14px; }
.cb-decision-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; }
.cb-decision-id { color: #f59e0b; font-size: 10px; font-family: 'JetBrains Mono', monospace; font-weight: 700; }
.cb-decision-urgency { font-size: 9px; font-weight: 700; letter-spacing: 1px; padding: 3px 10px; border-radius: 3px; }
.cb-decision-title { color: #fff; font-size: 14px; font-weight: 600; margin-bottom: 8px; }
.cb-decision-bg { color: #8899aa; font-size: 12px; line-height: 1.6; margin-bottom: 14px; }
.cb-decision-deadline { color: #ef4444; font-size: 11px; font-family: 'JetBrains Mono', monospace; margin-bottom: 14px; }
.cb-option { background: #111d30; border: 1px solid #1a2540; border-radius: 6px; padding: 12px; margin-bottom: 8px; cursor: pointer; transition: all 0.15s ease; }
.cb-option:hover { border-color: #3b82f6; background: #0f1d35; }
.cb-option-label { color: #e2e8f0; font-size: 12px; font-weight: 600; margin-bottom: 6px; }
.cb-option-risk { font-size: 9px; font-family: 'JetBrains Mono', monospace; font-weight: 700; letter-spacing: 0.5px; margin-left: 8px; }
.cb-option-detail { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 8px; }
.cb-option-pro, .cb-option-con { font-size: 11px; line-height: 1.5; }
.cb-option-pro { color: #86efac; }
.cb-option-con { color: #fca5a5; }
.cb-option-pro::before { content: '+ '; font-weight: bold; }
.cb-option-con::before { content: '- '; font-weight: bold; }

/* IOC Table */
.cb-ioc-type { font-size: 9px; font-family: 'JetBrains Mono', monospace; font-weight: 700; letter-spacing: 1px; padding: 2px 8px; border-radius: 3px; background: #1e293b; color: #93c5fd; white-space: nowrap; }
.cb-ioc-value { color: #f59e0b; font-family: 'JetBrains Mono', monospace; font-size: 11px; word-break: break-all; }
.cb-ioc-actor { color: #e2e8f0; font-size: 11px; }
.cb-ioc-context { color: #667788; font-size: 10px; }

/* Export modal */
.cb-export-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7); z-index: 1000; display: flex; align-items: center; justify-content: center; }
.cb-export-modal { background: #0c1220; border: 1px solid #1a2540; border-radius: 12px; padding: 24px; max-width: 800px; width: 90%; max-height: 80vh; overflow-y: auto; }
.cb-export-textarea { width: 100%; min-height: 400px; background: #070d18; border: 1px solid #1a2540; color: #c8d6e5; font-family: 'JetBrains Mono', monospace; font-size: 11px; padding: 16px; border-radius: 6px; resize: vertical; }
.cb-export-actions { display: flex; gap: 10px; margin-top: 12px; justify-content: flex-end; }

/* Stat cards row */
.cb-stats-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; margin-bottom: 16px; }
.cb-stat-card { background: #0a1220; border: 1px solid #1a2540; border-radius: 6px; padding: 12px; text-align: center; }
.cb-stat-value { font-size: 24px; font-weight: 700; font-family: 'JetBrains Mono', monospace; }
.cb-stat-label { font-size: 10px; color: #667788; font-family: 'JetBrains Mono', monospace; letter-spacing: 1px; text-transform: uppercase; margin-top: 4px; }

/* Responsive */
@media (max-width: 768px) {
  .cb-header { flex-direction: column; }
  .cb-action-item { grid-template-columns: 1fr; gap: 6px; }
  .cb-option-detail { grid-template-columns: 1fr; }
  .cb-sector-grid { grid-template-columns: 1fr; }
}

/* ── Pro Theme Overrides ── */
[data-style=pro] .cb-wrap { color: #3f3f46; }
[data-style=pro] .cb-header-left h1 { color: #18181b; }
[data-style=pro] .cb-header-left .cb-subtitle { color: #71717a; }
[data-style=pro] .cb-section { background: #fff; border-color: #e5e5e5; }
[data-style=pro] .cb-section-title { color: #2563eb; border-bottom-color: #e5e5e5; }
[data-style=pro] .cb-bluf { background: #f0f4ff; border-color: #dbeafe; border-left-color: #2563eb; }
[data-style=pro] .cb-bluf-text { color: #1e293b; }
[data-style=pro] .cb-select { background: #fff; border-color: #d4d4d8; color: #18181b; }
[data-style=pro] .cb-btn { background: #f4f4f5; border-color: #d4d4d8; color: #18181b; }
[data-style=pro] .cb-btn:hover { background: #e4e4e7; }
[data-style=pro] .cb-btn-primary { background: #2563eb; border-color: #2563eb; color: #fff; }
[data-style=pro] .cb-btn-primary:hover { background: #1d4ed8; }
[data-style=pro] .cb-table th { color: #2563eb; border-bottom-color: #e5e5e5; }
[data-style=pro] .cb-table td { border-bottom-color: #f4f4f5; }
[data-style=pro] .cb-table tbody tr:hover { background: rgba(37, 99, 235, 0.04); }
[data-style=pro] .cb-actor-name { color: #18181b; }
[data-style=pro] .cb-actor-alias { color: #71717a; }
[data-style=pro] .cb-nation { color: #52525b; }
[data-style=pro] .cb-sector-tag { background: #f4f4f5; color: #52525b; }
[data-style=pro] .cb-activity-bar-wrap { background: #e5e5e5; }
[data-style=pro] .cb-last-seen { color: #71717a; }
[data-style=pro] .cb-sector-card { background: #fff; border-color: #e5e5e5; }
[data-style=pro] .cb-sector-name { color: #18181b; }
[data-style=pro] .cb-sector-score-bar { background: #e5e5e5; }
[data-style=pro] .cb-sector-actors { color: #52525b; }
[data-style=pro] .cb-sector-desc { color: #71717a; }
[data-style=pro] .cb-sector-meta { border-top-color: #f4f4f5; }
[data-style=pro] .cb-intel-item { background: #fff; border-color: #e5e5e5; }
[data-style=pro] .cb-intel-title { color: #18181b; }
[data-style=pro] .cb-intel-summary { color: #3f3f46; }
[data-style=pro] .cb-intel-action { background: #fffbeb; border-left-color: #f59e0b; color: #92400e; }
[data-style=pro] .cb-score-track { background: #e5e5e5; }
[data-style=pro] .cb-action-text { color: #18181b; }
[data-style=pro] .cb-action-owner { color: #52525b; }
[data-style=pro] .cb-action-deadline { color: #71717a; }
[data-style=pro] .cb-decision { background: #fff; border-color: #dbeafe; }
[data-style=pro] .cb-decision-title { color: #18181b; }
[data-style=pro] .cb-decision-bg { color: #52525b; }
[data-style=pro] .cb-option { background: #fafafa; border-color: #e5e5e5; }
[data-style=pro] .cb-option:hover { background: #f0f4ff; border-color: #2563eb; }
[data-style=pro] .cb-option-label { color: #18181b; }
[data-style=pro] .cb-ioc-type { background: #f0f4ff; color: #2563eb; }
[data-style=pro] .cb-ioc-value { color: #b45309; }
[data-style=pro] .cb-ioc-actor { color: #18181b; }
[data-style=pro] .cb-ioc-context { color: #71717a; }
[data-style=pro] .cb-stat-card { background: #fff; border-color: #e5e5e5; }
[data-style=pro] .cb-stat-label { color: #71717a; }
[data-style=pro] .cb-export-modal { background: #fff; border-color: #e5e5e5; }
[data-style=pro] .cb-export-textarea { background: #fafafa; border-color: #e5e5e5; color: #18181b; }
`;
  document.head.appendChild(style);
}


// ═══════════════════════════════════════════════════════════════════════════════
// RENDERING
// ═══════════════════════════════════════════════════════════════════════════════

function getActivityColor(val) {
  if (val >= 80) return '#ef4444';
  if (val >= 60) return '#f59e0b';
  if (val >= 40) return '#3b82f6';
  return '#22c55e';
}

function getThreatColor(level) {
  switch (level) {
    case 'CRITICAL': return '#ef4444';
    case 'HIGH': return '#ea580c';
    case 'ELEVATED': return '#eab308';
    case 'MODERATE': return '#3b82f6';
    case 'LOW': return '#22c55e';
    default: return '#667788';
  }
}

function getThreatClass(level) {
  return 'cb-threat-' + level.toLowerCase();
}

function getPriorityClass(priority) {
  return 'cb-priority-' + priority.toLowerCase();
}

function formatDateShort(d) {
  return d;
}

function getNowISO() {
  return new Date().toISOString().replace('T', ' ').slice(0, 19) + 'Z';
}

function renderClassificationBanner(classification) {
  var c = CLASSIFICATIONS.find(function(x) { return x.id === classification; }) || CLASSIFICATIONS[0];
  return '<div class="cb-classification-banner" style="background:' + c.bg + ';color:' + c.color + ';border:2px solid ' + c.color + '">' + esc(c.label) + '</div>';
}

function renderFictionNotice() {
  return '<div class="cb-fiction-note"><strong>Training scenario - fictional.</strong> This briefing is an exercise for practising executive threat communication. ' +
    'Findings, incident counts, indicators, decisions and dates are invented; they are not real intelligence and are not sourced from or endorsed by any government agency. ' +
    'Threat-actor names are real public designations used only to make the scenario realistic; the activity described here is fictional. ' +
    'IP addresses and domains use reserved documentation ranges.</div>';
}

function renderHeader(classification, audience) {
  var h = '';
  h += '<div class="cb-header">';
  h += '<div class="cb-header-left">';
  h += '<h1>EXECUTIVE CYBER BRIEFING <span class="cb-fiction-badge">Training scenario - fictional</span></h1>';
  h += '<div class="cb-subtitle">Generated: ' + esc(getNowISO()) + ' | Exercise briefing for practice | Not real intelligence</div>';
  h += '</div>';
  h += '<div class="cb-controls">';
  h += '<select class="cb-select" id="cb-classification" title="Exercise marking">';
  for (var i = 0; i < CLASSIFICATIONS.length; i++) {
    var cl = CLASSIFICATIONS[i];
    h += '<option value="' + esc(cl.id) + '"' + (cl.id === classification ? ' selected' : '') + '>' + esc(cl.label) + '</option>';
  }
  h += '</select>';
  h += '<select class="cb-select" id="cb-audience">';
  for (var j = 0; j < AUDIENCES.length; j++) {
    var au = AUDIENCES[j];
    h += '<option value="' + esc(au.id) + '"' + (au.id === audience ? ' selected' : '') + '>' + esc(au.label) + '</option>';
  }
  h += '</select>';
  h += '<button class="cb-btn" id="cb-regenerate">&#8635; Regenerate</button>';
  h += '<button class="cb-btn cb-btn-primary" id="cb-export">&#9660; Export Briefing</button>';
  h += '</div>';
  h += '</div>';
  return h;
}

function renderStats() {
  var activeActors = THREAT_ACTORS.filter(function(a) { return a.status === 'active'; }).length;
  var totalIncidents = 0;
  for (var i = 0; i < SECTOR_THREATS.length; i++) totalIncidents += SECTOR_THREATS[i].incidents30d;
  var criticalSectors = SECTOR_THREATS.filter(function(s) { return s.level === 'CRITICAL' || s.level === 'HIGH'; }).length;
  var pendingDecisions = DECISION_POINTS.length;

  var stats = [
    { value: activeActors, label: 'Active Threat Actors', color: '#ef4444' },
    { value: totalIncidents, label: 'Scenario Incidents (30d)', color: '#f59e0b' },
    { value: criticalSectors, label: 'Sectors at Risk', color: '#ea580c' },
    { value: pendingDecisions, label: 'Pending Decisions', color: '#8b5cf6' },
    { value: IOCS.length, label: 'Exercise IOCs', color: '#3b82f6' },
    { value: RECOMMENDED_ACTIONS.filter(function(a) { return a.priority === 'IMMEDIATE'; }).length, label: 'Immediate Actions', color: '#dc2626' }
  ];

  var h = '<div class="cb-stats-row">';
  for (var s = 0; s < stats.length; s++) {
    h += '<div class="cb-stat-card">';
    h += '<div class="cb-stat-value" style="color:' + stats[s].color + '">' + stats[s].value + '</div>';
    h += '<div class="cb-stat-label">' + esc(stats[s].label) + '</div>';
    h += '</div>';
  }
  h += '</div>';
  return h;
}

function renderBLUF(audience) {
  var text = BLUF[audience] || BLUF.ciso;
  var h = '<div class="cb-bluf">';
  h += '<div class="cb-bluf-label">BOTTOM LINE UP FRONT (BLUF)</div>';
  h += '<div class="cb-bluf-text">' + esc(text) + '</div>';
  h += '</div>';
  return h;
}

function renderActorTable() {
  var h = '<div class="cb-section">';
  h += '<div class="cb-section-title"><span class="cb-icon">&#9888;</span> ACTIVE THREAT ACTORS</div>';
  h += '<div style="overflow-x:auto">';
  h += '<table class="cb-table">';
  h += '<thead><tr>';
  h += '<th>Actor</th><th>Nation</th><th>Target Sectors</th><th>Activity</th><th>Confidence</th><th>Status</th><th>Last Seen</th>';
  h += '</tr></thead><tbody>';

  for (var i = 0; i < THREAT_ACTORS.length; i++) {
    var a = THREAT_ACTORS[i];
    var actColor = getActivityColor(a.activity);
    var confClass = 'cb-confidence-' + a.confidence.toLowerCase();
    var statusClass = 'cb-status-' + a.status;

    h += '<tr>';
    h += '<td><span class="cb-actor-name">' + esc(a.name) + '</span><span class="cb-actor-alias">' + esc(a.alias) + '</span></td>';
    h += '<td><span class="cb-nation">' + esc(a.nation) + '</span></td>';
    h += '<td><div class="cb-sectors">';
    for (var s = 0; s < a.sectors.length; s++) {
      h += '<span class="cb-sector-tag">' + esc(a.sectors[s]) + '</span>';
    }
    h += '</div></td>';
    h += '<td><div class="cb-activity-bar-wrap"><div class="cb-activity-bar" style="width:' + a.activity + '%;background:' + actColor + '"></div></div><span style="font-size:10px;color:' + actColor + '">' + a.activity + '%</span></td>';
    h += '<td><span class="cb-confidence ' + confClass + '">' + esc(a.confidence) + '</span></td>';
    h += '<td><span class="' + statusClass + '" style="font-size:10px;font-family:monospace;font-weight:600;text-transform:uppercase">' + esc(a.status) + '</span></td>';
    h += '<td><span class="cb-last-seen">' + esc(a.lastSeen) + '</span></td>';
    h += '</tr>';
  }

  h += '</tbody></table>';
  h += '</div></div>';
  return h;
}

function renderSectorMatrix() {
  var h = '<div class="cb-section">';
  h += '<div class="cb-section-title"><span class="cb-icon">&#9881;</span> CRITICAL INFRASTRUCTURE SECTOR THREAT MATRIX (SCENARIO)</div>';
  h += '<div class="cb-sector-grid">';

  for (var i = 0; i < SECTOR_THREATS.length; i++) {
    var s = SECTOR_THREATS[i];
    var color = getThreatColor(s.level);
    var trendClass = 'cb-trend-' + s.trend;
    var trendIcon = s.trend === 'rising' ? '&#9650;' : s.trend === 'declining' ? '&#9660;' : '&#9654;';

    h += '<div class="cb-sector-card">';
    h += '<div class="cb-sector-header">';
    h += '<span class="cb-sector-name">' + esc(s.sector) + '</span>';
    h += '<span class="cb-threat-badge ' + getThreatClass(s.level) + '">' + esc(s.level) + '</span>';
    h += '</div>';
    h += '<div class="cb-sector-score-bar"><div class="cb-sector-score-fill" style="width:' + s.score + '%;background:' + color + '"></div></div>';
    h += '<div class="cb-sector-actors">Actors: ' + esc(s.actors.join(', ')) + '</div>';
    h += '<div class="cb-sector-desc">' + esc(s.description) + '</div>';
    h += '<div class="cb-sector-meta">';
    h += '<span class="cb-sector-incidents">' + s.incidents30d + ' incidents (30d)</span>';
    h += '<span class="cb-sector-trend ' + trendClass + '">' + trendIcon + ' ' + esc(s.trend.toUpperCase()) + '</span>';
    h += '</div>';
    h += '</div>';
  }

  h += '</div></div>';
  return h;
}

function renderIntelFindings() {
  var h = '<div class="cb-section">';
  h += '<div class="cb-section-title"><span class="cb-icon">&#9733;</span> KEY FINDINGS (FICTIONAL EXERCISE INJECTS)</div>';

  for (var i = 0; i < INTEL_FINDINGS.length; i++) {
    var f = INTEL_FINDINGS[i];
    var confColor = f.confidence >= 90 ? '#22c55e' : f.confidence >= 75 ? '#eab308' : '#ef4444';
    var relColor = f.relevance >= 90 ? '#ef4444' : f.relevance >= 75 ? '#f59e0b' : '#3b82f6';

    h += '<div class="cb-intel-item">';
    h += '<div class="cb-intel-header">';
    h += '<div>';
    h += '<div class="cb-intel-id">' + esc(f.id) + ' | ' + esc(f.date) + '</div>';
    h += '<div class="cb-intel-title">' + esc(f.title) + '</div>';
    h += '</div>';
    h += '</div>';
    h += '<div class="cb-intel-meta">';
    h += '<div class="cb-intel-meta-item">Source: <span>' + esc(f.source) + '</span></div>';
    h += '<div class="cb-intel-meta-item">Marking: <span>' + esc(f.classification) + '</span></div>';
    h += '<div class="cb-intel-meta-item">Confidence: <span class="cb-score-bar"><span class="cb-score-track"><span class="cb-score-fill" style="width:' + f.confidence + '%;background:' + confColor + '"></span></span> <span class="cb-score-val" style="color:' + confColor + '">' + f.confidence + '%</span></span></div>';
    h += '<div class="cb-intel-meta-item">Relevance: <span class="cb-score-bar"><span class="cb-score-track"><span class="cb-score-fill" style="width:' + f.relevance + '%;background:' + relColor + '"></span></span> <span class="cb-score-val" style="color:' + relColor + '">' + f.relevance + '%</span></span></div>';
    h += '</div>';
    h += '<div class="cb-intel-summary">' + esc(f.summary) + '</div>';
    if (f.actionRequired) {
      h += '<div class="cb-intel-action">&#9888; ACTION REQUIRED — See Recommended Actions section</div>';
    }
    h += '</div>';
  }

  h += '</div>';
  return h;
}

function renderActions() {
  var h = '<div class="cb-section">';
  h += '<div class="cb-section-title"><span class="cb-icon">&#9654;</span> RECOMMENDED ACTIONS</div>';

  h += '<div class="cb-action-item" style="font-weight:700;color:#60a5fa;font-size:10px;letter-spacing:1px;text-transform:uppercase;border-bottom:2px solid #1a2540;font-family:\'JetBrains Mono\',monospace">';
  h += '<div>Priority</div><div>Action</div><div>Owner</div><div>Deadline</div><div>Status</div>';
  h += '</div>';

  for (var i = 0; i < RECOMMENDED_ACTIONS.length; i++) {
    var a = RECOMMENDED_ACTIONS[i];
    var statusColor = a.status === 'IN PROGRESS' ? '#22c55e' : a.status === 'PENDING APPROVAL' ? '#f59e0b' : a.status === 'DRAFT' ? '#8899aa' : '#3b82f6';

    h += '<div class="cb-action-item">';
    h += '<div><span class="cb-priority ' + getPriorityClass(a.priority) + '">' + esc(a.priority) + '</span></div>';
    h += '<div class="cb-action-text">' + esc(a.action) + '</div>';
    h += '<div class="cb-action-owner">' + esc(a.owner) + '</div>';
    h += '<div class="cb-action-deadline">' + esc(a.deadline) + '</div>';
    h += '<div class="cb-action-status" style="color:' + statusColor + '">' + esc(a.status) + '</div>';
    h += '</div>';
  }

  h += '</div>';
  return h;
}

function renderDecisionPoints() {
  var h = '<div class="cb-section">';
  h += '<div class="cb-section-title"><span class="cb-icon">&#9873;</span> DECISION POINTS REQUIRING EXECUTIVE ACTION</div>';

  for (var i = 0; i < DECISION_POINTS.length; i++) {
    var dp = DECISION_POINTS[i];
    var urgencyColor = dp.urgency === 'IMMEDIATE' ? '#ef4444' : dp.urgency === 'URGENT' ? '#f59e0b' : '#3b82f6';
    var urgencyBg = dp.urgency === 'IMMEDIATE' ? '#7f1d1d' : dp.urgency === 'URGENT' ? '#7c2d12' : '#1e3a5f';

    h += '<div class="cb-decision">';
    h += '<div class="cb-decision-header">';
    h += '<span class="cb-decision-id">' + esc(dp.id) + '</span>';
    h += '<span class="cb-decision-urgency" style="background:' + urgencyBg + ';color:' + urgencyColor + '">' + esc(dp.urgency) + '</span>';
    h += '</div>';
    h += '<div class="cb-decision-title">' + esc(dp.title) + '</div>';
    h += '<div class="cb-decision-deadline">&#9201; DECISION REQUIRED BY: ' + esc(dp.deadline) + '</div>';
    h += '<div class="cb-decision-bg">' + esc(dp.background) + '</div>';

    h += '<div style="font-size:11px;color:#60a5fa;font-family:\'JetBrains Mono\',monospace;letter-spacing:1px;margin-bottom:8px;text-transform:uppercase">Options:</div>';
    for (var o = 0; o < dp.options.length; o++) {
      var opt = dp.options[o];
      var riskColor = opt.risk === 'MODERATE' ? '#eab308' : opt.risk === 'LOW' ? '#22c55e' : '#ef4444';
      h += '<div class="cb-option">';
      h += '<div class="cb-option-label">' + (o + 1) + '. ' + esc(opt.label) + '<span class="cb-option-risk" style="color:' + riskColor + '">' + esc(opt.risk) + ' RISK</span></div>';
      h += '<div class="cb-option-detail">';
      h += '<div class="cb-option-pro">' + esc(opt.pros) + '</div>';
      h += '<div class="cb-option-con">' + esc(opt.cons) + '</div>';
      h += '</div>';
      h += '</div>';
    }

    h += '</div>';
  }

  h += '</div>';
  return h;
}

function renderIOCTable() {
  var h = '<div class="cb-section">';
  h += '<div class="cb-section-title"><span class="cb-icon">&#128270;</span> APPENDIX: EXERCISE INDICATORS (fictional, not for blocking)</div>';
  h += '<div style="overflow-x:auto">';
  h += '<table class="cb-table">';
  h += '<thead><tr>';
  h += '<th>Type</th><th>Indicator</th><th>Attribution</th><th>Context</th><th>First Seen</th><th>Confidence</th>';
  h += '</tr></thead><tbody>';

  for (var i = 0; i < IOCS.length; i++) {
    var ioc = IOCS[i];
    var confClass = 'cb-confidence-' + ioc.confidence.toLowerCase();

    h += '<tr>';
    h += '<td><span class="cb-ioc-type">' + esc(ioc.type) + '</span></td>';
    h += '<td><span class="cb-ioc-value">' + esc(ioc.value) + '</span></td>';
    h += '<td><span class="cb-ioc-actor">' + esc(ioc.actor) + '</span></td>';
    h += '<td><span class="cb-ioc-context">' + esc(ioc.context) + '</span></td>';
    h += '<td><span class="cb-last-seen">' + esc(ioc.firstSeen) + '</span></td>';
    h += '<td><span class="cb-confidence ' + confClass + '">' + esc(ioc.confidence) + '</span></td>';
    h += '</tr>';
  }

  h += '</tbody></table>';
  h += '</div></div>';
  return h;
}

function generateExportText(classification, audience) {
  var cls = CLASSIFICATIONS.find(function(x) { return x.id === classification; }) || CLASSIFICATIONS[0];
  var aud = AUDIENCES.find(function(x) { return x.id === audience; }) || AUDIENCES[0];
  var sep = '═'.repeat(72);
  var line = '─'.repeat(72);

  var text = '';
  text += cls.label + '\n';
  text += sep + '\n';
  text += 'EXECUTIVE CYBER BRIEFING\n';
  text += 'Generated: ' + getNowISO() + '\n';
  text += 'Audience: ' + aud.label + '\n';
  text += 'TRAINING SCENARIO - FICTIONAL. Not real intelligence; not sourced from any government agency.\n';
  text += sep + '\n\n';

  text += 'BOTTOM LINE UP FRONT (BLUF)\n';
  text += line + '\n';
  text += (BLUF[audience] || BLUF.ciso) + '\n\n';

  text += 'ACTIVE THREAT ACTORS\n';
  text += line + '\n';
  for (var i = 0; i < THREAT_ACTORS.length; i++) {
    var a = THREAT_ACTORS[i];
    text += a.name + ' (' + a.alias + ') — ' + a.nation + ' / ' + a.sponsor + '\n';
    text += '  Status: ' + a.status.toUpperCase() + ' | Activity: ' + a.activity + '% | Confidence: ' + a.confidence + '\n';
    text += '  Campaign: ' + a.campaign + '\n';
    text += '  Targets: ' + a.sectors.join(', ') + '\n';
    text += '  Summary: ' + a.summary + '\n\n';
  }

  text += 'SECTOR THREAT MATRIX\n';
  text += line + '\n';
  for (var j = 0; j < SECTOR_THREATS.length; j++) {
    var s = SECTOR_THREATS[j];
    text += s.sector + ': ' + s.level + ' (Score: ' + s.score + '/100, Trend: ' + s.trend + ', Incidents: ' + s.incidents30d + ')\n';
    text += '  ' + s.description + '\n\n';
  }

  text += 'KEY INTELLIGENCE FINDINGS\n';
  text += line + '\n';
  for (var k = 0; k < INTEL_FINDINGS.length; k++) {
    var f = INTEL_FINDINGS[k];
    text += f.id + ' — ' + f.title + '\n';
    text += '  Source: ' + f.source + ' | Confidence: ' + f.confidence + '% | Relevance: ' + f.relevance + '%\n';
    text += '  ' + f.summary + '\n';
    if (f.actionRequired) text += '  *** ACTION REQUIRED ***\n';
    text += '\n';
  }

  text += 'RECOMMENDED ACTIONS\n';
  text += line + '\n';
  for (var l = 0; l < RECOMMENDED_ACTIONS.length; l++) {
    var ra = RECOMMENDED_ACTIONS[l];
    text += '[' + ra.priority + '] ' + ra.action + '\n';
    text += '  Owner: ' + ra.owner + ' | Deadline: ' + ra.deadline + ' | Status: ' + ra.status + '\n\n';
  }

  text += 'DECISION POINTS\n';
  text += line + '\n';
  for (var m = 0; m < DECISION_POINTS.length; m++) {
    var dp = DECISION_POINTS[m];
    text += dp.id + ' — ' + dp.title + '\n';
    text += '  Urgency: ' + dp.urgency + ' | Deadline: ' + dp.deadline + '\n';
    text += '  Background: ' + dp.background + '\n';
    text += '  Options:\n';
    for (var n = 0; n < dp.options.length; n++) {
      text += '    ' + (n + 1) + '. ' + dp.options[n].label + ' (Risk: ' + dp.options[n].risk + ')\n';
    }
    text += '\n';
  }

  text += 'EXERCISE INDICATORS (fictional, documentation ranges)\n';
  text += line + '\n';
  for (var p = 0; p < IOCS.length; p++) {
    var ioc = IOCS[p];
    text += '[' + ioc.type + '] ' + ioc.value + '\n';
    text += '  Actor: ' + ioc.actor + ' | Context: ' + ioc.context + ' | First Seen: ' + ioc.firstSeen + '\n\n';
  }

  text += sep + '\n';
  text += cls.label + '\n';
  text += 'END OF BRIEFING\n';

  return text;
}


// ═══════════════════════════════════════════════════════════════════════════════
// MAIN RENDER FUNCTION
// ═══════════════════════════════════════════════════════════════════════════════

export function renderCyberBriefing(container) {
  injectStyles();

  var curClassification = 'training';
  var curAudience = 'ciso';

  function render() {
    var h = '<div class="cb-wrap">';
    h += renderClassificationBanner(curClassification);
    h += renderHeader(curClassification, curAudience);
    h += renderFictionNotice();
    h += renderStats();
    h += renderBLUF(curAudience);
    h += renderActorTable();
    h += renderSectorMatrix();
    h += renderIntelFindings();
    h += renderActions();
    h += renderDecisionPoints();
    h += renderIOCTable();
    h += renderClassificationBanner(curClassification);
    h += '</div>';

    container.innerHTML = h;
    wireEvents();
  }

  function wireEvents() {
    var clsSelect = container.querySelector('#cb-classification');
    var audSelect = container.querySelector('#cb-audience');
    var regenBtn = container.querySelector('#cb-regenerate');
    var exportBtn = container.querySelector('#cb-export');

    if (clsSelect) {
      clsSelect.addEventListener('change', function() {
        curClassification = this.value;
        render();
      });
    }

    if (audSelect) {
      audSelect.addEventListener('change', function() {
        curAudience = this.value;
        render();
      });
    }

    if (regenBtn) {
      regenBtn.addEventListener('click', function() {
        render();
      });
    }

    if (exportBtn) {
      exportBtn.addEventListener('click', function() {
        showExport();
      });
    }
  }

  function showExport() {
    var text = generateExportText(curClassification, curAudience);
    var overlay = document.createElement('div');
    overlay.className = 'cb-export-overlay';
    overlay.innerHTML = '<div class="cb-export-modal">' +
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">' +
      '<div style="font-size:16px;font-weight:700;color:#e2e8f0">Export Briefing</div>' +
      '<button class="cb-btn" id="cb-export-close">&times; Close</button>' +
      '</div>' +
      '<textarea class="cb-export-textarea" id="cb-export-text" readonly>' + esc(text) + '</textarea>' +
      '<div class="cb-export-actions">' +
      '<button class="cb-btn" id="cb-copy-text">Copy to Clipboard</button>' +
      '</div>' +
      '</div>';

    document.body.appendChild(overlay);

    overlay.querySelector('#cb-export-close').addEventListener('click', function() {
      overlay.remove();
    });

    overlay.addEventListener('click', function(e) {
      if (e.target === overlay) overlay.remove();
    });

    overlay.querySelector('#cb-copy-text').addEventListener('click', function() {
      var textarea = overlay.querySelector('#cb-export-text');
      textarea.select();
      navigator.clipboard.writeText(textarea.value).then(function() {
        overlay.querySelector('#cb-copy-text').textContent = 'Copied!';
        setTimeout(function() {
          var btn = overlay.querySelector('#cb-copy-text');
          if (btn) btn.textContent = 'Copy to Clipboard';
        }, 2000);
      });
    });
  }

  render();
}
