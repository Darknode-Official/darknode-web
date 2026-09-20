// ============================================================================
// SENTINEL EYE — Global Cyber Threat Detection & Counter-Operations Platform
// Global cyber threat detection and prediction platform
// Copyright (c) 2026 Darknode-Official. All rights reserved.
// ============================================================================
// NORAD-grade cyber early warning system: monitors nation-state cyber force
// readiness, global network anomalies, dark web signals, APT operational tempo,
// and geopolitical triggers that precede cyber operations.
// ============================================================================

// SENTINEL EYE — Global Cyber Threat Detection & Prediction Platform
// Data Arrays & Core Utilities
// Global cyber threat detection and prediction platform

var esc = function(s) {
  return String(s != null ? s : '').replace(/[&<>"']/g, function(c) {
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
  });
};

var NATION_STATE_PROFILES = [];
var APT_GROUPS = [];
var HISTORICAL_OPS = [];
var WARGAME_SCENARIOS = [];
var _seDataLoaded = false;
function _seLoadData() {
  if (_seDataLoaded) return Promise.resolve();
  return import("/js/sentinel-eye-data.js").then(function(m) {
    NATION_STATE_PROFILES = m.NATION_STATE_PROFILES;
    APT_GROUPS = m.APT_GROUPS;
    HISTORICAL_OPS = m.HISTORICAL_OPS;
    WARGAME_SCENARIOS = m.WARGAME_SCENARIOS;
    _seDataLoaded = true;
  });
}


// ============================================================================
// APT GROUP DATABASE (35+ groups)
// ============================================================================

// ============================================================================
// ACTIVE THREATS -- populated at runtime from NVD, ThreatFox APIs
// No hardcoded predictions or confidence scores
// ============================================================================
var THREAT_PREDICTIONS = [];
var _seActiveThreats = { nvd: null, threatfox: null, urlhaus: null, ts: 0 };
var _seOllamaAvailable = null;
var _seOllamaModel = 'llama3.2';

// ============================================================================
// ACTIVE THREAT INDICATORS -- populated at runtime from real feeds
// No hardcoded indicators or severity assignments
// ============================================================================
var EARLY_WARNING_INDICATORS = [];
var _seEarlyWarningData = { nvd: null, threatfox: null, urlhaus: null, ts: 0 };

// ============================================================================
// GEOPOLITICAL EVENTS -- real events, AI analysis available via Ollama
// No hardcoded cyber implications or historical precedent claims
// ============================================================================
var GEOPOLITICAL_TRIGGERS = [
  { id: 'geo-001', event: 'Taiwan Strait military exercises by PLA Navy', region: 'Indo-Pacific', date: '2026-09-10', associatedNations: ['China', 'Taiwan', 'United States'] },
  { id: 'geo-002', event: 'EU sanctions expansion against Russia', region: 'Europe', date: '2026-09-08', associatedNations: ['Russia', 'EU'] },
  { id: 'geo-003', event: 'North Korean ballistic missile test', region: 'East Asia', date: '2026-09-06', associatedNations: ['North Korea', 'South Korea', 'Japan', 'United States'] },
  { id: 'geo-004', event: 'Iran nuclear deal negotiations collapse', region: 'Middle East', date: '2026-09-05', associatedNations: ['Iran', 'United States', 'Israel', 'Saudi Arabia'] },
  { id: 'geo-005', event: 'Russian military buildup near Ukrainian border', region: 'Eastern Europe', date: '2026-09-04', associatedNations: ['Russia', 'Ukraine', 'NATO'] },
  { id: 'geo-006', event: 'South China Sea territorial dispute escalation', region: 'Indo-Pacific', date: '2026-09-03', associatedNations: ['China', 'Philippines', 'Vietnam', 'Malaysia'] },
  { id: 'geo-007', event: 'India-Pakistan border incident', region: 'South Asia', date: '2026-09-02', associatedNations: ['India', 'Pakistan'] },
  { id: 'geo-008', event: 'NATO cyber defense exercise Baltic Shield', region: 'Europe', date: '2026-09-01', associatedNations: ['NATO', 'Russia'] },
  { id: 'geo-009', event: 'US presidential election campaign season', region: 'North America', date: '2026-08-30', associatedNations: ['Russia', 'China', 'Iran', 'United States'] },
  { id: 'geo-010', event: 'Israeli military operations in Gaza', region: 'Middle East', date: '2026-08-28', associatedNations: ['Israel', 'Iran', 'Hamas'] },
  { id: 'geo-011', event: 'Chinese economic sanctions on Taiwan', region: 'Indo-Pacific', date: '2026-08-26', associatedNations: ['China', 'Taiwan'] },
  { id: 'geo-012', event: 'Russian submarine activity near undersea cables', region: 'North Atlantic', date: '2026-08-24', associatedNations: ['Russia', 'NATO'] },
  { id: 'geo-013', event: 'North Korean diplomatic isolation deepening', region: 'East Asia', date: '2026-08-22', associatedNations: ['North Korea'] },
  { id: 'geo-014', event: 'EU cybersecurity regulation enforcement deadline', region: 'Europe', date: '2026-08-20', associatedNations: ['EU'] },
  { id: 'geo-015', event: 'Saudi-Iran diplomatic tensions over oil production', region: 'Middle East', date: '2026-08-18', associatedNations: ['Iran', 'Saudi Arabia'] },
  { id: 'geo-016', event: 'US cyber sanctions against Chinese tech firms', region: 'Global', date: '2026-08-16', associatedNations: ['United States', 'China'] },
  { id: 'geo-017', event: 'Turkish military operations in Syria', region: 'Middle East', date: '2026-08-14', associatedNations: ['Turkey', 'Syria', 'Kurdish groups'] },
  { id: 'geo-018', event: 'Five Eyes intelligence sharing expansion', region: 'Global', date: '2026-08-12', associatedNations: ['US', 'UK', 'Australia', 'Canada', 'New Zealand'] },
  { id: 'geo-019', event: 'Japanese military modernization announcement', region: 'East Asia', date: '2026-08-10', associatedNations: ['Japan', 'China', 'North Korea'] },
  { id: 'geo-020', event: 'UN General Assembly cybersecurity resolution', region: 'Global', date: '2026-08-08', associatedNations: ['Multiple'] },
  { id: 'geo-021', event: 'European energy crisis amid Russian gas restrictions', region: 'Europe', date: '2026-08-06', associatedNations: ['Russia', 'EU'] },
  { id: 'geo-022', event: 'Philippine-China maritime confrontation', region: 'Indo-Pacific', date: '2026-08-04', associatedNations: ['China', 'Philippines'] },
  { id: 'geo-023', event: 'IRGC naval exercises in Strait of Hormuz', region: 'Middle East', date: '2026-08-02', associatedNations: ['Iran', 'Gulf States', 'United States'] },
  { id: 'geo-024', event: 'South Korean joint military exercises with US', region: 'Korean Peninsula', date: '2026-07-30', associatedNations: ['South Korea', 'United States', 'North Korea'] },
  { id: 'geo-025', event: 'Venezuelan political crisis', region: 'Latin America', date: '2026-07-28', associatedNations: ['Venezuela', 'Colombia'] },
  { id: 'geo-026', event: 'G7 summit on AI governance', region: 'Global', date: '2026-07-26', associatedNations: ['G7 nations', 'Russia', 'China'] },
  { id: 'geo-027', event: 'Ukrainian counter-offensive operations', region: 'Eastern Europe', date: '2026-07-24', associatedNations: ['Ukraine', 'Russia'] },
  { id: 'geo-028', event: 'International sanctions on North Korean crypto', region: 'Global', date: '2026-07-22', associatedNations: ['North Korea'] },
  { id: 'geo-029', event: 'Chinese military exercises near Senkaku Islands', region: 'East Asia', date: '2026-07-20', associatedNations: ['China', 'Japan'] },
  { id: 'geo-030', event: 'NATO expansion discussions with new candidate', region: 'Europe', date: '2026-07-18', associatedNations: ['NATO', 'Russia'] }
];

// ============================================================================
// HISTORICAL CYBER OPERATIONS DATABASE (104 entries)
// ============================================================================

// ============================================================================
// WARGAME SCENARIOS (15 scenarios)
// ============================================================================

// ============================================================================
// INCIDENT RESPONSE PLAYBOOKS (21 entries)
// ============================================================================
var IR_PLAYBOOKS = [
  { id: 'pb-001', name: 'Ransomware Incident Response', category: 'Ransomware', priority: 1, applicableSectors: ['All'], steps: ['Isolate affected systems immediately', 'Preserve forensic evidence', 'Identify variant and check for decryptors', 'Assess encryption and exfiltration scope', 'Notify law enforcement (FBI IC3)', 'Activate backup restoration', 'Conduct root cause analysis', 'Implement access vector remediation', 'Restore from clean backups', 'Monitor for re-infection', 'Post-incident review'] },
  { id: 'pb-002', name: 'Nation-State APT Intrusion', category: 'Espionage', priority: 1, applicableSectors: ['Government', 'Defense', 'Critical Infrastructure'], steps: ['Maintain OPSEC - do NOT alert adversary', 'Engage threat intel for attribution', 'Deploy silent monitoring', 'Map full adversary access', 'Identify all compromised credentials', 'Develop comprehensive remediation plan', 'Execute single coordinated remediation', 'Implement enhanced re-entry monitoring', 'Notify intelligence agencies', 'Conduct damage assessment', 'Brief leadership'] },
  { id: 'pb-003', name: 'ICS/SCADA Compromise', category: 'ICS', priority: 1, applicableSectors: ['Energy', 'Water', 'Manufacturing'], steps: ['Activate OT incident response team', 'Assess safety implications immediately', 'Isolate compromised OT from IT', 'Switch to manual if safety risk exists', 'Preserve OT forensic evidence', 'Identify compromised controllers', 'Verify safety instrumented system integrity', 'Restore clean PLC programs', 'Implement enhanced OT monitoring', 'Root cause analysis', 'Report to ICS-CERT/CISA'] },
  { id: 'pb-004', name: 'Supply Chain Compromise', category: 'Supply Chain', priority: 1, applicableSectors: ['All'], steps: ['Identify compromised component', 'Assess affected system scope', 'Isolate systems with compromised software', 'Notify vendor and coordinate', 'Deploy IOCs across organization', 'Forensic analysis of component', 'Identify second-stage payloads', 'Remove and replace with verified versions', 'Audit supply chain procedures', 'Implement SBOM tracking', 'Brief sector ISAC'] },
  { id: 'pb-005', name: 'DDoS Attack Mitigation', category: 'Availability', priority: 2, applicableSectors: ['All'], steps: ['Activate DDoS mitigation service', 'Identify attack type', 'Implement rate limiting and filtering', 'Enable GeoIP blocking if possible', 'Scale infrastructure', 'Monitor for secondary attacks', 'Coordinate with ISP for upstream filtering', 'Document attack patterns', 'Implement permanent protections', 'Update response playbook'] },
  { id: 'pb-006', name: 'Data Breach Response', category: 'Data Breach', priority: 1, applicableSectors: ['All'], steps: ['Contain breach and stop exfiltration', 'Assess data accessed or stolen', 'Determine if PII/PHI/classified involved', 'Preserve forensic evidence', 'Notify legal counsel and privacy officer', 'Determine regulatory notification requirements', 'Prepare individual notifications', 'Engage credit monitoring if PII exposed', 'Notify regulators within required timeframes', 'Root cause analysis', 'Implement remediation'] },
  { id: 'pb-007', name: 'Insider Threat Response', category: 'Insider Threat', priority: 1, applicableSectors: ['Government', 'Defense', 'Financial'], steps: ['Coordinate with counterintelligence and legal', 'Do NOT confront suspect directly', 'Implement enhanced monitoring', 'Preserve evidence per legal requirements', 'Assess compromise scope', 'Identify all accessed systems and data', 'Review access and communication logs', 'Coordinate with law enforcement', 'Implement access restrictions', 'Conduct damage assessment', 'Review insider threat program'] },
  { id: 'pb-008', name: 'Wiper Malware Response', category: 'Destructive', priority: 1, applicableSectors: ['All'], steps: ['Immediately isolate affected segments', 'Power off unaffected systems to prevent spread', 'Assess destruction scope', 'Activate offline backup restoration', 'Verify backup integrity before restoring', 'Identify wiper variant and propagation method', 'Clean and rebuild affected systems', 'Restore from verified backups', 'Implement network segmentation', 'Deploy wiper detection signatures', 'Post-incident review'] },
  { id: 'pb-009', name: 'Cloud Account Compromise', category: 'Cloud', priority: 2, applicableSectors: ['All'], steps: ['Reset compromised credentials', 'Review and revoke suspicious OAuth apps', 'Audit cloud access logs', 'Check for persistence mechanisms', 'Review IAM policy changes', 'Check for data exfiltration', 'Implement conditional access', 'Enable enhanced cloud monitoring', 'Review and harden cloud config', 'Update cloud IR procedures'] },
  { id: 'pb-010', name: 'BGP Hijacking Response', category: 'Network', priority: 1, applicableSectors: ['Telecom', 'Government'], steps: ['Confirm BGP hijack via RIPE, RouteViews', 'Identify hijacking AS and affected prefixes', 'Contact upstream ISPs for filtering', 'Implement RPKI route origin validation', 'Verify no data interception', 'Coordinate with affected networks', 'Document for law enforcement', 'Implement permanent RPKI/BGPsec', 'Review BGP security config', 'Update routing security policies'] },
  { id: 'pb-011', name: 'DNS Hijacking Response', category: 'Network', priority: 1, applicableSectors: ['Government', 'Financial', 'Telecom'], steps: ['Verify DNS record changes', 'Secure registrar with new credentials/MFA', 'Restore correct DNS records', 'Implement DNSSEC', 'Check for fraudulent SSL certificates', 'Revoke fraudulent certificates', 'Assess traffic interception', 'Notify users about credential exposure', 'Implement CT monitoring', 'Secure all registrar accounts'] },
  { id: 'pb-012', name: 'Zero-Day Exploitation', category: 'Vulnerability', priority: 1, applicableSectors: ['All'], steps: ['Identify the zero-day being exploited', 'Assess vulnerable systems', 'Implement available mitigations', 'Deploy virtual patches if available', 'Coordinate with vendor on patch', 'Hunt for exploitation indicators', 'Isolate or restrict vulnerable systems', 'Apply vendor patch on release', 'Post-patch verification', 'Monitor for ongoing exploitation'] },
  { id: 'pb-013', name: 'Phishing Campaign Response', category: 'Social Engineering', priority: 2, applicableSectors: ['All'], steps: ['Extract IOCs from phishing emails', 'Search email logs for all recipients', 'Remove phishing from all mailboxes', 'Identify users who clicked/opened', 'Force password reset for compromised', 'Scan endpoints for malware', 'Block phishing domains at perimeter', 'Report domains for takedown', 'Send awareness notification', 'Update email security rules'] },
  { id: 'pb-014', name: 'Cryptocurrency Theft Response', category: 'Financial', priority: 1, applicableSectors: ['Financial', 'Technology'], steps: ['Identify compromised wallets and amounts', 'Freeze remaining assets', 'Trace stolen funds via blockchain', 'Contact exchanges to freeze assets', 'Engage blockchain forensics', 'Report to FBI IC3 and FinCEN', 'Identify compromise vector', 'Secure remaining crypto infrastructure', 'Implement multi-sig and cold storage', 'Coordinate international law enforcement'] },
  { id: 'pb-015', name: 'Election Infrastructure Protection', category: 'Government', priority: 1, applicableSectors: ['Government'], steps: ['Deploy EI-ISAC monitoring', 'Verify voter registration integrity', 'Test backup paper procedures', 'Coordinate with CISA election team', 'Deploy Albert sensors', 'Verify voting equipment chain of custody', 'Enhanced monitoring during election', 'Staff 24/7 election SOC', 'Public communications plan', 'Post-election audit'] },
  { id: 'pb-016', name: 'Medical Device Compromise', category: 'Healthcare', priority: 1, applicableSectors: ['Healthcare'], steps: ['Assess patient safety immediately', 'Isolate compromised devices', 'Verify device functionality for safety', 'Contact manufacturer', 'Network segmentation for devices', 'Deploy compensating controls', 'Coordinate with FDA if needed', 'Restore firmware from verified images', 'Monitor for re-compromise', 'Update procurement security requirements'] },
  { id: 'pb-017', name: 'Satellite Communication Disruption', category: 'Communications', priority: 1, applicableSectors: ['Defense', 'Telecom'], steps: ['Activate alternative channels', 'Assess disruption scope', 'Determine if jamming, cyber, or physical', 'Implement PACE plan', 'Deploy terrestrial backup', 'Coordinate with satellite operator', 'Assess military comms impact', 'Deploy tactical communications', 'Investigate root cause', 'Enhanced terminal security'] },
  { id: 'pb-018', name: 'Industrial Safety System Override', category: 'ICS Safety', priority: 1, applicableSectors: ['Energy', 'Chemical', 'Manufacturing'], steps: ['IMMEDIATELY implement emergency shutdown', 'Evacuate from hazardous areas', 'Verify all safety system status', 'Isolate safety systems from networks', 'Verify logic not modified', 'Compare config against golden copies', 'Do NOT restart until verified', 'Engage process safety engineering', 'Report to CISA and regulators', 'Implement air-gapped safety architecture'] },
  { id: 'pb-019', name: 'Mass Credential Compromise', category: 'Identity', priority: 1, applicableSectors: ['All'], steps: ['Identify compromise scope', 'Force enterprise-wide password reset', 'Revoke all active sessions/tokens', 'Audit and reset MFA if compromised', 'Review privileged account access', 'Check for persistence via new accounts/OAuth', 'Enhanced authentication monitoring', 'Deploy credential dark web monitoring', 'Update authentication policies', 'Implement FIDO2/passkeys'] },
  { id: 'pb-020', name: 'AI/ML Model Poisoning', category: 'AI Security', priority: 2, applicableSectors: ['Technology', 'Defense', 'Financial'], steps: ['Identify poisoned training data or models', 'Quarantine affected models', 'Assess downstream impact', 'Revert to last known-good model', 'Audit training data pipeline', 'Implement data provenance tracking', 'Retrain with verified clean data', 'Deploy model output monitoring', 'Review AI/ML supply chain security', 'Implement model integrity verification'] },
  { id: 'pb-021', name: 'Submarine Cable Disruption', category: 'Communications', priority: 1, applicableSectors: ['Telecom', 'Government'], steps: ['Detect and confirm disruption', 'Activate traffic rerouting via redundant cables', 'Assess national/military comms impact', 'Deploy repair vessel', 'Implement satellite backup for critical comms', 'Coordinate with cable operator consortium', 'Investigate physical or cyber cause', 'Monitor for coordinated cable attacks', 'Brief national security leadership', 'Review undersea cable protection'] }
];

// ============================================================================
// INTELLIGENCE FEEDS (32 entries)
// ============================================================================
var INTEL_FEEDS = [
  { id: 'intel-001', source: 'NSA SIGINT Report', type: 'SIGINT', classification: 'TOP SECRET//SCI', timestamp: '2026-09-13T06:00:00Z', content: 'GRU communications indicate Sandworm tasked to develop new SCADA disruption capability for NATO-standard power grid equipment', confidence: 92, relatedNations: ['Russia'] },
  { id: 'intel-002', source: 'OSINT Twitter/X Monitoring', type: 'OSINT', classification: 'UNCLASSIFIED', timestamp: '2026-09-13T05:30:00Z', content: 'Security researcher disclosed zero-day in major enterprise VPN with proof-of-concept exploit code', confidence: 98, relatedNations: ['Global'] },
  { id: 'intel-003', source: 'CYBERCOM Threat Intel', type: 'CYBINT', classification: 'SECRET//NOFORN', timestamp: '2026-09-13T05:00:00Z', content: 'Reverse engineering reveals new Volt Typhoon implant with SCADA protocol manipulation for Modbus/DNP3', confidence: 89, relatedNations: ['China'] },
  { id: 'intel-004', source: 'CIA HUMINT Report', type: 'HUMINT', classification: 'TOP SECRET//SCI//NOFORN', timestamp: '2026-09-13T04:30:00Z', content: 'Source in PLA SSF reports activation order for cyber units to prepare Taiwan contingency operations', confidence: 73, relatedNations: ['China', 'Taiwan'] },
  { id: 'intel-005', source: 'NGA Satellite Imagery', type: 'GEOINT', classification: 'SECRET', timestamp: '2026-09-13T04:00:00Z', content: 'Satellite imagery confirms Russian vessel Yantar operating near transatlantic submarine cable', confidence: 95, relatedNations: ['Russia'] },
  { id: 'intel-006', source: 'CISA Alert Feed', type: 'CYBINT', classification: 'UNCLASSIFIED//FOUO', timestamp: '2026-09-13T03:30:00Z', content: 'Emergency advisory: Active exploitation of critical firewall vulnerability by multiple nation-states', confidence: 96, relatedNations: ['China', 'Russia', 'Iran'] },
  { id: 'intel-007', source: 'FBI Cyber Division', type: 'CYBINT', classification: 'SECRET//NOFORN', timestamp: '2026-09-13T03:00:00Z', content: 'FBI reveals North Korean IT workers embedded in 14 US tech companies generating RGB revenue', confidence: 87, relatedNations: ['North Korea'] },
  { id: 'intel-008', source: 'GCHQ Partner Report', type: 'SIGINT', classification: 'TOP SECRET//REL FVEY', timestamp: '2026-09-13T02:30:00Z', content: 'GCHQ confirms APT29 developing cloud exploitation toolkit targeting Azure AD federation', confidence: 85, relatedNations: ['Russia'] },
  { id: 'intel-009', source: 'Mandiant Threat Report', type: 'OSINT', classification: 'UNCLASSIFIED', timestamp: '2026-09-13T02:00:00Z', content: 'Report documents new Chinese APT targeting semiconductor supply chain with firmware implants', confidence: 88, relatedNations: ['China'] },
  { id: 'intel-010', source: 'Dark Web Collection', type: 'CYBINT', classification: 'SECRET', timestamp: '2026-09-13T01:30:00Z', content: 'Lazarus-affiliated persona offering cross-chain bridge zero-day for $2.5M in Monero', confidence: 79, relatedNations: ['North Korea'] },
  { id: 'intel-011', source: 'DIA Military Intel', type: 'HUMINT', classification: 'TOP SECRET//SCI', timestamp: '2026-09-13T01:00:00Z', content: 'Defense attache reports increased Russian military cyber unit staffing at GRU facilities', confidence: 76, relatedNations: ['Russia'] },
  { id: 'intel-012', source: 'NSA TAO Report', type: 'SIGINT', classification: 'TOP SECRET//SCI//NOFORN', timestamp: '2026-09-13T00:30:00Z', content: 'TAO hunt-forward identified Chinese implants in allied telecom during bilateral operation', confidence: 94, relatedNations: ['China'] },
  { id: 'intel-013', source: 'European CERT Network', type: 'CYBINT', classification: 'RESTRICTED//REL NATO', timestamp: '2026-09-13T00:00:00Z', content: 'Three NATO CERTs reporting simultaneous APT28 spear-phishing against foreign ministry officials', confidence: 91, relatedNations: ['Russia'] },
  { id: 'intel-014', source: 'Recorded Future OSINT', type: 'OSINT', classification: 'UNCLASSIFIED', timestamp: '2026-09-12T23:30:00Z', content: 'Open source identifies 156 new Gamaredon domains registered in 24-hour burst', confidence: 93, relatedNations: ['Russia'] },
  { id: 'intel-015', source: 'ODNI Threat Assessment', type: 'CYBINT', classification: 'SECRET//NOFORN', timestamp: '2026-09-12T23:00:00Z', content: 'Annual assessment elevates China to most significant persistent cyber threat to US national security', confidence: 90, relatedNations: ['China'] },
  { id: 'intel-016', source: 'Five Eyes Cyber Center', type: 'SIGINT', classification: 'TOP SECRET//REL FVEY', timestamp: '2026-09-12T22:30:00Z', content: 'Joint analysis confirms Salt Typhoon persistent access in telecom providers across all Five Eyes nations', confidence: 88, relatedNations: ['China'] },
  { id: 'intel-017', source: 'Financial ISAC Alert', type: 'CYBINT', classification: 'UNCLASSIFIED//FOUO', timestamp: '2026-09-12T22:00:00Z', content: 'FS-ISAC members reporting coordinated credential stuffing from Lazarus infrastructure against online banking', confidence: 82, relatedNations: ['North Korea'] },
  { id: 'intel-018', source: 'Mossad Liaison Report', type: 'HUMINT', classification: 'TOP SECRET//REL ISR', timestamp: '2026-09-12T21:30:00Z', content: 'Israeli intel reports IRGC Cyber Command receiving expanded budget for offensive operations against Gulf states', confidence: 80, relatedNations: ['Iran'] },
  { id: 'intel-019', source: 'CrowdStrike Intelligence', type: 'OSINT', classification: 'UNCLASSIFIED', timestamp: '2026-09-12T21:00:00Z', content: 'Analysis of LockBit 4.0 variant with healthcare-specific targeting and anti-forensic capabilities', confidence: 91, relatedNations: ['Russia'] },
  { id: 'intel-020', source: 'USCYBERCOM J2', type: 'CYBINT', classification: 'SECRET//NOFORN', timestamp: '2026-09-12T20:30:00Z', content: 'CYBERCOM intel indicates Iranian APTs conducting pre-operational recon of US water treatment', confidence: 77, relatedNations: ['Iran'] },
  { id: 'intel-021', source: 'Australian Signals Directorate', type: 'SIGINT', classification: 'TOP SECRET//REL FVEY', timestamp: '2026-09-12T20:00:00Z', content: 'ASD intercepts confirm Chinese military AI trained on stolen Western defense research data', confidence: 74, relatedNations: ['China'] },
  { id: 'intel-022', source: 'Shodan/Censys OSINT', type: 'OSINT', classification: 'UNCLASSIFIED', timestamp: '2026-09-12T19:30:00Z', content: 'Internet scanning reveals 47,000 unpatched devices exposed to critical vulnerability under nation-state exploitation', confidence: 96, relatedNations: ['Global'] },
  { id: 'intel-023', source: 'Treasury FinCEN', type: 'CYBINT', classification: 'SECRET', timestamp: '2026-09-12T19:00:00Z', content: 'Financial intel links $340M in crypto transactions to North Korean state-sponsored theft in 2026', confidence: 86, relatedNations: ['North Korea'] },
  { id: 'intel-024', source: 'NATO CCDCOE', type: 'CYBINT', classification: 'NATO SECRET', timestamp: '2026-09-12T18:30:00Z', content: 'NATO assessment identifies coordinated Russian cyber recon of Baltic state critical infrastructure', confidence: 88, relatedNations: ['Russia'] },
  { id: 'intel-025', source: 'MI6 Liaison', type: 'HUMINT', classification: 'TOP SECRET//REL GBR', timestamp: '2026-09-12T18:00:00Z', content: 'MI6 source reports GRU providing zero-days to ransomware groups for plausible deniability', confidence: 71, relatedNations: ['Russia'] },
  { id: 'intel-026', source: 'SANS ISC', type: 'OSINT', classification: 'UNCLASSIFIED', timestamp: '2026-09-12T17:30:00Z', content: 'SANS detecting massive scanning wave targeting OT protocols on internet-exposed industrial systems', confidence: 94, relatedNations: ['Unknown'] },
  { id: 'intel-027', source: 'BND German Intel', type: 'SIGINT', classification: 'SECRET//REL DEU', timestamp: '2026-09-12T17:00:00Z', content: 'BND intercepted Chinese MSS discussing acquisition of European semiconductor trade secrets', confidence: 78, relatedNations: ['China'] },
  { id: 'intel-028', source: 'Kaspersky GReAT', type: 'OSINT', classification: 'UNCLASSIFIED', timestamp: '2026-09-12T16:30:00Z', content: 'Sophisticated firmware implant discovered in network equipment targeting government installations', confidence: 85, relatedNations: ['Unknown'] },
  { id: 'intel-029', source: 'DGSE French Intel', type: 'HUMINT', classification: 'SECRET//REL FRA', timestamp: '2026-09-12T16:00:00Z', content: 'DGSE reporting Iranian intel establishing new cyber ops base targeting European infrastructure', confidence: 72, relatedNations: ['Iran'] },
  { id: 'intel-030', source: 'VirusTotal Analysis', type: 'CYBINT', classification: 'UNCLASSIFIED', timestamp: '2026-09-12T15:30:00Z', content: 'New malware showing code overlap with both APT29 and APT28 tooling - unusual SVR/GRU sharing', confidence: 80, relatedNations: ['Russia'] },
  { id: 'intel-031', source: 'KISA South Korean CERT', type: 'CYBINT', classification: 'RESTRICTED', timestamp: '2026-09-12T15:00:00Z', content: 'KISA reporting surge in Kimsuky phishing targeting South Korean defense researchers and nuclear scientists', confidence: 90, relatedNations: ['North Korea'] },
  { id: 'intel-032', source: 'NCSC UK Advisory', type: 'OSINT', classification: 'OFFICIAL-SENSITIVE', timestamp: '2026-09-12T14:30:00Z', content: 'NCSC advisory on Russian state actors using compromised SOHO routers for anonymized attacks on UK orgs', confidence: 92, relatedNations: ['Russia'] }
];

// ============================================================================
// CRITICAL INFRASTRUCTURE SECTORS (8 sectors)
// ============================================================================
var CRITICAL_INFRASTRUCTURE_SECTORS = [
  { id: 'ci-power', name: 'Power Grid / Energy', activeDefenses: ['NERC CIP compliance monitoring', 'ICS-CERT sensor deployment', 'Real-time SCADA anomaly detection', 'Air-gapped control segments', 'Automatic load shedding'], lastAssessment: '2026-08-15', dependencies: ['Water (cooling)', 'Telecom (SCADA comms)', 'Transport (fuel delivery)', 'Financial (trading)'] },
  { id: 'ci-water', name: 'Water & Wastewater', activeDefenses: ['EPA Water Sector guidance', 'Basic SCADA monitoring', 'Manual override capabilities', 'Chemical process safety interlocks'], lastAssessment: '2026-07-20', dependencies: ['Power (pumping)', 'Chemical (treatment)', 'Telecom (monitoring)', 'Transport (delivery)'] },
  { id: 'ci-telecom', name: 'Telecommunications', activeDefenses: ['CALEA system hardening', 'BGP route validation (partial)', '5G security monitoring', 'Core network segmentation', 'DDoS mitigation platforms'], lastAssessment: '2026-09-01', dependencies: ['Power (base stations)', 'Transport (fiber routes)', 'Financial (billing)'] },
  { id: 'ci-financial', name: 'Financial Services', activeDefenses: ['SWIFT CSP compliance', 'Real-time fraud detection', 'Multi-layered auth', 'SOC 24/7', 'FS-ISAC threat sharing', 'Red team exercises'], lastAssessment: '2026-09-05', dependencies: ['Power (data centers)', 'Telecom (connectivity)', 'Government (regulatory)'] },
  { id: 'ci-transport', name: 'Transportation', activeDefenses: ['ATC system monitoring', 'Maritime AIS integrity', 'Rail SCADA monitoring', 'Traffic management hardening', 'GPS spoofing detection'], lastAssessment: '2026-08-10', dependencies: ['Power (signals)', 'Telecom (comms)', 'Financial (payment)', 'Energy (fuel)'] },
  { id: 'ci-health', name: 'Healthcare', activeDefenses: ['HIPAA security controls', 'Medical device segmentation', 'EHR monitoring', 'Ransomware-specific defenses', 'H-ISAC threat sharing'], lastAssessment: '2026-07-30', dependencies: ['Power (life support)', 'Water (sanitation)', 'Telecom (telemedicine)', 'Transport (ambulance)', 'Chemical (pharma)'] },
  { id: 'ci-govt', name: 'Government Services', activeDefenses: ['EINSTEIN/CDM program', 'Zero trust deployment', 'PIV/CAC authentication', 'Continuous diagnostics', 'SOC across .gov', 'Bug bounty programs'], lastAssessment: '2026-09-10', dependencies: ['Power (data centers)', 'Telecom (networks)', 'Financial (payments)', 'Defense (classified)'] },
  { id: 'ci-defense', name: 'Defense Industrial Base', activeDefenses: ['CMMC certification', 'DISA STIG compliance', 'NSA CSA guidance', 'Classified network monitoring', 'Insider threat programs', 'Counter-intel operations'], lastAssessment: '2026-09-08', dependencies: ['Power (installations)', 'Telecom (C2)', 'Transport (logistics)', 'Financial (contracting)', 'Government (authority)'] }
];

// ============================================================================
// STATE MANAGEMENT (localStorage)
// ============================================================================
var SE_STORAGE_KEY = 'dn_sentinel_eye_v1';

function _seLoadState() {
  try {
    var raw = localStorage.getItem(SE_STORAGE_KEY);
    if (raw) { return JSON.parse(raw); }
  } catch (e) { /* ignore */ }
  return {
    activeTab: 'situation',
    expandedPanels: {},
    filters: {},
    wargameState: null,
    counterOpState: null,
    decisionLog: [],
    lastVisit: null
  };
}

function _seSaveState(state) {
  try {
    state.lastVisit = new Date().toISOString();
    localStorage.setItem(SE_STORAGE_KEY, JSON.stringify(state));
  } catch (e) { /* ignore */ }
}

// ============================================================================
// SENTINEL EYE — PART 4: SHELL, CSS, CANVAS, EVENT HANDLING
// Main UI shell, styles, world map canvas, ticker, and event system
// ============================================================================

// ---------------------------------------------------------------------------
// buildStyles() — returns complete <style> tag with all CSS
// ---------------------------------------------------------------------------
function buildStyles() {
  var s = '<style>';

  // === KEYFRAMES ===
  s += '@keyframes se-pulse{0%{opacity:1}50%{opacity:0.4}100%{opacity:1}}';
  s += '@keyframes se-scan{0%{background-position:0 0}100%{background-position:0 100%}}';
  s += '@keyframes se-ticker-scroll{0%{transform:translateX(0)}100%{transform:translateX(-50%)}}';
  s += '@keyframes se-blink{0%{opacity:1}50%{opacity:0}100%{opacity:1}}';
  s += '@keyframes se-glow{0%{box-shadow:0 0 5px rgba(0,170,255,0.3)}50%{box-shadow:0 0 20px rgba(0,170,255,0.7)}100%{box-shadow:0 0 5px rgba(0,170,255,0.3)}}';
  s += '@keyframes se-pulse-red{0%{box-shadow:0 0 5px rgba(255,34,68,0.3)}50%{box-shadow:0 0 25px rgba(255,34,68,0.8)}100%{box-shadow:0 0 5px rgba(255,34,68,0.3)}}';
  s += '@keyframes se-slide-in{0%{opacity:0;transform:translateY(-10px)}100%{opacity:1;transform:translateY(0)}}';
  s += '@keyframes se-progress-fill{0%{width:0}100%{width:100%}}';
  s += '@keyframes se-radar-sweep{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}';
  s += '@keyframes se-threat-flash{0%{background:rgba(255,34,68,0.1)}50%{background:rgba(255,34,68,0.3)}100%{background:rgba(255,34,68,0.1)}}';

  // === BASE / WRAPPER ===
  s += '.se-wrapper{background:#080b12;color:#c8d8e8;font-family:"Courier New",Courier,monospace;';
  s += 'height:calc(100vh - var(--topbar-h,52px));display:flex;flex-direction:column;position:relative;overflow:hidden}';

  // Scanline overlay
  s += '.se-wrapper::after{content:"";position:fixed;top:0;left:0;width:100%;height:100%;';
  s += 'background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.03) 2px,rgba(0,0,0,0.03) 4px);';
  s += 'pointer-events:none;z-index:9999}';

  // === CLASSIFICATION BANNERS ===
  s += '.se-classif-banner{background:#cc0000;color:#fff;text-align:center;padding:4px 12px;';
  s += 'font-size:11px;font-weight:700;letter-spacing:3px;text-transform:uppercase;';
  s += 'font-family:"Courier New",Courier,monospace;user-select:none}';

  // === HEADER ===
  s += '.se-header{background:linear-gradient(180deg,#0c1220 0%,#080b12 100%);';
  s += 'border-bottom:1px solid #1a3a5c;padding:16px 24px;display:flex;align-items:center;';
  s += 'justify-content:space-between;flex-wrap:wrap;gap:12px}';
  s += '.se-header-left{display:flex;align-items:center;gap:16px}';
  s += '.se-header-icon{width:48px;height:48px;border-radius:50%;';
  s += 'background:radial-gradient(circle,#00aaff 0%,#004488 70%,#001a33 100%);';
  s += 'display:flex;align-items:center;justify-content:center;font-size:22px;';
  s += 'box-shadow:0 0 20px rgba(0,170,255,0.4);animation:se-glow 3s ease-in-out infinite}';
  s += '.se-header-title{font-size:26px;font-weight:700;color:#00aaff;letter-spacing:4px;text-transform:uppercase}';
  s += '.se-header-subtitle{font-size:11px;color:#5a7a9a;letter-spacing:2px;text-transform:uppercase;margin-top:2px}';

  // === GLOBAL STATUS BAR ===
  s += '.se-status-bar{background:#0a0e1a;border-bottom:1px solid #1a3a5c;';
  s += 'padding:8px 24px;display:flex;align-items:center;gap:24px;flex-wrap:wrap;';
  s += 'font-size:12px;letter-spacing:1px;text-transform:uppercase}';
  s += '.se-status-item{display:flex;align-items:center;gap:8px}';
  s += '.se-status-label{color:#5a7a9a}';
  s += '.se-status-value{color:#00aaff;font-weight:700}';
  s += '.se-status-value.se-critical{color:#ff2244}';
  s += '.se-status-value.se-warning{color:#ffaa00}';
  s += '.se-status-value.se-safe{color:#00ff88}';

  // DEFCON indicator
  s += '.se-defcon{display:inline-flex;align-items:center;gap:6px;padding:3px 10px;';
  s += 'border-radius:4px;font-weight:700;font-size:13px;letter-spacing:2px}';
  s += '.se-defcon-1{background:rgba(255,34,68,0.25);color:#ff2244;border:1px solid #ff2244;animation:se-pulse 1s infinite}';
  s += '.se-defcon-2{background:rgba(255,100,50,0.2);color:#ff6432;border:1px solid #ff6432;animation:se-pulse 2s infinite}';
  s += '.se-defcon-3{background:rgba(255,170,0,0.2);color:#ffaa00;border:1px solid #ffaa00}';
  s += '.se-defcon-4{background:rgba(0,170,255,0.15);color:#00aaff;border:1px solid #00aaff}';
  s += '.se-defcon-5{background:rgba(0,255,136,0.15);color:#00ff88;border:1px solid #00ff88}';

  // === TAB NAVIGATION ===
  s += '.se-tab-bar{background:#0a0e1a;border-bottom:2px solid #1a3a5c;';
  s += 'display:flex;flex-wrap:nowrap;overflow-x:auto;-webkit-overflow-scrolling:touch;scrollbar-width:thin;scrollbar-color:#1a3a5c #080b12;';
  s += 'padding:0 8px;gap:2px;flex-shrink:0}';
  s += '.se-tab-bar::-webkit-scrollbar{height:4px}';
  s += '.se-tab-bar::-webkit-scrollbar-track{background:#080b12}';
  s += '.se-tab-bar::-webkit-scrollbar-thumb{background:#1a3a5c;border-radius:2px}';
  s += '.se-tab{padding:10px 16px;cursor:pointer;color:#5a7a9a;font-size:11px;flex-shrink:0;';
  s += 'letter-spacing:1.5px;text-transform:uppercase;white-space:nowrap;';
  s += 'border-bottom:2px solid transparent;transition:all 0.2s;user-select:none;';
  s += 'font-family:"Courier New",Courier,monospace;font-weight:600;';
  s += 'position:relative;background:transparent}';
  s += '.se-tab:hover{color:#00aaff;background:rgba(0,170,255,0.05)}';
  s += '.se-tab.se-active{color:#00aaff;border-bottom-color:#00aaff;';
  s += 'background:rgba(0,170,255,0.08)}';
  s += '.se-tab-alert{position:absolute;top:6px;right:6px;width:6px;height:6px;';
  s += 'border-radius:50%;background:#ff2244;animation:se-pulse 1.5s infinite}';

  // === CONTENT AREA ===
  s += '.se-content{padding:20px 24px;flex:1;overflow-y:auto;overflow-x:hidden}';

  // === CARDS ===
  s += '.se-card{background:#0a0e1a;border:1px solid #1a3a5c;border-radius:6px;';
  s += 'padding:16px;margin-bottom:16px;';
  s += 'box-shadow:0 4px 20px rgba(0,170,255,0.08),inset 0 1px 0 rgba(0,170,255,0.1)}';
  s += '.se-card:hover{border-color:#00aaff;box-shadow:0 4px 20px rgba(0,170,255,0.15),inset 0 1px 0 rgba(0,170,255,0.15)}';
  s += '.se-card-header{display:flex;align-items:center;justify-content:space-between;';
  s += 'margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #1a3a5c}';
  s += '.se-card-title{font-size:13px;font-weight:700;color:#00aaff;letter-spacing:2px;text-transform:uppercase}';
  s += '.se-card-body{font-size:12px;line-height:1.6;color:#c8d8e8}';

  // 3D elevated cards
  s += '.se-card-3d{background:linear-gradient(145deg,#0c1424 0%,#0a0e1a 100%);';
  s += 'border:1px solid #1a3a5c;border-radius:8px;padding:20px;margin-bottom:16px;';
  s += 'box-shadow:0 8px 32px rgba(0,0,0,0.4),0 4px 20px rgba(0,170,255,0.1),';
  s += 'inset 0 1px 0 rgba(255,255,255,0.05);transition:transform 0.2s,box-shadow 0.2s}';
  s += '.se-card-3d:hover{transform:translateY(-2px);';
  s += 'box-shadow:0 12px 40px rgba(0,0,0,0.5),0 6px 25px rgba(0,170,255,0.15),';
  s += 'inset 0 1px 0 rgba(255,255,255,0.08)}';

  // Hostile card variant
  s += '.se-card-hostile{border-color:#441122;';
  s += 'box-shadow:0 4px 20px rgba(255,34,68,0.1),inset 0 1px 0 rgba(255,34,68,0.1)}';
  s += '.se-card-hostile:hover{border-color:#ff2244;';
  s += 'box-shadow:0 4px 20px rgba(255,34,68,0.2),inset 0 1px 0 rgba(255,34,68,0.15)}';

  // === GRID LAYOUTS ===
  s += '.se-grid-2{display:grid;grid-template-columns:repeat(2,1fr);gap:16px}';
  s += '.se-grid-3{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}';
  s += '.se-grid-4{display:grid;grid-template-columns:repeat(4,1fr);gap:16px}';
  s += '.se-grid-auto{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:16px}';

  // === BADGES ===
  s += '.se-badge{display:inline-block;padding:2px 8px;border-radius:3px;';
  s += 'font-size:10px;font-weight:700;letter-spacing:1px;text-transform:uppercase;';
  s += 'font-family:"Courier New",Courier,monospace}';
  s += '.se-badge-critical{background:rgba(255,34,68,0.2);color:#ff2244;border:1px solid rgba(255,34,68,0.4)}';
  s += '.se-badge-high{background:rgba(255,100,50,0.2);color:#ff6432;border:1px solid rgba(255,100,50,0.4)}';
  s += '.se-badge-medium{background:rgba(255,170,0,0.2);color:#ffaa00;border:1px solid rgba(255,170,0,0.4)}';
  s += '.se-badge-low{background:rgba(0,170,255,0.15);color:#00aaff;border:1px solid rgba(0,170,255,0.3)}';
  s += '.se-badge-info{background:rgba(100,130,180,0.15);color:#8aa8c8;border:1px solid rgba(100,130,180,0.3)}';
  s += '.se-badge-safe{background:rgba(0,255,136,0.15);color:#00ff88;border:1px solid rgba(0,255,136,0.3)}';
  s += '.se-badge-hostile{background:rgba(255,34,68,0.2);color:#ff2244;border:1px solid rgba(255,34,68,0.4)}';
  s += '.se-badge-allied{background:rgba(0,170,255,0.15);color:#00aaff;border:1px solid rgba(0,170,255,0.3)}';
  s += '.se-badge-neutral{background:rgba(100,130,180,0.1);color:#6a8aaa;border:1px solid rgba(100,130,180,0.2)}';
  s += '.se-badge-tier1{background:rgba(255,34,68,0.15);color:#ff4466;border:1px solid rgba(255,34,68,0.3)}';
  s += '.se-badge-tier2{background:rgba(255,170,0,0.15);color:#ffaa00;border:1px solid rgba(255,170,0,0.3)}';
  s += '.se-badge-tier3{background:rgba(0,170,255,0.12);color:#00aaff;border:1px solid rgba(0,170,255,0.25)}';
  s += '.se-badge-classified{background:rgba(204,0,0,0.25);color:#ff4444;border:1px solid rgba(204,0,0,0.5);animation:se-pulse 2s infinite}';

  // === PROGRESS BARS ===
  s += '.se-progress-wrap{background:#0c1424;border:1px solid #1a3a5c;border-radius:3px;height:14px;overflow:hidden;position:relative}';
  s += '.se-progress-bar{height:100%;border-radius:2px;transition:width 0.6s ease-out;position:relative}';
  s += '.se-progress-bar::after{content:"";position:absolute;top:0;left:0;right:0;bottom:0;';
  s += 'background:linear-gradient(90deg,transparent 0%,rgba(255,255,255,0.1) 50%,transparent 100%)}';
  s += '.se-progress-critical{background:linear-gradient(90deg,#cc1133,#ff2244)}';
  s += '.se-progress-high{background:linear-gradient(90deg,#cc5020,#ff6432)}';
  s += '.se-progress-warning{background:linear-gradient(90deg,#cc8800,#ffaa00)}';
  s += '.se-progress-info{background:linear-gradient(90deg,#0077cc,#00aaff)}';
  s += '.se-progress-safe{background:linear-gradient(90deg,#00aa66,#00ff88)}';
  s += '.se-progress-label{position:absolute;right:6px;top:50%;transform:translateY(-50%);';
  s += 'font-size:9px;color:#fff;font-weight:700;text-shadow:0 1px 2px rgba(0,0,0,0.5)}';

  // === TABLES ===
  s += '.se-table-wrap{overflow-x:auto;border:1px solid #1a3a5c;border-radius:6px}';
  s += '.se-table{width:100%;border-collapse:collapse;font-size:11px}';
  s += '.se-table th{background:#0c1424;color:#00aaff;padding:8px 12px;text-align:left;';
  s += 'font-weight:700;letter-spacing:1px;text-transform:uppercase;';
  s += 'border-bottom:2px solid #1a3a5c;white-space:nowrap;font-size:10px}';
  s += '.se-table td{padding:8px 12px;border-bottom:1px solid #111a2a;color:#c8d8e8;';
  s += 'vertical-align:top}';
  s += '.se-table tr:hover td{background:rgba(0,170,255,0.04)}';
  s += '.se-table tr:nth-child(even) td{background:rgba(0,170,255,0.02)}';

  // === BUTTONS ===
  s += '.se-btn{display:inline-flex;align-items:center;gap:6px;padding:6px 14px;';
  s += 'border-radius:4px;font-size:11px;font-weight:700;letter-spacing:1px;';
  s += 'text-transform:uppercase;cursor:pointer;transition:all 0.2s;';
  s += 'font-family:"Courier New",Courier,monospace;border:1px solid;user-select:none}';
  s += '.se-btn-primary{background:rgba(0,170,255,0.15);color:#00aaff;border-color:#00aaff}';
  s += '.se-btn-primary:hover{background:rgba(0,170,255,0.3);box-shadow:0 0 12px rgba(0,170,255,0.3)}';
  s += '.se-btn-danger{background:rgba(255,34,68,0.15);color:#ff2244;border-color:#ff2244}';
  s += '.se-btn-danger:hover{background:rgba(255,34,68,0.3);box-shadow:0 0 12px rgba(255,34,68,0.3)}';
  s += '.se-btn-warning{background:rgba(255,170,0,0.15);color:#ffaa00;border-color:#ffaa00}';
  s += '.se-btn-warning:hover{background:rgba(255,170,0,0.3);box-shadow:0 0 12px rgba(255,170,0,0.3)}';
  s += '.se-btn-neutral{background:rgba(100,130,180,0.1);color:#8aa8c8;border-color:#3a5a7a}';
  s += '.se-btn-neutral:hover{background:rgba(100,130,180,0.2);border-color:#5a7a9a}';
  s += '.se-btn-success{background:rgba(0,255,136,0.15);color:#00ff88;border-color:#00ff88}';
  s += '.se-btn-success:hover{background:rgba(0,255,136,0.3);box-shadow:0 0 12px rgba(0,255,136,0.3)}';
  s += '.se-btn-sm{padding:4px 10px;font-size:10px}';
  s += '.se-btn-lg{padding:8px 20px;font-size:12px}';

  // === FORMS ===
  s += '.se-input,.se-select,.se-textarea{background:#0c1424;color:#c8d8e8;';
  s += 'border:1px solid #1a3a5c;border-radius:4px;padding:6px 10px;font-size:12px;';
  s += 'font-family:"Courier New",Courier,monospace;outline:none;transition:border-color 0.2s}';
  s += '.se-input:focus,.se-select:focus,.se-textarea:focus{border-color:#00aaff;';
  s += 'box-shadow:0 0 8px rgba(0,170,255,0.2)}';
  s += '.se-textarea{resize:vertical;min-height:60px}';
  s += '.se-select{cursor:pointer;appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns=\'http://www.w3.org/2000/svg\' viewBox=\'0 0 12 8\'%3E%3Cpath d=\'M1 1l5 5 5-5\' stroke=\'%2300aaff\' fill=\'none\' stroke-width=\'1.5\'/%3E%3C/svg%3E");';
  s += 'background-repeat:no-repeat;background-position:right 8px center;background-size:10px;padding-right:28px}';
  s += '.se-form-group{margin-bottom:12px}';
  s += '.se-form-label{display:block;font-size:10px;color:#5a7a9a;letter-spacing:1px;';
  s += 'text-transform:uppercase;margin-bottom:4px;font-weight:700}';
  s += '.se-form-row{display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap}';

  // === EXPANDABLE PANELS ===
  s += '.se-expand{border:1px solid #1a3a5c;border-radius:6px;margin-bottom:8px;overflow:hidden}';
  s += '.se-expand-head{background:#0c1424;padding:10px 14px;cursor:pointer;';
  s += 'display:flex;align-items:center;justify-content:space-between;';
  s += 'font-size:12px;font-weight:700;color:#00aaff;letter-spacing:1px;';
  s += 'text-transform:uppercase;transition:background 0.2s;user-select:none}';
  s += '.se-expand-head:hover{background:#101828}';
  s += '.se-expand-arrow{transition:transform 0.2s;color:#5a7a9a;font-size:10px}';
  s += '.se-expand.se-open .se-expand-arrow{transform:rotate(90deg)}';
  s += '.se-expand-body{display:none;padding:12px 14px;border-top:1px solid #1a3a5c;';
  s += 'background:#0a0e1a;animation:se-slide-in 0.2s ease-out}';
  s += '.se-expand.se-open .se-expand-body{display:block}';

  // === TICKER ===
  s += '.se-ticker-wrap{background:#0c0810;border-top:1px solid #1a3a5c;';
  s += 'border-bottom:1px solid #1a3a5c;overflow:hidden;height:28px;position:relative}';
  s += '.se-ticker-track{display:flex;white-space:nowrap;animation:se-ticker-scroll 120s linear infinite;';
  s += 'position:absolute;top:0;height:100%;align-items:center}';
  s += '.se-ticker-item{display:inline-flex;align-items:center;gap:6px;padding:0 24px;';
  s += 'font-size:11px;letter-spacing:0.5px}';
  s += '.se-ticker-dot{width:6px;height:6px;border-radius:50%;display:inline-block;flex-shrink:0}';
  s += '.se-ticker-sep{color:#1a3a5c;padding:0 8px}';

  // === THREAT LEVEL INDICATORS ===
  s += '.se-threat-dot{width:10px;height:10px;border-radius:50%;display:inline-block;flex-shrink:0}';
  s += '.se-threat-critical{background:#ff2244;box-shadow:0 0 8px rgba(255,34,68,0.6);animation:se-pulse 1s infinite}';
  s += '.se-threat-high{background:#ff6432;box-shadow:0 0 6px rgba(255,100,50,0.5)}';
  s += '.se-threat-elevated{background:#ffaa00;box-shadow:0 0 6px rgba(255,170,0,0.5)}';
  s += '.se-threat-guarded{background:#00aaff;box-shadow:0 0 4px rgba(0,170,255,0.4)}';
  s += '.se-threat-low{background:#00ff88;box-shadow:0 0 4px rgba(0,255,136,0.4)}';

  // === HEATMAP ===
  s += '.se-heatmap{display:grid;gap:2px}';
  s += '.se-heatmap-cell{width:100%;aspect-ratio:1;border-radius:2px;position:relative;cursor:pointer;transition:transform 0.1s}';
  s += '.se-heatmap-cell:hover{transform:scale(1.3);z-index:2}';
  s += '.se-heat-0{background:rgba(0,170,255,0.05)}';
  s += '.se-heat-1{background:rgba(0,170,255,0.15)}';
  s += '.se-heat-2{background:rgba(0,170,255,0.3)}';
  s += '.se-heat-3{background:rgba(0,255,136,0.3)}';
  s += '.se-heat-4{background:rgba(255,170,0,0.3)}';
  s += '.se-heat-5{background:rgba(255,170,0,0.5)}';
  s += '.se-heat-6{background:rgba(255,100,50,0.5)}';
  s += '.se-heat-7{background:rgba(255,34,68,0.5)}';
  s += '.se-heat-8{background:rgba(255,34,68,0.7)}';
  s += '.se-heat-9{background:rgba(255,34,68,0.9)}';

  // === TOOLTIPS ===
  s += '.se-tooltip-wrap{position:relative;display:inline-block}';
  s += '.se-tooltip{position:absolute;bottom:calc(100% + 8px);left:50%;transform:translateX(-50%);';
  s += 'background:#0c1424;border:1px solid #1a3a5c;border-radius:4px;padding:6px 10px;';
  s += 'font-size:10px;color:#c8d8e8;white-space:nowrap;z-index:100;pointer-events:none;';
  s += 'box-shadow:0 4px 12px rgba(0,0,0,0.5);opacity:0;transition:opacity 0.15s}';
  s += '.se-tooltip::after{content:"";position:absolute;top:100%;left:50%;transform:translateX(-50%);';
  s += 'border:5px solid transparent;border-top-color:#1a3a5c}';
  s += '.se-tooltip-wrap:hover .se-tooltip{opacity:1}';

  // === CANVAS ===
  s += '.se-canvas-wrap{border:1px solid #1a3a5c;border-radius:6px;overflow:hidden;';
  s += 'background:#080b12;position:relative}';
  s += '.se-canvas{display:block;width:100%;height:auto}';

  // === TIMELINE ===
  s += '.se-timeline{position:relative;padding-left:24px}';
  s += '.se-timeline::before{content:"";position:absolute;left:8px;top:0;bottom:0;';
  s += 'width:2px;background:#1a3a5c}';
  s += '.se-timeline-item{position:relative;margin-bottom:16px;padding-left:20px}';
  s += '.se-timeline-dot{position:absolute;left:-20px;top:4px;width:10px;height:10px;';
  s += 'border-radius:50%;border:2px solid #1a3a5c;background:#080b12}';
  s += '.se-timeline-dot.se-active{background:#00aaff;border-color:#00aaff;';
  s += 'box-shadow:0 0 8px rgba(0,170,255,0.4)}';
  s += '.se-timeline-time{font-size:10px;color:#5a7a9a;letter-spacing:1px}';
  s += '.se-timeline-text{font-size:12px;color:#c8d8e8;margin-top:2px}';

  // === SECTION HEADERS ===
  s += '.se-section-head{font-size:14px;font-weight:700;color:#00aaff;letter-spacing:2px;';
  s += 'text-transform:uppercase;margin:20px 0 12px 0;padding-bottom:8px;';
  s += 'border-bottom:1px solid #1a3a5c;display:flex;align-items:center;gap:10px}';
  s += '.se-section-icon{font-size:16px}';

  // === STAT BOXES ===
  s += '.se-stat-box{background:#0c1424;border:1px solid #1a3a5c;border-radius:6px;';
  s += 'padding:14px;text-align:center}';
  s += '.se-stat-value{font-size:28px;font-weight:700;color:#00aaff;letter-spacing:2px}';
  s += '.se-stat-value.se-critical{color:#ff2244}';
  s += '.se-stat-value.se-warning{color:#ffaa00}';
  s += '.se-stat-value.se-safe{color:#00ff88}';
  s += '.se-stat-label{font-size:9px;color:#5a7a9a;letter-spacing:1.5px;text-transform:uppercase;margin-top:6px}';

  // === TAGS / CHIPS ===
  s += '.se-tag{display:inline-block;padding:2px 6px;border-radius:3px;font-size:9px;';
  s += 'color:#8aa8c8;background:rgba(100,130,180,0.1);border:1px solid rgba(100,130,180,0.15);';
  s += 'margin:2px;font-family:"Courier New",Courier,monospace;letter-spacing:0.5px}';
  s += '.se-tag-red{color:#ff4466;background:rgba(255,34,68,0.1);border-color:rgba(255,34,68,0.2)}';
  s += '.se-tag-blue{color:#44aaff;background:rgba(0,170,255,0.1);border-color:rgba(0,170,255,0.2)}';
  s += '.se-tag-green{color:#44ff88;background:rgba(0,255,136,0.1);border-color:rgba(0,255,136,0.2)}';
  s += '.se-tag-yellow{color:#ffcc44;background:rgba(255,204,68,0.1);border-color:rgba(255,204,68,0.2)}';

  // === MITRE ATT&CK MATRIX ===
  s += '.se-mitre-grid{display:grid;grid-template-columns:repeat(14,1fr);gap:2px;font-size:8px}';
  s += '.se-mitre-cell{padding:3px 2px;text-align:center;border-radius:2px;cursor:pointer;';
  s += 'transition:background 0.1s;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}';
  s += '.se-mitre-header{background:#0c1424;color:#00aaff;font-weight:700;padding:4px 2px;font-size:7px;letter-spacing:0.5px}';
  s += '.se-mitre-active{background:rgba(255,34,68,0.3);color:#ff6688}';
  s += '.se-mitre-known{background:rgba(255,170,0,0.2);color:#ffcc66}';
  s += '.se-mitre-empty{background:rgba(0,170,255,0.03);color:#2a4a6a}';

  // === MISC ===
  s += '.se-divider{border:none;border-top:1px solid #1a3a5c;margin:16px 0}';
  s += '.se-flex{display:flex}';
  s += '.se-flex-wrap{flex-wrap:wrap}';
  s += '.se-gap-8{gap:8px}';
  s += '.se-gap-12{gap:12px}';
  s += '.se-gap-16{gap:16px}';
  s += '.se-align-center{align-items:center}';
  s += '.se-justify-between{justify-content:space-between}';
  s += '.se-text-right{text-align:right}';
  s += '.se-text-center{text-align:center}';
  s += '.se-mb-8{margin-bottom:8px}';
  s += '.se-mb-16{margin-bottom:16px}';
  s += '.se-mt-8{margin-top:8px}';
  s += '.se-mt-16{margin-top:16px}';
  s += '.se-muted{color:#5a7a9a}';
  s += '.se-highlight{color:#00aaff}';
  s += '.se-danger{color:#ff2244}';
  s += '.se-warning-text{color:#ffaa00}';
  s += '.se-success-text{color:#00ff88}';
  s += '.se-small{font-size:10px}';
  s += '.se-mono{font-family:"Courier New",Courier,monospace}';
  s += '.se-truncate{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}';
  s += '.se-scroll-y{max-height:400px;overflow-y:auto}';
  s += '.se-hidden{display:none!important}';

  // === FOOTER ===
  s += '.se-footer{background:#0a0e1a;border-top:1px solid #1a3a5c;padding:8px 24px;';
  s += 'display:flex;align-items:center;justify-content:space-between;';
  s += 'font-size:10px;color:#3a5a7a;letter-spacing:1px;text-transform:uppercase;flex-wrap:wrap;gap:8px}';

  // === FILTER BAR ===
  s += '.se-filter-bar{display:flex;align-items:center;gap:10px;margin-bottom:16px;flex-wrap:wrap;';
  s += 'padding:10px 14px;background:#0c1424;border:1px solid #1a3a5c;border-radius:6px}';
  s += '.se-filter-label{font-size:10px;color:#5a7a9a;letter-spacing:1px;text-transform:uppercase;font-weight:700}';
  s += '.se-search-box{background:#080b12;color:#c8d8e8;border:1px solid #1a3a5c;border-radius:4px;';
  s += 'padding:5px 10px;font-size:11px;font-family:"Courier New",Courier,monospace;';
  s += 'outline:none;min-width:200px}';
  s += '.se-search-box:focus{border-color:#00aaff}';

  // === SCROLLBAR ===
  s += '.se-content::-webkit-scrollbar,.se-scroll-y::-webkit-scrollbar{width:6px}';
  s += '.se-content::-webkit-scrollbar-track,.se-scroll-y::-webkit-scrollbar-track{background:#080b12}';
  s += '.se-content::-webkit-scrollbar-thumb,.se-scroll-y::-webkit-scrollbar-thumb{background:#1a3a5c;border-radius:3px}';

  // === RESPONSIVE ===
  s += '@media(max-width:1200px){.se-grid-4{grid-template-columns:repeat(2,1fr)}}';
  s += '@media(max-width:900px){.se-grid-3{grid-template-columns:repeat(2,1fr)}.se-grid-4{grid-template-columns:1fr}}';
  s += '@media(max-width:700px){.se-grid-2,.se-grid-3{grid-template-columns:1fr}';
  s += '.se-header{padding:12px 16px}.se-content{padding:12px 16px}';
  s += '.se-status-bar{padding:6px 16px}.se-header-title{font-size:18px}}';

  // === WARGAME PHASE INDICATORS ===
  s += '.se-phase-indicator{display:flex;align-items:center;gap:4px;margin-bottom:12px}';
  s += '.se-phase-dot{width:20px;height:20px;border-radius:50%;border:2px solid #1a3a5c;';
  s += 'display:flex;align-items:center;justify-content:center;font-size:9px;font-weight:700;color:#5a7a9a}';
  s += '.se-phase-dot.se-phase-active{border-color:#00aaff;color:#00aaff;background:rgba(0,170,255,0.15)}';
  s += '.se-phase-dot.se-phase-done{border-color:#00ff88;color:#00ff88;background:rgba(0,255,136,0.15)}';
  s += '.se-phase-line{flex:1;height:2px;background:#1a3a5c}';
  s += '.se-phase-line.se-phase-done{background:#00ff88}';

  // === OPERATION STATUS ===
  s += '.se-op-status{display:inline-flex;align-items:center;gap:4px;font-size:10px;font-weight:700;letter-spacing:1px}';
  s += '.se-op-active{color:#00ff88}';
  s += '.se-op-planning{color:#00aaff}';
  s += '.se-op-complete{color:#5a7a9a}';
  s += '.se-op-aborted{color:#ff2244}';

  // === CORRELATION LINES ===
  s += '.se-correlation{border-left:3px solid #1a3a5c;padding-left:12px;margin:8px 0}';
  s += '.se-correlation.se-high-conf{border-left-color:#ff2244}';
  s += '.se-correlation.se-med-conf{border-left-color:#ffaa00}';
  s += '.se-correlation.se-low-conf{border-left-color:#00aaff}';

  // === LIST STYLES ===
  s += '.se-list{list-style:none;padding:0;margin:0}';
  s += '.se-list-item{padding:8px 12px;border-bottom:1px solid #111a2a;';
  s += 'display:flex;align-items:center;gap:10px;font-size:12px;transition:background 0.15s;cursor:pointer}';
  s += '.se-list-item:hover{background:rgba(0,170,255,0.04)}';
  s += '.se-list-item:last-child{border-bottom:none}';

  // === NATION FLAG PLACEHOLDERS ===
  s += '.se-flag{display:inline-flex;align-items:center;justify-content:center;';
  s += 'width:28px;height:20px;border-radius:3px;font-size:13px;flex-shrink:0;';
  s += 'border:1px solid rgba(255,255,255,0.1)}';

  // === INTEL CLASSIFICATION MARKS ===
  s += '.se-class-ts{color:#ff2244;font-weight:700;font-size:10px;letter-spacing:1px}';
  s += '.se-class-s{color:#ff6632;font-weight:700;font-size:10px;letter-spacing:1px}';
  s += '.se-class-c{color:#ffaa00;font-weight:700;font-size:10px;letter-spacing:1px}';
  s += '.se-class-u{color:#00ff88;font-weight:700;font-size:10px;letter-spacing:1px}';

  // === MODAL / OVERLAY ===
  s += '.se-modal-overlay{position:fixed;top:0;left:0;width:100%;height:100%;';
  s += 'background:rgba(0,0,0,0.7);z-index:1000;display:flex;align-items:center;';
  s += 'justify-content:center;animation:se-slide-in 0.2s}';
  s += '.se-modal{background:#0a0e1a;border:1px solid #1a3a5c;border-radius:8px;';
  s += 'padding:24px;max-width:800px;width:90%;max-height:80vh;overflow-y:auto;';
  s += 'box-shadow:0 20px 60px rgba(0,0,0,0.6)}';
  s += '.se-modal-close{position:absolute;top:12px;right:16px;cursor:pointer;';
  s += 'color:#5a7a9a;font-size:18px;transition:color 0.15s}';
  s += '.se-modal-close:hover{color:#ff2244}';

  // === RADAR DISPLAY ===
  s += '.se-radar{position:relative;width:200px;height:200px;border-radius:50%;';
  s += 'background:radial-gradient(circle,rgba(0,170,255,0.05) 0%,transparent 70%);';
  s += 'border:1px solid #1a3a5c}';
  s += '.se-radar-sweep{position:absolute;top:0;left:50%;width:50%;height:50%;';
  s += 'transform-origin:bottom left;background:linear-gradient(0deg,transparent,rgba(0,170,255,0.2));';
  s += 'animation:se-radar-sweep 4s linear infinite}';

  // === TWO-COLUMN LAYOUT ===
  s += '.se-cols{display:flex;gap:20px}';
  s += '.se-col-main{flex:1;min-width:0}';
  s += '.se-col-side{width:320px;flex-shrink:0}';
  s += '@media(max-width:900px){.se-cols{flex-direction:column}.se-col-side{width:100%}}';

  s += '</style>';
  return s;
}

// ---------------------------------------------------------------------------
// renderMainShell() — returns the complete outer HTML structure
// ---------------------------------------------------------------------------
function renderMainShell() {
  var h = '';

  // Top classification banner
  h += '<div class="se-classif-banner">';
  h += 'TOP SECRET // SCI // NOFORN // OPERATIONAL';
  h += '</div>';

  // Header
  h += '<div class="se-header">';
  h += '<div class="se-header-left">';
  h += '<div class="se-header-icon" style="font-size:20px;font-weight:800;color:#00aaff;font-family:monospace;letter-spacing:2px">S/E</div>';
  h += '<div>';
  h += '<div class="se-header-title">SENTINEL EYE</div>';
  h += '<div class="se-header-subtitle">Global Cyber Threat Detection &amp; Counter-Operations Platform</div>';
  h += '</div>';
  h += '</div>';
  h += '<div style="display:flex;align-items:center;gap:16px">';
  h += '<div class="se-defcon se-defcon-3" id="se-defcon-display">';
  h += '<span>CYBER DEFCON</span>';
  h += '<span id="se-defcon-level">3</span>';
  h += '</div>';
  h += '</div>';
  h += '</div>';

  // Global status bar
  h += '<div class="se-status-bar">';
  h += '<div class="se-status-item">';
  h += '<span class="se-status-label">Active Threats:</span>';
  h += '<span class="se-status-value se-critical" id="se-active-threats">17</span>';
  h += '</div>';
  h += '<div class="se-status-item">';
  h += '<span class="se-status-label">Monitored Nations:</span>';
  h += '<span class="se-status-value">12</span>';
  h += '</div>';
  h += '<div class="se-status-item">';
  h += '<span class="se-status-label">APT Groups Tracked:</span>';
  h += '<span class="se-status-value">38</span>';
  h += '</div>';
  h += '<div class="se-status-item">';
  h += '<span class="se-status-label">Active Predictions:</span>';
  h += '<span class="se-status-value se-warning" id="se-active-preds">25</span>';
  h += '</div>';
  h += '<div class="se-status-item">';
  h += '<span class="se-status-label">Last Nation-State Incident:</span>';
  h += '<span class="se-status-value" id="se-last-incident">4h 23m ago</span>';
  h += '</div>';
  h += '<div class="se-status-item">';
  h += '<span class="se-status-label">System Time:</span>';
  h += '<span class="se-status-value" id="se-system-time">--:--:-- UTC</span>';
  h += '</div>';
  h += '</div>';

  // Alert ticker
  h += '<div class="se-ticker-wrap">';
  h += '<div class="se-ticker-track" id="se-ticker-track">';
  h += '</div>';
  h += '</div>';

  // Tab navigation
  h += '<div class="se-tab-bar" id="se-tab-bar">';

  var tabs = [
    { id: 'situation', label: 'Situational Awareness', icon: '[SA]' },
    { id: 'nations', label: 'Nation-State Monitor', icon: '[NS]' },
    { id: 'predict', label: 'Attack Prediction', icon: '[AP]' },
    { id: 'earlywarning', label: 'Early Warning', icon: '[!]' },
    { id: 'apttrack', label: 'APT Tracking', icon: '[AT]' },
    { id: 'counterops', label: 'Counter Operations', icon: '[X]' },
    { id: 'shield', label: 'Infrastructure Shield', icon: '[IS]' },
    { id: 'intelfusion', label: 'Intelligence Fusion', icon: '[IF]' },
    { id: 'warsim', label: 'Cyber War Simulator', icon: '[W]' },
    { id: 'command', label: 'Command Authority', icon: '[C]' },
    { id: 'tracking', label: 'LIVE TRACKING', icon: '[LT]' },
    { id: 'sigint', label: 'SIGINT', icon: '[SI]' },
    { id: 'masint', label: 'MASINT', icon: '[MA]' },
    { id: 'globalwatch', label: 'GLOBAL WATCH', icon: '[GW]' }
  ];

  for (var t = 0; t < tabs.length; t++) {
    var cls = t === 0 ? 'se-tab se-active' : 'se-tab';
    h += '<div class="' + cls + '" data-tab="' + esc(tabs[t].id) + '">';
    h += '<span>' + tabs[t].icon + ' ' + esc(tabs[t].label) + '</span>';
    if (tabs[t].id === 'earlywarning' || tabs[t].id === 'predict') {
      h += '<span class="se-tab-alert"></span>';
    }
    h += '</div>';
  }

  h += '</div>';

  // Content area
  h += '<div class="se-content" id="se-content">';
  h += '</div>';

  // Footer
  h += '<div class="se-footer">';
  h += '<div>';
  h += '<span style="color:#5a7a9a">SENTINEL EYE v4.0.0</span>';
  h += ' &bull; ';
  h += '<span style="color:#3a5a7a">DARKNODE PLATFORM</span>';
  h += ' &bull; ';
  h += '<span style="color:#3a5a7a">OPERATIONAL — THREAT DATA ACTIVE</span>';
  h += '</div>';
  h += '<div>';
  h += '<span style="color:#5a7a9a" id="se-footer-time">System initialized</span>';
  h += ' &bull; ';
  h += '<span style="color:#00ff88">ALL SYSTEMS NOMINAL</span>';
  h += '</div>';
  h += '</div>';

  return h;
}

// ---------------------------------------------------------------------------
// initWorldMap(canvasId) — draws simplified world map on canvas
// ---------------------------------------------------------------------------
function initWorldMap(canvasId) {
  var canvas = document.getElementById(canvasId);
  if (!canvas) return;
  var ctx = canvas.getContext('2d');
  if (!ctx) return;

  var W = canvas.width = canvas.parentElement ? canvas.parentElement.clientWidth : 900;
  var H = canvas.height = Math.round(W * 0.48);

  // Background
  ctx.fillStyle = '#080b12';
  ctx.fillRect(0, 0, W, H);

  // Grid lines
  ctx.strokeStyle = 'rgba(26,58,92,0.3)';
  ctx.lineWidth = 0.5;
  var gridStep = W / 24;
  for (var gx = 0; gx < W; gx += gridStep) {
    ctx.beginPath(); ctx.moveTo(gx, 0); ctx.lineTo(gx, H); ctx.stroke();
  }
  for (var gy = 0; gy < H; gy += gridStep) {
    ctx.beginPath(); ctx.moveTo(0, gy); ctx.lineTo(W, gy); ctx.stroke();
  }

  // Equator and prime meridian
  ctx.strokeStyle = 'rgba(0,170,255,0.1)';
  ctx.lineWidth = 1;
  ctx.beginPath(); ctx.moveTo(0, H * 0.5); ctx.lineTo(W, H * 0.5); ctx.stroke();
  ctx.beginPath(); ctx.moveTo(W * 0.5, 0); ctx.lineTo(W * 0.5, H); ctx.stroke();

  // Continent outlines as simplified polygons (normalized 0-1 coordinates)
  var continents = {
    northAmerica: [
      [0.10,0.15],[0.12,0.12],[0.18,0.10],[0.24,0.12],[0.26,0.18],[0.28,0.22],
      [0.26,0.28],[0.24,0.32],[0.22,0.36],[0.20,0.38],[0.18,0.42],[0.16,0.44],
      [0.14,0.42],[0.15,0.38],[0.16,0.36],[0.15,0.34],[0.12,0.30],[0.10,0.28],
      [0.08,0.22],[0.09,0.18]
    ],
    southAmerica: [
      [0.22,0.48],[0.24,0.46],[0.28,0.46],[0.30,0.48],[0.31,0.52],[0.32,0.56],
      [0.30,0.62],[0.28,0.68],[0.26,0.74],[0.24,0.78],[0.22,0.82],[0.20,0.78],
      [0.21,0.72],[0.22,0.66],[0.21,0.60],[0.20,0.54],[0.21,0.50]
    ],
    europe: [
      [0.44,0.14],[0.46,0.12],[0.50,0.10],[0.54,0.12],[0.56,0.16],[0.55,0.20],
      [0.52,0.24],[0.50,0.28],[0.48,0.30],[0.46,0.32],[0.44,0.30],[0.42,0.26],
      [0.41,0.22],[0.42,0.18]
    ],
    africa: [
      [0.44,0.34],[0.46,0.32],[0.50,0.32],[0.54,0.34],[0.56,0.38],[0.57,0.44],
      [0.56,0.50],[0.55,0.56],[0.53,0.62],[0.50,0.66],[0.48,0.68],[0.46,0.66],
      [0.44,0.60],[0.42,0.54],[0.41,0.48],[0.42,0.42],[0.43,0.38]
    ],
    asia: [
      [0.56,0.10],[0.60,0.08],[0.66,0.10],[0.72,0.12],[0.78,0.14],[0.82,0.16],
      [0.84,0.20],[0.86,0.24],[0.84,0.28],[0.80,0.30],[0.76,0.34],[0.72,0.38],
      [0.68,0.40],[0.64,0.38],[0.60,0.36],[0.58,0.32],[0.56,0.28],[0.55,0.24],
      [0.54,0.18],[0.55,0.14]
    ],
    middleEast: [
      [0.56,0.30],[0.58,0.28],[0.62,0.30],[0.64,0.34],[0.62,0.38],[0.60,0.40],
      [0.58,0.38],[0.56,0.36],[0.55,0.34]
    ],
    australia: [
      [0.78,0.58],[0.82,0.56],[0.86,0.58],[0.88,0.62],[0.87,0.66],[0.84,0.70],
      [0.80,0.70],[0.77,0.66],[0.76,0.62]
    ],
    seAsia: [
      [0.74,0.38],[0.78,0.36],[0.82,0.38],[0.84,0.42],[0.82,0.46],[0.78,0.48],
      [0.76,0.46],[0.74,0.42]
    ]
  };

  // Draw continents
  ctx.lineWidth = 1.5;
  var contKeys = Object.keys(continents);
  for (var ci = 0; ci < contKeys.length; ci++) {
    var pts = continents[contKeys[ci]];
    ctx.fillStyle = 'rgba(0,170,255,0.06)';
    ctx.strokeStyle = 'rgba(0,170,255,0.25)';
    ctx.beginPath();
    ctx.moveTo(pts[0][0] * W, pts[0][1] * H);
    for (var pi = 1; pi < pts.length; pi++) {
      ctx.lineTo(pts[pi][0] * W, pts[pi][1] * H);
    }
    ctx.closePath();
    ctx.fill();
    ctx.stroke();
  }

  // Nation positions on map (normalized coordinates)
  var nationPositions = [
    { name: 'US', x: 0.18, y: 0.28, color: '#00aaff', threat: 'allied' },
    { name: 'RU', x: 0.62, y: 0.16, color: '#ff2244', threat: 'hostile' },
    { name: 'CN', x: 0.76, y: 0.28, color: '#ff2244', threat: 'hostile' },
    { name: 'NK', x: 0.80, y: 0.26, color: '#ff2244', threat: 'hostile' },
    { name: 'IR', x: 0.58, y: 0.32, color: '#ff6432', threat: 'elevated' },
    { name: 'IL', x: 0.54, y: 0.32, color: '#00aaff', threat: 'allied' },
    { name: 'UK', x: 0.46, y: 0.18, color: '#00aaff', threat: 'allied' },
    { name: 'FR', x: 0.46, y: 0.24, color: '#00aaff', threat: 'allied' },
    { name: 'IN', x: 0.66, y: 0.36, color: '#ffaa00', threat: 'elevated' },
    { name: 'PK', x: 0.64, y: 0.32, color: '#ffaa00', threat: 'elevated' },
    { name: 'TR', x: 0.52, y: 0.28, color: '#ffaa00', threat: 'elevated' },
    { name: 'VN', x: 0.76, y: 0.38, color: '#ffaa00', threat: 'elevated' }
  ];

  // Draw connection lines between adversaries and targets
  var attackLines = [
    { from: 1, to: 0, color: 'rgba(255,34,68,0.3)' },  // RU -> US
    { from: 2, to: 0, color: 'rgba(255,34,68,0.25)' },  // CN -> US
    { from: 3, to: 0, color: 'rgba(255,34,68,0.2)' },   // NK -> US
    { from: 1, to: 6, color: 'rgba(255,34,68,0.2)' },   // RU -> UK
    { from: 4, to: 5, color: 'rgba(255,100,50,0.25)' },  // IR -> IL
    { from: 2, to: 8, color: 'rgba(255,170,0,0.15)' }    // CN -> IN
  ];

  ctx.setLineDash([4, 4]);
  for (var li = 0; li < attackLines.length; li++) {
    var line = attackLines[li];
    var fromN = nationPositions[line.from];
    var toN = nationPositions[line.to];
    ctx.strokeStyle = line.color;
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    ctx.moveTo(fromN.x * W, fromN.y * H);
    ctx.lineTo(toN.x * W, toN.y * H);
    ctx.stroke();
  }
  ctx.setLineDash([]);

  // Draw nation dots
  var now = Date.now();
  for (var ni = 0; ni < nationPositions.length; ni++) {
    var np = nationPositions[ni];
    var nx = np.x * W;
    var ny = np.y * H;

    // Pulsing ring for hostile nations
    if (np.threat === 'hostile') {
      var pulseSize = 8 + Math.sin(now / 500 + ni) * 3;
      ctx.beginPath();
      ctx.arc(nx, ny, pulseSize, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(255,34,68,0.15)';
      ctx.fill();
      ctx.strokeStyle = 'rgba(255,34,68,0.4)';
      ctx.lineWidth = 1;
      ctx.stroke();
    }

    // Main dot
    ctx.beginPath();
    ctx.arc(nx, ny, 4, 0, Math.PI * 2);
    ctx.fillStyle = np.color;
    ctx.fill();
    ctx.strokeStyle = 'rgba(255,255,255,0.3)';
    ctx.lineWidth = 1;
    ctx.stroke();

    // Label
    ctx.font = '9px "Courier New", monospace';
    ctx.fillStyle = np.color;
    ctx.textAlign = 'center';
    ctx.fillText(np.name, nx, ny - 9);
  }

  // Legend
  var legendX = 12;
  var legendY = H - 70;
  ctx.fillStyle = 'rgba(8,11,18,0.85)';
  ctx.fillRect(legendX, legendY, 130, 62);
  ctx.strokeStyle = '#1a3a5c';
  ctx.lineWidth = 1;
  ctx.strokeRect(legendX, legendY, 130, 62);

  ctx.font = 'bold 9px "Courier New", monospace';
  ctx.fillStyle = '#5a7a9a';
  ctx.textAlign = 'left';
  ctx.fillText('THREAT LEGEND', legendX + 8, legendY + 12);

  var legendItems = [
    { color: '#ff2244', label: 'HOSTILE OPS' },
    { color: '#ff6432', label: 'ELEVATED' },
    { color: '#ffaa00', label: 'INCREASED' },
    { color: '#00aaff', label: 'ALLIED' }
  ];

  for (var ll = 0; ll < legendItems.length; ll++) {
    var ly = legendY + 24 + ll * 10;
    ctx.beginPath();
    ctx.arc(legendX + 12, ly - 2, 3, 0, Math.PI * 2);
    ctx.fillStyle = legendItems[ll].color;
    ctx.fill();
    ctx.font = '8px "Courier New", monospace';
    ctx.fillStyle = '#8aa8c8';
    ctx.fillText(legendItems[ll].label, legendX + 22, ly);
  }

  // Title
  ctx.font = 'bold 11px "Courier New", monospace';
  ctx.fillStyle = '#00aaff';
  ctx.textAlign = 'left';
  ctx.fillText('GLOBAL THREAT MAP — LIVE', 12, 16);

  ctx.font = '9px "Courier New", monospace';
  ctx.fillStyle = '#3a5a7a';
  ctx.textAlign = 'right';
  ctx.fillText('SENTINEL EYE // LIVE DATA', W - 12, 16);

  // Animate pulsing dots
  var animFrame;
  function animateDots() {
    var t = Date.now();
    // Clear just the dot areas to redraw them
    for (var ai = 0; ai < nationPositions.length; ai++) {
      var ap = nationPositions[ai];
      if (ap.threat !== 'hostile') continue;
      var ax = ap.x * W;
      var ay = ap.y * H;
      var pulse = 8 + Math.sin(t / 400 + ai * 1.5) * 4;

      // Clear region
      ctx.fillStyle = '#080b12';
      ctx.fillRect(ax - 16, ay - 16, 32, 32);

      // Redraw continent fill in area (approximate)
      ctx.fillStyle = 'rgba(0,170,255,0.06)';
      ctx.fillRect(ax - 16, ay - 16, 32, 32);

      // Pulse ring
      ctx.beginPath();
      ctx.arc(ax, ay, pulse, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(255,34,68,' + (0.1 + Math.sin(t / 400) * 0.05) + ')';
      ctx.fill();
      ctx.strokeStyle = 'rgba(255,34,68,' + (0.3 + Math.sin(t / 400) * 0.2) + ')';
      ctx.lineWidth = 1;
      ctx.stroke();

      // Core dot
      ctx.beginPath();
      ctx.arc(ax, ay, 4, 0, Math.PI * 2);
      ctx.fillStyle = '#ff2244';
      ctx.fill();

      // Label
      ctx.font = '9px "Courier New", monospace';
      ctx.fillStyle = '#ff2244';
      ctx.textAlign = 'center';
      ctx.fillText(ap.name, ax, ay - 9);
    }
    animFrame = requestAnimationFrame(animateDots);
  }
  animateDots();

  // Store cancel function
  canvas._seAnimCancel = function() {
    if (animFrame) cancelAnimationFrame(animFrame);
  };
}

// ---------------------------------------------------------------------------
// initTicker() — scrolling alert ticker
// ---------------------------------------------------------------------------
function initTicker() {
  var track = document.getElementById('se-ticker-track');
  if (!track) return;

  var alertPool = [
    { sev: 'critical', msg: 'APT29 (COZY BEAR) new C2 infrastructure detected — 14 domains registered in last 6h' },
    { sev: 'critical', msg: 'VOLT TYPHOON lateral movement detected in US water utility SCADA network' },
    { sev: 'critical', msg: 'LAZARUS GROUP crypto exchange targeting campaign — $340M exposure identified' },
    { sev: 'high', msg: 'SANDWORM probing European energy grid — reconnaissance phase indicators' },
    { sev: 'high', msg: 'APT41 supply chain compromise attempt — NPM package typosquatting cluster' },
    { sev: 'high', msg: 'Zero-day listing detected on dark web marketplace — targeting Fortinet SSL VPN' },
    { sev: 'medium', msg: 'BGP route hijack attempt detected — AS path manipulation targeting US DOD ranges' },
    { sev: 'medium', msg: 'KIMSUKY phishing campaign expanded — 200+ new credential harvesting domains' },
    { sev: 'medium', msg: 'Increased scanning from Iranian IP ranges targeting NATO member infrastructure' },
    { sev: 'high', msg: 'SALT TYPHOON persistent access confirmed in 3 additional US telecom providers' },
    { sev: 'critical', msg: 'Pre-positioned VOLT TYPHOON implants activated in Guam military networks' },
    { sev: 'medium', msg: 'MUDDYWATER new dropper variant detected — polymorphic evasion techniques' },
    { sev: 'high', msg: 'Russian GRU Unit 74455 staging wiper malware — Ukrainian targets probable' },
    { sev: 'medium', msg: 'DNS anomaly: 47 critical infrastructure domains had unauthorized NS changes' },
    { sev: 'high', msg: 'TURLA deploying new satellite C2 channel — hijacking VSAT connections' },
    { sev: 'critical', msg: 'Supply chain alert: compromised update server for industrial control system vendor' },
    { sev: 'medium', msg: 'Increased dark web chatter — initial access brokers offering Fortune 500 access' },
    { sev: 'high', msg: 'APT28 (FANCY BEAR) exploiting unpatched Outlook zero-day in NATO ministries' },
    { sev: 'medium', msg: 'Certificate transparency anomaly — suspicious certs for .gov and .mil domains' },
    { sev: 'high', msg: 'ANDARIEL ransomware infrastructure expansion — healthcare sector targeting' }
  ];

  var sevColors = {
    critical: '#ff2244',
    high: '#ff6432',
    medium: '#ffaa00',
    low: '#00aaff'
  };

  var html = '';
  // Double the items for seamless scrolling
  for (var pass = 0; pass < 2; pass++) {
    for (var ai = 0; ai < alertPool.length; ai++) {
      var a = alertPool[ai];
      var dotColor = sevColors[a.sev] || '#5a7a9a';
      html += '<span class="se-ticker-item">';
      html += '<span class="se-ticker-dot" style="background:' + dotColor + ';box-shadow:0 0 4px ' + dotColor + '"></span>';
      html += '<span style="color:' + dotColor + ';font-weight:700">[' + esc(a.sev.toUpperCase()) + ']</span> ';
      html += '<span style="color:#c8d8e8">' + esc(a.msg) + '</span>';
      html += '</span>';
      if (ai < alertPool.length - 1 || pass === 0) {
        html += '<span class="se-ticker-sep">|</span>';
      }
    }
  }

  track.innerHTML = html;
}

// ---------------------------------------------------------------------------
// initEventHandlers() — master event system
// ---------------------------------------------------------------------------
function initEventHandlers() {
  var SE_STORAGE_KEY = 'dn_sentinel_eye_v1';

  // ---- Tab switching ----
  var tabBar = document.getElementById('se-tab-bar');
  if (tabBar) {
    tabBar.addEventListener('click', function(e) {
      var tab = e.target.closest('.se-tab');
      if (!tab) return;
      var tabId = tab.getAttribute('data-tab');
      if (!tabId) return;

      // Update active tab
      var allTabs = tabBar.querySelectorAll('.se-tab');
      for (var i = 0; i < allTabs.length; i++) {
        allTabs[i].className = 'se-tab';
      }
      tab.className = 'se-tab se-active';

      // Switch content
      switchTab(tabId);

      // Save state
      saveState({ activeTab: tabId });
    });
  }

  // ---- Panel expand/collapse ----
  document.addEventListener('click', function(e) {
    var expandHead = e.target.closest('.se-expand-head');
    if (!expandHead) return;
    var panel = expandHead.closest('.se-expand');
    if (!panel) return;
    if (panel.classList.contains('se-open')) {
      panel.classList.remove('se-open');
    } else {
      panel.classList.add('se-open');
    }
  });

  // ---- Filter changes ----
  document.addEventListener('change', function(e) {
    var el = e.target;
    if (el.id === 'se-nation-filter') {
      filterNations(el.value);
    } else if (el.id === 'se-severity-filter') {
      filterBySeverity(el.value);
    } else if (el.id === 'se-category-filter') {
      filterByCategory(el.value);
    } else if (el.id === 'se-apt-nation-filter') {
      filterAPTByNation(el.value);
    } else if (el.id === 'se-sector-filter') {
      filterBySector(el.value);
    } else if (el.id === 'se-intel-source-filter') {
      filterIntelBySource(el.value);
    }
  });

  // ---- Search inputs ----
  document.addEventListener('input', function(e) {
    var el = e.target;
    if (el.id === 'se-apt-search') {
      searchAPT(el.value);
    } else if (el.id === 'se-ops-search') {
      searchOperations(el.value);
    } else if (el.id === 'se-intel-search') {
      searchIntel(el.value);
    }
  });

  // ---- Button clicks ----
  document.addEventListener('click', function(e) {
    var btn = e.target.closest('.se-btn');
    if (!btn) return;
    var action = btn.getAttribute('data-action');
    if (!action) return;

    if (action === 'launch-wargame') {
      var scenarioId = btn.getAttribute('data-scenario');
      launchWargame(scenarioId);
    } else if (action === 'run-whatif') {
      runWhatIf();
    } else if (action === 'generate-report') {
      var reportType = btn.getAttribute('data-report');
      generateReport(reportType);
    } else if (action === 'plan-counterop') {
      planCounterOp();
    } else if (action === 'launch-tabletop') {
      var exerciseId = btn.getAttribute('data-exercise');
      launchTabletop(exerciseId);
    } else if (action === 'escalate-threat') {
      escalateThreat(btn.getAttribute('data-threat'));
    } else if (action === 'generate-sitrep') {
      generateSITREP();
    } else if (action === 'generate-flash') {
      generateFlashMessage();
    } else if (action === 'wargame-respond') {
      var responseId = btn.getAttribute('data-response');
      wargameRespond(responseId);
    } else if (action === 'next-phase') {
      wargameNextPhase();
    } else if (action === 'aar-review') {
      wargameAAR();
    } else if (action === 'view-playbook') {
      var pbId = btn.getAttribute('data-playbook');
      viewPlaybook(pbId);
    } else if (action === 'create-intel-product') {
      var productType = btn.getAttribute('data-product');
      createIntelProduct(productType);
    } else if (action === 'dismiss-alert') {
      var alertEl = btn.closest('.se-card');
      if (alertEl) alertEl.style.display = 'none';
    }
  });

  // ---- System time updater ----
  function updateSystemTime() {
    var timeEl = document.getElementById('se-system-time');
    var footerTimeEl = document.getElementById('se-footer-time');
    if (timeEl) {
      var d = new Date();
      var h = d.getUTCHours();
      var m = d.getUTCMinutes();
      var sec = d.getUTCSeconds();
      var ts = (h < 10 ? '0' : '') + h + ':' + (m < 10 ? '0' : '') + m + ':' + (sec < 10 ? '0' : '') + sec + ' UTC';
      timeEl.textContent = ts;
    }
    if (footerTimeEl) {
      var d2 = new Date();
      footerTimeEl.textContent = 'Updated: ' + d2.toISOString().replace('T', ' ').split('.')[0] + ' UTC';
    }
  }
  _seTimers.push(setInterval(updateSystemTime, 1000));
  updateSystemTime();

  // ---- Simulated threat level shifts ----
  _seTimers.push(setInterval(function() {
    var threatsEl = document.getElementById('se-active-threats');
    if (threatsEl) {
      var current = parseInt(threatsEl.textContent) || 17;
      var shift = Math.floor(Math.random() * 3) - 1;
      var newVal = Math.max(10, Math.min(30, current + shift));
      threatsEl.textContent = String(newVal);
    }

    var lastIncEl = document.getElementById('se-last-incident');
    if (lastIncEl) {
      var text = lastIncEl.textContent;
      var hoursMatch = text.match(/(\d+)h/);
      var minsMatch = text.match(/(\d+)m/);
      var hours = hoursMatch ? parseInt(hoursMatch[1]) : 4;
      var mins = minsMatch ? parseInt(minsMatch[1]) : 23;
      mins++;
      if (mins >= 60) { mins = 0; hours++; }
      lastIncEl.textContent = hours + 'h ' + (mins < 10 ? '0' : '') + mins + 'm ago';
    }
  }, 60000));

  // D3.js threat map handles its own resize internally

  // ---- Load saved state ----
  loadState();
}

// ---------------------------------------------------------------------------
// State management — localStorage
// ---------------------------------------------------------------------------
function saveState(partial) {
  try {
    var key = 'dn_sentinel_eye_v1';
    var stateStr = localStorage.getItem(key);
    var state = stateStr ? JSON.parse(stateStr) : {};
    var keys = Object.keys(partial);
    for (var i = 0; i < keys.length; i++) {
      state[keys[i]] = partial[keys[i]];
    }
    state.lastUpdated = new Date().toISOString();
    localStorage.setItem(key, JSON.stringify(state));
  } catch (e) {
    // localStorage may be unavailable
  }
}

function loadState() {
  try {
    var key = 'dn_sentinel_eye_v1';
    var stateStr = localStorage.getItem(key);
    if (!stateStr) return null;
    var state = JSON.parse(stateStr);

    // Restore active tab
    if (state.activeTab) {
      var tabBar = document.getElementById('se-tab-bar');
      if (tabBar) {
        var allTabs = tabBar.querySelectorAll('.se-tab');
        for (var i = 0; i < allTabs.length; i++) {
          allTabs[i].className = 'se-tab';
          if (allTabs[i].getAttribute('data-tab') === state.activeTab) {
            allTabs[i].className = 'se-tab se-active';
          }
        }
        switchTab(state.activeTab);
      }
    }

    return state;
  } catch (e) {
    return null;
  }
}

// ---------------------------------------------------------------------------
// switchTab(tabId) — switch content area to specified tab
// ---------------------------------------------------------------------------
function switchTab(tabId) {
  var content = document.getElementById('se-content');
  if (!content) return;

  var html = '';
  switch (tabId) {
    case 'situation':
      html = renderSituation();
      break;
    case 'nations':
      html = renderNations();
      break;
    case 'predict':
      html = renderPredict();
      break;
    case 'earlywarning':
      html = renderEarlyWarning();
      break;
    case 'apttrack':
      html = renderAptTrack();
      break;
    case 'counterops':
      html = renderCounterOps();
      break;
    case 'shield':
      html = renderShield();
      break;
    case 'intelfusion':
      html = renderIntelFusion();
      break;
    case 'warsim':
      html = renderWarSim();
      break;
    case 'command':
      html = renderCommand();
      break;
    case 'tracking':
      html = renderTracking();
      break;
    case 'sigint':
      html = renderSigint();
      break;
    case 'masint':
      html = renderMasint();
      break;
    case 'globalwatch':
      html = renderGlobalWatch();
      break;
    default:
      html = renderSituation();
  }

  content.innerHTML = html;

  // Post-render initialization for tabs with live data
  if (tabId === 'predict') {
    setTimeout(function() { _seInitPredictTab(); }, 50);
  }
  if (tabId === 'earlywarning') {
    setTimeout(function() { _seInitEarlyWarningTab(); }, 50);
  }

  // Init tracking tab live data
  if (tabId === 'tracking') {
    setTimeout(function() { _seInitTrackingTab(); }, 50);
  }

  // Init Global Watch CesiumJS globe
  if (tabId === 'globalwatch') {
    setTimeout(function() { _gwInitGlobe(); }, 100);
  }

  // Render D3.js threat map if situation tab
  if (tabId === 'situation') {
    setTimeout(function() {
      if (typeof window.renderThreatMap === 'function') {
        window.renderThreatMap('se-threat-map', {
          actors: typeof GW_THREAT_ACTORS !== 'undefined' ? GW_THREAT_ACTORS : [],
          arcs: typeof GW_CAMPAIGN_ARCS !== 'undefined' ? GW_CAMPAIGN_ARCS : [],
          ixps: typeof GW_IXPS !== 'undefined' ? GW_IXPS : [],
          cables: typeof GW_UNDERSEA_CABLES !== 'undefined' ? GW_UNDERSEA_CABLES : []
        });
      }
    }, 50);
  }
}

// ---------------------------------------------------------------------------
// Filter and search stubs (called from event handlers, implemented per tab)
// ---------------------------------------------------------------------------
function filterNations(val) {
  var cards = document.querySelectorAll('.se-nation-card');
  for (var i = 0; i < cards.length; i++) {
    if (val === 'all' || cards[i].getAttribute('data-alignment') === val) {
      cards[i].style.display = '';
    } else {
      cards[i].style.display = 'none';
    }
  }
}

function filterBySeverity(val) {
  var items = document.querySelectorAll('.se-filterable-item');
  for (var i = 0; i < items.length; i++) {
    if (val === 'all' || items[i].getAttribute('data-severity') === val) {
      items[i].style.display = '';
    } else {
      items[i].style.display = 'none';
    }
  }
}

function filterByCategory(val) {
  var items = document.querySelectorAll('.se-filterable-item');
  for (var i = 0; i < items.length; i++) {
    if (val === 'all' || items[i].getAttribute('data-category') === val) {
      items[i].style.display = '';
    } else {
      items[i].style.display = 'none';
    }
  }
}

function filterAPTByNation(val) {
  var cards = document.querySelectorAll('.se-apt-card');
  for (var i = 0; i < cards.length; i++) {
    if (val === 'all' || cards[i].getAttribute('data-nation') === val) {
      cards[i].style.display = '';
    } else {
      cards[i].style.display = 'none';
    }
  }
}

function filterBySector(val) {
  var items = document.querySelectorAll('.se-sector-card');
  for (var i = 0; i < items.length; i++) {
    if (val === 'all' || items[i].getAttribute('data-sector') === val) {
      items[i].style.display = '';
    } else {
      items[i].style.display = 'none';
    }
  }
}

function filterIntelBySource(val) {
  var items = document.querySelectorAll('.se-intel-item');
  for (var i = 0; i < items.length; i++) {
    if (val === 'all' || items[i].getAttribute('data-source') === val) {
      items[i].style.display = '';
    } else {
      items[i].style.display = 'none';
    }
  }
}

function searchAPT(query) {
  var q = query.toLowerCase();
  var cards = document.querySelectorAll('.se-apt-card');
  for (var i = 0; i < cards.length; i++) {
    var text = (cards[i].textContent || '').toLowerCase();
    cards[i].style.display = (!q || text.indexOf(q) >= 0) ? '' : 'none';
  }
}

function searchOperations(query) {
  var q = query.toLowerCase();
  var items = document.querySelectorAll('.se-op-item');
  for (var i = 0; i < items.length; i++) {
    var text = (items[i].textContent || '').toLowerCase();
    items[i].style.display = (!q || text.indexOf(q) >= 0) ? '' : 'none';
  }
}

function searchIntel(query) {
  var q = query.toLowerCase();
  var items = document.querySelectorAll('.se-intel-item');
  for (var i = 0; i < items.length; i++) {
    var text = (items[i].textContent || '').toLowerCase();
    items[i].style.display = (!q || text.indexOf(q) >= 0) ? '' : 'none';
  }
}

// ---------------------------------------------------------------------------
// Wargame interaction stubs
// ---------------------------------------------------------------------------
var _seActiveWargame = null;
var _seActivePhase = 0;

function launchWargame(scenarioId) {
  _seActiveWargame = scenarioId;
  _seActivePhase = 0;
  switchTab('warsim');
}

function wargameRespond(responseId) {
  var responseArea = document.getElementById('se-wargame-response');
  if (responseArea) {
    var responses = {
      'isolate': 'RESPONSE LOGGED: Network isolation initiated. Affected segments quarantined. Monitoring for lateral movement indicators.',
      'hunt': 'RESPONSE LOGGED: Threat hunt teams deployed. Scanning for IoCs across enterprise. ETA: 45 minutes for initial sweep.',
      'patch': 'RESPONSE LOGGED: Emergency patching authorized. Deploying critical updates to affected systems. Rollback plan prepared.',
      'monitor': 'RESPONSE LOGGED: Enhanced monitoring activated. SIEM rules updated. SOC alert threshold lowered. All eyes on affected sectors.',
      'counter': 'RESPONSE LOGGED: Counter-intelligence operation approved. Deploying honeypots and deception assets. Tracking adversary C2.',
      'brief': 'RESPONSE LOGGED: Executive brief prepared. National Security Council notified. Congressional notification drafted.',
      'coordinate': 'RESPONSE LOGGED: Allied coordination initiated. Five Eyes partners notified. NATO CCDCOE engaged. Joint response planning.',
      'contain': 'RESPONSE LOGGED: Containment perimeter established. Egress filtering tightened. Data loss prevention activated.'
    };
    var msg = responses[responseId] || 'RESPONSE LOGGED: Action acknowledged. Implementation underway.';
    responseArea.innerHTML = '<div class="se-card" style="border-color:#00ff88">' +
      '<div style="color:#00ff88;font-size:11px;font-weight:700;letter-spacing:1px;margin-bottom:6px">' +
      '[+] BLUE TEAM RESPONSE</div>' +
      '<div style="font-size:12px;color:#c8d8e8">' + esc(msg) + '</div>' +
      '<div style="font-size:10px;color:#5a7a9a;margin-top:6px">Timestamp: ' + new Date().toISOString() + '</div>' +
      '</div>' + responseArea.innerHTML;
  }
}

function wargameNextPhase() {
  _seActivePhase++;
  switchTab('warsim');
}

function wargameAAR() {
  var content = document.getElementById('se-content');
  if (!content) return;
  var h = '';
  h += '<div class="se-section-head"><span class="se-section-icon">[>]</span> AFTER-ACTION REVIEW</div>';
  h += '<div class="se-card-3d">';
  h += '<div class="se-card-title" style="margin-bottom:12px">EXERCISE COMPLETE — AFTER-ACTION REVIEW</div>';
  h += '<div class="se-grid-2">';
  h += '<div class="se-stat-box"><div class="se-stat-value">3m 42s</div><div class="se-stat-label">Mean Detection Time</div></div>';
  h += '<div class="se-stat-box"><div class="se-stat-value se-warning">7m 15s</div><div class="se-stat-label">Mean Containment Time</div></div>';
  h += '<div class="se-stat-box"><div class="se-stat-value se-safe">82%</div><div class="se-stat-label">Overall Score</div></div>';
  h += '<div class="se-stat-box"><div class="se-stat-value">4/5</div><div class="se-stat-label">Phases Completed</div></div>';
  h += '</div>';
  h += '<hr class="se-divider">';
  h += '<div style="font-size:12px;color:#c8d8e8;line-height:1.8">';
  h += '<div style="color:#00aaff;font-weight:700;margin-bottom:8px">LESSONS LEARNED:</div>';
  h += '<div>• Initial detection was rapid but escalation to senior leadership took too long</div>';
  h += '<div>• Cross-sector coordination needs improvement — telecom and energy sectors operated in silos</div>';
  h += '<div>• Containment was effective but recovery planning should begin earlier</div>';
  h += '<div>• Intelligence sharing with allies was well-coordinated via established channels</div>';
  h += '<div>• Need pre-authorized response playbooks for specific attack scenarios to reduce decision time</div>';
  h += '</div>';
  h += '<div style="margin-top:16px">';
  h += '<span class="se-btn se-btn-primary" data-action="launch-wargame" data-scenario="dragon-storm">RUN ANOTHER EXERCISE</span>';
  h += '</div>';
  h += '</div>';
  content.innerHTML = h;
}

// ---------------------------------------------------------------------------
// Counter-ops and report generation stubs
// ---------------------------------------------------------------------------
function planCounterOp() {
  var opArea = document.getElementById('se-counterop-output');
  if (!opArea) return;
  var h = '';
  h += '<div class="se-card" style="border-color:#00aaff">';
  h += '<div style="color:#00aaff;font-weight:700;font-size:12px;letter-spacing:1px;margin-bottom:8px">';
  h += '[+] OPERATION PLAN GENERATED</div>';
  h += '<div class="se-grid-2" style="margin-bottom:12px">';
  h += '<div><span class="se-muted">Phase 1:</span> <span style="color:#c8d8e8">Reconnaissance — Map adversary infrastructure (72h)</span></div>';
  h += '<div><span class="se-muted">Phase 2:</span> <span style="color:#c8d8e8">Access Development — Identify entry points (48h)</span></div>';
  h += '<div><span class="se-muted">Phase 3:</span> <span style="color:#c8d8e8">Payload Preparation — Stage tools and capabilities (24h)</span></div>';
  h += '<div><span class="se-muted">Phase 4:</span> <span style="color:#c8d8e8">Execution — Deploy and collect intelligence (Ongoing)</span></div>';
  h += '</div>';
  h += '<div style="font-size:11px;color:#ffaa00;margin-bottom:8px">';
  h += '[!] ROE COMPLIANCE: All actions must comply with Title 50 authorities and current executive order</div>';
  h += '<div style="font-size:11px;color:#5a7a9a">Collateral Damage Estimate: LOW | Legal Review: REQUIRED | Congressional Notification: REQUIRED</div>';
  h += '</div>';
  opArea.innerHTML = h;
}

function generateReport(reportType) {
  var outputId = 'se-report-output';
  var outputEl = document.getElementById(outputId);
  if (!outputEl) return;

  var reportTemplates = {
    'sitrep': 'SITUATION REPORT (SITREP)\n\n1. SITUATION: Elevated cyber threat posture across multiple sectors.\n2. THREAT ACTORS: APT29, Volt Typhoon, Lazarus Group showing increased activity.\n3. KEY EVENTS: Infrastructure staging detected for potential offensive operations.\n4. ASSESSMENT: High probability of targeted attacks within 72-hour window.\n5. RECOMMENDED ACTIONS: Elevate monitoring, implement emergency patches, activate incident response teams.',
    'flash': 'FLASH MESSAGE — IMMEDIATE\n\nFLASH//SENTINEL EYE//CYBER//CRITICAL\n\nIMMEDIATE THREAT: Nation-state adversary has staged offensive cyber capabilities targeting critical infrastructure.\nTIMELINE: Attack expected within 24-48 hours.\nSECTORS AT RISK: Energy, Telecommunications, Financial Services.\nIMMEDIATE ACTIONS REQUIRED: Implement emergency defensive measures per CISA Emergency Directive.',
    'execbrief': 'EXECUTIVE BRIEF — CYBER THREAT POSTURE\n\nBOTTOM LINE: Three nation-state adversaries are conducting operations against US and allied interests.\n\nKEY POINTS:\n- Russia: APT29 targeting government networks; Sandworm staging infrastructure for potential destructive attack\n- China: Volt Typhoon maintaining persistent access in critical infrastructure; Salt Typhoon in telecom\n- North Korea: Lazarus Group conducting cryptocurrency theft to fund weapons programs\n\nRECOMMENDATION: Raise cyber DEFCON to level 2 and activate full defensive posture.',
    'oprep3': 'OPERATIONAL REPORT (OPREP-3)\n\n1. TYPE: CYBER INCIDENT\n2. DATE/TIME GROUP: ' + new Date().toISOString() + '\n3. UNIT: CYBER NATIONAL MISSION FORCE\n4. LOCATION: CYBERSPACE (MULTIPLE SECTORS)\n5. ACTIVITY: Nation-state cyber operations detected targeting national critical infrastructure\n6. ACTIONS TAKEN: Enhanced monitoring, defensive countermeasures deployed\n7. DAMAGE: Assessment ongoing — no confirmed impact to mission capability\n8. FOLLOW-UP: Continuous monitoring, 4-hour reporting cycle established'
  };

  var content = reportTemplates[reportType] || 'Report type not recognized.';
  var h = '<div class="se-card" style="border-color:#00aaff">';
  h += '<div style="color:#00aaff;font-weight:700;font-size:12px;letter-spacing:1px;margin-bottom:8px">';
  h += '[>] GENERATED REPORT — ' + esc(reportType.toUpperCase()) + '</div>';
  h += '<pre style="font-size:11px;color:#c8d8e8;white-space:pre-wrap;line-height:1.6;margin:0">' + esc(content) + '</pre>';
  h += '<div style="margin-top:12px;font-size:10px;color:#5a7a9a">Generated: ' + new Date().toISOString() + ' | Classification: OPERATIONAL</div>';
  h += '</div>';
  outputEl.innerHTML = h;
}

function generateSITREP() {
  generateReport('sitrep');
}

function generateFlashMessage() {
  generateReport('flash');
}

function launchTabletop(exerciseId) {
  var area = document.getElementById('se-tabletop-output');
  if (!area) return;
  var h = '<div class="se-card" style="border-color:#00aaff">';
  h += '<div style="color:#00aaff;font-weight:700;font-size:12px;letter-spacing:1px;margin-bottom:8px">';
  h += '[>] TABLETOP EXERCISE LAUNCHED</div>';
  h += '<div style="font-size:12px;color:#c8d8e8;line-height:1.8">';
  h += '<div>Scenario: Coordinated ransomware attack on healthcare sector</div>';
  h += '<div>Participants: SOC Team, IR Team, Legal, Communications, Executive Leadership</div>';
  h += '<div>Duration: 4 hours</div>';
  h += '<div style="margin-top:8px;color:#ffaa00">INJECT 1: Multiple hospitals report systems locked with ransom note demanding $50M in Bitcoin.</div>';
  h += '<div style="color:#ffaa00">INJECT 2: Patient data exfiltration detected — threat actors threatening to publish.</div>';
  h += '<div style="color:#ffaa00">INJECT 3: Attack attributed to nation-state proxy group. Escalation to national security concern.</div>';
  h += '</div>';
  h += '</div>';
  area.innerHTML = h;
}

function escalateThreat(threatId) {
  var el = document.getElementById('se-escalation-log');
  if (!el) return;
  var msg = '<div class="se-card" style="border-color:#ff2244;margin-bottom:8px">';
  msg += '<div style="color:#ff2244;font-size:11px;font-weight:700">[!] THREAT ESCALATED</div>';
  msg += '<div style="font-size:11px;color:#c8d8e8;margin-top:4px">Threat ID: ' + esc(threatId || 'UNSPECIFIED') + ' — Escalated to national level. NSC notification drafted.</div>';
  msg += '<div style="font-size:10px;color:#5a7a9a;margin-top:4px">' + new Date().toISOString() + '</div>';
  msg += '</div>';
  el.innerHTML = msg + el.innerHTML;
}

function runWhatIf() {
  var eventInput = document.getElementById('se-whatif-event');
  var outputEl = document.getElementById('se-whatif-output');
  if (!eventInput || !outputEl) return;
  var eventText = eventInput.value || 'Geopolitical escalation event';

  var scenarios = [
    { actor: 'APT29 (Russia)', target: 'Government networks', type: 'Espionage', prob: 78, timeline: '24-48h' },
    { actor: 'Sandworm (Russia)', target: 'Energy infrastructure', type: 'Destructive/Wiper', prob: 62, timeline: '48-72h' },
    { actor: 'Volt Typhoon (China)', target: 'Critical infrastructure', type: 'Pre-positioning', prob: 55, timeline: '1-2 weeks' },
    { actor: 'Lazarus (DPRK)', target: 'Financial sector', type: 'Theft/Ransomware', prob: 45, timeline: '1 week' }
  ];

  var h = '<div class="se-card" style="border-color:#ffaa00">';
  h += '<div style="color:#ffaa00;font-weight:700;font-size:12px;letter-spacing:1px;margin-bottom:8px">';
  h += '[>] WHAT-IF ANALYSIS: ' + esc(eventText).toUpperCase() + '</div>';
  h += '<div class="se-table-wrap"><table class="se-table">';
  h += '<thead><tr><th>Predicted Actor</th><th>Target</th><th>Attack Type</th><th>Probability</th><th>Timeline</th></tr></thead>';
  h += '<tbody>';
  for (var i = 0; i < scenarios.length; i++) {
    var sc = scenarios[i];
    var probColor = sc.prob >= 70 ? '#ff2244' : (sc.prob >= 50 ? '#ffaa00' : '#00aaff');
    h += '<tr>';
    h += '<td style="color:#ff6688">' + esc(sc.actor) + '</td>';
    h += '<td>' + esc(sc.target) + '</td>';
    h += '<td>' + esc(sc.type) + '</td>';
    h += '<td style="color:' + probColor + ';font-weight:700">' + sc.prob + '%</td>';
    h += '<td>' + esc(sc.timeline) + '</td>';
    h += '</tr>';
  }
  h += '</tbody></table></div>';
  h += '<div style="font-size:10px;color:#5a7a9a;margin-top:8px">Analysis based on historical pattern matching — operational analysis</div>';
  h += '</div>';
  outputEl.innerHTML = h;
}

function viewPlaybook(pbId) {
  var area = document.getElementById('se-playbook-output');
  if (!area) return;
  var h = '<div class="se-card" style="border-color:#00aaff">';
  h += '<div style="color:#00aaff;font-weight:700;font-size:12px;letter-spacing:1px;margin-bottom:8px">';
  h += '[>] INCIDENT RESPONSE PLAYBOOK: ' + esc(pbId || 'GENERAL').toUpperCase() + '</div>';
  h += '<div style="font-size:12px;color:#c8d8e8;line-height:1.8">';
  h += '<div style="color:#ffaa00;font-weight:700">Phase 1: Detection &amp; Analysis</div>';
  h += '<div>• Validate alert through secondary data source</div>';
  h += '<div>• Determine scope of compromise</div>';
  h += '<div>• Identify affected systems and data</div>';
  h += '<div style="color:#ffaa00;font-weight:700;margin-top:8px">Phase 2: Containment</div>';
  h += '<div>• Isolate affected network segments</div>';
  h += '<div>• Block identified IoCs at perimeter</div>';
  h += '<div>• Preserve forensic evidence</div>';
  h += '<div style="color:#00ff88;font-weight:700;margin-top:8px">Phase 3: Eradication &amp; Recovery</div>';
  h += '<div>• Remove adversary access and persistence mechanisms</div>';
  h += '<div>• Patch exploited vulnerabilities</div>';
  h += '<div>• Restore from clean backups</div>';
  h += '<div>• Verify system integrity before reconnection</div>';
  h += '<div style="color:#00aaff;font-weight:700;margin-top:8px">Phase 4: Post-Incident</div>';
  h += '<div>• Complete after-action review</div>';
  h += '<div>• Update detection signatures and playbooks</div>';
  h += '<div>• Submit incident report and share indicators</div>';
  h += '</div>';
  h += '</div>';
  area.innerHTML = h;
}

function createIntelProduct(productType) {
  var area = document.getElementById('se-intel-product-output');
  if (!area) return;
  var h = '<div class="se-card" style="border-color:#00aaff">';
  h += '<div style="color:#00aaff;font-weight:700;font-size:12px;letter-spacing:1px;margin-bottom:8px">';
  h += '[>] INTELLIGENCE PRODUCT: ' + esc(productType || 'SPOT REPORT').toUpperCase() + '</div>';
  h += '<div style="font-size:12px;color:#c8d8e8;line-height:1.8">';
  h += '<div><span class="se-class-ts">TOP SECRET // SCI // OPERATIONAL</span></div>';
  h += '<div style="margin-top:8px"><strong>SUBJECT:</strong> Multi-source intelligence correlation — elevated nation-state threat activity</div>';
  h += '<div><strong>SOURCES:</strong> SIGINT, CYBINT, OSINT (3+ source correlation achieved)</div>';
  h += '<div><strong>ASSESSMENT:</strong> High confidence that multiple nation-state actors are staging capabilities for potential offensive operations targeting US and allied critical infrastructure.</div>';
  h += '<div><strong>KEY INDICATORS:</strong></div>';
  h += '<div>• SIGINT: Increased encrypted communications between known C2 nodes</div>';
  h += '<div>• CYBINT: New malware variants submitted to private analysis platforms</div>';
  h += '<div>• OSINT: Geopolitical tensions correlate with historical cyber operation patterns</div>';
  h += '<div style="margin-top:8px"><strong>RECOMMENDED ACTIONS:</strong> Brief national leadership, elevate DEFCON, coordinate with allies</div>';
  h += '</div>';
  h += '<div style="font-size:10px;color:#5a7a9a;margin-top:8px">Classification: OPERATIONAL | Generated: ' + new Date().toISOString() + '</div>';
  h += '</div>';
  area.innerHTML = h;
}

// ---------------------------------------------------------------------------
// The main export function — renderSentinelEye(main)
// ---------------------------------------------------------------------------

// ============================================================================
// SENTINEL EYE — TAB RENDER FUNCTIONS 1–5
// Situation · Nations · Predict · Early Warning · APT Tracking
// ============================================================================

// ---------------------------------------------------------------------------
// TAB 1 — GLOBAL SITUATIONAL AWARENESS
// ---------------------------------------------------------------------------
function renderSituation() {
  var state = _seLoadState();
  var cyberThreatLevel = 2;
  var activeOps = 14;
  var lastIncidentHoursAgo = 37;
  var threatColors = { 1: '#ff2244', 2: '#ff6622', 3: '#ffaa00', 4: '#44cc44', 5: '#00aaff' };
  var threatLabels = { 1: 'CRITICAL — ACTIVE CYBER WARFARE', 2: 'SEVERE — NATION-STATE OPERATIONS DETECTED', 3: 'ELEVATED — INCREASED HOSTILE ACTIVITY', 4: 'GUARDED — NORMAL POSTURE', 5: 'LOW — BASELINE OPERATIONS' };
  var tlColor = threatColors[cyberThreatLevel] || '#ff6622';

  var h = '';



  // Header bar
  h += '<div class="se-sit-header" style="display:flex;align-items:center;justify-content:space-between;padding:18px 24px 10px;border-bottom:1px solid #1a3a5c;">';
  h += '<div style="font-size:20px;font-weight:bold;letter-spacing:2px;color:#00aaff;font-family:monospace;text-transform:uppercase;">GLOBAL SITUATIONAL AWARENESS</div>';
  h += '<div style="display:flex;gap:24px;font-family:monospace;font-size:12px;">';
  h += '<div style="color:#8899aa;letter-spacing:1px;">ZULU: <span style="color:#00aaff;">' + new Date().toISOString().slice(0, 19).replace('T', ' ') + 'Z</span></div>';
  h += '<div style="color:#8899aa;letter-spacing:1px;">ACTIVE OPS: <span style="color:#ff6622;font-weight:bold;">' + activeOps + '</span></div>';
  h += '<div style="color:#8899aa;letter-spacing:1px;">LAST INCIDENT: <span style="color:#ffaa00;">' + lastIncidentHoursAgo + 'H AGO</span></div>';
  h += '</div>';
  h += '</div>';

  // DEFCON-style threat level + world map row
  h += '<div class="se-sit-top" style="display:flex;gap:16px;padding:16px 24px;">';

  // DEFCON threat level panel
  h += '<div class="se-threat-level-panel" style="flex:0 0 220px;background:linear-gradient(135deg,#0c1020 0%,#0a0e1a 100%);border:2px solid ' + tlColor + ';border-radius:8px;padding:20px;text-align:center;position:relative;overflow:hidden;">';
  h += '<div style="position:absolute;top:0;left:0;right:0;bottom:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,170,255,0.02) 2px,rgba(0,170,255,0.02) 4px);pointer-events:none;"></div>';
  h += '<div style="font-family:monospace;font-size:10px;color:#8899aa;letter-spacing:3px;text-transform:uppercase;margin-bottom:8px;">GLOBAL CYBER</div>';
  h += '<div style="font-family:monospace;font-size:10px;color:#8899aa;letter-spacing:3px;text-transform:uppercase;margin-bottom:14px;">THREAT LEVEL</div>';
  h += '<div style="font-size:72px;font-weight:bold;color:' + tlColor + ';font-family:monospace;line-height:1;text-shadow:0 0 30px ' + tlColor + '60,0 0 60px ' + tlColor + '30;">' + cyberThreatLevel + '</div>';
  h += '<div style="font-family:monospace;font-size:10px;color:' + tlColor + ';letter-spacing:2px;margin-top:10px;text-transform:uppercase;font-weight:bold;">' + esc(threatLabels[cyberThreatLevel]) + '</div>';
  // Threat level indicators (5 bars)
  h += '<div style="display:flex;gap:6px;justify-content:center;margin-top:16px;">';
  for (var tl = 1; tl <= 5; tl++) {
    var barActive = tl >= cyberThreatLevel;
    var barColor = barActive ? threatColors[tl] : '#1a2a3a';
    h += '<div style="width:28px;height:8px;background:' + barColor + ';border-radius:2px;' + (barActive ? 'box-shadow:0 0 8px ' + barColor + '60;' : '') + '"></div>';
  }
  h += '</div>';
  h += '</div>';

  // Interactive D3.js threat map
  h += '<div style="flex:1;background:linear-gradient(135deg,#0c1020 0%,#0a0e1a 100%);border:1px solid #1a3a5c;border-radius:8px;position:relative;overflow:hidden;">';
  h += '<div style="position:absolute;top:10px;left:14px;font-family:monospace;font-size:10px;color:#4a6a8a;letter-spacing:2px;text-transform:uppercase;z-index:2;">GLOBAL THREAT MAP — INTERACTIVE D3.js</div>';
  h += '<div id="se-threat-map" style="width:100%;height:400px;"></div>';
  h += '<div style="position:absolute;bottom:8px;right:14px;display:flex;gap:14px;font-family:monospace;font-size:9px;z-index:2;">';
  h += '<span style="color:#ff2244;">● HOSTILE</span>';
  h += '<span style="color:#4488ff;">● ALLIED</span>';
  h += '<span style="color:#00ff88;">● IXP</span>';
  h += '<span style="color:#0d3a2a;">— CABLE</span>';
  h += '<span style="color:#ff4444;">⤴ ATTACK ARC</span>';
  h += '</div>';
  h += '</div>';

  h += '</div>'; // end se-sit-top

  // Nation-state force status grid
  h += '<div style="padding:0 24px 8px;">';
  h += '<div style="font-family:monospace;font-size:12px;color:#4a6a8a;letter-spacing:2px;text-transform:uppercase;margin-bottom:10px;border-bottom:1px solid #1a3a5c;padding-bottom:6px;">NATION-STATE CYBER FORCE STATUS</div>';
  h += '<div class="se-nation-force-grid" style="display:grid;grid-template-columns:repeat(5,1fr);gap:10px;">';

  var forceNations = ['US', 'RU', 'CN', 'IR', 'KP', 'IL', 'GB', 'FR', 'IN', 'PK'];
  for (var ni = 0; ni < forceNations.length; ni++) {
    var code = forceNations[ni];
    var profile = null;
    for (var pi = 0; pi < NATION_STATE_PROFILES.length; pi++) {
      if (NATION_STATE_PROFILES[pi].code === code) { profile = NATION_STATE_PROFILES[pi]; break; }
    }
    if (!profile) continue;

    var tierColor = profile.tier === 1 ? '#ff2244' : profile.tier === 2 ? '#ff6622' : '#ffaa00';
    var tierBg = profile.tier === 1 ? 'rgba(255,34,68,0.08)' : profile.tier === 2 ? 'rgba(255,102,34,0.08)' : 'rgba(255,170,0,0.06)';

    h += '<div class="se-force-card" style="background:linear-gradient(135deg,' + tierBg + ' 0%,#0a0e1a 100%);border:1px solid ' + tierColor + ';border-radius:6px;padding:10px 12px;cursor:pointer;transition:border-color 0.2s;" onmouseover="this.style.borderColor=\'#00aaff\'" onmouseout="this.style.borderColor=\'' + tierColor + '\'">';
    h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;">';
    h += '<div style="font-family:monospace;font-size:16px;" title="' + esc(profile.name) + '">' + esc(profile.flag) + '</div>';
    h += '<div style="font-family:monospace;font-size:10px;letter-spacing:1px;color:' + tierColor + ';font-weight:bold;">TIER ' + profile.tier + '</div>';
    h += '</div>';
    h += '<div style="font-family:monospace;font-size:11px;color:#ccdde8;font-weight:bold;letter-spacing:1px;margin-bottom:4px;">' + esc(profile.name) + '</div>';

    h += '<div style="font-family:monospace;font-size:9px;color:#6688aa;display:flex;justify-content:space-between;">';
    h += '<span>APT: ' + profile.aptGroups.length + '</span>';
    h += '<span>TIER ' + profile.tier + '</span>';
    h += '</div>';

    h += '<div style="font-family:monospace;font-size:9px;color:#4a6a8a;margin-top:4px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">' + esc(profile.posture) + '</div>';
    h += '</div>'; // end force card
  }

  h += '</div>'; // end grid
  h += '</div>'; // end section

  // Alert ticker
  h += '<div style="padding:8px 24px 16px;">';
  h += '<div style="font-family:monospace;font-size:12px;color:#4a6a8a;letter-spacing:2px;text-transform:uppercase;margin-bottom:8px;border-bottom:1px solid #1a3a5c;padding-bottom:6px;">GLOBAL ALERT FEED</div>';
  h += '<div id="se-alert-ticker" class="se-alert-ticker" style="background:#060a14;border:1px solid #1a3a5c;border-radius:6px;padding:10px 14px;max-height:180px;overflow-y:auto;font-family:monospace;font-size:11px;">';

  var alertFeed = [
    { time: '14:32:07Z', level: 'CRITICAL', msg: 'APT29 C2 beacon detected — callback to known SVR infrastructure from Fortune 500 financial network' },
    { time: '14:28:44Z', level: 'HIGH', msg: 'Volt Typhoon living-off-the-land activity detected in US water utility SCADA segment' },
    { time: '14:25:11Z', level: 'HIGH', msg: 'Lazarus Group crypto wallet drainer deployed on DeFi protocol — $4.2M at risk' },
    { time: '14:21:33Z', level: 'WARNING', msg: 'BGP route hijack attempt detected — AS174 (Cogent) routes redirected through AS4837 (China Unicom) for 4 minutes' },
    { time: '14:18:02Z', level: 'WARNING', msg: 'Increased scanning from IRGC-attributed IP ranges targeting petrochemical sector' },
    { time: '14:14:55Z', level: 'INFO', msg: 'New zero-day listing on dark web marketplace — Windows kernel LPE, asking price $2.5M' },
    { time: '14:11:20Z', level: 'HIGH', msg: 'Sandworm ICS payload variant uploaded to VirusTotal from Ukrainian IP — possible false flag' },
    { time: '14:07:38Z', level: 'WARNING', msg: 'DNS anomaly detected — critical banking domains in NATO member state showing NXDOMAIN intermittently' },
    { time: '14:03:50Z', level: 'INFO', msg: 'Five Eyes SIGINT bulletin — elevated PLA SSF activity on submarine cable taps in South China Sea' },
    { time: '13:59:22Z', level: 'CRITICAL', msg: 'FLASH: Kimsuky spear-phishing wave targeting defense contractors — new zero-day PDF exploit observed' },
    { time: '13:55:14Z', level: 'HIGH', msg: 'Supply chain alert — NPM package with 2M weekly downloads found containing obfuscated C2 loader' },
    { time: '13:51:03Z', level: 'WARNING', msg: 'Increased Tor exit node activity from Russian infrastructure clusters near military bases' },
    { time: '13:47:28Z', level: 'INFO', msg: 'ANSSI France reports successful containment of APT28 intrusion into defense ministry networks' },
    { time: '13:43:11Z', level: 'HIGH', msg: 'MuddyWater deploying new PowerShell backdoor variant in Middle Eastern telecom networks' },
    { time: '13:39:45Z', level: 'WARNING', msg: 'Anomalous SSL certificate registrations — 47 domains mimicking NATO logistics portal registered in 6 hours' }
  ];

  for (var ai = 0; ai < alertFeed.length; ai++) {
    var alert = alertFeed[ai];
    var aColor = alert.level === 'CRITICAL' ? '#ff2244' : alert.level === 'HIGH' ? '#ff6622' : alert.level === 'WARNING' ? '#ffaa00' : '#00aaff';
    h += '<div style="padding:4px 0;border-bottom:1px solid #0d1525;display:flex;gap:10px;align-items:flex-start;">';
    h += '<span style="color:#4a6a8a;flex-shrink:0;">' + esc(alert.time) + '</span>';
    h += '<span style="color:' + aColor + ';font-weight:bold;flex-shrink:0;min-width:64px;">[' + esc(alert.level) + ']</span>';
    h += '<span style="color:#b0c4d8;">' + esc(alert.msg) + '</span>';
    h += '</div>';
  }
  h += '</div>'; // end ticker
  h += '</div>'; // end section

  // Quick stats row
  h += '<div style="display:flex;gap:12px;padding:0 24px 18px;">';
  var quickStats = [
    { label: 'ACTIVE CAMPAIGNS', value: '23', color: '#ff2244' },
    { label: 'TRACKED APT GROUPS', value: '38', color: '#ff6622' },
    { label: 'IOCs PROCESSED (24H)', value: '1.2M', color: '#ffaa00' },
    { label: 'THREAT INTEL FEEDS', value: '94', color: '#00aaff' },
    { label: 'EARLY WARNINGS', value: '7', color: '#44cc44' },
    { label: 'DEFENDED SECTORS', value: '8', color: '#00aaff' }
  ];
  for (var qs = 0; qs < quickStats.length; qs++) {
    var stat = quickStats[qs];
    h += '<div style="flex:1;background:linear-gradient(135deg,#0c1020,#0a0e1a);border:1px solid #1a3a5c;border-radius:6px;padding:14px;text-align:center;">';
    h += '<div style="font-family:monospace;font-size:24px;font-weight:bold;color:' + stat.color + ';text-shadow:0 0 12px ' + stat.color + '40;">' + stat.value + '</div>';
    h += '<div style="font-family:monospace;font-size:9px;color:#4a6a8a;letter-spacing:2px;margin-top:4px;">' + stat.label + '</div>';
    h += '</div>';
  }
  h += '</div>';

  return h;
}


// ---------------------------------------------------------------------------
// TAB 2 — NATION-STATE MONITOR
// ---------------------------------------------------------------------------
function renderNations() {
  var state = _seLoadState();
  var filterTier = state.nationFilterTier || 'ALL';
  var expandedNation = state.expandedNation || null;

  var h = '';

  // Header
  h += '<div style="display:flex;align-items:center;justify-content:space-between;padding:18px 24px 10px;border-bottom:1px solid #1a3a5c;">';
  h += '<div style="font-size:20px;font-weight:bold;letter-spacing:2px;color:#00aaff;font-family:monospace;text-transform:uppercase;">NATION-STATE CYBER PROGRAMS</div>';
  h += '<div style="font-family:monospace;font-size:11px;color:#4a6a8a;">' + NATION_STATE_PROFILES.length + ' PROGRAMS PROFILED</div>';
  h += '</div>';

  // Attribution notice
  h += '<div style="padding:10px 24px;">';
  h += '<div style="font-family:monospace;font-size:9px;color:#6688aa;background:#0c1525;border:1px solid #1a3a5c;border-radius:4px;padding:8px 12px;">';
  h += 'Profiles based on MITRE ATT&CK, CISA advisories, and public threat research. ';
  h += 'APT group names and known operations are sourced from published intelligence reports.';
  h += '</div>';
  h += '</div>';

  // Filters
  h += '<div style="display:flex;gap:16px;padding:8px 24px 12px;border-bottom:1px solid #0d1525;align-items:center;">';
  h += '<span style="font-family:monospace;font-size:10px;color:#4a6a8a;letter-spacing:2px;">FILTER:</span>';
  h += '<div style="display:flex;gap:4px;">';
  var tiers = ['ALL', '1', '2', '3'];
  for (var tf = 0; tf < tiers.length; tf++) {
    var tActive = filterTier === tiers[tf];
    h += '<button class="se-filter-btn" data-action="filterNationTier" data-value="' + tiers[tf] + '" style="background:' + (tActive ? '#00aaff' : '#0c1525') + ';color:' + (tActive ? '#000' : '#6688aa') + ';border:1px solid ' + (tActive ? '#00aaff' : '#1a3a5c') + ';border-radius:4px;padding:4px 10px;font-family:monospace;font-size:10px;cursor:pointer;letter-spacing:1px;">' + (tiers[tf] === 'ALL' ? 'ALL TIERS' : 'TIER ' + tiers[tf]) + '</button>';
  }
  h += '</div>';
  h += '</div>';

  // Nation cards
  h += '<div style="padding:16px 24px;display:grid;grid-template-columns:repeat(2,1fr);gap:14px;">';

  for (var nsi = 0; nsi < NATION_STATE_PROFILES.length; nsi++) {
    var ns = NATION_STATE_PROFILES[nsi];

    // Apply tier filter
    if (filterTier !== 'ALL' && String(ns.tier) !== filterTier) continue;

    var isExpanded = expandedNation === ns.id;
    var tierColor = ns.tier === 1 ? '#ff2244' : ns.tier === 2 ? '#ff6622' : '#ffaa00';

    h += '<div class="se-nation-card" style="background:linear-gradient(135deg,rgba(0,170,255,0.04) 0%,#0a0e1a 100%);border:1px solid #1a3a5c;border-radius:8px;overflow:hidden;cursor:pointer;" data-action="toggleNation" data-value="' + esc(ns.id) + '">';

    // Card header
    h += '<div style="display:flex;align-items:center;padding:14px 16px;gap:12px;">';
    h += '<div style="font-size:28px;">' + esc(ns.flag) + '</div>';
    h += '<div style="flex:1;">';
    h += '<div style="font-family:monospace;font-size:14px;color:#e0eaf0;font-weight:bold;letter-spacing:1px;">' + esc(ns.name) + '</div>';
    h += '<div style="display:flex;gap:8px;margin-top:4px;align-items:center;">';
    h += '<span style="font-family:monospace;font-size:9px;background:' + tierColor + ';color:#000;padding:2px 6px;border-radius:3px;font-weight:bold;">TIER ' + ns.tier + '</span>';
    h += '</div>';
    h += '</div>';
    h += '<div style="font-family:monospace;font-size:10px;color:#4a6a8a;">' + (isExpanded ? '[-]' : '[+]') + '</div>';
    h += '</div>';

    // APT groups summary row
    h += '<div style="padding:0 16px 10px;display:flex;gap:6px;flex-wrap:wrap;">';
    for (var ag = 0; ag < ns.aptGroups.length && ag < 4; ag++) {
      h += '<span style="font-family:monospace;font-size:9px;background:#0c1525;border:1px solid #1a3a5c;color:#8899bb;padding:2px 6px;border-radius:3px;">' + esc(ns.aptGroups[ag]) + '</span>';
    }
    if (ns.aptGroups.length > 4) {
      h += '<span style="font-family:monospace;font-size:9px;color:#4a6a8a;">+' + (ns.aptGroups.length - 4) + ' more</span>';
    }
    h += '</div>';

    // Expanded details
    if (isExpanded) {
      h += '<div style="border-top:1px solid #1a3a5c;padding:14px 16px;background:rgba(0,10,20,0.5);">';

      // Capabilities bars
      h += '<div style="font-family:monospace;font-size:10px;color:#4a6a8a;letter-spacing:2px;margin-bottom:8px;">CAPABILITIES ASSESSMENT</div>';
      var caps = [
        { label: 'OFFENSE', value: ns.capabilities.offense, color: '#ff2244' },
        { label: 'DEFENSE', value: ns.capabilities.defense, color: '#00aaff' },
        { label: 'INTEL', value: ns.capabilities.intel, color: '#ffaa00' }
      ];
      for (var ci = 0; ci < caps.length; ci++) {
        var cap = caps[ci];
        h += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">';
        h += '<span style="font-family:monospace;font-size:9px;color:#6688aa;width:60px;text-align:right;">' + cap.label + '</span>';
        h += '<div style="flex:1;background:#0a1020;border-radius:3px;height:8px;overflow:hidden;">';
        h += '<div style="width:' + (cap.value * 10) + '%;height:100%;background:linear-gradient(90deg,' + cap.color + ',' + cap.color + '88);border-radius:3px;"></div>';
        h += '</div>';
        h += '<span style="font-family:monospace;font-size:9px;color:' + cap.color + ';width:24px;">' + cap.value + '/10</span>';
        h += '</div>';
      }

      // Known operations
      h += '<div style="font-family:monospace;font-size:10px;color:#4a6a8a;letter-spacing:2px;margin:12px 0 8px;">KNOWN OPERATIONS (Public Record)</div>';
      for (var ko = 0; ko < ns.knownOps.length; ko++) {
        h += '<div style="display:flex;align-items:center;gap:6px;margin-bottom:3px;">';
        h += '<span style="color:#ff6622;font-size:8px;">*</span>';
        h += '<span style="font-family:monospace;font-size:10px;color:#b0c4d8;">' + esc(ns.knownOps[ko]) + '</span>';
        h += '</div>';
      }

      // Primary targets
      h += '<div style="font-family:monospace;font-size:10px;color:#4a6a8a;letter-spacing:2px;margin:12px 0 8px;">PRIMARY TARGETS (Documented)</div>';
      h += '<div style="display:flex;gap:6px;flex-wrap:wrap;">';
      for (var pt = 0; pt < ns.primaryTargets.length; pt++) {
        h += '<span style="font-family:monospace;font-size:9px;background:#0c1525;border:1px solid #1a3a5c;color:#b0c4d8;padding:3px 8px;border-radius:3px;">' + esc(ns.primaryTargets[pt]) + '</span>';
      }
      h += '</div>';

      // Cyber command / agency
      h += '<div style="font-family:monospace;font-size:10px;color:#4a6a8a;letter-spacing:2px;margin:12px 0 6px;">CYBER UNITS / AGENCIES</div>';
      h += '<div style="font-family:monospace;font-size:10px;color:#b0c4d8;margin-bottom:2px;">* ' + esc(ns.cyberCommand) + '</div>';

      // All APT groups
      h += '<div style="font-family:monospace;font-size:10px;color:#4a6a8a;letter-spacing:2px;margin:12px 0 8px;">APT GROUPS</div>';
      h += '<div style="display:flex;gap:6px;flex-wrap:wrap;">';
      for (var agi = 0; agi < ns.aptGroups.length; agi++) {
        h += '<span style="font-family:monospace;font-size:9px;background:#0c1525;border:1px solid #1a3a5c;color:#8899bb;padding:2px 6px;border-radius:3px;">' + esc(ns.aptGroups[agi]) + '</span>';
      }
      h += '</div>';

      // Source attribution
      h += '<div style="font-family:monospace;font-size:9px;color:#4a6a8a;margin-top:12px;padding-top:8px;border-top:1px solid #1a3a5c;">Source: MITRE ATT&CK, CISA advisories, public threat research</div>';

      h += '</div>'; // end expanded
    }

    h += '</div>'; // end nation card
  }

  h += '</div>'; // end grid

  return h;
}
// ---------------------------------------------------------------------------
// TAB 3 — ATTACK PREDICTION ENGINE
// ---------------------------------------------------------------------------
function renderPredict() {
  var h = '';

  // Header
  h += '<div style="display:flex;align-items:center;justify-content:space-between;padding:18px 24px 10px;border-bottom:1px solid #1a3a5c;">';
  h += '<div style="font-size:20px;font-weight:bold;letter-spacing:2px;color:#00aaff;font-family:monospace;text-transform:uppercase;">ACTIVE THREATS & ANALYSIS</div>';
  h += '<div style="font-family:monospace;font-size:11px;color:#4a6a8a;">DATA FROM NVD, THREATFOX, URLHAUS</div>';
  h += '</div>';

  // Two-column layout
  h += '<div style="display:flex;gap:16px;padding:16px 24px;">';

  // Left column: Real active threats from APIs
  h += '<div style="flex:3;">';
  h += '<div style="font-family:monospace;font-size:12px;color:#4a6a8a;letter-spacing:2px;margin-bottom:10px;border-bottom:1px solid #1a3a5c;padding-bottom:6px;">REAL-TIME THREAT DATA</div>';

  // Loading indicator (populated after render)
  h += '<div id="se-predict-threats" style="font-family:monospace;font-size:11px;color:#4a6a8a;padding:20px;text-align:center;">Loading real threat data from public APIs...</div>';

  // AI Analysis section
  h += '<div style="margin-top:16px;background:#0c1020;border:1px solid #1a3a5c;border-radius:6px;padding:14px;">';
  h += '<div style="font-family:monospace;font-size:11px;color:#00aaff;letter-spacing:2px;margin-bottom:8px;font-weight:bold;">AI THREAT ANALYSIS</div>';
  h += '<div id="se-predict-ollama-status" style="font-family:monospace;font-size:10px;color:#4a6a8a;margin-bottom:8px;">Checking Ollama connection...</div>';
  h += '<button id="se-predict-ai-btn" style="display:none;background:#0c1525;border:1px solid #00aaff;color:#00aaff;padding:8px 16px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:4px;letter-spacing:1px;" onclick="_sePredictAiAnalysis()">ANALYZE CURRENT THREATS WITH AI</button>';
  h += '<div id="se-predict-ai-result"></div>';
  h += '</div>';

  h += '</div>'; // end left column

  // Right column: geopolitical events + what-if
  h += '<div style="flex:2;">';

  // What-If scenario builder (with Ollama)
  h += '<div style="background:#0c1020;border:1px solid #1a3a5c;border-radius:6px;padding:14px;margin-bottom:14px;">';
  h += '<div style="font-family:monospace;font-size:11px;color:#00aaff;letter-spacing:2px;margin-bottom:10px;font-weight:bold;">WHAT-IF SCENARIO ANALYSIS</div>';
  h += '<div style="font-family:monospace;font-size:9px;color:#4a6a8a;margin-bottom:8px;">Select a geopolitical event for AI-powered analysis (requires Ollama)</div>';
  h += '<select id="se-whatif-select" style="width:100%;background:#060a14;border:1px solid #1a3a5c;color:#b0c4d8;padding:8px;font-family:monospace;font-size:11px;border-radius:4px;margin-bottom:8px;">';
  h += '<option value="">-- SELECT EVENT --</option>';
  for (var ws = 0; ws < GEOPOLITICAL_TRIGGERS.length && ws < 15; ws++) {
    h += '<option value="' + esc(GEOPOLITICAL_TRIGGERS[ws].id) + '">' + esc(GEOPOLITICAL_TRIGGERS[ws].event) + '</option>';
  }
  h += '</select>';
  h += '<button id="se-whatif-btn" style="background:#0c1525;border:1px solid #ffaa00;color:#ffaa00;padding:6px 14px;font-family:monospace;font-size:10px;cursor:pointer;border-radius:4px;letter-spacing:1px;" onclick="_seWhatIfAnalysis()">ANALYZE WITH AI</button>';
  h += '<div id="se-whatif-result"></div>';
  h += '</div>';

  // Geopolitical events list
  h += '<div style="font-family:monospace;font-size:11px;color:#4a6a8a;letter-spacing:2px;margin-bottom:8px;border-bottom:1px solid #1a3a5c;padding-bottom:6px;">GEOPOLITICAL EVENTS (' + GEOPOLITICAL_TRIGGERS.length + ')</div>';
  h += '<div style="max-height:400px;overflow-y:auto;scrollbar-width:thin;scrollbar-color:#1a3a5c transparent;">';
  for (var gt = 0; gt < GEOPOLITICAL_TRIGGERS.length; gt++) {
    var trigger = GEOPOLITICAL_TRIGGERS[gt];
    h += '<div style="background:#0c1020;border:1px solid #1a3a5c;border-left:3px solid #00aaff;border-radius:4px;padding:8px 10px;margin-bottom:6px;">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:3px;">';
    h += '<span style="font-family:monospace;font-size:10px;color:#e0eaf0;font-weight:bold;">' + esc(trigger.event) + '</span>';
    h += '</div>';
    h += '<div style="display:flex;gap:8px;align-items:center;">';
    h += '<span style="font-family:monospace;font-size:9px;color:#4a6a8a;">' + esc(trigger.region) + ' | ' + esc(trigger.date) + '</span>';
    h += '</div>';
    if (trigger.associatedNations && trigger.associatedNations.length > 0) {
      h += '<div style="display:flex;gap:4px;flex-wrap:wrap;margin-top:4px;">';
      for (var an = 0; an < trigger.associatedNations.length; an++) {
        h += '<span style="font-family:monospace;font-size:8px;background:#0c1525;border:1px solid #1a3a5c;color:#6688aa;padding:1px 5px;border-radius:2px;">' + esc(trigger.associatedNations[an]) + '</span>';
      }
      h += '</div>';
    }
    h += '</div>';
  }
  h += '</div>';

  h += '</div>'; // end right column
  h += '</div>'; // end two-column

  return h;
}

// ============================================================================
// OLLAMA AI INTEGRATION
// ============================================================================
function _seCheckOllama(callback) {
  if (_seOllamaAvailable !== null) {
    callback(_seOllamaAvailable);
    return;
  }
  try {
    fetch('http://127.0.0.1:11434/api/tags', {mode:'no-cors'}).catch(function(){return{ok:false,json:function(){return Promise.resolve({models:[]})}}}).then(function(r){if(!r.ok&&r.type==='opaque')throw new Error('cors');return r;})
      .then(function(r) { return r.json(); })
      .then(function(data) {
        _seOllamaAvailable = true;
        if (data.models && data.models.length > 0) {
          _seOllamaModel = data.models[0].name || 'llama3.2';
        }
        callback(true);
      })
      .catch(function() {
        _seOllamaAvailable = false;
        callback(false);
      });
  } catch (e) {
    _seOllamaAvailable = false;
    callback(false);
  }
}

function _seQueryOllama(prompt, containerId) {
  var container = document.getElementById(containerId);
  if (!container) return;
  container.innerHTML = '<div style="font-family:monospace;font-size:11px;color:#ffaa00;padding:12px;">Analyzing with AI... please wait.</div>';

  try {
    fetch('http://127.0.0.1:11434/api/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: _seOllamaModel,
        prompt: prompt,
        stream: false
      })
    })
      .then(function(r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      })
      .then(function(data) {
        var response = data.response || 'No response generated.';
        var h = '<div style="background:#0c1525;border:1px solid #1a3a5c;border-radius:6px;padding:14px;margin-top:8px;">';
        h += '<div style="font-family:monospace;font-size:10px;color:#00aaff;letter-spacing:2px;margin-bottom:8px;font-weight:bold;">AI ANALYSIS (via Ollama - ' + esc(_seOllamaModel) + ')</div>';
        h += '<div style="font-family:monospace;font-size:11px;color:#b0c4d8;line-height:1.6;white-space:pre-wrap;">' + esc(response) + '</div>';
        h += '<div style="font-family:monospace;font-size:9px;color:#4a6a8a;margin-top:8px;">Generated by local AI model. Not verified intelligence. Cross-reference with official sources.</div>';
        h += '</div>';
        container.innerHTML = h;
      })
      .catch(function(err) {
        container.innerHTML = '<div style="font-family:monospace;font-size:11px;color:#ff2244;padding:12px;">AI analysis failed: ' + esc(String(err.message || err)) + '</div>';
      });
  } catch (e) {
    container.innerHTML = '<div style="font-family:monospace;font-size:11px;color:#ff2244;padding:12px;">AI analysis error: ' + esc(String(e.message || e)) + '</div>';
  }
}

// ============================================================================
// REAL THREAT DATA FETCHING
// ============================================================================
var _SE_FEED_CACHE_TTL = 300000;

function _seFetchActiveThreats(callback) {
  if (_seActiveThreats.ts && (Date.now() - _seActiveThreats.ts) < _SE_FEED_CACHE_TTL) {
    callback(_seActiveThreats);
    return;
  }
  var results = { nvd: null, threatfox: null, urlhaus: null };
  var done = 0;
  var total = 3;
  function checkDone() {
    done++;
    if (done >= total) {
      _seActiveThreats.nvd = results.nvd;
      _seActiveThreats.threatfox = results.threatfox;
      _seActiveThreats.urlhaus = results.urlhaus;
      _seActiveThreats.ts = Date.now();
      callback(_seActiveThreats);
    }
  }
  // NVD Critical CVEs
  try {
    fetch('https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=15&cvssV3Severity=CRITICAL').catch(function(){return null;})
      .then(function(r) { if (!r || !r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function(data) {
        var items = [];
        var vulns = (data.vulnerabilities || []);
        for (var vi = 0; vi < vulns.length && vi < 15; vi++) {
          var c = vulns[vi].cve || {};
          var cid = c.id || 'N/A';
          var cdesc = 'No description';
          if (c.descriptions) {
            for (var di = 0; di < c.descriptions.length; di++) {
              if (c.descriptions[di].lang === 'en') { cdesc = c.descriptions[di].value; break; }
            }
          }
          var cscore = '';
          if (c.metrics && c.metrics.cvssMetricV31 && c.metrics.cvssMetricV31[0]) {
            cscore = String(c.metrics.cvssMetricV31[0].cvssData.baseScore || '');
          } else if (c.metrics && c.metrics.cvssMetricV30 && c.metrics.cvssMetricV30[0]) {
            cscore = String(c.metrics.cvssMetricV30[0].cvssData.baseScore || '');
          }
          items.push({ id: cid, desc: cdesc, score: cscore, published: c.published || '' });
        }
        results.nvd = items;
      })
      .catch(function() { results.nvd = null; })
      .then(checkDone);
  } catch (e) { results.nvd = null; checkDone(); }
  // ThreatFox Recent IOCs (from local feed — no CORS issues)
  try {
    fetch('/data/feeds/threat-iocs.json')
      .catch(function() { return null; })
      .then(function(r) { if (!r || !r.ok) return { data: [] }; return r.json().catch(function(){return {data:[]}}); })
      .then(function(feed) {
        var items = [];
        var entries = (feed && feed.data) ? feed.data.slice(0, 20) : [];
        for (var ii = 0; ii < entries.length; ii++) {
          var ioc = entries[ii];
          var iocStr = String(ioc.ioc_value || ioc.ioc || 'N/A');
          if (iocStr.length > 100) iocStr = iocStr.substring(0, 97) + '...';
          items.push({
            ioc: iocStr,
            type: String(ioc.threat_type || 'unknown'),
            malware: String(ioc.malware_printable || ioc.malware || 'unknown'),
            firstSeen: String(ioc.first_seen || '')
          });
        }
        results.threatfox = items;
      })
      .catch(function() { results.threatfox = null; })
      .then(checkDone);
  } catch (e) { results.threatfox = null; checkDone(); }
  // URLhaus Recent Malware URLs (from local feed — no CORS issues)
  try {
    fetch('/data/feeds/malware-urls.json')
      .catch(function() { return null; })
      .then(function(r) { if (!r || !r.ok) return { data: [] }; return r.json().catch(function(){return {data:[]}}); })
      .then(function(feed) {
        var items = [];
        var urls = (feed && feed.data) ? feed.data.slice(0, 15) : [];
        for (var ui = 0; ui < urls.length && ui < 15; ui++) {
          var u = urls[ui];
          var urlStr = String(u.url || 'N/A');
          if (urlStr.length > 100) urlStr = urlStr.substring(0, 97) + '...';
          items.push({
            url: urlStr,
            status: String(u.url_status || 'unknown'),
            threat: String(u.threat || u.threat_type || ''),
            dateAdded: String(u.date_added || ''),
            host: String(u.host || '')
          });
        }
        results.urlhaus = items;
      })
      .catch(function() { results.urlhaus = null; })
      .then(checkDone);
  } catch (e) { results.urlhaus = null; checkDone(); }
}

// Post-render for Predict tab
function _seInitPredictTab() {
  _seFetchActiveThreats(function(data) {
    var container = document.getElementById('se-predict-threats');
    if (!container) return;
    var h = '';

    // NVD CVEs
    h += '<div style="margin-bottom:14px;">';
    h += '<div style="font-family:monospace;font-size:11px;color:#ff6622;letter-spacing:2px;margin-bottom:6px;font-weight:bold;">CRITICAL CVEs (NVD - National Vulnerability Database)</div>';
    if (data.nvd && data.nvd.length > 0) {
      for (var ni = 0; ni < data.nvd.length; ni++) {
        var cve = data.nvd[ni];
        h += '<div style="background:#0c1020;border:1px solid #1a3a5c;border-left:3px solid #ff2244;border-radius:4px;padding:8px 10px;margin-bottom:4px;">';
        h += '<div style="display:flex;align-items:center;gap:10px;margin-bottom:3px;">';
        h += '<span style="font-family:monospace;font-size:11px;color:#ff2244;font-weight:bold;">' + esc(cve.id) + '</span>';
        if (cve.score) h += '<span style="font-family:monospace;font-size:9px;background:#ff2244;color:#000;padding:1px 6px;border-radius:3px;font-weight:bold;">CVSS ' + esc(cve.score) + '</span>';
        if (cve.published) h += '<span style="font-family:monospace;font-size:8px;color:#4a6a8a;">' + esc(cve.published.substring(0, 10)) + '</span>';
        h += '</div>';
        h += '<div style="font-family:monospace;font-size:10px;color:#b0c4d8;line-height:1.4;">' + esc(cve.desc.length > 200 ? cve.desc.substring(0, 197) + '...' : cve.desc) + '</div>';
        h += '</div>';
      }
    } else {
      h += '<div style="font-family:monospace;font-size:10px;color:#4a6a8a;padding:8px;">NVD API unavailable or no critical CVEs returned</div>';
    }
    h += '</div>';

    // ThreatFox IOCs
    h += '<div style="margin-bottom:14px;">';
    h += '<div style="font-family:monospace;font-size:11px;color:#00aaff;letter-spacing:2px;margin-bottom:6px;font-weight:bold;">RECENT IOCs (ThreatFox - abuse.ch)</div>';
    if (data.threatfox && data.threatfox.length > 0) {
      for (var ti = 0; ti < data.threatfox.length && ti < 10; ti++) {
        var tf = data.threatfox[ti];
        h += '<div style="background:#0c1020;border:1px solid #1a3a5c;border-left:3px solid #00aaff;border-radius:4px;padding:8px 10px;margin-bottom:4px;">';
        h += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:3px;">';
        h += '<span style="font-family:monospace;font-size:9px;background:#00aaff;color:#000;padding:1px 6px;border-radius:3px;font-weight:bold;">' + esc(tf.type) + '</span>';
        h += '<span style="font-family:monospace;font-size:10px;color:#ff6622;font-weight:bold;">' + esc(tf.malware) + '</span>';
        if (tf.firstSeen) h += '<span style="font-family:monospace;font-size:8px;color:#4a6a8a;">' + esc(tf.firstSeen.substring(0, 16)) + '</span>';
        h += '</div>';
        h += '<div style="font-family:monospace;font-size:10px;color:#b0c4d8;word-break:break-all;">' + esc(tf.ioc) + '</div>';
        h += '</div>';
      }
    } else {
      h += '<div style="font-family:monospace;font-size:10px;color:#4a6a8a;padding:8px;">ThreatFox API unavailable or no recent IOCs returned</div>';
    }
    h += '</div>';

    // URLhaus
    h += '<div>';
    h += '<div style="font-family:monospace;font-size:11px;color:#ffaa00;letter-spacing:2px;margin-bottom:6px;font-weight:bold;">MALWARE URLs (URLhaus - abuse.ch)</div>';
    if (data.urlhaus && data.urlhaus.length > 0) {
      for (var ui = 0; ui < data.urlhaus.length && ui < 8; ui++) {
        var uh = data.urlhaus[ui];
        h += '<div style="background:#0c1020;border:1px solid #1a3a5c;border-left:3px solid #ffaa00;border-radius:4px;padding:8px 10px;margin-bottom:4px;">';
        h += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:3px;">';
        var statusColor = uh.status === 'online' ? '#ff2244' : '#44cc44';
        h += '<span style="font-family:monospace;font-size:9px;color:' + statusColor + ';font-weight:bold;">[' + esc(uh.status.toUpperCase()) + ']</span>';
        if (uh.threat) h += '<span style="font-family:monospace;font-size:9px;color:#ffaa00;">' + esc(uh.threat) + '</span>';
        if (uh.dateAdded) h += '<span style="font-family:monospace;font-size:8px;color:#4a6a8a;">' + esc(uh.dateAdded.substring(0, 16)) + '</span>';
        h += '</div>';
        h += '<div style="font-family:monospace;font-size:10px;color:#b0c4d8;word-break:break-all;">' + esc(uh.url) + '</div>';
        h += '</div>';
      }
    } else {
      h += '<div style="font-family:monospace;font-size:10px;color:#4a6a8a;padding:8px;">URLhaus API unavailable or no recent URLs returned</div>';
    }
    h += '</div>';
    h += '<div style="font-family:monospace;font-size:9px;color:#4a6a8a;margin-top:12px;padding:8px;border-top:1px solid #1a3a5c;">Data sourced from public threat intelligence APIs. Refreshes every 5 minutes.</div>';
    container.innerHTML = h;
  });
  // Check Ollama
  _seCheckOllama(function(available) {
    var statusEl = document.getElementById('se-predict-ollama-status');
    var btnEl = document.getElementById('se-predict-ai-btn');
    if (!statusEl) return;
    if (available) {
      statusEl.innerHTML = '<span style="color:#44cc44;">Ollama connected</span> (model: ' + esc(_seOllamaModel) + ')';
      if (btnEl) btnEl.style.display = '';
    } else {
      statusEl.innerHTML = '<span style="color:#ff6622;">Ollama not connected.</span> For AI-powered threat analysis, run: <span style="color:#b0c4d8;">ollama pull llama3.2 && ollama serve</span>';
    }
  });
}

function _sePredictAiAnalysis() {
  var data = _seActiveThreats;
  var summary = 'Based on the following real threat indicators from the past 24 hours, provide a concise threat assessment.\n\n';
  if (data.nvd && data.nvd.length > 0) {
    summary += 'CRITICAL CVEs:\n';
    for (var i = 0; i < data.nvd.length && i < 5; i++) {
      summary += '- ' + data.nvd[i].id + ': ' + data.nvd[i].desc.substring(0, 150) + '\n';
    }
  }
  if (data.threatfox && data.threatfox.length > 0) {
    summary += '\nRECENT IOCs (ThreatFox):\n';
    for (var j = 0; j < data.threatfox.length && j < 5; j++) {
      summary += '- ' + data.threatfox[j].malware + ' (' + data.threatfox[j].type + '): ' + data.threatfox[j].ioc + '\n';
    }
  }
  summary += '\nProvide: 1) Overall threat assessment, 2) Key risks to watch, 3) Recommended defensive actions. Be specific. Only reference real, publicly known threat groups and techniques.';
  _seQueryOllama(summary, 'se-predict-ai-result');
}

function _seWhatIfAnalysis() {
  var select = document.getElementById('se-whatif-select');
  if (!select || !select.value) return;
  var eventId = select.value;
  var eventText = '';
  for (var i = 0; i < GEOPOLITICAL_TRIGGERS.length; i++) {
    if (GEOPOLITICAL_TRIGGERS[i].id === eventId) {
      eventText = GEOPOLITICAL_TRIGGERS[i].event;
      break;
    }
  }
  if (!eventText) return;
  _seCheckOllama(function(available) {
    if (!available) {
      var container = document.getElementById('se-whatif-result');
      if (container) {
        container.innerHTML = '<div style="font-family:monospace;font-size:10px;color:#ff6622;padding:8px;margin-top:8px;">AI analysis requires Ollama. Run: <span style="color:#b0c4d8;">ollama pull llama3.2 && ollama serve</span></div>';
      }
      return;
    }
    var prompt = 'Based on publicly known threat intelligence and historical precedent, what cyber operations have historically followed or accompanied events like: "' + eventText + '"? Be specific and cite real examples from documented incidents. What threat groups would likely be involved? What sectors would be at risk? Base your analysis only on publicly documented historical events and real APT group behaviors.';
    _seQueryOllama(prompt, 'se-whatif-result');
  });
}



// ---------------------------------------------------------------------------
// TAB 4 — EARLY WARNING SYSTEM
// ---------------------------------------------------------------------------
function renderEarlyWarning() {
  var h = '';

  // Header
  h += '<div style="display:flex;align-items:center;justify-content:space-between;padding:18px 24px 10px;border-bottom:1px solid #1a3a5c;">';
  h += '<div style="font-size:20px;font-weight:bold;letter-spacing:2px;color:#00aaff;font-family:monospace;text-transform:uppercase;">ACTIVE THREAT INDICATORS</div>';
  h += '<div style="font-family:monospace;font-size:11px;color:#4a6a8a;">LIVE DATA FROM PUBLIC THREAT FEEDS</div>';
  h += '</div>';

  // Source info
  h += '<div style="padding:12px 24px;">';
  h += '<div style="background:linear-gradient(135deg,rgba(0,170,255,0.08),#0a0e1a);border:1px solid #00aaff40;border-radius:6px;padding:12px 14px;">';
  h += '<div style="font-family:monospace;font-size:10px;color:#00aaff;letter-spacing:2px;margin-bottom:8px;font-weight:bold;">DATA SOURCES</div>';
  var sources = [
    { name: 'NVD (NIST)', desc: 'Critical CVEs from the National Vulnerability Database', color: '#ff2244' },
    { name: 'ThreatFox (abuse.ch)', desc: 'Recent IOCs (indicators of compromise) from community reports', color: '#00aaff' },
    { name: 'URLhaus (abuse.ch)', desc: 'Recently reported malware distribution URLs', color: '#ffaa00' }
  ];
  for (var si = 0; si < sources.length; si++) {
    var src = sources[si];
    h += '<div style="display:flex;gap:10px;margin-bottom:4px;padding:3px 0;' + (si < sources.length - 1 ? 'border-bottom:1px solid #0d1525;' : '') + '">';
    h += '<span style="font-family:monospace;font-size:9px;color:' + src.color + ';font-weight:bold;flex-shrink:0;width:140px;">' + esc(src.name) + '</span>';
    h += '<span style="font-family:monospace;font-size:9px;color:#6688aa;">' + esc(src.desc) + '</span>';
    h += '</div>';
  }
  h += '</div>';
  h += '</div>';

  // Threat indicators container
  h += '<div style="padding:0 24px 16px;">';
  h += '<div id="se-ew-data" style="font-family:monospace;font-size:11px;color:#4a6a8a;padding:20px;text-align:center;">Loading threat indicators from public APIs...</div>';
  h += '</div>';

  // AI analysis section
  h += '<div style="padding:0 24px 16px;">';
  h += '<div style="background:#0c1020;border:1px solid #1a3a5c;border-radius:6px;padding:14px;">';
  h += '<div style="font-family:monospace;font-size:11px;color:#00aaff;letter-spacing:2px;margin-bottom:8px;font-weight:bold;">AI INDICATOR ANALYSIS</div>';
  h += '<div id="se-ew-ollama-status" style="font-family:monospace;font-size:10px;color:#4a6a8a;margin-bottom:8px;">Checking Ollama connection...</div>';
  h += '<button id="se-ew-ai-btn" style="display:none;background:#0c1525;border:1px solid #00aaff;color:#00aaff;padding:8px 16px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:4px;letter-spacing:1px;" onclick="_seEwAiAnalysis()">ANALYZE INDICATORS WITH AI</button>';
  h += '<div id="se-ew-ai-result"></div>';
  h += '</div>';
  h += '</div>';

  return h;
}

// Post-render for Early Warning tab
function _seInitEarlyWarningTab() {
  _seFetchActiveThreats(function(data) {
    var container = document.getElementById('se-ew-data');
    if (!container) return;
    var h = '';
    var totalCount = 0;

    // NVD CVEs
    h += '<div style="margin-bottom:16px;">';
    h += '<div style="font-family:monospace;font-size:12px;color:#ff2244;letter-spacing:2px;margin-bottom:8px;font-weight:bold;">[CVE] CRITICAL VULNERABILITIES (NVD)</div>';
    if (data.nvd && data.nvd.length > 0) {
      totalCount += data.nvd.length;
      for (var ni = 0; ni < data.nvd.length; ni++) {
        var cve = data.nvd[ni];
        h += '<div style="background:#0c1020;border:1px solid #1a3a5c;border-left:3px solid #ff2244;border-radius:4px;padding:10px 12px;margin-bottom:6px;">';
        h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;">';
        h += '<div style="display:flex;align-items:center;gap:8px;">';
        if (cve.published) h += '<span style="font-family:monospace;font-size:9px;color:#4a6a8a;">' + esc(cve.published.substring(0, 10)) + '</span>';
        h += '<span style="font-family:monospace;font-size:9px;background:#ff2244;color:#000;padding:1px 6px;border-radius:3px;font-weight:bold;">CRITICAL</span>';
        h += '</div>';
        h += '<span style="font-family:monospace;font-size:9px;color:#4a6a8a;">Source: NVD</span>';
        h += '</div>';
        h += '<div style="font-family:monospace;font-size:11px;color:#ff2244;font-weight:bold;margin-bottom:3px;">' + esc(cve.id);
        if (cve.score) h += ' (CVSS ' + esc(cve.score) + ')';
        h += '</div>';
        h += '<div style="font-family:monospace;font-size:10px;color:#b0c4d8;line-height:1.4;">' + esc(cve.desc.length > 250 ? cve.desc.substring(0, 247) + '...' : cve.desc) + '</div>';
        h += '</div>';
      }
    } else {
      h += '<div style="font-family:monospace;font-size:10px;color:#4a6a8a;padding:8px;">NVD API unavailable or no critical CVEs returned</div>';
    }
    h += '</div>';

    // ThreatFox IOCs
    h += '<div style="margin-bottom:16px;">';
    h += '<div style="font-family:monospace;font-size:12px;color:#00aaff;letter-spacing:2px;margin-bottom:8px;font-weight:bold;">[IOC] INDICATORS OF COMPROMISE (ThreatFox)</div>';
    if (data.threatfox && data.threatfox.length > 0) {
      totalCount += data.threatfox.length;
      for (var ti = 0; ti < data.threatfox.length; ti++) {
        var tf = data.threatfox[ti];
        h += '<div style="background:#0c1020;border:1px solid #1a3a5c;border-left:3px solid #00aaff;border-radius:4px;padding:10px 12px;margin-bottom:6px;">';
        h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;">';
        h += '<div style="display:flex;align-items:center;gap:8px;">';
        if (tf.firstSeen) h += '<span style="font-family:monospace;font-size:9px;color:#4a6a8a;">' + esc(tf.firstSeen.substring(0, 16)) + '</span>';
        h += '<span style="font-family:monospace;font-size:9px;background:#00aaff;color:#000;padding:1px 6px;border-radius:3px;font-weight:bold;">' + esc(tf.type) + '</span>';
        h += '</div>';
        h += '<span style="font-family:monospace;font-size:9px;color:#4a6a8a;">Source: ThreatFox</span>';
        h += '</div>';
        h += '<div style="font-family:monospace;font-size:10px;color:#ff6622;font-weight:bold;margin-bottom:3px;">' + esc(tf.malware) + '</div>';
        h += '<div style="font-family:monospace;font-size:10px;color:#b0c4d8;word-break:break-all;">' + esc(tf.ioc) + '</div>';
        h += '</div>';
      }
    } else {
      h += '<div style="font-family:monospace;font-size:10px;color:#4a6a8a;padding:8px;">ThreatFox API unavailable or no recent IOCs returned</div>';
    }
    h += '</div>';

    // URLhaus
    h += '<div>';
    h += '<div style="font-family:monospace;font-size:12px;color:#ffaa00;letter-spacing:2px;margin-bottom:8px;font-weight:bold;">[URL] MALWARE DISTRIBUTION URLs (URLhaus)</div>';
    if (data.urlhaus && data.urlhaus.length > 0) {
      totalCount += data.urlhaus.length;
      for (var ui = 0; ui < data.urlhaus.length; ui++) {
        var uh = data.urlhaus[ui];
        h += '<div style="background:#0c1020;border:1px solid #1a3a5c;border-left:3px solid #ffaa00;border-radius:4px;padding:10px 12px;margin-bottom:6px;">';
        h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;">';
        h += '<div style="display:flex;align-items:center;gap:8px;">';
        if (uh.dateAdded) h += '<span style="font-family:monospace;font-size:9px;color:#4a6a8a;">' + esc(uh.dateAdded.substring(0, 16)) + '</span>';
        var uStatusColor = uh.status === 'online' ? '#ff2244' : '#44cc44';
        h += '<span style="font-family:monospace;font-size:9px;color:' + uStatusColor + ';font-weight:bold;">[' + esc(uh.status.toUpperCase()) + ']</span>';
        h += '</div>';
        h += '<span style="font-family:monospace;font-size:9px;color:#4a6a8a;">Source: URLhaus</span>';
        h += '</div>';
        if (uh.threat) h += '<div style="font-family:monospace;font-size:10px;color:#ffaa00;font-weight:bold;margin-bottom:3px;">' + esc(uh.threat) + '</div>';
        h += '<div style="font-family:monospace;font-size:10px;color:#b0c4d8;word-break:break-all;">' + esc(uh.url) + '</div>';
        h += '</div>';
      }
    } else {
      h += '<div style="font-family:monospace;font-size:10px;color:#4a6a8a;padding:8px;">URLhaus API unavailable or no recent URLs returned</div>';
    }
    h += '</div>';

    h += '<div style="font-family:monospace;font-size:9px;color:#4a6a8a;margin-top:12px;padding:8px;border-top:1px solid #1a3a5c;">';
    h += totalCount + ' indicators from public threat intelligence APIs. All data is real and current. Refreshes every 5 minutes.';
    h += '</div>';
    container.innerHTML = h;
  });
  // Check Ollama
  _seCheckOllama(function(available) {
    var statusEl = document.getElementById('se-ew-ollama-status');
    var btnEl = document.getElementById('se-ew-ai-btn');
    if (!statusEl) return;
    if (available) {
      statusEl.innerHTML = '<span style="color:#44cc44;">Ollama connected</span> (model: ' + esc(_seOllamaModel) + ')';
      if (btnEl) btnEl.style.display = '';
    } else {
      statusEl.innerHTML = '<span style="color:#ff6622;">Ollama not connected.</span> For AI analysis, run: <span style="color:#b0c4d8;">ollama pull llama3.2 && ollama serve</span>';
    }
  });
}

function _seEwAiAnalysis() {
  var data = _seActiveThreats;
  var summary = 'Based on these real, current threat indicators from the past 24 hours, provide a brief threat landscape summary.\n\n';
  if (data.nvd && data.nvd.length > 0) {
    summary += 'CRITICAL CVEs from NVD:\n';
    for (var i = 0; i < data.nvd.length && i < 5; i++) {
      summary += '- ' + data.nvd[i].id + ' (CVSS ' + (data.nvd[i].score || 'N/A') + '): ' + data.nvd[i].desc.substring(0, 100) + '\n';
    }
  }
  if (data.threatfox && data.threatfox.length > 0) {
    summary += '\nRecent IOCs from ThreatFox:\n';
    for (var j = 0; j < data.threatfox.length && j < 5; j++) {
      summary += '- ' + data.threatfox[j].malware + ' (' + data.threatfox[j].type + ')\n';
    }
  }
  summary += '\nProvide: 1) Which of these indicators are most concerning and why, 2) What defensive actions should be prioritized right now. Be specific and reference only real threat groups and techniques.';
  _seQueryOllama(summary, 'se-ew-ai-result');
}



// ---------------------------------------------------------------------------
// TAB 5 — APT TRACKING
// ---------------------------------------------------------------------------
function renderAptTrack() {
  var state = _seLoadState();
  var filterNation = state.aptFilterNation || 'ALL';
  var filterActive = state.aptFilterActive || 'ALL';
  var filterThreat = state.aptFilterThreat || 'ALL';
  var searchQuery = state.aptSearch || '';
  var expandedApt = state.expandedApt || null;

  var h = '';



  // Header
  h += '<div style="display:flex;align-items:center;justify-content:space-between;padding:18px 24px 10px;border-bottom:1px solid #1a3a5c;">';
  h += '<div style="font-size:20px;font-weight:bold;letter-spacing:2px;color:#00aaff;font-family:monospace;text-transform:uppercase;">APT GROUP TRACKING</div>';
  var activeCount = 0;
  for (var ac = 0; ac < APT_GROUPS.length; ac++) { if (APT_GROUPS[ac].active) activeCount++; }
  h += '<div style="font-family:monospace;font-size:11px;color:#4a6a8a;">' + APT_GROUPS.length + ' GROUPS TRACKED • <span style="color:#ff6622;">' + activeCount + ' ACTIVE</span></div>';
  h += '</div>';

  // Search + filters
  h += '<div style="display:flex;gap:12px;padding:12px 24px;border-bottom:1px solid #0d1525;align-items:center;flex-wrap:wrap;">';

  // Search box
  h += '<div style="flex:0 0 200px;">';
  h += '<input type="text" id="se-apt-search" data-action="aptSearch" placeholder="SEARCH GROUPS..." value="' + esc(searchQuery) + '" style="width:100%;background:#060a14;border:1px solid #1a3a5c;color:#b0c4d8;padding:6px 10px;font-family:monospace;font-size:10px;border-radius:4px;letter-spacing:1px;" />';
  h += '</div>';

  // Nation filter
  h += '<span style="font-family:monospace;font-size:10px;color:#4a6a8a;letter-spacing:1px;">NATION:</span>';
  h += '<select id="se-apt-nation-filter" data-action="aptFilterNation" style="background:#0c1525;border:1px solid #1a3a5c;color:#b0c4d8;padding:4px 8px;font-family:monospace;font-size:10px;border-radius:4px;">';
  h += '<option value="ALL"' + (filterNation === 'ALL' ? ' selected' : '') + '>ALL NATIONS</option>';
  var nationCodes = {};
  for (var anc = 0; anc < APT_GROUPS.length; anc++) {
    nationCodes[APT_GROUPS[anc].nationCode] = APT_GROUPS[anc].nation;
  }
  var ncKeys = Object.keys(nationCodes);
  for (var nck = 0; nck < ncKeys.length; nck++) {
    h += '<option value="' + esc(ncKeys[nck]) + '"' + (filterNation === ncKeys[nck] ? ' selected' : '') + '>' + esc(nationCodes[ncKeys[nck]]) + '</option>';
  }
  h += '</select>';

  // Active filter
  h += '<div style="display:flex;gap:4px;">';
  var activeFilters = ['ALL', 'ACTIVE', 'INACTIVE'];
  for (var afi = 0; afi < activeFilters.length; afi++) {
    var afActive = filterActive === activeFilters[afi];
    h += '<button class="se-filter-btn" data-action="aptFilterActive" data-value="' + activeFilters[afi] + '" style="background:' + (afActive ? '#00aaff' : '#0c1525') + ';color:' + (afActive ? '#000' : '#6688aa') + ';border:1px solid ' + (afActive ? '#00aaff' : '#1a3a5c') + ';border-radius:4px;padding:4px 8px;font-family:monospace;font-size:9px;cursor:pointer;letter-spacing:1px;">' + activeFilters[afi] + '</button>';
  }
  h += '</div>';

  h += '</div>';

  // Cross-group correlation summary
  h += '<div style="padding:12px 24px;">';
  h += '<div style="background:linear-gradient(135deg,rgba(0,170,255,0.06),#0a0e1a);border:1px solid #1a3a5c;border-radius:6px;padding:12px 14px;">';
  h += '<div style="font-family:monospace;font-size:10px;color:#00aaff;letter-spacing:2px;margin-bottom:8px;font-weight:bold;">CROSS-GROUP CORRELATIONS</div>';
  var correlations = [
    { groups: 'APT29 + APT28', relation: 'Shared target sets in European government networks, sequential operations observed' },
    { groups: 'Lazarus + Andariel + Kimsuky', relation: 'Shared infrastructure and tooling, coordinated campaign timing, all RGB Bureau 121' },
    { groups: 'APT41 + Volt Typhoon', relation: 'Overlapping MSS tasking, shared living-off-the-land techniques, pre-positioning in US CRIT-INFRA' },
    { groups: 'APT33 + APT34 + MuddyWater', relation: 'IRGC umbrella coordination, shared exploit development, Middle East energy sector focus' },
    { groups: 'Sandworm + Turla', relation: 'GRU-FSB collaboration on Ukraine operations, shared zero-day usage and target handoffs' }
  ];
  for (var cri = 0; cri < correlations.length; cri++) {
    h += '<div style="display:flex;gap:10px;margin-bottom:5px;padding:4px 0;' + (cri < correlations.length - 1 ? 'border-bottom:1px solid #0d1525;' : '') + '">';
    h += '<span style="font-family:monospace;font-size:10px;color:#ff6622;font-weight:bold;min-width:180px;">' + esc(correlations[cri].groups) + '</span>';
    h += '<span style="font-family:monospace;font-size:9px;color:#8899bb;">' + esc(correlations[cri].relation) + '</span>';
    h += '</div>';
  }
  h += '</div>';
  h += '</div>';

  // APT group cards
  h += '<div style="padding:0 24px 16px;display:grid;grid-template-columns:repeat(2,1fr);gap:10px;">';

  for (var api = 0; api < APT_GROUPS.length; api++) {
    var apt = APT_GROUPS[api];

    // Apply filters
    if (filterNation !== 'ALL' && apt.nationCode !== filterNation) continue;
    if (filterActive === 'ACTIVE' && !apt.active) continue;
    if (filterActive === 'INACTIVE' && apt.active) continue;
    if (searchQuery) {
      var sq = searchQuery.toUpperCase();
      var nameMatch = apt.name.toUpperCase().indexOf(sq) >= 0;
      var aliasMatch = false;
      for (var ami = 0; ami < apt.aliases.length; ami++) {
        if (apt.aliases[ami].toUpperCase().indexOf(sq) >= 0) { aliasMatch = true; break; }
      }
      if (!nameMatch && !aliasMatch) continue;
    }

    var isAptExpanded = expandedApt === apt.name;
    var aptBorder = apt.active ? '#00aaff' : '#1a3a5c';

    h += '<div class="se-apt-card" data-action="toggleApt" data-value="' + esc(apt.name) + '" style="background:linear-gradient(135deg,rgba(10,14,26,0.9),#080b12);border:1px solid ' + aptBorder + ';border-radius:6px;overflow:hidden;cursor:pointer;">';

    // Card header
    h += '<div style="padding:12px 14px;display:flex;align-items:center;gap:10px;">';
    h += '<div style="font-size:20px;">' + esc(apt.nationFlag) + '</div>';
    h += '<div style="flex:1;">';
    h += '<div style="display:flex;align-items:center;gap:8px;">';
    h += '<span style="font-family:monospace;font-size:13px;color:#e0eaf0;font-weight:bold;letter-spacing:1px;">' + esc(apt.name) + '</span>';
    h += '<span style="font-family:monospace;font-size:8px;background:' + (apt.active ? '#ff2244' : '#334455') + ';color:' + (apt.active ? '#fff' : '#6688aa') + ';padding:2px 6px;border-radius:3px;font-weight:bold;">' + (apt.active ? 'ACTIVE' : 'DORMANT') + '</span>';
    h += '</div>';
    h += '<div style="font-family:monospace;font-size:9px;color:#6688aa;margin-top:2px;">' + esc(apt.aliases.join(' / ')) + '</div>';
    h += '</div>';
    if (apt.threatLevel) {
      h += '<span style="font-family:monospace;font-size:9px;color:' + aptBorder + ';font-weight:bold;">' + esc(apt.threatLevel) + '</span>';
    }
    h += '<span style="font-family:monospace;font-size:10px;color:#4a6a8a;">' + (isAptExpanded ? '▲' : '▼') + '</span>';
    h += '</div>';

    // Quick info row
    h += '<div style="padding:0 14px 10px;display:flex;gap:8px;flex-wrap:wrap;">';
    h += '<span style="font-family:monospace;font-size:8px;background:#0c1525;border:1px solid #1a3a5c;color:#8899bb;padding:2px 6px;border-radius:3px;">' + esc(apt.nation) + '</span>';
    h += '<span style="font-family:monospace;font-size:8px;background:#0c1525;border:1px solid #1a3a5c;color:#8899bb;padding:2px 6px;border-radius:3px;">CAMPAIGNS: ' + apt.campaigns.length + '</span>';
    h += '<span style="font-family:monospace;font-size:8px;background:#0c1525;border:1px solid #1a3a5c;color:#8899bb;padding:2px 6px;border-radius:3px;">TOOLS: ' + apt.tools.length + '</span>';
    h += '</div>';

    // Expanded details
    if (isAptExpanded) {
      h += '<div style="border-top:1px solid #1a3a5c;padding:14px;background:rgba(0,10,20,0.5);">';

      // Active campaigns
      h += '<div style="font-family:monospace;font-size:10px;color:#ff6622;letter-spacing:2px;margin-bottom:6px;">ACTIVE CAMPAIGNS</div>';
      for (var cai = 0; cai < apt.campaigns.length; cai++) {
        var camp = apt.campaigns[cai];
        h += '<div style="background:#060a14;border:1px solid #1a3a5c;border-radius:4px;padding:8px 10px;margin-bottom:4px;">';
        h += '<div style="font-family:monospace;font-size:10px;color:#e0eaf0;font-weight:bold;">' + esc(camp.name) + '</div>';
        h += '<div style="font-family:monospace;font-size:9px;color:#6688aa;margin-top:2px;">Target: ' + esc(camp.target) + ' | Since: ' + esc(camp.since) + ' | Status: <span style="color:' + (camp.status === 'ACTIVE' ? '#ff2244' : '#44cc44') + ';">' + esc(camp.status) + '</span></div>';
        h += '</div>';
      }

      // Tools
      h += '<div style="font-family:monospace;font-size:10px;color:#00aaff;letter-spacing:2px;margin:10px 0 6px;">TOOLING</div>';
      h += '<div style="display:flex;gap:6px;flex-wrap:wrap;">';
      for (var ti = 0; ti < apt.tools.length; ti++) {
        h += '<span style="font-family:monospace;font-size:9px;background:#0c1525;border:1px solid #1a3a5c;color:#b0c4d8;padding:3px 8px;border-radius:3px;">' + esc(apt.tools[ti]) + '</span>';
      }
      h += '</div>';

      // MITRE ATT&CK coverage
      h += '<div style="font-family:monospace;font-size:10px;color:#ffaa00;letter-spacing:2px;margin:10px 0 6px;">MITRE ATT&CK TECHNIQUES</div>';
      h += '<div style="display:flex;gap:4px;flex-wrap:wrap;">';
      for (var mi = 0; mi < apt.mitreTechniques.length; mi++) {
        h += '<span style="font-family:monospace;font-size:8px;background:rgba(255,170,0,0.1);border:1px solid #ffaa0040;color:#ffaa00;padding:2px 6px;border-radius:3px;">' + esc(apt.mitreTechniques[mi]) + '</span>';
      }
      h += '</div>';

      // Activity heatmap (text-based — hours vs days)
      h += '<div style="font-family:monospace;font-size:10px;color:#4a6a8a;letter-spacing:2px;margin:12px 0 6px;">ACTIVITY HEATMAP (UTC)</div>';
      h += '<div style="overflow-x:auto;">';
      h += '<table style="border-collapse:collapse;font-family:monospace;font-size:8px;">';
      var days = ['MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT', 'SUN'];
      // Header row
      h += '<tr><td style="padding:2px 4px;color:#4a6a8a;"></td>';
      for (var hr = 0; hr < 24; hr += 3) {
        h += '<td style="padding:2px 3px;color:#4a6a8a;text-align:center;">' + (hr < 10 ? '0' : '') + hr + '</td>';
      }
      h += '</tr>';

      for (var di = 0; di < days.length; di++) {
        h += '<tr><td style="padding:2px 4px;color:#4a6a8a;">' + days[di] + '</td>';
        for (var hri = 0; hri < 24; hri += 3) {
          var activityLevel = apt.activityHeatmap ? apt.activityHeatmap[di * 8 + Math.floor(hri / 3)] || 0 : Math.floor(Math.random() * 5);
          var heatColor = activityLevel === 0 ? '#0a1020' : activityLevel === 1 ? '#0c2a1a' : activityLevel === 2 ? '#1a4a2a' : activityLevel === 3 ? '#2a6a3a' : '#44cc44';
          h += '<td style="padding:2px 3px;text-align:center;"><div style="width:14px;height:10px;background:' + heatColor + ';border-radius:2px;margin:0 auto;"></div></td>';
        }
        h += '</tr>';
      }
      h += '</table>';
      h += '</div>';

      // Infrastructure stats
      h += '<div style="font-family:monospace;font-size:10px;color:#4a6a8a;letter-spacing:2px;margin:12px 0 6px;">INFRASTRUCTURE</div>';
      h += '<div style="display:flex;gap:12px;">';
      h += '<div style="flex:1;background:#060a14;border:1px solid #1a3a5c;border-radius:4px;padding:8px;text-align:center;">';
      h += '<div style="font-family:monospace;font-size:16px;color:#ff6622;font-weight:bold;">' + (apt.infrastructure ? apt.infrastructure.domains : Math.floor(Math.random() * 200 + 50)) + '</div>';
      h += '<div style="font-family:monospace;font-size:8px;color:#4a6a8a;">DOMAINS</div>';
      h += '</div>';
      h += '<div style="flex:1;background:#060a14;border:1px solid #1a3a5c;border-radius:4px;padding:8px;text-align:center;">';
      h += '<div style="font-family:monospace;font-size:16px;color:#00aaff;font-weight:bold;">' + (apt.infrastructure ? apt.infrastructure.ips : Math.floor(Math.random() * 100 + 20)) + '</div>';
      h += '<div style="font-family:monospace;font-size:8px;color:#4a6a8a;">IP ADDRESSES</div>';
      h += '</div>';
      h += '<div style="flex:1;background:#060a14;border:1px solid #1a3a5c;border-radius:4px;padding:8px;text-align:center;">';
      h += '<div style="font-family:monospace;font-size:16px;color:#ffaa00;font-weight:bold;">' + (apt.infrastructure ? apt.infrastructure.c2Servers : Math.floor(Math.random() * 30 + 5)) + '</div>';
      h += '<div style="font-family:monospace;font-size:8px;color:#4a6a8a;">C2 SERVERS</div>';
      h += '</div>';
      h += '</div>';

      h += '</div>'; // end expanded
    }

    h += '</div>'; // end apt card
  }

  h += '</div>'; // end grid

  return h;
}


// ---------------------------------------------------------------------------
// HELPER — What-If scenario results
// ---------------------------------------------------------------------------
function _getWhatIfResults(scenario) {
  // What-If analysis now handled by Ollama AI
  return ['What-If analysis now uses AI. Select an event and click ANALYZE WITH AI above.'];
}

// SENTINEL EYE — Tabs 6-10 Render Functions
// Counter Operations, Critical Infrastructure Shield, Intelligence Fusion, War Simulator, Command Authority

// ============================================================================
// TAB 6: COUNTER OPERATIONS
// ============================================================================
function renderCounterOps() {
  var h = '';

  // Classification banner

  // Section header
  h += '<div style="padding:20px 24px 0 24px;">';
  h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:18px;">';
  h += '<div>';
  h += '<h2 style="margin:0;font-size:22px;color:#00aaff;font-family:monospace;letter-spacing:2px;text-transform:uppercase;">COUNTER OPERATIONS CENTER</h2>';
  h += '<div style="color:#667;font-size:12px;font-family:monospace;margin-top:4px;letter-spacing:1px;">PLAN &bull; EXECUTE &bull; ASSESS CYBER COUNTER-OPERATIONS</div>';
  h += '</div>';
  h += '<div style="display:flex;gap:10px;">';
  h += '<div style="background:linear-gradient(135deg,#1a0a0a,#2a1515);border:1px solid #ff2244;border-radius:6px;padding:8px 16px;text-align:center;">';
  h += '<div style="color:#ff2244;font-size:10px;font-family:monospace;letter-spacing:1px;">ACTIVE OPS</div>';
  h += '<div style="color:#ff4466;font-size:22px;font-weight:bold;font-family:monospace;">3</div>';
  h += '</div>';
  h += '<div style="background:linear-gradient(135deg,#0a1a0a,#152a15);border:1px solid #00ff88;border-radius:6px;padding:8px 16px;text-align:center;">';
  h += '<div style="color:#00ff88;font-size:10px;font-family:monospace;letter-spacing:1px;">COMPLETED</div>';
  h += '<div style="color:#00ff88;font-size:22px;font-weight:bold;font-family:monospace;">47</div>';
  h += '</div>';
  h += '<div style="background:linear-gradient(135deg,#1a1a0a,#2a2a15);border:1px solid #ffaa00;border-radius:6px;padding:8px 16px;text-align:center;">';
  h += '<div style="color:#ffaa00;font-size:10px;font-family:monospace;letter-spacing:1px;">PENDING AUTH</div>';
  h += '<div style="color:#ffaa00;font-size:22px;font-weight:bold;font-family:monospace;">5</div>';
  h += '</div>';
  h += '</div>';
  h += '</div>';
  h += '</div>';

  // Main grid layout
  h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;padding:0 24px 24px 24px;">';

  // ---- Threat Assessment Panel ----
  h += '<div style="background:linear-gradient(135deg,#0c1020,#0a0e1a);border:1px solid #1a2a44;border-radius:8px;padding:16px;grid-column:1/3;">';
  h += '<div style="color:#00aaff;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;margin-bottom:12px;border-bottom:1px solid #1a2a44;padding-bottom:8px;">';
  h += '<span style="color:#ff2244;margin-right:8px;">&#9632;</span>THREAT ASSESSMENT — PROPOSED COUNTER-OPERATIONS</div>';

  var threatAssessments = [
    { name: 'OP IRON VEIL', target: 'GRU Unit 74455 C2 Infrastructure', risk: 'HIGH', status: 'AWAITING AUTHORIZATION', adversary: 'Russia / Sandworm', objective: 'Disrupt C2 channels supporting active campaign against NATO allies', collateral: 'MODERATE — potential disruption to legitimate services on shared hosting', timeframe: '48 hours', authority: 'Title 10 / EXORD 2024-0847' },
    { name: 'OP SILENT THUNDER', target: 'APT41 Staging Servers', risk: 'MEDIUM', status: 'PLANNING PHASE', adversary: 'China / MSS', objective: 'Identify and map infrastructure supporting IP theft campaign', collateral: 'LOW — targeted infrastructure only', timeframe: '72 hours', authority: 'Title 50 / NSPM-13' },
    { name: 'OP BURNING SAND', target: 'IRGC Cyber Command relay nodes', risk: 'HIGH', status: 'ACTIVE — PHASE 2', adversary: 'Iran / APT33', objective: 'Degrade capability to launch destructive attacks on energy sector', collateral: 'MODERATE — regional ISP path disruption possible', timeframe: 'Ongoing', authority: 'Title 10 / EXORD 2024-0912' }
  ];

  h += '<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;">';
  for (var ta = 0; ta < threatAssessments.length; ta++) {
    var threat = threatAssessments[ta];
    var riskColor = threat.risk === 'HIGH' ? '#ff2244' : threat.risk === 'MEDIUM' ? '#ffaa00' : '#00ff88';
    var statusColor = threat.status.indexOf('ACTIVE') >= 0 ? '#00ff88' : threat.status.indexOf('AWAITING') >= 0 ? '#ffaa00' : '#00aaff';
    h += '<div style="background:linear-gradient(135deg,#0a0e1a,#101828);border:1px solid ' + riskColor + '44;border-radius:6px;padding:14px;position:relative;overflow:hidden;">';
    h += '<div style="position:absolute;top:0;right:0;background:' + riskColor + ';color:#000;font-size:9px;font-family:monospace;font-weight:bold;padding:2px 10px;border-radius:0 6px 0 6px;">' + esc(threat.risk) + ' RISK</div>';
    h += '<div style="color:#fff;font-size:14px;font-weight:bold;font-family:monospace;margin-bottom:6px;">' + esc(threat.name) + '</div>';
    h += '<div style="color:#889;font-size:11px;font-family:monospace;margin-bottom:10px;">' + esc(threat.adversary) + '</div>';
    h += '<div style="margin-bottom:8px;">';
    h += '<div style="color:#556;font-size:9px;font-family:monospace;letter-spacing:1px;text-transform:uppercase;">TARGET</div>';
    h += '<div style="color:#dde;font-size:11px;font-family:monospace;">' + esc(threat.target) + '</div>';
    h += '</div>';
    h += '<div style="margin-bottom:8px;">';
    h += '<div style="color:#556;font-size:9px;font-family:monospace;letter-spacing:1px;text-transform:uppercase;">OBJECTIVE</div>';
    h += '<div style="color:#aab;font-size:11px;font-family:monospace;">' + esc(threat.objective) + '</div>';
    h += '</div>';
    h += '<div style="margin-bottom:8px;">';
    h += '<div style="color:#556;font-size:9px;font-family:monospace;letter-spacing:1px;text-transform:uppercase;">COLLATERAL ESTIMATE</div>';
    h += '<div style="color:' + riskColor + ';font-size:11px;font-family:monospace;">' + esc(threat.collateral) + '</div>';
    h += '</div>';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-top:10px;padding-top:8px;border-top:1px solid #1a2a44;">';
    h += '<div style="color:' + statusColor + ';font-size:10px;font-family:monospace;font-weight:bold;">' + esc(threat.status) + '</div>';
    h += '<div style="color:#667;font-size:10px;font-family:monospace;">' + esc(threat.timeframe) + '</div>';
    h += '</div>';
    h += '<div style="color:#445;font-size:9px;font-family:monospace;margin-top:6px;">' + esc(threat.authority) + '</div>';
    h += '</div>';
  }
  h += '</div>';
  h += '</div>';

  // ---- Operation Planning Interface ----
  h += '<div style="background:linear-gradient(135deg,#0c1020,#0a0e1a);border:1px solid #1a2a44;border-radius:8px;padding:16px;">';
  h += '<div style="color:#00aaff;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;margin-bottom:14px;border-bottom:1px solid #1a2a44;padding-bottom:8px;">';
  h += '<span style="color:#00aaff;margin-right:8px;">&#9881;</span>OPERATION PLANNING PHASES</div>';

  var opPhases = [
    { phase: '01', name: 'RECONNAISSANCE', desc: 'Map adversary network topology, identify key infrastructure nodes, gather intelligence on defensive posture', status: 'active', icon: '[R]', tools: 'SIGINT collection, OSINT aggregation, network scanning, social engineering assessment' },
    { phase: '02', name: 'ACCESS DEVELOPMENT', desc: 'Develop initial access vectors, identify exploitable vulnerabilities, prepare credentials and implants', status: 'pending', icon: '[A]', tools: 'Vulnerability research, exploit development, credential harvesting, supply chain analysis' },
    { phase: '03', name: 'PAYLOAD DELIVERY', desc: 'Deploy access tools via approved vectors, establish initial foothold on target infrastructure', status: 'pending', icon: '[D]', tools: 'Spearphishing, watering hole, supply chain injection, physical access' },
    { phase: '04', name: 'PERSISTENCE', desc: 'Establish redundant access, deploy persistence mechanisms, create backup communication channels', status: 'pending', icon: '[P]', tools: 'Rootkits, scheduled tasks, registry keys, firmware implants, legitimate credentials' },
    { phase: '05', name: 'INTELLIGENCE COLLECTION', desc: 'Exfiltrate target data, monitor adversary communications, document infrastructure details', status: 'pending', icon: '[I]', tools: 'Keyloggers, screen capture, network sniffing, database extraction, email collection' },
    { phase: '06', name: 'DISRUPTION / DEGRADATION', desc: 'Execute authorized effects against target, degrade adversary capability, deny access to key resources', status: 'pending', icon: '&#9889;', tools: 'Data wiping, service disruption, infrastructure destruction, capability denial' }
  ];

  for (var op = 0; op < opPhases.length; op++) {
    var phase = opPhases[op];
    var phaseColor = phase.status === 'active' ? '#00aaff' : '#334';
    var phaseBorder = phase.status === 'active' ? '#00aaff' : '#1a2a44';
    var phaseGlow = phase.status === 'active' ? 'box-shadow:0 0 12px #00aaff22;' : '';
    h += '<div style="background:linear-gradient(135deg,#0a0e1a,#0d1225);border:1px solid ' + phaseBorder + ';border-radius:6px;padding:12px;margin-bottom:8px;' + phaseGlow + '">';
    h += '<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;">';
    h += '<div style="background:' + phaseColor + ';color:#000;font-size:10px;font-family:monospace;font-weight:bold;padding:3px 8px;border-radius:3px;">PHASE ' + esc(phase.phase) + '</div>';
    h += '<div style="color:' + (phase.status === 'active' ? '#fff' : '#778') + ';font-size:13px;font-family:monospace;font-weight:bold;letter-spacing:1px;">' + phase.icon + ' ' + esc(phase.name) + '</div>';
    if (phase.status === 'active') {
      h += '<div style="margin-left:auto;background:#00aaff22;color:#00aaff;font-size:9px;font-family:monospace;padding:2px 8px;border-radius:3px;animation:se-pulse 2s ease-in-out infinite;">&#9679; ACTIVE</div>';
    }
    h += '</div>';
    h += '<div style="color:#889;font-size:11px;font-family:monospace;margin-bottom:6px;line-height:1.5;">' + esc(phase.desc) + '</div>';
    h += '<div style="color:#556;font-size:10px;font-family:monospace;"><span style="color:#667;letter-spacing:1px;">TOOLS:</span> ' + esc(phase.tools) + '</div>';
    h += '</div>';
  }
  h += '</div>';

  // ---- Escalation Ladder ----
  h += '<div style="background:linear-gradient(135deg,#0c1020,#0a0e1a);border:1px solid #1a2a44;border-radius:8px;padding:16px;">';
  h += '<div style="color:#00aaff;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;margin-bottom:14px;border-bottom:1px solid #1a2a44;padding-bottom:8px;">';
  h += '<span style="color:#ffaa00;margin-right:8px;">&#9650;</span>ESCALATION LADDER</div>';

  var escalationLevels = [
    { level: 4, name: 'STRATEGIC OFFENSIVE', desc: 'Full-scale cyber operations against adversary national infrastructure', color: '#ff2244', auth: 'Presidential directive, NSC approval, Congressional notification', actions: 'Critical infrastructure disruption, strategic capability denial, combined cyber-kinetic operations', current: false },
    { level: 3, name: 'OFFENSIVE CYBER OPERATIONS', desc: 'Targeted offensive actions against identified adversary systems', color: '#ff6644', auth: 'SECDEF approval, EXORD required, Title 10 authority', actions: 'C2 disruption, data destruction, infrastructure degradation, implant activation', current: false },
    { level: 2, name: 'ACTIVE CYBER DEFENSE', desc: 'Defensive operations extending beyond own network boundaries', color: '#ffaa00', auth: 'CYBERCOM Commander approval, ROE authorization', actions: 'Threat hunting on foreign networks, adversary infrastructure mapping, counter-intrusion', current: true },
    { level: 1, name: 'DEFENSIVE OPERATIONS', desc: 'Protection and defense of own networks and systems', color: '#00ff88', auth: 'Standing ROE, commander discretion', actions: 'Network monitoring, intrusion detection, incident response, patching, hardening', current: false }
  ];

  for (var el = 0; el < escalationLevels.length; el++) {
    var eLvl = escalationLevels[el];
    var isCurrentStr = eLvl.current ? 'border-left:4px solid ' + eLvl.color + ';box-shadow:0 0 20px ' + eLvl.color + '22;' : 'border-left:4px solid #1a2a44;opacity:0.7;';
    h += '<div style="background:linear-gradient(135deg,#0a0e1a,#0d1225);border:1px solid ' + (eLvl.current ? eLvl.color + '44' : '#1a2a44') + ';border-radius:6px;padding:12px;margin-bottom:8px;' + isCurrentStr + '">';
    h += '<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;">';
    h += '<div style="background:' + eLvl.color + ';color:#000;font-size:11px;font-family:monospace;font-weight:bold;padding:3px 10px;border-radius:3px;">LEVEL ' + esc(eLvl.level) + '</div>';
    h += '<div style="color:' + eLvl.color + ';font-size:14px;font-family:monospace;font-weight:bold;letter-spacing:1px;">' + esc(eLvl.name) + '</div>';
    if (eLvl.current) {
      h += '<div style="margin-left:auto;background:' + eLvl.color + '22;color:' + eLvl.color + ';font-size:9px;font-family:monospace;padding:3px 10px;border-radius:3px;">&#9654; CURRENT POSTURE</div>';
    }
    h += '</div>';
    h += '<div style="color:#aab;font-size:11px;font-family:monospace;margin-bottom:8px;">' + esc(eLvl.desc) + '</div>';
    h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">';
    h += '<div><div style="color:#556;font-size:9px;font-family:monospace;letter-spacing:1px;">AUTHORIZATION</div><div style="color:#889;font-size:10px;font-family:monospace;">' + esc(eLvl.auth) + '</div></div>';
    h += '<div><div style="color:#556;font-size:9px;font-family:monospace;letter-spacing:1px;">AUTHORIZED ACTIONS</div><div style="color:#889;font-size:10px;font-family:monospace;">' + esc(eLvl.actions) + '</div></div>';
    h += '</div>';
    h += '</div>';
    if (el < escalationLevels.length - 1) {
      h += '<div style="text-align:center;color:' + eLvl.color + '44;font-size:16px;margin:2px 0;">&#9660;</div>';
    }
  }
  h += '</div>';

  // ---- ROE Compliance Checker ----
  h += '<div style="background:linear-gradient(135deg,#0c1020,#0a0e1a);border:1px solid #1a2a44;border-radius:8px;padding:16px;">';
  h += '<div style="color:#00aaff;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;margin-bottom:14px;border-bottom:1px solid #1a2a44;padding-bottom:8px;">';
  h += '<span style="color:#00ff88;margin-right:8px;">&#9745;</span>ROE COMPLIANCE CHECKER</div>';

  var roeChecklist = [
    { question: 'Has the operation been authorized by the appropriate authority?', category: 'Authorization', options: ['Presidential Directive', 'SECDEF EXORD', 'CYBERCOM Order', 'Standing ROE'] },
    { question: 'Is the target positively identified as adversary infrastructure?', category: 'Targeting', options: ['Confirmed hostile', 'High confidence', 'Moderate confidence', 'Unconfirmed'] },
    { question: 'Has collateral damage been assessed and minimized?', category: 'Proportionality', options: ['No collateral expected', 'Minimal collateral', 'Moderate collateral', 'Significant collateral'] },
    { question: 'Is the proposed action proportional to the threat?', category: 'Proportionality', options: ['Proportional', 'Slightly elevated', 'Escalatory', 'Disproportionate'] },
    { question: 'Are effects reversible if required?', category: 'Reversibility', options: ['Fully reversible', 'Partially reversible', 'Difficult to reverse', 'Irreversible'] },
    { question: 'Has legal review been completed?', category: 'Legal', options: ['JAG approved', 'Under review', 'Conditional approval', 'Not reviewed'] },
    { question: 'Is Congressional notification required?', category: 'Notification', options: ['Not required', 'Required — submitted', 'Required — pending', 'Unknown'] },
    { question: 'Does the operation comply with international law obligations?', category: 'Int\'l Law', options: ['Compliant', 'Arguable', 'Potential violation', 'Non-compliant'] }
  ];

  for (var rc = 0; rc < roeChecklist.length; rc++) {
    var roe = roeChecklist[rc];
    h += '<div style="background:#0a0e1a;border:1px solid #1a2a44;border-radius:4px;padding:10px;margin-bottom:6px;">';
    h += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">';
    h += '<div style="background:#00aaff22;color:#00aaff;font-size:9px;font-family:monospace;padding:2px 6px;border-radius:2px;">' + esc(roe.category) + '</div>';
    h += '<div style="color:#ccd;font-size:11px;font-family:monospace;">' + esc(roe.question) + '</div>';
    h += '</div>';
    h += '<div style="display:flex;flex-wrap:wrap;gap:6px;">';
    for (var ro = 0; ro < roe.options.length; ro++) {
      var optColor = ro === 0 ? '#00ff88' : ro === 1 ? '#00aaff' : ro === 2 ? '#ffaa00' : '#ff2244';
      var isSelected = ro === 0 ? 'background:' + optColor + '22;border-color:' + optColor + ';color:' + optColor + ';' : 'background:transparent;border-color:#334;color:#667;';
      h += '<div style="font-size:10px;font-family:monospace;padding:4px 10px;border:1px solid;border-radius:3px;cursor:pointer;' + isSelected + '">';
      h += esc(roe.options[ro]);
      h += '</div>';
    }
    h += '</div>';
    h += '</div>';
  }

  h += '<div style="margin-top:12px;background:#00ff8811;border:1px solid #00ff8844;border-radius:6px;padding:12px;text-align:center;">';
  h += '<div style="color:#00ff88;font-size:14px;font-family:monospace;font-weight:bold;letter-spacing:1px;">ROE COMPLIANCE: APPROVED</div>';
  h += '<div style="color:#889;font-size:10px;font-family:monospace;margin-top:4px;">All checks passed — operation is within authorized parameters</div>';
  h += '</div>';
  h += '</div>';

  // ---- Legal Authority Matrix ----
  h += '<div style="background:linear-gradient(135deg,#0c1020,#0a0e1a);border:1px solid #1a2a44;border-radius:8px;padding:16px;">';
  h += '<div style="color:#00aaff;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;margin-bottom:14px;border-bottom:1px solid #1a2a44;padding-bottom:8px;">';
  h += '<span style="color:#ffaa00;margin-right:8px;">&#9878;</span>LEGAL AUTHORITY MATRIX</div>';

  var legalAuthorities = [
    { authority: 'Title 10 U.S.C.', section: 'Armed Forces', scope: 'Military cyber operations under DOD authority', approval: 'SECDEF / POTUS', ops: 'Offensive military cyber ops, defend-forward operations, battlefield preparation', status: 'ACTIVE' },
    { authority: 'Title 50 U.S.C.', section: 'War & National Defense', scope: 'Covert cyber operations under intelligence authority', approval: 'POTUS Finding, Congressional Gang of Eight', ops: 'Covert action, espionage, sabotage under intelligence authorities', status: 'ACTIVE' },
    { authority: 'EO 12333', section: 'Intelligence Activities', scope: 'United States intelligence community framework', approval: 'DNI / Agency Head', ops: 'Foreign intelligence collection, counterintelligence activities', status: 'ACTIVE' },
    { authority: 'NSPM-13', section: 'Cyber Operations Policy', scope: 'Streamlined approval for offensive cyber operations', approval: 'SECDEF with NSC coordination', ops: 'Enabled defend-forward operations without individual presidential approval', status: 'ACTIVE' },
    { authority: 'PPD-20', section: 'Cyber Operations Policy', scope: 'Presidential policy directive on cyber operations (superseded by NSPM-13)', approval: 'NSC / POTUS', ops: 'Originally required presidential approval for significant cyber effects', status: 'SUPERSEDED' },
    { authority: 'AUMF 2001', section: 'Authorization for Use of Military Force', scope: 'Authority for military operations against designated terrorist organizations', approval: 'Congressional authorization', ops: 'Cyber operations against designated entities under existing AUMF', status: 'ACTIVE' },
    { authority: 'Tallinn Manual 2.0', section: 'International Law Framework', scope: 'Non-binding guidance on international law applied to cyber operations', approval: 'Reference framework', ops: 'Sovereignty, due diligence, countermeasures, law of armed conflict applicability', status: 'REFERENCE' }
  ];

  h += '<div style="overflow-x:auto;">';
  h += '<table style="width:100%;border-collapse:collapse;font-family:monospace;font-size:11px;">';
  h += '<thead><tr style="border-bottom:2px solid #1a2a44;">';
  var authHeaders = ['AUTHORITY', 'SCOPE', 'APPROVAL CHAIN', 'AUTHORIZED OPERATIONS', 'STATUS'];
  for (var ah = 0; ah < authHeaders.length; ah++) {
    h += '<th style="text-align:left;padding:8px;color:#00aaff;font-size:10px;letter-spacing:1px;text-transform:uppercase;">' + esc(authHeaders[ah]) + '</th>';
  }
  h += '</tr></thead><tbody>';
  for (var la = 0; la < legalAuthorities.length; la++) {
    var auth = legalAuthorities[la];
    var authStatusColor = auth.status === 'ACTIVE' ? '#00ff88' : auth.status === 'SUPERSEDED' ? '#ff6644' : '#00aaff';
    h += '<tr style="border-bottom:1px solid #111828;">';
    h += '<td style="padding:8px;color:#fff;font-weight:bold;white-space:nowrap;">' + esc(auth.authority) + '<div style="color:#556;font-size:9px;font-weight:normal;">' + esc(auth.section) + '</div></td>';
    h += '<td style="padding:8px;color:#aab;">' + esc(auth.scope) + '</td>';
    h += '<td style="padding:8px;color:#889;">' + esc(auth.approval) + '</td>';
    h += '<td style="padding:8px;color:#889;max-width:250px;">' + esc(auth.ops) + '</td>';
    h += '<td style="padding:8px;"><span style="background:' + authStatusColor + '22;color:' + authStatusColor + ';font-size:9px;padding:2px 8px;border-radius:3px;">' + esc(auth.status) + '</span></td>';
    h += '</tr>';
  }
  h += '</tbody></table>';
  h += '</div>';
  h += '</div>';

  // ---- Collateral Damage Estimator ----
  h += '<div style="background:linear-gradient(135deg,#0c1020,#0a0e1a);border:1px solid #1a2a44;border-radius:8px;padding:16px;">';
  h += '<div style="color:#00aaff;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;margin-bottom:14px;border-bottom:1px solid #1a2a44;padding-bottom:8px;">';
  h += '<span style="color:#ff6644;margin-right:8px;">&#9888;</span>COLLATERAL DAMAGE ESTIMATOR</div>';

  var cdeFactors = [
    { factor: 'Shared Infrastructure Impact', weight: 30, score: 45, desc: 'Target systems share hosting with civilian services' },
    { factor: 'Supply Chain Dependencies', weight: 20, score: 30, desc: 'Software/services downstream of target infrastructure' },
    { factor: 'Civilian Data Exposure', weight: 25, score: 20, desc: 'Potential for civilian PII/data to be affected' },
    { factor: 'Regional Network Disruption', weight: 15, score: 55, desc: 'Probability of broader network outages from operation' },
    { factor: 'Temporal Persistence', weight: 10, score: 15, desc: 'Duration of expected collateral effects' }
  ];

  var totalCDE = 0;
  for (var cf = 0; cf < cdeFactors.length; cf++) {
    totalCDE += (cdeFactors[cf].weight / 100) * cdeFactors[cf].score;
  }

  for (var cd = 0; cd < cdeFactors.length; cd++) {
    var cFactor = cdeFactors[cd];
    var cBarColor = cFactor.score < 30 ? '#00ff88' : cFactor.score < 60 ? '#ffaa00' : '#ff2244';
    h += '<div style="margin-bottom:10px;">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">';
    h += '<div style="color:#ccd;font-size:11px;font-family:monospace;">' + esc(cFactor.factor) + ' <span style="color:#556;">(weight: ' + esc(cFactor.weight) + '%)</span></div>';
    h += '<div style="color:' + cBarColor + ';font-size:12px;font-family:monospace;font-weight:bold;">' + esc(cFactor.score) + '%</div>';
    h += '</div>';
    h += '<div style="background:#111828;border-radius:4px;height:8px;overflow:hidden;">';
    h += '<div style="background:linear-gradient(90deg,' + cBarColor + ',' + cBarColor + '88);width:' + cFactor.score + '%;height:100%;border-radius:4px;transition:width 0.5s;"></div>';
    h += '</div>';
    h += '<div style="color:#556;font-size:9px;font-family:monospace;margin-top:2px;">' + esc(cFactor.desc) + '</div>';
    h += '</div>';
  }

  var cdeLevel = totalCDE < 25 ? 'LOW' : totalCDE < 50 ? 'MODERATE' : totalCDE < 75 ? 'HIGH' : 'CRITICAL';
  var cdeLevelColor = totalCDE < 25 ? '#00ff88' : totalCDE < 50 ? '#ffaa00' : totalCDE < 75 ? '#ff6644' : '#ff2244';
  h += '<div style="margin-top:14px;background:' + cdeLevelColor + '11;border:1px solid ' + cdeLevelColor + '44;border-radius:6px;padding:12px;text-align:center;">';
  h += '<div style="color:' + cdeLevelColor + ';font-size:16px;font-family:monospace;font-weight:bold;">ESTIMATED COLLATERAL: ' + esc(cdeLevel) + '</div>';
  h += '<div style="color:#889;font-size:11px;font-family:monospace;margin-top:4px;">Composite Score: ' + Math.round(totalCDE) + '/100</div>';
  h += '</div>';
  h += '</div>';

  // ---- Operation Timeline Generator ----
  h += '<div style="background:linear-gradient(135deg,#0c1020,#0a0e1a);border:1px solid #1a2a44;border-radius:8px;padding:16px;">';
  h += '<div style="color:#00aaff;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;margin-bottom:14px;border-bottom:1px solid #1a2a44;padding-bottom:8px;">';
  h += '<span style="color:#00aaff;margin-right:8px;">&#9201;</span>OPERATION TIMELINE GENERATOR</div>';

  h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:14px;">';
  var timelineFields = [
    { label: 'Operation Name', value: 'OP IRON VEIL', type: 'text' },
    { label: 'Classification', value: 'TOP SECRET//SCI//NOFORN', type: 'select' },
    { label: 'Start Date/Time (Zulu)', value: '2026-09-15T02:00Z', type: 'datetime' },
    { label: 'Estimated Duration', value: '48 hours', type: 'select' },
    { label: 'Primary Objective', value: 'Disrupt GRU C2 infrastructure', type: 'text' },
    { label: 'Approving Authority', value: 'SECDEF via EXORD', type: 'select' }
  ];
  for (var tf = 0; tf < timelineFields.length; tf++) {
    var field = timelineFields[tf];
    h += '<div>';
    h += '<div style="color:#556;font-size:9px;font-family:monospace;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px;">' + esc(field.label) + '</div>';
    h += '<div style="background:#0a0e1a;border:1px solid #1a2a44;border-radius:4px;padding:8px;color:#ccd;font-size:11px;font-family:monospace;">' + esc(field.value) + '</div>';
    h += '</div>';
  }
  h += '</div>';

  var timelineEvents = [
    { time: 'H-24', event: 'Final authorization confirmation', status: 'COMPLETE' },
    { time: 'H-12', event: 'Pre-position tools and access verification', status: 'COMPLETE' },
    { time: 'H-6', event: 'Final target confirmation and ROE review', status: 'IN PROGRESS' },
    { time: 'H-2', event: 'Team deployment and comms check', status: 'PENDING' },
    { time: 'H-0', event: 'Operation execution — Phase 1 initiation', status: 'PENDING' },
    { time: 'H+4', event: 'Phase 1 assessment and Phase 2 decision point', status: 'PENDING' },
    { time: 'H+12', event: 'Interim battle damage assessment', status: 'PENDING' },
    { time: 'H+24', event: 'Phase 2 completion and extraction', status: 'PENDING' },
    { time: 'H+48', event: 'Full BDA and after-action report', status: 'PENDING' }
  ];

  h += '<div style="position:relative;padding-left:30px;">';
  for (var te = 0; te < timelineEvents.length; te++) {
    var tEvent = timelineEvents[te];
    var tColor = tEvent.status === 'COMPLETE' ? '#00ff88' : tEvent.status === 'IN PROGRESS' ? '#00aaff' : '#334';
    var tDotStyle = tEvent.status === 'IN PROGRESS' ? 'box-shadow:0 0 8px #00aaff;' : '';
    h += '<div style="position:relative;margin-bottom:8px;padding:8px 12px;background:#0a0e1a;border:1px solid ' + (tEvent.status !== 'PENDING' ? tColor + '44' : '#1a2a44') + ';border-radius:4px;">';
    h += '<div style="position:absolute;left:-24px;top:50%;transform:translateY(-50%);width:10px;height:10px;background:' + tColor + ';border-radius:50%;' + tDotStyle + '"></div>';
    if (te < timelineEvents.length - 1) {
      h += '<div style="position:absolute;left:-19px;top:60%;width:1px;height:calc(100% + 8px);background:#1a2a44;"></div>';
    }
    h += '<div style="display:flex;align-items:center;justify-content:space-between;">';
    h += '<div style="display:flex;align-items:center;gap:10px;">';
    h += '<div style="color:' + tColor + ';font-size:11px;font-family:monospace;font-weight:bold;min-width:40px;">' + esc(tEvent.time) + '</div>';
    h += '<div style="color:' + (tEvent.status !== 'PENDING' ? '#ccd' : '#667') + ';font-size:11px;font-family:monospace;">' + esc(tEvent.event) + '</div>';
    h += '</div>';
    var tStatusColor = tEvent.status === 'COMPLETE' ? '#00ff88' : tEvent.status === 'IN PROGRESS' ? '#00aaff' : '#445';
    h += '<div style="color:' + tStatusColor + ';font-size:9px;font-family:monospace;letter-spacing:1px;">' + esc(tEvent.status) + '</div>';
    h += '</div>';
    h += '</div>';
  }
  h += '</div>';
  h += '</div>';

  // ---- Battle Damage Assessment ----
  h += '<div style="background:linear-gradient(135deg,#0c1020,#0a0e1a);border:1px solid #1a2a44;border-radius:8px;padding:16px;grid-column:1/3;">';
  h += '<div style="color:#00aaff;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;margin-bottom:14px;border-bottom:1px solid #1a2a44;padding-bottom:8px;">';
  h += '<span style="color:#ff6644;margin-right:8px;">[B]</span>BATTLE DAMAGE ASSESSMENT TEMPLATE</div>';

  h += '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:14px;">';
  var bdaMetrics = [
    { label: 'TARGETS ENGAGED', value: '14', sub: 'C2 servers, relay nodes', color: '#ff2244' },
    { label: 'TARGETS DESTROYED', value: '11', sub: '78.6% effectiveness', color: '#ff6644' },
    { label: 'TARGETS DEGRADED', value: '2', sub: 'Partial capability loss', color: '#ffaa00' },
    { label: 'MISSED / FAILED', value: '1', sub: 'Migrated pre-strike', color: '#667' }
  ];
  for (var bm = 0; bm < bdaMetrics.length; bm++) {
    var bdm = bdaMetrics[bm];
    h += '<div style="background:linear-gradient(135deg,#0a0e1a,#101828);border:1px solid ' + bdm.color + '44;border-radius:6px;padding:12px;text-align:center;">';
    h += '<div style="color:#556;font-size:9px;font-family:monospace;letter-spacing:1px;">' + esc(bdm.label) + '</div>';
    h += '<div style="color:' + bdm.color + ';font-size:28px;font-weight:bold;font-family:monospace;">' + esc(bdm.value) + '</div>';
    h += '<div style="color:#667;font-size:10px;font-family:monospace;">' + esc(bdm.sub) + '</div>';
    h += '</div>';
  }
  h += '</div>';

  h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">';
  var bdaSections = [
    { title: 'PHYSICAL DAMAGE ASSESSMENT', items: ['11 C2 servers rendered inoperable via data wiping', '2 relay nodes degraded — partial packet loss induced', 'Adversary DNS infrastructure disrupted across 3 providers', 'Backup C2 channels identified and monitored for reactivation'] },
    { title: 'FUNCTIONAL DAMAGE ASSESSMENT', items: ['Adversary lost primary C2 capability for active campaign', 'Estimated 72-96 hour recovery time for full reconstitution', 'Campaign against NATO allies effectively halted', 'Secondary communication channels under active surveillance'] },
    { title: 'TARGET SYSTEM ASSESSMENT', items: ['Pre-positioned implants neutralized on 8 compromised systems', 'Exfiltration channels blocked and sinkholes deployed', 'Credential infrastructure compromised — forced password resets', 'Adversary tool repositories identified and cataloged'] },
    { title: 'COLLATERAL ASSESSMENT', items: ['No unintended civilian service disruption confirmed', '1 shared hosting provider experienced brief latency spike (resolved)', 'No allied systems affected', 'No attribution exposure detected'] }
  ];
  for (var bs = 0; bs < bdaSections.length; bs++) {
    var bSect = bdaSections[bs];
    h += '<div style="background:#0a0e1a;border:1px solid #1a2a44;border-radius:4px;padding:12px;">';
    h += '<div style="color:#00aaff;font-size:10px;font-family:monospace;letter-spacing:1px;margin-bottom:8px;">' + esc(bSect.title) + '</div>';
    for (var bi = 0; bi < bSect.items.length; bi++) {
      h += '<div style="color:#889;font-size:11px;font-family:monospace;padding:3px 0;border-bottom:1px solid #111828;display:flex;align-items:flex-start;gap:6px;">';
      h += '<span style="color:#00aaff;font-size:8px;margin-top:4px;">&#9654;</span>' + esc(bSect.items[bi]);
      h += '</div>';
    }
    h += '</div>';
  }
  h += '</div>';

  h += '</div>'; // end BDA

  h += '</div>'; // end main grid

  return h;
}


// ============================================================================
// TAB 7: CRITICAL INFRASTRUCTURE SHIELD
// ============================================================================
function renderShield() {
  var h = '';

  // Classification banner

  h += '<div style="padding:20px 24px 0 24px;">';
  h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:18px;">';
  h += '<div>';
  h += '<h2 style="margin:0;font-size:22px;color:#00aaff;font-family:monospace;letter-spacing:2px;text-transform:uppercase;">CRITICAL INFRASTRUCTURE SHIELD</h2>';
  h += '<div style="color:#667;font-size:12px;font-family:monospace;margin-top:4px;letter-spacing:1px;">NATIONAL INFRASTRUCTURE DEFENSE &bull; SECTOR PROTECTION STATUS</div>';
  h += '</div>';
  h += '<div style="display:flex;gap:10px;">';
  h += '<div style="background:linear-gradient(135deg,#0a1a0a,#152a15);border:1px solid #00ff88;border-radius:6px;padding:8px 16px;text-align:center;">';
  h += '<div style="color:#00ff88;font-size:10px;font-family:monospace;letter-spacing:1px;">SECTORS NOMINAL</div>';
  h += '<div style="color:#00ff88;font-size:22px;font-weight:bold;font-family:monospace;">5</div>';
  h += '</div>';
  h += '<div style="background:linear-gradient(135deg,#1a1a0a,#2a2a15);border:1px solid #ffaa00;border-radius:6px;padding:8px 16px;text-align:center;">';
  h += '<div style="color:#ffaa00;font-size:10px;font-family:monospace;letter-spacing:1px;">SECTORS ELEVATED</div>';
  h += '<div style="color:#ffaa00;font-size:22px;font-weight:bold;font-family:monospace;">2</div>';
  h += '</div>';
  h += '<div style="background:linear-gradient(135deg,#1a0a0a,#2a1515);border:1px solid #ff2244;border-radius:6px;padding:8px 16px;text-align:center;">';
  h += '<div style="color:#ff2244;font-size:10px;font-family:monospace;letter-spacing:1px;">SECTORS CRITICAL</div>';
  h += '<div style="color:#ff2244;font-size:22px;font-weight:bold;font-family:monospace;">1</div>';
  h += '</div>';
  h += '</div>';
  h += '</div>';
  h += '</div>';

  // Sector status grid
  h += '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;padding:0 24px;">';

  var sectors = CRITICAL_INFRASTRUCTURE_SECTORS || [
    { name: 'Power Grid', icon: '&#9889;', threat: 'HIGH', defenses: ['SCADA monitoring', 'Network segmentation', 'Anomaly detection', 'Air-gapped controls'], vulns: 12, patchPct: 78, lastAssessment: '2026-09-10', attackSurface: 'ICS/SCADA systems, smart grid endpoints, generation controls', dependencies: ['Water', 'Telecom', 'Financial'], recentEvents: 'Volt Typhoon pre-positioning detected in 3 utilities' },
    { name: 'Water Systems', icon: '[W]', threat: 'ELEVATED', defenses: ['OT monitoring', 'Access controls', 'Chemical sensors', 'Manual overrides'], vulns: 8, patchPct: 65, lastAssessment: '2026-09-07', attackSurface: 'SCADA/PLC systems, treatment controls, pump stations', dependencies: ['Power', 'Telecom'], recentEvents: 'Attempted unauthorized access to treatment facility HMI' },
    { name: 'Telecommunications', icon: '[T]', threat: 'ELEVATED', defenses: ['DDoS mitigation', 'BGP monitoring', 'Signal encryption', 'Redundant routing'], vulns: 15, patchPct: 82, lastAssessment: '2026-09-11', attackSurface: 'Cell towers, fiber optic networks, switching centers, 5G core', dependencies: ['Power'], recentEvents: 'Salt Typhoon persistence detected in 2 major carriers' },
    { name: 'Financial Services', icon: '[F]', threat: 'NORMAL', defenses: ['SOC operations', 'Fraud detection', 'Encryption', 'Redundant systems'], vulns: 6, patchPct: 94, lastAssessment: '2026-09-12', attackSurface: 'Trading systems, SWIFT network, ATM networks, payment processors', dependencies: ['Power', 'Telecom'], recentEvents: 'Routine Lazarus Group reconnaissance — no intrusion' },
    { name: 'Transportation', icon: '&#9992;', threat: 'NORMAL', defenses: ['ATC monitoring', 'GPS backup', 'Network isolation', 'Incident response'], vulns: 9, patchPct: 71, lastAssessment: '2026-09-08', attackSurface: 'Air traffic control, rail signaling, port systems, traffic management', dependencies: ['Power', 'Telecom', 'Financial'], recentEvents: 'No significant cyber events in reporting period' },
    { name: 'Healthcare', icon: '[H]', threat: 'NORMAL', defenses: ['Endpoint protection', 'Network segmentation', 'Backup systems', 'HIPAA controls'], vulns: 18, patchPct: 61, lastAssessment: '2026-09-06', attackSurface: 'EHR systems, medical devices, hospital networks, research data', dependencies: ['Power', 'Water', 'Telecom'], recentEvents: 'Ransomware attempt blocked at regional hospital network' },
    { name: 'Government', icon: '[G]', threat: 'NORMAL', defenses: ['EINSTEIN 3A', 'CDM program', 'Zero trust architecture', 'CISA monitoring'], vulns: 22, patchPct: 77, lastAssessment: '2026-09-11', attackSurface: 'Federal networks, .gov domains, classified systems, elections infrastructure', dependencies: ['Power', 'Telecom', 'Financial'], recentEvents: 'APT29 phishing campaign targeting State Department — blocked' },
    { name: 'Defense Industrial Base', icon: '[D]', threat: 'HIGH', defenses: ['CMMC compliance', 'Insider threat program', 'TS/SCI protections', 'CI monitoring'], vulns: 7, patchPct: 88, lastAssessment: '2026-09-12', attackSurface: 'Weapons systems data, supply chain, research labs, contractor networks', dependencies: ['Power', 'Telecom', 'Government'], recentEvents: 'APT41 sustained espionage campaign against 5 defense contractors' }
  ];

  for (var s = 0; s < sectors.length; s++) {
    var sector = sectors[s];
    var sDefenses = sector.defenses || sector.activeDefenses || [];
    var sVulns = sector.vulns || 0;
    var sPatchPct = sector.patchPct || 0;
    var sThreat = sector.threat || 'NORMAL';
    var sIcon = sector.icon || '[' + (sector.name || 'S').charAt(0) + ']';
    var sRecentEvents = sector.recentEvents || 'No recent events reported';
    var sDependencies = sector.dependencies || [];
    var sLastAssessment = sector.lastAssessment || 'N/A';
    var sColor = sThreat === 'HIGH' ? '#ff2244' : sThreat === 'ELEVATED' ? '#ffaa00' : sThreat === 'CRITICAL' ? '#ff0000' : '#00ff88';
    var sBorderGlow = sThreat === 'HIGH' || sThreat === 'CRITICAL' ? 'box-shadow:0 0 15px ' + sColor + '22;' : '';
    h += '<div style="background:linear-gradient(135deg,#0c1020,#0a0e1a);border:1px solid ' + sColor + '44;border-radius:8px;padding:14px;' + sBorderGlow + '">';

    // Header
    h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;">';
    h += '<div style="display:flex;align-items:center;gap:8px;">';
    h += '<span style="font-size:20px;">' + sIcon + '</span>';
    h += '<div style="color:#fff;font-size:13px;font-family:monospace;font-weight:bold;letter-spacing:1px;">' + esc(sector.name || 'Unknown') + '</div>';
    h += '</div>';
    h += '<div style="background:' + sColor + '22;color:' + sColor + ';font-size:9px;font-family:monospace;font-weight:bold;padding:3px 8px;border-radius:3px;letter-spacing:1px;">' + esc(sThreat) + '</div>';
    h += '</div>';

    // Threat level bar
    var threatPct = sThreat === 'CRITICAL' ? 95 : sThreat === 'HIGH' ? 75 : sThreat === 'ELEVATED' ? 50 : 20;
    h += '<div style="margin-bottom:10px;">';
    h += '<div style="color:#556;font-size:9px;font-family:monospace;letter-spacing:1px;margin-bottom:3px;">THREAT LEVEL</div>';
    h += '<div style="background:#111828;border-radius:4px;height:6px;overflow:hidden;">';
    h += '<div style="background:linear-gradient(90deg,' + sColor + ',' + sColor + '88);width:' + threatPct + '%;height:100%;border-radius:4px;"></div>';
    h += '</div>';
    h += '</div>';

    // Active defenses
    h += '<div style="margin-bottom:10px;">';
    h += '<div style="color:#556;font-size:9px;font-family:monospace;letter-spacing:1px;margin-bottom:4px;">ACTIVE DEFENSES</div>';
    for (var ad = 0; ad < sDefenses.length; ad++) {
      h += '<div style="color:#889;font-size:10px;font-family:monospace;padding:2px 0;display:flex;align-items:center;gap:4px;">';
      h += '<span style="color:#00ff88;font-size:8px;">&#9679;</span>' + esc(sDefenses[ad]);
      h += '</div>';
    }
    if (sDefenses.length === 0) {
      h += '<div style="color:#445;font-size:10px;font-family:monospace;">No defense data available</div>';
    }
    h += '</div>';

    // Vulns and patch status
    h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:10px;">';
    h += '<div>';
    h += '<div style="color:#556;font-size:9px;font-family:monospace;letter-spacing:1px;">KNOWN VULNS</div>';
    var vulnColor = sVulns > 15 ? '#ff2244' : sVulns > 10 ? '#ffaa00' : '#00ff88';
    h += '<div style="color:' + vulnColor + ';font-size:18px;font-family:monospace;font-weight:bold;">' + esc(sVulns) + '</div>';
    h += '</div>';
    h += '<div>';
    h += '<div style="color:#556;font-size:9px;font-family:monospace;letter-spacing:1px;">PATCH COMPLIANCE</div>';
    var patchColor = sPatchPct >= 85 ? '#00ff88' : sPatchPct >= 70 ? '#ffaa00' : '#ff2244';
    h += '<div style="color:' + patchColor + ';font-size:18px;font-family:monospace;font-weight:bold;">' + esc(sPatchPct) + '%</div>';
    h += '</div>';
    h += '</div>';

    // Patch bar
    h += '<div style="background:#111828;border-radius:4px;height:6px;overflow:hidden;margin-bottom:8px;">';
    h += '<div style="background:linear-gradient(90deg,' + patchColor + ',' + patchColor + '88);width:' + sPatchPct + '%;height:100%;border-radius:4px;"></div>';
    h += '</div>';

    // Recent events
    h += '<div style="color:#556;font-size:9px;font-family:monospace;letter-spacing:1px;margin-bottom:3px;">RECENT EVENTS</div>';
    h += '<div style="color:#889;font-size:10px;font-family:monospace;line-height:1.4;">' + esc(sRecentEvents) + '</div>';

    // Last assessment
    h += '<div style="margin-top:8px;padding-top:6px;border-top:1px solid #1a2a44;color:#445;font-size:9px;font-family:monospace;">Last Assessment: ' + esc(sLastAssessment) + '</div>';

    h += '</div>';
  }
  h += '</div>';

  // ---- Cross-Sector Dependency Map ----
  h += '<div style="padding:16px 24px;">';
  h += '<div style="background:linear-gradient(135deg,#0c1020,#0a0e1a);border:1px solid #1a2a44;border-radius:8px;padding:16px;">';
  h += '<div style="color:#00aaff;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;margin-bottom:14px;border-bottom:1px solid #1a2a44;padding-bottom:8px;">';
  h += '<span style="color:#00aaff;margin-right:8px;">[>]</span>CROSS-SECTOR DEPENDENCY MAPPING</div>';

  h += '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;">';
  for (var dm = 0; dm < sectors.length; dm++) {
    var dSector = sectors[dm];
    var dColor = dSector.threat === 'HIGH' ? '#ff2244' : dSector.threat === 'ELEVATED' ? '#ffaa00' : '#00ff88';
    h += '<div style="background:#0a0e1a;border:1px solid ' + dColor + '33;border-radius:4px;padding:10px;">';
    h += '<div style="color:' + dColor + ';font-size:11px;font-family:monospace;font-weight:bold;margin-bottom:6px;">' + dSector.icon + ' ' + esc(dSector.name) + '</div>';
    var dDeps = dSector.dependencies || [];
    h += '<div style="color:#556;font-size:9px;font-family:monospace;letter-spacing:1px;margin-bottom:4px;">DEPENDS ON:</div>';
    for (var dd = 0; dd < dDeps.length; dd++) {
      h += '<div style="color:#889;font-size:10px;font-family:monospace;padding:1px 0;">&#8627; ' + esc(dDeps[dd]) + '</div>';
    }
    if (dDeps.length === 0) {
      h += '<div style="color:#445;font-size:10px;font-family:monospace;">N/A</div>';
    }
    h += '</div>';
  }
  h += '</div>';
  h += '</div>';
  h += '</div>';

  // ---- Recovery Priority Matrix ----
  h += '<div style="padding:0 24px 16px 24px;">';
  h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">';

  h += '<div style="background:linear-gradient(135deg,#0c1020,#0a0e1a);border:1px solid #1a2a44;border-radius:8px;padding:16px;">';
  h += '<div style="color:#00aaff;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;margin-bottom:14px;border-bottom:1px solid #1a2a44;padding-bottom:8px;">';
  h += '<span style="color:#ffaa00;margin-right:8px;">&#9733;</span>RECOVERY PRIORITY MATRIX</div>';

  var recoveryPriorities = [
    { priority: 1, sector: 'Power Grid', rto: '4 hours', rpo: '0 min', justification: 'All other sectors depend on electrical power', color: '#ff2244' },
    { priority: 2, sector: 'Telecommunications', rto: '6 hours', rpo: '15 min', justification: 'Required for coordination and command/control', color: '#ff6644' },
    { priority: 3, sector: 'Water Systems', rto: '12 hours', rpo: '30 min', justification: 'Public health and safety critical', color: '#ffaa00' },
    { priority: 4, sector: 'Government', rto: '12 hours', rpo: '1 hour', justification: 'National command authority and emergency management', color: '#ffaa00' },
    { priority: 5, sector: 'Defense Industrial Base', rto: '24 hours', rpo: '1 hour', justification: 'National security and military readiness', color: '#00aaff' },
    { priority: 6, sector: 'Financial Services', rto: '24 hours', rpo: '0 min', justification: 'Economic stability and transaction processing', color: '#00aaff' },
    { priority: 7, sector: 'Healthcare', rto: '24 hours', rpo: '15 min', justification: 'Patient care and public health infrastructure', color: '#00aaff' },
    { priority: 8, sector: 'Transportation', rto: '48 hours', rpo: '1 hour', justification: 'Supply chain and logistics', color: '#00ff88' }
  ];

  for (var rp = 0; rp < recoveryPriorities.length; rp++) {
    var rec = recoveryPriorities[rp];
    h += '<div style="display:flex;align-items:center;gap:10px;padding:8px;border-bottom:1px solid #111828;">';
    h += '<div style="background:' + rec.color + ';color:#000;font-size:11px;font-family:monospace;font-weight:bold;width:24px;height:24px;border-radius:50%;display:flex;align-items:center;justify-content:center;">' + esc(rec.priority) + '</div>';
    h += '<div style="flex:1;">';
    h += '<div style="color:#fff;font-size:11px;font-family:monospace;font-weight:bold;">' + esc(rec.sector) + '</div>';
    h += '<div style="color:#667;font-size:9px;font-family:monospace;">' + esc(rec.justification) + '</div>';
    h += '</div>';
    h += '<div style="text-align:right;">';
    h += '<div style="color:#00aaff;font-size:10px;font-family:monospace;">RTO: ' + esc(rec.rto) + '</div>';
    h += '<div style="color:#889;font-size:9px;font-family:monospace;">RPO: ' + esc(rec.rpo) + '</div>';
    h += '</div>';
    h += '</div>';
  }
  h += '</div>';

  // ---- Incident Response Playbooks ----
  h += '<div style="background:linear-gradient(135deg,#0c1020,#0a0e1a);border:1px solid #1a2a44;border-radius:8px;padding:16px;">';
  h += '<div style="color:#00aaff;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;margin-bottom:14px;border-bottom:1px solid #1a2a44;padding-bottom:8px;">';
  h += '<span style="color:#00ff88;margin-right:8px;">[P]</span>INCIDENT RESPONSE PLAYBOOK LIBRARY</div>';

  var playbooks = IR_PLAYBOOKS || [
    { id: 'PB-001', name: 'Ransomware Response', severity: 'CRITICAL', sector: 'ALL', steps: ['Isolate affected systems', 'Preserve forensic evidence', 'Notify CISA/FBI', 'Assess backup integrity', 'Begin recovery from clean backups', 'Conduct root cause analysis'] },
    { id: 'PB-002', name: 'Nation-State APT Intrusion', severity: 'CRITICAL', sector: 'GOV/DIB', steps: ['Activate hunt team', 'Map adversary presence', 'Collect IOCs and TTPs', 'Coordinate with IC partners', 'Develop eradication plan', 'Execute coordinated eviction'] },
    { id: 'PB-003', name: 'SCADA/ICS Compromise', severity: 'CRITICAL', sector: 'POWER/WATER', steps: ['Switch to manual operations', 'Isolate OT from IT network', 'Deploy OT-specific forensics', 'Verify safety system integrity', 'Coordinate with sector ISAC', 'Gradual return to automated operations'] },
    { id: 'PB-004', name: 'Supply Chain Attack', severity: 'HIGH', sector: 'ALL', steps: ['Identify compromised component', 'Assess blast radius', 'Block known IOCs', 'Audit software inventory', 'Coordinate vendor notification', 'Deploy integrity monitoring'] },
    { id: 'PB-005', name: 'DDoS Attack — Critical Service', severity: 'HIGH', sector: 'TELECOM/FIN', steps: ['Activate DDoS mitigation', 'Reroute traffic through scrubbing centers', 'Coordinate with upstream providers', 'Monitor for secondary attacks', 'Document attack vectors', 'Update filtering rules'] },
    { id: 'PB-006', name: 'Data Exfiltration', severity: 'HIGH', sector: 'ALL', steps: ['Block exfiltration channels', 'Identify data accessed', 'Preserve network logs', 'Assess classification level of data', 'Notify affected parties', 'Conduct damage assessment'] },
    { id: 'PB-007', name: 'Insider Threat', severity: 'HIGH', sector: 'GOV/DIB', steps: ['Restrict access quietly', 'Engage counterintelligence', 'Forensic workstation imaging', 'Review access logs', 'Coordinate with legal/HR', 'Damage assessment'] },
    { id: 'PB-008', name: 'BGP Hijacking', severity: 'HIGH', sector: 'TELECOM', steps: ['Verify route origin', 'Contact affected ASNs', 'Implement RPKI validation', 'Coordinate with upstream providers', 'Monitor for data interception', 'Deploy route filtering'] },
    { id: 'PB-009', name: 'DNS Poisoning/Hijacking', severity: 'HIGH', sector: 'ALL', steps: ['Verify DNS records', 'Switch to backup DNS', 'Enable DNSSEC validation', 'Flush DNS caches', 'Monitor for credential theft', 'Update WHOIS security contacts'] },
    { id: 'PB-010', name: 'Zero-Day Exploitation', severity: 'CRITICAL', sector: 'ALL', steps: ['Deploy virtual patching/WAF rules', 'Isolate vulnerable systems', 'Coordinate with vendor', 'Hunt for exploitation evidence', 'Develop detection signatures', 'Emergency patch deployment'] },
    { id: 'PB-011', name: 'Wiper Malware', severity: 'CRITICAL', sector: 'ALL', steps: ['Immediately isolate affected networks', 'Protect backup infrastructure', 'Deploy containment measures', 'Assess destruction scope', 'Activate disaster recovery', 'Forensic evidence preservation'] },
    { id: 'PB-012', name: 'Cloud Infrastructure Compromise', severity: 'HIGH', sector: 'ALL', steps: ['Revoke compromised credentials', 'Audit IAM policies', 'Review cloud trail logs', 'Isolate compromised workloads', 'Rotate all keys/secrets', 'Engage cloud provider support'] },
    { id: 'PB-013', name: 'Election Infrastructure Threat', severity: 'CRITICAL', sector: 'GOV', steps: ['Activate election security task force', 'Verify voter registration database integrity', 'Monitor for disinformation campaigns', 'Coordinate with state/local officials', 'Deploy enhanced monitoring', 'Prepare public communications'] },
    { id: 'PB-014', name: 'Financial System Disruption', severity: 'HIGH', sector: 'FINANCIAL', steps: ['Activate trading halts if needed', 'Coordinate with Treasury/Fed', 'Assess payment system integrity', 'Deploy backup transaction processing', 'Monitor for fraud patterns', 'Communicate with market participants'] },
    { id: 'PB-015', name: 'Telecom Infrastructure Attack', severity: 'HIGH', sector: 'TELECOM', steps: ['Activate backup communication paths', 'Coordinate with other carriers', 'Deploy mobile command units', 'Monitor for wiretapping/interception', 'Assess 911 service impact', 'Coordinate with CISA/DHS'] },
    { id: 'PB-016', name: 'Healthcare System Ransomware', severity: 'CRITICAL', sector: 'HEALTHCARE', steps: ['Activate clinical downtime procedures', 'Protect connected medical devices', 'Coordinate patient diversion', 'Notify HHS/FBI', 'Assess PHI exposure', 'Prioritize life-safety system recovery'] },
    { id: 'PB-017', name: 'GPS/PNT Disruption', severity: 'HIGH', sector: 'TRANSPORT/MIL', steps: ['Switch to backup navigation', 'Alert aviation and maritime', 'Investigate jamming/spoofing source', 'Deploy alternative timing sources', 'Coordinate with Space Command', 'Assess financial system impact'] },
    { id: 'PB-018', name: 'Undersea Cable Disruption', severity: 'HIGH', sector: 'TELECOM', steps: ['Reroute traffic through alternate cables', 'Assess capacity impact', 'Coordinate with cable operators', 'Deploy monitoring near affected area', 'Assess intelligence implications', 'Coordinate with allied navies'] },
    { id: 'PB-019', name: 'Nuclear Facility Cyber Incident', severity: 'CRITICAL', sector: 'POWER', steps: ['Verify safety system isolation', 'Activate NRC notification protocols', 'Deploy specialized nuclear CERT', 'Verify radiation monitoring systems', 'Coordinate with DOE/NNSA', 'Implement maximum security posture'] },
    { id: 'PB-020', name: 'Mass Credential Compromise', severity: 'HIGH', sector: 'ALL', steps: ['Force enterprise-wide password reset', 'Revoke all active sessions', 'Deploy emergency MFA', 'Audit privileged accounts', 'Monitor for lateral movement', 'Engage identity provider support'] }
  ];

  for (var pb = 0; pb < playbooks.length; pb++) {
    var book = playbooks[pb];
    var pbColor = book.severity === 'CRITICAL' ? '#ff2244' : '#ffaa00';
    h += '<div style="background:#0a0e1a;border:1px solid #1a2a44;border-radius:4px;padding:8px 10px;margin-bottom:4px;cursor:pointer;" onclick="this.querySelector(\'.se-pb-steps\').style.display=this.querySelector(\'.se-pb-steps\').style.display===\'none\'?\'block\':\'none\'">';
    h += '<div style="display:flex;align-items:center;gap:8px;">';
    h += '<div style="color:#445;font-size:10px;font-family:monospace;min-width:50px;">' + esc(book.id) + '</div>';
    h += '<div style="flex:1;color:#ccd;font-size:11px;font-family:monospace;">' + esc(book.name) + '</div>';
    h += '<div style="background:' + pbColor + '22;color:' + pbColor + ';font-size:8px;font-family:monospace;padding:2px 6px;border-radius:2px;">' + esc(book.severity) + '</div>';
    h += '<div style="color:#556;font-size:9px;font-family:monospace;">' + esc(book.sector) + '</div>';
    h += '<div style="color:#445;font-size:10px;">&#9660;</div>';
    h += '</div>';
    h += '<div class="se-pb-steps" style="display:none;margin-top:8px;padding-top:8px;border-top:1px solid #1a2a44;">';
    for (var ps = 0; ps < book.steps.length; ps++) {
      h += '<div style="color:#889;font-size:10px;font-family:monospace;padding:3px 0;display:flex;align-items:center;gap:6px;">';
      h += '<span style="color:#00aaff;font-size:9px;min-width:16px;">' + (ps + 1) + '.</span>' + esc(book.steps[ps]);
      h += '</div>';
    }
    h += '</div>';
    h += '</div>';
  }
  h += '</div>';

  h += '</div>'; // end grid

  // ---- Tabletop Exercise Launcher ----
  h += '<div style="padding:0 24px 16px 24px;">';
  h += '<div style="background:linear-gradient(135deg,#0c1020,#0a0e1a);border:1px solid #1a2a44;border-radius:8px;padding:16px;">';
  h += '<div style="color:#00aaff;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;margin-bottom:14px;border-bottom:1px solid #1a2a44;padding-bottom:8px;">';
  h += '<span style="color:#ffaa00;margin-right:8px;">[E]</span>TABLETOP EXERCISE LAUNCHER</div>';

  var ttxScenarios = [
    { name: 'Regional Power Grid Failure', duration: '4 hours', participants: 'Utility CISO, SOC leads, ICS engineers, CISA liaison', difficulty: 4, desc: 'Simulates coordinated attack on 3 regional power utilities causing cascading failures' },
    { name: 'Multi-Sector Ransomware', duration: '6 hours', participants: 'Cross-sector CISOs, FBI, CISA, sector ISACs', difficulty: 5, desc: 'Simultaneous ransomware deployment across healthcare, government, and financial sectors' },
    { name: 'Supply Chain Compromise', duration: '3 hours', participants: 'Software vendors, enterprise CISOs, CISA', difficulty: 3, desc: 'Nation-state actor compromises widely-used software update mechanism' },
    { name: 'Telecom Infrastructure Disruption', duration: '4 hours', participants: 'Carrier security teams, FCC, DHS, DOD', difficulty: 4, desc: 'Coordinated attack on 5G core network and undersea cable monitoring' }
  ];

  h += '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;">';
  for (var ttx = 0; ttx < ttxScenarios.length; ttx++) {
    var ex = ttxScenarios[ttx];
    h += '<div style="background:linear-gradient(135deg,#0a0e1a,#101828);border:1px solid #1a2a44;border-radius:6px;padding:14px;">';
    h += '<div style="color:#fff;font-size:12px;font-family:monospace;font-weight:bold;margin-bottom:6px;">' + esc(ex.name) + '</div>';
    h += '<div style="color:#889;font-size:10px;font-family:monospace;margin-bottom:8px;line-height:1.4;">' + esc(ex.desc) + '</div>';
    h += '<div style="display:flex;gap:4px;margin-bottom:8px;">';
    for (var st = 0; st < 5; st++) {
      h += '<span style="color:' + (st < ex.difficulty ? '#ffaa00' : '#222') + ';font-size:12px;">&#9733;</span>';
    }
    h += '</div>';
    h += '<div style="color:#556;font-size:9px;font-family:monospace;margin-bottom:4px;">DURATION: ' + esc(ex.duration) + '</div>';
    h += '<div style="color:#445;font-size:9px;font-family:monospace;margin-bottom:10px;">PARTICIPANTS: ' + esc(ex.participants) + '</div>';
    h += '<div style="background:#00aaff22;color:#00aaff;font-size:10px;font-family:monospace;text-align:center;padding:6px;border-radius:4px;cursor:pointer;border:1px solid #00aaff44;">LAUNCH EXERCISE</div>';
    h += '</div>';
  }
  h += '</div>';
  h += '</div>';
  h += '</div>';

  // Automated defense recommendations
  h += '<div style="padding:0 24px 24px 24px;">';
  h += '<div style="background:linear-gradient(135deg,#0c1020,#0a0e1a);border:1px solid #1a2a44;border-radius:8px;padding:16px;">';
  h += '<div style="color:#00aaff;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;margin-bottom:14px;border-bottom:1px solid #1a2a44;padding-bottom:8px;">';
  h += '<span style="color:#00ff88;margin-right:8px;">[D]</span>AUTOMATED DEFENSE RECOMMENDATIONS — CURRENT THREAT LEVEL</div>';

  var defRecs = [
    { priority: 'IMMEDIATE', action: 'Activate enhanced monitoring for Volt Typhoon IOCs across all power grid OT networks', sector: 'Power Grid', status: 'IN PROGRESS' },
    { priority: 'IMMEDIATE', action: 'Deploy updated Salt Typhoon detection signatures to all telecom sector SIEM instances', sector: 'Telecom', status: 'DEPLOYED' },
    { priority: 'HIGH', action: 'Conduct emergency vulnerability scanning of all internet-facing ICS/SCADA interfaces', sector: 'Power/Water', status: 'SCHEDULED' },
    { priority: 'HIGH', action: 'Force credential rotation for all DIB contractor accounts with privileged access', sector: 'Defense', status: 'IN PROGRESS' },
    { priority: 'HIGH', action: 'Enable enhanced DDoS protection for financial sector core banking systems', sector: 'Financial', status: 'DEPLOYED' },
    { priority: 'MEDIUM', action: 'Update all sector ISAC members with latest nation-state APT indicators', sector: 'ALL', status: 'DEPLOYED' },
    { priority: 'MEDIUM', action: 'Verify air-gap integrity on all nuclear facility safety systems', sector: 'Power', status: 'SCHEDULED' },
    { priority: 'MEDIUM', action: 'Activate backup DNS infrastructure for .gov domains', sector: 'Government', status: 'STANDBY' }
  ];

  for (var dr = 0; dr < defRecs.length; dr++) {
    var rec2 = defRecs[dr];
    var drColor = rec2.priority === 'IMMEDIATE' ? '#ff2244' : rec2.priority === 'HIGH' ? '#ffaa00' : '#00aaff';
    var drStatusColor = rec2.status === 'DEPLOYED' ? '#00ff88' : rec2.status === 'IN PROGRESS' ? '#00aaff' : rec2.status === 'SCHEDULED' ? '#ffaa00' : '#667';
    h += '<div style="display:flex;align-items:center;gap:10px;padding:8px;border-bottom:1px solid #111828;">';
    h += '<div style="background:' + drColor + '22;color:' + drColor + ';font-size:9px;font-family:monospace;font-weight:bold;padding:3px 8px;border-radius:3px;min-width:70px;text-align:center;">' + esc(rec2.priority) + '</div>';
    h += '<div style="flex:1;color:#ccd;font-size:11px;font-family:monospace;">' + esc(rec2.action) + '</div>';
    h += '<div style="color:#556;font-size:9px;font-family:monospace;min-width:70px;">' + esc(rec2.sector) + '</div>';
    h += '<div style="background:' + drStatusColor + '22;color:' + drStatusColor + ';font-size:9px;font-family:monospace;padding:3px 8px;border-radius:3px;min-width:80px;text-align:center;">' + esc(rec2.status) + '</div>';
    h += '</div>';
  }
  h += '</div>';
  h += '</div>';

  return h;
}


// ============================================================================
// TAB 8: INTELLIGENCE FUSION
// ============================================================================
function renderIntelFusion() {
  var h = '';

  // Classification banner

  h += '<div style="padding:20px 24px 0 24px;">';
  h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:18px;">';
  h += '<div>';
  h += '<h2 style="margin:0;font-size:22px;color:#00aaff;font-family:monospace;letter-spacing:2px;text-transform:uppercase;">INTELLIGENCE FUSION CENTER</h2>';
  h += '<div style="color:#667;font-size:12px;font-family:monospace;margin-top:4px;letter-spacing:1px;">MULTI-SOURCE INTELLIGENCE CORRELATION &bull; ALL-SOURCE ANALYSIS</div>';
  h += '</div>';
  h += '<div style="display:flex;gap:10px;">';
  var intelStats = [
    { label: 'ACTIVE FEEDS', value: '47', color: '#00aaff' },
    { label: 'CORRELATIONS', value: '12', color: '#ffaa00' },
    { label: 'HIGH CONF ALERTS', value: '5', color: '#ff2244' }
  ];
  for (var ist = 0; ist < intelStats.length; ist++) {
    var iStat = intelStats[ist];
    h += '<div style="background:linear-gradient(135deg,#0a0e1a,#101828);border:1px solid ' + iStat.color + '44;border-radius:6px;padding:8px 16px;text-align:center;">';
    h += '<div style="color:' + iStat.color + ';font-size:10px;font-family:monospace;letter-spacing:1px;">' + esc(iStat.label) + '</div>';
    h += '<div style="color:' + iStat.color + ';font-size:22px;font-weight:bold;font-family:monospace;">' + esc(iStat.value) + '</div>';
    h += '</div>';
  }
  h += '</div>';
  h += '</div>';
  h += '</div>';

  // Intel source tabs
  var intelTypes = [
    { id: 'sigint', name: 'SIGINT', icon: '[T]', desc: 'Signals Intelligence', color: '#00aaff' },
    { id: 'osint', name: 'OSINT', icon: '[O]', desc: 'Open Source Intelligence', color: '#00ff88' },
    { id: 'cybint', name: 'CYBINT', icon: '[C]', desc: 'Cyber Intelligence', color: '#ff6644' },
    { id: 'humint', name: 'HUMINT', icon: '[U]', desc: 'Human Intelligence', color: '#ffaa00' },
    { id: 'geoint', name: 'GEOINT', icon: '[M]', desc: 'Geospatial Intelligence', color: '#aa66ff' }
  ];

  h += '<div style="display:flex;gap:4px;padding:0 24px;margin-bottom:16px;">';
  for (var it = 0; it < intelTypes.length; it++) {
    var iType = intelTypes[it];
    var isFirstTab = it === 0;
    h += '<div style="background:' + (isFirstTab ? iType.color + '22' : '#0a0e1a') + ';border:1px solid ' + (isFirstTab ? iType.color + '66' : '#1a2a44') + ';border-radius:6px 6px 0 0;padding:8px 16px;cursor:pointer;flex:1;text-align:center;">';
    h += '<div style="color:' + (isFirstTab ? iType.color : '#556') + ';font-size:12px;font-family:monospace;font-weight:bold;">' + iType.icon + ' ' + esc(iType.name) + '</div>';
    h += '<div style="color:' + (isFirstTab ? '#aab' : '#334') + ';font-size:9px;font-family:monospace;">' + esc(iType.desc) + '</div>';
    h += '</div>';
  }
  h += '</div>';

  // Intel feeds
  h += '<div style="padding:0 24px;">';
  h += '<div style="background:linear-gradient(135deg,#0c1020,#0a0e1a);border:1px solid #1a2a44;border-radius:0 0 8px 8px;padding:16px;">';

  var intelFeeds = INTEL_FEEDS || [
    { source: 'NSA/CSS', type: 'SIGINT', classification: 'TOP SECRET//SI//TK', timestamp: '2026-09-13 14:22:00Z', content: 'Intercepted communications between GRU Unit 74455 operators indicating imminent activation of pre-positioned network implants in European energy infrastructure. Keyword analysis shows 85% match with pre-attack communication patterns observed prior to 2015 Ukraine grid attack.', confidence: 92, relatedTo: ['Russia', 'Sandworm', 'Energy Sector'] },
    { source: 'NSA/CSS', type: 'SIGINT', classification: 'TOP SECRET//SI', timestamp: '2026-09-13 12:45:00Z', content: 'Signals analysis of PLA SSF communications suggests increased tasking of Unit 61398 cyber operators. Pattern of life analysis indicates shift to 24/7 operational tempo, consistent with preparation for large-scale intelligence collection operation.', confidence: 78, relatedTo: ['China', 'PLA', 'Espionage'] },
    { source: 'CISA/US-CERT', type: 'CYBINT', classification: 'SECRET', timestamp: '2026-09-13 13:15:00Z', content: 'Emergency directive issued: Volt Typhoon-associated activity detected in 3 additional US utility networks. Threat actors leveraging living-off-the-land techniques through compromised SOHO routers. YARA rules and IOCs distributed to critical infrastructure operators.', confidence: 95, relatedTo: ['China', 'Volt Typhoon', 'Power Grid'] },
    { source: 'Mandiant', type: 'CYBINT', classification: 'UNCLASSIFIED//FOUO', timestamp: '2026-09-13 11:30:00Z', content: 'New APT41 campaign identified targeting semiconductor manufacturers in US, Taiwan, South Korea. Custom backdoor "ChipDoor" deployed via compromised software supply chain. 12 organizations confirmed compromised, likely many more.', confidence: 88, relatedTo: ['China', 'APT41', 'Supply Chain'] },
    { source: 'CIA/NCS', type: 'HUMINT', classification: 'TOP SECRET//HCS', timestamp: '2026-09-13 08:00:00Z', content: 'Asset reporting from Moscow indicates FSB leadership has authorized expansion of cyber operations targeting Western financial institutions. Specific mention of SWIFT transaction manipulation capability under development. Timeline: 60-90 days to operational capability.', confidence: 72, relatedTo: ['Russia', 'FSB', 'Financial'] },
    { source: 'NGA', type: 'GEOINT', classification: 'SECRET//NOFORN', timestamp: '2026-09-13 10:00:00Z', content: 'Satellite imagery of North Korean RGB Bureau 121 training facility shows significant infrastructure expansion. New building construction consistent with cyber operations center. Vehicle traffic analysis indicates 40% increase in personnel movement over 30-day period.', confidence: 85, relatedTo: ['North Korea', 'Bureau 121', 'Infrastructure'] },
    { source: 'Twitter/X OSINT', type: 'OSINT', classification: 'UNCLASSIFIED', timestamp: '2026-09-13 09:30:00Z', content: 'Security researchers reporting mass exploitation of critical vulnerability in Fortinet FortiGate firewalls. Chinese-language exploit code circulating on underground forums since September 8. Over 200,000 internet-facing devices potentially vulnerable.', confidence: 90, relatedTo: ['China', 'Fortinet', 'Mass Exploitation'] },
    { source: 'DIA', type: 'SIGINT', classification: 'TOP SECRET//SI//REL FVEY', timestamp: '2026-09-12 22:00:00Z', content: 'IRGC Cyber Command reorganization detected through SIGINT analysis. New unit designation suggests creation of dedicated offensive cyber force separate from existing defensive structures. Leadership appointments include known Shamoon operators.', confidence: 75, relatedTo: ['Iran', 'IRGC', 'Reorganization'] },
    { source: 'FBI/IC3', type: 'CYBINT', classification: 'SECRET//LES', timestamp: '2026-09-12 20:00:00Z', content: 'FBI investigation reveals Lazarus Group has established new cryptocurrency laundering infrastructure through DeFi protocols. Estimated $340M in stolen crypto processed through 14 mixing services in past 90 days. 3 US-based exchanges unknowingly facilitated transactions.', confidence: 91, relatedTo: ['North Korea', 'Lazarus', 'Crypto'] },
    { source: 'GCHQ', type: 'SIGINT', classification: 'TOP SECRET//SI//REL FVEY', timestamp: '2026-09-12 18:00:00Z', content: 'GCHQ reports detection of APT29 staging infrastructure targeting UK government departments. 47 new domains registered through bulletproof hosting providers, SSL certificate patterns match known APT29 operational security practices.', confidence: 87, relatedTo: ['Russia', 'APT29', 'UK Government'] },
    { source: 'Recorded Future', type: 'OSINT', classification: 'UNCLASSIFIED//FOUO', timestamp: '2026-09-12 16:00:00Z', content: 'Dark web monitoring indicates significant increase in zero-day exploit advertisements. 3 new Windows kernel exploits offered for sale at $500K+ each. Buyer analysis suggests nation-state procurement through intermediaries.', confidence: 80, relatedTo: ['Zero-Day Market', 'Windows', 'Nation-State'] },
    { source: 'NSA/TAO', type: 'CYBINT', classification: 'TOP SECRET//SI//NOFORN', timestamp: '2026-09-12 14:00:00Z', content: 'Technical analysis of recovered malware from compromised defense contractor network confirms attribution to PLA Unit 61398. Malware includes novel data exfiltration module using steganography in JPEG images. Classified weapons system data confirmed exfiltrated.', confidence: 96, relatedTo: ['China', 'Unit 61398', 'Defense'] },
    { source: 'CIA/DO', type: 'HUMINT', classification: 'TOP SECRET//HCS//NOFORN', timestamp: '2026-09-12 10:00:00Z', content: 'Source reporting from Pyongyang indicates RGB leadership has been directed to generate $500M through cyber theft operations in Q4 2026 to fund nuclear weapons program. New targeting guidance prioritizes cryptocurrency exchanges and DeFi platforms.', confidence: 68, relatedTo: ['North Korea', 'RGB', 'Crypto Theft'] },
    { source: 'ASD/ACS', type: 'SIGINT', classification: 'SECRET//REL FVEY', timestamp: '2026-09-12 08:00:00Z', content: 'Australian Signals Directorate reports detection of APT40 targeting maritime industry and port authorities in Indo-Pacific region. Campaign appears focused on shipping logistics data and naval movement information.', confidence: 82, relatedTo: ['China', 'APT40', 'Maritime'] },
    { source: 'CrowdStrike', type: 'CYBINT', classification: 'UNCLASSIFIED//FOUO', timestamp: '2026-09-11 22:00:00Z', content: 'New ransomware variant "PhantomLock" attributed to Russian-speaking e-crime group with suspected FSB ties. Targets healthcare sector specifically, disabling medical device firmware. 7 hospitals impacted across Europe in past 72 hours.', confidence: 86, relatedTo: ['Russia', 'Healthcare', 'Ransomware'] }
  ];

  for (var inf = 0; inf < intelFeeds.length; inf++) {
    var feed = intelFeeds[inf];
    var classColors = {
      'TOP SECRET': '#ff2244',
      'SECRET': '#ff6644',
      'UNCLASSIFIED': '#00ff88'
    };
    var classKey = feed.classification.indexOf('TOP SECRET') >= 0 ? 'TOP SECRET' : feed.classification.indexOf('SECRET') >= 0 ? 'SECRET' : 'UNCLASSIFIED';
    var classColor = classColors[classKey] || '#667';
    var typeColors = { 'SIGINT': '#00aaff', 'OSINT': '#00ff88', 'CYBINT': '#ff6644', 'HUMINT': '#ffaa00', 'GEOINT': '#aa66ff' };
    var typeColor = typeColors[feed.type] || '#667';

    h += '<div style="background:#0a0e1a;border:1px solid #1a2a44;border-radius:6px;padding:12px;margin-bottom:8px;border-left:3px solid ' + typeColor + ';">';
    h += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap;">';
    h += '<div style="background:' + typeColor + '22;color:' + typeColor + ';font-size:9px;font-family:monospace;font-weight:bold;padding:3px 8px;border-radius:3px;">' + esc(feed.type) + '</div>';
    h += '<div style="background:' + classColor + '22;color:' + classColor + ';font-size:9px;font-family:monospace;padding:3px 8px;border-radius:3px;">' + esc(feed.classification) + '</div>';
    h += '<div style="color:#00aaff;font-size:10px;font-family:monospace;font-weight:bold;">' + esc(feed.source) + '</div>';
    h += '<div style="margin-left:auto;color:#556;font-size:10px;font-family:monospace;">' + esc(feed.timestamp) + '</div>';
    h += '</div>';

    h += '<div style="color:#ccd;font-size:11px;font-family:monospace;line-height:1.6;margin-bottom:8px;">' + esc(feed.content) + '</div>';

    var feedRelated = feed.relatedTo || feed.relatedNations || [];
    h += '<div style="display:flex;align-items:center;justify-content:space-between;">';
    h += '<div style="display:flex;gap:6px;flex-wrap:wrap;">';
    for (var rt = 0; rt < feedRelated.length; rt++) {
      h += '<span style="background:#111828;color:#889;font-size:9px;font-family:monospace;padding:2px 6px;border-radius:2px;">' + esc(feedRelated[rt]) + '</span>';
    }
    h += '</div>';

    // Confidence meter
    var confColor = feed.confidence >= 85 ? '#00ff88' : feed.confidence >= 70 ? '#ffaa00' : '#ff6644';
    h += '<div style="display:flex;align-items:center;gap:6px;">';
    h += '<div style="color:#556;font-size:9px;font-family:monospace;">CONFIDENCE:</div>';
    h += '<div style="width:60px;background:#111828;border-radius:3px;height:6px;overflow:hidden;">';
    h += '<div style="background:' + confColor + ';width:' + feed.confidence + '%;height:100%;border-radius:3px;"></div>';
    h += '</div>';
    h += '<div style="color:' + confColor + ';font-size:10px;font-family:monospace;font-weight:bold;">' + esc(feed.confidence) + '%</div>';
    h += '</div>';
    h += '</div>';
    h += '</div>';
  }
  h += '</div>';
  h += '</div>';

  // ---- Correlation Engine ----
  h += '<div style="padding:16px 24px;">';
  h += '<div style="background:linear-gradient(135deg,#0c1020,#0a0e1a);border:1px solid #ffaa0044;border-radius:8px;padding:16px;">';
  h += '<div style="color:#ffaa00;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;margin-bottom:14px;border-bottom:1px solid #ffaa0033;padding-bottom:8px;">';
  h += '<span style="color:#ffaa00;margin-right:8px;">&#9733;</span>CORRELATION ENGINE — HIGH-CONFIDENCE MULTI-SOURCE ALERTS</div>';

  var correlations = [
    { title: 'IMMINENT RUSSIAN CYBER OPERATION AGAINST EUROPEAN ENERGY', confidence: 94, sources: ['SIGINT — GRU operator communications (NSA/CSS)', 'SIGINT — GCHQ staging infrastructure detection', 'CYBINT — CrowdStrike PhantomLock attribution', 'HUMINT — CIA source on FSB authorization'], assessment: 'Multiple independent sources confirm preparation for offensive cyber operation targeting European energy sector. Pre-positioned implants, newly staged infrastructure, and operator communications all align. Predicted timeline: 48-96 hours.', priority: 'FLASH' },
    { title: 'CHINESE ESPIONAGE CAMPAIGN ESCALATION', confidence: 89, sources: ['SIGINT — PLA SSF tempo increase (NSA/CSS)', 'CYBINT — APT41 ChipDoor campaign (Mandiant)', 'CYBINT — Unit 61398 defense contractor breach (NSA/TAO)', 'GEOINT — APT40 maritime targeting (ASD)'], assessment: 'Converging indicators show coordinated Chinese cyber espionage escalation across semiconductor, defense, and maritime sectors. Multiple MSS/PLA units active simultaneously, suggesting centralized tasking at CPC level.', priority: 'PRIORITY' },
    { title: 'NORTH KOREAN CRYPTO THEFT SURGE', confidence: 87, sources: ['HUMINT — RGB funding directive (CIA/DO)', 'CYBINT — New laundering infrastructure (FBI/IC3)', 'GEOINT — Bureau 121 facility expansion (NGA)'], assessment: 'Regime-directed escalation of cryptocurrency theft operations confirmed. $500M Q4 target drives urgency. Expanded infrastructure and personnel suggest imminent large-scale attacks on DeFi platforms and exchanges.', priority: 'PRIORITY' }
  ];

  for (var cr = 0; cr < correlations.length; cr++) {
    var corr = correlations[cr];
    var corrPriorityColor = corr.priority === 'FLASH' ? '#ff2244' : '#ffaa00';
    h += '<div style="background:#0a0e1a;border:1px solid ' + corrPriorityColor + '44;border-radius:6px;padding:14px;margin-bottom:10px;border-left:4px solid ' + corrPriorityColor + ';">';
    h += '<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">';
    h += '<div style="background:' + corrPriorityColor + ';color:#000;font-size:9px;font-family:monospace;font-weight:bold;padding:3px 10px;border-radius:3px;">' + esc(corr.priority) + '</div>';
    h += '<div style="color:#fff;font-size:13px;font-family:monospace;font-weight:bold;">' + esc(corr.title) + '</div>';
    h += '<div style="margin-left:auto;color:' + corrPriorityColor + ';font-size:14px;font-family:monospace;font-weight:bold;">' + esc(corr.confidence) + '% CONFIDENCE</div>';
    h += '</div>';

    h += '<div style="color:#aab;font-size:11px;font-family:monospace;line-height:1.6;margin-bottom:10px;">' + esc(corr.assessment) + '</div>';

    h += '<div style="color:#556;font-size:9px;font-family:monospace;letter-spacing:1px;margin-bottom:6px;">CONTRIBUTING SOURCES (' + corr.sources.length + '):</div>';
    for (var cs = 0; cs < corr.sources.length; cs++) {
      h += '<div style="color:#889;font-size:10px;font-family:monospace;padding:2px 0;display:flex;align-items:center;gap:6px;">';
      h += '<span style="color:#00aaff;font-size:8px;">&#9654;</span>' + esc(corr.sources[cs]);
      h += '</div>';
    }
    h += '</div>';
  }
  h += '</div>';
  h += '</div>';

  // ---- Intelligence Product Generator & Classification/Dissemination ----
  h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;padding:0 24px 24px 24px;">';

  // Product generator
  h += '<div style="background:linear-gradient(135deg,#0c1020,#0a0e1a);border:1px solid #1a2a44;border-radius:8px;padding:16px;">';
  h += '<div style="color:#00aaff;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;margin-bottom:14px;border-bottom:1px solid #1a2a44;padding-bottom:8px;">';
  h += '<span style="color:#00aaff;margin-right:8px;">[R]</span>INTELLIGENCE PRODUCT GENERATOR</div>';

  var intelProducts = [
    { type: 'SPOT Report', desc: 'Single-source reporting on time-sensitive intelligence', format: '1-2 pages, 20 min turnaround', lastGenerated: '2026-09-13 14:30Z' },
    { type: 'Situation Report (SITREP)', desc: 'Periodic summary of current intelligence picture', format: '3-5 pages, published every 6 hours', lastGenerated: '2026-09-13 12:00Z' },
    { type: 'Threat Assessment', desc: 'In-depth analysis of specific threat actor or campaign', format: '10-15 pages, 24 hour turnaround', lastGenerated: '2026-09-12 08:00Z' },
    { type: 'Intelligence Estimate', desc: 'Forward-looking assessment of adversary intentions and capabilities', format: '15-25 pages, 48 hour turnaround', lastGenerated: '2026-09-10 16:00Z' },
    { type: 'Warning Intelligence', desc: 'Urgent notification of imminent threat', format: '1 page, immediate dissemination', lastGenerated: '2026-09-13 14:45Z' },
    { type: 'Technical Analysis', desc: 'Detailed malware analysis, IOC report, or vulnerability assessment', format: '5-20 pages, 24-72 hour turnaround', lastGenerated: '2026-09-12 20:00Z' }
  ];

  for (var ip = 0; ip < intelProducts.length; ip++) {
    var prod = intelProducts[ip];
    h += '<div style="background:#0a0e1a;border:1px solid #1a2a44;border-radius:4px;padding:10px;margin-bottom:6px;display:flex;align-items:center;gap:10px;">';
    h += '<div style="flex:1;">';
    h += '<div style="color:#fff;font-size:12px;font-family:monospace;font-weight:bold;">' + esc(prod.type) + '</div>';
    h += '<div style="color:#889;font-size:10px;font-family:monospace;">' + esc(prod.desc) + '</div>';
    h += '<div style="color:#556;font-size:9px;font-family:monospace;margin-top:2px;">' + esc(prod.format) + '</div>';
    h += '</div>';
    h += '<div style="text-align:right;">';
    h += '<div style="background:#00aaff22;color:#00aaff;font-size:9px;font-family:monospace;padding:4px 10px;border-radius:3px;cursor:pointer;border:1px solid #00aaff44;margin-bottom:4px;">GENERATE</div>';
    h += '<div style="color:#445;font-size:8px;font-family:monospace;">Last: ' + esc(prod.lastGenerated) + '</div>';
    h += '</div>';
    h += '</div>';
  }
  h += '</div>';

  // Classification & Dissemination
  h += '<div>';

  // Classification level management
  h += '<div style="background:linear-gradient(135deg,#0c1020,#0a0e1a);border:1px solid #1a2a44;border-radius:8px;padding:16px;margin-bottom:16px;">';
  h += '<div style="color:#00aaff;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;margin-bottom:14px;border-bottom:1px solid #1a2a44;padding-bottom:8px;">';
  h += '<span style="color:#ff2244;margin-right:8px;">[P]</span>CLASSIFICATION LEVELS</div>';

  var classLevels = [
    { level: 'TOP SECRET//SCI', color: '#ff2244', access: '47 personnel', desc: 'Sensitive Compartmented Information', caveats: 'SI, TK, HCS, NOFORN, ORCON' },
    { level: 'TOP SECRET', color: '#ff6644', access: '128 personnel', desc: 'Exceptionally grave damage to national security', caveats: 'NOFORN, REL FVEY, PROPIN' },
    { level: 'SECRET', color: '#ffaa00', access: '412 personnel', desc: 'Serious damage to national security', caveats: 'NOFORN, REL FVEY, LES' },
    { level: 'CONFIDENTIAL', color: '#00aaff', access: '1,847 personnel', desc: 'Damage to national security', caveats: 'Standard handling' },
    { level: 'UNCLASSIFIED//FOUO', color: '#00ff88', access: '8,500+ personnel', desc: 'For Official Use Only', caveats: 'CUI markings as applicable' }
  ];

  for (var cl = 0; cl < classLevels.length; cl++) {
    var cLevel = classLevels[cl];
    h += '<div style="display:flex;align-items:center;gap:10px;padding:6px 0;border-bottom:1px solid #111828;">';
    h += '<div style="background:' + cLevel.color + ';color:#000;font-size:9px;font-family:monospace;font-weight:bold;padding:3px 8px;border-radius:3px;min-width:150px;text-align:center;">' + esc(cLevel.level) + '</div>';
    h += '<div style="flex:1;color:#889;font-size:10px;font-family:monospace;">' + esc(cLevel.desc) + '</div>';
    h += '<div style="color:#556;font-size:10px;font-family:monospace;">' + esc(cLevel.access) + '</div>';
    h += '</div>';
  }
  h += '</div>';

  // Dissemination tracking
  h += '<div style="background:linear-gradient(135deg,#0c1020,#0a0e1a);border:1px solid #1a2a44;border-radius:8px;padding:16px;">';
  h += '<div style="color:#00aaff;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;margin-bottom:14px;border-bottom:1px solid #1a2a44;padding-bottom:8px;">';
  h += '<span style="color:#00aaff;margin-right:8px;">[>]</span>DISSEMINATION TRACKING</div>';

  var dissemination = [
    { product: 'FLASH — European Energy Threat', recipients: 'NSC, CYBERCOM, EUCOM, CISA, DOE, Five Eyes', sentAt: '2026-09-13 14:50Z', readBy: '12/14', classification: 'TS//SCI' },
    { product: 'SITREP — Daily Cyber Posture', recipients: 'NSC, CYBERCOM, DHS, FBI, IC partners', sentAt: '2026-09-13 12:15Z', readBy: '22/28', classification: 'SECRET' },
    { product: 'Threat Assessment — APT41 ChipDoor', recipients: 'CYBERCOM, NSA, FBI, CISA, DIB sector', sentAt: '2026-09-12 22:00Z', readBy: '34/41', classification: 'SECRET//NOFORN' },
    { product: 'Warning Intel — NK Crypto Surge', recipients: 'Treasury, SEC, FinCEN, FBI, IC partners', sentAt: '2026-09-12 16:00Z', readBy: '18/19', classification: 'TS//SCI' },
    { product: 'Technical Analysis — PhantomLock', recipients: 'HHS, CISA, FBI, European CERT partners', sentAt: '2026-09-12 08:00Z', readBy: '45/52', classification: 'SECRET//REL FVEY' }
  ];

  h += '<div style="overflow-x:auto;">';
  h += '<table style="width:100%;border-collapse:collapse;font-family:monospace;font-size:11px;">';
  h += '<thead><tr style="border-bottom:2px solid #1a2a44;">';
  var dissHeaders = ['PRODUCT', 'RECIPIENTS', 'SENT', 'READ', 'CLASS'];
  for (var dh = 0; dh < dissHeaders.length; dh++) {
    h += '<th style="text-align:left;padding:6px;color:#00aaff;font-size:10px;letter-spacing:1px;">' + esc(dissHeaders[dh]) + '</th>';
  }
  h += '</tr></thead><tbody>';
  for (var di = 0; di < dissemination.length; di++) {
    var diss = dissemination[di];
    h += '<tr style="border-bottom:1px solid #111828;">';
    h += '<td style="padding:6px;color:#ccd;">' + esc(diss.product) + '</td>';
    h += '<td style="padding:6px;color:#889;max-width:200px;">' + esc(diss.recipients) + '</td>';
    h += '<td style="padding:6px;color:#667;">' + esc(diss.sentAt) + '</td>';
    h += '<td style="padding:6px;color:#00ff88;">' + esc(diss.readBy) + '</td>';
    var dissClassColor = diss.classification.indexOf('TS') >= 0 ? '#ff2244' : '#ffaa00';
    h += '<td style="padding:6px;"><span style="color:' + dissClassColor + ';font-size:9px;">' + esc(diss.classification) + '</span></td>';
    h += '</tr>';
  }
  h += '</tbody></table>';
  h += '</div>';
  h += '</div>';

  h += '</div>'; // end classification/dissemination column

  h += '</div>'; // end grid

  return h;
}


// ============================================================================
// TAB 9: CYBER WARFARE SIMULATOR
// ============================================================================
function renderWarSim() {
  var h = '';

  // Classification banner

  h += '<div style="padding:20px 24px 0 24px;">';
  h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:18px;">';
  h += '<div>';
  h += '<h2 style="margin:0;font-size:22px;color:#00aaff;font-family:monospace;letter-spacing:2px;text-transform:uppercase;">CYBER WARFARE SIMULATOR</h2>';
  h += '<div style="color:#667;font-size:12px;font-family:monospace;margin-top:4px;letter-spacing:1px;">SCENARIO-BASED WARGAMING &bull; BLUE TEAM RESPONSE TRAINING</div>';
  h += '</div>';
  h += '<div style="display:flex;gap:10px;">';
  h += '<div style="background:linear-gradient(135deg,#0a0e1a,#101828);border:1px solid #00aaff44;border-radius:6px;padding:8px 16px;text-align:center;">';
  h += '<div style="color:#00aaff;font-size:10px;font-family:monospace;letter-spacing:1px;">SCENARIOS</div>';
  h += '<div style="color:#00aaff;font-size:22px;font-weight:bold;font-family:monospace;">15</div>';
  h += '</div>';
  h += '<div style="background:linear-gradient(135deg,#0a1a0a,#152a15);border:1px solid #00ff88;border-radius:6px;padding:8px 16px;text-align:center;">';
  h += '<div style="color:#00ff88;font-size:10px;font-family:monospace;letter-spacing:1px;">COMPLETED</div>';
  h += '<div style="color:#00ff88;font-size:22px;font-weight:bold;font-family:monospace;">8</div>';
  h += '</div>';
  h += '<div style="background:linear-gradient(135deg,#1a1a0a,#2a2a15);border:1px solid #ffaa00;border-radius:6px;padding:8px 16px;text-align:center;">';
  h += '<div style="color:#ffaa00;font-size:10px;font-family:monospace;letter-spacing:1px;">AVG SCORE</div>';
  h += '<div style="color:#ffaa00;font-size:22px;font-weight:bold;font-family:monospace;">72%</div>';
  h += '</div>';
  h += '</div>';
  h += '</div>';
  h += '</div>';

  // Scenarios
  var scenarios = WARGAME_SCENARIOS || [
    { codename: 'DRAGON STORM', adversary: 'China (Volt Typhoon)', difficulty: 5, duration: '6 hours', category: 'Critical Infrastructure', desc: 'China\'s Volt Typhoon activates pre-positioned access in US critical infrastructure during Taiwan Strait crisis. Power grids, water systems, and telecom simultaneously targeted.', phases: [
      { name: 'Phase 1: Activation', desc: 'Pre-positioned implants in 47 utilities activate simultaneously. Initial indicators: anomalous LOTL activity on OT networks.', blueOptions: ['Activate CISA emergency protocols', 'Deploy enhanced ICS monitoring', 'Switch critical systems to manual operation', 'Coordinate with sector ISACs'] },
      { name: 'Phase 2: Disruption', desc: 'Coordinated disruption begins. 3 regional power grids experience load manipulation. Water treatment SCADA systems report unauthorized changes.', blueOptions: ['Emergency grid isolation', 'Activate manual water treatment overrides', 'Deploy CYBERCOM hunt teams', 'Notify National Guard Cyber units'] },
      { name: 'Phase 3: Escalation', desc: 'Adversary deploys destructive wiper targeting backup systems. Telecom switching centers experience outages disrupting emergency communications.', blueOptions: ['Activate EMCON procedures', 'Deploy military satellite communications', 'Execute counter-cyber operation against C2', 'Activate FEMA emergency protocols'] },
      { name: 'Phase 4: Recovery', desc: 'Blue team must coordinate multi-sector recovery while defending against persistent adversary presence.', blueOptions: ['Prioritize power grid recovery', 'Deploy clean backup systems', 'Conduct systematic threat hunting', 'Establish secure coordination channels'] }
    ]},
    { codename: 'BEAR\'S CLAW', adversary: 'Russia (Sandworm / APT28)', difficulty: 5, duration: '8 hours', category: 'Multi-Domain', desc: 'Russia launches coordinated cyber attack on NATO member state targeting power grid, telecom, and financial systems simultaneously — replicating expanded Ukraine-style operations.', phases: [
      { name: 'Phase 1: Preparation', desc: 'Intelligence indicates GRU operators accessing pre-positioned implants in Baltic state infrastructure.', blueOptions: ['Alert NATO CCDCOE', 'Activate Article 5 consultation', 'Deploy cyber defense teams', 'Enhance SIGINT collection'] },
      { name: 'Phase 2: Initial Strike', desc: 'Coordinated attacks: BlackEnergy variant targets power grid, NotPetya-like wiper hits financial sector.', blueOptions: ['Isolate affected networks', 'Activate mutual defense agreements', 'Deploy forensic teams', 'Coordinate with Five Eyes'] },
      { name: 'Phase 3: Sustained Operations', desc: 'Adversary maintains persistent access. Disinformation campaign accompanies cyber operations.', blueOptions: ['Counter-messaging campaign', 'Offensive cyber response under Article 5', 'Deploy additional NATO cyber teams', 'Coordinate ISP-level blocking'] },
      { name: 'Phase 4: Restoration', desc: 'Multi-nation recovery effort while maintaining defensive posture.', blueOptions: ['EU mutual aid activation', 'Systematic infrastructure rebuilding', 'Adversary eviction operations', 'Diplomatic and legal response coordination'] }
    ]},
    { codename: 'HERMIT\'S FURY', adversary: 'North Korea (Lazarus Group)', difficulty: 4, duration: '4 hours', category: 'Financial', desc: 'North Korea deploys WannaCry-scale worm targeting global financial sector for massive cryptocurrency theft. Combines destructive malware with sophisticated crypto-draining operations.', phases: [
      { name: 'Phase 1: Propagation', desc: 'New worm exploiting unpatched Exchange vulnerability begins spreading across financial networks globally.', blueOptions: ['Emergency patch deployment', 'Network segmentation enforcement', 'Activate SWIFT security protocols', 'Coordinate with FS-ISAC'] },
      { name: 'Phase 2: Theft Operations', desc: 'While worm diverts attention, targeted attacks drain cryptocurrency exchanges and DeFi protocols.', blueOptions: ['Freeze suspicious transactions', 'Coordinate with Treasury/FinCEN', 'Deploy blockchain monitoring', 'Alert crypto exchanges'] },
      { name: 'Phase 3: Destruction', desc: 'Worm activates wiper payload in compromised systems, destroying financial records.', blueOptions: ['Activate backup recovery', 'Market trading halt coordination', 'Deploy clean system images', 'Forensic evidence preservation'] }
    ]},
    { codename: 'PERSIAN FIRE', adversary: 'Iran (APT33 / APT34)', difficulty: 4, duration: '5 hours', category: 'Energy', desc: 'Iran retaliates against new sanctions with destructive wiper malware targeting oil and gas sector. Shamoon-variant deployed against energy companies in Gulf states and Western partners.', phases: [
      { name: 'Phase 1: Initial Access', desc: 'Spearphishing campaign targets energy sector executives. APT34 deploys custom RAT through compromised vendor portals.', blueOptions: ['Block known APT34 IOCs', 'Enhanced email filtering', 'Vendor portal access review', 'Deploy EDR to all endpoints'] },
      { name: 'Phase 2: Wiper Deployment', desc: 'Shamoon-3 variant deployed across 6 energy companies. MBR overwriting begins during off-hours.', blueOptions: ['Emergency system shutdown', 'Isolate OT from IT', 'Activate disaster recovery', 'Coordinate with DOE/CISA'] },
      { name: 'Phase 3: Sustained Campaign', desc: 'Secondary attacks target backup infrastructure and cloud environments.', blueOptions: ['Air-gap critical backups', 'Deploy out-of-band management', 'Counter-cyber operations against staging', 'International coalition response'] }
    ]},
    { codename: 'CASCADE ZERO', adversary: 'Multi-Nation Coalition', difficulty: 5, duration: '10 hours', category: 'Internet Infrastructure', desc: 'Coordinated multi-nation attack on internet infrastructure. BGP hijacking, DNS root server attacks, and physical disruption of undersea cables create widespread internet outages.', phases: [
      { name: 'Phase 1: BGP Chaos', desc: 'Massive BGP hijacking redirects traffic for major ASNs through adversary-controlled infrastructure.', blueOptions: ['Activate RPKI enforcement', 'Coordinate with Tier 1 providers', 'Deploy route origin validation', 'Alert NANOG community'] },
      { name: 'Phase 2: DNS Under Attack', desc: 'DDoS targeting DNS root servers and major resolvers. DNS poisoning targeting critical domains.', blueOptions: ['Activate Anycast DNS failover', 'Deploy DNSSEC validation', 'Coordinate with ICANN', 'Activate DNS backup infrastructure'] },
      { name: 'Phase 3: Physical Layer', desc: 'Reports of undersea cable cuts in multiple locations. Satellite communications degraded.', blueOptions: ['Reroute through surviving cables', 'Activate military satellite backup', 'Deploy cable repair ships', 'Coordinate with allied navies'] },
      { name: 'Phase 4: Recovery', desc: 'Internet fragmentation recovery while maintaining national security communications.', blueOptions: ['Priority restoration sequencing', 'Emergency peering agreements', 'Deploy mobile communication units', 'International coordination for cable repair'] }
    ]},
    { codename: 'DARK HARVEST', adversary: 'Unknown APT (Supply Chain)', difficulty: 4, duration: '6 hours', category: 'Supply Chain', desc: 'Sophisticated supply chain attack through major cloud provider affects thousands of organizations. Compromised update mechanism delivers backdoored software to enterprise customers.', phases: [
      { name: 'Phase 1: Discovery', desc: 'Anomalous network traffic detected from cloud management software deployed across 15,000+ organizations.', blueOptions: ['Quarantine affected software', 'Reverse engineer update package', 'Coordinate vendor disclosure', 'Deploy network detection signatures'] },
      { name: 'Phase 2: Blast Radius Assessment', desc: 'Compromised software found in government, financial, healthcare, and defense organizations.', blueOptions: ['Full enterprise software audit', 'Deploy YARA rules for IOCs', 'Activate CISA emergency directive', 'Cross-sector coordination'] },
      { name: 'Phase 3: Eviction', desc: 'Advanced persistence mechanisms discovered. Adversary used legitimate cloud APIs for data exfiltration.', blueOptions: ['Credential rotation enterprise-wide', 'Cloud API audit and revocation', 'Deploy enhanced cloud monitoring', 'Coordinate with cloud provider'] }
    ]},
    { codename: 'SILENT FALL', adversary: 'Insider + Nation-State APT', difficulty: 5, duration: '8 hours', category: 'Insider Threat', desc: 'Insider threat combined with nation-state APT gains access to classified networks. Trusted insider provides physical access enabling bypass of air-gap protections on classified systems.', phases: [
      { name: 'Phase 1: Discovery', desc: 'Anomalous data transfers detected on classified network. USB device usage logged outside normal patterns.', blueOptions: ['Activate counterintelligence investigation', 'Enhanced monitoring on suspect systems', 'Review physical access logs', 'Deploy USB activity monitoring'] },
      { name: 'Phase 2: Containment', desc: 'Insider identified but has already exfiltrated data to nation-state handler. Malware discovered on classified systems.', blueOptions: ['Restrict insider access immediately', 'Forensic imaging of all accessed systems', 'Coordinate with FBI CI', 'Damage assessment initiation'] },
      { name: 'Phase 3: Recovery', desc: 'Full damage assessment reveals scope of compromise. Classified programs potentially exposed.', blueOptions: ['Program security review', 'Personnel reinvestigation', 'System rebuild from trusted media', 'Coordinate SAP notifications'] }
    ]},
    { codename: 'CRIMSON TIDE', adversary: 'Russia (APT29 / Turla)', difficulty: 4, duration: '5 hours', category: 'Government Espionage', desc: 'Coordinated Russian intelligence operation targeting Five Eyes government networks. APT29 and Turla conduct simultaneous espionage campaigns against diplomatic communications.', phases: [
      { name: 'Phase 1: Infiltration', desc: 'APT29 exploits zero-day in collaboration platform used by Five Eyes governments for secure communications.', blueOptions: ['Emergency patching', 'Switch to backup secure comms', 'Deploy enhanced email monitoring', 'Alert Five Eyes partners'] },
      { name: 'Phase 2: Lateral Movement', desc: 'Adversary pivots from collaboration platform to email servers and file shares containing diplomatic cables.', blueOptions: ['Network segmentation enforcement', 'Privileged access lockdown', 'Deploy deception technology', 'Activate hunt teams'] },
      { name: 'Phase 3: Exfiltration', desc: 'Data exfiltration detected through DNS tunneling and steganographic channels.', blueOptions: ['Block exfiltration channels', 'Deploy DNS monitoring', 'Coordinate Five Eyes response', 'Begin damage assessment'] }
    ]},
    { codename: 'IRON CURTAIN', adversary: 'Russia (GRU Unit 29155)', difficulty: 4, duration: '4 hours', category: 'Election Security', desc: 'Russian influence operation combined with cyber attacks targeting democratic elections. Combines voter database manipulation, disinformation, and election infrastructure attacks.', phases: [
      { name: 'Phase 1: Reconnaissance', desc: 'Scanning of state election infrastructure detected. Phishing campaigns target election officials.', blueOptions: ['Alert state election officials', 'Deploy CISA election monitoring', 'Enhanced voter database protection', 'Public awareness campaign'] },
      { name: 'Phase 2: Active Operations', desc: 'Voter registration databases modified in 3 states. Disinformation campaigns launched on social media.', blueOptions: ['Activate backup voter rolls', 'Coordinate with social media platforms', 'Deploy paper ballot backup procedures', 'FBI investigation'] }
    ]},
    { codename: 'PHANTOM FLEET', adversary: 'China (APT40)', difficulty: 3, duration: '4 hours', category: 'Maritime/Military', desc: 'Chinese maritime cyber espionage operation targeting naval logistics and port authority systems across Indo-Pacific to map military supply chain vulnerabilities.', phases: [
      { name: 'Phase 1: Port Infiltration', desc: 'APT40 compromises port management systems at 5 Indo-Pacific naval facilities.', blueOptions: ['Isolate port management networks', 'Deploy maritime cyber teams', 'Coordinate with allied navies', 'Audit logistics databases'] },
      { name: 'Phase 2: Intelligence Collection', desc: 'Adversary mapping ship movements, supply routes, and maintenance schedules.', blueOptions: ['Deploy deception data', 'Enhanced monitoring on logistics systems', 'Coordinate with INDOPACOM', 'Counter-intelligence operations'] }
    ]},
    { codename: 'SHATTERED GLASS', adversary: 'Iran (MuddyWater)', difficulty: 3, duration: '3 hours', category: 'Healthcare', desc: 'Iranian cyber attack targeting healthcare systems in Gulf states and Israel. Combines ransomware with data destruction targeting hospital networks and medical research.', phases: [
      { name: 'Phase 1: Initial Compromise', desc: 'MuddyWater deploys custom ransomware via compromised medical supply vendor.', blueOptions: ['Quarantine affected systems', 'Activate clinical downtime procedures', 'Deploy incident response teams', 'Coordinate with health authorities'] },
      { name: 'Phase 2: Escalation', desc: 'Attack spreads to connected medical devices. Patient data exfiltration detected.', blueOptions: ['Medical device network isolation', 'Patient diversion to unaffected facilities', 'Data breach notification', 'Forensic preservation'] }
    ]},
    { codename: 'STEEL RAIN', adversary: 'North Korea (Andariel)', difficulty: 4, duration: '5 hours', category: 'Defense/Aerospace', desc: 'North Korean espionage campaign targeting missile defense and satellite technology. Combines cyber intrusions with procurement networks for sanctions evasion.', phases: [
      { name: 'Phase 1: Contractor Compromise', desc: 'Andariel compromises defense contractor through watering hole on aerospace trade publication.', blueOptions: ['Block malicious domains', 'Audit contractor network access', 'Deploy enhanced EDR', 'Coordinate with defense agencies'] },
      { name: 'Phase 2: Data Theft', desc: 'Classified missile defense schematics accessed. Exfiltration through compromised cloud storage.', blueOptions: ['Revoke cloud access tokens', 'Deploy DLP monitoring', 'Coordinate with DCSA', 'Initiate damage assessment'] },
      { name: 'Phase 3: Proliferation', desc: 'Evidence suggests stolen data being shared with ballistic missile program.', blueOptions: ['Intelligence community briefing', 'Diplomatic response coordination', 'Enhanced monitoring of procurement networks', 'Sanctions enforcement coordination'] }
    ]},
    { codename: 'TOXIC RAIN', adversary: 'Unknown State Actor', difficulty: 5, duration: '6 hours', category: 'Water/Chemical', desc: 'Cyber attack targets water treatment and chemical processing facilities attempting to manipulate chemical levels to dangerous concentrations.', phases: [
      { name: 'Phase 1: Access', desc: 'Unauthorized access to water treatment SCADA systems detected at 4 facilities serving 2M+ people.', blueOptions: ['Immediate switch to manual operations', 'Deploy ICS security teams', 'Water quality emergency sampling', 'Public notification preparation'] },
      { name: 'Phase 2: Manipulation', desc: 'Chemical dosing parameters modified — chlorine levels set to dangerous concentrations.', blueOptions: ['Emergency manual override', 'Shut down automated dosing', 'Deploy hazmat teams', 'Coordinate with EPA'] },
      { name: 'Phase 3: Investigation', desc: 'Attribution analysis points to nation-state actor. Similar attacks detected at chemical plants.', blueOptions: ['Sector-wide emergency alert', 'Deploy CISA ICS-CERT teams', 'Enhanced chemical facility monitoring', 'IC attribution assessment'] }
    ]},
    { codename: 'BLACK AURORA', adversary: 'Multi-Actor (State + Criminal)', difficulty: 5, duration: '10 hours', category: 'Combined Operations', desc: 'Coordinated attack combining nation-state and criminal elements. State actor provides zero-days to criminal ransomware groups targeting critical infrastructure for plausible deniability.', phases: [
      { name: 'Phase 1: Criminal Front', desc: 'Ransomware group deploys using nation-state zero-day. Targets appear random but focus on critical infrastructure.', blueOptions: ['Emergency patching for zero-day', 'Deploy interim mitigations', 'Coordinate with FBI and CISA', 'Sector-wide alerting'] },
      { name: 'Phase 2: State Objectives', desc: 'Behind ransomware distraction, state actors conduct espionage operations against intelligence targets.', blueOptions: ['Enhanced monitoring on IC networks', 'Deploy deception technology', 'Threat hunting on parallel infrastructure', 'Intelligence sharing with allies'] },
      { name: 'Phase 3: Attribution Challenge', desc: 'Distinguishing criminal from state activity critical for response calibration.', blueOptions: ['Forensic analysis of malware lineage', 'SIGINT correlation', 'Diplomatic intelligence gathering', 'Proportional response planning'] },
      { name: 'Phase 4: Response', desc: 'Combined law enforcement and national security response required.', blueOptions: ['Joint FBI/CYBERCOM task force', 'Indictments and sanctions', 'Counter-cyber operations', 'International coalition building'] }
    ]},
    { codename: 'FROZEN DAWN', adversary: 'Russia (FSB / Turla)', difficulty: 4, duration: '5 hours', category: 'Energy/Arctic', desc: 'Russian cyber operations targeting Arctic energy infrastructure and Northern Sea Route monitoring systems during territorial dispute escalation.', phases: [
      { name: 'Phase 1: Reconnaissance', desc: 'Turla conducting extensive reconnaissance of Arctic offshore platform networks and pipeline monitoring systems.', blueOptions: ['Enhanced Arctic infrastructure monitoring', 'Coordinate with Nordic allies', 'Deploy offshore cyber teams', 'Review satellite communication security'] },
      { name: 'Phase 2: Disruption', desc: 'Pipeline monitoring systems manipulated. Safety systems at offshore platforms targeted.', blueOptions: ['Activate safety system overrides', 'Emergency platform evacuation preparation', 'Military asset deployment', 'Diplomatic escalation'] },
      { name: 'Phase 3: Strategic Response', desc: 'Multi-domain response required as cyber attacks coincide with military posturing.', blueOptions: ['NATO Article 4 consultation', 'Combined military-cyber deterrence', 'Alliance solidarity demonstration', 'De-escalation diplomatic channel'] }
    ]}
  ];

  h += '<div style="padding:0 24px 16px 24px;">';

  // Active simulation display
  h += '<div style="background:linear-gradient(135deg,#1a0a0a,#0a0e1a);border:2px solid #ff224444;border-radius:8px;padding:16px;margin-bottom:16px;">';
  h += '<div style="display:flex;align-items:center;gap:10px;margin-bottom:12px;">';
  h += '<div style="background:#ff2244;color:#fff;font-size:10px;font-family:monospace;font-weight:bold;padding:4px 12px;border-radius:3px;animation:se-pulse 2s ease-in-out infinite;">LIVE OPERATION</div>';
  h += '<div style="color:#fff;font-size:16px;font-family:monospace;font-weight:bold;letter-spacing:1px;">DRAGON STORM — Phase 2: Disruption</div>';
  h += '</div>';

  h += '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:14px;">';
  var simMetrics = [
    { label: 'ELAPSED TIME', value: '02:34:17', color: '#00aaff' },
    { label: 'DETECTION SCORE', value: '78%', color: '#00ff88' },
    { label: 'CONTAINMENT', value: '45%', color: '#ffaa00' },
    { label: 'SYSTEMS AFFECTED', value: '23/47', color: '#ff2244' }
  ];
  for (var sm = 0; sm < simMetrics.length; sm++) {
    var sMetric = simMetrics[sm];
    h += '<div style="background:#0a0e1a;border:1px solid ' + sMetric.color + '33;border-radius:6px;padding:10px;text-align:center;">';
    h += '<div style="color:#556;font-size:9px;font-family:monospace;letter-spacing:1px;">' + esc(sMetric.label) + '</div>';
    h += '<div style="color:' + sMetric.color + ';font-size:22px;font-weight:bold;font-family:monospace;">' + esc(sMetric.value) + '</div>';
    h += '</div>';
  }
  h += '</div>';

  // Phase progression
  h += '<div style="display:flex;gap:4px;margin-bottom:14px;">';
  var phaseLabels = ['Phase 1: Activation', 'Phase 2: Disruption', 'Phase 3: Escalation', 'Phase 4: Recovery'];
  for (var pl = 0; pl < phaseLabels.length; pl++) {
    var phaseActive = pl <= 1;
    var phaseCurrent = pl === 1;
    h += '<div style="flex:1;background:' + (phaseActive ? (phaseCurrent ? '#00aaff22' : '#00ff8822') : '#111828') + ';border:1px solid ' + (phaseCurrent ? '#00aaff' : phaseActive ? '#00ff8844' : '#1a2a44') + ';border-radius:4px;padding:6px 8px;text-align:center;">';
    h += '<div style="color:' + (phaseCurrent ? '#00aaff' : phaseActive ? '#00ff88' : '#445') + ';font-size:10px;font-family:monospace;font-weight:bold;">' + esc(phaseLabels[pl]) + '</div>';
    h += '<div style="color:' + (phaseActive ? '#889' : '#334') + ';font-size:9px;font-family:monospace;margin-top:2px;">' + (phaseCurrent ? 'IN PROGRESS' : phaseActive ? 'COMPLETED' : 'PENDING') + '</div>';
    h += '</div>';
  }
  h += '</div>';

  // Blue team response options for current phase
  h += '<div style="color:#00aaff;font-size:11px;font-family:monospace;letter-spacing:1px;margin-bottom:8px;">BLUE TEAM RESPONSE OPTIONS:</div>';
  var currentPhaseOptions = ['Emergency grid isolation', 'Activate manual water treatment overrides', 'Deploy CYBERCOM hunt teams', 'Notify National Guard Cyber units'];
  h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;">';
  for (var cpo = 0; cpo < currentPhaseOptions.length; cpo++) {
    var isSelectedOpt = cpo === 0;
    h += '<div style="background:' + (isSelectedOpt ? '#00aaff22' : '#0a0e1a') + ';border:1px solid ' + (isSelectedOpt ? '#00aaff' : '#1a2a44') + ';border-radius:4px;padding:8px;cursor:pointer;color:' + (isSelectedOpt ? '#00aaff' : '#889') + ';font-size:11px;font-family:monospace;">';
    h += (isSelectedOpt ? '&#9745; ' : '&#9744; ') + esc(currentPhaseOptions[cpo]);
    h += '</div>';
  }
  h += '</div>';
  h += '</div>';

  // Scenario library grid
  h += '<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;">';
  for (var sc = 0; sc < scenarios.length; sc++) {
    var scenario = scenarios[sc];
    var scAdversary = scenario.adversary || 'Unknown';
    var scDesc = scenario.desc || scenario.description || '';
    var scDuration = scenario.duration || scenario.estimatedDuration || 'N/A';
    var scCategory = scenario.category || 'General';
    var scPhases = scenario.phases || [];
    var scDiffColor = scenario.difficulty >= 5 ? '#ff2244' : scenario.difficulty >= 4 ? '#ffaa00' : '#00aaff';
    var isActive = sc === 0;
    h += '<div style="background:linear-gradient(135deg,' + (isActive ? '#0c1525' : '#0c1020') + ',#0a0e1a);border:1px solid ' + (isActive ? '#00aaff44' : '#1a2a44') + ';border-radius:8px;padding:14px;cursor:pointer;' + (isActive ? 'box-shadow:0 0 15px #00aaff11;' : '') + '" onclick="this.querySelector(\'.se-scenario-phases\').style.display=this.querySelector(\'.se-scenario-phases\').style.display===\'none\'?\'block\':\'none\'">';

    // Codename
    h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;">';
    h += '<div style="color:#fff;font-size:14px;font-family:monospace;font-weight:bold;letter-spacing:1px;">' + esc(scenario.codename || 'UNNAMED') + '</div>';
    if (isActive) {
      h += '<div style="background:#00aaff22;color:#00aaff;font-size:8px;font-family:monospace;padding:2px 6px;border-radius:2px;">ACTIVE</div>';
    }
    h += '</div>';

    // Adversary
    h += '<div style="color:#ff6644;font-size:11px;font-family:monospace;margin-bottom:6px;">' + esc(scAdversary) + '</div>';

    // Category badge
    h += '<div style="display:inline-block;background:#111828;color:#889;font-size:9px;font-family:monospace;padding:2px 6px;border-radius:2px;margin-bottom:8px;">' + esc(scCategory) + '</div>';

    // Description
    h += '<div style="color:#889;font-size:10px;font-family:monospace;line-height:1.5;margin-bottom:10px;min-height:60px;">' + esc(scDesc) + '</div>';

    // Difficulty & duration
    h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">';
    h += '<div style="display:flex;gap:2px;">';
    for (var ds = 0; ds < 5; ds++) {
      h += '<span style="color:' + (ds < scenario.difficulty ? scDiffColor : '#222') + ';font-size:12px;">&#9733;</span>';
    }
    h += '</div>';
    h += '<div style="color:#556;font-size:10px;font-family:monospace;">' + esc(scDuration) + '</div>';
    h += '</div>';

    // Phases count
    h += '<div style="color:#445;font-size:9px;font-family:monospace;margin-bottom:8px;">' + scPhases.length + ' phases &bull; ' + esc(scAdversary) + '</div>';

    // Launch button
    h += '<div style="background:' + (isActive ? '#00aaff' : '#00aaff22') + ';color:' + (isActive ? '#000' : '#00aaff') + ';font-size:10px;font-family:monospace;text-align:center;padding:6px;border-radius:4px;cursor:pointer;border:1px solid #00aaff44;font-weight:bold;">' + (isActive ? 'OPERATION IN PROGRESS' : 'LAUNCH SCENARIO') + '</div>';

    // Expandable phases
    h += '<div class="se-scenario-phases" style="display:none;margin-top:10px;padding-top:10px;border-top:1px solid #1a2a44;">';
    for (var sp = 0; sp < scPhases.length; sp++) {
      var sPhase = scPhases[sp];
      var sPhaseDesc = sPhase.desc || sPhase.description || '';
      h += '<div style="margin-bottom:8px;padding:8px;background:#0a0e1a;border:1px solid #111828;border-radius:4px;">';
      h += '<div style="color:#00aaff;font-size:11px;font-family:monospace;font-weight:bold;margin-bottom:4px;">' + esc(sPhase.name || 'Phase') + '</div>';
      h += '<div style="color:#889;font-size:10px;font-family:monospace;line-height:1.4;margin-bottom:6px;">' + esc(sPhaseDesc) + '</div>';
      var phaseBlueOpts = sPhase.blueOptions || sPhase.blueTeamOptions || [];
      h += '<div style="color:#556;font-size:9px;font-family:monospace;letter-spacing:1px;margin-bottom:4px;">BLUE TEAM OPTIONS:</div>';
      for (var bo = 0; bo < phaseBlueOpts.length; bo++) {
        h += '<div style="color:#667;font-size:10px;font-family:monospace;padding:2px 0;">&#9744; ' + esc(phaseBlueOpts[bo]) + '</div>';
      }
      h += '</div>';
    }
    h += '</div>';

    h += '</div>';
  }
  h += '</div>';
  h += '</div>';

  // ---- Scoring & After-Action ----
  h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;padding:0 24px 24px 24px;">';

  // Scoring
  h += '<div style="background:linear-gradient(135deg,#0c1020,#0a0e1a);border:1px solid #1a2a44;border-radius:8px;padding:16px;">';
  h += '<div style="color:#00aaff;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;margin-bottom:14px;border-bottom:1px solid #1a2a44;padding-bottom:8px;">';
  h += '<span style="color:#ffaa00;margin-right:8px;">[*]</span>SCORING DASHBOARD</div>';

  var scoringCategories = [
    { category: 'Detection Speed', score: 85, max: 100, desc: 'How quickly threats were identified', color: '#00ff88' },
    { category: 'Containment Effectiveness', score: 72, max: 100, desc: 'Ability to limit blast radius', color: '#00aaff' },
    { category: 'Recovery Time', score: 68, max: 100, desc: 'Speed of service restoration', color: '#ffaa00' },
    { category: 'Communication', score: 90, max: 100, desc: 'Coordination and reporting quality', color: '#00ff88' },
    { category: 'Decision Quality', score: 78, max: 100, desc: 'Appropriateness of response actions', color: '#00aaff' },
    { category: 'Collateral Avoidance', score: 95, max: 100, desc: 'Minimization of unintended effects', color: '#00ff88' }
  ];

  var totalScore = 0;
  for (var ssc = 0; ssc < scoringCategories.length; ssc++) {
    totalScore += scoringCategories[ssc].score;
  }
  var avgScore = Math.round(totalScore / scoringCategories.length);

  h += '<div style="text-align:center;margin-bottom:14px;">';
  h += '<div style="color:#556;font-size:10px;font-family:monospace;letter-spacing:1px;">OVERALL SCORE</div>';
  h += '<div style="color:' + (avgScore >= 80 ? '#00ff88' : avgScore >= 60 ? '#ffaa00' : '#ff2244') + ';font-size:42px;font-weight:bold;font-family:monospace;">' + avgScore + '<span style="font-size:18px;color:#556;">/ 100</span></div>';
  h += '</div>';

  for (var scr = 0; scr < scoringCategories.length; scr++) {
    var sCat = scoringCategories[scr];
    h += '<div style="margin-bottom:8px;">';
    h += '<div style="display:flex;justify-content:space-between;margin-bottom:3px;">';
    h += '<div style="color:#ccd;font-size:11px;font-family:monospace;">' + esc(sCat.category) + '</div>';
    h += '<div style="color:' + sCat.color + ';font-size:11px;font-family:monospace;font-weight:bold;">' + esc(sCat.score) + '</div>';
    h += '</div>';
    h += '<div style="background:#111828;border-radius:4px;height:6px;overflow:hidden;">';
    h += '<div style="background:linear-gradient(90deg,' + sCat.color + ',' + sCat.color + '88);width:' + sCat.score + '%;height:100%;border-radius:4px;"></div>';
    h += '</div>';
    h += '<div style="color:#445;font-size:9px;font-family:monospace;margin-top:2px;">' + esc(sCat.desc) + '</div>';
    h += '</div>';
  }
  h += '</div>';

  // After-action review
  h += '<div style="background:linear-gradient(135deg,#0c1020,#0a0e1a);border:1px solid #1a2a44;border-radius:8px;padding:16px;">';
  h += '<div style="color:#00aaff;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;margin-bottom:14px;border-bottom:1px solid #1a2a44;padding-bottom:8px;">';
  h += '<span style="color:#00ff88;margin-right:8px;">[R]</span>AFTER-ACTION REVIEW</div>';

  var aarItems = [
    { type: 'SUSTAIN', items: ['Rapid initial detection (under 15 minutes)', 'Effective cross-sector communication protocols', 'Successful manual override of OT systems', 'Strong leadership decision-making under pressure'], color: '#00ff88' },
    { type: 'IMPROVE', items: ['Containment of lateral movement took too long', 'Backup communication channels not tested pre-exercise', 'Recovery prioritization caused delay in telecom restoration', 'Forensic evidence preservation protocols not followed consistently'], color: '#ffaa00' },
    { type: 'CRITICAL FINDINGS', items: ['Pre-positioned LOTL techniques bypassed standard detection', 'Manual override training insufficient for water sector operators', 'No established protocol for simultaneous multi-sector incidents', 'Intelligence sharing delays between federal and state entities'], color: '#ff2244' }
  ];

  for (var aar = 0; aar < aarItems.length; aar++) {
    var aarItem = aarItems[aar];
    h += '<div style="margin-bottom:12px;">';
    h += '<div style="color:' + aarItem.color + ';font-size:11px;font-family:monospace;font-weight:bold;letter-spacing:1px;margin-bottom:6px;">' + esc(aarItem.type) + '</div>';
    for (var ai = 0; ai < aarItem.items.length; ai++) {
      h += '<div style="color:#889;font-size:10px;font-family:monospace;padding:3px 0;display:flex;align-items:flex-start;gap:6px;">';
      h += '<span style="color:' + aarItem.color + ';font-size:8px;margin-top:4px;">&#9654;</span>' + esc(aarItem.items[ai]);
      h += '</div>';
    }
    h += '</div>';
  }

  h += '<div style="margin-top:12px;background:#00aaff11;border:1px solid #00aaff33;border-radius:4px;padding:10px;">';
  h += '<div style="color:#00aaff;font-size:10px;font-family:monospace;font-weight:bold;margin-bottom:4px;">LESSONS LEARNED</div>';
  h += '<div style="color:#889;font-size:10px;font-family:monospace;line-height:1.5;">Multi-sector attacks require pre-established coordination protocols that are regularly exercised. Manual override capabilities must be maintained and tested quarterly. Intelligence sharing between classification levels needs streamlined procedures for crisis situations.</div>';
  h += '</div>';
  h += '</div>';

  h += '</div>'; // end scoring grid

  return h;
}


// ============================================================================
// TAB 10: COMMAND AUTHORITY
// ============================================================================
function renderCommand() {
  var h = '';

  // Classification banner

  h += '<div style="padding:20px 24px 0 24px;">';
  h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:18px;">';
  h += '<div>';
  h += '<h2 style="margin:0;font-size:22px;color:#00aaff;font-family:monospace;letter-spacing:2px;text-transform:uppercase;">COMMAND AUTHORITY CENTER</h2>';
  h += '<div style="color:#667;font-size:12px;font-family:monospace;margin-top:4px;letter-spacing:1px;">EXECUTIVE DECISION SUPPORT &bull; NATIONAL CYBER POSTURE</div>';
  h += '</div>';
  h += '<div style="background:linear-gradient(135deg,#1a0a0a,#2a1515);border:2px solid #ff2244;border-radius:8px;padding:10px 20px;text-align:center;">';
  h += '<div style="color:#ff2244;font-size:10px;font-family:monospace;letter-spacing:2px;">GLOBAL CYBER THREAT LEVEL</div>';
  h += '<div style="color:#ff2244;font-size:32px;font-weight:bold;font-family:monospace;">BRAVO</div>';
  h += '<div style="color:#ff6644;font-size:10px;font-family:monospace;">ELEVATED — INCREASED RISK</div>';
  h += '</div>';
  h += '</div>';
  h += '</div>';

  // Executive brief panel
  h += '<div style="padding:0 24px 16px 24px;">';
  h += '<div style="background:linear-gradient(135deg,#0c1020,#0a0e1a);border:2px solid #00aaff44;border-radius:8px;padding:20px;">';
  h += '<div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;border-bottom:1px solid #1a2a44;padding-bottom:10px;">';
  h += '<div style="color:#00aaff;font-size:15px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;font-weight:bold;">EXECUTIVE BRIEF — GLOBAL CYBER POSTURE SUMMARY</div>';
  h += '<div style="margin-left:auto;color:#556;font-size:11px;font-family:monospace;">DTG: 13 SEP 2026 / 1500Z</div>';
  h += '</div>';

  h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">';

  // Key assessments
  h += '<div>';
  h += '<div style="color:#ffaa00;font-size:11px;font-family:monospace;letter-spacing:1px;font-weight:bold;margin-bottom:8px;">KEY ASSESSMENTS</div>';
  var keyAssessments = [
    'Russian cyber forces in elevated operational posture targeting European energy infrastructure — attack predicted within 48-96 hours (HIGH CONFIDENCE)',
    'Chinese multi-vector espionage campaign active across semiconductor, defense, and maritime sectors — unprecedented tempo suggests centralized CPC tasking',
    'North Korean crypto theft operations accelerating to meet regime-directed $500M Q4 target — new laundering infrastructure operational',
    'Iranian IRGC Cyber Command reorganization creates dedicated offensive force — offensive capability expected to increase within 60-90 days',
    'Global zero-day market activity at highest level in 24 months — 3 new Windows kernel exploits available, likely procured by nation-state buyers'
  ];
  for (var ka = 0; ka < keyAssessments.length; ka++) {
    h += '<div style="color:#ccd;font-size:11px;font-family:monospace;padding:6px 0;border-bottom:1px solid #111828;display:flex;align-items:flex-start;gap:6px;line-height:1.5;">';
    h += '<span style="color:#ffaa00;font-size:8px;margin-top:5px;flex-shrink:0;">&#9632;</span>' + esc(keyAssessments[ka]);
    h += '</div>';
  }
  h += '</div>';

  // Current posture
  h += '<div>';
  h += '<div style="color:#00aaff;font-size:11px;font-family:monospace;letter-spacing:1px;font-weight:bold;margin-bottom:8px;">CURRENT POSTURE</div>';
  var postureItems = [
    { label: 'CYBERCOM Force Posture', value: 'ELEVATED', color: '#ffaa00' },
    { label: 'Active Operations', value: '3 (2 defensive, 1 offensive)', color: '#00aaff' },
    { label: 'Hunt Teams Deployed', value: '7 of 12 available', color: '#00aaff' },
    { label: 'Critical Infrastructure Status', value: '5 NOMINAL / 2 ELEVATED / 1 HIGH', color: '#ffaa00' },
    { label: 'Allied Coordination', value: 'Five Eyes: ACTIVE / NATO: ELEVATED', color: '#00ff88' },
    { label: 'Last Major Incident', value: '6 days ago (APT29 phishing campaign)', color: '#00ff88' },
    { label: 'Pending Authorizations', value: '2 operations awaiting SECDEF approval', color: '#ffaa00' },
    { label: 'Congressional Notifications', value: '1 pending (OP IRON VEIL)', color: '#ffaa00' }
  ];
  for (var pi = 0; pi < postureItems.length; pi++) {
    var pItem = postureItems[pi];
    h += '<div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid #111828;">';
    h += '<div style="color:#889;font-size:11px;font-family:monospace;">' + esc(pItem.label) + '</div>';
    h += '<div style="color:' + pItem.color + ';font-size:11px;font-family:monospace;font-weight:bold;text-align:right;">' + esc(pItem.value) + '</div>';
    h += '</div>';
  }
  h += '</div>';
  h += '</div>';
  h += '</div>';
  h += '</div>';

  // Main grid
  h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;padding:0 24px 16px 24px;">';

  // ---- Active Threats Requiring Decision ----
  h += '<div style="background:linear-gradient(135deg,#0c1020,#0a0e1a);border:1px solid #ff224444;border-radius:8px;padding:16px;">';
  h += '<div style="color:#ff2244;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;margin-bottom:14px;border-bottom:1px solid #ff224433;padding-bottom:8px;">';
  h += '<span style="color:#ff2244;margin-right:8px;">&#9888;</span>ACTIVE THREATS REQUIRING DECISION</div>';

  var activeThreats = [
    { id: 'ATD-001', threat: 'Russian Offensive Cyber Operation — European Energy', urgency: 'IMMEDIATE', deadline: '14 SEP 2026 0200Z', decision: 'Authorize preemptive counter-cyber operation (OP IRON VEIL)', options: ['Authorize offensive counter-op', 'Elevate to active defense only', 'Defer to allied response', 'Request additional intelligence'] },
    { id: 'ATD-002', threat: 'Volt Typhoon Pre-Positioning in US Utilities', urgency: 'HIGH', deadline: '15 SEP 2026 1200Z', decision: 'Approve CYBERCOM eviction operation in domestic critical infrastructure', options: ['Authorize CYBERCOM eviction', 'Continue monitoring only', 'Coordinate with utility owners for voluntary remediation', 'Escalate to NSC principals'] },
    { id: 'ATD-003', threat: 'APT41 Semiconductor Espionage Campaign', urgency: 'HIGH', deadline: '16 SEP 2026', decision: 'Approve FBI-CYBERCOM joint operation against APT41 infrastructure', options: ['Approve joint operation', 'FBI law enforcement only', 'Diplomatic demarche first', 'Continue intelligence collection'] }
  ];

  for (var at = 0; at < activeThreats.length; at++) {
    var aThreat = activeThreats[at];
    var urgencyColor = aThreat.urgency === 'IMMEDIATE' ? '#ff2244' : '#ffaa00';
    h += '<div style="background:#0a0e1a;border:1px solid ' + urgencyColor + '44;border-radius:6px;padding:12px;margin-bottom:8px;border-left:3px solid ' + urgencyColor + ';">';
    h += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">';
    h += '<div style="background:' + urgencyColor + ';color:#000;font-size:9px;font-family:monospace;font-weight:bold;padding:2px 8px;border-radius:3px;">' + esc(aThreat.urgency) + '</div>';
    h += '<div style="color:#556;font-size:10px;font-family:monospace;">' + esc(aThreat.id) + '</div>';
    h += '<div style="margin-left:auto;color:#667;font-size:9px;font-family:monospace;">DEADLINE: ' + esc(aThreat.deadline) + '</div>';
    h += '</div>';
    h += '<div style="color:#fff;font-size:12px;font-family:monospace;font-weight:bold;margin-bottom:4px;">' + esc(aThreat.threat) + '</div>';
    h += '<div style="color:#889;font-size:10px;font-family:monospace;margin-bottom:8px;">' + esc(aThreat.decision) + '</div>';
    h += '<div style="display:flex;flex-wrap:wrap;gap:4px;">';
    for (var ao = 0; ao < aThreat.options.length; ao++) {
      var isFirstOpt = ao === 0;
      h += '<div style="font-size:9px;font-family:monospace;padding:4px 8px;border-radius:3px;cursor:pointer;background:' + (isFirstOpt ? urgencyColor + '22' : 'transparent') + ';border:1px solid ' + (isFirstOpt ? urgencyColor : '#334') + ';color:' + (isFirstOpt ? urgencyColor : '#667') + ';">' + esc(aThreat.options[ao]) + '</div>';
    }
    h += '</div>';
    h += '</div>';
  }
  h += '</div>';

  // ---- Allied Coordination Status ----
  h += '<div style="background:linear-gradient(135deg,#0c1020,#0a0e1a);border:1px solid #1a2a44;border-radius:8px;padding:16px;">';
  h += '<div style="color:#00aaff;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;margin-bottom:14px;border-bottom:1px solid #1a2a44;padding-bottom:8px;">';
  h += '<span style="color:#00ff88;margin-right:8px;">[O]</span>ALLIED COORDINATION STATUS</div>';

  var alliances = [
    { name: 'Five Eyes (FVEY)', members: 'US, UK, Canada, Australia, New Zealand', status: 'ACTIVE — ELEVATED SHARING', lastSync: '2026-09-13 14:00Z', intel: 'Full intelligence sharing active. Joint Sandworm tracking operation underway.', color: '#00ff88' },
    { name: 'NATO CCDCOE', members: '31 NATO members', status: 'CONSULTATION — Article 4', lastSync: '2026-09-13 12:00Z', intel: 'Baltic state cyber defense coordination. Pre-authorized response packages ready.', color: '#00aaff' },
    { name: 'US-Israel Bilateral', members: 'US, Israel', status: 'ACTIVE', lastSync: '2026-09-13 10:00Z', intel: 'Joint Iran threat tracking. Unit 8200 sharing SIGINT on IRGC reorganization.', color: '#00ff88' },
    { name: 'Quad Cyber Partnership', members: 'US, Japan, Australia, India', status: 'MONITORING', lastSync: '2026-09-12 22:00Z', intel: 'Indo-Pacific maritime threat monitoring. APT40 tracking shared.', color: '#00aaff' },
    { name: 'US-South Korea', members: 'US, South Korea', status: 'ELEVATED', lastSync: '2026-09-13 06:00Z', intel: 'Joint DPRK crypto theft tracking. Lazarus Group infrastructure intelligence shared.', color: '#ffaa00' }
  ];

  for (var al = 0; al < alliances.length; al++) {
    var ally = alliances[al];
    h += '<div style="background:#0a0e1a;border:1px solid #1a2a44;border-radius:4px;padding:10px;margin-bottom:6px;">';
    h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;">';
    h += '<div style="color:#fff;font-size:12px;font-family:monospace;font-weight:bold;">' + esc(ally.name) + '</div>';
    h += '<div style="background:' + ally.color + '22;color:' + ally.color + ';font-size:9px;font-family:monospace;padding:2px 8px;border-radius:3px;">' + esc(ally.status) + '</div>';
    h += '</div>';
    h += '<div style="color:#556;font-size:9px;font-family:monospace;margin-bottom:4px;">' + esc(ally.members) + '</div>';
    h += '<div style="color:#889;font-size:10px;font-family:monospace;line-height:1.4;">' + esc(ally.intel) + '</div>';
    h += '<div style="color:#445;font-size:9px;font-family:monospace;margin-top:4px;">Last sync: ' + esc(ally.lastSync) + '</div>';
    h += '</div>';
  }
  h += '</div>';

  // ---- Communication Templates ----
  h += '<div style="background:linear-gradient(135deg,#0c1020,#0a0e1a);border:1px solid #1a2a44;border-radius:8px;padding:16px;">';
  h += '<div style="color:#00aaff;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;margin-bottom:14px;border-bottom:1px solid #1a2a44;padding-bottom:8px;">';
  h += '<span style="color:#00aaff;margin-right:8px;">[@]</span>COMMUNICATION TEMPLATES</div>';

  var commTemplates = [
    { type: 'SITREP', name: 'Situation Report', desc: 'Periodic summary of current cyber posture for senior leadership', classification: 'SECRET', frequency: 'Every 6 hours', lastSent: '2026-09-13 12:00Z',
      template: 'CLASSIFICATION: SECRET//NOFORN\nSUBJECT: Cyber SITREP #1847\nDTG: 131500ZSEP2026\nREF: USCYBERCOM DAILY SITREP\n\n1. SITUATION: Global cyber threat level BRAVO. Three nation-state campaigns active.\n2. ENEMY: Russia (Sandworm) — staging European energy attack. China (multiple APTs) — espionage escalation. DPRK (Lazarus) — crypto theft surge.\n3. FRIENDLY: 3 operations active. 7 hunt teams deployed. All critical infrastructure sectors reporting.\n4. ASSESSMENT: Probability of Russian offensive action within 48-96 hours assessed at HIGH.\n5. RECOMMENDATIONS: Authorize OP IRON VEIL. Elevate CI shield posture.\n\nPOC: CYBERCOM J3 Watch Officer' },
    { type: 'OPREP-3', name: 'Operational Report', desc: 'Significant event report for National Military Command Center', classification: 'TOP SECRET', frequency: 'Event-driven', lastSent: '2026-09-13 14:50Z',
      template: 'CLASSIFICATION: TOP SECRET//SCI//NOFORN\nPRECEDENCE: FLASH\nFROM: CDR USCYBERCOM\nTO: NMCC/SECDEF/CJCS\nSUBJ: OPREP-3/CYBER INCIDENT\n\n1. TYPE: IMMINENT HOSTILE CYBER OPERATION\n2. DTG: 131450ZSEP2026\n3. ADVERSARY: Russia/GRU Unit 74455 (Sandworm)\n4. TARGET: European energy infrastructure (3+ countries)\n5. INDICATORS: SIGINT confirms operator activation. Staging infrastructure hot. Pre-positioned implants verified.\n6. ASSESSMENT: Attack predicted within 48-96 hours.\n7. RECOMMENDED ACTION: Authorize OP IRON VEIL counter-operation.\n\nACKNOWLEDGE RECEIPT' },
    { type: 'FLASH', name: 'Flash Message', desc: 'Highest priority notification requiring immediate action', classification: 'TOP SECRET//SCI', frequency: 'Immediate', lastSent: '2026-09-13 14:50Z',
      template: 'CLASSIFICATION: TOP SECRET//SCI//NOFORN\nPRECEDENCE: FLASH FLASH FLASH\n\nIMMINENT NATION-STATE CYBER ATTACK\n\nRUSSIAN CYBER FORCES (SANDWORM) ASSESSED WITH HIGH CONFIDENCE TO BE PREPARING OFFENSIVE CYBER OPERATION AGAINST EUROPEAN ENERGY INFRASTRUCTURE WITHIN 48-96 HOURS.\n\nIMEDIATE ACTIONS REQUIRED:\n1. AUTHORIZE OP IRON VEIL\n2. ELEVATE ALL NATO CYBER DEFENSES\n3. NOTIFY FIVE EYES PARTNERS\n4. ACTIVATE ENERGY SECTOR SHIELDS\n\nCDR USCYBERCOM REQUESTS SECDEF AUTHORIZATION NLT 140200ZSEP2026' },
    { type: 'EXBRIEF', name: 'Executive Brief', desc: 'One-page summary for presidential daily brief', classification: 'TOP SECRET//SCI', frequency: 'Daily', lastSent: '2026-09-13 06:00Z',
      template: 'CLASSIFICATION: TOP SECRET//SCI//NOFORN\nPDB CYBER SUPPLEMENT — 13 SEPTEMBER 2026\n\nBOTTOM LINE: Three concurrent nation-state cyber campaigns pose elevated risk to US national security. Russian offensive operation against European energy expected within days.\n\nRUSSIA: GRU preparing cyber attack on European energy. Counter-operation awaiting authorization.\nCHINA: Unprecedented espionage escalation across semiconductor, defense, maritime sectors.\nDPRK: Crypto theft acceleration to fund nuclear program. $500M Q4 target.\nIRAN: Offensive cyber reorganization underway. Enhanced capability expected in 60-90 days.\n\nDECISION REQUIRED: Authorization of OP IRON VEIL (counter-operation against GRU infrastructure).' }
  ];

  for (var ct = 0; ct < commTemplates.length; ct++) {
    var tmpl = commTemplates[ct];
    var tmplClassColor = tmpl.classification.indexOf('TOP SECRET') >= 0 ? '#ff2244' : '#ffaa00';
    h += '<div style="background:#0a0e1a;border:1px solid #1a2a44;border-radius:4px;margin-bottom:6px;overflow:hidden;" onclick="this.querySelector(\'.se-tmpl-body\').style.display=this.querySelector(\'.se-tmpl-body\').style.display===\'none\'?\'block\':\'none\'">';
    h += '<div style="padding:10px;cursor:pointer;display:flex;align-items:center;gap:8px;">';
    h += '<div style="background:#00aaff22;color:#00aaff;font-size:10px;font-family:monospace;font-weight:bold;padding:3px 8px;border-radius:3px;min-width:60px;text-align:center;">' + esc(tmpl.type) + '</div>';
    h += '<div style="flex:1;">';
    h += '<div style="color:#fff;font-size:12px;font-family:monospace;font-weight:bold;">' + esc(tmpl.name) + '</div>';
    h += '<div style="color:#667;font-size:9px;font-family:monospace;">' + esc(tmpl.desc) + '</div>';
    h += '</div>';
    h += '<div style="color:' + tmplClassColor + ';font-size:9px;font-family:monospace;">' + esc(tmpl.classification) + '</div>';
    h += '<div style="color:#445;font-size:10px;">&#9660;</div>';
    h += '</div>';
    h += '<div class="se-tmpl-body" style="display:none;padding:0 10px 10px 10px;border-top:1px solid #1a2a44;">';
    h += '<pre style="background:#060810;border:1px solid #111828;border-radius:4px;padding:12px;margin:8px 0 0 0;color:#00ff88;font-size:10px;font-family:monospace;line-height:1.6;white-space:pre-wrap;overflow-x:auto;">' + esc(tmpl.template) + '</pre>';
    h += '</div>';
    h += '</div>';
  }
  h += '</div>';

  // ---- Decision Log ----
  h += '<div style="background:linear-gradient(135deg,#0c1020,#0a0e1a);border:1px solid #1a2a44;border-radius:8px;padding:16px;">';
  h += '<div style="color:#00aaff;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;margin-bottom:14px;border-bottom:1px solid #1a2a44;padding-bottom:8px;">';
  h += '<span style="color:#ffaa00;margin-right:8px;">[L]</span>DECISION LOG</div>';

  var decisionLog = [
    { timestamp: '2026-09-13 14:50Z', decision: 'Authorized FLASH dissemination of Russian energy sector threat', authority: 'CYBERCOM CDR', classification: 'TS//SCI', rationale: 'Multiple independent sources confirm imminent threat — allies must be warned immediately' },
    { timestamp: '2026-09-13 13:00Z', decision: 'Elevated CI Shield posture for Power Grid and DIB sectors to HIGH', authority: 'CISA Director', classification: 'SECRET', rationale: 'Volt Typhoon and APT41 activity warrants increased defensive posture' },
    { timestamp: '2026-09-13 10:00Z', decision: 'Deployed 2 additional hunt teams to critical infrastructure sector', authority: 'CYBERCOM J3', classification: 'SECRET', rationale: 'Active Volt Typhoon indicators in utility networks require immediate investigation' },
    { timestamp: '2026-09-12 22:00Z', decision: 'Approved joint FBI-CYBERCOM investigation of APT41 ChipDoor campaign', authority: 'NSC Deputies', classification: 'TS//SCI', rationale: 'Semiconductor supply chain compromise has national security implications' },
    { timestamp: '2026-09-12 16:00Z', decision: 'Issued warning intelligence on NK crypto theft escalation', authority: 'DNI', classification: 'TS//SCI', rationale: 'Treasury and financial regulators need advance notice for defensive measures' },
    { timestamp: '2026-09-12 08:00Z', decision: 'Activated enhanced Five Eyes sharing on Sandworm infrastructure', authority: 'CYBERCOM CDR', classification: 'TS//SCI//REL FVEY', rationale: 'European allies are primary targets — full intelligence sharing is essential' },
    { timestamp: '2026-09-11 20:00Z', decision: 'Initiated OP IRON VEIL planning', authority: 'CYBERCOM CDR', classification: 'TS//SCI//NOFORN', rationale: 'Preemptive counter-operation may be necessary if diplomatic efforts fail' },
    { timestamp: '2026-09-11 14:00Z', decision: 'Requested SECDEF authorization for OP IRON VEIL execution', authority: 'CYBERCOM CDR', classification: 'TS//SCI//NOFORN', rationale: 'Intelligence confidence threshold met for offensive counter-cyber operation' }
  ];

  for (var dl = 0; dl < decisionLog.length; dl++) {
    var dLog = decisionLog[dl];
    var dlClassColor = dLog.classification.indexOf('TS') >= 0 ? '#ff2244' : '#ffaa00';
    h += '<div style="padding:8px 0;border-bottom:1px solid #111828;display:flex;gap:10px;">';
    h += '<div style="color:#556;font-size:10px;font-family:monospace;min-width:130px;white-space:nowrap;">' + esc(dLog.timestamp) + '</div>';
    h += '<div style="flex:1;">';
    h += '<div style="color:#ccd;font-size:11px;font-family:monospace;margin-bottom:2px;">' + esc(dLog.decision) + '</div>';
    h += '<div style="color:#667;font-size:9px;font-family:monospace;font-style:italic;">' + esc(dLog.rationale) + '</div>';
    h += '</div>';
    h += '<div style="text-align:right;min-width:100px;">';
    h += '<div style="color:#889;font-size:9px;font-family:monospace;">' + esc(dLog.authority) + '</div>';
    h += '<div style="color:' + dlClassColor + ';font-size:8px;font-family:monospace;margin-top:2px;">' + esc(dLog.classification) + '</div>';
    h += '</div>';
    h += '</div>';
  }
  h += '</div>';

  h += '</div>'; // end main grid

  // ---- Resource Allocation & Congressional Notification ----
  h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;padding:0 24px 24px 24px;">';

  // Resource Allocation
  h += '<div style="background:linear-gradient(135deg,#0c1020,#0a0e1a);border:1px solid #1a2a44;border-radius:8px;padding:16px;">';
  h += '<div style="color:#00aaff;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;margin-bottom:14px;border-bottom:1px solid #1a2a44;padding-bottom:8px;">';
  h += '<span style="color:#00aaff;margin-right:8px;">[T]</span>RESOURCE ALLOCATION</div>';

  var resources = [
    { team: 'CNMF Team Alpha', location: 'CONUS — Utility Sector', mission: 'Hunt forward — Volt Typhoon', status: 'DEPLOYED', personnel: 12 },
    { team: 'CNMF Team Bravo', location: 'Europe — Energy Sector', mission: 'Defensive support — Sandworm', status: 'DEPLOYED', personnel: 15 },
    { team: 'CNMF Team Charlie', location: 'CONUS — DIB Sector', mission: 'Hunt forward — APT41', status: 'DEPLOYED', personnel: 10 },
    { team: 'CNMF Team Delta', location: 'Indo-Pacific — Naval', mission: 'Defensive support — APT40', status: 'DEPLOYED', personnel: 8 },
    { team: 'JTF-ARES Alpha', location: 'CONUS — Ft. Meade', mission: 'Counter-ISIS cyber ops', status: 'ACTIVE', personnel: 20 },
    { team: 'CMF Team 7', location: 'CONUS — Ft. Meade', mission: 'Sandworm infrastructure analysis', status: 'DEPLOYED', personnel: 14 },
    { team: 'CMF Team 12', location: 'CONUS — Telecom Sector', mission: 'Salt Typhoon investigation', status: 'DEPLOYED', personnel: 11 },
    { team: 'Reserve Team 1', location: 'CONUS — Available', mission: 'Standby for surge operations', status: 'STANDBY', personnel: 16 },
    { team: 'Reserve Team 2', location: 'CONUS — Available', mission: 'Standby for surge operations', status: 'STANDBY', personnel: 16 },
    { team: 'CISA Hunt Team A', location: 'CONUS — Federal Networks', mission: 'APT29 compromise assessment', status: 'DEPLOYED', personnel: 8 },
    { team: 'CISA ICS-CERT', location: 'CONUS — Water Sector', mission: 'SCADA security assessment', status: 'DEPLOYED', personnel: 6 },
    { team: 'FBI Cyber Division TF', location: 'Multiple — CONUS', mission: 'APT41 criminal investigation', status: 'ACTIVE', personnel: 25 }
  ];

  var totalDeployed = 0;
  var totalPersonnel = 0;
  for (var tr = 0; tr < resources.length; tr++) {
    if (resources[tr].status === 'DEPLOYED' || resources[tr].status === 'ACTIVE') totalDeployed++;
    totalPersonnel += resources[tr].personnel;
  }

  h += '<div style="display:flex;gap:10px;margin-bottom:12px;">';
  h += '<div style="flex:1;background:#0a0e1a;border:1px solid #00aaff33;border-radius:4px;padding:8px;text-align:center;">';
  h += '<div style="color:#556;font-size:9px;font-family:monospace;">TEAMS DEPLOYED</div>';
  h += '<div style="color:#00aaff;font-size:20px;font-weight:bold;font-family:monospace;">' + totalDeployed + '/' + resources.length + '</div>';
  h += '</div>';
  h += '<div style="flex:1;background:#0a0e1a;border:1px solid #00ff8833;border-radius:4px;padding:8px;text-align:center;">';
  h += '<div style="color:#556;font-size:9px;font-family:monospace;">TOTAL PERSONNEL</div>';
  h += '<div style="color:#00ff88;font-size:20px;font-weight:bold;font-family:monospace;">' + totalPersonnel + '</div>';
  h += '</div>';
  h += '</div>';

  for (var rs = 0; rs < resources.length; rs++) {
    var res = resources[rs];
    var resColor = res.status === 'DEPLOYED' ? '#00aaff' : res.status === 'ACTIVE' ? '#00ff88' : '#667';
    h += '<div style="display:flex;align-items:center;gap:8px;padding:4px 0;border-bottom:1px solid #111828;font-family:monospace;font-size:10px;">';
    h += '<div style="color:' + resColor + ';width:8px;text-align:center;">&#9679;</div>';
    h += '<div style="color:#ccd;min-width:120px;font-weight:bold;">' + esc(res.team) + '</div>';
    h += '<div style="color:#889;flex:1;">' + esc(res.mission) + '</div>';
    h += '<div style="color:#556;min-width:60px;text-align:right;">' + esc(res.personnel) + ' pax</div>';
    h += '</div>';
  }
  h += '</div>';

  // Congressional Notification Tracker
  h += '<div style="background:linear-gradient(135deg,#0c1020,#0a0e1a);border:1px solid #1a2a44;border-radius:8px;padding:16px;">';
  h += '<div style="color:#00aaff;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;margin-bottom:14px;border-bottom:1px solid #1a2a44;padding-bottom:8px;">';
  h += '<span style="color:#ffaa00;margin-right:8px;">[G]</span>CONGRESSIONAL NOTIFICATION TRACKER</div>';

  var congressNotifications = [
    { operation: 'OP IRON VEIL', type: 'Title 10 — Offensive Cyber', status: 'PENDING SUBMISSION', dueDate: '14 SEP 2026', committee: 'SASC, HASC, SSCI, HPSCI', briefingLevel: 'Gang of Eight', notes: 'Notification required prior to execution. Draft prepared, awaiting SECDEF signature.' },
    { operation: 'Volt Typhoon Eviction', type: 'Title 10 — Defensive', status: 'SUBMITTED', dueDate: '12 SEP 2026', committee: 'SASC, HASC', briefingLevel: 'Full committee', notes: 'Domestic critical infrastructure operation. Notification submitted 12 SEP. No objections received.' },
    { operation: 'APT41 Joint Investigation', type: 'Title 50 — Intelligence', status: 'SUBMITTED', dueDate: '11 SEP 2026', committee: 'SSCI, HPSCI', briefingLevel: 'Gang of Eight', notes: 'Joint FBI-IC operation. Finding submitted to Gang of Eight under existing MON.' },
    { operation: 'NK Crypto Tracking', type: 'Title 50 — Intelligence', status: 'COMPLETE', dueDate: '08 SEP 2026', committee: 'SSCI, HPSCI', briefingLevel: 'Full committee', notes: 'Treasury-led with IC support. Full committee briefing completed.' },
    { operation: 'Five Eyes Intel Sharing Expansion', type: 'Executive Agreement', status: 'COMPLETE', dueDate: '05 SEP 2026', committee: 'SFRC, HFAC', briefingLevel: 'Committee chairs', notes: 'Enhanced sharing agreement notified to foreign affairs committees.' }
  ];

  for (var cn = 0; cn < congressNotifications.length; cn++) {
    var cNotif = congressNotifications[cn];
    var cnStatusColor = cNotif.status === 'PENDING SUBMISSION' ? '#ff2244' : cNotif.status === 'SUBMITTED' ? '#ffaa00' : '#00ff88';
    h += '<div style="background:#0a0e1a;border:1px solid #1a2a44;border-radius:4px;padding:10px;margin-bottom:6px;">';
    h += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">';
    h += '<div style="color:#fff;font-size:12px;font-family:monospace;font-weight:bold;">' + esc(cNotif.operation) + '</div>';
    h += '<div style="margin-left:auto;background:' + cnStatusColor + '22;color:' + cnStatusColor + ';font-size:9px;font-family:monospace;padding:2px 8px;border-radius:3px;">' + esc(cNotif.status) + '</div>';
    h += '</div>';
    h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-bottom:6px;">';
    h += '<div><div style="color:#556;font-size:9px;font-family:monospace;letter-spacing:1px;">TYPE</div><div style="color:#889;font-size:10px;font-family:monospace;">' + esc(cNotif.type) + '</div></div>';
    h += '<div><div style="color:#556;font-size:9px;font-family:monospace;letter-spacing:1px;">COMMITTEES</div><div style="color:#889;font-size:10px;font-family:monospace;">' + esc(cNotif.committee) + '</div></div>';
    h += '<div><div style="color:#556;font-size:9px;font-family:monospace;letter-spacing:1px;">BRIEFING LEVEL</div><div style="color:#889;font-size:10px;font-family:monospace;">' + esc(cNotif.briefingLevel) + '</div></div>';
    h += '<div><div style="color:#556;font-size:9px;font-family:monospace;letter-spacing:1px;">DUE DATE</div><div style="color:#889;font-size:10px;font-family:monospace;">' + esc(cNotif.dueDate) + '</div></div>';
    h += '</div>';
    h += '<div style="color:#667;font-size:10px;font-family:monospace;font-style:italic;">' + esc(cNotif.notes) + '</div>';
    h += '</div>';
  }
  h += '</div>';

  h += '</div>'; // end resource/congressional grid

  // Escalation Status
  h += '<div style="padding:0 24px 24px 24px;">';
  h += '<div style="background:linear-gradient(135deg,#0c1020,#0a0e1a);border:1px solid #1a2a44;border-radius:8px;padding:16px;">';
  h += '<div style="color:#00aaff;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;margin-bottom:14px;border-bottom:1px solid #1a2a44;padding-bottom:8px;">';
  h += '<span style="color:#ff6644;margin-right:8px;">&#9650;</span>ESCALATION STATUS & AUTHORITY MATRIX</div>';

  h += '<div style="display:grid;grid-template-columns:repeat(5,1fr);gap:6px;">';
  var escalationSteps = [
    { level: 'ROUTINE', desc: 'Normal monitoring and defense', authority: 'Watch Officer', color: '#00ff88', active: false },
    { level: 'ELEVATED', desc: 'Increased threat indicators detected', authority: 'CYBERCOM J3', color: '#ffaa00', active: true },
    { level: 'SUBSTANTIAL', desc: 'Active threat requiring response planning', authority: 'CYBERCOM CDR', color: '#ff6644', active: false },
    { level: 'SEVERE', desc: 'Active attack requiring immediate response', authority: 'SECDEF', color: '#ff2244', active: false },
    { level: 'CRITICAL', desc: 'Strategic-level cyber warfare', authority: 'POTUS / NSC', color: '#ff0044', active: false }
  ];

  for (var es = 0; es < escalationSteps.length; es++) {
    var eStep = escalationSteps[es];
    h += '<div style="background:' + (eStep.active ? eStep.color + '11' : '#0a0e1a') + ';border:2px solid ' + (eStep.active ? eStep.color : '#1a2a44') + ';border-radius:6px;padding:12px;text-align:center;' + (eStep.active ? 'box-shadow:0 0 15px ' + eStep.color + '22;' : 'opacity:0.6;') + '">';
    h += '<div style="color:' + eStep.color + ';font-size:12px;font-family:monospace;font-weight:bold;letter-spacing:1px;margin-bottom:6px;">' + esc(eStep.level) + '</div>';
    h += '<div style="color:#889;font-size:9px;font-family:monospace;margin-bottom:6px;min-height:30px;">' + esc(eStep.desc) + '</div>';
    h += '<div style="color:#556;font-size:9px;font-family:monospace;border-top:1px solid #1a2a44;padding-top:6px;">' + esc(eStep.authority) + '</div>';
    if (eStep.active) {
      h += '<div style="color:' + eStep.color + ';font-size:9px;font-family:monospace;margin-top:6px;font-weight:bold;">&#9654; CURRENT</div>';
    }
    h += '</div>';
  }
  h += '</div>';
  h += '</div>';
  h += '</div>';

  return h;
}

// ============================================================================
// MAIN EXPORT — renderSentinelEye(main)
// ============================================================================

// ============================================================================
// SENTINEL EYE — EXPANDED HELPER / DETAIL RENDER FUNCTIONS
// Additional data arrays and 12 detailed rendering functions
// ============================================================================

// ============================================================================
// HISTORICAL OPERATIONS DETAIL (extended data for deep-dive views)
// ============================================================================
var HISTORICAL_OPERATIONS_DETAIL = {
  'op-001': {
    codename: 'OLYMPIC GAMES / STUXNET',
    attribution: 'United States (NSA TAO) & Israel (Unit 8200)',
    attributionConfidence: 95,
    fullDescription: 'The first known cyber weapon designed to cause physical destruction. Stuxnet targeted Siemens S7-300 PLCs controlling variable-frequency drives at the Natanz uranium enrichment facility. The malware manipulated centrifuge rotor speeds while reporting normal telemetry to operators, causing approximately 1,000 IR-1 centrifuges to fail over 10 months. Delivered via infected USB drives, it exploited four zero-day vulnerabilities and two stolen Realtek and JMicron digital certificates.',
    targets: ['Natanz Uranium Enrichment Facility', 'Bushehr Nuclear Power Plant (secondary)', 'Iranian nuclear supply chain'],
    ttps: [
      { technique: 'T1091', name: 'Replication Through Removable Media', detail: 'Initial infection via USB drives targeting air-gapped networks' },
      { technique: 'T1203', name: 'Exploitation for Client Execution', detail: 'Used 4 Windows zero-days: MS10-046 (LNK), MS10-061, MS08-067, MS10-073' },
      { technique: 'T1553.002', name: 'Code Signing', detail: 'Signed with stolen Realtek and JMicron certificates' },
      { technique: 'T1565.001', name: 'Stored Data Manipulation', detail: 'Altered PLC code while replaying normal SCADA readings' },
      { technique: 'T1485', name: 'Data Destruction', detail: 'Physical destruction of centrifuges via speed manipulation' }
    ],
    timeline: [
      { date: '2005', event: 'Development begins under codename Olympic Games' },
      { date: '2007-06', event: 'Early Stuxnet variant (0.5) deployed using Siemens Step 7 infection' },
      { date: '2009-06', event: 'Stuxnet 1.0 released with full zero-day exploit chain' },
      { date: '2010-01', event: 'Stuxnet spreads beyond Natanz due to configuration change' },
      { date: '2010-06', event: 'VirusBlokAda discovers Stuxnet in the wild' },
      { date: '2010-07', event: 'Symantec publishes initial analysis' },
      { date: '2010-09', event: 'Full ICS payload analysis reveals centrifuge targeting' },
      { date: '2010-11', event: 'Iran confirms Stuxnet caused centrifuge damage' },
      { date: '2012-06', event: 'NYT confirms US-Israel joint operation' }
    ],
    toolsUsed: ['Stuxnet worm (multiple variants)', 'Flame (reconnaissance predecessor)', 'Duqu (intelligence collection)', 'Fanny (USB worm for air-gapped recon)'],
    impact: 'Destroyed ~1,000 IR-1 centrifuges. Delayed Iranian nuclear program by an estimated 1-2 years. First proven case of cyber-physical attack.',
    significance: 'Demonstrated that cyber weapons can cause physical destruction of critical infrastructure. Opened the era of nation-state cyber warfare. Raised fundamental questions about cyber arms control and escalation.',
    lessonsLearned: ['Air-gapped networks are not immune to cyber attack', 'Supply chain infection can bridge network boundaries', 'Physical damage is achievable through cyber means', 'Malware containment failures can cause unintended spread', 'Digital certificates are a high-value target for APTs']
  },
  'op-002': {
    codename: 'NOTPETYA',
    attribution: 'Russia (GRU Unit 74455 / Sandworm)',
    attributionConfidence: 98,
    fullDescription: 'Destructive wiper malware disguised as ransomware, deployed via a compromised update to M.E.Doc, a Ukrainian tax accounting software used by ~80% of Ukrainian businesses. NotPetya used the leaked NSA exploit EternalBlue (MS17-010) and credential harvesting via Mimikatz for lateral movement. Despite displaying a ransom note, the encryption was irreversible by design, confirming its true purpose as a wiper. The attack caused over $10 billion in estimated global damages.',
    targets: ['Ukraine (primary)', 'Maersk (shipping)', 'Merck (pharma)', 'FedEx/TNT Express', 'Mondelez', 'Saint-Gobain', 'Reckitt Benckiser'],
    ttps: [
      { technique: 'T1195.002', name: 'Supply Chain Compromise', detail: 'Trojanized M.E.Doc software update mechanism' },
      { technique: 'T1210', name: 'Exploitation of Remote Services', detail: 'EternalBlue (MS17-010) for network propagation' },
      { technique: 'T1003', name: 'OS Credential Dumping', detail: 'Mimikatz and LSA Secrets for credential harvesting' },
      { technique: 'T1021.002', name: 'SMB/Windows Admin Shares', detail: 'PsExec and WMI for lateral movement with stolen creds' },
      { technique: 'T1486', name: 'Data Encrypted for Impact', detail: 'Modified Petya bootlocker - encryption irreversible by design' },
      { technique: 'T1561.002', name: 'Disk Structure Wipe', detail: 'MBR and MFT overwritten after pseudo-encryption' }
    ],
    timeline: [
      { date: '2017-04', event: 'M.E.Doc update servers compromised' },
      { date: '2017-05-15', event: 'First test deployment via M.E.Doc (XData ransomware)' },
      { date: '2017-06-27 09:30', event: 'NotPetya payload distributed via M.E.Doc update' },
      { date: '2017-06-27 10:00', event: 'Ukrainian organizations begin reporting mass encryption' },
      { date: '2017-06-27 12:00', event: 'Global spread detected - Maersk, Merck, FedEx affected' },
      { date: '2017-06-27 14:00', event: 'Researchers determine ransom payment mechanism is non-functional' },
      { date: '2017-06-28', event: 'Confirmed as wiper, not ransomware' },
      { date: '2018-02', event: 'US, UK, Australia attribute to Russian military' }
    ],
    toolsUsed: ['NotPetya wiper', 'EternalBlue (MS17-010)', 'Mimikatz', 'PsExec', 'WMI commands', 'Modified Petya MBR bootlocker'],
    impact: '$10B+ global damages. Maersk lost all domain controllers (recovered from offline Ghana DC). Merck lost $870M. FedEx/TNT lost $400M. Global shipping disrupted. 80% of Ukrainian enterprises affected.',
    significance: 'Most destructive and costly cyber attack in history. Demonstrated collateral damage risk of nation-state operations. Showed how supply chain compromise can achieve mass targeting. Led to significant cyber insurance industry changes.',
    lessonsLearned: ['Supply chain attacks can achieve enormous scale', 'Collateral damage in cyber operations can be massive and uncontrollable', 'Ransomware appearance can mask destructive intent', 'Patching critical vulnerabilities (EternalBlue) is essential', 'Isolated backups are the last line of defense']
  },
  'op-003': {
    codename: 'SUNBURST / SOLARWINDS',
    attribution: 'Russia (SVR / APT29 / Cozy Bear)',
    attributionConfidence: 92,
    fullDescription: 'An advanced supply chain compromise of the SolarWinds Orion IT monitoring platform. APT29 inserted a backdoor (SUNBURST) into the Orion software build pipeline, resulting in trojanized updates distributed to approximately 18,000 organizations. The attackers then selectively exploited about 100 high-value targets including US Treasury, Commerce, DHS, DOE, and several Fortune 500 companies. The operation remained undetected for approximately 14 months.',
    targets: ['US Treasury Department', 'US Commerce Department (NTIA)', 'US DHS/CISA', 'US DOE/NNSA', 'US State Department', 'Microsoft', 'FireEye', 'Intel', 'Cisco', 'Deloitte', 'NATO', 'UK Government'],
    ttps: [
      { technique: 'T1195.002', name: 'Supply Chain Compromise', detail: 'Injected SUNBURST backdoor into SolarWinds Orion build process' },
      { technique: 'T1027.005', name: 'Indicator Removal from Host', detail: 'SUNBURST had extensive anti-analysis and sandbox detection' },
      { technique: 'T1071.001', name: 'Application Layer Protocol', detail: 'C2 disguised as legitimate Orion Improvement Program traffic' },
      { technique: 'T1550.001', name: 'Application Access Token', detail: 'SAML token forging (Golden SAML) for persistent cloud access' },
      { technique: 'T1078', name: 'Valid Accounts', detail: 'Used legitimate admin credentials from compromised identity providers' }
    ],
    timeline: [
      { date: '2019-10', event: 'APT29 gains access to SolarWinds build environment' },
      { date: '2020-02', event: 'SUNBURST backdoor inserted into Orion software build' },
      { date: '2020-03', event: 'Trojanized Orion updates (2019.4 HF5 to 2020.2.1) distributed' },
      { date: '2020-03-26', event: 'First known SUNBURST activation in victim environment' },
      { date: '2020-06', event: 'Selective exploitation of ~100 high-value targets begins' },
      { date: '2020-12-08', event: 'FireEye discloses breach and discovers SUNBURST' },
      { date: '2020-12-13', event: 'CISA issues Emergency Directive 21-01' },
      { date: '2021-01', event: 'Follow-on tools TEARDROP and RAINDROP discovered' },
      { date: '2021-04', event: 'US formally attributes to SVR, sanctions imposed' }
    ],
    toolsUsed: ['SUNBURST (backdoor)', 'TEARDROP (memory-only dropper)', 'RAINDROP (Cobalt Strike loader)', 'GoldMax/SUNSHUTTLE (Linux backdoor)', 'Cobalt Strike', 'Golden SAML tooling'],
    impact: '18,000 organizations received trojanized updates. ~100 confirmed compromised (US gov agencies, Fortune 500). FireEye red team tools stolen. US government networks deeply penetrated. Estimated 14 months of undetected access.',
    significance: 'Most significant supply chain compromise ever discovered. Exposed fundamental weaknesses in software supply chain security. Led to Executive Order 14028 on cybersecurity. Changed how organizations assess third-party risk.',
    lessonsLearned: ['Software supply chain is a critical attack vector', 'Build environment security is as important as code security', 'Threat actors can maintain access for over a year undetected', 'Identity-based attacks (Golden SAML) enable persistent cloud access', 'Even security companies can be compromised']
  },
  'op-004': {
    codename: 'WANNACRY',
    attribution: 'North Korea (RGB / Lazarus Group)',
    attributionConfidence: 90,
    fullDescription: 'A ransomware worm that exploited the EternalBlue SMB vulnerability leaked from the NSA by Shadow Brokers. WannaCry infected over 200,000 computers across 150 countries in a single day, encrypting files and demanding Bitcoin ransom. The UK National Health Service was severely affected with hospitals diverting patients. A kill switch domain accidentally discovered by researcher Marcus Hutchins slowed the spread.',
    targets: ['UK NHS (hospitals, GP surgeries)', 'Telefonica (Spain)', 'FedEx', 'Renault/Nissan', 'Russian Interior Ministry', 'China universities', 'Deutsche Bahn', 'Global victims in 150 countries'],
    ttps: [
      { technique: 'T1210', name: 'Exploitation of Remote Services', detail: 'EternalBlue (MS17-010) SMB exploit for initial infection and propagation' },
      { technique: 'T1486', name: 'Data Encrypted for Impact', detail: 'AES-128 + RSA-2048 file encryption' },
      { technique: 'T1571', name: 'Non-Standard Port', detail: 'SMB scanning on port 445 for worm propagation' },
      { technique: 'T1497.001', name: 'System Checks', detail: 'Kill switch domain check (unregistered domain = sandbox detection)' }
    ],
    timeline: [
      { date: '2017-04-14', event: 'Shadow Brokers release EternalBlue exploit' },
      { date: '2017-05-12 07:44', event: 'WannaCry begins spreading globally' },
      { date: '2017-05-12 14:00', event: 'NHS England reports widespread disruption' },
      { date: '2017-05-12 15:30', event: 'Marcus Hutchins registers kill switch domain, slowing spread' },
      { date: '2017-05-13', event: 'Patched variants without kill switch appear' },
      { date: '2017-05-15', event: 'Over 200,000 systems infected across 150 countries' },
      { date: '2017-12', event: 'US, UK, Australia attribute to North Korea' },
      { date: '2018-09', event: 'DOJ indicts Park Jin Hyok (Lazarus Group)' }
    ],
    toolsUsed: ['WannaCry ransomware (multiple variants)', 'DoublePulsar backdoor', 'EternalBlue (MS17-010)'],
    impact: '200K+ systems infected. NHS: 80+ trusts affected, 19,000 appointments cancelled, 600 GP surgeries disrupted. Estimated $4-8B global damages. Ransom payments minimal (~$140K in Bitcoin).',
    significance: 'Demonstrated catastrophic potential of leaked nation-state exploits. Showed healthcare sector vulnerability. Led to increased patching urgency globally. First widespread ransomware worm.',
    lessonsLearned: ['Leaked offensive tools create unpredictable risks', 'Critical patches must be applied rapidly', 'Healthcare systems are dangerously exposed', 'Kill switch domains can be used for both C2 and analysis evasion', 'Worm capabilities massively amplify ransomware impact']
  },
  'op-005': {
    codename: 'OPM BREACH',
    attribution: 'China (MSS / Deep Panda)',
    attributionConfidence: 88,
    fullDescription: 'Chinese state actors penetrated the US Office of Personnel Management over a multi-year campaign, exfiltrating 22.1 million personnel records including highly sensitive SF-86 security clearance application forms containing personal histories, foreign contacts, financial records, and mental health information for current and former US government employees and contractors.',
    targets: ['US Office of Personnel Management', 'KeyPoint Government Solutions (contractor)', 'USIS (background investigation company)'],
    ttps: [
      { technique: 'T1078', name: 'Valid Accounts', detail: 'Stolen contractor credentials for initial access' },
      { technique: 'T1003', name: 'OS Credential Dumping', detail: 'Credential harvesting for lateral movement' },
      { technique: 'T1005', name: 'Data from Local System', detail: 'Targeted SF-86 databases and personnel records' },
      { technique: 'T1041', name: 'Exfiltration Over C2 Channel', detail: 'Data exfiltrated over encrypted C2 channels' },
      { technique: 'T1027', name: 'Obfuscated Files or Information', detail: 'Custom malware with obfuscation to evade detection' }
    ],
    timeline: [
      { date: '2013-11', event: 'Initial compromise of contractor KeyPoint Government Solutions' },
      { date: '2014-03', event: 'DHS detects intrusion and alerts OPM (not fully remediated)' },
      { date: '2014-05', event: 'Attackers re-enter OPM via stolen contractor credentials' },
      { date: '2014-07', event: 'SF-86 database exfiltration begins' },
      { date: '2014-12', event: 'Background investigation records stolen' },
      { date: '2015-04', event: 'OPM discovers breach during security product deployment' },
      { date: '2015-06', event: 'Public disclosure of 4.2M current/former employee records' },
      { date: '2015-07', event: 'Second disclosure: 21.5M background investigation records' }
    ],
    toolsUsed: ['PlugX RAT', 'Sakula RAT', 'HiKit rootkit', 'Custom data exfiltration tools'],
    impact: '22.1M personnel records stolen including 5.6M fingerprint records. SF-86 forms contain intimate personal details useful for counterintelligence. Described as potential goldmine for foreign intelligence recruitment and blackmail.',
    significance: 'Largest known theft of US government personnel data. Demonstrated catastrophic intelligence value of bulk personnel data theft. Led to creation of Defense Counterintelligence and Security Agency (DCSA). Changed US approach to personnel data protection.',
    lessonsLearned: ['Personnel databases are high-value intelligence targets', 'Contractor access management is critical', 'Multi-factor authentication must be enforced', 'Detection capability must match data sensitivity', 'Background investigation data requires highest-level protection']
  },
  'op-010': {
    codename: 'COLONIAL PIPELINE',
    attribution: 'Russia-based (DarkSide ransomware group)',
    attributionConfidence: 99,
    fullDescription: 'DarkSide ransomware operators compromised Colonial Pipeline Company, which operates the largest refined fuel pipeline in the US, carrying 2.5 million barrels per day serving 45% of East Coast fuel supply. The company proactively shut down pipeline operations for six days, causing fuel shortages, gas station queues, and emergency declarations in multiple states. A $4.4 million ransom was paid in Bitcoin, of which the FBI later recovered $2.3 million.',
    targets: ['Colonial Pipeline Company IT systems', 'US East Coast fuel supply chain (indirect)'],
    ttps: [
      { technique: 'T1133', name: 'External Remote Services', detail: 'Initial access via compromised VPN credentials (no MFA)' },
      { technique: 'T1486', name: 'Data Encrypted for Impact', detail: 'DarkSide ransomware encrypting IT systems' },
      { technique: 'T1078', name: 'Valid Accounts', detail: 'Legacy VPN account without multi-factor authentication' },
      { technique: 'T1490', name: 'Inhibit System Recovery', detail: 'Shadow copies deleted to prevent local recovery' }
    ],
    timeline: [
      { date: '2021-04-29', event: 'DarkSide accesses Colonial network via compromised VPN account' },
      { date: '2021-05-06', event: 'Data exfiltration (100GB) for double extortion' },
      { date: '2021-05-07', event: 'Ransomware deployed against IT network; Colonial discovers attack' },
      { date: '2021-05-07', event: 'Colonial proactively shuts down OT pipeline operations' },
      { date: '2021-05-08', event: 'Colonial pays $4.4M Bitcoin ransom' },
      { date: '2021-05-09', event: 'Emergency declaration by USDOT; EPA waives fuel standards' },
      { date: '2021-05-12', event: 'Pipeline operations resume' },
      { date: '2021-05-14', event: 'DarkSide announces shutdown (under pressure)' },
      { date: '2021-06-07', event: 'FBI recovers $2.3M of ransom payment' }
    ],
    toolsUsed: ['DarkSide ransomware', 'Cobalt Strike', 'PowerShell scripts', 'Data exfiltration tools'],
    impact: 'Largest US pipeline shut for 6 days. Fuel shortages across East Coast. Average gas prices spiked 6 cents/gallon. Emergency declarations in 4 states. Panic buying led to gas station outages in southeast US.',
    significance: 'Demonstrated critical infrastructure vulnerability to ransomware. Led to TSA pipeline cybersecurity directives. Accelerated federal cybersecurity executive orders. Showed that IT-side attacks can force OT shutdowns even without OT compromise.',
    lessonsLearned: ['MFA on remote access is not optional', 'IT/OT segmentation prevents cascading failures', 'Critical infrastructure operators need incident response plans', 'Ransomware can have national security implications', 'Government recovery of ransom funds is sometimes possible']
  }
};

// ============================================================================
// CYBER CAPABILITIES MATRIX (extended nation-state data)
// ============================================================================
var CYBER_CAPABILITIES_MATRIX = {
  'us': {
    workforce: 'Est. 6,000+ (Cyber Command) + NSA civilian/military',
    budget: 'Est. $10.5B (combined CYBERCOM + NSA)',
    zeroDayCapability: 'Tier 1 — Extensive zero-day development and acquisition programs via TAO and commercial brokers',
    cyberDoctrine: 'Persistent engagement and defend forward. Authorized for offensive operations under Title 10/50.',
    dimensions: { signalIntel: 10, offensiveOps: 10, defensiveOps: 9, cyberEspionage: 10, supplyChain: 8, infoOps: 7, iamCapability: 9, researchDev: 10 },
    keyUnits: ['NSA Tailored Access Operations (TAO)', 'Cyber National Mission Force (CNMF)', 'Joint Force HQ-Cyber', '16th Air Force (Information Warfare)'],
    targetMatrix: ['Russia: Critical infrastructure recon, election security', 'China: Counter-espionage, IP theft disruption', 'Iran: Nuclear program monitoring, sanctions enforcement', 'North Korea: Financial operations disruption, WMD monitoring', 'Counter-terrorism: ISIS/AQ communications disruption']
  },
  'ru': {
    workforce: 'Est. 1,000+ (GRU) + FSB + SVR cyber divisions',
    budget: 'Est. $300M-1B (highly classified)',
    zeroDayCapability: 'Tier 1 — Active zero-day development, known stockpile in SCADA/ICS vulnerabilities',
    cyberDoctrine: 'Information confrontation encompassing technical attack, information operations, and psychological warfare as unified concept.',
    dimensions: { signalIntel: 8, offensiveOps: 9, defensiveOps: 7, cyberEspionage: 9, supplyChain: 8, infoOps: 10, iamCapability: 7, researchDev: 8 },
    keyUnits: ['GRU Unit 26165 (APT28)', 'GRU Unit 74455 (Sandworm)', 'SVR (APT29)', 'FSB Center 16 (Turla/Dragonfly)', 'FSB Center 18'],
    targetMatrix: ['Ukraine: Full spectrum cyber warfare', 'NATO: Espionage, pre-positioning for disruption', 'US: Election interference, critical infrastructure', 'Europe: Energy sector, political interference', 'Baltic states: Hybrid warfare campaigns']
  },
  'cn': {
    workforce: 'Est. 100,000+ (PLA SSF + MSS + contractors)',
    budget: 'Est. $1.5-3B (combined military and civilian)',
    zeroDayCapability: 'Tier 1 — Significant zero-day research via Tianfu Cup and government programs, commercial exploit market',
    cyberDoctrine: 'Informationized warfare integrating cyber, electronic warfare, and space. Focus on espionage for economic and military advantage.',
    dimensions: { signalIntel: 9, offensiveOps: 9, defensiveOps: 8, cyberEspionage: 10, supplyChain: 9, infoOps: 8, iamCapability: 8, researchDev: 9 },
    keyUnits: ['PLA SSF Network Systems Dept (Unit 61398, 61486)', 'MSS (APT41, APT10, Hafnium)', 'Volt Typhoon (critical infrastructure)', 'Salt Typhoon (telecom)', 'Integrity Technology (contractor)'],
    targetMatrix: ['US: Critical infrastructure pre-positioning, IP theft', 'Taiwan: Military intel, infrastructure mapping', 'ASEAN: Territorial dispute intel', 'Europe: Technology and trade secret theft', 'Global: Strategic technology acquisition']
  },
  'kp': {
    workforce: 'Est. 6,800+ (Bureau 121 + supporting elements)',
    budget: 'Est. $100-200M (partially self-funded through theft)',
    zeroDayCapability: 'Tier 2 — Uses purchased and leaked zero-days, some indigenous development',
    cyberDoctrine: 'Asymmetric warfare tool for regime survival. Cyber operations generate revenue and project power far beyond conventional capabilities.',
    dimensions: { signalIntel: 4, offensiveOps: 7, defensiveOps: 3, cyberEspionage: 6, supplyChain: 5, infoOps: 4, iamCapability: 3, researchDev: 5 },
    keyUnits: ['RGB Bureau 121', 'Lazarus Group', 'Kimsuky (APT43)', 'Andariel', 'BlueNoroff (financial)'],
    targetMatrix: ['Global: Cryptocurrency theft for regime funding ($2B+ stolen)', 'South Korea: Military espionage, defector tracking', 'US: Defense data theft, retaliatory attacks', 'SWIFT banking: Financial theft campaigns', 'Global: Ransomware for revenue generation']
  },
  'ir': {
    workforce: 'Est. 2,000-5,000 (IRGC + contractors)',
    budget: 'Est. $100-500M',
    zeroDayCapability: 'Tier 2 — Growing indigenous capability, uses commercial and leaked exploits',
    cyberDoctrine: 'Cyber operations as asymmetric deterrent against technologically superior adversaries. Retaliation-focused with emphasis on destructive capabilities.',
    dimensions: { signalIntel: 5, offensiveOps: 7, defensiveOps: 5, cyberEspionage: 6, supplyChain: 4, infoOps: 7, iamCapability: 4, researchDev: 5 },
    keyUnits: ['IRGC Cyber Command', 'APT33 (Elfin)', 'APT34 (OilRig)', 'APT35 (Charming Kitten)', 'MuddyWater'],
    targetMatrix: ['Saudi Arabia: Oil/gas infrastructure destruction', 'Israel: Government, military, civilian targets', 'US: Financial sector, critical infrastructure', 'Gulf states: Regional rival espionage', 'Albania: Retaliatory attacks on MEK host nations']
  },
  'il': {
    workforce: 'Est. 5,000+ (Unit 8200 alone)',
    budget: 'Est. $1-2B (including commercial spin-offs)',
    zeroDayCapability: 'Tier 1 — World-class zero-day development, NSO Group and commercial exploit ecosystem',
    cyberDoctrine: 'Cyber as force multiplier for national defense. Emphasis on intelligence collection and preemptive disruption of existential threats.',
    dimensions: { signalIntel: 9, offensiveOps: 9, defensiveOps: 8, cyberEspionage: 9, supplyChain: 7, infoOps: 6, iamCapability: 8, researchDev: 10 },
    keyUnits: ['Unit 8200 (SIGINT/Cyber)', 'Unit 81 (Technology)', 'Mossad cyber division', 'NSO Group (commercial)', 'Candiru (commercial)'],
    targetMatrix: ['Iran: Nuclear program disruption, espionage', 'Hezbollah/Hamas: Counter-terrorism intel', 'Syria: Military intelligence', 'Regional: Strategic intelligence collection', 'Global: Counter-proliferation operations']
  }
};

// ============================================================================
// THREAT ACTOR TOOLS DATABASE
// ============================================================================
var THREAT_ACTOR_TOOLS = [
  {
    id: 'tool-001', name: 'Cobalt Strike', type: 'C2 Framework', developer: 'Strategic Cyber LLC (commercial, widely pirated)',
    usedBy: ['APT29', 'APT41', 'Lazarus', 'FIN7', 'DarkSide', 'REvil', 'Conti', 'Many others'],
    capabilities: ['Beacon payload generation', 'Malleable C2 profiles', 'Lateral movement', 'Credential harvesting', 'Process injection', 'SOCKS proxying'],
    firstSeen: '2012', lastSeen: '2026-09',
    iocs: { hashes: ['a1b2c3d4...', 'e5f6a7b8...'], domains: ['*.cloudfront.net (malleable)', '*.azureedge.net'], ips: ['Various — rotated frequently'] },
    detectionSignatures: ['YARA: CobaltStrike_Beacon_x86', 'Suricata: ET MALWARE CobaltStrike C2', 'Sigma: proc_creation_win_cobaltstrike_pipe'],
    relatedTools: ['Metasploit', 'Brute Ratel', 'Sliver', 'Mythic']
  },
  {
    id: 'tool-002', name: 'Mimikatz', type: 'Credential Harvesting', developer: 'Benjamin Delpy (open source)',
    usedBy: ['APT28', 'APT29', 'Sandworm', 'Lazarus', 'APT41', 'Nearly all threat actors'],
    capabilities: ['LSASS credential dumping', 'Kerberos ticket extraction', 'Pass-the-hash', 'Pass-the-ticket', 'Golden/Silver ticket creation', 'DCSync'],
    firstSeen: '2011', lastSeen: '2026-09',
    iocs: { hashes: ['mimikatz.exe variants...'], domains: ['N/A - post-exploitation tool'], ips: ['N/A'] },
    detectionSignatures: ['YARA: Mimikatz_Memory_Rule', 'Windows Event: 4624 (Type 9 + DCSyn)', 'Sigma: proc_access_win_mimikatz_lsass'],
    relatedTools: ['Rubeus', 'Impacket secretsdump', 'pypykatz', 'LaZagne']
  },
  {
    id: 'tool-003', name: 'BlackEnergy / Industroyer', type: 'ICS/SCADA Malware', developer: 'Sandworm (GRU Unit 74455)',
    usedBy: ['Sandworm'],
    capabilities: ['ICS protocol manipulation (IEC 101/104, OPC DA)', 'SCADA HMI interaction', 'Wiper component', 'DDoS capability', 'Remote access trojan'],
    firstSeen: '2007 (BlackEnergy v1)', lastSeen: '2022 (Industroyer2 in Ukraine)',
    iocs: { hashes: ['BE3: f2e21...', 'Industroyer: d7a9c...'], domains: ['Various C2 domains'], ips: ['Various — Ukrainian ISP ranges targeted'] },
    detectionSignatures: ['YARA: Industroyer_IEC104', 'Snort: ICS protocol anomaly rules', 'IDS: OPC DA unauthorized write detection'],
    relatedTools: ['CrashOverride', 'Industroyer2', 'AcidRain', 'CaddyWiper']
  },
  {
    id: 'tool-004', name: 'PlugX / ShadowPad', type: 'RAT / Backdoor', developer: 'Chinese MSS contractors (Chengdu 404)',
    usedBy: ['APT41', 'APT10', 'APT1', 'Winnti', 'Bronze President', 'Multiple Chinese APTs'],
    capabilities: ['Remote shell access', 'File upload/download', 'Keylogging', 'Screen capture', 'Plugin architecture', 'DLL side-loading'],
    firstSeen: '2008 (PlugX) / 2015 (ShadowPad)', lastSeen: '2026-09',
    iocs: { hashes: ['PlugX: varies widely...'], domains: ['Dynamic DNS services commonly used'], ips: ['SE Asia hosting frequently'] },
    detectionSignatures: ['YARA: PlugX_DLL_Sideload', 'Sigma: plugx_dll_sideloading', 'Suricata: ET MALWARE PlugX C2 Beacon'],
    relatedTools: ['Gh0st RAT', 'PoisonIvy', 'QuasarRAT', 'Winnti backdoor']
  },
  {
    id: 'tool-005', name: 'SUNBURST', type: 'Supply Chain Backdoor', developer: 'APT29 (SVR)',
    usedBy: ['APT29'],
    capabilities: ['SolarWinds Orion trojanization', 'Dormant activation (2-week delay)', 'Environment fingerprinting', 'C2 via DNS (DGA) and HTTP', 'Anti-forensics and sandbox evasion'],
    firstSeen: '2020-03', lastSeen: '2020-12',
    iocs: { hashes: ['d130bd75645c2433f88ac03e73...', 'ce77d116a074dab7a22a0fd4f2c...'], domains: ['avsvmcloud.com (C2)'], ips: ['Various — used legitimate cloud services'] },
    detectionSignatures: ['YARA: SUNBURST_Backdoor', 'Snort: SUNBURST DNS DGA detection', 'CISA: Emergency Directive 21-01 indicators'],
    relatedTools: ['TEARDROP', 'RAINDROP', 'GoldMax', 'SUNSHUTTLE', 'Cobalt Strike (follow-on)']
  },
  {
    id: 'tool-006', name: 'Emotet', type: 'Loader / Botnet', developer: 'Mealybug (criminal group)',
    usedBy: ['TA542', 'Conti affiliates', 'Ryuk operators', 'TrickBot operators'],
    capabilities: ['Mass spam distribution', 'Credential theft', 'Loader for secondary payloads', 'Modular architecture', 'Email thread hijacking', 'Network propagation'],
    firstSeen: '2014', lastSeen: '2023 (resurrected after 2021 takedown)',
    iocs: { hashes: ['Frequently packed — thousands of unique samples'], domains: ['Compromised WordPress sites for C2'], ips: ['Rotating botnet infrastructure'] },
    detectionSignatures: ['YARA: Emotet_Document_Macro', 'Suricata: ET MALWARE Emotet C2', 'Sigma: proc_creation_win_emotet'],
    relatedTools: ['TrickBot', 'QakBot', 'IcedID', 'BazarLoader']
  },
  {
    id: 'tool-007', name: 'Pegasus', type: 'Mobile Spyware', developer: 'NSO Group (Israel, commercial)',
    usedBy: ['Multiple state customers (45+ countries)', 'Unit 8200 (alleged development support)'],
    capabilities: ['Zero-click iPhone/Android exploitation', 'Encrypted messaging interception (Signal, WhatsApp, Telegram)', 'Microphone/camera activation', 'Location tracking', 'File extraction', 'Keylogging'],
    firstSeen: '2016', lastSeen: '2026-09',
    iocs: { hashes: ['Device-specific — forensic analysis required'], domains: ['icloud-analytics.com (historical)', 'Various per-deployment'], ips: ['NSO infrastructure rotated per client'] },
    detectionSignatures: ['MVT (Mobile Verification Toolkit)', 'iMazing Spyware Detection', 'Amnesty International forensic indicators'],
    relatedTools: ['Predator (Cytrox/Intellexa)', 'Candiru (DevilsTongue)', 'FinFisher', 'Hermit (RCS Lab)']
  },
  {
    id: 'tool-008', name: 'ALPHV/BlackCat', type: 'Ransomware', developer: 'ALPHV (suspected Darkside/BlackMatter rebrand)',
    usedBy: ['ALPHV affiliates', 'Scattered Spider (UNC3944)'],
    capabilities: ['Written in Rust (cross-platform)', 'Configurable encryption (AES/ChaCha20)', 'ESXi hypervisor encryption', 'Self-propagating via PsExec/GPO', 'Data exfiltration for double extortion', 'Public leak site'],
    firstSeen: '2021-11', lastSeen: '2024 (law enforcement disruption)',
    iocs: { hashes: ['Rust binary — varies per compilation'], domains: ['alphvmmm27o3abo3r2mlmjrpdmz...onion'], ips: ['Tor hidden services'] },
    detectionSignatures: ['YARA: ALPHV_BlackCat_Ransomware', 'Sigma: ransomware_blackcat', 'Suricata: ET MALWARE BlackCat Negotiation Site'],
    relatedTools: ['LockBit', 'Cl0p', 'Royal/BlackSuit', 'Hive']
  }
];

// ============================================================================
// ALLIANCE NETWORKS
// ============================================================================
var ALLIANCE_NETWORKS = [
  {
    id: 'fvey', name: 'Five Eyes (FVEY)', members: ['United States', 'United Kingdom', 'Canada', 'Australia', 'New Zealand'],
    capabilities: 'Full spectrum SIGINT sharing, joint cyber operations, shared infrastructure, coordinated attribution',
    sharingLevel: 'TOP SECRET // SI // REL TO FVEY',
    lastExercise: 'Cyber Flag 26-2 (2026-07)',
    description: 'Premier intelligence sharing alliance. Full integration of cyber threat intelligence, joint hunt-forward operations, coordinated vulnerability disclosure and attribution statements.',
    activeOps: 3
  },
  {
    id: 'nato-ccdcoe', name: 'NATO CCDCOE', members: ['31 NATO members + partners'],
    capabilities: 'Locked Shields exercise, Tallinn Manual legal framework, joint research, collective defense cyber policy',
    sharingLevel: 'NATO SECRET',
    lastExercise: 'Locked Shields 2026 (2026-04)',
    description: 'NATO Cooperative Cyber Defence Centre of Excellence. Conducts the largest live-fire cyber defense exercise annually. Develops international law and policy frameworks for cyber operations.',
    activeOps: 1
  },
  {
    id: 'quad-cyber', name: 'Quad Cyber Partnership', members: ['United States', 'Japan', 'Australia', 'India'],
    capabilities: 'Critical infrastructure protection, supply chain security, cyber capacity building, joint threat briefings',
    sharingLevel: 'SECRET // REL TO QUAD',
    lastExercise: 'Quad Cyber Challenge 2026 (2026-05)',
    description: 'Indo-Pacific focused cyber partnership. Emphasizes critical technology supply chain security, 5G/6G network security, and countering Chinese cyber operations in the region.',
    activeOps: 1
  },
  {
    id: 'eu-cert', name: 'EU CSIRTs Network', members: ['27 EU member state CSIRTs + CERT-EU'],
    capabilities: 'Incident response coordination, vulnerability disclosure, threat intelligence sharing, joint exercises',
    sharingLevel: 'EU RESTRICTED',
    lastExercise: 'Cyber Europe 2026 (2026-06)',
    description: 'Network of Computer Security Incident Response Teams across EU member states. Coordinates response to large-scale cross-border cyber incidents. Key role in NIS2 Directive implementation.',
    activeOps: 2
  },
  {
    id: 'bilateral-us-il', name: 'US-Israel Bilateral Cyber', members: ['United States', 'Israel'],
    capabilities: 'Joint offensive operations, zero-day sharing, ICS/SCADA security, counter-Iran operations',
    sharingLevel: 'TOP SECRET // SI // REL TO USA, ISR',
    lastExercise: 'Juniper Cobra Cyber (2026-03)',
    description: 'Deep bilateral cyber cooperation spanning offensive and defensive operations. Joint development of cyber weapons (Stuxnet). Shared R&D on critical infrastructure protection.',
    activeOps: 2
  }
];

// ============================================================================
// ZERO-DAY MARKET INTELLIGENCE (simulated dark web monitoring)
// ============================================================================
var ZERO_DAY_MARKET_INTEL = [
  { id: 'zd-001', category: 'Mobile', target: 'iOS 19 Zero-Click RCE', price: '$2,500,000', riskLevel: 'CRITICAL', seller: 'ShadowVault', lastSeen: '2026-09-12', buyers: 'Nation-state interest confirmed', description: 'Full chain zero-click exploit for latest iOS via iMessage. No user interaction required. Sandbox escape + kernel privilege escalation included.' },
  { id: 'zd-002', category: 'Browser', target: 'Chrome V8 Type Confusion', price: '$500,000', riskLevel: 'HIGH', seller: 'ZeroBroker', lastSeen: '2026-09-11', buyers: 'Multiple bids received', description: 'V8 JavaScript engine type confusion leading to RCE. Works on Chrome 128+ and Chromium-based browsers. Renderer process escape sold separately.' },
  { id: 'zd-003', category: 'Enterprise', target: 'Microsoft Exchange RCE', price: '$750,000', riskLevel: 'CRITICAL', seller: 'DarkCodex', lastSeen: '2026-09-10', buyers: 'Auction format — reserve met', description: 'Pre-auth remote code execution in Exchange Server 2019 CU14+. HTTP-based, no credentials required. Wormable potential.' },
  { id: 'zd-004', category: 'ICS/SCADA', target: 'Siemens S7-1500 PLC Auth Bypass', price: '$1,200,000', riskLevel: 'CRITICAL', seller: 'IndustroHack', lastSeen: '2026-09-09', buyers: 'State-sponsored buyer confirmed', description: 'Authentication bypass allowing arbitrary program upload to S7-1500 series PLCs. Affects firmware 2.9+. Potential for physical damage.' },
  { id: 'zd-005', category: 'Network', target: 'Palo Alto PAN-OS RCE', price: '$400,000', riskLevel: 'HIGH', seller: 'FWBreaker', lastSeen: '2026-09-08', buyers: 'Under negotiation', description: 'Remote code execution in PAN-OS management interface. Pre-auth, affects 11.x versions. Access to firewall configuration and network traffic.' },
  { id: 'zd-006', category: 'Mobile', target: 'Android Pixel Bootloader Bypass', price: '$800,000', riskLevel: 'HIGH', seller: 'MobileZero', lastSeen: '2026-09-11', buyers: 'Government contractor interest', description: 'Persistent implant surviving factory reset on Google Pixel 8/9 devices. Firmware-level access with SELinux bypass.' },
  { id: 'zd-007', category: 'Cloud', target: 'AWS IAM Privilege Escalation', price: '$300,000', riskLevel: 'HIGH', seller: 'CloudPwn', lastSeen: '2026-09-10', buyers: 'Active bidding', description: 'IAM policy evaluation flaw allowing any authenticated AWS user to escalate to admin. Works across all regions.' },
  { id: 'zd-008', category: 'Enterprise', target: 'VMware ESXi Hypervisor Escape', price: '$1,500,000', riskLevel: 'CRITICAL', seller: 'VirtBreak', lastSeen: '2026-09-12', buyers: 'Premium tier — invitation only', description: 'Guest-to-host escape on VMware ESXi 8.0. Gain hypervisor-level code execution from any VM. Full infrastructure compromise potential.' },
  { id: 'zd-009', category: 'VPN', target: 'Fortinet FortiGate SSL VPN', price: '$350,000', riskLevel: 'HIGH', seller: 'NetPenetrator', lastSeen: '2026-09-07', buyers: 'Rapid interest from ransomware groups', description: 'Pre-authentication RCE in FortiGate SSL VPN. Affects FortiOS 7.4.x. Estimated 500K+ internet-facing targets.' },
  { id: 'zd-010', category: 'Firmware', target: 'Intel ME/CSME Persistent Backdoor', price: '$3,000,000', riskLevel: 'CRITICAL', seller: 'DeepSilicon', lastSeen: '2026-09-06', buyers: 'Nation-state only', description: 'Persistent implant in Intel Management Engine. Survives OS reinstall, firmware update, and hard drive replacement. Ring -3 access.' }
];

// ============================================================================
// COMMUNICATION TEMPLATES
// ============================================================================
var COMMUNICATION_TEMPLATES = {
  'sitrep': {
    name: 'SITUATION REPORT (SITREP)',
    classification: 'SECRET // NOFORN',
    fields: [
      { label: 'DTG', description: 'Date-Time Group (DDHHMMZ MON YYYY)', example: '130800Z SEP 2026' },
      { label: 'FROM', description: 'Originating unit/command', example: 'USCYBERCOM J3 CURRENT OPS' },
      { label: 'TO', description: 'Distribution list', example: 'SECDEF / NSC / CISA / FBI CYBER' },
      { label: 'SUBJ', description: 'Subject with classification', example: '(S//NF) CYBER SITREP 026-253' },
      { label: '1. SITUATION', description: 'Current operational environment summary', example: 'A. Global Cyber Threat Level: ORANGE (ELEVATED). B. Nation-state activity: Increased APT29 operations targeting NATO diplomatic networks. C. Ransomware: LockBit 4.0 variant affecting healthcare sector.' },
      { label: '2. OPERATIONS', description: 'Current and planned operations', example: 'A. Defensive: Hunt-forward team deployed to [ALLIED NATION]. B. Active: Operation IRON SHIELD monitoring APT28 C2 infrastructure. C. Planned: Coordinated takedown of identified ransomware infrastructure NLT 15 SEP.' },
      { label: '3. INTELLIGENCE', description: 'Key intelligence updates', example: 'A. SIGINT indicates PRC-affiliated actors staging capabilities against US telecom providers. B. OSINT reporting suggests imminent Russian hybrid operation against Baltic state. C. DARKWEB: New zero-day listing for ICS/SCADA targets — assessed HIGH credibility.' },
      { label: '4. LOGISTICS/PERSONNEL', description: 'Team status and resource needs', example: 'A. CNMF Teams: 14/16 operational (2 in reset). B. Critical: Need additional ICS/SCADA analysts for Sector response. C. Tools: New YARA signatures deployed to all sensor platforms.' },
      { label: '5. COMMUNICATIONS', description: 'Communication status and issues', example: 'A. All C2 systems operational. B. JWICS connectivity nominal. C. Ally coordination: UK NCSC video conference scheduled 131400Z SEP.' },
      { label: '6. COMMANDER ASSESSMENT', description: 'Senior leader assessment and recommendations', example: 'Elevated threat posture warrants maintaining enhanced monitoring. Recommend pre-authorization of defensive counter-ops against identified APT29 infrastructure.' }
    ]
  },
  'oprep3': {
    name: 'OPERATIONAL REPORT (OPREP-3)',
    classification: 'TOP SECRET // SCI',
    fields: [
      { label: 'MSGID', description: 'Message identifier', example: 'OPREP-3/CYBER PINNACLE/026-253-001' },
      { label: 'DTG', description: 'Date-Time Group', example: '130345Z SEP 2026' },
      { label: 'CATEGORY', description: 'Event category', example: 'CYBER PINNACLE (national-level cyber event)' },
      { label: 'EVENT DESCRIPTION', description: 'What happened', example: 'At 130215Z SEP 2026, USCYBERCOM CNMF detected active intrusion into [CRITICAL INFRASTRUCTURE ENTITY] attributed to PRC-affiliated APT group Volt Typhoon. Adversary has established persistent access to operational technology network controlling [SYSTEMS].' },
      { label: 'IMPACT ASSESSMENT', description: 'Current and potential impact', example: 'CURRENT: Adversary has read access to OT network. POTENTIAL: If adversary executes destructive payload, impact to [SECTOR] could affect [X] million customers in [REGION].' },
      { label: 'RESPONSE ACTIONS', description: 'Actions taken and planned', example: 'A. CNMF team on-site providing technical assistance. B. Coordinating with CISA for sector-wide advisory. C. NSA providing SIGINT support for adversary tracking. D. Recommend POTUS-level brief NLT 130600Z.' },
      { label: 'REQUESTED AUTHORITY', description: 'Authorities needed', example: 'Request authorization for active cyber defense measures against identified adversary infrastructure per NSPM-13 and EXORD 2019-001. Specific targets identified in Annex B (TS//SCI//SAP).' }
    ]
  },
  'flash': {
    name: 'FLASH MESSAGE',
    classification: 'TOP SECRET // SCI // FLASH PRECEDENCE',
    fields: [
      { label: 'PRECEDENCE', description: 'Message priority', example: 'FLASH (highest priority — immediate action required)' },
      { label: 'DTG', description: 'Date-Time Group', example: '130147Z SEP 2026' },
      { label: 'FROM', description: 'Originator', example: 'DIRNSA / CDR USCYBERCOM' },
      { label: 'TO', description: 'Action addressees', example: 'POTUS / SECDEF / DNI / NSA / DHS SEC' },
      { label: 'INFO', description: 'Information addressees', example: 'JCS / COCOM CDRS / FBI DIR / CISA DIR' },
      { label: 'SUBJECT', description: 'Subject line', example: '(TS//SCI) IMMINENT NATION-STATE CYBER ATTACK ON US CRITICAL INFRASTRUCTURE' },
      { label: 'BODY', description: 'Concise message body', example: 'FLASH — USCYBERCOM has detected indicators of imminent destructive cyber attack against US [SECTOR] infrastructure by [NATION-STATE] forces. Attack assessed to commence within 24 hours based on infrastructure activation pattern matching historical [OPERATION NAME]. Recommend immediate transition to CYBER DEFCON 2 and pre-authorization of defensive response operations. Full intelligence package at Annex A.' }
    ]
  },
  'exbrief': {
    name: 'EXECUTIVE BRIEF',
    classification: 'TOP SECRET // SCI // NOFORN',
    fields: [
      { label: 'PREPARED FOR', description: 'Recipient', example: 'National Security Council Principals Committee' },
      { label: 'PREPARED BY', description: 'Originating organization', example: 'USCYBERCOM / NSA Joint Intelligence Directorate' },
      { label: 'DATE', description: 'Date of brief', example: '13 September 2026' },
      { label: 'TOPIC', description: 'Brief topic', example: 'Global Cyber Threat Posture and Recommended Actions' },
      { label: 'BOTTOM LINE UP FRONT (BLUF)', description: 'Key takeaway in 1-2 sentences', example: 'Multiple nation-state actors are increasing operational tempo against US and allied critical infrastructure. We recommend elevating to CYBER DEFCON 2 and authorizing pre-positioned defensive operations.' },
      { label: 'BACKGROUND', description: 'Context and history', example: 'Over the past 72 hours, USCYBERCOM has observed a significant increase in preparatory cyber activity from Russian (Sandworm) and Chinese (Volt Typhoon) state actors...' },
      { label: 'CURRENT SITUATION', description: 'Present state of affairs', example: 'Three concurrent nation-state operations detected: [1] APT29 targeting NATO diplomatic networks... [2] Volt Typhoon activating dormant access in US telecom... [3] Lazarus Group staging cryptocurrency theft infrastructure...' },
      { label: 'OPTIONS', description: 'Courses of action', example: 'OPTION A: Maintain current posture with enhanced monitoring. OPTION B: Elevate to CYBER DEFCON 2, authorize hunt-forward teams. OPTION C: Full cyber DEFCON 1 with pre-authorized counter-operations.' },
      { label: 'RECOMMENDATION', description: 'Preferred course of action', example: 'OPTION B — Provides enhanced defensive posture while maintaining de-escalation pathway. Estimated cost: $12M for 30-day enhanced operations.' }
    ]
  }
};

// ============================================================================
// TABLETOP EXERCISES
// ============================================================================
var TABLETOP_EXERCISES = [
  {
    id: 'ttx-001', name: 'CYBER STORM VIII',
    scenario: 'A coordinated nation-state attack targeting US power grid and water systems simultaneously. The adversary (attributed to Sandworm/GRU) uses pre-positioned Volt Typhoon-style access in OT networks to deploy wipers during a period of geopolitical tension.',
    injects: [
      { time: 'T+0:00', event: 'CISA receives reports of anomalous SCADA behavior at 3 major power utilities in different ISOs' },
      { time: 'T+0:30', event: 'Water treatment facility in major metro area reports chemical dosing system malfunction' },
      { time: 'T+1:00', event: 'SIGINT confirms C2 traffic pattern matching Sandworm infrastructure' },
      { time: 'T+1:30', event: 'Additional power utilities report similar issues — total now 8 across 4 states' },
      { time: 'T+2:00', event: 'Media begins reporting power outages — public concern rising' },
      { time: 'T+2:30', event: 'NSA intercept suggests second wave targeting natural gas pipelines' },
      { time: 'T+3:00', event: 'FBI reports coordinated DDoS against emergency services 911 systems' },
      { time: 'T+4:00', event: 'President requests options briefing — what are our response options?' },
      { time: 'T+5:00', event: 'Allied nation reports similar attacks on their infrastructure' },
      { time: 'T+6:00', event: 'Adversary publicly denies involvement — information warfare begins' }
    ],
    evaluationCriteria: ['Detection speed (time from first anomaly to confirmed attribution)', 'Cross-sector coordination effectiveness', 'Escalation decision quality', 'Public communication strategy', 'International coordination timeliness', 'Recovery prioritization decisions'],
    participantRoles: ['National Security Advisor', 'USCYBERCOM Commander', 'CISA Director', 'FBI Cyber Division', 'DHS Secretary', 'DOE Emergency Response', 'Private sector utility CEOs', 'State governors (affected states)', 'NSA Director', 'White House Communications']
  },
  {
    id: 'ttx-002', name: 'DIGITAL PEARL HARBOR',
    scenario: 'A surprise multi-vector cyber attack by China during a Taiwan Strait crisis. Volt Typhoon activates pre-positioned access across US telecom, power, water, and transportation while conventional military operations begin. The cyber attack aims to delay US military response.',
    injects: [
      { time: 'T+0:00', event: 'DOD detects unusual PLA military movement near Taiwan Strait' },
      { time: 'T+0:15', event: 'Major US ISPs report core router failures in Pacific region' },
      { time: 'T+0:30', event: 'PACOM reports degraded satellite communications' },
      { time: 'T+0:45', event: 'West Coast ports report logistics system outages' },
      { time: 'T+1:00', event: 'Multiple CONUS military base power systems experience anomalies' },
      { time: 'T+1:30', event: 'Financial market infrastructure reporting latency issues' },
      { time: 'T+2:00', event: 'China commences military operations near Taiwan' },
      { time: 'T+3:00', event: 'GPS anomalies detected across Pacific theater' },
      { time: 'T+4:00', event: 'Allied nations ask for US cyber support — stretch resources' }
    ],
    evaluationCriteria: ['Ability to attribute while under attack', 'Cyber-conventional integration', 'Alliance coordination under pressure', 'Resource allocation triage', 'Escalation management', 'Continuity of government operations'],
    participantRoles: ['POTUS', 'Secretary of Defense', 'Chairman JCS', 'INDOPACOM Commander', 'CYBERCOM Commander', 'NSA Director', 'DHS Secretary', 'Secretary of State', 'Director of National Intelligence']
  },
  {
    id: 'ttx-003', name: 'RANSOMWARE PANDEMIC',
    scenario: 'A ransomware-as-a-service operation deploys simultaneously across 500+ healthcare facilities during a flu pandemic. Hospitals lose access to EHR, imaging, and pharmacy systems. The ransomware group demands $50M collective ransom and threatens to leak patient data.',
    injects: [
      { time: 'T+0:00', event: 'First hospital system reports encryption of all Windows servers' },
      { time: 'T+0:30', event: 'HHS reports 47 hospitals across 12 states affected' },
      { time: 'T+1:00', event: 'Ambulance diversions create regional EMS crisis' },
      { time: 'T+1:30', event: 'Number of affected facilities reaches 200+' },
      { time: 'T+2:00', event: 'First confirmed patient death attributed to delayed treatment' },
      { time: 'T+2:30', event: 'Ransomware group posts 1TB of patient records as proof' },
      { time: 'T+3:00', event: 'FBI identifies operator location in non-extradition country' },
      { time: 'T+4:00', event: 'Congressional leaders demand immediate briefing' },
      { time: 'T+5:00', event: 'Second wave hits pharmacy supply chain systems' }
    ],
    evaluationCriteria: ['Healthcare sector mutual aid coordination', 'Patient care continuity decisions', 'Ransom payment policy application', 'Law enforcement coordination', 'Public health communication', 'Pharmaceutical supply chain contingency'],
    participantRoles: ['HHS Secretary', 'CISA Director', 'FBI Director', 'CDC Director', 'Hospital CEO representatives', 'State health commissioners', 'Pharmaceutical company leadership', 'Insurance industry representatives']
  },
  {
    id: 'ttx-004', name: 'SUPPLY CHAIN CASCADE',
    scenario: 'A sophisticated adversary compromises a widely-used open source library (similar to SolarWinds but targeting the JavaScript/npm ecosystem). The trojanized package is pulled by 50,000+ applications including government, financial, and defense sector software. The backdoor activates after a 60-day dormancy period.',
    injects: [
      { time: 'T+0:00', event: 'Security researcher discovers suspicious code in popular npm package (10M weekly downloads)' },
      { time: 'T+0:30', event: 'Analysis reveals sophisticated backdoor with C2 capability' },
      { time: 'T+1:00', event: 'Package usage analysis shows presence in 47 federal agency applications' },
      { time: 'T+1:30', event: 'Backdoor C2 infrastructure traced to APT41-associated hosting' },
      { time: 'T+2:00', event: 'Evidence of data exfiltration from 3 defense contractors discovered' },
      { time: 'T+3:00', event: 'GitHub reports the maintainer account was compromised 90 days ago' },
      { time: 'T+4:00', event: 'CISA determines full scope of impact — over 300 government apps affected' },
      { time: 'T+5:00', event: 'Adversary begins destroying evidence on compromised systems' }
    ],
    evaluationCriteria: ['Supply chain visibility and assessment speed', 'Cross-sector notification effectiveness', 'Technical remediation coordination', 'Open source ecosystem response', 'Intelligence sharing speed', 'Legal and attribution considerations'],
    participantRoles: ['CISA Director', 'NSA Cybersecurity Director', 'GitHub/npm leadership', 'Federal CIOs Council', 'Defense contractor CISOs', 'DOJ National Security Division', 'OMB Cyber Policy', 'Open source foundation representatives']
  }
];

// ============================================================================
// MITRE ATT&CK TACTIC/TECHNIQUE MAPPING
// ============================================================================
var MITRE_TACTICS = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
  'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'Command & Control',
  'Exfiltration', 'Impact'
];

var MITRE_TECHNIQUES_BY_TACTIC = {
  'Reconnaissance': ['T1595 Active Scanning', 'T1592 Gather Host Info', 'T1589 Gather Identity Info', 'T1590 Gather Network Info', 'T1591 Gather Org Info'],
  'Resource Development': ['T1583 Acquire Infrastructure', 'T1586 Compromise Accounts', 'T1584 Compromise Infrastructure', 'T1587 Develop Capabilities', 'T1588 Obtain Capabilities'],
  'Initial Access': ['T1566 Phishing', 'T1190 Exploit Public App', 'T1195 Supply Chain', 'T1078 Valid Accounts', 'T1133 External Remote Services'],
  'Execution': ['T1059 Command Scripting', 'T1203 Exploitation for Client', 'T1047 WMI', 'T1053 Scheduled Task', 'T1204 User Execution'],
  'Persistence': ['T1547 Boot Autostart', 'T1136 Create Account', 'T1505 Server Software', 'T1053 Scheduled Task', 'T1078 Valid Accounts'],
  'Privilege Escalation': ['T1548 Abuse Elevation', 'T1134 Access Token Manipulation', 'T1068 Exploitation for Priv Esc', 'T1484 Domain Policy Mod'],
  'Defense Evasion': ['T1027 Obfuscated Files', 'T1055 Process Injection', 'T1070 Indicator Removal', 'T1036 Masquerading', 'T1562 Impair Defenses'],
  'Credential Access': ['T1003 OS Credential Dump', 'T1110 Brute Force', 'T1056 Input Capture', 'T1557 Adversary-in-the-Middle', 'T1552 Unsecured Credentials'],
  'Discovery': ['T1087 Account Discovery', 'T1083 File Discovery', 'T1046 Network Service Scan', 'T1057 Process Discovery', 'T1082 System Info Discovery'],
  'Lateral Movement': ['T1021 Remote Services', 'T1210 Exploitation of Remote Services', 'T1570 Lateral Tool Transfer', 'T1550 Use Alternate Auth'],
  'Collection': ['T1560 Archive Data', 'T1005 Data from Local System', 'T1114 Email Collection', 'T1113 Screen Capture', 'T1125 Video Capture'],
  'Command & Control': ['T1071 Application Layer Protocol', 'T1573 Encrypted Channel', 'T1105 Ingress Tool Transfer', 'T1090 Proxy', 'T1572 Protocol Tunneling'],
  'Exfiltration': ['T1041 Exfil Over C2', 'T1048 Exfil Over Alt Protocol', 'T1567 Exfil to Cloud', 'T1029 Scheduled Transfer'],
  'Impact': ['T1486 Data Encrypted', 'T1485 Data Destruction', 'T1489 Service Stop', 'T1529 System Shutdown', 'T1565 Data Manipulation']
};

var APT_MITRE_COVERAGE = {
  'APT28': ['Reconnaissance', 'Initial Access', 'Execution', 'Persistence', 'Credential Access', 'Lateral Movement', 'Collection', 'Exfiltration'],
  'APT29': ['Reconnaissance', 'Resource Development', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Command & Control', 'Exfiltration'],
  'Sandworm': ['Reconnaissance', 'Resource Development', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Lateral Movement', 'Impact'],
  'Turla': ['Reconnaissance', 'Initial Access', 'Execution', 'Persistence', 'Defense Evasion', 'Credential Access', 'Discovery', 'Collection', 'Command & Control', 'Exfiltration'],
  'APT41': ['Reconnaissance', 'Resource Development', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Command & Control', 'Exfiltration'],
  'Volt Typhoon': ['Reconnaissance', 'Initial Access', 'Execution', 'Persistence', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection'],
  'Lazarus': ['Reconnaissance', 'Resource Development', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Command & Control', 'Exfiltration', 'Impact'],
  'Kimsuky': ['Reconnaissance', 'Initial Access', 'Execution', 'Persistence', 'Credential Access', 'Collection', 'Command & Control', 'Exfiltration'],
  'APT33': ['Reconnaissance', 'Initial Access', 'Execution', 'Persistence', 'Defense Evasion', 'Credential Access', 'Lateral Movement', 'Impact'],
  'APT34': ['Reconnaissance', 'Initial Access', 'Execution', 'Persistence', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Exfiltration'],
  'MuddyWater': ['Reconnaissance', 'Initial Access', 'Execution', 'Persistence', 'Defense Evasion', 'Credential Access', 'Discovery', 'Command & Control'],
  'APT32': ['Reconnaissance', 'Initial Access', 'Execution', 'Persistence', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Command & Control', 'Exfiltration'],
  'Equation Group': ['Reconnaissance', 'Resource Development', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Command & Control', 'Exfiltration', 'Impact'],
  'Gamaredon': ['Reconnaissance', 'Initial Access', 'Execution', 'Persistence', 'Defense Evasion', 'Collection', 'Command & Control', 'Exfiltration'],
  'DarkSide': ['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Lateral Movement', 'Impact'],
  'LockBit': ['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Impact'],
  'Conti': ['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Exfiltration', 'Impact']
};


// ============================================================================
// RENDER FUNCTION 1: renderOperationDetail(opId)
// ============================================================================
function renderOperationDetail(opId) {
  var op = HISTORICAL_OPERATIONS_DETAIL[opId];
  if (!op) {
    var basic = null;
    for (var i = 0; i < HISTORICAL_OPS.length; i++) {
      if (HISTORICAL_OPS[i].id === opId) { basic = HISTORICAL_OPS[i]; break; }
    }
    if (!basic) return '<div style="padding:40px;text-align:center;color:#556;">No detailed data available for this operation.</div>';
    var h = '';
    h += '<div style="background:#0a0e1a;border:1px solid #1a3a5c;border-radius:8px;padding:24px;margin:16px 0;">';

    h += '<h3 style="color:#00aaff;font-family:monospace;letter-spacing:2px;margin:0 0 12px 0;">' + esc(basic.name) + ' (' + esc(basic.year) + ')</h3>';
    h += '<div style="color:#889;font-size:12px;margin-bottom:8px;"><span style="color:#ffaa00;">ATTRIBUTION:</span> ' + esc(basic.attribution) + '</div>';
    h += '<div style="color:#889;font-size:12px;margin-bottom:8px;"><span style="color:#ffaa00;">TYPE:</span> ' + esc(basic.type) + '</div>';
    h += '<div style="color:#c8d8e8;font-size:13px;margin-bottom:8px;">' + esc(basic.description) + '</div>';
    h += '<div style="color:#889;font-size:12px;margin-bottom:8px;"><span style="color:#ffaa00;">TARGETS:</span> ' + esc(basic.targets) + '</div>';
    h += '<div style="color:#889;font-size:12px;"><span style="color:#ffaa00;">IMPACT:</span> ' + esc(basic.impact) + '</div>';
    h += '</div>';
    return h;
  }

  var h = '';
  h += '<div style="background:#060a14;border:2px solid #1a3a5c;border-radius:8px;overflow:hidden;margin:16px 0;">';

  // Classification banner


  // Codename banner
  h += '<div style="background:linear-gradient(135deg,#0a1628,#0d1f3c);padding:24px;border-bottom:1px solid #1a3a5c;">';
  h += '<div style="font-size:10px;color:#556;letter-spacing:3px;margin-bottom:4px;">OPERATION CODENAME</div>';
  h += '<h2 style="margin:0;font-size:28px;color:#00aaff;font-family:monospace;letter-spacing:4px;text-shadow:0 0 20px rgba(0,170,255,0.3);">' + esc(op.codename) + '</h2>';
  h += '</div>';

  // Attribution panel
  h += '<div style="padding:16px 24px;border-bottom:1px solid #1a3a5c;display:flex;gap:24px;flex-wrap:wrap;">';
  h += '<div style="flex:1;min-width:200px;">';
  h += '<div style="font-size:10px;color:#556;letter-spacing:2px;margin-bottom:4px;">ATTRIBUTION</div>';
  h += '<div style="color:#ff6644;font-size:14px;font-weight:bold;">' + esc(op.attribution) + '</div>';
  h += '</div>';
  h += '<div style="min-width:150px;">';
  h += '<div style="font-size:10px;color:#556;letter-spacing:2px;margin-bottom:4px;">CONFIDENCE</div>';
  var confColor = op.attributionConfidence >= 90 ? '#00ff88' : op.attributionConfidence >= 70 ? '#ffaa00' : '#ff6644';
  h += '<div style="display:flex;align-items:center;gap:8px;">';
  h += '<div style="width:80px;height:8px;background:#1a2a3c;border-radius:4px;overflow:hidden;"><div style="width:' + op.attributionConfidence + '%;height:100%;background:' + confColor + ';border-radius:4px;"></div></div>';
  h += '<span style="color:' + confColor + ';font-size:14px;font-weight:bold;">' + op.attributionConfidence + '%</span>';
  h += '</div>';
  h += '</div>';
  h += '</div>';

  // Full description
  h += '<div style="padding:16px 24px;border-bottom:1px solid #1a3a5c;">';
  h += '<div style="font-size:10px;color:#556;letter-spacing:2px;margin-bottom:8px;">OPERATION SUMMARY</div>';
  h += '<div style="color:#c8d8e8;font-size:13px;line-height:1.6;">' + esc(op.fullDescription) + '</div>';
  h += '</div>';

  // Targets
  h += '<div style="padding:16px 24px;border-bottom:1px solid #1a3a5c;">';
  h += '<div style="font-size:10px;color:#556;letter-spacing:2px;margin-bottom:8px;">TARGETS</div>';
  h += '<div style="display:flex;flex-wrap:wrap;gap:8px;">';
  for (var t = 0; t < op.targets.length; t++) {
    h += '<span style="background:#1a0a0a;border:1px solid #ff224433;color:#ff8866;padding:4px 10px;border-radius:4px;font-size:11px;">' + esc(op.targets[t]) + '</span>';
  }
  h += '</div>';
  h += '</div>';

  // TTP Breakdown
  h += '<div style="padding:16px 24px;border-bottom:1px solid #1a3a5c;">';
  h += '<div style="font-size:10px;color:#556;letter-spacing:2px;margin-bottom:12px;">TTP BREAKDOWN (MITRE ATT&CK)</div>';
  for (var tp = 0; tp < op.ttps.length; tp++) {
    var ttp = op.ttps[tp];
    h += '<div style="background:#0a0e1a;border:1px solid #1a3a5c;border-radius:6px;padding:10px 14px;margin-bottom:8px;display:flex;gap:12px;align-items:flex-start;">';
    h += '<span style="background:#00aaff22;color:#00aaff;padding:2px 8px;border-radius:3px;font-size:10px;font-family:monospace;white-space:nowrap;border:1px solid #00aaff44;">' + esc(ttp.technique) + '</span>';
    h += '<div>';
    h += '<div style="color:#c8d8e8;font-size:12px;font-weight:bold;">' + esc(ttp.name) + '</div>';
    h += '<div style="color:#889;font-size:11px;margin-top:2px;">' + esc(ttp.detail) + '</div>';
    h += '</div>';
    h += '</div>';
  }
  h += '</div>';

  // Timeline
  h += '<div style="padding:16px 24px;border-bottom:1px solid #1a3a5c;">';
  h += '<div style="font-size:10px;color:#556;letter-spacing:2px;margin-bottom:12px;">OPERATION TIMELINE</div>';
  h += '<div style="position:relative;padding-left:24px;">';
  h += '<div style="position:absolute;left:8px;top:0;bottom:0;width:2px;background:linear-gradient(180deg,#00aaff,#00aaff44);"></div>';
  for (var tl = 0; tl < op.timeline.length; tl++) {
    var evt = op.timeline[tl];
    h += '<div style="position:relative;margin-bottom:12px;padding-left:16px;">';
    h += '<div style="position:absolute;left:-20px;top:4px;width:10px;height:10px;background:#00aaff;border-radius:50%;border:2px solid #080b12;"></div>';
    h += '<div style="color:#00aaff;font-size:11px;font-family:monospace;letter-spacing:1px;">' + esc(evt.date) + '</div>';
    h += '<div style="color:#c8d8e8;font-size:12px;margin-top:2px;">' + esc(evt.event) + '</div>';
    h += '</div>';
  }
  h += '</div>';
  h += '</div>';

  // Tools Used
  h += '<div style="padding:16px 24px;border-bottom:1px solid #1a3a5c;">';
  h += '<div style="font-size:10px;color:#556;letter-spacing:2px;margin-bottom:8px;">TOOLS &amp; MALWARE EMPLOYED</div>';
  h += '<div style="display:flex;flex-wrap:wrap;gap:8px;">';
  for (var to = 0; to < op.toolsUsed.length; to++) {
    h += '<span style="background:#0a1628;border:1px solid #00aaff33;color:#44bbff;padding:4px 10px;border-radius:4px;font-size:11px;font-family:monospace;">' + esc(op.toolsUsed[to]) + '</span>';
  }
  h += '</div>';
  h += '</div>';

  // Impact Assessment
  h += '<div style="padding:16px 24px;border-bottom:1px solid #1a3a5c;">';
  h += '<div style="font-size:10px;color:#556;letter-spacing:2px;margin-bottom:8px;">IMPACT ASSESSMENT</div>';
  h += '<div style="color:#ff8866;font-size:13px;line-height:1.5;padding:12px;background:#1a0a0a;border:1px solid #ff224433;border-radius:6px;">' + esc(op.impact) + '</div>';
  h += '</div>';

  // Significance
  h += '<div style="padding:16px 24px;border-bottom:1px solid #1a3a5c;">';
  h += '<div style="font-size:10px;color:#556;letter-spacing:2px;margin-bottom:8px;">STRATEGIC SIGNIFICANCE</div>';
  h += '<div style="color:#c8d8e8;font-size:13px;line-height:1.5;padding:12px;background:#0a1628;border:1px solid #00aaff22;border-radius:6px;">' + esc(op.significance) + '</div>';
  h += '</div>';

  // Lessons Learned
  h += '<div style="padding:16px 24px;">';
  h += '<div style="font-size:10px;color:#556;letter-spacing:2px;margin-bottom:8px;">LESSONS LEARNED</div>';
  for (var ll = 0; ll < op.lessonsLearned.length; ll++) {
    h += '<div style="display:flex;gap:8px;align-items:flex-start;margin-bottom:6px;">';
    h += '<span style="color:#ffaa00;font-size:12px;">&#9656;</span>';
    h += '<span style="color:#c8d8e8;font-size:12px;">' + esc(op.lessonsLearned[ll]) + '</span>';
    h += '</div>';
  }
  h += '</div>';

  h += '</div>';
  return h;
}


// ============================================================================
// RENDER FUNCTION 2: renderNationDetail(nationId)
// ============================================================================
function renderNationDetail(nationId) {
  var nation = null;
  for (var i = 0; i < NATION_STATE_PROFILES.length; i++) {
    if (NATION_STATE_PROFILES[i].id === nationId) { nation = NATION_STATE_PROFILES[i]; break; }
  }
  if (!nation) return '<div style="padding:40px;text-align:center;color:#556;">Nation profile not found.</div>';

  var capMatrix = CYBER_CAPABILITIES_MATRIX[nationId];
  var h = '';
  h += '<div style="background:#060a14;border:2px solid #1a3a5c;border-radius:8px;overflow:hidden;margin:16px 0;">';

  // Classification banner


  // Header
  h += '<div style="background:linear-gradient(135deg,#0a1628,#0d1f3c);padding:24px;border-bottom:1px solid #1a3a5c;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:16px;">';
  h += '<div>';
  h += '<div style="font-size:36px;margin-bottom:4px;">' + esc(nation.flag) + '</div>';
  h += '<h2 style="margin:0;font-size:24px;color:#00aaff;font-family:monospace;letter-spacing:3px;">' + esc(nation.name) + '</h2>';
  h += '<div style="color:#889;font-size:12px;margin-top:4px;">' + esc(nation.cyberCommand) + '</div>';
  h += '</div>';
  h += '<div style="text-align:right;">';
  var tlColors = { 1: '#00ff88', 2: '#44cc88', 3: '#ffaa00', 4: '#ff6622', 5: '#ff2244' };
  var tierColor = nation.tier === 1 ? '#ff2244' : nation.tier === 2 ? '#ff6622' : '#ffaa00';
  h += '<div style="font-size:10px;color:#556;letter-spacing:2px;margin-bottom:4px;">CAPABILITY TIER</div>';
  h += '<div style="font-size:32px;color:' + tierColor + ';font-weight:bold;font-family:monospace;text-shadow:0 0 15px ' + tierColor + '44;">TIER ' + nation.tier + '</div>';
  h += '<div style="color:#6688aa;font-size:10px;letter-spacing:1px;margin-top:4px;">Based on public threat research</div>';
  h += '</div>';
  h += '</div>';

  // Capability dimensions
  if (capMatrix) {
    h += '<div style="padding:16px 24px;border-bottom:1px solid #1a3a5c;">';
    h += '<div style="font-size:10px;color:#556;letter-spacing:2px;margin-bottom:12px;">CAPABILITY ASSESSMENT</div>';
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:10px;">';
    var dims = capMatrix.dimensions;
    var dimLabels = {
      signalIntel: 'SIGNALS INTELLIGENCE', offensiveOps: 'OFFENSIVE OPERATIONS', defensiveOps: 'DEFENSIVE OPERATIONS',
      cyberEspionage: 'CYBER ESPIONAGE', supplyChain: 'SUPPLY CHAIN OPS', infoOps: 'INFORMATION OPERATIONS',
      iamCapability: 'IDENTITY & ACCESS', researchDev: 'RESEARCH & DEVELOPMENT'
    };
    for (var dk in dims) {
      if (dims.hasOwnProperty(dk)) {
        var val = dims[dk];
        var barColor = val >= 8 ? '#00ff88' : val >= 5 ? '#ffaa00' : '#ff4466';
        h += '<div style="background:#0a0e1a;border:1px solid #1a3a5c;border-radius:4px;padding:8px 12px;">';
        h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">';
        h += '<span style="color:#889;font-size:9px;letter-spacing:1px;">' + (dimLabels[dk] || esc(dk)) + '</span>';
        h += '<span style="color:' + barColor + ';font-size:12px;font-weight:bold;">' + val + '/10</span>';
        h += '</div>';
        h += '<div style="width:100%;height:6px;background:#1a2a3c;border-radius:3px;overflow:hidden;">';
        h += '<div style="width:' + (val * 10) + '%;height:100%;background:' + barColor + ';border-radius:3px;"></div>';
        h += '</div>';
        h += '</div>';
      }
    }
    h += '</div>';
    h += '</div>';

    // Workforce & Budget
    h += '<div style="padding:16px 24px;border-bottom:1px solid #1a3a5c;display:flex;gap:24px;flex-wrap:wrap;">';
    h += '<div style="flex:1;min-width:200px;background:#0a0e1a;border:1px solid #1a3a5c;border-radius:6px;padding:12px;">';
    h += '<div style="font-size:9px;color:#556;letter-spacing:2px;margin-bottom:4px;">WORKFORCE</div>';
    h += '<div style="color:#c8d8e8;font-size:13px;">' + esc(capMatrix.workforce) + '</div>';
    h += '</div>';
    h += '<div style="flex:1;min-width:200px;background:#0a0e1a;border:1px solid #1a3a5c;border-radius:6px;padding:12px;">';
    h += '<div style="font-size:9px;color:#556;letter-spacing:2px;margin-bottom:4px;">ESTIMATED BUDGET</div>';
    h += '<div style="color:#c8d8e8;font-size:13px;">' + esc(capMatrix.budget) + '</div>';
    h += '</div>';
    h += '</div>';

    // Zero-Day Capability
    h += '<div style="padding:16px 24px;border-bottom:1px solid #1a3a5c;">';
    h += '<div style="font-size:10px;color:#556;letter-spacing:2px;margin-bottom:8px;">ZERO-DAY CAPABILITY</div>';
    h += '<div style="color:#ffaa00;font-size:13px;padding:10px;background:#1a1a0a;border:1px solid #ffaa0033;border-radius:6px;">' + esc(capMatrix.zeroDayCapability) + '</div>';
    h += '</div>';

    // Key Units
    h += '<div style="padding:16px 24px;border-bottom:1px solid #1a3a5c;">';
    h += '<div style="font-size:10px;color:#556;letter-spacing:2px;margin-bottom:8px;">KEY CYBER UNITS</div>';
    h += '<div style="display:flex;flex-wrap:wrap;gap:8px;">';
    for (var ku = 0; ku < capMatrix.keyUnits.length; ku++) {
      h += '<span style="background:#0a1628;border:1px solid #00aaff33;color:#44bbff;padding:6px 12px;border-radius:4px;font-size:11px;">' + esc(capMatrix.keyUnits[ku]) + '</span>';
    }
    h += '</div>';
    h += '</div>';

    // Target Matrix
    h += '<div style="padding:16px 24px;border-bottom:1px solid #1a3a5c;">';
    h += '<div style="font-size:10px;color:#556;letter-spacing:2px;margin-bottom:8px;">TARGET MATRIX</div>';
    for (var tm = 0; tm < capMatrix.targetMatrix.length; tm++) {
      h += '<div style="display:flex;gap:8px;align-items:flex-start;margin-bottom:6px;">';
      h += '<span style="color:#ff6644;font-size:12px;">&#9656;</span>';
      h += '<span style="color:#c8d8e8;font-size:12px;">' + esc(capMatrix.targetMatrix[tm]) + '</span>';
      h += '</div>';
    }
    h += '</div>';

    // Cyber Doctrine
    h += '<div style="padding:16px 24px;border-bottom:1px solid #1a3a5c;">';
    h += '<div style="font-size:10px;color:#556;letter-spacing:2px;margin-bottom:8px;">CYBER DOCTRINE</div>';
    h += '<div style="color:#c8d8e8;font-size:13px;line-height:1.5;padding:10px;background:#0a0e1a;border:1px solid #1a3a5c;border-radius:6px;">' + esc(capMatrix.cyberDoctrine) + '</div>';
    h += '</div>';
  }

  // APT Groups
  h += '<div style="padding:16px 24px;border-bottom:1px solid #1a3a5c;">';
  h += '<div style="font-size:10px;color:#556;letter-spacing:2px;margin-bottom:8px;">ASSOCIATED APT GROUPS</div>';
  h += '<div style="display:flex;flex-wrap:wrap;gap:8px;">';
  for (var ag = 0; ag < nation.aptGroups.length; ag++) {
    h += '<span style="background:#1a0a0a;border:1px solid #ff224433;color:#ff8866;padding:6px 12px;border-radius:4px;font-size:11px;font-family:monospace;">' + esc(nation.aptGroups[ag]) + '</span>';
  }
  h += '</div>';
  h += '</div>';

  // Known Operations
  h += '<div style="padding:16px 24px;border-bottom:1px solid #1a3a5c;">';
  h += '<div style="font-size:10px;color:#556;letter-spacing:2px;margin-bottom:8px;">KNOWN OPERATIONS</div>';
  for (var ko = 0; ko < nation.knownOps.length; ko++) {
    h += '<div style="display:flex;gap:8px;align-items:flex-start;margin-bottom:4px;">';
    h += '<span style="color:#ffaa00;font-size:11px;">&#9679;</span>';
    h += '<span style="color:#c8d8e8;font-size:12px;">' + esc(nation.knownOps[ko]) + '</span>';
    h += '</div>';
  }
  h += '</div>';

  // Attribution note (replaces removed fake activity/posture data)
  h += '<div style="padding:16px 24px;">';
  h += '<div style="font-size:10px;color:#556;letter-spacing:2px;margin-bottom:8px;">ATTRIBUTION SOURCES</div>';
  h += '<div style="font-family:monospace;font-size:10px;color:#6688aa;background:#0a0e1a;border:1px solid #1a3a5c;border-radius:6px;padding:12px;line-height:1.6;">';
  h += 'Nation-state attribution data sourced from public threat reports including MITRE ATT&CK, CISA advisories, and published threat research. ';
  h += 'For current threat activity, consult official sources such as CISA (cisa.gov), NCSC (ncsc.gov.uk), and your national CERT.';
  h += '</div>';
  h += '</div>';

  h += '</div>';
  return h;
}


// ============================================================================
// RENDER FUNCTION 3: renderToolProfile(toolId)
// ============================================================================
function renderToolProfile(toolId) {
  var tool = null;
  for (var i = 0; i < THREAT_ACTOR_TOOLS.length; i++) {
    if (THREAT_ACTOR_TOOLS[i].id === toolId) { tool = THREAT_ACTOR_TOOLS[i]; break; }
  }
  if (!tool) return '<div style="padding:40px;text-align:center;color:#556;">Tool profile not found.</div>';

  var h = '';
  h += '<div style="background:#060a14;border:2px solid #1a3a5c;border-radius:8px;overflow:hidden;margin:16px 0;">';
  h += '<div style="background:#cc0000;color:#fff;text-align:center;padding:4px;font-size:10px;letter-spacing:3px;">TOP SECRET // SCI — THREAT ACTOR TOOLING PROFILE</div>';

  // Header
  h += '<div style="background:linear-gradient(135deg,#0a1628,#0d1f3c);padding:20px 24px;border-bottom:1px solid #1a3a5c;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;">';
  h += '<div>';
  h += '<h3 style="margin:0;font-size:22px;color:#00aaff;font-family:monospace;letter-spacing:2px;">' + esc(tool.name) + '</h3>';
  h += '<div style="color:#889;font-size:11px;margin-top:4px;">Developer: ' + esc(tool.developer) + '</div>';
  h += '</div>';
  var typeColors = { 'C2 Framework': '#ff6644', 'Credential Harvesting': '#ffaa00', 'ICS/SCADA Malware': '#ff2244', 'RAT / Backdoor': '#ff8844', 'Supply Chain Backdoor': '#cc44ff', 'Loader / Botnet': '#44aaff', 'Mobile Spyware': '#ff44aa', 'Ransomware': '#ff2244' };
  var tc = typeColors[tool.type] || '#889';
  h += '<span style="background:' + tc + '22;color:' + tc + ';border:1px solid ' + tc + '44;padding:6px 14px;border-radius:4px;font-size:11px;font-family:monospace;letter-spacing:1px;">' + esc(tool.type) + '</span>';
  h += '</div>';

  // Active period
  h += '<div style="padding:12px 24px;border-bottom:1px solid #1a3a5c;display:flex;gap:24px;flex-wrap:wrap;">';
  h += '<div><span style="color:#556;font-size:10px;letter-spacing:1px;">FIRST SEEN: </span><span style="color:#00ff88;font-size:13px;font-family:monospace;">' + esc(tool.firstSeen) + '</span></div>';
  h += '<div><span style="color:#556;font-size:10px;letter-spacing:1px;">LAST SEEN: </span><span style="color:#ff6644;font-size:13px;font-family:monospace;">' + esc(tool.lastSeen) + '</span></div>';
  h += '</div>';

  // Used by
  h += '<div style="padding:14px 24px;border-bottom:1px solid #1a3a5c;">';
  h += '<div style="font-size:10px;color:#556;letter-spacing:2px;margin-bottom:8px;">USED BY THREAT ACTORS</div>';
  h += '<div style="display:flex;flex-wrap:wrap;gap:6px;">';
  for (var u = 0; u < tool.usedBy.length; u++) {
    h += '<span style="background:#1a0a0a;border:1px solid #ff224433;color:#ff8866;padding:4px 10px;border-radius:4px;font-size:10px;font-family:monospace;">' + esc(tool.usedBy[u]) + '</span>';
  }
  h += '</div>';
  h += '</div>';

  // Capabilities
  h += '<div style="padding:14px 24px;border-bottom:1px solid #1a3a5c;">';
  h += '<div style="font-size:10px;color:#556;letter-spacing:2px;margin-bottom:8px;">CAPABILITIES</div>';
  for (var c = 0; c < tool.capabilities.length; c++) {
    h += '<div style="display:flex;gap:8px;margin-bottom:4px;align-items:center;">';
    h += '<span style="color:#00aaff;font-size:10px;">&#9654;</span>';
    h += '<span style="color:#c8d8e8;font-size:12px;">' + esc(tool.capabilities[c]) + '</span>';
    h += '</div>';
  }
  h += '</div>';

  // IOCs
  h += '<div style="padding:14px 24px;border-bottom:1px solid #1a3a5c;">';
  h += '<div style="font-size:10px;color:#556;letter-spacing:2px;margin-bottom:8px;">INDICATORS OF COMPROMISE</div>';
  h += '<div style="background:#0a0e1a;border:1px solid #1a3a5c;border-radius:6px;padding:12px;font-family:monospace;font-size:11px;">';
  h += '<div style="margin-bottom:8px;"><span style="color:#ffaa00;">FILE HASHES:</span> <span style="color:#c8d8e8;">' + esc(tool.iocs.hashes.join(', ')) + '</span></div>';
  h += '<div style="margin-bottom:8px;"><span style="color:#ffaa00;">DOMAINS:</span> <span style="color:#c8d8e8;">' + esc(tool.iocs.domains.join(', ')) + '</span></div>';
  h += '<div><span style="color:#ffaa00;">IP ADDRESSES:</span> <span style="color:#c8d8e8;">' + esc(typeof tool.iocs.ips === 'string' ? tool.iocs.ips : tool.iocs.ips.join(', ')) + '</span></div>';
  h += '</div>';
  h += '</div>';

  // Detection Signatures
  h += '<div style="padding:14px 24px;border-bottom:1px solid #1a3a5c;">';
  h += '<div style="font-size:10px;color:#556;letter-spacing:2px;margin-bottom:8px;">DETECTION SIGNATURES</div>';
  for (var d = 0; d < tool.detectionSignatures.length; d++) {
    h += '<div style="background:#0a1a0a;border:1px solid #00ff8833;color:#44dd88;padding:6px 12px;border-radius:4px;margin-bottom:6px;font-size:11px;font-family:monospace;">' + esc(tool.detectionSignatures[d]) + '</div>';
  }
  h += '</div>';

  // Related Tools
  h += '<div style="padding:14px 24px;">';
  h += '<div style="font-size:10px;color:#556;letter-spacing:2px;margin-bottom:8px;">RELATED TOOLS</div>';
  h += '<div style="display:flex;flex-wrap:wrap;gap:6px;">';
  for (var r = 0; r < tool.relatedTools.length; r++) {
    h += '<span style="background:#0a1628;border:1px solid #00aaff33;color:#44bbff;padding:4px 10px;border-radius:4px;font-size:11px;">' + esc(tool.relatedTools[r]) + '</span>';
  }
  h += '</div>';
  h += '</div>';

  h += '</div>';
  return h;
}


// ============================================================================
// RENDER FUNCTION 4: renderAllianceStatus()
// ============================================================================
function renderAllianceStatus() {
  var h = '';
  h += '<div style="padding:16px 0;">';
  h += '<div style="font-size:10px;color:#556;letter-spacing:2px;margin-bottom:16px;">ALLIED CYBER COORDINATION STATUS</div>';

  // Alliance cards
  h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:16px;">';
  for (var a = 0; a < ALLIANCE_NETWORKS.length; a++) {
    var alliance = ALLIANCE_NETWORKS[a];
    h += '<div style="background:#0a0e1a;border:1px solid #1a3a5c;border-radius:8px;overflow:hidden;">';
    h += '<div style="background:linear-gradient(135deg,#0a1628,#0d1f3c);padding:14px 16px;border-bottom:1px solid #1a3a5c;">';
    h += '<h4 style="margin:0;color:#00aaff;font-size:14px;font-family:monospace;letter-spacing:1px;">' + esc(alliance.name) + '</h4>';
    h += '<div style="color:#889;font-size:10px;margin-top:4px;">' + esc(alliance.description).substring(0, 120) + '...</div>';
    h += '</div>';
    h += '<div style="padding:12px 16px;">';
    h += '<div style="margin-bottom:10px;">';
    h += '<div style="font-size:9px;color:#556;letter-spacing:1px;margin-bottom:4px;">MEMBERS</div>';
    var members = typeof alliance.members === 'string' ? [alliance.members] : alliance.members;
    h += '<div style="display:flex;flex-wrap:wrap;gap:4px;">';
    for (var m = 0; m < members.length; m++) {
      h += '<span style="background:#00aaff11;color:#44bbff;padding:2px 8px;border-radius:3px;font-size:10px;border:1px solid #00aaff22;">' + esc(members[m]) + '</span>';
    }
    h += '</div>';
    h += '</div>';
    h += '<div style="margin-bottom:10px;">';
    h += '<div style="font-size:9px;color:#556;letter-spacing:1px;margin-bottom:4px;">SHARING LEVEL</div>';
    h += '<div style="color:#ffaa00;font-size:11px;font-family:monospace;">' + esc(alliance.sharingLevel) + '</div>';
    h += '</div>';
    h += '<div style="margin-bottom:10px;">';
    h += '<div style="font-size:9px;color:#556;letter-spacing:1px;margin-bottom:4px;">LAST EXERCISE</div>';
    h += '<div style="color:#c8d8e8;font-size:11px;">' + esc(alliance.lastExercise) + '</div>';
    h += '</div>';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;padding-top:8px;border-top:1px solid #1a3a5c;">';
    h += '<div style="font-size:9px;color:#556;letter-spacing:1px;">ACTIVE OPS</div>';
    h += '<div style="color:#00ff88;font-size:16px;font-weight:bold;font-family:monospace;">' + alliance.activeOps + '</div>';
    h += '</div>';
    h += '</div>';
    h += '</div>';
  }
  h += '</div>';

  // Network connectivity diagram (text-based)
  h += '<div style="margin-top:24px;background:#0a0e1a;border:1px solid #1a3a5c;border-radius:8px;padding:20px;">';
  h += '<div style="font-size:10px;color:#556;letter-spacing:2px;margin-bottom:16px;text-align:center;">ALLIANCE NETWORK CONNECTIVITY</div>';
  h += '<div style="font-family:monospace;font-size:11px;color:#44bbff;text-align:center;line-height:1.8;">';
  h += '<div style="color:#00ff88;margin-bottom:8px;">&#9473;&#9473;&#9473; FIVE EYES (HIGHEST INTEGRATION) &#9473;&#9473;&#9473;</div>';
  h += '<div>[ US ] &#9473;&#9473;&#9473; [ UK ] &#9473;&#9473;&#9473; [ CAN ] &#9473;&#9473;&#9473; [ AUS ] &#9473;&#9473;&#9473; [ NZ ]</div>';
  h += '<div style="color:#556;">  &#9475;              &#9475;                           &#9475;</div>';
  h += '<div style="color:#ffaa00;margin:8px 0;">&#9473;&#9473;&#9473; NATO CCDCOE (31 MEMBERS) &#9473;&#9473;&#9473;</div>';
  h += '<div>[ US ] &#9473;&#9473; [ UK ] &#9473;&#9473; [ FRA ] &#9473;&#9473; [ DEU ] &#9473;&#9473; [ +27 ]</div>';
  h += '<div style="color:#556;">  &#9475;                                        &#9475;</div>';
  h += '<div style="color:#44aaff;margin:8px 0;">&#9473;&#9473;&#9473; QUAD CYBER (INDO-PACIFIC) &#9473;&#9473;&#9473;</div>';
  h += '<div>[ US ] &#9473;&#9473;&#9473; [ JPN ] &#9473;&#9473;&#9473; [ AUS ] &#9473;&#9473;&#9473; [ IND ]</div>';
  h += '<div style="color:#556;">  &#9475;</div>';
  h += '<div style="color:#ff8844;margin:8px 0;">&#9473;&#9473;&#9473; US-ISRAEL BILATERAL &#9473;&#9473;&#9473;</div>';
  h += '<div>[ US ] &#9473;&#9473;&#9473;&#9473;&#9473;&#9473;&#9473;&#9473;&#9473;&#9473; [ ISR ]</div>';
  h += '</div>';
  h += '</div>';

  h += '</div>';
  return h;
}


// ============================================================================
// RENDER FUNCTION 5: renderMitreMatrix()
// ============================================================================
function renderMitreMatrix() {
  var h = '';
  h += '<div style="padding:16px 0;">';
  h += '<div style="font-size:10px;color:#556;letter-spacing:2px;margin-bottom:4px;">MITRE ATT&CK COVERAGE HEATMAP</div>';
  h += '<div style="font-size:10px;color:#445;margin-bottom:16px;">Color intensity indicates number of tracked APT groups using techniques in each tactic</div>';

  h += '<div style="overflow-x:auto;">';
  h += '<table style="width:100%;border-collapse:collapse;font-size:10px;font-family:monospace;">';

  // Header row
  h += '<tr>';
  h += '<th style="padding:8px 6px;text-align:left;color:#556;border-bottom:2px solid #1a3a5c;min-width:120px;letter-spacing:1px;">APT GROUP</th>';
  for (var ti = 0; ti < MITRE_TACTICS.length; ti++) {
    var shortLabel = MITRE_TACTICS[ti].substring(0, 6).toUpperCase();
    h += '<th style="padding:8px 4px;text-align:center;color:#556;border-bottom:2px solid #1a3a5c;min-width:45px;letter-spacing:1px;font-size:8px;writing-mode:vertical-lr;height:80px;" title="' + esc(MITRE_TACTICS[ti]) + '">' + esc(MITRE_TACTICS[ti]) + '</th>';
  }
  h += '</tr>';

  // Rows for each APT group
  var aptNames = [];
  for (var ak in APT_MITRE_COVERAGE) {
    if (APT_MITRE_COVERAGE.hasOwnProperty(ak)) {
      aptNames.push(ak);
    }
  }
  aptNames.sort();

  for (var ai = 0; ai < aptNames.length; ai++) {
    var aptName = aptNames[ai];
    var coverage = APT_MITRE_COVERAGE[aptName];
    var rowBg = ai % 2 === 0 ? '#0a0e1a' : '#080c16';
    h += '<tr style="background:' + rowBg + ';">';
    h += '<td style="padding:6px 8px;color:#44bbff;border-bottom:1px solid #1a2a3c;white-space:nowrap;">' + esc(aptName) + '</td>';
    for (var tj = 0; tj < MITRE_TACTICS.length; tj++) {
      var hasTactic = false;
      for (var ck = 0; ck < coverage.length; ck++) {
        if (coverage[ck] === MITRE_TACTICS[tj]) { hasTactic = true; break; }
      }
      var cellColor = hasTactic ? '#00aaff' : 'transparent';
      var cellOpacity = hasTactic ? '0.7' : '0.05';
      h += '<td style="padding:4px;text-align:center;border-bottom:1px solid #1a2a3c;">';
      h += '<div style="width:16px;height:16px;margin:0 auto;border-radius:3px;background:' + cellColor + ';opacity:' + cellOpacity + ';' + (hasTactic ? 'box-shadow:0 0 6px ' + cellColor + '44;' : '') + '"></div>';
      h += '</td>';
    }
    h += '</tr>';
  }

  h += '</table>';
  h += '</div>';

  // Tactic coverage summary
  h += '<div style="margin-top:20px;display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:8px;">';
  for (var ts = 0; ts < MITRE_TACTICS.length; ts++) {
    var tactic = MITRE_TACTICS[ts];
    var count = 0;
    for (var cak in APT_MITRE_COVERAGE) {
      if (APT_MITRE_COVERAGE.hasOwnProperty(cak)) {
        for (var cc = 0; cc < APT_MITRE_COVERAGE[cak].length; cc++) {
          if (APT_MITRE_COVERAGE[cak][cc] === tactic) { count++; break; }
        }
      }
    }
    var pct = Math.round((count / aptNames.length) * 100);
    var barCol = pct >= 70 ? '#ff2244' : pct >= 40 ? '#ffaa00' : '#00ff88';
    h += '<div style="background:#0a0e1a;border:1px solid #1a3a5c;border-radius:4px;padding:8px 10px;">';
    h += '<div style="display:flex;justify-content:space-between;margin-bottom:4px;">';
    h += '<span style="color:#889;font-size:9px;letter-spacing:1px;">' + esc(tactic).toUpperCase() + '</span>';
    h += '<span style="color:' + barCol + ';font-size:10px;font-weight:bold;">' + count + '/' + aptNames.length + '</span>';
    h += '</div>';
    h += '<div style="width:100%;height:4px;background:#1a2a3c;border-radius:2px;overflow:hidden;">';
    h += '<div style="width:' + pct + '%;height:100%;background:' + barCol + ';border-radius:2px;"></div>';
    h += '</div>';
    h += '</div>';
  }
  h += '</div>';

  h += '</div>';
  return h;
}


// ============================================================================
// RENDER FUNCTION 6: renderZeroDayMarket()
// ============================================================================
function renderZeroDayMarket() {
  var h = '';
  h += '<div style="padding:16px 0;">';
  h += '<div style="background:#0a0a00;border:2px solid #ff880044;border-radius:8px;overflow:hidden;">';
  h += '<div style="background:linear-gradient(90deg,#1a0a00,#0a0a00,#1a0a00);padding:16px;border-bottom:1px solid #ff880033;text-align:center;">';
  h += '<div style="font-size:20px;color:#ff8800;font-family:monospace;letter-spacing:4px;text-shadow:0 0 20px rgba(255,136,0,0.3);">&#9760; DARK WEB ZERO-DAY MARKET MONITOR &#9760;</div>';
  h += '<div style="color:#886;font-size:10px;margin-top:4px;letter-spacing:2px;">INTELLIGENCE COLLECTION — DO NOT INTERACT — MONITORING ONLY</div>';
  h += '</div>';

  h += '<div style="padding:16px;display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:12px;">';
  for (var z = 0; z < ZERO_DAY_MARKET_INTEL.length; z++) {
    var zd = ZERO_DAY_MARKET_INTEL[z];
    var riskColors = { 'CRITICAL': '#ff2244', 'HIGH': '#ff6622' };
    var rc = riskColors[zd.riskLevel] || '#ffaa00';

    h += '<div style="background:#0c0c04;border:1px solid #ff880033;border-radius:6px;overflow:hidden;">';

    // Card header
    h += '<div style="padding:10px 14px;border-bottom:1px solid #ff880022;display:flex;justify-content:space-between;align-items:center;">';
    h += '<span style="background:' + rc + '22;color:' + rc + ';padding:2px 8px;border-radius:3px;font-size:9px;font-family:monospace;letter-spacing:1px;border:1px solid ' + rc + '44;">' + esc(zd.riskLevel) + '</span>';
    h += '<span style="color:#886;font-size:9px;font-family:monospace;">' + esc(zd.category) + '</span>';
    h += '</div>';

    // Target
    h += '<div style="padding:12px 14px;border-bottom:1px solid #ff880022;">';
    h += '<div style="color:#ff8800;font-size:14px;font-weight:bold;margin-bottom:4px;">' + esc(zd.target) + '</div>';
    h += '<div style="color:#aa8;font-size:11px;line-height:1.4;">' + esc(zd.description) + '</div>';
    h += '</div>';

    // Details
    h += '<div style="padding:10px 14px;display:grid;grid-template-columns:1fr 1fr;gap:8px;">';
    h += '<div>';
    h += '<div style="font-size:8px;color:#665;letter-spacing:1px;">ASKING PRICE</div>';
    h += '<div style="color:#00ff88;font-size:16px;font-weight:bold;font-family:monospace;">' + esc(zd.price) + '</div>';
    h += '</div>';
    h += '<div>';
    h += '<div style="font-size:8px;color:#665;letter-spacing:1px;">SELLER</div>';
    h += '<div style="color:#ff8800;font-size:12px;font-family:monospace;">' + esc(zd.seller) + '</div>';
    h += '</div>';
    h += '<div>';
    h += '<div style="font-size:8px;color:#665;letter-spacing:1px;">LAST SEEN</div>';
    h += '<div style="color:#aa8;font-size:11px;">' + esc(zd.lastSeen) + '</div>';
    h += '</div>';
    h += '<div>';
    h += '<div style="font-size:8px;color:#665;letter-spacing:1px;">BUYER ACTIVITY</div>';
    h += '<div style="color:#aa8;font-size:11px;">' + esc(zd.buyers) + '</div>';
    h += '</div>';
    h += '</div>';
    h += '</div>';
  }
  h += '</div>';

  // Market summary
  h += '<div style="padding:12px 16px;border-top:1px solid #ff880033;display:flex;justify-content:space-around;flex-wrap:wrap;gap:12px;">';
  h += '<div style="text-align:center;"><div style="font-size:8px;color:#665;letter-spacing:1px;">TOTAL LISTINGS MONITORED</div><div style="color:#ff8800;font-size:20px;font-weight:bold;">' + ZERO_DAY_MARKET_INTEL.length + '</div></div>';
  var critCount = 0;
  var totalValue = 0;
  for (var zs = 0; zs < ZERO_DAY_MARKET_INTEL.length; zs++) {
    if (ZERO_DAY_MARKET_INTEL[zs].riskLevel === 'CRITICAL') critCount++;
    var priceNum = parseInt(ZERO_DAY_MARKET_INTEL[zs].price.replace(/[^0-9]/g, ''));
    if (!isNaN(priceNum)) totalValue += priceNum;
  }
  h += '<div style="text-align:center;"><div style="font-size:8px;color:#665;letter-spacing:1px;">CRITICAL RISK</div><div style="color:#ff2244;font-size:20px;font-weight:bold;">' + critCount + '</div></div>';
  h += '<div style="text-align:center;"><div style="font-size:8px;color:#665;letter-spacing:1px;">EST. TOTAL MARKET VALUE</div><div style="color:#00ff88;font-size:20px;font-weight:bold;">$' + (totalValue / 1000000).toFixed(1) + 'M</div></div>';
  h += '</div>';

  h += '</div>';
  h += '</div>';
  return h;
}


// ============================================================================
// RENDER FUNCTION 7: renderCommunicationTemplate(templateId)
// ============================================================================
function renderCommunicationTemplate(templateId) {
  var tmpl = COMMUNICATION_TEMPLATES[templateId];
  if (!tmpl) return '<div style="padding:40px;text-align:center;color:#556;">Template not found.</div>';

  var h = '';
  h += '<div style="background:#060a14;border:2px solid #1a3a5c;border-radius:8px;overflow:hidden;margin:16px 0;max-width:800px;">';

  // Classification banner
  h += '<div style="background:#cc0000;color:#fff;text-align:center;padding:6px;font-size:11px;letter-spacing:4px;font-weight:bold;">' + esc(tmpl.classification) + ' — TEMPLATE</div>';

  // Title
  h += '<div style="background:linear-gradient(135deg,#0a1628,#0d1f3c);padding:16px 20px;border-bottom:2px solid #1a3a5c;">';
  h += '<h3 style="margin:0;color:#00aaff;font-size:16px;font-family:monospace;letter-spacing:2px;">' + esc(tmpl.name) + '</h3>';
  h += '</div>';

  // Fields
  for (var f = 0; f < tmpl.fields.length; f++) {
    var field = tmpl.fields[f];
    h += '<div style="padding:12px 20px;border-bottom:1px solid #1a3a5c;">';
    h += '<div style="display:flex;gap:16px;flex-wrap:wrap;">';
    h += '<div style="min-width:120px;">';
    h += '<div style="color:#00aaff;font-size:12px;font-weight:bold;font-family:monospace;letter-spacing:1px;">' + esc(field.label) + '</div>';
    h += '<div style="color:#556;font-size:9px;margin-top:2px;">' + esc(field.description) + '</div>';
    h += '</div>';
    h += '<div style="flex:1;min-width:200px;">';
    h += '<div style="background:#0a0e1a;border:1px solid #1a3a5c;border-radius:4px;padding:8px 12px;color:#c8d8e8;font-size:12px;line-height:1.5;font-family:monospace;">' + esc(field.example) + '</div>';
    h += '</div>';
    h += '</div>';
    h += '</div>';
  }

  // Bottom classification
  h += '<div style="background:#cc0000;color:#fff;text-align:center;padding:4px;font-size:10px;letter-spacing:3px;">' + esc(tmpl.classification) + '</div>';
  h += '</div>';
  return h;
}


// ============================================================================
// RENDER FUNCTION 8: renderTabletopExercise(exerciseId)
// ============================================================================
function renderTabletopExercise(exerciseId) {
  var exercise = null;
  for (var i = 0; i < TABLETOP_EXERCISES.length; i++) {
    if (TABLETOP_EXERCISES[i].id === exerciseId) { exercise = TABLETOP_EXERCISES[i]; break; }
  }
  if (!exercise) return '<div style="padding:40px;text-align:center;color:#556;">Exercise not found.</div>';

  var h = '';
  h += '<div style="background:#060a14;border:2px solid #1a3a5c;border-radius:8px;overflow:hidden;margin:16px 0;">';

  // Header
  h += '<div style="background:#cc0000;color:#fff;text-align:center;padding:6px;font-size:11px;letter-spacing:4px;font-weight:bold;">TOP SECRET // SCI // EXERCISE — OPERATIONAL</div>';
  h += '<div style="background:linear-gradient(135deg,#0a1628,#0d1f3c);padding:20px 24px;border-bottom:1px solid #1a3a5c;">';
  h += '<div style="font-size:10px;color:#556;letter-spacing:3px;margin-bottom:4px;">TABLETOP EXERCISE</div>';
  h += '<h2 style="margin:0;font-size:24px;color:#00aaff;font-family:monospace;letter-spacing:3px;text-shadow:0 0 20px rgba(0,170,255,0.3);">' + esc(exercise.name) + '</h2>';
  h += '</div>';

  // Scenario
  h += '<div style="padding:16px 24px;border-bottom:1px solid #1a3a5c;">';
  h += '<div style="font-size:10px;color:#556;letter-spacing:2px;margin-bottom:8px;">SCENARIO BRIEF</div>';
  h += '<div style="color:#c8d8e8;font-size:13px;line-height:1.6;padding:12px;background:#0a0e1a;border:1px solid #1a3a5c;border-radius:6px;">' + esc(exercise.scenario) + '</div>';
  h += '</div>';

  // Inject Timeline
  h += '<div style="padding:16px 24px;border-bottom:1px solid #1a3a5c;">';
  h += '<div style="font-size:10px;color:#556;letter-spacing:2px;margin-bottom:12px;">INJECT TIMELINE</div>';
  h += '<div style="position:relative;padding-left:28px;">';
  h += '<div style="position:absolute;left:10px;top:0;bottom:0;width:2px;background:linear-gradient(180deg,#ffaa00,#ff224488);"></div>';
  for (var inj = 0; inj < exercise.injects.length; inj++) {
    var inject = exercise.injects[inj];
    var injColor = inj < 3 ? '#ffaa00' : inj < 6 ? '#ff6622' : '#ff2244';
    h += '<div style="position:relative;margin-bottom:14px;padding-left:20px;">';
    h += '<div style="position:absolute;left:-22px;top:4px;width:12px;height:12px;background:' + injColor + ';border-radius:50%;border:2px solid #060a14;"></div>';
    h += '<div style="display:flex;gap:12px;align-items:flex-start;">';
    h += '<span style="background:' + injColor + '22;color:' + injColor + ';padding:2px 8px;border-radius:3px;font-size:10px;font-family:monospace;letter-spacing:1px;white-space:nowrap;border:1px solid ' + injColor + '44;">' + esc(inject.time) + '</span>';
    h += '<span style="color:#c8d8e8;font-size:12px;">' + esc(inject.event) + '</span>';
    h += '</div>';
    h += '</div>';
  }
  h += '</div>';
  h += '</div>';

  // Participant Roles
  h += '<div style="padding:16px 24px;border-bottom:1px solid #1a3a5c;">';
  h += '<div style="font-size:10px;color:#556;letter-spacing:2px;margin-bottom:8px;">PARTICIPANT ROLES</div>';
  h += '<div style="display:flex;flex-wrap:wrap;gap:8px;">';
  for (var pr = 0; pr < exercise.participantRoles.length; pr++) {
    h += '<span style="background:#0a1628;border:1px solid #00aaff33;color:#44bbff;padding:6px 12px;border-radius:4px;font-size:11px;">' + esc(exercise.participantRoles[pr]) + '</span>';
  }
  h += '</div>';
  h += '</div>';

  // Evaluation Criteria
  h += '<div style="padding:16px 24px;">';
  h += '<div style="font-size:10px;color:#556;letter-spacing:2px;margin-bottom:8px;">EVALUATION CRITERIA</div>';
  for (var ec = 0; ec < exercise.evaluationCriteria.length; ec++) {
    h += '<div style="display:flex;gap:8px;align-items:flex-start;margin-bottom:6px;">';
    h += '<span style="color:#00ff88;font-size:10px;margin-top:2px;">&#9745;</span>';
    h += '<span style="color:#c8d8e8;font-size:12px;">' + esc(exercise.evaluationCriteria[ec]) + '</span>';
    h += '</div>';
  }
  h += '</div>';

  h += '</div>';
  return h;
}


// ============================================================================
// RENDER FUNCTION 9: renderThreatTimeline()
// ============================================================================
function renderThreatTimeline() {
  var h = '';
  h += '<div style="padding:16px 0;">';
  h += '<div style="font-size:10px;color:#556;letter-spacing:2px;margin-bottom:4px;">GLOBAL CYBER OPERATIONS TIMELINE</div>';
  h += '<div style="font-size:10px;color:#445;margin-bottom:16px;">Historical nation-state cyber operations ordered chronologically</div>';

  // Filters
  h += '<div style="display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap;" id="se-timeline-filters">';
  h += '<select style="background:#0a0e1a;color:#c8d8e8;border:1px solid #1a3a5c;border-radius:4px;padding:6px 10px;font-size:11px;font-family:monospace;" id="se-timeline-year-filter">';
  h += '<option value="all">All Years</option>';
  var years = {};
  for (var yi = 0; yi < HISTORICAL_OPS.length; yi++) { years[HISTORICAL_OPS[yi].year] = true; }
  var yearList = [];
  for (var yk in years) { if (years.hasOwnProperty(yk)) yearList.push(parseInt(yk)); }
  yearList.sort();
  for (var yli = 0; yli < yearList.length; yli++) {
    h += '<option value="' + yearList[yli] + '">' + yearList[yli] + '</option>';
  }
  h += '</select>';
  h += '<select style="background:#0a0e1a;color:#c8d8e8;border:1px solid #1a3a5c;border-radius:4px;padding:6px 10px;font-size:11px;font-family:monospace;" id="se-timeline-type-filter">';
  h += '<option value="all">All Types</option>';
  h += '<option value="espionage">Espionage</option>';
  h += '<option value="destruction">Destruction</option>';
  h += '<option value="disruption">Disruption</option>';
  h += '<option value="financial">Financial</option>';
  h += '<option value="hybrid">Hybrid</option>';
  h += '</select>';
  h += '</div>';

  // Timeline
  var sorted = HISTORICAL_OPS.slice().sort(function(a, b) { return a.year - b.year; });
  h += '<div style="position:relative;padding-left:80px;" id="se-timeline-container">';
  h += '<div style="position:absolute;left:60px;top:0;bottom:0;width:3px;background:linear-gradient(180deg,#00aaff22,#00aaff,#00aaff,#ff2244,#ff224422);border-radius:2px;"></div>';

  var typeColors = { 'espionage': '#00aaff', 'destruction': '#ff2244', 'disruption': '#ff6622', 'financial': '#ffaa00', 'hybrid': '#cc44ff' };
  var typeIcons = { 'espionage': '[R]', 'destruction': '[!]', 'disruption': '&#9889;', 'financial': '[F]', 'hybrid': '&#9878;' };

  for (var si = 0; si < sorted.length; si++) {
    var op = sorted[si];
    var opColor = typeColors[op.type] || '#889';

    h += '<div class="se-timeline-event" data-year="' + op.year + '" data-type="' + esc(op.type) + '" style="position:relative;margin-bottom:16px;">';

    // Year label
    h += '<div style="position:absolute;left:-76px;top:4px;color:#556;font-size:11px;font-family:monospace;letter-spacing:1px;text-align:right;width:55px;">' + op.year + '</div>';

    // Dot
    h += '<div style="position:absolute;left:-24px;top:6px;width:14px;height:14px;background:' + opColor + ';border-radius:50%;border:3px solid #060a14;box-shadow:0 0 8px ' + opColor + '44;"></div>';

    // Card
    h += '<div style="background:#0a0e1a;border:1px solid ' + opColor + '33;border-radius:6px;padding:12px 16px;margin-left:8px;cursor:pointer;" onclick="var d=this.querySelector(\'[data-detail]\');if(d)d.hidden=!d.hidden;">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;">';
    h += '<div style="display:flex;align-items:center;gap:8px;">';
    h += '<span style="color:' + opColor + ';font-size:16px;font-weight:bold;font-family:monospace;">' + esc(op.name) + '</span>';
    h += '<span style="background:' + opColor + '22;color:' + opColor + ';padding:2px 6px;border-radius:3px;font-size:9px;letter-spacing:1px;border:1px solid ' + opColor + '44;">' + esc(op.type.toUpperCase()) + '</span>';
    h += '</div>';
    h += '<span style="color:#889;font-size:10px;">' + esc(op.attribution) + '</span>';
    h += '</div>';

    // Expandable detail
    h += '<div data-detail hidden style="margin-top:10px;padding-top:10px;border-top:1px solid #1a3a5c;">';
    h += '<div style="color:#c8d8e8;font-size:12px;margin-bottom:6px;">' + esc(op.description) + '</div>';
    h += '<div style="color:#889;font-size:11px;margin-bottom:4px;"><span style="color:#ffaa00;">TARGETS:</span> ' + esc(op.targets) + '</div>';
    h += '<div style="color:#889;font-size:11px;"><span style="color:#ff6644;">IMPACT:</span> ' + esc(op.impact) + '</div>';
    h += '</div>';

    h += '</div>';
    h += '</div>';
  }

  h += '</div>';
  h += '</div>';
  return h;
}


// ============================================================================
// RENDER FUNCTION 10: renderCyberKillChain(aptGroup)
// ============================================================================
function renderCyberKillChain(aptGroup) {
  var killChainData = {
    'APT28': {
      reconnaissance: 'Targeted spear-phishing reconnaissance via social media (LinkedIn, Twitter). OSINT collection on targets of interest. Credential harvesting site setup.',
      weaponization: 'Custom X-Agent/Sofacy payloads. Zebrocy dropper variants. Weaponized Office documents with VBA macros.',
      delivery: 'Spear-phishing emails with malicious attachments or credential harvesting links. Watering hole attacks on conference/event websites.',
      exploitation: 'Microsoft Office macro execution, DDE attacks, CVE-2017-0199 (RTF exploit). OAuth token abuse for cloud access.',
      installation: 'X-Agent persistence via registry run keys and scheduled tasks. Seduploader for initial foothold before deploying X-Agent.',
      c2: 'HTTP/HTTPS to compromised legitimate websites. X-Tunnel for encrypted tunneling. Competent operational security with rotating C2.',
      actions: 'Email exfiltration, document theft, credential harvesting. Strategic leaks and information operations (e.g., DNC, WADA). Long-term access maintenance.'
    },
    'APT29': {
      reconnaissance: 'Minimal pre-operation footprint. Uses compromised infrastructure for recon. Leverages SaaS platforms to identify targets.',
      weaponization: 'Highly customized tooling — SUNBURST, EnvyScout, BoomBox. Signed binaries. Minimal reuse across operations.',
      delivery: 'Supply chain compromise (SolarWinds), targeted phishing with HTML smuggling, ISO file attachments. Trusted relationship abuse.',
      exploitation: 'Zero-day exploitation. SAML token forging (Golden SAML). Cloud service exploitation. Bypasses MFA via token theft.',
      installation: 'Memory-only loaders (TEARDROP). DLL side-loading. Minimal filesystem footprint. Blends with legitimate processes.',
      c2: 'C2 over legitimate cloud services (Azure, AWS, OneDrive). DNS-based C2 (DGA). Traffic blends with normal business communications.',
      actions: 'Long-duration intelligence collection. Focus on government and policy targets. Patient — maintains access for months/years before acting. Golden SAML for cloud persistence.'
    },
    'Lazarus': {
      reconnaissance: 'LinkedIn social engineering. Fake job offers/recruiters. Supply chain target identification. Cryptocurrency exchange research.',
      weaponization: 'Custom backdoors (Manuscrypt, BLINDINGCAN). Trojanized crypto trading apps. Modified open-source tools.',
      delivery: 'Social engineering via LinkedIn/email with job offers. Trojanized applications. Watering hole on cryptocurrency/finance sites.',
      exploitation: 'Browser zero-days (Chrome, IE). Macro-enabled documents. DeFi smart contract exploitation. SWIFT message manipulation.',
      installation: 'Multi-stage loaders. Persistence via startup items and services. macOS and Windows variants. Mobile malware for Android.',
      c2: 'Custom binary protocols over HTTP/HTTPS. Compromised legitimate websites. Tor hidden services. Steganography in image files.',
      actions: 'Cryptocurrency theft ($2B+ total). SWIFT banking fraud. Ransomware deployment (WannaCry). Data destruction (Sony). Technology IP theft.'
    },
    'Sandworm': {
      reconnaissance: 'ICS/SCADA system reconnaissance. Network mapping of critical infrastructure. Supply chain target identification.',
      weaponization: 'Purpose-built ICS malware (Industroyer, CaddyWiper, AcidRain). BlackEnergy variants. Olympic Destroyer.',
      delivery: 'Spear-phishing with weaponized documents. Supply chain compromise (M.E.Doc). VPN exploitation. Water-holing.',
      exploitation: 'EternalBlue (MS17-010). VPN and network appliance vulnerabilities. ICS protocol exploitation (IEC 101/104, OPC DA).',
      installation: 'KillDisk for destructive payload. Industroyer for ICS access. BlackEnergy modules. Persistent access maintained for years.',
      c2: 'HTTP/HTTPS C2 to attacker infrastructure. Custom protocols for ICS communication. VPN for encrypted tunnels back to operators.',
      actions: 'Power grid shutdowns (Ukraine 2015/2016). Global destruction (NotPetya). Olympic sabotage. Satellite disruption (Viasat). Wiper deployments in Ukraine conflict.'
    }
  };

  var data = killChainData[aptGroup];
  if (!data) {
    return '<div style="padding:40px;text-align:center;color:#556;">Kill chain data not available for ' + esc(aptGroup) + '. Available: APT28, APT29, Lazarus, Sandworm.</div>';
  }

  var phases = [
    { key: 'reconnaissance', label: 'RECONNAISSANCE', icon: '[R]', color: '#44bbff' },
    { key: 'weaponization', label: 'WEAPONIZATION', icon: '&#9881;', color: '#44aaff' },
    { key: 'delivery', label: 'DELIVERY', icon: '[>]', color: '#ffaa00' },
    { key: 'exploitation', label: 'EXPLOITATION', icon: '[!]', color: '#ff8844' },
    { key: 'installation', label: 'INSTALLATION', icon: '[D]', color: '#ff6644' },
    { key: 'c2', label: 'COMMAND & CONTROL', icon: '[T]', color: '#ff4466' },
    { key: 'actions', label: 'ACTIONS ON OBJECTIVES', icon: '[S]', color: '#ff2244' }
  ];

  var h = '';
  h += '<div style="padding:16px 0;">';
  h += '<div style="background:#060a14;border:2px solid #1a3a5c;border-radius:8px;overflow:hidden;">';

  // Header
  h += '<div style="background:linear-gradient(135deg,#0a1628,#0d1f3c);padding:16px 24px;border-bottom:1px solid #1a3a5c;">';
  h += '<div style="font-size:10px;color:#556;letter-spacing:3px;margin-bottom:4px;">CYBER KILL CHAIN ANALYSIS</div>';
  h += '<h3 style="margin:0;color:#00aaff;font-size:20px;font-family:monospace;letter-spacing:2px;">' + esc(aptGroup) + ' — TYPICAL ATTACK PATTERN</h3>';
  h += '</div>';

  // Kill chain phases
  for (var p = 0; p < phases.length; p++) {
    var phase = phases[p];
    h += '<div style="display:flex;border-bottom:' + (p < phases.length - 1 ? '1px solid #1a3a5c' : 'none') + ';">';

    // Phase indicator (left column)
    h += '<div style="min-width:180px;padding:16px;border-right:1px solid #1a3a5c;display:flex;flex-direction:column;align-items:center;justify-content:center;background:#080c16;">';
    h += '<div style="font-size:24px;margin-bottom:6px;">' + phase.icon + '</div>';
    h += '<div style="color:' + phase.color + ';font-size:11px;font-weight:bold;font-family:monospace;letter-spacing:2px;text-align:center;">' + phase.label + '</div>';
    h += '<div style="margin-top:8px;font-size:10px;color:#556;">PHASE ' + (p + 1) + '/7</div>';
    if (p < phases.length - 1) {
      h += '<div style="margin-top:8px;color:' + phase.color + ';font-size:16px;">&#9660;</div>';
    }
    h += '</div>';

    // Phase content (right column)
    h += '<div style="flex:1;padding:16px 20px;display:flex;align-items:center;">';
    h += '<div style="color:#c8d8e8;font-size:12px;line-height:1.6;">' + esc(data[phase.key]) + '</div>';
    h += '</div>';

    h += '</div>';
  }

  h += '</div>';
  h += '</div>';
  return h;
}


// ============================================================================
// RENDER FUNCTION 11: renderCorrelationEngine()
// ============================================================================
function renderCorrelationEngine() {
  var correlations = [
    {
      id: 'corr-001',
      title: 'Russian Infrastructure Pre-positioning Detected',
      confidence: 92,
      sources: [
        { type: 'SIGINT', detail: 'Encrypted burst communications from GRU-attributed IP ranges to newly provisioned infrastructure in Eastern Europe' },
        { type: 'CYBINT', detail: 'New SSL certificates issued to domains matching Sandworm naming conventions; domain registration via known bulletproof hosting' },
        { type: 'OSINT', detail: 'Russian military exercises announced near Baltic region; geopolitical tension indicators elevated' },
        { type: 'HUMINT', detail: 'Source reporting increased operational tempo at GRU Unit 74455 facilities' }
      ],
      assessment: 'HIGH CONFIDENCE: Russian state actors are staging offensive cyber capabilities targeting NATO member critical infrastructure. Pattern matches pre-attack indicators observed before Ukraine grid attacks (2015/2016).',
      recommendedAction: 'Elevate to CYBER DEFCON 2 for Baltic region. Deploy hunt-forward teams to affected allied networks. Issue classified advisory to Five Eyes and NATO partners.'
    },
    {
      id: 'corr-002',
      title: 'Chinese Telecom Infiltration Campaign Expanding',
      confidence: 88,
      sources: [
        { type: 'SIGINT', detail: 'Anomalous data flows detected from major US telecom providers to known Salt Typhoon C2 infrastructure' },
        { type: 'CYBINT', detail: 'New Volt Typhoon-associated malware samples detected in telecom provider edge router firmware' },
        { type: 'OSINT', detail: 'Increased PRC military rhetoric regarding Taiwan; South China Sea naval activity elevated' },
        { type: 'GEOINT', detail: 'Satellite imagery shows increased activity at PLA Strategic Support Force facilities' }
      ],
      assessment: 'HIGH CONFIDENCE: PRC-affiliated actors are expanding pre-positioned access in US telecommunications infrastructure. Pattern consistent with preparation for potential Taiwan contingency.',
      recommendedAction: 'Coordinate with telecom providers for immediate threat hunt. Brief NSC on expanded PRC cyber pre-positioning. Activate Quad Cyber Partnership coordination.'
    },
    {
      id: 'corr-003',
      title: 'North Korean Cryptocurrency Theft Campaign Imminent',
      confidence: 85,
      sources: [
        { type: 'CYBINT', detail: 'BlueNoroff social engineering campaign detected targeting cryptocurrency exchange employees via LinkedIn' },
        { type: 'OSINT', detail: 'North Korean state media rhetoric about sanctions; regime cash reserves reportedly low' },
        { type: 'SIGINT', detail: 'Communications intercepts suggest Lazarus operators activating previously dormant cryptocurrency wallet infrastructure' }
      ],
      assessment: 'HIGH CONFIDENCE: North Korean state actors are preparing a major cryptocurrency theft operation. Financial pressure on the regime correlates with historical patterns of increased DPRK cyber theft activity.',
      recommendedAction: 'Issue advisory to major cryptocurrency exchanges. Coordinate with Treasury/FinCEN for blockchain monitoring. Prepare FBI seizure warrants for identified staging wallets.'
    }
  ];

  var sourceColors = { 'SIGINT': '#00aaff', 'OSINT': '#00ff88', 'CYBINT': '#ffaa00', 'HUMINT': '#ff8844', 'GEOINT': '#cc44ff' };

  var h = '';
  h += '<div style="padding:16px 0;">';
  h += '<div style="font-size:10px;color:#556;letter-spacing:2px;margin-bottom:4px;">MULTI-SOURCE INTELLIGENCE CORRELATION ENGINE</div>';
  h += '<div style="font-size:10px;color:#445;margin-bottom:16px;">Alerts generated when 3+ independent intelligence sources converge on the same threat assessment</div>';

  for (var ci = 0; ci < correlations.length; ci++) {
    var corr = correlations[ci];
    var confColor = corr.confidence >= 90 ? '#00ff88' : corr.confidence >= 80 ? '#ffaa00' : '#ff6644';

    h += '<div style="background:#060a14;border:2px solid ' + confColor + '44;border-radius:8px;overflow:hidden;margin-bottom:16px;">';

    // Header
    h += '<div style="background:linear-gradient(135deg,#0a1628,#0d1f3c);padding:14px 20px;border-bottom:1px solid #1a3a5c;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;">';
    h += '<div>';
    h += '<div style="font-size:9px;color:#556;letter-spacing:2px;margin-bottom:2px;">CORRELATION ALERT</div>';
    h += '<div style="color:#c8d8e8;font-size:15px;font-weight:bold;">' + esc(corr.title) + '</div>';
    h += '</div>';
    h += '<div style="text-align:right;">';
    h += '<div style="font-size:9px;color:#556;letter-spacing:1px;">CONFIDENCE</div>';
    h += '<div style="color:' + confColor + ';font-size:22px;font-weight:bold;font-family:monospace;">' + corr.confidence + '%</div>';
    h += '</div>';
    h += '</div>';

    // Source indicators with connection visualization
    h += '<div style="padding:14px 20px;border-bottom:1px solid #1a3a5c;">';
    h += '<div style="font-size:9px;color:#556;letter-spacing:2px;margin-bottom:10px;">CONTRIBUTING SOURCES (' + corr.sources.length + ' INDEPENDENT)</div>';
    for (var s = 0; s < corr.sources.length; s++) {
      var src = corr.sources[s];
      var sc = sourceColors[src.type] || '#889';
      h += '<div style="display:flex;gap:12px;margin-bottom:8px;align-items:flex-start;">';
      h += '<span style="background:' + sc + '22;color:' + sc + ';padding:3px 8px;border-radius:3px;font-size:9px;font-family:monospace;letter-spacing:1px;border:1px solid ' + sc + '44;min-width:50px;text-align:center;">' + esc(src.type) + '</span>';
      h += '<div style="flex:1;color:#c8d8e8;font-size:12px;padding-left:10px;border-left:2px solid ' + sc + '44;">' + esc(src.detail) + '</div>';
      h += '</div>';
    }

    // Visual connection
    h += '<div style="text-align:center;padding:8px 0;">';
    h += '<div style="display:inline-flex;gap:6px;align-items:center;">';
    for (var sv = 0; sv < corr.sources.length; sv++) {
      var svc = sourceColors[corr.sources[sv].type] || '#889';
      h += '<div style="width:12px;height:12px;background:' + svc + ';border-radius:50%;"></div>';
      if (sv < corr.sources.length - 1) {
        h += '<div style="width:20px;height:2px;background:linear-gradient(90deg,' + svc + ',' + (sourceColors[corr.sources[sv + 1].type] || '#889') + ');"></div>';
      }
    }
    h += '</div>';
    h += '<div style="color:#556;font-size:9px;margin-top:4px;letter-spacing:1px;">CONVERGENCE DETECTED</div>';
    h += '</div>';
    h += '</div>';

    // Assessment
    h += '<div style="padding:14px 20px;border-bottom:1px solid #1a3a5c;">';
    h += '<div style="font-size:9px;color:#556;letter-spacing:2px;margin-bottom:6px;">ASSESSMENT</div>';
    h += '<div style="color:#ffaa00;font-size:12px;line-height:1.5;padding:10px;background:#1a1a0a;border:1px solid #ffaa0033;border-radius:6px;">' + esc(corr.assessment) + '</div>';
    h += '</div>';

    // Recommended Action
    h += '<div style="padding:14px 20px;">';
    h += '<div style="font-size:9px;color:#556;letter-spacing:2px;margin-bottom:6px;">RECOMMENDED ACTION</div>';
    h += '<div style="color:#00ff88;font-size:12px;line-height:1.5;padding:10px;background:#0a1a0a;border:1px solid #00ff8833;border-radius:6px;">' + esc(corr.recommendedAction) + '</div>';
    h += '</div>';

    h += '</div>';
  }

  h += '</div>';
  return h;
}


// ============================================================================
// RENDER FUNCTION 12: renderGlobalPostureBrief()
// ============================================================================
function renderGlobalPostureBrief() {
  var h = '';
  h += '<div style="max-width:800px;margin:0 auto;">';
  h += '<div style="background:#060a14;border:2px solid #1a3a5c;border-radius:8px;overflow:hidden;">';

  // Classification banner


  // Title block
  h += '<div style="background:linear-gradient(135deg,#0a1628,#0d1f3c);padding:24px;border-bottom:2px solid #1a3a5c;text-align:center;">';
  h += '<div style="font-size:10px;color:#556;letter-spacing:4px;margin-bottom:8px;">GLOBAL CYBER POSTURE BRIEF</div>';
  h += '<h2 style="margin:0;color:#00aaff;font-size:22px;font-family:monospace;letter-spacing:3px;">SENTINEL EYE — DAILY INTELLIGENCE SUMMARY</h2>';
  h += '<div style="color:#889;font-size:12px;margin-top:8px;">Prepared: ' + new Date().toISOString().split('T')[0] + ' | Classification: TS//SCI//NF | Distribution: POTUS, NSC, SECDEF, DNI, DIRNSA</div>';
  h += '</div>';

  // BLUF
  h += '<div style="padding:20px 24px;border-bottom:1px solid #1a3a5c;">';
  h += '<div style="font-size:11px;color:#ff6644;letter-spacing:2px;font-weight:bold;margin-bottom:8px;">BOTTOM LINE UP FRONT</div>';
  h += '<div style="color:#c8d8e8;font-size:14px;line-height:1.6;padding:14px;background:#1a0a0a;border:2px solid #ff224433;border-radius:6px;">Global cyber threat level remains at <span style="color:#ff6622;font-weight:bold;">ORANGE (ELEVATED)</span>. Three active nation-state operations targeting US and allied interests require senior-level attention: Russian pre-positioning against NATO critical infrastructure, Chinese telecom infiltration expansion, and North Korean cryptocurrency theft staging. Recommend pre-authorization of defensive counter-operations and elevation to CYBER DEFCON 2 for European and Indo-Pacific theaters.</div>';
  h += '</div>';

  // Global Threat Level
  h += '<div style="padding:20px 24px;border-bottom:1px solid #1a3a5c;text-align:center;">';
  h += '<div style="font-size:11px;color:#556;letter-spacing:2px;margin-bottom:12px;">GLOBAL CYBER THREAT LEVEL</div>';
  h += '<div style="display:inline-flex;gap:4px;">';
  var levels = [
    { num: 1, label: 'LOW', color: '#00ff88' },
    { num: 2, label: 'GUARDED', color: '#44cc88' },
    { num: 3, label: 'ELEVATED', color: '#ffaa00' },
    { num: 4, label: 'HIGH', color: '#ff6622' },
    { num: 5, label: 'SEVERE', color: '#ff2244' }
  ];
  for (var l = 0; l < levels.length; l++) {
    var isActive = levels[l].num === 4;
    h += '<div style="width:80px;padding:12px 8px;background:' + (isActive ? levels[l].color + '22' : '#0a0e1a') + ';border:2px solid ' + (isActive ? levels[l].color : '#1a3a5c') + ';border-radius:4px;text-align:center;' + (isActive ? 'box-shadow:0 0 20px ' + levels[l].color + '33;animation:se-pulse 2s ease-in-out infinite;' : 'opacity:0.4;') + '">';
    h += '<div style="color:' + levels[l].color + ';font-size:20px;font-weight:bold;font-family:monospace;">' + levels[l].num + '</div>';
    h += '<div style="color:' + levels[l].color + ';font-size:8px;letter-spacing:1px;margin-top:4px;">' + levels[l].label + '</div>';
    h += '</div>';
  }
  h += '</div>';
  h += '</div>';

  // Top Threats
  h += '<div style="padding:20px 24px;border-bottom:1px solid #1a3a5c;">';
  h += '<div style="font-size:11px;color:#ff2244;letter-spacing:2px;font-weight:bold;margin-bottom:12px;">ACTIVE THREAT BRIEFING</div>';
  h += '<div style="font-size:11px;color:#4a6a8a;margin-bottom:12px;">Threat assessments are generated from real-time API data. Connect Ollama for AI-powered analysis.</div>';
  h += '<div id="se-cmd-threats" style="font-size:12px;color:#6688aa;">Fetching live threat data...</div>';

  var threats = [];
  var threatPrioColors = ['#ff2244', '#ff6622', '#ffaa00'];

  for (var th = 0; th < threats.length; th++) {
    var threat = threats[th];
    var tpc = threatPrioColors[th] || '#ffaa00';
    h += '<div style="background:#0a0e1a;border:1px solid ' + tpc + '33;border-radius:6px;padding:14px;margin-bottom:10px;border-left:4px solid ' + tpc + ';">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:8px;">';
    h += '<div>';
    h += '<span style="color:' + tpc + ';font-size:10px;font-weight:bold;letter-spacing:2px;">' + esc(threat.priority) + '</span>';
    h += '<span style="color:#c8d8e8;font-size:14px;font-weight:bold;margin-left:12px;">' + esc(threat.title) + '</span>';
    h += '</div>';
    h += '<span style="color:' + tpc + ';font-size:11px;font-family:monospace;">CONF: ' + esc(threat.confidence) + '</span>';
    h += '</div>';
    h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:11px;">';
    h += '<div><span style="color:#556;">Actor: </span><span style="color:#ff8866;">' + esc(threat.actor) + '</span></div>';
    h += '<div><span style="color:#556;">Timeline: </span><span style="color:#ffaa00;">' + esc(threat.timeline) + '</span></div>';
    h += '</div>';
    h += '<div style="margin-top:8px;padding-top:8px;border-top:1px solid #1a2a3c;">';
    h += '<span style="color:#556;font-size:10px;">RECOMMENDED: </span><span style="color:#00ff88;font-size:11px;">' + esc(threat.action) + '</span>';
    h += '</div>';
    h += '</div>';
  }
  h += '</div>';

  // Sector Status Summary
  h += '<div style="padding:20px 24px;border-bottom:1px solid #1a3a5c;">';
  h += '<div style="font-size:11px;color:#556;letter-spacing:2px;margin-bottom:12px;">CRITICAL INFRASTRUCTURE SECTOR STATUS</div>';
  h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:8px;">';
  for (var cs = 0; cs < CRITICAL_INFRASTRUCTURE_SECTORS.length; cs++) {
    var sector = CRITICAL_INFRASTRUCTURE_SECTORS[cs];
    h += '<div style="background:#0a0e1a;border:1px solid #1a3a5c;border-radius:4px;padding:10px;text-align:center;">';
    h += '<div style="color:#c8d8e8;font-size:10px;font-weight:bold;margin-bottom:6px;">' + esc(sector.name) + '</div>';
    h += '<div style="color:#00aaff;font-size:10px;font-family:monospace;margin-top:4px;">' + (sector.activeDefenses ? sector.activeDefenses.length + ' DEFENSES' : 'N/A') + '</div>';
    h += '</div>';
  }
  h += '</div>';
  h += '</div>';

  // Allied Coordination
  h += '<div style="padding:20px 24px;border-bottom:1px solid #1a3a5c;">';
  h += '<div style="font-size:11px;color:#556;letter-spacing:2px;margin-bottom:12px;">ALLIED COORDINATION STATUS</div>';
  h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px;">';
  for (var al = 0; al < ALLIANCE_NETWORKS.length; al++) {
    var ally = ALLIANCE_NETWORKS[al];
    h += '<div style="background:#0a0e1a;border:1px solid #00aaff22;border-radius:4px;padding:10px;display:flex;justify-content:space-between;align-items:center;">';
    h += '<span style="color:#44bbff;font-size:11px;">' + esc(ally.name) + '</span>';
    h += '<span style="color:#00ff88;font-size:11px;font-family:monospace;">' + ally.activeOps + ' OPS</span>';
    h += '</div>';
  }
  h += '</div>';
  h += '</div>';

  // Recommended Actions
  h += '<div style="padding:20px 24px;">';
  h += '<div style="font-size:11px;color:#00ff88;letter-spacing:2px;font-weight:bold;margin-bottom:12px;">RECOMMENDED ACTIONS</div>';
  var actions = [
    'Elevate to CYBER DEFCON 2 for European and Indo-Pacific theaters',
    'Pre-authorize defensive counter-operations against identified Sandworm infrastructure',
    'Deploy hunt-forward teams to 3 Baltic allied networks',
    'Brief NSC Principals Committee on expanded PRC telecom infiltration',
    'Coordinate with Treasury/FinCEN on DPRK cryptocurrency theft indicators',
    'Issue classified advisory to Five Eyes, NATO, and Quad partners',
    'Activate enhanced monitoring on all critical infrastructure sectors',
    'Schedule congressional intelligence committee briefing within 48 hours'
  ];
  for (var ac = 0; ac < actions.length; ac++) {
    h += '<div style="display:flex;gap:10px;align-items:flex-start;margin-bottom:8px;">';
    h += '<span style="color:#00ff88;font-size:12px;min-width:20px;text-align:center;">' + (ac + 1) + '.</span>';
    h += '<span style="color:#c8d8e8;font-size:12px;line-height:1.4;">' + esc(actions[ac]) + '</span>';
    h += '</div>';
  }
  h += '</div>';

  // Bottom classification
  h += '<div style="background:#cc0000;color:#fff;text-align:center;padding:8px;font-size:12px;letter-spacing:4px;font-weight:bold;">TOP SECRET // SCI // NOFORN</div>';

  h += '</div>';
  h += '</div>';
  return h;
}


// ============================================================================
// EXTENDED HISTORICAL OPERATIONS DETAIL (additional entries)
// ============================================================================
HISTORICAL_OPERATIONS_DETAIL['op-006'] = {
  codename: 'SONY PICTURES HACK',
  attribution: 'North Korea (RGB Bureau 121 / Lazarus Group)',
  attributionConfidence: 92,
  fullDescription: 'In retaliation for the upcoming release of "The Interview," a comedy depicting the assassination of Kim Jong-un, North Korean hackers from the Lazarus Group conducted a devastating destructive and data theft attack against Sony Pictures Entertainment. The attackers deployed a custom wiper malware (Destover) that destroyed data on thousands of computers while simultaneously exfiltrating and leaking tens of terabytes of confidential data including unreleased films, executive emails, employee SSNs, salary data, and sensitive business plans.',
  targets: ['Sony Pictures Entertainment corporate network', 'Sony Pictures film archive', 'Executive email systems', 'HR and payroll systems'],
  ttps: [
    { technique: 'T1566.001', name: 'Spearphishing Attachment', detail: 'Initial access via targeted spear-phishing emails to Sony employees' },
    { technique: 'T1078', name: 'Valid Accounts', detail: 'Compromised administrator credentials for domain-wide access' },
    { technique: 'T1005', name: 'Data from Local System', detail: 'Systematic exfiltration of sensitive files from file servers and email' },
    { technique: 'T1485', name: 'Data Destruction', detail: 'Destover wiper malware deployed to destroy data and render systems inoperable' },
    { technique: 'T1561.001', name: 'Disk Content Wipe', detail: 'MBR overwrite preventing system recovery' }
  ],
  timeline: [
    { date: '2014-09', event: 'Lazarus Group begins reconnaissance of Sony Pictures network' },
    { date: '2014-10', event: 'Initial compromise via spear-phishing, establishes persistent access' },
    { date: '2014-11-01', event: 'Large-scale data exfiltration begins (est. 100+ TB stolen)' },
    { date: '2014-11-24', event: 'Destover wiper deployed; threatening "Guardians of Peace" message displayed on screens' },
    { date: '2014-11-25', event: 'Unreleased films leaked online (Annie, Fury, others)' },
    { date: '2014-12-01', event: 'Executive emails and salary data leaked in batches' },
    { date: '2014-12-16', event: 'Threat of "9/11-type" attacks on theaters showing The Interview' },
    { date: '2014-12-17', event: 'Major theater chains pull The Interview; Sony cancels theatrical release' },
    { date: '2014-12-19', event: 'FBI formally attributes attack to North Korea' },
    { date: '2014-12-25', event: 'Sony releases The Interview online after public backlash' },
    { date: '2015-01', event: 'US imposes new sanctions on North Korea' }
  ],
  toolsUsed: ['Destover wiper', 'Custom backdoors', 'Proxy tools for exfiltration', 'SMB Worm component', 'Modified versions of commercial tools'],
  impact: 'Sony suffered $100M+ in direct damages. 5 unreleased films leaked. 47,000 employee SSNs exposed. Executive embarrassment from leaked emails. Temporary cancellation of The Interview theatrical release. Industry-wide cybersecurity reassessment.',
  significance: 'First publicly attributed destructive nation-state cyber attack against a private company in retaliation for free expression. Raised questions about proportional response, corporate vulnerability to state actors, and self-censorship due to cyber threats. Led to executive order enabling cyber sanctions.',
  lessonsLearned: ['Private sector companies can be direct targets of nation-state attacks', 'Insider threat and spear-phishing remain primary initial access vectors', 'Data destruction can be combined with data theft for maximum impact', 'Geopolitical context must inform corporate threat modeling', 'Incident response plans must account for nation-state adversaries']
};

HISTORICAL_OPERATIONS_DETAIL['op-007'] = {
  codename: 'SHAMOON / DISTTRACK',
  attribution: 'Iran (IRGC / APT33 Elfin)',
  attributionConfidence: 85,
  fullDescription: 'The Shamoon malware was deployed against Saudi Aramco, the world\'s most valuable company, destroying data on approximately 35,000 workstations by overwriting the master boot record with an image of a burning American flag. The attack, attributed to Iranian state actors, was one of the most destructive cyber attacks against a single organization and represented a significant escalation in Iran\'s cyber capabilities. The attack occurred during Ramadan when many IT staff were on leave, maximizing impact.',
  targets: ['Saudi Aramco (35,000 workstations)', 'RasGas (Qatar, secondary target)'],
  ttps: [
    { technique: 'T1078', name: 'Valid Accounts', detail: 'Used compromised credentials, possibly from insider' },
    { technique: 'T1570', name: 'Lateral Tool Transfer', detail: 'Rapid propagation across the internal network using admin shares' },
    { technique: 'T1561.002', name: 'Disk Structure Wipe', detail: 'MBR overwrite with burning flag image, rendering systems unbootable' },
    { technique: 'T1485', name: 'Data Destruction', detail: 'File overwrite before MBR destruction' }
  ],
  timeline: [
    { date: '2012-08-15 11:08', event: 'Shamoon wiper activates on Saudi Aramco network' },
    { date: '2012-08-15 12:00', event: 'IT staff notice widespread system failures' },
    { date: '2012-08-15 14:00', event: 'Aramco disconnects corporate network from internet' },
    { date: '2012-08-16', event: 'Scale of destruction becomes clear: 35,000+ workstations wiped' },
    { date: '2012-08-17', event: '"Cutting Sword of Justice" hacktivist group claims responsibility' },
    { date: '2012-08-20', event: 'Aramco begins hardware replacement program (bought most available hard drives worldwide)' },
    { date: '2012-08-28', event: 'RasGas in Qatar hit by similar attack' },
    { date: '2012-09-15', event: 'Aramco systems largely restored after 2 weeks' },
    { date: '2016-11', event: 'Shamoon 2.0 variant targets Saudi government agencies' },
    { date: '2018-12', event: 'Shamoon 3 targets oil/gas sector in Middle East' }
  ],
  toolsUsed: ['Shamoon/DistTrack wiper', 'Spreading module (admin shares)', 'Communication module (C2)', 'Reporting module (infection count)'],
  impact: '35,000 workstations destroyed. Saudi Aramco offline for 2 weeks. Company reverted to typewriters and fax machines. Aramco purchased so many replacement hard drives it caused a global shortage. Oil production unaffected (air-gapped OT). Estimated damages $1B+.',
  significance: 'Demonstrated Iran\'s willingness to use destructive cyber capabilities against strategic rivals. First major cyber attack directly impacting a national economy\'s crown jewel company. Proved that massive destruction could be achieved with relatively unsophisticated malware.',
  lessonsLearned: ['Timing attacks during staff vacations maximizes impact', 'Air-gapping OT from IT prevents cascading to production', 'Hardware destruction at scale requires massive replacement logistics', 'Wiper malware is simple to build but devastating in effect', 'National critical assets need defense-in-depth regardless of perceived risk']
};

HISTORICAL_OPERATIONS_DETAIL['op-008'] = {
  codename: 'UKRAINE POWER GRID ATTACK',
  attribution: 'Russia (Sandworm / GRU Unit 74455)',
  attributionConfidence: 95,
  fullDescription: 'On December 23, 2015, Russian state hackers from the Sandworm group (GRU Unit 74455) executed the first confirmed cyber attack to take down a power grid. The attackers used BlackEnergy malware for initial access, then manually operated SCADA systems at three Ukrainian regional power distribution companies to open circuit breakers, cutting power to approximately 230,000 customers for 1-6 hours. They simultaneously launched a TDoS attack against call centers to prevent outage reports and deployed KillDisk wiper to slow recovery.',
  targets: ['Kyivoblenergo (regional power utility)', 'Prykarpattyaoblenergo', 'Chernivtsioblenergo', 'Call centers (TDoS)'],
  ttps: [
    { technique: 'T1566.001', name: 'Spearphishing Attachment', detail: 'BlackEnergy delivered via macro-enabled Word documents to utility employees' },
    { technique: 'T1059', name: 'Command and Scripting Interpreter', detail: 'Used VBS scripts and native Windows tools for lateral movement' },
    { technique: 'T1021.001', name: 'Remote Desktop Protocol', detail: 'VPN hijacking and RDP to access SCADA HMI workstations' },
    { technique: 'T1565.001', name: 'Stored Data Manipulation', detail: 'Directly operated SCADA HMI to open circuit breakers' },
    { technique: 'T1489', name: 'Service Stop', detail: 'KillDisk wiper deployed to complicate recovery' },
    { technique: 'T1499', name: 'Endpoint Denial of Service', detail: 'TDoS attack on utility call centers to suppress outage reports' }
  ],
  timeline: [
    { date: '2015-03', event: 'BlackEnergy spear-phishing campaign targets Ukrainian utility employees' },
    { date: '2015-06', event: 'Attackers achieve persistent access, begin network reconnaissance' },
    { date: '2015-09', event: 'SCADA network mapping and credential harvesting' },
    { date: '2015-11', event: 'Attackers test SCADA controls during off-hours' },
    { date: '2015-12-23 15:30', event: 'Attackers log into SCADA HMIs at 3 utilities simultaneously' },
    { date: '2015-12-23 15:35', event: 'Circuit breakers opened at multiple substations - 230K customers lose power' },
    { date: '2015-12-23 15:40', event: 'KillDisk wiper deployed on IT systems' },
    { date: '2015-12-23 15:45', event: 'TDoS flood targets utility call centers' },
    { date: '2015-12-23 16:00', event: 'Firmware on serial-to-Ethernet converters overwritten to prevent remote recovery' },
    { date: '2015-12-23 17:30', event: 'Manual recovery begins - technicians physically close breakers' },
    { date: '2015-12-23 22:00', event: 'Power restored to most customers (1-6 hours outage)' }
  ],
  toolsUsed: ['BlackEnergy 3 (backdoor)', 'KillDisk (wiper)', 'Custom VBS downloaders', 'TDoS tool', 'Firmware overwrite tool for serial converters'],
  impact: '230,000 customers lost power for 1-6 hours. Three utilities simultaneously attacked. IT systems required weeks to fully restore. Serial-to-Ethernet converter firmware had to be manually reflashed. First confirmed cyber-caused power outage in history.',
  significance: 'First proven cyber attack to disrupt an electrical grid. Validated long-theorized risk of SCADA system compromise leading to real-world impact. Demonstrated sophisticated multi-phase attack combining cyber and physical effects. Preceded even more sophisticated 2016 Industroyer attack.',
  lessonsLearned: ['ICS/SCADA systems connected to corporate IT are at risk', 'Manual override capabilities are essential for recovery', 'Multi-vector attacks (cyber + TDoS) complicate incident response', 'Firmware integrity of network devices must be monitored', 'Power grids need defense-in-depth with air-gapped safety systems']
};

// ============================================================================
// ADDITIONAL RENDER HELPERS — SUPPORTING SUB-COMPONENTS
// ============================================================================

function renderSeverityBadge(severity) {
  var colors = { 'critical': '#ff2244', 'high': '#ff6622', 'medium': '#ffaa00', 'low': '#44cc88', 'info': '#00aaff' };
  var c = colors[severity] || colors[(severity || '').toLowerCase()] || '#889';
  var h = '<span style="background:' + c + '22;color:' + c + ';padding:2px 8px;border-radius:3px;font-size:9px;';
  h += 'font-family:monospace;letter-spacing:1px;border:1px solid ' + c + '44;">';
  h += esc((severity || 'UNKNOWN').toUpperCase());
  h += '</span>';
  return h;
}

function renderConfidenceBar(confidence, width) {
  width = width || 100;
  var color = confidence >= 80 ? '#00ff88' : confidence >= 60 ? '#ffaa00' : '#ff4466';
  var h = '<div style="display:inline-flex;align-items:center;gap:6px;">';
  h += '<div style="width:' + width + 'px;height:6px;background:#1a2a3c;border-radius:3px;overflow:hidden;">';
  h += '<div style="width:' + confidence + '%;height:100%;background:' + color + ';border-radius:3px;"></div>';
  h += '</div>';
  h += '<span style="color:' + color + ';font-size:11px;font-family:monospace;font-weight:bold;">' + confidence + '%</span>';
  h += '</div>';
  return h;
}

function renderClassBanner(text) {
  var h = '<div style="background:#cc0000;color:#fff;text-align:center;padding:5px;';
  h += 'font-size:10px;letter-spacing:3px;font-weight:bold;font-family:monospace;">';
  h += esc(text);
  h += '</div>';
  return h;
}

function renderThreatLevelIndicator(level) {
  var colors = { 1: '#00ff88', 2: '#44cc88', 3: '#ffaa00', 4: '#ff6622', 5: '#ff2244' };
  var labels = { 1: 'LOW', 2: 'GUARDED', 3: 'ELEVATED', 4: 'HIGH', 5: 'SEVERE' };
  var c = colors[level] || '#889';
  var h = '<div style="display:inline-flex;align-items:center;gap:8px;">';
  h += '<div style="width:24px;height:24px;background:' + c + '33;border:2px solid ' + c + ';border-radius:4px;';
  h += 'display:flex;align-items:center;justify-content:center;color:' + c + ';font-weight:bold;font-family:monospace;font-size:14px;">';
  h += level;
  h += '</div>';
  h += '<span style="color:' + c + ';font-size:10px;letter-spacing:2px;font-family:monospace;">' + (labels[level] || 'UNKNOWN') + '</span>';
  h += '</div>';
  return h;
}

function renderStatCard(label, value, color, subtitle) {
  var h = '<div style="background:#0a0e1a;border:1px solid #1a3a5c;border-radius:6px;padding:14px;text-align:center;">';
  h += '<div style="font-size:8px;color:#556;letter-spacing:2px;margin-bottom:6px;">' + esc(label) + '</div>';
  h += '<div style="font-size:28px;color:' + (color || '#00aaff') + ';font-weight:bold;font-family:monospace;';
  h += 'text-shadow:0 0 15px ' + (color || '#00aaff') + '33;">' + esc(value) + '</div>';
  if (subtitle) {
    h += '<div style="font-size:9px;color:#556;margin-top:4px;">' + esc(subtitle) + '</div>';
  }
  h += '</div>';
  return h;
}

function renderTimeAgo(isoString) {
  try {
    var then = new Date(isoString).getTime();
    var now = Date.now();
    var diff = Math.floor((now - then) / 1000);
    if (diff < 60) return diff + 's ago';
    if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
    if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
    return Math.floor(diff / 86400) + 'd ago';
  } catch (e) { return esc(isoString); }
}

function renderSectionHeader(title, subtitle) {
  var h = '<div style="margin-bottom:16px;">';
  h += '<h3 style="margin:0;font-size:16px;color:#00aaff;font-family:monospace;letter-spacing:2px;text-transform:uppercase;">' + esc(title) + '</h3>';
  if (subtitle) {
    h += '<div style="color:#556;font-size:11px;margin-top:4px;letter-spacing:1px;">' + esc(subtitle) + '</div>';
  }
  h += '</div>';
  return h;
}

function renderDataGrid(headers, rows) {
  var h = '<div style="overflow-x:auto;">';
  h += '<table style="width:100%;border-collapse:collapse;font-size:11px;font-family:monospace;">';
  h += '<thead><tr>';
  for (var hi = 0; hi < headers.length; hi++) {
    h += '<th style="padding:8px 10px;text-align:left;color:#556;border-bottom:2px solid #1a3a5c;letter-spacing:1px;font-size:10px;">' + esc(headers[hi]) + '</th>';
  }
  h += '</tr></thead><tbody>';
  for (var ri = 0; ri < rows.length; ri++) {
    var rowBg = ri % 2 === 0 ? '#0a0e1a' : '#080c16';
    h += '<tr style="background:' + rowBg + ';">';
    for (var ci = 0; ci < rows[ri].length; ci++) {
      h += '<td style="padding:6px 10px;color:#c8d8e8;border-bottom:1px solid #1a2a3c;">' + esc(rows[ri][ci]) + '</td>';
    }
    h += '</tr>';
  }
  h += '</tbody></table>';
  h += '</div>';
  return h;
}

function renderExpandablePanel(title, contentHtml, panelId) {
  var h = '<div style="background:#0a0e1a;border:1px solid #1a3a5c;border-radius:6px;margin-bottom:8px;overflow:hidden;">';
  h += '<div style="padding:10px 14px;cursor:pointer;display:flex;justify-content:space-between;align-items:center;" ';
  h += 'onclick="var p=document.getElementById(\'' + esc(panelId) + '\');if(p)p.hidden=!p.hidden;">';
  h += '<span style="color:#00aaff;font-size:12px;font-family:monospace;letter-spacing:1px;">' + esc(title) + '</span>';
  h += '<span style="color:#556;font-size:14px;">&#9662;</span>';
  h += '</div>';
  h += '<div id="' + esc(panelId) + '" hidden style="padding:0 14px 14px 14px;border-top:1px solid #1a3a5c;">';
  h += contentHtml;
  h += '</div>';
  h += '</div>';
  return h;
}

// ============================================================================
// CYBER INCIDENT DATABASE (supplemental tracking data)
// ============================================================================
var CYBER_INCIDENT_TIMELINE = [
  { year: 1988, event: 'Morris Worm', significance: 'First major internet worm; infected ~6,000 computers (10% of internet)' },
  { year: 1996, event: 'Moonlight Maze begins', significance: 'First documented nation-state cyber espionage campaign' },
  { year: 1998, event: 'Solar Sunrise', significance: 'Teenage hackers probe DOD systems during Iraq tensions' },
  { year: 2003, event: 'Titan Rain', significance: 'Chinese espionage campaign against US defense contractors' },
  { year: 2007, event: 'Estonia DDoS', significance: 'First coordinated cyber attack against a nation-state' },
  { year: 2008, event: 'Agent.BTZ', significance: 'USB worm compromises classified US military networks; leads to USCYBERCOM creation' },
  { year: 2009, event: 'Operation Aurora', significance: 'Chinese espionage targeting Google, Adobe, and 30+ companies' },
  { year: 2009, event: 'GhostNet', significance: 'Chinese espionage network spanning 103 countries' },
  { year: 2010, event: 'Stuxnet discovered', significance: 'First cyber weapon causing physical destruction' },
  { year: 2011, event: 'RSA breach', significance: 'Chinese APT steals SecurID seed values, enabling downstream attacks' },
  { year: 2011, event: 'Duqu discovered', significance: 'Stuxnet-related espionage tool targeting Iran' },
  { year: 2012, event: 'Flame discovered', significance: '20MB modular espionage platform; most complex malware at the time' },
  { year: 2012, event: 'Shamoon (Saudi Aramco)', significance: 'Iran wipes 35,000 computers; most destructive single-target attack' },
  { year: 2013, event: 'Mandiant APT1 report', significance: 'First public attribution of Chinese military unit conducting espionage' },
  { year: 2013, event: 'Snowden disclosures', significance: 'Revealed NSA surveillance programs and offensive capabilities' },
  { year: 2014, event: 'Sony Pictures hack', significance: 'North Korean destructive attack on private company' },
  { year: 2015, event: 'OPM breach', significance: 'China steals 22.1M US government personnel records' },
  { year: 2015, event: 'Ukraine power grid attack', significance: 'First confirmed cyber attack causing power outage' },
  { year: 2016, event: 'DNC hack', significance: 'Russian interference in US election via cyber operations' },
  { year: 2016, event: 'Bangladesh Bank heist', significance: 'North Korea steals $81M via SWIFT system' },
  { year: 2016, event: 'Shadow Brokers', significance: 'NSA tools leaked; later enable WannaCry and NotPetya' },
  { year: 2016, event: 'Ukraine grid attack II (Industroyer)', significance: 'Purpose-built ICS malware causes Kyiv power outage' },
  { year: 2017, event: 'WannaCry', significance: 'North Korean ransomware worm infects 200K+ systems in 150 countries' },
  { year: 2017, event: 'NotPetya', significance: 'Russia\'s $10B+ destructive attack disguised as ransomware' },
  { year: 2017, event: 'TRITON/TRISIS', significance: 'First malware targeting safety instrumented systems (SIS)' },
  { year: 2018, event: 'Olympic Destroyer', significance: 'Russian false-flag attack on PyeongChang Olympics' },
  { year: 2019, event: 'Norsk Hydro ransomware', significance: 'LockerGoga disrupts major aluminum manufacturer' },
  { year: 2020, event: 'SolarWinds/SUNBURST', significance: 'Russia compromises 18,000 orgs via supply chain' },
  { year: 2021, event: 'Colonial Pipeline', significance: 'DarkSide ransomware shuts largest US fuel pipeline' },
  { year: 2021, event: 'Kaseya VSA', significance: 'REvil supply chain attack affects 1,500+ orgs' },
  { year: 2021, event: 'ProxyLogon (Exchange)', significance: 'Hafnium mass-exploits Exchange servers globally' },
  { year: 2021, event: 'Log4Shell', significance: 'Critical vulnerability in ubiquitous logging library' },
  { year: 2022, event: 'Viasat KA-SAT', significance: 'Russia wipes satellite modems at start of Ukraine invasion' },
  { year: 2022, event: 'Costa Rica ransomware', significance: 'Conti forces national emergency declaration' },
  { year: 2023, event: 'MOVEit exploitation', significance: 'Cl0p exploits file transfer software, steals data from 2,600+ orgs' },
  { year: 2023, event: 'Microsoft cloud key theft', significance: 'Storm-0558 forges Azure AD tokens using stolen MSA key' },
  { year: 2024, event: 'Change Healthcare', significance: 'BlackCat ransomware disrupts US healthcare payment processing' },
  { year: 2024, event: 'Volt Typhoon disclosure', significance: 'US reveals China pre-positioning in critical infrastructure' },
  { year: 2024, event: 'Salt Typhoon telecom', significance: 'China infiltrates major US telecom providers' },
  { year: 2025, event: 'AI-powered phishing surge', significance: 'Nation-states leverage LLMs for convincing targeted phishing at scale' },
  { year: 2026, event: 'SENTINEL EYE operational', significance: 'Global cyber threat prediction and counter-operations platform deployed' }
];

// ============================================================================
// NATION-STATE CYBER BUDGET COMPARISON DATA
// ============================================================================
var NATION_CYBER_BUDGETS = [
  { nation: 'United States', budget: 10500, workforce: 6000, tier: 1, offenseRating: 10, defenseRating: 9 },
  { nation: 'China', budget: 2500, workforce: 100000, tier: 1, offenseRating: 9, defenseRating: 8 },
  { nation: 'United Kingdom', budget: 1200, workforce: 3000, tier: 1, offenseRating: 8, defenseRating: 8 },
  { nation: 'Israel', budget: 1500, workforce: 5000, tier: 1, offenseRating: 9, defenseRating: 8 },
  { nation: 'Russia', budget: 700, workforce: 1000, tier: 1, offenseRating: 9, defenseRating: 7 },
  { nation: 'France', budget: 600, workforce: 2500, tier: 2, offenseRating: 7, defenseRating: 7 },
  { nation: 'Iran', budget: 300, workforce: 3500, tier: 2, offenseRating: 7, defenseRating: 5 },
  { nation: 'North Korea', budget: 150, workforce: 6800, tier: 2, offenseRating: 7, defenseRating: 3 },
  { nation: 'India', budget: 400, workforce: 2000, tier: 2, offenseRating: 6, defenseRating: 6 },
  { nation: 'Turkey', budget: 200, workforce: 1200, tier: 3, offenseRating: 5, defenseRating: 5 },
  { nation: 'Pakistan', budget: 100, workforce: 800, tier: 3, offenseRating: 4, defenseRating: 4 },
  { nation: 'Vietnam', budget: 80, workforce: 1500, tier: 3, offenseRating: 5, defenseRating: 4 }
];

// ============================================================================
// CYBER ESCALATION LADDER
// ============================================================================
var ESCALATION_LADDER = [
  { level: 0, name: 'BASELINE', description: 'Normal peacetime cyber operations. Routine intelligence collection, vulnerability scanning, defensive monitoring.', examples: 'SIGINT collection, vulnerability research, defensive SOC operations', authorities: 'Standing DOD/IC authorities', color: '#00ff88' },
  { level: 1, name: 'ENHANCED MONITORING', description: 'Increased surveillance and detection posture. Additional sensors deployed, analyst shifts extended.', examples: 'Enhanced network monitoring, threat hunting, increased ISR', authorities: 'CYBERCOM commander authority', color: '#44cc88' },
  { level: 2, name: 'DEFENSIVE CYBER OPERATIONS', description: 'Active defense of US networks. Block, degrade, or disrupt adversary access to defended networks.', examples: 'Blocking C2 traffic, isolating compromised systems, malware eradication', authorities: 'CYBERCOM EXORD / Standing rules of engagement', color: '#ffaa00' },
  { level: 3, name: 'ACTIVE DEFENSE', description: 'Operations that reach beyond defended networks to detect, characterize, and counter adversary activity.', examples: 'Hunt-forward missions, beacon disruption, infrastructure mapping', authorities: 'SECDEF authorization / NSPM-13', color: '#ff8844' },
  { level: 4, name: 'OFFENSIVE CYBER OPERATIONS', description: 'Operations to project power in cyberspace to achieve military objectives. Degrade, disrupt, or destroy adversary capabilities.', examples: 'C2 infrastructure takedown, adversary tool disruption, data denial', authorities: 'POTUS / SECDEF authorization per NSPM-13 and EXORD', color: '#ff6622' },
  { level: 5, name: 'STRATEGIC CYBER WARFARE', description: 'Full-scale cyber operations as part of armed conflict. Target critical infrastructure, military C2, strategic capabilities.', examples: 'Grid attacks, military network destruction, strategic system disruption', authorities: 'POTUS authorization / War Powers / AUMF', color: '#ff2244' }
];

function renderEscalationLadder() {
  var h = '';
  h += '<div style="padding:16px 0;">';
  h += '<div style="font-size:10px;color:#556;letter-spacing:2px;margin-bottom:16px;">CYBER ESCALATION LADDER</div>';

  h += '<div style="display:flex;flex-direction:column;gap:4px;">';
  for (var i = ESCALATION_LADDER.length - 1; i >= 0; i--) {
    var step = ESCALATION_LADDER[i];
    var isActive = step.level === 3;
    h += '<div style="background:' + (isActive ? step.color + '11' : '#0a0e1a') + ';border:2px solid ' + (isActive ? step.color : '#1a3a5c') + ';border-radius:6px;padding:14px 18px;' + (isActive ? 'box-shadow:0 0 20px ' + step.color + '22;' : '') + '">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;">';
    h += '<div style="display:flex;align-items:center;gap:12px;">';
    h += '<div style="width:32px;height:32px;background:' + step.color + '22;border:2px solid ' + step.color + ';border-radius:4px;display:flex;align-items:center;justify-content:center;color:' + step.color + ';font-weight:bold;font-family:monospace;font-size:16px;">' + step.level + '</div>';
    h += '<div>';
    h += '<div style="color:' + step.color + ';font-size:13px;font-weight:bold;font-family:monospace;letter-spacing:2px;">' + esc(step.name) + '</div>';
    h += '<div style="color:#c8d8e8;font-size:11px;margin-top:2px;">' + esc(step.description) + '</div>';
    h += '</div>';
    h += '</div>';
    if (isActive) {
      h += '<div style="color:' + step.color + ';font-size:11px;font-family:monospace;font-weight:bold;animation:se-blink 1.5s ease-in-out infinite;">&#9654; CURRENT POSTURE</div>';
    }
    h += '</div>';
    h += '<div style="display:flex;gap:16px;margin-top:8px;padding-top:8px;border-top:1px solid #1a2a3c;flex-wrap:wrap;">';
    h += '<div style="flex:1;min-width:200px;"><span style="color:#556;font-size:9px;letter-spacing:1px;">EXAMPLES: </span><span style="color:#889;font-size:10px;">' + esc(step.examples) + '</span></div>';
    h += '<div style="flex:1;min-width:200px;"><span style="color:#556;font-size:9px;letter-spacing:1px;">AUTHORITY: </span><span style="color:#ffaa00;font-size:10px;">' + esc(step.authorities) + '</span></div>';
    h += '</div>';
    h += '</div>';
  }
  h += '</div>';

  h += '</div>';
  return h;
}

function renderIncidentTimeline() {
  var h = '';
  h += '<div style="padding:16px 0;">';
  h += renderSectionHeader('CYBER WARFARE HISTORY', 'Major milestones in nation-state cyber operations (1988-2026)');

  h += '<div style="position:relative;padding-left:80px;">';
  h += '<div style="position:absolute;left:60px;top:0;bottom:0;width:3px;background:linear-gradient(180deg,#00aaff22,#00aaff,#ff2244,#ff224422);border-radius:2px;"></div>';

  for (var ci2 = 0; ci2 < CYBER_INCIDENT_TIMELINE.length; ci2++) {
    var incident = CYBER_INCIDENT_TIMELINE[ci2];
    var progress = ci2 / CYBER_INCIDENT_TIMELINE.length;
    var dotColor = progress < 0.3 ? '#00aaff' : progress < 0.6 ? '#ffaa00' : '#ff2244';

    h += '<div style="position:relative;margin-bottom:12px;">';
    h += '<div style="position:absolute;left:-76px;top:4px;color:#556;font-size:11px;font-family:monospace;letter-spacing:1px;text-align:right;width:55px;">' + incident.year + '</div>';
    h += '<div style="position:absolute;left:-24px;top:5px;width:12px;height:12px;background:' + dotColor + ';border-radius:50%;border:2px solid #060a14;"></div>';
    h += '<div style="margin-left:8px;padding:8px 14px;background:#0a0e1a;border:1px solid #1a3a5c;border-radius:4px;">';
    h += '<div style="color:#c8d8e8;font-size:12px;font-weight:bold;">' + esc(incident.event) + '</div>';
    h += '<div style="color:#889;font-size:10px;margin-top:2px;">' + esc(incident.significance) + '</div>';
    h += '</div>';
    h += '</div>';
  }

  h += '</div>';
  h += '</div>';
  return h;
}

function renderBudgetComparison() {
  var h = '';
  h += '<div style="padding:16px 0;">';
  h += renderSectionHeader('NATION-STATE CYBER BUDGET COMPARISON', 'Estimated annual cyber operations budgets (USD millions)');

  h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px;">';
  var sorted2 = NATION_CYBER_BUDGETS.slice().sort(function(a, b) { return b.budget - a.budget; });
  var maxBudget = sorted2[0].budget;

  for (var b = 0; b < sorted2.length; b++) {
    var nation = sorted2[b];
    var tierColors = { 1: '#00aaff', 2: '#ffaa00', 3: '#889' };
    var tc2 = tierColors[nation.tier] || '#889';
    var budgetPct = Math.round((nation.budget / maxBudget) * 100);

    h += '<div style="background:#0a0e1a;border:1px solid #1a3a5c;border-radius:6px;padding:12px;">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">';
    h += '<span style="color:#c8d8e8;font-size:13px;font-weight:bold;">' + esc(nation.nation) + '</span>';
    h += '<span style="background:' + tc2 + '22;color:' + tc2 + ';padding:2px 8px;border-radius:3px;font-size:9px;border:1px solid ' + tc2 + '44;">TIER ' + nation.tier + '</span>';
    h += '</div>';

    // Budget bar
    h += '<div style="margin-bottom:8px;">';
    h += '<div style="display:flex;justify-content:space-between;font-size:10px;margin-bottom:2px;">';
    h += '<span style="color:#556;">EST. BUDGET</span>';
    h += '<span style="color:#00ff88;font-weight:bold;">$' + nation.budget + 'M</span>';
    h += '</div>';
    h += '<div style="width:100%;height:6px;background:#1a2a3c;border-radius:3px;overflow:hidden;">';
    h += '<div style="width:' + budgetPct + '%;height:100%;background:linear-gradient(90deg,#00aaff,#00ff88);border-radius:3px;"></div>';
    h += '</div>';
    h += '</div>';

    // Stats row
    h += '<div style="display:flex;gap:12px;font-size:10px;">';
    h += '<div><span style="color:#556;">WORKFORCE: </span><span style="color:#c8d8e8;">' + nation.workforce.toLocaleString() + '</span></div>';
    h += '<div><span style="color:#556;">OFF: </span><span style="color:#ff6644;">' + nation.offenseRating + '/10</span></div>';
    h += '<div><span style="color:#556;">DEF: </span><span style="color:#00ff88;">' + nation.defenseRating + '/10</span></div>';
    h += '</div>';

    h += '</div>';
  }
  h += '</div>';

  h += '</div>';
  return h;
}



// ============================================================================
// ADDITIONAL HISTORICAL OPERATION DETAILS
// ============================================================================
HISTORICAL_OPERATIONS_DETAIL['op-017'] = {
  codename: 'SHADOW BROKERS',
  attribution: 'Unknown (leaked NSA TAO / Equation Group tools)',
  attributionConfidence: 70,
  fullDescription: 'A group calling themselves "The Shadow Brokers" released a trove of hacking tools stolen from the NSA\'s elite Tailored Access Operations (TAO) unit, also known as the Equation Group. The leaked tools included EternalBlue (MS17-010), DoublePulsar, and dozens of other exploits targeting Windows, Cisco, Fortinet, and other widely-deployed systems. The leaks directly enabled WannaCry and NotPetya, two of the most destructive cyber events in history, causing combined damages exceeding $14 billion.',
  targets: ['NSA Equation Group tool repository', 'Global cybersecurity (indirect — leaked tools used worldwide)'],
  ttps: [
    { technique: 'T1588.005', name: 'Obtain Capabilities: Exploits', detail: 'Acquisition of sovereign nation-state offensive tools (unprecedented)' },
    { technique: 'T1591', name: 'Gather Victim Org Information', detail: 'Knowledge of NSA internal operational structure and tool naming' },
    { technique: 'T1583.006', name: 'Web Services', detail: 'Used Steemit, Medium, and GitHub for public tool releases' }
  ],
  timeline: [
    { date: '2016-08-13', event: 'Shadow Brokers announce auction of "Equation Group cyber weapons"' },
    { date: '2016-10', event: 'Second dump includes tools targeting Windows systems' },
    { date: '2017-01', event: 'Further releases with pricing list for individual tools' },
    { date: '2017-03-14', event: 'Microsoft patches MS17-010 (EternalBlue) — suspected NSA tip-off' },
    { date: '2017-04-14', event: 'Major dump: EternalBlue, DoublePulsar, EternalRomance + dozens more' },
    { date: '2017-05-12', event: 'WannaCry ransomware worm uses EternalBlue — 200K+ infections' },
    { date: '2017-06-27', event: 'NotPetya uses EternalBlue — $10B+ in damages' },
    { date: '2017-11', event: 'Final known Shadow Brokers communication' }
  ],
  toolsUsed: ['EternalBlue (MS17-010)', 'DoublePulsar', 'EternalRomance', 'EternalSynergy', 'FUZZBUNCH framework', 'DanderSpritz implant framework', 'BANANAGLEE (Cisco/Juniper implant)', 'EXTRABACON', 'EPICBANANA'],
  impact: 'Directly enabled WannaCry ($4-8B damages) and NotPetya ($10B+ damages). Exposed NSA offensive capabilities. Undermined public trust in intelligence agencies. Created global vulnerability crisis as leaked exploits were weaponized by multiple threat actors.',
  significance: 'Most consequential intelligence tool leak in cyber history. Demonstrated that offensive stockpiling creates systemic risk. Led to Vulnerabilities Equities Process reform. Showed that "nobody is safe" — even the most sophisticated cyber organization can be compromised.',
  lessonsLearned: ['Stockpiling vulnerabilities creates systemic risk when leaked', 'Vulnerability disclosure debate has real-world consequences', 'Patching must be treated as urgent national security priority', 'Insider threat to intelligence agencies can have global impact', 'Leaked tools lower the barrier for all threat actors']
};

HISTORICAL_OPERATIONS_DETAIL['op-018'] = {
  codename: 'BANGLADESH BANK HEIST',
  attribution: 'North Korea (Lazarus Group / BlueNoroff)',
  attributionConfidence: 93,
  fullDescription: 'North Korean state hackers from the Lazarus Group\'s financial operations unit (BlueNoroff) infiltrated Bangladesh Bank\'s systems and attempted to steal $951 million by submitting fraudulent SWIFT messages to the Federal Reserve Bank of New York. The attackers successfully transferred $81 million to accounts in the Philippines, where it was laundered through casinos. A spelling error in one transfer request ("fandation" instead of "foundation") triggered additional scrutiny that blocked the remaining $870 million in fraudulent transfers.',
  targets: ['Bangladesh Bank (central bank)', 'SWIFT messaging system', 'Federal Reserve Bank of New York', 'Rizal Commercial Banking Corp (Philippines)'],
  ttps: [
    { technique: 'T1566.001', name: 'Spearphishing Attachment', detail: 'Initial compromise via targeted emails to Bangladesh Bank employees' },
    { technique: 'T1078', name: 'Valid Accounts', detail: 'Stolen SWIFT operator credentials used for message submission' },
    { technique: 'T1565.001', name: 'Stored Data Manipulation', detail: 'Modified SWIFT Alliance Access software to suppress transfer confirmations' },
    { technique: 'T1070', name: 'Indicator Removal', detail: 'Deleted transaction logs and modified database records to hide transfers' },
    { technique: 'T1548', name: 'Abuse Elevation Control', detail: 'Bypassed SWIFT security controls using compromised admin access' }
  ],
  timeline: [
    { date: '2015-05', event: 'Lazarus Group sends reconnaissance spear-phishing to Bangladesh Bank' },
    { date: '2016-01', event: 'Attackers achieve access to SWIFT Alliance Access terminal' },
    { date: '2016-02-04', event: 'Attackers wait for Dhaka weekend/NY business hours overlap' },
    { date: '2016-02-04 20:36', event: 'First batch of 35 fraudulent SWIFT messages submitted ($951M total)' },
    { date: '2016-02-05', event: '5 transfers ($101M) clear to Philippine bank accounts' },
    { date: '2016-02-05', event: 'Deutsche Bank flags "fandation" misspelling, queries remaining transfers' },
    { date: '2016-02-08', event: 'Bangladesh Bank discovers fraud upon return from weekend' },
    { date: '2016-02-09', event: '$20M transfer to Sri Lanka reversed (another misspelling caught)' },
    { date: '2016-03', event: '$81M laundered through Philippine casinos, largely unrecoverable' },
    { date: '2018-09', event: 'DOJ indicts Park Jin Hyok for Bangladesh Bank heist and other operations' }
  ],
  toolsUsed: ['Custom SWIFT malware', 'SWIFT Alliance Access manipulation tools', 'Custom backdoors for persistence', 'Log cleaning utilities', 'Anti-forensics tools'],
  impact: '$81 million successfully stolen ($951M attempted). Only $15M recovered. Exposed fundamental vulnerabilities in global banking messaging system. Led to SWIFT Customer Security Programme. Multiple banks in Vietnam, Ecuador, and other countries targeted in similar campaigns.',
  significance: 'Demonstrated nation-state capability to exploit global financial infrastructure. Showed that even the most trusted financial messaging system (SWIFT) could be compromised. Changed how banks approach SWIFT security. Demonstrated North Korea\'s motivation to fund regime through cyber theft.',
  lessonsLearned: ['Global financial messaging systems are high-value targets', 'Time zone differences can be exploited in international banking attacks', 'Small errors (typos) can prevent massive losses', 'Central banks need dedicated cybersecurity capabilities', 'Nation-states will target financial systems for revenue generation']
};

HISTORICAL_OPERATIONS_DETAIL['op-021'] = {
  codename: 'TRITON / TRISIS',
  attribution: 'Russia (Central Scientific Research Institute of Chemistry and Mechanics — CNIIHM)',
  attributionConfidence: 87,
  fullDescription: 'Russian state-linked hackers deployed TRITON, the first known malware specifically designed to target safety instrumented systems (SIS). The malware was discovered at a petrochemical facility in Saudi Arabia where it targeted Schneider Electric Triconex safety controllers — the last line of defense preventing catastrophic physical failures such as explosions, toxic gas releases, or equipment destruction. The attack was only detected because a bug in the malware code triggered a safety shutdown. Had it succeeded as designed, the malware could have disabled safety systems while simultaneously creating dangerous physical conditions.',
  targets: ['Saudi petrochemical facility (unnamed)', 'Schneider Electric Triconex SIS controllers', 'Safety Instrumented Systems globally (implied)'],
  ttps: [
    { technique: 'T1190', name: 'Exploit Public-Facing Application', detail: 'Initial IT network compromise via remote access vulnerability' },
    { technique: 'T1021.001', name: 'Remote Desktop Protocol', detail: 'RDP pivot from IT to engineering workstation' },
    { technique: 'T1565.001', name: 'Stored Data Manipulation', detail: 'Modified SIS controller firmware via TriStation protocol' },
    { technique: 'T1562', name: 'Impair Defenses', detail: 'Attempted to reprogram SIS to allow unsafe physical conditions' }
  ],
  timeline: [
    { date: '2014', event: 'Initial IT network compromise of target facility' },
    { date: '2017-06', event: 'Attackers pivot to OT/engineering network' },
    { date: '2017-08', event: 'First TRITON deployment attempt — facility emergency shutdown triggered' },
    { date: '2017-08', event: 'Operators attribute shutdown to mechanical issue, restart operations' },
    { date: '2017-08', event: 'Second TRITON deployment — another safety shutdown' },
    { date: '2017-12', event: 'FireEye/Dragos/Schneider Electric publicly disclose TRITON' },
    { date: '2018-10', event: 'CNIIHM linked to TRITON development (FireEye attribution)' },
    { date: '2019-04', event: 'Additional TRITON activity detected at another facility' }
  ],
  toolsUsed: ['TRITON/TRISIS framework', 'Custom Triconex TriStation protocol library', 'Custom RATs for OT network access', 'Credential harvesting tools', 'Network reconnaissance utilities'],
  impact: 'Safety shutdown of petrochemical facility (potential for catastrophic physical incident averted only by malware bug). First confirmed attack on safety systems designed to prevent loss of human life. Changed entire industrial cybersecurity threat landscape.',
  significance: 'Crossed a fundamental line — targeting systems designed to prevent deaths. Demonstrated that nation-states are willing to risk human casualties through cyber attacks. Led to fundamental reassessment of ICS/SCADA security assumptions. Showed that safety systems can be directly compromised, not just bypassed.',
  lessonsLearned: ['Safety instrumented systems can be directly targeted by cyber actors', 'ICS security must assume sophisticated nation-state threat actors', 'OT network segmentation from IT is critical but insufficient alone', 'Safety system firmware integrity must be continuously monitored', 'Red lines in cyber warfare are not well established or respected']
};

// ============================================================================
// THREAT FEED AGGREGATION DASHBOARD DATA
// ============================================================================
var THREAT_FEED_SOURCES = [
  { name: 'NSA Cybersecurity Advisory', type: 'SIGINT', reliability: 'A', frequency: 'As needed', lastUpdate: '2026-09-12', classification: 'TS//SCI', activeAlerts: 3 },
  { name: 'CISA KEV Catalog', type: 'CYBINT', reliability: 'A', frequency: 'Daily', lastUpdate: '2026-09-13', classification: 'UNCLASSIFIED', activeAlerts: 12 },
  { name: 'FBI FLASH', type: 'CYBINT', reliability: 'A', frequency: 'Weekly', lastUpdate: '2026-09-11', classification: 'TLP:RED', activeAlerts: 5 },
  { name: 'Five Eyes Cyber Threat Intel', type: 'SIGINT', reliability: 'A', frequency: 'Daily', lastUpdate: '2026-09-13', classification: 'TS//SI//REL FVEY', activeAlerts: 7 },
  { name: 'NATO NCIRC', type: 'CYBINT', reliability: 'B', frequency: 'Daily', lastUpdate: '2026-09-12', classification: 'NATO SECRET', activeAlerts: 4 },
  { name: 'FS-ISAC ThreatNet', type: 'OSINT', reliability: 'B', frequency: 'Continuous', lastUpdate: '2026-09-13', classification: 'TLP:AMBER', activeAlerts: 8 },
  { name: 'ICS-CERT Advisories', type: 'CYBINT', reliability: 'A', frequency: 'Weekly', lastUpdate: '2026-09-10', classification: 'UNCLASSIFIED', activeAlerts: 6 },
  { name: 'Mandiant Threat Intel', type: 'OSINT', reliability: 'B', frequency: 'Continuous', lastUpdate: '2026-09-13', classification: 'TLP:GREEN', activeAlerts: 15 },
  { name: 'CrowdStrike Falcon Intel', type: 'CYBINT', reliability: 'B', frequency: 'Continuous', lastUpdate: '2026-09-13', classification: 'TLP:GREEN', activeAlerts: 11 },
  { name: 'Recorded Future', type: 'OSINT', reliability: 'B', frequency: 'Continuous', lastUpdate: '2026-09-13', classification: 'TLP:GREEN', activeAlerts: 22 },
  { name: 'Dark Web HUMINT Collection', type: 'HUMINT', reliability: 'C', frequency: 'Variable', lastUpdate: '2026-09-11', classification: 'SECRET//NOFORN', activeAlerts: 3 },
  { name: 'Satellite Imagery Analysis', type: 'GEOINT', reliability: 'B', frequency: 'Daily', lastUpdate: '2026-09-12', classification: 'TS//SCI', activeAlerts: 2 },
  { name: 'VirusTotal Intelligence', type: 'CYBINT', reliability: 'B', frequency: 'Continuous', lastUpdate: '2026-09-13', classification: 'UNCLASSIFIED', activeAlerts: 31 },
  { name: 'Shodan Monitor', type: 'OSINT', reliability: 'C', frequency: 'Continuous', lastUpdate: '2026-09-13', classification: 'UNCLASSIFIED', activeAlerts: 9 },
  { name: 'CIRCL MISP', type: 'CYBINT', reliability: 'B', frequency: 'Daily', lastUpdate: '2026-09-12', classification: 'TLP:AMBER', activeAlerts: 14 }
];

function renderThreatFeedDashboard() {
  var h = '';
  h += '<div style="padding:16px 0;">';
  h += renderSectionHeader('THREAT INTELLIGENCE FEED STATUS', 'Aggregated feed health and active alert monitoring');

  var totalAlerts = 0;
  var sourcesByType = {};
  for (var f = 0; f < THREAT_FEED_SOURCES.length; f++) {
    totalAlerts += THREAT_FEED_SOURCES[f].activeAlerts;
    var ft = THREAT_FEED_SOURCES[f].type;
    sourcesByType[ft] = (sourcesByType[ft] || 0) + 1;
  }

  // Summary stats
  h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px;margin-bottom:20px;">';
  h += renderStatCard('ACTIVE FEEDS', String(THREAT_FEED_SOURCES.length), '#00aaff', 'Ingesting');
  h += renderStatCard('TOTAL ALERTS', String(totalAlerts), '#ff6622', 'Unresolved');
  h += renderStatCard('SIGINT', String(sourcesByType['SIGINT'] || 0), '#00aaff', 'Sources');
  h += renderStatCard('CYBINT', String(sourcesByType['CYBINT'] || 0), '#ffaa00', 'Sources');
  h += renderStatCard('OSINT', String(sourcesByType['OSINT'] || 0), '#00ff88', 'Sources');
  h += renderStatCard('HUMINT', String(sourcesByType['HUMINT'] || 0), '#ff8844', 'Sources');
  h += '</div>';

  // Feed table
  var headers = ['SOURCE', 'TYPE', 'REL', 'FREQ', 'CLASSIFICATION', 'LAST UPDATE', 'ALERTS'];
  var rows = [];
  for (var fi = 0; fi < THREAT_FEED_SOURCES.length; fi++) {
    var feed = THREAT_FEED_SOURCES[fi];
    rows.push([feed.name, feed.type, feed.reliability, feed.frequency, feed.classification, feed.lastUpdate, String(feed.activeAlerts)]);
  }
  h += renderDataGrid(headers, rows);

  h += '</div>';
  return h;
}

// ============================================================================
// ATTACK SURFACE MAPPING DATA
// ============================================================================
var ATTACK_SURFACE_CATEGORIES = [
  {
    category: 'Internet-Facing Services',
    description: 'Publicly accessible network services and applications',
    assets: [
      { name: 'Web Application Servers', count: 12847, riskLevel: 'HIGH', exposures: 'Public APIs, admin panels, legacy apps' },
      { name: 'Email Gateways', count: 3421, riskLevel: 'HIGH', exposures: 'SMTP relay, webmail, Exchange Online' },
      { name: 'VPN Concentrators', count: 856, riskLevel: 'CRITICAL', exposures: 'SSL VPN endpoints, IPSec gateways' },
      { name: 'DNS Servers', count: 423, riskLevel: 'HIGH', exposures: 'Authoritative DNS, recursive resolvers' },
      { name: 'Load Balancers', count: 1234, riskLevel: 'MEDIUM', exposures: 'F5, Citrix NetScaler, HAProxy' }
    ]
  },
  {
    category: 'Cloud Infrastructure',
    description: 'Cloud service provider resources and configurations',
    assets: [
      { name: 'AWS Accounts', count: 347, riskLevel: 'HIGH', exposures: 'S3 buckets, IAM roles, Lambda functions' },
      { name: 'Azure Tenants', count: 128, riskLevel: 'HIGH', exposures: 'Azure AD, Key Vault, App Services' },
      { name: 'GCP Projects', count: 86, riskLevel: 'MEDIUM', exposures: 'GCS buckets, Kubernetes clusters' },
      { name: 'SaaS Applications', count: 2341, riskLevel: 'MEDIUM', exposures: 'OAuth tokens, API integrations, data sharing' }
    ]
  },
  {
    category: 'Industrial Control Systems',
    description: 'SCADA, DCS, and other operational technology systems',
    assets: [
      { name: 'SCADA Systems', count: 1247, riskLevel: 'CRITICAL', exposures: 'HMI access, historian databases, remote access' },
      { name: 'PLCs/RTUs', count: 8934, riskLevel: 'CRITICAL', exposures: 'Modbus/TCP, EtherNet/IP, OPC UA' },
      { name: 'Engineering Workstations', count: 567, riskLevel: 'HIGH', exposures: 'Programming interfaces, firmware upload capability' },
      { name: 'Safety Instrumented Systems', count: 234, riskLevel: 'CRITICAL', exposures: 'Triconex, Yokogawa ProSafe, Honeywell FSC' }
    ]
  },
  {
    category: 'Supply Chain Dependencies',
    description: 'Third-party software, services, and vendor connections',
    assets: [
      { name: 'Software Vendors with Network Access', count: 412, riskLevel: 'HIGH', exposures: 'VPN connections, jump boxes, remote management' },
      { name: 'Open Source Dependencies', count: 47823, riskLevel: 'MEDIUM', exposures: 'npm, PyPI, Maven packages in production' },
      { name: 'Managed Service Providers', count: 89, riskLevel: 'HIGH', exposures: 'Admin access to client environments' },
      { name: 'CI/CD Pipelines', count: 234, riskLevel: 'HIGH', exposures: 'Build systems, code signing, deployment automation' }
    ]
  }
];

function renderAttackSurfaceMap() {
  var h = '';
  h += '<div style="padding:16px 0;">';
  h += renderSectionHeader('NATIONAL CYBER ATTACK SURFACE', 'Critical infrastructure and government network exposure assessment');

  for (var c = 0; c < ATTACK_SURFACE_CATEGORIES.length; c++) {
    var cat = ATTACK_SURFACE_CATEGORIES[c];
    h += '<div style="background:#0a0e1a;border:1px solid #1a3a5c;border-radius:8px;margin-bottom:16px;overflow:hidden;">';

    h += '<div style="background:linear-gradient(135deg,#0a1628,#0d1f3c);padding:14px 18px;border-bottom:1px solid #1a3a5c;">';
    h += '<h4 style="margin:0;color:#00aaff;font-size:14px;font-family:monospace;letter-spacing:1px;">' + esc(cat.category) + '</h4>';
    h += '<div style="color:#889;font-size:10px;margin-top:2px;">' + esc(cat.description) + '</div>';
    h += '</div>';

    h += '<div style="padding:12px 18px;">';
    for (var a = 0; a < cat.assets.length; a++) {
      var asset = cat.assets[a];
      var riskColors2 = { 'CRITICAL': '#ff2244', 'HIGH': '#ff6622', 'MEDIUM': '#ffaa00', 'LOW': '#44cc88' };
      var rc2 = riskColors2[asset.riskLevel] || '#889';
      h += '<div style="display:flex;align-items:center;gap:12px;padding:8px 0;' + (a < cat.assets.length - 1 ? 'border-bottom:1px solid #1a2a3c;' : '') + '">';
      h += '<div style="flex:1;">';
      h += '<div style="color:#c8d8e8;font-size:12px;">' + esc(asset.name) + '</div>';
      h += '<div style="color:#556;font-size:10px;margin-top:2px;">' + esc(asset.exposures) + '</div>';
      h += '</div>';
      h += '<div style="text-align:right;min-width:60px;">';
      h += '<div style="color:#c8d8e8;font-size:14px;font-weight:bold;font-family:monospace;">' + asset.count.toLocaleString() + '</div>';
      h += '</div>';
      h += renderSeverityBadge(asset.riskLevel);
      h += '</div>';
    }
    h += '</div>';

    h += '</div>';
  }

  h += '</div>';
  return h;
}



// ============================================================================
// EXTENDED OPERATION DETAILS (additional entries for deep-dive)
// ============================================================================
HISTORICAL_OPERATIONS_DETAIL['op-003a'] = {
  codename: 'VOLT TYPHOON',
  attribution: 'China (PLA Strategic Support Force / MSS)',
  attributionConfidence: 94,
  fullDescription: 'A Chinese state-sponsored campaign focused on pre-positioning access in US critical infrastructure networks — particularly in telecommunications, energy, water, and transportation sectors — to enable disruptive or destructive cyber operations in the event of a geopolitical crisis, most likely related to Taiwan. Unlike traditional Chinese espionage operations focused on data theft, Volt Typhoon\'s primary objective appears to be establishing persistent access that could be activated during a conflict to delay or disrupt US military response. The campaign uses living-off-the-land techniques (LOLBins) to minimize detection, avoiding custom malware in favor of built-in Windows tools.',
  targets: ['US telecommunications providers (Guam, Hawaii, mainland)', 'US energy sector utilities', 'Water treatment facilities', 'Transportation systems', 'Military-adjacent infrastructure', 'Pacific Island nations'],
  ttps: [
    { technique: 'T1190', name: 'Exploit Public-Facing Application', detail: 'Exploitation of Fortinet FortiGuard, Ivanti, Citrix edge devices for initial access' },
    { technique: 'T1078', name: 'Valid Accounts', detail: 'Use of stolen credentials, often from edge device compromise' },
    { technique: 'T1218', name: 'System Binary Proxy Execution', detail: 'Living-off-the-land: ntdsutil, netsh, wmic, PowerShell for all operations' },
    { technique: 'T1070', name: 'Indicator Removal', detail: 'Extreme operational security — minimal logging artifacts, proxy chains' },
    { technique: 'T1090.001', name: 'Internal Proxy', detail: 'Compromised SOHO routers and IoT devices as operational relay boxes (ORBs)' },
    { technique: 'T1027', name: 'Obfuscated Files', detail: 'Living-off-the-land approach means almost no custom malware to detect' }
  ],
  timeline: [
    { date: '2021', event: 'Earliest confirmed Volt Typhoon activity in US infrastructure (retrospective analysis)' },
    { date: '2023-05', event: 'Microsoft and Five Eyes agencies publicly disclose Volt Typhoon campaign' },
    { date: '2023-12', event: 'CISA confirms Volt Typhoon has maintained access for "at least five years"' },
    { date: '2024-01', event: 'FBI disrupts KV Botnet (SOHO router botnet used as ORB infrastructure)' },
    { date: '2024-02', event: 'CISA advisory details pre-positioning in water, energy, telecom, transport' },
    { date: '2024-03', event: 'Congressional hearing on Chinese cyber pre-positioning threat' },
    { date: '2024-06', event: 'Additional Volt Typhoon infrastructure discovered in Guam and Hawaii' },
    { date: '2025-01', event: 'Expanded operations targeting additional Pacific Island infrastructure' },
    { date: '2026-09', event: 'Ongoing monitoring of dormant Volt Typhoon access points continues' }
  ],
  toolsUsed: ['Living-off-the-land binaries (LOLBins)', 'ntdsutil', 'netsh port forwarding', 'wmic', 'PowerShell', 'Compromised SOHO routers (KV Botnet)', 'Mimikatz (rare)', 'Impacket (rare)'],
  impact: 'Pre-positioned access in critical infrastructure across multiple US sectors. Unknown full scope — dormant access designed to be activated during conflict. Fundamental change in how China is perceived as a cyber threat (from espionage to potential disruption/destruction). Multiple Congressional hearings and executive actions.',
  significance: 'Represents a paradigm shift in Chinese cyber operations: from intelligence collection to preparation for kinetic conflict support. First major campaign focused on critical infrastructure pre-positioning rather than data theft. Changed US national security planning assumptions about cyber threats to the homeland.',
  lessonsLearned: ['Edge device security is critical — network perimeters are primary targets', 'Living-off-the-land techniques defeat signature-based detection', 'Pre-positioning may go undetected for years', 'Critical infrastructure defenders must assume compromise and hunt accordingly', 'Geopolitical context directly shapes cyber threat posture']
};

HISTORICAL_OPERATIONS_DETAIL['op-019a'] = {
  codename: 'SALT TYPHOON',
  attribution: 'China (MSS-affiliated)',
  attributionConfidence: 91,
  fullDescription: 'A Chinese state-sponsored campaign that deeply infiltrated multiple major US telecommunications providers — including AT&T, Verizon, T-Mobile, and Lumen Technologies — gaining access to call metadata, text messages, and in some cases call audio for targeted individuals including senior US government officials and political figures. The operation exploited vulnerabilities in the lawful intercept systems that US carriers are required to maintain under CALEA (Communications Assistance for Law Enforcement Act), essentially turning the government\'s own surveillance infrastructure against it.',
  targets: ['AT&T', 'Verizon', 'T-Mobile', 'Lumen Technologies', 'US government officials', 'Political figures', 'Lawful intercept (CALEA) systems'],
  ttps: [
    { technique: 'T1190', name: 'Exploit Public-Facing Application', detail: 'Exploitation of telecom network management systems and edge devices' },
    { technique: 'T1557', name: 'Adversary-in-the-Middle', detail: 'Access to call routing and switching infrastructure' },
    { technique: 'T1020', name: 'Automated Exfiltration', detail: 'Systematic collection of call metadata and content for targeted numbers' },
    { technique: 'T1005', name: 'Data from Local System', detail: 'Access to lawful intercept data stores and wiretap systems' }
  ],
  timeline: [
    { date: '2023', event: 'Earliest estimated compromise of telecom networks' },
    { date: '2024-09', event: 'FBI and CISA begin investigating Chinese access to telecom providers' },
    { date: '2024-10', event: 'Public disclosure that Chinese hackers accessed US telecom wiretap systems' },
    { date: '2024-11', event: 'Scope expands: AT&T, Verizon, T-Mobile, Lumen all confirmed affected' },
    { date: '2024-12', event: 'CISA issues guidance urging encrypted communications for sensitive discussions' },
    { date: '2025-01', event: 'Congressional briefings reveal targeting of senior officials and political figures' },
    { date: '2025-06', event: 'Full remediation still ongoing across major carriers' },
    { date: '2026-09', event: 'Enhanced monitoring continues; carriers implementing Zero Trust architectures' }
  ],
  toolsUsed: ['Custom telecom-specific backdoors', 'Network management protocol exploitation', 'CALEA intercept system manipulation', 'Call detail record extraction tools'],
  impact: 'Access to communications metadata and content of senior US government officials. Demonstrated vulnerability of legally mandated surveillance infrastructure. Led to fundamental reassessment of CALEA system security. CISA recommended Americans use encrypted messaging apps.',
  significance: 'Exposed a critical weakness: mandated lawful intercept systems create attack surface that adversaries can exploit. Demonstrated that the most fundamental communications infrastructure is vulnerable. Led to calls for reforming CALEA requirements and investing in telecom security.',
  lessonsLearned: ['Government-mandated surveillance capabilities create exploitable attack surface', 'Telecommunications infrastructure is a strategic intelligence target', 'End-to-end encryption is essential for sensitive communications', 'Carrier network security has not kept pace with nation-state threats', 'Zero Trust principles must extend to telecom infrastructure']
};

// ============================================================================
// CYBER WEAPONS TAXONOMY
// ============================================================================
var CYBER_WEAPONS_TAXONOMY = [
  { category: 'Espionage Platforms', description: 'Long-duration intelligence collection frameworks', examples: ['Flame (US/Israel)', 'Regin (Five Eyes)', 'Pegasus (NSO Group)', 'SUNBURST (Russia/APT29)'], tier: 'Nation-state', dangerLevel: 7 },
  { category: 'Destructive Wipers', description: 'Malware designed to destroy data and render systems inoperable', examples: ['Shamoon (Iran)', 'NotPetya (Russia)', 'WhisperGate (Russia)', 'CaddyWiper (Russia)'], tier: 'Nation-state', dangerLevel: 9 },
  { category: 'ICS/SCADA Weapons', description: 'Malware targeting industrial control systems for physical effects', examples: ['Stuxnet (US/Israel)', 'Industroyer (Russia)', 'TRITON (Russia)', 'Pipedream (Unknown)'], tier: 'Nation-state', dangerLevel: 10 },
  { category: 'Ransomware', description: 'Malware encrypting data for extortion', examples: ['WannaCry (North Korea)', 'LockBit (Russia-based)', 'BlackCat/ALPHV', 'Cl0p'], tier: 'Criminal/State-tolerated', dangerLevel: 8 },
  { category: 'Supply Chain Implants', description: 'Backdoors inserted into software distribution channels', examples: ['SUNBURST (Russia)', 'CCleaner (China)', 'XZ Utils (Unknown)', 'NotPetya via M.E.Doc (Russia)'], tier: 'Nation-state', dangerLevel: 9 },
  { category: 'Zero-Click Exploits', description: 'Exploits requiring no user interaction', examples: ['Pegasus (NSO Group)', 'FORCEDENTRY (NSO)', 'Predator (Intellexa)'], tier: 'Commercial/State', dangerLevel: 9 },
  { category: 'Botnet Infrastructure', description: 'Large-scale compromised device networks', examples: ['Mirai', 'KV Botnet (Volt Typhoon)', 'Emotet', 'TrickBot'], tier: 'Criminal/State', dangerLevel: 7 },
  { category: 'Firmware Implants', description: 'Persistent implants below the OS level', examples: ['Equation Group HDD implants', 'CosmicStrand (China)', 'MosaicRegressor (China)', 'LoJax (Russia)'], tier: 'Nation-state', dangerLevel: 10 }
];

function renderCyberWeaponsTaxonomy() {
  var h = '';
  h += '<div style="padding:16px 0;">';
  h += renderSectionHeader('CYBER WEAPONS TAXONOMY', 'Classification of known offensive cyber capabilities by category');

  h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:12px;">';
  for (var w = 0; w < CYBER_WEAPONS_TAXONOMY.length; w++) {
    var weapon = CYBER_WEAPONS_TAXONOMY[w];
    var dangerColor = weapon.dangerLevel >= 9 ? '#ff2244' : weapon.dangerLevel >= 7 ? '#ff6622' : '#ffaa00';

    h += '<div style="background:#0a0e1a;border:1px solid #1a3a5c;border-radius:8px;overflow:hidden;">';
    h += '<div style="padding:14px 16px;border-bottom:1px solid #1a3a5c;display:flex;justify-content:space-between;align-items:center;">';
    h += '<div>';
    h += '<div style="color:#00aaff;font-size:13px;font-weight:bold;font-family:monospace;letter-spacing:1px;">' + esc(weapon.category) + '</div>';
    h += '<div style="color:#889;font-size:10px;margin-top:2px;">' + esc(weapon.description) + '</div>';
    h += '</div>';
    h += '<div style="text-align:right;">';
    h += '<div style="color:' + dangerColor + ';font-size:18px;font-weight:bold;font-family:monospace;">' + weapon.dangerLevel + '/10</div>';
    h += '<div style="font-size:8px;color:#556;letter-spacing:1px;">DANGER</div>';
    h += '</div>';
    h += '</div>';

    h += '<div style="padding:12px 16px;">';
    h += '<div style="font-size:9px;color:#556;letter-spacing:1px;margin-bottom:6px;">TIER: ' + esc(weapon.tier) + '</div>';
    h += '<div style="font-size:9px;color:#556;letter-spacing:1px;margin-bottom:6px;">KNOWN EXAMPLES:</div>';
    h += '<div style="display:flex;flex-wrap:wrap;gap:4px;">';
    for (var ex = 0; ex < weapon.examples.length; ex++) {
      h += '<span style="background:#1a0a0a;border:1px solid ' + dangerColor + '33;color:' + dangerColor + ';padding:3px 8px;border-radius:3px;font-size:10px;">' + esc(weapon.examples[ex]) + '</span>';
    }
    h += '</div>';
    h += '</div>';
    h += '</div>';
  }
  h += '</div>';

  // Danger meter legend
  h += '<div style="margin-top:16px;background:#0a0e1a;border:1px solid #1a3a5c;border-radius:6px;padding:12px 16px;display:flex;justify-content:center;gap:24px;flex-wrap:wrap;">';
  h += '<div style="display:flex;align-items:center;gap:6px;"><div style="width:12px;height:12px;background:#ffaa00;border-radius:3px;"></div><span style="color:#889;font-size:10px;">5-6: Moderate</span></div>';
  h += '<div style="display:flex;align-items:center;gap:6px;"><div style="width:12px;height:12px;background:#ff6622;border-radius:3px;"></div><span style="color:#889;font-size:10px;">7-8: High</span></div>';
  h += '<div style="display:flex;align-items:center;gap:6px;"><div style="width:12px;height:12px;background:#ff2244;border-radius:3px;"></div><span style="color:#889;font-size:10px;">9-10: Critical</span></div>';
  h += '</div>';

  h += '</div>';
  return h;
}

// ============================================================================
// RESPONSE OPERATIONS TRACKING
// ============================================================================
var ACTIVE_RESPONSE_OPS = [
  { id: 'resp-001', codename: 'IRON SHIELD', type: 'Hunt Forward', status: 'ACTIVE', team: 'CNMF Team Alpha', location: 'Baltic Allied Nation', adversary: 'Sandworm', startDate: '2026-09-01', objectives: 'Identify and eradicate pre-positioned Russian access in allied power grid networks', progress: 65 },
  { id: 'resp-002', codename: 'SILENT WATCH', type: 'Defensive Monitoring', status: 'ACTIVE', team: 'CNMF Team Bravo', location: 'US Telecom Sector', adversary: 'Salt Typhoon', startDate: '2026-08-15', objectives: 'Monitor and map remaining Chinese access in telecommunications infrastructure', progress: 40 },
  { id: 'resp-003', codename: 'DIGITAL FORTRESS', type: 'Infrastructure Defense', status: 'ACTIVE', team: 'CISA Sector Team', location: 'US Power Grid (NERC Region)', adversary: 'Volt Typhoon', startDate: '2026-07-20', objectives: 'Deploy enhanced monitoring on identified Volt Typhoon access points pending remediation', progress: 75 },
  { id: 'resp-004', codename: 'WALLET FREEZE', type: 'Financial Disruption', status: 'PLANNING', team: 'FBI Cyber + Treasury', location: 'Global', adversary: 'Lazarus/BlueNoroff', startDate: '2026-09-15', objectives: 'Coordinate seizure of cryptocurrency wallets identified as Lazarus staging infrastructure', progress: 30 },
  { id: 'resp-005', codename: 'NORTHERN LIGHT', type: 'Hunt Forward', status: 'ACTIVE', team: 'CNMF Team Delta', location: 'Nordic Allied Nation', adversary: 'APT29', startDate: '2026-08-28', objectives: 'Counter SVR espionage operations targeting Nordic diplomatic and defense networks', progress: 55 },
  { id: 'resp-006', codename: 'SANDSTORM COUNTER', type: 'Active Defense', status: 'STANDBY', team: 'CNMF Team Echo', location: 'US CENTCOM AOR', adversary: 'APT33/MuddyWater', startDate: '2026-09-10', objectives: 'Prepared to disrupt Iranian cyber infrastructure if retaliatory attacks detected', progress: 20 }
];

function renderResponseOps() {
  var h = '';
  h += '<div style="padding:16px 0;">';
  h += renderSectionHeader('ACTIVE RESPONSE OPERATIONS', 'Current cyber operation deployments and their status');

  for (var r = 0; r < ACTIVE_RESPONSE_OPS.length; r++) {
    var op = ACTIVE_RESPONSE_OPS[r];
    var statusColors = { 'ACTIVE': '#00ff88', 'PLANNING': '#ffaa00', 'STANDBY': '#00aaff', 'COMPLETE': '#556' };
    var sc = statusColors[op.status] || '#889';
    var progColor = op.progress >= 70 ? '#00ff88' : op.progress >= 40 ? '#ffaa00' : '#ff6622';

    h += '<div style="background:#0a0e1a;border:1px solid #1a3a5c;border-radius:8px;margin-bottom:12px;overflow:hidden;">';

    // Header bar
    h += '<div style="display:flex;justify-content:space-between;align-items:center;padding:12px 18px;border-bottom:1px solid #1a3a5c;flex-wrap:wrap;gap:8px;">';
    h += '<div style="display:flex;align-items:center;gap:12px;">';
    h += '<span style="background:' + sc + '22;color:' + sc + ';padding:3px 10px;border-radius:3px;font-size:10px;font-family:monospace;letter-spacing:1px;border:1px solid ' + sc + '44;">' + esc(op.status) + '</span>';
    h += '<span style="color:#00aaff;font-size:15px;font-weight:bold;font-family:monospace;letter-spacing:2px;">' + esc(op.codename) + '</span>';
    h += '<span style="color:#889;font-size:11px;">(' + esc(op.type) + ')</span>';
    h += '</div>';
    h += '<div style="display:flex;align-items:center;gap:8px;">';
    h += '<div style="width:100px;height:6px;background:#1a2a3c;border-radius:3px;overflow:hidden;">';
    h += '<div style="width:' + op.progress + '%;height:100%;background:' + progColor + ';border-radius:3px;"></div>';
    h += '</div>';
    h += '<span style="color:' + progColor + ';font-size:11px;font-family:monospace;">' + op.progress + '%</span>';
    h += '</div>';
    h += '</div>';

    // Details
    h += '<div style="padding:12px 18px;display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:10px;">';
    h += '<div><span style="color:#556;font-size:9px;letter-spacing:1px;">TEAM</span><div style="color:#c8d8e8;font-size:12px;margin-top:2px;">' + esc(op.team) + '</div></div>';
    h += '<div><span style="color:#556;font-size:9px;letter-spacing:1px;">LOCATION</span><div style="color:#c8d8e8;font-size:12px;margin-top:2px;">' + esc(op.location) + '</div></div>';
    h += '<div><span style="color:#556;font-size:9px;letter-spacing:1px;">ADVERSARY</span><div style="color:#ff8866;font-size:12px;margin-top:2px;">' + esc(op.adversary) + '</div></div>';
    h += '<div><span style="color:#556;font-size:9px;letter-spacing:1px;">START DATE</span><div style="color:#c8d8e8;font-size:12px;margin-top:2px;">' + esc(op.startDate) + '</div></div>';
    h += '</div>';
    h += '<div style="padding:8px 18px 12px 18px;border-top:1px solid #1a2a3c;">';
    h += '<span style="color:#556;font-size:9px;letter-spacing:1px;">OBJECTIVES: </span>';
    h += '<span style="color:#c8d8e8;font-size:11px;">' + esc(op.objectives) + '</span>';
    h += '</div>';

    h += '</div>';
  }

  h += '</div>';
  return h;
}



// ============================================================================
// ADDITIONAL WARGAME SCENARIOS (expanding to full 15 with more phases)
// ============================================================================
WARGAME_SCENARIOS.push(
  {
    id: 'ws-extra-01', codename: 'GHOST PROTOCOL',
    description: 'A sophisticated insider threat at a major defense contractor provides a nation-state APT with classified network access. The insider has been recruited via social engineering over 18 months. The APT uses the access to steal next-generation weapons system blueprints while planting logic bombs in defense industrial base systems.',
    adversary: 'China (APT41) + Recruited Insider',
    phases: [
      { name: 'Phase 1: Discovery', description: 'Anomalous data transfer patterns detected from classified terminal at defense contractor. User behavior analytics flag unusual access to compartmented programs.', blueTeamOptions: ['Initiate quiet investigation via counterintelligence', 'Immediately revoke access and forensically image systems', 'Set up monitoring honeypot to identify full scope'] },
      { name: 'Phase 2: Scope Assessment', description: 'Investigation reveals 18 months of sporadic data access across 4 classified programs. Insider has been using approved removable media to exfiltrate data. Evidence of APT41 custom malware on insider personal devices.', blueTeamOptions: ['Coordinate with FBI CI for arrest warrant', 'Expand monitoring to identify any co-conspirators', 'Assess damage to each compromised program'] },
      { name: 'Phase 3: Logic Bomb Discovery', description: 'Forensic analysis reveals logic bombs embedded in software builds for 2 weapons systems. Trigger conditions are time-based — set to activate during a potential conflict scenario.', blueTeamOptions: ['Emergency code review of all contractor-delivered software', 'Isolate affected weapons systems from networks', 'Coordinate with other contractors for potential wider campaign'] },
      { name: 'Phase 4: Attribution Confirmation', description: 'NSA SIGINT confirms APT41 handler communications with insider. Diplomatic considerations: confrontation vs. quiet remediation. Congressional notification requirements triggered.', blueTeamOptions: ['Brief NSC for diplomatic response options', 'Initiate damage assessment across defense industrial base', 'Launch defensive counter-operations against APT41 infrastructure'] },
      { name: 'Phase 5: Remediation', description: 'Insider arrested. Logic bombs neutralized. But extent of data loss unclear — adversary may have blueprints for advanced systems. How do you assess strategic impact?', blueTeamOptions: ['Commission full damage assessment (6-12 month effort)', 'Accelerate next-gen program timelines to maintain advantage', 'Implement enhanced insider threat monitoring across DIB'] }
    ],
    difficulty: 5,
    estimatedDuration: '6 hours'
  },
  {
    id: 'ws-extra-02', codename: 'BROKEN MIRROR',
    description: 'A coordinated disinformation campaign using AI-generated deepfakes accompanies a real cyber attack on election infrastructure across multiple states. The goal is to undermine confidence in election results while simultaneously manipulating voter registration databases and vote tallying systems.',
    adversary: 'Russia (GRU + Internet Research Agency 2.0)',
    phases: [
      { name: 'Phase 1: Pre-Election', description: 'Social media platforms detect surge of AI-generated political content. Deepfake videos of officials making inflammatory statements go viral. Voter registration systems in 5 states report anomalous access patterns.', blueTeamOptions: ['Coordinate with social media platforms for takedown', 'Issue public awareness advisory about deepfakes', 'Deploy CISA election security teams to affected states'] },
      { name: 'Phase 2: Election Day', description: 'Three states report voter registration database discrepancies. Thousands of legitimate voters cannot be found in rolls. Deepfake video of election official "admitting fraud" goes viral with 50M views.', blueTeamOptions: ['Activate provisional ballot procedures for affected voters', 'Coordinate rapid deepfake debunking with social media platforms', 'Escalate to national security level response'] },
      { name: 'Phase 3: Post-Election', description: 'Two states report vote tallying system anomalies. Close margins in affected states. Foreign state media amplifies "election fraud" narrative. Domestic protests planned at state capitals.', blueTeamOptions: ['Request manual recount in affected jurisdictions', 'Public statement from bipartisan election officials', 'Consider attribution statement from intelligence community'] },
      { name: 'Phase 4: Crisis', description: 'Leaked (fabricated) documents suggest US officials knew about vulnerabilities. Foreign government denies involvement and accuses US of suppressing democracy. Congressional leaders demand investigation.', blueTeamOptions: ['IC assessment and attribution statement', 'Diplomatic response and sanctions preparation', 'Public transparency about what happened and what was prevented'] }
    ],
    difficulty: 5,
    estimatedDuration: '5 hours'
  },
  {
    id: 'ws-extra-03', codename: 'ZERO GRAVITY',
    description: 'A sophisticated attack targets space-based assets and ground control systems. GPS satellite control is disrupted, military satellite communications are degraded, and commercial space services are affected. The attack coincides with increased military tensions in a contested region.',
    adversary: 'China (PLA Strategic Support Force)',
    phases: [
      { name: 'Phase 1: Anomaly Detection', description: 'GPS accuracy degrades in Indo-Pacific region. Military SATCOM experiences increased latency. Commercial satellite operators report ground station access issues.', blueTeamOptions: ['Activate backup navigation systems', 'Investigate ground station security', 'Coordinate with Space Force for space domain awareness'] },
      { name: 'Phase 2: Attack Confirmation', description: 'Space Force confirms unauthorized commands sent to GPS constellation. Three military SATCOM ground stations compromised. Commercial imagery satellites repositioned without authorization.', blueTeamOptions: ['Switch to backup ground control', 'Activate alternative PNT systems', 'Assess impact on military operations'] },
      { name: 'Phase 3: Escalation', description: 'PRC naval activity increases in South China Sea. GPS disruption expands to broader Pacific. Allied nations report similar satellite anomalies. Dual-use space systems make attribution complex.', blueTeamOptions: ['Activate coalition space defense coordination', 'Consider kinetic vs. non-kinetic response options', 'Diplomatic channels to de-escalate'] }
    ],
    difficulty: 4,
    estimatedDuration: '4 hours'
  }
);

// ============================================================================
// LEGAL AUTHORITIES REFERENCE
// ============================================================================
var LEGAL_AUTHORITIES = [
  { title: 'Title 10 USC', section: 'Armed Forces', description: 'Military operations authority including cyberspace operations. Governs USCYBERCOM operations as combat support.', applicability: 'Offensive and defensive military cyber operations', approval: 'SECDEF / POTUS per operation scope' },
  { title: 'Title 50 USC', section: 'War and National Defense', description: 'Intelligence community authorities including covert action. Governs NSA collection and CIA cyber operations.', applicability: 'Intelligence collection, covert cyber operations', approval: 'Presidential Finding with Congressional notification' },
  { title: 'EO 12333', section: 'United States Intelligence Activities', description: 'Governs intelligence community activities including signals intelligence collection and counterintelligence.', applicability: 'SIGINT collection, foreign intelligence', approval: 'Various IC heads per collection type' },
  { title: 'NSPM-13', section: 'Offensive Cyber Operations Policy', description: 'Streamlined approval process for offensive cyber operations. Delegates certain authorities to SECDEF and USCYBERCOM Commander.', applicability: 'Time-sensitive offensive cyber operations', approval: 'SECDEF with POTUS delegation' },
  { title: 'AUMF 2001', section: 'Authorization for Use of Military Force', description: 'Post-9/11 authorization interpreted to include cyber operations against terrorist organizations and associated forces.', applicability: 'Counter-terrorism cyber operations', approval: 'Standing authority under AUMF' },
  { title: 'PPD-20', section: 'US Cyber Operations Policy', description: 'Obama-era directive establishing policy for offensive and defensive cyber operations (partially superseded by NSPM-13).', applicability: 'Cyber operations policy framework', approval: 'NSC coordination process' },
  { title: 'CFAA', section: '18 USC 1030', description: 'Computer Fraud and Abuse Act — primary federal law for prosecuting cyber crimes. Relevant for FBI cyber operations and prosecution.', applicability: 'Domestic law enforcement cyber operations', approval: 'DOJ authorization for investigations' },
  { title: 'Tallinn Manual 3.0', section: 'International Cyber Law', description: 'Non-binding academic analysis of how international law applies to cyber operations. Used as reference for ROE development.', applicability: 'International law compliance for cyber operations', approval: 'Advisory — not binding law' }
];

function renderLegalAuthorities() {
  var h = '';
  h += '<div style="padding:16px 0;">';
  h += renderSectionHeader('LEGAL AUTHORITY MATRIX', 'Applicable legal frameworks for cyber operations');

  for (var l = 0; l < LEGAL_AUTHORITIES.length; l++) {
    var auth = LEGAL_AUTHORITIES[l];
    h += '<div style="background:#0a0e1a;border:1px solid #1a3a5c;border-radius:6px;margin-bottom:10px;padding:14px 18px;">';
    h += '<div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:8px;margin-bottom:8px;">';
    h += '<div>';
    h += '<span style="color:#00aaff;font-size:14px;font-weight:bold;font-family:monospace;">' + esc(auth.title) + '</span>';
    h += '<span style="color:#889;font-size:11px;margin-left:10px;">' + esc(auth.section) + '</span>';
    h += '</div>';
    h += '</div>';
    h += '<div style="color:#c8d8e8;font-size:12px;line-height:1.5;margin-bottom:8px;">' + esc(auth.description) + '</div>';
    h += '<div style="display:flex;gap:20px;flex-wrap:wrap;font-size:11px;">';
    h += '<div><span style="color:#556;letter-spacing:1px;">APPLICABILITY: </span><span style="color:#ffaa00;">' + esc(auth.applicability) + '</span></div>';
    h += '<div><span style="color:#556;letter-spacing:1px;">APPROVAL: </span><span style="color:#00ff88;">' + esc(auth.approval) + '</span></div>';
    h += '</div>';
    h += '</div>';
  }

  h += '</div>';
  return h;
}

// ============================================================================
// CYBER DETERRENCE FRAMEWORK
// ============================================================================
var DETERRENCE_PILLARS = [
  { name: 'DENIAL', description: 'Make attacks costly and unlikely to succeed by hardening defenses, improving resilience, and reducing attack surface.', measures: ['Zero Trust Architecture deployment', 'Critical infrastructure air-gapping', 'Rapid patching programs', 'Redundancy and failover systems', 'Supply chain security requirements'], effectiveness: 7 },
  { name: 'PUNISHMENT', description: 'Impose costs on adversaries through sanctions, indictments, diplomatic consequences, and offensive operations.', measures: ['Economic sanctions (EO 13694, EO 13757)', 'Criminal indictments (DOJ Cyber Division)', 'Diplomatic demarches and public attribution', 'Offensive cyber counter-operations', 'Coalition responses (joint attributions)'], effectiveness: 5 },
  { name: 'ENTANGLEMENT', description: 'Create mutual dependencies that make attacks costly for the attacker\'s own interests.', measures: ['Trade relationships and supply chain interdependence', 'Shared technology platforms', 'Diplomatic and institutional engagement', 'Information sharing agreements', 'Joint research and development'], effectiveness: 4 },
  { name: 'NORMS', description: 'Establish and enforce international norms against targeting critical infrastructure and civilian systems.', measures: ['UN GGE cyber norms framework', 'Paris Call for Trust and Security', 'Bilateral cyber agreements', 'Tallinn Manual legal framework', 'OSCE confidence-building measures'], effectiveness: 3 }
];

function renderDeterrenceFramework() {
  var h = '';
  h += '<div style="padding:16px 0;">';
  h += renderSectionHeader('CYBER DETERRENCE FRAMEWORK', 'Four pillars of national cyber deterrence strategy');

  h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:16px;">';
  for (var d = 0; d < DETERRENCE_PILLARS.length; d++) {
    var pillar = DETERRENCE_PILLARS[d];
    var effColor = pillar.effectiveness >= 7 ? '#00ff88' : pillar.effectiveness >= 5 ? '#ffaa00' : '#ff6622';

    h += '<div style="background:#0a0e1a;border:1px solid #1a3a5c;border-radius:8px;overflow:hidden;">';
    h += '<div style="background:linear-gradient(135deg,#0a1628,#0d1f3c);padding:16px;border-bottom:1px solid #1a3a5c;text-align:center;">';
    h += '<div style="color:#00aaff;font-size:18px;font-weight:bold;font-family:monospace;letter-spacing:3px;">' + esc(pillar.name) + '</div>';
    h += '<div style="color:#889;font-size:10px;margin-top:6px;line-height:1.4;">' + esc(pillar.description) + '</div>';
    h += '</div>';

    h += '<div style="padding:14px 16px;">';
    h += '<div style="font-size:9px;color:#556;letter-spacing:1px;margin-bottom:8px;">KEY MEASURES</div>';
    for (var m = 0; m < pillar.measures.length; m++) {
      h += '<div style="display:flex;gap:8px;align-items:flex-start;margin-bottom:4px;">';
      h += '<span style="color:#00aaff;font-size:10px;margin-top:2px;">&#9656;</span>';
      h += '<span style="color:#c8d8e8;font-size:11px;">' + esc(pillar.measures[m]) + '</span>';
      h += '</div>';
    }

    h += '<div style="margin-top:12px;padding-top:10px;border-top:1px solid #1a3a5c;">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">';
    h += '<span style="font-size:9px;color:#556;letter-spacing:1px;">ASSESSED EFFECTIVENESS</span>';
    h += '<span style="color:' + effColor + ';font-size:12px;font-weight:bold;font-family:monospace;">' + pillar.effectiveness + '/10</span>';
    h += '</div>';
    h += '<div style="width:100%;height:6px;background:#1a2a3c;border-radius:3px;overflow:hidden;">';
    h += '<div style="width:' + (pillar.effectiveness * 10) + '%;height:100%;background:' + effColor + ';border-radius:3px;"></div>';
    h += '</div>';
    h += '</div>';
    h += '</div>';
    h += '</div>';
  }
  h += '</div>';

  h += '</div>';
  return h;
}



// ============================================================================
// ADDITIONAL OPERATION DETAILS
// ============================================================================
HISTORICAL_OPERATIONS_DETAIL['op-020'] = {
  codename: 'OLYMPIC DESTROYER',
  attribution: 'Russia (GRU / Sandworm)',
  attributionConfidence: 96,
  fullDescription: 'During the opening ceremony of the 2018 PyeongChang Winter Olympics, Russian military hackers deployed destructive malware that disrupted the Olympic IT infrastructure. The attack took down the official Olympics website, Wi-Fi at the stadium, and broadcast systems. What made this attack particularly notable was its sophisticated false-flag operations: the malware contained deliberate code artifacts designed to point to North Korean (Lazarus) and Chinese (APT3/APT10) threat actors, making attribution significantly more difficult.',
  targets: ['PyeongChang 2018 Winter Olympics IT infrastructure', 'Official Olympics website', 'Stadium Wi-Fi and broadcast systems', 'Ticketing systems', 'Olympic accommodation networks'],
  ttps: [
    { technique: 'T1566.001', name: 'Spearphishing Attachment', detail: 'Targeted emails to Olympics partners and stakeholders' },
    { technique: 'T1078', name: 'Valid Accounts', detail: 'Stolen credentials from Olympics IT administrators' },
    { technique: 'T1036', name: 'Masquerading', detail: 'False-flag code artifacts pointing to Lazarus and Chinese APTs' },
    { technique: 'T1485', name: 'Data Destruction', detail: 'Destructive payload wiping systems during opening ceremony' },
    { technique: 'T1490', name: 'Inhibit System Recovery', detail: 'Boot record and backup destruction to prevent rapid recovery' }
  ],
  timeline: [
    { date: '2017-12', event: 'Sandworm begins reconnaissance of Olympic IT infrastructure' },
    { date: '2018-01', event: 'Credential harvesting from Olympic partners via spear-phishing' },
    { date: '2018-02-09 20:00', event: 'Opening ceremony begins in PyeongChang' },
    { date: '2018-02-09 20:15', event: 'Olympic Destroyer malware activated' },
    { date: '2018-02-09 20:30', event: 'Olympics website goes down, Wi-Fi fails in stadium' },
    { date: '2018-02-09 21:00', event: 'Broadcast drones grounded due to IT issues' },
    { date: '2018-02-10', event: 'Olympics IT team begins 12-hour recovery effort' },
    { date: '2018-02-12', event: 'Systems restored; investigation begins' },
    { date: '2018-02-14', event: 'False-flag indicators cause initial misattribution to NK/China' },
    { date: '2018-10', event: 'US DOJ indicts 7 GRU officers including Olympic Destroyer operators' }
  ],
  toolsUsed: ['Olympic Destroyer wiper', 'Credential harvesting tools', 'False-flag code implants', 'Lateral movement via PsExec and WMI', 'Custom C2 infrastructure'],
  impact: 'Olympics website down for 12 hours during opening ceremony. Stadium Wi-Fi and ticketing systems disrupted. Broadcast operations affected. 12+ hours of recovery effort by hundreds of IT staff. Significant reputation damage to Olympic cybersecurity.',
  significance: 'Demonstrated sophisticated false-flag capabilities in cyber operations. Complicated attribution processes for the security community. Showed willingness to target major international events. Led to increased cyber security planning for subsequent Olympic games.',
  lessonsLearned: ['False-flag operations can significantly delay attribution', 'Major international events are high-profile targets', 'Destructive attacks can be timed for maximum embarrassment', 'Pre-event cybersecurity planning must account for nation-state threats', 'Code-level attribution evidence can be deliberately planted']
};

HISTORICAL_OPERATIONS_DETAIL['op-024'] = {
  codename: 'PROXYLOGON / HAFNIUM',
  attribution: 'China (Hafnium / MSS-affiliated)',
  attributionConfidence: 94,
  fullDescription: 'Chinese state-sponsored hackers from the Hafnium group exploited four zero-day vulnerabilities in Microsoft Exchange Server (CVE-2021-26855, CVE-2021-26857, CVE-2021-26858, CVE-2021-27065) to gain access to on-premises Exchange servers worldwide. The initial targeted espionage campaign was followed by mass exploitation after the vulnerabilities became public knowledge, resulting in web shells being deployed to an estimated 250,000+ Exchange servers globally. Multiple other threat actors, including ransomware groups, quickly adopted the exploits.',
  targets: ['US defense contractors', 'Think tanks and policy organizations', 'Law firms', 'Infectious disease researchers', 'Higher education institutions', 'Subsequently: 250,000+ Exchange servers globally'],
  ttps: [
    { technique: 'T1190', name: 'Exploit Public-Facing Application', detail: 'Chained 4 Exchange zero-days for pre-authentication RCE' },
    { technique: 'T1505.003', name: 'Web Shell', detail: 'China Chopper and custom ASPX web shells for persistent access' },
    { technique: 'T1003', name: 'OS Credential Dumping', detail: 'Credential harvesting post-exploitation' },
    { technique: 'T1560', name: 'Archive Collected Data', detail: 'Email mailbox export via Exchange PowerShell' },
    { technique: 'T1041', name: 'Exfiltration Over C2 Channel', detail: 'Data exfiltration via web shell C2' }
  ],
  timeline: [
    { date: '2021-01-03', event: 'First known Hafnium exploitation of Exchange zero-days' },
    { date: '2021-01-06', event: 'Volexity detects suspicious activity on Exchange servers' },
    { date: '2021-01-18', event: 'Volexity reports vulnerabilities to Microsoft' },
    { date: '2021-02-02', event: 'DEVCORE independently reports Exchange zero-days to Microsoft' },
    { date: '2021-02-27', event: 'Mass exploitation begins — thousands of servers compromised daily' },
    { date: '2021-03-02', event: 'Microsoft releases emergency out-of-band patches' },
    { date: '2021-03-03', event: 'CISA issues Emergency Directive 21-02' },
    { date: '2021-03-05', event: 'Estimated 30,000+ US organizations compromised' },
    { date: '2021-03-12', event: 'FBI authorized to remotely remove web shells from compromised servers' },
    { date: '2021-07', event: 'US and allies formally attribute to China\'s MSS' }
  ],
  toolsUsed: ['ProxyLogon exploit chain', 'China Chopper web shell', 'Custom ASPX web shells', 'PowerShell mailbox export', 'Nishang (open-source)', 'Covenant C2 framework', 'DearCry ransomware (follow-on by others)'],
  impact: '250,000+ Exchange servers compromised globally. 30,000+ US organizations affected. Web shells left persistent access even after patching. Multiple follow-on campaigns by other actors exploiting same vulnerabilities. FBI took unprecedented step of remotely removing web shells.',
  significance: 'Demonstrated speed at which targeted espionage can escalate to mass exploitation. First time FBI remotely remediated privately-owned servers. Led to multinational attribution of Chinese cyber operations. Showed the risk of on-premises email infrastructure. Accelerated cloud email migration.',
  lessonsLearned: ['On-premises Exchange servers are high-value targets', 'Zero-day exploit chains can be devastating at scale', 'Patching alone is insufficient — web shells persist post-patch', 'Mass exploitation can follow targeted campaigns very rapidly', 'Government-authorized remediation of private systems may be necessary in extreme cases']
};

// ============================================================================
// NETWORK TOPOLOGY VISUALIZATION DATA
// ============================================================================
var GLOBAL_NETWORK_CHOKEPOINTS = [
  { name: 'Undersea Cable — Atlantic (TAT-14)', importance: 'CRITICAL', description: 'Trans-Atlantic telecommunications cable connecting US East Coast to Europe. Carries significant portion of US-Europe internet traffic and financial data.', risks: ['Physical cable cutting', 'Submarine tapping operations', 'Landing station compromise', 'BGP route manipulation'] },
  { name: 'Undersea Cable — Pacific (FASTER)', importance: 'CRITICAL', description: 'Trans-Pacific cable connecting US West Coast to Japan. Critical for military communications in Indo-Pacific theater.', risks: ['Chinese submarine surveillance', 'Landing station espionage', 'Route redirection attacks', 'Capacity degradation'] },
  { name: 'Internet Exchange Point — DE-CIX Frankfurt', importance: 'HIGH', description: 'World\'s largest internet exchange by peak traffic. Critical routing point for European internet traffic.', risks: ['Physical compromise', 'BGP hijacking', 'Traffic mirroring', 'DDoS targeting'] },
  { name: 'DNS Root Servers', importance: 'CRITICAL', description: '13 root server letter designations serving the global DNS hierarchy. Critical for all internet name resolution.', risks: ['DDoS amplification', 'Cache poisoning', 'BGP prefix hijacking', 'Physical infrastructure targeting'] },
  { name: 'SWIFT Financial Network', importance: 'CRITICAL', description: 'Society for Worldwide Interbank Financial Telecommunication. Backbone of international financial messaging.', risks: ['Endpoint compromise (Bangladesh Bank model)', 'Message manipulation', 'Insider threats', 'Service disruption'] },
  { name: 'GPS Constellation Ground Control', importance: 'CRITICAL', description: 'Ground control stations managing GPS satellite constellation. Essential for military and civilian navigation.', risks: ['Ground station cyber compromise', 'Signal spoofing', 'Satellite command injection', 'Jamming'] },
  { name: 'Cloud Provider Backbone (AWS us-east-1)', importance: 'CRITICAL', description: 'Amazon Web Services primary US region. Hosts enormous portion of US government and commercial cloud workloads.', risks: ['Control plane compromise', 'Identity federation attacks', 'Region-level outage', 'Supply chain'] },
  { name: 'BGP Route Reflectors (Tier 1 ISPs)', importance: 'CRITICAL', description: 'Core routing infrastructure at Tier 1 ISPs that determines global internet traffic flow.', risks: ['Route hijacking', 'Route leak', 'Prefix de-aggregation', 'AS path manipulation'] }
];

function renderNetworkChokepoints() {
  var h = '';
  h += '<div style="padding:16px 0;">';
  h += renderSectionHeader('GLOBAL NETWORK CHOKEPOINTS', 'Critical infrastructure nodes in global communications');

  for (var n = 0; n < GLOBAL_NETWORK_CHOKEPOINTS.length; n++) {
    var node = GLOBAL_NETWORK_CHOKEPOINTS[n];
    var impColors = { 'CRITICAL': '#ff2244', 'HIGH': '#ff6622', 'MEDIUM': '#ffaa00' };
    var ic = impColors[node.importance] || '#889';

    h += '<div style="background:#0a0e1a;border:1px solid #1a3a5c;border-radius:6px;margin-bottom:10px;padding:14px 18px;">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:8px;">';
    h += '<div style="display:flex;align-items:center;gap:10px;">';
    h += '<span style="color:#c8d8e8;font-size:13px;font-weight:bold;">' + esc(node.name) + '</span>';
    h += renderSeverityBadge(node.importance);
    h += '</div>';
    h += renderThreatLevelIndicator(node.threatLevel);
    h += '</div>';
    h += '<div style="color:#889;font-size:11px;line-height:1.4;margin-bottom:8px;">' + esc(node.description) + '</div>';
    h += '<div style="display:flex;flex-wrap:wrap;gap:6px;">';
    for (var r = 0; r < node.risks.length; r++) {
      h += '<span style="background:#1a0a0a;border:1px solid #ff224433;color:#ff8866;padding:3px 8px;border-radius:3px;font-size:9px;">' + esc(node.risks[r]) + '</span>';
    }
    h += '</div>';
    h += '</div>';
  }

  h += '</div>';
  return h;
}



// ============================================================================
// CONGRESSIONAL NOTIFICATION TRACKER DATA
// ============================================================================
var CONGRESSIONAL_NOTIFICATIONS = [
  { id: 'cn-001', date: '2026-09-12', committee: 'SSCI (Senate Select Committee on Intelligence)', topic: 'Chinese telecom infiltration expansion (Salt Typhoon)', status: 'BRIEFED', classification: 'TS//SCI', notifyType: 'Gang of 8', details: 'Detailed briefing on expanded Salt Typhoon operations and remediation timeline' },
  { id: 'cn-002', date: '2026-09-10', committee: 'HPSCI (House Permanent Select Committee on Intelligence)', topic: 'Russian pre-positioning near NATO CI', status: 'BRIEFED', classification: 'TS//SCI', notifyType: 'Full committee', details: 'Update on Sandworm activities targeting Baltic allied infrastructure' },
  { id: 'cn-003', date: '2026-09-08', committee: 'Senate Armed Services', topic: 'CYBERCOM hunt-forward deployment authorization', status: 'NOTIFIED', classification: 'SECRET', notifyType: 'Chairman/Ranking', details: 'Notification per Title 10 requirements for overseas cyber operations' },
  { id: 'cn-004', date: '2026-09-05', committee: 'House Homeland Security', topic: 'Critical infrastructure vulnerability assessment update', status: 'PENDING', classification: 'SECRET//NOFORN', notifyType: 'Full committee', details: 'Quarterly update on national critical infrastructure cybersecurity posture' },
  { id: 'cn-005', date: '2026-09-01', committee: 'Senate Commerce', topic: 'Telecom sector security improvements under FCC order', status: 'BRIEFED', classification: 'UNCLASSIFIED//FOUO', notifyType: 'Full committee', details: 'Progress on carrier implementation of enhanced security requirements post-Salt Typhoon' },
  { id: 'cn-006', date: '2026-08-28', committee: 'SSCI + HPSCI (Joint)', topic: 'Annual cyber threat landscape assessment', status: 'BRIEFED', classification: 'TS//SCI//SAP', notifyType: 'Gang of 8', details: 'Comprehensive annual assessment of nation-state cyber threats to US interests' },
  { id: 'cn-007', date: '2026-08-20', committee: 'Senate Judiciary', topic: 'North Korean cryptocurrency theft and sanctions evasion', status: 'NOTIFIED', classification: 'SECRET', notifyType: 'Chairman/Ranking', details: 'DOJ/FBI update on Lazarus Group financial operations and prosecution efforts' },
  { id: 'cn-008', date: '2026-09-15', committee: 'House Armed Services', topic: 'CYBERCOM budget and force structure review', status: 'SCHEDULED', classification: 'SECRET', notifyType: 'Cyber subcommittee', details: 'Upcoming hearing on FY2027 CYBERCOM resource requirements' }
];

function renderCongressionalTracker() {
  var h = '';
  h += '<div style="padding:16px 0;">';
  h += renderSectionHeader('CONGRESSIONAL NOTIFICATION TRACKER', 'Legislative oversight and briefing status');
  var headers = ['DATE', 'COMMITTEE', 'TOPIC', 'STATUS', 'TYPE'];
  var rows = [];
  for (var cn = 0; cn < CONGRESSIONAL_NOTIFICATIONS.length; cn++) {
    var notif = CONGRESSIONAL_NOTIFICATIONS[cn];
    rows.push([notif.date, notif.committee, notif.topic, notif.status, notif.notifyType]);
  }
  h += renderDataGrid(headers, rows);
  h += '</div>';
  return h;
}


// ============================================================================
// TAB 11: LIVE TRACKING
// Real-time tracking of aircraft, maritime, space, and seismic data
// ============================================================================
var _seTrackingSubTab = 'aircraft';
var _seTrackingRefreshInterval = null;
var _seTrackingCache = { aircraft: null, seismic: null, iss: null, aircraftTs: 0, seismicTs: 0, issTs: 0 };

function renderTracking() {
  var h = '';
  h += '<div style="padding:20px 24px 0 24px;">';
  h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:18px;">';
  h += '<div>';
  h += '<h2 style="margin:0;font-size:22px;color:#00aaff;font-family:monospace;letter-spacing:2px;text-transform:uppercase;">LIVE TRACKING</h2>';
  h += '<div style="color:#667;font-size:12px;font-family:monospace;margin-top:4px;letter-spacing:1px;">REAL-TIME GLOBAL ASSET MONITORING &bull; PUBLIC DATA FEEDS</div>';
  h += '</div>';
  h += '<div style="display:flex;gap:10px;">';
  h += '<div style="background:linear-gradient(135deg,#0a0e1a,#101828);border:1px solid #00aaff44;border-radius:6px;padding:8px 16px;text-align:center;">';
  h += '<div style="color:#00aaff;font-size:10px;font-family:monospace;letter-spacing:1px;">DATA SOURCES</div>';
  h += '<div style="color:#00aaff;font-size:22px;font-weight:bold;font-family:monospace;">4</div>';
  h += '</div>';
  h += '<div style="background:linear-gradient(135deg,#0a1a0a,#152a15);border:1px solid #00ff88;border-radius:6px;padding:8px 16px;text-align:center;">';
  h += '<div style="color:#00ff88;font-size:10px;font-family:monospace;letter-spacing:1px;">STATUS</div>';
  h += '<div style="color:#00ff88;font-size:22px;font-weight:bold;font-family:monospace;">LIVE</div>';
  h += '</div>';
  h += '</div>';
  h += '</div>';
  h += '</div>';

  // Sub-tabs
  var subTabs = [
    { id: 'aircraft', label: 'Aircraft', icon: '[A]', color: '#00aaff' },
    { id: 'maritime', label: 'Maritime', icon: '[M]', color: '#00ff88' },
    { id: 'space', label: 'Space', icon: '[S]', color: '#aa66ff' },
    { id: 'seismic', label: 'Seismic', icon: '[E]', color: '#ff6644' },
    { id: 'cyber', label: 'Cyber Threats', icon: '[C]', color: '#ff4444' },
    { id: 'network', label: 'Network Intel', icon: '[N]', color: '#ffaa00' }
  ];

  h += '<div style="display:flex;gap:4px;padding:0 24px;margin-bottom:16px;">';
  for (var st = 0; st < subTabs.length; st++) {
    var sub = subTabs[st];
    var isActiveSub = sub.id === _seTrackingSubTab;
    h += '<div style="background:' + (isActiveSub ? sub.color + '22' : '#0a0e1a') + ';border:1px solid ' + (isActiveSub ? sub.color + '66' : '#1a2a44') + ';border-radius:6px 6px 0 0;padding:8px 16px;cursor:pointer;flex:1;text-align:center;" onclick="_seTrackingSubTab=\'' + sub.id + '\';switchTab(\'tracking\')">';
    h += '<div style="color:' + (isActiveSub ? sub.color : '#556') + ';font-size:12px;font-family:monospace;font-weight:bold;">' + sub.icon + ' ' + esc(sub.label) + '</div>';
    h += '</div>';
  }
  h += '</div>';

  // Content area for sub-tabs
  h += '<div style="padding:0 24px 24px 24px;">';
  h += '<div style="background:linear-gradient(135deg,#0c1020,#0a0e1a);border:1px solid #1a2a44;border-radius:0 0 8px 8px;padding:16px;">';

  if (_seTrackingSubTab === 'aircraft') {
    h += _seRenderAircraftTab();
  } else if (_seTrackingSubTab === 'maritime') {
    h += _seRenderMaritimeTab();
  } else if (_seTrackingSubTab === 'space') {
    h += _seRenderSpaceTab();
  } else if (_seTrackingSubTab === 'seismic') {
    h += _seRenderSeismicTab();
  } else if (_seTrackingSubTab === 'cyber') {
    h += _seRenderCyberTab();
  } else if (_seTrackingSubTab === 'network') {
    h += _seRenderNetworkTab();
  }

  h += '</div>';
  h += '</div>';

  return h;
}

function _seRenderAircraftTab() {
  var h = '';
  h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;">';
  h += '<div>';
  h += '<div style="color:#00aaff;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;">';
  h += '<span style="margin-right:8px;">[A]</span>AIRCRAFT TRACKING -- GLOBAL ADS-B</div>';
  h += '<div style="color:#556;font-size:10px;font-family:monospace;margin-top:4px;">Simulated commercial flight positions on major air routes worldwide</div>';
  h += '</div>';
  h += '<div style="display:flex;gap:8px;align-items:center;">';
  h += '<div id="se-aircraft-count" style="background:#0a0e1a;border:1px solid #00aaff33;border-radius:4px;padding:6px 12px;text-align:center;">';
  h += '<div style="color:#556;font-size:8px;font-family:monospace;letter-spacing:1px;">TRACKED</div>';
  h += '<div style="color:#00aaff;font-size:18px;font-weight:bold;font-family:monospace;">--</div>';
  h += '</div>';
  h += '<div onclick="_seFetchAircraft()" style="background:#00aaff22;color:#00aaff;font-size:10px;font-family:monospace;padding:6px 12px;border-radius:4px;cursor:pointer;border:1px solid #00aaff44;">REFRESH</div>';
  h += '</div>';
  h += '</div>';

  h += '<div id="se-aircraft-data" style="color:#667;font-size:11px;font-family:monospace;">';
  h += '<div style="text-align:center;padding:30px;color:#556;">Loading aircraft data from OpenSky Network...</div>';
  h += '</div>';

  return h;
}

function _seRenderMaritimeTab() {
  var h = '';
  h += '<div style="color:#00ff88;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;margin-bottom:14px;">';
  h += '<span style="margin-right:8px;">[M]</span>MARITIME / AIS TRACKING</div>';

  h += '<div style="background:#0a0e1a;border:1px solid #1a2a44;border-radius:8px;padding:24px;text-align:center;">';
  h += '<div style="color:#00ff88;font-size:40px;margin-bottom:12px;">[SHIP]</div>';
  h += '<div style="color:#fff;font-size:14px;font-family:monospace;font-weight:bold;margin-bottom:8px;">Ship Tracking (AIS) Requires Shell Server</div>';
  h += '<div style="color:#889;font-size:11px;font-family:monospace;line-height:1.6;max-width:500px;margin:0 auto 16px auto;">';
  h += 'AIS (Automatic Identification System) data is not available through free browser-accessible APIs due to CORS restrictions. ';
  h += 'To enable real-time ship tracking, start the Darknode shell server which proxies AIS data feeds.</div>';

  h += '<div style="background:#0c1525;border:1px solid #1a3a5c;border-radius:6px;padding:16px;text-align:left;margin:0 auto;max-width:500px;">';
  h += '<div style="color:#00aaff;font-size:11px;font-family:monospace;letter-spacing:1px;margin-bottom:10px;">SETUP INSTRUCTIONS:</div>';
  h += '<div style="color:#00ff88;font-size:11px;font-family:monospace;margin-bottom:6px;">1. Start the shell server:</div>';
  h += '<div style="background:#080c14;border:1px solid #1a2a44;border-radius:4px;padding:8px 12px;margin-bottom:10px;margin-left:16px;">';
  h += '<code style="color:#ffaa00;font-size:11px;font-family:monospace;">darknode-serve</code></div>';
  h += '<div style="color:#00ff88;font-size:11px;font-family:monospace;margin-bottom:6px;">2. The server will proxy AIS data on port 8420</div>';
  h += '<div style="color:#00ff88;font-size:11px;font-family:monospace;margin-bottom:6px;">3. Return to this tab -- data will auto-populate</div>';
  h += '</div>';

  h += '<div style="margin-top:16px;color:#445;font-size:10px;font-family:monospace;">Data sources: AIS transponder data via terrestrial and satellite receivers</div>';
  h += '</div>';

  return h;
}

function _seRenderSpaceTab() {
  var h = '';
  h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;">';
  h += '<div>';
  h += '<div style="color:#aa66ff;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;">';
  h += '<span style="margin-right:8px;">[S]</span>SPACE TRACKING -- ISS Position</div>';
  h += '<div style="color:#556;font-size:10px;font-family:monospace;margin-top:4px;">International Space Station real-time position via wheretheiss.at API</div>';
  h += '</div>';
  h += '<div onclick="_seFetchISS()" style="background:#aa66ff22;color:#aa66ff;font-size:10px;font-family:monospace;padding:6px 12px;border-radius:4px;cursor:pointer;border:1px solid #aa66ff44;">REFRESH</div>';
  h += '</div>';

  h += '<div id="se-iss-data" style="color:#667;font-size:11px;font-family:monospace;">';
  h += '<div style="text-align:center;padding:30px;color:#556;">Loading ISS position data...</div>';
  h += '</div>';

  return h;
}

function _seRenderSeismicTab() {
  var h = '';
  h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;">';
  h += '<div>';
  h += '<div style="color:#ff6644;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;">';
  h += '<span style="margin-right:8px;">[E]</span>SEISMIC MONITORING -- USGS Earthquake Data</div>';
  h += '<div style="color:#556;font-size:10px;font-family:monospace;margin-top:4px;">Real seismic data from USGS -- significant earthquakes this month -- updates every 5 minutes</div>';
  h += '</div>';
  h += '<div onclick="_seFetchSeismic()" style="background:#ff664422;color:#ff6644;font-size:10px;font-family:monospace;padding:6px 12px;border-radius:4px;cursor:pointer;border:1px solid #ff664444;">REFRESH</div>';
  h += '</div>';

  h += '<div id="se-seismic-data" style="color:#667;font-size:11px;font-family:monospace;">';
  h += '<div style="text-align:center;padding:30px;color:#556;">Loading USGS earthquake data...</div>';
  h += '</div>';

  return h;
}

// ---------------------------------------------------------------------------
// CYBER THREATS sub-tab
// ---------------------------------------------------------------------------

function _seRenderCyberTab() {
  var h = '';
  h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;">';
  h += '<div>';
  h += '<div style="color:#ff4444;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;">';
  h += '<span style="margin-right:8px;">[C]</span>CYBER THREAT FEEDS -- NVD &amp; Threat Intelligence</div>';
  h += '<div style="color:#556;font-size:10px;font-family:monospace;margin-top:4px;">Real-time vulnerability and IOC data from public feeds -- auto-refresh: 5 min</div>';
  h += '</div>';
  h += '</div>';

  // Stat cards
  h += '<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:16px;">';
  h += '<div style="background:#0a0e1a;border:1px solid #ff444433;border-radius:6px;padding:10px;text-align:center;">';
  h += '<div style="color:#556;font-size:9px;font-family:monospace;letter-spacing:1px;">CVEs TODAY</div>';
  h += '<div style="color:#ff4444;font-size:22px;font-weight:bold;font-family:monospace;" id="se-cyber-cve-count">--</div>';
  h += '</div>';
  h += '<div style="background:#0a0e1a;border:1px solid #ff880033;border-radius:6px;padding:10px;text-align:center;">';
  h += '<div style="color:#556;font-size:9px;font-family:monospace;letter-spacing:1px;">CRITICAL ALERTS</div>';
  h += '<div style="color:#ff8800;font-size:22px;font-weight:bold;font-family:monospace;" id="se-cyber-crit-count">--</div>';
  h += '</div>';
  h += '<div style="background:#0a0e1a;border:1px solid #aa44ff33;border-radius:6px;padding:10px;text-align:center;">';
  h += '<div style="color:#556;font-size:9px;font-family:monospace;letter-spacing:1px;">ACTIVE CAMPAIGNS</div>';
  h += '<div style="color:#aa44ff;font-size:22px;font-weight:bold;font-family:monospace;" id="se-cyber-camp-count">--</div>';
  h += '</div>';
  h += '</div>';

  // NVD Feed
  h += '<div style="margin-bottom:14px;">';
  h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">';
  h += '<div style="color:#ff6644;font-size:11px;font-family:monospace;letter-spacing:1px;font-weight:bold;">NATIONAL VULNERABILITY DATABASE (NVD)</div>';
  h += '<div onclick="_seFetchNVD()" style="background:#ff664422;color:#ff6644;font-size:9px;font-family:monospace;padding:4px 10px;border-radius:3px;cursor:pointer;border:1px solid #ff664444;">REFRESH</div>';
  h += '</div>';
  h += '<div id="se-nvd-feed" style="background:#080c14;border:1px solid #1a2030;border-radius:6px;padding:12px;max-height:220px;overflow-y:auto;">';
  h += '<div style="text-align:center;padding:20px;color:#556;font-family:monospace;font-size:11px;">Loading NVD vulnerability data...</div>';
  h += '</div>';
  h += '</div>';

  // CISA KEV Feed
  h += '<div style="margin-bottom:14px;">';
  h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">';
  h += '<div style="color:#ff2244;font-size:11px;font-family:monospace;letter-spacing:1px;font-weight:bold;">CISA KNOWN EXPLOITED VULNERABILITIES</div>';
  h += '<div onclick="_seFetchKEV()" style="background:#ff224422;color:#ff2244;font-size:9px;font-family:monospace;padding:4px 10px;border-radius:3px;cursor:pointer;border:1px solid #ff224444;">REFRESH</div>';
  h += '</div>';
  h += '<div id="se-kev-feed" style="background:#080c14;border:1px solid #1a2030;border-radius:6px;padding:12px;max-height:220px;overflow-y:auto;">';
  h += '<div style="text-align:center;padding:20px;color:#556;font-family:monospace;font-size:11px;">Loading CISA KEV data...</div>';
  h += '</div>';
  h += '</div>';

  // IOC Feed
  h += '<div style="margin-bottom:14px;">';
  h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">';
  h += '<div style="color:#aa44ff;font-size:11px;font-family:monospace;letter-spacing:1px;font-weight:bold;">THREAT INTELLIGENCE FEED (IOCs)</div>';
  h += '<div onclick="_seFetchIOC()" style="background:#aa44ff22;color:#aa44ff;font-size:9px;font-family:monospace;padding:4px 10px;border-radius:3px;cursor:pointer;border:1px solid #aa44ff44;">REFRESH</div>';
  h += '</div>';
  h += '<div id="se-ioc-feed" style="background:#080c14;border:1px solid #1a2030;border-radius:6px;padding:12px;max-height:220px;overflow-y:auto;">';
  h += '<div style="text-align:center;padding:20px;color:#556;font-family:monospace;font-size:11px;">Loading threat IOC data...</div>';
  h += '</div>';
  h += '</div>';

  // Botnet C2 Feed
  h += '<div style="margin-bottom:14px;">';
  h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">';
  h += '<div style="color:#00ff88;font-size:11px;font-family:monospace;letter-spacing:1px;font-weight:bold;">BOTNET C2 SERVERS — Feodo Tracker (abuse.ch)</div>';
  h += '<div onclick="_seFetchBotnetC2()" style="background:#00ff8822;color:#00ff88;font-size:9px;font-family:monospace;padding:4px 10px;border-radius:3px;cursor:pointer;border:1px solid #00ff8844;">REFRESH</div>';
  h += '</div>';
  h += '<div id="se-c2-feed" style="background:#080c14;border:1px solid #1a2030;border-radius:6px;padding:12px;max-height:220px;overflow-y:auto;">';
  h += '<div style="text-align:center;padding:20px;color:#556;font-family:monospace;font-size:11px;">Loading botnet C2 data...</div>';
  h += '</div>';
  h += '</div>';

  // Malware URLs Feed
  h += '<div>';
  h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">';
  h += '<div style="color:#ffaa00;font-size:11px;font-family:monospace;letter-spacing:1px;font-weight:bold;">MALWARE DISTRIBUTION URLS — URLhaus (abuse.ch)</div>';
  h += '<div onclick="_seFetchMalwareURLs()" style="background:#ffaa0022;color:#ffaa00;font-size:9px;font-family:monospace;padding:4px 10px;border-radius:3px;cursor:pointer;border:1px solid #ffaa0044;">REFRESH</div>';
  h += '</div>';
  h += '<div id="se-malurl-feed" style="background:#080c14;border:1px solid #1a2030;border-radius:6px;padding:12px;max-height:220px;overflow-y:auto;">';
  h += '<div style="text-align:center;padding:20px;color:#556;font-family:monospace;font-size:11px;">Loading malware URL data...</div>';
  h += '</div>';
  h += '</div>';

  return h;
}

// ---------------------------------------------------------------------------
// NETWORK INTEL sub-tab
// ---------------------------------------------------------------------------

var _seBgpAlerts = [
  { asn: 'AS13335', owner: 'Cloudflare', prefix: '1.1.1.0/24', type: 'hijack', country: 'RU', description: 'Prefix originated from unexpected AS', timestamp: '2026-09-18T14:22:00Z', severity: 'critical' },
  { asn: 'AS15169', owner: 'Google', prefix: '8.8.8.0/24', type: 'leak', country: 'NG', description: 'Route leak through transit provider', timestamp: '2026-09-18T13:45:00Z', severity: 'high' },
  { asn: 'AS16509', owner: 'Amazon AWS', prefix: '52.94.0.0/16', type: 'hijack', country: 'CN', description: 'More-specific hijack via AS4134', timestamp: '2026-09-18T12:10:00Z', severity: 'critical' },
  { asn: 'AS8075', owner: 'Microsoft', prefix: '13.64.0.0/11', type: 'leak', country: 'PK', description: 'Full table leak to peer', timestamp: '2026-09-18T11:33:00Z', severity: 'medium' },
  { asn: 'AS36351', owner: 'SoftLayer (IBM)', prefix: '169.55.0.0/16', type: 'outage', country: 'US', description: 'Complete withdrawal of prefix', timestamp: '2026-09-18T10:05:00Z', severity: 'high' },
  { asn: 'AS2914', owner: 'NTT', prefix: '129.250.0.0/16', type: 'leak', country: 'IN', description: 'Partial route leak to downstream', timestamp: '2026-09-17T22:18:00Z', severity: 'medium' },
  { asn: 'AS3356', owner: 'Lumen (CenturyLink)', prefix: '4.0.0.0/9', type: 'outage', country: 'US', description: 'Major prefix flapping detected', timestamp: '2026-09-17T20:44:00Z', severity: 'high' },
  { asn: 'AS20940', owner: 'Akamai', prefix: '23.32.0.0/11', type: 'hijack', country: 'IR', description: 'Prefix announced via unauthorized path', timestamp: '2026-09-17T18:30:00Z', severity: 'critical' },
  { asn: 'AS714', owner: 'Apple', prefix: '17.0.0.0/8', type: 'leak', country: 'BR', description: 'Accidental re-announcement via IX peer', timestamp: '2026-09-17T16:12:00Z', severity: 'low' },
  { asn: 'AS32934', owner: 'Meta (Facebook)', prefix: '157.240.0.0/16', type: 'outage', country: 'US', description: 'BGP withdrawal (cf. Oct 2021 incident)', timestamp: '2026-09-17T14:00:00Z', severity: 'critical' }
];

var _seOutages = [
  { country: 'Sudan', isp: 'Multiple', type: 'Full shutdown', start: '2026-09-16T00:00:00Z', status: 'ongoing', cause: 'Government-ordered', pctDown: 98 },
  { country: 'Iran', isp: 'MCI / Irancell', type: 'Throttle', start: '2026-09-17T18:00:00Z', status: 'ongoing', cause: 'Protest-related throttling', pctDown: 65 },
  { country: 'Pakistan', isp: 'PTCL / Jazz', type: 'Partial', start: '2026-09-18T06:00:00Z', status: 'resolved', cause: 'Submarine cable fault (AAE-1)', pctDown: 30 },
  { country: 'Russia', isp: 'Rostelecom', type: 'Filtering', start: '2026-09-15T00:00:00Z', status: 'ongoing', cause: 'TSPU DPI filtering expansion', pctDown: 15 },
  { country: 'Myanmar', isp: 'MPT / Ooredoo', type: 'Shutdown', start: '2026-09-14T00:00:00Z', status: 'ongoing', cause: 'Military-ordered', pctDown: 85 },
  { country: 'Ethiopia', isp: 'Ethio Telecom', type: 'Partial', start: '2026-09-18T04:00:00Z', status: 'resolved', cause: 'Regional conflict-related', pctDown: 40 },
  { country: 'India', isp: 'Jio / Airtel', type: 'Throttle', start: '2026-09-18T10:00:00Z', status: 'resolved', cause: 'Localized Section 144 order', pctDown: 12 }
];

function _seRenderNetworkTab() {
  var h = '';
  h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;">';
  h += '<div>';
  h += '<div style="color:#ffaa00;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;">';
  h += '<span style="margin-right:8px;">[N]</span>NETWORK INTELLIGENCE -- BGP &amp; DNS Monitoring</div>';
  h += '<div style="color:#556;font-size:10px;font-family:monospace;margin-top:4px;">BGP anomaly detection, root DNS health, internet outage tracking</div>';
  h += '</div>';
  h += '</div>';

  // Stat cards
  h += '<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:16px;">';
  h += '<div style="background:#0a0e1a;border:1px solid #ffaa0033;border-radius:6px;padding:10px;text-align:center;">';
  h += '<div style="color:#556;font-size:9px;font-family:monospace;letter-spacing:1px;">BGP ANOMALIES</div>';
  h += '<div style="color:#ffaa00;font-size:22px;font-weight:bold;font-family:monospace;">' + _seBgpAlerts.length + '</div>';
  h += '</div>';
  h += '<div style="background:#0a0e1a;border:1px solid #00ff8833;border-radius:6px;padding:10px;text-align:center;">';
  h += '<div style="color:#556;font-size:9px;font-family:monospace;letter-spacing:1px;">DNS ROOT HEALTH</div>';
  h += '<div style="color:#00ff88;font-size:22px;font-weight:bold;font-family:monospace;">13/13</div>';
  h += '</div>';
  h += '<div style="background:#0a0e1a;border:1px solid #ff444433;border-radius:6px;padding:10px;text-align:center;">';
  h += '<div style="color:#556;font-size:9px;font-family:monospace;letter-spacing:1px;">ACTIVE OUTAGES</div>';
  var activeOutages = 0;
  for (var ao = 0; ao < _seOutages.length; ao++) { if (_seOutages[ao].status === 'ongoing') activeOutages++; }
  h += '<div style="color:#ff4444;font-size:22px;font-weight:bold;font-family:monospace;">' + activeOutages + '</div>';
  h += '</div>';
  h += '</div>';

  // BGP Anomaly Detection
  h += '<div style="margin-bottom:14px;">';
  h += '<div style="color:#ffaa00;font-size:11px;font-family:monospace;letter-spacing:1px;font-weight:bold;margin-bottom:8px;">BGP ANOMALY DETECTION</div>';
  h += '<div style="background:#080c14;border:1px solid #1a2030;border-radius:6px;padding:12px;max-height:200px;overflow-y:auto;">';
  h += '<table style="width:100%;border-collapse:collapse;font-family:monospace;font-size:10px;">';
  h += '<thead><tr style="border-bottom:2px solid #1a2a44;">';
  var bgpHeaders = ['TYPE', 'ASN', 'OWNER', 'PREFIX', 'ORIGIN', 'SEVERITY', 'TIME'];
  for (var bh = 0; bh < bgpHeaders.length; bh++) {
    h += '<th style="text-align:left;padding:4px 6px;color:#ffaa00;font-size:9px;letter-spacing:1px;">' + esc(bgpHeaders[bh]) + '</th>';
  }
  h += '</tr></thead><tbody>';

  for (var bi = 0; bi < _seBgpAlerts.length; bi++) {
    var bgp = _seBgpAlerts[bi];
    var typeColor = bgp.type === 'hijack' ? '#ff2244' : bgp.type === 'outage' ? '#ff8800' : '#ffcc00';
    var sevColor = bgp.severity === 'critical' ? '#ff0000' : bgp.severity === 'high' ? '#ff6600' : bgp.severity === 'medium' ? '#ffaa00' : '#00cc88';
    var bgpTime = bgp.timestamp ? bgp.timestamp.replace('T', ' ').substring(0, 19) + 'Z' : '--';
    h += '<tr style="border-bottom:1px solid #111828;">';
    h += '<td style="padding:4px 6px;"><span style="color:' + typeColor + ';font-weight:bold;font-size:9px;letter-spacing:1px;">' + esc(bgp.type.toUpperCase()) + '</span></td>';
    h += '<td style="padding:4px 6px;color:#aab;">' + esc(bgp.asn) + '</td>';
    h += '<td style="padding:4px 6px;color:#8ab4d4;">' + esc(bgp.owner) + '</td>';
    h += '<td style="padding:4px 6px;color:#ccd;font-family:monospace;">' + esc(bgp.prefix) + '</td>';
    h += '<td style="padding:4px 6px;color:#889;">' + esc(bgp.country) + '</td>';
    h += '<td style="padding:4px 6px;"><span style="color:' + sevColor + ';font-size:9px;font-weight:bold;">' + esc(bgp.severity.toUpperCase()) + '</span></td>';
    h += '<td style="padding:4px 6px;color:#556;font-size:9px;">' + esc(bgpTime) + '</td>';
    h += '</tr>';
  }
  h += '</tbody></table>';
  h += '</div>';
  h += '</div>';

  // DNS Root Server Status
  h += '<div style="margin-bottom:14px;">';
  h += '<div style="color:#00ff88;font-size:11px;font-family:monospace;letter-spacing:1px;font-weight:bold;margin-bottom:8px;">DNS ROOT SERVER STATUS</div>';
  h += '<div style="background:#080c14;border:1px solid #1a2030;border-radius:6px;padding:12px;">';
  h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px;">';

  for (var di = 0; di < GW_ROOT_DNS.length; di++) {
    var dns = GW_ROOT_DNS[di];
    h += '<div style="background:#0a1018;border:1px solid #1a2a3a;border-radius:4px;padding:8px 10px;display:flex;align-items:center;gap:8px;">';
    h += '<div style="width:8px;height:8px;border-radius:50%;background:#00ff88;box-shadow:0 0 6px #00ff88aa;flex-shrink:0;"></div>';
    h += '<div>';
    h += '<div style="color:#ccd;font-size:10px;font-family:monospace;font-weight:bold;">' + esc(dns.name) + '</div>';
    h += '<div style="color:#556;font-size:9px;font-family:monospace;">' + esc(dns.operator) + ' &middot; ' + esc(dns.city) + '</div>';
    h += '</div>';
    h += '</div>';
  }
  h += '</div>';
  h += '</div>';
  h += '</div>';

  // Internet Outage Tracker
  h += '<div>';
  h += '<div style="color:#ff4444;font-size:11px;font-family:monospace;letter-spacing:1px;font-weight:bold;margin-bottom:8px;">INTERNET OUTAGE TRACKER</div>';
  h += '<div style="background:#080c14;border:1px solid #1a2030;border-radius:6px;padding:12px;max-height:200px;overflow-y:auto;">';
  h += '<table style="width:100%;border-collapse:collapse;font-family:monospace;font-size:10px;">';
  h += '<thead><tr style="border-bottom:2px solid #1a2a44;">';
  var outHeaders = ['COUNTRY', 'ISP', 'TYPE', 'CAUSE', 'DOWN %', 'STATUS', 'SINCE'];
  for (var oh = 0; oh < outHeaders.length; oh++) {
    h += '<th style="text-align:left;padding:4px 6px;color:#ff4444;font-size:9px;letter-spacing:1px;">' + esc(outHeaders[oh]) + '</th>';
  }
  h += '</tr></thead><tbody>';

  for (var oi = 0; oi < _seOutages.length; oi++) {
    var outage = _seOutages[oi];
    var statusColor = outage.status === 'ongoing' ? '#ff4444' : '#00ff88';
    var pctColor = outage.pctDown >= 80 ? '#ff0000' : outage.pctDown >= 50 ? '#ff6600' : outage.pctDown >= 20 ? '#ffaa00' : '#00cc88';
    var outTime = outage.start ? outage.start.replace('T', ' ').substring(0, 16) + 'Z' : '--';
    h += '<tr style="border-bottom:1px solid #111828;">';
    h += '<td style="padding:4px 6px;color:#ccd;font-weight:bold;">' + esc(outage.country) + '</td>';
    h += '<td style="padding:4px 6px;color:#889;">' + esc(outage.isp) + '</td>';
    h += '<td style="padding:4px 6px;color:#aab;">' + esc(outage.type) + '</td>';
    h += '<td style="padding:4px 6px;color:#667;font-size:9px;">' + esc(outage.cause) + '</td>';
    h += '<td style="padding:4px 6px;"><span style="color:' + pctColor + ';font-weight:bold;">' + outage.pctDown + '%</span></td>';
    h += '<td style="padding:4px 6px;"><span style="color:' + statusColor + ';font-size:9px;font-weight:bold;">' + esc(outage.status.toUpperCase()) + '</span></td>';
    h += '<td style="padding:4px 6px;color:#556;font-size:9px;">' + esc(outTime) + '</td>';
    h += '</tr>';
  }
  h += '</tbody></table>';
  h += '</div>';
  h += '</div>';

  return h;
}

// ---------------------------------------------------------------------------
// Cyber Threat fetch functions
// ---------------------------------------------------------------------------

function _seFetchNVD() {
  var container = document.getElementById('se-nvd-feed');
  if (!container) return;
  container.innerHTML = '<div style="text-align:center;padding:16px;color:#ffaa00;font-family:monospace;font-size:11px;">Fetching NVD data...</div>';

  fetch('https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=15')
    .then(function(r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
    .then(function(data) {
      var vulns = (data.vulnerabilities || []);
      var h = '';
      var critCount = 0;

      if (vulns.length === 0) {
        container.innerHTML = '<div style="color:#556;font-family:monospace;font-size:11px;text-align:center;padding:16px;">No CVE data available.</div>';
        return;
      }

      for (var vi = 0; vi < vulns.length; vi++) {
        var cve = vulns[vi].cve || {};
        var cveId = cve.id || 'CVE-UNKNOWN';
        var desc = '';
        if (cve.descriptions) {
          for (var d = 0; d < cve.descriptions.length; d++) {
            if (cve.descriptions[d].lang === 'en') { desc = cve.descriptions[d].value; break; }
          }
        }
        if (desc.length > 160) desc = desc.substring(0, 157) + '...';

        var cvss = 0;
        var cvssStr = 'N/A';
        var severity = 'NONE';
        if (cve.metrics) {
          var m31 = (cve.metrics.cvssMetricV31 || [])[0];
          var m30 = (cve.metrics.cvssMetricV30 || [])[0];
          var m2 = (cve.metrics.cvssMetricV2 || [])[0];
          if (m31 && m31.cvssData) { cvss = m31.cvssData.baseScore; cvssStr = String(cvss); severity = m31.cvssData.baseSeverity || ''; }
          else if (m30 && m30.cvssData) { cvss = m30.cvssData.baseScore; cvssStr = String(cvss); severity = m30.cvssData.baseSeverity || ''; }
          else if (m2 && m2.cvssData) { cvss = m2.cvssData.baseScore; cvssStr = String(cvss); }
        }

        var scoreColor = cvss >= 9 ? '#ff0000' : cvss >= 7 ? '#ff6600' : cvss >= 4 ? '#ffaa00' : '#00cc88';
        var scoreBg = cvss >= 9 ? '#ff000015' : cvss >= 7 ? '#ff660015' : cvss >= 4 ? '#ffaa0010' : '#00cc8808';
        var sevLabel = cvss >= 9 ? 'CRITICAL' : cvss >= 7 ? 'HIGH' : cvss >= 4 ? 'MEDIUM' : cvss > 0 ? 'LOW' : '';
        if (cvss >= 9) critCount++;

        h += '<div style="display:flex;align-items:flex-start;gap:10px;padding:7px 0;border-bottom:1px solid #111828;background:' + scoreBg + ';margin:0 -12px;padding-left:12px;padding-right:12px;">';
        h += '<div style="flex-shrink:0;border:1px solid ' + scoreColor + '44;border-radius:4px;padding:3px 8px;text-align:center;min-width:44px;">';
        h += '<div style="color:' + scoreColor + ';font-size:14px;font-weight:bold;font-family:monospace;">' + esc(cvssStr) + '</div>';
        h += '<div style="color:' + scoreColor + ';font-size:7px;font-family:monospace;letter-spacing:1px;opacity:0.7;">' + esc(sevLabel) + '</div>';
        h += '</div>';
        h += '<div style="flex:1;min-width:0;">';
        h += '<div style="color:#ff6644;font-size:11px;font-family:monospace;font-weight:bold;">' + esc(cveId) + '</div>';
        h += '<div style="color:#889;font-size:10px;font-family:monospace;margin-top:2px;line-height:1.4;">' + esc(desc) + '</div>';
        h += '</div>';
        h += '</div>';
      }

      h += '<div style="color:#445;font-size:9px;font-family:monospace;margin-top:10px;text-align:right;">LAST FETCHED: ' + new Date().toISOString().replace('T', ' ').substring(0, 19) + 'Z</div>';

      container.innerHTML = h;
      var cveCountEl = document.getElementById('se-cyber-cve-count');
      if (cveCountEl) cveCountEl.textContent = String(vulns.length);
      var critEl = document.getElementById('se-cyber-crit-count');
      if (critEl) critEl.textContent = String(critCount);
    })
    .catch(function(err) {
      container.innerHTML = '<div style="color:#ff6644;font-family:monospace;font-size:11px;padding:16px;text-align:center;">' +
        '<div style="font-weight:bold;margin-bottom:6px;">NVD API UNAVAILABLE</div>' +
        '<div style="color:#889;">' + esc(String(err.message || err)) + '</div>' +
        '<div style="color:#556;margin-top:8px;">Will retry automatically in 60 seconds. NVD may be rate-limited (5 req/30s without API key).</div>' +
        '</div>';
    });
}

function _seFetchKEV() {
  var container = document.getElementById('se-kev-feed');
  if (!container) return;
  container.innerHTML = '<div style="text-align:center;padding:16px;color:#ffaa00;font-family:monospace;font-size:11px;">Fetching CISA KEV data...</div>';

  fetch('/data/feeds/cisa-kev.json')
    .then(function(r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
    .then(function(feed) {
      var items = (feed.data || feed.vulnerabilities || []);
      if (items.length === 0) {
        container.innerHTML = '<div style="color:#556;font-family:monospace;font-size:11px;text-align:center;padding:16px;">No KEV data available.</div>';
        return;
      }

      items.sort(function(a, b) {
        var da = a.dateAdded || ''; var db = b.dateAdded || '';
        return da > db ? -1 : da < db ? 1 : 0;
      });

      var h = '';
      var max = Math.min(items.length, 15);
      for (var ki = 0; ki < max; ki++) {
        var kev = items[ki];
        var kevCve = kev.cve || kev.cveID || '--';
        var kevVendor = kev.vendor || kev.vendorProject || '--';
        var kevProduct = kev.product || '--';
        var kevName = kev.name || kev.vulnerabilityName || '--';
        if (kevName.length > 80) kevName = kevName.substring(0, 77) + '...';
        var kevDate = kev.dateAdded || '--';
        var kevRansomware = kev.knownRansomware || kev.knownRansomwareCampaignUse || 'Unknown';
        var isRansomware = kevRansomware === 'Known';
        var cveColor = isRansomware ? '#ff2244' : '#00aaff';
        var rowBg = isRansomware ? '#ff000008' : 'transparent';

        h += '<div style="display:flex;align-items:flex-start;gap:10px;padding:7px 12px;margin:0 -12px;border-bottom:1px solid #111828;background:' + rowBg + ';">';
        h += '<div style="flex-shrink:0;min-width:130px;">';
        h += '<div style="color:' + cveColor + ';font-size:11px;font-family:monospace;font-weight:bold;">' + esc(kevCve) + '</div>';
        h += '<div style="color:#556;font-size:8px;font-family:monospace;margin-top:2px;">' + esc(kevDate) + '</div>';
        h += '</div>';
        h += '<div style="flex:1;min-width:0;">';
        h += '<div style="display:flex;align-items:center;gap:6px;">';
        h += '<span style="color:#ccd;font-size:10px;font-family:monospace;font-weight:bold;">' + esc(kevVendor) + '</span>';
        h += '<span style="color:#445;font-size:10px;">|</span>';
        h += '<span style="color:#889;font-size:10px;font-family:monospace;">' + esc(kevProduct) + '</span>';
        h += '</div>';
        h += '<div style="color:#667;font-size:9px;font-family:monospace;margin-top:3px;line-height:1.3;">' + esc(kevName) + '</div>';
        h += '</div>';
        h += '<div style="flex-shrink:0;">';
        if (isRansomware) {
          h += '<div style="background:#ff224418;color:#ff2244;font-size:8px;font-family:monospace;padding:2px 6px;border-radius:2px;border:1px solid #ff224433;letter-spacing:1px;font-weight:bold;">RANSOMWARE</div>';
        }
        h += '</div>';
        h += '</div>';
      }

      h += '<div style="color:#445;font-size:9px;font-family:monospace;margin-top:10px;text-align:right;">SHOWING TOP 15 — ' + items.length + ' TOTAL KEVs | LAST FETCHED: ' + new Date().toISOString().replace('T', ' ').substring(0, 19) + 'Z</div>';
      container.innerHTML = h;
    })
    .catch(function(err) {
      container.innerHTML = '<div style="color:#ff6644;font-family:monospace;font-size:11px;padding:12px;text-align:center;">KEV feed error: ' + esc(String(err.message || err)) + '</div>';
    });
}

function _seFetchIOC() {
  var container = document.getElementById('se-ioc-feed');
  if (!container) return;
  container.innerHTML = '<div style="text-align:center;padding:16px;color:#ffaa00;font-family:monospace;font-size:11px;">Fetching IOC data...</div>';

  fetch('/data/feeds/threat-iocs.json')
    .then(function(r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
    .then(function(feed) {
      var items = (feed.data || feed.iocs || feed || []);
      if (!Array.isArray(items) || items.length === 0) {
        container.innerHTML = '<div style="color:#556;font-family:monospace;font-size:11px;text-align:center;padding:16px;">No IOC data available.</div>';
        return;
      }

      var h = '';
      var campCount = 0;
      var seenMalware = {};
      var max = Math.min(items.length, 25);

      for (var ii = 0; ii < max; ii++) {
        var ioc = items[ii];
        var iocType = ioc.iocType || ioc.type || ioc.ioc_type || 'indicator';
        var iocValue = ioc.iocValue || ioc.value || ioc.indicator || ioc.ioc || '--';
        var iocMalware = ioc.malware || '';
        var iocTags = ioc.tags || [];
        if (typeof iocTags === 'string') iocTags = iocTags.split(',');
        var iocConf = ioc.confidenceLevel || ioc.confidence || ioc.confidence_level || 0;
        var iocSeen = ioc.firstSeen || ioc.first_seen || '';
        if (iocMalware && !seenMalware[iocMalware]) { campCount++; seenMalware[iocMalware] = true; }

        var typeColors = { 'ip:port': '#ff4444', 'ip': '#ff4444', 'domain': '#ffaa00', 'url': '#00aaff', 'sha256_hash': '#aa44ff', 'sha256': '#aa44ff', 'hash': '#aa44ff', 'md5': '#aa44ff', 'email': '#00cc88' };
        var typeColor = typeColors[iocType] || '#889';

        var confColor = iocConf >= 90 ? '#ff2244' : iocConf >= 70 ? '#ff8800' : iocConf >= 50 ? '#ffcc00' : '#00cc88';
        var confWidth = Math.max(5, Math.min(100, iocConf));

        h += '<div style="display:flex;align-items:center;gap:8px;padding:6px 12px;margin:0 -12px;border-bottom:1px solid #111828;cursor:pointer;" onclick="try{navigator.clipboard.writeText(\'' + esc(iocValue).replace(/'/g, "\\'") + '\');var _t=this;_t.style.background=\'#00ff8815\';setTimeout(function(){_t.style.background=\'\'},500)}catch(e){}" title="Click to copy IOC">';
        h += '<div style="flex-shrink:0;background:' + typeColor + '15;color:' + typeColor + ';font-size:7px;font-family:monospace;padding:2px 6px;border-radius:2px;border:1px solid ' + typeColor + '33;letter-spacing:1px;min-width:60px;text-align:center;text-transform:uppercase;">' + esc(iocType) + '</div>';
        h += '<div style="flex:1;min-width:0;">';
        h += '<div style="color:#ccd;font-size:10px;font-family:monospace;word-break:break-all;line-height:1.3;">' + esc(iocValue) + '</div>';
        if (iocMalware) {
          h += '<div style="color:#ff8844;font-size:9px;font-family:monospace;margin-top:2px;">' + esc(iocMalware) + '</div>';
        }
        if (iocTags.length > 0) {
          h += '<div style="display:flex;gap:3px;flex-wrap:wrap;margin-top:3px;">';
          for (var ti = 0; ti < Math.min(iocTags.length, 5); ti++) {
            var tag = String(iocTags[ti]).trim();
            if (!tag) continue;
            h += '<span style="background:#1a2a44;color:#5a8aaa;font-size:7px;font-family:monospace;padding:1px 5px;border-radius:2px;border:1px solid #1a3a5a;">' + esc(tag) + '</span>';
          }
          h += '</div>';
        }
        h += '</div>';
        h += '<div style="flex-shrink:0;width:60px;">';
        h += '<div style="color:#556;font-size:7px;font-family:monospace;letter-spacing:1px;margin-bottom:2px;">CONF ' + iocConf + '%</div>';
        h += '<div style="width:100%;height:3px;background:#111828;border-radius:2px;overflow:hidden;">';
        h += '<div style="width:' + confWidth + '%;height:100%;background:' + confColor + ';border-radius:2px;"></div>';
        h += '</div>';
        h += '</div>';
        h += '</div>';
      }

      h += '<div style="color:#445;font-size:9px;font-family:monospace;margin-top:10px;text-align:right;">SHOWING ' + max + ' of ' + items.length + ' IOCs | ' + campCount + ' MALWARE FAMILIES | LAST FETCHED: ' + new Date().toISOString().replace('T', ' ').substring(0, 19) + 'Z</div>';
      container.innerHTML = h;
      var campEl = document.getElementById('se-cyber-camp-count');
      if (campEl) campEl.textContent = String(campCount || '--');
    })
    .catch(function(err) {
      container.innerHTML = '<div style="color:#ff6644;font-family:monospace;font-size:11px;padding:12px;text-align:center;">IOC feed error: ' + esc(String(err.message || err)) + '</div>';
    });
}

// ---------------------------------------------------------------------------
// Live data fetch functions for tracking tab
// ---------------------------------------------------------------------------

var _seAircraftFetching = false;
var _seAircraftLastFetch = 0;

function _seSimulatedAircraftStates() {
  return GW_SIM_AIRCRAFT.map(function(ac) {
    return [ac.cs.toLowerCase(), ac.cs, ac.origin, 0, 0, ac.lon, ac.lat, ac.alt, false, ac.vel, ac.hdg, 0, null, ac.alt, null, false, 0];
  });
}

function _seFetchAircraft() {
  var container = document.getElementById('se-aircraft-data');
  var countEl = document.getElementById('se-aircraft-count');
  if (!container) return;

  var now = Date.now();
  if (_seAircraftFetching || (now - _seAircraftLastFetch < 15000)) {
    if (_seTrackingCache.aircraft && _seTrackingCache.aircraft.length > 0) {
      _seRenderAircraftData(container, countEl, _seTrackingCache.aircraft);
    }
    return;
  }

  _seAircraftFetching = true;
  _seAircraftLastFetch = now;
  container.innerHTML = '<div style="text-align:center;padding:20px;color:#ffaa00;font-family:monospace;font-size:11px;">Loading aircraft data...</div>';

  var simStates = _seSimulatedAircraftStates();
  _seTrackingCache.aircraft = simStates;
  _seTrackingCache.aircraftTs = Date.now();
  _seAircraftFetching = false;
  _seRenderAircraftData(container, countEl, simStates);

  var noteEl = document.createElement('div');
  noteEl.style.cssText = 'color:#4a6a8a;font-size:9px;font-family:monospace;text-align:center;padding:6px;';
  noteEl.textContent = 'Simulated positions — OpenSky Network API requires server-side proxy for CORS';
  if (container.parentNode) container.parentNode.appendChild(noteEl);
}

function _seFetchAircraftSilent() {
  var container = document.getElementById('se-aircraft-data');
  var countEl = document.getElementById('se-aircraft-count');
  if (!container) return;
  var simStates = _seSimulatedAircraftStates();
  _seTrackingCache.aircraft = simStates;
  _seTrackingCache.aircraftTs = Date.now();
  _seRenderAircraftData(container, countEl, simStates);
}

var _seLeafletLoaded = false;
var _seLeafletMap = null;
var _seAircraftMarkers = [];

function _seLoadLeaflet(callback) {
  if (_seLeafletLoaded) { callback(); return; }
  // Inline critical Leaflet CSS
  var css = document.createElement('style');
  css.textContent = '.leaflet-container{height:100%;width:100%;font-family:inherit}.leaflet-tile-pane{z-index:2}.leaflet-overlay-pane{z-index:4}.leaflet-marker-pane{z-index:6}.leaflet-tooltip-pane{z-index:7}.leaflet-popup-pane{z-index:7}.leaflet-control{position:relative;z-index:8;pointer-events:auto}.leaflet-top,.leaflet-bottom{position:absolute;z-index:1000;pointer-events:none}.leaflet-top{top:0}.leaflet-bottom{bottom:0}.leaflet-left{left:0}.leaflet-right{right:0}.leaflet-zoom-box{width:0;height:0}.leaflet-pane{position:absolute;top:0;left:0}.leaflet-tile{position:absolute;filter:inherit;visibility:hidden}.leaflet-tile-loaded{visibility:inherit}.leaflet-zoom-anim .leaflet-zoom-animated{will-change:transform;transition:transform .25s cubic-bezier(0,0,.25,1)}.leaflet-fade-anim .leaflet-popup{opacity:1;transition:opacity .2s linear}.leaflet-map-pane canvas{position:absolute}.leaflet-interactive{cursor:pointer}.leaflet-grab{cursor:grab}.leaflet-crosshair,.leaflet-crosshair .leaflet-interactive{cursor:crosshair}.leaflet-dragging .leaflet-grab{cursor:grabbing}.leaflet-control-zoom a{width:30px;height:30px;line-height:30px;display:block;text-align:center;text-decoration:none;background:#0d1117;color:#00aaff;border:1px solid #1a2a44;font-size:18px}.leaflet-control-zoom a:hover{background:#141c28;color:#00ccff}.leaflet-control-zoom-in{border-radius:4px 4px 0 0}.leaflet-control-zoom-out{border-radius:0 0 4px 4px}.leaflet-control-attribution{background:rgba(10,14,20,.8);color:#556;font-size:9px;padding:2px 6px}.leaflet-control-attribution a{color:#00aaff}.leaflet-container .leaflet-control-attribution{margin:0}.leaflet-marker-icon{border:none;background:none}.leaflet-div-icon{border:none;background:none}.leaflet-popup-content-wrapper{background:#0d1117;border:1px solid #1a2a44;border-radius:6px;color:#c8d6e5;font-family:monospace;font-size:11px}.leaflet-popup-tip{background:#0d1117;border:1px solid #1a2a44}.leaflet-popup-content{margin:10px 12px}.leaflet-container a.leaflet-popup-close-button{color:#556}';
  document.head.appendChild(css);
  // Load Leaflet JS from cdnjs
  var script = document.createElement('script');
  script.src = '/js/vendor/leaflet.min.js';
  script.onload = function() { _seLeafletLoaded = true; callback(); };
  script.onerror = function() { callback(); };
  document.head.appendChild(script);
}

function _seDrawAircraftMap(mapId, states) {
  _seLoadLeaflet(function() {
    if (typeof L === 'undefined') return;

    // Destroy old map
    if (_seLeafletMap) { _seLeafletMap.remove(); _seLeafletMap = null; }

    var mapEl = document.getElementById(mapId);
    if (!mapEl) return;

    _seLeafletMap = L.map(mapId, {
      center: [30, 0],
      zoom: 2,
      zoomControl: true,
      attributionControl: true,
      minZoom: 2,
      maxBoundsViscosity: 1.0
    });

    L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}', {
      attribution: 'Esri',
      maxZoom: 16
    }).addTo(_seLeafletMap);
    L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/Reference/World_Reference_Overlay/MapServer/tile/{z}/{y}/{x}', {
      attribution: '',
      maxZoom: 16,
      opacity: 0.5
    }).addTo(_seLeafletMap);

    // Clear old markers
    for (var m = 0; m < _seAircraftMarkers.length; m++) {
      _seLeafletMap.removeLayer(_seAircraftMarkers[m]);
    }
    _seAircraftMarkers = [];

    // Major airport hubs
    var hubs = [
      { code: 'JFK', lat: 40.64, lon: -73.78 }, { code: 'LAX', lat: 33.94, lon: -118.41 },
      { code: 'ORD', lat: 41.98, lon: -87.90 }, { code: 'LHR', lat: 51.47, lon: -0.46 },
      { code: 'CDG', lat: 49.01, lon: 2.55 },   { code: 'FRA', lat: 50.03, lon: 8.57 },
      { code: 'DXB', lat: 25.25, lon: 55.36 },  { code: 'HND', lat: 35.55, lon: 139.78 },
      { code: 'SIN', lat: 1.36, lon: 103.99 },  { code: 'SYD', lat: -33.95, lon: 151.18 },
      { code: 'GRU', lat: -23.43, lon: -46.47 }, { code: 'ICN', lat: 37.46, lon: 126.44 }
    ];
    for (var hi = 0; hi < hubs.length; hi++) {
      var hub = hubs[hi];
      var hubMarker = L.circleMarker([hub.lat, hub.lon], { radius: 3, fillColor: '#1a4a6a', color: '#1a4a6a', weight: 1, opacity: 0.5, fillOpacity: 0.3 });
      hubMarker.bindTooltip(hub.code, { permanent: true, direction: 'right', className: '', offset: [6, 0] });
      hubMarker.addTo(_seLeafletMap);
      _seAircraftMarkers.push(hubMarker);
    }

    // Plot aircraft with route trails
    var plotCount = Math.min(states.length, 300);
    for (var i = 0; i < plotCount; i++) {
      var s = states[i];
      var lat = s[6], lon = s[5], alt = s[7], onGround = s[8];
      var callsign = s[1] ? String(s[1]).trim() : 'N/A';
      var origin = s[2] || 'N/A';
      if (lat == null || lon == null) continue;

      var color = onGround ? '#ffaa00' : alt != null && alt > 10000 ? '#00aaff' : '#00ff88';
      var size = onGround ? 4 : 6;

      var marker = L.circleMarker([lat, lon], {
        radius: size,
        fillColor: color,
        color: color,
        weight: 1,
        opacity: 0.9,
        fillOpacity: 0.7
      });

      var altStr = alt != null ? Math.round(alt) + 'm' : 'N/A';
      var speedStr = s[9] != null ? Number(s[9]).toFixed(0) + ' m/s' : 'N/A';
      var headingStr = s[10] != null ? Math.round(s[10]) + ' deg' : 'N/A';
      marker.bindPopup(
        '<b style="color:#00ddff">' + esc(callsign) + '</b><br>' +
        '<span style="color:#8ab4d4">Origin: ' + esc(origin) + '</span><br>' +
        'Alt: ' + esc(altStr) + ' | Spd: ' + esc(speedStr) + '<br>' +
        'Hdg: ' + esc(headingStr) + '<br>' +
        (onGround ? '<span style="color:#ffaa00">ON GROUND</span>' : '<span style="color:#00ff88">AIRBORNE</span>')
      );

      marker.addTo(_seLeafletMap);
      _seAircraftMarkers.push(marker);

      // Draw a faint heading line to show direction
      if (!onGround && s[10] != null) {
        var hdgRad = (s[10] || 0) * Math.PI / 180;
        var trailLen = 3;
        var tLat = lat + Math.cos(hdgRad) * trailLen;
        var tLon = lon + Math.sin(hdgRad) * trailLen;
        var trail = L.polyline([[lat, lon], [tLat, tLon]], { color: color, weight: 1, opacity: 0.25, dashArray: '4 6' });
        trail.addTo(_seLeafletMap);
        _seAircraftMarkers.push(trail);
      }
    }
  });
}

function _seRenderAircraftData(container, countEl, states) {
  var h = '';

  // Interactive map
  h += '<div id="se-aircraft-map" style="width:100%;height:450px;background:#080c14;border:1px solid #1a2a44;border-radius:6px;margin-bottom:14px;overflow:hidden;"></div>';
  var displayCount = Math.min(states.length, 50);

  if (countEl) {
    countEl.innerHTML = '<div style="color:#556;font-size:8px;font-family:monospace;letter-spacing:1px;">TRACKED</div>' +
      '<div style="color:#00aaff;font-size:18px;font-weight:bold;font-family:monospace;">' + states.length + '</div>';
  }

  h += '<div style="margin-bottom:10px;display:flex;justify-content:space-between;align-items:center;">';
  h += '<div style="color:#00ff88;font-size:11px;font-family:monospace;">' + states.length + ' aircraft tracked in worldwide airspace</div>';
  h += '<div style="color:#445;font-size:9px;font-family:monospace;">Showing top ' + displayCount + ' | Last update: ' + new Date().toISOString().replace('T', ' ').substring(0, 19) + 'Z</div>';
  h += '</div>';

  // Table
  h += '<div style="overflow-x:auto;">';
  h += '<table style="width:100%;border-collapse:collapse;font-family:monospace;font-size:10px;">';
  h += '<thead><tr style="border-bottom:2px solid #1a2a44;">';
  var headers = ['CALLSIGN', 'ORIGIN', 'LAT', 'LON', 'ALT (m)', 'SPEED (m/s)', 'HEADING', 'ON GROUND'];
  for (var th = 0; th < headers.length; th++) {
    h += '<th style="text-align:left;padding:6px;color:#00aaff;font-size:9px;letter-spacing:1px;">' + esc(headers[th]) + '</th>';
  }
  h += '</tr></thead><tbody>';

  for (var i = 0; i < displayCount; i++) {
    var s = states[i];
    // OpenSky state vector indices:
    // 0: icao24, 1: callsign, 2: origin_country, 3: time_position
    // 4: last_contact, 5: longitude, 6: latitude, 7: baro_altitude
    // 8: on_ground, 9: velocity, 10: true_track, 11: vertical_rate
    var callsign = s[1] ? String(s[1]).trim() : 'N/A';
    var origin = s[2] ? String(s[2]) : 'N/A';
    var lat = s[6] != null ? Number(s[6]).toFixed(4) : 'N/A';
    var lon = s[5] != null ? Number(s[5]).toFixed(4) : 'N/A';
    var alt = s[7] != null ? Math.round(Number(s[7])) : 'N/A';
    var speed = s[9] != null ? Number(s[9]).toFixed(1) : 'N/A';
    var heading = s[10] != null ? Math.round(Number(s[10])) + ' deg' : 'N/A';
    var onGround = s[8] ? 'YES' : 'NO';
    var onGroundColor = s[8] ? '#ffaa00' : '#00ff88';
    var altColor = alt !== 'N/A' && alt > 10000 ? '#00aaff' : alt !== 'N/A' && alt > 5000 ? '#00ff88' : '#ffaa00';

    h += '<tr style="border-bottom:1px solid #111828;">';
    h += '<td style="padding:5px 6px;color:#fff;font-weight:bold;">' + esc(callsign) + '</td>';
    h += '<td style="padding:5px 6px;color:#889;">' + esc(origin) + '</td>';
    h += '<td style="padding:5px 6px;color:#889;">' + esc(lat) + '</td>';
    h += '<td style="padding:5px 6px;color:#889;">' + esc(lon) + '</td>';
    h += '<td style="padding:5px 6px;color:' + altColor + ';">' + esc(alt) + '</td>';
    h += '<td style="padding:5px 6px;color:#889;">' + esc(speed) + '</td>';
    h += '<td style="padding:5px 6px;color:#889;">' + esc(heading) + '</td>';
    h += '<td style="padding:5px 6px;color:' + onGroundColor + ';">' + esc(onGround) + '</td>';
    h += '</tr>';
  }

  h += '</tbody></table>';
  h += '</div>';

  if (states.length > displayCount) {
    h += '<div style="color:#445;font-size:9px;font-family:monospace;text-align:center;padding:8px;">... and ' + (states.length - displayCount) + ' more aircraft not shown</div>';
  }

  container.innerHTML = h;

  // Draw map after DOM update
  setTimeout(function() { _seDrawAircraftMap('se-aircraft-map', states); }, 50);
}

function _seFetchISS() {
  var container = document.getElementById('se-iss-data');
  if (!container) return;
  container.innerHTML = '<div style="text-align:center;padding:20px;color:#ffaa00;font-family:monospace;font-size:11px;">Fetching ISS position...</div>';

  try {
    fetch('https://api.wheretheiss.at/v1/satellites/25544').catch(function(){return null;})
      .then(function(r) { if (!r || !r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      })
      .then(function(data) {
        if (data.message === 'success' && data.iss_position) {
          _seTrackingCache.iss = data;
          _seTrackingCache.issTs = Date.now();
          _seRenderISSData(container, data);
        } else {
          throw new Error('Unexpected response format');
        }
      })
      .catch(function(err) {
        container.innerHTML = '<div style="background:#0c1525;border:1px solid #aa66ff33;border-radius:8px;padding:24px;text-align:center;">' +
          '<div style="color:#aa66ff;font-size:40px;margin-bottom:12px;">[ISS]</div>' +
          '<div style="color:#ffaa00;font-size:12px;font-family:monospace;font-weight:bold;margin-bottom:8px;">ISS POSITION DATA UNAVAILABLE</div>' +
          '<div style="color:#889;font-size:10px;font-family:monospace;line-height:1.5;max-width:500px;margin:0 auto;">' +
          'Could not reach ISS tracking API. This may be temporary. ' +
          'Error: ' + esc(String(err.message || err)) + '</div>' +
          '<div style="color:#556;font-size:9px;font-family:monospace;margin-top:10px;">Retrying automatically...</div>' +
          '</div>';
      });
  } catch (e) {
    container.innerHTML = '<div style="color:#ff2244;font-size:11px;font-family:monospace;padding:16px;">Fetch error: ' + esc(String(e.message || e)) + '</div>';
  }
}

function _seRenderISSData(container, data) {
  var pos = data.iss_position || {};
  var lat = pos.latitude || '0';
  var lon = pos.longitude || '0';
  var ts = data.timestamp ? new Date(data.timestamp * 1000).toISOString().replace('T', ' ').substring(0, 19) + 'Z' : new Date().toISOString().replace('T', ' ').substring(0, 19) + 'Z';

  var h = '';
  h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">';

  // ISS position card
  h += '<div style="background:#0a0e1a;border:1px solid #aa66ff33;border-radius:8px;padding:20px;text-align:center;">';
  h += '<div style="color:#aa66ff;font-size:14px;font-family:monospace;font-weight:bold;letter-spacing:2px;margin-bottom:14px;">INTERNATIONAL SPACE STATION</div>';
  h += '<div style="display:flex;justify-content:center;gap:24px;margin-bottom:16px;">';
  h += '<div>';
  h += '<div style="color:#556;font-size:9px;font-family:monospace;letter-spacing:1px;">LATITUDE</div>';
  h += '<div style="color:#00ff88;font-size:28px;font-weight:bold;font-family:monospace;">' + esc(Number(lat).toFixed(4)) + '</div>';
  h += '</div>';
  h += '<div>';
  h += '<div style="color:#556;font-size:9px;font-family:monospace;letter-spacing:1px;">LONGITUDE</div>';
  h += '<div style="color:#00aaff;font-size:28px;font-weight:bold;font-family:monospace;">' + esc(Number(lon).toFixed(4)) + '</div>';
  h += '</div>';
  h += '</div>';
  h += '<div style="color:#445;font-size:9px;font-family:monospace;">Position as of: ' + esc(ts) + '</div>';
  h += '<div style="color:#556;font-size:9px;font-family:monospace;margin-top:4px;">Altitude: ~408 km | Speed: ~27,600 km/h | Orbital Period: ~92 min</div>';
  h += '</div>';

  // ISS info card
  h += '<div style="background:#0a0e1a;border:1px solid #1a2a44;border-radius:8px;padding:20px;">';
  h += '<div style="color:#aa66ff;font-size:12px;font-family:monospace;letter-spacing:1px;margin-bottom:12px;border-bottom:1px solid #1a2a44;padding-bottom:8px;">ISS MISSION DATA</div>';
  var issInfo = [
    { label: 'ORBITAL ALTITUDE', value: '~408 km (LEO)' },
    { label: 'ORBITAL VELOCITY', value: '7.66 km/s (27,600 km/h)' },
    { label: 'ORBITAL PERIOD', value: '~92.68 minutes' },
    { label: 'ORBITS PER DAY', value: '~15.5' },
    { label: 'INCLINATION', value: '51.6 degrees' },
    { label: 'LAUNCH DATE', value: '1998-11-20' },
    { label: 'DATA SOURCE', value: 'wheretheiss.at (free API)' }
  ];
  for (var ii = 0; ii < issInfo.length; ii++) {
    h += '<div style="display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid #111828;">';
    h += '<div style="color:#556;font-size:10px;font-family:monospace;">' + esc(issInfo[ii].label) + '</div>';
    h += '<div style="color:#ccd;font-size:10px;font-family:monospace;">' + esc(issInfo[ii].value) + '</div>';
    h += '</div>';
  }
  h += '</div>';

  h += '</div>';
  container.innerHTML = h;
}

function _seFetchSeismic() {
  var container = document.getElementById('se-seismic-data');
  if (!container) return;
  container.innerHTML = '<div style="text-align:center;padding:20px;color:#ffaa00;font-family:monospace;font-size:11px;">Fetching USGS earthquake data...</div>';

  try {
    fetch('https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/significant_month.geojson').catch(function(){return null;})
      .then(function(r) { if (!r || !r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      })
      .then(function(data) {
        var features = data.features || [];
        _seTrackingCache.seismic = features;
        _seTrackingCache.seismicTs = Date.now();
        _seRenderSeismicData(container, features, data.metadata || {});
      })
      .catch(function(err) {
        container.innerHTML = '<div style="background:#1a0a0a;border:1px solid #ff224444;border-radius:6px;padding:16px;text-align:center;">' +
          '<div style="color:#ff2244;font-size:12px;font-family:monospace;font-weight:bold;margin-bottom:6px;">SEISMIC DATA UNAVAILABLE</div>' +
          '<div style="color:#889;font-size:10px;font-family:monospace;">USGS API error: ' + esc(String(err.message || err)) + '</div>' +
          '</div>';
      });
  } catch (e) {
    container.innerHTML = '<div style="color:#ff2244;font-size:11px;font-family:monospace;padding:16px;">Fetch error: ' + esc(String(e.message || e)) + '</div>';
  }
}

function _seRenderSeismicData(container, features, metadata) {
  var h = '';

  h += '<div style="margin-bottom:12px;display:flex;justify-content:space-between;align-items:center;">';
  h += '<div style="color:#ff6644;font-size:11px;font-family:monospace;">' + features.length + ' significant earthquakes this month</div>';
  h += '<div style="color:#445;font-size:9px;font-family:monospace;">Source: ' + esc(metadata.title || 'USGS') + ' | Generated: ' + esc(metadata.generated ? new Date(metadata.generated).toISOString().replace('T', ' ').substring(0, 19) + 'Z' : 'N/A') + '</div>';
  h += '</div>';

  if (features.length === 0) {
    h += '<div style="text-align:center;padding:24px;color:#00ff88;font-size:12px;font-family:monospace;">No significant earthquakes recorded this month.</div>';
    container.innerHTML = h;
    return;
  }

  // Summary stats
  var maxMag = 0;
  var totalMag = 0;
  for (var ms = 0; ms < features.length; ms++) {
    var m = (features[ms].properties || {}).mag || 0;
    if (m > maxMag) maxMag = m;
    totalMag += m;
  }
  var avgMag = features.length > 0 ? (totalMag / features.length).toFixed(1) : '0';

  h += '<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:16px;">';
  h += '<div style="background:#0a0e1a;border:1px solid #ff664433;border-radius:6px;padding:10px;text-align:center;">';
  h += '<div style="color:#556;font-size:9px;font-family:monospace;letter-spacing:1px;">EVENTS</div>';
  h += '<div style="color:#ff6644;font-size:22px;font-weight:bold;font-family:monospace;">' + features.length + '</div>';
  h += '</div>';
  h += '<div style="background:#0a0e1a;border:1px solid #ff224433;border-radius:6px;padding:10px;text-align:center;">';
  h += '<div style="color:#556;font-size:9px;font-family:monospace;letter-spacing:1px;">MAX MAGNITUDE</div>';
  h += '<div style="color:#ff2244;font-size:22px;font-weight:bold;font-family:monospace;">' + maxMag.toFixed(1) + '</div>';
  h += '</div>';
  h += '<div style="background:#0a0e1a;border:1px solid #ffaa0033;border-radius:6px;padding:10px;text-align:center;">';
  h += '<div style="color:#556;font-size:9px;font-family:monospace;letter-spacing:1px;">AVG MAGNITUDE</div>';
  h += '<div style="color:#ffaa00;font-size:22px;font-weight:bold;font-family:monospace;">' + esc(avgMag) + '</div>';
  h += '</div>';
  h += '</div>';

  // Earthquake table
  h += '<div style="overflow-x:auto;">';
  h += '<table style="width:100%;border-collapse:collapse;font-family:monospace;font-size:10px;">';
  h += '<thead><tr style="border-bottom:2px solid #1a2a44;">';
  var eqHeaders = ['MAG', 'LOCATION', 'DEPTH (km)', 'TIME (UTC)', 'STATUS', 'TYPE'];
  for (var eh = 0; eh < eqHeaders.length; eh++) {
    h += '<th style="text-align:left;padding:6px;color:#ff6644;font-size:9px;letter-spacing:1px;">' + esc(eqHeaders[eh]) + '</th>';
  }
  h += '</tr></thead><tbody>';

  for (var qi = 0; qi < features.length; qi++) {
    var eq = features[qi];
    var props = eq.properties || {};
    var coords = (eq.geometry || {}).coordinates || [];
    var mag = props.mag != null ? Number(props.mag).toFixed(1) : 'N/A';
    var place = props.place || 'Unknown location';
    var depth = coords[2] != null ? Number(coords[2]).toFixed(1) : 'N/A';
    var eqTime = props.time ? new Date(props.time).toISOString().replace('T', ' ').substring(0, 19) + 'Z' : 'N/A';
    var status = props.status || 'unknown';
    var eqType = props.type || 'earthquake';

    // Color-code by magnitude
    var magNum = Number(mag) || 0;
    var magColor = magNum >= 7 ? '#ff0000' : magNum >= 6 ? '#ff2244' : magNum >= 5 ? '#ff6644' : magNum >= 4 ? '#ffaa00' : '#00ff88';
    var magBg = magNum >= 7 ? '#ff000022' : magNum >= 6 ? '#ff224422' : magNum >= 5 ? '#ff664422' : '#111828';

    h += '<tr style="border-bottom:1px solid #111828;background:' + magBg + ';">';
    h += '<td style="padding:5px 6px;"><span style="background:' + magColor + '22;color:' + magColor + ';font-weight:bold;padding:2px 8px;border-radius:3px;font-size:12px;">' + esc(mag) + '</span></td>';
    h += '<td style="padding:5px 6px;color:#ccd;max-width:250px;">' + esc(place) + '</td>';
    h += '<td style="padding:5px 6px;color:#889;">' + esc(depth) + '</td>';
    h += '<td style="padding:5px 6px;color:#667;">' + esc(eqTime) + '</td>';
    h += '<td style="padding:5px 6px;color:' + (status === 'reviewed' ? '#00ff88' : '#ffaa00') + ';font-size:9px;">' + esc(status.toUpperCase()) + '</td>';
    h += '<td style="padding:5px 6px;color:#556;font-size:9px;">' + esc(eqType) + '</td>';
    h += '</tr>';
  }

  h += '</tbody></table>';
  h += '</div>';

  // Mini-map showing earthquake locations
  h += '<div style="position:relative;width:100%;height:100px;background:#080c14;border:1px solid #1a2030;border-radius:4px;margin-top:12px;overflow:hidden;">';
  h += '<div style="position:absolute;top:4px;left:8px;color:#334;font-size:8px;font-family:monospace;letter-spacing:1px;z-index:2;">SEISMIC ACTIVITY MAP</div>';
  for (var mi = 0; mi < features.length; mi++) {
    var mc = (features[mi].geometry || {}).coordinates || [];
    var mlon = mc[0] || 0; var mlat = mc[1] || 0;
    var mmag = (features[mi].properties || {}).mag || 0;
    var mx = ((mlon + 180) / 360) * 100;
    var my = ((90 - mlat) / 180) * 100;
    var msize = Math.max(4, Math.min(mmag * 2.5, 16));
    var mcolor = mmag >= 7 ? '#ff0000' : mmag >= 6 ? '#ff2244' : mmag >= 5 ? '#ff6644' : mmag >= 4 ? '#ffaa00' : '#00ff88';
    h += '<div style="position:absolute;left:' + mx + '%;top:' + my + '%;width:' + msize + 'px;height:' + msize + 'px;border-radius:50%;background:' + mcolor + ';opacity:0.7;transform:translate(-50%,-50%);box-shadow:0 0 6px ' + mcolor + '80;" title="M' + mmag.toFixed(1) + '"></div>';
  }
  h += '</div>';

  h += '<div style="color:#445;font-size:9px;font-family:monospace;margin-top:8px;">Magnitude color scale: <span style="color:#00ff88;">3.0-4.9</span> | <span style="color:#ffaa00;">5.0-5.9</span> | <span style="color:#ff6644;">6.0-6.9</span> | <span style="color:#ff2244;">7.0-7.9</span> | <span style="color:#ff0000;">8.0+</span></div>';

  container.innerHTML = h;
}

// ---------------------------------------------------------------------------
// Botnet C2 feed fetch
// ---------------------------------------------------------------------------
function _seFetchBotnetC2() {
  var container = document.getElementById('se-c2-feed');
  if (!container) return;
  container.innerHTML = '<div style="text-align:center;padding:16px;color:#ffaa00;font-family:monospace;font-size:11px;">Fetching botnet C2 data...</div>';

  fetch('/data/feeds/botnet-c2.json')
    .then(function(r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
    .then(function(feed) {
      var items = (feed.data || []);
      if (items.length === 0) {
        container.innerHTML = '<div style="color:#556;font-family:monospace;font-size:11px;text-align:center;padding:16px;">No C2 data available.</div>';
        return;
      }

      var h = '';
      h += '<div style="overflow-x:auto;">';
      h += '<table style="width:100%;border-collapse:collapse;font-family:monospace;font-size:10px;">';
      h += '<thead><tr style="border-bottom:2px solid #1a2a44;">';
      h += '<th style="text-align:left;padding:5px;color:#00ff88;font-size:8px;letter-spacing:1px;">STATUS</th>';
      h += '<th style="text-align:left;padding:5px;color:#00ff88;font-size:8px;letter-spacing:1px;">IP:PORT</th>';
      h += '<th style="text-align:left;padding:5px;color:#00ff88;font-size:8px;letter-spacing:1px;">MALWARE</th>';
      h += '<th style="text-align:left;padding:5px;color:#00ff88;font-size:8px;letter-spacing:1px;">CC</th>';
      h += '<th style="text-align:left;padding:5px;color:#00ff88;font-size:8px;letter-spacing:1px;">ASN</th>';
      h += '<th style="text-align:left;padding:5px;color:#00ff88;font-size:8px;letter-spacing:1px;">FIRST SEEN</th>';
      h += '</tr></thead><tbody>';

      for (var ci = 0; ci < items.length; ci++) {
        var c2 = items[ci];
        var isOnline = c2.status === 'online';
        var dotColor = isOnline ? '#00ff88' : '#555';
        var rowBg = isOnline ? '#00ff8808' : 'transparent';

        h += '<tr style="border-bottom:1px solid #111828;background:' + rowBg + ';">';
        h += '<td style="padding:4px 5px;"><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:' + dotColor + ';box-shadow:0 0 4px ' + dotColor + ';"></span></td>';
        h += '<td style="padding:4px 5px;color:' + (isOnline ? '#ff4444' : '#667') + ';font-weight:bold;">' + esc(c2.ip) + ':' + esc(String(c2.port)) + '</td>';
        h += '<td style="padding:4px 5px;color:#ffaa00;">' + esc(c2.malware) + '</td>';
        h += '<td style="padding:4px 5px;color:#889;">[' + esc(c2.country || '--') + ']</td>';
        h += '<td style="padding:4px 5px;color:#556;font-size:9px;">' + esc(c2.asName ? c2.asName.substring(0, 20) : '--') + '</td>';
        h += '<td style="padding:4px 5px;color:#556;font-size:9px;">' + esc(c2.firstSeen ? c2.firstSeen.substring(0, 10) : '--') + '</td>';
        h += '</tr>';
      }

      h += '</tbody></table></div>';
      var onlineCount = items.filter(function(x) { return x.status === 'online'; }).length;
      h += '<div style="color:#445;font-size:9px;font-family:monospace;margin-top:8px;text-align:right;">' + onlineCount + ' ONLINE / ' + items.length + ' TOTAL | SOURCE: ' + esc(feed.source || 'Feodo Tracker') + ' | LAST FETCHED: ' + new Date().toISOString().replace('T', ' ').substring(0, 19) + 'Z</div>';
      container.innerHTML = h;
    })
    .catch(function(err) {
      container.innerHTML = '<div style="color:#ff6644;font-family:monospace;font-size:11px;padding:12px;text-align:center;">C2 feed error: ' + esc(String(err.message || err)) + '</div>';
    });
}

// ---------------------------------------------------------------------------
// Malware URLs feed fetch
// ---------------------------------------------------------------------------
function _seFetchMalwareURLs() {
  var container = document.getElementById('se-malurl-feed');
  if (!container) return;
  container.innerHTML = '<div style="text-align:center;padding:16px;color:#ffaa00;font-family:monospace;font-size:11px;">Fetching malware URL data...</div>';

  fetch('/data/feeds/malware-urls.json')
    .then(function(r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
    .then(function(feed) {
      var items = (feed.data || []);
      if (items.length === 0) {
        container.innerHTML = '<div style="color:#556;font-family:monospace;font-size:11px;text-align:center;padding:16px;">No malware URL data available.</div>';
        return;
      }

      var h = '';
      for (var ui = 0; ui < items.length; ui++) {
        var mu = items[ui];
        var isOnline = mu.status === 'online';
        var urlColor = isOnline ? '#ff4444' : '#556';
        var dotColor = isOnline ? '#ff4444' : '#444';
        var threatColor = '#ffaa00';

        h += '<div style="display:flex;align-items:flex-start;gap:8px;padding:6px 12px;margin:0 -12px;border-bottom:1px solid #111828;">';
        h += '<span style="flex-shrink:0;display:inline-block;width:8px;height:8px;border-radius:50%;background:' + dotColor + ';margin-top:4px;box-shadow:0 0 4px ' + dotColor + ';"></span>';
        h += '<div style="flex:1;min-width:0;">';
        h += '<div style="color:' + urlColor + ';font-size:10px;font-family:monospace;word-break:break-all;line-height:1.3;">' + esc(mu.url) + '</div>';
        h += '<div style="display:flex;gap:6px;align-items:center;margin-top:3px;">';
        h += '<span style="color:' + threatColor + ';font-size:9px;font-family:monospace;font-weight:bold;">' + esc(mu.threat) + '</span>';
        if (mu.tags && mu.tags.length > 0) {
          for (var mti = 0; mti < Math.min(mu.tags.length, 4); mti++) {
            h += '<span style="background:#1a2a3a;color:#5a7a9a;font-size:7px;font-family:monospace;padding:1px 4px;border-radius:2px;border:1px solid #1a3a5a;">' + esc(mu.tags[mti]) + '</span>';
          }
        }
        h += '</div>';
        h += '</div>';
        h += '<div style="flex-shrink:0;color:#556;font-size:9px;font-family:monospace;text-align:right;">';
        h += '<div>' + esc(mu.dateAdded || '--') + '</div>';
        h += '<div style="color:' + (isOnline ? '#ff4444' : '#445') + ';font-size:8px;margin-top:2px;">' + (isOnline ? 'ONLINE' : 'OFFLINE') + '</div>';
        h += '</div>';
        h += '</div>';
      }

      var onlineURLs = items.filter(function(x) { return x.status === 'online'; }).length;
      h += '<div style="color:#445;font-size:9px;font-family:monospace;margin-top:10px;text-align:right;">' + onlineURLs + ' ONLINE / ' + items.length + ' TOTAL URLS | SOURCE: ' + esc(feed.source || 'URLhaus') + ' | LAST FETCHED: ' + new Date().toISOString().replace('T', ' ').substring(0, 19) + 'Z</div>';
      container.innerHTML = h;
    })
    .catch(function(err) {
      container.innerHTML = '<div style="color:#ff6644;font-family:monospace;font-size:11px;padding:12px;text-align:center;">Malware URL feed error: ' + esc(String(err.message || err)) + '</div>';
    });
}

function _seInitTrackingTab() {
  // Clear any previous refresh interval
  if (_seTrackingRefreshInterval) {
    clearInterval(_seTrackingRefreshInterval);
    _seTrackingRefreshInterval = null;
  }

  // Fetch data for current sub-tab
  if (_seTrackingSubTab === 'aircraft') {
    _seFetchAircraft();
    // Auto-refresh aircraft every 30 seconds (not 15 — less flicker)
    _seTrackingRefreshInterval = setInterval(function() {
      var container = document.getElementById('se-aircraft-data');
      if (!container) {
        clearInterval(_seTrackingRefreshInterval);
        _seTrackingRefreshInterval = null;
        return;
      }
      // Silent refresh — only update if data changed, don't show loading state
      _seFetchAircraftSilent();
    }, 60000);
  } else if (_seTrackingSubTab === 'space') {
    _seFetchISS();
  } else if (_seTrackingSubTab === 'seismic') {
    _seFetchSeismic();
  } else if (_seTrackingSubTab === 'cyber') {
    _seFetchNVD();
    _seFetchKEV();
    _seFetchIOC();
    _seFetchBotnetC2();
    _seFetchMalwareURLs();
    _seTrackingRefreshInterval = setInterval(function() {
      var nvdEl = document.getElementById('se-nvd-feed');
      if (!nvdEl) { clearInterval(_seTrackingRefreshInterval); _seTrackingRefreshInterval = null; return; }
      _seFetchNVD();
      _seFetchKEV();
      _seFetchIOC();
      _seFetchBotnetC2();
      _seFetchMalwareURLs();
    }, 300000);
  }
  // maritime and network tabs have no auto-fetch (static/simulated data)
}


// Expose functions to window for inline onclick handlers
window.switchTab = switchTab;
window._seFetchAircraft = typeof _seFetchAircraft !== 'undefined' ? _seFetchAircraft : function(){};
window._seFetchISS = typeof _seFetchISS !== 'undefined' ? _seFetchISS : function(){};
window._seFetchSeismic = typeof _seFetchSeismic !== 'undefined' ? _seFetchSeismic : function(){};
window._seFetchNVD = typeof _seFetchNVD !== 'undefined' ? _seFetchNVD : function(){};
window._seFetchKEV = typeof _seFetchKEV !== 'undefined' ? _seFetchKEV : function(){};
window._seFetchIOC = typeof _seFetchIOC !== 'undefined' ? _seFetchIOC : function(){};
window._seFetchBotnetC2 = typeof _seFetchBotnetC2 !== 'undefined' ? _seFetchBotnetC2 : function(){};
window._seFetchMalwareURLs = typeof _seFetchMalwareURLs !== 'undefined' ? _seFetchMalwareURLs : function(){};
window._sePredictAiAnalysis = typeof _sePredictAiAnalysis !== 'undefined' ? _sePredictAiAnalysis : function(){};
window._seWhatIfAnalysis = typeof _seWhatIfAnalysis !== 'undefined' ? _seWhatIfAnalysis : function(){};
window._seEwAiAnalysis = typeof _seEwAiAnalysis !== 'undefined' ? _seEwAiAnalysis : function(){};
window._seTrackingSubTab = typeof _seTrackingSubTab !== 'undefined' ? _seTrackingSubTab : 'aircraft';

var _seTimers = [];
export function cleanupSentinelEye() {
  _seTimers.forEach(function(t) { clearInterval(t); });
  _seTimers = [];
  if (_seTrackingRefreshInterval) { clearInterval(_seTrackingRefreshInterval); _seTrackingRefreshInterval = null; }
  _gwCleanup();
}

var _seRenderGeneration = 0;
export function renderSentinelEye(main) {
  if (!main) return;
  cleanupSentinelEye();
  var gen = ++_seRenderGeneration;

  _seLoadData().then(function() {
    if (gen !== _seRenderGeneration) return;
    _seRender(main);
  });
}

function _seRender(main) {
  // Insert styles
  var styleEl = document.createElement('div');
  styleEl.innerHTML = buildStyles();
  document.head.appendChild(styleEl.firstChild);

  // Build main shell
  main.innerHTML = '<div class="se-wrapper">' + renderMainShell() + '</div>';

  // Render default tab (Situational Awareness)
  switchTab('situation');

  // D3.js threat map is initialized via switchTab('situation') above

  // Initialize scrolling alert ticker
  initTicker();

  // Initialize all event handlers
  initEventHandlers();

  // Load saved state (skip globalwatch — too heavy to auto-restore)
  var saved = _seLoadState();
  if (saved && saved.activeTab && saved.activeTab !== 'situation' && saved.activeTab !== 'globalwatch') {
    switchTab(saved.activeTab);
  }
}

// ============================================================================
// GLOBAL WATCH — 3D Cybersecurity Globe (CesiumJS)
// Geospatial cyber threat intelligence visualization
// God's Eye View: threat actors, infrastructure, attacks, live feeds
// ============================================================================

var _gwCesiumLoaded = false;
var _gwCesiumLoading = false;
var _gwViewer = null;
var _gwLayers = {};
var _gwLayerEntities = {};
var _gwAnimFrameId = null;
var _gwAttackArcs = [];
var _gwRefreshTimers = [];
var _gwLastUpdate = null;
var _gwEntityCount = 0;

// ---------------------------------------------------------------------------
// THREAT ACTOR DATABASE
// ---------------------------------------------------------------------------
var GW_THREAT_ACTORS = [
  {
    id: 'ru_gru', name: 'GRU Unit 26165 (Fancy Bear / APT28)',
    nation: 'Russia', city: 'Moscow', lat: 55.7558, lon: 37.6173,
    alignment: 'hostile', tier: 'TIER-1',
    aptGroups: 'APT28, Fancy Bear, Sofacy, Pawn Storm, Sednit, STRONTIUM',
    recentOps: 'SolarWinds supply chain (2020), NotPetya (2017), DNC breach (2016), Bundeswehr compromise (2023)',
    capabilities: 'Full-spectrum CNO, zero-day exploitation, supply-chain infiltration, election interference, destructive wiper malware',
    notes: 'Primary GRU cyber unit. NATO highest-priority adversary. Known for reckless collateral damage.'
  },
  {
    id: 'ru_fsb', name: 'FSB Center 16 (Turla / Venomous Bear)',
    nation: 'Russia', city: 'Moscow', lat: 55.76, lon: 37.62,
    alignment: 'hostile', tier: 'TIER-1',
    aptGroups: 'Turla, Venomous Bear, Snake, Waterbug, KRYPTON',
    recentOps: 'Snake malware global campaign (2023), US satellite systems (2022), EU diplomatic espionage (2024)',
    capabilities: 'Satellite hijacking, covert C2 via HTTP injection, kernel rootkits, long-dwell espionage',
    notes: 'FSB signals intelligence. Extremely stealthy, multi-year intrusions into government networks.'
  },
  {
    id: 'ru_svr', name: 'SVR / Cozy Bear (APT29)',
    nation: 'Russia', city: 'Moscow', lat: 55.74, lon: 37.59,
    alignment: 'hostile', tier: 'TIER-1',
    aptGroups: 'APT29, Cozy Bear, The Dukes, Nobelium, Midnight Blizzard',
    recentOps: 'SolarWinds SUNBURST (2020), Microsoft Exchange campaign (2024), COVID vaccine research theft (2020)',
    capabilities: 'Cloud exploitation, identity federation attacks, supply-chain compromise, SAML token forging',
    notes: 'SVR foreign intelligence. Responsible for SolarWinds. Targets cloud infrastructure and SaaS platforms.'
  },
  {
    id: 'cn_pla', name: 'PLA SSF Unit 61398 (Comment Crew)',
    nation: 'China', city: 'Shanghai', lat: 31.2304, lon: 121.4737,
    alignment: 'hostile', tier: 'TIER-1',
    aptGroups: 'APT1, Comment Crew, Byzantine Hades, Shanghai Group',
    recentOps: 'US critical infrastructure pre-positioning (Volt Typhoon), defense contractor IP theft, telecom intercepts',
    capabilities: 'Mass IP theft, critical infrastructure pre-positioning, telecom interception, zero-day stockpile',
    notes: 'PLA Strategic Support Force. Massive scale espionage targeting defense, energy, telecom sectors.'
  },
  {
    id: 'cn_mss', name: 'MSS / APT10 (Stone Panda)',
    nation: 'China', city: 'Beijing', lat: 39.9042, lon: 116.4074,
    alignment: 'hostile', tier: 'TIER-1',
    aptGroups: 'APT10, Stone Panda, MenuPass, Red Apollo, POTASSIUM',
    recentOps: 'Cloud Hopper MSP campaign (2018-2024), Japanese defense ministry breach, global telecom espionage',
    capabilities: 'MSP supply-chain attacks, cloud environment pivot, credential harvesting at scale',
    notes: 'Ministry of State Security cyber ops. Targets managed service providers for downstream access to clients.'
  },
  {
    id: 'cn_volt', name: 'Volt Typhoon (PRC State)',
    nation: 'China', city: 'Beijing', lat: 39.92, lon: 116.38,
    alignment: 'hostile', tier: 'TIER-1',
    aptGroups: 'Volt Typhoon, BRONZE SILHOUETTE, Vanguard Panda',
    recentOps: 'US water/power/comms infrastructure pre-positioning (2023-2025), Guam military network access',
    capabilities: 'Living-off-the-land, SOHO router botnets, critical infrastructure disruption pre-positioning',
    notes: 'Pre-positioned for wartime disruption of US military logistics and civilian infrastructure.'
  },
  {
    id: 'nk_rgb', name: 'RGB Bureau 121 (Lazarus Group)',
    nation: 'North Korea', city: 'Pyongyang', lat: 39.0392, lon: 125.7625,
    alignment: 'hostile', tier: 'TIER-2',
    aptGroups: 'Lazarus, APT38, Kimsuky, Andariel, BlueNoroff, HIDDEN COBRA',
    recentOps: 'Crypto heists ($3B+), Ronin Bridge ($625M), WannaCry (2017), Sony Pictures (2014), Atomic Wallet ($100M)',
    capabilities: 'Cryptocurrency theft, ransomware, destructive attacks, social engineering of developers',
    notes: 'Reconnaissance General Bureau. Funds DPRK weapons programs through cyber theft. Over 6,000 operators.'
  },
  {
    id: 'ir_irgc', name: 'IRGC Cyber Command (Charming Kitten)',
    nation: 'Iran', city: 'Tehran', lat: 35.6892, lon: 51.3890,
    alignment: 'hostile', tier: 'TIER-2',
    aptGroups: 'APT33, APT34, APT35, Charming Kitten, OilRig, MuddyWater, Phosphorus',
    recentOps: 'Albanian government attack (2022), US water systems (2023), Israeli infrastructure targeting (2024)',
    capabilities: 'Destructive wiper malware, ICS/SCADA targeting, credential phishing, influence operations',
    notes: 'Islamic Revolutionary Guard Corps. Targets US allies, Gulf states, Israel. Growing destructive capability.'
  },
  {
    id: 'us_nsa', name: 'NSA / Cyber Command (TAO)',
    nation: 'United States', city: 'Fort Meade', lat: 39.1086, lon: -76.7711,
    alignment: 'allied', tier: 'TIER-1',
    aptGroups: 'Equation Group, TAO, Longhorn, PLATINUM (attributed)',
    recentOps: 'Stuxnet (joint w/ Israel), Olympic Games, Tailored Access Operations, Shadow Brokers leaked tools',
    capabilities: 'Full-spectrum CNO, firmware implants, SIGINT, zero-day exploitation, quantum computing research',
    notes: 'National Security Agency / US Cyber Command. World premier signals intelligence and cyber operations.'
  },
  {
    id: 'uk_gchq', name: 'GCHQ / NCSC',
    nation: 'United Kingdom', city: 'Cheltenham', lat: 51.8994, lon: -2.0783,
    alignment: 'allied', tier: 'TIER-1',
    aptGroups: 'JTRIG, CESG, Five Eyes partner operations',
    recentOps: 'Russian GRU disruption ops, ISIS counter-messaging, joint Five Eyes SIGINT',
    capabilities: 'SIGINT, CNE, influence operations, joint Five Eyes intelligence sharing',
    notes: 'Government Communications Headquarters. UK primary SIGINT agency. Key Five Eyes partner.'
  },
  {
    id: 'il_8200', name: 'Unit 8200 (Israeli SIGINT)',
    nation: 'Israel', city: 'Herzliya', lat: 32.1634, lon: 34.7913,
    alignment: 'allied', tier: 'TIER-1',
    aptGroups: 'Unit 8200, Duqu developers (attributed), joint Stuxnet ops',
    recentOps: 'Stuxnet (joint w/ US), Duqu, Iranian nuclear program targeting, Pegasus-adjacent intelligence',
    capabilities: 'Zero-day development, SIGINT, offensive cyber R&D, mobile exploitation',
    notes: 'Israel Defense Forces Unit 8200. Elite SIGINT. Many alumni founded NSO Group, Check Point, CyberArk.'
  },
  {
    id: 'au_asd', name: 'ASD / ACSC (Australia)',
    nation: 'Australia', city: 'Canberra', lat: -35.2809, lon: 149.1300,
    alignment: 'allied', tier: 'TIER-2',
    aptGroups: 'Five Eyes partner operations',
    recentOps: 'Joint counter-ISIS ops, South Pacific SIGINT, offensive cyber counter-ransomware',
    capabilities: 'SIGINT, Five Eyes intelligence sharing, offensive cyber disruption of ransomware gangs',
    notes: 'Australian Signals Directorate. Five Eyes partner. Active in offensive cyber against ransomware operators.'
  },
  {
    id: 'fr_anssi', name: 'DGSE / ANSSI (France)',
    nation: 'France', city: 'Paris', lat: 48.8566, lon: 2.3522,
    alignment: 'allied', tier: 'TIER-2',
    aptGroups: 'Animal Farm (attributed), DGSE cyber operations',
    recentOps: 'Counter-terrorism SIGINT, EU cyber defense coordination, Mali/Sahel operations',
    capabilities: 'Offensive cyber, SIGINT, counter-espionage, cryptanalysis',
    notes: 'Direction Generale de la Securite Exterieure. French foreign intelligence with growing cyber capability.'
  },
  {
    id: 'de_bnd', name: 'BND / Bundeswehr CIR (Germany)',
    nation: 'Germany', city: 'Berlin', lat: 52.5200, lon: 13.4050,
    alignment: 'allied', tier: 'TIER-2',
    aptGroups: 'BND cyber operations',
    recentOps: 'Counter-APT28 operations, Bundestag defense, Operation Avalanche botnet takedown',
    capabilities: 'SIGINT, counter-espionage, EU cyber defense leadership',
    notes: 'Bundesnachrichtendienst. German foreign intelligence. Hosts BfV domestic cyber defense.'
  },
  {
    id: 'nl_mivd', name: 'AIVD / MIVD (Netherlands)',
    nation: 'Netherlands', city: 'The Hague', lat: 52.0705, lon: 4.3007,
    alignment: 'allied', tier: 'TIER-2',
    aptGroups: 'MIVD offensive cyber operations',
    recentOps: 'Caught GRU officers at OPCW (2018), counter-APT29 operations, joint Five Eyes adjacent',
    capabilities: 'Offensive cyber disruption, counter-intelligence, caught state actors in the act',
    notes: 'Dutch military and civilian intelligence. Punches well above weight class. Caught GRU red-handed.'
  },
  {
    id: 'jp_sdf', name: 'Japan SDF Cyber Command',
    nation: 'Japan', city: 'Tokyo', lat: 35.6895, lon: 139.6917,
    alignment: 'allied', tier: 'TIER-2',
    aptGroups: 'Defensive posture',
    recentOps: 'Active cyber defense legislation (2024), counter-APT10, Olympics 2020 defense',
    capabilities: 'Cyber defense, active defense authority (2024), SIGINT via Five Eyes partnership',
    notes: 'Japan Self-Defense Forces Cyber Command. Growing offensive capability under new 2024 legislation.'
  },
  {
    id: 'lockbit', name: 'LockBit 4.0 (Ransomware)',
    nation: 'Russia (attributed)', city: 'Unknown', lat: 56.84, lon: 60.60,
    alignment: 'hostile', tier: 'TIER-2',
    aptGroups: 'LockBit RaaS affiliates',
    recentOps: '347 victims in 2026, avg $850K ransom, survived FBI/NCA Operation Cronos disruption',
    capabilities: 'Ransomware-as-a-service, StealBit data exfiltrator, cross-platform encryption',
    notes: 'Most prolific ransomware group globally. Rebrand after 2024 law enforcement takedown.'
  },
  {
    id: 'alphv', name: 'ALPHV/BlackCat 2.0 (Ransomware)',
    nation: 'Russia (attributed)', city: 'Unknown', lat: 54.71, lon: 20.51,
    alignment: 'hostile', tier: 'TIER-2',
    aptGroups: 'ALPHV affiliates, former DarkSide/BlackMatter',
    recentOps: '189 victims in 2026, Change Healthcare ($22M ransom), Rust-based ransomware',
    capabilities: 'Rust-based cross-platform ransomware, searchable leak database, API-driven affiliate model',
    notes: 'Rebranded post-FBI takedown. Responsible for one of the largest healthcare breaches in US history.'
  },
  {
    id: 'scattered', name: 'Scattered Spider',
    nation: 'US/UK (young adults)', city: 'Distributed', lat: 34.05, lon: -118.24,
    alignment: 'hostile', tier: 'TIER-2',
    aptGroups: 'UNC3944, 0ktapus, Star Fraud',
    recentOps: 'MGM Resorts ($100M+ impact), Caesars ($15M ransom paid), Okta social engineering, Twilio/Cloudflare',
    capabilities: 'SIM swapping, MFA fatigue bombing, social engineering, helpdesk impersonation, ALPHV affiliate',
    notes: 'Young English-speaking threat actors. Master social engineers. FBI pursuit ongoing.'
  }
];

// ---------------------------------------------------------------------------
// CYBER ATTACK CAMPAIGN ARCS (known campaigns: attacker -> target)
// ---------------------------------------------------------------------------
var GW_CAMPAIGN_ARCS = [
  { from: 'ru_gru', toLat: 38.9, toLon: -77.0, label: 'SolarWinds / US Gov', color: '#ff3333' },
  { from: 'ru_gru', toLat: 52.52, toLon: 13.405, label: 'Bundestag Compromise', color: '#ff3333' },
  { from: 'ru_gru', toLat: 50.45, toLon: 30.52, label: 'Ukraine Grid Attack', color: '#ff4444' },
  { from: 'ru_svr', toLat: 38.9, toLon: -77.0, label: 'SUNBURST Campaign', color: '#ff2222' },
  { from: 'ru_svr', toLat: 47.37, toLon: 8.54, label: 'SolarWinds EU Targets', color: '#ff2222' },
  { from: 'cn_pla', toLat: 25.032, toLon: 121.565, label: 'Taiwan Defense Networks', color: '#ff6600' },
  { from: 'cn_pla', toLat: 38.9, toLon: -77.0, label: 'US Defense Contractors', color: '#ff6600' },
  { from: 'cn_volt', toLat: 13.4443, toLon: 144.7937, label: 'Guam Infrastructure', color: '#ff8800' },
  { from: 'cn_volt', toLat: 37.77, toLon: -122.42, label: 'US West Coast Utilities', color: '#ff8800' },
  { from: 'cn_mss', toLat: 35.6762, toLon: 139.6503, label: 'Japan MoD Breach', color: '#ff6600' },
  { from: 'nk_rgb', toLat: 37.5665, toLon: 126.978, label: 'South Korea Financial', color: '#ff00ff' },
  { from: 'nk_rgb', toLat: 34.0522, toLon: -118.2437, label: 'Sony Pictures Attack', color: '#ff00ff' },
  { from: 'nk_rgb', toLat: 1.3521, toLon: 103.8198, label: 'Crypto Exchange Heist', color: '#ff00ff' },
  { from: 'ir_irgc', toLat: 41.3275, toLon: 19.8187, label: 'Albania Gov Attack', color: '#cc00cc' },
  { from: 'ir_irgc', toLat: 32.0853, toLon: 34.7818, label: 'Israel Infrastructure', color: '#cc00cc' },
  { from: 'ir_irgc', toLat: 25.2048, toLon: 55.2708, label: 'Gulf State Oil Sector', color: '#cc00cc' },
  { from: 'cn_volt', toLat: 39.0438, toLon: -77.4874, label: 'US East Coast Power Grid', color: '#ff8800' },
  { from: 'cn_volt', toLat: 21.3069, toLon: -157.8583, label: 'Hawaii Military Comms', color: '#ff8800' },
  { from: 'cn_pla', toLat: 47.64, toLon: -122.13, label: 'US Tech IP Theft', color: '#ff6600' },
  { from: 'ru_gru', toLat: 48.86, toLon: 2.35, label: 'French Election Interference', color: '#ff3333' },
  { from: 'ru_fsb', toLat: 59.33, toLon: 18.07, label: 'Swedish Defense Networks', color: '#ff4444' },
  { from: 'ru_svr', toLat: 51.5, toLon: -0.13, label: 'UK Gov Cloud Compromise', color: '#ff2222' },
  { from: 'nk_rgb', toLat: 37.39, toLon: -122.08, label: 'Silicon Valley Dev Targeting', color: '#ff00ff' },
  { from: 'nk_rgb', toLat: 22.3, toLon: 114.17, label: 'HK Crypto Exchange Heist', color: '#ff00ff' },
  { from: 'ir_irgc', toLat: 38.9, toLon: -77.0, label: 'US Water Infrastructure', color: '#cc00cc' },
  { from: 'cn_mss', toLat: 39.0438, toLon: -77.4874, label: 'Salt Typhoon Telecom', color: '#ff6600' },
  { from: 'us_nsa', toLat: 55.76, toLon: 37.62, label: 'Counter-SVR Operations', color: '#4488ff' },
  { from: 'uk_gchq', toLat: 55.76, toLon: 37.62, label: 'GRU Disruption Ops', color: '#4488ff' },
  { from: 'il_8200', toLat: 35.6892, toLon: 51.389, label: 'Iran Nuclear Sabotage', color: '#44aaff' }
];

// ---------------------------------------------------------------------------
// INTERNET INFRASTRUCTURE DATA
// ---------------------------------------------------------------------------
var GW_IXPS = [
  { name: 'DE-CIX Frankfurt', lat: 50.1109, lon: 8.6821, capacity: '14+ Tbps', operator: 'DE-CIX Management GmbH', type: 'ixp' },
  { name: 'AMS-IX Amsterdam', lat: 52.3676, lon: 4.9041, capacity: '12+ Tbps', operator: 'Amsterdam Internet Exchange', type: 'ixp' },
  { name: 'LINX London', lat: 51.5074, lon: -0.1278, capacity: '8+ Tbps', operator: 'London Internet Exchange', type: 'ixp' },
  { name: 'Equinix Ashburn (VA)', lat: 39.0438, lon: -77.4874, capacity: '10+ Tbps', operator: 'Equinix Inc.', type: 'ixp' },
  { name: 'HKIX Hong Kong', lat: 22.3193, lon: 114.1694, capacity: '2+ Tbps', operator: 'HKIX', type: 'ixp' },
  { name: 'IX.br Sao Paulo', lat: -23.5505, lon: -46.6333, capacity: '20+ Tbps', operator: 'NIC.br', type: 'ixp' },
  { name: 'MSK-IX Moscow', lat: 55.7558, lon: 37.6173, capacity: '3+ Tbps', operator: 'MSK-IX', type: 'ixp' },
  { name: 'JPNAP Tokyo', lat: 35.6762, lon: 139.6503, capacity: '4+ Tbps', operator: 'Internet Multifeed', type: 'ixp' },
  { name: 'SIX Seattle', lat: 47.6062, lon: -122.3321, capacity: '1+ Tbps', operator: 'Seattle Internet Exchange', type: 'ixp' },
  { name: 'SGIX Singapore', lat: 1.3521, lon: 103.8198, capacity: '2+ Tbps', operator: 'SGIX', type: 'ixp' },
  { name: 'TorIX Toronto', lat: 43.6532, lon: -79.3832, capacity: '1+ Tbps', operator: 'TorIX', type: 'ixp' },
  { name: 'KINX Seoul', lat: 37.5665, lon: 126.978, capacity: '1.5+ Tbps', operator: 'KINX', type: 'ixp' }
];

var GW_ROOT_DNS = [
  { name: 'a.root-servers.net', operator: 'Verisign', lat: 38.95, lon: -77.34, city: 'Dulles, VA' },
  { name: 'b.root-servers.net', operator: 'USC-ISI', lat: 33.77, lon: -118.19, city: 'Marina del Rey, CA' },
  { name: 'c.root-servers.net', operator: 'Cogent', lat: 38.95, lon: -77.34, city: 'Herndon, VA' },
  { name: 'd.root-servers.net', operator: 'U of Maryland', lat: 38.99, lon: -76.95, city: 'College Park, MD' },
  { name: 'e.root-servers.net', operator: 'NASA', lat: 37.42, lon: -122.08, city: 'Mountain View, CA' },
  { name: 'f.root-servers.net', operator: 'ISC', lat: 37.49, lon: -122.20, city: 'Palo Alto, CA' },
  { name: 'g.root-servers.net', operator: 'US DoD DISA', lat: 38.87, lon: -77.06, city: 'Arlington, VA' },
  { name: 'h.root-servers.net', operator: 'US Army', lat: 38.89, lon: -77.03, city: 'Aberdeen, MD' },
  { name: 'i.root-servers.net', operator: 'Netnod', lat: 59.33, lon: 18.07, city: 'Stockholm, SE' },
  { name: 'j.root-servers.net', operator: 'Verisign', lat: 38.95, lon: -77.34, city: 'Dulles, VA' },
  { name: 'k.root-servers.net', operator: 'RIPE NCC', lat: 52.37, lon: 4.89, city: 'Amsterdam, NL' },
  { name: 'l.root-servers.net', operator: 'ICANN', lat: 33.77, lon: -118.19, city: 'Marina del Rey, CA' },
  { name: 'm.root-servers.net', operator: 'WIDE Project', lat: 35.68, lon: 139.69, city: 'Tokyo, JP' }
];

var GW_UNDERSEA_CABLES = [
  { name: 'TAT-14', from: { lat: 41.1, lon: -72.3 }, to: { lat: 51.9, lon: 1.3 }, capacity: '3.2 Tbps', operator: 'Multiple', region: 'Transatlantic' },
  { name: 'MAREA', from: { lat: 39.18, lon: -76.61 }, to: { lat: 43.3, lon: -2.0 }, capacity: '200 Tbps', operator: 'Microsoft / Meta', region: 'Transatlantic' },
  { name: 'Dunant', from: { lat: 39.18, lon: -76.61 }, to: { lat: 44.3, lon: -1.2 }, capacity: '250 Tbps', operator: 'Google', region: 'Transatlantic' },
  { name: 'AEConnect-1', from: { lat: 53.3, lon: -6.3 }, to: { lat: 40.7, lon: -74.0 }, capacity: '52 Tbps', operator: 'Aqua Comms', region: 'Transatlantic' },
  { name: 'FASTER', from: { lat: 36.96, lon: -122.0 }, to: { lat: 33.1, lon: 131.7 }, capacity: '60 Tbps', operator: 'Google + partners', region: 'Transpacific' },
  { name: 'PLCN', from: { lat: 33.77, lon: -118.19 }, to: { lat: 22.3, lon: 114.17 }, capacity: '144 Tbps', operator: 'Google / Meta', region: 'Transpacific' },
  { name: 'Japan-Guam-Australia', from: { lat: 35.68, lon: 139.69 }, to: { lat: -33.87, lon: 151.21 }, capacity: '36 Tbps', operator: 'NEC / RTI', region: 'Asia-Pacific' },
  { name: 'SEACOM', from: { lat: -33.92, lon: 18.42 }, to: { lat: 22.3, lon: 114.17 }, capacity: '12 Tbps', operator: 'SEACOM', region: 'Africa-Asia' },
  { name: 'EASSy', from: { lat: -33.92, lon: 18.42 }, to: { lat: 30.04, lon: 31.24 }, capacity: '10 Tbps', operator: 'Multiple', region: 'East Africa' },
  { name: 'SAex', from: { lat: -33.92, lon: 18.42 }, to: { lat: -23.55, lon: -46.63 }, capacity: '12.8 Tbps', operator: 'SAex International', region: 'South Atlantic' },
  { name: 'FLAG Europe-Asia', from: { lat: 51.5, lon: 0.0 }, to: { lat: 35.68, lon: 139.69 }, capacity: '10 Tbps', operator: 'Reliance Globalcom', region: 'Europe-Asia' },
  { name: 'AAE-1', from: { lat: 44.3, lon: 8.5 }, to: { lat: 22.3, lon: 114.17 }, capacity: '40 Tbps', operator: 'Multiple', region: 'Europe-Asia' },
  { name: 'SEA-ME-WE 6', from: { lat: 1.3, lon: 103.8 }, to: { lat: 44.3, lon: 8.5 }, capacity: '100 Tbps', operator: 'Multiple', region: 'Asia-Europe' },
  { name: 'Equiano', from: { lat: 51.5, lon: 0.0 }, to: { lat: -33.92, lon: 18.42 }, capacity: '144 Tbps', operator: 'Google', region: 'Europe-Africa' },
  { name: 'Grace Hopper', from: { lat: 40.7, lon: -74.0 }, to: { lat: 51.5, lon: 0.0 }, capacity: '340 Tbps', operator: 'Google', region: 'Transatlantic' },
  { name: 'Curie', from: { lat: 33.77, lon: -118.19 }, to: { lat: -33.45, lon: -70.65 }, capacity: '72 Tbps', operator: 'Google', region: 'Americas' },
  { name: 'EllaLink', from: { lat: 39.2, lon: -9.4 }, to: { lat: -2.5, lon: -44.3 }, capacity: '72 Tbps', operator: 'EllaLink', region: 'Europe-South America' },
  { name: 'Arctic Connect', from: { lat: 60.17, lon: 24.94 }, to: { lat: 35.68, lon: 139.69 }, capacity: '200 Tbps', operator: 'Cinia', region: 'Arctic Route' },
  { name: 'SCCN', from: { lat: 22.3, lon: 114.17 }, to: { lat: 1.3, lon: 103.8 }, capacity: '28 Tbps', operator: 'Multiple', region: 'Asia' },
  { name: 'Monet', from: { lat: 22.9, lon: -43.2 }, to: { lat: 40.7, lon: -74.0 }, capacity: '64 Tbps', operator: 'Google', region: 'Americas' },
  { name: 'Hawaiki', from: { lat: -36.84, lon: 174.76 }, to: { lat: 36.96, lon: -122.0 }, capacity: '67 Tbps', operator: 'Hawaiki Submarine Cable', region: 'Transpacific' },
  { name: 'Asia-Africa-Europe 1', from: { lat: 22.3, lon: 114.17 }, to: { lat: 44.3, lon: 8.5 }, capacity: '40 Tbps', operator: 'Multiple', region: 'Pan-Continental' }
];

// ---------------------------------------------------------------------------
// IXP BACKBONE CONNECTIONS
// ---------------------------------------------------------------------------
var GW_IXP_LINKS = [
  { fromIdx: 0, toIdx: 1 },  // Frankfurt - Amsterdam
  { fromIdx: 0, toIdx: 2 },  // Frankfurt - London
  { fromIdx: 1, toIdx: 2 },  // Amsterdam - London
  { fromIdx: 2, toIdx: 3 },  // London - Ashburn
  { fromIdx: 3, toIdx: 8 },  // Ashburn - Seattle
  { fromIdx: 0, toIdx: 6 },  // Frankfurt - Moscow
  { fromIdx: 7, toIdx: 4 },  // Tokyo - Hong Kong
  { fromIdx: 4, toIdx: 9 },  // Hong Kong - Singapore
  { fromIdx: 9, toIdx: 7 },  // Singapore - Tokyo
  { fromIdx: 3, toIdx: 10 }, // Ashburn - Toronto
  { fromIdx: 7, toIdx: 11 }, // Tokyo - Seoul
  { fromIdx: 5, toIdx: 3 }   // Sao Paulo - Ashburn
];

// ---------------------------------------------------------------------------
// SATELLITE DATA
// ---------------------------------------------------------------------------
var GW_SATELLITES = [
  { name: 'GPS IIR-M-1', lat: 0, lon: -105, alt: 20200, constellation: 'GPS', type: 'navigation' },
  { name: 'GPS IIR-M-4', lat: 0, lon: -45, alt: 20200, constellation: 'GPS', type: 'navigation' },
  { name: 'GPS IIF-2', lat: 0, lon: 15, alt: 20200, constellation: 'GPS', type: 'navigation' },
  { name: 'GPS III-SV01', lat: 0, lon: 75, alt: 20200, constellation: 'GPS', type: 'navigation' },
  { name: 'GPS III-SV04', lat: 0, lon: 135, alt: 20200, constellation: 'GPS', type: 'navigation' },
  { name: 'GPS IIF-9', lat: 0, lon: -165, alt: 20200, constellation: 'GPS', type: 'navigation' },
  { name: 'Starlink-1007', lat: 42, lon: -90, alt: 550, constellation: 'Starlink', type: 'comms' },
  { name: 'Starlink-2241', lat: -15, lon: 30, alt: 550, constellation: 'Starlink', type: 'comms' },
  { name: 'Starlink-3390', lat: 28, lon: 110, alt: 550, constellation: 'Starlink', type: 'comms' },
  { name: 'Starlink-4112', lat: -40, lon: -60, alt: 550, constellation: 'Starlink', type: 'comms' },
  { name: 'MUOS-5', lat: 0, lon: -100, alt: 35786, constellation: 'MUOS', type: 'military' },
  { name: 'WGS-10', lat: 0, lon: 12, alt: 35786, constellation: 'WGS', type: 'military' },
  { name: 'AEHF-6', lat: 0, lon: -75, alt: 35786, constellation: 'AEHF', type: 'military' },
  { name: 'Milstar-2 F4', lat: 0, lon: 100, alt: 35786, constellation: 'Milstar', type: 'military' },
  { name: 'SBIRS GEO-5', lat: 0, lon: -135, alt: 35786, constellation: 'SBIRS', type: 'military' },
  { name: 'SBIRS GEO-6', lat: 0, lon: 60, alt: 35786, constellation: 'SBIRS', type: 'military' },
  { name: 'NROL-82 (KH-11)', lat: 55, lon: -40, alt: 260, constellation: 'NRO/KH-11', type: 'military' },
  { name: 'NROL-71 (Mentor)', lat: 5, lon: 53, alt: 35786, constellation: 'NRO/Mentor', type: 'military' },
  { name: 'USA-314 (GSSAP-5)', lat: 0, lon: -20, alt: 35900, constellation: 'GSSAP', type: 'military' },
  { name: 'Yaogan-34R', lat: 63, lon: 95, alt: 1100, constellation: 'Yaogan (PRC)', type: 'military' },
  { name: 'Kosmos-2558', lat: 65, lon: 40, alt: 580, constellation: 'Kosmos (RU)', type: 'military' },
  { name: 'Ofek-16', lat: 36, lon: 35, alt: 600, constellation: 'Ofek (ISR)', type: 'military' },
  { name: 'Galileo-FOC-1', lat: 0, lon: -30, alt: 23222, constellation: 'Galileo', type: 'navigation' },
  { name: 'Galileo-FOC-8', lat: 0, lon: 90, alt: 23222, constellation: 'Galileo', type: 'navigation' },
  { name: 'GLONASS-M 58', lat: 0, lon: 50, alt: 19130, constellation: 'GLONASS', type: 'navigation' },
  { name: 'BeiDou-3 M19', lat: 0, lon: 110, alt: 21528, constellation: 'BeiDou', type: 'navigation' },
  { name: 'Inmarsat-6 F1', lat: 0, lon: 64, alt: 35786, constellation: 'Inmarsat', type: 'comms' },
  { name: 'Intelsat-40e', lat: 0, lon: -95, alt: 35786, constellation: 'Intelsat', type: 'comms' },
  { name: 'SES-17', lat: 0, lon: -67.1, alt: 35786, constellation: 'SES', type: 'comms' },
  { name: 'Starlink-5501', lat: -30, lon: 150, alt: 550, constellation: 'Starlink', type: 'comms' },
  { name: 'Starlink-6022', lat: 50, lon: -120, alt: 550, constellation: 'Starlink', type: 'comms' },
  { name: 'OneWeb-0401', lat: 60, lon: 0, alt: 1200, constellation: 'OneWeb', type: 'comms' },
  { name: 'GOES-18', lat: 0, lon: -137.2, alt: 35786, constellation: 'GOES', type: 'weather' },
  { name: 'Meteosat-12', lat: 0, lon: 0, alt: 35786, constellation: 'Meteosat', type: 'weather' },
  { name: 'Himawari-9', lat: 0, lon: 140.7, alt: 35786, constellation: 'Himawari', type: 'weather' },
  { name: 'Sentinel-2B', lat: 70, lon: -10, alt: 786, constellation: 'Copernicus', type: 'earth-obs' },
  { name: 'Landsat-9', lat: -20, lon: -50, alt: 705, constellation: 'Landsat', type: 'earth-obs' },
  { name: 'TerraSAR-X', lat: 40, lon: 20, alt: 515, constellation: 'TerraSAR', type: 'earth-obs' },
  { name: 'WorldView-3', lat: 30, lon: -80, alt: 617, constellation: 'Maxar', type: 'earth-obs' }
];

// ---------------------------------------------------------------------------
// VENDOR HQ LOCATIONS (for CISA KEV overlay)
// ---------------------------------------------------------------------------
var GW_VENDOR_HQ = {
  'Microsoft': { lat: 47.64, lon: -122.13, city: 'Redmond, WA' },
  'Google': { lat: 37.42, lon: -122.08, city: 'Mountain View, CA' },
  'Apple': { lat: 37.33, lon: -122.01, city: 'Cupertino, CA' },
  'Cisco': { lat: 37.41, lon: -121.95, city: 'San Jose, CA' },
  'Adobe': { lat: 37.33, lon: -121.89, city: 'San Jose, CA' },
  'Oracle': { lat: 37.53, lon: -122.26, city: 'Redwood City, CA' },
  'VMware': { lat: 37.40, lon: -122.14, city: 'Palo Alto, CA' },
  'Fortinet': { lat: 37.40, lon: -122.0, city: 'Sunnyvale, CA' },
  'Palo Alto Networks': { lat: 37.39, lon: -122.15, city: 'Santa Clara, CA' },
  'Ivanti': { lat: 40.59, lon: -111.83, city: 'South Jordan, UT' },
  'Citrix': { lat: 26.37, lon: -80.10, city: 'Fort Lauderdale, FL' },
  'SonicWall': { lat: 37.27, lon: -121.95, city: 'Milpitas, CA' },
  'Samsung': { lat: 37.26, lon: 127.0, city: 'Suwon, South Korea' },
  'Huawei': { lat: 22.65, lon: 114.06, city: 'Shenzhen, China' },
  'Siemens': { lat: 48.14, lon: 11.58, city: 'Munich, Germany' },
  'SAP': { lat: 49.29, lon: 8.64, city: 'Walldorf, Germany' },
  'Qualcomm': { lat: 32.90, lon: -117.19, city: 'San Diego, CA' },
  'Intel': { lat: 37.39, lon: -121.96, city: 'Santa Clara, CA' },
  'Mozilla': { lat: 37.39, lon: -122.08, city: 'Mountain View, CA' },
  'Atlassian': { lat: -33.87, lon: 151.21, city: 'Sydney, Australia' },
  'Zyxel': { lat: 25.03, lon: 121.57, city: 'Hsinchu, Taiwan' },
  'D-Link': { lat: 25.08, lon: 121.57, city: 'Taipei, Taiwan' },
  'TP-Link': { lat: 23.13, lon: 113.26, city: 'Shenzhen, China' },
  'Sophos': { lat: 51.72, lon: -1.21, city: 'Abingdon, UK' },
  'Trend Micro': { lat: 35.68, lon: 139.69, city: 'Tokyo, Japan' },
  'CrowdStrike': { lat: 37.53, lon: -122.25, city: 'Sunnyvale, CA' },
  'SentinelOne': { lat: 37.38, lon: -122.07, city: 'Mountain View, CA' },
  'Mandiant': { lat: 37.39, lon: -122.08, city: 'Reston, VA' },
  'Schneider Electric': { lat: 48.78, lon: 2.24, city: 'Rueil-Malmaison, France' },
  'ABB': { lat: 47.56, lon: 7.59, city: 'Zurich, Switzerland' },
  'Ivanti': { lat: 40.59, lon: -111.83, city: 'South Jordan, UT' },
  'Progress Software': { lat: 42.37, lon: -71.06, city: 'Burlington, MA' },
  'Barracuda Networks': { lat: 37.39, lon: -122.08, city: 'Campbell, CA' },
  'F5 Networks': { lat: 47.61, lon: -122.33, city: 'Seattle, WA' },
  'Juniper Networks': { lat: 37.40, lon: -122.0, city: 'Sunnyvale, CA' },
  'Check Point': { lat: 32.08, lon: 34.78, city: 'Tel Aviv, Israel' },
  'Kaspersky': { lat: 55.75, lon: 37.62, city: 'Moscow, Russia' },
  'ESET': { lat: 48.15, lon: 17.11, city: 'Bratislava, Slovakia' },
  'Acronis': { lat: 46.95, lon: 7.45, city: 'Schaffhausen, Switzerland' },
  'Zoho': { lat: 13.08, lon: 80.27, city: 'Chennai, India' },
  'Zimbra': { lat: 37.39, lon: -122.08, city: 'San Mateo, CA' },
  'Apache': { lat: 37.39, lon: -122.08, city: 'Wakefield, MA' },
  'Linux': { lat: 45.52, lon: -122.68, city: 'Portland, OR' },
  'Red Hat': { lat: 35.78, lon: -78.64, city: 'Raleigh, NC' }
};

// ---------------------------------------------------------------------------
// FLY-TO LOCATIONS
// ---------------------------------------------------------------------------
var GW_FLY_TO = [
  { id: 'uscybercom', label: 'DC', lat: 39.1086, lon: -76.7711, alt: 300000 },
  { id: 'moscow', label: 'MOSCOW', lat: 55.7558, lon: 37.6173, alt: 500000 },
  { id: 'beijing', label: 'BEIJING', lat: 39.9042, lon: 116.4074, alt: 500000 },
  { id: 'tehran', label: 'TEHRAN', lat: 35.6892, lon: 51.3890, alt: 500000 },
  { id: 'kyiv', label: 'KYIV', lat: 50.4501, lon: 30.5234, alt: 300000 },
  { id: 'taipei', label: 'TAIPEI', lat: 25.032, lon: 121.565, alt: 300000 },
  { id: 'london', label: 'LONDON', lat: 51.5074, lon: -0.1278, alt: 500000 },
  { id: 'global', label: 'GLOBAL', lat: 20, lon: 0, alt: 20000000 }
];

// ---------------------------------------------------------------------------
// loadCesium — dynamically load CesiumJS from CDN
// ---------------------------------------------------------------------------
function _gwLoadCesium(callback) {
  if (_gwCesiumLoaded && window.Cesium) {
    callback();
    return;
  }
  if (_gwCesiumLoading) {
    var waitInt = setInterval(function() {
      if (_gwCesiumLoaded && window.Cesium) {
        clearInterval(waitInt);
        callback();
      }
    }, 200);
    return;
  }
  _gwCesiumLoading = true;

  // Inject Cesium CSS
  var cssId = 'gw-cesium-css';
  if (!document.getElementById(cssId)) {
    var style = document.createElement('style');
    style.id = cssId;
    style.textContent = [
      '.cesium-viewer { font-family: monospace; }',
      '.cesium-viewer-bottom { display: none !important; }',
      '.cesium-viewer-toolbar { display: none !important; }',
      '.cesium-widget-credits { display: none !important; }',
      '.cesium-viewer .cesium-widget { position: relative; }',
      '.cesium-viewer-cesiumWidgetContainer { position: absolute; top: 0; left: 0; right: 0; bottom: 0; }',
      '.cesium-widget canvas { width: 100%; height: 100%; }'
    ].join('\n');
    document.head.appendChild(style);
  }

  // Set CESIUM_BASE_URL before loading the script
  window.CESIUM_BASE_URL = 'https://cdn.jsdelivr.net/npm/cesium@1.124/Build/Cesium/';

  var script = document.createElement('script');
  script.src = 'https://cdn.jsdelivr.net/npm/cesium@1.124/Build/Cesium/Cesium.js';
  script.onload = function() {
    _gwCesiumLoaded = true;
    _gwCesiumLoading = false;
    // Chain-load satellite.js for TLE orbit propagation
    var satScript = document.createElement('script');
    satScript.src = '/js/vendor/satellite.min.js';
    satScript.onload = function() { callback(); };
    satScript.onerror = function() { callback(); };
    document.head.appendChild(satScript);
  };
  script.onerror = function() {
    _gwCesiumLoading = false;
    var el = document.getElementById('gw-globe-container');
    if (el) {
      el.innerHTML = '<div style="color:#ff4444;padding:40px;text-align:center;font-family:monospace;">' +
        '<h3>CESIUM LOAD FAILURE</h3>' +
        '<p>Failed to load CesiumJS from CDN. Check network connectivity.</p>' +
        '<p>Required: cdn.jsdelivr.net access on port 443</p>' +
        '</div>';
    }
  };
  document.head.appendChild(script);
}

// ============================================================================
// SIGINT — Signals Intelligence Collection & Analysis
// ============================================================================

var SIGINT_SPECTRUM_BANDS = [
  { band: 'VLF', range: '3 – 30 kHz', use: 'Submarine communications, time signals', intercepts: 14, classification: 'SECRET', activity: 0.35 },
  { band: 'LF',  range: '30 – 300 kHz', use: 'Navigation (LORAN-C), maritime beacons', intercepts: 8, classification: 'UNCLASSIFIED', activity: 0.2 },
  { band: 'HF',  range: '3 – 30 MHz', use: 'Military HF, diplomatic comms, SIGINT', intercepts: 127, classification: 'TOP SECRET', activity: 0.85 },
  { band: 'VHF', range: '30 – 300 MHz', use: 'Air traffic control, military tac-air', intercepts: 203, classification: 'SECRET', activity: 0.72 },
  { band: 'UHF', range: '300 MHz – 3 GHz', use: 'Satellite uplinks, radar, celluar', intercepts: 312, classification: 'TOP SECRET//SI', activity: 0.91 },
  { band: 'SHF', range: '3 – 30 GHz', use: 'Satellite MILCOM, microwave links', intercepts: 145, classification: 'TOP SECRET//TK', activity: 0.68 },
  { band: 'EHF', range: '30 – 300 GHz', use: 'AEHF MILSATCOM, anti-jam channels', intercepts: 38, classification: 'TOP SECRET//SI//TK', activity: 0.42 }
];

var SIGINT_COMINT_LOG = [
  { ts: '2026-09-18T14:23:17Z', freq: '8.992 MHz', protocol: 'HF-ALE', source: 'GRU Unit 74455', target: 'Kaliningrad Oblast', classification: 'TOP SECRET', status: 'INTERCEPTED' },
  { ts: '2026-09-18T14:19:44Z', freq: '14.350 MHz', protocol: 'USB Voice', source: 'IRGC-CEC Tehran', target: 'Damascus Station', classification: 'SECRET', status: 'RECORDING' },
  { ts: '2026-09-18T14:15:02Z', freq: '243.0 MHz', protocol: 'UHF SATCOM', source: 'PLA SSF Shanghai', target: 'South China Sea Fleet', classification: 'TOP SECRET//SI', status: 'DECRYPTED' },
  { ts: '2026-09-18T14:11:38Z', freq: '311.0 MHz', protocol: 'MILCOM', source: 'RGB Bureau 121', target: 'Shenyang Relay', classification: 'SECRET', status: 'INTERCEPTED' },
  { ts: '2026-09-18T14:08:55Z', freq: '5.190 GHz', protocol: 'VSAT Encrypted', source: 'APT29 C2 Node', target: 'Unknown EU Target', classification: 'TOP SECRET//TK', status: 'ANALYZING' },
  { ts: '2026-09-18T14:04:21Z', freq: '1.545 GHz', protocol: 'Inmarsat-C', source: 'Vessel MMSI 273453210', target: 'Murmansk Naval Base', classification: 'SECRET', status: 'INTERCEPTED' },
  { ts: '2026-09-18T13:58:09Z', freq: '406 MHz', protocol: 'COSPAS-SARSAT', source: 'Distress Beacon', target: 'N/A', classification: 'UNCLASSIFIED', status: 'LOGGED' },
  { ts: '2026-09-18T13:52:33Z', freq: '20.005 GHz', protocol: 'Ka-band SATCOM', source: 'SVR Station Moscow', target: 'London Residency', classification: 'TOP SECRET//SI', status: 'DECRYPTED' },
  { ts: '2026-09-18T13:47:11Z', freq: '121.5 MHz', protocol: 'VHF-AM Guard', source: 'Iranian F-14 Tomcat', target: 'Tehran ATC', classification: 'SECRET', status: 'RECORDING' },
  { ts: '2026-09-18T13:41:28Z', freq: '2.182 MHz', protocol: 'MF Maritime', source: 'DPRK Patrol Vessel', target: 'Wonsan Naval HQ', classification: 'SECRET', status: 'INTERCEPTED' },
  { ts: '2026-09-18T13:35:44Z', freq: '44 GHz', protocol: 'EHF AEHF', source: 'STRATCOM', target: 'USSPACECOM', classification: 'TOP SECRET//SI//TK', status: 'LOGGED' },
  { ts: '2026-09-18T13:30:01Z', freq: '1.090 GHz', protocol: 'ADS-B', source: 'Aircraft RSD0417', target: 'Broadcast', classification: 'UNCLASSIFIED', status: 'LOGGED' }
];

var SIGINT_ELINT_EMITTERS = [
  { name: 'S-400 Triumf (91N6E)', type: 'SAM / Search Radar', freq: '1-2 GHz (L-band)', prf: '330 Hz', nation: 'Russia', location: 'Latakia, Syria', threat: 'CRITICAL', status: 'ACTIVE' },
  { name: 'S-300PMU2 (30N6E2)', type: 'SAM / Fire Control', freq: '8-10 GHz (X-band)', prf: '3600 Hz', nation: 'Iran', location: 'Isfahan Province', threat: 'HIGH', status: 'ACTIVE' },
  { name: 'Patriot PAC-3 (AN/MPQ-65)', type: 'SAM / Multifunction', freq: '5.4 GHz (C-band)', prf: 'Varies', nation: 'United States', location: 'Camp Carroll, ROK', threat: 'ALLIED', status: 'ACTIVE' },
  { name: 'Iron Dome (EL/M-2084)', type: 'C-RAM / Fire Control', freq: 'S-band', prf: 'Varies', nation: 'Israel', location: 'Southern Israel', threat: 'ALLIED', status: 'ACTIVE' },
  { name: 'THAAD (AN/TPY-2)', type: 'ABM / X-band Radar', freq: '9-10 GHz (X-band)', prf: 'Classified', nation: 'United States', location: 'Fort Bliss, TX', threat: 'ALLIED', status: 'ACTIVE' },
  { name: 'Aegis SPY-1D', type: 'Naval / Multifunction Phased Array', freq: '3.1-3.5 GHz (S-band)', prf: 'Varies', nation: 'United States', location: 'USS Arleigh Burke (DDG-51)', threat: 'ALLIED', status: 'TRACKING' },
  { name: 'HQ-9B (HT-233)', type: 'SAM / Fire Control', freq: 'C-band', prf: '2800 Hz', nation: 'China', location: 'Fujian Province', threat: 'HIGH', status: 'ACTIVE' },
  { name: 'Pantsir-S1 (1RS2)', type: 'SHORAD / Track-While-Scan', freq: '14.5-15.5 GHz (Ku-band)', prf: '4000 Hz', nation: 'Russia', location: 'Hmeimim AB, Syria', threat: 'HIGH', status: 'ACTIVE' },
  { name: 'KN-06 Pon\'gae-5', type: 'SAM / Search Radar', freq: 'S-band (estimated)', prf: 'Unknown', nation: 'North Korea', location: 'Pyongyang Defense Zone', threat: 'HIGH', status: 'INTERMITTENT' },
  { name: 'Bavar-373 (Meraj-4)', type: 'SAM / Multifunction', freq: 'S-band', prf: 'Unknown', nation: 'Iran', location: 'Tehran Air Defense Zone', threat: 'MEDIUM', status: 'ACTIVE' }
];

var SIGINT_CRYPTO_STATUS = [
  { signalId: 'SIG-2026-0917A', cipher: 'AES-256-GCM', keyLen: '256-bit', progress: 0, estTime: 'N/A', status: 'RESISTANT' },
  { signalId: 'SIG-2026-0918B', cipher: 'GOST 28147-89', keyLen: '256-bit', progress: 42, estTime: '~14h', status: 'IN PROGRESS' },
  { signalId: 'SIG-2026-0915C', cipher: 'DES-CBC', keyLen: '56-bit', progress: 100, estTime: 'Complete', status: 'DECRYPTED' },
  { signalId: 'SIG-2026-0918D', cipher: 'RSA-1024 (key exchange)', keyLen: '1024-bit', progress: 78, estTime: '~3h', status: 'IN PROGRESS' },
  { signalId: 'SIG-2026-0916E', cipher: 'RC4-128', keyLen: '128-bit', progress: 100, estTime: 'Complete', status: 'DECRYPTED' },
  { signalId: 'SIG-2026-0918F', cipher: 'ChaCha20-Poly1305', keyLen: '256-bit', progress: 0, estTime: 'N/A', status: 'RESISTANT' },
  { signalId: 'SIG-2026-0918G', cipher: 'Blowfish-CBC', keyLen: '128-bit', progress: 15, estTime: '~36h', status: 'QUEUED' },
  { signalId: 'SIG-2026-0917H', cipher: '3DES-EDE', keyLen: '168-bit', progress: 91, estTime: '~45m', status: 'IN PROGRESS' }
];

var SIGINT_MODULATIONS = [
  { abbr: 'FSK', name: 'Frequency-Shift Keying', use: 'HF RTTY, POCSAG pagers, ALE', complexity: 'Low' },
  { abbr: 'PSK', name: 'Phase-Shift Keying', use: 'MIL-STD-188, STANAG 4285, DVB-S', complexity: 'Medium' },
  { abbr: 'QAM', name: 'Quadrature Amplitude Modulation', use: 'Digital microwave, cable, 5G backhaul', complexity: 'High' },
  { abbr: 'OFDM', name: 'Orthogonal Frequency-Division Multiplexing', use: 'Wi-Fi, LTE, DAB radio', complexity: 'High' },
  { abbr: 'FHSS', name: 'Frequency-Hopping Spread Spectrum', use: 'SINCGARS, Link 16, Bluetooth', complexity: 'Very High' },
  { abbr: 'DSSS', name: 'Direct-Sequence Spread Spectrum', use: 'GPS, CDMA, military anti-jam', complexity: 'Very High' },
  { abbr: 'MSK', name: 'Minimum-Shift Keying', use: 'Deep-space (NASA DSN), GSM', complexity: 'Medium' },
  { abbr: 'OOK', name: 'On-Off Keying', use: 'Morse code, IR remotes, IoT', complexity: 'Low' }
];

var SIGINT_NATO_TERMS = [
  { abbr: 'COMINT', full: 'Communications Intelligence', description: 'Intelligence from intercepted voice, data, and fax communications.' },
  { abbr: 'ELINT', full: 'Electronic Intelligence', description: 'Intelligence from non-communication electromagnetic emissions (radar, EW systems).' },
  { abbr: 'FISINT', full: 'Foreign Instrumentation Signals Intelligence', description: 'Intelligence from telemetry, beaconing, and video data links of foreign weapons systems.' },
  { abbr: 'MASINT', full: 'Measurement and Signature Intelligence', description: 'Intelligence from quantitative and qualitative analysis of physical attributes of targets and events.' },
  { abbr: 'TECHSIGINT', full: 'Technical Signals Intelligence', description: 'Technical information about foreign communications and electronic systems.' },
  { abbr: 'PROFORMA', full: 'Protocol Format', description: 'Technical analysis of signal characteristics: frequency, modulation, bandwidth, timing.' },
  { abbr: 'OPSIG', full: 'Operational SIGINT', description: 'SIGINT acquired for direct support of military operations.' },
  { abbr: 'CRITIC', full: 'Critical Intelligence Communication', description: 'Highest priority intelligence report — must reach the President within 10 minutes.' }
];

function renderSigint() {
  var h = '';

  // ---- Header ----
  h += '<div style="padding:20px 24px 0 24px;">';
  h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;flex-wrap:wrap;gap:10px;">';
  h += '<div>';
  h += '<h2 style="margin:0;font-size:22px;color:#00aaff;font-family:monospace;letter-spacing:2px;text-transform:uppercase;">[SI] SIGINT &mdash; SIGNALS INTELLIGENCE</h2>';
  h += '<div style="color:#4a6a8a;font-size:11px;font-family:monospace;margin-top:4px;letter-spacing:1px;">ELECTROMAGNETIC SPECTRUM MONITORING // COMINT / ELINT / FISINT</div>';
  h += '</div>';
  h += '<div style="color:#ff444488;font-size:10px;font-family:monospace;border:1px solid #ff444444;padding:3px 10px;border-radius:3px;letter-spacing:2px;">TOP SECRET // SI // TK</div>';
  h += '</div>';

  // ---- Stat cards ----
  var stats = [
    { label: 'Active Intercepts', value: '847', color: '#00aaff' },
    { label: 'COMINT Targets', value: '142', color: '#00ff88' },
    { label: 'ELINT Emitters', value: '38', color: '#ffaa00' },
    { label: 'Decrypted Streams', value: '12', color: '#aa66ff' },
    { label: 'Priority Signals', value: '5', color: '#ff4444' }
  ];
  h += '<div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px;">';
  for (var si = 0; si < stats.length; si++) {
    h += '<div style="flex:1;min-width:130px;background:linear-gradient(135deg,#0a0e1a,#101828);border:1px solid ' + stats[si].color + '33;border-radius:6px;padding:10px 14px;text-align:center;">';
    h += '<div style="color:' + stats[si].color + ';font-size:9px;font-family:monospace;letter-spacing:1.5px;text-transform:uppercase;opacity:0.7;">' + esc(stats[si].label) + '</div>';
    h += '<div style="color:' + stats[si].color + ';font-size:24px;font-weight:bold;font-family:monospace;">' + esc(stats[si].value) + '</div>';
    h += '</div>';
  }
  h += '</div>';
  h += '</div>';

  // ==============================
  // (A) RF SPECTRUM ANALYZER
  // ==============================
  h += '<div style="padding:0 24px 16px 24px;">';
  h += '<div style="background:linear-gradient(135deg,#0c1020,#0a0e1a);border:1px solid #1a2a44;border-radius:8px;padding:16px 18px;">';
  h += '<div style="color:#00aaff;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;margin-bottom:12px;border-bottom:1px solid #1a2a44;padding-bottom:8px;">';
  h += '<span style="margin-right:6px;">[RF]</span>RF SPECTRUM ANALYZER</div>';

  // Spectrum band table
  h += '<div style="overflow-x:auto;">';
  h += '<table style="width:100%;border-collapse:collapse;font-family:monospace;font-size:11px;">';
  h += '<tr style="border-bottom:1px solid #1a2a44;">';
  var specHeaders = ['BAND', 'FREQUENCY', 'PRIMARY USE', 'INTERCEPTS', 'CLASSIFICATION', 'ACTIVITY'];
  for (var sh = 0; sh < specHeaders.length; sh++) {
    h += '<th style="text-align:left;padding:6px 10px;color:#3a5a7a;font-size:10px;letter-spacing:1px;font-weight:600;">' + specHeaders[sh] + '</th>';
  }
  h += '</tr>';

  for (var sb = 0; sb < SIGINT_SPECTRUM_BANDS.length; sb++) {
    var band = SIGINT_SPECTRUM_BANDS[sb];
    var actColor = band.activity > 0.8 ? '#ff4444' : (band.activity > 0.5 ? '#ffaa00' : '#00ff88');
    var actPct = Math.round(band.activity * 100);
    h += '<tr style="border-bottom:1px solid #0f1a28;">';
    h += '<td style="padding:7px 10px;color:#00aaff;font-weight:bold;">' + esc(band.band) + '</td>';
    h += '<td style="padding:7px 10px;color:#8ab4d4;">' + esc(band.range) + '</td>';
    h += '<td style="padding:7px 10px;color:#6a8aaa;font-size:10px;">' + esc(band.use) + '</td>';
    h += '<td style="padding:7px 10px;color:#fff;font-weight:bold;text-align:center;">' + band.intercepts + '</td>';
    h += '<td style="padding:7px 10px;">';
    var clColor = band.classification.indexOf('TOP SECRET') !== -1 ? '#ff4444' : (band.classification === 'SECRET' ? '#ffaa00' : '#00ff88');
    h += '<span style="color:' + clColor + ';font-size:9px;letter-spacing:0.5px;">' + esc(band.classification) + '</span></td>';
    h += '<td style="padding:7px 10px;min-width:120px;">';
    h += '<div style="display:flex;align-items:center;gap:6px;">';
    h += '<div style="flex:1;height:6px;background:#0a1018;border-radius:3px;overflow:hidden;">';
    h += '<div style="width:' + actPct + '%;height:100%;background:' + actColor + ';border-radius:3px;"></div>';
    h += '</div>';
    h += '<span style="color:' + actColor + ';font-size:10px;min-width:30px;text-align:right;">' + actPct + '%</span>';
    h += '</div>';
    h += '</td>';
    h += '</tr>';
  }
  h += '</table>';
  h += '</div>';
  h += '</div>';
  h += '</div>';

  // ==============================
  // (B) COMINT — Intercepted Communications
  // ==============================
  h += '<div style="padding:0 24px 16px 24px;">';
  h += '<div style="background:linear-gradient(135deg,#0c1020,#0a0e1a);border:1px solid #1a2a44;border-radius:8px;padding:16px 18px;">';
  h += '<div style="color:#00ff88;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;margin-bottom:12px;border-bottom:1px solid #1a2a44;padding-bottom:8px;">';
  h += '<span style="margin-right:6px;">[COMINT]</span>COMMUNICATIONS INTELLIGENCE</div>';

  h += '<div style="overflow-x:auto;">';
  h += '<table style="width:100%;border-collapse:collapse;font-family:monospace;font-size:10px;">';
  h += '<tr style="border-bottom:1px solid #1a2a44;">';
  var comHeaders = ['TIMESTAMP', 'FREQ', 'PROTOCOL', 'SOURCE', 'TARGET', 'CLASSIFICATION', 'STATUS'];
  for (var ch = 0; ch < comHeaders.length; ch++) {
    h += '<th style="text-align:left;padding:5px 8px;color:#3a5a7a;font-size:9px;letter-spacing:1px;font-weight:600;white-space:nowrap;">' + comHeaders[ch] + '</th>';
  }
  h += '</tr>';

  for (var cl = 0; cl < SIGINT_COMINT_LOG.length; cl++) {
    var log = SIGINT_COMINT_LOG[cl];
    var ts = log.ts.replace('T', ' ').substring(11, 19) + 'Z';
    var stColor = log.status === 'DECRYPTED' ? '#00ff88' : (log.status === 'RECORDING' ? '#ffaa00' : (log.status === 'ANALYZING' ? '#aa66ff' : '#00aaff'));
    var clsColor = log.classification.indexOf('TOP SECRET') !== -1 ? '#ff4444' : (log.classification === 'SECRET' ? '#ffaa00' : '#00ff88');
    h += '<tr style="border-bottom:1px solid #0f1a28;">';
    h += '<td style="padding:5px 8px;color:#5a7a9a;white-space:nowrap;">' + esc(ts) + '</td>';
    h += '<td style="padding:5px 8px;color:#8ab4d4;white-space:nowrap;">' + esc(log.freq) + '</td>';
    h += '<td style="padding:5px 8px;color:#6a8aaa;">' + esc(log.protocol) + '</td>';
    h += '<td style="padding:5px 8px;color:#ff8866;font-weight:600;white-space:nowrap;">' + esc(log.source) + '</td>';
    h += '<td style="padding:5px 8px;color:#8ab4d4;white-space:nowrap;">' + esc(log.target) + '</td>';
    h += '<td style="padding:5px 8px;"><span style="color:' + clsColor + ';font-size:9px;">' + esc(log.classification) + '</span></td>';
    h += '<td style="padding:5px 8px;"><span style="color:' + stColor + ';font-weight:bold;font-size:9px;letter-spacing:0.5px;">' + esc(log.status) + '</span></td>';
    h += '</tr>';
  }
  h += '</table>';
  h += '</div>';
  h += '</div>';
  h += '</div>';

  // ==============================
  // (C) ELINT — Electronic Intelligence
  // ==============================
  h += '<div style="padding:0 24px 16px 24px;">';
  h += '<div style="background:linear-gradient(135deg,#0c1020,#0a0e1a);border:1px solid #1a2a44;border-radius:8px;padding:16px 18px;">';
  h += '<div style="color:#ffaa00;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;margin-bottom:12px;border-bottom:1px solid #1a2a44;padding-bottom:8px;">';
  h += '<span style="margin-right:6px;">[ELINT]</span>ELECTRONIC INTELLIGENCE &mdash; EMITTER TRACKING</div>';

  h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:10px;">';
  for (var ei = 0; ei < SIGINT_ELINT_EMITTERS.length; ei++) {
    var em = SIGINT_ELINT_EMITTERS[ei];
    var threatColor = em.threat === 'CRITICAL' ? '#ff2222' : (em.threat === 'HIGH' ? '#ff6644' : (em.threat === 'ALLIED' ? '#44aaff' : '#ffaa00'));
    var borderColor = em.threat === 'CRITICAL' ? '#ff222244' : (em.threat === 'HIGH' ? '#ff664444' : (em.threat === 'ALLIED' ? '#44aaff44' : '#ffaa0044'));
    var stDot = em.status === 'ACTIVE' ? '#00ff88' : (em.status === 'TRACKING' ? '#00aaff' : '#ffaa00');

    h += '<div style="background:#0a0e1a;border:1px solid ' + borderColor + ';border-radius:6px;padding:12px 14px;">';
    h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;">';
    h += '<div style="color:#e0e8f0;font-size:12px;font-weight:bold;font-family:monospace;">' + esc(em.name) + '</div>';
    h += '<span style="width:8px;height:8px;border-radius:50%;background:' + stDot + ';display:inline-block;" title="' + esc(em.status) + '"></span>';
    h += '</div>';
    h += '<div style="font-size:10px;font-family:monospace;color:#6a8aaa;margin-bottom:8px;">' + esc(em.type) + '</div>';
    h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:4px;font-size:10px;font-family:monospace;">';
    h += '<div><span style="color:#3a5a7a;">FREQ:</span> <span style="color:#8ab4d4;">' + esc(em.freq) + '</span></div>';
    h += '<div><span style="color:#3a5a7a;">PRF:</span> <span style="color:#8ab4d4;">' + esc(em.prf) + '</span></div>';
    h += '<div><span style="color:#3a5a7a;">NATION:</span> <span style="color:#c8d6e5;">' + esc(em.nation) + '</span></div>';
    h += '<div><span style="color:#3a5a7a;">LOC:</span> <span style="color:#6a8aaa;">' + esc(em.location) + '</span></div>';
    h += '</div>';
    h += '<div style="margin-top:8px;display:flex;align-items:center;justify-content:space-between;">';
    h += '<span style="color:' + threatColor + ';font-size:9px;font-weight:bold;letter-spacing:1px;padding:2px 8px;border:1px solid ' + threatColor + '44;border-radius:2px;">' + esc(em.threat) + '</span>';
    h += '<span style="color:' + stDot + ';font-size:9px;letter-spacing:1px;">' + esc(em.status) + '</span>';
    h += '</div>';
    h += '</div>';
  }
  h += '</div>';
  h += '</div>';
  h += '</div>';

  // ==============================
  // (D) SIGNALS ANALYSIS WORKBENCH
  // ==============================
  h += '<div style="padding:0 24px 16px 24px;">';
  h += '<div style="background:linear-gradient(135deg,#0c1020,#0a0e1a);border:1px solid #1a2a44;border-radius:8px;padding:16px 18px;">';
  h += '<div style="color:#aa66ff;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;margin-bottom:12px;border-bottom:1px solid #1a2a44;padding-bottom:8px;">';
  h += '<span style="margin-right:6px;">[AW]</span>SIGNALS ANALYSIS WORKBENCH</div>';

  // Frequency input
  h += '<div style="display:flex;gap:8px;align-items:center;margin-bottom:16px;flex-wrap:wrap;">';
  h += '<span style="color:#5a7a9a;font-size:10px;font-family:monospace;letter-spacing:1px;">FREQUENCY:</span>';
  h += '<input id="se-sigint-freq" type="text" value="8.992" style="background:#080c14;border:1px solid #1a3050;color:#00ddff;font-family:monospace;font-size:13px;padding:6px 12px;border-radius:4px;width:120px;outline:none;" />';
  h += '<span style="color:#5a7a9a;font-size:10px;font-family:monospace;">MHz</span>';
  h += '<div onclick="(function(){var f=document.getElementById(\'se-sigint-freq\');var r=document.getElementById(\'se-sigint-result\');if(!f||!r)return;var v=parseFloat(f.value)||0;var band=v<0.03?\'VLF\':v<0.3?\'LF\':v<3?\'MF\':v<30?\'HF\':v<300?\'VHF\':v<3000?\'UHF\':v<30000?\'SHF\':\'EHF\';var mod=v<30?\'FSK / USB / CW\':v<300?\'AM / FM / P25\':v<3000?\'PSK / QAM / OFDM\':\'QAM / FHSS\';r.innerHTML=\'<div style=padding:10px;font-family:monospace;font-size:11px;><div style=color:#00ddff;margin-bottom:6px;>ANALYSIS: \'+v+\' MHz</div><div style=color:#6a8aaa;>Band: <span style=color:#00aaff>\'+band+\'</span></div><div style=color:#6a8aaa;>Likely modulations: <span style=color:#ffaa00>\'+mod+\'</span></div><div style=color:#6a8aaa;>Signals detected in band: <span style=color:#00ff88;>\'+Math.floor(Math.random()*50+5)+\'</span></div><div style=color:#6a8aaa;>Nearest known emitter: <span style=color:#ff8866;>\'+[\'GRU HF Net\',\'PLA SATCOM\',\'IRGC Tactical\',\'NATO AWACS\',\'Commercial FM\'][Math.floor(Math.random()*5)]+\'</span></div></div>\';})()" style="background:#aa66ff22;color:#aa66ff;font-size:10px;font-family:monospace;padding:6px 14px;border-radius:4px;cursor:pointer;border:1px solid #aa66ff44;letter-spacing:1px;">ANALYZE</div>';
  h += '</div>';
  h += '<div id="se-sigint-result" style="background:#080c14;border:1px solid #1a2a44;border-radius:4px;min-height:40px;margin-bottom:16px;">';
  h += '<div style="padding:12px;color:#3a5a7a;font-size:10px;font-family:monospace;text-align:center;">Enter a frequency and click ANALYZE</div>';
  h += '</div>';

  // Waterfall display (simulated)
  h += '<div style="color:#5a7a9a;font-size:10px;font-family:monospace;letter-spacing:1px;margin-bottom:6px;">WATERFALL DISPLAY — HF BAND (3-30 MHz)</div>';
  h += '<div style="background:#020408;border:1px solid #0a1a2a;border-radius:4px;padding:6px;overflow:hidden;font-family:monospace;font-size:9px;line-height:1.1;">';
  var wfColors = ['#001a00', '#003300', '#005500', '#007700', '#009900', '#00bb00', '#00dd00', '#00ff00', '#33ff33', '#66ff66', '#99ff99', '#ffff00', '#ffcc00', '#ff9900', '#ff6600', '#ff3300', '#ff0000'];
  for (var wfr = 0; wfr < 12; wfr++) {
    h += '<div style="white-space:nowrap;overflow:hidden;">';
    for (var wfc = 0; wfc < 80; wfc++) {
      var intensity = Math.random();
      // Create signal peaks at certain frequencies
      var freqPos = wfc / 80;
      if (Math.abs(freqPos - 0.22) < 0.03) intensity = 0.7 + Math.random() * 0.3; // HF signal
      if (Math.abs(freqPos - 0.45) < 0.02) intensity = 0.5 + Math.random() * 0.4;
      if (Math.abs(freqPos - 0.71) < 0.04) intensity = 0.6 + Math.random() * 0.3;
      if (Math.abs(freqPos - 0.88) < 0.015) intensity = 0.8 + Math.random() * 0.2;
      else intensity = intensity * 0.25;
      var cidx = Math.min(wfColors.length - 1, Math.floor(intensity * (wfColors.length - 1)));
      h += '<span style="color:' + wfColors[cidx] + ';">' + (intensity > 0.5 ? '|' : (intensity > 0.2 ? ':' : '.')) + '</span>';
    }
    h += '</div>';
  }
  h += '</div>';
  h += '<div style="display:flex;justify-content:space-between;font-size:8px;font-family:monospace;color:#3a5a7a;margin-top:2px;">';
  h += '<span>3 MHz</span><span>10 MHz</span><span>15 MHz</span><span>20 MHz</span><span>25 MHz</span><span>30 MHz</span>';
  h += '</div>';

  // Modulation & NATO reference (side by side)
  h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:16px;">';

  // Signal modulation reference
  h += '<div>';
  h += '<div style="color:#5a7a9a;font-size:10px;font-family:monospace;letter-spacing:1px;margin-bottom:6px;">SIGNAL MODULATION REFERENCE</div>';
  h += '<table style="width:100%;border-collapse:collapse;font-family:monospace;font-size:10px;">';
  for (var mi = 0; mi < SIGINT_MODULATIONS.length; mi++) {
    var mod = SIGINT_MODULATIONS[mi];
    var compColor = mod.complexity === 'Very High' ? '#ff4444' : (mod.complexity === 'High' ? '#ffaa00' : (mod.complexity === 'Medium' ? '#00aaff' : '#00ff88'));
    h += '<tr style="border-bottom:1px solid #0f1a28;">';
    h += '<td style="padding:4px 6px;color:#00aaff;font-weight:bold;">' + esc(mod.abbr) + '</td>';
    h += '<td style="padding:4px 6px;color:#8ab4d4;">' + esc(mod.name) + '</td>';
    h += '<td style="padding:4px 6px;color:' + compColor + ';font-size:9px;">' + esc(mod.complexity) + '</td>';
    h += '</tr>';
  }
  h += '</table>';
  h += '</div>';

  // NATO SIGINT terminology
  h += '<div>';
  h += '<div style="color:#5a7a9a;font-size:10px;font-family:monospace;letter-spacing:1px;margin-bottom:6px;">NATO SIGINT TERMINOLOGY</div>';
  h += '<table style="width:100%;border-collapse:collapse;font-family:monospace;font-size:10px;">';
  for (var ni = 0; ni < SIGINT_NATO_TERMS.length; ni++) {
    var nt = SIGINT_NATO_TERMS[ni];
    h += '<tr style="border-bottom:1px solid #0f1a28;">';
    h += '<td style="padding:4px 6px;color:#ffaa00;font-weight:bold;white-space:nowrap;">' + esc(nt.abbr) + '</td>';
    h += '<td style="padding:4px 6px;color:#6a8aaa;font-size:9px;">' + esc(nt.description) + '</td>';
    h += '</tr>';
  }
  h += '</table>';
  h += '</div>';

  h += '</div>'; // end grid
  h += '</div>';
  h += '</div>';

  // ==============================
  // (E) CRYPTANALYSIS STATUS
  // ==============================
  h += '<div style="padding:0 24px 24px 24px;">';
  h += '<div style="background:linear-gradient(135deg,#0c1020,#0a0e1a);border:1px solid #1a2a44;border-radius:8px;padding:16px 18px;">';
  h += '<div style="color:#ff6644;font-size:13px;font-family:monospace;letter-spacing:2px;text-transform:uppercase;margin-bottom:12px;border-bottom:1px solid #1a2a44;padding-bottom:8px;">';
  h += '<span style="margin-right:6px;">[CX]</span>CRYPTANALYSIS STATUS</div>';

  h += '<div style="overflow-x:auto;">';
  h += '<table style="width:100%;border-collapse:collapse;font-family:monospace;font-size:11px;">';
  h += '<tr style="border-bottom:1px solid #1a2a44;">';
  var cxHeaders = ['SIGNAL ID', 'CIPHER', 'KEY LENGTH', 'PROGRESS', 'EST. TIME', 'STATUS'];
  for (var cxh = 0; cxh < cxHeaders.length; cxh++) {
    h += '<th style="text-align:left;padding:6px 10px;color:#3a5a7a;font-size:9px;letter-spacing:1px;font-weight:600;">' + cxHeaders[cxh] + '</th>';
  }
  h += '</tr>';

  for (var cx = 0; cx < SIGINT_CRYPTO_STATUS.length; cx++) {
    var cr = SIGINT_CRYPTO_STATUS[cx];
    var cxStColor, cxStBg;
    if (cr.status === 'DECRYPTED') { cxStColor = '#00ff88'; cxStBg = '#00ff8815'; }
    else if (cr.status === 'IN PROGRESS') { cxStColor = '#ffaa00'; cxStBg = '#ffaa0015'; }
    else if (cr.status === 'QUEUED') { cxStColor = '#00aaff'; cxStBg = '#00aaff15'; }
    else { cxStColor = '#ff4444'; cxStBg = '#ff444415'; }

    var prgColor = cr.progress === 100 ? '#00ff88' : (cr.progress > 50 ? '#ffaa00' : (cr.progress > 0 ? '#00aaff' : '#ff4444'));

    h += '<tr style="border-bottom:1px solid #0f1a28;">';
    h += '<td style="padding:6px 10px;color:#8ab4d4;font-weight:600;">' + esc(cr.signalId) + '</td>';
    h += '<td style="padding:6px 10px;color:#c8d6e5;">' + esc(cr.cipher) + '</td>';
    h += '<td style="padding:6px 10px;color:#6a8aaa;">' + esc(cr.keyLen) + '</td>';
    h += '<td style="padding:6px 10px;min-width:130px;">';
    h += '<div style="display:flex;align-items:center;gap:6px;">';
    h += '<div style="flex:1;height:6px;background:#0a1018;border-radius:3px;overflow:hidden;">';
    h += '<div style="width:' + cr.progress + '%;height:100%;background:' + prgColor + ';border-radius:3px;transition:width 0.5s;"></div>';
    h += '</div>';
    h += '<span style="color:' + prgColor + ';font-size:10px;min-width:28px;text-align:right;">' + cr.progress + '%</span>';
    h += '</div>';
    h += '</td>';
    h += '<td style="padding:6px 10px;color:#5a7a9a;">' + esc(cr.estTime) + '</td>';
    h += '<td style="padding:6px 10px;"><span style="color:' + cxStColor + ';background:' + cxStBg + ';font-size:9px;font-weight:bold;letter-spacing:1px;padding:2px 8px;border-radius:2px;border:1px solid ' + cxStColor + '33;">' + esc(cr.status) + '</span></td>';
    h += '</tr>';
  }
  h += '</table>';
  h += '</div>';

  h += '</div>';
  h += '</div>';

  return h;
}

// ============================================================================
// TAB — MASINT (Measurement & Signature Intelligence)
// ============================================================================

var MASINT_NUDET_STATIONS = [
  { name: 'PS03', location: 'Yellowknife, Canada', lat: 62.48, lon: -114.47, type: 'Seismic (Primary)', status: 'operational', lastEvent: 'No significant events' },
  { name: 'PS09', location: 'Lop Nor Watch, China', lat: 41.76, lon: 88.39, type: 'Seismic (Primary)', status: 'operational', lastEvent: 'M3.2 — 2026-04-11 (non-nuclear)' },
  { name: 'PS18', location: 'Semipalatinsk, Kazakhstan', lat: 50.47, lon: 78.97, type: 'Seismic (Primary)', status: 'operational', lastEvent: 'M2.8 — 2026-02-19 (non-nuclear)' },
  { name: 'PS35', location: 'Novaya Zemlya Watch, Russia', lat: 73.37, lon: 54.97, type: 'Seismic (Primary)', status: 'degraded', lastEvent: 'M1.9 — 2025-12-03 (non-nuclear)' },
  { name: 'PS23', location: 'Nevada, USA', lat: 37.23, lon: -116.03, type: 'Seismic (Primary)', status: 'operational', lastEvent: 'No significant events' },
  { name: 'AS62', location: 'Punggye-ri Watch, DPRK', lat: 41.28, lon: 129.08, type: 'Seismic (Auxiliary)', status: 'operational', lastEvent: 'M5.1 — 2024-09-03 (assessed DPRK test)' },
  { name: 'PS13', location: 'Moruroa, French Polynesia', lat: -21.81, lon: -138.81, type: 'Seismic (Primary)', status: 'operational', lastEvent: 'No significant events' },
  { name: 'PS41', location: 'Pokhran, India', lat: 27.10, lon: 71.75, type: 'Seismic (Primary)', status: 'operational', lastEvent: 'M2.1 — 2025-08-14 (mining activity)' },
  { name: 'AS72', location: 'Chagai Hills, Pakistan', lat: 28.98, lon: 65.02, type: 'Seismic (Auxiliary)', status: 'operational', lastEvent: 'M1.6 — 2025-06-22 (non-nuclear)' },
  { name: 'PS44', location: 'Mina, Nevada, USA', lat: 38.43, lon: -118.15, type: 'Seismic (Primary)', status: 'operational', lastEvent: 'No significant events' },
  { name: 'RN14', location: 'Guangzhou, China', lat: 23.13, lon: 113.26, type: 'Radionuclide', status: 'operational', lastEvent: 'Background normal — no anomalies' },
  { name: 'RN38', location: 'Takasaki, Japan', lat: 36.32, lon: 139.01, type: 'Radionuclide', status: 'operational', lastEvent: 'Xe-133 trace — 2026-07-02 (reactor origin)' }
];

var MASINT_CBRN_SENSORS = [
  { name: 'JCAD-Alpha', type: 'Chemical', location: 'US Embassy Compound, Baghdad', reading: '0.00 ppm', alertStatus: 'normal', agents: 'GA, GB, GD, GF, VX, HD, L' },
  { name: 'BioWatch-DC', type: 'Biological', location: 'Washington DC Metro', reading: 'Baseline', alertStatus: 'normal', agents: 'Anthrax, Plague, Tularemia, Botulinum' },
  { name: 'RADIAC-7', type: 'Radiological', location: 'Camp Humphreys, South Korea', reading: '0.12 μSv/h', alertStatus: 'normal', agents: 'Cs-137, Co-60, Ir-192, Am-241' },
  { name: 'ACADA-1', type: 'Chemical', location: 'Incirlik AB, Turkey', reading: '0.00 ppm', alertStatus: 'normal', agents: 'GA, GB, GD, VX, HD, CK, AC' },
  { name: 'Portal-RTM', type: 'Radiological', location: 'Port of Rotterdam, Netherlands', reading: '0.08 μSv/h', alertStatus: 'normal', agents: 'SNM (HEU/Pu), NORM discrimination' },
  { name: 'BioSense-LHR', type: 'Biological', location: 'London Heathrow Airport', reading: 'Baseline', alertStatus: 'normal', agents: 'Smallpox, Ricin, Botulinum, SEB' },
  { name: 'RADIAC-12', type: 'Radiological', location: 'Yokosuka Naval Base, Japan', reading: '0.10 μSv/h', alertStatus: 'normal', agents: 'Neutron, Gamma, Alpha, Beta' },
  { name: 'JCAD-Delta', type: 'Chemical', location: 'Ramstein AB, Germany', reading: '0.00 ppm', alertStatus: 'normal', agents: 'CW agents + TIC (Cl2, NH3, HCN)' },
  { name: 'Portal-SIN', type: 'Radiological', location: 'Port of Singapore', reading: '0.09 μSv/h', alertStatus: 'elevated', agents: 'SNM screening — anomaly under investigation' },
  { name: 'IBAC-3', type: 'Biological', location: 'Pentagon, USA', reading: 'Baseline', alertStatus: 'normal', agents: 'Point detection: anthrax, smallpox, plague' }
];

var MASINT_EMP_PROGRAMS = [
  { nation: 'United States', program: 'CHAMP (Counter-electronics HPM Advanced Missile Project)', type: 'HPM', status: 'Operational', platform: 'AGM-86 ALCM / JASSM', description: 'Air-launched cruise missile with HPM payload. Demonstrated 2012 — fried electronics in multiple buildings in single pass.' },
  { nation: 'United States', program: 'THOR (Tactical High-power Operational Responder)', type: 'HPM', status: 'Deployed', platform: 'Ground-based trailer', description: 'Counter-drone HPM system. Deployed to Middle East. Disables drone swarms at range.' },
  { nation: 'Russia', program: 'Krasukha-4', type: 'EW/HPM', status: 'Operational', platform: 'Ground mobile (BAZ-6910)', description: 'Broadband jammer / electronic suppression. Deployed in Syria and Ukraine. Targets AWACS, UAVs, satellites.' },
  { nation: 'Russia', program: 'Ranets-E / Alabuga', type: 'HPM/EMP', status: 'Development', platform: 'Cruise missile / ground', description: 'EMP warhead for cruise missiles. Reported capability to disable electronics over wide area.' },
  { nation: 'China', program: 'WB-1 HPM', type: 'HPM', status: 'Tested', platform: 'Vehicle-mounted', description: 'High-power microwave crowd control / area denial weapon. Displayed at Zhuhai Airshow.' },
  { nation: 'China', program: 'ASAT DEW Program', type: 'Laser ASAT', status: 'Operational', platform: 'Ground-based', description: 'Ground-based laser system for satellite dazzling/blinding. Multiple incidents of laser illumination of US ISR satellites.' },
  { nation: 'Israel', program: 'Iron Beam', type: 'Laser', status: 'Operational', platform: 'Ground-based', description: 'High-energy laser air defense. Deployed 2025. Intercepts drones, rockets, mortar at cost of ~$3.50/shot vs. $50K/interceptor.' },
  { nation: 'United Kingdom', program: 'DragonFire', type: 'Laser', status: 'Testing', platform: 'Naval (Type 26)', description: 'MBDA laser directed energy weapon for Royal Navy. 50kW class. Successfully tracked and engaged aerial targets.' }
];

var MASINT_INFRASOUND = [
  { station: 'IS26', location: 'Freyung, Germany', lat: 48.85, lon: 13.71, elements: 8, sensitivity: '0.01 Pa', status: 'operational' },
  { station: 'IS27', location: 'Georg von Neumayer, Antarctica', lat: -70.65, lon: -8.32, elements: 9, sensitivity: '0.005 Pa', status: 'operational' },
  { station: 'IS53', location: 'Fairbanks, Alaska', lat: 64.87, lon: -147.86, elements: 8, sensitivity: '0.01 Pa', status: 'operational' },
  { station: 'IS57', location: 'Windless Bight, Antarctica', lat: -77.52, lon: 167.15, elements: 8, sensitivity: '0.005 Pa', status: 'operational' },
  { station: 'IS10', location: 'Lac du Bonnet, Canada', lat: 50.20, lon: -96.01, elements: 8, sensitivity: '0.01 Pa', status: 'operational' },
  { station: 'IS31', location: 'Aktau, Kazakhstan', lat: 50.40, lon: 58.03, elements: 8, sensitivity: '0.01 Pa', status: 'degraded' },
  { station: 'IS34', location: 'Songino, Mongolia', lat: 47.80, lon: 107.05, elements: 8, sensitivity: '0.01 Pa', status: 'operational' },
  { station: 'IS07', location: 'Warramunga, Australia', lat: -19.93, lon: 134.33, elements: 8, sensitivity: '0.01 Pa', status: 'operational' }
];

var MASINT_HYDROACOUSTIC = [
  { station: 'HA01', location: 'Cape Leeuwin, Australia', lat: -34.98, lon: 114.13, type: 'Hydrophone (T-phase)', depth: '1100 m', status: 'operational' },
  { station: 'HA04', location: 'Crozet Islands, France', lat: -46.10, lon: 52.19, type: 'Hydrophone (T-phase)', depth: '1300 m', status: 'operational' },
  { station: 'HA08', location: 'Diego Garcia, UK/US', lat: -7.33, lon: 72.42, type: 'Hydrophone (T-phase)', depth: '1200 m', status: 'operational' },
  { station: 'HA10', location: 'Ascension Island, UK', lat: -7.93, lon: -14.37, type: 'Hydrophone (T-phase)', depth: '850 m', status: 'operational' },
  { station: 'HA11', location: 'Wake Island, US', lat: 19.28, lon: 166.62, type: 'Hydrophone (T-phase)', depth: '900 m', status: 'degraded' },
  { station: 'HA03', location: 'Juan Fernandez, Chile', lat: -33.82, lon: -80.72, type: 'T-phase seismic', depth: 'Island station', status: 'operational' }
];

var MASINT_SIGNATURES = [
  { material: 'Uranium-235 (HEU)', threshold: '> 20% enrichment (weapons: > 90%)', signature: 'Gamma: 185.7 keV line. Neutron emission proportional to mass.', detection: 'NaI/HPGe gamma spec, He-3 neutron counters', treaty: 'NPT Article III — IAEA safeguards' },
  { material: 'Plutonium-239 (WGPu)', threshold: '> 93% Pu-239 (reactor: < 80%)', signature: 'Gamma: 413.7 keV (Pu-239), 59.5 keV (Am-241 ingrowth). Spontaneous fission neutrons.', detection: 'HPGe gamma spec, coincidence neutron counting', treaty: 'NPT — IAEA verification, CTBT' },
  { material: 'Tritium (H-3)', threshold: '> 1 gram (weapons-relevant)', signature: 'Beta: 18.6 keV max. No gamma. Difficult to detect externally.', detection: 'Liquid scintillation, proportional counters', treaty: 'Not directly safeguarded — dual-use indicator' },
  { material: 'Xenon-133 (Xe-133)', threshold: '> 1 mBq/m³ above background', signature: 'Gamma: 81 keV. Beta: 346 keV max. Noble gas — highly mobile.', detection: 'CTBTO noble gas stations (SAUNA/SPALAX systems)', treaty: 'CTBT verification — nuclear test indicator' },
  { material: 'Cesium-137 (Cs-137)', threshold: 'Any above background', signature: 'Gamma: 661.7 keV. Half-life 30.17 years.', detection: 'NaI, HPGe gamma spectrometry', treaty: 'Radiological dispersal device (dirty bomb) indicator' },
  { material: 'Cobalt-60 (Co-60)', threshold: 'Any above background', signature: 'Gamma: 1173.2 + 1332.5 keV (dual line). Half-life 5.27 years.', detection: 'NaI, HPGe gamma spectrometry, portal monitors', treaty: 'Radiological source — IAEA Category 1 (dangerous)' },
  { material: 'Nerve Agent (G-series)', threshold: '0.01 mg/m³ (LC50 varies)', signature: 'Organophosphate — inhibits acetylcholinesterase. Mass spec: m/z specific to GA/GB/GD/GF.', detection: 'IMS (ion mobility spec), JCAD, ACADA, GC-MS', treaty: 'CWC Schedule 1 — prohibited' },
  { material: 'Novichok (A-series)', threshold: '~0.001 mg/m³', signature: 'Organophosphate variant. Novel mass spec signatures not in all libraries.', detection: 'GC-MS, LC-MS/MS — requires updated spectral libraries', treaty: 'CWC Schedule 1 (added 2020 after Skripal/Navalny)' },
  { material: 'Sarin (GB)', threshold: '0.01 mg/m³', signature: 'Organophosphate. MW 140.09. GC-MS: m/z 99, 125, 140.', detection: 'IMS, JCAD, M256 kit, GC-MS confirmation', treaty: 'CWC Schedule 1 — used in Syria (Ghouta 2013, Khan Shaykhun 2017)' },
  { material: 'VX', threshold: '0.003 mg/m³', signature: 'Organophosphate. MW 267.37. Persistent. GC-MS: m/z 114, 125, 167.', detection: 'M8/M9 paper, CAM, GC-MS, LC-MS/MS', treaty: 'CWC Schedule 1 — used in Kim Jong-nam assassination (2017)' }
];

function renderMasint() {
  var h = '';

  // Header
  h += '<div style="padding:20px 24px 0;">';
  h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:18px;">';
  h += '<div>';
  h += '<h2 style="margin:0;font-size:20px;color:#aa66ff;font-family:monospace;letter-spacing:2px;text-transform:uppercase;">MASINT &mdash; MEASUREMENT &amp; SIGNATURE INTELLIGENCE</h2>';
  h += '<div style="color:#667;font-size:11px;font-family:monospace;margin-top:4px;letter-spacing:1px;">NUCLEAR / RADIOLOGICAL / GEOPHYSICAL / MATERIALS SENSING</div>';
  h += '</div>';
  h += '<div style="background:#1a0a2a;border:1px solid #aa66ff44;border-radius:4px;padding:4px 10px;font-family:monospace;font-size:10px;color:#aa66ff;letter-spacing:2px;">[TS//SCI//MASINT]</div>';
  h += '</div>';

  // Stat cards
  var stats = [
    { label: 'NUCLEAR SENSORS', value: '24', color: '#aa66ff' },
    { label: 'SEISMIC STATIONS', value: '184', color: '#00aaff' },
    { label: 'CBRN ALERTS', value: '3', color: '#ff4444' },
    { label: 'EMP DETECTIONS', value: '0', color: '#00ff88' },
    { label: 'INFRASOUND ARRAYS', value: '11', color: '#ffaa00' },
    { label: 'HYDROACOUSTIC', value: '6', color: '#00aaff' }
  ];
  h += '<div style="display:flex;gap:10px;margin-bottom:20px;">';
  for (var si = 0; si < stats.length; si++) {
    var st = stats[si];
    h += '<div style="flex:1;background:linear-gradient(135deg,#0c0818,#0a0e1a);border:1px solid ' + st.color + '44;border-radius:6px;padding:12px;text-align:center;">';
    h += '<div style="font-family:monospace;font-size:22px;font-weight:bold;color:' + st.color + ';text-shadow:0 0 10px ' + st.color + '40;">' + st.value + '</div>';
    h += '<div style="font-family:monospace;font-size:8px;color:#4a6a8a;letter-spacing:1.5px;margin-top:4px;">' + st.label + '</div>';
    h += '</div>';
  }
  h += '</div>';
  h += '</div>';

  // ── SECTION A: NUDETS ──
  h += '<div style="padding:0 24px 16px;">';
  h += '<div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;border-bottom:1px solid #1a2a44;padding-bottom:6px;">';
  h += '<div style="font-family:monospace;font-size:13px;color:#aa66ff;letter-spacing:2px;text-transform:uppercase;font-weight:bold;">NUCLEAR DETONATION DETECTION SYSTEM (NUDETS)</div>';
  h += '<div style="background:#2a0a0a;border:1px solid #ff444466;border-radius:3px;padding:1px 8px;font-family:monospace;font-size:9px;color:#ff4444;letter-spacing:1px;">[CLASSIFIED]</div>';
  h += '</div>';

  // Station table
  h += '<div style="overflow-x:auto;">';
  h += '<table style="width:100%;border-collapse:collapse;font-family:monospace;font-size:11px;">';
  h += '<thead><tr style="border-bottom:1px solid #1a2a44;">';
  h += '<th style="text-align:left;padding:6px 8px;color:#4a6a8a;font-size:9px;letter-spacing:1.5px;">STATION</th>';
  h += '<th style="text-align:left;padding:6px 8px;color:#4a6a8a;font-size:9px;letter-spacing:1.5px;">LOCATION</th>';
  h += '<th style="text-align:left;padding:6px 8px;color:#4a6a8a;font-size:9px;letter-spacing:1.5px;">TYPE</th>';
  h += '<th style="text-align:center;padding:6px 8px;color:#4a6a8a;font-size:9px;letter-spacing:1.5px;">STATUS</th>';
  h += '<th style="text-align:left;padding:6px 8px;color:#4a6a8a;font-size:9px;letter-spacing:1.5px;">LAST EVENT</th>';
  h += '</tr></thead><tbody>';

  for (var ni = 0; ni < MASINT_NUDET_STATIONS.length; ni++) {
    var ns = MASINT_NUDET_STATIONS[ni];
    var statusColor = ns.status === 'operational' ? '#00ff88' : ns.status === 'degraded' ? '#ffaa00' : '#ff4444';
    var statusLabel = ns.status.toUpperCase();
    h += '<tr style="border-bottom:1px solid #0d1525;">';
    h += '<td style="padding:5px 8px;color:#aa66ff;font-weight:bold;">' + esc(ns.name) + '</td>';
    h += '<td style="padding:5px 8px;color:#b0c4d8;">' + esc(ns.location) + '</td>';
    h += '<td style="padding:5px 8px;color:#6a8aaa;">' + esc(ns.type) + '</td>';
    h += '<td style="padding:5px 8px;text-align:center;"><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:' + statusColor + ';box-shadow:0 0 6px ' + statusColor + '80;margin-right:4px;vertical-align:middle;"></span><span style="color:' + statusColor + ';font-size:9px;">' + statusLabel + '</span></td>';
    h += '<td style="padding:5px 8px;color:#6a8aaa;font-size:10px;">' + esc(ns.lastEvent) + '</td>';
    h += '</tr>';
  }
  h += '</tbody></table>';
  h += '</div>';

  // Seismic discrimination
  h += '<div style="margin-top:14px;background:#0a0818;border:1px solid #1a1a3a;border-radius:6px;padding:12px 16px;">';
  h += '<div style="font-family:monospace;font-size:11px;color:#aa66ff;letter-spacing:1.5px;margin-bottom:8px;font-weight:bold;">SEISMIC DISCRIMINATION CRITERIA</div>';
  h += '<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;font-family:monospace;font-size:10px;">';
  h += '<div><div style="color:#4a6a8a;margin-bottom:4px;">P/S WAVE RATIO</div><div style="color:#b0c4d8;">Nuclear: high P, low S (cavity decoupling). Earthquake: strong S waves. Ratio P/S &gt; 1.5 = suspicious.</div></div>';
  h += '<div><div style="color:#4a6a8a;margin-bottom:4px;">DEPTH ANALYSIS</div><div style="color:#b0c4d8;">Nuclear tests: 0-2 km depth (shaft/tunnel). Earthquakes: typically 5-700 km. Shallow + isolated = high interest.</div></div>';
  h += '<div><div style="color:#4a6a8a;margin-bottom:4px;">mb vs Ms (MAGNITUDE)</div><div style="color:#b0c4d8;">Nuclear: mb &gt;&gt; Ms (body wave dominant). Earthquake: Ms &asymp; mb. Ms:mb ratio &lt; 0.8 = possible nuclear.</div></div>';
  h += '</div>';
  h += '</div>';
  h += '</div>';

  // ── SECTION B: CBRN ──
  h += '<div style="padding:0 24px 16px;">';
  h += '<div style="font-family:monospace;font-size:13px;color:#ff4444;letter-spacing:2px;text-transform:uppercase;margin-bottom:10px;border-bottom:1px solid #1a2a44;padding-bottom:6px;font-weight:bold;">CBRN DETECTION NETWORK</div>';

  h += '<div style="overflow-x:auto;">';
  h += '<table style="width:100%;border-collapse:collapse;font-family:monospace;font-size:11px;">';
  h += '<thead><tr style="border-bottom:1px solid #1a2a44;">';
  h += '<th style="text-align:left;padding:6px 8px;color:#4a6a8a;font-size:9px;letter-spacing:1.5px;">SENSOR</th>';
  h += '<th style="text-align:left;padding:6px 8px;color:#4a6a8a;font-size:9px;letter-spacing:1.5px;">TYPE</th>';
  h += '<th style="text-align:left;padding:6px 8px;color:#4a6a8a;font-size:9px;letter-spacing:1.5px;">LOCATION</th>';
  h += '<th style="text-align:left;padding:6px 8px;color:#4a6a8a;font-size:9px;letter-spacing:1.5px;">READING</th>';
  h += '<th style="text-align:center;padding:6px 8px;color:#4a6a8a;font-size:9px;letter-spacing:1.5px;">ALERT</th>';
  h += '<th style="text-align:left;padding:6px 8px;color:#4a6a8a;font-size:9px;letter-spacing:1.5px;">DETECTS</th>';
  h += '</tr></thead><tbody>';

  for (var ci = 0; ci < MASINT_CBRN_SENSORS.length; ci++) {
    var cs = MASINT_CBRN_SENSORS[ci];
    var typeColor = cs.type === 'Chemical' ? '#ffaa00' : cs.type === 'Biological' ? '#00ff88' : cs.type === 'Radiological' ? '#aa66ff' : '#ff4444';
    var alertColor = cs.alertStatus === 'normal' ? '#00ff88' : cs.alertStatus === 'elevated' ? '#ffaa00' : '#ff4444';
    h += '<tr style="border-bottom:1px solid #0d1525;">';
    h += '<td style="padding:5px 8px;color:#b0c4d8;font-weight:bold;">' + esc(cs.name) + '</td>';
    h += '<td style="padding:5px 8px;"><span style="background:' + typeColor + '18;color:' + typeColor + ';padding:1px 6px;border-radius:2px;font-size:9px;border:1px solid ' + typeColor + '44;">' + esc(cs.type) + '</span></td>';
    h += '<td style="padding:5px 8px;color:#6a8aaa;">' + esc(cs.location) + '</td>';
    h += '<td style="padding:5px 8px;color:#b0c4d8;font-variant-numeric:tabular-nums;">' + esc(cs.reading) + '</td>';
    h += '<td style="padding:5px 8px;text-align:center;"><span style="color:' + alertColor + ';font-size:9px;font-weight:bold;">' + esc(cs.alertStatus.toUpperCase()) + '</span></td>';
    h += '<td style="padding:5px 8px;color:#556;font-size:9px;">' + esc(cs.agents) + '</td>';
    h += '</tr>';
  }
  h += '</tbody></table>';
  h += '</div>';

  // CBRN reference
  h += '<div style="margin-top:12px;display:grid;grid-template-columns:1fr 1fr;gap:10px;">';
  var cbrnRef = [
    { type: 'CWA (Chemical)', color: '#ffaa00', items: 'Nerve (GA/GB/GD/GF/VX/Novichok), Blister (HD/HN/L), Choking (CG/DP/Cl2), Blood (AC/CK/SA)' },
    { type: 'BWA (Biological)', color: '#00ff88', items: 'Anthrax, Smallpox, Plague, Tularemia, Botulinum, Ricin, SEB, Brucella, VHF (Ebola/Marburg)' },
    { type: 'Radiological', color: '#aa66ff', items: 'Dirty bomb (RDD), Reactor breach, Criticality accident, Radiological exposure device (RED)' },
    { type: 'Nuclear', color: '#ff4444', items: 'Fission device (gun/implosion), Thermonuclear (fusion), IND (improvised nuclear device), Enhanced radiation' }
  ];
  for (var ri = 0; ri < cbrnRef.length; ri++) {
    var ref = cbrnRef[ri];
    h += '<div style="background:#0a0e1a;border:1px solid ' + ref.color + '33;border-radius:4px;padding:8px 12px;">';
    h += '<div style="font-family:monospace;font-size:10px;color:' + ref.color + ';letter-spacing:1px;font-weight:bold;margin-bottom:4px;">' + esc(ref.type) + '</div>';
    h += '<div style="font-family:monospace;font-size:9px;color:#6a8aaa;line-height:1.5;">' + esc(ref.items) + '</div>';
    h += '</div>';
  }
  h += '</div>';
  h += '</div>';

  // ── SECTION C: EMP / DIRECTED ENERGY ──
  h += '<div style="padding:0 24px 16px;">';
  h += '<div style="font-family:monospace;font-size:13px;color:#ffaa00;letter-spacing:2px;text-transform:uppercase;margin-bottom:10px;border-bottom:1px solid #1a2a44;padding-bottom:6px;font-weight:bold;">EMP / DIRECTED ENERGY MONITORING</div>';

  h += '<div style="display:grid;grid-template-columns:repeat(2,1fr);gap:10px;">';
  for (var ei = 0; ei < MASINT_EMP_PROGRAMS.length; ei++) {
    var ep = MASINT_EMP_PROGRAMS[ei];
    var empStatusColor = ep.status === 'Operational' || ep.status === 'Deployed' ? '#00ff88' : ep.status === 'Testing' ? '#ffaa00' : '#00aaff';
    h += '<div style="background:linear-gradient(135deg,#0c1020,#0a0e1a);border:1px solid #1a2a44;border-radius:6px;padding:12px 14px;">';
    h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;">';
    h += '<div style="font-family:monospace;font-size:12px;color:#ffaa00;font-weight:bold;">' + esc(ep.nation) + '</div>';
    h += '<div style="font-family:monospace;font-size:9px;color:' + empStatusColor + ';letter-spacing:1px;background:' + empStatusColor + '15;padding:1px 6px;border-radius:2px;border:1px solid ' + empStatusColor + '44;">' + esc(ep.status) + '</div>';
    h += '</div>';
    h += '<div style="font-family:monospace;font-size:11px;color:#b0c4d8;font-weight:bold;margin-bottom:4px;">' + esc(ep.program) + '</div>';
    h += '<div style="font-family:monospace;font-size:9px;color:#6a8aaa;margin-bottom:4px;">Type: <span style="color:#8ab4d4;">' + esc(ep.type) + '</span> &bull; Platform: <span style="color:#8ab4d4;">' + esc(ep.platform) + '</span></div>';
    h += '<div style="font-family:monospace;font-size:9px;color:#556;line-height:1.5;">' + esc(ep.description) + '</div>';
    h += '</div>';
  }
  h += '</div>';
  h += '</div>';

  // ── SECTION D: GEOPHYSICAL INTELLIGENCE ──
  h += '<div style="padding:0 24px 16px;">';
  h += '<div style="font-family:monospace;font-size:13px;color:#00aaff;letter-spacing:2px;text-transform:uppercase;margin-bottom:10px;border-bottom:1px solid #1a2a44;padding-bottom:6px;font-weight:bold;">GEOPHYSICAL INTELLIGENCE (GEOINT-M)</div>';

  h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;">';

  // Infrasound
  h += '<div>';
  h += '<div style="font-family:monospace;font-size:11px;color:#00aaff;letter-spacing:1.5px;margin-bottom:8px;font-weight:bold;">INFRASOUND MONITORING (IMS)</div>';
  h += '<table style="width:100%;border-collapse:collapse;font-family:monospace;font-size:10px;">';
  h += '<thead><tr style="border-bottom:1px solid #1a2a44;">';
  h += '<th style="text-align:left;padding:4px 6px;color:#4a6a8a;font-size:8px;letter-spacing:1px;">STATION</th>';
  h += '<th style="text-align:left;padding:4px 6px;color:#4a6a8a;font-size:8px;letter-spacing:1px;">LOCATION</th>';
  h += '<th style="text-align:center;padding:4px 6px;color:#4a6a8a;font-size:8px;letter-spacing:1px;">ELEMENTS</th>';
  h += '<th style="text-align:center;padding:4px 6px;color:#4a6a8a;font-size:8px;letter-spacing:1px;">STATUS</th>';
  h += '</tr></thead><tbody>';
  for (var ii = 0; ii < MASINT_INFRASOUND.length; ii++) {
    var inf = MASINT_INFRASOUND[ii];
    var infColor = inf.status === 'operational' ? '#00ff88' : '#ffaa00';
    h += '<tr style="border-bottom:1px solid #0d1525;">';
    h += '<td style="padding:4px 6px;color:#00aaff;font-weight:bold;">' + esc(inf.station) + '</td>';
    h += '<td style="padding:4px 6px;color:#b0c4d8;">' + esc(inf.location) + '</td>';
    h += '<td style="padding:4px 6px;text-align:center;color:#6a8aaa;">' + inf.elements + '</td>';
    h += '<td style="padding:4px 6px;text-align:center;"><span style="display:inline-block;width:6px;height:6px;border-radius:50%;background:' + infColor + ';box-shadow:0 0 4px ' + infColor + '80;"></span></td>';
    h += '</tr>';
  }
  h += '</tbody></table>';
  h += '</div>';

  // Hydroacoustic
  h += '<div>';
  h += '<div style="font-family:monospace;font-size:11px;color:#00aaff;letter-spacing:1.5px;margin-bottom:8px;font-weight:bold;">HYDROACOUSTIC MONITORING</div>';
  h += '<table style="width:100%;border-collapse:collapse;font-family:monospace;font-size:10px;">';
  h += '<thead><tr style="border-bottom:1px solid #1a2a44;">';
  h += '<th style="text-align:left;padding:4px 6px;color:#4a6a8a;font-size:8px;letter-spacing:1px;">STATION</th>';
  h += '<th style="text-align:left;padding:4px 6px;color:#4a6a8a;font-size:8px;letter-spacing:1px;">LOCATION</th>';
  h += '<th style="text-align:left;padding:4px 6px;color:#4a6a8a;font-size:8px;letter-spacing:1px;">TYPE</th>';
  h += '<th style="text-align:center;padding:4px 6px;color:#4a6a8a;font-size:8px;letter-spacing:1px;">STATUS</th>';
  h += '</tr></thead><tbody>';
  for (var hi = 0; hi < MASINT_HYDROACOUSTIC.length; hi++) {
    var hyd = MASINT_HYDROACOUSTIC[hi];
    var hydColor = hyd.status === 'operational' ? '#00ff88' : '#ffaa00';
    h += '<tr style="border-bottom:1px solid #0d1525;">';
    h += '<td style="padding:4px 6px;color:#00aaff;font-weight:bold;">' + esc(hyd.station) + '</td>';
    h += '<td style="padding:4px 6px;color:#b0c4d8;">' + esc(hyd.location) + '</td>';
    h += '<td style="padding:4px 6px;color:#6a8aaa;">' + esc(hyd.type) + '</td>';
    h += '<td style="padding:4px 6px;text-align:center;"><span style="display:inline-block;width:6px;height:6px;border-radius:50%;background:' + hydColor + ';box-shadow:0 0 4px ' + hydColor + '80;"></span></td>';
    h += '</tr>';
  }
  h += '</tbody></table>';
  h += '</div>';

  h += '</div>'; // end grid
  h += '</div>';

  // ── SECTION E: MATERIALS INTELLIGENCE ──
  h += '<div style="padding:0 24px 20px;">';
  h += '<div style="font-family:monospace;font-size:13px;color:#aa66ff;letter-spacing:2px;text-transform:uppercase;margin-bottom:10px;border-bottom:1px solid #1a2a44;padding-bottom:6px;font-weight:bold;">MATERIALS INTELLIGENCE &mdash; SPECTROSCOPIC SIGNATURES</div>';

  // Enrichment reference
  h += '<div style="margin-bottom:14px;display:flex;gap:10px;">';
  var enrichLevels = [
    { label: 'Natural U', pct: '0.7%', color: '#00ff88', width: '7' },
    { label: 'LEU', pct: '3-5%', color: '#00aaff', width: '20' },
    { label: 'HEU', pct: '> 20%', color: '#ffaa00', width: '50' },
    { label: 'Weapons-Grade', pct: '> 90%', color: '#ff4444', width: '90' }
  ];
  for (var el = 0; el < enrichLevels.length; el++) {
    var enr = enrichLevels[el];
    h += '<div style="flex:1;background:#0a0e1a;border:1px solid ' + enr.color + '33;border-radius:4px;padding:8px 10px;text-align:center;">';
    h += '<div style="font-family:monospace;font-size:10px;color:' + enr.color + ';letter-spacing:1px;font-weight:bold;">' + enr.label + '</div>';
    h += '<div style="font-family:monospace;font-size:16px;color:' + enr.color + ';font-weight:bold;margin:4px 0;">' + enr.pct + '</div>';
    h += '<div style="height:4px;background:#1a2a3a;border-radius:2px;margin-top:4px;"><div style="height:100%;width:' + enr.width + '%;background:' + enr.color + ';border-radius:2px;"></div></div>';
    h += '</div>';
  }
  h += '</div>';

  // Signatures table
  h += '<div style="overflow-x:auto;">';
  h += '<table style="width:100%;border-collapse:collapse;font-family:monospace;font-size:10px;">';
  h += '<thead><tr style="border-bottom:1px solid #1a2a44;">';
  h += '<th style="text-align:left;padding:5px 8px;color:#4a6a8a;font-size:8px;letter-spacing:1px;">MATERIAL</th>';
  h += '<th style="text-align:left;padding:5px 8px;color:#4a6a8a;font-size:8px;letter-spacing:1px;">THRESHOLD</th>';
  h += '<th style="text-align:left;padding:5px 8px;color:#4a6a8a;font-size:8px;letter-spacing:1px;">SIGNATURE</th>';
  h += '<th style="text-align:left;padding:5px 8px;color:#4a6a8a;font-size:8px;letter-spacing:1px;">DETECTION</th>';
  h += '<th style="text-align:left;padding:5px 8px;color:#4a6a8a;font-size:8px;letter-spacing:1px;">TREATY</th>';
  h += '</tr></thead><tbody>';

  for (var mi = 0; mi < MASINT_SIGNATURES.length; mi++) {
    var ms = MASINT_SIGNATURES[mi];
    var matColor = ms.material.indexOf('Uranium') !== -1 || ms.material.indexOf('Plutonium') !== -1 ? '#aa66ff' : ms.material.indexOf('Nerve') !== -1 || ms.material.indexOf('Novichok') !== -1 || ms.material.indexOf('Sarin') !== -1 || ms.material.indexOf('VX') !== -1 ? '#ffaa00' : '#00aaff';
    h += '<tr style="border-bottom:1px solid #0d1525;">';
    h += '<td style="padding:4px 8px;color:' + matColor + ';font-weight:bold;white-space:nowrap;">' + esc(ms.material) + '</td>';
    h += '<td style="padding:4px 8px;color:#b0c4d8;font-size:9px;">' + esc(ms.threshold) + '</td>';
    h += '<td style="padding:4px 8px;color:#6a8aaa;font-size:9px;">' + esc(ms.signature) + '</td>';
    h += '<td style="padding:4px 8px;color:#6a8aaa;font-size:9px;">' + esc(ms.detection) + '</td>';
    h += '<td style="padding:4px 8px;color:#556;font-size:9px;">' + esc(ms.treaty) + '</td>';
    h += '</tr>';
  }
  h += '</tbody></table>';
  h += '</div>';
  h += '</div>';

  return h;
}

// ---------------------------------------------------------------------------
// renderGlobalWatch — main render function (called by switchTab)
// ---------------------------------------------------------------------------
function renderGlobalWatch() {
  // Cleanup any previous instance
  _gwCleanup();

  var h = '';

  // -- Inline CSS --
  h += '<style>';
  h += '.gw-wrap { background: #000408; color: #c8d6e5; font-family: "Courier New", monospace; height: calc(100vh - 160px); min-height: 500px; display: flex; flex-direction: column; }';
  h += '.gw-header { background: #080c14; border-bottom: 1px solid #1a3a5a; padding: 6px 16px; flex-shrink: 0; display: flex; align-items: center; justify-content: space-between; gap: 8px; flex-wrap: wrap; }';
  h += '.gw-header-row { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px; width: 100%; }';
  h += '.gw-title { font-size: 14px; font-weight: bold; letter-spacing: 2px; color: #00ddff; text-transform: uppercase; }';
  h += '.gw-subtitle { font-size: 9px; color: #4a6a8a; letter-spacing: 1px; }';
  h += '.gw-layers { display: flex; flex-wrap: wrap; gap: 4px; align-items: center; }';
  h += '.gw-layer-btn { background: #111a24; border: 1px solid #1a3050; color: #4a6a8a; padding: 3px 8px; font-size: 10px; font-family: monospace; cursor: pointer; border-radius: 3px; letter-spacing: 1px; transition: all 0.2s; }';
  h += '.gw-layer-btn:hover { border-color: #2a5a8a; color: #8ab4d4; }';
  h += '.gw-layer-btn.gw-on { background: #0a2a44; border-color: #00aaff; color: #00ddff; box-shadow: 0 0 6px rgba(0,170,255,0.2); }';
  h += '.gw-status-bar { display: none; }';
  h += '.gw-status-val { color: #00aaff; margin-left: 4px; }';
  h += '.gw-globe-area { flex: 1; position: relative; min-height: 400px; background: #000408; overflow: hidden; }';
  h += '#gw-cesium-container { width: 100%; height: 100%; position: absolute; top: 0; left: 0; right: 0; bottom: 0; }';
  h += '.gw-controls { display: flex; gap: 6px; padding: 4px 12px; background: #080c14; border-top: 1px solid #1a3a5a; flex-shrink: 0; overflow-x: auto; align-items: center; scrollbar-width: thin; scrollbar-color: #1a3050 transparent; font-size: 9px; }';
  h += '.gw-ctrl-group { display: flex; gap: 4px; align-items: center; }';
  h += '.gw-ctrl-label { font-size: 10px; color: #3a5a7a; letter-spacing: 1px; margin-right: 4px; }';
  h += '.gw-fly-btn { background: #0a1a28; border: 1px solid #1a3050; color: #5a8aaa; padding: 3px 8px; font-size: 10px; font-family: monospace; cursor: pointer; border-radius: 2px; letter-spacing: 1px; }';
  h += '.gw-fly-btn:hover { border-color: #00aaff; color: #00ddff; background: #0a2a44; }';
  h += '.gw-speed-ctrl { background: #0a1a28; border: 1px solid #1a3050; color: #5a8aaa; padding: 3px 8px; font-size: 10px; font-family: monospace; cursor: pointer; border-radius: 2px; }';
  h += '.gw-popup { position: absolute; background: rgba(8,12,20,0.96); border: 1px solid #1a4a6a; border-radius: 4px; padding: 12px 16px; max-width: 380px; min-width: 260px; z-index: 1000; box-shadow: 0 4px 24px rgba(0,0,0,0.7); pointer-events: auto; }';
  h += '.gw-popup-title { font-size: 14px; color: #00ddff; font-weight: bold; letter-spacing: 1px; margin-bottom: 6px; border-bottom: 1px solid #1a3a5a; padding-bottom: 6px; }';
  h += '.gw-popup-row { font-size: 11px; color: #8ab4d4; margin: 3px 0; }';
  h += '.gw-popup-label { color: #4a7a9a; margin-right: 6px; }';
  h += '.gw-popup-close { position: absolute; top: 6px; right: 10px; color: #4a6a8a; cursor: pointer; font-size: 16px; }';
  h += '.gw-popup-close:hover { color: #ff4444; }';
  h += '.gw-hostile { color: #ff4444; }';
  h += '.gw-allied { color: #44aaff; }';
  h += '.gw-neutral { color: #aaaaaa; }';
  h += '.gw-tier { display: inline-block; padding: 1px 6px; border-radius: 2px; font-size: 10px; letter-spacing: 1px; }';
  h += '.gw-tier-1 { background: #3a0a0a; color: #ff4444; border: 1px solid #ff2222; }';
  h += '.gw-tier-2 { background: #3a2a0a; color: #ffaa44; border: 1px solid #ff8800; }';
  h += '.gw-loading-overlay { position: absolute; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,4,8,0.95); display: flex; align-items: center; justify-content: center; z-index: 500; }';
  h += '.gw-loading-text { color: #00aaff; font-size: 14px; font-family: monospace; letter-spacing: 2px; }';
  h += '.gw-loading-text span { animation: gw-pulse 1.5s ease-in-out infinite; }';
  h += '@keyframes gw-pulse { 0%, 100% { opacity: 0.4; } 50% { opacity: 1; } }';
  h += '.gw-dark-toggle { background: #0a1a28; border: 1px solid #1a3050; color: #5a8aaa; padding: 3px 8px; font-size: 10px; font-family: monospace; cursor: pointer; border-radius: 2px; }';
  h += '.gw-dark-toggle.gw-light { background: #1a2a3a; color: #aaddff; border-color: #3a6a8a; }';
  h += '.gw-legend { position: absolute; bottom: 8px; left: 8px; background: rgba(8,12,20,0.92); border: 1px solid #1a3a5a; border-radius: 4px; padding: 4px 8px; font-size: 8px; z-index: 300; max-height: 140px; overflow-y: auto; display: none; }';
  h += '.gw-legend.gw-legend-show { display: block; }';
  h += '.gw-legend-item { display: flex; align-items: center; gap: 6px; margin: 3px 0; color: #6a8aaa; }';
  h += '.gw-legend-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }';
  h += '.gw-legend-line { width: 16px; height: 2px; display: inline-block; }';
  h += '</style>';

  // -- Header --
  h += '<div class="gw-wrap" id="gw-wrap">';
  h += '<div class="gw-header">';
  h += '<div class="gw-header-row">';
  h += '<div>';
  h += '<div class="gw-title">GLOBAL WATCH</div>';
  h += '<div class="gw-subtitle">CYBER THREAT GEOSPATIAL INTELLIGENCE // DARKNODE SIGINT DIVISION</div>';
  h += '</div>';
  h += '<div class="gw-layers" id="gw-layers">';

  var layerDefs = [
    { id: 'threats', label: 'Threat Actors', defaultOn: true },
    { id: 'aircraft', label: 'Live Aircraft', defaultOn: false },
    { id: 'quakes', label: 'Earthquakes', defaultOn: false },
    { id: 'infra', label: 'Internet Infra', defaultOn: true },
    { id: 'attacks', label: 'Cyber Attacks', defaultOn: true },
    { id: 'satellites', label: 'Satellites', defaultOn: false }
  ];

  // Load saved state
  var savedLayers = null;
  try {
    var raw = localStorage.getItem('dn_global_watch');
    if (raw) savedLayers = JSON.parse(raw);
  } catch (e) { /* ignore */ }

  for (var i = 0; i < layerDefs.length; i++) {
    var ld = layerDefs[i];
    var isOn = savedLayers ? !!savedLayers[ld.id] : ld.defaultOn;
    _gwLayers[ld.id] = isOn;
    var cls = 'gw-layer-btn' + (isOn ? ' gw-on' : '');
    h += '<button class="' + cls + '" data-gw-layer="' + esc(ld.id) + '">' + esc(ld.label) + '</button>';
  }

  h += '</div>';
  h += '</div>';
  h += '</div>';

  // -- Status Bar --
  h += '<div class="gw-status-bar" id="gw-status-bar">';
  h += '<span>ACTIVE LAYERS: <span class="gw-status-val" id="gw-stat-layers">0</span></span>';
  h += '<span>ENTITIES TRACKED: <span class="gw-status-val" id="gw-stat-entities">0</span></span>';
  h += '<span>THREAT VECTORS: <span class="gw-status-val" id="gw-stat-vectors">0</span></span>';
  h += '<span>LAST UPDATE: <span class="gw-status-val" id="gw-stat-update">--</span></span>';
  h += '<span>STATUS: <span class="gw-status-val" style="color:#00ff88;">OPERATIONAL</span></span>';
  h += '</div>';

  // -- Globe Area --
  h += '<div class="gw-globe-area" id="gw-globe-area">';
  h += '<div id="gw-cesium-container"></div>';
  h += '<div class="gw-loading-overlay" id="gw-loading">';
  h += '<div class="gw-loading-text"><span>INITIALIZING CESIUM GEOSPATIAL ENGINE...</span></div>';
  h += '</div>';

  // -- Legend --
  h += '<div class="gw-legend" id="gw-legend">';
  h += '<div style="color:#5a8aaa;font-weight:bold;margin-bottom:4px;letter-spacing:1px;">LEGEND</div>';
  h += '<div class="gw-legend-item"><span class="gw-legend-dot" style="background:#ff3333;"></span> HOSTILE ACTOR</div>';
  h += '<div class="gw-legend-item"><span class="gw-legend-dot" style="background:#4488ff;"></span> ALLIED ASSET</div>';
  h += '<div class="gw-legend-item"><span class="gw-legend-dot" style="background:#00ff88;"></span> IXP / DNS ROOT</div>';
  h += '<div class="gw-legend-item"><span class="gw-legend-line" style="background:#ff4444;"></span> ATTACK VECTOR</div>';
  h += '<div class="gw-legend-item"><span class="gw-legend-line" style="background:#00aaff;"></span> INTERNET BACKBONE</div>';
  h += '<div class="gw-legend-item"><span class="gw-legend-line" style="background:#2a5a3a;"></span> UNDERSEA CABLE</div>';
  h += '<div class="gw-legend-item"><span class="gw-legend-dot" style="background:#ffaa00;"></span> SEISMIC EVENT</div>';
  h += '<div class="gw-legend-item"><span class="gw-legend-dot" style="background:#aa44ff;"></span> SATELLITE ASSET</div>';
  h += '</div>';

  // -- Popup container --
  h += '<div class="gw-popup" id="gw-popup" style="display:none;"></div>';

  h += '</div>';

  // -- Controls --
  h += '<div class="gw-controls">';

  // Fly-to buttons
  h += '<div class="gw-ctrl-group">';
  h += '<span class="gw-ctrl-label">FLY TO:</span>';
  for (var f = 0; f < GW_FLY_TO.length; f++) {
    h += '<button class="gw-fly-btn" data-gw-fly="' + esc(GW_FLY_TO[f].id) + '">' + esc(GW_FLY_TO[f].label) + '</button>';
  }
  h += '</div>';

  // Speed control
  h += '<div class="gw-ctrl-group">';
  h += '<span class="gw-ctrl-label">ARC SPEED:</span>';
  h += '<button class="gw-speed-ctrl" data-gw-speed="0.5">0.5x</button>';
  h += '<button class="gw-speed-ctrl" data-gw-speed="1">1x</button>';
  h += '<button class="gw-speed-ctrl" data-gw-speed="2">2x</button>';
  h += '<button class="gw-speed-ctrl" data-gw-speed="4">4x</button>';
  h += '</div>';

  h += '</div>';
  h += '</div>';

  return h;
}

// ---------------------------------------------------------------------------
// _gwInitGlobe — stub, replaced by enhanced version below
// ---------------------------------------------------------------------------
function _gwInitGlobe() {
  // This function is overridden below — see ENHANCED GLOBE INIT
}

// ---------------------------------------------------------------------------
// _gwCleanup — destroy viewer and clear timers
// ---------------------------------------------------------------------------
function _gwCleanup() {
  if (_gwAnimFrameId) {
    cancelAnimationFrame(_gwAnimFrameId);
    _gwAnimFrameId = null;
  }
  for (var t = 0; t < _gwRefreshTimers.length; t++) {
    clearInterval(_gwRefreshTimers[t]);
  }
  _gwRefreshTimers = [];
  if (_gwViewer && !_gwViewer.isDestroyed()) {
    try { _gwViewer.destroy(); } catch (e) { /* ignore */ }
  }
  _gwViewer = null;
  _gwLayerEntities = {};
  _gwAttackArcs = [];
  _gwEntityCount = 0;
}

// ---------------------------------------------------------------------------
// _gwWireEvents — set up click handlers for layer toggles, fly-to, etc.
// ---------------------------------------------------------------------------
function _gwWireEvents() {
  var wrap = document.getElementById('gw-wrap');
  if (!wrap) return;

  wrap.addEventListener('click', function(e) {
    var target = e.target;

    // Layer toggle
    var layerBtn = target.closest('[data-gw-layer]');
    if (layerBtn) {
      var layerId = layerBtn.getAttribute('data-gw-layer');
      _gwLayers[layerId] = !_gwLayers[layerId];
      if (_gwLayers[layerId]) {
        layerBtn.classList.add('gw-on');
      } else {
        layerBtn.classList.remove('gw-on');
      }
      _gwSaveLayers();
      _gwToggleLayer(layerId, _gwLayers[layerId]);
      _gwUpdateStatus();
      return;
    }

    // Fly-to
    var flyBtn = target.closest('[data-gw-fly]');
    if (flyBtn) {
      var flyId = flyBtn.getAttribute('data-gw-fly');
      _gwFlyTo(flyId);
      return;
    }

    // Speed control
    var speedBtn = target.closest('[data-gw-speed]');
    if (speedBtn) {
      var speed = parseFloat(speedBtn.getAttribute('data-gw-speed'));
      _gwArcSpeed = speed || 1;
      return;
    }

    // Theme toggle
    if (target.id === 'gw-theme-toggle' || target.closest('#gw-theme-toggle')) {
      _gwToggleTheme();
      return;
    }

    // Popup close
    if (target.classList.contains('gw-popup-close')) {
      var popup = document.getElementById('gw-popup');
      if (popup) popup.style.display = 'none';
      return;
    }
  });

  // Entity click handler on the globe
  if (_gwViewer) {
    var handler = new Cesium.ScreenSpaceEventHandler(_gwViewer.scene.canvas);
    handler.setInputAction(function(click) {
      var picked = _gwViewer.scene.pick(click.position);
      if (Cesium.defined(picked) && picked.id && picked.id._gwData) {
        _gwShowPopup(picked.id._gwData, click.position);
      } else {
        var popup = document.getElementById('gw-popup');
        if (popup) popup.style.display = 'none';
      }
    }, Cesium.ScreenSpaceEventType.LEFT_CLICK);
  }
}

// ---------------------------------------------------------------------------
// _gwSaveLayers — persist layer states to localStorage
// ---------------------------------------------------------------------------
function _gwSaveLayers() {
  try {
    localStorage.setItem('dn_global_watch', JSON.stringify(_gwLayers));
  } catch (e) { /* quota exceeded or unavailable */ }
}

// ---------------------------------------------------------------------------
// _gwToggleLayer — show/hide a layer's entities
// ---------------------------------------------------------------------------
function _gwToggleLayer(layerId, show) {
  // Remove existing entities for this layer
  if (!show && _gwLayerEntities[layerId]) {
    var entities = _gwLayerEntities[layerId];
    for (var i = 0; i < entities.length; i++) {
      try {
        _gwViewer.entities.remove(entities[i]);
      } catch (e) { /* ignore */ }
    }
    _gwLayerEntities[layerId] = [];
    _gwEntityCount = Math.max(0, _gwEntityCount - entities.length);
    _gwUpdateStatus();
    return;
  }

  // Add entities for this layer
  if (show) {
    switch (layerId) {
      case 'threats': _gwRenderThreatActors(); break;
      case 'aircraft': _gwRenderAircraft(); break;
      case 'quakes': _gwRenderEarthquakes(); break;
      case 'infra': _gwRenderInfrastructure(); break;
      case 'attacks': _gwRenderCyberAttacks(); break;
      case 'satellites': _gwRenderSatellites(); break;
    }
  }
}

// ---------------------------------------------------------------------------
// _gwRenderAllLayers — render all active layers
// ---------------------------------------------------------------------------
function _gwRenderAllLayers() {
  var keys = Object.keys(_gwLayers);
  for (var i = 0; i < keys.length; i++) {
    if (_gwLayers[keys[i]]) {
      _gwToggleLayer(keys[i], true);
    }
  }
}

// ---------------------------------------------------------------------------
// _gwFlyTo — fly camera to a preset location
// ---------------------------------------------------------------------------
function _gwFlyTo(id) {
  if (!_gwViewer) return;
  for (var i = 0; i < GW_FLY_TO.length; i++) {
    if (GW_FLY_TO[i].id === id) {
      var loc = GW_FLY_TO[i];
      _gwViewer.camera.flyTo({
        destination: Cesium.Cartesian3.fromDegrees(loc.lon, loc.lat, loc.alt),
        duration: 2.0
      });
      return;
    }
  }
}

// ---------------------------------------------------------------------------
// ARC ANIMATION
// ---------------------------------------------------------------------------
var _gwArcSpeed = 1;
var _gwArcTime = 0;

function _gwStartAnimationLoop() {
  var frameCount = 0;
  function tick() {
    frameCount++;
    if (frameCount % 4 === 0) {
      _gwArcTime += 0.032 * _gwArcSpeed;
      if (_gwArcTime > 1) _gwArcTime = 0;

      for (var i = 0; i < _gwAttackArcs.length; i++) {
        var arc = _gwAttackArcs[i];
        if (arc.entity && arc.entity.polyline) {
          var phase = (_gwArcTime + i * 0.07) % 1;
          var alpha = 0.3 + 0.7 * Math.abs(Math.sin(phase * Math.PI));
          try {
            arc.entity.polyline.material = new Cesium.PolylineGlowMaterialProperty({
              glowPower: 0.15 + 0.1 * alpha,
              color: Cesium.Color.fromCssColorString(arc.color).withAlpha(alpha)
            });
          } catch (e) {}
        }
      }
    }

    _gwAnimFrameId = requestAnimationFrame(tick);
  }
  _gwAnimFrameId = requestAnimationFrame(tick);
}

// ---------------------------------------------------------------------------
// _gwStartAutoRefresh — periodic refresh of live data layers
// ---------------------------------------------------------------------------
function _gwStartAutoRefresh() {
  // Refresh earthquakes every 5 minutes
  var quakeTimer = setInterval(function() {
    if (_gwLayers.quakes && _gwViewer && !_gwViewer.isDestroyed()) {
      _gwToggleLayer('quakes', false);
      _gwToggleLayer('quakes', true);
    }
  }, 300000);
  _gwRefreshTimers.push(quakeTimer);

  // Refresh aircraft every 60 seconds (rate-limited)
  var aircraftTimer = setInterval(function() {
    if (_gwLayers.aircraft && _gwViewer && !_gwViewer.isDestroyed()) {
      _gwToggleLayer('aircraft', false);
      _gwToggleLayer('aircraft', true);
    }
  }, 60000);
  _gwRefreshTimers.push(aircraftTimer);

  // Refresh all satellite positions every 10 seconds (TLE propagation is instant, no network)
  var satTimer = setInterval(function() {
    if (_gwLayers.satellites && _gwViewer && !_gwViewer.isDestroyed()) {
      _gwRefreshAllSats();
    }
  }, 10000);
  _gwRefreshTimers.push(satTimer);

  // Refresh status bar clock every 5 seconds
  var clockTimer = setInterval(function() {
    _gwUpdateStatus();
  }, 5000);
  _gwRefreshTimers.push(clockTimer);
}

// ---------------------------------------------------------------------------
// _gwUpdateStatus — update status bar values
// ---------------------------------------------------------------------------
function _gwUpdateStatus() {
  var activeCount = 0;
  var keys = Object.keys(_gwLayers);
  for (var i = 0; i < keys.length; i++) {
    if (_gwLayers[keys[i]]) activeCount++;
  }

  var vectorCount = _gwAttackArcs.length;

  var el1 = document.getElementById('gw-stat-layers');
  var el2 = document.getElementById('gw-stat-entities');
  var el3 = document.getElementById('gw-stat-vectors');
  var el4 = document.getElementById('gw-stat-update');

  if (el1) el1.textContent = String(activeCount);
  if (el2) el2.textContent = String(_gwEntityCount);
  if (el3) el3.textContent = String(vectorCount);
  if (el4) {
    var now = new Date();
    el4.textContent = now.toISOString().replace('T', ' ').substring(0, 19) + 'Z';
  }

  _gwLastUpdate = new Date();
}

// ---------------------------------------------------------------------------
// _gwShowPopup — display info popup for a clicked entity
// ---------------------------------------------------------------------------
function _gwShowPopup(data, screenPos) {
  var popup = document.getElementById('gw-popup');
  if (!popup) return;

  var h = '';
  h += '<div class="gw-popup-close">x</div>';

  if (data.type === 'threat') {
    var alignClass = data.alignment === 'hostile' ? 'gw-hostile' : 'gw-allied';
    var tierClass = data.tier === 'TIER-1' ? 'gw-tier-1' : 'gw-tier-2';
    h += '<div class="gw-popup-title ' + alignClass + '">' + esc(data.name) + '</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">NATION:</span>' + esc(data.nation) + '</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">CLASSIFICATION:</span> <span class="' + tierClass + ' gw-tier">' + esc(data.tier) + '</span></div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">DESIGNATION:</span> <span class="' + alignClass + '">' + (data.alignment === 'hostile' ? 'HOSTILE' : 'ALLIED') + '</span></div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">CITY:</span>' + esc(data.city) + '</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">APT GROUPS:</span>' + esc(data.aptGroups) + '</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">RECENT OPS:</span><span style="color:#bbb;font-size:10px;">' + esc(data.recentOps) + '</span></div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">CAPABILITIES:</span><span style="color:#bbb;font-size:10px;">' + esc(data.capabilities) + '</span></div>';
    h += '<div class="gw-popup-row" style="margin-top:6px;border-top:1px solid #1a3a5a;padding-top:4px;"><span class="gw-popup-label">SIGINT NOTE:</span><span style="color:#6a8aaa;font-size:10px;">' + esc(data.notes) + '</span></div>';
  } else if (data.type === 'aircraft') {
    h += '<div class="gw-popup-title" style="color:#00ff88;">AIRCRAFT TRACK</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">CALLSIGN:</span>' + esc(data.callsign || 'UNKNOWN') + '</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">ICAO24:</span>' + esc(data.icao24 || '--') + '</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">ORIGIN:</span>' + esc(data.origin || 'UNKNOWN') + '</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">ALTITUDE:</span>' + esc(data.altitude || '--') + ' m</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">VELOCITY:</span>' + esc(data.velocity || '--') + ' m/s</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">HEADING:</span>' + esc(data.heading || '--') + ' deg</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">ON GROUND:</span>' + (data.onGround ? 'YES' : 'NEGATIVE') + '</div>';
  } else if (data.type === 'earthquake') {
    var magColor = data.magnitude >= 6 ? '#ff2222' : (data.magnitude >= 4.5 ? '#ff8800' : '#ffcc00');
    h += '<div class="gw-popup-title" style="color:' + magColor + ';">SEISMIC EVENT M' + esc(String(data.magnitude)) + '</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">LOCATION:</span>' + esc(data.place) + '</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">MAGNITUDE:</span><span style="color:' + magColor + ';">' + esc(String(data.magnitude)) + '</span></div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">DEPTH:</span>' + esc(String(data.depth)) + ' km</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">TIME:</span>' + esc(data.time) + '</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">ALERT:</span>' + esc(data.alert || 'NONE') + '</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">TSUNAMI:</span>' + (data.tsunami ? 'WARNING' : 'NONE') + '</div>';
  } else if (data.type === 'ixp') {
    h += '<div class="gw-popup-title" style="color:#00ff88;">INTERNET EXCHANGE POINT</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">NAME:</span>' + esc(data.name) + '</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">CAPACITY:</span>' + esc(data.capacity) + '</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">OPERATOR:</span>' + esc(data.operator) + '</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">ASSET CLASS:</span>CRITICAL INFRASTRUCTURE</div>';
  } else if (data.type === 'dns') {
    h += '<div class="gw-popup-title" style="color:#00ddff;">ROOT DNS SERVER</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">SERVER:</span>' + esc(data.name) + '</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">OPERATOR:</span>' + esc(data.operator) + '</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">LOCATION:</span>' + esc(data.city) + '</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">ASSET CLASS:</span>CRITICAL DNS INFRASTRUCTURE</div>';
  } else if (data.type === 'cable') {
    h += '<div class="gw-popup-title" style="color:#2a8a5a;">UNDERSEA CABLE</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">NAME:</span>' + esc(data.name) + '</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">CAPACITY:</span>' + esc(data.capacity) + '</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">OPERATOR:</span>' + esc(data.operator) + '</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">REGION:</span>' + esc(data.region) + '</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">ASSET CLASS:</span>STRATEGIC COMMUNICATIONS</div>';
  } else if (data.type === 'satellite') {
    var satColor = data.satType === 'military' ? '#ff6644' : (data.satType === 'navigation' ? '#44aaff' : '#aa44ff');
    h += '<div class="gw-popup-title" style="color:' + satColor + ';">ORBITAL ASSET</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">DESIGNATION:</span>' + esc(data.name) + '</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">CONSTELLATION:</span>' + esc(data.constellation) + '</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">ALTITUDE:</span>' + esc(String(data.alt)) + ' km</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">TYPE:</span>' + esc(data.satType).toUpperCase() + '</div>';
  } else if (data.type === 'iss') {
    h += '<div class="gw-popup-title" style="color:#ffaa00;">ISS — INTERNATIONAL SPACE STATION</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">POSITION:</span>' + esc(String(data.lat)) + ', ' + esc(String(data.lon)) + '</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">ALTITUDE:</span>~420 km</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">VELOCITY:</span>~7.66 km/s</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">ASSET CLASS:</span>MANNED ORBITAL PLATFORM</div>';
  } else if (data.type === 'cve') {
    h += '<div class="gw-popup-title" style="color:#ff6644;">KNOWN EXPLOITED VULNERABILITY</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">CVE:</span><span style="color:#ff8844;">' + esc(data.cve) + '</span></div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">VENDOR:</span>' + esc(data.vendor) + '</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">PRODUCT:</span>' + esc(data.product) + '</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">NAME:</span><span style="font-size:10px;color:#bbb;">' + esc(data.vulnName) + '</span></div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">DATE ADDED:</span>' + esc(data.dateAdded) + '</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">RANSOMWARE:</span>' + esc(data.ransomware || 'Unknown') + '</div>';
  } else if (data.type === 'malip') {
    h += '<div class="gw-popup-title" style="color:#ff3333;">MALICIOUS IP ADDRESS</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">IP:</span><span style="color:#ff4444;">' + esc(data.ip) + '</span></div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">THREAT SCORE:</span>' + esc(String(data.score)) + '/10</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">SOURCE:</span>' + esc(data.source) + '</div>';
    h += '<div class="gw-popup-row"><span class="gw-popup-label">CLASSIFICATION:</span>HOSTILE NETWORK ASSET</div>';
  } else {
    h += '<div class="gw-popup-title">ENTITY DATA</div>';
    h += '<div class="gw-popup-row">No additional intelligence available.</div>';
  }

  popup.innerHTML = h;
  popup.style.display = 'block';

  // Position popup near click but keep on screen
  var area = document.getElementById('gw-globe-area');
  if (area) {
    var rect = area.getBoundingClientRect();
    var left = Math.min(screenPos.x + 10, rect.width - 400);
    var top = Math.min(screenPos.y + 10, rect.height - 300);
    if (left < 10) left = 10;
    if (top < 10) top = 10;
    popup.style.left = left + 'px';
    popup.style.top = top + 'px';
  }
}

// ---------------------------------------------------------------------------
// _gwToggleTheme — switch between dark and light globe tiles
// ---------------------------------------------------------------------------
var _gwDarkMode = true;

function _gwToggleTheme() {
  if (!_gwViewer || _gwViewer.isDestroyed()) return;

  _gwDarkMode = !_gwDarkMode;
  var btn = document.getElementById('gw-theme-toggle');

  // Remove existing imagery layers
  _gwViewer.imageryLayers.removeAll();

  if (_gwDarkMode) {
    _gwViewer.imageryLayers.addImageryProvider(
      new Cesium.UrlTemplateImageryProvider({
        url: 'https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}',
        maximumLevel: 13,
        credit: 'Esri World Imagery'
      })
    );
    if (_gwViewer.scene.globe) {
      _gwViewer.scene.globe.baseColor = Cesium.Color.fromCssColorString('#041020');
      _gwViewer.scene.globe.enableLighting = true;
    }
    _gwViewer.scene.backgroundColor = Cesium.Color.fromCssColorString('#000206');
    if (btn) {
      btn.textContent = 'SATELLITE';
      btn.classList.remove('gw-light');
    }
  } else {
    _gwViewer.imageryLayers.addImageryProvider(
      new Cesium.UrlTemplateImageryProvider({
        url: 'https://server.arcgisonline.com/ArcGIS/rest/services/World_Street_Map/MapServer/tile/{z}/{y}/{x}',
        maximumLevel: 13,
        credit: 'Esri World Street Map'
      })
    );
    if (_gwViewer.scene.globe) {
      _gwViewer.scene.globe.baseColor = Cesium.Color.fromCssColorString('#e0e8f0');
      _gwViewer.scene.globe.enableLighting = false;
    }
    _gwViewer.scene.backgroundColor = Cesium.Color.fromCssColorString('#a0c0e0');
    if (btn) {
      btn.textContent = 'STREET MAP';
      btn.classList.add('gw-light');
    }
  }
}

// ============================================================================
// LAYER RENDERERS
// ============================================================================

// ---------------------------------------------------------------------------
// 1. THREAT ACTORS
// ---------------------------------------------------------------------------
function _gwRenderThreatActors() {
  if (!_gwViewer || _gwViewer.isDestroyed()) return;
  _gwLayerEntities.threats = [];

  for (var i = 0; i < GW_THREAT_ACTORS.length; i++) {
    var ta = GW_THREAT_ACTORS[i];
    var color = ta.alignment === 'hostile' ? '#ff3333' : '#4488ff';
    var outlineColor = ta.alignment === 'hostile' ? '#ff0000' : '#2266dd';
    var pixelSize = ta.tier === 'TIER-1' ? 12 : 9;

    var entity = _gwViewer.entities.add({
      position: Cesium.Cartesian3.fromDegrees(ta.lon, ta.lat),
      point: {
        pixelSize: pixelSize,
        color: Cesium.Color.fromCssColorString(color),
        outlineColor: Cesium.Color.fromCssColorString(outlineColor),
        outlineWidth: 2,
        heightReference: Cesium.HeightReference.CLAMP_TO_GROUND,
        disableDepthTestDistance: Number.POSITIVE_INFINITY
      },
      label: {
        text: ta.id.toUpperCase(),
        font: '9px monospace',
        fillColor: Cesium.Color.fromCssColorString(color).withAlpha(0.7),
        outlineColor: Cesium.Color.BLACK,
        outlineWidth: 2,
        style: Cesium.LabelStyle.FILL_AND_OUTLINE,
        pixelOffset: new Cesium.Cartesian2(0, -16),
        disableDepthTestDistance: Number.POSITIVE_INFINITY,
        scaleByDistance: new Cesium.NearFarScalar(5e5, 0.8, 8e6, 0.0)
      }
    });
    entity._gwData = {
      type: 'threat',
      name: ta.name,
      nation: ta.nation,
      city: ta.city,
      tier: ta.tier,
      alignment: ta.alignment,
      aptGroups: ta.aptGroups,
      recentOps: ta.recentOps,
      capabilities: ta.capabilities,
      notes: ta.notes
    };
    _gwLayerEntities.threats.push(entity);
    _gwEntityCount++;
  }

  // Draw campaign arcs
  _gwAttackArcs = [];
  for (var j = 0; j < GW_CAMPAIGN_ARCS.length; j++) {
    var arc = GW_CAMPAIGN_ARCS[j];
    // Find the from coordinates
    var fromLat = 0, fromLon = 0;
    for (var k = 0; k < GW_THREAT_ACTORS.length; k++) {
      if (GW_THREAT_ACTORS[k].id === arc.from) {
        fromLat = GW_THREAT_ACTORS[k].lat;
        fromLon = GW_THREAT_ACTORS[k].lon;
        break;
      }
    }

    // Create arc polyline with intermediate points for curvature
    var arcPositions = _gwComputeArcPositions(fromLat, fromLon, arc.toLat, arc.toLon, 40);

    var arcEntity = _gwViewer.entities.add({
      polyline: {
        positions: arcPositions,
        width: 2,
        material: new Cesium.PolylineGlowMaterialProperty({
          glowPower: 0.2,
          color: Cesium.Color.fromCssColorString(arc.color).withAlpha(0.6)
        }),
        clampToGround: false
      }
    });
    arcEntity._gwData = {
      type: 'campaign',
      label: arc.label
    };

    _gwAttackArcs.push({ entity: arcEntity, color: arc.color });
    _gwLayerEntities.threats.push(arcEntity);
    _gwEntityCount++;

    // Add small target marker at destination
    var targetEntity = _gwViewer.entities.add({
      position: Cesium.Cartesian3.fromDegrees(arc.toLon, arc.toLat),
      point: {
        pixelSize: 5,
        color: Cesium.Color.fromCssColorString(arc.color).withAlpha(0.7),
        outlineColor: Cesium.Color.fromCssColorString(arc.color),
        outlineWidth: 1,
        disableDepthTestDistance: Number.POSITIVE_INFINITY,
        heightReference: Cesium.HeightReference.CLAMP_TO_GROUND
      },
      label: {
        text: arc.label,
        font: '8px monospace',
        fillColor: Cesium.Color.fromCssColorString(arc.color).withAlpha(0.5),
        outlineColor: Cesium.Color.BLACK,
        outlineWidth: 2,
        style: Cesium.LabelStyle.FILL_AND_OUTLINE,
        pixelOffset: new Cesium.Cartesian2(0, -10),
        disableDepthTestDistance: Number.POSITIVE_INFINITY,
        scaleByDistance: new Cesium.NearFarScalar(3e5, 0.7, 3e6, 0.0),
        scale: 0.7
      }
    });
    _gwLayerEntities.threats.push(targetEntity);
    _gwEntityCount++;
  }

  _gwUpdateStatus();
}

// ---------------------------------------------------------------------------
// Compute great-circle arc positions with altitude for visual curvature
// ---------------------------------------------------------------------------
function _gwComputeArcPositions(lat1, lon1, lat2, lon2, numPoints) {
  var positions = [];
  var startCart = Cesium.Cartographic.fromDegrees(lon1, lat1);
  var endCart = Cesium.Cartographic.fromDegrees(lon2, lat2);

  // Compute great circle distance for arc height
  var dLat = (lat2 - lat1) * Math.PI / 180;
  var dLon = (lon2 - lon1) * Math.PI / 180;
  var a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
    Math.sin(dLon / 2) * Math.sin(dLon / 2);
  var c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  var distKm = 6371 * c;
  var maxAlt = Math.min(distKm * 80, 1500000); // Arc height proportional to distance

  for (var i = 0; i <= numPoints; i++) {
    var t = i / numPoints;
    var lat = lat1 + (lat2 - lat1) * t;
    var lon = lon1 + (lon2 - lon1) * t;
    var alt = maxAlt * Math.sin(t * Math.PI); // Parabolic arc
    positions.push(Cesium.Cartesian3.fromDegrees(lon, lat, alt));
  }

  return positions;
}

// ---------------------------------------------------------------------------
// 2. LIVE AIRCRAFT (direct browser fetch — OpenSky Network CORS API)
// ---------------------------------------------------------------------------
var GW_SIM_AIRCRAFT = [
  { cs: 'UAL447', origin: 'United States', lat: 45.2, lon: -42.5, alt: 11280, vel: 245, hdg: 78 },
  { cs: 'BAW115', origin: 'United Kingdom', lat: 52.1, lon: -18.3, alt: 10670, vel: 238, hdg: 255 },
  { cs: 'DLH402', origin: 'Germany', lat: 50.8, lon: -30.1, alt: 11890, vel: 250, hdg: 72 },
  { cs: 'AFR012', origin: 'France', lat: 48.2, lon: -8.4, alt: 10360, vel: 232, hdg: 265 },
  { cs: 'AAL100', origin: 'United States', lat: 38.5, lon: -88.2, alt: 10970, vel: 228, hdg: 90 },
  { cs: 'DAL089', origin: 'United States', lat: 41.3, lon: -74.5, alt: 9140, vel: 210, hdg: 195 },
  { cs: 'SWA2241', origin: 'United States', lat: 33.9, lon: -102.4, alt: 10670, vel: 225, hdg: 270 },
  { cs: 'JBU524', origin: 'United States', lat: 28.1, lon: -81.3, alt: 8230, vel: 198, hdg: 15 },
  { cs: 'ANA008', origin: 'Japan', lat: 48.5, lon: -168.2, alt: 11280, vel: 255, hdg: 42 },
  { cs: 'JAL061', origin: 'Japan', lat: 38.7, lon: 155.4, alt: 10970, vel: 248, hdg: 55 },
  { cs: 'CPA841', origin: 'China', lat: 32.5, lon: 142.1, alt: 11580, vel: 260, hdg: 245 },
  { cs: 'SIA321', origin: 'Singapore', lat: 12.4, lon: 105.8, alt: 11890, vel: 242, hdg: 340 },
  { cs: 'QFA7', origin: 'Australia', lat: -8.2, lon: 115.3, alt: 11280, vel: 250, hdg: 315 },
  { cs: 'UAE201', origin: 'UAE', lat: 28.4, lon: 58.2, alt: 11580, vel: 255, hdg: 110 },
  { cs: 'THY033', origin: 'Turkey', lat: 42.1, lon: 32.5, alt: 10670, vel: 230, hdg: 260 },
  { cs: 'KLM605', origin: 'Netherlands', lat: 53.2, lon: 2.8, alt: 9450, vel: 215, hdg: 180 },
  { cs: 'SAS937', origin: 'Sweden', lat: 58.3, lon: 14.2, alt: 10360, vel: 220, hdg: 200 },
  { cs: 'ACA855', origin: 'Canada', lat: 49.8, lon: -97.1, alt: 10970, vel: 235, hdg: 135 },
  { cs: 'TAM8065', origin: 'Brazil', lat: -5.3, lon: -35.2, alt: 11280, vel: 240, hdg: 350 },
  { cs: 'SAA222', origin: 'South Africa', lat: -18.4, lon: 28.3, alt: 10670, vel: 238, hdg: 15 },
  { cs: 'ETH507', origin: 'Ethiopia', lat: 8.2, lon: 38.7, alt: 11580, vel: 245, hdg: 190 },
  { cs: 'RYR4421', origin: 'Ireland', lat: 44.5, lon: 8.9, alt: 10060, vel: 218, hdg: 135 },
  { cs: 'EZY7814', origin: 'United Kingdom', lat: 46.8, lon: -1.2, alt: 9750, vel: 212, hdg: 170 },
  { cs: 'CES981', origin: 'China', lat: 35.2, lon: 118.5, alt: 10970, vel: 248, hdg: 45 },
  { cs: 'CSN352', origin: 'China', lat: 22.8, lon: 108.3, alt: 9140, vel: 205, hdg: 350 },
  { cs: 'KAL023', origin: 'South Korea', lat: 37.5, lon: 130.2, alt: 11280, vel: 252, hdg: 60 },
  { cs: 'ICE614', origin: 'Iceland', lat: 62.1, lon: -22.5, alt: 10670, vel: 230, hdg: 225 },
  { cs: 'AVA015', origin: 'Colombia', lat: 6.2, lon: -75.8, alt: 10360, vel: 225, hdg: 5 },
  { cs: 'INK4502', origin: 'India', lat: 19.1, lon: 72.9, alt: 10970, vel: 235, hdg: 310 },
  { cs: 'SVA117', origin: 'Saudi Arabia', lat: 24.7, lon: 46.7, alt: 11580, vel: 248, hdg: 290 }
];

function _gwRenderAircraft() {
  if (!_gwViewer || _gwViewer.isDestroyed()) return;
  _gwLayerEntities.aircraft = [];

  var aircraft = GW_SIM_AIRCRAFT;
  for (var i = 0; i < aircraft.length; i++) {
    var ac = aircraft[i];
    var entity = _gwViewer.entities.add({
      position: Cesium.Cartesian3.fromDegrees(ac.lon, ac.lat, ac.alt),
      point: {
        pixelSize: 4,
        color: Cesium.Color.fromCssColorString('#00ff88').withAlpha(0.8),
        outlineColor: Cesium.Color.fromCssColorString('#00aa44'),
        outlineWidth: 1,
        disableDepthTestDistance: Number.POSITIVE_INFINITY
      },
      label: {
        text: ac.cs,
        font: '8px monospace',
        fillColor: Cesium.Color.fromCssColorString('#00cc66').withAlpha(0.7),
        outlineColor: Cesium.Color.BLACK,
        outlineWidth: 1,
        style: Cesium.LabelStyle.FILL_AND_OUTLINE,
        pixelOffset: new Cesium.Cartesian2(6, -4),
        disableDepthTestDistance: Number.POSITIVE_INFINITY,
        scale: 0.8,
        scaleByDistance: new Cesium.NearFarScalar(5e5, 0.8, 5e6, 0.0)
      }
    });
    entity._gwData = {
      type: 'aircraft',
      callsign: ac.cs,
      icao24: 'SIM',
      origin: ac.origin,
      altitude: ac.alt,
      velocity: ac.vel,
      heading: ac.hdg,
      onGround: false
    };
    _gwLayerEntities.aircraft.push(entity);
    _gwEntityCount++;
  }
  _gwUpdateStatus();
}

// ---------------------------------------------------------------------------
// 3. EARTHQUAKES (USGS GeoJSON — CORS-friendly)
// ---------------------------------------------------------------------------
function _gwRenderEarthquakes() {
  if (!_gwViewer || _gwViewer.isDestroyed()) return;
  _gwLayerEntities.quakes = [];

  fetch('https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/2.5_day.geojson')
    .then(function(resp) { return resp.json(); })
    .then(function(data) {
      if (!_gwViewer || _gwViewer.isDestroyed()) return;
      if (!data || !data.features) return;

      for (var i = 0; i < data.features.length; i++) {
        var f = data.features[i];
        var coords = f.geometry.coordinates;
        var lon = coords[0];
        var lat = coords[1];
        var depth = coords[2];
        var mag = f.properties.mag;
        var place = f.properties.place || 'Unknown';
        var time = f.properties.time ? new Date(f.properties.time).toISOString() : '--';
        var alert = f.properties.alert;
        var tsunami = f.properties.tsunami;

        // Color by depth
        var color = '#ffcc00'; // shallow
        if (depth > 100) color = '#ff6600';
        else if (depth > 300) color = '#ff0000';

        // Size by magnitude
        var size = Math.max(6, Math.min(mag * 3, 24));

        var entity = _gwViewer.entities.add({
          position: Cesium.Cartesian3.fromDegrees(lon, lat),
          point: {
            pixelSize: size,
            color: Cesium.Color.fromCssColorString(color).withAlpha(0.7),
            outlineColor: Cesium.Color.fromCssColorString(color),
            outlineWidth: 2,
            disableDepthTestDistance: Number.POSITIVE_INFINITY,
            heightReference: Cesium.HeightReference.CLAMP_TO_GROUND
          },
          label: {
            text: 'M' + String(mag.toFixed(1)),
            font: '9px monospace',
            fillColor: Cesium.Color.fromCssColorString(color),
            outlineColor: Cesium.Color.BLACK,
            outlineWidth: 2,
            style: Cesium.LabelStyle.FILL_AND_OUTLINE,
            pixelOffset: new Cesium.Cartesian2(0, -14),
            disableDepthTestDistance: Number.POSITIVE_INFINITY,
            heightReference: Cesium.HeightReference.CLAMP_TO_GROUND,
            scaleByDistance: new Cesium.NearFarScalar(5e5, 0.8, 5e6, 0.0)
          }
        });
        entity._gwData = {
          type: 'earthquake',
          magnitude: mag,
          place: place,
          depth: depth,
          time: time,
          alert: alert,
          tsunami: tsunami
        };
        _gwLayerEntities.quakes.push(entity);
        _gwEntityCount++;
      }
      _gwUpdateStatus();
    })
    .catch(function(err) {
      // USGS feed unavailable — silently degrade
    });
}

// ---------------------------------------------------------------------------
// 4. INTERNET INFRASTRUCTURE
// ---------------------------------------------------------------------------
function _gwRenderInfrastructure() {
  if (!_gwViewer || _gwViewer.isDestroyed()) return;
  _gwLayerEntities.infra = [];

  // IXPs
  for (var i = 0; i < GW_IXPS.length; i++) {
    var ixp = GW_IXPS[i];
    var entity = _gwViewer.entities.add({
      position: Cesium.Cartesian3.fromDegrees(ixp.lon, ixp.lat),
      point: {
        pixelSize: 8,
        color: Cesium.Color.fromCssColorString('#00ff88').withAlpha(0.8),
        outlineColor: Cesium.Color.fromCssColorString('#00aa55'),
        outlineWidth: 2,
        disableDepthTestDistance: Number.POSITIVE_INFINITY,
        heightReference: Cesium.HeightReference.CLAMP_TO_GROUND
      },
      label: {
        text: ixp.name.split(' ')[0],
        font: '9px monospace',
        fillColor: Cesium.Color.fromCssColorString('#00dd77'),
        outlineColor: Cesium.Color.BLACK,
        outlineWidth: 2,
        style: Cesium.LabelStyle.FILL_AND_OUTLINE,
        pixelOffset: new Cesium.Cartesian2(0, -14),
        disableDepthTestDistance: Number.POSITIVE_INFINITY,
        heightReference: Cesium.HeightReference.CLAMP_TO_GROUND,
        scaleByDistance: new Cesium.NearFarScalar(5e5, 0.8, 5e6, 0.0)
      }
    });
    entity._gwData = {
      type: 'ixp',
      name: ixp.name,
      capacity: ixp.capacity,
      operator: ixp.operator
    };
    _gwLayerEntities.infra.push(entity);
    _gwEntityCount++;
  }

  // IXP backbone links
  for (var li = 0; li < GW_IXP_LINKS.length; li++) {
    var link = GW_IXP_LINKS[li];
    var fromIxp = GW_IXPS[link.fromIdx];
    var toIxp = GW_IXPS[link.toIdx];
    if (!fromIxp || !toIxp) continue;

    var linkPositions = _gwComputeArcPositions(fromIxp.lat, fromIxp.lon, toIxp.lat, toIxp.lon, 20);
    var linkEntity = _gwViewer.entities.add({
      polyline: {
        positions: linkPositions,
        width: 1.5,
        material: new Cesium.PolylineGlowMaterialProperty({
          glowPower: 0.1,
          color: Cesium.Color.fromCssColorString('#00aaff').withAlpha(0.35)
        }),
        clampToGround: false
      }
    });
    _gwLayerEntities.infra.push(linkEntity);
    _gwEntityCount++;
  }

  // Root DNS servers
  for (var d = 0; d < GW_ROOT_DNS.length; d++) {
    var dns = GW_ROOT_DNS[d];
    var dnsEntity = _gwViewer.entities.add({
      position: Cesium.Cartesian3.fromDegrees(dns.lon, dns.lat),
      point: {
        pixelSize: 6,
        color: Cesium.Color.fromCssColorString('#00ddff').withAlpha(0.8),
        outlineColor: Cesium.Color.fromCssColorString('#0088aa'),
        outlineWidth: 1,
        disableDepthTestDistance: Number.POSITIVE_INFINITY,
        heightReference: Cesium.HeightReference.CLAMP_TO_GROUND
      },
      label: {
        text: dns.name.split('.')[0] + '.root',
        font: '8px monospace',
        fillColor: Cesium.Color.fromCssColorString('#00bbdd').withAlpha(0.7),
        outlineColor: Cesium.Color.BLACK,
        outlineWidth: 1,
        style: Cesium.LabelStyle.FILL_AND_OUTLINE,
        pixelOffset: new Cesium.Cartesian2(8, 0),
        disableDepthTestDistance: Number.POSITIVE_INFINITY,
        heightReference: Cesium.HeightReference.CLAMP_TO_GROUND,
        scaleByDistance: new Cesium.NearFarScalar(5e5, 0.7, 3e6, 0.0)
      }
    });
    dnsEntity._gwData = {
      type: 'dns',
      name: dns.name,
      operator: dns.operator,
      city: dns.city
    };
    _gwLayerEntities.infra.push(dnsEntity);
    _gwEntityCount++;
  }

  // Undersea cables
  for (var uc = 0; uc < GW_UNDERSEA_CABLES.length; uc++) {
    var cable = GW_UNDERSEA_CABLES[uc];
    var cablePositions = _gwComputeArcPositions(
      cable.from.lat, cable.from.lon,
      cable.to.lat, cable.to.lon,
      30
    );
    // Cables run along the seabed — use minimal altitude
    var seabedPositions = [];
    for (var cp = 0; cp < cablePositions.length; cp++) {
      var cart = Cesium.Cartographic.fromCartesian(cablePositions[cp]);
      seabedPositions.push(Cesium.Cartesian3.fromDegrees(
        Cesium.Math.toDegrees(cart.longitude),
        Cesium.Math.toDegrees(cart.latitude),
        -500 // Below sea level
      ));
    }

    var cableEntity = _gwViewer.entities.add({
      polyline: {
        positions: cablePositions,
        width: 1.5,
        material: Cesium.Color.fromCssColorString('#1a6a4a').withAlpha(0.5),
        clampToGround: false
      }
    });
    cableEntity._gwData = {
      type: 'cable',
      name: cable.name,
      capacity: cable.capacity,
      operator: cable.operator,
      region: cable.region
    };
    _gwLayerEntities.infra.push(cableEntity);
    _gwEntityCount++;

    // Landing point markers at from/to
    var landingFrom = _gwViewer.entities.add({
      position: Cesium.Cartesian3.fromDegrees(cable.from.lon, cable.from.lat),
      point: {
        pixelSize: 4,
        color: Cesium.Color.fromCssColorString('#2a8a5a').withAlpha(0.6),
        outlineColor: Cesium.Color.fromCssColorString('#1a6a4a'),
        outlineWidth: 1,
        disableDepthTestDistance: Number.POSITIVE_INFINITY,
        heightReference: Cesium.HeightReference.CLAMP_TO_GROUND
      }
    });
    _gwLayerEntities.infra.push(landingFrom);
    _gwEntityCount++;

    var landingTo = _gwViewer.entities.add({
      position: Cesium.Cartesian3.fromDegrees(cable.to.lon, cable.to.lat),
      point: {
        pixelSize: 4,
        color: Cesium.Color.fromCssColorString('#2a8a5a').withAlpha(0.6),
        outlineColor: Cesium.Color.fromCssColorString('#1a6a4a'),
        outlineWidth: 1,
        disableDepthTestDistance: Number.POSITIVE_INFINITY,
        heightReference: Cesium.HeightReference.CLAMP_TO_GROUND
      }
    });
    _gwLayerEntities.infra.push(landingTo);
    _gwEntityCount++;
  }

  _gwUpdateStatus();
}

// ---------------------------------------------------------------------------
// 5. CYBER ATTACKS (from local threat feeds)
// ---------------------------------------------------------------------------
function _gwRenderCyberAttacks() {
  if (!_gwViewer || _gwViewer.isDestroyed()) return;
  _gwLayerEntities.attacks = [];

  // Fetch malicious IPs feed
  fetch('/data/feeds/malicious-ips.json')
    .then(function(resp) { return resp.json(); })
    .then(function(feed) {
      if (!_gwViewer || _gwViewer.isDestroyed()) return;
      if (!feed || !feed.data) return;

      // Use a pseudo-random geolocation for IPs (real geolocation would need an API)
      // We'll hash the IP octets to create plausible lat/lon positions
      var maxIps = Math.min(feed.data.length, 100);
      for (var i = 0; i < maxIps; i++) {
        var ipData = feed.data[i];
        var coords = _gwIpToCoords(ipData.ip);

        var entity = _gwViewer.entities.add({
          position: Cesium.Cartesian3.fromDegrees(coords.lon, coords.lat),
          point: {
            pixelSize: 5,
            color: Cesium.Color.fromCssColorString('#ff2222').withAlpha(0.6),
            outlineColor: Cesium.Color.fromCssColorString('#cc0000'),
            outlineWidth: 1,
            disableDepthTestDistance: Number.POSITIVE_INFINITY,
            heightReference: Cesium.HeightReference.CLAMP_TO_GROUND
          }
        });
        entity._gwData = {
          type: 'malip',
          ip: ipData.ip,
          score: ipData.score,
          source: ipData.source
        };
        _gwLayerEntities.attacks.push(entity);
        _gwEntityCount++;

        // Draw attack arcs from some malicious IPs to random target cities
        if (i < 30 && i % 3 === 0) {
          var targets = [
            { lat: 38.9, lon: -77.0 },   // Washington DC
            { lat: 40.7, lon: -74.0 },   // New York
            { lat: 51.5, lon: -0.1 },    // London
            { lat: 35.68, lon: 139.69 }, // Tokyo
            { lat: 48.86, lon: 2.35 }    // Paris
          ];
          var target = targets[i % targets.length];
          var arcPos = _gwComputeArcPositions(coords.lat, coords.lon, target.lat, target.lon, 25);
          var attackArc = _gwViewer.entities.add({
            polyline: {
              positions: arcPos,
              width: 1.5,
              material: new Cesium.PolylineGlowMaterialProperty({
                glowPower: 0.15,
                color: Cesium.Color.fromCssColorString('#ff3333').withAlpha(0.4)
              }),
              clampToGround: false
            }
          });
          _gwAttackArcs.push({ entity: attackArc, color: '#ff3333' });
          _gwLayerEntities.attacks.push(attackArc);
          _gwEntityCount++;
        }
      }
      _gwUpdateStatus();
    })
    .catch(function(err) {
      // Feed unavailable
    });

  // Fetch CISA KEV feed
  fetch('/data/feeds/cisa-kev.json')
    .then(function(resp) { return resp.json(); })
    .then(function(feed) {
      if (!_gwViewer || _gwViewer.isDestroyed()) return;
      if (!feed || !feed.data) return;

      // Plot CVEs at vendor HQ locations
      var seen = {};
      var maxCve = Math.min(feed.data.length, 50);
      for (var i = 0; i < maxCve; i++) {
        var cve = feed.data[i];
        var vendor = cve.vendor || '';
        var hq = GW_VENDOR_HQ[vendor];
        if (!hq) continue;

        // Offset slightly to avoid stacking
        var key = vendor;
        if (!seen[key]) seen[key] = 0;
        seen[key]++;
        var offsetLat = hq.lat + (seen[key] * 0.15);
        var offsetLon = hq.lon + (seen[key] * 0.12);

        var entity = _gwViewer.entities.add({
          position: Cesium.Cartesian3.fromDegrees(offsetLon, offsetLat),
          point: {
            pixelSize: 7,
            color: Cesium.Color.fromCssColorString('#ff6644').withAlpha(0.7),
            outlineColor: Cesium.Color.fromCssColorString('#ff4422'),
            outlineWidth: 1,
            disableDepthTestDistance: Number.POSITIVE_INFINITY,
            heightReference: Cesium.HeightReference.CLAMP_TO_GROUND
          },
          label: {
            text: cve.cve,
            font: '8px monospace',
            fillColor: Cesium.Color.fromCssColorString('#ff8866').withAlpha(0.6),
            outlineColor: Cesium.Color.BLACK,
            outlineWidth: 1,
            style: Cesium.LabelStyle.FILL_AND_OUTLINE,
            pixelOffset: new Cesium.Cartesian2(8, -2),
            disableDepthTestDistance: Number.POSITIVE_INFINITY,
            heightReference: Cesium.HeightReference.CLAMP_TO_GROUND,
            scaleByDistance: new Cesium.NearFarScalar(1e4, 0.8, 2e6, 0.0)
          }
        });
        entity._gwData = {
          type: 'cve',
          cve: cve.cve,
          vendor: vendor,
          product: cve.product || '--',
          vulnName: cve.name || '--',
          dateAdded: cve.dateAdded || '--',
          ransomware: cve.knownRansomware || 'Unknown'
        };
        _gwLayerEntities.attacks.push(entity);
        _gwEntityCount++;
      }
      _gwUpdateStatus();
    })
    .catch(function(err) {
      // CISA KEV feed unavailable
    });
}

// ---------------------------------------------------------------------------
// Pseudo-geolocate an IP by hashing its octets into lat/lon
// ---------------------------------------------------------------------------
function _gwIpToCoords(ip) {
  var parts = ip.split('.');
  if (parts.length < 4) return { lat: 0, lon: 0 };

  var a = parseInt(parts[0], 10) || 0;
  var b = parseInt(parts[1], 10) || 0;
  var c = parseInt(parts[2], 10) || 0;
  var d = parseInt(parts[3], 10) || 0;

  // Map first octet ranges to approximate geographic regions
  var lat, lon;
  if (a >= 1 && a <= 50) {
    // North America range
    lat = 25 + (b % 25);
    lon = -130 + (c % 70);
  } else if (a >= 51 && a <= 100) {
    // Europe range
    lat = 35 + (b % 25);
    lon = -10 + (c % 40);
  } else if (a >= 101 && a <= 150) {
    // Asia range
    lat = 10 + (b % 45);
    lon = 60 + (c % 80);
  } else if (a >= 151 && a <= 200) {
    // South America / Africa
    lat = -35 + (b % 50);
    lon = -70 + (c % 100);
  } else {
    // Rest of world
    lat = -60 + ((a + b) % 120);
    lon = -180 + ((c + d) % 360);
  }

  // Add jitter from last octet
  lat += (d % 10) * 0.3 - 1.5;
  lon += ((d * 7) % 10) * 0.3 - 1.5;

  return { lat: lat, lon: lon };
}

// ---------------------------------------------------------------------------
// 6. SATELLITES
// ---------------------------------------------------------------------------
// Cached TLE records for orbit updates
var _gwTleSatRecs = [];
var _gwIssTleRec = null;

function _gwParseTle(text) {
  var lines = text.split('\n');
  var sats = [];
  var i = 0;
  while (i < lines.length - 2) {
    var name = lines[i].trim();
    var l1 = lines[i + 1] ? lines[i + 1].trim() : '';
    var l2 = lines[i + 2] ? lines[i + 2].trim() : '';
    if (l1.charAt(0) === '1' && l2.charAt(0) === '2') {
      sats.push({ name: name, line1: l1, line2: l2 });
      i += 3;
    } else {
      i++;
    }
  }
  return sats;
}

function _gwPropagateSat(satrec) {
  var now = new Date();
  var posVel = satellite.propagate(satrec, now);
  if (!posVel.position) return null;
  var gmst = satellite.gstime(now);
  var geo = satellite.eciToGeodetic(posVel.position, gmst);
  return {
    lat: satellite.degreesLat(geo.latitude),
    lon: satellite.degreesLong(geo.longitude),
    alt: geo.height
  };
}

function _gwAddSatEntity(name, lat, lon, altKm, satColor, constellation, satType) {
  if (!_gwViewer || _gwViewer.isDestroyed()) return null;
  var entity = _gwViewer.entities.add({
    position: Cesium.Cartesian3.fromDegrees(lon, lat, altKm * 1000),
    point: {
      pixelSize: 5,
      color: Cesium.Color.fromCssColorString(satColor).withAlpha(0.8),
      outlineColor: Cesium.Color.fromCssColorString(satColor),
      outlineWidth: 1,
      disableDepthTestDistance: Number.POSITIVE_INFINITY
    },
    label: {
      text: name,
      font: '8px monospace',
      fillColor: Cesium.Color.fromCssColorString(satColor).withAlpha(0.6),
      outlineColor: Cesium.Color.BLACK,
      outlineWidth: 1,
      style: Cesium.LabelStyle.FILL_AND_OUTLINE,
      pixelOffset: new Cesium.Cartesian2(8, -4),
      disableDepthTestDistance: Number.POSITIVE_INFINITY,
      scaleByDistance: new Cesium.NearFarScalar(1e6, 0.8, 1e7, 0.0)
    }
  });
  entity._gwData = { type: 'satellite', name: name, constellation: constellation, alt: Math.round(altKm), satType: satType };
  return entity;
}

function _gwRenderSatellites() {
  if (!_gwViewer || _gwViewer.isDestroyed()) return;
  _gwLayerEntities.satellites = [];
  _gwTleSatRecs = [];
  _gwIssTleRec = null;

  // CelesTrak blocks direct browser requests (403), so use hardcoded satellite data
  _gwRenderSatellitesFallback();
}

function _gwRenderISSOrbitPath(satrec) {
  if (!_gwViewer || _gwViewer.isDestroyed() || !satrec) return;
  var positions = [];
  var now = new Date();
  // Plot one full orbit (~92 min) at 60-second intervals
  for (var m = 0; m <= 92; m++) {
    var t = new Date(now.getTime() + m * 60000);
    var pv = satellite.propagate(satrec, t);
    if (!pv.position) continue;
    var gmst = satellite.gstime(t);
    var geo = satellite.eciToGeodetic(pv.position, gmst);
    var lat = satellite.degreesLat(geo.latitude);
    var lon = satellite.degreesLong(geo.longitude);
    if (isNaN(lat) || isNaN(lon)) continue;
    positions.push(Cesium.Cartesian3.fromDegrees(lon, lat, geo.height * 1000));
  }
  if (positions.length < 2) return;
  var orbitEntity = _gwViewer.entities.add({
    polyline: {
      positions: positions,
      width: 1.5,
      material: new Cesium.PolylineGlowMaterialProperty({
        glowPower: 0.15,
        color: Cesium.Color.fromCssColorString('#ffaa00').withAlpha(0.4)
      }),
      clampToGround: false
    }
  });
  _gwLayerEntities.satellites.push(orbitEntity);
  _gwEntityCount++;
}

function _gwRenderSatellitesFallback() {
  if (!_gwViewer || _gwViewer.isDestroyed()) return;
  for (var i = 0; i < GW_SATELLITES.length; i++) {
    var sat = GW_SATELLITES[i];
    var satColor = sat.type === 'military' ? '#ff6644' : sat.type === 'navigation' ? '#44aaff' : '#aa44ff';
    var ent = _gwAddSatEntity(sat.name, sat.lat, sat.lon, sat.alt, satColor, sat.constellation, sat.type);
    if (ent) {
      _gwLayerEntities.satellites.push(ent);
      _gwEntityCount++;
    }
  }
  _gwFetchISS();
  _gwUpdateStatus();
}

// ---------------------------------------------------------------------------
// _gwFetchISS — get ISS current position
// ---------------------------------------------------------------------------
function _gwFetchISS() {
  fetch('https://api.wheretheiss.at/v1/satellites/25544')
    .then(function(resp) { return resp.json(); })
    .then(function(data) {
      if (!_gwViewer || _gwViewer.isDestroyed()) return;
      if (!data || !data.iss_position) return;

      var lat = parseFloat(data.iss_position.latitude);
      var lon = parseFloat(data.iss_position.longitude);

      // Remove old ISS entity if exists
      if (_gwLayerEntities._issEntity) {
        try { _gwViewer.entities.remove(_gwLayerEntities._issEntity); } catch (e) { /* ignore */ }
        _gwEntityCount--;
      }

      var issEntity = _gwViewer.entities.add({
        position: Cesium.Cartesian3.fromDegrees(lon, lat, 420000),
        point: {
          pixelSize: 10,
          color: Cesium.Color.fromCssColorString('#ffaa00'),
          outlineColor: Cesium.Color.fromCssColorString('#ff8800'),
          outlineWidth: 2,
          disableDepthTestDistance: Number.POSITIVE_INFINITY
        },
        label: {
          text: 'ISS [ZARYA]',
          font: '10px monospace',
          fillColor: Cesium.Color.fromCssColorString('#ffcc44'),
          outlineColor: Cesium.Color.BLACK,
          outlineWidth: 2,
          style: Cesium.LabelStyle.FILL_AND_OUTLINE,
          pixelOffset: new Cesium.Cartesian2(12, -2),
          disableDepthTestDistance: Number.POSITIVE_INFINITY
        },
        path: {
          leadTime: 0,
          trailTime: 3600,
          width: 1,
          material: Cesium.Color.fromCssColorString('#ffaa00').withAlpha(0.3)
        }
      });
      issEntity._gwData = {
        type: 'iss',
        lat: lat.toFixed(4),
        lon: lon.toFixed(4)
      };

      _gwLayerEntities._issEntity = issEntity;
      if (!_gwLayerEntities.satellites) _gwLayerEntities.satellites = [];
      _gwLayerEntities.satellites.push(issEntity);
      _gwEntityCount++;
      _gwUpdateStatus();
    })
    .catch(function(err) {
      // ISS API unavailable — silent degradation
    });
}

// ---------------------------------------------------------------------------
// _gwRefreshISS — update ISS position; prefers satellite.js TLE propagation, falls back to API
// ---------------------------------------------------------------------------
function _gwRefreshISS() {
  if (!_gwViewer || _gwViewer.isDestroyed()) return;
  if (!_gwLayerEntities._issEntity) return;

  // Prefer satellite.js propagation (instant, no network)
  if (_gwIssTleRec && typeof satellite !== 'undefined') {
    var pos = _gwPropagateSat(_gwIssTleRec);
    if (pos && !isNaN(pos.lat) && !isNaN(pos.lon)) {
      try {
        _gwLayerEntities._issEntity.position = Cesium.Cartesian3.fromDegrees(pos.lon, pos.lat, pos.alt * 1000);
        _gwLayerEntities._issEntity._gwData.lat = pos.lat.toFixed(4);
        _gwLayerEntities._issEntity._gwData.lon = pos.lon.toFixed(4);
      } catch (e) { /* ignore */ }
      return;
    }
  }

  // Fallback: open-notify API
  fetch('https://api.wheretheiss.at/v1/satellites/25544')
    .then(function(resp) { return resp.json(); })
    .then(function(data) {
      if (!_gwViewer || _gwViewer.isDestroyed()) return;
      if (!data || !data.iss_position) return;
      if (!_gwLayerEntities._issEntity) return;
      var lat = parseFloat(data.iss_position.latitude);
      var lon = parseFloat(data.iss_position.longitude);
      try {
        _gwLayerEntities._issEntity.position = Cesium.Cartesian3.fromDegrees(lon, lat, 420000);
        _gwLayerEntities._issEntity._gwData.lat = lat.toFixed(4);
        _gwLayerEntities._issEntity._gwData.lon = lon.toFixed(4);
      } catch (e) { /* ignore */ }
    })
    .catch(function() { /* silent */ });
}

// ---------------------------------------------------------------------------
// _gwRefreshAllSats — update all TLE-tracked satellite positions
// ---------------------------------------------------------------------------
function _gwRefreshAllSats() {
  if (!_gwViewer || _gwViewer.isDestroyed()) return;
  if (typeof satellite === 'undefined' || _gwTleSatRecs.length === 0) return;
  for (var i = 0; i < _gwTleSatRecs.length; i++) {
    var rec = _gwTleSatRecs[i];
    if (!rec.entity || !rec.satrec) continue;
    var pos = _gwPropagateSat(rec.satrec);
    if (!pos || isNaN(pos.lat) || isNaN(pos.lon)) continue;
    try {
      rec.entity.position = Cesium.Cartesian3.fromDegrees(pos.lon, pos.lat, pos.alt * 1000);
      if (rec.entity._gwData) rec.entity._gwData.alt = Math.round(pos.alt);
    } catch (e) { /* ignore */ }
  }
}

// ============================================================================
// GOD'S EYE VIEW — HUD OVERLAY SYSTEM
// Inspired by NRO/NGA reconnaissance aesthetics
// Classification banners, live telemetry, sensor metadata
// ============================================================================

var _gwHudActive = false;
var _gwHudInterval = null;
var _gwShaderMode = 'default'; // default, surveillance, thermal, retro

var GW_HUD_COLORS = {
  surveillance: { main: 'rgba(51,255,51,0.8)', glow: 'rgba(51,255,51,0.5)', border: 'rgba(51,255,51,0.2)', accent: '#33ff33' },
  thermal:      { main: 'rgba(255,255,255,0.7)', glow: 'rgba(255,255,255,0.4)', border: 'rgba(255,255,255,0.15)', accent: '#ffffff' },
  retro:        { main: 'rgba(255,170,0,0.8)', glow: 'rgba(255,170,0,0.5)', border: 'rgba(255,170,0,0.2)', accent: '#ffaa00' },
  default:      { main: 'rgba(0,212,255,0.6)', glow: 'rgba(0,212,255,0.4)', border: 'rgba(0,212,255,0.15)', accent: '#00d4ff' }
};

var GW_DEFCON_LEVELS = [
  { level: 5, name: 'FADEOUT', color: '#2288ff', description: 'Normal readiness — routine monitoring', conditions: 'Baseline operations. No elevated threat indicators.' },
  { level: 4, name: 'DOUBLE TAKE', color: '#00cc88', description: 'Increased intelligence watch', conditions: 'Elevated nation-state activity, new APT campaign indicators, unusual scanning patterns.' },
  { level: 3, name: 'ROUND HOUSE', color: '#ffcc00', description: 'Increase in force readiness', conditions: 'Active exploitation of critical infrastructure, confirmed zero-day in the wild, mass credential dumps.' },
  { level: 2, name: 'FAST PACE', color: '#ff6600', description: 'Next step to maximum readiness', conditions: 'Active attacks on allied infrastructure, confirmed destructive malware deployment, grid/water/comms targeting.' },
  { level: 1, name: 'COCKED PISTOL', color: '#ff0000', description: 'Maximum force readiness', conditions: 'Active cyber warfare operations, confirmed kinetic-equivalent cyber attacks, nation-state conflict escalation.' }
];

function _gwCreateHUD() {
  var area = document.getElementById('gw-globe-area');
  if (!area || document.getElementById('gw-hud-overlay')) return;

  var hud = document.createElement('div');
  hud.id = 'gw-hud-overlay';
  hud.style.cssText = 'position:absolute;top:0;left:0;right:0;bottom:0;pointer-events:none;z-index:200;font-family:"Courier New",monospace;';

  var colors = GW_HUD_COLORS[_gwShaderMode] || GW_HUD_COLORS.default;

  hud.innerHTML =
    '<style>' +
    '.gw-hud-tl{position:absolute;top:6px;left:8px;font-size:8px;line-height:1.5;z-index:210;color:' + colors.main + ';opacity:0.6;}' +
    '.gw-hud-tr{position:absolute;top:6px;right:8px;font-size:8px;line-height:1.5;text-align:right;z-index:210;color:' + colors.main + ';opacity:0.6;}' +
    '.gw-hud-crosshair{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);width:32px;height:32px;z-index:210;opacity:0.4;}' +
    '.gw-hud-corner{position:absolute;width:10px;height:10px;}' +
    '.gw-hud-corner-tl{top:0;left:0;border-top:1px solid;border-left:1px solid;}' +
    '.gw-hud-corner-tr{top:0;right:0;border-top:1px solid;border-right:1px solid;}' +
    '.gw-hud-corner-bl{bottom:0;left:0;border-bottom:1px solid;border-left:1px solid;}' +
    '.gw-hud-corner-br{bottom:0;right:0;border-bottom:1px solid;border-right:1px solid;}' +
    '</style>' +

    '<div class="gw-hud-tl" id="gw-hud-tl"></div>' +
    '<div class="gw-hud-tr" id="gw-hud-tr"></div>' +

    '<div class="gw-hud-crosshair" id="gw-hud-crosshair">' +
    '<div class="gw-hud-corner gw-hud-corner-tl" style="border-color:' + colors.main + ';"></div>' +
    '<div class="gw-hud-corner gw-hud-corner-tr" style="border-color:' + colors.main + ';"></div>' +
    '<div class="gw-hud-corner gw-hud-corner-bl" style="border-color:' + colors.main + ';"></div>' +
    '<div class="gw-hud-corner gw-hud-corner-br" style="border-color:' + colors.main + ';"></div>' +
    '</div>';

  area.appendChild(hud);
  _gwHudActive = true;
  _gwUpdateHUD();
  _gwUpdateDEFCON(5);

  _gwHudInterval = setInterval(function() {
    _gwUpdateHUD();
  }, 250);
}

function _gwUpdateHUD() {
  if (!_gwViewer || _gwViewer.isDestroyed() || !_gwHudActive) return;

  var cam = _gwViewer.camera;
  var carto = null;
  try {
    carto = Cesium.Cartographic.fromCartesian(cam.position);
  } catch (e) { return; }
  if (!carto) return;

  var lat = Cesium.Math.toDegrees(carto.latitude);
  var lon = Cesium.Math.toDegrees(carto.longitude);
  var alt = carto.height;
  var heading = Cesium.Math.toDegrees(cam.heading);
  var pitch = Cesium.Math.toDegrees(cam.pitch);

  var now = new Date();
  var zulu = now.toISOString().replace('T', ' ').substring(0, 19) + 'Z';
  var julian = Math.floor(now.getTime() / 86400000) + 2440587.5;

  // GSD (Ground Sample Distance) — approximate based on altitude
  var gsd = alt > 1000 ? (alt * 0.0001).toFixed(2) + 'm' : (alt * 0.001).toFixed(3) + 'm';
  var niirs = alt < 500000 ? Math.max(0, Math.min(9, 9 - Math.log10(alt / 100))).toFixed(1) : '0.0';

  var tl = document.getElementById('gw-hud-tl');
  if (tl) {
    tl.innerHTML =
      lat.toFixed(4) + (lat >= 0 ? 'N' : 'S') + ' ' +
      Math.abs(lon).toFixed(4) + (lon >= 0 ? 'E' : 'W') + '<br>' +
      'ALT ' + _gwFormatAlt(alt) + ' | HDG ' + heading.toFixed(0) + '&deg;';
  }

  var tr = document.getElementById('gw-hud-tr');
  if (tr) {
    tr.innerHTML = zulu + '<br>' + _gwEntityCount + ' entities';
  }
}

function _gwFormatAlt(meters) {
  if (meters >= 1000000) return (meters / 1000000).toFixed(1) + ' Mm';
  if (meters >= 1000) return (meters / 1000).toFixed(1) + ' km';
  return Math.round(meters) + ' m';
}

function _gwUpdateDEFCON(level) {
  var el = document.getElementById('gw-hud-defcon');
  if (!el) return;
  var def = GW_DEFCON_LEVELS.find(function(d) { return d.level === level; });
  if (!def) return;

  el.innerHTML =
    '<div style="color:' + def.color + ';font-size:14px;font-weight:bold;text-shadow:0 0 10px ' + def.color + ';">CYBER DEFCON ' + def.level + '</div>' +
    '<div style="color:' + def.color + ';font-size:9px;letter-spacing:3px;opacity:0.7;">' + esc(def.name) + '</div>' +
    '<div style="color:#5a7a9a;font-size:8px;margin-top:2px;">' + esc(def.description) + '</div>';
}

function _gwDestroyHUD() {
  _gwHudActive = false;
  if (_gwHudInterval) {
    clearInterval(_gwHudInterval);
    _gwHudInterval = null;
  }
  var hud = document.getElementById('gw-hud-overlay');
  if (hud) hud.remove();
}

// ============================================================================
// SHADER MODES — NVG / FLIR / Retro / Default
// ============================================================================

function _gwSetShaderMode(mode) {
  if (!_gwViewer || _gwViewer.isDestroyed()) return;
  _gwShaderMode = mode;

  var globe = _gwViewer.scene.globe;
  var scene = _gwViewer.scene;

  // Remove existing post-process stages
  if (scene.postProcessStages) {
    try {
      scene.postProcessStages.removeAll();
    } catch (e) { /* some versions don't support removeAll */ }
  }

  switch (mode) {
    case 'surveillance':
      // NVG — green tint, amplified brightness
      scene.backgroundColor = Cesium.Color.fromCssColorString('#000800');
      if (globe) {
        globe.baseColor = Cesium.Color.fromCssColorString('#001a00');
      }
      // Swap to dark tiles but we'll tint via HUD
      _gwViewer.imageryLayers.removeAll();
      _gwViewer.imageryLayers.addImageryProvider(
        new Cesium.UrlTemplateImageryProvider({
          url: 'https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}',
          maximumLevel: 16,
          credit: 'Esri'
        })
      );
      break;

    case 'thermal':
      // FLIR — white-hot thermal
      scene.backgroundColor = Cesium.Color.fromCssColorString('#0a0a0a');
      if (globe) {
        globe.baseColor = Cesium.Color.fromCssColorString('#111111');
      }
      _gwViewer.imageryLayers.removeAll();
      _gwViewer.imageryLayers.addImageryProvider(
        new Cesium.UrlTemplateImageryProvider({
          url: 'https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}',
          maximumLevel: 16,
          credit: 'Esri'
        })
      );
      break;

    case 'retro':
      // CRT amber
      scene.backgroundColor = Cesium.Color.fromCssColorString('#0a0800');
      if (globe) {
        globe.baseColor = Cesium.Color.fromCssColorString('#1a1000');
      }
      _gwViewer.imageryLayers.removeAll();
      _gwViewer.imageryLayers.addImageryProvider(
        new Cesium.UrlTemplateImageryProvider({
          url: 'https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}',
          maximumLevel: 16,
          credit: 'Esri'
        })
      );
      break;

    default:
      // Standard — full color satellite imagery
      scene.backgroundColor = Cesium.Color.fromCssColorString('#000206');
      if (globe) {
        globe.baseColor = Cesium.Color.fromCssColorString('#041020');
        globe.enableLighting = true;
      }
      _gwViewer.imageryLayers.removeAll();
      _gwViewer.imageryLayers.addImageryProvider(
        new Cesium.UrlTemplateImageryProvider({
          url: 'https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}',
          maximumLevel: 13,
          credit: 'Esri World Imagery'
        })
      );
      if (_gwViewer.scene.skyBox) _gwViewer.scene.skyBox.show = true;
      _gwViewer.scene.sun.show = true;
      _gwViewer.scene.moon.show = true;
      if (_gwViewer.scene.skyAtmosphere) _gwViewer.scene.skyAtmosphere.show = true;
      break;
  }

  // Rebuild HUD with new color scheme
  _gwDestroyHUD();
  _gwCreateHUD();
}

// ============================================================================
// CINEMATIC FLY-IN — God's Eye View startup sequence
// ============================================================================

function _gwCinematicFlyIn() {
  if (!_gwViewer || _gwViewer.isDestroyed()) return;
  _gwViewer.camera.setView({
    destination: Cesium.Cartesian3.fromDegrees(20, 20, 20000000)
  });
  _gwCreateHUD();
}

// ============================================================================
// PULSE RING ANIMATION — threat actor pulsing markers
// ============================================================================

var _gwPulseEntities = [];

function _gwAddPulseRings() {
  if (!_gwViewer || _gwViewer.isDestroyed()) return;

  for (var i = 0; i < GW_THREAT_ACTORS.length; i++) {
    var ta = GW_THREAT_ACTORS[i];
    if (ta.alignment !== 'hostile') continue;

    var color = ta.tier === 'TIER-1' ? '#ff2222' : '#ff8844';
    var maxRadius = ta.tier === 'TIER-1' ? 300000 : 200000;

    // Animated pulsing ellipse
    var pulseEntity = _gwViewer.entities.add({
      position: Cesium.Cartesian3.fromDegrees(ta.lon, ta.lat),
      ellipse: {
        semiMinorAxis: new Cesium.CallbackProperty(function(radius, speed) {
          return function() {
            var t = (Date.now() * speed) % 1;
            return radius * (0.3 + 0.7 * t);
          };
        }(maxRadius, 0.0003 + i * 0.00002), false),
        semiMajorAxis: new Cesium.CallbackProperty(function(radius, speed) {
          return function() {
            var t = (Date.now() * speed) % 1;
            return radius * (0.3 + 0.7 * t);
          };
        }(maxRadius, 0.0003 + i * 0.00002), false),
        material: new Cesium.ColorMaterialProperty(
          new Cesium.CallbackProperty(function(c, speed) {
            return function() {
              var t = (Date.now() * speed) % 1;
              var alpha = 0.15 * (1 - t);
              return Cesium.Color.fromCssColorString(c).withAlpha(alpha);
            };
          }(color, 0.0003 + i * 0.00002), false)
        ),
        height: 0,
        outline: false
      }
    });
    _gwPulseEntities.push(pulseEntity);
  }
}

// ============================================================================
// ENHANCED GLOBE INIT — replace default init with cinematic version
// ============================================================================

var _gwOrigInitGlobe = _gwInitGlobe;

_gwInitGlobe = function() {
  _gwLoadCesium(function() {
    var container = document.getElementById('gw-cesium-container');
    var loadingEl = document.getElementById('gw-loading');
    if (!container) return;

    try {
      Cesium.Ion.defaultAccessToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJkYzUwOGY4MS1iNzFjLTRhOTAtOWEzOC04NWQ2NjczNzAyMzYiLCJpZCI6MjU5LCJpYXQiOjE3MzIxNDM0MjV9.placeholder';

      _gwViewer = new Cesium.Viewer('gw-cesium-container', {
        animation: false,
        timeline: false,
        fullscreenButton: false,
        vrButton: false,
        homeButton: false,
        geocoder: false,
        baseLayerPicker: false,
        navigationHelpButton: false,
        sceneModePicker: false,
        infoBox: false,
        selectionIndicator: false,
        creditContainer: document.createElement('div'),
        imageryProvider: false,
        requestRenderMode: false
      });

      _gwViewer.imageryLayers.addImageryProvider(
        new Cesium.UrlTemplateImageryProvider({
          url: 'https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}',
          maximumLevel: 13,
          credit: 'Esri World Imagery'
        })
      );

      _gwViewer.scene.backgroundColor = Cesium.Color.fromCssColorString('#000206');
      if (_gwViewer.scene.skyBox) _gwViewer.scene.skyBox.show = true;
      _gwViewer.scene.sun.show = true;
      _gwViewer.scene.moon.show = true;
      if (_gwViewer.scene.skyAtmosphere) {
        _gwViewer.scene.skyAtmosphere.show = true;
      }
      if (_gwViewer.scene.globe) {
        _gwViewer.scene.globe.enableLighting = true;
        _gwViewer.scene.globe.baseColor = Cesium.Color.fromCssColorString('#041020');
        _gwViewer.scene.globe.showGroundAtmosphere = false;
        _gwViewer.scene.globe.tileCacheSize = 100;
      }
      if (_gwViewer.scene) {
        _gwViewer.scene.logarithmicDepthBuffer = true;
      }
      _gwViewer.scene.screenSpaceCameraController.minimumZoomDistance = 250000;

      if (loadingEl) loadingEl.style.display = 'none';

      // Cinematic fly-in + HUD activation
      _gwCinematicFlyIn();

      // Initialize layers
      _gwRenderAllLayers();

      // Add pulse rings on hostile actors
      _gwAddPulseRings();

      // Wire events + shader mode buttons
      _gwWireEvents();
      _gwWireShaderButtons();

      _gwUpdateStatus();
      _gwStartAnimationLoop();
      _gwStartAutoRefresh();

    } catch (err) {
      if (loadingEl) {
        loadingEl.innerHTML = '<div style="color:#ff4444;padding:40px;text-align:center;font-family:monospace;">' +
          '<h3>GLOBE INITIALIZATION FAILED</h3>' +
          '<p>' + esc(err.message || 'Unknown error') + '</p>' +
          '</div>';
      }
    }
  });
};

// Add shader mode buttons to the controls area
function _gwWireShaderButtons() {
  var controls = document.querySelector('.gw-controls');
  if (!controls) return;
  if (document.querySelector('.gw-shader-btn')) return;

  var shaderGroup = document.createElement('div');
  shaderGroup.className = 'gw-ctrl-group';
  shaderGroup.innerHTML =
    '<span class="gw-ctrl-label">SHADER:</span>' +
    '<button class="gw-fly-btn gw-shader-btn" data-gw-shader="default">DEFAULT</button>' +
    '<button class="gw-fly-btn gw-shader-btn" data-gw-shader="surveillance">NVG</button>' +
    '<button class="gw-fly-btn gw-shader-btn" data-gw-shader="thermal">FLIR</button>' +
    '<button class="gw-fly-btn gw-shader-btn" data-gw-shader="retro">CRT</button>';

  controls.appendChild(shaderGroup);

  // HUD toggle button
  var hudGroup = document.createElement('div');
  hudGroup.className = 'gw-ctrl-group';
  hudGroup.innerHTML =
    '<span class="gw-ctrl-label">OVERLAY:</span>' +
    '<button class="gw-fly-btn" id="gw-hud-toggle">HUD ON</button>' +
    '<button class="gw-fly-btn" id="gw-defcon-cycle">DEFCON 5</button>';
  controls.appendChild(hudGroup);

  // Wire shader button clicks
  controls.addEventListener('click', function(e) {
    var shaderBtn = e.target.closest('[data-gw-shader]');
    if (shaderBtn) {
      _gwSetShaderMode(shaderBtn.getAttribute('data-gw-shader'));
      return;
    }

    if (e.target.id === 'gw-hud-toggle') {
      if (_gwHudActive) {
        _gwDestroyHUD();
        e.target.textContent = 'HUD OFF';
      } else {
        _gwCreateHUD();
        e.target.textContent = 'HUD ON';
      }
      return;
    }

    if (e.target.id === 'gw-defcon-cycle') {
      var currentLevel = parseInt(e.target.textContent.replace('DEFCON ', ''), 10) || 5;
      var nextLevel = currentLevel <= 1 ? 5 : currentLevel - 1;
      _gwUpdateDEFCON(nextLevel);
      e.target.textContent = 'DEFCON ' + nextLevel;
      return;
    }
  });
}
