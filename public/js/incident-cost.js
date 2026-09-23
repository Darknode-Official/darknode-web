// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Source-available for learning only. Redistribution prohibited. See LICENSE.

function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

function fmt$(n) {
  if (n >= 1e9) return '$' + (n / 1e9).toFixed(2) + 'B';
  if (n >= 1e6) return '$' + (n / 1e6).toFixed(2) + 'M';
  if (n >= 1e3) return '$' + (n / 1e3).toFixed(1) + 'K';
  return '$' + n.toFixed(0);
}

function fmtN(n) {
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(0) + 'K';
  return n.toString();
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECTOR DATA (IBM Cost of Data Breach 2024)
// ═══════════════════════════════════════════════════════════════════════════════
const SECTORS = [
  { id: 'healthcare',     name: 'Healthcare',             avgCost: 10930000, perRecord: 408, multiplier: 2.10 },
  { id: 'financial',      name: 'Financial Services',     avgCost: 5900000,  perRecord: 266, multiplier: 1.13 },
  { id: 'pharma',         name: 'Pharmaceuticals',        avgCost: 4820000,  perRecord: 247, multiplier: 0.93 },
  { id: 'energy',         name: 'Energy',                 avgCost: 4720000,  perRecord: 239, multiplier: 0.91 },
  { id: 'technology',     name: 'Technology',             avgCost: 4660000,  perRecord: 231, multiplier: 0.90 },
  { id: 'industrial',     name: 'Industrial / Mfg',       avgCost: 4430000,  perRecord: 225, multiplier: 0.85 },
  { id: 'services',       name: 'Professional Services',  avgCost: 4290000,  perRecord: 218, multiplier: 0.83 },
  { id: 'transportation', name: 'Transportation',         avgCost: 4180000,  perRecord: 212, multiplier: 0.80 },
  { id: 'communications', name: 'Communications',         avgCost: 3900000,  perRecord: 199, multiplier: 0.75 },
  { id: 'education',      name: 'Education',              avgCost: 3650000,  perRecord: 188, multiplier: 0.70 },
  { id: 'retail',         name: 'Retail',                 avgCost: 3480000,  perRecord: 182, multiplier: 0.67 },
  { id: 'entertainment',  name: 'Media / Entertainment',  avgCost: 3300000,  perRecord: 175, multiplier: 0.64 },
  { id: 'government',     name: 'Government / Public',    avgCost: 2600000,  perRecord: 155, multiplier: 0.50 },
  { id: 'hospitality',    name: 'Hospitality',            avgCost: 2200000,  perRecord: 144, multiplier: 0.42 },
];

const ATTACK_VECTORS = [
  { id: 'phishing',     name: 'Phishing',                costAdj: 1.08, avgDays: 261 },
  { id: 'stolen_creds', name: 'Stolen / Compromised Credentials', costAdj: 1.10, avgDays: 292 },
  { id: 'vuln_exploit', name: 'Vulnerability Exploit',   costAdj: 1.05, avgDays: 247 },
  { id: 'insider',      name: 'Malicious Insider',       costAdj: 1.18, avgDays: 306 },
  { id: 'misconfig',    name: 'Cloud Misconfiguration',  costAdj: 0.95, avgDays: 198 },
  { id: 'social_eng',   name: 'Social Engineering',      costAdj: 1.12, avgDays: 280 },
  { id: 'supply_chain', name: 'Supply Chain Compromise',  costAdj: 1.15, avgDays: 294 },
  { id: 'ransomware',   name: 'Ransomware',              costAdj: 1.20, avgDays: 237 },
  { id: 'bec',          name: 'Business Email Compromise', costAdj: 1.06, avgDays: 266 },
];

const DATA_TYPES = [
  { id: 'pii',         name: 'PII (names, SSN, DOB)',   multiplier: 1.0 },
  { id: 'phi',         name: 'PHI (medical records)',    multiplier: 1.35 },
  { id: 'financial',   name: 'Financial data',           multiplier: 1.20 },
  { id: 'ip',          name: 'Intellectual property',    multiplier: 1.30 },
  { id: 'credentials', name: 'Credentials / passwords',  multiplier: 1.10 },
  { id: 'payment',     name: 'Payment card data (PCI)',  multiplier: 1.25 },
];

const AMPLIFIERS = [
  { id: 'compliance',    name: 'Compliance failures',          cost: 1500000 },
  { id: 'remote',        name: 'Remote workforce involved',    cost: 1070000 },
  { id: 'skills',        name: 'Security skills shortage',     cost: 580000 },
  { id: 'complexity',    name: 'System complexity',            cost: 470000 },
  { id: 'migration',     name: 'Cloud migration in progress',  cost: 390000 },
  { id: 'third_party',   name: 'Third-party involvement',      cost: 370000 },
  { id: 'iot',           name: 'IoT / OT environment',        cost: 340000 },
];

const MITIGATORS = [
  { id: 'ai_auto',     name: 'AI & automation in security',   savings: 1760000 },
  { id: 'devsecops',   name: 'DevSecOps adoption',            savings: 249000 },
  { id: 'ir_plan',     name: 'Incident response plan & team', savings: 232000 },
  { id: 'training',    name: 'Employee training program',      savings: 232000 },
  { id: 'encryption',  name: 'Extensive encryption',           savings: 221000 },
  { id: 'threat_intel', name: 'Threat intelligence sharing',   savings: 198000 },
  { id: 'asm',         name: 'Attack surface management',      savings: 181000 },
  { id: 'ciso',        name: 'Board-level CISO involvement',   savings: 167000 },
];

const HISTORICAL_BREACHES = [
  { name: 'Equifax',       year: 2017, records: 147000000, totalCost: 1400000000, sector: 'Financial',   vector: 'Vulnerability (Apache Struts)' },
  { name: 'Yahoo',         year: 2016, records: 3000000000, totalCost: 350000000,  sector: 'Technology',  vector: 'State-sponsored attack' },
  { name: 'T-Mobile',      year: 2023, records: 37000000,  totalCost: 350000000,  sector: 'Telecom',     vector: 'API exploitation' },
  { name: 'Capital One',   year: 2019, records: 106000000, totalCost: 190000000,  sector: 'Financial',   vector: 'Cloud misconfiguration' },
  { name: 'Target',        year: 2013, records: 70000000,  totalCost: 292000000,  sector: 'Retail',      vector: 'Third-party vendor compromise' },
  { name: 'Home Depot',    year: 2014, records: 56000000,  totalCost: 179000000,  sector: 'Retail',      vector: 'Vendor credential theft' },
  { name: 'Anthem',        year: 2015, records: 78800000,  totalCost: 115000000,  sector: 'Healthcare',  vector: 'Spear phishing' },
  { name: 'Marriott',      year: 2018, records: 383000000, totalCost: 72000000,   sector: 'Hospitality', vector: 'Persistent access (Starwood)' },
  { name: 'SolarWinds',    year: 2020, records: 18000,     totalCost: 40000000,   sector: 'Technology',  vector: 'Supply chain (build system)' },
  { name: 'Colonial Pipeline', year: 2021, records: 0,     totalCost: 15000000,   sector: 'Energy',      vector: 'Ransomware (DarkSide)' },
  { name: 'Change Healthcare', year: 2024, records: 100000000, totalCost: 2450000000, sector: 'Healthcare', vector: 'Ransomware (ALPHV)' },
  { name: 'MGM Resorts',   year: 2023, records: 10600000,  totalCost: 100000000,  sector: 'Hospitality', vector: 'Social engineering + ransomware' },
];

const INSURANCE_TIERS = [
  { limit: 1000000,   label: '$1M',  premiumLow: 1500,   premiumHigh: 8000 },
  { limit: 5000000,   label: '$5M',  premiumLow: 5000,   premiumHigh: 30000 },
  { limit: 10000000,  label: '$10M', premiumLow: 15000,  premiumHigh: 60000 },
  { limit: 25000000,  label: '$25M', premiumLow: 40000,  premiumHigh: 150000 },
  { limit: 50000000,  label: '$50M', premiumLow: 80000,  premiumHigh: 300000 },
  { limit: 100000000, label: '$100M', premiumLow: 200000, premiumHigh: 600000 },
];


// ═══════════════════════════════════════════════════════════════════════════════
// COST CALCULATION ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

function calculateCosts(params) {
  var sector = SECTORS.find(function(s) { return s.id === params.sectorId; }) || SECTORS[0];
  var vector = ATTACK_VECTORS.find(function(v) { return v.id === params.vectorId; }) || ATTACK_VECTORS[0];
  var records = params.records || 10000;

  // Base per-record cost adjusted by sector
  var basePerRecord = 165; // IBM 2024 global average
  var sectorPerRecord = basePerRecord * sector.multiplier;

  // Data type multiplier (average of selected types)
  var dataTypeMult = 1.0;
  if (params.dataTypes && params.dataTypes.length > 0) {
    var sum = 0;
    for (var i = 0; i < params.dataTypes.length; i++) {
      var dt = DATA_TYPES.find(function(d) { return d.id === params.dataTypes[i]; });
      if (dt) sum += dt.multiplier;
    }
    dataTypeMult = sum / params.dataTypes.length;
  }

  // Attack vector adjustment
  var vectorMult = vector.costAdj;

  // Size curve: larger breaches have lower per-record cost but higher total
  var sizeFactor = 1.0;
  if (records > 1000000) sizeFactor = 0.55;
  else if (records > 500000) sizeFactor = 0.65;
  else if (records > 100000) sizeFactor = 0.75;
  else if (records > 50000) sizeFactor = 0.85;
  else if (records > 10000) sizeFactor = 0.92;

  // Time factor: longer detection/containment = higher cost
  var mtti = params.mtti || 204;
  var mttc = params.mttc || 73;
  var totalDays = mtti + mttc;
  // Baseline: 277 days (204 identify + 73 contain). Under 200 days saves ~23%
  var timeFactor = 1.0;
  if (totalDays < 200) timeFactor = 0.77;
  else if (totalDays < 250) timeFactor = 0.88;
  else if (totalDays < 300) timeFactor = 1.0;
  else if (totalDays < 350) timeFactor = 1.10;
  else timeFactor = 1.23;

  // Adjusted per-record cost
  var adjPerRecord = sectorPerRecord * dataTypeMult * vectorMult * sizeFactor * timeFactor;

  // Base breach cost
  var baseCost = records * adjPerRecord;

  // Cost components (distribution based on IBM report)
  var detection = baseCost * 0.29;
  var notification = baseCost * 0.06;
  var postBreach = baseCost * 0.27;
  var lostBusiness = baseCost * 0.38;

  // Amplifiers
  var amplifierTotal = 0;
  var activeAmplifiers = [];
  if (params.amplifiers) {
    for (var a = 0; a < params.amplifiers.length; a++) {
      var amp = AMPLIFIERS.find(function(x) { return x.id === params.amplifiers[a]; });
      if (amp) { amplifierTotal += amp.cost; activeAmplifiers.push(amp); }
    }
  }

  // Mitigators
  var mitigatorTotal = 0;
  var activeMitigators = [];
  if (params.aiAutomation) { mitigatorTotal += 1760000; activeMitigators.push({ name: 'AI & automation', savings: 1760000 }); }
  if (params.irRetainer) { mitigatorTotal += 232000; activeMitigators.push({ name: 'IR team retainer', savings: 232000 }); }
  if (params.lawEnforcement) { mitigatorTotal += 176000; activeMitigators.push({ name: 'Law enforcement involvement', savings: 176000 }); }
  if (params.mitigators) {
    for (var m = 0; m < params.mitigators.length; m++) {
      var mit = MITIGATORS.find(function(x) { return x.id === params.mitigators[m]; });
      if (mit && mit.id !== 'ai_auto' && mit.id !== 'ir_plan') {
        mitigatorTotal += mit.savings; activeMitigators.push(mit);
      }
    }
  }

  // Regulatory fines estimate
  var fines = 0;
  var fineBreakdown = [];
  var revenue = params.revenue || 0;

  if (params.dataTypes && params.dataTypes.indexOf('phi') >= 0) {
    var hipaaFine = Math.min(records * 50, 1500000 * 4);
    fines += hipaaFine;
    fineBreakdown.push({ reg: 'HIPAA', amount: hipaaFine });
  }
  if (params.dataTypes && params.dataTypes.indexOf('payment') >= 0) {
    var pciFine = Math.min(100000 * 6, 600000);
    fines += pciFine;
    fineBreakdown.push({ reg: 'PCI DSS', amount: pciFine });
  }
  if (params.gdprApplicable && revenue > 0) {
    var gdprFine = Math.max(20000000, revenue * 0.04) * 0.15; // 15% chance of max fine
    fines += gdprFine;
    fineBreakdown.push({ reg: 'GDPR', amount: gdprFine });
  }
  if (records > 500) {
    var stateFine = Math.min(records * 5, 5000000);
    fines += stateFine;
    fineBreakdown.push({ reg: 'State notification laws', amount: stateFine });
  }

  var totalCost = baseCost + amplifierTotal - mitigatorTotal + fines;
  if (totalCost < 0) totalCost = baseCost * 0.3;

  return {
    total: totalCost,
    baseCost: baseCost,
    perRecord: adjPerRecord,
    detection: detection,
    notification: notification,
    postBreach: postBreach,
    lostBusiness: lostBusiness,
    amplifierTotal: amplifierTotal,
    activeAmplifiers: activeAmplifiers,
    mitigatorTotal: mitigatorTotal,
    activeMitigators: activeMitigators,
    fines: fines,
    fineBreakdown: fineBreakdown,
    sector: sector,
    vector: vector,
    records: records,
    mtti: mtti,
    mttc: mttc,
    confidenceLow: totalCost * 0.75,
    confidenceHigh: totalCost * 1.35,
  };
}


// ═══════════════════════════════════════════════════════════════════════════════
// STYLES
// ═══════════════════════════════════════════════════════════════════════════════

var _icStyled = false;
function injectStyles() {
  if (_icStyled) return;
  _icStyled = true;
  var s = document.createElement('style');
  s.textContent =
  '.ic-wrap { font-family: ui-sans-serif, system-ui, -apple-system, sans-serif; color: #c8d6e5; max-width: 1300px; margin: 0 auto; }' +
  '.ic-header { padding: 24px 0 20px; border-bottom: 1px solid #1a2a44; margin-bottom: 24px; }' +
  '.ic-title { font-size: 24px; font-weight: 800; color: #fff; margin: 0 0 4px; letter-spacing: -0.02em; }' +
  '.ic-subtitle { font-size: 13px; color: #667788; margin: 0; }' +
  '.ic-grid { display: grid; grid-template-columns: 380px 1fr; gap: 24px; }' +
  '@media (max-width: 900px) { .ic-grid { grid-template-columns: 1fr; } }' +

  // Panel base
  '.ic-panel { background: #0d1117; border: 1px solid #1a2332; border-radius: 10px; padding: 20px; margin-bottom: 20px; }' +
  '.ic-panel-title { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 1.5px; color: #00e5ff; margin: 0 0 16px; padding-bottom: 10px; border-bottom: 1px solid #1a2332; }' +

  // Hero cost
  '.ic-hero { background: linear-gradient(135deg, #0d1117, #111d2b); border: 1px solid #1a3050; border-radius: 12px; padding: 28px 24px; margin-bottom: 24px; text-align: center; }' +
  '.ic-hero-label { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 2px; color: #667788; margin-bottom: 8px; }' +
  '.ic-hero-cost { font-size: 48px; font-weight: 800; font-family: ui-monospace, monospace; color: #ff5c6c; margin: 0; letter-spacing: -2px; line-height: 1.1; }' +
  '.ic-hero-range { font-size: 12px; color: #667788; margin-top: 6px; font-family: monospace; }' +
  '.ic-hero-per-record { font-size: 13px; color: #8899aa; margin-top: 10px; }' +
  '.ic-hero-per-record span { color: #ffaa00; font-weight: 700; font-family: monospace; }' +

  // Cost breakdown cards row
  '.ic-cost-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; margin-bottom: 20px; }' +
  '.ic-cost-card { background: #111820; border: 1px solid #1a2332; border-radius: 8px; padding: 12px; text-align: center; }' +
  '.ic-cost-card-label { font-size: 10px; text-transform: uppercase; letter-spacing: 1px; color: #667788; margin-bottom: 6px; }' +
  '.ic-cost-card-val { font-size: 20px; font-weight: 700; font-family: monospace; }' +
  '.ic-cost-card-pct { font-size: 10px; color: #667788; margin-top: 2px; }' +

  // Form elements
  '.ic-form-group { margin-bottom: 14px; }' +
  '.ic-label { display: block; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; color: #8899aa; margin-bottom: 6px; }' +
  '.ic-select { width: 100%; background: #111820; border: 1px solid #1a2332; border-radius: 6px; color: #c8d6e5; padding: 8px 10px; font-size: 13px; font-family: inherit; cursor: pointer; }' +
  '.ic-select:focus { outline: none; border-color: #00e5ff; }' +
  '.ic-range-wrap { display: flex; align-items: center; gap: 10px; }' +
  '.ic-range { flex: 1; accent-color: #00e5ff; }' +
  '.ic-range-val { font-family: monospace; font-size: 13px; color: #00e5ff; font-weight: 700; min-width: 60px; text-align: right; }' +
  '.ic-checkbox-group { display: flex; flex-wrap: wrap; gap: 6px; }' +
  '.ic-check { display: flex; align-items: center; gap: 5px; background: #111820; border: 1px solid #1a2332; border-radius: 4px; padding: 5px 10px; font-size: 11px; cursor: pointer; transition: all .15s; }' +
  '.ic-check:hover { border-color: #2a3a4a; }' +
  '.ic-check.active { background: #0a2a3a; border-color: #00e5ff; color: #00e5ff; }' +
  '.ic-check input { accent-color: #00e5ff; margin: 0; }' +
  '.ic-toggle-row { display: flex; align-items: center; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #111820; }' +
  '.ic-toggle-label { font-size: 12px; color: #aabbcc; }' +
  '.ic-toggle-savings { font-size: 11px; color: #2ee6a6; font-family: monospace; }' +
  '.ic-toggle { position: relative; width: 36px; height: 20px; background: #1a2332; border-radius: 10px; cursor: pointer; transition: background .2s; flex-shrink: 0; }' +
  '.ic-toggle.on { background: #00e5ff; }' +
  '.ic-toggle::after { content: ""; position: absolute; top: 2px; left: 2px; width: 16px; height: 16px; border-radius: 50%; background: #fff; transition: transform .2s; }' +
  '.ic-toggle.on::after { transform: translateX(16px); }' +

  // Breakdown bars
  '.ic-bar-row { margin-bottom: 10px; }' +
  '.ic-bar-header { display: flex; justify-content: space-between; font-size: 11px; margin-bottom: 4px; }' +
  '.ic-bar-name { color: #aabbcc; }' +
  '.ic-bar-val { font-family: monospace; font-weight: 700; }' +
  '.ic-bar-track { height: 8px; background: #111820; border-radius: 4px; overflow: hidden; }' +
  '.ic-bar-fill { height: 100%; border-radius: 4px; transition: width .4s ease; }' +
  '.ic-bar-fill.red { background: linear-gradient(90deg, #ef4444, #ff6b6b); }' +
  '.ic-bar-fill.orange { background: linear-gradient(90deg, #f59e0b, #fbbf24); }' +
  '.ic-bar-fill.blue { background: linear-gradient(90deg, #3b82f6, #60a5fa); }' +
  '.ic-bar-fill.green { background: linear-gradient(90deg, #10b981, #34d399); }' +
  '.ic-bar-fill.purple { background: linear-gradient(90deg, #8b5cf6, #a78bfa); }' +
  '.ic-bar-fill.cyan { background: linear-gradient(90deg, #06b6d4, #22d3ee); }' +

  // Amplifier / mitigator list
  '.ic-factor-item { display: flex; align-items: center; justify-content: space-between; padding: 7px 0; border-bottom: 1px solid #111820; font-size: 12px; }' +
  '.ic-factor-name { color: #aabbcc; }' +
  '.ic-factor-cost { font-family: monospace; font-weight: 700; }' +
  '.ic-factor-cost.amp { color: #ff5c6c; }' +
  '.ic-factor-cost.mit { color: #2ee6a6; }' +

  // Table
  '.ic-table { width: 100%; border-collapse: collapse; font-size: 12px; }' +
  '.ic-table th { text-align: left; padding: 8px 10px; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; color: #667788; border-bottom: 2px solid #1a2332; }' +
  '.ic-table td { padding: 8px 10px; border-bottom: 1px solid #111820; color: #aabbcc; }' +
  '.ic-table tr:hover td { background: #111820; }' +
  '.ic-table .mono { font-family: monospace; }' +

  // Insurance
  '.ic-insurance-bar { display: flex; align-items: stretch; height: 32px; border-radius: 6px; overflow: hidden; margin-bottom: 8px; }' +
  '.ic-ins-covered { background: #10b981; display: flex; align-items: center; justify-content: center; font-size: 10px; font-weight: 700; color: #fff; }' +
  '.ic-ins-gap { background: #ef4444; display: flex; align-items: center; justify-content: center; font-size: 10px; font-weight: 700; color: #fff; }' +

  // Revenue input
  '.ic-input { width: 100%; background: #111820; border: 1px solid #1a2332; border-radius: 6px; color: #c8d6e5; padding: 8px 10px; font-size: 13px; font-family: monospace; }' +
  '.ic-input:focus { outline: none; border-color: #00e5ff; }' +

  // Tabs
  '.ic-tabs { display: flex; gap: 2px; margin-bottom: 20px; background: #0a0e14; border-radius: 8px; padding: 3px; }' +
  '.ic-tab { flex: 1; text-align: center; padding: 8px 12px; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; color: #667788; cursor: pointer; border-radius: 4px; transition: all .15s; border: none; background: none; font-family: inherit; }' +
  '.ic-tab:hover { color: #aabbcc; }' +
  '.ic-tab.active { background: #1a2332; color: #00e5ff; }' +

  // Report button
  '.ic-btn { display: inline-flex; align-items: center; gap: 6px; background: #00e5ff; color: #000; border: none; border-radius: 4px; padding: 8px 16px; font-size: 12px; font-weight: 700; cursor: pointer; font-family: inherit; transition: all .15s; }' +
  '.ic-btn:hover { background: #33eeff; transform: translateY(-1px); }' +
  '.ic-btn.ghost { background: transparent; color: #c8d6e5; border: 1px solid #1a2332; }' +
  '.ic-btn.ghost:hover { border-color: #00e5ff; color: #00e5ff; }' +

  // Stat row
  '.ic-stats-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 20px; }' +
  '.ic-stat { background: #111820; border: 1px solid #1a2332; border-radius: 8px; padding: 14px; text-align: center; }' +
  '.ic-stat-val { font-size: 22px; font-weight: 800; font-family: monospace; }' +
  '.ic-stat-label { font-size: 10px; text-transform: uppercase; letter-spacing: 1px; color: #667788; margin-top: 4px; }' +
  '@media (max-width: 700px) { .ic-stats-row { grid-template-columns: repeat(2, 1fr); } }' +

  // Fine tier
  '.ic-fine-row { display: flex; align-items: center; justify-content: space-between; padding: 8px 12px; background: #111820; border: 1px solid #1a2332; border-radius: 6px; margin-bottom: 6px; }' +
  '.ic-fine-reg { font-size: 12px; font-weight: 600; color: #c8d6e5; }' +
  '.ic-fine-amount { font-size: 13px; font-family: monospace; font-weight: 700; color: #ff5c6c; }' +

  // Pro (light) theme overrides
  '[data-style=pro] .ic-wrap { color: #3f3f46; }' +
  '[data-style=pro] .ic-header { border-bottom-color: #e5e5e5; }' +
  '[data-style=pro] .ic-title { color: #18181b; }' +
  '[data-style=pro] .ic-subtitle { color: #71717a; }' +
  '[data-style=pro] .ic-panel { background: #fff; border-color: #e5e5e5; }' +
  '[data-style=pro] .ic-panel-title { color: #2563eb; border-bottom-color: #e5e5e5; }' +
  '[data-style=pro] .ic-hero { background: linear-gradient(135deg, #fff, #f0f4ff); border-color: #dbeafe; }' +
  '[data-style=pro] .ic-hero-label { color: #71717a; }' +
  '[data-style=pro] .ic-hero-cost { color: #dc2626; }' +
  '[data-style=pro] .ic-hero-range { color: #71717a; }' +
  '[data-style=pro] .ic-hero-per-record { color: #52525b; }' +
  '[data-style=pro] .ic-hero-per-record span { color: #ca8a04; }' +
  '[data-style=pro] .ic-cost-card { background: #fafafa; border-color: #e5e5e5; }' +
  '[data-style=pro] .ic-cost-card-label { color: #71717a; }' +
  '[data-style=pro] .ic-cost-card-pct { color: #a1a1aa; }' +
  '[data-style=pro] .ic-select { background: #fafafa; border-color: #e5e5e5; color: #18181b; }' +
  '[data-style=pro] .ic-select:focus { border-color: #2563eb; }' +
  '[data-style=pro] .ic-range { accent-color: #2563eb; }' +
  '[data-style=pro] .ic-range-val { color: #2563eb; }' +
  '[data-style=pro] .ic-check { background: #fafafa; border-color: #e5e5e5; color: #3f3f46; }' +
  '[data-style=pro] .ic-check:hover { border-color: #d4d4d8; }' +
  '[data-style=pro] .ic-check.active { background: #eff6ff; border-color: #2563eb; color: #2563eb; }' +
  '[data-style=pro] .ic-check input { accent-color: #2563eb; }' +
  '[data-style=pro] .ic-toggle-row { border-bottom-color: #f4f4f5; }' +
  '[data-style=pro] .ic-toggle-label { color: #3f3f46; }' +
  '[data-style=pro] .ic-toggle-savings { color: #16a34a; }' +
  '[data-style=pro] .ic-toggle { background: #e5e5e5; }' +
  '[data-style=pro] .ic-toggle.on { background: #2563eb; }' +
  '[data-style=pro] .ic-bar-name { color: #52525b; }' +
  '[data-style=pro] .ic-bar-track { background: #f4f4f5; }' +
  '[data-style=pro] .ic-factor-item { border-bottom-color: #f4f4f5; }' +
  '[data-style=pro] .ic-factor-name { color: #52525b; }' +
  '[data-style=pro] .ic-factor-cost.amp { color: #dc2626; }' +
  '[data-style=pro] .ic-factor-cost.mit { color: #16a34a; }' +
  '[data-style=pro] .ic-table th { color: #71717a; border-bottom-color: #e5e5e5; }' +
  '[data-style=pro] .ic-table td { color: #3f3f46; border-bottom-color: #f4f4f5; }' +
  '[data-style=pro] .ic-table tr:hover td { background: #fafafa; }' +
  '[data-style=pro] .ic-input { background: #fafafa; border-color: #e5e5e5; color: #18181b; }' +
  '[data-style=pro] .ic-input:focus { border-color: #2563eb; }' +
  '[data-style=pro] .ic-tabs { background: #f4f4f5; }' +
  '[data-style=pro] .ic-tab { color: #71717a; }' +
  '[data-style=pro] .ic-tab:hover { color: #3f3f46; }' +
  '[data-style=pro] .ic-tab.active { background: #fff; color: #2563eb; }' +
  '[data-style=pro] .ic-btn { background: #18181b; color: #fff; }' +
  '[data-style=pro] .ic-btn:hover { background: #3f3f46; }' +
  '[data-style=pro] .ic-btn.ghost { background: transparent; color: #3f3f46; border-color: #e5e5e5; }' +
  '[data-style=pro] .ic-btn.ghost:hover { border-color: #2563eb; color: #2563eb; }' +
  '[data-style=pro] .ic-stat { background: #fafafa; border-color: #e5e5e5; }' +
  '[data-style=pro] .ic-stat-label { color: #71717a; }' +
  '[data-style=pro] .ic-fine-row { background: #fafafa; border-color: #e5e5e5; }' +
  '[data-style=pro] .ic-fine-reg { color: #18181b; }' +
  '[data-style=pro] .ic-fine-amount { color: #dc2626; }' +
  '';
  document.head.appendChild(s);
}


// ═══════════════════════════════════════════════════════════════════════════════
// RENDER
// ═══════════════════════════════════════════════════════════════════════════════

export function renderIncidentCost(container) {
  injectStyles();

  var state = {
    sectorId: 'healthcare',
    vectorId: 'phishing',
    records: 50000,
    dataTypes: ['pii'],
    mtti: 204,
    mttc: 73,
    aiAutomation: false,
    irRetainer: false,
    lawEnforcement: false,
    amplifiers: [],
    mitigators: [],
    revenue: 500000000,
    gdprApplicable: false,
    insuranceTier: 2,
    activeTab: 'calculator',
  };

  function render() {
    var costs = calculateCosts(state);
    var h = '';
    h += '<div class="ic-wrap">';

    // Header
    h += '<div class="ic-header">';
    h += '<h1 class="ic-title">Cyber Incident Cost Calculator</h1>';
    h += '<p class="ic-subtitle">Estimate breach costs using IBM/Ponemon methodology &mdash; sector-adjusted, regulation-aware, with insurance gap analysis</p>';
    h += '</div>';

    // Tabs
    h += '<div class="ic-tabs">';
    var tabs = [
      ['calculator', 'Cost Calculator'],
      ['regulatory', 'Regulatory Fines'],
      ['insurance', 'Insurance Analysis'],
      ['historical', 'Breach Comparisons'],
      ['report', 'Executive Report'],
    ];
    for (var t = 0; t < tabs.length; t++) {
      h += '<button class="ic-tab' + (state.activeTab === tabs[t][0] ? ' active' : '') + '" data-tab="' + tabs[t][0] + '">' + tabs[t][1] + '</button>';
    }
    h += '</div>';

    if (state.activeTab === 'calculator') {
      h += renderCalculator(costs);
    } else if (state.activeTab === 'regulatory') {
      h += renderRegulatory(costs);
    } else if (state.activeTab === 'insurance') {
      h += renderInsurance(costs);
    } else if (state.activeTab === 'historical') {
      h += renderHistorical(costs);
    } else if (state.activeTab === 'report') {
      h += renderReport(costs);
    }

    h += '</div>';
    container.innerHTML = h;
    wireEvents();
  }

  function renderCalculator(costs) {
    var h = '';

    // Hero cost display
    h += '<div class="ic-hero">';
    h += '<div class="ic-hero-label">Estimated Total Breach Cost</div>';
    h += '<div class="ic-hero-cost">' + fmt$(costs.total) + '</div>';
    h += '<div class="ic-hero-range">Confidence range: ' + fmt$(costs.confidenceLow) + ' &mdash; ' + fmt$(costs.confidenceHigh) + '</div>';
    h += '<div class="ic-hero-per-record">Per record: <span>' + fmt$(costs.perRecord) + '</span> &times; ' + fmtN(costs.records) + ' records (' + esc(costs.sector.name) + ')</div>';
    h += '</div>';

    // Cost breakdown cards
    h += '<div class="ic-cost-cards">';
    var comps = [
      { label: 'Detection & Escalation', val: costs.detection, pct: 29, color: '#3b82f6' },
      { label: 'Lost Business', val: costs.lostBusiness, pct: 38, color: '#ef4444' },
      { label: 'Post-Breach Response', val: costs.postBreach, pct: 27, color: '#f59e0b' },
      { label: 'Notification', val: costs.notification, pct: 6, color: '#8b5cf6' },
      { label: 'Regulatory Fines', val: costs.fines, pct: Math.round(costs.fines / costs.total * 100) || 0, color: '#ef4444' },
    ];
    for (var c = 0; c < comps.length; c++) {
      h += '<div class="ic-cost-card">';
      h += '<div class="ic-cost-card-label">' + comps[c].label + '</div>';
      h += '<div class="ic-cost-card-val" style="color:' + comps[c].color + '">' + fmt$(comps[c].val) + '</div>';
      h += '<div class="ic-cost-card-pct">' + comps[c].pct + '% of total</div>';
      h += '</div>';
    }
    h += '</div>';

    // Main grid: form + breakdown
    h += '<div class="ic-grid">';

    // LEFT: Form
    h += '<div>';
    h += '<div class="ic-panel">';
    h += '<div class="ic-panel-title">Incident Parameters</div>';

    // Sector
    h += '<div class="ic-form-group">';
    h += '<label class="ic-label">Industry Sector</label>';
    h += '<select class="ic-select" id="ic-sector">';
    for (var s = 0; s < SECTORS.length; s++) {
      h += '<option value="' + SECTORS[s].id + '"' + (state.sectorId === SECTORS[s].id ? ' selected' : '') + '>' + esc(SECTORS[s].name) + ' (avg ' + fmt$(SECTORS[s].avgCost) + ')</option>';
    }
    h += '</select></div>';

    // Attack vector
    h += '<div class="ic-form-group">';
    h += '<label class="ic-label">Attack Vector</label>';
    h += '<select class="ic-select" id="ic-vector">';
    for (var v = 0; v < ATTACK_VECTORS.length; v++) {
      h += '<option value="' + ATTACK_VECTORS[v].id + '"' + (state.vectorId === ATTACK_VECTORS[v].id ? ' selected' : '') + '>' + esc(ATTACK_VECTORS[v].name) + '</option>';
    }
    h += '</select></div>';

    // Records
    h += '<div class="ic-form-group">';
    h += '<label class="ic-label">Records Compromised</label>';
    h += '<div class="ic-range-wrap">';
    h += '<input type="range" class="ic-range" id="ic-records" min="1000" max="100000000" value="' + state.records + '" step="1000">';
    h += '<span class="ic-range-val">' + fmtN(state.records) + '</span>';
    h += '</div></div>';

    // Data types
    h += '<div class="ic-form-group">';
    h += '<label class="ic-label">Data Types Compromised</label>';
    h += '<div class="ic-checkbox-group">';
    for (var d = 0; d < DATA_TYPES.length; d++) {
      var checked = state.dataTypes.indexOf(DATA_TYPES[d].id) >= 0;
      h += '<label class="ic-check' + (checked ? ' active' : '') + '">';
      h += '<input type="checkbox" data-dtype="' + DATA_TYPES[d].id + '"' + (checked ? ' checked' : '') + '>';
      h += esc(DATA_TYPES[d].name);
      h += '</label>';
    }
    h += '</div></div>';

    // MTTI
    h += '<div class="ic-form-group">';
    h += '<label class="ic-label">Mean Time to Identify (days)</label>';
    h += '<div class="ic-range-wrap">';
    h += '<input type="range" class="ic-range" id="ic-mtti" min="1" max="365" value="' + state.mtti + '">';
    h += '<span class="ic-range-val">' + state.mtti + 'd</span>';
    h += '</div></div>';

    // MTTC
    h += '<div class="ic-form-group">';
    h += '<label class="ic-label">Mean Time to Contain (days)</label>';
    h += '<div class="ic-range-wrap">';
    h += '<input type="range" class="ic-range" id="ic-mttc" min="1" max="200" value="' + state.mttc + '">';
    h += '<span class="ic-range-val">' + state.mttc + 'd</span>';
    h += '</div></div>';

    // Revenue (for GDPR)
    h += '<div class="ic-form-group">';
    h += '<label class="ic-label">Annual Revenue (for fine calculation)</label>';
    h += '<input type="text" class="ic-input" id="ic-revenue" value="$' + state.revenue.toLocaleString() + '" placeholder="$500,000,000">';
    h += '</div>';

    // GDPR toggle
    h += '<div class="ic-toggle-row">';
    h += '<div><span class="ic-toggle-label">GDPR applicable (EU data subjects)</span></div>';
    h += '<div class="ic-toggle dn-round' + (state.gdprApplicable ? ' on' : '') + '" id="ic-gdpr"></div>';
    h += '</div>';

    h += '</div>'; // panel

    // Cost reduction toggles
    h += '<div class="ic-panel">';
    h += '<div class="ic-panel-title">Cost Reduction Factors</div>';

    var toggles = [
      { id: 'aiAutomation', label: 'AI & automation in security response', savings: '$1.76M', key: 'aiAutomation' },
      { id: 'irRetainer', label: 'Incident response team retainer', savings: '$232K', key: 'irRetainer' },
      { id: 'lawEnforcement', label: 'Law enforcement involvement', savings: '$176K', key: 'lawEnforcement' },
    ];
    for (var tg = 0; tg < toggles.length; tg++) {
      h += '<div class="ic-toggle-row">';
      h += '<div>';
      h += '<span class="ic-toggle-label">' + toggles[tg].label + '</span><br>';
      h += '<span class="ic-toggle-savings">saves ' + toggles[tg].savings + '</span>';
      h += '</div>';
      h += '<div class="ic-toggle dn-round' + (state[toggles[tg].key] ? ' on' : '') + '" data-toggle="' + toggles[tg].key + '"></div>';
      h += '</div>';
    }

    h += '</div>'; // panel
    h += '</div>'; // left col

    // RIGHT: Breakdown
    h += '<div>';

    // Cost breakdown bars
    h += '<div class="ic-panel">';
    h += '<div class="ic-panel-title">Cost Breakdown</div>';
    var maxVal = Math.max(costs.detection, costs.lostBusiness, costs.postBreach, costs.notification);
    var bars = [
      { name: 'Lost Business Impact', val: costs.lostBusiness, cls: 'red' },
      { name: 'Detection & Escalation', val: costs.detection, cls: 'blue' },
      { name: 'Post-Breach Response', val: costs.postBreach, cls: 'orange' },
      { name: 'Regulatory Fines', val: costs.fines, cls: 'purple' },
      { name: 'Notification Costs', val: costs.notification, cls: 'cyan' },
    ];
    for (var b = 0; b < bars.length; b++) {
      var pct = maxVal > 0 ? Math.round(bars[b].val / maxVal * 100) : 0;
      h += '<div class="ic-bar-row">';
      h += '<div class="ic-bar-header"><span class="ic-bar-name">' + bars[b].name + '</span><span class="ic-bar-val" style="color:inherit">' + fmt$(bars[b].val) + '</span></div>';
      h += '<div class="ic-bar-track"><div class="ic-bar-fill ' + bars[b].cls + '" style="width:' + pct + '%"></div></div>';
      h += '</div>';
    }
    h += '</div>';

    // Amplifiers
    h += '<div class="ic-panel">';
    h += '<div class="ic-panel-title">Cost Amplifiers</div>';
    for (var ai = 0; ai < AMPLIFIERS.length; ai++) {
      var ampActive = state.amplifiers.indexOf(AMPLIFIERS[ai].id) >= 0;
      h += '<div class="ic-toggle-row">';
      h += '<div>';
      h += '<span class="ic-toggle-label">' + esc(AMPLIFIERS[ai].name) + '</span><br>';
      h += '<span class="ic-factor-cost amp">+' + fmt$(AMPLIFIERS[ai].cost) + '</span>';
      h += '</div>';
      h += '<div class="ic-toggle dn-round' + (ampActive ? ' on' : '') + '" data-amplifier="' + AMPLIFIERS[ai].id + '"></div>';
      h += '</div>';
    }
    if (costs.amplifierTotal > 0) {
      h += '<div style="text-align:right;padding-top:8px;font-family:monospace;font-size:13px;color:#ff5c6c;font-weight:700">Total amplification: +' + fmt$(costs.amplifierTotal) + '</div>';
    }
    h += '</div>';

    // Mitigators
    h += '<div class="ic-panel">';
    h += '<div class="ic-panel-title">Additional Mitigators</div>';
    for (var mi = 0; mi < MITIGATORS.length; mi++) {
      if (MITIGATORS[mi].id === 'ai_auto' || MITIGATORS[mi].id === 'ir_plan') continue;
      var mitActive = state.mitigators.indexOf(MITIGATORS[mi].id) >= 0;
      h += '<div class="ic-toggle-row">';
      h += '<div>';
      h += '<span class="ic-toggle-label">' + esc(MITIGATORS[mi].name) + '</span><br>';
      h += '<span class="ic-factor-cost mit">-' + fmt$(MITIGATORS[mi].savings) + '</span>';
      h += '</div>';
      h += '<div class="ic-toggle dn-round' + (mitActive ? ' on' : '') + '" data-mitigator="' + MITIGATORS[mi].id + '"></div>';
      h += '</div>';
    }
    if (costs.mitigatorTotal > 0) {
      h += '<div style="text-align:right;padding-top:8px;font-family:monospace;font-size:13px;color:#2ee6a6;font-weight:700">Total savings: -' + fmt$(costs.mitigatorTotal) + '</div>';
    }
    h += '</div>';

    // Time impact note
    h += '<div class="ic-panel">';
    h += '<div class="ic-panel-title">Detection Time Impact</div>';
    var lifecycle = state.mtti + state.mttc;
    var lifecycleColor = lifecycle < 200 ? '#2ee6a6' : lifecycle < 280 ? '#f59e0b' : '#ef4444';
    var lifecycleLabel = lifecycle < 200 ? 'FAST — saves ~23% vs average' : lifecycle < 280 ? 'AVERAGE — 277 day benchmark' : 'SLOW — adds 10-23% to cost';
    h += '<div style="text-align:center;padding:10px 0">';
    h += '<div style="font-size:36px;font-weight:800;font-family:monospace;color:' + lifecycleColor + '">' + lifecycle + ' days</div>';
    h += '<div style="font-size:11px;color:#667788;margin-top:4px">breach lifecycle (identify + contain)</div>';
    h += '<div style="font-size:12px;color:' + lifecycleColor + ';margin-top:8px;font-weight:600">' + lifecycleLabel + '</div>';
    h += '</div>';
    h += '<div style="display:flex;justify-content:space-between;font-size:11px;color:#667788;margin-top:8px">';
    h += '<span>MTTI: ' + state.mtti + ' days (avg 204)</span>';
    h += '<span>MTTC: ' + state.mttc + ' days (avg 73)</span>';
    h += '</div>';
    h += '</div>';

    h += '</div>'; // right col
    h += '</div>'; // grid

    return h;
  }


  function renderRegulatory(costs) {
    var h = '';
    h += '<div class="ic-panel">';
    h += '<div class="ic-panel-title">Regulatory Fine Estimator</div>';

    if (costs.fineBreakdown.length === 0) {
      h += '<div style="text-align:center;padding:30px;color:#667788">Select data types and toggle GDPR applicability in the Calculator tab to see fine estimates.</div>';
    } else {
      h += '<div class="ic-stats-row">';
      h += '<div class="ic-stat"><div class="ic-stat-val" style="color:#ff5c6c">' + fmt$(costs.fines) + '</div><div class="ic-stat-label">Total Estimated Fines</div></div>';
      h += '<div class="ic-stat"><div class="ic-stat-val" style="color:#3b82f6">' + costs.fineBreakdown.length + '</div><div class="ic-stat-label">Applicable Regulations</div></div>';
      h += '<div class="ic-stat"><div class="ic-stat-val" style="color:#f59e0b">' + fmtN(costs.records) + '</div><div class="ic-stat-label">Records Affected</div></div>';
      h += '<div class="ic-stat"><div class="ic-stat-val" style="color:#8b5cf6">' + Math.round(costs.fines / costs.total * 100) + '%</div><div class="ic-stat-label">of Total Cost</div></div>';
      h += '</div>';

      for (var f = 0; f < costs.fineBreakdown.length; f++) {
        h += '<div class="ic-fine-row">';
        h += '<span class="ic-fine-reg">' + esc(costs.fineBreakdown[f].reg) + '</span>';
        h += '<span class="ic-fine-amount">' + fmt$(costs.fineBreakdown[f].amount) + '</span>';
        h += '</div>';
      }
    }
    h += '</div>';

    // Regulation reference
    h += '<div class="ic-panel">';
    h += '<div class="ic-panel-title">Regulation Reference</div>';
    h += '<table class="ic-table">';
    h += '<thead><tr><th>Regulation</th><th>Scope</th><th>Max Penalty</th><th>Notification Deadline</th></tr></thead>';
    h += '<tbody>';
    var regs = [
      ['GDPR', 'EU/EEA personal data', '4% of global revenue or €20M', '72 hours'],
      ['HIPAA', 'Protected health info (US)', '$1.5M per violation category/year', '60 days'],
      ['PCI DSS', 'Payment card data', '$100K/month non-compliance', 'Varies by brand'],
      ['CCPA/CPRA', 'California residents', '$7,500 per intentional violation', '72 hours (AG)'],
      ['GLBA', 'Financial institution data', 'Up to $100K per violation', '36 hours (banking)'],
      ['SOX', 'Public company financials', '$5M fine + 20yr prison', '4 business days (SEC)'],
      ['SEC Rules', 'Material cyber incidents', 'Enforcement action', '4 business days (8-K)'],
      ['FISMA', 'Federal agency data', 'Budget/oversight impact', 'US-CERT within 1 hour'],
      ['State Laws', '50 states + territories', 'Varies ($1K-$750K per violation)', '30-90 days (varies)'],
    ];
    for (var r = 0; r < regs.length; r++) {
      h += '<tr>';
      h += '<td style="font-weight:600;color:#c8d6e5">' + regs[r][0] + '</td>';
      h += '<td>' + regs[r][1] + '</td>';
      h += '<td class="mono" style="color:#ff5c6c">' + regs[r][2] + '</td>';
      h += '<td>' + regs[r][3] + '</td>';
      h += '</tr>';
    }
    h += '</tbody></table>';
    h += '</div>';

    // SEC disclosure timeline
    h += '<div class="ic-panel">';
    h += '<div class="ic-panel-title">SEC Cyber Incident Disclosure Timeline (2023 Rules)</div>';
    var secSteps = [
      { day: 'Day 0', event: 'Incident discovered', note: 'Clock starts for materiality determination' },
      { day: 'Day 1-4', event: 'Materiality assessment', note: 'Determine if incident is material to investors' },
      { day: 'Day 4', event: '8-K filing due', note: 'Must disclose material cyber incidents within 4 business days of materiality determination' },
      { day: 'Day 30', event: 'Initial remediation update', note: 'Ongoing disclosure obligations if facts change' },
      { day: 'Annual', event: '10-K disclosure', note: 'Annual report must describe cyber risk management, strategy, and governance' },
    ];
    for (var ss = 0; ss < secSteps.length; ss++) {
      var dotColor = ss < 2 ? '#f59e0b' : ss === 2 ? '#ef4444' : '#3b82f6';
      h += '<div style="display:flex;gap:14px;padding:10px 0;border-bottom:1px solid #111820">';
      h += '<div style="min-width:70px;font-family:monospace;font-size:12px;font-weight:700;color:' + dotColor + '">' + secSteps[ss].day + '</div>';
      h += '<div>';
      h += '<div style="font-size:13px;font-weight:600;color:#c8d6e5">' + secSteps[ss].event + '</div>';
      h += '<div style="font-size:11px;color:#667788;margin-top:2px">' + secSteps[ss].note + '</div>';
      h += '</div></div>';
    }
    h += '</div>';

    return h;
  }


  function renderInsurance(costs) {
    var h = '';
    var selectedTier = INSURANCE_TIERS[state.insuranceTier];

    h += '<div class="ic-stats-row">';
    h += '<div class="ic-stat"><div class="ic-stat-val" style="color:#ff5c6c">' + fmt$(costs.total) + '</div><div class="ic-stat-label">Estimated Breach Cost</div></div>';
    h += '<div class="ic-stat"><div class="ic-stat-val" style="color:#3b82f6">' + fmt$(selectedTier.limit) + '</div><div class="ic-stat-label">Policy Limit</div></div>';
    var gap = Math.max(0, costs.total - selectedTier.limit);
    h += '<div class="ic-stat"><div class="ic-stat-val" style="color:' + (gap > 0 ? '#ef4444' : '#2ee6a6') + '">' + (gap > 0 ? fmt$(gap) : '$0') + '</div><div class="ic-stat-label">Coverage Gap</div></div>';
    var covPct = Math.min(100, Math.round(selectedTier.limit / costs.total * 100));
    h += '<div class="ic-stat"><div class="ic-stat-val" style="color:' + (covPct >= 100 ? '#2ee6a6' : covPct >= 50 ? '#f59e0b' : '#ef4444') + '">' + covPct + '%</div><div class="ic-stat-label">Coverage Ratio</div></div>';
    h += '</div>';

    // Coverage visualization
    h += '<div class="ic-panel">';
    h += '<div class="ic-panel-title">Coverage Gap Analysis</div>';

    var covWidth = Math.min(100, Math.round(selectedTier.limit / costs.total * 100));
    var gapWidth = 100 - covWidth;
    h += '<div class="ic-insurance-bar">';
    if (covWidth > 0) h += '<div class="ic-ins-covered" style="width:' + covWidth + '%">COVERED ' + fmt$(Math.min(selectedTier.limit, costs.total)) + '</div>';
    if (gapWidth > 0) h += '<div class="ic-ins-gap" style="width:' + gapWidth + '%">GAP ' + fmt$(gap) + '</div>';
    h += '</div>';

    // Tier selector
    h += '<div class="ic-form-group" style="margin-top:16px">';
    h += '<label class="ic-label">Select Coverage Tier</label>';
    h += '<select class="ic-select" id="ic-ins-tier">';
    for (var it = 0; it < INSURANCE_TIERS.length; it++) {
      h += '<option value="' + it + '"' + (state.insuranceTier === it ? ' selected' : '') + '>' + INSURANCE_TIERS[it].label + ' limit (premium: ' + fmt$(INSURANCE_TIERS[it].premiumLow) + '-' + fmt$(INSURANCE_TIERS[it].premiumHigh) + '/yr)</option>';
    }
    h += '</select></div>';
    h += '</div>';

    // All tiers comparison
    h += '<div class="ic-panel">';
    h += '<div class="ic-panel-title">Coverage Tier Comparison</div>';
    h += '<table class="ic-table">';
    h += '<thead><tr><th>Limit</th><th>Premium Range</th><th>Coverage</th><th>Gap</th><th>Recommendation</th></tr></thead>';
    h += '<tbody>';
    for (var tt = 0; tt < INSURANCE_TIERS.length; tt++) {
      var tierGap = Math.max(0, costs.total - INSURANCE_TIERS[tt].limit);
      var tierCov = Math.min(100, Math.round(INSURANCE_TIERS[tt].limit / costs.total * 100));
      var rec = tierCov >= 100 ? 'Full coverage' : tierCov >= 75 ? 'Good coverage' : tierCov >= 50 ? 'Partial — consider upgrading' : 'Insufficient';
      var recColor = tierCov >= 100 ? '#2ee6a6' : tierCov >= 75 ? '#3b82f6' : tierCov >= 50 ? '#f59e0b' : '#ef4444';
      h += '<tr>';
      h += '<td class="mono" style="font-weight:700;color:#c8d6e5">' + INSURANCE_TIERS[tt].label + '</td>';
      h += '<td class="mono">' + fmt$(INSURANCE_TIERS[tt].premiumLow) + ' - ' + fmt$(INSURANCE_TIERS[tt].premiumHigh) + '</td>';
      h += '<td class="mono" style="color:#3b82f6">' + tierCov + '%</td>';
      h += '<td class="mono" style="color:' + (tierGap > 0 ? '#ef4444' : '#2ee6a6') + '">' + (tierGap > 0 ? fmt$(tierGap) : '—') + '</td>';
      h += '<td style="color:' + recColor + ';font-weight:600">' + rec + '</td>';
      h += '</tr>';
    }
    h += '</tbody></table>';
    h += '</div>';

    // Typical exclusions
    h += '<div class="ic-panel">';
    h += '<div class="ic-panel-title">Common Policy Exclusions to Review</div>';
    var exclusions = [
      { item: 'Acts of war / nation-state attacks', risk: 'HIGH', note: 'Some insurers invoke war exclusions for state-sponsored attacks' },
      { item: 'Known unpatched vulnerabilities', risk: 'HIGH', note: 'Claims denied if breach exploited a known, unpatched vulnerability' },
      { item: 'Social engineering / BEC', risk: 'MEDIUM', note: 'Often requires separate rider; may cap at $250K' },
      { item: 'Infrastructure outage costs', risk: 'MEDIUM', note: 'Business interruption from infrastructure failure often excluded' },
      { item: 'Regulatory fines in certain jurisdictions', risk: 'MEDIUM', note: 'Some jurisdictions prohibit insuring against regulatory fines' },
      { item: 'Prior acts / ongoing incidents', risk: 'LOW', note: 'Incidents that began before policy inception date' },
    ];
    for (var ex = 0; ex < exclusions.length; ex++) {
      var riskColor = exclusions[ex].risk === 'HIGH' ? '#ef4444' : exclusions[ex].risk === 'MEDIUM' ? '#f59e0b' : '#3b82f6';
      h += '<div style="padding:10px 0;border-bottom:1px solid #111820">';
      h += '<div style="display:flex;align-items:center;justify-content:space-between">';
      h += '<span style="font-size:13px;font-weight:600;color:#c8d6e5">' + exclusions[ex].item + '</span>';
      h += '<span style="font-size:10px;font-weight:700;color:' + riskColor + ';background:' + riskColor + '22;padding:2px 8px;border-radius:3px">' + exclusions[ex].risk + ' RISK</span>';
      h += '</div>';
      h += '<div style="font-size:11px;color:#667788;margin-top:4px">' + exclusions[ex].note + '</div>';
      h += '</div>';
    }
    h += '</div>';

    return h;
  }


  function renderHistorical(costs) {
    var h = '';

    h += '<div class="ic-panel">';
    h += '<div class="ic-panel-title">Historical Breach Cost Comparison</div>';
    h += '<p style="font-size:12px;color:#667788;margin:0 0 16px">Your estimated cost of <span style="color:#ff5c6c;font-weight:700;font-family:monospace">' + fmt$(costs.total) + '</span> compared to notable breaches</p>';

    h += '<table class="ic-table">';
    h += '<thead><tr><th>Organization</th><th>Year</th><th>Records</th><th>Total Cost</th><th>Cost/Record</th><th>Sector</th><th>Attack Vector</th></tr></thead>';
    h += '<tbody>';

    // Add user's scenario
    h += '<tr style="background:#00e5ff08;border-left:3px solid #00e5ff">';
    h += '<td style="font-weight:700;color:#00e5ff">YOUR SCENARIO</td>';
    h += '<td>2026</td>';
    h += '<td class="mono">' + fmtN(costs.records) + '</td>';
    h += '<td class="mono" style="color:#ff5c6c;font-weight:700">' + fmt$(costs.total) + '</td>';
    h += '<td class="mono">' + fmt$(costs.perRecord) + '</td>';
    h += '<td>' + esc(costs.sector.name) + '</td>';
    h += '<td>' + esc(costs.vector.name) + '</td>';
    h += '</tr>';

    // Sort by total cost descending
    var sorted = HISTORICAL_BREACHES.slice().sort(function(a, b) { return b.totalCost - a.totalCost; });
    for (var hb = 0; hb < sorted.length; hb++) {
      var breach = sorted[hb];
      var perRec = breach.records > 0 ? breach.totalCost / breach.records : 0;
      h += '<tr>';
      h += '<td style="font-weight:600;color:#c8d6e5">' + esc(breach.name) + '</td>';
      h += '<td>' + breach.year + '</td>';
      h += '<td class="mono">' + (breach.records > 0 ? fmtN(breach.records) : 'N/A') + '</td>';
      h += '<td class="mono" style="font-weight:700">' + fmt$(breach.totalCost) + '</td>';
      h += '<td class="mono">' + (perRec > 0 ? fmt$(perRec) : 'N/A') + '</td>';
      h += '<td>' + esc(breach.sector) + '</td>';
      h += '<td style="font-size:11px">' + esc(breach.vector) + '</td>';
      h += '</tr>';
    }
    h += '</tbody></table>';
    h += '</div>';

    // Cost per record comparison
    h += '<div class="ic-panel">';
    h += '<div class="ic-panel-title">Cost Per Record by Sector (IBM 2024)</div>';
    var maxPR = 0;
    for (var sp = 0; sp < SECTORS.length; sp++) { if (SECTORS[sp].perRecord > maxPR) maxPR = SECTORS[sp].perRecord; }
    for (var sb = 0; sb < SECTORS.length; sb++) {
      var isActive = SECTORS[sb].id === state.sectorId;
      var pctWidth = Math.round(SECTORS[sb].perRecord / maxPR * 100);
      h += '<div class="ic-bar-row">';
      h += '<div class="ic-bar-header"><span class="ic-bar-name" style="' + (isActive ? 'color:#00e5ff;font-weight:700' : '') + '">' + esc(SECTORS[sb].name) + (isActive ? ' ←' : '') + '</span><span class="ic-bar-val" style="' + (isActive ? 'color:#00e5ff' : '') + '">' + fmt$(SECTORS[sb].perRecord) + '</span></div>';
      h += '<div class="ic-bar-track"><div class="ic-bar-fill ' + (isActive ? 'cyan' : 'blue') + '" style="width:' + pctWidth + '%"></div></div>';
      h += '</div>';
    }
    h += '</div>';

    return h;
  }


  function renderReport(costs) {
    var h = '';
    var sector = costs.sector;
    var vector = costs.vector;
    var now = new Date().toISOString().split('T')[0];

    h += '<div class="ic-panel">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">';
    h += '<div class="ic-panel-title" style="margin:0;border:0;padding:0">Executive Incident Cost Report</div>';
    h += '<button class="ic-btn" id="ic-copy-report">Copy Report</button>';
    h += '</div>';

    var report = '';
    report += '═══════════════════════════════════════════════════════════════\n';
    report += '  CYBER INCIDENT COST ASSESSMENT — EXECUTIVE SUMMARY\n';
    report += '  Generated: ' + now + '\n';
    report += '  Methodology: IBM/Ponemon Cost of Data Breach 2024\n';
    report += '═══════════════════════════════════════════════════════════════\n\n';

    report += 'BOTTOM LINE\n';
    report += '───────────\n';
    report += 'A data breach affecting ' + fmtN(costs.records) + ' records in the ' + sector.name + '\n';
    report += 'sector via ' + vector.name.toLowerCase() + ' is estimated to cost:\n\n';
    report += '  TOTAL ESTIMATED COST: ' + fmt$(costs.total) + '\n';
    report += '  Confidence range:     ' + fmt$(costs.confidenceLow) + ' — ' + fmt$(costs.confidenceHigh) + '\n';
    report += '  Cost per record:      ' + fmt$(costs.perRecord) + '\n\n';

    report += 'COST BREAKDOWN\n';
    report += '──────────────\n';
    report += '  Lost Business Impact:     ' + fmt$(costs.lostBusiness) + ' (38%)\n';
    report += '  Detection & Escalation:   ' + fmt$(costs.detection) + ' (29%)\n';
    report += '  Post-Breach Response:     ' + fmt$(costs.postBreach) + ' (27%)\n';
    report += '  Notification:             ' + fmt$(costs.notification) + ' (6%)\n';
    report += '  Regulatory Fines:         ' + fmt$(costs.fines) + '\n\n';

    report += 'BREACH LIFECYCLE\n';
    report += '────────────────\n';
    report += '  Time to identify: ' + state.mtti + ' days (industry avg: 204)\n';
    report += '  Time to contain:  ' + state.mttc + ' days (industry avg: 73)\n';
    report += '  Total lifecycle:  ' + (state.mtti + state.mttc) + ' days\n';
    var lifecycleSavings = (state.mtti + state.mttc) < 200 ? 'Detecting in under 200 days reduces cost by ~23%.' : 'Reducing lifecycle below 200 days could save ~23%.';
    report += '  Note: ' + lifecycleSavings + '\n\n';

    if (costs.activeMitigators.length > 0) {
      report += 'ACTIVE COST MITIGATORS\n';
      report += '──────────────────────\n';
      for (var mm = 0; mm < costs.activeMitigators.length; mm++) {
        report += '  - ' + costs.activeMitigators[mm].name + ': -' + fmt$(costs.activeMitigators[mm].savings) + '\n';
      }
      report += '  Total savings: -' + fmt$(costs.mitigatorTotal) + '\n\n';
    }

    report += 'TOP 3 COST REDUCTION RECOMMENDATIONS\n';
    report += '─────────────────────────────────────\n';
    report += '  1. Deploy AI & automation in security operations\n';
    report += '     Potential savings: $1.76M | ROI: 300-500%\n\n';
    report += '  2. Reduce breach lifecycle below 200 days\n';
    report += '     Potential savings: ~23% of total cost\n';
    report += '     Actions: SIEM tuning, EDR deployment, regular tabletop exercises\n\n';
    report += '  3. Establish incident response retainer with external firm\n';
    report += '     Potential savings: $232K | ROI: 150-200%\n';
    report += '     Actions: Negotiate retainer with IR firm, update runbooks\n\n';

    report += '═══════════════════════════════════════════════════════════════\n';
    report += '  Disclaimer: Estimates based on industry averages and the IBM\n';
    report += '  Cost of Data Breach Report 2024 methodology. Actual costs may\n';
    report += '  vary based on specific circumstances, jurisdiction, and response.\n';
    report += '═══════════════════════════════════════════════════════════════\n';

    h += '<pre style="font-family:ui-monospace,monospace;font-size:12px;line-height:1.6;white-space:pre-wrap;color:#c8d6e5;background:#0a0e14;border:1px solid #1a2332;border-radius:8px;padding:20px;overflow-x:auto" id="ic-report-text">' + esc(report) + '</pre>';
    h += '</div>';

    return h;
  }


  function wireEvents() {
    var wrap = container.querySelector('.ic-wrap');
    if (!wrap) return;

    // Tab switching
    wrap.querySelectorAll('.ic-tab').forEach(function(tab) {
      tab.addEventListener('click', function() {
        state.activeTab = this.dataset.tab;
        render();
      });
    });

    // Sector
    var sectorEl = wrap.querySelector('#ic-sector');
    if (sectorEl) sectorEl.addEventListener('change', function() { state.sectorId = this.value; render(); });

    // Vector
    var vectorEl = wrap.querySelector('#ic-vector');
    if (vectorEl) vectorEl.addEventListener('change', function() { state.vectorId = this.value; render(); });

    // Records
    var recordsEl = wrap.querySelector('#ic-records');
    if (recordsEl) recordsEl.addEventListener('input', function() { state.records = parseInt(this.value); render(); });

    // Data types
    wrap.querySelectorAll('[data-dtype]').forEach(function(cb) {
      cb.addEventListener('change', function() {
        var dt = this.dataset.dtype;
        var idx = state.dataTypes.indexOf(dt);
        if (this.checked && idx < 0) state.dataTypes.push(dt);
        else if (!this.checked && idx >= 0) state.dataTypes.splice(idx, 1);
        render();
      });
    });

    // MTTI
    var mttiEl = wrap.querySelector('#ic-mtti');
    if (mttiEl) mttiEl.addEventListener('input', function() { state.mtti = parseInt(this.value); render(); });

    // MTTC
    var mttcEl = wrap.querySelector('#ic-mttc');
    if (mttcEl) mttcEl.addEventListener('input', function() { state.mttc = parseInt(this.value); render(); });

    // Revenue
    var revEl = wrap.querySelector('#ic-revenue');
    if (revEl) revEl.addEventListener('change', function() {
      var val = this.value.replace(/[^0-9]/g, '');
      state.revenue = parseInt(val) || 0;
      render();
    });

    // GDPR toggle
    var gdprEl = wrap.querySelector('#ic-gdpr');
    if (gdprEl) gdprEl.addEventListener('click', function() { state.gdprApplicable = !state.gdprApplicable; render(); });

    // Main toggles
    wrap.querySelectorAll('[data-toggle]').forEach(function(el) {
      el.addEventListener('click', function() {
        var key = this.dataset.toggle;
        state[key] = !state[key];
        render();
      });
    });

    // Amplifier toggles
    wrap.querySelectorAll('[data-amplifier]').forEach(function(el) {
      el.addEventListener('click', function() {
        var id = this.dataset.amplifier;
        var idx = state.amplifiers.indexOf(id);
        if (idx >= 0) state.amplifiers.splice(idx, 1);
        else state.amplifiers.push(id);
        render();
      });
    });

    // Mitigator toggles
    wrap.querySelectorAll('[data-mitigator]').forEach(function(el) {
      el.addEventListener('click', function() {
        var id = this.dataset.mitigator;
        var idx = state.mitigators.indexOf(id);
        if (idx >= 0) state.mitigators.splice(idx, 1);
        else state.mitigators.push(id);
        render();
      });
    });

    // Insurance tier
    var insEl = wrap.querySelector('#ic-ins-tier');
    if (insEl) insEl.addEventListener('change', function() { state.insuranceTier = parseInt(this.value); render(); });

    // Copy report
    var copyBtn = wrap.querySelector('#ic-copy-report');
    if (copyBtn) copyBtn.addEventListener('click', function() {
      var reportText = wrap.querySelector('#ic-report-text');
      if (reportText) {
        navigator.clipboard.writeText(reportText.textContent).then(function() {
          copyBtn.textContent = 'Copied!';
          setTimeout(function() { copyBtn.textContent = 'Copy Report'; }, 2000);
        });
      }
    });
  }

  render();
}
