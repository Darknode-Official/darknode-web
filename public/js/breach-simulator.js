// Breach Impact Simulator — What Happens After You're Hacked
// Simulates the full business, legal, and financial aftermath of a cyber breach.
// Copyright (c) 2026 Darknode-Official. All rights reserved.

const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// ============================================================================
// BREACH TYPE DATABASE
// ============================================================================
const BREACH_TYPES = [
  { id: 'ransomware', name: 'Ransomware', desc: 'Attacker encrypts systems and demands ransom. May include data theft (double extortion).', avgCost: 5130000, downtimeDays: 22, recoveryWeeks: 8, ransomProbability: 0.6, avgRansom: 812000 },
  { id: 'data_theft', name: 'Data Theft / Exfiltration', desc: 'Attacker steals sensitive data without encryption. Often discovered weeks or months later.', avgCost: 4450000, downtimeDays: 3, recoveryWeeks: 12, ransomProbability: 0, avgRansom: 0 },
  { id: 'insider', name: 'Insider Threat', desc: 'Employee or contractor steals data or sabotages systems intentionally.', avgCost: 4900000, downtimeDays: 5, recoveryWeeks: 10, ransomProbability: 0, avgRansom: 0 },
  { id: 'supply_chain', name: 'Supply Chain Compromise', desc: 'Attacker compromises a vendor or supplier to reach your organization indirectly.', avgCost: 4760000, downtimeDays: 7, recoveryWeeks: 14, ransomProbability: 0.2, avgRansom: 500000 },
  { id: 'apt', name: 'Nation-State APT', desc: 'Advanced persistent threat from a state-sponsored actor. Long dwell time, targeted objectives.', avgCost: 6200000, downtimeDays: 2, recoveryWeeks: 20, ransomProbability: 0, avgRansom: 0 },
  { id: 'hacktivism', name: 'Hacktivism / Defacement', desc: 'Politically motivated attack. Public defacement, data leaks, or DDoS.', avgCost: 1800000, downtimeDays: 3, recoveryWeeks: 4, ransomProbability: 0, avgRansom: 0 },
  { id: 'credential_stuffing', name: 'Credential Stuffing', desc: 'Automated login attempts using leaked username/password pairs from other breaches.', avgCost: 3200000, downtimeDays: 1, recoveryWeeks: 6, ransomProbability: 0, avgRansom: 0 },
  { id: 'cloud_misconfig', name: 'Cloud Misconfiguration', desc: 'Data exposed via misconfigured S3 bucket, database, or cloud service.', avgCost: 4140000, downtimeDays: 0.5, recoveryWeeks: 5, ransomProbability: 0, avgRansom: 0 },
];

// ============================================================================
// INDUSTRY DATA
// ============================================================================
const INDUSTRY_DATA = {
  healthcare: { name: 'Healthcare', costMultiplier: 2.45, regs: ['HIPAA', 'HITECH', 'State breach notification', 'HHS OCR'], sensitivity: 'PHI is among the most regulated data types', fineRange: '$100-$50,000 per violation (HIPAA), up to $1.5M per category', notificationDays: 60, perRecordCost: 408, avgRecords: 50000 },
  finance: { name: 'Finance / Banking', costMultiplier: 1.37, regs: ['GLBA', 'SOX', 'PCI DSS', 'SEC', 'FINRA', 'State regulators', 'NYDFS'], sensitivity: 'Financial data requires immediate disclosure to regulators', fineRange: 'PCI: $5K-$100K/mo, SEC: up to $2M+, NYDFS: $250K+', notificationDays: 3, perRecordCost: 312, avgRecords: 100000 },
  tech: { name: 'Technology', costMultiplier: 1.22, regs: ['GDPR', 'CCPA/CPRA', 'State breach notification', 'FTC Act'], sensitivity: 'Customer data and IP are primary targets', fineRange: 'GDPR: up to 4% annual revenue, CCPA: $2,500-$7,500 per violation', notificationDays: 72, perRecordCost: 188, avgRecords: 500000 },
  government: { name: 'Government', costMultiplier: 0.61, regs: ['FISMA', 'FedRAMP', 'CISA reporting', 'State laws'], sensitivity: 'Government data may involve national security implications', fineRange: 'Administrative penalties, clearance revocations, contract termination', notificationDays: 1, perRecordCost: 171, avgRecords: 200000 },
  education: { name: 'Education', costMultiplier: 0.82, regs: ['FERPA', 'State breach notification', 'COPPA (if minors)'], sensitivity: 'Student records are protected under FERPA', fineRange: 'Loss of federal funding eligibility, state penalties', notificationDays: 30, perRecordCost: 142, avgRecords: 75000 },
  retail: { name: 'Retail', costMultiplier: 0.78, regs: ['PCI DSS', 'CCPA/CPRA', 'State breach notification', 'FTC Act'], sensitivity: 'Payment card data requires PCI DSS compliance', fineRange: 'PCI: $5K-$100K/mo, card brand fines up to $500K per incident', notificationDays: 30, perRecordCost: 166, avgRecords: 250000 },
  energy: { name: 'Energy / Utilities', costMultiplier: 1.07, regs: ['NERC CIP', 'TSA Security Directives', 'State PUC', 'CISA'], sensitivity: 'Critical infrastructure — potential physical safety impact', fineRange: 'NERC CIP: up to $1M/day per violation', notificationDays: 1, perRecordCost: 198, avgRecords: 30000 },
  manufacturing: { name: 'Manufacturing', costMultiplier: 1.06, regs: ['State breach notification', 'GDPR (if EU)', 'Industry-specific'], sensitivity: 'Trade secrets and operational technology at risk', fineRange: 'Varies by jurisdiction', notificationDays: 30, perRecordCost: 172, avgRecords: 40000 },
};

// ============================================================================
// COMPANY SIZE MULTIPLIERS
// ============================================================================
const SIZE_DATA = {
  startup: { name: 'Startup (<50)', multiplier: 0.4, revenue: 2000000, downtimeCostPerHour: 2000, recoveryMultiplier: 0.5, survivalRisk: 'HIGH — 60% of small businesses close within 6 months of a breach' },
  small: { name: 'Small (50-500)', multiplier: 0.7, revenue: 20000000, downtimeCostPerHour: 8000, recoveryMultiplier: 0.7, survivalRisk: 'ELEVATED — significant financial strain likely' },
  medium: { name: 'Medium (500-5000)', multiplier: 1.0, revenue: 200000000, downtimeCostPerHour: 50000, recoveryMultiplier: 1.0, survivalRisk: 'MODERATE — substantial but survivable with proper response' },
  enterprise: { name: 'Enterprise (5000+)', multiplier: 1.5, revenue: 2000000000, downtimeCostPerHour: 300000, recoveryMultiplier: 1.3, survivalRisk: 'LOW — resources to recover, but reputation and stock price impact' },
};

// ============================================================================
// HISTORICAL BREACHES FOR COMPARISON
// ============================================================================
const HISTORICAL_BREACHES = [
  { name: 'Equifax (2017)', type: 'data_theft', industry: 'finance', records: 147000000, cost: 1400000000, details: 'Unpatched Apache Struts vulnerability. 147M records. $1.4B total cost including $700M settlement.' },
  { name: 'Marriott (2018)', type: 'apt', industry: 'retail', records: 500000000, cost: 124000000, details: 'APT in Starwood systems for 4 years before discovery. 500M guest records. $124M fine (GDPR + ICO).' },
  { name: 'Capital One (2019)', type: 'cloud_misconfig', industry: 'finance', records: 106000000, cost: 190000000, details: 'Misconfigured WAF on AWS allowed SSRF to IMDS. 106M records. $190M settlement.' },
  { name: 'SolarWinds (2020)', type: 'supply_chain', industry: 'tech', records: 0, cost: 100000000, details: 'Supply chain attack via Orion platform update. 18,000 organizations affected. Nation-state (APT29).' },
  { name: 'Colonial Pipeline (2021)', type: 'ransomware', industry: 'energy', records: 0, cost: 15000000, details: 'DarkSide ransomware. $4.4M ransom paid. 6-day shutdown of largest US fuel pipeline. $15M+ total costs.' },
  { name: 'Change Healthcare (2024)', type: 'ransomware', industry: 'healthcare', records: 100000000, cost: 2450000000, details: 'BlackCat/ALPHV ransomware. $22M ransom paid. Disrupted healthcare billing nationwide for weeks. 100M records.' },
  { name: 'MOVEit (2023)', type: 'supply_chain', industry: 'tech', records: 77000000, cost: 500000000, details: 'Cl0p exploited MOVEit Transfer zero-day. 2,700+ organizations affected. Mass data theft without encryption.' },
  { name: 'MGM Resorts (2023)', type: 'credential_stuffing', industry: 'retail', records: 10000000, cost: 110000000, details: 'Scattered Spider social engineered help desk. 10-day outage. $110M+ impact including lost revenue.' },
  { name: 'T-Mobile (2023)', type: 'data_theft', industry: 'tech', records: 37000000, cost: 350000000, details: 'API exploitation. 37M customer records. $350M class action settlement. Fifth major breach since 2018.' },
  { name: 'Uber (2022)', type: 'credential_stuffing', industry: 'tech', records: 57000000, cost: 148000000, details: 'MFA fatigue attack. Attacker accessed Slack, HackerOne reports, cloud systems. Previous breach covered up (CISO convicted).' },
];

// ============================================================================
// INCIDENT TIMELINE GENERATOR
// ============================================================================
function generateTimeline(breachType, industry, size) {
  var bt = BREACH_TYPES.find(function(b) { return b.id === breachType; }) || BREACH_TYPES[0];
  var ind = INDUSTRY_DATA[industry] || INDUSTRY_DATA.tech;
  var sz = SIZE_DATA[size] || SIZE_DATA.medium;
  var timeline = [];

  // Discovery
  var discoveryMethods = {
    ransomware: 'Ransom note displayed on encrypted systems. All file extensions changed to .locked.',
    data_theft: 'Unusual data transfer detected by network monitoring (or discovered via dark web listing 47 days later).',
    insider: 'Anomalous file access patterns flagged by DLP (or discovered when data appears in competitor product).',
    supply_chain: 'FBI/CISA notification that vendor software was compromised. Your organization is on the affected list.',
    apt: 'Third-party threat intelligence firm notifies you of C2 beacons originating from your IP range.',
    hacktivism: 'Social media posts from hacktivist group claiming responsibility. Website defaced.',
    credential_stuffing: 'Customer reports unauthorized account access. Investigation reveals mass credential testing.',
    cloud_misconfig: 'Security researcher or journalist contacts you — your S3 bucket with customer data is publicly listed.',
  };

  timeline.push({ time: 'Hour 0', phase: 'Discovery', title: 'Breach Discovered', detail: discoveryMethods[breachType] || 'Anomaly detected by security monitoring.', stakeholders: ['IT Security Team', 'SOC Analyst'], urgency: 'CRITICAL' });

  timeline.push({ time: 'Hour 0-1', phase: 'Initial Response', title: 'Incident Commander Assigned', detail: 'CISO or senior security leader takes command. War room established. Initial scope assessment begins.', stakeholders: ['CISO', 'IT Director', 'SOC Team'], urgency: 'CRITICAL' });

  timeline.push({ time: 'Hour 1-2', phase: 'Escalation', title: 'Executive Notification', detail: 'CEO, General Counsel, and Board Chair notified. External IR retainer firm engaged. Insurance carrier notified.', stakeholders: ['CEO', 'General Counsel', 'Board Chair', 'Insurance Broker'], urgency: 'CRITICAL' });

  timeline.push({ time: 'Hour 2-4', phase: 'Triage', title: 'Containment Decisions', detail: 'Decision to isolate affected systems. Network segmentation activated. VPN access suspended. Critical systems assessed.', stakeholders: ['IT Operations', 'Network Team', 'IR Team'], urgency: 'CRITICAL' });

  if (breachType === 'ransomware') {
    timeline.push({ time: 'Hour 4-8', phase: 'Containment', title: 'Encryption Spread Assessment', detail: 'Determine which systems are encrypted. Check if backups are compromised. Assess business continuity.', stakeholders: ['IR Team', 'Backup Team', 'Business Continuity'], urgency: 'CRITICAL' });
    timeline.push({ time: 'Hour 8-24', phase: 'Decision', title: 'Ransom Payment Decision', detail: 'Board-level decision on whether to pay ransom ($' + bt.avgRansom.toLocaleString() + ' average). FBI advises against payment. Insurance may cover portion.', stakeholders: ['Board of Directors', 'FBI', 'Legal Counsel', 'Insurance'], urgency: 'CRITICAL' });
  }

  timeline.push({ time: 'Day 1-3', phase: 'Investigation', title: 'Forensic Investigation', detail: 'External forensics firm analyzes logs, memory dumps, and disk images. Root cause identified. Full scope of compromise determined.', stakeholders: ['External Forensics Firm', 'IR Team', 'Legal (privilege)'], urgency: 'HIGH' });

  timeline.push({ time: 'Day 3-5', phase: 'Scope', title: 'Data Impact Assessment', detail: 'Determine exactly what data was accessed/stolen. Classify affected records by type (PII, PHI, financial, credentials).', stakeholders: ['Forensics', 'Legal', 'Privacy Officer', 'Data Governance'], urgency: 'HIGH' });

  timeline.push({ time: 'Day ' + ind.notificationDays + ' (deadline)', phase: 'Notification', title: 'Regulatory Notification', detail: 'Legal obligation to notify regulators: ' + ind.regs.join(', ') + '. Notification deadline: ' + ind.notificationDays + ' days from discovery.', stakeholders: ['Legal', 'Privacy Officer', 'Regulatory Affairs'], urgency: 'CRITICAL' });

  timeline.push({ time: 'Week 1-2', phase: 'Notification', title: 'Individual Notification', detail: 'Notify affected individuals via mail/email. Offer credit monitoring ($10-30/person). Set up call center for inquiries.', stakeholders: ['Legal', 'Communications', 'Customer Service', 'Vendor (notification service)'], urgency: 'HIGH' });

  timeline.push({ time: 'Week 1-4', phase: 'Recovery', title: 'System Recovery', detail: 'Rebuild compromised systems from clean images. Reset all credentials. Patch vulnerabilities. Enhanced monitoring deployed.', stakeholders: ['IT Operations', 'Security Team', 'Vendors'], urgency: 'HIGH' });

  timeline.push({ time: 'Month 1-2', phase: 'Remediation', title: 'Security Improvements', detail: 'Implement improvements identified during investigation. Deploy additional controls. Conduct organization-wide password reset.', stakeholders: ['CISO', 'IT', 'All Employees'], urgency: 'MEDIUM' });

  timeline.push({ time: 'Month 2-6', phase: 'Aftermath', title: 'Legal & Regulatory Response', detail: 'Respond to regulatory investigations. Handle class action lawsuits. Manage media inquiries. Assess long-term customer impact.', stakeholders: ['Legal', 'PR/Communications', 'Executive Team'], urgency: 'MEDIUM' });

  timeline.push({ time: 'Month 6-12', phase: 'Recovery', title: 'Long-Term Recovery', detail: 'Complete security transformation. Rebuild customer trust. Assess stock price / revenue impact. Update insurance. Executive accountability.', stakeholders: ['Board', 'Executive Team', 'All Functions'], urgency: 'LOW' });

  return timeline;
}

// ============================================================================
// FINANCIAL IMPACT CALCULATOR
// ============================================================================
function calculateFinancialImpact(breachType, industry, size, recordCount) {
  var bt = BREACH_TYPES.find(function(b) { return b.id === breachType; }) || BREACH_TYPES[0];
  var ind = INDUSTRY_DATA[industry] || INDUSTRY_DATA.tech;
  var sz = SIZE_DATA[size] || SIZE_DATA.medium;
  var records = recordCount || ind.avgRecords;

  var directCosts = {};
  directCosts.forensics = Math.round(400 * 24 * 10 * sz.recoveryMultiplier); // $400/hr * 24hr/day * 10 days
  directCosts.legal = Math.round(1000 * 8 * 30 * sz.recoveryMultiplier); // $1000/hr * 8hr/day * 30 days
  directCosts.notification = records * 2; // $2 per record average
  directCosts.creditMonitoring = records * 15; // $15/person * 1 year
  directCosts.ransom = bt.ransomProbability > 0 ? Math.round(bt.avgRansom * bt.ransomProbability) : 0;
  directCosts.callCenter = Math.round(records * 0.5); // $0.50 per affected individual
  directCosts.total = Object.values(directCosts).reduce(function(a, b) { return a + b; }, 0);

  var indirectCosts = {};
  indirectCosts.downtime = Math.round(bt.downtimeDays * 24 * sz.downtimeCostPerHour);
  indirectCosts.customerChurn = Math.round(sz.revenue * 0.06); // 6% avg customer churn
  indirectCosts.stockDrop = sz.multiplier >= 1.5 ? Math.round(sz.revenue * 0.04) : 0; // 4% market cap for public companies
  indirectCosts.insurancePremium = Math.round(sz.revenue * 0.003); // 30bps premium increase
  indirectCosts.securitySpend = Math.round(sz.revenue * 0.005); // increased security budget
  indirectCosts.reputationDamage = Math.round(sz.revenue * 0.03); // 3% long-term revenue impact
  indirectCosts.total = Object.values(indirectCosts).reduce(function(a, b) { return a + b; }, 0);

  var regulatoryFines = {};
  if (ind.regs.indexOf('GDPR') !== -1) regulatoryFines.GDPR = Math.round(Math.min(sz.revenue * 0.04, 20000000));
  if (ind.regs.indexOf('HIPAA') !== -1) regulatoryFines.HIPAA = Math.min(records * 50, 1500000);
  if (ind.regs.indexOf('PCI DSS') !== -1) regulatoryFines.PCI = Math.min(100000 * 6, 600000);
  if (ind.regs.indexOf('CCPA/CPRA') !== -1 || ind.regs.indexOf('CCPA') !== -1) regulatoryFines.CCPA = Math.min(records * 7500, 50000000);
  if (ind.regs.indexOf('SOX') !== -1) regulatoryFines.SOX = 1000000;
  if (ind.regs.indexOf('NERC CIP') !== -1) regulatoryFines.NERC = Math.min(1000000 * 30, 30000000);
  regulatoryFines.total = Object.values(regulatoryFines).reduce(function(a, b) { return a + b; }, 0);

  var totalCost = directCosts.total + indirectCosts.total + regulatoryFines.total;

  return { directCosts: directCosts, indirectCosts: indirectCosts, regulatoryFines: regulatoryFines, totalCost: totalCost, perRecord: Math.round(totalCost / Math.max(records, 1)), downtimeDays: bt.downtimeDays, recoveryWeeks: bt.recoveryWeeks, survivalRisk: sz.survivalRisk, records: records };
}

// ============================================================================
// RENDER
// ============================================================================
export function renderBreachSimulator(main) {
  var activeTab = 'scenario';
  var simConfig = { breachType: 'ransomware', industry: 'tech', size: 'medium', records: 0, dataTypes: [] };
  var simResults = null;
  var timeline = null;
  var financials = null;

  function render() {
    main.innerHTML =
      '<div class="tool-intro">' +
        '<h2>Breach Simulator</h2>' +
        '<p>Walks you through real-world data breach scenarios step by step. Learn how attacks happen and how to defend against them.</p>' +
        '<div class="tool-steps">' +
          '<div class="tool-step"><span class="step-num">1</span><div class="step-text"><strong>Pick a scenario</strong>Choose breach type, industry, and company size</div></div>' +
          '<div class="tool-step"><span class="step-num">2</span><div class="step-text"><strong>Follow the attack chain</strong>See the timeline, financial impact, and regulatory response</div></div>' +
          '<div class="tool-step"><span class="step-num">3</span><div class="step-text"><strong>Review defense strategies</strong>Learn what could have prevented the breach</div></div>' +
        '</div>' +
      '</div>' +
      '<style>' +
      '.bs-header { display:flex; align-items:center; gap:16px; padding:16px 0; border-bottom:2px solid #ff1744; }' +
      '.bs-title { font-size:1.5rem; font-weight:800; color:#ff1744; margin:0; letter-spacing:.05em; }' +
      '.bs-tabs { display:flex; gap:2px; overflow-x:auto; padding:12px 0 0; }' +
      '.bs-tab { background:transparent; border:none; border-bottom:2px solid transparent; color:var(--mut); padding:10px 16px; font-size:.75rem; font-weight:600; letter-spacing:.04em; text-transform:uppercase; cursor:pointer; white-space:nowrap; font-family:inherit; }' +
      '.bs-tab:hover { color:var(--txt); }' +
      '.bs-tab.active { color:#ff1744; border-bottom-color:#ff1744; }' +
      '.bs-card { background:var(--card); border:1px solid var(--line); border-radius:6px; padding:16px; margin-bottom:12px; }' +
      '.bs-phase { border-left:3px solid; padding:12px 16px; margin-bottom:8px; background:var(--card); border-radius:0 4px 4px 0; }' +
      '.bs-cost-row { display:flex; justify-content:space-between; padding:8px 0; border-bottom:1px solid var(--line); font-size:.82rem; }' +
      '.bs-cost-row:last-child { border-bottom:none; }' +
      '.bs-metric { background:var(--card); border:1px solid var(--line); border-radius:6px; padding:14px 20px; text-align:center; }' +
      '.bs-metric-val { font-size:1.6rem; font-weight:800; font-variant-numeric:tabular-nums; }' +
      '.bs-metric-label { font-size:.7rem; color:var(--mut); text-transform:uppercase; letter-spacing:.04em; margin-top:2px; }' +
      '.bs-select { background:var(--card); color:var(--txt); border:1px solid var(--line); padding:8px 12px; border-radius:4px; font-size:.8rem; width:100%; font-family:inherit; }' +
      '.bs-btn { background:#ff1744; color:#fff; border:none; padding:12px 28px; font-size:.85rem; font-weight:700; border-radius:4px; cursor:pointer; letter-spacing:.04em; text-transform:uppercase; font-family:inherit; }' +
      '.bs-breach-card { background:var(--card); border:1px solid var(--line); border-radius:6px; padding:14px; cursor:pointer; transition:all .15s; }' +
      '.bs-breach-card:hover { border-color:#ff1744; }' +
      '.bs-breach-card.selected { border-color:#ff1744; background:rgba(255,23,68,0.06); }' +
      '.bs-hist { background:var(--card); border:1px solid var(--line); border-radius:4px; padding:12px; margin-bottom:8px; font-size:.82rem; }' +
      '</style>' +
      '<div>' +
        '<div class="bs-header">' +
          '<h1 class="bs-title">BREACH SIMULATOR</h1>' +
          '<span style="color:var(--mut);font-size:.75rem">Post-Breach Impact Analysis</span>' +
        '</div>' +
        '<div class="bs-tabs">' +
          '<button class="bs-tab' + (activeTab === 'scenario' ? ' active' : '') + '" data-tab="scenario">Scenario</button>' +
          '<button class="bs-tab' + (activeTab === 'timeline' ? ' active' : '') + '" data-tab="timeline">Incident Timeline</button>' +
          '<button class="bs-tab' + (activeTab === 'financial' ? ' active' : '') + '" data-tab="financial">Financial Impact</button>' +
          '<button class="bs-tab' + (activeTab === 'regulatory' ? ' active' : '') + '" data-tab="regulatory">Compliance</button>' +
          '<button class="bs-tab' + (activeTab === 'recovery' ? ' active' : '') + '" data-tab="recovery">Recovery Plan</button>' +
          '<button class="bs-tab' + (activeTab === 'historical' ? ' active' : '') + '" data-tab="historical">Historical Breaches</button>' +
          '<button class="bs-tab' + (activeTab === 'brief' ? ' active' : '') + '" data-tab="brief">Board Brief</button>' +
        '</div>' +
        '<div id="bs-content" style="padding:16px 0"></div>' +
      '</div>';

    main.querySelector('.bs-tabs').onclick = function(e) {
      var b = e.target.closest('.bs-tab');
      if (b) { activeTab = b.dataset.tab; render(); }
    };
    var content = main.querySelector('#bs-content');
    if (activeTab === 'scenario') renderScenarioTab(content);
    else if (activeTab === 'timeline') renderTimelineTab(content);
    else if (activeTab === 'financial') renderFinancialTab(content);
    else if (activeTab === 'regulatory') renderRegulatoryTab(content);
    else if (activeTab === 'recovery') renderRecoveryTab(content);
    else if (activeTab === 'historical') renderHistoricalTab(content);
    else if (activeTab === 'brief') renderBriefTab(content);
  }

  function runSimulation() {
    timeline = generateTimeline(simConfig.breachType, simConfig.industry, simConfig.size);
    financials = calculateFinancialImpact(simConfig.breachType, simConfig.industry, simConfig.size, simConfig.records || 0);
    simResults = { timeline: timeline, financials: financials, config: Object.assign({}, simConfig) };
  }

  function renderScenarioTab(container) {
    container.innerHTML =
      '<h2 style="font-size:1rem;margin:0 0 16px">Build Your Breach Scenario</h2>' +
      '<p class="muted" style="font-size:.82rem;margin:-12px 0 20px">Select the type of breach, your industry, and company size to see the full impact simulation.</p>' +

      '<div style="margin-bottom:16px"><label style="font-size:.82rem;font-weight:600;display:block;margin-bottom:8px">Breach Type</label>' +
      '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px">' +
        BREACH_TYPES.map(function(bt) {
          return '<div class="bs-breach-card' + (simConfig.breachType === bt.id ? ' selected' : '') + '" data-type="' + bt.id + '">' +
            '<div style="font-weight:600;margin-bottom:4px">' + esc(bt.name) + '</div>' +
            '<div style="font-size:.75rem;color:var(--mut)">' + esc(bt.desc) + '</div>' +
          '</div>';
        }).join('') +
      '</div></div>' +

      '<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:16px">' +
        '<div><label style="font-size:.82rem;font-weight:600;display:block;margin-bottom:6px">Industry</label>' +
          '<select class="bs-select" id="bs-industry">' +
            Object.keys(INDUSTRY_DATA).map(function(k) {
              return '<option value="' + k + '"' + (simConfig.industry === k ? ' selected' : '') + '>' + esc(INDUSTRY_DATA[k].name) + '</option>';
            }).join('') +
          '</select></div>' +
        '<div><label style="font-size:.82rem;font-weight:600;display:block;margin-bottom:6px">Company Size</label>' +
          '<select class="bs-select" id="bs-size">' +
            Object.keys(SIZE_DATA).map(function(k) {
              return '<option value="' + k + '"' + (simConfig.size === k ? ' selected' : '') + '>' + esc(SIZE_DATA[k].name) + '</option>';
            }).join('') +
          '</select></div>' +
        '<div><label style="font-size:.82rem;font-weight:600;display:block;margin-bottom:6px">Records Affected (0 = auto)</label>' +
          '<input type="number" class="bs-select" id="bs-records" value="' + simConfig.records + '" min="0"></div>' +
      '</div>' +

      '<button class="bs-btn" id="bs-run">Simulate Breach Impact</button>';

    container.querySelectorAll('.bs-breach-card').forEach(function(card) {
      card.onclick = function() {
        simConfig.breachType = card.dataset.type;
        container.querySelectorAll('.bs-breach-card').forEach(function(c) { c.classList.toggle('selected', c === card); });
      };
    });

    container.querySelector('#bs-run').onclick = function() {
      simConfig.industry = container.querySelector('#bs-industry').value;
      simConfig.size = container.querySelector('#bs-size').value;
      simConfig.records = parseInt(container.querySelector('#bs-records').value) || 0;
      runSimulation();
      activeTab = 'timeline';
      render();
    };
  }

  function renderTimelineTab(container) {
    if (!simResults) { container.innerHTML = '<p class="muted" style="padding:40px;text-align:center">Configure and run the simulation first.</p>'; return; }
    var phaseColors = { Discovery: '#ff1744', 'Initial Response': '#ff1744', Escalation: '#ff9100', Triage: '#ff9100', Containment: '#ffd600', Decision: '#ffd600', Investigation: 'var(--acc)', Scope: 'var(--acc)', Notification: '#d500f9', Recovery: '#00e676', Remediation: '#00e676', Aftermath: 'var(--mut)' };
    var html = '<h2 style="font-size:1rem;margin:0 0 16px">Incident Timeline</h2>' +
      '<p class="muted" style="font-size:.82rem;margin:-12px 0 16px">What happens hour by hour, day by day after the breach is discovered.</p>';

    simResults.timeline.forEach(function(event) {
      var color = phaseColors[event.phase] || 'var(--acc)';
      html += '<div class="bs-phase" style="border-left-color:' + color + '">' +
        '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">' +
          '<span style="font-size:.7rem;font-weight:700;color:' + color + ';letter-spacing:.04em">' + esc(event.time) + '</span>' +
          '<span style="font-weight:600">' + esc(event.title) + '</span>' +
          '<span style="font-size:.65rem;padding:2px 6px;border-radius:3px;background:' + (event.urgency === 'CRITICAL' ? 'rgba(255,23,68,0.15);color:#ff1744' : event.urgency === 'HIGH' ? 'rgba(255,145,0,0.15);color:#ff9100' : 'rgba(0,229,255,0.15);color:var(--acc)') + '">' + esc(event.urgency) + '</span>' +
        '</div>' +
        '<div style="font-size:.82rem;color:var(--mut);margin-bottom:4px">' + esc(event.detail) + '</div>' +
        '<div style="font-size:.72rem;color:var(--acc)">Stakeholders: ' + event.stakeholders.join(', ') + '</div>' +
      '</div>';
    });
    container.innerHTML = html;
  }

  function renderFinancialTab(container) {
    if (!simResults) { container.innerHTML = '<p class="muted" style="padding:40px;text-align:center">Run the simulation first.</p>'; return; }
    var f = simResults.financials;
    var fmtM = function(n) { return '$' + (n / 1000000).toFixed(1) + 'M'; };
    var fmtK = function(n) { return n >= 1000000 ? fmtM(n) : '$' + (n / 1000).toFixed(0) + 'K'; };

    var html = '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-bottom:20px">' +
      '<div class="bs-metric"><div class="bs-metric-val" style="color:#ff1744">' + fmtM(f.totalCost) + '</div><div class="bs-metric-label">Total Estimated Cost</div></div>' +
      '<div class="bs-metric"><div class="bs-metric-val" style="color:#ff9100">' + fmtK(f.perRecord) + '</div><div class="bs-metric-label">Cost Per Record</div></div>' +
      '<div class="bs-metric"><div class="bs-metric-val" style="color:#ffd600">' + f.downtimeDays + ' days</div><div class="bs-metric-label">Downtime</div></div>' +
      '<div class="bs-metric"><div class="bs-metric-val" style="color:var(--acc)">' + f.recoveryWeeks + ' weeks</div><div class="bs-metric-label">Recovery Time</div></div>' +
      '<div class="bs-metric"><div class="bs-metric-val" style="color:var(--txt)">' + f.records.toLocaleString() + '</div><div class="bs-metric-label">Records Affected</div></div>' +
    '</div>';

    html += '<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px">';

    // Direct costs
    html += '<div class="bs-card"><h3 style="font-size:.85rem;margin:0 0 12px;color:#ff1744">Direct Costs</h3>';
    var directItems = [['Forensics Investigation', f.directCosts.forensics], ['Legal Counsel', f.directCosts.legal], ['Individual Notification', f.directCosts.notification], ['Credit Monitoring', f.directCosts.creditMonitoring], ['Ransom Payment (prob-weighted)', f.directCosts.ransom], ['Call Center', f.directCosts.callCenter]];
    directItems.forEach(function(item) {
      if (item[1] > 0) html += '<div class="bs-cost-row"><span>' + item[0] + '</span><span style="font-weight:600">' + fmtK(item[1]) + '</span></div>';
    });
    html += '<div class="bs-cost-row" style="font-weight:700;color:#ff1744"><span>Total Direct</span><span>' + fmtK(f.directCosts.total) + '</span></div></div>';

    // Indirect costs
    html += '<div class="bs-card"><h3 style="font-size:.85rem;margin:0 0 12px;color:#ff9100">Indirect Costs</h3>';
    var indirectItems = [['Business Downtime', f.indirectCosts.downtime], ['Customer Churn', f.indirectCosts.customerChurn], ['Stock Price Impact', f.indirectCosts.stockDrop], ['Insurance Premium Increase', f.indirectCosts.insurancePremium], ['Increased Security Spend', f.indirectCosts.securitySpend], ['Reputation Damage', f.indirectCosts.reputationDamage]];
    indirectItems.forEach(function(item) {
      if (item[1] > 0) html += '<div class="bs-cost-row"><span>' + item[0] + '</span><span style="font-weight:600">' + fmtK(item[1]) + '</span></div>';
    });
    html += '<div class="bs-cost-row" style="font-weight:700;color:#ff9100"><span>Total Indirect</span><span>' + fmtK(f.indirectCosts.total) + '</span></div></div>';

    // Regulatory fines
    html += '<div class="bs-card"><h3 style="font-size:.85rem;margin:0 0 12px;color:#d500f9">Regulatory Fines</h3>';
    Object.keys(f.regulatoryFines).forEach(function(reg) {
      if (reg !== 'total' && f.regulatoryFines[reg] > 0) html += '<div class="bs-cost-row"><span>' + reg + '</span><span style="font-weight:600">' + fmtK(f.regulatoryFines[reg]) + '</span></div>';
    });
    html += '<div class="bs-cost-row" style="font-weight:700;color:#d500f9"><span>Total Fines</span><span>' + fmtK(f.regulatoryFines.total) + '</span></div></div>';

    html += '</div>';
    html += '<div class="bs-card" style="margin-top:12px;border-color:#ff1744"><div style="font-weight:700;color:#ff1744;margin-bottom:4px">Business Survival Risk</div><div style="font-size:.85rem">' + esc(f.survivalRisk) + '</div></div>';

    container.innerHTML = html;
  }

  function renderRegulatoryTab(container) {
    if (!simResults) { container.innerHTML = '<p class="muted" style="padding:40px;text-align:center">Run the simulation first.</p>'; return; }
    var ind = INDUSTRY_DATA[simResults.config.industry] || INDUSTRY_DATA.tech;
    var html = '<h2 style="font-size:1rem;margin:0 0 16px">Compliance Obligations</h2>' +
      '<p class="muted" style="font-size:.82rem;margin:-12px 0 16px">Based on your industry (' + esc(ind.name) + '), these are the regulatory requirements triggered by a breach.</p>';

    html += '<div class="bs-card"><h3 style="font-size:.85rem;margin:0 0 12px">Applicable Regulations</h3>';
    ind.regs.forEach(function(reg) { html += '<div style="padding:6px 0;border-bottom:1px solid var(--line);font-size:.85rem">' + esc(reg) + '</div>'; });
    html += '</div>';

    html += '<div class="bs-card"><h3 style="font-size:.85rem;margin:0 0 8px">Notification Deadline</h3>' +
      '<div style="font-size:1.4rem;font-weight:700;color:#ff1744">' + ind.notificationDays + ' days</div>' +
      '<div style="font-size:.8rem;color:var(--mut);margin-top:4px">from date of discovery</div></div>';

    html += '<div class="bs-card"><h3 style="font-size:.85rem;margin:0 0 8px">Potential Fine Range</h3>' +
      '<div style="font-size:.85rem">' + esc(ind.fineRange) + '</div></div>';

    html += '<div class="bs-card"><h3 style="font-size:.85rem;margin:0 0 8px">Industry Sensitivity</h3>' +
      '<div style="font-size:.85rem;color:var(--mut)">' + esc(ind.sensitivity) + '</div></div>';

    container.innerHTML = html;
  }

  function renderRecoveryTab(container) {
    if (!simResults) { container.innerHTML = '<p class="muted" style="padding:40px;text-align:center">Run the simulation first.</p>'; return; }
    var f = simResults.financials;
    var weeks = [
      { week: '1', title: 'Contain and Stabilize', tasks: ['Complete forensic investigation', 'Isolate compromised systems', 'Activate business continuity plan', 'Engage external IR and legal teams'] },
      { week: '2', title: 'Eradicate Threat', tasks: ['Remove attacker access and persistence', 'Rebuild compromised systems from clean images', 'Reset ALL credentials organization-wide', 'Patch exploited vulnerabilities'] },
      { week: '3-4', title: 'Restore Operations', tasks: ['Restore systems from verified clean backups', 'Gradually bring services back online', 'Enhanced monitoring on restored systems', 'Employee communication and training'] },
      { week: '5-8', title: 'Harden Defenses', tasks: ['Deploy additional security controls identified during investigation', 'Implement recommendations from forensic report', 'Conduct penetration test to verify fixes', 'Update incident response plan'] },
      { week: '9-' + f.recoveryWeeks, title: 'Long-Term Recovery', tasks: ['Complete regulatory and legal processes', 'Rebuild customer trust and brand reputation', 'Assess and improve security program maturity', 'Conduct tabletop exercises for future incidents'] },
    ];

    var html = '<h2 style="font-size:1rem;margin:0 0 16px">Recovery Roadmap</h2>' +
      '<p class="muted" style="font-size:.82rem;margin:-12px 0 16px">Estimated recovery time: ' + f.recoveryWeeks + ' weeks. Here is the week-by-week plan.</p>';

    weeks.forEach(function(w) {
      html += '<div class="bs-phase" style="border-left-color:var(--acc)">' +
        '<div style="font-weight:600;margin-bottom:6px">Week ' + w.week + ': ' + esc(w.title) + '</div>' +
        '<ul style="margin:0;padding-left:20px;font-size:.82rem;color:var(--mut)">' +
          w.tasks.map(function(t) { return '<li>' + esc(t) + '</li>'; }).join('') +
        '</ul></div>';
    });
    container.innerHTML = html;
  }

  function renderHistoricalTab(container) {
    var html = '<h2 style="font-size:1rem;margin:0 0 16px">Historical Breach Comparison</h2>' +
      '<p class="muted" style="font-size:.82rem;margin:-12px 0 16px">Real-world breaches for context. Compare your simulated scenario against actual incidents.</p>';

    HISTORICAL_BREACHES.forEach(function(b) {
      html += '<div class="bs-hist">' +
        '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">' +
          '<span style="font-weight:700">' + esc(b.name) + '</span>' +
          '<span style="font-size:.65rem;padding:2px 6px;border:1px solid var(--line);border-radius:3px;color:var(--acc)">' + esc(b.type.replace(/_/g, ' ')) + '</span>' +
        '</div>' +
        '<div style="display:flex;gap:16px;font-size:.78rem;color:var(--mut);margin-bottom:4px">' +
          (b.records > 0 ? '<span>Records: ' + b.records.toLocaleString() + '</span>' : '') +
          '<span>Cost: $' + (b.cost / 1000000).toFixed(0) + 'M</span>' +
        '</div>' +
        '<div style="font-size:.78rem;color:var(--mut)">' + esc(b.details) + '</div>' +
      '</div>';
    });
    container.innerHTML = html;
  }

  function renderBriefTab(container) {
    if (!simResults) { container.innerHTML = '<p class="muted" style="padding:40px;text-align:center">Run the simulation first.</p>'; return; }
    var f = simResults.financials;
    var ind = INDUSTRY_DATA[simResults.config.industry] || INDUSTRY_DATA.tech;
    var bt = BREACH_TYPES.find(function(b) { return b.id === simResults.config.breachType; }) || BREACH_TYPES[0];
    var fmtM = function(n) { return '$' + (n / 1000000).toFixed(1) + 'M'; };

    var brief = '=== BREACH IMPACT ASSESSMENT — BOARD BRIEF ===\n';
    brief += 'Date: ' + new Date().toISOString().split('T')[0] + '\n';
    brief += 'Classification: CONFIDENTIAL\n\n';
    brief += '--- SCENARIO ---\n';
    brief += 'Breach Type: ' + bt.name + '\n';
    brief += 'Industry: ' + ind.name + '\n';
    brief += 'Records Affected: ' + f.records.toLocaleString() + '\n\n';
    brief += '--- FINANCIAL IMPACT ---\n';
    brief += 'Total Estimated Cost: ' + fmtM(f.totalCost) + '\n';
    brief += '  Direct Costs: ' + fmtM(f.directCosts.total) + '\n';
    brief += '  Indirect Costs: ' + fmtM(f.indirectCosts.total) + '\n';
    brief += '  Regulatory Fines: ' + fmtM(f.regulatoryFines.total) + '\n';
    brief += 'Cost Per Record: $' + f.perRecord.toLocaleString() + '\n';
    brief += 'Business Downtime: ' + f.downtimeDays + ' days\n';
    brief += 'Recovery Timeline: ' + f.recoveryWeeks + ' weeks\n\n';
    brief += '--- REGULATORY OBLIGATIONS ---\n';
    brief += 'Applicable: ' + ind.regs.join(', ') + '\n';
    brief += 'Notification Deadline: ' + ind.notificationDays + ' days from discovery\n';
    brief += 'Fine Range: ' + ind.fineRange + '\n\n';
    brief += '--- BUSINESS SURVIVAL RISK ---\n';
    brief += f.survivalRisk + '\n\n';
    brief += '--- RECOMMENDATION ---\n';
    brief += 'Invest in prevention. The average ROI on cybersecurity spending is 5-10x based on avoided breach costs.\n';

    container.innerHTML =
      '<div style="display:flex;align-items:center;gap:8px;margin-bottom:12px">' +
        '<h2 style="font-size:1rem;margin:0;flex:1">Board Presentation Brief</h2>' +
        '<button class="btn sm" id="bs-copy">Copy to Clipboard</button>' +
      '</div>' +
      '<pre style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:16px;font-size:.78rem;white-space:pre-wrap;max-height:500px;overflow-y:auto;line-height:1.6">' + esc(brief) + '</pre>';
    container.querySelector('#bs-copy').onclick = function() {
      navigator.clipboard.writeText(brief).then(function() {
        container.querySelector('#bs-copy').textContent = 'Copied!';
        setTimeout(function() { container.querySelector('#bs-copy').textContent = 'Copy to Clipboard'; }, 1500);
      });
    };
  }

  render();
}
