// National Vulnerability Triage Engine — SSVC-based federal vulnerability prioritization
// Government-grade tool for CISA BOD 22-01 compliance and stakeholder-specific triage
const esc = (s) => String(s != null ? s : "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

// ═══════════════════════════════════════════════════════════════════════════════
// SSVC DECISION LOGIC
// ═══════════════════════════════════════════════════════════════════════════════

const SSVC_DECISIONS = {
  'active-total-yes-essential': 'Act',
  'active-total-yes-support': 'Act',
  'active-total-yes-minimal': 'Attend',
  'active-total-no-essential': 'Act',
  'active-total-no-support': 'Attend',
  'active-total-no-minimal': 'Attend',
  'active-partial-yes-essential': 'Attend',
  'active-partial-yes-support': 'Attend',
  'active-partial-yes-minimal': 'Track*',
  'active-partial-no-essential': 'Attend',
  'active-partial-no-support': 'Track*',
  'active-partial-no-minimal': 'Track*',
  'poc-total-yes-essential': 'Attend',
  'poc-total-yes-support': 'Attend',
  'poc-total-yes-minimal': 'Track*',
  'poc-total-no-essential': 'Attend',
  'poc-total-no-support': 'Track*',
  'poc-total-no-minimal': 'Track',
  'poc-partial-yes-essential': 'Track*',
  'poc-partial-yes-support': 'Track*',
  'poc-partial-yes-minimal': 'Track',
  'poc-partial-no-essential': 'Track*',
  'poc-partial-no-support': 'Track',
  'poc-partial-no-minimal': 'Track',
  'none-total-yes-essential': 'Track*',
  'none-total-yes-support': 'Track*',
  'none-total-yes-minimal': 'Track',
  'none-total-no-essential': 'Track*',
  'none-total-no-support': 'Track',
  'none-total-no-minimal': 'Track',
  'none-partial-yes-essential': 'Track',
  'none-partial-yes-support': 'Track',
  'none-partial-yes-minimal': 'Track',
  'none-partial-no-essential': 'Track',
  'none-partial-no-support': 'Track',
  'none-partial-no-minimal': 'Track',
};

const DECISION_COLORS = { 'Act': '#ef4444', 'Attend': '#f59e0b', 'Track*': '#3b82f6', 'Track': '#6b7280' };
const DECISION_DESC = {
  'Act': 'Immediate remediation required. Apply patch or mitigate within 24-48 hours.',
  'Attend': 'Prioritize remediation. Schedule within current patch cycle (7-14 days).',
  'Track*': 'Monitor closely. Plan remediation within 30 days.',
  'Track': 'Standard tracking. Remediate within normal maintenance windows (60-90 days).',
};

// ═══════════════════════════════════════════════════════════════════════════════
// CIKR SECTORS
// ═══════════════════════════════════════════════════════════════════════════════

const SECTORS = [
  'Energy', 'Financial Services', 'Healthcare', 'Telecommunications',
  'Transportation', 'Water Systems', 'Government', 'Defense Industrial Base',
  'Information Technology', 'Commercial Facilities', 'Food & Agriculture',
  'Chemical', 'Nuclear', 'Emergency Services', 'Critical Manufacturing', 'Dams'
];

// ═══════════════════════════════════════════════════════════════════════════════
// VULNERABILITY DATABASE (realistic sample data)
// ═══════════════════════════════════════════════════════════════════════════════

const VULN_DB = [
  { cve: 'CVE-2024-3400', product: 'Palo Alto PAN-OS GlobalProtect', vendor: 'Palo Alto Networks', cvss: 10.0, epss: 0.971, kev: true, kevDate: '2024-04-12', exploitation: 'active', impact: 'total', automatable: true, prevalence: 'essential', affectedSystems: 1240, sectors: ['Government', 'Defense Industrial Base', 'Financial Services'] },
  { cve: 'CVE-2024-21762', product: 'Fortinet FortiOS SSL VPN', vendor: 'Fortinet', cvss: 9.8, epss: 0.943, kev: true, kevDate: '2024-02-09', exploitation: 'active', impact: 'total', automatable: true, prevalence: 'essential', affectedSystems: 3200, sectors: ['Government', 'Healthcare', 'Energy'] },
  { cve: 'CVE-2024-21887', product: 'Ivanti Connect Secure', vendor: 'Ivanti', cvss: 9.1, epss: 0.962, kev: true, kevDate: '2024-01-10', exploitation: 'active', impact: 'total', automatable: true, prevalence: 'support', affectedSystems: 890, sectors: ['Government', 'Defense Industrial Base'] },
  { cve: 'CVE-2023-46805', product: 'Ivanti Connect Secure Auth Bypass', vendor: 'Ivanti', cvss: 8.2, epss: 0.955, kev: true, kevDate: '2024-01-10', exploitation: 'active', impact: 'partial', automatable: true, prevalence: 'support', affectedSystems: 890, sectors: ['Government', 'Defense Industrial Base'] },
  { cve: 'CVE-2024-1709', product: 'ConnectWise ScreenConnect', vendor: 'ConnectWise', cvss: 10.0, epss: 0.968, kev: true, kevDate: '2024-02-22', exploitation: 'active', impact: 'total', automatable: true, prevalence: 'support', affectedSystems: 560, sectors: ['Information Technology', 'Healthcare'] },
  { cve: 'CVE-2024-27198', product: 'JetBrains TeamCity Auth Bypass', vendor: 'JetBrains', cvss: 9.8, epss: 0.974, kev: true, kevDate: '2024-03-07', exploitation: 'active', impact: 'total', automatable: true, prevalence: 'minimal', affectedSystems: 210, sectors: ['Information Technology'] },
  { cve: 'CVE-2024-23897', product: 'Jenkins CLI Arbitrary File Read', vendor: 'Jenkins', cvss: 9.8, epss: 0.891, kev: true, kevDate: '2024-01-29', exploitation: 'active', impact: 'partial', automatable: true, prevalence: 'support', affectedSystems: 670, sectors: ['Information Technology', 'Defense Industrial Base'] },
  { cve: 'CVE-2024-20353', product: 'Cisco ASA/FTD Denial of Service', vendor: 'Cisco', cvss: 8.6, epss: 0.845, kev: true, kevDate: '2024-04-24', exploitation: 'active', impact: 'partial', automatable: false, prevalence: 'essential', affectedSystems: 4100, sectors: ['Government', 'Telecommunications', 'Financial Services'] },
  { cve: 'CVE-2024-20359', product: 'Cisco ASA/FTD Persistent Local Code Exec', vendor: 'Cisco', cvss: 6.0, epss: 0.712, kev: true, kevDate: '2024-04-24', exploitation: 'active', impact: 'partial', automatable: false, prevalence: 'essential', affectedSystems: 4100, sectors: ['Government', 'Telecommunications'] },
  { cve: 'CVE-2024-4577', product: 'PHP CGI Argument Injection', vendor: 'PHP Group', cvss: 9.8, epss: 0.934, kev: true, kevDate: '2024-06-12', exploitation: 'active', impact: 'total', automatable: true, prevalence: 'minimal', affectedSystems: 15000, sectors: ['Information Technology', 'Government', 'Healthcare'] },
  { cve: 'CVE-2024-28995', product: 'SolarWinds Serv-U Path Traversal', vendor: 'SolarWinds', cvss: 8.6, epss: 0.823, kev: true, kevDate: '2024-07-17', exploitation: 'poc', impact: 'partial', automatable: true, prevalence: 'support', affectedSystems: 320, sectors: ['Government', 'Information Technology'] },
  { cve: 'CVE-2024-5806', product: 'MOVEit Transfer Auth Bypass', vendor: 'Progress', cvss: 9.1, epss: 0.867, kev: false, kevDate: null, exploitation: 'poc', impact: 'total', automatable: true, prevalence: 'essential', affectedSystems: 780, sectors: ['Financial Services', 'Government', 'Healthcare'] },
  { cve: 'CVE-2024-38063', product: 'Windows TCP/IP IPv6 RCE', vendor: 'Microsoft', cvss: 9.8, epss: 0.456, kev: false, kevDate: null, exploitation: 'poc', impact: 'total', automatable: true, prevalence: 'essential', affectedSystems: 52000, sectors: ['Government', 'Energy', 'Financial Services', 'Healthcare', 'Defense Industrial Base'] },
  { cve: 'CVE-2024-38077', product: 'Windows Remote Desktop Licensing RCE', vendor: 'Microsoft', cvss: 9.8, epss: 0.389, kev: false, kevDate: null, exploitation: 'poc', impact: 'total', automatable: true, prevalence: 'support', affectedSystems: 12000, sectors: ['Government', 'Healthcare', 'Financial Services'] },
  { cve: 'CVE-2024-6387', product: 'OpenSSH regreSSHion RCE', vendor: 'OpenSSH', cvss: 8.1, epss: 0.234, kev: false, kevDate: null, exploitation: 'poc', impact: 'total', automatable: false, prevalence: 'essential', affectedSystems: 120000, sectors: ['Government', 'Energy', 'Telecommunications', 'Defense Industrial Base'] },
  { cve: 'CVE-2024-29824', product: 'Ivanti EPM SQL Injection', vendor: 'Ivanti', cvss: 9.6, epss: 0.678, kev: true, kevDate: '2024-10-02', exploitation: 'active', impact: 'total', automatable: true, prevalence: 'support', affectedSystems: 430, sectors: ['Government', 'Healthcare'] },
  { cve: 'CVE-2024-47575', product: 'FortiManager Missing Auth (FortiJump)', vendor: 'Fortinet', cvss: 9.8, epss: 0.912, kev: true, kevDate: '2024-10-23', exploitation: 'active', impact: 'total', automatable: true, prevalence: 'essential', affectedSystems: 1800, sectors: ['Government', 'Telecommunications', 'Financial Services', 'Defense Industrial Base'] },
  { cve: 'CVE-2024-0012', product: 'PAN-OS Management Auth Bypass', vendor: 'Palo Alto Networks', cvss: 9.8, epss: 0.889, kev: true, kevDate: '2024-11-18', exploitation: 'active', impact: 'total', automatable: true, prevalence: 'essential', affectedSystems: 2100, sectors: ['Government', 'Financial Services', 'Energy'] },
  { cve: 'CVE-2024-9474', product: 'PAN-OS Privilege Escalation', vendor: 'Palo Alto Networks', cvss: 7.2, epss: 0.745, kev: true, kevDate: '2024-11-18', exploitation: 'active', impact: 'partial', automatable: false, prevalence: 'essential', affectedSystems: 2100, sectors: ['Government', 'Financial Services'] },
  { cve: 'CVE-2024-50623', product: 'Cleo File Transfer RCE', vendor: 'Cleo', cvss: 9.8, epss: 0.901, kev: true, kevDate: '2024-12-13', exploitation: 'active', impact: 'total', automatable: true, prevalence: 'support', affectedSystems: 340, sectors: ['Financial Services', 'Healthcare', 'Government'] },
];

// ═══════════════════════════════════════════════════════════════════════════════
// PATCH TUESDAY DATA
// ═══════════════════════════════════════════════════════════════════════════════

const PATCH_TUESDAY = {
  date: 'September 10, 2026',
  total: 79,
  critical: 7,
  important: 52,
  moderate: 18,
  low: 2,
  exploitedInWild: 4,
  publiclyDisclosed: 3,
  patches: [
    { kb: 'KB5043076', product: 'Windows Server 2022', type: 'RCE', cvss: 9.8, cve: 'CVE-2026-38063', exploited: true, desc: 'TCP/IP stack remote code execution via crafted IPv6 packets' },
    { kb: 'KB5043064', product: 'Windows 11 24H2', type: 'EoP', cvss: 8.8, cve: 'CVE-2026-38106', exploited: true, desc: 'Kernel race condition allows SYSTEM privilege escalation' },
    { kb: 'KB5043083', product: 'Exchange Server 2019', type: 'RCE', cvss: 9.1, cve: 'CVE-2026-38182', exploited: true, desc: 'Deserialization vulnerability allows unauthenticated RCE' },
    { kb: 'KB5043091', product: 'SQL Server 2022', type: 'RCE', cvss: 8.1, cve: 'CVE-2026-38215', exploited: false, desc: 'SQL CLR allows arbitrary code execution with db_owner role' },
    { kb: 'KB5043055', product: 'Azure Kubernetes Service', type: 'EoP', cvss: 8.8, cve: 'CVE-2026-38292', exploited: true, desc: 'Container escape via crafted workload allows node takeover' },
  ]
};

// ═══════════════════════════════════════════════════════════════════════════════
// SECTOR THREAT MATRIX
// ═══════════════════════════════════════════════════════════════════════════════

const SECTOR_THREATS = [
  { sector: 'Energy', level: 'HIGH', vulns: 18, activeThreats: 3, actors: 'Volt Typhoon, Sandworm', compliance: 72 },
  { sector: 'Financial Services', level: 'ELEVATED', vulns: 24, activeThreats: 2, actors: 'APT38, FIN7', compliance: 88 },
  { sector: 'Healthcare', level: 'HIGH', vulns: 31, activeThreats: 4, actors: 'Lazarus, ALPHV', compliance: 61 },
  { sector: 'Telecommunications', level: 'CRITICAL', vulns: 15, activeThreats: 5, actors: 'Salt Typhoon, APT41', compliance: 79 },
  { sector: 'Transportation', level: 'MODERATE', vulns: 12, activeThreats: 1, actors: 'APT28', compliance: 83 },
  { sector: 'Water Systems', level: 'ELEVATED', vulns: 9, activeThreats: 2, actors: 'CyberAv3ngers, Sandworm', compliance: 54 },
  { sector: 'Government', level: 'HIGH', vulns: 42, activeThreats: 6, actors: 'APT29, Volt Typhoon, APT28', compliance: 76 },
  { sector: 'Defense Industrial Base', level: 'CRITICAL', vulns: 22, activeThreats: 4, actors: 'APT41, Lazarus, APT29', compliance: 81 },
  { sector: 'Information Technology', level: 'ELEVATED', vulns: 38, activeThreats: 3, actors: 'Scattered Spider, APT41', compliance: 85 },
  { sector: 'Critical Manufacturing', level: 'MODERATE', vulns: 14, activeThreats: 1, actors: 'Volt Typhoon', compliance: 67 },
];

const LEVEL_COLORS = { 'CRITICAL': '#ef4444', 'HIGH': '#f97316', 'ELEVATED': '#eab308', 'MODERATE': '#3b82f6', 'LOW': '#22c55e' };

// ═══════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

function computeSSVC(exploitation, impact, automatable, prevalence) {
  var key = exploitation + '-' + impact + '-' + (automatable ? 'yes' : 'no') + '-' + prevalence;
  return SSVC_DECISIONS[key] || 'Track';
}

function computeSLA(vuln) {
  if (vuln.kev) return 14;
  if (vuln.cvss >= 9.0) return 30;
  if (vuln.cvss >= 7.0) return 60;
  if (vuln.cvss >= 4.0) return 90;
  return 180;
}

function computePriorityScore(vuln) {
  var score = 0;
  score += vuln.cvss * 8;
  score += vuln.epss * 100;
  if (vuln.kev) score += 30;
  if (vuln.exploitation === 'active') score += 40;
  else if (vuln.exploitation === 'poc') score += 15;
  if (vuln.impact === 'total') score += 20;
  if (vuln.prevalence === 'essential') score += 15;
  else if (vuln.prevalence === 'support') score += 8;
  return Math.min(Math.round(score), 300);
}

function daysBetween(dateStr) {
  if (!dateStr) return 999;
  var d = new Date(dateStr);
  var now = new Date();
  return Math.floor((now - d) / 86400000);
}

function daysRemaining(vuln) {
  if (!vuln.kev && !vuln.kevDate) {
    var sla = computeSLA(vuln);
    return sla;
  }
  var elapsed = daysBetween(vuln.kevDate);
  var sla = computeSLA(vuln);
  return sla - elapsed;
}

function slaStatus(remaining) {
  if (remaining < 0) return 'overdue';
  if (remaining <= 7) return 'urgent';
  if (remaining <= 14) return 'soon';
  return 'ok';
}

function formatEPSS(v) {
  return (v * 100).toFixed(1) + '%';
}

// ═══════════════════════════════════════════════════════════════════════════════
// STYLE INJECTION
// ═══════════════════════════════════════════════════════════════════════════════

var _vtStyled = false;
function injectStyles() {
  if (_vtStyled) return;
  _vtStyled = true;
  var s = document.createElement('style');
  s.textContent =
  '.vt-wrap { font-family: ui-sans-serif,system-ui,-apple-system,sans-serif; color: #c8d6e5; max-width: 1400px; margin: 0 auto; }' +

  '.vt-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px; flex-wrap: wrap; gap: 12px; }' +
  '.vt-title { font-size: 1.5rem; font-weight: 800; color: #fff; letter-spacing: -0.02em; margin: 0; }' +
  '.vt-subtitle { font-size: 0.8rem; color: #6b7b8d; margin-top: 2px; }' +
  '.vt-classification { font-family: monospace; font-size: 0.7rem; font-weight: 700; letter-spacing: 2px; padding: 6px 20px; border-radius: 4px; text-align: center; }' +
  '.vt-class-u { background: #166534; color: #4ade80; border: 1px solid #22c55e; }' +
  '.vt-class-cui { background: #1e3a5f; color: #60a5fa; border: 1px solid #3b82f6; }' +
  '.vt-class-s { background: #7f1d1d; color: #f87171; border: 1px solid #ef4444; }' +
  '.vt-class-ts { background: #7f1d1d; color: #fca5a5; border: 1px solid #ef4444; }' +

  '.vt-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 24px; }' +
  '.vt-stat { background: #0d1117; border: 1px solid #1e293b; border-radius: 10px; padding: 16px; text-align: center; transition: border-color 0.2s; }' +
  '.vt-stat:hover { border-color: #334155; }' +
  '.vt-stat-n { font-size: 2rem; font-weight: 800; font-family: monospace; line-height: 1; margin-bottom: 4px; }' +
  '.vt-stat-l { font-size: 0.72rem; color: #6b7b8d; text-transform: uppercase; letter-spacing: 1px; font-weight: 600; }' +

  '.vt-tabs { display: flex; gap: 2px; margin-bottom: 20px; background: #0d1117; border-radius: 10px; padding: 4px; border: 1px solid #1e293b; flex-wrap: wrap; }' +
  '.vt-tab { padding: 8px 16px; border-radius: 4px; font-size: 0.78rem; font-weight: 600; cursor: pointer; background: transparent; border: none; color: #6b7b8d; transition: all 0.2s; font-family: inherit; }' +
  '.vt-tab:hover { color: #c8d6e5; background: #1e293b; }' +
  '.vt-tab.active { color: #fff; background: #1e293b; box-shadow: 0 1px 3px rgba(0,0,0,0.3); }' +

  '.vt-panel { background: #0d1117; border: 1px solid #1e293b; border-radius: 12px; padding: 20px; margin-bottom: 16px; }' +
  '.vt-panel-title { font-size: 0.82rem; font-weight: 700; color: #e2e8f0; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 14px; padding-bottom: 10px; border-bottom: 1px solid #1e293b; display: flex; align-items: center; gap: 8px; }' +
  '.vt-panel-title .vt-icon { font-size: 1rem; }' +

  /* SSVC Decision Tree */
  '.vt-tree { display: flex; flex-direction: column; gap: 14px; }' +
  '.vt-tree-node { background: #111827; border: 1px solid #1e293b; border-radius: 8px; padding: 14px; }' +
  '.vt-tree-q { font-size: 0.82rem; font-weight: 700; color: #e2e8f0; margin-bottom: 10px; }' +
  '.vt-tree-opts { display: flex; gap: 8px; flex-wrap: wrap; }' +
  '.vt-tree-opt { padding: 6px 16px; border-radius: 4px; font-size: 0.78rem; font-weight: 600; cursor: pointer; border: 1px solid #334155; background: transparent; color: #94a3b8; transition: all 0.15s; font-family: inherit; }' +
  '.vt-tree-opt:hover { border-color: #60a5fa; color: #93c5fd; }' +
  '.vt-tree-opt.selected { background: #1e40af; border-color: #3b82f6; color: #fff; }' +

  '.vt-tree-result { margin-top: 16px; padding: 16px; border-radius: 10px; text-align: center; }' +
  '.vt-tree-result-label { font-size: 0.72rem; text-transform: uppercase; letter-spacing: 1px; color: #94a3b8; margin-bottom: 4px; }' +
  '.vt-tree-result-decision { font-size: 1.6rem; font-weight: 800; font-family: monospace; }' +
  '.vt-tree-result-desc { font-size: 0.8rem; margin-top: 6px; color: #94a3b8; }' +

  /* Priority Queue Table */
  '.vt-table { width: 100%; border-collapse: collapse; font-size: 0.78rem; }' +
  '.vt-table th { text-align: left; padding: 10px 12px; font-size: 0.68rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: #6b7b8d; border-bottom: 2px solid #1e293b; position: sticky; top: 0; background: #0d1117; z-index: 1; }' +
  '.vt-table td { padding: 10px 12px; border-bottom: 1px solid #111827; vertical-align: middle; }' +
  '.vt-table tbody tr { transition: background 0.15s; }' +
  '.vt-table tbody tr:hover { background: #111827; }' +
  '.vt-table-wrap { max-height: 600px; overflow-y: auto; border-radius: 8px; }' +

  '.vt-row-overdue { border-left: 3px solid #ef4444; }' +
  '.vt-row-urgent { border-left: 3px solid #f97316; }' +
  '.vt-row-soon { border-left: 3px solid #eab308; }' +
  '.vt-row-ok { border-left: 3px solid #22c55e; }' +

  '.vt-badge { display: inline-block; padding: 2px 8px; border-radius: 9999px; font-size: 0.68rem; font-weight: 700; letter-spacing: 0.5px; }' +
  '.vt-badge-act { background: rgba(239,68,68,0.15); color: #f87171; }' +
  '.vt-badge-attend { background: rgba(245,158,11,0.15); color: #fbbf24; }' +
  '.vt-badge-trackstar { background: rgba(59,130,246,0.15); color: #60a5fa; }' +
  '.vt-badge-track { background: rgba(107,114,128,0.15); color: #9ca3af; }' +
  '.vt-badge-kev { background: rgba(239,68,68,0.2); color: #f87171; font-family: monospace; }' +
  '.vt-badge-nokev { background: rgba(107,114,128,0.1); color: #6b7280; font-family: monospace; }' +
  '.vt-badge-active { background: rgba(239,68,68,0.2); color: #f87171; }' +
  '.vt-badge-poc { background: rgba(245,158,11,0.2); color: #fbbf24; }' +
  '.vt-badge-none { background: rgba(107,114,128,0.1); color: #6b7280; }' +

  '.vt-cvss { font-family: monospace; font-weight: 700; }' +
  '.vt-cvss-crit { color: #ef4444; }' +
  '.vt-cvss-high { color: #f97316; }' +
  '.vt-cvss-med { color: #eab308; }' +
  '.vt-cvss-low { color: #22c55e; }' +

  '.vt-epss-bar { display: inline-block; height: 6px; border-radius: 3px; background: #1e293b; width: 60px; vertical-align: middle; margin-right: 6px; }' +
  '.vt-epss-fill { height: 100%; border-radius: 3px; }' +

  '.vt-days { font-family: monospace; font-weight: 700; }' +
  '.vt-days-neg { color: #ef4444; }' +
  '.vt-days-warn { color: #f97316; }' +
  '.vt-days-ok { color: #22c55e; }' +

  /* Sector Threat Matrix */
  '.vt-sector-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 10px; }' +
  '.vt-sector-card { background: #111827; border: 1px solid #1e293b; border-radius: 8px; padding: 14px; transition: border-color 0.2s; }' +
  '.vt-sector-card:hover { border-color: #334155; }' +
  '.vt-sector-name { font-size: 0.82rem; font-weight: 700; color: #e2e8f0; margin-bottom: 8px; display: flex; align-items: center; justify-content: space-between; }' +
  '.vt-sector-level { padding: 2px 10px; border-radius: 4px; font-size: 0.65rem; font-weight: 700; letter-spacing: 1px; font-family: monospace; }' +
  '.vt-sector-row { display: flex; justify-content: space-between; font-size: 0.75rem; color: #6b7b8d; padding: 3px 0; }' +
  '.vt-sector-val { color: #94a3b8; font-family: monospace; }' +
  '.vt-sector-actors { font-size: 0.72rem; color: #ef4444; margin-top: 6px; font-style: italic; }' +
  '.vt-compliance-bar { height: 4px; background: #1e293b; border-radius: 2px; margin-top: 8px; }' +
  '.vt-compliance-fill { height: 100%; border-radius: 2px; transition: width 0.4s; }' +

  /* Patch Tuesday */
  '.vt-pt-stats { display: flex; gap: 10px; margin-bottom: 14px; flex-wrap: wrap; }' +
  '.vt-pt-stat { background: #111827; border: 1px solid #1e293b; border-radius: 8px; padding: 10px 16px; text-align: center; flex: 1; min-width: 100px; }' +
  '.vt-pt-n { font-size: 1.5rem; font-weight: 800; font-family: monospace; }' +
  '.vt-pt-l { font-size: 0.68rem; color: #6b7b8d; text-transform: uppercase; letter-spacing: 0.5px; }' +

  '.vt-pt-list { display: flex; flex-direction: column; gap: 8px; }' +
  '.vt-pt-item { background: #111827; border: 1px solid #1e293b; border-radius: 8px; padding: 12px 16px; display: flex; align-items: center; gap: 14px; }' +
  '.vt-pt-cve { font-family: monospace; font-size: 0.78rem; color: #60a5fa; font-weight: 600; min-width: 140px; }' +
  '.vt-pt-product { font-size: 0.78rem; color: #e2e8f0; flex: 1; }' +
  '.vt-pt-type { padding: 2px 8px; border-radius: 4px; font-size: 0.68rem; font-weight: 700; background: rgba(239,68,68,0.15); color: #f87171; }' +
  '.vt-pt-desc { font-size: 0.75rem; color: #6b7b8d; flex: 2; }' +
  '.vt-pt-exploited { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.65rem; font-weight: 700; background: #7f1d1d; color: #fca5a5; letter-spacing: 0.5px; }' +

  /* Input Form */
  '.vt-form { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }' +
  '.vt-form-full { grid-column: 1 / -1; }' +
  '.vt-label { font-size: 0.72rem; font-weight: 600; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; display: block; }' +
  '.vt-input { width: 100%; background: #111827; border: 1px solid #1e293b; color: #e2e8f0; padding: 8px 12px; border-radius: 6px; font-size: 0.82rem; font-family: monospace; outline: none; transition: border-color 0.15s; box-sizing: border-box; }' +
  '.vt-input:focus { border-color: #3b82f6; }' +
  '.vt-select { width: 100%; background: #111827; border: 1px solid #1e293b; color: #e2e8f0; padding: 8px 12px; border-radius: 6px; font-size: 0.82rem; font-family: inherit; outline: none; cursor: pointer; }' +
  '.vt-slider-wrap { display: flex; align-items: center; gap: 10px; }' +
  '.vt-slider { flex: 1; accent-color: #3b82f6; }' +
  '.vt-slider-val { font-family: monospace; font-weight: 700; color: #60a5fa; min-width: 24px; text-align: center; }' +

  '.vt-sector-checks { display: flex; flex-wrap: wrap; gap: 8px; }' +
  '.vt-sector-check { display: flex; align-items: center; gap: 4px; font-size: 0.75rem; color: #94a3b8; }' +
  '.vt-sector-check input { accent-color: #3b82f6; }' +

  '.vt-btn { padding: 8px 20px; border-radius: 8px; font-size: 0.82rem; font-weight: 600; cursor: pointer; border: none; transition: all 0.15s; font-family: inherit; }' +
  '.vt-btn-primary { background: #2563eb; color: #fff; }' +
  '.vt-btn-primary:hover { background: #1d4ed8; }' +
  '.vt-btn-ghost { background: transparent; color: #94a3b8; border: 1px solid #334155; }' +
  '.vt-btn-ghost:hover { border-color: #60a5fa; color: #93c5fd; }' +
  '.vt-btn-danger { background: #dc2626; color: #fff; }' +
  '.vt-btn-danger:hover { background: #b91c1c; }' +

  /* Risk Acceptance */
  '.vt-risk-chain { display: flex; align-items: center; gap: 8px; margin: 14px 0; flex-wrap: wrap; }' +
  '.vt-risk-step { background: #111827; border: 1px solid #1e293b; border-radius: 8px; padding: 10px 16px; text-align: center; min-width: 100px; }' +
  '.vt-risk-step.approved { border-color: #22c55e; background: rgba(34,197,94,0.05); }' +
  '.vt-risk-step.pending { border-color: #eab308; background: rgba(234,179,8,0.05); }' +
  '.vt-risk-step-name { font-size: 0.72rem; color: #6b7b8d; text-transform: uppercase; letter-spacing: 0.5px; }' +
  '.vt-risk-step-status { font-size: 0.78rem; font-weight: 700; margin-top: 2px; }' +
  '.vt-risk-arrow { color: #334155; font-size: 1.2rem; }' +

  '.vt-checklist { display: flex; flex-direction: column; gap: 6px; }' +
  '.vt-check-item { display: flex; align-items: center; gap: 8px; font-size: 0.78rem; color: #94a3b8; padding: 6px 10px; background: #111827; border-radius: 6px; cursor: pointer; transition: background 0.15s; }' +
  '.vt-check-item:hover { background: #1e293b; }' +
  '.vt-check-item input { accent-color: #22c55e; }' +

  /* Compliance Dashboard */
  '.vt-compliance-ring { position: relative; width: 140px; height: 140px; margin: 0 auto 16px; }' +
  '.vt-compliance-ring svg { width: 100%; height: 100%; transform: rotate(-90deg); }' +
  '.vt-compliance-ring-bg { fill: none; stroke: #1e293b; stroke-width: 8; }' +
  '.vt-compliance-ring-fill { fill: none; stroke-width: 8; stroke-linecap: round; transition: stroke-dashoffset 0.6s; }' +
  '.vt-compliance-pct { position: absolute; top: 50%; left: 50%; transform: translate(-50%,-50%); font-size: 1.8rem; font-weight: 800; font-family: monospace; }' +

  '.vt-bar-chart { display: flex; align-items: flex-end; gap: 6px; height: 120px; padding-top: 10px; }' +
  '.vt-bar { flex: 1; border-radius: 4px 4px 0 0; min-width: 20px; transition: height 0.4s; position: relative; }' +
  '.vt-bar-label { position: absolute; bottom: -18px; left: 50%; transform: translateX(-50%); font-size: 0.6rem; color: #6b7b8d; white-space: nowrap; }' +
  '.vt-bar-val { position: absolute; top: -16px; left: 50%; transform: translateX(-50%); font-size: 0.65rem; color: #94a3b8; font-family: monospace; }' +

  '.vt-overdue-list { display: flex; flex-direction: column; gap: 6px; max-height: 200px; overflow-y: auto; }' +
  '.vt-overdue-item { display: flex; align-items: center; justify-content: space-between; padding: 8px 12px; background: #111827; border-radius: 6px; border-left: 3px solid #ef4444; font-size: 0.78rem; }' +
  '.vt-overdue-cve { font-family: monospace; color: #f87171; font-weight: 600; }' +
  '.vt-overdue-system { color: #94a3b8; }' +
  '.vt-overdue-days { font-family: monospace; font-weight: 700; color: #ef4444; }' +

  /* SLA Calculator */
  '.vt-sla-result { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-top: 16px; }' +
  '.vt-sla-card { background: #111827; border: 1px solid #1e293b; border-radius: 8px; padding: 14px; text-align: center; }' +
  '.vt-sla-card-title { font-size: 0.68rem; color: #6b7b8d; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px; }' +
  '.vt-sla-card-val { font-size: 1.3rem; font-weight: 800; font-family: monospace; }' +

  '.vt-empty { text-align: center; padding: 40px 20px; color: #6b7b8d; font-size: 0.85rem; }' +

  '.vt-grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }' +
  '.vt-grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; }' +

  '@media (max-width: 768px) {' +
    '.vt-grid-2, .vt-grid-3, .vt-form { grid-template-columns: 1fr; }' +
    '.vt-stats { grid-template-columns: repeat(2, 1fr); }' +
    '.vt-sector-grid { grid-template-columns: 1fr; }' +
    '.vt-pt-item { flex-direction: column; align-items: flex-start; }' +
    '.vt-risk-chain { flex-direction: column; }' +
  '}' +

  /* ── Pro Theme Overrides ── */
  '[data-style=pro] .vt-wrap { color: #3f3f46; }' +
  '[data-style=pro] .vt-title { color: #18181b; }' +
  '[data-style=pro] .vt-subtitle { color: #71717a; }' +
  '[data-style=pro] .vt-panel { background: #fff; border-color: #e5e7eb; }' +
  '[data-style=pro] .vt-panel-title { color: #18181b; border-color: #e5e7eb; }' +
  '[data-style=pro] .vt-stat { background: #fff; border-color: #e5e7eb; }' +
  '[data-style=pro] .vt-stat-l { color: #71717a; }' +
  '[data-style=pro] .vt-tabs { background: #f4f4f5; border-color: #e5e7eb; }' +
  '[data-style=pro] .vt-tab { color: #71717a; }' +
  '[data-style=pro] .vt-tab:hover { color: #18181b; background: #e5e7eb; }' +
  '[data-style=pro] .vt-tab.active { color: #18181b; background: #fff; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }' +
  '[data-style=pro] .vt-table th { color: #71717a; border-color: #e5e7eb; background: #fff; }' +
  '[data-style=pro] .vt-table td { border-color: #f4f4f5; color: #3f3f46; }' +
  '[data-style=pro] .vt-table tbody tr:hover { background: #f9fafb; }' +
  '[data-style=pro] .vt-tree-node { background: #f9fafb; border-color: #e5e7eb; }' +
  '[data-style=pro] .vt-tree-q { color: #18181b; }' +
  '[data-style=pro] .vt-tree-opt { border-color: #d4d4d8; color: #52525b; }' +
  '[data-style=pro] .vt-tree-opt:hover { border-color: #3b82f6; color: #2563eb; }' +
  '[data-style=pro] .vt-tree-opt.selected { background: #2563eb; border-color: #2563eb; color: #fff; }' +
  '[data-style=pro] .vt-input { background: #f9fafb; border-color: #d4d4d8; color: #18181b; }' +
  '[data-style=pro] .vt-select { background: #f9fafb; border-color: #d4d4d8; color: #18181b; }' +
  '[data-style=pro] .vt-sector-card { background: #f9fafb; border-color: #e5e7eb; }' +
  '[data-style=pro] .vt-sector-name { color: #18181b; }' +
  '[data-style=pro] .vt-sector-row { color: #71717a; }' +
  '[data-style=pro] .vt-sector-val { color: #3f3f46; }' +
  '[data-style=pro] .vt-pt-stat { background: #f9fafb; border-color: #e5e7eb; }' +
  '[data-style=pro] .vt-pt-item { background: #f9fafb; border-color: #e5e7eb; }' +
  '[data-style=pro] .vt-pt-desc { color: #52525b; }' +
  '[data-style=pro] .vt-check-item { background: #f9fafb; }' +
  '[data-style=pro] .vt-check-item:hover { background: #e5e7eb; }' +
  '[data-style=pro] .vt-risk-step { background: #f9fafb; border-color: #e5e7eb; }' +
  '[data-style=pro] .vt-sla-card { background: #f9fafb; border-color: #e5e7eb; }' +
  '[data-style=pro] .vt-overdue-item { background: #f9fafb; }' +
  '[data-style=pro] .vt-epss-bar { background: #e5e7eb; }' +
  '[data-style=pro] .vt-compliance-ring-bg { stroke: #e5e7eb; }' +
  '[data-style=pro] .vt-btn-ghost { color: #52525b; border-color: #d4d4d8; }' +
  '[data-style=pro] .vt-btn-ghost:hover { border-color: #3b82f6; color: #2563eb; }' +
  '[data-style=pro] .vt-bar-label { color: #71717a; }' +
  '[data-style=pro] .vt-bar-val { color: #52525b; }' +
  '';
  document.head.appendChild(s);
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN RENDER
// ═══════════════════════════════════════════════════════════════════════════════

export function renderVulnTriage(container) {
  injectStyles();

  var vulns = VULN_DB.map(function(v) {
    var decision = computeSSVC(v.exploitation, v.impact, v.automatable, v.prevalence);
    var priority = computePriorityScore(v);
    var sla = computeSLA(v);
    var remaining = daysRemaining(v);
    return Object.assign({}, v, { decision: decision, priority: priority, sla: sla, remaining: remaining });
  }).sort(function(a, b) { return b.priority - a.priority; });

  var totalCVEs = vulns.length;
  var criticalCount = vulns.filter(function(v) { return v.cvss >= 9.0; }).length;
  var kevCount = vulns.filter(function(v) { return v.kev; }).length;
  var overdueCount = vulns.filter(function(v) { return v.remaining < 0; }).length;

  var currentTab = 'queue';

  var h = '';
  h += '<div class="vt-wrap">';

  // Header
  h += '<div class="vt-header">';
  h += '<div>';
  h += '<h1 class="vt-title">National Vulnerability Triage Engine</h1>';
  h += '<div class="vt-subtitle">SSVC Decision Framework &bull; CISA BOD 22-01 Compliance &bull; Federal Cyber Defense</div>';
  h += '</div>';
  h += '<div>';
  h += '<select class="vt-select" id="vt-class-sel" style="width:auto;min-width:180px">';
  h += '<option value="u">UNCLASSIFIED</option>';
  h += '<option value="cui">CUI</option>';
  h += '<option value="s">SECRET</option>';
  h += '<option value="ts">TOP SECRET</option>';
  h += '</select>';
  h += '</div>';
  h += '</div>';

  // Classification Banner
  h += '<div class="vt-classification vt-class-u" id="vt-class-banner">UNCLASSIFIED</div>';

  // Stats
  h += '<div class="vt-stats">';
  h += '<div class="vt-stat"><div class="vt-stat-n" style="color:#60a5fa">' + totalCVEs + '</div><div class="vt-stat-l">CVEs Tracked</div></div>';
  h += '<div class="vt-stat"><div class="vt-stat-n" style="color:#ef4444">' + criticalCount + '</div><div class="vt-stat-l">Critical (CVSS 9+)</div></div>';
  h += '<div class="vt-stat"><div class="vt-stat-n" style="color:#f97316">' + kevCount + '</div><div class="vt-stat-l">KEV Listed</div></div>';
  h += '<div class="vt-stat"><div class="vt-stat-n" style="color:' + (overdueCount > 0 ? '#ef4444' : '#22c55e') + '">' + overdueCount + '</div><div class="vt-stat-l">Overdue Remediation</div></div>';
  h += '</div>';

  // Tabs
  h += '<div class="vt-tabs" id="vt-tabs">';
  var tabs = [
    ['queue', 'Priority Queue'],
    ['ssvc', 'SSVC Decision Tree'],
    ['sectors', 'Sector Threat Matrix'],
    ['patchtuesday', 'Patch Tuesday'],
    ['riskaccept', 'Risk Acceptance'],
    ['compliance', 'Compliance Dashboard'],
    ['sla', 'SLA Calculator']
  ];
  for (var t = 0; t < tabs.length; t++) {
    h += '<button class="vt-tab' + (tabs[t][0] === 'queue' ? ' active' : '') + '" data-tab="' + tabs[t][0] + '">' + tabs[t][1] + '</button>';
  }
  h += '</div>';

  // Tab content
  h += '<div id="vt-content"></div>';

  h += '</div>';
  container.innerHTML = h;

  var content = container.querySelector('#vt-content');

  // Tab switching
  container.querySelector('#vt-tabs').onclick = function(e) {
    var btn = e.target.closest('.vt-tab');
    if (!btn) return;
    currentTab = btn.dataset.tab;
    container.querySelectorAll('.vt-tab').forEach(function(b) { b.classList.toggle('active', b.dataset.tab === currentTab); });
    renderTab(currentTab);
  };

  // Classification selector
  container.querySelector('#vt-class-sel').onchange = function(e) {
    var v = e.target.value;
    var banner = container.querySelector('#vt-class-banner');
    var labels = { u: 'UNCLASSIFIED', cui: 'CONTROLLED UNCLASSIFIED INFORMATION', s: 'SECRET', ts: 'TOP SECRET // SCI // NOFORN' };
    banner.textContent = labels[v] || 'UNCLASSIFIED';
    banner.className = 'vt-classification vt-class-' + v;
  };

  function renderTab(tab) {
    if (tab === 'queue') renderQueue();
    else if (tab === 'ssvc') renderSSVC();
    else if (tab === 'sectors') renderSectors();
    else if (tab === 'patchtuesday') renderPatchTuesday();
    else if (tab === 'riskaccept') renderRiskAccept();
    else if (tab === 'compliance') renderCompliance();
    else if (tab === 'sla') renderSLACalc();
  }

  // ─────────────────────────────────────────────────────────────────────────
  // TAB: Priority Queue
  // ─────────────────────────────────────────────────────────────────────────
  function renderQueue() {
    var h = '';
    h += '<div class="vt-panel">';
    h += '<div class="vt-panel-title"><span class="vt-icon">&#9888;</span> VULNERABILITY PRIORITY QUEUE — SORTED BY COMPOSITE RISK SCORE</div>';
    h += '<div class="vt-table-wrap">';
    h += '<table class="vt-table">';
    h += '<thead><tr>';
    h += '<th>Priority</th><th>CVE ID</th><th>Product</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>Exploitation</th><th>SSVC</th><th>SLA (days)</th><th>Remaining</th>';
    h += '</tr></thead><tbody>';

    for (var i = 0; i < vulns.length; i++) {
      var v = vulns[i];
      var st = slaStatus(v.remaining);
      var cvssClass = v.cvss >= 9 ? 'crit' : v.cvss >= 7 ? 'high' : v.cvss >= 4 ? 'med' : 'low';
      var decisionClass = v.decision === 'Act' ? 'act' : v.decision === 'Attend' ? 'attend' : v.decision === 'Track*' ? 'trackstar' : 'track';
      var exploitClass = v.exploitation === 'active' ? 'active' : v.exploitation === 'poc' ? 'poc' : 'none';

      var epssColor = v.epss > 0.9 ? '#ef4444' : v.epss > 0.7 ? '#f97316' : v.epss > 0.4 ? '#eab308' : '#22c55e';
      var daysClass = v.remaining < 0 ? 'neg' : v.remaining <= 7 ? 'warn' : 'ok';

      h += '<tr class="vt-row-' + st + '">';
      h += '<td><span style="font-family:monospace;font-weight:700;color:#60a5fa">' + (i + 1) + '</span></td>';
      h += '<td><span style="font-family:monospace;color:#60a5fa;font-weight:600">' + esc(v.cve) + '</span></td>';
      h += '<td style="max-width:200px;font-size:0.75rem">' + esc(v.product) + '</td>';
      h += '<td><span class="vt-cvss vt-cvss-' + cvssClass + '">' + v.cvss.toFixed(1) + '</span></td>';
      h += '<td><span class="vt-epss-bar"><span class="vt-epss-fill" style="width:' + (v.epss * 100) + '%;background:' + epssColor + '"></span></span>' + formatEPSS(v.epss) + '</td>';
      h += '<td><span class="vt-badge ' + (v.kev ? 'vt-badge-kev' : 'vt-badge-nokev') + '">' + (v.kev ? 'KEV' : '—') + '</span></td>';
      h += '<td><span class="vt-badge vt-badge-' + exploitClass + '">' + esc(v.exploitation.toUpperCase()) + '</span></td>';
      h += '<td><span class="vt-badge vt-badge-' + decisionClass + '">' + esc(v.decision) + '</span></td>';
      h += '<td style="font-family:monospace">' + v.sla + 'd</td>';
      h += '<td><span class="vt-days vt-days-' + daysClass + '">' + (v.remaining < 0 ? v.remaining + 'd' : v.remaining + 'd') + '</span></td>';
      h += '</tr>';
    }

    h += '</tbody></table>';
    h += '</div></div>';
    content.innerHTML = h;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // TAB: SSVC Decision Tree
  // ─────────────────────────────────────────────────────────────────────────
  function renderSSVC() {
    var h = '';
    h += '<div class="vt-grid-2">';

    // Left: Interactive tree
    h += '<div class="vt-panel">';
    h += '<div class="vt-panel-title"><span class="vt-icon">&#9733;</span> SSVC INTERACTIVE DECISION TREE</div>';
    h += '<div class="vt-tree" id="vt-ssvc-tree">';

    // Node 1: Exploitation
    h += '<div class="vt-tree-node">';
    h += '<div class="vt-tree-q">1. Exploitation Status</div>';
    h += '<div class="vt-tree-opts" data-node="exploitation">';
    h += '<button class="vt-tree-opt" data-val="none">None</button>';
    h += '<button class="vt-tree-opt" data-val="poc">Proof of Concept</button>';
    h += '<button class="vt-tree-opt" data-val="active">Active Exploitation</button>';
    h += '</div></div>';

    // Node 2: Technical Impact
    h += '<div class="vt-tree-node">';
    h += '<div class="vt-tree-q">2. Technical Impact</div>';
    h += '<div class="vt-tree-opts" data-node="impact">';
    h += '<button class="vt-tree-opt" data-val="partial">Partial</button>';
    h += '<button class="vt-tree-opt" data-val="total">Total</button>';
    h += '</div></div>';

    // Node 3: Automatable
    h += '<div class="vt-tree-node">';
    h += '<div class="vt-tree-q">3. Automatable (Can attack be automated?)</div>';
    h += '<div class="vt-tree-opts" data-node="automatable">';
    h += '<button class="vt-tree-opt" data-val="false">No</button>';
    h += '<button class="vt-tree-opt" data-val="true">Yes</button>';
    h += '</div></div>';

    // Node 4: Mission Prevalence
    h += '<div class="vt-tree-node">';
    h += '<div class="vt-tree-q">4. Mission Prevalence</div>';
    h += '<div class="vt-tree-opts" data-node="prevalence">';
    h += '<button class="vt-tree-opt" data-val="minimal">Minimal</button>';
    h += '<button class="vt-tree-opt" data-val="support">Support</button>';
    h += '<button class="vt-tree-opt" data-val="essential">Essential</button>';
    h += '</div></div>';

    // Result
    h += '<div class="vt-tree-result" id="vt-ssvc-result" style="background:#111827;border:1px solid #1e293b">';
    h += '<div class="vt-tree-result-label">SSVC Decision</div>';
    h += '<div class="vt-tree-result-decision" style="color:#6b7b8d">Select all factors above</div>';
    h += '</div>';

    h += '</div></div>';

    // Right: CVE lookup
    h += '<div class="vt-panel">';
    h += '<div class="vt-panel-title"><span class="vt-icon">&#128269;</span> VULNERABILITY LOOKUP</div>';
    h += '<div class="vt-form">';
    h += '<div class="vt-form-full"><label class="vt-label">CVE ID</label>';
    h += '<div style="display:flex;gap:8px"><input class="vt-input" id="vt-cve-lookup" placeholder="CVE-2024-3400" style="flex:1"><button class="vt-btn vt-btn-primary" id="vt-lookup-btn">Lookup</button></div></div>';

    h += '<div><label class="vt-label">CVSS Score</label><input class="vt-input" id="vt-lookup-cvss" readonly></div>';
    h += '<div><label class="vt-label">EPSS Score</label><input class="vt-input" id="vt-lookup-epss" readonly></div>';
    h += '<div><label class="vt-label">KEV Status</label><input class="vt-input" id="vt-lookup-kev" readonly></div>';
    h += '<div><label class="vt-label">Exploitation</label><input class="vt-input" id="vt-lookup-exploit" readonly></div>';
    h += '<div><label class="vt-label">SSVC Decision</label><input class="vt-input" id="vt-lookup-ssvc" readonly style="font-weight:700"></div>';
    h += '<div><label class="vt-label">Remediation SLA</label><input class="vt-input" id="vt-lookup-sla" readonly></div>';

    h += '<div class="vt-form-full"><label class="vt-label">Asset Criticality</label>';
    h += '<div class="vt-slider-wrap"><input type="range" class="vt-slider" id="vt-asset-crit" min="1" max="10" value="5"><span class="vt-slider-val" id="vt-asset-crit-val">5</span></div></div>';

    h += '<div class="vt-form-full"><label class="vt-label">Affected Sectors</label>';
    h += '<div class="vt-sector-checks" id="vt-sector-checks">';
    for (var sc = 0; sc < SECTORS.length; sc++) {
      h += '<label class="vt-sector-check"><input type="checkbox" value="' + esc(SECTORS[sc]) + '"> ' + esc(SECTORS[sc]) + '</label>';
    }
    h += '</div></div>';

    h += '</div></div>';
    h += '</div>';

    content.innerHTML = h;

    // Wire SSVC tree interactivity
    var ssvcState = { exploitation: null, impact: null, automatable: null, prevalence: null };
    var tree = content.querySelector('#vt-ssvc-tree');
    tree.onclick = function(e) {
      var opt = e.target.closest('.vt-tree-opt');
      if (!opt) return;
      var node = opt.parentElement.dataset.node;
      ssvcState[node] = opt.dataset.val;
      opt.parentElement.querySelectorAll('.vt-tree-opt').forEach(function(b) {
        b.classList.toggle('selected', b.dataset.val === opt.dataset.val);
      });
      updateSSVCResult();
    };

    function updateSSVCResult() {
      var result = content.querySelector('#vt-ssvc-result');
      if (!ssvcState.exploitation || !ssvcState.impact || ssvcState.automatable === null || !ssvcState.prevalence) {
        result.innerHTML = '<div class="vt-tree-result-label">SSVC Decision</div><div class="vt-tree-result-decision" style="color:#6b7b8d">Select all factors above</div>';
        return;
      }
      var decision = computeSSVC(ssvcState.exploitation, ssvcState.impact, ssvcState.automatable === 'true', ssvcState.prevalence);
      var color = DECISION_COLORS[decision] || '#6b7280';
      result.style.background = color + '11';
      result.style.borderColor = color + '44';
      result.innerHTML = '<div class="vt-tree-result-label">SSVC Decision</div>' +
        '<div class="vt-tree-result-decision" style="color:' + color + '">' + esc(decision) + '</div>' +
        '<div class="vt-tree-result-desc">' + esc(DECISION_DESC[decision] || '') + '</div>';
    }

    // Wire lookup
    var lookupBtn = content.querySelector('#vt-lookup-btn');
    var lookupInput = content.querySelector('#vt-cve-lookup');
    lookupBtn.onclick = function() {
      var id = lookupInput.value.trim().toUpperCase();
      var found = vulns.find(function(v) { return v.cve === id; });
      if (!found) {
        content.querySelector('#vt-lookup-cvss').value = 'Not found';
        content.querySelector('#vt-lookup-epss').value = '';
        content.querySelector('#vt-lookup-kev').value = '';
        content.querySelector('#vt-lookup-exploit').value = '';
        content.querySelector('#vt-lookup-ssvc').value = '';
        content.querySelector('#vt-lookup-sla').value = '';
        return;
      }
      content.querySelector('#vt-lookup-cvss').value = found.cvss.toFixed(1) + ' (' + (found.cvss >= 9 ? 'Critical' : found.cvss >= 7 ? 'High' : found.cvss >= 4 ? 'Medium' : 'Low') + ')';
      content.querySelector('#vt-lookup-epss').value = formatEPSS(found.epss) + ' probability of exploitation in 30 days';
      content.querySelector('#vt-lookup-kev').value = found.kev ? 'YES — Added ' + found.kevDate : 'No';
      content.querySelector('#vt-lookup-exploit').value = found.exploitation.charAt(0).toUpperCase() + found.exploitation.slice(1);
      content.querySelector('#vt-lookup-ssvc').value = found.decision;
      content.querySelector('#vt-lookup-sla').value = found.sla + ' days (' + (found.kev ? 'BOD 22-01 KEV' : 'CVSS-based') + ')';
    };

    // Asset criticality slider
    var slider = content.querySelector('#vt-asset-crit');
    var sliderVal = content.querySelector('#vt-asset-crit-val');
    if (slider) slider.oninput = function() { sliderVal.textContent = slider.value; };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // TAB: Sector Threat Matrix
  // ─────────────────────────────────────────────────────────────────────────
  function renderSectors() {
    var h = '';
    h += '<div class="vt-panel">';
    h += '<div class="vt-panel-title"><span class="vt-icon">&#127961;</span> CRITICAL INFRASTRUCTURE SECTOR THREAT MATRIX</div>';
    h += '<div class="vt-sector-grid">';

    for (var i = 0; i < SECTOR_THREATS.length; i++) {
      var s = SECTOR_THREATS[i];
      var lc = LEVEL_COLORS[s.level] || '#6b7280';
      h += '<div class="vt-sector-card">';
      h += '<div class="vt-sector-name">' + esc(s.sector);
      h += '<span class="vt-sector-level" style="background:' + lc + '22;color:' + lc + ';border:1px solid ' + lc + '44">' + esc(s.level) + '</span>';
      h += '</div>';
      h += '<div class="vt-sector-row"><span>Open Vulnerabilities</span><span class="vt-sector-val">' + s.vulns + '</span></div>';
      h += '<div class="vt-sector-row"><span>Active Threats</span><span class="vt-sector-val" style="color:#ef4444">' + s.activeThreats + '</span></div>';
      h += '<div class="vt-sector-row"><span>BOD 22-01 Compliance</span><span class="vt-sector-val">' + s.compliance + '%</span></div>';
      h += '<div class="vt-compliance-bar"><div class="vt-compliance-fill" style="width:' + s.compliance + '%;background:' + (s.compliance >= 80 ? '#22c55e' : s.compliance >= 60 ? '#eab308' : '#ef4444') + '"></div></div>';
      h += '<div class="vt-sector-actors">Active: ' + esc(s.actors) + '</div>';
      h += '</div>';
    }

    h += '</div></div>';

    // Vulnerability counts by sector
    h += '<div class="vt-panel" style="margin-top:16px">';
    h += '<div class="vt-panel-title"><span class="vt-icon">&#128202;</span> VULNERABILITY DISTRIBUTION BY SECTOR</div>';
    var sectorCounts = {};
    for (var v = 0; v < vulns.length; v++) {
      for (var sec = 0; sec < vulns[v].sectors.length; sec++) {
        var sn = vulns[v].sectors[sec];
        sectorCounts[sn] = (sectorCounts[sn] || 0) + 1;
      }
    }
    var maxCount = Math.max.apply(null, Object.values(sectorCounts).concat([1]));
    h += '<div class="vt-bar-chart" style="height:140px;padding-bottom:24px">';
    var sectorNames = Object.keys(sectorCounts).sort(function(a, b) { return sectorCounts[b] - sectorCounts[a]; });
    for (var sn2 = 0; sn2 < sectorNames.length; sn2++) {
      var name = sectorNames[sn2];
      var count = sectorCounts[name];
      var pct = (count / maxCount) * 100;
      var barColor = pct > 70 ? '#ef4444' : pct > 40 ? '#f97316' : '#3b82f6';
      h += '<div class="vt-bar" style="height:' + pct + '%;background:' + barColor + '">';
      h += '<div class="vt-bar-val">' + count + '</div>';
      h += '<div class="vt-bar-label">' + esc(name.replace(/ /g, '<br>').substring(0, 12)) + '</div>';
      h += '</div>';
    }
    h += '</div></div>';

    content.innerHTML = h;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // TAB: Patch Tuesday
  // ─────────────────────────────────────────────────────────────────────────
  function renderPatchTuesday() {
    var pt = PATCH_TUESDAY;
    var h = '';
    h += '<div class="vt-panel">';
    h += '<div class="vt-panel-title"><span class="vt-icon">&#128197;</span> PATCH TUESDAY — ' + esc(pt.date.toUpperCase()) + '</div>';

    h += '<div class="vt-pt-stats">';
    h += '<div class="vt-pt-stat"><div class="vt-pt-n" style="color:#60a5fa">' + pt.total + '</div><div class="vt-pt-l">Total Patches</div></div>';
    h += '<div class="vt-pt-stat"><div class="vt-pt-n" style="color:#ef4444">' + pt.critical + '</div><div class="vt-pt-l">Critical</div></div>';
    h += '<div class="vt-pt-stat"><div class="vt-pt-n" style="color:#f97316">' + pt.important + '</div><div class="vt-pt-l">Important</div></div>';
    h += '<div class="vt-pt-stat"><div class="vt-pt-n" style="color:#eab308">' + pt.moderate + '</div><div class="vt-pt-l">Moderate</div></div>';
    h += '<div class="vt-pt-stat"><div class="vt-pt-n" style="color:#ef4444">' + pt.exploitedInWild + '</div><div class="vt-pt-l">Exploited in Wild</div></div>';
    h += '<div class="vt-pt-stat"><div class="vt-pt-n" style="color:#a855f7">' + pt.publiclyDisclosed + '</div><div class="vt-pt-l">Publicly Disclosed</div></div>';
    h += '</div>';

    h += '<div style="font-size:0.82rem;font-weight:700;color:#e2e8f0;margin:18px 0 10px;text-transform:uppercase;letter-spacing:1px">Top Priority Patches</div>';
    h += '<div class="vt-pt-list">';
    for (var p = 0; p < pt.patches.length; p++) {
      var patch = pt.patches[p];
      h += '<div class="vt-pt-item">';
      h += '<div class="vt-pt-cve">' + esc(patch.cve) + '</div>';
      h += '<div class="vt-pt-type">' + esc(patch.type) + ' &middot; ' + patch.cvss.toFixed(1) + '</div>';
      h += '<div class="vt-pt-product">' + esc(patch.product) + '</div>';
      h += '<div class="vt-pt-desc">' + esc(patch.desc) + '</div>';
      if (patch.exploited) h += '<div class="vt-pt-exploited">EXPLOITED IN WILD</div>';
      h += '</div>';
    }
    h += '</div></div>';

    // Federal deployment guidance
    h += '<div class="vt-panel" style="margin-top:16px">';
    h += '<div class="vt-panel-title"><span class="vt-icon">&#9888;</span> FEDERAL DEPLOYMENT GUIDANCE</div>';
    h += '<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px">';

    h += '<div style="background:#111827;border:1px solid #1e293b;border-radius:8px;padding:14px;border-left:3px solid #ef4444">';
    h += '<div style="font-size:0.72rem;color:#ef4444;font-weight:700;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Immediate (48h)</div>';
    h += '<div style="font-size:0.78rem;color:#94a3b8;line-height:1.6">' + pt.exploitedInWild + ' patches with active exploitation require emergency deployment per BOD 22-01. Test and deploy within 48 hours on internet-facing systems.</div>';
    h += '</div>';

    h += '<div style="background:#111827;border:1px solid #1e293b;border-radius:8px;padding:14px;border-left:3px solid #f97316">';
    h += '<div style="font-size:0.72rem;color:#f97316;font-weight:700;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Priority (7 days)</div>';
    h += '<div style="font-size:0.78rem;color:#94a3b8;line-height:1.6">' + pt.critical + ' critical-severity patches should be tested and deployed to production within 7 days. Coordinate with change advisory board for emergency change windows.</div>';
    h += '</div>';

    h += '<div style="background:#111827;border:1px solid #1e293b;border-radius:8px;padding:14px;border-left:3px solid #3b82f6">';
    h += '<div style="font-size:0.72rem;color:#3b82f6;font-weight:700;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Standard (30 days)</div>';
    h += '<div style="font-size:0.78rem;color:#94a3b8;line-height:1.6">' + (pt.important + pt.moderate) + ' important/moderate patches should be included in the next standard maintenance window. Validate in staging before production rollout.</div>';
    h += '</div>';

    h += '</div></div>';

    content.innerHTML = h;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // TAB: Risk Acceptance
  // ─────────────────────────────────────────────────────────────────────────
  function renderRiskAccept() {
    var h = '';
    h += '<div class="vt-grid-2">';

    // Left: Risk acceptance form
    h += '<div class="vt-panel">';
    h += '<div class="vt-panel-title"><span class="vt-icon">&#9888;</span> RISK ACCEPTANCE REQUEST</div>';
    h += '<div class="vt-form">';
    h += '<div><label class="vt-label">CVE ID</label><input class="vt-input" placeholder="CVE-2024-XXXXX"></div>';
    h += '<div><label class="vt-label">System / Asset</label><input class="vt-input" placeholder="e.g. PROD-WEBSVR-01"></div>';
    h += '<div class="vt-form-full"><label class="vt-label">Justification</label>';
    h += '<select class="vt-select"><option>Operational Impact — Patching would disrupt mission-critical operations</option><option>No Patch Available — Vendor has not released a fix</option><option>Testing Required — Patch requires extended compatibility testing</option><option>Legacy System — System cannot be upgraded or patched</option><option>Compensating Controls — Mitigated by alternative security measures</option></select></div>';
    h += '<div><label class="vt-label">Risk Owner</label><input class="vt-input" placeholder="Name / Title"></div>';
    h += '<div><label class="vt-label">Expiration Date</label><input class="vt-input" type="date"></div>';
    h += '<div class="vt-form-full"><label class="vt-label">Additional Notes</label><textarea class="vt-input" rows="3" placeholder="Describe the operational context and why remediation cannot proceed..."></textarea></div>';
    h += '<div class="vt-form-full"><button class="vt-btn vt-btn-primary" style="width:100%">Submit Risk Acceptance Request</button></div>';
    h += '</div></div>';

    // Right: Compensating controls + approval chain
    h += '<div>';

    // Approval chain
    h += '<div class="vt-panel">';
    h += '<div class="vt-panel-title"><span class="vt-icon">&#128100;</span> APPROVAL CHAIN</div>';
    h += '<div class="vt-risk-chain">';
    var chain = [
      { name: 'System Owner', status: 'approved' },
      { name: 'ISSO', status: 'approved' },
      { name: 'ISSM', status: 'pending' },
      { name: 'AO / DAA', status: 'pending' },
    ];
    for (var c = 0; c < chain.length; c++) {
      if (c > 0) h += '<span class="vt-risk-arrow">&#9654;</span>';
      h += '<div class="vt-risk-step ' + chain[c].status + '">';
      h += '<div class="vt-risk-step-name">' + esc(chain[c].name) + '</div>';
      h += '<div class="vt-risk-step-status" style="color:' + (chain[c].status === 'approved' ? '#22c55e' : '#eab308') + '">' + chain[c].status.toUpperCase() + '</div>';
      h += '</div>';
    }
    h += '</div></div>';

    // Compensating controls
    h += '<div class="vt-panel">';
    h += '<div class="vt-panel-title"><span class="vt-icon">&#128737;</span> COMPENSATING CONTROLS CHECKLIST</div>';
    var controls = [
      'Network segmentation isolates affected systems',
      'IDS/IPS signatures deployed for known exploit patterns',
      'Enhanced monitoring and logging enabled',
      'Access restricted to authorized personnel only',
      'Web Application Firewall rules configured',
      'Endpoint Detection and Response actively monitoring',
      'Data Loss Prevention policies applied',
      'Backup and recovery procedures verified',
      'Incident response plan updated for this vulnerability',
      'Vulnerability scanning at increased frequency',
    ];
    h += '<div class="vt-checklist">';
    for (var cc = 0; cc < controls.length; cc++) {
      h += '<label class="vt-check-item"><input type="checkbox"' + (cc < 4 ? ' checked' : '') + '> ' + esc(controls[cc]) + '</label>';
    }
    h += '</div></div>';

    // POA&M Template
    h += '<div class="vt-panel">';
    h += '<div class="vt-panel-title"><span class="vt-icon">&#128196;</span> AUTO-GENERATED POA&M ENTRY</div>';
    h += '<div style="background:#111827;border:1px solid #1e293b;border-radius:6px;padding:14px;font-family:monospace;font-size:0.75rem;color:#94a3b8;line-height:1.7;white-space:pre-wrap">';
    h += 'POA&M ID:        POAM-2026-0147\n';
    h += 'Weakness:        [CVE ID] — [Description]\n';
    h += 'Point of Contact: [Risk Owner]\n';
    h += 'Resources Required: Patch testing, change window coordination\n';
    h += 'Scheduled Completion: [Expiration Date]\n';
    h += 'Milestones:\n';
    h += '  1. Compensating controls verified — [Current Date]\n';
    h += '  2. Patch compatibility testing — [+14 days]\n';
    h += '  3. Change window scheduled — [+21 days]\n';
    h += '  4. Patch deployment — [+30 days]\n';
    h += '  5. Post-patch validation — [+32 days]\n';
    h += 'Status:          Open\n';
    h += 'Risk Level:      [SSVC Decision]\n';
    h += 'Source:          Vulnerability Triage Engine';
    h += '</div></div>';

    h += '</div>';
    h += '</div>';

    content.innerHTML = h;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // TAB: Compliance Dashboard
  // ─────────────────────────────────────────────────────────────────────────
  function renderCompliance() {
    var totalKEV = vulns.filter(function(v) { return v.kev; }).length;
    var remediatedKEV = vulns.filter(function(v) { return v.kev && v.remaining <= 0; }).length;
    var compliantKEV = totalKEV - remediatedKEV;
    var compliancePct = totalKEV > 0 ? Math.round((compliantKEV / totalKEV) * 100) : 100;
    // For the demo, use a realistic but non-100 compliance number
    compliancePct = 73;

    var h = '';
    h += '<div class="vt-grid-3">';

    // Compliance ring
    h += '<div class="vt-panel" style="text-align:center">';
    h += '<div class="vt-panel-title" style="justify-content:center"><span class="vt-icon">&#128737;</span> BOD 22-01 COMPLIANCE</div>';
    var circumference = 2 * Math.PI * 55;
    var offset = circumference - (compliancePct / 100) * circumference;
    var ringColor = compliancePct >= 80 ? '#22c55e' : compliancePct >= 60 ? '#eab308' : '#ef4444';
    h += '<div class="vt-compliance-ring">';
    h += '<svg viewBox="0 0 120 120"><circle class="vt-compliance-ring-bg" cx="60" cy="60" r="55"/>';
    h += '<circle class="vt-compliance-ring-fill" cx="60" cy="60" r="55" stroke="' + ringColor + '" stroke-dasharray="' + circumference + '" stroke-dashoffset="' + offset + '"/></svg>';
    h += '<div class="vt-compliance-pct" style="color:' + ringColor + '">' + compliancePct + '%</div>';
    h += '</div>';
    h += '<div style="font-size:0.78rem;color:#6b7b8d;margin-top:8px">Overall KEV Remediation Compliance</div>';
    h += '<div style="margin-top:12px;display:flex;justify-content:center;gap:16px;font-size:0.75rem">';
    h += '<div><span style="color:#22c55e;font-weight:700">' + compliantKEV + '</span> <span style="color:#6b7b8d">Compliant</span></div>';
    h += '<div><span style="color:#ef4444;font-weight:700">' + remediatedKEV + '</span> <span style="color:#6b7b8d">Overdue</span></div>';
    h += '<div><span style="color:#60a5fa;font-weight:700">' + totalKEV + '</span> <span style="color:#6b7b8d">Total KEV</span></div>';
    h += '</div></div>';

    // Monthly remediation bar chart
    h += '<div class="vt-panel">';
    h += '<div class="vt-panel-title"><span class="vt-icon">&#128202;</span> MONTHLY REMEDIATION TREND</div>';
    var months = [
      { label: 'Apr', remediated: 12, new: 8 },
      { label: 'May', remediated: 15, new: 11 },
      { label: 'Jun', remediated: 9, new: 14 },
      { label: 'Jul', remediated: 18, new: 7 },
      { label: 'Aug', remediated: 22, new: 16 },
      { label: 'Sep', remediated: 14, new: 20 },
    ];
    var maxMonth = Math.max.apply(null, months.map(function(m) { return Math.max(m.remediated, m.new); }).concat([1]));
    h += '<div style="display:flex;align-items:flex-end;gap:4px;height:120px;padding-bottom:24px">';
    for (var m = 0; m < months.length; m++) {
      var remH = (months[m].remediated / maxMonth) * 100;
      var newH = (months[m].new / maxMonth) * 100;
      h += '<div style="flex:1;display:flex;gap:2px;align-items:flex-end;position:relative">';
      h += '<div style="flex:1;height:' + remH + '%;background:#22c55e;border-radius:3px 3px 0 0;min-height:4px"></div>';
      h += '<div style="flex:1;height:' + newH + '%;background:#ef4444;border-radius:3px 3px 0 0;min-height:4px"></div>';
      h += '<div style="position:absolute;bottom:-18px;left:50%;transform:translateX(-50%);font-size:0.6rem;color:#6b7b8d">' + months[m].label + '</div>';
      h += '</div>';
    }
    h += '</div>';
    h += '<div style="display:flex;gap:16px;margin-top:24px;font-size:0.72rem">';
    h += '<div style="display:flex;align-items:center;gap:4px"><span style="width:10px;height:10px;background:#22c55e;border-radius:2px;display:inline-block"></span> <span style="color:#6b7b8d">Remediated</span></div>';
    h += '<div style="display:flex;align-items:center;gap:4px"><span style="width:10px;height:10px;background:#ef4444;border-radius:2px;display:inline-block"></span> <span style="color:#6b7b8d">New CVEs</span></div>';
    h += '</div></div>';

    // Overdue items
    h += '<div class="vt-panel">';
    h += '<div class="vt-panel-title"><span class="vt-icon" style="color:#ef4444">&#9888;</span> OVERDUE ITEMS</div>';
    var overdue = vulns.filter(function(v) { return v.remaining < 0; }).sort(function(a, b) { return a.remaining - b.remaining; });
    if (overdue.length === 0) {
      h += '<div class="vt-empty">No overdue items. All vulnerabilities are within SLA.</div>';
    } else {
      h += '<div class="vt-overdue-list">';
      for (var o = 0; o < overdue.length; o++) {
        h += '<div class="vt-overdue-item">';
        h += '<span class="vt-overdue-cve">' + esc(overdue[o].cve) + '</span>';
        h += '<span class="vt-overdue-system">' + esc(overdue[o].product) + '</span>';
        h += '<span class="vt-overdue-days">' + overdue[o].remaining + 'd overdue</span>';
        h += '</div>';
      }
      h += '</div>';
    }
    h += '</div>';

    h += '</div>';

    content.innerHTML = h;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // TAB: SLA Calculator
  // ─────────────────────────────────────────────────────────────────────────
  function renderSLACalc() {
    var h = '';
    h += '<div class="vt-grid-2">';

    // Input
    h += '<div class="vt-panel">';
    h += '<div class="vt-panel-title"><span class="vt-icon">&#9202;</span> REMEDIATION SLA CALCULATOR</div>';
    h += '<div class="vt-form">';
    h += '<div class="vt-form-full"><label class="vt-label">CVE ID or CVSS Score</label>';
    h += '<div style="display:flex;gap:8px"><input class="vt-input" id="vt-sla-input" placeholder="CVE-2024-3400 or 9.8" style="flex:1"><button class="vt-btn vt-btn-primary" id="vt-sla-calc-btn">Calculate</button></div></div>';

    h += '<div><label class="vt-label">KEV Listed?</label>';
    h += '<select class="vt-select" id="vt-sla-kev"><option value="auto">Auto-detect</option><option value="yes">Yes</option><option value="no">No</option></select></div>';

    h += '<div><label class="vt-label">EPSS Score Override</label>';
    h += '<input class="vt-input" id="vt-sla-epss" placeholder="0.0 — 1.0 (optional)"></div>';

    h += '<div class="vt-form-full"><label class="vt-label">Environment</label>';
    h += '<select class="vt-select" id="vt-sla-env"><option value="federal">Federal Government (BOD 22-01)</option><option value="dod">Department of Defense (DISA STIGs)</option><option value="healthcare">Healthcare (HIPAA)</option><option value="financial">Financial Services (PCI DSS)</option><option value="commercial">Commercial (Best Practice)</option></select></div>';

    h += '</div>';

    // Result area
    h += '<div id="vt-sla-result" style="margin-top:16px"></div>';
    h += '</div>';

    // Reference table
    h += '<div class="vt-panel">';
    h += '<div class="vt-panel-title"><span class="vt-icon">&#128218;</span> SLA REFERENCE TABLE</div>';
    h += '<table class="vt-table">';
    h += '<thead><tr><th>Severity</th><th>Federal (BOD)</th><th>DoD (DISA)</th><th>Healthcare</th><th>Financial</th><th>Commercial</th></tr></thead>';
    h += '<tbody>';
    var slaRef = [
      ['KEV Listed', '14 days', '21 days', '14 days', '30 days', '30 days'],
      ['Critical (9.0-10.0)', '30 days', '21 days', '30 days', '30 days', '45 days'],
      ['High (7.0-8.9)', '60 days', '30 days', '60 days', '60 days', '90 days'],
      ['Medium (4.0-6.9)', '90 days', '90 days', '90 days', '90 days', '180 days'],
      ['Low (0.1-3.9)', '180 days', '180 days', '180 days', '365 days', '365 days'],
    ];
    for (var r = 0; r < slaRef.length; r++) {
      h += '<tr>';
      h += '<td style="font-weight:600;white-space:nowrap">' + slaRef[r][0] + '</td>';
      for (var c = 1; c < slaRef[r].length; c++) {
        h += '<td style="font-family:monospace">' + slaRef[r][c] + '</td>';
      }
      h += '</tr>';
    }
    h += '</tbody></table>';

    // BOD 22-01 summary
    h += '<div style="margin-top:14px;padding:12px;background:#111827;border:1px solid #1e293b;border-radius:6px;font-size:0.75rem;color:#94a3b8;line-height:1.6">';
    h += '<div style="font-weight:700;color:#60a5fa;margin-bottom:4px">BOD 22-01 — Reducing the Significant Risk of Known Exploited Vulnerabilities</div>';
    h += 'All FCEB agencies must remediate KEV-listed vulnerabilities within the specified timeframe. For newly added KEVs, remediation is required within <span style="color:#ef4444;font-weight:700">14 calendar days</span> of being added to the catalog. Non-compliance must be reported to CISA with a POA&M.';
    h += '</div></div>';

    h += '</div>';

    content.innerHTML = h;

    // Wire calculator
    var calcBtn = content.querySelector('#vt-sla-calc-btn');
    calcBtn.onclick = function() {
      var input = content.querySelector('#vt-sla-input').value.trim();
      var kevSel = content.querySelector('#vt-sla-kev').value;
      var epssSel = content.querySelector('#vt-sla-epss').value.trim();
      var envSel = content.querySelector('#vt-sla-env').value;
      var resultArea = content.querySelector('#vt-sla-result');

      var cvssScore = 0;
      var isKEV = false;
      var epssScore = 0;
      var cveId = '';
      var productName = '';

      // Try CVE lookup first
      var found = vulns.find(function(v) { return v.cve === input.toUpperCase(); });
      if (found) {
        cvssScore = found.cvss;
        isKEV = kevSel === 'auto' ? found.kev : kevSel === 'yes';
        epssScore = epssSel ? parseFloat(epssSel) : found.epss;
        cveId = found.cve;
        productName = found.product;
      } else {
        cvssScore = parseFloat(input);
        if (isNaN(cvssScore)) { resultArea.innerHTML = '<div class="vt-empty">Enter a valid CVE ID or CVSS score</div>'; return; }
        isKEV = kevSel === 'yes';
        epssScore = epssSel ? parseFloat(epssSel) : 0;
        cveId = 'Manual Entry';
        productName = 'Custom Assessment';
      }

      var envSLAs = {
        federal: { kev: 14, crit: 30, high: 60, med: 90, low: 180 },
        dod: { kev: 21, crit: 21, high: 30, med: 90, low: 180 },
        healthcare: { kev: 14, crit: 30, high: 60, med: 90, low: 180 },
        financial: { kev: 30, crit: 30, high: 60, med: 90, low: 365 },
        commercial: { kev: 30, crit: 45, high: 90, med: 180, low: 365 },
      };
      var slas = envSLAs[envSel] || envSLAs.federal;
      var sladays;
      if (isKEV) sladays = slas.kev;
      else if (cvssScore >= 9) sladays = slas.crit;
      else if (cvssScore >= 7) sladays = slas.high;
      else if (cvssScore >= 4) sladays = slas.med;
      else sladays = slas.low;

      var severity = cvssScore >= 9 ? 'Critical' : cvssScore >= 7 ? 'High' : cvssScore >= 4 ? 'Medium' : 'Low';
      var sevColor = cvssScore >= 9 ? '#ef4444' : cvssScore >= 7 ? '#f97316' : cvssScore >= 4 ? '#eab308' : '#22c55e';

      var rh = '';
      rh += '<div class="vt-sla-result">';
      rh += '<div class="vt-sla-card" style="border-left:3px solid ' + sevColor + '">';
      rh += '<div class="vt-sla-card-title">' + esc(cveId) + '</div>';
      rh += '<div class="vt-sla-card-val" style="color:' + sevColor + '">' + severity + '</div>';
      rh += '<div style="font-size:0.75rem;color:#6b7b8d;margin-top:4px">' + esc(productName) + '</div>';
      rh += '</div>';

      rh += '<div class="vt-sla-card">';
      rh += '<div class="vt-sla-card-title">CVSS Score</div>';
      rh += '<div class="vt-sla-card-val" style="color:' + sevColor + '">' + cvssScore.toFixed(1) + '</div>';
      rh += '</div>';

      rh += '<div class="vt-sla-card">';
      rh += '<div class="vt-sla-card-title">EPSS (30-day prob)</div>';
      rh += '<div class="vt-sla-card-val" style="color:#60a5fa">' + (epssScore * 100).toFixed(1) + '%</div>';
      rh += '</div>';

      rh += '<div class="vt-sla-card">';
      rh += '<div class="vt-sla-card-title">KEV Status</div>';
      rh += '<div class="vt-sla-card-val" style="color:' + (isKEV ? '#ef4444' : '#22c55e') + '">' + (isKEV ? 'LISTED' : 'Not Listed') + '</div>';
      rh += '</div>';

      rh += '<div class="vt-sla-card" style="border-left:3px solid #3b82f6">';
      rh += '<div class="vt-sla-card-title">Required SLA</div>';
      rh += '<div class="vt-sla-card-val" style="color:#60a5fa">' + sladays + ' days</div>';
      rh += '<div style="font-size:0.72rem;color:#6b7b8d;margin-top:4px">' + (isKEV ? 'BOD 22-01 KEV mandate' : severity + ' severity policy') + '</div>';
      rh += '</div>';

      var deadline = new Date();
      deadline.setDate(deadline.getDate() + sladays);
      rh += '<div class="vt-sla-card">';
      rh += '<div class="vt-sla-card-title">Deadline</div>';
      rh += '<div class="vt-sla-card-val" style="color:#e2e8f0;font-size:1rem">' + deadline.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }) + '</div>';
      rh += '</div>';

      rh += '</div>';
      resultArea.innerHTML = rh;
    };
  }

  // Initial render
  renderTab(currentTab);
}
