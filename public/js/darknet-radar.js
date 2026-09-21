// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Darknet Radar — Dark web intelligence, ransomware tracking, IOC aggregation
// Simulated threat feeds for educational/training purposes. All client-side.

var esc = function(s) {
  return String(s != null ? s : '').replace(/[&<>"']/g, function(c) {
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
  });
};

// ── Simulated Threat Feed Data ──────────────────────────────────────────────

var _drBreaches = [
  { id: 'BR-2026-0918', target: 'MegaHealth Insurance', records: 4200000, dataTypes: 'SSN, DOB, Medical records, Insurance IDs', discovered: '2026-09-16', posted: '2026-09-17', forum: 'BreachForums v4', seller: 'ghostdata_rx', price: '14 BTC (~$840K)', status: 'ACTIVE', sector: 'Healthcare' },
  { id: 'BR-2026-0915', target: 'NovaTech Solutions', records: 18700000, dataTypes: 'Email, Password hashes (bcrypt), API keys', discovered: '2026-09-14', posted: '2026-09-15', forum: 'XSS.is', seller: 'data_merchant', price: '8 BTC (~$480K)', status: 'ACTIVE', sector: 'Technology' },
  { id: 'BR-2026-0912', target: 'First National Bank (Regional)', records: 890000, dataTypes: 'Account numbers, Routing numbers, Transaction history', discovered: '2026-09-10', posted: '2026-09-12', forum: 'Exploit.in', seller: 'financier_dark', price: '22 BTC (~$1.3M)', status: 'VERIFIED', sector: 'Financial' },
  { id: 'BR-2026-0908', target: 'EduConnect Platform', records: 52000000, dataTypes: 'Student records, Grades, Parent contact info', discovered: '2026-09-06', posted: '2026-09-08', forum: 'BreachForums v4', seller: 'academic_leak', price: '3 BTC (~$180K)', status: 'ACTIVE', sector: 'Education' },
  { id: 'BR-2026-0905', target: 'CityGov Municipal Systems', records: 1400000, dataTypes: 'Voter records, Property tax data, Permits', discovered: '2026-09-03', posted: '2026-09-05', forum: 'Dread', seller: 'civhack_ops', price: '5 BTC (~$300K)', status: 'STALE', sector: 'Government' },
  { id: 'BR-2026-0901', target: 'StreamVault Media', records: 31200000, dataTypes: 'Email, Passwords (SHA1), Payment tokens', discovered: '2026-08-29', posted: '2026-09-01', forum: 'XSS.is', seller: 'mediabreaker', price: '6 BTC (~$360K)', status: 'SOLD', sector: 'Entertainment' },
  { id: 'BR-2026-0828', target: 'GreenEnergy Corp', records: 420000, dataTypes: 'Employee PII, SCADA network diagrams, VPN credentials', discovered: '2026-08-26', posted: '2026-08-28', forum: 'RAMP', seller: 'industrial_spy', price: '30 BTC (~$1.8M)', status: 'ACTIVE', sector: 'Energy' },
  { id: 'BR-2026-0825', target: 'TravelBuddy App', records: 8900000, dataTypes: 'Passport scans, Flight itineraries, Hotel bookings', discovered: '2026-08-23', posted: '2026-08-25', forum: 'BreachForums v4', seller: 'passport_king', price: '12 BTC (~$720K)', status: 'VERIFIED', sector: 'Travel' }
];

var _drRansomwareGroups = [
  { name: 'LockBit 4.0', status: 'ACTIVE', victims2026: 142, avgRansom: '$2.4M', ttps: 'Double extortion, data theft + encryption, affiliate model', infra: '3 .onion mirrors, dedicated leak site, chat portal', sectors: 'Manufacturing, Healthcare, Finance', lastPost: '2026-09-18', notes: 'Rebuilt after 2024 takedown. New encryptor. Fastest encryption speed.' },
  { name: 'BlackCat/ALPHV 3.0', status: 'ACTIVE', victims2026: 98, avgRansom: '$3.1M', ttps: 'Triple extortion (encrypt + leak + DDoS), Rust-based encryptor', infra: '2 mirrors, searchable leak database', sectors: 'Legal, Healthcare, Critical Infrastructure', lastPost: '2026-09-17', notes: 'Rebranded after exit scam. Cross-platform: Windows, Linux, ESXi, NAS.' },
  { name: 'Cl0p', status: 'ACTIVE', victims2026: 67, avgRansom: '$4.8M', ttps: 'Zero-day exploitation (MOVEit, GoAnywhere), mass exploitation campaigns', infra: 'Dedicated leak site with victim countdown timers', sectors: 'Finance, Government, Technology', lastPost: '2026-09-15', notes: 'Specializes in supply-chain exploitation. Targets file transfer software.' },
  { name: 'Play', status: 'ACTIVE', victims2026: 84, avgRansom: '$1.8M', ttps: 'Custom tooling, intermittent encryption for speed, ProxyNotShell exploitation', infra: '1 leak site, Tor-based negotiation', sectors: 'Government, Manufacturing, Technology', lastPost: '2026-09-16', notes: 'No affiliate program — closed group. Custom .play extension.' },
  { name: 'Akira', status: 'ACTIVE', victims2026: 71, avgRansom: '$1.2M', ttps: 'VPN exploitation (Cisco ASA/FTD), credential theft, ESXi targeting', infra: 'Retro 80s-themed leak site', sectors: 'Education, Manufacturing, Professional Services', lastPost: '2026-09-14', notes: 'Unusual retro aesthetic. Targets SMBs. Growing affiliate network.' },
  { name: 'RansomHub', status: 'ACTIVE', victims2026: 112, avgRansom: '$1.5M', ttps: 'Affiliate model, quick encryption, stolen credential initial access', infra: '2 leak sites, negotiation portal', sectors: 'Healthcare, Retail, Technology', lastPost: '2026-09-18', notes: 'Rapid growth in 2026. Former Hive/ALPHV affiliates. 90/10 affiliate split.' },
  { name: 'BianLian', status: 'ACTIVE', victims2026: 53, avgRansom: '$2.0M', ttps: 'Data exfiltration only (no encryption since 2024), ProxyShell exploitation', infra: '1 leak site', sectors: 'Healthcare, Legal, Manufacturing', lastPost: '2026-09-12', notes: 'Pivoted to pure data extortion. No decryptor needed — only exfiltrates.' },
  { name: 'Medusa', status: 'ACTIVE', victims2026: 48, avgRansom: '$2.2M', ttps: 'RDP brute-force, phishing, multi-extortion with countdown timer', infra: 'Leak blog with video proof of stolen data', sectors: 'Education, Healthcare, Government', lastPost: '2026-09-13', notes: 'Posts video walkthroughs of stolen data. Increasing sophistication.' }
];

var _drTorExitNodes = [
  { ip: '185.220.101.42', country: 'DE', bandwidth: '120 Mbps', uptime: '99.2%', flags: 'Exit, Fast, Guard, Stable, Valid', operator: 'Artikel10', firstSeen: '2022-03-14' },
  { ip: '104.244.76.13', country: 'LU', bandwidth: '80 Mbps', uptime: '98.8%', flags: 'Exit, Fast, Stable, Valid', operator: 'CalyxInstitute', firstSeen: '2021-08-22' },
  { ip: '199.249.230.89', country: 'US', bandwidth: '95 Mbps', uptime: '99.5%', flags: 'Exit, Fast, Guard, HSDir, Stable, Valid', operator: 'Quintex', firstSeen: '2020-11-03' },
  { ip: '51.15.43.205', country: 'NL', bandwidth: '60 Mbps', uptime: '97.1%', flags: 'Exit, Fast, Stable, Valid', operator: 'Anonymous', firstSeen: '2023-01-19' },
  { ip: '176.10.99.200', country: 'CH', bandwidth: '45 Mbps', uptime: '99.0%', flags: 'Exit, Fast, Guard, Stable, Valid', operator: 'AccessNow', firstSeen: '2019-06-11' },
  { ip: '23.129.64.210', country: 'US', bandwidth: '110 Mbps', uptime: '99.3%', flags: 'Exit, Fast, Guard, Stable, Valid, V2Dir', operator: 'EmeraldOnion', firstSeen: '2021-02-28' },
  { ip: '193.218.118.183', country: 'UA', bandwidth: '35 Mbps', uptime: '96.4%', flags: 'Exit, Fast, Stable, Valid', operator: 'Unknown', firstSeen: '2024-07-15' },
  { ip: '45.138.16.240', country: 'SE', bandwidth: '70 Mbps', uptime: '98.6%', flags: 'Exit, Fast, Guard, HSDir, Stable, Valid', operator: 'F3Netze', firstSeen: '2022-09-30' },
  { ip: '162.247.74.27', country: 'US', bandwidth: '55 Mbps', uptime: '99.1%', flags: 'Exit, Fast, Guard, Stable, Valid', operator: 'CalyxInstitute', firstSeen: '2020-04-08' },
  { ip: '77.247.181.162', country: 'NL', bandwidth: '40 Mbps', uptime: '98.2%', flags: 'Exit, Fast, Stable, Valid', operator: 'XS4ALL-Tor', firstSeen: '2018-12-01' }
];

var _drIOCs = [
  { type: 'IP', value: '185.220.101.42', source: 'Tor Exit Node', confidence: 'low', context: 'Known Tor exit — may be benign or malicious depending on traffic patterns', tags: ['tor', 'proxy'] },
  { type: 'IP', value: '91.234.99.41', source: 'AbuseIPDB', confidence: 'high', context: 'C2 server for Cobalt Strike beacon. Active since 2026-08-14. Linked to LockBit affiliate.', tags: ['c2', 'cobalt-strike', 'lockbit'] },
  { type: 'Domain', value: 'update-service-cdn.xyz', source: 'MalwareBazaar', confidence: 'high', context: 'Hosting AsyncRAT payload. Resolves to bulletproof hosting in Moldova.', tags: ['rat', 'malware', 'bulletproof'] },
  { type: 'Hash (SHA256)', value: 'a1b2c3d4e5f6789012345678abcdef0123456789abcdef0123456789abcdef01', source: 'VirusTotal', confidence: 'critical', context: 'LockBit 4.0 encryptor binary. 62/72 detections. Targets Windows + ESXi.', tags: ['ransomware', 'lockbit', 'encryptor'] },
  { type: 'Domain', value: 'microsft-update.com', source: 'PhishTank', confidence: 'high', context: 'Credential phishing page mimicking Microsoft 365 login. Hosted on Cloudflare Workers.', tags: ['phishing', 'credential-theft', 'microsoft'] },
  { type: 'IP', value: '45.155.205.233', source: 'Shadowserver', confidence: 'high', context: 'Scanning for vulnerable Fortinet SSL-VPN (CVE-2024-21762). Part of mass exploitation campaign.', tags: ['scanner', 'exploit', 'fortinet'] },
  { type: 'Hash (MD5)', value: 'd41d8cd98f00b204e9800998ecf8427e', source: 'YARA Match', confidence: 'medium', context: 'Empty file hash — often used as a test/placeholder. May indicate sandbox evasion technique.', tags: ['evasion', 'sandbox'] },
  { type: 'URL', value: 'hxxps://cdn-images-delivery[.]net/invoice.html', source: 'URLhaus', confidence: 'high', context: 'HTML smuggling payload delivering QakBot. Bypasses email gateway via encoded JavaScript.', tags: ['html-smuggling', 'qakbot', 'loader'] },
  { type: 'Email', value: 'accounting@mega-corp-invoices.com', source: 'Spamhaus', confidence: 'high', context: 'BEC (Business Email Compromise) sender. Part of Nigerian threat actor group targeting CFOs.', tags: ['bec', 'fraud', 'social-engineering'] },
  { type: 'IP', value: '103.75.201.4', source: 'Emerging Threats', confidence: 'critical', context: 'Active C2 for SolarMarker infostealer. Exfiltrating browser credentials and crypto wallets.', tags: ['infostealer', 'c2', 'solarmarker'] }
];

var _drPasteLeaks = [
  { site: 'Pastebin', title: 'MegaHealth_DB_dump_2026.sql', size: '4.2 GB', posted: '2026-09-17T08:14:22Z', contentPreview: 'Contains SQL dump with patient_id, ssn, dob, diagnosis_code, insurance_id...', status: 'REMOVED', matchedBreach: 'BR-2026-0918' },
  { site: 'Ghostbin', title: 'novaTech_all_users_export', size: '890 MB', posted: '2026-09-15T22:41:08Z', contentPreview: 'CSV format: email,bcrypt_hash,created_at,last_login,api_key...', status: 'ACTIVE', matchedBreach: 'BR-2026-0915' },
  { site: 'PrivateBin', title: 'vpn_creds_greenEnergy_internal', size: '12 KB', posted: '2026-08-28T14:55:33Z', contentPreview: 'username:password pairs for Cisco AnyConnect VPN, 420 entries...', status: 'ACTIVE', matchedBreach: 'BR-2026-0828' },
  { site: 'Rentry', title: 'combo_list_Q3_2026_fresh', size: '2.1 GB', posted: '2026-09-10T06:22:17Z', contentPreview: 'email:password combo list, 28M lines, mixed sources, partially dehashed...', status: 'ACTIVE', matchedBreach: null },
  { site: 'Pastebin', title: 'aws_keys_leaked_startup_xyz', size: '4 KB', posted: '2026-09-12T19:08:44Z', contentPreview: 'AKIA... AWS Access Key IDs and Secret Access Keys, 8 pairs...', status: 'REMOVED', matchedBreach: null },
  { site: 'JustPaste.it', title: 'gov_employee_data_2026', size: '340 MB', posted: '2026-09-05T11:33:09Z', contentPreview: 'SSN, name, address, dept, clearance_level for municipal employees...', status: 'ACTIVE', matchedBreach: 'BR-2026-0905' }
];

// ── Formatting helpers ──────────────────────────────────────────────────────

function _drFmtNum(n) {
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(0) + 'K';
  return String(n);
}

// ── Main Render ─────────────────────────────────────────────────────────────

export function renderDarknetRadar(container) {
  var el = typeof container === 'string' ? document.getElementById(container) : container;
  if (!el) return;

  var h = '';
  h += '<div style="background:#0a0e16;color:#c8d6e5;font-family:\'Courier New\',monospace;padding:24px;min-height:100%;">';

  // Header
  h += '<div style="display:flex;align-items:center;gap:12px;margin-bottom:20px;flex-wrap:wrap;">';
  h += '<h2 style="margin:0;color:#ff2244;letter-spacing:2px;font-size:18px;">DARKNET RADAR</h2>';
  h += '<span style="color:#3a0a0a;background:#ff2244;padding:2px 8px;font-size:10px;font-weight:bold;border-radius:2px;letter-spacing:2px;">SIMULATED INTEL</span>';
  h += '</div>';
  h += '<div style="color:#4a6a8a;font-size:11px;margin-bottom:20px;">Dark web threat intelligence monitoring | Ransomware tracking | IOC aggregation<br>All data is simulated for educational/training purposes.</div>';

  // Tabs
  h += '<div id="dr-tabs" style="display:flex;gap:4px;margin-bottom:16px;flex-wrap:wrap;">';
  var tabs = ['Data Breaches', 'Ransomware Groups', 'Tor Exit Nodes', 'IOC Feed', 'Paste Monitoring'];
  for (var ti = 0; ti < tabs.length; ti++) {
    var isActive = ti === 0;
    h += '<button class="dr-tab" data-dr-tab="' + ti + '" style="background:' + (isActive ? '#2a0a0a' : '#0f1218') + ';border:1px solid ' + (isActive ? '#ff2244' : '#1a2a3a') + ';color:' + (isActive ? '#ff2244' : '#5a7a9a') + ';padding:6px 14px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:3px;letter-spacing:1px;">' + esc(tabs[ti]) + '</button>';
  }
  h += '</div>';

  // ── Tab 0: Data Breaches ──
  h += '<div id="dr-panel-0" class="dr-panel">';
  h += '<h3 style="color:#ff6644;font-size:13px;letter-spacing:2px;margin:0 0 10px;border-bottom:1px solid #3a1a1a;padding-bottom:6px;">RECENT DATA BREACHES (' + _drBreaches.length + ')</h3>';
  for (var bi = 0; bi < _drBreaches.length; bi++) {
    var b = _drBreaches[bi];
    var statusColor = b.status === 'ACTIVE' ? '#ff2244' : (b.status === 'VERIFIED' ? '#ff6644' : (b.status === 'SOLD' ? '#888' : '#4a6a8a'));
    h += '<div style="background:#0f1218;padding:12px 16px;margin-bottom:8px;border-radius:4px;border-left:3px solid ' + statusColor + ';">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;flex-wrap:wrap;gap:6px;">';
    h += '<span style="color:#ff4444;font-size:14px;font-weight:bold;">' + esc(b.target) + '</span>';
    h += '<span style="color:' + statusColor + ';font-size:10px;border:1px solid ' + statusColor + ';padding:1px 6px;border-radius:2px;">' + esc(b.status) + '</span>';
    h += '</div>';
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:4px 16px;font-size:10px;color:#8ab4d4;line-height:1.6;">';
    h += '<div><span style="color:#4a6a8a;">Records:</span> ' + _drFmtNum(b.records) + '</div>';
    h += '<div><span style="color:#4a6a8a;">Sector:</span> ' + esc(b.sector) + '</div>';
    h += '<div><span style="color:#4a6a8a;">Forum:</span> ' + esc(b.forum) + '</div>';
    h += '<div><span style="color:#4a6a8a;">Price:</span> ' + esc(b.price) + '</div>';
    h += '<div><span style="color:#4a6a8a;">Seller:</span> ' + esc(b.seller) + '</div>';
    h += '<div><span style="color:#4a6a8a;">Posted:</span> ' + esc(b.posted) + '</div>';
    h += '</div>';
    h += '<div style="font-size:10px;color:#6a8aaa;margin-top:4px;"><span style="color:#4a6a8a;">Data types:</span> ' + esc(b.dataTypes) + '</div>';
    h += '</div>';
  }
  h += '</div>';

  // ── Tab 1: Ransomware Groups ──
  h += '<div id="dr-panel-1" class="dr-panel" style="display:none;">';
  h += '<h3 style="color:#ff2244;font-size:13px;letter-spacing:2px;margin:0 0 10px;border-bottom:1px solid #3a1a1a;padding-bottom:6px;">RANSOMWARE GROUP TRACKER</h3>';
  h += '<table style="width:100%;border-collapse:collapse;font-size:11px;">';
  h += '<tr style="color:#4a6a8a;text-align:left;"><th style="padding:6px 8px;">GROUP</th><th style="padding:6px 8px;">STATUS</th><th style="padding:6px 8px;">VICTIMS 2026</th><th style="padding:6px 8px;">AVG RANSOM</th><th style="padding:6px 8px;">SECTORS</th><th style="padding:6px 8px;">LAST POST</th></tr>';
  for (var ri = 0; ri < _drRansomwareGroups.length; ri++) {
    var rg = _drRansomwareGroups[ri];
    h += '<tr style="border-bottom:1px solid #0f1a24;cursor:pointer;" data-dr-rg="' + ri + '">';
    h += '<td style="padding:6px 8px;color:#ff4444;font-weight:bold;">' + esc(rg.name) + '</td>';
    h += '<td style="padding:6px 8px;color:#ff2244;">' + esc(rg.status) + '</td>';
    h += '<td style="padding:6px 8px;color:#ff8844;">' + rg.victims2026 + '</td>';
    h += '<td style="padding:6px 8px;color:#ffaa22;">' + esc(rg.avgRansom) + '</td>';
    h += '<td style="padding:6px 8px;color:#8ab4d4;font-size:10px;">' + esc(rg.sectors) + '</td>';
    h += '<td style="padding:6px 8px;color:#5a8aaa;">' + esc(rg.lastPost) + '</td>';
    h += '</tr>';
  }
  h += '</table>';
  h += '<div id="dr-rg-detail" style="margin-top:12px;"></div>';
  h += '</div>';

  // ── Tab 2: Tor Exit Nodes ──
  h += '<div id="dr-panel-2" class="dr-panel" style="display:none;">';
  h += '<h3 style="color:#7c5cff;font-size:13px;letter-spacing:2px;margin:0 0 10px;border-bottom:1px solid #1a1a3a;padding-bottom:6px;">TOR EXIT NODE TRACKER (' + _drTorExitNodes.length + ' NODES)</h3>';
  h += '<table style="width:100%;border-collapse:collapse;font-size:11px;">';
  h += '<tr style="color:#4a6a8a;text-align:left;"><th style="padding:6px 8px;">IP ADDRESS</th><th style="padding:6px 8px;">COUNTRY</th><th style="padding:6px 8px;">BANDWIDTH</th><th style="padding:6px 8px;">UPTIME</th><th style="padding:6px 8px;">FLAGS</th><th style="padding:6px 8px;">OPERATOR</th></tr>';
  for (var ni = 0; ni < _drTorExitNodes.length; ni++) {
    var n = _drTorExitNodes[ni];
    h += '<tr style="border-bottom:1px solid #0f1a24;">';
    h += '<td style="padding:6px 8px;color:#7c5cff;font-family:monospace;">' + esc(n.ip) + '</td>';
    h += '<td style="padding:6px 8px;color:#c8d6e5;">' + esc(n.country) + '</td>';
    h += '<td style="padding:6px 8px;color:#44aaff;">' + esc(n.bandwidth) + '</td>';
    h += '<td style="padding:6px 8px;color:#00cc66;">' + esc(n.uptime) + '</td>';
    h += '<td style="padding:6px 8px;color:#8ab4d4;font-size:9px;">' + esc(n.flags) + '</td>';
    h += '<td style="padding:6px 8px;color:#5a8aaa;">' + esc(n.operator) + '</td>';
    h += '</tr>';
  }
  h += '</table></div>';

  // ── Tab 3: IOC Feed ──
  h += '<div id="dr-panel-3" class="dr-panel" style="display:none;">';
  h += '<h3 style="color:#ff6644;font-size:13px;letter-spacing:2px;margin:0 0 10px;border-bottom:1px solid #3a1a1a;padding-bottom:6px;">INDICATORS OF COMPROMISE FEED</h3>';
  for (var ii = 0; ii < _drIOCs.length; ii++) {
    var ioc = _drIOCs[ii];
    var confColor = ioc.confidence === 'critical' ? '#ff2244' : (ioc.confidence === 'high' ? '#ff6644' : (ioc.confidence === 'medium' ? '#ffaa22' : '#5a8aaa'));
    h += '<div style="background:#0f1218;padding:10px 14px;margin-bottom:6px;border-radius:4px;border-left:3px solid ' + confColor + ';">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;flex-wrap:wrap;gap:6px;">';
    h += '<div><span style="color:#4a6a8a;font-size:10px;">' + esc(ioc.type) + ':</span> <span style="color:' + confColor + ';font-family:monospace;font-size:12px;word-break:break-all;">' + esc(ioc.value.length > 50 ? ioc.value.substring(0, 50) + '...' : ioc.value) + '</span></div>';
    h += '<span style="color:' + confColor + ';font-size:9px;border:1px solid ' + confColor + ';padding:1px 6px;border-radius:2px;">' + esc(ioc.confidence.toUpperCase()) + '</span>';
    h += '</div>';
    h += '<div style="font-size:10px;color:#8ab4d4;margin-bottom:3px;">' + esc(ioc.context) + '</div>';
    h += '<div style="font-size:9px;color:#4a6a8a;">Source: ' + esc(ioc.source) + ' | Tags: ' + ioc.tags.map(function(t) { return '<span style="background:#1a1a2a;color:#5a8aaa;padding:1px 5px;border-radius:2px;margin-right:3px;">' + esc(t) + '</span>'; }).join('') + '</div>';
    h += '</div>';
  }
  h += '</div>';

  // ── Tab 4: Paste Monitoring ──
  h += '<div id="dr-panel-4" class="dr-panel" style="display:none;">';
  h += '<h3 style="color:#ffaa22;font-size:13px;letter-spacing:2px;margin:0 0 10px;border-bottom:1px solid #3a2a0a;padding-bottom:6px;">PASTE SITE MONITORING</h3>';
  for (var pi = 0; pi < _drPasteLeaks.length; pi++) {
    var pl = _drPasteLeaks[pi];
    var plStatus = pl.status === 'ACTIVE' ? '#ff2244' : '#5a8aaa';
    h += '<div style="background:#0f1218;padding:10px 14px;margin-bottom:6px;border-radius:4px;border-left:3px solid ' + plStatus + ';">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;flex-wrap:wrap;gap:6px;">';
    h += '<span style="color:#ffaa22;font-size:12px;font-weight:bold;">' + esc(pl.title) + '</span>';
    h += '<span style="color:' + plStatus + ';font-size:10px;">' + esc(pl.status) + '</span>';
    h += '</div>';
    h += '<div style="font-size:10px;color:#8ab4d4;line-height:1.6;">';
    h += '<span style="color:#4a6a8a;">Site:</span> ' + esc(pl.site) + ' | <span style="color:#4a6a8a;">Size:</span> ' + esc(pl.size) + ' | <span style="color:#4a6a8a;">Posted:</span> ' + esc(pl.posted) + '<br>';
    h += '<span style="color:#4a6a8a;">Preview:</span> <span style="color:#6a8aaa;font-style:italic;">' + esc(pl.contentPreview) + '</span>';
    if (pl.matchedBreach) {
      h += '<br><span style="color:#ff4444;">Matched breach: ' + esc(pl.matchedBreach) + '</span>';
    }
    h += '</div></div>';
  }
  h += '</div>';

  h += '</div>';
  el.innerHTML = h;

  // ── Wire tab switching ──
  el.addEventListener('click', function(e) {
    var tabBtn = e.target.closest('.dr-tab');
    if (tabBtn) {
      var idx = tabBtn.getAttribute('data-dr-tab');
      var allTabs = el.querySelectorAll('.dr-tab');
      var allPanels = el.querySelectorAll('.dr-panel');
      for (var a = 0; a < allTabs.length; a++) {
        allTabs[a].style.background = '#0f1218';
        allTabs[a].style.borderColor = '#1a2a3a';
        allTabs[a].style.color = '#5a7a9a';
      }
      tabBtn.style.background = '#2a0a0a';
      tabBtn.style.borderColor = '#ff2244';
      tabBtn.style.color = '#ff2244';
      for (var b = 0; b < allPanels.length; b++) {
        allPanels[b].style.display = 'none';
      }
      var panel = document.getElementById('dr-panel-' + idx);
      if (panel) panel.style.display = 'block';
      return;
    }

    // Ransomware group detail expand
    var rgRow = e.target.closest('[data-dr-rg]');
    if (rgRow) {
      var rgIdx = parseInt(rgRow.getAttribute('data-dr-rg'), 10);
      var rg = _drRansomwareGroups[rgIdx];
      if (!rg) return;
      var detail = document.getElementById('dr-rg-detail');
      if (!detail) return;
      detail.innerHTML =
        '<div style="background:#1a0a0a;padding:14px;border-radius:4px;border:1px solid #3a1a1a;">' +
        '<div style="color:#ff4444;font-size:14px;font-weight:bold;margin-bottom:8px;">' + esc(rg.name) + ' — DETAILED PROFILE</div>' +
        '<div style="font-size:11px;color:#8ab4d4;line-height:1.8;">' +
        '<div><span style="color:#4a6a8a;">TTPs:</span> ' + esc(rg.ttps) + '</div>' +
        '<div><span style="color:#4a6a8a;">Infrastructure:</span> ' + esc(rg.infra) + '</div>' +
        '<div><span style="color:#4a6a8a;">Target Sectors:</span> ' + esc(rg.sectors) + '</div>' +
        '<div><span style="color:#4a6a8a;">Intel Notes:</span> ' + esc(rg.notes) + '</div>' +
        '</div></div>';
    }
  });
};
