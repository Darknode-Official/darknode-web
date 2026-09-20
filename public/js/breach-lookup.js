// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Data Breach Intelligence Dashboard — major breach database, search, timeline
// All data is hardcoded reference — no external API needed

var esc = function(s) { return String(s != null ? s : '').replace(/[&<>"']/g, function(c) { return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); };

var BREACHES = [
  { company: 'Yahoo', year: 2013, records: 3000000000, domain: 'yahoo.com', data: ['emails','passwords','names','dates of birth','security questions'], vector: 'State-sponsored attack', sector: 'Technology', severity: 'critical' },
  { company: 'National Public Data', year: 2024, records: 2900000000, domain: 'nationalpublicdata.com', data: ['SSNs','names','addresses','phone numbers'], vector: 'Unsecured database', sector: 'Data Broker', severity: 'critical' },
  { company: 'First American Financial', year: 2019, records: 885000000, domain: 'firstam.com', data: ['bank records','SSNs','wire transactions','mortgage docs'], vector: 'Authentication bypass', sector: 'Financial', severity: 'critical' },
  { company: 'Facebook', year: 2019, records: 540000000, domain: 'facebook.com', data: ['user IDs','phone numbers','comments','likes','account names'], vector: 'Unsecured S3 bucket', sector: 'Social Media', severity: 'critical' },
  { company: 'Marriott', year: 2018, records: 500000000, domain: 'marriott.com', data: ['names','passport numbers','emails','credit cards','travel dates'], vector: 'Starwood network compromise (APT)', sector: 'Hospitality', severity: 'critical' },
  { company: 'LinkedIn', year: 2021, records: 700000000, domain: 'linkedin.com', data: ['emails','phone numbers','names','geolocation','work history'], vector: 'API scraping', sector: 'Social Media', severity: 'high' },
  { company: 'Adobe', year: 2013, records: 153000000, domain: 'adobe.com', data: ['emails','passwords (encrypted)','usernames','credit cards'], vector: 'Server compromise', sector: 'Technology', severity: 'critical' },
  { company: 'Equifax', year: 2017, records: 147000000, domain: 'equifax.com', data: ['SSNs','birth dates','addresses','driver licenses','credit card numbers'], vector: 'Apache Struts CVE-2017-5638', sector: 'Financial', severity: 'critical' },
  { company: 'eBay', year: 2014, records: 145000000, domain: 'ebay.com', data: ['emails','passwords','names','addresses','phone numbers'], vector: 'Employee credential compromise', sector: 'E-Commerce', severity: 'high' },
  { company: 'Heartland Payment Systems', year: 2008, records: 130000000, domain: 'heartland.us', data: ['credit card numbers','cardholder names'], vector: 'SQL injection → malware', sector: 'Financial', severity: 'critical' },
  { company: 'Target', year: 2013, records: 110000000, domain: 'target.com', data: ['credit cards','names','addresses','phone numbers','emails'], vector: 'HVAC vendor compromise → POS malware', sector: 'Retail', severity: 'critical' },
  { company: 'Capital One', year: 2019, records: 106000000, domain: 'capitalone.com', data: ['SSNs','bank accounts','credit scores','addresses','names'], vector: 'AWS SSRF misconfiguration', sector: 'Financial', severity: 'critical' },
  { company: 'Zynga', year: 2019, records: 218000000, domain: 'zynga.com', data: ['emails','passwords','usernames','phone numbers'], vector: 'Database breach', sector: 'Gaming', severity: 'high' },
  { company: 'Under Armour / MyFitnessPal', year: 2018, records: 150000000, domain: 'myfitnesspal.com', data: ['emails','usernames','passwords (bcrypt)'], vector: 'Database compromise', sector: 'Health/Fitness', severity: 'high' },
  { company: 'Exactis', year: 2018, records: 340000000, domain: 'exactis.com', data: ['emails','phone numbers','addresses','interests','habits','children ages'], vector: 'Unsecured Elasticsearch', sector: 'Data Broker', severity: 'critical' },
  { company: 'Twitter', year: 2022, records: 5400000, domain: 'twitter.com', data: ['emails','phone numbers','user IDs'], vector: 'API vulnerability (CVE-2021-XXXX)', sector: 'Social Media', severity: 'medium' },
  { company: 'MOVEit (multiple)', year: 2023, records: 77000000, domain: 'progress.com', data: ['varied — SSNs, financial records, personal data'], vector: 'CVE-2023-34362 (SQLi zero-day)', sector: 'Multi-sector', severity: 'critical' },
  { company: 'T-Mobile', year: 2021, records: 77000000, domain: 'tmobile.com', data: ['SSNs','names','dates of birth','driver licenses','IMEI'], vector: 'API exploitation', sector: 'Telecom', severity: 'critical' },
  { company: 'Anthem', year: 2015, records: 78800000, domain: 'anthem.com', data: ['SSNs','names','dates of birth','addresses','employment info'], vector: 'Spear-phishing (APT — China)', sector: 'Healthcare', severity: 'critical' },
  { company: 'Sony PlayStation Network', year: 2011, records: 77000000, domain: 'sony.com', data: ['emails','passwords','names','addresses','credit cards','PSN IDs'], vector: 'SQL injection + known vulnerability', sector: 'Gaming', severity: 'critical' },
  { company: 'JP Morgan Chase', year: 2014, records: 83000000, domain: 'jpmorgan.com', data: ['names','emails','phone numbers','addresses'], vector: 'Server compromise via stolen credentials', sector: 'Financial', severity: 'high' },
  { company: 'Home Depot', year: 2014, records: 56000000, domain: 'homedepot.com', data: ['credit cards','debit cards','emails'], vector: 'Vendor credential → POS RAM scraper', sector: 'Retail', severity: 'critical' },
  { company: 'Dropbox', year: 2012, records: 68000000, domain: 'dropbox.com', data: ['emails','passwords (bcrypt + SHA-1)'], vector: 'Employee credential reuse from LinkedIn', sector: 'Technology', severity: 'high' },
  { company: 'Uber', year: 2016, records: 57000000, domain: 'uber.com', data: ['names','emails','phone numbers','driver license numbers'], vector: 'GitHub credentials → AWS S3', sector: 'Transportation', severity: 'high' },
  { company: 'Canva', year: 2019, records: 139000000, domain: 'canva.com', data: ['emails','usernames','names','cities','passwords (bcrypt)'], vector: 'Database compromise', sector: 'Technology', severity: 'high' },
  { company: 'MGM Resorts', year: 2023, records: 10600000, domain: 'mgmresorts.com', data: ['SSNs','passport numbers','driver licenses'], vector: 'Social engineering (Scattered Spider)', sector: 'Hospitality', severity: 'critical' },
  { company: 'Change Healthcare', year: 2024, records: 100000000, domain: 'changehealthcare.com', data: ['medical records','SSNs','insurance data','billing records'], vector: 'Stolen credentials → ALPHV ransomware', sector: 'Healthcare', severity: 'critical' },
  { company: 'SolarWinds', year: 2020, records: 18000, domain: 'solarwinds.com', data: ['source code','internal communications','government data'], vector: 'Supply chain (SUNBURST backdoor, APT29)', sector: 'Technology', severity: 'critical' },
  { company: 'Twitch', year: 2021, records: 0, domain: 'twitch.tv', data: ['full source code','creator payouts','internal tools','SDKs'], vector: 'Server misconfiguration', sector: 'Technology', severity: 'high' },
  { company: 'LastPass', year: 2022, records: 25000000, domain: 'lastpass.com', data: ['encrypted vaults','master password hashes','customer metadata'], vector: 'DevOps engineer home computer compromise', sector: 'Cybersecurity', severity: 'critical' },
  { company: 'Okta', year: 2023, records: 0, domain: 'okta.com', data: ['support case files','HAR files with session tokens','customer names'], vector: 'Stolen support credentials', sector: 'Cybersecurity', severity: 'high' },
  { company: 'MOVEit — BBC/British Airways', year: 2023, records: 100000, domain: 'bbc.co.uk', data: ['employee NINOs','names','dates of birth','home addresses'], vector: 'CVE-2023-34362 (Cl0p)', sector: 'Media', severity: 'critical' },
  { company: 'Microsoft (Storm-0558)', year: 2023, records: 0, domain: 'microsoft.com', data: ['government emails','State Dept','Commerce Dept','congressional staff'], vector: 'MSA signing key theft → token forging', sector: 'Government', severity: 'critical' },
  { company: 'Optus', year: 2022, records: 9800000, domain: 'optus.com.au', data: ['names','dates of birth','passport numbers','driver licenses','emails'], vector: 'Unauthenticated API endpoint', sector: 'Telecom', severity: 'critical' },
  { company: 'Medibank', year: 2022, records: 9700000, domain: 'medibank.com.au', data: ['medical records','mental health data','names','addresses','Medicare numbers'], vector: 'Stolen credentials (REvil-linked)', sector: 'Healthcare', severity: 'critical' },
  { company: 'Colonial Pipeline', year: 2021, records: 0, domain: 'colpipe.com', data: ['operational shutdown','fuel supply disruption'], vector: 'Compromised VPN password (no MFA)', sector: 'Energy', severity: 'critical' },
  { company: 'Kaseya VSA', year: 2021, records: 1500, domain: 'kaseya.com', data: ['MSP customers encrypted','ransom demanded'], vector: 'Zero-day supply chain (REvil)', sector: 'Technology', severity: 'critical' },
  { company: 'GoDaddy', year: 2021, records: 1200000, domain: 'godaddy.com', data: ['emails','WordPress passwords','SSL keys','admin credentials'], vector: 'Compromised password for provisioning system', sector: 'Technology', severity: 'high' },
  { company: 'Accellion FTA', year: 2021, records: 3500000, domain: 'accellion.com', data: ['varied — health records, financial data, personal info'], vector: 'Zero-day in legacy file transfer (Cl0p/FIN11)', sector: 'Multi-sector', severity: 'critical' },
  { company: 'Wattpad', year: 2020, records: 271000000, domain: 'wattpad.com', data: ['emails','usernames','passwords (bcrypt)','names','dates of birth'], vector: 'Database compromise', sector: 'Technology', severity: 'high' },
  { company: 'CAM4', year: 2020, records: 10880000000, domain: 'cam4.com', data: ['emails','IP addresses','usernames','payment logs','chat logs'], vector: 'Misconfigured Elasticsearch', sector: 'Adult', severity: 'critical' },
  { company: 'Cit0day', year: 2020, records: 226000000, domain: 'N/A', data: ['emails','passwords from 23,000 breached databases'], vector: 'Aggregated breach compilation', sector: 'N/A', severity: 'critical' },
  { company: 'Clearview AI', year: 2020, records: 3000000000, domain: 'clearview.ai', data: ['scraped photos','facial recognition data','source URLs'], vector: 'Mass web scraping', sector: 'Surveillance', severity: 'high' },
  { company: 'Nintendo', year: 2020, records: 300000, domain: 'nintendo.com', data: ['Nintendo Network IDs','emails','dates of birth','countries'], vector: 'Credential stuffing via legacy NNID', sector: 'Gaming', severity: 'medium' },
  { company: 'Zoom', year: 2020, records: 500000, domain: 'zoom.us', data: ['emails','passwords','meeting URLs','host keys'], vector: 'Credential stuffing → dark web sale', sector: 'Technology', severity: 'medium' }
];

function _blFormatNum(n) {
  if (n >= 1000000000) return (n / 1000000000).toFixed(1) + 'B';
  if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
  if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
  return String(n);
}

function _blSevColor(s) {
  if (s === 'critical') return '#ff4444';
  if (s === 'high') return '#ff8800';
  if (s === 'medium') return '#ffcc00';
  return '#00cc88';
}

function _blFilter(query, yearFilter, dataFilter) {
  return BREACHES.filter(function(b) {
    if (query && b.company.toLowerCase().indexOf(query.toLowerCase()) === -1 && b.domain.toLowerCase().indexOf(query.toLowerCase()) === -1) return false;
    if (yearFilter && yearFilter !== 'all' && String(b.year) !== yearFilter) return false;
    if (dataFilter && dataFilter !== 'all' && b.data.indexOf(dataFilter) === -1) return false;
    return true;
  });
}

function _blRenderCards(breaches, container) {
  if (!container) return;
  if (breaches.length === 0) { container.innerHTML = '<div style="color:#4a6a8a;font-family:monospace;font-size:11px;text-align:center;padding:30px;">No breaches match your filters.</div>'; return; }

  var h = '';
  for (var i = 0; i < breaches.length; i++) {
    var b = breaches[i];
    var sevColor = _blSevColor(b.severity);
    h += '<div style="background:#0a0e1a;border:1px solid #1a2a44;border-left:3px solid ' + sevColor + ';border-radius:4px;padding:12px 16px;margin-bottom:8px;">';
    h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;">';
    h += '<div style="font-family:monospace;font-size:14px;color:#c8d6e5;font-weight:bold;">' + esc(b.company) + '</div>';
    h += '<div style="display:flex;gap:8px;align-items:center;">';
    h += '<span style="font-family:monospace;font-size:10px;color:#4a6a8a;">' + b.year + '</span>';
    h += '<span style="background:' + sevColor + '22;color:' + sevColor + ';font-size:9px;font-family:monospace;padding:2px 6px;border-radius:2px;border:1px solid ' + sevColor + '44;font-weight:bold;letter-spacing:1px;">' + b.severity.toUpperCase() + '</span>';
    h += '</div></div>';
    h += '<div style="display:flex;gap:16px;font-family:monospace;font-size:11px;margin-bottom:6px;">';
    h += '<span style="color:#ff6644;font-weight:bold;">' + _blFormatNum(b.records) + ' records</span>';
    h += '<span style="color:#4a6a8a;">' + esc(b.domain) + '</span>';
    h += '<span style="color:#4a6a8a;">' + esc(b.sector) + '</span>';
    h += '</div>';
    h += '<div style="font-family:monospace;font-size:10px;color:#8ab4d4;margin-bottom:4px;">Vector: ' + esc(b.vector) + '</div>';
    h += '<div style="display:flex;gap:4px;flex-wrap:wrap;">';
    for (var d = 0; d < b.data.length; d++) {
      h += '<span style="background:#0a1a2a;color:#5a8aaa;font-size:8px;font-family:monospace;padding:1px 5px;border-radius:2px;border:1px solid #1a2a44;">' + esc(b.data[d]) + '</span>';
    }
    h += '</div></div>';
  }
  container.innerHTML = h;
}

window.renderBreachLookup = function(container) {
  var totalRecords = 0;
  var sectors = {};
  var vectors = {};
  var years = {};
  for (var i = 0; i < BREACHES.length; i++) {
    totalRecords += BREACHES[i].records;
    sectors[BREACHES[i].sector] = (sectors[BREACHES[i].sector] || 0) + 1;
    vectors[BREACHES[i].vector] = (vectors[BREACHES[i].vector] || 0) + 1;
    years[BREACHES[i].year] = (years[BREACHES[i].year] || 0) + 1;
  }

  var h = '';
  h += '<div style="padding:20px 24px;max-width:1100px;margin:0 auto;">';
  h += '<h2 style="margin:0 0 4px;font-size:20px;color:#ff4444;font-family:monospace;letter-spacing:2px;text-transform:uppercase;">BREACH INTELLIGENCE</h2>';
  h += '<div style="color:#4a6a8a;font-size:11px;font-family:monospace;margin-bottom:16px;">Database of ' + BREACHES.length + ' major data breaches — ' + _blFormatNum(totalRecords) + '+ records exposed</div>';

  // Stats row
  h += '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:16px;">';
  h += '<div style="background:#0a0e1a;border:1px solid #ff444433;border-radius:6px;padding:12px;text-align:center;"><div style="color:#ff4444;font-size:22px;font-weight:bold;font-family:monospace;">' + _blFormatNum(totalRecords) + '</div><div style="color:#4a6a8a;font-size:9px;font-family:monospace;letter-spacing:1px;">TOTAL RECORDS</div></div>';
  h += '<div style="background:#0a0e1a;border:1px solid #ff880033;border-radius:6px;padding:12px;text-align:center;"><div style="color:#ff8800;font-size:22px;font-weight:bold;font-family:monospace;">' + BREACHES.length + '</div><div style="color:#4a6a8a;font-size:9px;font-family:monospace;letter-spacing:1px;">BREACHES TRACKED</div></div>';
  h += '<div style="background:#0a0e1a;border:1px solid #00aaff33;border-radius:6px;padding:12px;text-align:center;"><div style="color:#00aaff;font-size:22px;font-weight:bold;font-family:monospace;">' + Object.keys(sectors).length + '</div><div style="color:#4a6a8a;font-size:9px;font-family:monospace;letter-spacing:1px;">SECTORS HIT</div></div>';
  h += '<div style="background:#0a0e1a;border:1px solid #00ff8833;border-radius:6px;padding:12px;text-align:center;"><div style="color:#00ff88;font-size:22px;font-weight:bold;font-family:monospace;">' + BREACHES.filter(function(b) { return b.severity === 'critical'; }).length + '</div><div style="color:#4a6a8a;font-size:9px;font-family:monospace;letter-spacing:1px;">CRITICAL</div></div>';
  h += '</div>';

  // Timeline
  h += '<div style="margin-bottom:16px;">';
  h += '<div style="color:#00aaff;font-size:10px;font-family:monospace;letter-spacing:2px;margin-bottom:6px;">BREACH TIMELINE</div>';
  h += '<div style="display:flex;gap:3px;align-items:flex-end;height:60px;padding:0 4px;background:#080c14;border:1px solid #1a2a44;border-radius:6px;overflow-x:auto;">';
  var sortedYears = Object.keys(years).sort();
  var maxY = Math.max.apply(null, Object.values(years));
  for (var yi = 0; yi < sortedYears.length; yi++) {
    var yr = sortedYears[yi];
    var barH = Math.max(4, (years[yr] / maxY) * 50);
    h += '<div style="display:flex;flex-direction:column;align-items:center;min-width:28px;">';
    h += '<div style="width:20px;height:' + barH + 'px;background:linear-gradient(180deg,#ff4444,#ff880088);border-radius:2px 2px 0 0;"></div>';
    h += '<div style="font-size:7px;color:#4a6a8a;font-family:monospace;margin-top:2px;">' + yr + '</div>';
    h += '</div>';
  }
  h += '</div></div>';

  // Filters
  h += '<div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;align-items:center;">';
  h += '<input id="bl-search" type="text" placeholder="Search company or domain..." oninput="_blDoFilter()" style="flex:1;min-width:200px;background:#0a0e1a;border:1px solid #1a2a44;border-radius:6px;padding:8px 12px;color:#c8d6e5;font-family:monospace;font-size:12px;outline:none;">';
  h += '<select id="bl-year" onchange="_blDoFilter()" style="background:#0a0e1a;border:1px solid #1a2a44;border-radius:6px;padding:8px;color:#c8d6e5;font-family:monospace;font-size:11px;">';
  h += '<option value="all">All Years</option>';
  for (var y = 2024; y >= 2008; y--) { h += '<option value="' + y + '">' + y + '</option>'; }
  h += '</select>';
  h += '<select id="bl-data" onchange="_blDoFilter()" style="background:#0a0e1a;border:1px solid #1a2a44;border-radius:6px;padding:8px;color:#c8d6e5;font-family:monospace;font-size:11px;">';
  h += '<option value="all">All Data Types</option>';
  var allDataTypes = {};
  BREACHES.forEach(function(b) { b.data.forEach(function(d) { allDataTypes[d] = 1; }); });
  Object.keys(allDataTypes).sort().forEach(function(d) { h += '<option value="' + esc(d) + '">' + esc(d) + '</option>'; });
  h += '</select>';
  h += '</div>';

  // Breach cards
  h += '<div id="bl-cards" style="max-height:600px;overflow-y:auto;scrollbar-width:thin;scrollbar-color:#1a3050 transparent;"></div>';
  h += '</div>';

  container.innerHTML = h;

  // Initial render sorted by records descending
  var sorted = BREACHES.slice().sort(function(a, b) { return b.records - a.records; });
  _blRenderCards(sorted, document.getElementById('bl-cards'));
};

window._blDoFilter = function() {
  var q = (document.getElementById('bl-search') || {}).value || '';
  var yr = (document.getElementById('bl-year') || {}).value || 'all';
  var dt = (document.getElementById('bl-data') || {}).value || 'all';
  var filtered = _blFilter(q, yr, dt).sort(function(a, b) { return b.records - a.records; });
  _blRenderCards(filtered, document.getElementById('bl-cards'));
};
