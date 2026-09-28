// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Threat Intelligence Dashboard — visualises the saved ThreatFox / URLhaus feed snapshots
// (/data/feeds/*.json, written by tools/threat-feed-sync.py). Not a live feed.

const COUNTRIES = {
  US: { name: "United States", lat: 39.8, lon: -98.5, cx: 0.225, cy: 0.38 },
  CN: { name: "China", lat: 35.8, lon: 104.1, cx: 0.78, cy: 0.37 },
  RU: { name: "Russia", lat: 61.5, lon: 105.3, cx: 0.72, cy: 0.22 },
  DE: { name: "Germany", lat: 51.1, lon: 10.4, cx: 0.52, cy: 0.30 },
  GB: { name: "United Kingdom", lat: 55.3, lon: -3.4, cx: 0.48, cy: 0.27 },
  FR: { name: "France", lat: 46.2, lon: 2.2, cx: 0.50, cy: 0.32 },
  JP: { name: "Japan", lat: 36.2, lon: 138.2, cx: 0.88, cy: 0.37 },
  KR: { name: "South Korea", lat: 35.9, lon: 127.7, cx: 0.85, cy: 0.38 },
  BR: { name: "Brazil", lat: -14.2, lon: -51.9, cx: 0.32, cy: 0.62 },
  IN: { name: "India", lat: 20.6, lon: 78.9, cx: 0.70, cy: 0.44 },
  AU: { name: "Australia", lat: -25.3, lon: 133.7, cx: 0.87, cy: 0.68 },
  CA: { name: "Canada", lat: 56.1, lon: -106.3, cx: 0.20, cy: 0.22 },
  NL: { name: "Netherlands", lat: 52.1, lon: 5.3, cx: 0.51, cy: 0.29 },
  UA: { name: "Ukraine", lat: 48.3, lon: 31.1, cx: 0.57, cy: 0.30 },
  IR: { name: "Iran", lat: 32.4, lon: 53.6, cx: 0.62, cy: 0.39 },
  KP: { name: "North Korea", lat: 40.3, lon: 127.5, cx: 0.85, cy: 0.36 },
  IL: { name: "Israel", lat: 31.0, lon: 34.8, cx: 0.58, cy: 0.40 },
  SG: { name: "Singapore", lat: 1.3, lon: 103.8, cx: 0.78, cy: 0.52 },
  ZA: { name: "South Africa", lat: -30.5, lon: 22.9, cx: 0.55, cy: 0.72 },
  NG: { name: "Nigeria", lat: 9.1, lon: 8.6, cx: 0.50, cy: 0.50 },
  SE: { name: "Sweden", lat: 60.1, lon: 18.6, cx: 0.53, cy: 0.23 },
  PL: { name: "Poland", lat: 51.9, lon: 19.1, cx: 0.54, cy: 0.29 },
  TR: { name: "Turkey", lat: 38.9, lon: 35.2, cx: 0.58, cy: 0.36 },
  EG: { name: "Egypt", lat: 26.8, lon: 30.8, cx: 0.56, cy: 0.44 },
  MX: { name: "Mexico", lat: 23.6, lon: -102.5, cx: 0.18, cy: 0.45 },
  AR: { name: "Argentina", lat: -38.4, lon: -63.6, cx: 0.28, cy: 0.75 },
  ID: { name: "Indonesia", lat: -0.8, lon: 113.9, cx: 0.80, cy: 0.53 },
  TH: { name: "Thailand", lat: 15.8, lon: 100.9, cx: 0.76, cy: 0.46 },
  VN: { name: "Vietnam", lat: 14.0, lon: 108.2, cx: 0.78, cy: 0.47 },
  PH: { name: "Philippines", lat: 12.8, lon: 121.7, cx: 0.83, cy: 0.48 },
  RO: { name: "Romania", lat: 45.9, lon: 24.9, cx: 0.55, cy: 0.32 },
  CZ: { name: "Czech Republic", lat: 49.8, lon: 15.5, cx: 0.53, cy: 0.30 },
  MY: { name: "Malaysia", lat: 4.2, lon: 101.9, cx: 0.77, cy: 0.51 },
  CO: { name: "Colombia", lat: 4.5, lon: -74.3, cx: 0.26, cy: 0.52 },
  CL: { name: "Chile", lat: -35.6, lon: -71.5, cx: 0.26, cy: 0.73 },
  PK: { name: "Pakistan", lat: 30.3, lon: 69.3, cx: 0.66, cy: 0.40 },
  BD: { name: "Bangladesh", lat: 23.6, lon: 90.3, cx: 0.72, cy: 0.44 },
  SA: { name: "Saudi Arabia", lat: 23.8, lon: 45.0, cx: 0.60, cy: 0.43 },
  AE: { name: "UAE", lat: 23.4, lon: 53.8, cx: 0.62, cy: 0.43 },
  IT: { name: "Italy", lat: 41.8, lon: 12.5, cx: 0.52, cy: 0.34 },
  ES: { name: "Spain", lat: 40.4, lon: -3.7, cx: 0.48, cy: 0.35 },
  PT: { name: "Portugal", lat: 39.3, lon: -8.2, cx: 0.47, cy: 0.35 },
  NO: { name: "Norway", lat: 60.4, lon: 8.4, cx: 0.51, cy: 0.22 },
  FI: { name: "Finland", lat: 61.9, lon: 25.7, cx: 0.55, cy: 0.21 },
  DK: { name: "Denmark", lat: 56.2, lon: 9.5, cx: 0.51, cy: 0.26 },
  CH: { name: "Switzerland", lat: 46.8, lon: 8.2, cx: 0.51, cy: 0.32 },
  AT: { name: "Austria", lat: 47.5, lon: 14.5, cx: 0.53, cy: 0.32 },
  BE: { name: "Belgium", lat: 50.5, lon: 4.4, cx: 0.50, cy: 0.30 },
  IE: { name: "Ireland", lat: 53.1, lon: -7.6, cx: 0.47, cy: 0.28 },
  NZ: { name: "New Zealand", lat: -40.9, lon: 174.8, cx: 0.94, cy: 0.74 },
};

const ATTACK_TYPES = [
  { name: "DDoS", weight: 25, color: "#ef4444" },
  { name: "Brute Force", weight: 20, color: "#f97316" },
  { name: "SQL Injection", weight: 12, color: "#eab308" },
  { name: "XSS", weight: 10, color: "#22c55e" },
  { name: "Malware C2", weight: 8, color: "#3b82f6" },
  { name: "Port Scan", weight: 15, color: "#8b5cf6" },
  { name: "Phishing", weight: 5, color: "#ec4899" },
  { name: "Ransomware", weight: 3, color: "#dc2626" },
  { name: "Data Exfil", weight: 2, color: "#14b8a6" },
];

const PROTOCOLS = [
  { name: "TCP", pct: 68 }, { name: "UDP", pct: 22 }, { name: "ICMP", pct: 6 },
  { name: "HTTP/S", pct: 45 }, { name: "SSH", pct: 15 }, { name: "DNS", pct: 12 },
  { name: "SMB", pct: 8 }, { name: "RDP", pct: 7 }, { name: "FTP", pct: 5 },
  { name: "SMTP", pct: 4 }, { name: "Telnet", pct: 3 }, { name: "SNMP", pct: 1 },
];

const TOP_PORTS = [
  { port: 22, name: "SSH", hits: 0 }, { port: 80, name: "HTTP", hits: 0 },
  { port: 443, name: "HTTPS", hits: 0 }, { port: 445, name: "SMB", hits: 0 },
  { port: 3389, name: "RDP", hits: 0 }, { port: 23, name: "Telnet", hits: 0 },
  { port: 3306, name: "MySQL", hits: 0 }, { port: 8080, name: "HTTP-Alt", hits: 0 },
  { port: 21, name: "FTP", hits: 0 }, { port: 25, name: "SMTP", hits: 0 },
  { port: 53, name: "DNS", hits: 0 }, { port: 1433, name: "MSSQL", hits: 0 },
  { port: 5432, name: "Postgres", hits: 0 }, { port: 6379, name: "Redis", hits: 0 },
  { port: 27017, name: "MongoDB", hits: 0 },
];


var esc = function(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function(c) { return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]; }); };

// Snapshot metadata for the header label: { source, updated }.
var _tdSnapshot = null;

function fetchThreats() {
  return fetch('/data/feeds/threat-iocs.json')
  .then(function(r) { return r.json(); })
  .then(function(feed) {
    if (feed && feed.data && feed.data.length > 0) {
      _tdSnapshot = { source: feed.source || 'ThreatFox (abuse.ch)', updated: feed.updated || null };
      // Snapshot entries use camelCase (iocValue, iocType, confidenceLevel,
      // firstSeen); map them to the snake_case names parseIOC reads.
      return feed.data.slice(0, 100).map(function(e) {
        return {
          ioc_value: e.ioc_value || e.iocValue || '',
          ioc_type: e.ioc_type || e.iocType || '',
          threat_type: e.threat_type || e.threatType || '',
          threat_type_desc: e.threat_type_desc || e.threatTypeDesc || ((e.tags || []).indexOf('c2') !== -1 ? 'Botnet C2' : ''),
          malware_printable: e.malware_printable || e.malwarePrintable || e.malware || 'unknown',
          confidence_level: e.confidence_level != null ? e.confidence_level : (e.confidenceLevel || 0),
          first_seen_utc: e.first_seen_utc || e.firstSeen || '',
          tags: e.tags || [],
          reporter: e.reporter || '',
        };
      });
    }
    return null;
  })
  .catch(function() { return null; });
}

function fetchURLhaus() {
  return fetch('/data/feeds/malware-urls.json')
  .then(function(r) { return r.json(); })
  .then(function(feed) {
    if (feed && feed.data && feed.data.length > 0) {
      _tdSnapshot = { source: feed.source || 'URLhaus (abuse.ch)', updated: feed.updated || null };
      return feed.data.map(function(u) {
        return {
          ioc_value: u.url || u.host || '',
          ioc_type: u.url ? 'url' : 'ip:port',
          threat_type: u.threat || u.threat_type || 'malware_download',
          threat_type_desc: u.threat || u.threat_type || 'Malware download',
          malware_printable: (u.tags && u.tags.length > 0) ? u.tags[0] : 'unknown',
          confidence_level: 75,
          first_seen_utc: u.date_added || u.dateAdded || '',
          tags: u.tags || [],
          reporter: 'URLhaus',
        };
      });
    }
    return null;
  })
  .catch(function() { return null; });
}

export function renderThreatDashboard(container) {
  var events = [];
  var totalEvents = 0;
  var interval = null;
  var lastUpdated = null;
  var loadError = null;

  function parseIOC(ioc) {
    var ip = '';
    var port = 0;
    var portName = '';
    var val = ioc.ioc_value || '';

    if (ioc.ioc_type === 'ip:port') {
      var colonIdx = val.lastIndexOf(':');
      if (colonIdx > 0) {
        ip = val.substring(0, colonIdx);
        port = parseInt(val.substring(colonIdx + 1), 10) || 0;
      } else {
        ip = val;
      }
    } else if (ioc.ioc_type === 'url') {
      var hostMatch = val.match(/\/\/([^/:]+)/);
      ip = hostMatch ? hostMatch[1] : val;
    } else {
      ip = val;
    }

    for (var i = 0; i < TOP_PORTS.length; i++) {
      if (TOP_PORTS[i].port === port) { portName = TOP_PORTS[i].name; TOP_PORTS[i].hits++; break; }
    }
    if (!portName && port) portName = 'Port ' + port;

    var confidence = ioc.confidence_level || 0;
    var severity = confidence >= 75 ? 'critical' : confidence >= 50 ? 'high' : 'medium';

    var tsStr = ioc.first_seen_utc || '';
    var tsDate;
    if (tsStr) {
      tsDate = new Date(tsStr.replace(' ', 'T') + (tsStr.indexOf('Z') === -1 && tsStr.indexOf('+') === -1 ? 'Z' : ''));
      if (isNaN(tsDate.getTime())) tsDate = null;
    } else {
      tsDate = null;
    }

    return {
      ts: tsDate,
      ioc: val,
      iocType: ioc.ioc_type || 'unknown',
      threatType: ioc.threat_type_desc || ioc.threat_type || 'Unknown',
      malware: ioc.malware_printable || 'unknown',
      confidence: confidence,
      severity: severity,
      ip: ip,
      port: port,
      portName: portName,
      tags: ioc.tags || [],
      reporter: ioc.reporter || '',
    };
  }

  function loadThreats() {
    return fetchThreats().then(function(data) {
      if (data) return data;
      return fetchURLhaus();
    }).then(function(data) {
      if (!data) {
        loadError = 'Could not load threat intelligence feeds. Run: python3 tools/threat-feed-sync.py to refresh local data.';
        return;
      }
      loadError = null;
      TOP_PORTS.forEach(function(p) { p.hits = 0; });
      events = data.map(parseIOC);
      totalEvents = events.length;
      lastUpdated = new Date();
    });
  }

  function topMalware(n) {
    var counts = {};
    events.forEach(function(e) {
      var m = e.malware || 'unknown';
      counts[m] = (counts[m] || 0) + 1;
    });
    return Object.keys(counts).map(function(name) {
      return { name: name, count: counts[name] };
    }).sort(function(a, b) { return b.count - a.count; }).slice(0, n);
  }

  function topThreatTypes(n) {
    var counts = {};
    events.forEach(function(e) {
      var t = e.threatType || 'unknown';
      counts[t] = (counts[t] || 0) + 1;
    });
    return Object.keys(counts).map(function(name) {
      return { name: name, count: counts[name] };
    }).sort(function(a, b) { return b.count - a.count; }).slice(0, n);
  }

  function iocTypeDistribution() {
    var counts = {};
    events.forEach(function(e) {
      var t = e.iocType || 'unknown';
      counts[t] = (counts[t] || 0) + 1;
    });
    return Object.keys(counts).map(function(name) {
      return { name: name, count: counts[name] };
    }).sort(function(a, b) { return b.count - a.count; });
  }

  function drawMap(canvas) {
    var ctx = canvas.getContext('2d');
    var W = canvas.width, H = canvas.height;
    ctx.clearRect(0, 0, W, H);

    ctx.fillStyle = '#070d1a';
    ctx.fillRect(0, 0, W, H);

    ctx.strokeStyle = 'rgba(0,212,255,0.05)';
    ctx.lineWidth = 0.5;
    for (var x = 0; x < W; x += 40) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke(); }
    for (var y = 0; y < H; y += 40) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke(); }

    var codes = Object.keys(COUNTRIES);
    for (var i = 0; i < codes.length; i++) {
      var c = COUNTRIES[codes[i]];
      var px = c.cx * W, py = c.cy * H;
      ctx.beginPath();
      ctx.arc(px, py, 3, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(0,212,255,0.3)';
      ctx.fill();
    }

    ctx.fillStyle = 'rgba(100,116,139,0.6)';
    ctx.font = '11px system-ui, sans-serif';
    ctx.fillText('Illustrative map: dots mark reference country positions, not IOC locations', 10, H - 10);
  }

  function render() {
    var malware = topMalware(8);
    var threats = topThreatTypes(8);
    var iocTypes = iocTypeDistribution();
    var maxMalwareCount = 1;
    var maxThreatCount = 1;
    var maxIocTypeCount = 1;

    malware.forEach(function(m) { if (m.count > maxMalwareCount) maxMalwareCount = m.count; });
    threats.forEach(function(t) { if (t.count > maxThreatCount) maxThreatCount = t.count; });
    iocTypes.forEach(function(t) { if (t.count > maxIocTypeCount) maxIocTypeCount = t.count; });

    var criticalCount = events.filter(function(e) { return e.severity === 'critical'; }).length;
    var latestThreat = events.length > 0 ? events[0].malware : '--';
    var snapDate = _tdSnapshot && _tdSnapshot.updated ? String(_tdSnapshot.updated).slice(0, 10) : '';
    var snapLabel = _tdSnapshot
      ? 'SAVED SNAPSHOT - ' + totalEvents + ' IOCs from ' + _tdSnapshot.source + (snapDate ? ', updated ' + snapDate : '') + ' (not live)'
      : (loadError ? 'NO DATA' : 'Loading snapshot...');

    var html = '<style>' +
      '.td-wrap{font-family:system-ui,-apple-system,sans-serif;color:#e2e8f0;background:#070d1a;padding:16px;min-height:100vh}' +
      '.td-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:8px}' +
      '.td-header h2{margin:0;font-size:1.4rem;background:linear-gradient(135deg,#00d4ff,#7c5cff);-webkit-background-clip:text;background-clip:text;color:transparent}' +
      '.td-live{display:flex;align-items:center;gap:6px;font-size:.8rem;color:#f59e0b}' +
      '.td-live::before{content:\'\';width:8px;height:8px;border-radius:50%;background:#f59e0b}' +
      '@keyframes td-pulse{0%,100%{opacity:1}50%{opacity:.3}}' +
      '.td-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:16px}' +
      '.td-kpi{background:#0f172a;border:1px solid #1e293b;border-radius:10px;padding:14px;text-align:center}' +
      '.td-kpi-n{font-size:1.6rem;font-weight:700;color:#00d4ff}' +
      '.td-kpi-l{font-size:.7rem;color:#64748b;text-transform:uppercase;letter-spacing:.05em}' +
      '.td-grid{display:grid;grid-template-columns:1fr 320px;gap:16px}' +
      '@media(max-width:1000px){.td-grid{grid-template-columns:1fr}}' +
      '.td-map-wrap{background:#0a1020;border:1px solid #1e293b;border-radius:12px;overflow:hidden;position:relative}' +
      '.td-map-wrap canvas{width:100%;height:auto;display:block}' +
      '.td-panels{display:flex;flex-direction:column;gap:12px}' +
      '.td-panel{background:#0f172a;border:1px solid #1e293b;border-radius:10px;padding:14px}' +
      '.td-panel h4{margin:0 0 10px;font-size:.75rem;color:#64748b;text-transform:uppercase;letter-spacing:.06em}' +
      '.td-bar-row{display:flex;align-items:center;gap:8px;margin-bottom:6px;font-size:.78rem}' +
      '.td-bar-label{width:110px;text-align:right;color:#94a3b8;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}' +
      '.td-bar{flex:1;height:16px;background:#1e293b;border-radius:3px;overflow:hidden}' +
      '.td-bar-fill{height:100%;border-radius:3px;transition:width .3s}' +
      '.td-bar-val{width:36px;font-size:.7rem;color:#64748b;text-align:right;flex-shrink:0}' +
      '.td-log{max-height:200px;overflow-y:auto;font-family:\'JetBrains Mono\',monospace;font-size:.68rem}' +
      '.td-log::-webkit-scrollbar{width:4px}' +
      '.td-log::-webkit-scrollbar-thumb{background:#334155;border-radius:2px}' +
      '.td-log-entry{padding:3px 0;border-bottom:1px solid #0f172a;display:flex;gap:8px;flex-wrap:wrap}' +
      '.td-log-ts{color:#475569;flex-shrink:0}' +
      '.td-log-sev{padding:0 5px;border-radius:3px;font-size:.6rem;font-weight:600;flex-shrink:0}' +
      '.td-log-sev.high{background:#7f1d1d;color:#fca5a5}' +
      '.td-log-sev.medium{background:#713f12;color:#fde047}' +
      '.td-log-sev.critical{background:#581c87;color:#d8b4fe}' +
      '.td-bottom{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:16px}' +
      '@media(max-width:700px){.td-bottom{grid-template-columns:1fr}}' +
      '</style>';

    html += '<div class="td-wrap">' +
      '<div class="td-header"><h2>Threat Intelligence Dashboard</h2>' +
      '<div class="td-live">' + esc(snapLabel) + '</div></div>';

    if (loadError) {
      html += '<div style="background:#1e1215;border:1px solid #7f1d1d;border-radius:8px;padding:14px;margin-bottom:16px;font-size:.82rem;color:#fca5a5">' +
        '<strong>Feed error:</strong> ' + esc(loadError) + '</div>';
    }

    html += '<div class="td-kpis">' +
      '<div class="td-kpi"><div class="td-kpi-n">' + totalEvents + '</div><div class="td-kpi-l">Total IOCs</div></div>' +
      '<div class="td-kpi"><div class="td-kpi-n" style="color:#ef4444">' + criticalCount + '</div><div class="td-kpi-l">High Confidence</div></div>' +
      '<div class="td-kpi"><div class="td-kpi-n">' + iocTypes.length + '</div><div class="td-kpi-l">IOC Types</div></div>' +
      '<div class="td-kpi"><div class="td-kpi-n">' + esc(latestThreat) + '</div><div class="td-kpi-l">Latest Malware</div></div>' +
      '</div>';

    html += '<div class="td-grid">' +
      '<div class="td-map-wrap"><canvas id="td-map" width="800" height="420" aria-label="Illustrative world map (decorative, not live data)"></canvas></div>' +
      '<div class="td-panels">' +
        '<div class="td-panel"><h4>Top Malware Families</h4>' +
        (malware.length === 0 ? '<div style="color:#64748b;font-size:.78rem">Loading threat data...</div>' :
          malware.map(function(m) {
            return '<div class="td-bar-row"><div class="td-bar-label">' + esc(m.name) + '</div>' +
              '<div class="td-bar"><div class="td-bar-fill" style="width:' + ((m.count / maxMalwareCount) * 100) + '%;background:#ef4444"></div></div>' +
              '<div class="td-bar-val">' + m.count + '</div></div>';
          }).join('')) +
        '</div>' +
        '<div class="td-panel"><h4>Threat Types</h4>' +
        (threats.length === 0 ? '<div style="color:#64748b;font-size:.78rem">Loading threat data...</div>' :
          threats.map(function(t) {
            return '<div class="td-bar-row"><div class="td-bar-label">' + esc(t.name) + '</div>' +
              '<div class="td-bar"><div class="td-bar-fill" style="width:' + ((t.count / maxThreatCount) * 100) + '%;background:#3b82f6"></div></div>' +
              '<div class="td-bar-val">' + t.count + '</div></div>';
          }).join('')) +
        '</div>' +
      '</div></div>';

    html += '<div class="td-bottom">' +
      '<div class="td-panel"><h4>IOC Type Distribution</h4>' +
      (iocTypes.length === 0 ? '<div style="color:#64748b;font-size:.78rem">Loading threat data...</div>' :
        iocTypes.map(function(t) {
          return '<div class="td-bar-row"><div class="td-bar-label">' + esc(t.name) + '</div>' +
            '<div class="td-bar"><div class="td-bar-fill" style="width:' + ((t.count / maxIocTypeCount) * 100) + '%;background:#22c55e"></div></div>' +
            '<div class="td-bar-val">' + t.count + '</div></div>';
        }).join('')) +
      '</div>' +
      '<div class="td-panel"><h4>Threat Feed</h4><div class="td-log" id="td-log">' +
      (events.length === 0 ? '<div style="color:#64748b;padding:8px">Loading saved ThreatFox snapshot...</div>' :
        events.slice(0, 30).map(function(e) {
          var ts = (e.ts instanceof Date && !isNaN(e.ts.getTime())) ? e.ts.toISOString().slice(5, 16).replace('T', ' ') : '--';
          return '<div class="td-log-entry">' +
            '<span class="td-log-ts">' + ts + '</span>' +
            '<span class="td-log-sev ' + esc(e.severity) + '">' + esc(e.severity) + '</span>' +
            '<span>' + esc(e.malware) + '</span>' +
            '<span style="color:#64748b">' + esc(e.ioc) + (e.portName ? ' (' + esc(e.portName) + ')' : '') + '</span>' +
            '</div>';
        }).join('')) +
      '</div></div></div>';

    html += '</div>';
    container.innerHTML = html;

    var canvas = container.querySelector('#td-map');
    if (canvas) drawMap(canvas);
  }

  // Show loading state, then fetch real threat data
  render();
  loadThreats().then(function() { render(); });

  // Re-read the snapshot files every 5 minutes (picks up a newer sync if one was deployed)
  interval = setInterval(function() {
    loadThreats().then(function() { render(); });
  }, 300000);

  // Cleanup on remove
  var observer = new MutationObserver(function() {
    if (!document.contains(container)) { clearInterval(interval); observer.disconnect(); }
  });
  if (container.parentNode) observer.observe(container.parentNode, { childList: true });
}
