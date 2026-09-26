// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Network Traffic Analyzer — protocol distribution, top talkers, anomaly detection
// All analysis runs client-side. Nothing leaves the browser.

var esc = function(s) {
  return String(s != null ? s : '').replace(/[&<>"']/g, function(c) {
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
  });
};

// ── Sample data generators ──────────────────────────────────────────────────

function _taGenProtocols() {
  return [
    { name: 'HTTPS', port: 443, packets: 48210, bytes: 62418920, pct: 42.1 },
    { name: 'HTTP', port: 80, packets: 18340, bytes: 21507600, pct: 16.0 },
    { name: 'DNS', port: 53, packets: 14920, bytes: 1790400, pct: 13.0 },
    { name: 'SSH', port: 22, packets: 8210, bytes: 5746100, pct: 7.2 },
    { name: 'SMTP', port: 25, packets: 4120, bytes: 4944000, pct: 3.6 },
    { name: 'SMB', port: 445, packets: 3890, bytes: 6224000, pct: 3.4 },
    { name: 'RDP', port: 3389, packets: 3210, bytes: 7062000, pct: 2.8 },
    { name: 'FTP', port: 21, packets: 2140, bytes: 1712000, pct: 1.9 },
    { name: 'MySQL', port: 3306, packets: 1980, bytes: 2376000, pct: 1.7 },
    { name: 'LDAP', port: 389, packets: 1740, bytes: 1566000, pct: 1.5 },
    { name: 'Kerberos', port: 88, packets: 1520, bytes: 912000, pct: 1.3 },
    { name: 'SNMP', port: 161, packets: 1210, bytes: 605000, pct: 1.1 },
    { name: 'NTP', port: 123, packets: 980, bytes: 78400, pct: 0.9 },
    { name: 'ICMP', port: 0, packets: 870, bytes: 69600, pct: 0.8 },
    { name: 'Other', port: 0, packets: 3120, bytes: 3744000, pct: 2.7 }
  ];
}

function _taGenTopTalkers() {
  return [
    { ip: '10.0.1.45', hostname: 'ws-jdoe.corp', sent: 18420000, recv: 42180000, conns: 842, flag: '' },
    { ip: '10.0.1.12', hostname: 'srv-web01.corp', sent: 62400000, recv: 8410000, conns: 4210, flag: '' },
    { ip: '10.0.1.100', hostname: 'dc01.corp', sent: 12800000, recv: 14200000, conns: 2180, flag: '' },
    { ip: '10.0.2.88', hostname: 'dev-box.corp', sent: 48100000, recv: 2100000, conns: 128, flag: 'HIGH EGRESS' },
    { ip: '192.168.5.22', hostname: 'cam-lobby.iot', sent: 8400000, recv: 420000, conns: 14, flag: 'IOT DEVICE' },
    { ip: '10.0.1.201', hostname: 'mail01.corp', sent: 9200000, recv: 11400000, conns: 680, flag: '' },
    { ip: '10.0.3.15', hostname: 'unknown', sent: 320000, recv: 42000, conns: 4210, flag: 'PORT SCAN' },
    { ip: '172.16.0.5', hostname: 'nas01.corp', sent: 28400000, recv: 6200000, conns: 94, flag: '' },
    { ip: '10.0.1.77', hostname: 'ws-admin.corp', sent: 4200000, recv: 8100000, conns: 312, flag: '' },
    { ip: '10.0.2.199', hostname: 'staging.corp', sent: 2100000, recv: 1800000, conns: 64, flag: '' }
  ];
}

function _taGenSuspicious() {
  return [
    { type: 'PORT_SCAN', severity: 'high', src: '10.0.3.15', dst: '10.0.1.0/24', detail: 'Sequential port scan detected: 4210 connections to 1024 unique ports in 38 seconds. SYN-only (half-open) pattern.', time: '2026-09-18T14:22:08Z' },
    { type: 'BEACONING', severity: 'critical', src: '10.0.2.88', dst: '185.220.101.42', detail: 'Regular interval connections every 60±2s to external IP. 482 beacons in 8 hours. TLS on non-standard port 8443. Possible C2 channel.', time: '2026-09-18T12:04:11Z' },
    { type: 'DATA_EXFIL', severity: 'critical', src: '10.0.2.88', dst: '104.21.33.18', detail: 'Anomalous egress: 48.1 MB sent to external host in 12 minutes via HTTPS. Upload/download ratio 22:1. Normal ratio for this host is 0.3:1.', time: '2026-09-18T13:41:55Z' },
    { type: 'DNS_TUNNEL', severity: 'high', src: '10.0.1.45', dst: '10.0.1.100 (DC)', detail: 'Suspected DNS tunneling: 1842 TXT queries to subdomain pattern [a-f0-9]{32}.data.suspicious-domain.xyz. Average query length 84 chars (normal: 24).', time: '2026-09-18T11:18:33Z' },
    { type: 'BRUTE_FORCE', severity: 'medium', src: '10.0.3.15', dst: '10.0.1.201', detail: 'SSH brute force: 842 failed auth attempts from single source in 5 minutes against mail01.corp.', time: '2026-09-18T14:28:44Z' },
    { type: 'LATERAL_MOVE', severity: 'high', src: '10.0.2.88', dst: '10.0.1.100', detail: 'SMB/RPC connections to domain controller from compromised host. PsExec-like behavior detected. NTLM auth with admin credentials.', time: '2026-09-18T13:55:02Z' },
    { type: 'POLICY_VIOLATION', severity: 'low', src: '192.168.5.22', dst: '54.230.11.xx', detail: 'IoT camera making outbound HTTPS connections to AWS CloudFront. Device should be isolated to VLAN with no internet access.', time: '2026-09-18T10:44:19Z' },
    { type: 'CRYPTO_MINING', severity: 'medium', src: '10.0.2.199', dst: 'stratum+tcp://pool.mining', detail: 'Stratum protocol traffic detected on port 3333. Staging server connecting to known mining pool. CPU-based miner suspected.', time: '2026-09-18T09:12:07Z' }
  ];
}

function _taGenPacketSizes() {
  return [
    { range: '0-64', count: 28420, label: 'Tiny (ACK/SYN)' },
    { range: '65-128', count: 14210, label: 'Small (DNS/ICMP)' },
    { range: '129-256', count: 8940, label: 'Medium-small' },
    { range: '257-512', count: 12100, label: 'Medium' },
    { range: '513-1024', count: 18200, label: 'Medium-large' },
    { range: '1025-1460', count: 24800, label: 'Near-MTU' },
    { range: '1461-1500', count: 6180, label: 'MTU (full)' },
    { range: '1500+', count: 1420, label: 'Jumbo/fragmented' }
  ];
}

function _taFmt(bytes) {
  if (bytes >= 1e9) return (bytes / 1e9).toFixed(1) + ' GB';
  if (bytes >= 1e6) return (bytes / 1e6).toFixed(1) + ' MB';
  if (bytes >= 1e3) return (bytes / 1e3).toFixed(1) + ' KB';
  return bytes + ' B';
}

function _taBar(pct, color) {
  return '<div style="background:#1a1e2e;border-radius:3px;height:14px;width:100%;position:relative;">' +
    '<div style="background:' + color + ';height:100%;width:' + Math.min(pct, 100) + '%;border-radius:3px;transition:width 0.4s;"></div>' +
    '<span style="position:absolute;right:4px;top:0;font-size:9px;color:#8a9ab0;line-height:14px;">' + pct.toFixed(1) + '%</span></div>';
}

// ── Main render ─────────────────────────────────────────────────────────────

export function renderTrafficAnalyzer(container) {
  var el = typeof container === 'string' ? document.getElementById(container) : container;
  if (!el) return;

  var protocols = _taGenProtocols();
  var talkers = _taGenTopTalkers();
  var suspicious = _taGenSuspicious();
  var pktSizes = _taGenPacketSizes();
  var maxPkt = Math.max.apply(null, pktSizes.map(function(p) { return p.count; }));

  var sevColors = { critical: '#ff2244', high: '#ff6644', medium: '#ffaa22', low: '#44aaff' };
  var typeIcons = { PORT_SCAN: '[SCAN]', BEACONING: '[C2]', DATA_EXFIL: '[EXFIL]', DNS_TUNNEL: '[TUNNEL]', BRUTE_FORCE: '[BRUTE]', LATERAL_MOVE: '[LATERAL]', POLICY_VIOLATION: '[POLICY]', CRYPTO_MINING: '[MINER]' };

  var h = '';
  h += '<div style="background:#0a0e16;color:#c8d6e5;font-family:\'Courier New\',monospace;padding:24px;min-height:100%;">';

  // Header
  h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;flex-wrap:wrap;gap:12px;">';
  h += '<div>';
  h += '<h2 style="margin:0;color:#00d4ff;letter-spacing:2px;font-size:18px;">NETWORK TRAFFIC ANALYZER</h2>';
  h += '<div style="margin-top:6px;display:inline-block;padding:2px 8px;border:1px solid #ffaa22;color:#ffaa22;font-size:11px;border-radius:3px;letter-spacing:1px;">SAMPLE TRAFFIC</div>';
  h += '<div style="color:#4a6a8a;font-size:11px;margin-top:4px;">Illustrative sample data generated in your browser for learning. It is not a capture of your network.</div>';
  h += '</div>';
  h += '<button id="ta-export" style="background:#0a2a3a;border:1px solid #1a4a6a;color:#00d4ff;padding:6px 14px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:3px;">EXPORT REPORT</button>';
  h += '</div>';

  // ── Protocol Distribution ──
  h += '<div style="margin-bottom:24px;">';
  h += '<h3 style="color:#5a9abb;font-size:13px;letter-spacing:2px;margin:0 0 10px;border-bottom:1px solid #1a2a3a;padding-bottom:6px;">PROTOCOL DISTRIBUTION</h3>';
  h += '<table style="width:100%;border-collapse:collapse;font-size:11px;">';
  h += '<tr style="color:#4a6a8a;text-align:left;"><th style="padding:4px 8px;">PROTOCOL</th><th style="padding:4px 8px;">PORT</th><th style="padding:4px 8px;">PACKETS</th><th style="padding:4px 8px;">BYTES</th><th style="padding:4px 8px;width:40%;">DISTRIBUTION</th></tr>';
  for (var i = 0; i < protocols.length; i++) {
    var p = protocols[i];
    var barColor = p.pct > 20 ? '#00d4ff' : (p.pct > 5 ? '#00aa88' : '#3a5a7a');
    h += '<tr style="border-bottom:1px solid #0f1a24;">';
    h += '<td style="padding:4px 8px;color:#c8d6e5;">' + esc(p.name) + '</td>';
    h += '<td style="padding:4px 8px;color:#5a8aaa;">' + (p.port || '--') + '</td>';
    h += '<td style="padding:4px 8px;color:#8ab4d4;">' + p.packets.toLocaleString() + '</td>';
    h += '<td style="padding:4px 8px;color:#8ab4d4;">' + _taFmt(p.bytes) + '</td>';
    h += '<td style="padding:4px 8px;">' + _taBar(p.pct, barColor) + '</td>';
    h += '</tr>';
  }
  h += '</table></div>';

  // ── Packet Size Histogram ──
  h += '<div style="margin-bottom:24px;">';
  h += '<h3 style="color:#5a9abb;font-size:13px;letter-spacing:2px;margin:0 0 10px;border-bottom:1px solid #1a2a3a;padding-bottom:6px;">PACKET SIZE DISTRIBUTION</h3>';
  h += '<div style="display:flex;align-items:flex-end;gap:4px;height:120px;padding:0 8px;">';
  for (var j = 0; j < pktSizes.length; j++) {
    var ps = pktSizes[j];
    var barH = Math.round((ps.count / maxPkt) * 100);
    h += '<div style="flex:1;display:flex;flex-direction:column;align-items:center;">';
    h += '<div style="font-size:8px;color:#5a8aaa;margin-bottom:2px;">' + ps.count.toLocaleString() + '</div>';
    h += '<div style="width:100%;height:' + barH + 'px;background:linear-gradient(180deg,#00d4ff,#0066aa);border-radius:2px 2px 0 0;min-height:4px;"></div>';
    h += '<div style="font-size:8px;color:#4a6a8a;margin-top:4px;text-align:center;line-height:1.2;">' + esc(ps.range) + '</div>';
    h += '</div>';
  }
  h += '</div></div>';

  // ── Top Talkers ──
  h += '<div style="margin-bottom:24px;">';
  h += '<h3 style="color:#5a9abb;font-size:13px;letter-spacing:2px;margin:0 0 10px;border-bottom:1px solid #1a2a3a;padding-bottom:6px;">TOP TALKERS</h3>';
  h += '<table style="width:100%;border-collapse:collapse;font-size:11px;">';
  h += '<tr style="color:#4a6a8a;text-align:left;"><th style="padding:4px 8px;">IP</th><th style="padding:4px 8px;">HOSTNAME</th><th style="padding:4px 8px;">SENT</th><th style="padding:4px 8px;">RECV</th><th style="padding:4px 8px;">CONNS</th><th style="padding:4px 8px;">FLAG</th></tr>';
  for (var k = 0; k < talkers.length; k++) {
    var t = talkers[k];
    var flagColor = t.flag === 'PORT SCAN' ? '#ff2244' : (t.flag === 'HIGH EGRESS' ? '#ff6644' : (t.flag ? '#ffaa22' : '#3a5a7a'));
    h += '<tr style="border-bottom:1px solid #0f1a24;">';
    h += '<td style="padding:4px 8px;color:#00aacc;font-family:monospace;">' + esc(t.ip) + '</td>';
    h += '<td style="padding:4px 8px;color:#8ab4d4;">' + esc(t.hostname) + '</td>';
    h += '<td style="padding:4px 8px;color:#c8d6e5;">' + _taFmt(t.sent) + '</td>';
    h += '<td style="padding:4px 8px;color:#c8d6e5;">' + _taFmt(t.recv) + '</td>';
    h += '<td style="padding:4px 8px;color:#8ab4d4;">' + t.conns.toLocaleString() + '</td>';
    h += '<td style="padding:4px 8px;color:' + flagColor + ';font-weight:bold;font-size:10px;">' + esc(t.flag || '—') + '</td>';
    h += '</tr>';
  }
  h += '</table></div>';

  // ── Suspicious Activity ──
  h += '<div style="margin-bottom:24px;">';
  h += '<h3 style="color:#ff4444;font-size:13px;letter-spacing:2px;margin:0 0 10px;border-bottom:1px solid #3a1a1a;padding-bottom:6px;">SUSPICIOUS ACTIVITY DETECTED (' + suspicious.length + ')</h3>';
  for (var m = 0; m < suspicious.length; m++) {
    var s = suspicious[m];
    var sc = sevColors[s.severity] || '#aaa';
    var icon = typeIcons[s.type] || '[?]';
    h += '<div style="background:#0f1218;border-left:3px solid ' + sc + ';padding:10px 14px;margin-bottom:8px;border-radius:0 4px 4px 0;">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">';
    h += '<span style="color:' + sc + ';font-weight:bold;font-size:12px;">' + esc(icon) + ' ' + esc(s.type.replace(/_/g, ' ')) + '</span>';
    h += '<span style="color:' + sc + ';font-size:10px;border:1px solid ' + sc + ';padding:1px 6px;border-radius:2px;">' + esc(s.severity.toUpperCase()) + '</span>';
    h += '</div>';
    h += '<div style="font-size:10px;color:#5a8aaa;margin-bottom:4px;">' + esc(s.src) + ' &rarr; ' + esc(s.dst) + ' | ' + esc(s.time) + '</div>';
    h += '<div style="font-size:11px;color:#8aa0b8;line-height:1.5;">' + esc(s.detail) + '</div>';
    h += '</div>';
  }
  h += '</div>';

  // ── DNS Tunneling Analysis ──
  h += '<div style="margin-bottom:24px;">';
  h += '<h3 style="color:#5a9abb;font-size:13px;letter-spacing:2px;margin:0 0 10px;border-bottom:1px solid #1a2a3a;padding-bottom:6px;">DNS TUNNELING DETECTION</h3>';
  h += '<div style="background:#0f1218;padding:14px;border-radius:4px;font-size:11px;line-height:1.8;">';
  h += '<div style="color:#4a6a8a;">Analysis of ' + protocols[2].packets.toLocaleString() + ' DNS queries:</div>';
  h += '<div style="margin-top:8px;">';
  h += '<div>Average query length: <span style="color:#ffaa22;">84 chars</span> (baseline: 24 chars) <span style="color:#ff4444;">[ANOMALOUS]</span></div>';
  h += '<div>TXT record ratio: <span style="color:#ffaa22;">38.2%</span> (baseline: 2.1%) <span style="color:#ff4444;">[ANOMALOUS]</span></div>';
  h += '<div>Unique subdomains: <span style="color:#ffaa22;">1,842</span> under single domain <span style="color:#ff4444;">[ANOMALOUS]</span></div>';
  h += '<div>Entropy of subdomain labels: <span style="color:#ffaa22;">4.82 bits/char</span> (random threshold: 3.5) <span style="color:#ff4444;">[HIGH ENTROPY]</span></div>';
  h += '<div>Query interval: <span style="color:#ffaa22;">0.8±0.2s</span> (periodic) <span style="color:#ff6644;">[SUSPICIOUS]</span></div>';
  h += '<div style="margin-top:8px;color:#ff4444;font-weight:bold;">VERDICT: DNS tunneling highly probable. Recommend blocking suspicious-domain.xyz and investigating 10.0.1.45.</div>';
  h += '</div></div></div>';

  h += '</div>';
  el.innerHTML = h;

  // Wire export button
  var exportBtn = document.getElementById('ta-export');
  if (exportBtn) {
    exportBtn.addEventListener('click', function() {
      var report = '=== DARKNODE TRAFFIC ANALYSIS REPORT ===\n';
      report += 'Generated: ' + new Date().toISOString() + '\n';
      report += 'NOTE: SAMPLE TRAFFIC - illustrative data generated in the browser, not a real capture.\n\n';
      report += '--- SUSPICIOUS ACTIVITY ---\n';
      for (var r = 0; r < suspicious.length; r++) {
        report += '[' + suspicious[r].severity.toUpperCase() + '] ' + suspicious[r].type + ': ' + suspicious[r].src + ' -> ' + suspicious[r].dst + '\n';
        report += '  ' + suspicious[r].detail + '\n\n';
      }
      report += '--- TOP TALKERS ---\n';
      for (var tt = 0; tt < talkers.length; tt++) {
        report += talkers[tt].ip + ' (' + talkers[tt].hostname + ') S:' + _taFmt(talkers[tt].sent) + ' R:' + _taFmt(talkers[tt].recv) + (talkers[tt].flag ? ' [' + talkers[tt].flag + ']' : '') + '\n';
      }
      try {
        navigator.clipboard.writeText(report);
        exportBtn.textContent = 'COPIED!';
        setTimeout(function() { exportBtn.textContent = 'EXPORT REPORT'; }, 1500);
      } catch (e) {
        exportBtn.textContent = 'COPY FAILED';
        setTimeout(function() { exportBtn.textContent = 'EXPORT REPORT'; }, 1500);
      }
    });
  }
};
