// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Network Scanner — port check, ping simulation, traceroute visualization
// All checks run client-side using fetch/WebSocket timing for port detection

var esc = function(s) { return String(s != null ? s : '').replace(/[&<>"']/g, function(c) {
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); };

var _nsCommonPorts = [
  { port: 21, service: 'FTP', category: 'file' },
  { port: 22, service: 'SSH', category: 'remote' },
  { port: 23, service: 'Telnet', category: 'remote' },
  { port: 25, service: 'SMTP', category: 'mail' },
  { port: 53, service: 'DNS', category: 'infra' },
  { port: 80, service: 'HTTP', category: 'web' },
  { port: 110, service: 'POP3', category: 'mail' },
  { port: 143, service: 'IMAP', category: 'mail' },
  { port: 443, service: 'HTTPS', category: 'web' },
  { port: 445, service: 'SMB', category: 'file' },
  { port: 993, service: 'IMAPS', category: 'mail' },
  { port: 995, service: 'POP3S', category: 'mail' },
  { port: 1433, service: 'MSSQL', category: 'db' },
  { port: 1521, service: 'Oracle', category: 'db' },
  { port: 3306, service: 'MySQL', category: 'db' },
  { port: 3389, service: 'RDP', category: 'remote' },
  { port: 5432, service: 'PostgreSQL', category: 'db' },
  { port: 5900, service: 'VNC', category: 'remote' },
  { port: 6379, service: 'Redis', category: 'db' },
  { port: 8080, service: 'HTTP-Alt', category: 'web' },
  { port: 8443, service: 'HTTPS-Alt', category: 'web' },
  { port: 9200, service: 'Elasticsearch', category: 'db' },
  { port: 27017, service: 'MongoDB', category: 'db' }
];

window.renderNetworkScanner = function(container) {
  var h = '';
  h += '<div style="background:#0a0e14;color:#c8d6e5;font-family:\'Courier New\',monospace;padding:20px;min-height:600px;">';
  h += '<h2 style="color:#00ddff;font-size:18px;letter-spacing:2px;margin:0 0 4px;">NETWORK SCANNER</h2>';
  h += '<div style="color:#4a6a8a;font-size:11px;margin-bottom:20px;">Port reachability, DNS resolution, HTTP probing — all from the browser</div>';

  // Input
  h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:16px;margin-bottom:16px;">';
  h += '<div style="display:flex;gap:8px;margin-bottom:10px;">';
  h += '<input id="ns-target" style="flex:1;background:#080c14;border:1px solid #1a2a44;border-radius:4px;color:#c8d6e5;font-family:monospace;font-size:12px;padding:8px 12px;" placeholder="example.com or IP address">';
  h += '<button onclick="_nsQuickScan()" style="background:#00aaff22;color:#00aaff;border:1px solid #00aaff44;padding:8px 16px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:4px;">QUICK SCAN</button>';
  h += '<button onclick="_nsFullScan()" style="background:#ff444422;color:#ff4444;border:1px solid #ff444444;padding:8px 16px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:4px;">FULL SCAN</button>';
  h += '</div>';
  h += '<div style="color:#4a6a8a;font-size:9px;">Quick scan checks common web ports (80, 443, 8080, 8443). Full scan checks all 23 common ports. Uses HTTP/HTTPS fetch timing.</div>';
  h += '</div>';

  // Results
  h += '<div id="ns-results"></div>';

  // Port reference
  h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:14px;margin-top:16px;">';
  h += '<div style="color:#00aaff;font-size:12px;font-weight:bold;margin-bottom:10px;">COMMON PORTS REFERENCE</div>';
  h += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:6px;">';
  for (var p = 0; p < _nsCommonPorts.length; p++) {
    var port = _nsCommonPorts[p];
    var catColor = { web: '#00aaff', remote: '#ff6644', mail: '#ffaa00', db: '#aa66ff', file: '#00ff88', infra: '#44cc44' }[port.category] || '#4a6a8a';
    h += '<div style="background:#080c14;border:1px solid #1a2a44;border-radius:3px;padding:4px 8px;font-size:10px;display:flex;justify-content:space-between;">';
    h += '<span style="color:' + catColor + ';font-weight:bold;">' + port.port + '</span>';
    h += '<span style="color:#6a8aaa;">' + esc(port.service) + '</span>';
    h += '</div>';
  }
  h += '</div>';
  h += '</div>';

  h += '</div>';
  container.innerHTML = h;
};

function _nsCheckPort(host, port, protocol) {
  return new Promise(function(resolve) {
    var url = protocol + '://' + host + ':' + port + '/';
    var start = performance.now();
    var controller = new AbortController();
    var timeout = setTimeout(function() { controller.abort(); }, 3000);

    fetch(url, { mode: 'no-cors', signal: controller.signal })
      .then(function() {
        clearTimeout(timeout);
        var elapsed = performance.now() - start;
        resolve({ port: port, status: 'open', time: Math.round(elapsed), protocol: protocol });
      })
      .catch(function(err) {
        clearTimeout(timeout);
        var elapsed = performance.now() - start;
        if (err.name === 'AbortError') {
          resolve({ port: port, status: 'filtered', time: 3000, protocol: protocol });
        } else if (elapsed < 100) {
          resolve({ port: port, status: 'closed', time: Math.round(elapsed), protocol: protocol });
        } else {
          resolve({ port: port, status: 'open', time: Math.round(elapsed), protocol: protocol });
        }
      });
  });
}

window._nsQuickScan = function() {
  var target = (document.getElementById('ns-target') || {}).value;
  if (!target) return;
  target = target.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:.*$/, '');
  _nsScan(target, [80, 443, 8080, 8443]);
};

window._nsFullScan = function() {
  var target = (document.getElementById('ns-target') || {}).value;
  if (!target) return;
  target = target.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:.*$/, '');
  _nsScan(target, _nsCommonPorts.map(function(p) { return p.port; }));
};

function _nsScan(host, ports) {
  var results = document.getElementById('ns-results');
  if (!results) return;

  results.innerHTML = '<div style="color:#ffaa00;font-size:12px;font-family:monospace;padding:16px;text-align:center;">Scanning ' + esc(host) + ' — ' + ports.length + ' ports...</div>';

  // DNS resolution first
  var h = '';
  h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:14px;margin-bottom:12px;">';
  h += '<div style="color:#00ddff;font-size:12px;font-weight:bold;margin-bottom:8px;">SCAN RESULTS: ' + esc(host) + '</div>';
  h += '<div id="ns-dns-info" style="margin-bottom:10px;"><span style="color:#ffaa00;font-size:10px;">Resolving DNS...</span></div>';
  h += '<div id="ns-port-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:6px;"></div>';
  h += '<div id="ns-scan-progress" style="margin-top:10px;color:#4a6a8a;font-size:10px;">0/' + ports.length + ' ports scanned</div>';
  h += '</div>';
  results.innerHTML = h;

  // DNS lookup
  fetch('https://dns.google/resolve?name=' + encodeURIComponent(host) + '&type=A')
    .then(function(r) { return r.json(); })
    .then(function(data) {
      var dnsEl = document.getElementById('ns-dns-info');
      if (dnsEl && data.Answer) {
        var ips = data.Answer.filter(function(a) { return a.type === 1; }).map(function(a) { return a.data; });
        dnsEl.innerHTML = '<span style="color:#00ff88;font-size:10px;">DNS: ' + esc(host) + ' &#8594; ' + ips.map(function(ip) { return esc(ip); }).join(', ') + '</span>';
      } else if (dnsEl) {
        dnsEl.innerHTML = '<span style="color:#ff4444;font-size:10px;">DNS resolution failed</span>';
      }
    })
    .catch(function() {});

  // Port scan
  var completed = 0;
  var portResults = [];
  var grid = document.getElementById('ns-port-grid');
  var progress = document.getElementById('ns-scan-progress');

  for (var i = 0; i < ports.length; i++) {
    (function(port) {
      var proto = (port === 443 || port === 8443 || port === 993 || port === 995) ? 'https' : 'https';
      _nsCheckPort(host, port, proto).then(function(result) {
        completed++;
        portResults.push(result);

        var portInfo = null;
        for (var pi = 0; pi < _nsCommonPorts.length; pi++) {
          if (_nsCommonPorts[pi].port === port) { portInfo = _nsCommonPorts[pi]; break; }
        }

        var statusColor = result.status === 'open' ? '#00ff88' : result.status === 'filtered' ? '#ffaa00' : '#ff4444';
        var statusBg = result.status === 'open' ? 'rgba(0,255,136,0.08)' : result.status === 'filtered' ? 'rgba(255,170,0,0.08)' : 'rgba(255,68,68,0.05)';

        if (grid) {
          var card = document.createElement('div');
          card.style.cssText = 'background:' + statusBg + ';border:1px solid ' + statusColor + '33;border-radius:4px;padding:8px 10px;font-size:10px;';
          card.innerHTML =
            '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">' +
            '<span style="color:#00aaff;font-weight:bold;font-size:12px;">' + port + '</span>' +
            '<span style="color:' + statusColor + ';font-weight:bold;font-size:9px;padding:1px 6px;background:' + statusColor + '15;border:1px solid ' + statusColor + '33;border-radius:2px;">' + result.status.toUpperCase() + '</span>' +
            '</div>' +
            '<div style="color:#6a8aaa;">' + (portInfo ? esc(portInfo.service) : 'Unknown') + '</div>' +
            '<div style="color:#3a5a7a;font-size:9px;">' + result.time + 'ms</div>';
          grid.appendChild(card);
        }

        if (progress) {
          progress.textContent = completed + '/' + ports.length + ' ports scanned' + (completed >= ports.length ? ' — COMPLETE' : '');
          if (completed >= ports.length) progress.style.color = '#00ff88';
        }
      });
    })(ports[i]);
  }
}
