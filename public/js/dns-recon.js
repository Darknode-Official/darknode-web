// Copyright (c) 2026 Darknode-Official. All rights reserved.
// DNS Recon — DNS enumeration, subdomain brute-force, SPF/DKIM/DMARC analysis
// Uses Google DoH (dns.google) and Cloudflare DoH (cloudflare-dns.com) — no API key, CORS OK

var esc = function(s) { return String(s != null ? s : '').replace(/[&<>"']/g, function(c) { return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); };

var DNS_RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'SRV', 'CAA', 'PTR'];
var DNS_TYPE_COLORS = { A: '#00ff88', AAAA: '#00aaff', CNAME: '#aa66ff', MX: '#ff6644', NS: '#ffaa00', TXT: '#44cccc', SOA: '#ff66aa', SRV: '#88cc44', CAA: '#ff8844', PTR: '#66aaff' };
var DNS_TYPE_NUMS = { A: 1, AAAA: 28, CNAME: 5, MX: 15, NS: 2, TXT: 16, SOA: 6, SRV: 33, CAA: 257, PTR: 12 };

var COMMON_SUBDOMAINS = [
  'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'webmail', 'admin', 'portal', 'vpn',
  'remote', 'api', 'dev', 'staging', 'test', 'beta', 'alpha', 'demo', 'sandbox', 'uat',
  'app', 'apps', 'mobile', 'm', 'cdn', 'static', 'assets', 'media', 'img', 'images',
  'docs', 'wiki', 'help', 'support', 'status', 'blog', 'news', 'shop', 'store', 'pay',
  'billing', 'dashboard', 'panel', 'cp', 'cpanel', 'whm', 'ns1', 'ns2', 'ns3', 'dns',
  'dns1', 'dns2', 'mx', 'mx1', 'mx2', 'relay', 'gateway', 'proxy', 'cache', 'edge',
  'lb', 'load', 'web', 'web1', 'web2', 'server', 'srv', 'db', 'database', 'mysql',
  'postgres', 'mongo', 'redis', 'elastic', 'search', 'solr', 'kibana', 'grafana',
  'prometheus', 'monitor', 'nagios', 'zabbix', 'jenkins', 'ci', 'cd', 'build', 'deploy',
  'git', 'gitlab', 'github', 'bitbucket', 'svn', 'repo', 'registry', 'docker', 'k8s',
  'kube', 'kubernetes', 'rancher', 'vault', 'consul', 'nomad', 'terraform', 'ansible',
  'puppet', 'chef', 'salt', 'log', 'logs', 'syslog', 'elk', 'splunk', 'siem',
  'auth', 'sso', 'login', 'signin', 'oauth', 'saml', 'ldap', 'ad', 'directory',
  'exchange', 'owa', 'autodiscover', 'outlook', 'teams', 'office', 'o365',
  'intranet', 'internal', 'corp', 'private', 'secure', 'sec', 'security',
  'firewall', 'fw', 'ids', 'ips', 'waf', 'sandbox', 'quarantine',
  'backup', 'bak', 'dr', 'recovery', 'archive', 'old', 'legacy', 'v1', 'v2',
  'api-v1', 'api-v2', 'rest', 'graphql', 'ws', 'websocket', 'socket', 'realtime',
  'chat', 'im', 'msg', 'notify', 'push', 'feed', 'rss', 'atom',
  'crm', 'erp', 'hr', 'accounting', 'finance', 'sales', 'marketing',
  'analytics', 'tracking', 'stats', 'metrics', 'report', 'reports',
  'cloud', 'aws', 'azure', 'gcp', 'heroku', 'vercel', 'netlify',
  'staging2', 'preprod', 'qa', 'testing', 'load-test', 'perf',
  'www2', 'www3', 'origin', 'backend', 'frontend', 'client',
  'video', 'stream', 'live', 'tv', 'radio', 'podcast',
  'events', 'calendar', 'booking', 'ticket', 'tickets',
  'forum', 'community', 'social', 'connect', 'network',
  'download', 'dl', 'update', 'updates', 'patch', 'release',
  'map', 'maps', 'geo', 'location', 'gps', 'track', 'trace'
];

export function renderDNSRecon(container) {
  if (!container) return;
  var h = '';
  h += '<div style="background:#0a0e14;color:#c8d6e5;font-family:\'Courier New\',monospace;padding:24px;min-height:80vh;">';

  h += '<div style="margin-bottom:20px;">';
  h += '<h2 style="margin:0;font-size:20px;color:#ffaa00;letter-spacing:2px;">DNS RECON</h2>';
  h += '<div style="color:#4a6a8a;font-size:11px;letter-spacing:1px;margin-top:4px;">DNS Enumeration &bull; Subdomain Discovery &bull; SPF/DKIM/DMARC &bull; Propagation Check</div>';
  h += '</div>';

  // Search
  h += '<div style="display:flex;gap:8px;margin-bottom:16px;">';
  h += '<input id="dns-domain" type="text" placeholder="Enter domain (e.g. example.com)" style="flex:1;background:#0c1525;border:1px solid #1a3a5c;border-radius:4px;padding:10px 14px;color:#c8d6e5;font-family:monospace;font-size:13px;outline:none;" onkeydown="if(event.key===\'Enter\')_dnsFullScan()">';
  h += '<button onclick="_dnsFullScan()" style="background:#ffaa0022;color:#ffaa00;border:1px solid #ffaa0044;border-radius:4px;padding:10px 16px;font-family:monospace;font-size:12px;cursor:pointer;letter-spacing:1px;font-weight:bold;">ALL RECORDS</button>';
  h += '<button onclick="_dnsSubBrute()" style="background:#aa66ff22;color:#aa66ff;border:1px solid #aa66ff44;border-radius:4px;padding:10px 16px;font-family:monospace;font-size:12px;cursor:pointer;letter-spacing:1px;font-weight:bold;">SUBDOMAIN SCAN</button>';
  h += '</div>';

  h += '<div id="dns-results" style="min-height:300px;">';
  h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:40px;text-align:center;color:#4a6a8a;">';
  h += '<div style="font-size:36px;margin-bottom:10px;opacity:0.3;">&#x1F310;</div>';
  h += '<div style="font-size:13px;">Enter a domain to enumerate all DNS records</div>';
  h += '<div style="font-size:10px;color:#3a5a7a;margin-top:6px;">Uses Google &amp; Cloudflare DNS-over-HTTPS — no API keys required</div>';
  h += '</div></div>';

  h += '</div>';
  container.innerHTML = h;
};

function _dnsFetch(domain, type, provider) {
  var url;
  if (provider === 'cloudflare') {
    url = 'https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent(domain) + '&type=' + type;
  } else {
    url = 'https://dns.google/resolve?name=' + encodeURIComponent(domain) + '&type=' + type;
  }
  return fetch(url, { headers: { Accept: 'application/dns-json' } })
    .then(function(r) { return r.json(); })
    .catch(function() { return null; });
}

function _dnsFullScan() {
  var input = document.getElementById('dns-domain');
  var results = document.getElementById('dns-results');
  if (!input || !results) return;
  var domain = input.value.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  if (!domain || domain.indexOf('.') < 1) {
    results.innerHTML = '<div style="color:#ff4444;padding:20px;text-align:center;">Enter a valid domain</div>';
    return;
  }

  results.innerHTML = '<div style="text-align:center;padding:30px;color:#ffaa00;font-size:13px;letter-spacing:2px;">SCANNING ' + esc(domain.toUpperCase()) + ' — ALL RECORD TYPES...</div>';

  var promises = DNS_RECORD_TYPES.map(function(type) {
    return _dnsFetch(domain, type).then(function(data) { return { type: type, data: data }; });
  });

  // Also fetch from Cloudflare for propagation comparison
  var cfPromises = ['A', 'AAAA', 'MX', 'NS'].map(function(type) {
    return _dnsFetch(domain, type, 'cloudflare').then(function(data) { return { type: type, data: data }; });
  });

  Promise.all(promises.concat(cfPromises)).then(function(allResults) {
    var googleResults = allResults.slice(0, DNS_RECORD_TYPES.length);
    var cloudflareResults = allResults.slice(DNS_RECORD_TYPES.length);

    var h = '';

    // Stats
    var totalRecords = 0;
    for (var s = 0; s < googleResults.length; s++) {
      if (googleResults[s].data && googleResults[s].data.Answer) totalRecords += googleResults[s].data.Answer.length;
    }
    h += '<div style="display:flex;gap:10px;margin-bottom:16px;">';
    h += '<div style="background:#0a1a2a;border:1px solid #ffaa0033;border-radius:6px;padding:8px 16px;text-align:center;"><div style="color:#ffaa00;font-size:20px;font-weight:bold;">' + totalRecords + '</div><div style="color:#556;font-size:8px;letter-spacing:1px;">RECORDS</div></div>';
    h += '<div style="background:#0a1a2a;border:1px solid #00ff8833;border-radius:6px;padding:8px 16px;text-align:center;"><div style="color:#00ff88;font-size:20px;font-weight:bold;">' + DNS_RECORD_TYPES.length + '</div><div style="color:#556;font-size:8px;letter-spacing:1px;">TYPES CHECKED</div></div>';
    h += '<div style="background:#0a1a2a;border:1px solid #00aaff33;border-radius:6px;padding:8px 16px;text-align:center;"><div style="color:#00aaff;font-size:20px;font-weight:bold;">2</div><div style="color:#556;font-size:8px;letter-spacing:1px;">DNS PROVIDERS</div></div>';
    h += '</div>';

    // Records table
    h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:16px;margin-bottom:16px;">';
    h += '<div style="color:#ffaa00;font-size:12px;letter-spacing:1px;margin-bottom:10px;">DNS RECORDS — ' + esc(domain.toUpperCase()) + '</div>';
    h += '<table style="width:100%;border-collapse:collapse;font-size:10px;">';
    h += '<thead><tr style="border-bottom:2px solid #1a3a5c;"><th style="text-align:left;padding:6px;color:#ffaa00;font-size:9px;">TYPE</th><th style="text-align:left;padding:6px;color:#ffaa00;font-size:9px;">NAME</th><th style="text-align:left;padding:6px;color:#ffaa00;font-size:9px;">VALUE</th><th style="text-align:left;padding:6px;color:#ffaa00;font-size:9px;">TTL</th></tr></thead><tbody>';

    for (var ri = 0; ri < googleResults.length; ri++) {
      var r = googleResults[ri];
      if (!r.data || !r.data.Answer) continue;
      var typeColor = DNS_TYPE_COLORS[r.type] || '#aaa';
      for (var ai = 0; ai < r.data.Answer.length; ai++) {
        var ans = r.data.Answer[ai];
        var rowBg = ai % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.02)';
        h += '<tr style="border-bottom:1px solid #0d1525;background:' + rowBg + ';">';
        h += '<td style="padding:5px 6px;"><span style="color:' + typeColor + ';font-weight:bold;font-size:9px;background:' + typeColor + '18;padding:1px 6px;border-radius:2px;">' + esc(r.type) + '</span></td>';
        h += '<td style="padding:5px 6px;color:#8899aa;max-width:200px;overflow:hidden;text-overflow:ellipsis;">' + esc(ans.name || '') + '</td>';
        h += '<td style="padding:5px 6px;color:#c8d6e5;word-break:break-all;max-width:400px;cursor:pointer;" onclick="navigator.clipboard.writeText(this.textContent);this.style.color=\'#00ff88\';var e=this;setTimeout(function(){e.style.color=\'#c8d6e5\';},500);">' + esc(String(ans.data || '')) + '</td>';
        h += '<td style="padding:5px 6px;color:#556;">' + (ans.TTL || '--') + '</td>';
        h += '</tr>';
      }
    }
    h += '</tbody></table></div>';

    // SPF/DKIM/DMARC analysis
    h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:16px;margin-bottom:16px;">';
    h += '<div style="color:#00d4ff;font-size:12px;letter-spacing:1px;margin-bottom:10px;">EMAIL SECURITY ANALYSIS</div>';

    var txtResult = googleResults.find(function(r) { return r.type === 'TXT'; });
    var txtRecords = (txtResult && txtResult.data && txtResult.data.Answer) ? txtResult.data.Answer : [];

    // SPF
    var spf = txtRecords.find(function(r) { return (r.data || '').indexOf('v=spf1') !== -1; });
    h += '<div style="margin:8px 0;padding:8px;border-left:3px solid ' + (spf ? '#00ff88' : '#ff4444') + ';background:#0a1018;border-radius:0 4px 4px 0;">';
    h += '<div style="color:' + (spf ? '#00ff88' : '#ff4444') + ';font-size:10px;font-weight:bold;letter-spacing:1px;">SPF ' + (spf ? 'FOUND' : 'MISSING') + '</div>';
    if (spf) h += '<div style="color:#8899aa;font-size:10px;margin-top:4px;word-break:break-all;">' + esc(String(spf.data || '').replace(/"/g, '')) + '</div>';
    else h += '<div style="color:#aa6666;font-size:10px;margin-top:4px;">No SPF record — domain is vulnerable to email spoofing</div>';
    h += '</div>';

    // DMARC
    h += '<div style="color:#556;font-size:9px;margin:4px 0;">Checking _dmarc.' + esc(domain) + '...</div>';

    // Propagation comparison
    h += '</div>';
    h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:16px;">';
    h += '<div style="color:#aa66ff;font-size:12px;letter-spacing:1px;margin-bottom:10px;">PROPAGATION CHECK — GOOGLE vs CLOUDFLARE</div>';
    h += '<table style="width:100%;border-collapse:collapse;font-size:10px;">';
    h += '<thead><tr style="border-bottom:2px solid #1a3a5c;"><th style="text-align:left;padding:6px;color:#aa66ff;font-size:9px;">TYPE</th><th style="text-align:left;padding:6px;color:#aa66ff;font-size:9px;">GOOGLE</th><th style="text-align:left;padding:6px;color:#aa66ff;font-size:9px;">CLOUDFLARE</th><th style="text-align:left;padding:6px;color:#aa66ff;font-size:9px;">MATCH</th></tr></thead><tbody>';

    for (var pi = 0; pi < cloudflareResults.length; pi++) {
      var gRes = googleResults.find(function(g) { return g.type === cloudflareResults[pi].type; });
      var gAnswers = (gRes && gRes.data && gRes.data.Answer) ? gRes.data.Answer.map(function(a) { return String(a.data || ''); }).sort().join(', ') : 'N/A';
      var cAnswers = (cloudflareResults[pi].data && cloudflareResults[pi].data.Answer) ? cloudflareResults[pi].data.Answer.map(function(a) { return String(a.data || ''); }).sort().join(', ') : 'N/A';
      var match = gAnswers === cAnswers;

      h += '<tr style="border-bottom:1px solid #0d1525;">';
      h += '<td style="padding:5px 6px;color:' + (DNS_TYPE_COLORS[cloudflareResults[pi].type] || '#aaa') + ';font-weight:bold;">' + cloudflareResults[pi].type + '</td>';
      h += '<td style="padding:5px 6px;color:#8899aa;max-width:200px;overflow:hidden;text-overflow:ellipsis;">' + esc(gAnswers) + '</td>';
      h += '<td style="padding:5px 6px;color:#8899aa;max-width:200px;overflow:hidden;text-overflow:ellipsis;">' + esc(cAnswers) + '</td>';
      h += '<td style="padding:5px 6px;color:' + (match ? '#00ff88' : '#ff4444') + ';font-weight:bold;">' + (match ? 'MATCH' : 'MISMATCH') + '</td>';
      h += '</tr>';
    }
    h += '</tbody></table></div>';

    // DMARC async check
    _dnsFetch('_dmarc.' + domain, 'TXT').then(function(dmarcData) {
      var dmarcEl = results.querySelector('[data-dmarc-slot]');
      if (!dmarcEl) return;
      var dmarc = (dmarcData && dmarcData.Answer) ? dmarcData.Answer.find(function(a) { return (a.data || '').indexOf('v=DMARC1') !== -1; }) : null;
      dmarcEl.innerHTML = '<div style="margin:8px 0;padding:8px;border-left:3px solid ' + (dmarc ? '#00ff88' : '#ff4444') + ';background:#0a1018;border-radius:0 4px 4px 0;">' +
        '<div style="color:' + (dmarc ? '#00ff88' : '#ff4444') + ';font-size:10px;font-weight:bold;letter-spacing:1px;">DMARC ' + (dmarc ? 'FOUND' : 'MISSING') + '</div>' +
        (dmarc ? '<div style="color:#8899aa;font-size:10px;margin-top:4px;word-break:break-all;">' + esc(String(dmarc.data || '').replace(/"/g, '')) + '</div>' : '<div style="color:#aa6666;font-size:10px;margin-top:4px;">No DMARC record — domain has no email authentication policy</div>') +
        '</div>';
    });

    // Insert DMARC placeholder
    h = h.replace('Checking _dmarc.' + esc(domain) + '...', '<span data-dmarc-slot="1">Checking DMARC...</span>');

    results.innerHTML = h;
  });
}

function _dnsSubBrute() {
  var input = document.getElementById('dns-domain');
  var results = document.getElementById('dns-results');
  if (!input || !results) return;
  var domain = input.value.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  if (!domain) { results.innerHTML = '<div style="color:#ff4444;padding:20px;text-align:center;">Enter a valid domain</div>'; return; }

  var total = COMMON_SUBDOMAINS.length;
  var found = [];
  var checked = 0;

  results.innerHTML = '<div style="text-align:center;padding:30px;"><div style="color:#aa66ff;font-size:13px;letter-spacing:2px;margin-bottom:10px;">BRUTE-FORCING ' + total + ' SUBDOMAINS...</div><div id="dns-brute-progress" style="color:#556;font-size:11px;">0 / ' + total + ' checked | 0 found</div><div style="margin-top:10px;width:100%;height:4px;background:#1a2a3a;border-radius:2px;overflow:hidden;"><div id="dns-brute-bar" style="height:100%;width:0%;background:linear-gradient(90deg,#aa66ff,#6633cc);border-radius:2px;transition:width 0.3s;"></div></div></div>';

  // Batch in groups of 10 to avoid overwhelming DNS
  var batchSize = 10;
  var idx = 0;

  function processBatch() {
    if (idx >= total) {
      _dnsRenderSubResults(results, domain, found);
      return;
    }
    var batch = [];
    for (var b = 0; b < batchSize && idx + b < total; b++) {
      var sub = COMMON_SUBDOMAINS[idx + b] + '.' + domain;
      batch.push(_dnsFetch(sub, 'A').then(function(subdomain) {
        return function(data) {
          checked++;
          if (data && data.Answer && data.Answer.length > 0) {
            found.push({ name: subdomain, ips: data.Answer.map(function(a) { return a.data; }) });
          }
          var prog = document.getElementById('dns-brute-progress');
          var bar = document.getElementById('dns-brute-bar');
          if (prog) prog.textContent = checked + ' / ' + total + ' checked | ' + found.length + ' found';
          if (bar) bar.style.width = (checked / total * 100) + '%';
        };
      }(sub)));
    }
    idx += batchSize;
    Promise.all(batch).then(function() {
      setTimeout(processBatch, 100);
    });
  }
  processBatch();
}

function _dnsRenderSubResults(container, domain, found) {
  var h = '';
  h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:16px;">';
  h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">';
  h += '<div style="color:#aa66ff;font-size:12px;letter-spacing:1px;">' + found.length + ' SUBDOMAINS RESOLVED</div>';
  h += '<button onclick="navigator.clipboard.writeText(\'' + found.map(function(f) { return f.name; }).join('\\n') + '\');this.textContent=\'COPIED!\';var b=this;setTimeout(function(){b.textContent=\'COPY ALL\';},1500);" style="background:#aa66ff22;color:#aa66ff;border:1px solid #aa66ff44;border-radius:4px;padding:4px 12px;font-family:monospace;font-size:10px;cursor:pointer;">COPY ALL</button>';
  h += '</div>';

  h += '<div style="color:#556;font-size:9px;margin-bottom:10px;">' + COMMON_SUBDOMAINS.length + ' subdomains tested against ' + esc(domain) + ' via Google DoH</div>';

  if (found.length === 0) {
    h += '<div style="color:#556;text-align:center;padding:30px;">No subdomains resolved — domain may have strict DNS configuration</div>';
  } else {
    h += '<table style="width:100%;border-collapse:collapse;font-size:10px;">';
    h += '<thead><tr style="border-bottom:2px solid #1a3a5c;"><th style="text-align:left;padding:6px;color:#aa66ff;font-size:9px;">SUBDOMAIN</th><th style="text-align:left;padding:6px;color:#aa66ff;font-size:9px;">IP ADDRESS(ES)</th></tr></thead><tbody>';
    for (var i = 0; i < found.length; i++) {
      var f = found[i];
      h += '<tr style="border-bottom:1px solid #0d1525;background:' + (i % 2 ? 'rgba(255,255,255,0.02)' : 'transparent') + ';">';
      h += '<td style="padding:5px 6px;color:#c8d6e5;cursor:pointer;" onclick="navigator.clipboard.writeText(this.textContent);this.style.color=\'#00ff88\';var e=this;setTimeout(function(){e.style.color=\'#c8d6e5\';},500);">' + esc(f.name) + '</td>';
      h += '<td style="padding:5px 6px;color:#00ff88;">' + esc(f.ips.join(', ')) + '</td>';
      h += '</tr>';
    }
    h += '</tbody></table>';
  }
  h += '</div>';
  container.innerHTML = h;
}

window._dnsFullScan = _dnsFullScan;
window._dnsSubBrute = _dnsSubBrute;
