import { esc } from '/js/shared.js';

var DEFAULT_WORDLIST = [
  'www', 'mail', 'api', 'dev', 'staging', 'admin', 'cdn', 'blog', 'shop',
  'portal', 'vpn', 'ftp', 'ns1', 'ns2', 'mx', 'webmail', 'test', 'demo',
  'beta', 'alpha', 'app', 'dashboard', 'docs', 'status', 'git', 'gitlab',
  'jenkins', 'ci', 'cd', 'monitor', 'grafana', 'kibana', 'elastic', 'redis',
  'db', 'database', 'mysql', 'postgres', 'mongo', 'cache', 'proxy', 'edge',
  'static', 'assets', 'media', 'images', 'img', 'files', 'upload', 'download',
  'backup', 'bak', 'old', 'legacy', 'internal', 'intranet', 'corp', 'office',
  'remote', 'sso', 'auth', 'login', 'oauth', 'id', 'identity', 'accounts',
  'support', 'help', 'helpdesk', 'ticket', 'jira', 'confluence', 'wiki',
  'forum', 'community', 'chat', 'slack', 'teams', 'meet', 'video', 'webinar',
  'crm', 'erp', 'hr', 'finance', 'billing', 'pay', 'payments', 'checkout',
  'store', 'marketplace', 'sandbox', 'uat', 'qa', 'stage', 'preprod', 'prod',
  'www2', 'www3', 'web', 'web01', 'web02', 'srv', 'server', 'host', 'node1'
];

var SAMPLE_RESULTS = [
  { sub: 'www.example.com', ip: '93.184.216.34', status: 200, tech: 'Nginx 1.25, TLS 1.3', live: true },
  { sub: 'mail.example.com', ip: '93.184.216.40', status: 200, tech: 'Postfix, Dovecot', live: true },
  { sub: 'api.example.com', ip: '93.184.216.50', status: 200, tech: 'Node.js, Express, Cloudflare', live: true },
  { sub: 'dev.example.com', ip: '10.0.1.15', status: 403, tech: 'Apache 2.4, PHP 8.2', live: true },
  { sub: 'staging.example.com', ip: '10.0.2.20', status: 401, tech: 'Nginx, Docker', live: true },
  { sub: 'admin.example.com', ip: '93.184.216.55', status: 302, tech: 'React, Nginx', live: true },
  { sub: 'cdn.example.com', ip: '104.18.32.7', status: 200, tech: 'Cloudflare CDN', live: true },
  { sub: 'blog.example.com', ip: '93.184.216.60', status: 200, tech: 'WordPress 6.4, PHP 8.1', live: true },
  { sub: 'shop.example.com', ip: '93.184.216.65', status: 200, tech: 'Shopify, TLS 1.3', live: true },
  { sub: 'portal.example.com', ip: '93.184.216.70', status: 200, tech: 'Angular, .NET 8', live: true },
  { sub: 'vpn.example.com', ip: '93.184.216.75', status: 200, tech: 'OpenVPN, Nginx', live: true },
  { sub: 'ftp.example.com', ip: '93.184.216.80', status: 200, tech: 'vsftpd 3.0.5', live: true },
  { sub: 'ns1.example.com', ip: '93.184.216.2', status: 0, tech: 'BIND 9.18', live: true },
  { sub: 'ns2.example.com', ip: '93.184.216.3', status: 0, tech: 'BIND 9.18', live: true },
  { sub: 'mx.example.com', ip: '93.184.216.41', status: 0, tech: 'Postfix MTA', live: true },
  { sub: 'webmail.example.com', ip: '93.184.216.42', status: 200, tech: 'Roundcube 1.6, PHP 8.2', live: true },
  { sub: 'test.example.com', ip: '192.168.1.100', status: 500, tech: 'Apache 2.4, Tomcat 10', live: true },
  { sub: 'demo.example.com', ip: '93.184.216.85', status: 200, tech: 'Vue.js, Python Flask', live: true },
  { sub: 'beta.example.com', ip: '93.184.216.90', status: 200, tech: 'Next.js 14, Vercel', live: true },
  { sub: 'git.example.com', ip: '93.184.216.95', status: 200, tech: 'GitLab CE 16.8', live: true },
  { sub: 'jenkins.example.com', ip: '10.0.3.10', status: 403, tech: 'Jenkins 2.440, Java 17', live: true },
  { sub: 'grafana.example.com', ip: '10.0.3.20', status: 302, tech: 'Grafana 10.2, Go', live: true },
  { sub: 'old.example.com', ip: '93.184.216.100', status: 301, tech: 'Apache 2.2, PHP 5.6', live: true },
  { sub: 'backup.example.com', ip: '', status: 0, tech: '', live: false }
];

function randomIP() {
  return Math.floor(Math.random() * 223 + 1) + '.' +
    Math.floor(Math.random() * 255) + '.' +
    Math.floor(Math.random() * 255) + '.' +
    Math.floor(Math.random() * 254 + 1);
}

var TECH_SAMPLES = [
  'Nginx 1.25, TLS 1.3', 'Apache 2.4, PHP 8.2', 'Node.js, Express',
  'Cloudflare', 'IIS 10, ASP.NET', 'Python Flask', 'Go, Caddy',
  'Tomcat 10, Java 17', 'Nginx, Docker', 'LiteSpeed, WordPress',
  'React, Vercel', 'Vue.js, Nginx', 'Ruby on Rails, Puma'
];

var STATUS_CODES = [200, 200, 200, 200, 301, 302, 403, 401, 500, 200];

export function renderSubdomainEnum(container) {
  var activeTab = 'enumerate';
  var results = [];
  var wordlist = DEFAULT_WORDLIST.slice();
  var scanning = false;
  var scanProgress = 0;
  var scanTotal = 0;
  var domain = '';
  var filterText = '';
  var filterStatus = 'all';
  var sortCol = 'sub';
  var sortAsc = true;
  var settings = { threads: 10, timeout: 5, resolvers: '8.8.8.8, 1.1.1.1' };

  var SE_CSS = '<style>' +
    '.se-wrap{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#c8d6e5;max-width:1100px}' +
    '.se-title{font-size:1.6rem;font-weight:700;margin:0 0 6px;color:var(--txt)}' +
    '.se-sub{color:var(--mut);font-size:.85rem;margin-bottom:20px;line-height:1.5}' +
    '.se-tabs{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:24px}' +
    '.se-tab{background:var(--card);border:1px solid var(--line);color:var(--mut);padding:8px 16px;font-size:.75rem;font-weight:600;letter-spacing:.04em;text-transform:uppercase;cursor:pointer;border-radius:4px;transition:all .15s;font-family:inherit}' +
    '.se-tab:hover{background:color-mix(in srgb,var(--acc) 8%,var(--card));color:var(--txt)}' +
    '.se-tab.active{background:var(--acc);color:var(--on-acc,#fff);border-color:var(--acc)}' +
    '.se-panel{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:20px;margin-bottom:16px}' +
    '.se-panel-title{font-size:.8rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--acc);margin-bottom:12px}' +
    '.se-input{width:100%;background:var(--card2,#0a0e14);border:1px solid var(--line);color:var(--txt);font-family:ui-monospace,monospace;font-size:.82rem;padding:10px 12px;border-radius:6px;box-sizing:border-box}' +
    '.se-input:focus{border-color:var(--acc);outline:none}' +
    '.se-textarea{width:100%;min-height:200px;background:var(--card2,#0a0e14);border:1px solid var(--line);color:var(--txt);font-family:ui-monospace,monospace;font-size:.75rem;padding:12px;border-radius:6px;resize:vertical;box-sizing:border-box}' +
    '.se-textarea:focus{border-color:var(--acc);outline:none}' +
    '.se-btn{background:var(--acc);color:var(--on-acc,#fff);border:1px solid var(--acc);padding:8px 16px;border-radius:4px;font-size:.78rem;font-weight:600;cursor:pointer;font-family:inherit;transition:all .15s}' +
    '.se-btn:hover{opacity:.9}' +
    '.se-btn:disabled{opacity:.5;cursor:not-allowed}' +
    '.se-btn.ghost{background:transparent;color:var(--acc);border-color:var(--line)}' +
    '.se-btn.ghost:hover{border-color:var(--acc);background:color-mix(in srgb,var(--acc) 8%,transparent)}' +
    '.se-btn.danger{background:#dc2626;border-color:#dc2626;color:#fff}' +
    '.se-btn.danger:hover{background:#b91c1c}' +
    '.se-row{display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap;align-items:flex-start}' +
    '.se-row.center{align-items:center}' +
    '.se-field-group{display:flex;flex-direction:column;gap:4px;flex:1;min-width:180px}' +
    '.se-label{font-size:.7rem;font-weight:600;text-transform:uppercase;letter-spacing:.04em;color:var(--mut)}' +
    '.se-table{width:100%;border-collapse:collapse;font-size:.78rem}' +
    '.se-table th{text-align:left;padding:10px 12px;background:rgba(0,0,0,.2);color:var(--mut);font-weight:600;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;border-bottom:2px solid var(--line);cursor:pointer;user-select:none;white-space:nowrap}' +
    '.se-table th:hover{color:var(--acc)}' +
    '.se-table th .se-sort{margin-left:4px;font-size:.6rem;opacity:.5}' +
    '.se-table th.sorted .se-sort{opacity:1;color:var(--acc)}' +
    '.se-table td{padding:10px 12px;border-bottom:1px solid var(--line);color:var(--txt);vertical-align:top}' +
    '.se-table tr:hover td{background:rgba(0,0,0,.05)}' +
    '.se-status{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.65rem;font-weight:700;letter-spacing:.04em;font-family:ui-monospace,monospace}' +
    '.se-status.s2xx{background:rgba(22,163,74,.15);color:#16a34a}' +
    '.se-status.s3xx{background:rgba(37,99,235,.15);color:#60a5fa}' +
    '.se-status.s4xx{background:rgba(217,119,6,.15);color:#d97706}' +
    '.se-status.s5xx{background:rgba(220,38,38,.15);color:#dc2626}' +
    '.se-status.dead{background:rgba(100,116,139,.15);color:#64748b}' +
    '.se-progress-wrap{background:var(--card2,#0a0e14);border-radius:6px;height:24px;overflow:hidden;position:relative;margin:12px 0}' +
    '.se-progress-bar{height:100%;background:var(--acc);border-radius:6px;transition:width .3s ease;min-width:0}' +
    '.se-progress-text{position:absolute;top:0;left:0;right:0;bottom:0;display:flex;align-items:center;justify-content:center;font-size:.7rem;font-weight:600;color:var(--txt)}' +
    '.se-stat-row{display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap}' +
    '.se-stat{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px 18px;flex:1;min-width:120px;text-align:center}' +
    '.se-stat-n{font-size:1.6rem;font-weight:700;color:var(--acc);display:block}' +
    '.se-stat-l{font-size:.7rem;color:var(--mut);text-transform:uppercase;letter-spacing:.04em;margin-top:2px}' +
    '.se-filter-row{display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap;align-items:center}' +
    '.se-filter-input{background:var(--card2,#0a0e14);border:1px solid var(--line);color:var(--txt);font-size:.8rem;padding:7px 12px;border-radius:6px;min-width:200px;font-family:inherit}' +
    '.se-filter-input:focus{border-color:var(--acc);outline:none}' +
    '.se-select{background:var(--card2,#0a0e14);border:1px solid var(--line);color:var(--txt);font-size:.78rem;padding:7px 12px;border-radius:6px;font-family:inherit;cursor:pointer}' +
    '.se-select:focus{border-color:var(--acc);outline:none}' +
    '.se-mono{font-family:ui-monospace,monospace;font-size:.75rem}' +
    '.se-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}' +
    '.se-grid-3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px}' +
    '@media(max-width:768px){.se-grid,.se-grid-3{grid-template-columns:1fr}.se-filter-row{flex-direction:column}.se-stat-row{flex-direction:column}}' +
    '.se-export-pre{background:var(--card2,#0a0e14);border:1px solid var(--line);border-radius:6px;padding:14px;font-family:ui-monospace,monospace;font-size:.72rem;color:var(--txt);max-height:350px;overflow:auto;white-space:pre;line-height:1.6;margin-top:10px}' +
    '.se-badge{display:inline-block;padding:3px 8px;border-radius:4px;font-size:.65rem;font-weight:700;letter-spacing:.04em;text-transform:uppercase}' +
    '.se-badge.live{background:rgba(22,163,74,.15);color:#16a34a}' +
    '.se-badge.down{background:rgba(220,38,38,.15);color:#dc2626}' +
    '.se-wordlist-info{font-size:.78rem;color:var(--mut);margin-bottom:12px;line-height:1.5}' +
    '.se-chip{display:inline-block;background:var(--card2,#0a0e14);border:1px solid var(--line);padding:3px 10px;border-radius:4px;font-size:.7rem;color:var(--txt);margin:2px 4px 2px 0;font-family:ui-monospace,monospace}' +
    '.se-scan-log{background:var(--card2,#0a0e14);border:1px solid var(--line);border-radius:6px;padding:12px;font-family:ui-monospace,monospace;font-size:.7rem;color:var(--mut);max-height:180px;overflow-y:auto;line-height:1.8;margin-top:10px}' +
    '.se-scan-log .found{color:#16a34a}' +
    '.se-scan-log .notfound{color:#64748b}' +
    '.se-scan-log .info{color:var(--acc)}' +
    '[data-style=pro] .se-wrap{color:#0f172a}' +
    '[data-style=pro] .se-panel{background:#fff;border-color:#e2e8f0}' +
    '[data-style=pro] .se-input,[data-style=pro] .se-textarea{background:#f8fafc;border-color:#e2e8f0;color:#0f172a}' +
    '[data-style=pro] .se-filter-input,[data-style=pro] .se-select{background:#f8fafc;border-color:#e2e8f0;color:#0f172a}' +
    '[data-style=pro] .se-table td{color:#334155}' +
    '[data-style=pro] .se-table th{background:#f1f5f9;color:#475569}' +
    '[data-style=pro] .se-table tr:hover td{background:#f8fafc}' +
    '[data-style=pro] .se-stat{background:#fff;border-color:#e2e8f0}' +
    '[data-style=pro] .se-export-pre{background:#f8fafc;border-color:#e2e8f0;color:#0f172a}' +
    '[data-style=pro] .se-scan-log{background:#f8fafc;border-color:#e2e8f0;color:#64748b}' +
    '[data-style=pro] .se-chip{background:#f1f5f9;border-color:#e2e8f0;color:#334155}' +
    '[data-style=pro] .se-progress-wrap{background:#e2e8f0}' +
    '</style>';

  function statusClass(code) {
    if (!code || code === 0) return 'dead';
    if (code >= 200 && code < 300) return 's2xx';
    if (code >= 300 && code < 400) return 's3xx';
    if (code >= 400 && code < 500) return 's4xx';
    return 's5xx';
  }

  function getFiltered() {
    var filtered = results.slice();
    if (filterStatus !== 'all') {
      if (filterStatus === 'live') filtered = filtered.filter(function(r) { return r.live; });
      else if (filterStatus === 'dead') filtered = filtered.filter(function(r) { return !r.live; });
      else if (filterStatus === '2xx') filtered = filtered.filter(function(r) { return r.status >= 200 && r.status < 300; });
      else if (filterStatus === '3xx') filtered = filtered.filter(function(r) { return r.status >= 300 && r.status < 400; });
      else if (filterStatus === '4xx') filtered = filtered.filter(function(r) { return r.status >= 400 && r.status < 500; });
      else if (filterStatus === '5xx') filtered = filtered.filter(function(r) { return r.status >= 500; });
    }
    if (filterText) {
      var ft = filterText.toLowerCase();
      filtered = filtered.filter(function(r) {
        return r.sub.toLowerCase().indexOf(ft) !== -1 ||
               r.ip.toLowerCase().indexOf(ft) !== -1 ||
               r.tech.toLowerCase().indexOf(ft) !== -1;
      });
    }
    filtered.sort(function(a, b) {
      var va, vb;
      if (sortCol === 'sub') { va = a.sub; vb = b.sub; }
      else if (sortCol === 'ip') { va = a.ip; vb = b.ip; }
      else if (sortCol === 'status') { va = a.status; vb = b.status; }
      else if (sortCol === 'tech') { va = a.tech; vb = b.tech; }
      else { va = a.sub; vb = b.sub; }
      if (typeof va === 'number') return sortAsc ? va - vb : vb - va;
      va = va || ''; vb = vb || '';
      return sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
    });
    return filtered;
  }

  function generateCSV() {
    var rows = ['Subdomain,IP,Status,Technology,Live'];
    results.forEach(function(r) {
      rows.push('"' + r.sub + '","' + r.ip + '",' + r.status + ',"' + r.tech + '",' + r.live);
    });
    return rows.join('\n');
  }

  function generateJSON() {
    return JSON.stringify(results.map(function(r) {
      return { subdomain: r.sub, ip: r.ip, status_code: r.status, technology: r.tech, live: r.live };
    }), null, 2);
  }

  function generateScope() {
    var lines = ['# Scope file generated by Darknode Subdomain Enumerator',
      '# Domain: ' + domain,
      '# Date: ' + new Date().toISOString(),
      '# Total: ' + results.length + ' subdomains',
      ''];
    results.forEach(function(r) {
      if (r.live && r.ip) lines.push(r.sub + ' ' + r.ip);
    });
    return lines.join('\n');
  }

  // Scan results are randomly generated (and "Load Sample" is fixed demo data),
  // so everything sent to the graph is tagged simulated.
  function sendResultsToGraph(btn) {
    var tags = ['subdomain-enum', 'simulated'];
    var meta = { simulated: true, scannedAt: new Date().toISOString() };
    btn.disabled = true;
    import('/js/graph-bridge.js?v=20260923c').then(function(gb) {
      var root = gb.sendToGraph('Subdomain Enum', [{ type: 'DOMAIN', name: domain, data: Object.assign({ subdomainCount: results.length }, meta), opts: { tags: tags.concat('root-domain') } }], undefined, true).entities[0];
      var created = 0, updated = 0, links = 0;
      results.forEach(function(r) {
        var sr = gb.sendToGraph('Subdomain Enum', [{
          type: 'DOMAIN', name: r.sub,
          data: Object.assign({ ip: r.ip || '', httpStatus: r.status, technology: r.tech || '', live: r.live, parent: domain }, meta),
          opts: { tags: tags.concat('subdomain', r.live ? 'live' : 'down') }
        }], undefined, true);
        created += sr.created; updated += sr.updated;
        var sub = sr.entities[0];
        if (!sub) return;
        if (root && sub.id !== root.id && gb.linkEntities(root.id, sub.id, 'related_to')) links++;
        if (r.ip) {
          var ir = gb.sendToGraph('Subdomain Enum', [{ type: 'IP', name: r.ip, data: Object.assign({ resolvedFrom: r.sub }, meta), opts: { tags: tags } }], undefined, true);
          created += ir.created; updated += ir.updated;
          if (ir.entities[0] && gb.linkEntities(sub.id, ir.entities[0].id, 'related_to')) links++;
        }
      });
      btn.textContent = 'Sent: ' + created + ' new, ' + updated + ' merged';
      gb.showGraphToast('Security Graph: ' + results.length + ' subdomains of ' + domain + ', ' + created + ' added, ' + links + ' links (tagged simulated)');
    }).catch(function() { btn.textContent = 'Security Graph unavailable'; btn.disabled = false; });
  }

  function graphBtnHtml() {
    return '<button class="se-btn ghost se-to-graph" title="Simulated results are tagged simulated">Send ' + results.length + ' subdomains to Security Graph</button>';
  }

  function downloadFile(content, filename, mime) {
    var blob = new Blob([content], { type: mime });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function render() {
    var tabsHtml = ['enumerate', 'results', 'export', 'wordlist'].map(function(t) {
      var labels = { enumerate: 'Enumerate', results: 'Results (' + results.length + ')', export: 'Export', wordlist: 'Wordlist' };
      return '<button class="se-tab' + (activeTab === t ? ' active' : '') + '" data-tab="' + t + '">' + labels[t] + '</button>';
    }).join('');

    var contentHtml = '';

    if (activeTab === 'enumerate') {
      var pctText = scanning ? Math.round((scanProgress / scanTotal) * 100) + '%' : '';
      var pctWidth = scanning ? Math.round((scanProgress / scanTotal) * 100) : 0;

      contentHtml = '<div class="se-panel">' +
        '<div class="se-panel-title">Target Domain</div>' +
        '<div class="se-row center">' +
          '<div class="se-field-group" style="flex:3">' +
            '<label class="se-label">Root Domain</label>' +
            '<input class="se-input" id="se-domain" type="text" placeholder="example.com" value="' + esc(domain) + '"' + (scanning ? ' disabled' : '') + '>' +
          '</div>' +
          '<div style="display:flex;gap:8px;align-self:flex-end">' +
            '<button class="se-btn" id="se-start"' + (scanning ? ' disabled' : '') + '>' + (scanning ? 'Scanning...' : 'Start Enumeration') + '</button>' +
            '<button class="se-btn ghost" id="se-sample"' + (scanning ? ' disabled' : '') + '>Load Sample</button>' +
          '</div>' +
        '</div>' +
      '</div>' +
      '<div class="se-panel">' +
        '<div class="se-panel-title">Scan Settings</div>' +
        '<div class="se-grid-3">' +
          '<div class="se-field-group">' +
            '<label class="se-label">Threads</label>' +
            '<input class="se-input" id="se-threads" type="number" min="1" max="50" value="' + settings.threads + '"' + (scanning ? ' disabled' : '') + '>' +
          '</div>' +
          '<div class="se-field-group">' +
            '<label class="se-label">Timeout (seconds)</label>' +
            '<input class="se-input" id="se-timeout" type="number" min="1" max="30" value="' + settings.timeout + '"' + (scanning ? ' disabled' : '') + '>' +
          '</div>' +
          '<div class="se-field-group">' +
            '<label class="se-label">DNS Resolvers</label>' +
            '<input class="se-input" id="se-resolvers" type="text" value="' + esc(settings.resolvers) + '"' + (scanning ? ' disabled' : '') + '>' +
          '</div>' +
        '</div>' +
      '</div>';

      if (scanning) {
        contentHtml += '<div class="se-panel">' +
          '<div class="se-panel-title">Scan Progress</div>' +
          '<div class="se-progress-wrap">' +
            '<div class="se-progress-bar" style="width:' + pctWidth + '%"></div>' +
            '<div class="se-progress-text">' + pctText + ' (' + scanProgress + ' / ' + scanTotal + ')</div>' +
          '</div>' +
          '<div class="se-scan-log" id="se-log"></div>' +
        '</div>';
      }

      if (!scanning && results.length > 0) {
        var liveCount = results.filter(function(r) { return r.live; }).length;
        contentHtml += '<div class="se-panel">' +
          '<div class="se-panel-title">Last Scan Summary</div>' +
          '<div class="se-stat-row">' +
            '<div class="se-stat"><span class="se-stat-n">' + results.length + '</span><span class="se-stat-l">Total Found</span></div>' +
            '<div class="se-stat"><span class="se-stat-n" style="color:#16a34a">' + liveCount + '</span><span class="se-stat-l">Live</span></div>' +
            '<div class="se-stat"><span class="se-stat-n" style="color:#dc2626">' + (results.length - liveCount) + '</span><span class="se-stat-l">Dead</span></div>' +
            '<div class="se-stat"><span class="se-stat-n">' + wordlist.length + '</span><span class="se-stat-l">Wordlist Size</span></div>' +
          '</div>' +
        '</div>';
      }

    } else if (activeTab === 'results') {
      if (results.length === 0) {
        contentHtml = '<div class="se-panel" style="text-align:center;padding:40px">' +
          '<p style="color:var(--mut);font-size:.85rem;margin:0">No results yet. Run an enumeration scan or load sample data first.</p>' +
        '</div>';
      } else {
        var filtered = getFiltered();
        var liveCount = results.filter(function(r) { return r.live; }).length;

        contentHtml = '<div class="se-stat-row">' +
          '<div class="se-stat"><span class="se-stat-n">' + results.length + '</span><span class="se-stat-l">Total</span></div>' +
          '<div class="se-stat"><span class="se-stat-n" style="color:#16a34a">' + liveCount + '</span><span class="se-stat-l">Live</span></div>' +
          '<div class="se-stat"><span class="se-stat-n" style="color:#dc2626">' + (results.length - liveCount) + '</span><span class="se-stat-l">Dead</span></div>' +
          '<div class="se-stat"><span class="se-stat-n">' + filtered.length + '</span><span class="se-stat-l">Filtered</span></div>' +
        '</div>';

        contentHtml += '<div class="se-filter-row">' +
          '<input class="se-filter-input" id="se-filter-text" type="text" placeholder="Filter subdomains, IPs, tech..." value="' + esc(filterText) + '">' +
          '<select class="se-select" id="se-filter-status">' +
            '<option value="all"' + (filterStatus === 'all' ? ' selected' : '') + '>All Status</option>' +
            '<option value="live"' + (filterStatus === 'live' ? ' selected' : '') + '>Live Only</option>' +
            '<option value="dead"' + (filterStatus === 'dead' ? ' selected' : '') + '>Dead Only</option>' +
            '<option value="2xx"' + (filterStatus === '2xx' ? ' selected' : '') + '>2xx Success</option>' +
            '<option value="3xx"' + (filterStatus === '3xx' ? ' selected' : '') + '>3xx Redirect</option>' +
            '<option value="4xx"' + (filterStatus === '4xx' ? ' selected' : '') + '>4xx Client Error</option>' +
            '<option value="5xx"' + (filterStatus === '5xx' ? ' selected' : '') + '>5xx Server Error</option>' +
          '</select>' +
          '<button class="se-btn ghost" id="se-clear-filters" style="font-size:.72rem">Clear Filters</button>' +
          graphBtnHtml() +
        '</div>';

        var sortArrow = function(col) {
          var arrow = sortCol === col ? (sortAsc ? '▲' : '▼') : '▲';
          return '<span class="se-sort">' + arrow + '</span>';
        };

        contentHtml += '<div class="se-panel" style="padding:0;overflow-x:auto">' +
          '<table class="se-table">' +
          '<thead><tr>' +
            '<th data-sort="sub" class="' + (sortCol === 'sub' ? 'sorted' : '') + '">Subdomain ' + sortArrow('sub') + '</th>' +
            '<th data-sort="ip" class="' + (sortCol === 'ip' ? 'sorted' : '') + '">IP Address ' + sortArrow('ip') + '</th>' +
            '<th data-sort="status" class="' + (sortCol === 'status' ? 'sorted' : '') + '">Status ' + sortArrow('status') + '</th>' +
            '<th data-sort="tech" class="' + (sortCol === 'tech' ? 'sorted' : '') + '">Technology ' + sortArrow('tech') + '</th>' +
            '<th>State</th>' +
          '</tr></thead><tbody>';

        filtered.forEach(function(r) {
          var statusDisplay = r.status === 0 ? 'N/A' : String(r.status);
          contentHtml += '<tr>' +
            '<td class="se-mono">' + esc(r.sub) + '</td>' +
            '<td class="se-mono">' + (r.ip ? esc(r.ip) : '<span style="color:var(--mut)">--</span>') + '</td>' +
            '<td><span class="se-status ' + statusClass(r.status) + '">' + statusDisplay + '</span></td>' +
            '<td>' + (r.tech ? esc(r.tech) : '<span style="color:var(--mut)">Unknown</span>') + '</td>' +
            '<td><span class="se-badge ' + (r.live ? 'live' : 'down') + '">' + (r.live ? 'Live' : 'Down') + '</span></td>' +
          '</tr>';
        });

        contentHtml += '</tbody></table></div>';
      }

    } else if (activeTab === 'export') {
      if (results.length === 0) {
        contentHtml = '<div class="se-panel" style="text-align:center;padding:40px">' +
          '<p style="color:var(--mut);font-size:.85rem;margin:0">No results to export. Run a scan first.</p>' +
        '</div>';
      } else {
        contentHtml = '<div class="se-panel">' +
          '<div class="se-panel-title">Export Options</div>' +
          '<p style="font-size:.8rem;color:var(--mut);margin:0 0 16px;line-height:1.5">Export ' + results.length + ' discovered subdomains in your preferred format. Live: ' + results.filter(function(r) { return r.live; }).length + ', Dead: ' + results.filter(function(r) { return !r.live; }).length + '.</p>' +
          '<div class="se-row">' +
            '<button class="se-btn" id="se-export-csv">Export CSV</button>' +
            '<button class="se-btn ghost" id="se-export-json">Export JSON</button>' +
            '<button class="se-btn ghost" id="se-export-scope">Export Scope File</button>' +
            graphBtnHtml() +
          '</div>' +
        '</div>' +
        '<div class="se-grid">' +
          '<div class="se-panel">' +
            '<div class="se-panel-title">CSV Preview</div>' +
            '<div class="se-export-pre" id="se-csv-pre">' + esc(generateCSV().substring(0, 1500)) + '</div>' +
          '</div>' +
          '<div class="se-panel">' +
            '<div class="se-panel-title">JSON Preview</div>' +
            '<div class="se-export-pre" id="se-json-pre">' + esc(generateJSON().substring(0, 1500)) + '</div>' +
          '</div>' +
        '</div>' +
        '<div class="se-panel">' +
          '<div class="se-panel-title">Scope File Preview</div>' +
          '<div class="se-export-pre" id="se-scope-pre">' + esc(generateScope()) + '</div>' +
        '</div>';
      }

    } else if (activeTab === 'wordlist') {
      contentHtml = '<div class="se-panel">' +
        '<div class="se-panel-title">Subdomain Wordlist</div>' +
        '<div class="se-wordlist-info">Customize the subdomain prefixes used during enumeration. One prefix per line. Current count: <strong>' + wordlist.length + '</strong> entries.</div>' +
        '<textarea class="se-textarea" id="se-wordlist-edit" style="min-height:260px">' + esc(wordlist.join('\n')) + '</textarea>' +
        '<div class="se-row" style="margin-top:12px">' +
          '<button class="se-btn" id="se-wl-save">Save Wordlist</button>' +
          '<button class="se-btn ghost" id="se-wl-reset">Reset to Default</button>' +
          '<button class="se-btn ghost" id="se-wl-sort">Sort A-Z</button>' +
          '<button class="se-btn ghost" id="se-wl-dedup">Remove Duplicates</button>' +
        '</div>' +
      '</div>' +
      '<div class="se-panel">' +
        '<div class="se-panel-title">Quick Add Common Prefixes</div>' +
        '<p style="font-size:.78rem;color:var(--mut);margin:0 0 10px;line-height:1.5">Click to add any missing prefixes to your wordlist:</p>' +
        '<div id="se-quickadd">';

      var quickPrefixes = ['www', 'mail', 'api', 'dev', 'staging', 'admin', 'cdn', 'blog', 'shop', 'portal',
        'vpn', 'ftp', 'ns1', 'ns2', 'mx', 'webmail', 'test', 'demo', 'beta', 'alpha',
        'sso', 'auth', 'login', 'dashboard', 'docs', 'status', 'git', 'jenkins', 'ci',
        'monitor', 'grafana', 'kibana', 'elastic', 'redis', 'db', 'mysql', 'postgres',
        'backup', 'internal', 'intranet', 'corp', 'remote', 'support', 'help', 'wiki',
        'crm', 'erp', 'hr', 'billing', 'store', 'sandbox', 'qa', 'uat', 'preprod', 'prod'];

      quickPrefixes.forEach(function(p) {
        var inList = wordlist.indexOf(p) !== -1;
        contentHtml += '<span class="se-chip" style="cursor:pointer;' + (inList ? 'opacity:.4;text-decoration:line-through' : '') + '" data-prefix="' + p + '">' + p + '</span>';
      });

      contentHtml += '</div></div>' +
      '<div class="se-panel">' +
        '<div class="se-panel-title">Import / Export Wordlist</div>' +
        '<div class="se-row">' +
          '<button class="se-btn ghost" id="se-wl-export">Export Wordlist</button>' +
          '<button class="se-btn ghost" id="se-wl-import">Import from File</button>' +
        '</div>' +
      '</div>';
    }

    container.innerHTML = SE_CSS +
      '<div class="se-wrap">' +
        '<h1 class="se-title">Subdomain Enumerator</h1>' +
        '<p class="se-sub">Passive subdomain enumeration and discovery. Input a root domain to discover subdomains, resolve IPs, and identify technology stacks.</p>' +
        '<div class="se-tabs">' + tabsHtml + '</div>' +
        contentHtml +
      '</div>';

    /* --- Event Binding --- */

    container.querySelectorAll('.se-tab').forEach(function(btn) {
      btn.onclick = function() { activeTab = btn.dataset.tab; render(); };
    });

    /* Enumerate tab */
    var startBtn = container.querySelector('#se-start');
    if (startBtn) startBtn.onclick = function() {
      var input = container.querySelector('#se-domain');
      var d = input ? input.value.trim() : '';
      if (!d) return;
      domain = d.replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase();
      settings.threads = parseInt(container.querySelector('#se-threads').value) || 10;
      settings.timeout = parseInt(container.querySelector('#se-timeout').value) || 5;
      settings.resolvers = container.querySelector('#se-resolvers').value || '8.8.8.8, 1.1.1.1';
      startScan();
    };

    var sampleBtn = container.querySelector('#se-sample');
    if (sampleBtn) sampleBtn.onclick = function() {
      domain = 'example.com';
      results = SAMPLE_RESULTS.slice();
      activeTab = 'results';
      render();
    };

    /* Results tab */
    container.querySelectorAll('.se-table th[data-sort]').forEach(function(th) {
      th.onclick = function() {
        var col = th.dataset.sort;
        if (sortCol === col) sortAsc = !sortAsc;
        else { sortCol = col; sortAsc = true; }
        render();
      };
    });

    var filterInput = container.querySelector('#se-filter-text');
    if (filterInput) filterInput.oninput = function() {
      filterText = filterInput.value;
      render();
      var el = container.querySelector('#se-filter-text');
      if (el) { el.focus(); el.selectionStart = el.selectionEnd = filterText.length; }
    };

    var filterSelect = container.querySelector('#se-filter-status');
    if (filterSelect) filterSelect.onchange = function() {
      filterStatus = filterSelect.value;
      render();
    };

    var clearFiltersBtn = container.querySelector('#se-clear-filters');
    if (clearFiltersBtn) clearFiltersBtn.onclick = function() {
      filterText = '';
      filterStatus = 'all';
      render();
    };

    /* Export tab */
    var csvBtn = container.querySelector('#se-export-csv');
    if (csvBtn) csvBtn.onclick = function() {
      downloadFile(generateCSV(), domain.replace(/\./g, '_') + '_subdomains.csv', 'text/csv');
    };
    var jsonBtn = container.querySelector('#se-export-json');
    if (jsonBtn) jsonBtn.onclick = function() {
      downloadFile(generateJSON(), domain.replace(/\./g, '_') + '_subdomains.json', 'application/json');
    };
    var scopeBtn = container.querySelector('#se-export-scope');
    if (scopeBtn) scopeBtn.onclick = function() {
      downloadFile(generateScope(), domain.replace(/\./g, '_') + '_scope.txt', 'text/plain');
    };

    container.querySelectorAll('.se-to-graph').forEach(function(btn) {
      btn.onclick = function() { sendResultsToGraph(btn); };
    });

    /* Wordlist tab */
    var wlSaveBtn = container.querySelector('#se-wl-save');
    if (wlSaveBtn) wlSaveBtn.onclick = function() {
      var ta = container.querySelector('#se-wordlist-edit');
      if (ta) {
        wordlist = ta.value.split('\n').map(function(l) { return l.trim(); }).filter(function(l) { return l.length > 0; });
        render();
      }
    };

    var wlResetBtn = container.querySelector('#se-wl-reset');
    if (wlResetBtn) wlResetBtn.onclick = function() {
      wordlist = DEFAULT_WORDLIST.slice();
      render();
    };

    var wlSortBtn = container.querySelector('#se-wl-sort');
    if (wlSortBtn) wlSortBtn.onclick = function() {
      var ta = container.querySelector('#se-wordlist-edit');
      if (ta) {
        wordlist = ta.value.split('\n').map(function(l) { return l.trim(); }).filter(function(l) { return l.length > 0; });
        wordlist.sort();
        render();
      }
    };

    var wlDedupBtn = container.querySelector('#se-wl-dedup');
    if (wlDedupBtn) wlDedupBtn.onclick = function() {
      var ta = container.querySelector('#se-wordlist-edit');
      if (ta) {
        var lines = ta.value.split('\n').map(function(l) { return l.trim(); }).filter(function(l) { return l.length > 0; });
        var seen = {};
        wordlist = [];
        lines.forEach(function(l) {
          var key = l.toLowerCase();
          if (!seen[key]) { seen[key] = true; wordlist.push(l); }
        });
        render();
      }
    };

    var wlExportBtn = container.querySelector('#se-wl-export');
    if (wlExportBtn) wlExportBtn.onclick = function() {
      downloadFile(wordlist.join('\n'), 'subdomain_wordlist.txt', 'text/plain');
    };

    var wlImportBtn = container.querySelector('#se-wl-import');
    if (wlImportBtn) wlImportBtn.onclick = function() {
      var inp = document.createElement('input');
      inp.type = 'file';
      inp.accept = '.txt,.csv,.lst';
      inp.onchange = function() {
        if (inp.files.length === 0) return;
        var reader = new FileReader();
        reader.onload = function(e) {
          var lines = e.target.result.split('\n').map(function(l) { return l.trim(); }).filter(function(l) { return l.length > 0; });
          wordlist = wordlist.concat(lines);
          render();
        };
        reader.readAsText(inp.files[0]);
      };
      inp.click();
    };

    container.querySelectorAll('#se-quickadd .se-chip').forEach(function(chip) {
      chip.onclick = function() {
        var prefix = chip.dataset.prefix;
        if (wordlist.indexOf(prefix) === -1) {
          wordlist.push(prefix);
          render();
        }
      };
    });
  }

  function startScan() {
    scanning = true;
    scanProgress = 0;
    scanTotal = wordlist.length;
    results = [];
    render();

    var logEl = container.querySelector('#se-log');
    var idx = 0;
    var batchSize = Math.max(1, Math.floor(wordlist.length / 30));

    function tick() {
      if (idx >= wordlist.length) {
        scanning = false;
        activeTab = 'results';
        render();
        return;
      }

      var end = Math.min(idx + batchSize, wordlist.length);
      for (var i = idx; i < end; i++) {
        var prefix = wordlist[i];
        var sub = prefix + '.' + domain;
        var found = Math.random() > 0.7;
        if (found) {
          var ip = randomIP();
          var status = STATUS_CODES[Math.floor(Math.random() * STATUS_CODES.length)];
          var tech = TECH_SAMPLES[Math.floor(Math.random() * TECH_SAMPLES.length)];
          results.push({ sub: sub, ip: ip, status: status, tech: tech, live: true });
          if (logEl) logEl.innerHTML += '<div class="found">[+] Found: ' + esc(sub) + ' -> ' + esc(ip) + ' [' + status + ']</div>';
        } else {
          if (logEl && Math.random() > 0.6) {
            logEl.innerHTML += '<div class="notfound">[-] ' + esc(sub) + ' - NXDOMAIN</div>';
          }
        }
      }

      idx = end;
      scanProgress = idx;

      var bar = container.querySelector('.se-progress-bar');
      var text = container.querySelector('.se-progress-text');
      if (bar) bar.style.width = Math.round((scanProgress / scanTotal) * 100) + '%';
      if (text) text.textContent = Math.round((scanProgress / scanTotal) * 100) + '% (' + scanProgress + ' / ' + scanTotal + ')';

      if (logEl) logEl.scrollTop = logEl.scrollHeight;

      setTimeout(tick, 60 + Math.floor(Math.random() * 80));
    }

    if (logEl) logEl.innerHTML = '<div class="info">[*] Starting subdomain enumeration for ' + esc(domain) + '</div>' +
      '<div class="info">[*] Wordlist: ' + wordlist.length + ' entries | Threads: ' + settings.threads + ' | Timeout: ' + settings.timeout + 's</div>' +
      '<div class="info">[*] Resolvers: ' + esc(settings.resolvers) + '</div>';

    setTimeout(tick, 300);
  }

  render();
}
