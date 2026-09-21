import { esc } from '/js/shared.js';

const SS_WORDLIST = ['www','mail','ftp','admin','blog','dev','staging','api','cdn','app','portal','vpn',
  'remote','webmail','ns1','ns2','mx','smtp','pop','imap','test','demo','beta','alpha','docs','wiki',
  'git','jenkins','ci','cd','grafana','kibana','elastic','prometheus','monitor','status','health',
  'login','sso','auth','oauth','id','accounts','dashboard','panel','console','cloud','s3','storage',
  'media','assets','static','img','images','files','upload','download','backup','db','database','redis',
  'mongo','postgres','mysql','phpmyadmin','adminer','minio','vault','secrets','internal','intranet',
  'extranet','partner','vendor','support','help','helpdesk','ticket','jira','confluence','slack',
  'teams','meet','zoom','calendar','crm','erp','hr','payroll','finance','billing','pay','shop','store',
  'checkout','cart','orders','inventory','warehouse','logistics','tracking','analytics','metrics',
  'data','bigdata','ml','ai','lab','sandbox','stg','uat','qa','prod','production','edge','node',
  'proxy','gateway','lb','loadbalancer','waf','firewall','ids','ips','siem','soc','noc'];

const SS_TECHS = ['Apache/2.4.57','nginx/1.24.0','Microsoft-IIS/10.0','LiteSpeed','Cloudflare','Express',
  'Tomcat/9.0','Caddy','HAProxy','Varnish','Envoy','Traefik','OpenResty','Gunicorn','Uvicorn'];

const SS_STATUSES = [
  { code: 200, label: 'OK', color: '#16a34a' },
  { code: 301, label: 'Moved', color: '#eab308' },
  { code: 302, label: 'Found', color: '#eab308' },
  { code: 403, label: 'Forbidden', color: '#f97316' },
  { code: 404, label: 'Not Found', color: '#dc2626' },
  { code: 500, label: 'Error', color: '#dc2626' },
  { code: 503, label: 'Unavailable', color: '#dc2626' }
];

function fakeIP() {
  return [10 + Math.floor(Math.random() * 230), Math.floor(Math.random() * 256), Math.floor(Math.random() * 256), Math.floor(Math.random() * 254) + 1].join('.');
}

function fakeScan(domain) {
  var results = [];
  var count = 8 + Math.floor(Math.random() * 15);
  var used = new Set();
  for (var i = 0; i < count; i++) {
    var sub;
    do { sub = SS_WORDLIST[Math.floor(Math.random() * SS_WORDLIST.length)]; } while (used.has(sub));
    used.add(sub);
    var st = SS_STATUSES[Math.floor(Math.random() * SS_STATUSES.length)];
    var tech = SS_TECHS[Math.floor(Math.random() * SS_TECHS.length)];
    var ports = [80, 443];
    if (Math.random() > 0.7) ports.push(8080);
    if (Math.random() > 0.8) ports.push(8443);
    if (Math.random() > 0.9) ports.push(22);
    results.push({ subdomain: sub + '.' + domain, ip: fakeIP(), status: st.code, statusLabel: st.label, statusColor: st.color, server: tech, ports: ports, ssl: Math.random() > 0.3, wildcard: Math.random() > 0.85 });
  }
  results.sort(function(a, b) { return a.subdomain.localeCompare(b.subdomain); });
  return results;
}

export function renderSubdomainScanner(container) {
  var state = { tab: 'scan', domain: '', results: [], scanning: false, progress: 0, filter: 'all', sortBy: 'name' };
  var scanTimer = null;

  var CSS = '<style>' +
    '.ss-wrap{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:var(--txt,#c8d6e5)}' +
    '.ss-header{margin-bottom:24px}' +
    '.ss-title{font-size:1.5rem;font-weight:700;margin:0 0 6px}' +
    '.ss-sub{color:var(--mut,#64748b);font-size:.85rem}' +
    '.ss-tabs{display:flex;gap:4px;margin-bottom:20px;flex-wrap:wrap}' +
    '.ss-tab{padding:8px 16px;border:1px solid var(--line,#1e293b);border-radius:6px;background:transparent;color:var(--mut,#8899aa);cursor:pointer;font-size:.78rem;font-weight:600;text-transform:uppercase;letter-spacing:.04em;transition:all .15s;font-family:inherit}' +
    '.ss-tab:hover{background:rgba(255,255,255,.05);color:var(--txt)}' +
    '.ss-tab.active{background:var(--acc,#2563eb);color:#fff;border-color:var(--acc,#2563eb)}' +
    '.ss-panel{background:var(--card,#0d1117);border:1px solid var(--line,#1e293b);border-radius:8px;padding:20px;margin-bottom:16px}' +
    '.ss-input-row{display:flex;gap:8px;align-items:center}' +
    '.ss-input{flex:1;background:var(--card2,#080c14);border:1px solid var(--line,#1e293b);border-radius:6px;color:var(--txt,#e2e8f0);font-family:ui-monospace,monospace;font-size:.85rem;padding:10px 14px}' +
    '.ss-input:focus{border-color:var(--acc);outline:none}' +
    '.ss-btn{padding:10px 20px;border:none;border-radius:6px;background:var(--acc,#2563eb);color:#fff;cursor:pointer;font-size:.78rem;font-weight:600;font-family:inherit;transition:all .15s}' +
    '.ss-btn:hover{opacity:.9}' +
    '.ss-btn:disabled{opacity:.5;cursor:not-allowed}' +
    '.ss-btn-ghost{background:transparent;border:1px solid var(--line);color:var(--mut);padding:7px 14px}' +
    '.ss-btn-ghost:hover{border-color:var(--acc);color:var(--acc)}' +
    '.ss-progress{height:4px;border-radius:2px;background:var(--line);margin:14px 0;overflow:hidden}' +
    '.ss-progress-fill{height:100%;border-radius:2px;background:var(--acc);transition:width .3s}' +
    '.ss-stat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px;margin-bottom:16px}' +
    '.ss-stat{background:var(--card2,#080c14);border:1px solid var(--line);border-radius:8px;padding:14px;text-align:center}' +
    '.ss-stat-val{font-size:1.3rem;font-weight:800;color:var(--acc);font-variant-numeric:tabular-nums}' +
    '.ss-stat-lbl{font-size:.65rem;color:var(--mut);text-transform:uppercase;letter-spacing:.04em;margin-top:2px}' +
    '.ss-table{width:100%;border-collapse:collapse;font-size:.75rem}' +
    '.ss-table th{text-align:left;padding:8px 10px;border-bottom:2px solid var(--line);color:var(--mut);font-weight:600;text-transform:uppercase;letter-spacing:.04em;font-size:.68rem;cursor:pointer}' +
    '.ss-table th:hover{color:var(--acc)}' +
    '.ss-table td{padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:middle}' +
    '.ss-table tr:hover td{background:rgba(255,255,255,.02)}' +
    '.ss-badge{display:inline-block;padding:2px 8px;border-radius:3px;font-size:.65rem;font-weight:700;text-transform:uppercase;letter-spacing:.03em}' +
    '.ss-port{display:inline-block;padding:1px 6px;border-radius:3px;font-size:.63rem;font-family:ui-monospace,monospace;background:rgba(37,99,235,.1);color:var(--acc);margin:1px 2px}' +
    '.ss-ssl{display:inline-flex;align-items:center;gap:3px;font-size:.65rem;font-weight:600}' +
    '.ss-filters{display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap}' +
    '.ss-filter{padding:4px 10px;border:1px solid var(--line);border-radius:4px;background:transparent;color:var(--mut);cursor:pointer;font-size:.7rem;font-family:inherit;transition:all .15s}' +
    '.ss-filter:hover{border-color:var(--acc);color:var(--acc)}' +
    '.ss-filter.active{background:var(--acc);color:#fff;border-color:var(--acc)}' +
    '.ss-empty{text-align:center;padding:40px;color:var(--mut);font-size:.85rem}' +
    '.ss-tree{font-size:.78rem}' +
    '.ss-tree-node{padding:4px 0 4px 20px;border-left:1px solid var(--line);margin-left:8px}' +
    '.ss-tree-root{font-weight:700;padding:6px 0;font-size:.85rem;color:var(--acc)}' +
    '.ss-tree-sub{display:flex;align-items:center;gap:8px;padding:3px 0;cursor:default}' +
    '.ss-tree-dot{width:6px;height:6px;border-radius:50%;flex-shrink:0}' +
    '[data-style=pro] .ss-wrap{color:#0f172a}' +
    '[data-style=pro] .ss-panel{background:#fff;border-color:#e2e8f0}' +
    '[data-style=pro] .ss-input{background:#f8fafc;border-color:#e2e8f0;color:#0f172a}' +
    '[data-style=pro] .ss-stat{background:#f8fafc;border-color:#e2e8f0}' +
    '[data-style=pro] .ss-table td{border-bottom-color:#f1f5f9;color:#334155}' +
    '[data-style=pro] .ss-table th{border-bottom-color:#e2e8f0;color:#64748b}' +
    '[data-style=pro] .ss-table tr:hover td{background:#f8fafc}' +
    '[data-style=pro] .ss-tab{border-color:#e2e8f0;color:#64748b}' +
    '[data-style=pro] .ss-tab:hover{background:#f1f5f9;color:#0f172a}' +
    '[data-style=pro] .ss-tab.active{background:#2563eb;color:#fff;border-color:#2563eb}' +
    '[data-style=pro] .ss-filter{border-color:#e2e8f0;color:#64748b}' +
    '[data-style=pro] .ss-filter:hover{border-color:#2563eb;color:#2563eb}' +
    '[data-style=pro] .ss-filter.active{background:#2563eb;color:#fff;border-color:#2563eb}' +
    '[data-style=pro] .ss-progress{background:#e2e8f0}' +
    '[data-style=pro] .ss-tree-node{border-left-color:#e2e8f0}' +
    '[data-style=pro] .ss-btn-ghost{border-color:#e2e8f0;color:#64748b}' +
    '</style>';

  function render() {
    var tabs = [
      { id: 'scan', label: 'Scan' },
      { id: 'results', label: 'Results (' + state.results.length + ')' },
      { id: 'tree', label: 'Tree View' }
    ];
    var html = CSS + '<div class="ss-wrap">' +
      '<div class="ss-header"><h1 class="ss-title">Subdomain Scanner</h1><p class="ss-sub">Enumerate and discover subdomains using simulated wordlist-based scanning</p></div>' +
      '<div class="ss-tabs">' + tabs.map(function(t) { return '<button class="ss-tab' + (state.tab === t.id ? ' active' : '') + '" data-tab="' + t.id + '">' + t.label + '</button>'; }).join('') + '</div>';

    if (state.tab === 'scan') html += renderScan();
    else if (state.tab === 'results') html += renderResults();
    else if (state.tab === 'tree') html += renderTree();

    html += '</div>';
    container.innerHTML = html;
    wireEvents();
  }

  function renderScan() {
    var h = '<div class="ss-panel">' +
      '<div style="margin-bottom:10px;font-size:.78rem;color:var(--mut)">Enter a target domain to simulate subdomain enumeration</div>' +
      '<div class="ss-input-row">' +
      '<input class="ss-input" id="ss-domain" placeholder="example.com" value="' + esc(state.domain) + '">' +
      '<button class="ss-btn" id="ss-scan"' + (state.scanning ? ' disabled' : '') + '>' + (state.scanning ? 'Scanning...' : 'Start Scan') + '</button></div>';
    if (state.scanning) {
      h += '<div class="ss-progress"><div class="ss-progress-fill" style="width:' + state.progress + '%"></div></div>' +
        '<div style="font-size:.72rem;color:var(--mut);text-align:center">Checking ' + SS_WORDLIST.length + ' subdomains... ' + state.progress + '%</div>';
    }
    h += '</div>';

    if (state.results.length) {
      var live = state.results.filter(function(r) { return r.status === 200; }).length;
      var ssl = state.results.filter(function(r) { return r.ssl; }).length;
      var uniqueIPs = new Set(state.results.map(function(r) { return r.ip; })).size;
      h += '<div class="ss-stat-grid">' +
        '<div class="ss-stat"><div class="ss-stat-val">' + state.results.length + '</div><div class="ss-stat-lbl">Found</div></div>' +
        '<div class="ss-stat"><div class="ss-stat-val" style="color:#16a34a">' + live + '</div><div class="ss-stat-lbl">Live (200)</div></div>' +
        '<div class="ss-stat"><div class="ss-stat-val">' + uniqueIPs + '</div><div class="ss-stat-lbl">Unique IPs</div></div>' +
        '<div class="ss-stat"><div class="ss-stat-val">' + ssl + '</div><div class="ss-stat-lbl">SSL/TLS</div></div>' +
        '</div>';
    }
    return h;
  }

  function getFiltered() {
    var f = state.results;
    if (state.filter === 'live') f = f.filter(function(r) { return r.status === 200; });
    else if (state.filter === 'redirect') f = f.filter(function(r) { return r.status === 301 || r.status === 302; });
    else if (state.filter === 'error') f = f.filter(function(r) { return r.status >= 400; });
    else if (state.filter === 'ssl') f = f.filter(function(r) { return r.ssl; });
    if (state.sortBy === 'status') f = f.slice().sort(function(a, b) { return a.status - b.status; });
    else if (state.sortBy === 'ip') f = f.slice().sort(function(a, b) { return a.ip.localeCompare(b.ip); });
    return f;
  }

  function renderResults() {
    if (!state.results.length) return '<div class="ss-empty">No results yet. Run a scan first.</div>';
    var filtered = getFiltered();
    var h = '<div class="ss-filters">' +
      ['all', 'live', 'redirect', 'error', 'ssl'].map(function(f) {
        var labels = { all: 'All', live: 'Live (200)', redirect: 'Redirects', error: 'Errors', ssl: 'SSL Only' };
        return '<button class="ss-filter' + (state.filter === f ? ' active' : '') + '" data-filter="' + f + '">' + labels[f] + '</button>';
      }).join('') + '</div>';

    h += '<div class="ss-panel" style="overflow-x:auto"><table class="ss-table"><thead><tr>' +
      '<th data-sort="name">Subdomain</th><th data-sort="ip">IP</th><th data-sort="status">Status</th><th>Server</th><th>Ports</th><th>SSL</th></tr></thead><tbody>';
    filtered.forEach(function(r) {
      h += '<tr><td style="font-family:ui-monospace,monospace;font-weight:600">' + esc(r.subdomain) + (r.wildcard ? ' <span style="color:#f97316;font-size:.6rem">WILDCARD</span>' : '') + '</td>' +
        '<td style="font-family:ui-monospace,monospace">' + esc(r.ip) + '</td>' +
        '<td><span class="ss-badge" style="background:' + r.statusColor + '22;color:' + r.statusColor + '">' + r.status + ' ' + esc(r.statusLabel) + '</span></td>' +
        '<td style="font-size:.7rem;color:var(--mut)">' + esc(r.server) + '</td>' +
        '<td>' + r.ports.map(function(p) { return '<span class="ss-port">' + p + '</span>'; }).join('') + '</td>' +
        '<td><span class="ss-ssl" style="color:' + (r.ssl ? '#16a34a' : '#dc2626') + '">' + (r.ssl ? '&#9679; Yes' : '&#9675; No') + '</span></td></tr>';
    });
    h += '</tbody></table></div>';
    h += '<div style="display:flex;gap:8px"><button class="ss-btn-ghost ss-btn" id="ss-export">Copy Results</button></div>';
    return h;
  }

  function renderTree() {
    if (!state.results.length) return '<div class="ss-empty">No results to visualize.</div>';
    var byIP = {};
    state.results.forEach(function(r) {
      if (!byIP[r.ip]) byIP[r.ip] = [];
      byIP[r.ip].push(r);
    });
    var h = '<div class="ss-panel"><div class="ss-tree">';
    h += '<div class="ss-tree-root">' + esc(state.domain) + '</div>';
    Object.keys(byIP).forEach(function(ip) {
      h += '<div class="ss-tree-node">';
      h += '<div style="font-weight:600;font-size:.78rem;margin-bottom:4px;color:var(--mut)">' + esc(ip) + ' (' + byIP[ip].length + ' hosts)</div>';
      byIP[ip].forEach(function(r) {
        h += '<div class="ss-tree-sub"><div class="ss-tree-dot" style="background:' + r.statusColor + '"></div><span>' + esc(r.subdomain) + '</span><span class="ss-badge" style="background:' + r.statusColor + '22;color:' + r.statusColor + ';font-size:.6rem">' + r.status + '</span></div>';
      });
      h += '</div>';
    });
    h += '</div></div>';
    return h;
  }

  function startScan() {
    var el = container.querySelector('#ss-domain');
    if (!el || !el.value.trim()) return;
    state.domain = el.value.trim();
    state.scanning = true;
    state.progress = 0;
    state.results = [];
    render();
    var steps = 20;
    var step = 0;
    scanTimer = setInterval(function() {
      step++;
      state.progress = Math.min(100, Math.round(step / steps * 100));
      if (step >= steps) {
        clearInterval(scanTimer);
        scanTimer = null;
        state.scanning = false;
        state.results = fakeScan(state.domain);
        state.tab = 'results';
      }
      render();
    }, 150);
  }

  function wireEvents() {
    container.querySelectorAll('.ss-tab').forEach(function(btn) {
      btn.onclick = function() { state.tab = btn.dataset.tab; render(); };
    });
    var scanBtn = container.querySelector('#ss-scan');
    if (scanBtn) scanBtn.onclick = startScan;
    var domainInput = container.querySelector('#ss-domain');
    if (domainInput) domainInput.onkeydown = function(e) { if (e.key === 'Enter') startScan(); };
    container.querySelectorAll('.ss-filter').forEach(function(btn) {
      btn.onclick = function() { state.filter = btn.dataset.filter; render(); };
    });
    container.querySelectorAll('th[data-sort]').forEach(function(th) {
      th.onclick = function() { state.sortBy = th.dataset.sort; render(); };
    });
    var exportBtn = container.querySelector('#ss-export');
    if (exportBtn) exportBtn.onclick = function() {
      var lines = state.results.map(function(r) { return r.subdomain + ',' + r.ip + ',' + r.status + ',' + r.server + ',' + (r.ssl ? 'SSL' : 'No SSL'); });
      lines.unshift('Subdomain,IP,Status,Server,SSL');
      if (navigator.clipboard) navigator.clipboard.writeText(lines.join('\n'));
      exportBtn.textContent = 'Copied!';
      setTimeout(function() { exportBtn.textContent = 'Copy Results'; }, 1500);
    };
  }

  render();
}
