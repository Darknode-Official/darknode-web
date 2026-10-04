import { esc } from '/js/shared.js';

// Real subdomain discovery — no fabricated data.
//   * Passive:  crt.sh certificate-transparency logs (every name a CA ever signed).
//   * Active:   DNS-over-HTTPS (dns.google) resolves each candidate to a real A record.
// Both endpoints are in the site CSP. A browser cannot port-scan or read a remote
// host's HTTP status/server header (no raw sockets, CORS), so this reports only
// what is genuinely observable: the name, its resolved IP(s), and whether it is live
// in DNS. crt.sh may be CORS-blocked from some networks; when it is, the wordlist is
// still resolved over DoH, so the scan stays real either way.

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

const MAX_CANDIDATES = 160; // cap work so a scan stays snappy and polite to the resolvers
const DOH_CONCURRENCY = 8;

// Passive discovery from certificate transparency. Best-effort: resolves to [] if
// crt.sh is unreachable or blocks CORS, and the caller falls back to the wordlist.
async function crtshNames(domain) {
  try {
    const ctrl = new AbortController();
    const to = setTimeout(function () { ctrl.abort(); }, 12000);
    const res = await fetch('https://crt.sh/?q=%25.' + encodeURIComponent(domain) + '&output=json', { signal: ctrl.signal, headers: { Accept: 'application/json' } });
    clearTimeout(to);
    if (!res.ok) return { names: [], wildcard: new Set(), ok: false };
    const data = await res.json();
    const set = new Set(), wildcard = new Set();
    for (const row of (Array.isArray(data) ? data : [])) {
      const raw = String(row.name_value || '').split(/\n+/).concat([String(row.common_name || '')]);
      for (let n of raw) {
        n = n.trim().toLowerCase();
        if (!n) continue;
        if (n.indexOf('*.') === 0) { n = n.slice(2); wildcard.add(n); }
        if (n === domain || n.endsWith('.' + domain)) set.add(n);
      }
    }
    return { names: [...set], wildcard: wildcard, ok: true };
  } catch (_) { return { names: [], wildcard: new Set(), ok: false }; }
}

// Active resolution over DoH. Returns the first A record (real IP) or ''.
async function resolveA(name) {
  try {
    const ctrl = new AbortController();
    const to = setTimeout(function () { ctrl.abort(); }, 6000);
    const r = await fetch('https://dns.google/resolve?name=' + encodeURIComponent(name) + '&type=A', { signal: ctrl.signal });
    clearTimeout(to);
    if (!r.ok) return '';
    const j = await r.json();
    const a = (j.Answer || []).filter(function (x) { return x.type === 1; }).map(function (x) { return x.data; });
    return a[0] || '';
  } catch (_) { return ''; }
}

// Resolve a list with bounded concurrency, calling onTick after each for progress.
async function resolveAll(names, onTick) {
  const results = new Array(names.length);
  let i = 0, done = 0;
  async function worker() {
    while (i < names.length) {
      const idx = i++;
      results[idx] = await resolveA(names[idx]);
      done++;
      if (onTick) onTick(done, names.length);
    }
  }
  const pool = [];
  for (let w = 0; w < Math.min(DOH_CONCURRENCY, names.length); w++) pool.push(worker());
  await Promise.all(pool);
  return results;
}

// The real scan: passive CT names ∪ wordlist, resolved over DoH. onProgress(pct, label).
async function realScan(domain, onProgress) {
  onProgress(5, 'Querying crt.sh certificate transparency…');
  const ct = await crtshNames(domain);
  const cand = new Set();
  for (const n of ct.names) cand.add(n);
  for (const w of SS_WORDLIST) cand.add(w + '.' + domain);
  let names = [...cand];
  if (names.length > MAX_CANDIDATES) names = names.slice(0, MAX_CANDIDATES);
  onProgress(20, 'Resolving ' + names.length + ' candidates over DNS-over-HTTPS…');
  const ips = await resolveAll(names, function (d, total) { onProgress(20 + Math.round(d / total * 78), 'Resolving ' + d + '/' + total + '…'); });
  const ctSet = new Set(ct.names);
  const results = [];
  for (let k = 0; k < names.length; k++) {
    const name = names[k], ip = ips[k];
    const fromCT = ctSet.has(name);
    // Keep anything that is live in DNS, plus CT-attested names even if they have no A record.
    if (!ip && !fromCT) continue;
    results.push({
      subdomain: name,
      ip: ip || '',
      resolves: !!ip,
      wildcard: ct.wildcard.has(name),
      source: fromCT ? (ip ? 'crt.sh + dns' : 'crt.sh') : 'dns'
    });
  }
  results.sort(function (a, b) { return a.subdomain.localeCompare(b.subdomain); });
  onProgress(100, 'Done');
  return { results: results, crtOk: ct.ok };
}

export function renderSubdomainScanner(container) {
  var state = { tab: 'scan', domain: '', results: [], scanning: false, progress: 0, progressLabel: '', filter: 'all', sortBy: 'name', crtOk: true, error: '' };

  var CSS = '<style>' +
    '.ss-wrap{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:var(--txt,#c8d6e5)}' +
    '.ss-header{margin-bottom:24px}' +
    '.ss-title{font-size:1.5rem;font-weight:700;margin:0 0 6px}' +
    '.ss-sub{color:var(--mut,#64748b);font-size:.85rem}' +
    '.ss-tabs{display:flex;gap:4px;margin-bottom:20px;flex-wrap:wrap}' +
    '.ss-tab{padding:8px 16px;border:1px solid var(--line,#1e293b);border-radius:4px;background:transparent;color:var(--mut,#8899aa);cursor:pointer;font-size:.78rem;font-weight:600;text-transform:uppercase;letter-spacing:.04em;transition:all .15s;font-family:inherit}' +
    '.ss-tab:hover{background:rgba(255,255,255,.05);color:var(--txt)}' +
    '.ss-tab.active{background:var(--acc,#2563eb);color:#fff;border-color:var(--acc,#2563eb)}' +
    '.ss-panel{background:var(--card,#0d1117);border:1px solid var(--line,#1e293b);border-radius:8px;padding:20px;margin-bottom:16px}' +
    '.ss-input-row{display:flex;gap:8px;align-items:center}' +
    '.ss-input{flex:1;background:var(--card2,#080c14);border:1px solid var(--line,#1e293b);border-radius:6px;color:var(--txt,#e2e8f0);font-family:ui-monospace,monospace;font-size:.85rem;padding:10px 14px}' +
    '.ss-input:focus{border-color:var(--acc);outline:none}' +
    '.ss-btn{padding:10px 20px;border:none;border-radius:4px;background:var(--acc,#2563eb);color:#fff;cursor:pointer;font-size:.78rem;font-weight:600;font-family:inherit;transition:all .15s}' +
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
    '.ss-src{display:inline-block;padding:1px 6px;border-radius:3px;font-size:.63rem;font-family:ui-monospace,monospace;background:rgba(37,99,235,.1);color:var(--acc)}' +
    '.ss-filters{display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap}' +
    '.ss-filter{padding:4px 10px;border:1px solid var(--line);border-radius:4px;background:transparent;color:var(--mut);cursor:pointer;font-size:.7rem;font-family:inherit;transition:all .15s}' +
    '.ss-filter:hover{border-color:var(--acc);color:var(--acc)}' +
    '.ss-filter.active{background:var(--acc);color:#fff;border-color:var(--acc)}' +
    '.ss-empty{text-align:center;padding:40px;color:var(--mut);font-size:.85rem}' +
    '.ss-note{font-size:.7rem;color:var(--mut);margin-top:10px;line-height:1.5}' +
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
      '<div class="ss-header"><h1 class="ss-title">Subdomain Scanner</h1><p class="ss-sub">Real passive + active enumeration: crt.sh certificate transparency and live DNS-over-HTTPS resolution.</p></div>' +
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
      '<div style="margin-bottom:10px;font-size:.78rem;color:var(--mut)">Enter a target domain. Queries public certificate-transparency logs and resolves candidates over DNS — use only on domains you are authorized to assess.</div>' +
      '<div class="ss-input-row">' +
      '<input class="ss-input" id="ss-domain" placeholder="example.com" value="' + esc(state.domain) + '">' +
      '<button class="ss-btn" id="ss-scan"' + (state.scanning ? ' disabled' : '') + '>' + (state.scanning ? 'Scanning…' : 'Start Scan') + '</button></div>';
    if (state.scanning) {
      h += '<div class="ss-progress"><div class="ss-progress-fill" style="width:' + state.progress + '%"></div></div>' +
        '<div style="font-size:.72rem;color:var(--mut);text-align:center">' + esc(state.progressLabel) + '</div>';
    }
    if (state.error) h += '<div class="ss-note" style="color:#dc2626">' + esc(state.error) + '</div>';
    h += '</div>';

    if (state.results.length) {
      var live = state.results.filter(function(r) { return r.resolves; }).length;
      var uniqueIPs = new Set(state.results.filter(function(r){ return r.ip; }).map(function(r) { return r.ip; })).size;
      var wild = state.results.filter(function(r){ return r.wildcard; }).length;
      h += '<div class="ss-stat-grid">' +
        '<div class="ss-stat"><div class="ss-stat-val">' + state.results.length + '</div><div class="ss-stat-lbl">Discovered</div></div>' +
        '<div class="ss-stat"><div class="ss-stat-val" style="color:#16a34a">' + live + '</div><div class="ss-stat-lbl">Resolving</div></div>' +
        '<div class="ss-stat"><div class="ss-stat-val">' + uniqueIPs + '</div><div class="ss-stat-lbl">Unique IPs</div></div>' +
        '<div class="ss-stat"><div class="ss-stat-val">' + wild + '</div><div class="ss-stat-lbl">Wildcards</div></div>' +
        '</div>';
      if (!state.crtOk) h += '<div class="ss-note">Note: crt.sh was unreachable or CORS-blocked from this network — results are from live DNS resolution of the wordlist only. Passive CT discovery works best via the Darknode CLI (<code>darknode subs</code>).</div>';
    }
    return h;
  }

  function getFiltered() {
    var f = state.results;
    if (state.filter === 'resolving') f = f.filter(function(r) { return r.resolves; });
    else if (state.filter === 'unresolved') f = f.filter(function(r) { return !r.resolves; });
    else if (state.filter === 'wildcard') f = f.filter(function(r) { return r.wildcard; });
    if (state.sortBy === 'ip') f = f.slice().sort(function(a, b) { return (a.ip || '').localeCompare(b.ip || ''); });
    else if (state.sortBy === 'resolves') f = f.slice().sort(function(a, b) { return (b.resolves ? 1 : 0) - (a.resolves ? 1 : 0); });
    return f;
  }

  function renderResults() {
    if (!state.results.length) return '<div class="ss-empty">No results yet. Run a scan first.</div>';
    var filtered = getFiltered();
    var h = '<div class="ss-filters">' +
      ['all', 'resolving', 'unresolved', 'wildcard'].map(function(f) {
        var labels = { all: 'All', resolving: 'Resolving', unresolved: 'No A record', wildcard: 'Wildcards' };
        return '<button class="ss-filter' + (state.filter === f ? ' active' : '') + '" data-filter="' + f + '">' + labels[f] + '</button>';
      }).join('') + '</div>';

    h += '<div class="ss-panel" style="overflow-x:auto"><table class="ss-table"><thead><tr>' +
      '<th data-sort="name">Subdomain</th><th data-sort="ip">IP (A record)</th><th data-sort="resolves">DNS</th><th>Source</th></tr></thead><tbody>';
    filtered.forEach(function(r) {
      var color = r.resolves ? '#16a34a' : '#64748b';
      h += '<tr><td style="font-family:ui-monospace,monospace;font-weight:600">' + esc(r.subdomain) + (r.wildcard ? ' <span style="color:#f97316;font-size:.6rem">WILDCARD</span>' : '') + '</td>' +
        '<td style="font-family:ui-monospace,monospace">' + (r.ip ? esc(r.ip) : '<span style="color:var(--mut)">—</span>') + '</td>' +
        '<td><span class="ss-badge" style="background:' + color + '22;color:' + color + '">' + (r.resolves ? 'LIVE' : 'NO A') + '</span></td>' +
        '<td><span class="ss-src">' + esc(r.source) + '</span></td></tr>';
    });
    h += '</tbody></table></div>';
    h += '<div style="display:flex;gap:8px"><button class="ss-btn-ghost ss-btn" id="ss-export">Copy Results</button></div>';
    return h;
  }

  function renderTree() {
    if (!state.results.length) return '<div class="ss-empty">No results to visualize.</div>';
    var byIP = {};
    state.results.forEach(function(r) {
      var key = r.ip || '(unresolved)';
      if (!byIP[key]) byIP[key] = [];
      byIP[key].push(r);
    });
    var h = '<div class="ss-panel"><div class="ss-tree">';
    h += '<div class="ss-tree-root">' + esc(state.domain) + '</div>';
    Object.keys(byIP).forEach(function(ip) {
      h += '<div class="ss-tree-node">';
      h += '<div style="font-weight:600;font-size:.78rem;margin-bottom:4px;color:var(--mut)">' + esc(ip) + ' (' + byIP[ip].length + ' hosts)</div>';
      byIP[ip].forEach(function(r) {
        var color = r.resolves ? '#16a34a' : '#64748b';
        h += '<div class="ss-tree-sub"><div class="ss-tree-dot" style="background:' + color + '"></div><span>' + esc(r.subdomain) + '</span></div>';
      });
      h += '</div>';
    });
    h += '</div></div>';
    return h;
  }

  function startScan() {
    var el = container.querySelector('#ss-domain');
    if (!el || !el.value.trim()) return;
    // Accept a bare domain; strip scheme/path if pasted.
    var dom = el.value.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^\*?\.?/, '');
    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(dom)) { state.error = 'Enter a valid domain, e.g. example.com'; render(); return; }
    state.domain = dom;
    state.scanning = true;
    state.progress = 0;
    state.progressLabel = 'Starting…';
    state.error = '';
    state.results = [];
    render();
    realScan(dom, function (pct, label) {
      state.progress = pct; state.progressLabel = label;
      if (state.scanning) {
        var fill = container.querySelector('.ss-progress-fill');
        var lbl = fill && fill.parentElement ? fill.parentElement.nextElementSibling : null;
        if (fill) { fill.style.width = pct + '%'; if (lbl) lbl.textContent = label; }
      }
    }).then(function (out) {
      state.scanning = false;
      state.results = out.results;
      state.crtOk = out.crtOk;
      if (!out.results.length) state.error = 'No subdomains found that resolve, and no certificate-transparency records returned.';
      state.tab = out.results.length ? 'results' : 'scan';
      render();
    }).catch(function (e) {
      state.scanning = false;
      state.error = 'Scan failed: ' + (e && e.message ? e.message : 'network error');
      render();
    });
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
      var lines = state.results.map(function(r) { return r.subdomain + ',' + (r.ip || '') + ',' + (r.resolves ? 'LIVE' : 'NO_A') + ',' + r.source; });
      lines.unshift('Subdomain,IP,DNS,Source');
      if (navigator.clipboard) navigator.clipboard.writeText(lines.join('\n'));
      exportBtn.textContent = 'Copied!';
      setTimeout(function() { exportBtn.textContent = 'Copy Results'; }, 1500);
    };
  }

  render();
}
