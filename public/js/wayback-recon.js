/**
 * DARKNODE — Wayback Machine Reconnaissance
 * Historical website intelligence via the Wayback CDX API
 * Copyright 2024-2026 Darknode Project. All rights reserved.
 */

export function renderWaybackRecon(container) {
  var esc = function(s) { var d = document.createElement('div'); d.textContent = s; return d.innerHTML; };
  var state = { results: [], filtered: [], loading: false, sort: { col: 'timestamp', dir: 'desc' } };

  container.innerHTML =
    '<div style="background:#0a0e14;color:#c8d6e5;font-family:\'Courier New\',monospace;padding:20px;min-height:100vh;">' +
      '<div style="text-align:center;margin-bottom:20px;border-bottom:1px solid #1a2a44;padding-bottom:14px;">' +
        '<div style="font-size:24px;font-weight:800;color:#00ddff;letter-spacing:4px;text-shadow:0 0 20px rgba(0,212,255,0.3);">WAYBACK RECON</div>' +
        '<div style="font-size:10px;color:#4a6a8a;letter-spacing:2px;">HISTORICAL WEBSITE INTELLIGENCE</div>' +
      '</div>' +
      '<div style="display:flex;gap:8px;margin-bottom:16px;">' +
        '<input id="wb-domain" placeholder="example.com" style="flex:1;background:#060a14;border:2px solid #1a3050;border-radius:6px;color:#00ddff;font-family:monospace;font-size:15px;padding:10px 14px;outline:none;" />' +
        '<button id="wb-scan" style="background:#00aaff15;border:2px solid #00aaff;color:#00ddff;font-family:monospace;font-size:13px;font-weight:bold;letter-spacing:2px;padding:10px 22px;cursor:pointer;border-radius:6px;">SCAN</button>' +
      '</div>' +
      '<div id="wb-status" style="font-size:10px;color:#4a6a8a;margin-bottom:10px;"></div>' +
      '<div id="wb-summary" style="display:none;margin-bottom:16px;"></div>' +
      '<div id="wb-filters" style="display:none;margin-bottom:12px;"></div>' +
      '<div id="wb-results"></div>' +
    '</div>';

  var domainEl = document.getElementById('wb-domain');
  var scanBtn = document.getElementById('wb-scan');
  var statusEl = document.getElementById('wb-status');
  var summaryEl = document.getElementById('wb-summary');
  var filtersEl = document.getElementById('wb-filters');
  var resultsEl = document.getElementById('wb-results');

  var INTERESTING = [
    'robots.txt','.env','.git/config','.htaccess','wp-config.php','web.config',
    '.git/HEAD','.svn/entries','.DS_Store','Thumbs.db','crossdomain.xml',
    'sitemap.xml','phpinfo.php','.well-known/security.txt','server-status',
    'elmah.axd','trace.axd','wp-login.php','administrator','wp-admin'
  ];
  var BACKUP_PATTERNS = /\.(bak|old|orig|save|swp|tmp|zip|tar|tar\.gz|tgz|rar|7z|sql|dump|db|sqlite|mdb)$/i;
  var API_DOCS = /\/(swagger|openapi|api-docs|graphql|graphiql|playground)\b/i;
  var CONFIG_FILES = /(package\.json|composer\.json|Gemfile|requirements\.txt|Pipfile|yarn\.lock|Cargo\.toml|go\.mod|pom\.xml|build\.gradle|Makefile|Dockerfile|docker-compose)/i;

  var TECH_SIGS = [
    { pattern: /wp-content|wp-includes|wp-admin|wp-login/i, tech: 'WordPress', color: '#21759b' },
    { pattern: /\/joomla|\/administrator\/index\.php/i, tech: 'Joomla', color: '#5091cd' },
    { pattern: /\/drupal|\/sites\/default/i, tech: 'Drupal', color: '#0077c0' },
    { pattern: /node_modules|package\.json|\.npmrc/i, tech: 'Node.js', color: '#339933' },
    { pattern: /\/rails|\.rb$|Gemfile/i, tech: 'Ruby/Rails', color: '#cc0000' },
    { pattern: /\.php($|\?)|phpinfo|phpmyadmin/i, tech: 'PHP', color: '#777bb3' },
    { pattern: /\.asp($|\?)|\.aspx($|\?)|web\.config/i, tech: 'ASP.NET', color: '#512bd4' },
    { pattern: /\.jsp($|\?)|\/WEB-INF|\.do($|\?)/i, tech: 'Java/JSP', color: '#f89820' },
    { pattern: /django|\/admin\/login|\.py($|\?)/i, tech: 'Python/Django', color: '#3776ab' },
    { pattern: /\/static\/|\/media\/.*\.(js|css)/i, tech: 'Static Assets CDN', color: '#4a6a8a' },
    { pattern: /angular|ng-|\.ng\./i, tech: 'Angular', color: '#dd0031' },
    { pattern: /react|\/bundle\.js|\/chunk\./i, tech: 'React', color: '#61dafb' },
    { pattern: /vue|\/app\.js.*vue/i, tech: 'Vue.js', color: '#42b883' },
    { pattern: /swagger|openapi|api-docs/i, tech: 'API Docs', color: '#85ea2d' },
    { pattern: /graphql|graphiql/i, tech: 'GraphQL', color: '#e10098' },
    { pattern: /\.cgi($|\?)/i, tech: 'CGI', color: '#aa4444' },
    { pattern: /\/xmlrpc\.php/i, tech: 'XML-RPC', color: '#ff6600' }
  ];

  function formatTs(ts) {
    if (!ts || ts.length < 14) return ts || '';
    return ts.substring(0,4) + '-' + ts.substring(4,6) + '-' + ts.substring(6,8) + ' ' + ts.substring(8,10) + ':' + ts.substring(10,12);
  }

  function classifyUrl(url) {
    var tags = [];
    var path = url.replace(/^https?:\/\/[^/]+/i, '').toLowerCase();
    INTERESTING.forEach(function(f) { if (path.indexOf(f.toLowerCase()) !== -1) tags.push('SENSITIVE'); });
    if (BACKUP_PATTERNS.test(path)) tags.push('BACKUP');
    if (API_DOCS.test(path)) tags.push('API-DOC');
    if (CONFIG_FILES.test(path)) tags.push('CONFIG');
    return tags;
  }

  function detectTech(urls) {
    var found = {};
    urls.forEach(function(u) {
      TECH_SIGS.forEach(function(sig) {
        if (sig.pattern.test(u)) found[sig.tech] = sig;
      });
    });
    return Object.keys(found).map(function(k) { return found[k]; });
  }

  function statusAnalysis(rows) {
    var groups = {};
    rows.forEach(function(r) {
      var code = r.statuscode || '???';
      if (!groups[code]) groups[code] = 0;
      groups[code]++;
    });
    return groups;
  }

  function digestAnalysis(rows) {
    var byUrl = {};
    rows.forEach(function(r) {
      if (!byUrl[r.original]) byUrl[r.original] = new Set();
      byUrl[r.original].add(r.digest);
    });
    var changed = [];
    Object.keys(byUrl).forEach(function(url) {
      if (byUrl[url].size > 1) changed.push({ url: url, versions: byUrl[url].size });
    });
    changed.sort(function(a, b) { return b.versions - a.versions; });
    return changed;
  }

  function renderSummary(rows) {
    var urls = rows.map(function(r) { return r.original; });
    var uniqueUrls = [];
    var seen = {};
    urls.forEach(function(u) { if (!seen[u]) { seen[u] = true; uniqueUrls.push(u); } });
    var timestamps = rows.map(function(r) { return r.timestamp; }).sort();
    var techs = detectTech(urls);
    var statuses = statusAnalysis(rows);
    var changed = digestAnalysis(rows);
    var interesting = rows.filter(function(r) { return classifyUrl(r.original).length > 0; });

    var h = '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px;margin-bottom:12px;">';
    var stats = [
      { label: 'SNAPSHOTS', val: rows.length, color: '#00ddff' },
      { label: 'UNIQUE URLS', val: uniqueUrls.length, color: '#00aaff' },
      { label: 'FIRST SEEN', val: formatTs(timestamps[0]), color: '#aa66ff' },
      { label: 'LAST SEEN', val: formatTs(timestamps[timestamps.length - 1]), color: '#aa66ff' },
      { label: 'INTERESTING', val: interesting.length, color: interesting.length > 0 ? '#ff6600' : '#00cc88' },
      { label: 'CONTENT CHANGES', val: changed.length, color: changed.length > 0 ? '#ffaa00' : '#00cc88' }
    ];
    stats.forEach(function(s) {
      h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:10px;text-align:center;">' +
        '<div style="color:' + s.color + ';font-size:18px;font-weight:bold;">' + esc(String(s.val)) + '</div>' +
        '<div style="color:#4a6a8a;font-size:8px;letter-spacing:1px;margin-top:2px;">' + s.label + '</div></div>';
    });
    h += '</div>';

    if (techs.length > 0) {
      h += '<div style="margin-bottom:10px;"><span style="color:#4a6a8a;font-size:9px;letter-spacing:1px;">DETECTED TECH: </span>';
      techs.forEach(function(t) {
        h += '<span style="display:inline-block;background:' + t.color + '20;color:' + t.color + ';border:1px solid ' + t.color + '44;padding:2px 8px;border-radius:3px;font-size:9px;margin:2px 3px;">' + esc(t.tech) + '</span>';
      });
      h += '</div>';
    }

    if (Object.keys(statuses).length > 0) {
      h += '<details style="margin-bottom:10px;"><summary style="color:#00aaff;font-size:11px;cursor:pointer;padding:4px 0;font-weight:bold;">STATUS CODE ANALYSIS</summary>';
      h += '<div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:6px;">';
      Object.keys(statuses).sort().forEach(function(code) {
        var c = code.charAt(0) === '2' ? '#00ff88' : code.charAt(0) === '3' ? '#ffaa00' : code === '403' ? '#ff6600' : code.charAt(0) === '4' ? '#ff4444' : code.charAt(0) === '5' ? '#ff2222' : '#4a6a8a';
        h += '<div style="background:#080c18;border:1px solid ' + c + '44;border-radius:4px;padding:6px 10px;text-align:center;">' +
          '<div style="color:' + c + ';font-size:16px;font-weight:bold;">' + statuses[code] + '</div>' +
          '<div style="color:' + c + ';font-size:10px;opacity:0.7;">' + esc(code) + '</div></div>';
      });
      h += '</div></details>';
    }

    if (changed.length > 0) {
      h += '<details style="margin-bottom:10px;"><summary style="color:#ffaa00;font-size:11px;cursor:pointer;padding:4px 0;font-weight:bold;">CONTENT CHANGES (' + changed.length + ' URLs modified)</summary>';
      h += '<div style="background:#050a10;border:1px solid #1a2a44;border-radius:4px;padding:8px;margin-top:4px;max-height:200px;overflow-y:auto;">';
      changed.slice(0, 50).forEach(function(c) {
        h += '<div style="display:flex;justify-content:space-between;font-size:10px;padding:2px 0;border-bottom:1px solid #0d1525;">' +
          '<span style="color:#8ab4d4;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:80%;">' + esc(c.url) + '</span>' +
          '<span style="color:#ffaa00;flex-shrink:0;">' + c.versions + ' ver</span></div>';
      });
      h += '</div></details>';
    }

    if (interesting.length > 0) {
      h += '<details style="margin-bottom:10px;"><summary style="color:#ff6600;font-size:11px;cursor:pointer;padding:4px 0;font-weight:bold;">INTERESTING FILES (' + interesting.length + ' hits)</summary>';
      h += '<div style="background:#050a10;border:1px solid #1a2a44;border-radius:4px;padding:8px;margin-top:4px;max-height:200px;overflow-y:auto;">';
      var seenInt = {};
      interesting.forEach(function(r) {
        if (seenInt[r.original]) return;
        seenInt[r.original] = true;
        var tags = classifyUrl(r.original);
        h += '<div style="display:flex;gap:6px;font-size:10px;padding:2px 0;border-bottom:1px solid #0d1525;align-items:center;">';
        tags.forEach(function(t) {
          var tc = t === 'SENSITIVE' ? '#ff2222' : t === 'BACKUP' ? '#ff6600' : t === 'CONFIG' ? '#ffaa00' : '#00aaff';
          h += '<span style="color:' + tc + ';font-size:8px;background:' + tc + '15;border:1px solid ' + tc + '33;padding:0 4px;border-radius:2px;flex-shrink:0;">' + t + '</span>';
        });
        h += '<span style="color:#8ab4d4;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + esc(r.original) + '</span>';
        h += '<span style="color:#3a5a7a;flex-shrink:0;">' + esc(r.statuscode) + '</span></div>';
      });
      h += '</div></details>';
    }

    summaryEl.innerHTML = h;
    summaryEl.style.display = 'block';
  }

  function renderFilters() {
    filtersEl.innerHTML =
      '<div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;">' +
        '<span style="color:#4a6a8a;font-size:9px;letter-spacing:1px;">FILTER:</span>' +
        '<button class="wb-f" data-f="all" style="background:#00aaff20;color:#00aaff;border:1px solid #00aaff44;padding:3px 10px;font-family:monospace;font-size:9px;cursor:pointer;border-radius:3px;">ALL</button>' +
        '<button class="wb-f" data-f="interesting" style="background:#ff660015;color:#ff6600;border:1px solid #ff660033;padding:3px 10px;font-family:monospace;font-size:9px;cursor:pointer;border-radius:3px;">INTERESTING</button>' +
        '<button class="wb-f" data-f="200" style="background:#00ff8815;color:#00ff88;border:1px solid #00ff8833;padding:3px 10px;font-family:monospace;font-size:9px;cursor:pointer;border-radius:3px;">200 OK</button>' +
        '<button class="wb-f" data-f="redirect" style="background:#ffaa0015;color:#ffaa00;border:1px solid #ffaa0033;padding:3px 10px;font-family:monospace;font-size:9px;cursor:pointer;border-radius:3px;">REDIRECTS</button>' +
        '<button class="wb-f" data-f="403" style="background:#ff444415;color:#ff4444;border:1px solid #ff444433;padding:3px 10px;font-family:monospace;font-size:9px;cursor:pointer;border-radius:3px;">403</button>' +
        '<input id="wb-search" placeholder="Search URLs..." style="background:#060a14;border:1px solid #1a3050;border-radius:3px;color:#8ab4d4;font-family:monospace;font-size:10px;padding:4px 8px;width:180px;outline:none;" />' +
        '<span style="flex:1;"></span>' +
        '<button id="wb-csv" style="background:#0a1a28;border:1px solid #1a3050;color:#5a8aaa;padding:4px 10px;font-family:monospace;font-size:9px;cursor:pointer;border-radius:3px;">CSV</button>' +
        '<button id="wb-json" style="background:#0a1a28;border:1px solid #1a3050;color:#5a8aaa;padding:4px 10px;font-family:monospace;font-size:9px;cursor:pointer;border-radius:3px;">JSON</button>' +
      '</div>';
    filtersEl.style.display = 'block';

    filtersEl.querySelectorAll('.wb-f').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var f = btn.getAttribute('data-f');
        if (f === 'all') state.filtered = state.results.slice();
        else if (f === 'interesting') state.filtered = state.results.filter(function(r) { return classifyUrl(r.original).length > 0; });
        else if (f === '200') state.filtered = state.results.filter(function(r) { return r.statuscode === '200'; });
        else if (f === 'redirect') state.filtered = state.results.filter(function(r) { return r.statuscode === '301' || r.statuscode === '302'; });
        else if (f === '403') state.filtered = state.results.filter(function(r) { return r.statuscode === '403'; });
        renderTable();
      });
    });

    document.getElementById('wb-search').addEventListener('input', function(e) {
      var q = e.target.value.toLowerCase();
      if (!q) { state.filtered = state.results.slice(); renderTable(); return; }
      state.filtered = state.results.filter(function(r) { return r.original.toLowerCase().indexOf(q) !== -1; });
      renderTable();
    });

    document.getElementById('wb-csv').addEventListener('click', function() { exportData('csv'); });
    document.getElementById('wb-json').addEventListener('click', function() { exportData('json'); });
  }

  function renderTable() {
    var rows = state.filtered;
    var h = '<div style="font-size:9px;color:#3a5a7a;margin-bottom:4px;">' + rows.length + ' results</div>';
    h += '<div style="overflow-x:auto;"><table style="width:100%;border-collapse:collapse;font-size:10px;">';
    h += '<thead><tr>';
    var cols = [
      { key: 'original', label: 'URL' },
      { key: 'timestamp', label: 'CAPTURED' },
      { key: 'statuscode', label: 'STATUS' },
      { key: 'mimetype', label: 'TYPE' },
      { key: 'digest', label: 'HASH' }
    ];
    cols.forEach(function(c) {
      var arrow = state.sort.col === c.key ? (state.sort.dir === 'asc' ? ' ▲' : ' ▼') : '';
      h += '<th data-col="' + c.key + '" style="text-align:left;padding:6px;color:#4a7a9a;font-size:9px;letter-spacing:1px;border-bottom:2px solid #1a2a44;cursor:pointer;white-space:nowrap;user-select:none;">' + c.label + arrow + '</th>';
    });
    h += '<th style="padding:6px;color:#4a7a9a;font-size:9px;border-bottom:2px solid #1a2a44;">TAGS</th></tr></thead><tbody>';

    rows.slice(0, 500).forEach(function(r) {
      var tags = classifyUrl(r.original);
      var sc = r.statuscode;
      var sColor = sc === '200' ? '#00ff88' : sc === '301' || sc === '302' ? '#ffaa00' : sc === '403' ? '#ff6600' : sc >= '400' ? '#ff4444' : '#4a6a8a';
      h += '<tr style="border-bottom:1px solid #0d1525;">';
      h += '<td style="padding:4px 6px;color:#8ab4d4;max-width:350px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + esc(r.original) + '">' + esc(r.original) + '</td>';
      h += '<td style="padding:4px 6px;color:#aa88cc;white-space:nowrap;">' + formatTs(r.timestamp) + '</td>';
      h += '<td style="padding:4px 6px;color:' + sColor + ';font-weight:bold;">' + esc(sc) + '</td>';
      h += '<td style="padding:4px 6px;color:#4a6a8a;">' + esc(r.mimetype || '') + '</td>';
      h += '<td style="padding:4px 6px;color:#3a5a7a;font-size:9px;">' + esc((r.digest || '').substring(0, 12)) + '</td>';
      h += '<td style="padding:4px 6px;">';
      tags.forEach(function(t) {
        var tc = t === 'SENSITIVE' ? '#ff2222' : t === 'BACKUP' ? '#ff6600' : t === 'CONFIG' ? '#ffaa00' : '#00aaff';
        h += '<span style="color:' + tc + ';font-size:7px;background:' + tc + '15;border:1px solid ' + tc + '33;padding:0 3px;border-radius:2px;margin-right:2px;">' + t + '</span>';
      });
      h += '</td></tr>';
    });
    h += '</tbody></table></div>';
    if (rows.length > 500) h += '<div style="color:#4a6a8a;font-size:9px;text-align:center;margin-top:6px;">Showing 500 of ' + rows.length + '</div>';
    resultsEl.innerHTML = h;

    resultsEl.querySelectorAll('th[data-col]').forEach(function(th) {
      th.addEventListener('click', function() {
        var col = th.getAttribute('data-col');
        if (state.sort.col === col) state.sort.dir = state.sort.dir === 'asc' ? 'desc' : 'asc';
        else { state.sort.col = col; state.sort.dir = 'asc'; }
        state.filtered.sort(function(a, b) {
          var va = (a[col] || '').toLowerCase(), vb = (b[col] || '').toLowerCase();
          var cmp = va < vb ? -1 : va > vb ? 1 : 0;
          return state.sort.dir === 'asc' ? cmp : -cmp;
        });
        renderTable();
      });
    });
  }

  function exportData(fmt) {
    var data;
    if (fmt === 'json') {
      data = JSON.stringify(state.filtered, null, 2);
    } else {
      data = 'URL,Timestamp,Status,MimeType,Digest,Tags\n';
      state.filtered.forEach(function(r) {
        var tags = classifyUrl(r.original).join(';');
        data += '"' + r.original.replace(/"/g, '""') + '",' + formatTs(r.timestamp) + ',' + r.statuscode + ',' + (r.mimetype || '') + ',' + (r.digest || '') + ',' + tags + '\n';
      });
    }
    try {
      navigator.clipboard.writeText(data);
      statusEl.textContent = fmt.toUpperCase() + ' copied to clipboard (' + Math.round(data.length / 1024) + ' KB)';
      statusEl.style.color = '#00ff88';
    } catch (e) {
      statusEl.textContent = 'Copy failed: ' + e.message;
      statusEl.style.color = '#ff4444';
    }
  }

  async function scan() {
    var domain = domainEl.value.trim().replace(/^https?:\/\//, '').replace(/\/+$/, '');
    if (!domain) { statusEl.textContent = 'Enter a domain'; statusEl.style.color = '#ff4444'; return; }
    if (state.loading) return;
    state.loading = true;
    scanBtn.textContent = 'SCANNING...';
    scanBtn.style.borderColor = '#ffaa00';
    scanBtn.style.color = '#ffaa00';
    statusEl.textContent = 'Querying Wayback CDX API for ' + domain + '...';
    statusEl.style.color = '#ffaa00';
    summaryEl.style.display = 'none';
    filtersEl.style.display = 'none';
    resultsEl.innerHTML = '';

    try {
      var url = 'https://web.archive.org/cdx/search/cdx?url=' + encodeURIComponent(domain) + '/*&output=json&fl=timestamp,original,mimetype,statuscode,digest&collapse=urlkey&limit=500';
      var resp = await fetch(url);
      if (!resp.ok) throw new Error('CDX API returned ' + resp.status);
      var data = await resp.json();
      if (!data || data.length < 2) {
        statusEl.textContent = 'No snapshots found for ' + domain;
        statusEl.style.color = '#ff6600';
        state.loading = false;
        scanBtn.textContent = 'SCAN';
        scanBtn.style.borderColor = '#00aaff';
        scanBtn.style.color = '#00ddff';
        return;
      }

      var headers = data[0];
      var rows = data.slice(1).map(function(row) {
        var obj = {};
        headers.forEach(function(h, i) { obj[h] = row[i] || ''; });
        return obj;
      });

      state.results = rows;
      state.filtered = rows.slice();
      statusEl.textContent = rows.length + ' snapshots retrieved for ' + domain;
      statusEl.style.color = '#00ff88';

      renderSummary(rows);
      renderFilters();
      renderTable();
    } catch (e) {
      statusEl.textContent = 'Error: ' + e.message;
      statusEl.style.color = '#ff4444';
      resultsEl.innerHTML = '<div style="color:#ff4444;font-size:11px;padding:12px;background:#1a0a0a;border:1px solid #ff444433;border-radius:6px;">Scan failed: ' + esc(e.message) + '<br><span style="color:#4a6a8a;font-size:9px;">Check that web.archive.org is in the CSP connect-src directive.</span></div>';
    }

    state.loading = false;
    scanBtn.textContent = 'SCAN';
    scanBtn.style.borderColor = '#00aaff';
    scanBtn.style.color = '#00ddff';
  }

  scanBtn.addEventListener('click', scan);
  domainEl.addEventListener('keydown', function(e) { if (e.key === 'Enter') scan(); });
};
