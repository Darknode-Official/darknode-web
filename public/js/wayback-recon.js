/**
 * DARKNODE — Wayback Machine Reconnaissance
 * Historical website intelligence via the Wayback CDX API
 * Copyright 2024-2026 Darknode Project. All rights reserved.
 */

var _WB_CSS = '<style>' +
  '.wb-domain{flex:1}' +
  '.wb-status{font-size:12px;color:var(--mut,#7a93b8);margin-bottom:10px}' +
  '.wb-stat{background:var(--card2,#0f1726);border:1px solid var(--line,#283a5a);border-radius:6px;padding:10px;text-align:center}' +
  '.wb-stat-v{font-size:18px;font-weight:bold}' +
  '.wb-stat-l{color:var(--mut,#7a93b8);font-size:12px;margin-top:2px}' +
  '.wb-sum-lbl{color:var(--mut,#7a93b8);font-size:12px}' +
  '.wb-summary-link{font-size:12px;cursor:pointer;padding:4px 0;font-weight:bold}' +
  '.wb-panel{background:var(--card,#0b1120);border:1px solid var(--line,#283a5a);border-radius:4px;padding:8px;margin-top:4px;max-height:200px;overflow-y:auto}' +
  '.wb-row{display:flex;justify-content:space-between;font-size:12px;padding:2px 0;border-bottom:1px solid var(--line,#283a5a)}' +
  '.wb-url{color:var(--txt-2,#9fb0cc);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:var(--font-mono)}' +
  '.wb-fbtn{font-family:var(--font-mono);font-size:12px;cursor:pointer;border-radius:3px;padding:3px 10px}' +
  '.wb-search{background:var(--card2,#0f1726);border:1px solid var(--line,#283a5a);border-radius:3px;color:var(--txt-2,#9fb0cc);font-family:var(--font-mono);font-size:12px;padding:4px 8px;width:180px;outline:none}' +
  '.wb-th{text-align:left;padding:6px;color:var(--mut,#7a93b8);font-size:12px;border-bottom:2px solid var(--line,#283a5a);cursor:pointer;white-space:nowrap;user-select:none}' +
  '.wb-errbox{color:var(--bad);font-size:12px;padding:12px;background:color-mix(in srgb,var(--bad) 8%,transparent);border:1px solid color-mix(in srgb,var(--bad) 25%,transparent);border-radius:6px}' +
  '</style>';

export function renderWaybackRecon(container) {
  var esc = function(s) { var d = document.createElement('div'); d.textContent = s; return d.innerHTML; };
  var state = { results: [], filtered: [], loading: false, sort: { col: 'timestamp', dir: 'desc' } };

  container.innerHTML = _WB_CSS +
    '<div class="wb-wrap">' +
      '<div class="pg-head"><div><h1 class="pg-h1">Wayback recon</h1>' +
        '<p class="muted pg-sub">Lists archived URLs for a domain from the Internet Archive Wayback CDX API (up to 500 distinct captures) and flags sensitive paths.</p></div></div>' +
      '<div class="card" style="display:flex;gap:8px;margin-bottom:16px;">' +
        '<input id="wb-domain" placeholder="example.com" class="wb-domain" />' +
        '<button id="wb-scan" class="btn">Search archive</button>' +
      '</div>' +
      '<div id="wb-status" class="wb-status"></div>' +
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
    if (INTERESTING.some(function(f) { return path.indexOf(f.toLowerCase()) !== -1; })) tags.push('SENSITIVE'); // one tag, however many names match
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
      { label: 'Captures', val: rows.length, color: 'var(--acc,#2563eb)' },
      { label: 'Unique URLs', val: uniqueUrls.length, color: 'var(--acc,#2563eb)' },
      { label: 'First seen', val: formatTs(timestamps[0]), color: 'var(--txt)' },
      { label: 'Last seen', val: formatTs(timestamps[timestamps.length - 1]), color: 'var(--txt)' },
      { label: 'Interesting', val: interesting.length, color: interesting.length > 0 ? 'var(--warn)' : 'var(--ok)' },
      { label: 'Content changes', val: changed.length, color: changed.length > 0 ? 'var(--warn)' : 'var(--ok)' }
    ];
    stats.forEach(function(s) {
      h += '<div class="wb-stat">' +
        '<div class="wb-stat-v" style="color:' + s.color + ';">' + esc(String(s.val)) + '</div>' +
        '<div class="wb-stat-l">' + s.label + '</div></div>';
    });
    h += '</div>';

    if (techs.length > 0) {
      h += '<div style="margin-bottom:10px;"><span class="wb-sum-lbl">Tech hinted by archived paths: </span>';
      techs.forEach(function(t) {
        h += '<span style="display:inline-block;background:' + t.color + '20;color:' + t.color + ';border:1px solid ' + t.color + '44;padding:2px 8px;border-radius:3px;font-size:12px;margin:2px 3px;">' + esc(t.tech) + '</span>';
      });
      h += '</div>';
    }

    if (Object.keys(statuses).length > 0) {
      h += '<details style="margin-bottom:10px;"><summary class="wb-summary-link" style="color:var(--txt);">Status codes</summary>';
      h += '<div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:6px;">';
      Object.keys(statuses).sort().forEach(function(code) {
        var c = code.charAt(0) === '2' ? '#16a34a' : code.charAt(0) === '3' ? '#d97706' : code === '403' ? '#ea580c' : code.charAt(0) === '4' ? '#dc2626' : code.charAt(0) === '5' ? '#b91c1c' : '#64748b';
        h += '<div style="background:var(--card,#0b1120);border:1px solid ' + c + '44;border-radius:4px;padding:6px 10px;text-align:center;">' +
          '<div style="color:' + c + ';font-size:16px;font-weight:bold;">' + statuses[code] + '</div>' +
          '<div style="color:' + c + ';font-size:12px;opacity:0.7;">' + esc(code) + '</div></div>';
      });
      h += '</div></details>';
    }

    if (changed.length > 0) {
      h += '<details style="margin-bottom:10px;"><summary class="wb-summary-link" style="color:var(--txt);">Content changes (' + changed.length + ' URLs modified)</summary>';
      h += '<div class="wb-panel">';
      changed.slice(0, 50).forEach(function(c) {
        h += '<div class="wb-row">' +
          '<span class="wb-url" style="max-width:80%;">' + esc(c.url) + '</span>' +
          '<span style="color:var(--warn);flex-shrink:0;">' + c.versions + ' ver</span></div>';
      });
      h += '</div></details>';
    }

    if (interesting.length > 0) {
      h += '<details style="margin-bottom:10px;"><summary class="wb-summary-link" style="color:var(--txt);">Interesting files (' + interesting.length + ' hits)</summary>';
      h += '<div class="wb-panel">';
      var seenInt = {};
      interesting.forEach(function(r) {
        if (seenInt[r.original]) return;
        seenInt[r.original] = true;
        var tags = classifyUrl(r.original);
        h += '<div style="display:flex;gap:6px;font-size:12px;padding:2px 0;border-bottom:1px solid var(--line,#283a5a);align-items:center;">';
        tags.forEach(function(t) {
          var tc = t === 'SENSITIVE' ? '#dc2626' : t === 'BACKUP' ? '#ea580c' : t === 'CONFIG' ? '#d97706' : '#2563eb';
          h += '<span style="color:' + tc + ';font-size:12px;background:' + tc + '15;border:1px solid ' + tc + '33;padding:0 4px;border-radius:2px;flex-shrink:0;">' + t + '</span>';
        });
        h += '<span class="wb-url">' + esc(r.original) + '</span>';
        h += '<span style="color:var(--mut,#7a93b8);flex-shrink:0;">' + esc(r.statuscode) + '</span></div>';
      });
      h += '</div></details>';
    }

    summaryEl.innerHTML = h;
    summaryEl.style.display = 'block';
  }

  function renderFilters() {
    filtersEl.innerHTML =
      '<div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;">' +
        '<span class="wb-sum-lbl">Filter:</span>' +
        '<button class="wb-f btn ghost sm" data-f="all">All</button>' +
        '<button class="wb-f btn ghost sm" data-f="interesting">Interesting</button>' +
        '<button class="wb-f btn ghost sm" data-f="200">200 OK</button>' +
        '<button class="wb-f btn ghost sm" data-f="redirect">Redirects</button>' +
        '<button class="wb-f btn ghost sm" data-f="403">403</button>' +
        '<input id="wb-search" placeholder="Search URLs" class="wb-search" />' +
        '<span style="flex:1;"></span>' +
        '<button id="wb-csv" class="btn ghost sm">Copy CSV</button>' +
        '<button id="wb-json" class="btn ghost sm">Copy JSON</button>' +
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
    var h = '<div style="font-size:12px;color:var(--mut,#7a93b8);margin-bottom:4px;">' + rows.length + ' results</div>';
    h += '<div style="overflow-x:auto;"><table style="width:100%;border-collapse:collapse;font-size:12px;font-family:var(--font-mono);">';
    h += '<thead><tr>';
    var cols = [
      { key: 'original', label: 'URL' },
      { key: 'timestamp', label: 'Captured' },
      { key: 'statuscode', label: 'Status' },
      { key: 'mimetype', label: 'Type' },
      { key: 'digest', label: 'Digest' }
    ];
    cols.forEach(function(c) {
      var arrow = state.sort.col === c.key ? (state.sort.dir === 'asc' ? ' ▲' : ' ▼') : '';
      h += '<th data-col="' + c.key + '" class="wb-th">' + c.label + arrow + '</th>';
    });
    h += '<th class="wb-th" style="cursor:default;">TAGS</th></tr></thead><tbody>';

    rows.slice(0, 500).forEach(function(r) {
      var tags = classifyUrl(r.original);
      var sc = r.statuscode;
      var sColor = sc === '200' ? '#16a34a' : sc === '301' || sc === '302' ? '#d97706' : sc === '403' ? '#ea580c' : sc >= '400' ? '#dc2626' : '#64748b';
      h += '<tr style="border-bottom:1px solid var(--line,#283a5a);">';
      h += '<td style="padding:4px 6px;color:var(--txt-2,#9fb0cc);max-width:350px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + esc(r.original) + '">' + esc(r.original) + '</td>';
      h += '<td style="padding:4px 6px;color:var(--txt-2);white-space:nowrap;">' + formatTs(r.timestamp) + '</td>';
      h += '<td style="padding:4px 6px;color:' + sColor + ';font-weight:bold;">' + esc(sc) + '</td>';
      h += '<td style="padding:4px 6px;color:var(--mut,#7a93b8);">' + esc(r.mimetype || '') + '</td>';
      h += '<td style="padding:4px 6px;color:var(--mut,#7a93b8);font-size:12px;">' + esc((r.digest || '').substring(0, 12)) + '</td>';
      h += '<td style="padding:4px 6px;">';
      tags.forEach(function(t) {
        var tc = t === 'SENSITIVE' ? '#dc2626' : t === 'BACKUP' ? '#ea580c' : t === 'CONFIG' ? '#d97706' : '#2563eb';
        h += '<span style="color:' + tc + ';font-size:12px;background:' + tc + '15;border:1px solid ' + tc + '33;padding:0 3px;border-radius:2px;margin-right:2px;">' + t + '</span>';
      });
      h += '</td></tr>';
    });
    h += '</tbody></table></div>';
    if (rows.length > 500) h += '<div style="color:var(--mut,#7a93b8);font-size:12px;text-align:center;margin-top:6px;">Showing 500 of ' + rows.length + '</div>';
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
    var fail = function(e) {
      statusEl.textContent = 'Copy failed: ' + (e && e.message ? e.message : 'clipboard unavailable');
      statusEl.style.color = 'var(--bad)';
    };
    // writeText resolves or rejects later: report the copy only once it has happened
    try {
      navigator.clipboard.writeText(data).then(function() {
        statusEl.textContent = fmt.toUpperCase() + ' copied to clipboard (' + Math.round(data.length / 1024) + ' KB)';
        statusEl.style.color = 'var(--ok)';
      }, fail);
    } catch (e) { fail(e); }
  }

  async function scan() {
    var domain = domainEl.value.trim().replace(/^https?:\/\//, '').replace(/\/+$/, '');
    if (!domain) { statusEl.textContent = 'Enter a domain'; statusEl.style.color = 'var(--bad)'; return; }
    if (state.loading) return;
    state.loading = true;
    scanBtn.textContent = 'Searching...';
    scanBtn.disabled = true;
    statusEl.textContent = 'Querying Wayback CDX API for ' + domain + '...';
    statusEl.style.color = 'var(--warn)';
    summaryEl.style.display = 'none';
    filtersEl.style.display = 'none';
    resultsEl.innerHTML = '';

    try {
      var url = 'https://web.archive.org/cdx/search/cdx?url=' + encodeURIComponent(domain) + '/*&output=json&fl=timestamp,original,mimetype,statuscode,digest&collapse=digest&limit=500';
      var resp = await fetch(url);
      if (!resp.ok) throw new Error('CDX API returned ' + resp.status);
      var data = await resp.json();
      if (!data || data.length < 2) {
        statusEl.textContent = 'No snapshots found for ' + domain;
        statusEl.style.color = 'var(--warn)';
        state.loading = false;
        scanBtn.textContent = 'Search archive';
        scanBtn.disabled = false;
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
      statusEl.textContent = rows.length + ' distinct captures retrieved for ' + domain + (rows.length >= 500 ? ' (capped at 500; older or rarer URLs may be missing)' : '');
      statusEl.style.color = 'var(--ok)';

      renderSummary(rows);
      renderFilters();
      renderTable();
    } catch (e) {
      statusEl.textContent = 'Error: ' + e.message;
      statusEl.style.color = 'var(--bad)';
      resultsEl.innerHTML = '<div class="wb-errbox">Scan failed: ' + esc(e.message) + '<br><span style="color:var(--mut,#7a93b8);font-size:12px;">Check that web.archive.org is in the CSP connect-src directive.</span></div>';
    }

    state.loading = false;
    scanBtn.textContent = 'Search archive';
    scanBtn.disabled = false;
  }

  scanBtn.addEventListener('click', scan);
  domainEl.addEventListener('keydown', function(e) { if (e.key === 'Enter') scan(); });
};
