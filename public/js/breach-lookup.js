// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved.
// Data Breach Intelligence Dashboard — searches the REAL, live Have I Been Pwned
// breach catalog (https://haveibeenpwned.com/api/v3/breaches), which is keyless.
// Nothing here is hardcoded or synthesised: company names, breach dates, pwn
// counts and exposed data classes are exactly what HIBP returns. Per-EMAIL
// account checks require a paid HIBP key and are NOT faked (see the note below).
import { dnFetchJSON, proxyConfigured } from "/js/net.js";

var esc = function(s) { return String(s != null ? s : '').replace(/[&<>"']/g, function(c) { return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); };

var HIBP_BREACHES_URL = 'https://haveibeenpwned.com/api/v3/breaches';

// Live catalog, populated by _blLoad(). Never pre-seeded with fake rows.
var BREACHES = [];

function _blFormatNum(n) {
  n = Number(n) || 0;
  if (n >= 1000000000) return (n / 1000000000).toFixed(1) + 'B';
  if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
  if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
  return String(n);
}

// Severity is DERIVED from the real pwn count (a transparent bucketing of HIBP's
// own figure), not an invented field. Labelled as "scale" in the UI.
function _blSeverity(records) {
  if (records >= 100000000) return 'critical';
  if (records >= 10000000) return 'high';
  if (records >= 1000000) return 'medium';
  return 'low';
}

// Severity hex values mirror the pro-theme token fallbacks. These are kept as
// plain hex (not var()) because the renderers concatenate alpha suffixes onto
// them (e.g. sevColor + '22'), which only works on a literal hex color.
function _blSevColor(s) {
  if (s === 'critical') return '#dc2626';
  if (s === 'high') return '#d97706';
  if (s === 'medium') return '#d97706';
  return '#16a34a';
}

// Map a raw HIBP breach record to the shape this view renders.
function _blMap(b) {
  var records = Number(b.PwnCount) || 0;
  var flags = [];
  if (b.IsVerified) flags.push('verified'); else flags.push('unverified');
  if (b.IsSensitive) flags.push('sensitive');
  if (b.IsFabricated) flags.push('fabricated');
  if (b.IsMalware) flags.push('malware');
  if (b.IsStealerLog) flags.push('stealer log');
  if (b.IsSpamList) flags.push('spam list');
  if (b.IsRetired) flags.push('retired');
  return {
    company: b.Title || b.Name || '(unnamed)',
    year: (b.BreachDate || '').slice(0, 4),
    date: b.BreachDate || '',
    added: (b.AddedDate || '').slice(0, 10),
    records: records,
    domain: b.Domain || '',
    data: Array.isArray(b.DataClasses) ? b.DataClasses : [],
    flags: flags,
    verified: !!b.IsVerified,
    severity: _blSeverity(records)
  };
}

function _blFilter(query, yearFilter, dataFilter) {
  return BREACHES.filter(function(b) {
    var q = (query || '').toLowerCase();
    if (q && b.company.toLowerCase().indexOf(q) === -1 && b.domain.toLowerCase().indexOf(q) === -1) return false;
    if (yearFilter && yearFilter !== 'all' && String(b.year) !== yearFilter) return false;
    if (dataFilter && dataFilter !== 'all' && b.data.indexOf(dataFilter) === -1) return false;
    return true;
  });
}

function _blRenderCards(breaches, container) {
  if (!container) return;
  if (breaches.length === 0) { container.innerHTML = '<div style="color:var(--mut,#7a93b8);font-family:\'Segoe UI\',system-ui,sans-serif;font-size:11px;text-align:center;padding:30px;">No breaches match your filters.</div>'; return; }

  var h = '';
  for (var i = 0; i < breaches.length; i++) {
    var b = breaches[i];
    var sevColor = _blSevColor(b.severity);
    h += '<div style="background:var(--card2,#0f1726);border:1px solid var(--line,#283a5a);border-left:3px solid ' + sevColor + ';border-radius:4px;padding:12px 16px;margin-bottom:8px;">';
    h += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;">';
    h += '<div style="font-family:\'Segoe UI\',system-ui,sans-serif;font-size:14px;color:var(--txt,#e7eefc);font-weight:bold;">' + esc(b.company) + '</div>';
    h += '<div style="display:flex;gap:8px;align-items:center;">';
    h += '<span style="font-family:\'Segoe UI\',system-ui,sans-serif;font-size:10px;color:var(--mut,#7a93b8);">' + esc(b.date || b.year) + '</span>';
    h += '<span style="background:' + sevColor + '22;color:' + sevColor + ';font-size:9px;font-family:\'Segoe UI\',system-ui,sans-serif;padding:2px 6px;border-radius:2px;border:1px solid ' + sevColor + '44;font-weight:bold;letter-spacing:1px;">' + b.severity.toUpperCase() + ' SCALE</span>';
    h += '</div></div>';
    h += '<div style="display:flex;gap:16px;font-family:\'Segoe UI\',system-ui,sans-serif;font-size:11px;margin-bottom:6px;flex-wrap:wrap;">';
    h += '<span style="color:var(--bad,#dc2626);font-weight:bold;">' + _blFormatNum(b.records) + ' accounts</span>';
    if (b.domain) h += '<span style="color:var(--mut,#7a93b8);font-family:var(--font-mono);">' + esc(b.domain) + '</span>';
    if (b.added) h += '<span style="color:var(--mut,#7a93b8);">added ' + esc(b.added) + '</span>';
    h += '</div>';
    if (b.flags.length) {
      h += '<div style="display:flex;gap:4px;flex-wrap:wrap;margin-bottom:6px;">';
      for (var f = 0; f < b.flags.length; f++) {
        var fc = b.flags[f] === 'verified' ? '#16a34a' : (b.flags[f] === 'unverified' ? '#d97706' : '#dc2626');
        h += '<span style="background:' + fc + '18;color:' + fc + ';font-size:8px;font-family:\'Segoe UI\',system-ui,sans-serif;padding:1px 5px;border-radius:2px;border:1px solid ' + fc + '33;letter-spacing:1px;">' + esc(b.flags[f].toUpperCase()) + '</span>';
      }
      h += '</div>';
    }
    if (b.data.length) {
      h += '<div style="font-family:\'Segoe UI\',system-ui,sans-serif;font-size:9px;color:var(--mut,#7a93b8);margin-bottom:4px;">Compromised data:</div>';
      h += '<div style="display:flex;gap:4px;flex-wrap:wrap;">';
      for (var d = 0; d < b.data.length; d++) {
        h += '<span style="background:var(--card,#0b1120);color:var(--txt-2,#9fb0cc);font-size:8px;font-family:\'Segoe UI\',system-ui,sans-serif;padding:1px 5px;border-radius:2px;border:1px solid var(--line,#283a5a);">' + esc(b.data[d]) + '</span>';
      }
      h += '</div>';
    }
    h += '</div>';
  }
  container.innerHTML = h;
}

function _blRenderDashboard() {
  var totalRecords = 0;
  var dataClasses = {};
  var years = {};
  var verified = 0;
  for (var i = 0; i < BREACHES.length; i++) {
    totalRecords += BREACHES[i].records;
    if (BREACHES[i].verified) verified++;
    BREACHES[i].data.forEach(function(d) { dataClasses[d] = 1; });
    if (BREACHES[i].year) years[BREACHES[i].year] = (years[BREACHES[i].year] || 0) + 1;
  }

  var h = '';
  // Stats row
  h += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(min(120px,100%),1fr));gap:10px;margin-bottom:16px;">';
  h += '<div style="background:var(--card2,#0f1726);border:1px solid var(--line,#283a5a);border-radius:6px;padding:12px;text-align:center;"><div style="color:var(--bad,#dc2626);font-size:22px;font-weight:bold;font-family:\'Segoe UI\',system-ui,sans-serif;">' + _blFormatNum(totalRecords) + '</div><div style="color:var(--mut,#7a93b8);font-size:9px;font-family:\'Segoe UI\',system-ui,sans-serif;letter-spacing:1px;">ACCOUNTS EXPOSED</div></div>';
  h += '<div style="background:var(--card2,#0f1726);border:1px solid var(--line,#283a5a);border-radius:6px;padding:12px;text-align:center;"><div style="color:var(--warn,#d97706);font-size:22px;font-weight:bold;font-family:\'Segoe UI\',system-ui,sans-serif;">' + BREACHES.length + '</div><div style="color:var(--mut,#7a93b8);font-size:9px;font-family:\'Segoe UI\',system-ui,sans-serif;letter-spacing:1px;">BREACHES IN CATALOG</div></div>';
  h += '<div style="background:var(--card2,#0f1726);border:1px solid var(--line,#283a5a);border-radius:6px;padding:12px;text-align:center;"><div style="color:var(--acc,#2563eb);font-size:22px;font-weight:bold;font-family:\'Segoe UI\',system-ui,sans-serif;">' + Object.keys(dataClasses).length + '</div><div style="color:var(--mut,#7a93b8);font-size:9px;font-family:\'Segoe UI\',system-ui,sans-serif;letter-spacing:1px;">DATA CLASSES</div></div>';
  h += '<div style="background:var(--card2,#0f1726);border:1px solid var(--line,#283a5a);border-radius:6px;padding:12px;text-align:center;"><div style="color:var(--ok,#16a34a);font-size:22px;font-weight:bold;font-family:\'Segoe UI\',system-ui,sans-serif;">' + verified + '</div><div style="color:var(--mut,#7a93b8);font-size:9px;font-family:\'Segoe UI\',system-ui,sans-serif;letter-spacing:1px;">VERIFIED</div></div>';
  h += '</div>';

  // Timeline
  var sortedYears = Object.keys(years).sort();
  if (sortedYears.length) {
    h += '<div style="margin-bottom:16px;">';
    h += '<div style="color:var(--acc,#2563eb);font-size:10px;font-family:\'Segoe UI\',system-ui,sans-serif;letter-spacing:2px;margin-bottom:6px;">BREACHES BY YEAR</div>';
    h += '<div style="display:flex;gap:3px;align-items:flex-end;height:60px;padding:0 4px;background:var(--card,#0b1120);border:1px solid var(--line,#283a5a);border-radius:6px;overflow-x:auto;">';
    var maxY = Math.max.apply(null, Object.keys(years).map(function(k){ return years[k]; }));
    for (var yi = 0; yi < sortedYears.length; yi++) {
      var yr = sortedYears[yi];
      var barH = Math.max(4, (years[yr] / maxY) * 50);
      h += '<div style="display:flex;flex-direction:column;align-items:center;min-width:26px;" title="' + esc(yr) + ': ' + years[yr] + ' breaches">';
      h += '<div style="width:18px;height:' + barH + 'px;background:linear-gradient(180deg,var(--bad,#dc2626),var(--warn,#d97706));border-radius:2px 2px 0 0;"></div>';
      h += '<div style="font-size:7px;color:var(--mut,#7a93b8);font-family:\'Segoe UI\',system-ui,sans-serif;margin-top:2px;">' + esc(yr) + '</div>';
      h += '</div>';
    }
    h += '</div></div>';
  }

  // Filters
  h += '<div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;align-items:center;">';
  h += '<input id="bl-search" type="text" placeholder="Search company or domain..." oninput="_blDoFilter()" style="flex:1;min-width:200px;background:var(--card2,#0f1726);border:1px solid var(--line,#283a5a);border-radius:6px;padding:8px 12px;color:var(--txt,#e7eefc);font-family:\'Segoe UI\',system-ui,sans-serif;font-size:12px;outline:none;">';
  h += '<select id="bl-year" onchange="_blDoFilter()" style="background:var(--card2,#0f1726);border:1px solid var(--line,#283a5a);border-radius:6px;padding:8px;color:var(--txt,#e7eefc);font-family:\'Segoe UI\',system-ui,sans-serif;font-size:11px;">';
  h += '<option value="all">All Years</option>';
  for (var y = sortedYears.length - 1; y >= 0; y--) { h += '<option value="' + esc(sortedYears[y]) + '">' + esc(sortedYears[y]) + '</option>'; }
  h += '</select>';
  h += '<select id="bl-data" onchange="_blDoFilter()" style="background:var(--card2,#0f1726);border:1px solid var(--line,#283a5a);border-radius:6px;padding:8px;color:var(--txt,#e7eefc);font-family:\'Segoe UI\',system-ui,sans-serif;font-size:11px;">';
  h += '<option value="all">All Data Types</option>';
  Object.keys(dataClasses).sort().forEach(function(d) { h += '<option value="' + esc(d) + '">' + esc(d) + '</option>'; });
  h += '</select>';
  h += '</div>';

  // Breach cards
  h += '<div id="bl-cards" style="max-height:600px;overflow-y:auto;scrollbar-width:thin;scrollbar-color:var(--line,#283a5a) transparent;"></div>';

  var mount = document.getElementById('bl-body');
  if (mount) mount.innerHTML = h;

  var sorted = BREACHES.slice().sort(function(a, b) { return b.records - a.records; });
  _blRenderCards(sorted, document.getElementById('bl-cards'));
}

export function renderBreachLookup(container) {
  var h = '';
  h += '<div style="padding:20px 24px;">';
  h += '<h2 style="margin:0 0 4px;font-size:20px;color:var(--acc,#2563eb);font-family:\'Segoe UI\',system-ui,sans-serif;letter-spacing:2px;text-transform:uppercase;">BREACH INTELLIGENCE</h2>';
  h += '<div style="color:var(--txt-2,#9fb0cc);font-size:11px;font-family:\'Segoe UI\',system-ui,sans-serif;margin-bottom:8px;">Live catalog from Have I Been Pwned (haveibeenpwned.com) &mdash; searchable by company and domain.</div>';
  h += '<div style="background:var(--card2,#0f1726);border:1px solid var(--line,#283a5a);border-radius:6px;padding:8px 12px;margin-bottom:16px;color:var(--txt-2,#9fb0cc);font-family:\'Segoe UI\',system-ui,sans-serif;font-size:10px;line-height:1.6;">';
  h += 'This searches the public breach <b>catalog</b> (which sites were breached, when, and what data was exposed). Checking whether a <b>specific email address</b> appears in these breaches requires a paid HIBP API key and is not performed here &mdash; no per-email results are simulated.';
  h += '</div>';
  h += '<div id="bl-body"><div style="color:var(--mut,#7a93b8);font-family:\'Segoe UI\',system-ui,sans-serif;font-size:11px;text-align:center;padding:40px;">Loading live breach catalog&hellip;</div></div>';
  h += '</div>';
  container.innerHTML = h;
  _blLoad();
}

async function _blLoad() {
  var body = document.getElementById('bl-body');
  if (!proxyConfigured()) {
    if (body) body.innerHTML = '<div style="background:rgba(220,38,38,0.08);border:1px solid rgba(220,38,38,0.3);border-radius:6px;padding:16px;text-align:center;font-family:\'Segoe UI\',system-ui,sans-serif;"><div style="color:var(--bad,#dc2626);font-size:12px;font-weight:bold;margin-bottom:4px;">LIVE FETCH UNAVAILABLE</div><div style="color:var(--txt-2,#9fb0cc);font-size:10px;">The Darknode proxy is not configured, so the HIBP breach catalog cannot be loaded. No placeholder data is shown.</div></div>';
    return;
  }
  try {
    var raw = await dnFetchJSON(HIBP_BREACHES_URL, { timeout: 25000 });
    if (!Array.isArray(raw)) throw new Error('HIBP returned an unexpected response.');
    BREACHES = raw.map(_blMap).filter(function(b) { return b.company; });
    _blRenderDashboard();
  } catch (err) {
    if (body) body.innerHTML = '<div style="background:rgba(220,38,38,0.08);border:1px solid rgba(220,38,38,0.3);border-radius:6px;padding:16px;text-align:center;font-family:\'Segoe UI\',system-ui,sans-serif;">' +
      '<div style="color:var(--bad,#dc2626);font-size:12px;font-weight:bold;margin-bottom:4px;">COULD NOT LOAD BREACH CATALOG</div>' +
      '<div style="color:var(--txt-2,#9fb0cc);font-size:10px;">' + esc(String((err && err.message) || err)) + '</div>' +
      '<div style="color:var(--mut,#7a93b8);font-size:9px;margin-top:6px;">Source: haveibeenpwned.com/api/v3/breaches. No cached or synthetic data is substituted.</div>' +
      '</div>';
  }
}

window._blDoFilter = function() {
  var q = (document.getElementById('bl-search') || {}).value || '';
  var yr = (document.getElementById('bl-year') || {}).value || 'all';
  var dt = (document.getElementById('bl-data') || {}).value || 'all';
  var filtered = _blFilter(q, yr, dt).sort(function(a, b) { return b.records - a.records; });
  _blRenderCards(filtered, document.getElementById('bl-cards'));
};
