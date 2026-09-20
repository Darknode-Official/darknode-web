// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Subdomain Enumerator — CT log search + DNS brute force, all browser-native

var esc = function(s) { return String(s != null ? s : '').replace(/[&<>"']/g, function(c) {
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); };

var _subWordlist = [
  'www','mail','ftp','admin','api','dev','staging','test','beta','app',
  'blog','shop','store','cdn','assets','static','media','img','images',
  'portal','vpn','remote','webmail','owa','autodiscover','cpanel','whm',
  'ns1','ns2','dns','dns1','dns2','mx','smtp','pop','imap','exchange',
  'cloud','auth','sso','login','id','accounts','secure','gateway',
  'dashboard','panel','manage','monitor','status','health','docs',
  'wiki','support','help','helpdesk','service','services','internal',
  'intranet','extranet','demo','sandbox','uat','qa','pre','preprod',
  'prod','production','stage','release','backup','bak','old','legacy',
  'new','v2','v3','mobile','m','wap','git','gitlab','github','bitbucket',
  'jenkins','ci','cd','build','deploy','docker','k8s','kubernetes',
  'grafana','kibana','elastic','prometheus','nagios','zabbix','splunk',
  'db','database','mysql','postgres','redis','mongo','sql','mssql',
  'ftp2','sftp','ssh','proxy','cache','edge','lb','load','node',
  'web','web1','web2','app1','app2','server','srv','host','vps',
  'crm','erp','hr','jira','confluence','slack','teams','zoom',
  'analytics','tracking','ads','marketing','newsletter','survey'
];

window.renderSubdomainEnum = function(container) {
  var h = '';
  h += '<div style="background:#0a0e14;color:#c8d6e5;font-family:\'Courier New\',monospace;padding:20px;min-height:600px;">';
  h += '<h2 style="color:#00ddff;font-size:18px;letter-spacing:2px;margin:0 0 4px;">SUBDOMAIN ENUMERATOR</h2>';
  h += '<div style="color:#4a6a8a;font-size:11px;margin-bottom:20px;">Certificate Transparency + DNS brute force — all in the browser</div>';

  h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:16px;margin-bottom:16px;">';
  h += '<div style="display:flex;gap:8px;margin-bottom:8px;">';
  h += '<input id="sub-domain" style="flex:1;background:#080c14;border:1px solid #1a2a44;border-radius:4px;color:#c8d6e5;font-family:monospace;font-size:12px;padding:8px 12px;" placeholder="example.com">';
  h += '<button onclick="_subEnumCT()" style="background:#00aaff22;color:#00aaff;border:1px solid #00aaff44;padding:8px 14px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:4px;">CT SEARCH</button>';
  h += '<button onclick="_subEnumBrute()" style="background:#ff664422;color:#ff6644;border:1px solid #ff664444;padding:8px 14px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:4px;">BRUTE FORCE</button>';
  h += '<button onclick="_subEnumBoth()" style="background:#00ff8822;color:#00ff88;border:1px solid #00ff8844;padding:8px 14px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:4px;">FULL ENUM</button>';
  h += '</div>';
  h += '<div style="color:#3a5a7a;font-size:9px;">CT Search: crt.sh certificate transparency. Brute Force: ' + _subWordlist.length + ' common subdomains via Google DoH.</div>';
  h += '</div>';

  h += '<div id="sub-progress" style="display:none;margin-bottom:12px;"></div>';
  h += '<div id="sub-stats" style="display:none;margin-bottom:12px;"></div>';
  h += '<div id="sub-results"></div>';
  h += '</div>';
  container.innerHTML = h;

  document.getElementById('sub-domain').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') _subEnumBoth();
  });
};

var _subFound = {};
var _subScanning = false;

function _subClean(domain) {
  return domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^\*\./, '');
}

function _subUpdateProgress(msg, pct) {
  var el = document.getElementById('sub-progress');
  if (!el) return;
  el.style.display = 'block';
  el.innerHTML = '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:10px 14px;">' +
    '<div style="display:flex;justify-content:space-between;margin-bottom:4px;">' +
    '<span style="color:#ffaa00;font-size:10px;">' + esc(msg) + '</span>' +
    '<span style="color:#00aaff;font-size:10px;">' + Math.round(pct) + '%</span></div>' +
    '<div style="background:#1a2a44;border-radius:2px;height:4px;overflow:hidden;">' +
    '<div style="background:linear-gradient(90deg,#00aaff,#00ddff);height:100%;width:' + Math.round(pct) + '%;transition:width 0.2s;border-radius:2px;"></div></div></div>';
}

function _subRenderResults() {
  var el = document.getElementById('sub-results');
  var statsEl = document.getElementById('sub-stats');
  if (!el) return;

  var subs = Object.keys(_subFound).sort();
  var live = subs.filter(function(s) { return _subFound[s].live; });

  if (statsEl) {
    statsEl.style.display = 'block';
    statsEl.innerHTML = '<div style="display:flex;gap:12px;">' +
      '<div style="background:#0c1020;border:1px solid #00aaff33;border-radius:6px;padding:8px 14px;text-align:center;flex:1;">' +
      '<div style="color:#00aaff;font-size:22px;font-weight:bold;">' + subs.length + '</div><div style="color:#3a5a7a;font-size:9px;">DISCOVERED</div></div>' +
      '<div style="background:#0c1020;border:1px solid #00ff8833;border-radius:6px;padding:8px 14px;text-align:center;flex:1;">' +
      '<div style="color:#00ff88;font-size:22px;font-weight:bold;">' + live.length + '</div><div style="color:#3a5a7a;font-size:9px;">LIVE (DNS)</div></div>' +
      '<div style="background:#0c1020;border:1px solid #ff444433;border-radius:6px;padding:8px 14px;text-align:center;flex:1;">' +
      '<div style="color:#ff4444;font-size:22px;font-weight:bold;">' + (subs.length - live.length) + '</div><div style="color:#3a5a7a;font-size:9px;">DEAD</div></div>' +
      '<div style="background:#0c1020;border:1px solid #ffaa0033;border-radius:6px;padding:8px 14px;text-align:center;">' +
      '<button onclick="_subCopyAll()" style="background:#ffaa0022;color:#ffaa00;border:1px solid #ffaa0044;padding:4px 12px;font-family:monospace;font-size:10px;cursor:pointer;border-radius:3px;">EXPORT</button></div></div>';
  }

  if (subs.length === 0) { el.innerHTML = '<div style="color:#4a6a8a;font-size:11px;text-align:center;">No subdomains found yet.</div>'; return; }

  var h = '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:14px;">';
  h += '<table style="width:100%;border-collapse:collapse;font-size:10px;">';
  h += '<thead><tr style="border-bottom:2px solid #1a2a44;">';
  h += '<th style="text-align:left;padding:6px;color:#00aaff;">SUBDOMAIN</th>';
  h += '<th style="text-align:left;padding:6px;color:#00aaff;">IP</th>';
  h += '<th style="text-align:left;padding:6px;color:#00aaff;">STATUS</th>';
  h += '<th style="text-align:left;padding:6px;color:#00aaff;">SOURCE</th>';
  h += '</tr></thead><tbody>';

  for (var i = 0; i < subs.length; i++) {
    var sub = subs[i];
    var data = _subFound[sub];
    var statusColor = data.live ? '#00ff88' : '#ff4444';
    var statusText = data.live ? 'LIVE' : 'DEAD';
    h += '<tr style="border-bottom:1px solid #0d1525;">';
    h += '<td style="padding:5px 6px;color:#c8d6e5;font-weight:bold;">' + esc(sub) + '</td>';
    h += '<td style="padding:5px 6px;color:#00aaff;">' + esc(data.ip || '--') + '</td>';
    h += '<td style="padding:5px 6px;"><span style="color:' + statusColor + ';font-size:9px;padding:1px 6px;background:' + statusColor + '15;border:1px solid ' + statusColor + '33;border-radius:2px;">' + statusText + '</span></td>';
    h += '<td style="padding:5px 6px;color:#4a6a8a;">' + esc(data.source) + '</td>';
    h += '</tr>';
  }
  h += '</tbody></table></div>';
  el.innerHTML = h;
}

window._subCopyAll = function() {
  var subs = Object.keys(_subFound).sort();
  var text = subs.join('\n');
  navigator.clipboard.writeText(text).then(function() { alert('Copied ' + subs.length + ' subdomains!'); });
};

window._subEnumCT = function() {
  var domain = _subClean((document.getElementById('sub-domain') || {}).value);
  if (!domain) return;
  _subFound = {};
  _subUpdateProgress('Searching crt.sh for ' + domain + '...', 10);

  fetch('https://crt.sh/?q=%25.' + encodeURIComponent(domain) + '&output=json')
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (!Array.isArray(data)) { _subUpdateProgress('No results from crt.sh', 100); _subRenderResults(); return; }
      var seen = {};
      for (var i = 0; i < data.length; i++) {
        var names = (data[i].name_value || '').split('\n');
        for (var n = 0; n < names.length; n++) {
          var name = names[n].trim().toLowerCase().replace(/^\*\./, '');
          if (name && name.indexOf(domain) !== -1 && !seen[name]) {
            seen[name] = true;
            _subFound[name] = { ip: null, live: false, source: 'CT' };
          }
        }
      }
      _subUpdateProgress('Found ' + Object.keys(_subFound).length + ' from CT. Verifying DNS...', 50);
      _subVerifyDNS(Object.keys(_subFound), domain);
    })
    .catch(function(err) {
      _subUpdateProgress('crt.sh error: ' + String(err.message || err), 100);
    });
};

window._subEnumBrute = function() {
  var domain = _subClean((document.getElementById('sub-domain') || {}).value);
  if (!domain) return;
  _subFound = {};
  _subBruteForce(domain);
};

window._subEnumBoth = function() {
  var domain = _subClean((document.getElementById('sub-domain') || {}).value);
  if (!domain) return;
  _subFound = {};
  _subUpdateProgress('Phase 1: CT search on ' + domain + '...', 5);

  fetch('https://crt.sh/?q=%25.' + encodeURIComponent(domain) + '&output=json')
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (Array.isArray(data)) {
        var seen = {};
        for (var i = 0; i < data.length; i++) {
          var names = (data[i].name_value || '').split('\n');
          for (var n = 0; n < names.length; n++) {
            var name = names[n].trim().toLowerCase().replace(/^\*\./, '');
            if (name && name.indexOf(domain) !== -1 && !seen[name]) {
              seen[name] = true;
              _subFound[name] = { ip: null, live: false, source: 'CT' };
            }
          }
        }
      }
      _subUpdateProgress('CT: ' + Object.keys(_subFound).length + ' found. Phase 2: Brute force...', 30);
      _subBruteForce(domain);
    })
    .catch(function() {
      _subUpdateProgress('CT failed. Starting brute force...', 20);
      _subBruteForce(domain);
    });
};

function _subBruteForce(domain) {
  var total = _subWordlist.length;
  var done = 0;
  var batch = 10;

  function processBatch(start) {
    var promises = [];
    for (var i = start; i < Math.min(start + batch, total); i++) {
      (function(word) {
        var sub = word + '.' + domain;
        promises.push(
          fetch('https://dns.google/resolve?name=' + encodeURIComponent(sub) + '&type=A')
            .then(function(r) { return r.json(); })
            .then(function(data) {
              if (data.Answer && data.Answer.length > 0) {
                var ip = '';
                for (var a = 0; a < data.Answer.length; a++) { if (data.Answer[a].type === 1) { ip = data.Answer[a].data; break; } }
                if (!_subFound[sub]) _subFound[sub] = { ip: ip, live: true, source: 'BRUTE' };
                else { _subFound[sub].ip = ip; _subFound[sub].live = true; }
              }
            })
            .catch(function() {})
        );
      })(_subWordlist[i]);
    }
    Promise.all(promises).then(function() {
      done += promises.length;
      var pct = 30 + (done / total) * 60;
      _subUpdateProgress('Brute force: ' + done + '/' + total + ' checked. Found: ' + Object.keys(_subFound).length, pct);
      _subRenderResults();
      if (done < total) {
        setTimeout(function() { processBatch(start + batch); }, 100);
      } else {
        _subUpdateProgress('Enumeration complete — ' + Object.keys(_subFound).length + ' subdomains', 100);
        // Verify any CT-only subs that haven't been DNS-checked
        var unverified = Object.keys(_subFound).filter(function(s) { return !_subFound[s].live && _subFound[s].source === 'CT'; });
        if (unverified.length > 0) _subVerifyDNS(unverified, domain);
      }
    });
  }

  processBatch(0);
}

function _subVerifyDNS(subs, domain) {
  var total = subs.length;
  var done = 0;
  var batch = 10;

  function processBatch(start) {
    var promises = [];
    for (var i = start; i < Math.min(start + batch, total); i++) {
      (function(sub) {
        promises.push(
          fetch('https://dns.google/resolve?name=' + encodeURIComponent(sub) + '&type=A')
            .then(function(r) { return r.json(); })
            .then(function(data) {
              if (data.Answer) {
                for (var a = 0; a < data.Answer.length; a++) {
                  if (data.Answer[a].type === 1) { _subFound[sub].ip = data.Answer[a].data; _subFound[sub].live = true; break; }
                }
              }
            })
            .catch(function() {})
        );
      })(subs[i]);
    }
    Promise.all(promises).then(function() {
      done += promises.length;
      _subRenderResults();
      if (done < total) setTimeout(function() { processBatch(start + batch); }, 100);
    });
  }

  processBatch(0);
}
