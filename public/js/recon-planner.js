import { esc } from '/js/shared.js';

const RP_TEMPLATES = {
  webapp: {
    name: 'Web Application',
    scope: 'Target: example.com (*.example.com)\nType: Web Application Pentest\nRules of Engagement: No DoS, no social engineering\nTime Window: Business hours only\nEmergency Contact: security@example.com',
    recon: [
      { tool: 'Nmap', cmd: 'nmap -sC -sV -oA webapp_scan example.com', status: 'pending', notes: '' },
      { tool: 'Subfinder', cmd: 'subfinder -d example.com -o subs.txt', status: 'pending', notes: '' },
      { tool: 'Nuclei', cmd: 'nuclei -u https://example.com -t cves/', status: 'pending', notes: '' },
      { tool: 'Ffuf', cmd: 'ffuf -u https://example.com/FUZZ -w /usr/share/wordlists/dirb/common.txt', status: 'pending', notes: '' },
      { tool: 'WhatWeb', cmd: 'whatweb -v example.com', status: 'pending', notes: '' }
    ]
  },
  network: {
    name: 'Internal Network',
    scope: 'Target: 10.0.0.0/24\nType: Internal Network Pentest\nRules of Engagement: No disruption to production services\nTime Window: After hours (22:00-06:00)\nEmergency Contact: noc@company.com',
    recon: [
      { tool: 'Nmap', cmd: 'nmap -sn 10.0.0.0/24 -oA host_discovery', status: 'pending', notes: '' },
      { tool: 'Nmap', cmd: 'nmap -sC -sV -p- -oA full_scan 10.0.0.0/24', status: 'pending', notes: '' },
      { tool: 'Enum4linux', cmd: 'enum4linux -a 10.0.0.x', status: 'pending', notes: '' },
      { tool: 'Responder', cmd: 'responder -I eth0 -A', status: 'pending', notes: '' },
      { tool: 'CrackMapExec', cmd: 'crackmapexec smb 10.0.0.0/24', status: 'pending', notes: '' }
    ]
  },
  api: {
    name: 'API Security',
    scope: 'Target: api.example.com\nType: REST API Security Assessment\nRules of Engagement: Rate limit to 10 req/s, staging environment only\nTime Window: Anytime on staging\nEmergency Contact: devops@example.com',
    recon: [
      { tool: 'Nmap', cmd: 'nmap -sV -p 80,443,8080,8443 api.example.com', status: 'pending', notes: '' },
      { tool: 'Nikto', cmd: 'nikto -h https://api.example.com', status: 'pending', notes: '' },
      { tool: 'Postman', cmd: 'Import API spec and test each endpoint', status: 'pending', notes: '' },
      { tool: 'SQLMap', cmd: 'sqlmap -u "https://api.example.com/v1/users?id=1" --batch', status: 'pending', notes: '' },
      { tool: 'JWT_Tool', cmd: 'jwt_tool <token> -M at', status: 'pending', notes: '' }
    ]
  }
};

const RP_PHASES = [
  { id: 'scope', label: 'Scope', icon: '&#9678;' },
  { id: 'recon', label: 'Recon', icon: '&#9673;' },
  { id: 'enumerate', label: 'Enumerate', icon: '&#9638;' },
  { id: 'exploit', label: 'Exploit', icon: '&#9889;' },
  { id: 'post', label: 'Post-Exploit', icon: '&#9733;' },
  { id: 'report', label: 'Report', icon: '&#9998;' }
];

export function renderReconPlanner(container) {
  var state = {
    tab: 'scope',
    scope: '',
    reconTasks: [],
    enumResults: [],
    exploits: [],
    postActions: [],
    findings: [],
    nextId: 1
  };

  var CSS = '<style>' +
    '.rp-wrap{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:var(--txt,#c8d6e5)}' +
    '.rp-header{margin-bottom:24px}' +
    '.rp-title{font-size:1.5rem;font-weight:700;margin:0 0 6px}' +
    '.rp-sub{color:var(--mut,#64748b);font-size:.85rem}' +
    '.rp-phases{display:flex;gap:2px;margin-bottom:20px;position:relative}' +
    '@media(max-width:600px){.rp-phases{overflow-x:auto;scrollbar-width:none}.rp-phase{flex:1 0 auto;min-width:64px}}' +
    '.rp-phases::before{content:"";position:absolute;top:50%;left:0;right:0;height:2px;background:var(--line,#1e293b);z-index:0}' +
    '.rp-phase{position:relative;z-index:1;flex:1;display:flex;flex-direction:column;align-items:center;gap:6px;padding:10px 4px;border:none;background:transparent;color:var(--mut,#64748b);cursor:pointer;font-size:.7rem;font-weight:600;text-transform:uppercase;letter-spacing:.04em;transition:all .15s;font-family:inherit}' +
    '.rp-phase:hover{color:var(--txt)}' +
    '.rp-phase-dot{width:32px;height:32px;border-radius:50%;border:2px solid var(--line,#1e293b);background:var(--card,#0d1117);display:flex;align-items:center;justify-content:center;font-size:.85rem;transition:all .2s}' +
    '.rp-phase.active .rp-phase-dot{background:var(--acc,#2563eb);border-color:var(--acc,#2563eb);color:#fff;box-shadow:0 0 12px rgba(37,99,235,.4)}' +
    '.rp-phase.active{color:var(--acc,#2563eb)}' +
    '.rp-phase.done .rp-phase-dot{background:#16a34a;border-color:#16a34a;color:#fff}' +
    '.rp-phase.done{color:#16a34a}' +
    '.rp-panel{background:var(--card,#0d1117);border:1px solid var(--line,#1e293b);border-radius:8px;padding:20px;margin-bottom:16px}' +
    '.rp-panel-title{font-size:.85rem;font-weight:700;margin:0 0 14px;display:flex;align-items:center;justify-content:space-between}' +
    '.rp-textarea{width:100%;min-height:180px;background:var(--card2,#080c14);border:1px solid var(--line,#1e293b);border-radius:6px;color:var(--txt,#e2e8f0);font-family:ui-monospace,monospace;font-size:.78rem;padding:14px;resize:vertical;line-height:1.6}' +
    '.rp-textarea:focus{border-color:var(--acc);outline:none}' +
    '.rp-btn{padding:7px 16px;border:none;border-radius:6px;background:var(--acc,#2563eb);color:#fff;cursor:pointer;font-size:.78rem;font-weight:600;font-family:inherit;transition:all .15s}' +
    '.rp-btn:hover{opacity:.9}' +
    '.rp-btn-sm{padding:4px 10px;font-size:.7rem}' +
    '.rp-btn-ghost{background:transparent;border:1px solid var(--line);color:var(--mut)}' +
    '.rp-btn-ghost:hover{border-color:var(--acc);color:var(--acc)}' +
    '.rp-btn-danger{background:#dc2626}' +
    '.rp-templates{display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap}' +
    '.rp-tmpl-btn{padding:6px 14px;border:1px solid var(--line,#1e293b);border-radius:6px;background:transparent;color:var(--mut);cursor:pointer;font-size:.72rem;font-family:inherit;transition:all .15s}' +
    '.rp-tmpl-btn:hover{border-color:var(--acc);color:var(--acc)}' +
    '.rp-task-list{display:flex;flex-direction:column;gap:8px}' +
    '.rp-task{background:var(--card2,#080c14);border:1px solid var(--line);border-radius:6px;padding:12px 14px;display:flex;align-items:flex-start;gap:10px}' +
    '.rp-task-status{width:10px;height:10px;border-radius:50%;margin-top:4px;flex-shrink:0;cursor:pointer;transition:all .15s}' +
    '.rp-task-status:hover{transform:scale(1.3)}' +
    '.rp-task-body{flex:1;min-width:0}' +
    '.rp-task-tool{font-weight:700;font-size:.78rem;margin-bottom:2px}' +
    '.rp-task-cmd{font-family:ui-monospace,monospace;font-size:.72rem;color:var(--acc,#2563eb);word-break:break-all;padding:4px 8px;background:rgba(37,99,235,.06);border-radius:3px;margin:4px 0}' +
    '.rp-task-notes{font-size:.72rem;color:var(--mut);margin-top:4px}' +
    '.rp-task-input{width:100%;background:transparent;border:none;border-bottom:1px solid var(--line);color:var(--txt);font-family:ui-monospace,monospace;font-size:.72rem;padding:4px 0;margin-top:4px}' +
    '.rp-task-input:focus{outline:none;border-bottom-color:var(--acc)}' +
    '.rp-add-row{display:flex;gap:8px;margin-top:12px}' +
    '.rp-add-input{flex:1;background:transparent;border:1px solid var(--line);border-radius:6px;color:var(--txt);padding:6px 10px;font-size:.75rem;font-family:inherit}' +
    '.rp-add-input:focus{outline:none;border-color:var(--acc)}' +
    '.rp-sev{display:inline-block;padding:2px 8px;border-radius:3px;font-size:.65rem;font-weight:700;text-transform:uppercase;letter-spacing:.03em}' +
    '.rp-finding{border-left:3px solid;padding:12px 14px;margin-bottom:8px;border-radius:0 6px 6px 0;background:rgba(0,0,0,.15)}' +
    '.rp-finding-title{font-weight:700;font-size:.82rem;margin-bottom:4px}' +
    '.rp-finding-desc{font-size:.75rem;color:var(--mut)}' +
    '.rp-stat-row{display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap}' +
    '.rp-stat{flex:1;min-width:120px;background:var(--card2,#080c14);border:1px solid var(--line);border-radius:8px;padding:14px;text-align:center}' +
    '.rp-stat-val{font-size:1.3rem;font-weight:800;color:var(--acc,#2563eb);font-variant-numeric:tabular-nums}' +
    '.rp-stat-label{font-size:.65rem;color:var(--mut);text-transform:uppercase;letter-spacing:.04em;margin-top:2px}' +
    '.rp-empty{text-align:center;padding:40px;color:var(--mut);font-size:.85rem}' +
    '.rp-checklist{list-style:none;padding:0;margin:0}' +
    '.rp-checklist li{display:flex;align-items:center;gap:8px;padding:8px 10px;border-bottom:1px solid var(--line);font-size:.78rem;cursor:pointer;transition:background .15s}' +
    '.rp-checklist li:hover{background:rgba(255,255,255,.02)}' +
    '.rp-checklist li:last-child{border-bottom:none}' +
    '.rp-check{width:16px;height:16px;border:2px solid var(--line);border-radius:3px;flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:.6rem;transition:all .15s}' +
    '.rp-check.checked{background:var(--acc);border-color:var(--acc);color:#fff}' +
    '[data-style=pro] .rp-wrap{color:#0f172a}' +
    '[data-style=pro] .rp-panel{background:#fff;border-color:#e2e8f0}' +
    '[data-style=pro] .rp-textarea{background:#f8fafc;border-color:#e2e8f0;color:#0f172a}' +
    '[data-style=pro] .rp-task{background:#f8fafc;border-color:#e2e8f0}' +
    '[data-style=pro] .rp-task-cmd{background:rgba(37,99,235,.05)}' +
    '[data-style=pro] .rp-stat{background:#f8fafc;border-color:#e2e8f0}' +
    '[data-style=pro] .rp-phase-dot{background:#fff;border-color:#e2e8f0}' +
    '[data-style=pro] .rp-phases::before{background:#e2e8f0}' +
    '[data-style=pro] .rp-tmpl-btn{border-color:#e2e8f0;color:#64748b}' +
    '[data-style=pro] .rp-tmpl-btn:hover{border-color:#2563eb;color:#2563eb}' +
    '[data-style=pro] .rp-finding{background:#fafafa}' +
    '[data-style=pro] .rp-checklist li{border-bottom-color:#f1f5f9}' +
    '[data-style=pro] .rp-checklist li:hover{background:#f8fafc}' +
    '[data-style=pro] .rp-add-input{border-color:#e2e8f0;color:#0f172a}' +
    '[data-style=pro] .rp-task-input{border-bottom-color:#e2e8f0;color:#0f172a}' +
    '</style>';

  function statusColor(s) {
    return s === 'done' ? '#16a34a' : s === 'running' ? '#eab308' : s === 'failed' ? '#dc2626' : '#475569';
  }

  function sevColor(s) {
    return s === 'critical' ? '#dc2626' : s === 'high' ? '#f97316' : s === 'medium' ? '#eab308' : '#22c55e';
  }

  function render() {
    var html = CSS + '<div class="rp-wrap">';
    html += '<div class="rp-header"><h1 class="rp-title">Network Recon Planner</h1><p class="rp-sub">Plan and track penetration testing engagements from scope to report</p></div>';

    html += '<div class="rp-phases">';
    RP_PHASES.forEach(function(p) {
      var cls = 'rp-phase';
      if (p.id === state.tab) cls += ' active';
      html += '<button class="' + cls + '" data-phase="' + p.id + '"><div class="rp-phase-dot">' + p.icon + '</div><span>' + p.label + '</span></button>';
    });
    html += '</div>';

    if (state.tab === 'scope') html += renderScope();
    else if (state.tab === 'recon') html += renderRecon();
    else if (state.tab === 'enumerate') html += renderEnumerate();
    else if (state.tab === 'exploit') html += renderExploit();
    else if (state.tab === 'post') html += renderPost();
    else if (state.tab === 'report') html += renderReport();

    html += '</div>';
    container.innerHTML = html;
    wireEvents();
  }

  function renderScope() {
    var h = '<div class="rp-panel"><div class="rp-panel-title">Engagement Scope</div>' +
      '<div class="rp-templates"><span style="font-size:.72rem;color:var(--mut)">Templates:</span>';
    Object.keys(RP_TEMPLATES).forEach(function(k) {
      h += '<button class="rp-tmpl-btn" data-tmpl="' + k + '">' + RP_TEMPLATES[k].name + '</button>';
    });
    h += '</div>' +
      '<textarea class="rp-textarea" id="rp-scope" placeholder="Define target scope, rules of engagement, time windows, emergency contacts...">' + esc(state.scope) + '</textarea>' +
      '<div style="display:flex;gap:8px;margin-top:12px">' +
      '<button class="rp-btn" id="rp-save-scope">Save &amp; Continue to Recon</button>' +
      '</div></div>';
    return h;
  }

  function renderRecon() {
    var h = '<div class="rp-panel"><div class="rp-panel-title"><span>Reconnaissance Tasks</span><span style="font-size:.72rem;color:var(--mut)">' + state.reconTasks.filter(function(t) { return t.status === 'done'; }).length + '/' + state.reconTasks.length + ' complete</span></div>';
    if (state.reconTasks.length) {
      h += '<div class="rp-task-list">';
      state.reconTasks.forEach(function(t, i) {
        h += '<div class="rp-task">' +
          '<div class="rp-task-status" data-idx="' + i + '" data-type="recon" style="background:' + statusColor(t.status) + ';box-shadow:0 0 6px ' + statusColor(t.status) + '44" title="Click to cycle: pending → running → done → failed"></div>' +
          '<div class="rp-task-body">' +
          '<div class="rp-task-tool">' + esc(t.tool) + '</div>' +
          '<div class="rp-task-cmd">' + esc(t.cmd) + '</div>' +
          '<input class="rp-task-input" data-idx="' + i + '" data-type="recon-notes" placeholder="Notes..." value="' + esc(t.notes) + '">' +
          '</div>' +
          '<button class="rp-btn rp-btn-sm rp-btn-ghost" data-idx="' + i + '" data-del="recon" title="Remove">&#10005;</button>' +
          '</div>';
      });
      h += '</div>';
    } else {
      h += '<div class="rp-empty">No recon tasks yet. Add one below or load a template from the Scope tab.</div>';
    }
    h += '<div class="rp-add-row">' +
      '<input class="rp-add-input" id="rp-add-tool" placeholder="Tool name (e.g. Nmap)" style="max-width:140px">' +
      '<input class="rp-add-input" id="rp-add-cmd" placeholder="Command to run">' +
      '<button class="rp-btn rp-btn-sm" id="rp-add-recon">Add Task</button></div>';
    h += '</div>';
    return h;
  }

  function renderEnumerate() {
    var h = '<div class="rp-panel"><div class="rp-panel-title"><span>Enumeration Results</span></div>' +
      '<div style="margin-bottom:12px;font-size:.75rem;color:var(--mut)">Record services, open ports, usernames, shares, and other enumeration findings.</div>';
    if (state.enumResults.length) {
      h += '<div class="rp-task-list">';
      state.enumResults.forEach(function(e, i) {
        h += '<div class="rp-task"><div class="rp-task-body"><div class="rp-task-tool">' + esc(e.title) + '</div><div class="rp-task-notes">' + esc(e.detail) + '</div></div>' +
          '<button class="rp-btn rp-btn-sm rp-btn-ghost" data-idx="' + i + '" data-del="enum" title="Remove">&#10005;</button></div>';
      });
      h += '</div>';
    } else {
      h += '<div class="rp-empty">No enumeration results recorded yet.</div>';
    }
    h += '<div class="rp-add-row">' +
      '<input class="rp-add-input" id="rp-add-enum-title" placeholder="Finding (e.g. SMB Open on 10.0.0.5)" style="max-width:260px">' +
      '<input class="rp-add-input" id="rp-add-enum-detail" placeholder="Details">' +
      '<button class="rp-btn rp-btn-sm" id="rp-add-enum">Add</button></div>';
    h += '</div>';
    return h;
  }

  function renderExploit() {
    var h = '<div class="rp-panel"><div class="rp-panel-title"><span>Exploit Attempts</span></div>';
    if (state.exploits.length) {
      h += '<div class="rp-task-list">';
      state.exploits.forEach(function(e, i) {
        var sc = e.success ? '#16a34a' : '#dc2626';
        h += '<div class="rp-task">' +
          '<div class="rp-task-status" style="background:' + sc + ';box-shadow:0 0 6px ' + sc + '44" data-idx="' + i + '" data-type="exploit"></div>' +
          '<div class="rp-task-body">' +
          '<div class="rp-task-tool">' + esc(e.target) + '</div>' +
          '<div class="rp-task-cmd">' + esc(e.technique) + '</div>' +
          '<div class="rp-task-notes">' + (e.success ? '<span style="color:#16a34a;font-weight:600">SUCCESS</span>' : '<span style="color:#dc2626;font-weight:600">FAILED</span>') + ' — ' + esc(e.notes) + '</div>' +
          '</div>' +
          '<button class="rp-btn rp-btn-sm rp-btn-ghost" data-idx="' + i + '" data-del="exploit" title="Remove">&#10005;</button></div>';
      });
      h += '</div>';
    } else {
      h += '<div class="rp-empty">No exploit attempts recorded.</div>';
    }
    h += '<div class="rp-add-row" style="flex-wrap:wrap;gap:8px">' +
      '<input class="rp-add-input" id="rp-add-ex-target" placeholder="Target (e.g. 10.0.0.5:445)" style="max-width:180px">' +
      '<input class="rp-add-input" id="rp-add-ex-tech" placeholder="Technique / CVE">' +
      '<select id="rp-add-ex-result" style="padding:6px 10px;border:1px solid var(--line,#1e293b);border-radius:6px;background:var(--card2,#080c14);color:var(--txt);font-size:.75rem"><option value="1">Success</option><option value="0">Failed</option></select>' +
      '<input class="rp-add-input" id="rp-add-ex-notes" placeholder="Notes" style="max-width:200px">' +
      '<button class="rp-btn rp-btn-sm" id="rp-add-exploit">Add</button></div>';
    h += '</div>';
    return h;
  }

  function renderPost() {
    var h = '<div class="rp-panel"><div class="rp-panel-title"><span>Post-Exploitation Checklist</span></div>';
    var items = [
      { id: 'persist', label: 'Persistence mechanism established', cat: 'Access' },
      { id: 'privesc', label: 'Privilege escalation attempted', cat: 'Access' },
      { id: 'lateral', label: 'Lateral movement paths identified', cat: 'Movement' },
      { id: 'exfil', label: 'Data exfiltration simulated', cat: 'Impact' },
      { id: 'creds', label: 'Credential harvesting tested', cat: 'Access' },
      { id: 'logs', label: 'Log artifacts documented', cat: 'Cleanup' },
      { id: 'cleanup', label: 'All test artifacts removed', cat: 'Cleanup' },
      { id: 'screenshot', label: 'Screenshots / proof collected', cat: 'Evidence' }
    ];
    h += '<ul class="rp-checklist">';
    items.forEach(function(item) {
      var checked = state.postActions.includes(item.id);
      h += '<li data-check="' + item.id + '">' +
        '<div class="rp-check' + (checked ? ' checked' : '') + '">' + (checked ? '&#10003;' : '') + '</div>' +
        '<span style="flex:1">' + item.label + '</span>' +
        '<span style="font-size:.65rem;color:var(--mut);text-transform:uppercase;letter-spacing:.03em">' + item.cat + '</span></li>';
    });
    h += '</ul></div>';
    h += '<div class="rp-panel"><div class="rp-panel-title">Custom Actions</div>';
    if (state.postActions.filter(function(a) { return a.startsWith('custom:'); }).length) {
      h += '<div class="rp-task-list" style="margin-bottom:12px">';
      state.postActions.filter(function(a) { return a.startsWith('custom:'); }).forEach(function(a) {
        h += '<div class="rp-task"><div class="rp-task-body"><div class="rp-task-tool">' + esc(a.replace('custom:', '')) + '</div></div></div>';
      });
      h += '</div>';
    }
    h += '<div class="rp-add-row"><input class="rp-add-input" id="rp-add-post" placeholder="Add custom post-exploitation action"><button class="rp-btn rp-btn-sm" id="rp-add-post-btn">Add</button></div></div>';
    return h;
  }

  function renderReport() {
    var h = '<div class="rp-stat-row">' +
      '<div class="rp-stat"><div class="rp-stat-val">' + state.reconTasks.length + '</div><div class="rp-stat-label">Recon Tasks</div></div>' +
      '<div class="rp-stat"><div class="rp-stat-val">' + state.reconTasks.filter(function(t) { return t.status === 'done'; }).length + '</div><div class="rp-stat-label">Completed</div></div>' +
      '<div class="rp-stat"><div class="rp-stat-val">' + state.enumResults.length + '</div><div class="rp-stat-label">Enum Findings</div></div>' +
      '<div class="rp-stat"><div class="rp-stat-val">' + state.exploits.filter(function(e) { return e.success; }).length + '/' + state.exploits.length + '</div><div class="rp-stat-label">Exploits</div></div>' +
      '</div>';

    h += '<div class="rp-panel"><div class="rp-panel-title"><span>Add Finding</span></div>' +
      '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px">' +
      '<input class="rp-add-input" id="rp-f-title" placeholder="Finding title" style="min-width:200px">' +
      '<select id="rp-f-sev" style="padding:6px 10px;border:1px solid var(--line,#1e293b);border-radius:6px;background:var(--card2,#080c14);color:var(--txt);font-size:.75rem">' +
      '<option value="critical">Critical</option><option value="high">High</option><option value="medium" selected>Medium</option><option value="low">Low</option></select>' +
      '<input class="rp-add-input" id="rp-f-desc" placeholder="Description / impact">' +
      '<button class="rp-btn rp-btn-sm" id="rp-add-finding">Add Finding</button></div></div>';

    if (state.findings.length) {
      h += '<div class="rp-panel"><div class="rp-panel-title"><span>Findings (' + state.findings.length + ')</span></div>';
      state.findings.forEach(function(f) {
        h += '<div class="rp-finding" style="border-left-color:' + sevColor(f.severity) + '">' +
          '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">' +
          '<span class="rp-sev" style="background:' + sevColor(f.severity) + '22;color:' + sevColor(f.severity) + '">' + esc(f.severity) + '</span>' +
          '<span class="rp-finding-title">' + esc(f.title) + '</span></div>' +
          '<div class="rp-finding-desc">' + esc(f.description) + '</div></div>';
      });
      h += '</div>';
    }

    h += '<div class="rp-panel"><div class="rp-panel-title">Export Report</div>' +
      '<div style="display:flex;gap:8px">' +
      '<button class="rp-btn" id="rp-export">Copy Report as Text</button>' +
      '</div></div>';
    return h;
  }

  function exportReport() {
    var lines = ['# Penetration Test Report', '', '## Scope', state.scope || '(not defined)', '', '## Reconnaissance'];
    state.reconTasks.forEach(function(t) { lines.push('- [' + t.status.toUpperCase() + '] ' + t.tool + ': ' + t.cmd + (t.notes ? ' — ' + t.notes : '')); });
    lines.push('', '## Enumeration');
    state.enumResults.forEach(function(e) { lines.push('- ' + e.title + ': ' + e.detail); });
    lines.push('', '## Exploits');
    state.exploits.forEach(function(e) { lines.push('- [' + (e.success ? 'SUCCESS' : 'FAILED') + '] ' + e.target + ' — ' + e.technique + (e.notes ? ' (' + e.notes + ')' : '')); });
    lines.push('', '## Findings');
    state.findings.forEach(function(f) { lines.push('- [' + f.severity.toUpperCase() + '] ' + f.title + ': ' + f.description); });
    if (typeof navigator !== 'undefined' && navigator.clipboard) {
      navigator.clipboard.writeText(lines.join('\n'));
    }
  }

  function wireEvents() {
    container.querySelectorAll('.rp-phase').forEach(function(btn) {
      btn.onclick = function() { state.tab = btn.dataset.phase; render(); };
    });
    container.querySelectorAll('.rp-tmpl-btn').forEach(function(btn) {
      btn.onclick = function() {
        var tmpl = RP_TEMPLATES[btn.dataset.tmpl];
        if (!tmpl) return;
        state.scope = tmpl.scope;
        state.reconTasks = JSON.parse(JSON.stringify(tmpl.recon));
        render();
      };
    });

    var saveScope = container.querySelector('#rp-save-scope');
    if (saveScope) saveScope.onclick = function() {
      var el = container.querySelector('#rp-scope');
      if (el) state.scope = el.value;
      state.tab = 'recon';
      render();
    };

    container.querySelectorAll('.rp-task-status[data-type="recon"]').forEach(function(dot) {
      dot.onclick = function() {
        var i = parseInt(dot.dataset.idx);
        var cycle = ['pending', 'running', 'done', 'failed'];
        var cur = cycle.indexOf(state.reconTasks[i].status);
        state.reconTasks[i].status = cycle[(cur + 1) % cycle.length];
        render();
      };
    });

    container.querySelectorAll('.rp-task-status[data-type="exploit"]').forEach(function(dot) {
      dot.onclick = function() {
        var i = parseInt(dot.dataset.idx);
        state.exploits[i].success = !state.exploits[i].success;
        render();
      };
    });

    container.querySelectorAll('input[data-type="recon-notes"]').forEach(function(inp) {
      inp.onchange = function() {
        var i = parseInt(inp.dataset.idx);
        state.reconTasks[i].notes = inp.value;
      };
    });

    container.querySelectorAll('[data-del]').forEach(function(btn) {
      btn.onclick = function() {
        var i = parseInt(btn.dataset.idx);
        var type = btn.dataset.del;
        if (type === 'recon') state.reconTasks.splice(i, 1);
        else if (type === 'enum') state.enumResults.splice(i, 1);
        else if (type === 'exploit') state.exploits.splice(i, 1);
        render();
      };
    });

    var addRecon = container.querySelector('#rp-add-recon');
    if (addRecon) addRecon.onclick = function() {
      var tool = container.querySelector('#rp-add-tool');
      var cmd = container.querySelector('#rp-add-cmd');
      if (tool && cmd && tool.value.trim() && cmd.value.trim()) {
        state.reconTasks.push({ tool: tool.value.trim(), cmd: cmd.value.trim(), status: 'pending', notes: '' });
        render();
      }
    };

    var addEnum = container.querySelector('#rp-add-enum');
    if (addEnum) addEnum.onclick = function() {
      var t = container.querySelector('#rp-add-enum-title');
      var d = container.querySelector('#rp-add-enum-detail');
      if (t && d && t.value.trim()) {
        state.enumResults.push({ title: t.value.trim(), detail: d.value.trim() });
        render();
      }
    };

    var addExploit = container.querySelector('#rp-add-exploit');
    if (addExploit) addExploit.onclick = function() {
      var target = container.querySelector('#rp-add-ex-target');
      var tech = container.querySelector('#rp-add-ex-tech');
      var res = container.querySelector('#rp-add-ex-result');
      var notes = container.querySelector('#rp-add-ex-notes');
      if (target && tech && target.value.trim()) {
        state.exploits.push({ target: target.value.trim(), technique: tech.value.trim(), success: res.value === '1', notes: notes.value.trim() });
        render();
      }
    };

    container.querySelectorAll('[data-check]').forEach(function(li) {
      li.onclick = function() {
        var id = li.dataset.check;
        var idx = state.postActions.indexOf(id);
        if (idx >= 0) state.postActions.splice(idx, 1);
        else state.postActions.push(id);
        render();
      };
    });

    var addPost = container.querySelector('#rp-add-post-btn');
    if (addPost) addPost.onclick = function() {
      var inp = container.querySelector('#rp-add-post');
      if (inp && inp.value.trim()) {
        state.postActions.push('custom:' + inp.value.trim());
        render();
      }
    };

    var addFinding = container.querySelector('#rp-add-finding');
    if (addFinding) addFinding.onclick = function() {
      var t = container.querySelector('#rp-f-title');
      var s = container.querySelector('#rp-f-sev');
      var d = container.querySelector('#rp-f-desc');
      if (t && t.value.trim()) {
        state.findings.push({ title: t.value.trim(), severity: s.value, description: d.value.trim() });
        render();
      }
    };

    var exportBtn = container.querySelector('#rp-export');
    if (exportBtn) exportBtn.onclick = function() {
      exportReport();
      exportBtn.textContent = 'Copied!';
      exportBtn.style.background = '#16a34a';
      setTimeout(function() { exportBtn.textContent = 'Copy Report as Text'; exportBtn.style.background = ''; }, 2000);
    };
  }

  render();
}
