const esc = (s) => String(s != null ? s : '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

const STORE_KEY = 'dn_secdash';
function loadData() { try { return JSON.parse(localStorage.getItem(STORE_KEY)) || defaultData(); } catch (_) { return defaultData(); } }
function saveData(d) { try { localStorage.setItem(STORE_KEY, JSON.stringify(d)); } catch (_) {} }
function defaultData() { return { assets: [], vulns: [], risks: [], patches: [], slaConfig: { critical: 24, high: 168, medium: 720, low: 2160 } }; }
function genId() { return Date.now().toString(36) + Math.random().toString(36).slice(2, 7); }

var SLA_DEFAULTS = { critical: 24, high: 168, medium: 720, low: 2160 };
var SEVERITIES = ['Critical', 'High', 'Medium', 'Low'];
var VULN_STATUSES = ['Open', 'In Progress', 'Mitigated', 'Accepted'];
var RISK_STATUSES = ['Open', 'Mitigated', 'Accepted', 'Transferred'];
var PATCH_STATUSES = ['Pending', 'Testing', 'Deployed', 'Failed', 'Deferred'];
var CRITICALITIES = ['Critical', 'High', 'Medium', 'Low'];
var OS_OPTIONS = ['Windows Server 2022', 'Windows Server 2019', 'Windows 11', 'Windows 10', 'Ubuntu 22.04', 'Ubuntu 20.04', 'RHEL 9', 'RHEL 8', 'CentOS 7', 'Debian 12', 'Debian 11', 'macOS Ventura', 'macOS Sonoma', 'FreeBSD 14', 'ESXi 8', 'Cisco IOS-XE', 'Palo Alto PAN-OS', 'FortiOS', 'Junos OS', 'Custom/Other'];

function selectHtml(id, options, selected) {
  return '<select class="tk-in" id="' + id + '">' +
    options.map(function(o) { return '<option value="' + esc(o) + '"' + (o === selected ? ' selected' : '') + '>' + esc(o) + '</option>'; }).join('') +
    '</select>';
}

export function renderSecurityDashboard(main) {
  var data = loadData();

  main.innerHTML =
    '<h1 class="pg-h1">Security Dashboard</h1>' +
    '<p class="muted pg-sub">Organization security posture -- asset inventory, vulnerability tracking, risk register, patch management, and metrics. All data stored locally.</p>' +
    '<div class="tool-intro">' +
      '<h2>Security Dashboard</h2>' +
      '<p>Gives you a single view of your security posture. See vulnerability counts, threat levels, compliance status, and recent alerts.</p>' +
      '<div class="tool-steps">' +
        '<div class="tool-step"><span class="step-num">1</span><div class="step-text"><strong>Review the overview</strong>See your security score, open vulnerabilities, and SLA status</div></div>' +
        '<div class="tool-step"><span class="step-num">2</span><div class="step-text"><strong>Click into any metric</strong>Switch tabs to manage assets, vulnerabilities, risks, or patches</div></div>' +
        '<div class="tool-step"><span class="step-num">3</span><div class="step-text"><strong>Take action on findings</strong>Add entries, update statuses, and generate reports</div></div>' +
      '</div>' +
    '</div>' +
    '<div class="tab-bar" id="sd-tabs">' +
      '<button class="tab active" data-tab="overview">Overview</button>' +
      '<button class="tab" data-tab="assets">Assets</button>' +
      '<button class="tab" data-tab="vulns">Vulnerabilities</button>' +
      '<button class="tab" data-tab="risks">Risk Register</button>' +
      '<button class="tab" data-tab="patches">Patches</button>' +
      '<button class="tab" data-tab="metrics">Metrics</button>' +
      '<button class="tab" data-tab="sla">SLA Config</button>' +
      '<button class="tab" data-tab="report">Report</button>' +
    '</div>' +
    '<div id="sd-content"></div>';

  var content = main.querySelector('#sd-content');
  var tabs = main.querySelector('#sd-tabs');

  function switchTab(id) {
    tabs.querySelectorAll('.tab').forEach(function(t) { t.classList.toggle('active', t.dataset.tab === id); });
    var r = { overview: renderOverview, assets: renderAssets, vulns: renderVulns, risks: renderRisks,
      patches: renderPatches, metrics: renderMetrics, sla: renderSLA, report: renderReport };
    if (r[id]) r[id]();
  }

  function renderOverview() {
    var totalAssets = data.assets.length;
    var openVulns = data.vulns.filter(function(v) { return v.status === 'Open' || v.status === 'In Progress'; }).length;
    var critVulns = data.vulns.filter(function(v) { return v.severity === 'Critical' && v.status === 'Open'; }).length;
    var openRisks = data.risks.filter(function(r) { return r.status === 'Open'; }).length;
    var pendingPatches = data.patches.filter(function(p) { return p.status === 'Pending' || p.status === 'Testing'; }).length;

    var slaBreaches = 0;
    var now = Date.now();
    data.vulns.forEach(function(v) {
      if (v.status === 'Open' || v.status === 'In Progress') {
        var slaHours = data.slaConfig[v.severity.toLowerCase()] || SLA_DEFAULTS[v.severity.toLowerCase()] || 720;
        var deadline = new Date(v.created).getTime() + slaHours * 3600000;
        if (now > deadline) slaBreaches++;
      }
    });

    var score = 100;
    score -= critVulns * 15;
    score -= (openVulns - critVulns) * 3;
    score -= openRisks * 2;
    score -= slaBreaches * 10;
    score -= pendingPatches * 2;
    score = Math.max(0, Math.min(100, score));
    var scoreColor = score >= 80 ? '#22c55e' : score >= 60 ? '#f59e0b' : '#ef4444';
    var scoreLabel = score >= 80 ? 'Good' : score >= 60 ? 'Fair' : 'Critical';

    content.innerHTML =
      '<div style="margin-top:12px;display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px">' +
        '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:16px;text-align:center">' +
          '<div style="font-size:2rem;font-weight:700;color:' + scoreColor + '">' + score + '</div>' +
          '<div style="font-size:.8rem;color:var(--mut)">Security Score</div>' +
          '<div style="font-size:.75rem;color:' + scoreColor + '">' + scoreLabel + '</div></div>' +
        '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:16px;text-align:center">' +
          '<div style="font-size:2rem;font-weight:700;color:var(--acc)">' + totalAssets + '</div>' +
          '<div style="font-size:.8rem;color:var(--mut)">Total Assets</div></div>' +
        '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:16px;text-align:center">' +
          '<div style="font-size:2rem;font-weight:700;color:#ef4444">' + openVulns + '</div>' +
          '<div style="font-size:.8rem;color:var(--mut)">Open Vulnerabilities</div>' +
          '<div style="font-size:.75rem;color:#ef4444">' + critVulns + ' critical</div></div>' +
        '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:16px;text-align:center">' +
          '<div style="font-size:2rem;font-weight:700;color:#f59e0b">' + openRisks + '</div>' +
          '<div style="font-size:.8rem;color:var(--mut)">Open Risks</div></div>' +
        '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:16px;text-align:center">' +
          '<div style="font-size:2rem;font-weight:700;color:#a855f7">' + pendingPatches + '</div>' +
          '<div style="font-size:.8rem;color:var(--mut)">Pending Patches</div></div>' +
        '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:16px;text-align:center">' +
          '<div style="font-size:2rem;font-weight:700;color:' + (slaBreaches ? '#ef4444' : '#22c55e') + '">' + slaBreaches + '</div>' +
          '<div style="font-size:.8rem;color:var(--mut)">SLA Breaches</div></div>' +
      '</div>' +
      '<div style="margin-top:16px;background:var(--card);border:1px solid var(--line);border-radius:6px;padding:16px">' +
        '<h3 style="margin-top:0;font-size:.95rem">Quick Actions</h3>' +
        '<div style="display:flex;gap:8px;flex-wrap:wrap">' +
          '<button class="btn sm" id="sd-add-asset-btn">Add Asset</button>' +
          '<button class="btn sm" id="sd-add-vuln-btn">Add Vulnerability</button>' +
          '<button class="btn sm" id="sd-add-risk-btn">Add Risk</button>' +
          '<button class="btn sm" id="sd-add-patch-btn">Add Patch</button>' +
          '<button class="btn sm ghost" id="sd-clear-btn">Clear All Data</button>' +
        '</div>' +
      '</div>';

    main.querySelector('#sd-add-asset-btn').onclick = function() { switchTab('assets'); };
    main.querySelector('#sd-add-vuln-btn').onclick = function() { switchTab('vulns'); };
    main.querySelector('#sd-add-risk-btn').onclick = function() { switchTab('risks'); };
    main.querySelector('#sd-add-patch-btn').onclick = function() { switchTab('patches'); };
    main.querySelector('#sd-clear-btn').onclick = function() {
      if (confirm('Clear all security dashboard data?')) { data = defaultData(); saveData(data); renderOverview(); }
    };
  }

  function renderAssets() {
    var html = '<div style="margin-top:12px">' +
      '<h2 class="pg-h2">Asset Inventory</h2>' +
      '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:16px;margin-bottom:12px">' +
        '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px">' +
          '<input type="text" class="tk-in" id="sd-a-host" placeholder="Hostname" style="flex:1;min-width:120px">' +
          '<input type="text" class="tk-in" id="sd-a-ip" placeholder="IP Address" style="width:130px">' +
          selectHtml('sd-a-os', OS_OPTIONS, '') +
          '<input type="text" class="tk-in" id="sd-a-owner" placeholder="Owner" style="width:120px">' +
          selectHtml('sd-a-crit', CRITICALITIES, 'Medium') +
          '<button class="btn sm" id="sd-a-add">Add</button>' +
        '</div>' +
      '</div>';

    if (data.assets.length) {
      html += '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.78rem">' +
        '<thead><tr style="border-bottom:2px solid var(--line);text-align:left">' +
        '<th style="padding:6px 8px">Hostname</th><th style="padding:6px 8px">IP</th><th style="padding:6px 8px">OS</th>' +
        '<th style="padding:6px 8px">Owner</th><th style="padding:6px 8px">Criticality</th><th style="padding:6px 8px">Added</th><th style="padding:6px 8px"></th></tr></thead><tbody>';
      for (var i = 0; i < data.assets.length; i++) {
        var a = data.assets[i];
        var critColor = a.criticality === 'Critical' ? '#ef4444' : a.criticality === 'High' ? '#f59e0b' : a.criticality === 'Medium' ? 'var(--acc)' : '#22c55e';
        html += '<tr style="border-bottom:1px solid var(--line)">' +
          '<td style="padding:6px 8px;font-weight:500">' + esc(a.hostname) + '</td>' +
          '<td style="padding:6px 8px;font-family:var(--mono,monospace)">' + esc(a.ip) + '</td>' +
          '<td style="padding:6px 8px;font-size:.72rem">' + esc(a.os) + '</td>' +
          '<td style="padding:6px 8px">' + esc(a.owner) + '</td>' +
          '<td style="padding:6px 8px;color:' + critColor + ';font-weight:600">' + esc(a.criticality) + '</td>' +
          '<td style="padding:6px 8px;color:var(--mut);font-size:.72rem">' + new Date(a.added).toLocaleDateString() + '</td>' +
          '<td style="padding:6px 8px"><button class="btn sm ghost" data-del-asset="' + esc(a.id) + '" style="color:#ef4444">X</button></td></tr>';
      }
      html += '</tbody></table></div>';
    } else {
      html += '<p style="color:var(--mut);padding:12px">No assets added yet.</p>';
    }
    html += '</div>';
    content.innerHTML = html;

    main.querySelector('#sd-a-add').onclick = function() {
      var hostname = main.querySelector('#sd-a-host').value.trim();
      if (!hostname) return;
      data.assets.push({
        id: genId(), hostname: hostname,
        ip: main.querySelector('#sd-a-ip').value.trim(),
        os: main.querySelector('#sd-a-os').value,
        owner: main.querySelector('#sd-a-owner').value.trim(),
        criticality: main.querySelector('#sd-a-crit').value,
        added: new Date().toISOString()
      });
      saveData(data); renderAssets();
    };
    content.querySelectorAll('[data-del-asset]').forEach(function(btn) {
      btn.onclick = function() { data.assets = data.assets.filter(function(a) { return a.id !== btn.dataset.delAsset; }); saveData(data); renderAssets(); };
    });
  }

  function renderVulns() {
    var html = '<div style="margin-top:12px">' +
      '<h2 class="pg-h2">Vulnerability Tracker</h2>' +
      '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:16px;margin-bottom:12px">' +
        '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px">' +
          '<input type="text" class="tk-in" id="sd-v-cve" placeholder="CVE-YYYY-NNNNN" style="width:160px">' +
          '<input type="number" class="tk-in" id="sd-v-cvss" placeholder="CVSS" min="0" max="10" step="0.1" style="width:70px">' +
          selectHtml('sd-v-sev', SEVERITIES, 'High') +
          '<input type="text" class="tk-in" id="sd-v-asset" placeholder="Affected asset" style="flex:1;min-width:120px">' +
          selectHtml('sd-v-status', VULN_STATUSES, 'Open') +
          '<button class="btn sm" id="sd-v-add">Add</button>' +
        '</div>' +
      '</div>';

    var filtered = data.vulns.slice().sort(function(a, b) {
      var si = SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity);
      return si !== 0 ? si : new Date(b.created) - new Date(a.created);
    });

    if (filtered.length) {
      html += '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.78rem">' +
        '<thead><tr style="border-bottom:2px solid var(--line);text-align:left">' +
        '<th style="padding:6px 8px">CVE</th><th style="padding:6px 8px">CVSS</th><th style="padding:6px 8px">Severity</th>' +
        '<th style="padding:6px 8px">Asset</th><th style="padding:6px 8px">Status</th><th style="padding:6px 8px">SLA</th><th style="padding:6px 8px"></th></tr></thead><tbody>';
      var now = Date.now();
      for (var i = 0; i < filtered.length; i++) {
        var v = filtered[i];
        var sevColor = v.severity === 'Critical' ? '#ef4444' : v.severity === 'High' ? '#f59e0b' : v.severity === 'Medium' ? 'var(--acc)' : '#22c55e';
        var slaHours = data.slaConfig[v.severity.toLowerCase()] || 720;
        var deadline = new Date(v.created).getTime() + slaHours * 3600000;
        var remaining = deadline - now;
        var slaText = '', slaColor = '#22c55e';
        if (v.status === 'Mitigated' || v.status === 'Accepted') { slaText = 'Resolved'; slaColor = '#22c55e'; }
        else if (remaining < 0) { slaText = 'BREACHED (' + Math.ceil(-remaining / 3600000) + 'h ago)'; slaColor = '#ef4444'; }
        else { var hrs = Math.ceil(remaining / 3600000); slaText = hrs > 48 ? Math.ceil(hrs / 24) + 'd left' : hrs + 'h left'; slaColor = hrs < 24 ? '#f59e0b' : '#22c55e'; }

        html += '<tr style="border-bottom:1px solid var(--line)">' +
          '<td style="padding:6px 8px;font-family:var(--mono,monospace);font-weight:500">' + esc(v.cve) + '</td>' +
          '<td style="padding:6px 8px;color:' + sevColor + ';font-weight:600">' + (v.cvss || '-') + '</td>' +
          '<td style="padding:6px 8px;color:' + sevColor + '">' + esc(v.severity) + '</td>' +
          '<td style="padding:6px 8px">' + esc(v.asset) + '</td>' +
          '<td style="padding:6px 8px">' + esc(v.status) + '</td>' +
          '<td style="padding:6px 8px;font-size:.72rem;color:' + slaColor + '">' + slaText + '</td>' +
          '<td style="padding:6px 8px"><button class="btn sm ghost" data-del-vuln="' + esc(v.id) + '" style="color:#ef4444">X</button></td></tr>';
      }
      html += '</tbody></table></div>';
    } else { html += '<p style="color:var(--mut);padding:12px">No vulnerabilities tracked yet.</p>'; }
    html += '</div>';
    content.innerHTML = html;

    main.querySelector('#sd-v-add').onclick = function() {
      var cve = main.querySelector('#sd-v-cve').value.trim();
      if (!cve) return;
      data.vulns.push({
        id: genId(), cve: cve, cvss: parseFloat(main.querySelector('#sd-v-cvss').value) || 0,
        severity: main.querySelector('#sd-v-sev').value,
        asset: main.querySelector('#sd-v-asset').value.trim(),
        status: main.querySelector('#sd-v-status').value,
        created: new Date().toISOString()
      });
      saveData(data); renderVulns();
    };
    content.querySelectorAll('[data-del-vuln]').forEach(function(btn) {
      btn.onclick = function() { data.vulns = data.vulns.filter(function(v) { return v.id !== btn.dataset.delVuln; }); saveData(data); renderVulns(); };
    });
  }

  function renderRisks() {
    var html = '<div style="margin-top:12px">' +
      '<h2 class="pg-h2">Risk Register</h2>' +
      '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:16px;margin-bottom:12px">' +
        '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px">' +
          '<input type="text" class="tk-in" id="sd-r-name" placeholder="Risk description" style="flex:1;min-width:200px">' +
          '<div><label style="font-size:.72rem;color:var(--mut)">Likelihood (1-5)</label><input type="number" class="tk-in" id="sd-r-like" value="3" min="1" max="5" style="width:60px"></div>' +
          '<div><label style="font-size:.72rem;color:var(--mut)">Impact (1-5)</label><input type="number" class="tk-in" id="sd-r-imp" value="3" min="1" max="5" style="width:60px"></div>' +
          '<input type="text" class="tk-in" id="sd-r-owner" placeholder="Owner" style="width:120px">' +
          selectHtml('sd-r-status', RISK_STATUSES, 'Open') +
          '<button class="btn sm" id="sd-r-add">Add</button>' +
        '</div>' +
      '</div>';

    if (data.risks.length) {
      html += '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.78rem">' +
        '<thead><tr style="border-bottom:2px solid var(--line);text-align:left">' +
        '<th style="padding:6px 8px">Risk</th><th style="padding:6px 8px">L</th><th style="padding:6px 8px">I</th>' +
        '<th style="padding:6px 8px">Score</th><th style="padding:6px 8px">Owner</th><th style="padding:6px 8px">Status</th><th style="padding:6px 8px"></th></tr></thead><tbody>';
      for (var i = 0; i < data.risks.length; i++) {
        var r = data.risks[i];
        var score = r.likelihood * r.impact;
        var sColor = score >= 15 ? '#ef4444' : score >= 8 ? '#f59e0b' : '#22c55e';
        html += '<tr style="border-bottom:1px solid var(--line)">' +
          '<td style="padding:6px 8px">' + esc(r.name) + '</td>' +
          '<td style="padding:6px 8px">' + r.likelihood + '</td>' +
          '<td style="padding:6px 8px">' + r.impact + '</td>' +
          '<td style="padding:6px 8px;color:' + sColor + ';font-weight:700">' + score + '</td>' +
          '<td style="padding:6px 8px">' + esc(r.owner) + '</td>' +
          '<td style="padding:6px 8px">' + esc(r.status) + '</td>' +
          '<td style="padding:6px 8px"><button class="btn sm ghost" data-del-risk="' + esc(r.id) + '" style="color:#ef4444">X</button></td></tr>';
      }
      html += '</tbody></table></div>';
    } else { html += '<p style="color:var(--mut);padding:12px">No risks registered yet.</p>'; }
    html += '</div>';
    content.innerHTML = html;

    main.querySelector('#sd-r-add').onclick = function() {
      var name = main.querySelector('#sd-r-name').value.trim();
      if (!name) return;
      data.risks.push({
        id: genId(), name: name,
        likelihood: parseInt(main.querySelector('#sd-r-like').value) || 3,
        impact: parseInt(main.querySelector('#sd-r-imp').value) || 3,
        owner: main.querySelector('#sd-r-owner').value.trim(),
        status: main.querySelector('#sd-r-status').value,
        created: new Date().toISOString()
      });
      saveData(data); renderRisks();
    };
    content.querySelectorAll('[data-del-risk]').forEach(function(btn) {
      btn.onclick = function() { data.risks = data.risks.filter(function(r) { return r.id !== btn.dataset.delRisk; }); saveData(data); renderRisks(); };
    });
  }

  function renderPatches() {
    var html = '<div style="margin-top:12px">' +
      '<h2 class="pg-h2">Patch Management</h2>' +
      '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:16px;margin-bottom:12px">' +
        '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px">' +
          '<input type="text" class="tk-in" id="sd-p-kb" placeholder="KB/CVE ID" style="width:160px">' +
          '<input type="text" class="tk-in" id="sd-p-desc" placeholder="Description" style="flex:1;min-width:150px">' +
          '<input type="text" class="tk-in" id="sd-p-systems" placeholder="Affected systems" style="width:150px">' +
          selectHtml('sd-p-status', PATCH_STATUSES, 'Pending') +
          '<button class="btn sm" id="sd-p-add">Add</button>' +
        '</div>' +
      '</div>';

    if (data.patches.length) {
      html += '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.78rem">' +
        '<thead><tr style="border-bottom:2px solid var(--line);text-align:left">' +
        '<th style="padding:6px 8px">KB/CVE</th><th style="padding:6px 8px">Description</th>' +
        '<th style="padding:6px 8px">Systems</th><th style="padding:6px 8px">Status</th><th style="padding:6px 8px"></th></tr></thead><tbody>';
      for (var i = 0; i < data.patches.length; i++) {
        var p = data.patches[i];
        var pColor = p.status === 'Deployed' ? '#22c55e' : p.status === 'Failed' ? '#ef4444' : p.status === 'Testing' ? '#f59e0b' : 'var(--mut)';
        html += '<tr style="border-bottom:1px solid var(--line)">' +
          '<td style="padding:6px 8px;font-family:var(--mono,monospace)">' + esc(p.kb) + '</td>' +
          '<td style="padding:6px 8px">' + esc(p.desc) + '</td>' +
          '<td style="padding:6px 8px;font-size:.72rem">' + esc(p.systems) + '</td>' +
          '<td style="padding:6px 8px;color:' + pColor + ';font-weight:500">' + esc(p.status) + '</td>' +
          '<td style="padding:6px 8px"><button class="btn sm ghost" data-del-patch="' + esc(p.id) + '" style="color:#ef4444">X</button></td></tr>';
      }
      html += '</tbody></table></div>';
    } else { html += '<p style="color:var(--mut);padding:12px">No patches tracked yet.</p>'; }
    html += '</div>';
    content.innerHTML = html;

    main.querySelector('#sd-p-add').onclick = function() {
      var kb = main.querySelector('#sd-p-kb').value.trim();
      if (!kb) return;
      data.patches.push({
        id: genId(), kb: kb,
        desc: main.querySelector('#sd-p-desc').value.trim(),
        systems: main.querySelector('#sd-p-systems').value.trim(),
        status: main.querySelector('#sd-p-status').value,
        created: new Date().toISOString()
      });
      saveData(data); renderPatches();
    };
    content.querySelectorAll('[data-del-patch]').forEach(function(btn) {
      btn.onclick = function() { data.patches = data.patches.filter(function(p) { return p.id !== btn.dataset.delPatch; }); saveData(data); renderPatches(); };
    });
  }

  function renderMetrics() {
    var open = data.vulns.filter(function(v) { return v.status === 'Open'; });
    var inProg = data.vulns.filter(function(v) { return v.status === 'In Progress'; });
    var mitigated = data.vulns.filter(function(v) { return v.status === 'Mitigated'; });
    var accepted = data.vulns.filter(function(v) { return v.status === 'Accepted'; });

    var bySev = {};
    SEVERITIES.forEach(function(s) {
      bySev[s] = data.vulns.filter(function(v) { return v.severity === s && (v.status === 'Open' || v.status === 'In Progress'); }).length;
    });

    var now = Date.now();
    var aging = { '<7d': 0, '7-30d': 0, '30-90d': 0, '>90d': 0 };
    data.vulns.forEach(function(v) {
      if (v.status !== 'Open' && v.status !== 'In Progress') return;
      var age = (now - new Date(v.created).getTime()) / 86400000;
      if (age < 7) aging['<7d']++;
      else if (age < 30) aging['7-30d']++;
      else if (age < 90) aging['30-90d']++;
      else aging['>90d']++;
    });

    var patchDeployed = data.patches.filter(function(p) { return p.status === 'Deployed'; }).length;
    var patchTotal = data.patches.length || 1;
    var patchRate = Math.round(patchDeployed / patchTotal * 100);

    content.innerHTML =
      '<div style="margin-top:12px">' +
        '<h2 class="pg-h2">Security Metrics</h2>' +
        '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:12px">' +
          '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:16px">' +
            '<h3 style="margin-top:0;font-size:.9rem">Vulnerability Status</h3>' +
            '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:.82rem">' +
              '<div>Open: <strong style="color:#ef4444">' + open.length + '</strong></div>' +
              '<div>In Progress: <strong style="color:#f59e0b">' + inProg.length + '</strong></div>' +
              '<div>Mitigated: <strong style="color:#22c55e">' + mitigated.length + '</strong></div>' +
              '<div>Accepted: <strong style="color:var(--mut)">' + accepted.length + '</strong></div>' +
            '</div></div>' +
          '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:16px">' +
            '<h3 style="margin-top:0;font-size:.9rem">Open by Severity</h3>' +
            '<div style="font-size:.82rem">' +
              '<div style="display:flex;justify-content:space-between;margin:4px 0"><span>Critical</span><strong style="color:#ef4444">' + (bySev.Critical || 0) + '</strong></div>' +
              '<div style="display:flex;justify-content:space-between;margin:4px 0"><span>High</span><strong style="color:#f59e0b">' + (bySev.High || 0) + '</strong></div>' +
              '<div style="display:flex;justify-content:space-between;margin:4px 0"><span>Medium</span><strong style="color:var(--acc)">' + (bySev.Medium || 0) + '</strong></div>' +
              '<div style="display:flex;justify-content:space-between;margin:4px 0"><span>Low</span><strong style="color:#22c55e">' + (bySev.Low || 0) + '</strong></div>' +
            '</div></div>' +
          '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:16px">' +
            '<h3 style="margin-top:0;font-size:.9rem">Vulnerability Aging</h3>' +
            '<div style="font-size:.82rem">' +
              '<div style="display:flex;justify-content:space-between;margin:4px 0"><span>&lt;7 days</span><strong style="color:#22c55e">' + aging['<7d'] + '</strong></div>' +
              '<div style="display:flex;justify-content:space-between;margin:4px 0"><span>7-30 days</span><strong style="color:var(--acc)">' + aging['7-30d'] + '</strong></div>' +
              '<div style="display:flex;justify-content:space-between;margin:4px 0"><span>30-90 days</span><strong style="color:#f59e0b">' + aging['30-90d'] + '</strong></div>' +
              '<div style="display:flex;justify-content:space-between;margin:4px 0"><span>&gt;90 days</span><strong style="color:#ef4444">' + aging['>90d'] + '</strong></div>' +
            '</div></div>' +
          '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:16px">' +
            '<h3 style="margin-top:0;font-size:.9rem">Patch Compliance</h3>' +
            '<div style="text-align:center;margin:12px 0"><div style="font-size:2rem;font-weight:700;color:' + (patchRate >= 80 ? '#22c55e' : patchRate >= 60 ? '#f59e0b' : '#ef4444') + '">' + patchRate + '%</div>' +
            '<div style="font-size:.8rem;color:var(--mut)">' + patchDeployed + ' / ' + data.patches.length + ' patches deployed</div></div></div>' +
        '</div>' +
      '</div>';
  }

  function renderSLA() {
    content.innerHTML =
      '<div style="margin-top:12px">' +
        '<h2 class="pg-h2">SLA Configuration</h2>' +
        '<p class="muted" style="margin-bottom:12px">Set remediation deadlines by vulnerability severity (in hours).</p>' +
        '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:16px;max-width:400px">' +
          '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;align-items:center;font-size:.85rem">' +
            '<label style="color:#ef4444;font-weight:600">Critical</label><div style="display:flex;gap:4px;align-items:center"><input type="number" class="tk-in" id="sd-sla-crit" value="' + (data.slaConfig.critical || 24) + '" style="width:80px"> hours (' + Math.round((data.slaConfig.critical || 24) / 24) + 'd)</div>' +
            '<label style="color:#f59e0b;font-weight:600">High</label><div style="display:flex;gap:4px;align-items:center"><input type="number" class="tk-in" id="sd-sla-high" value="' + (data.slaConfig.high || 168) + '" style="width:80px"> hours (' + Math.round((data.slaConfig.high || 168) / 24) + 'd)</div>' +
            '<label style="color:var(--acc);font-weight:600">Medium</label><div style="display:flex;gap:4px;align-items:center"><input type="number" class="tk-in" id="sd-sla-med" value="' + (data.slaConfig.medium || 720) + '" style="width:80px"> hours (' + Math.round((data.slaConfig.medium || 720) / 24) + 'd)</div>' +
            '<label style="color:#22c55e;font-weight:600">Low</label><div style="display:flex;gap:4px;align-items:center"><input type="number" class="tk-in" id="sd-sla-low" value="' + (data.slaConfig.low || 2160) + '" style="width:80px"> hours (' + Math.round((data.slaConfig.low || 2160) / 24) + 'd)</div>' +
          '</div>' +
          '<button class="btn sm" id="sd-sla-save" style="margin-top:12px">Save SLA Config</button>' +
        '</div>' +
      '</div>';

    main.querySelector('#sd-sla-save').onclick = function() {
      data.slaConfig = {
        critical: parseInt(main.querySelector('#sd-sla-crit').value) || 24,
        high: parseInt(main.querySelector('#sd-sla-high').value) || 168,
        medium: parseInt(main.querySelector('#sd-sla-med').value) || 720,
        low: parseInt(main.querySelector('#sd-sla-low').value) || 2160,
      };
      saveData(data);
      renderSLA();
    };
  }

  function renderReport() {
    var now = new Date();
    var open = data.vulns.filter(function(v) { return v.status === 'Open' || v.status === 'In Progress'; });
    var critOpen = open.filter(function(v) { return v.severity === 'Critical'; });
    var highOpen = open.filter(function(v) { return v.severity === 'High'; });
    var openRisks = data.risks.filter(function(r) { return r.status === 'Open'; });
    var patchPending = data.patches.filter(function(p) { return p.status === 'Pending' || p.status === 'Testing'; });

    var report = 'SECURITY POSTURE REPORT\n';
    report += '=======================\n';
    report += 'Generated: ' + now.toISOString().slice(0, 10) + '\n\n';
    report += 'EXECUTIVE SUMMARY\n';
    report += '-----------------\n';
    report += 'Total assets under management: ' + data.assets.length + '\n';
    report += 'Open vulnerabilities: ' + open.length + ' (' + critOpen.length + ' critical, ' + highOpen.length + ' high)\n';
    report += 'Open risks: ' + openRisks.length + '\n';
    report += 'Pending patches: ' + patchPending.length + '\n\n';

    if (critOpen.length) {
      report += 'CRITICAL VULNERABILITIES\n';
      report += '-----------------------\n';
      critOpen.forEach(function(v) { report += '  - ' + v.cve + ' (CVSS ' + v.cvss + ') on ' + v.asset + ' [' + v.status + ']\n'; });
      report += '\n';
    }

    if (openRisks.length) {
      report += 'TOP RISKS\n';
      report += '---------\n';
      openRisks.sort(function(a, b) { return (b.likelihood * b.impact) - (a.likelihood * a.impact); });
      openRisks.forEach(function(r) { report += '  - ' + r.name + ' (Score: ' + (r.likelihood * r.impact) + ', Owner: ' + r.owner + ')\n'; });
      report += '\n';
    }

    report += 'RECOMMENDATIONS\n';
    report += '---------------\n';
    if (critOpen.length) report += '  1. Immediately remediate ' + critOpen.length + ' critical vulnerabilities\n';
    if (patchPending.length) report += '  2. Deploy ' + patchPending.length + ' pending patches\n';
    if (openRisks.length) report += '  3. Address ' + openRisks.length + ' open risks in the risk register\n';
    report += '  4. Review and update asset inventory\n';
    report += '  5. Conduct next vulnerability scan\n';

    content.innerHTML =
      '<div style="margin-top:12px">' +
        '<h2 class="pg-h2">Executive Report</h2>' +
        '<p class="muted" style="margin-bottom:12px">Auto-generated security posture summary. Copy and share with stakeholders.</p>' +
        '<div style="display:flex;gap:8px;margin-bottom:8px"><button class="btn sm" id="sd-rpt-copy">Copy to Clipboard</button></div>' +
        '<pre class="tk-out" id="sd-rpt-text" style="max-height:500px;overflow:auto">' + esc(report) + '</pre>' +
      '</div>';

    main.querySelector('#sd-rpt-copy').onclick = function() {
      var el = document.createElement('textarea');
      el.value = report; document.body.appendChild(el); el.select(); document.execCommand('copy'); document.body.removeChild(el);
    };
  }

  tabs.onclick = function(e) {
    var btn = e.target.closest('.tab');
    if (btn) switchTab(btn.dataset.tab);
  };

  renderOverview();
}
