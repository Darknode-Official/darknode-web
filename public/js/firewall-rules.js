import { esc } from '/js/shared.js';

const FW_PLATFORMS = {
  iptables: 'iptables (Linux)',
  nftables: 'nftables (Linux)',
  netsh: 'Windows Firewall',
  pf: 'pf (BSD/macOS)',
  cisco: 'Cisco ACL'
};

const FW_PROTOCOLS = ['TCP', 'UDP', 'ICMP', 'ANY'];
const FW_ACTIONS = ['ALLOW', 'DENY', 'DROP', 'REJECT'];
const FW_DIRECTIONS = ['IN', 'OUT', 'FORWARD'];

const FW_TEMPLATES = {
  webserver: {
    name: 'Web Server (SSH + HTTP/S)',
    desc: 'Block all inbound except SSH (22), HTTP (80), HTTPS (443)',
    rules: [
      { proto: 'TCP', srcIp: '0.0.0.0/0', dstIp: '0.0.0.0/0', srcPort: '', dstPort: '22', action: 'ALLOW', dir: 'IN', comment: 'Allow SSH' },
      { proto: 'TCP', srcIp: '0.0.0.0/0', dstIp: '0.0.0.0/0', srcPort: '', dstPort: '80', action: 'ALLOW', dir: 'IN', comment: 'Allow HTTP' },
      { proto: 'TCP', srcIp: '0.0.0.0/0', dstIp: '0.0.0.0/0', srcPort: '', dstPort: '443', action: 'ALLOW', dir: 'IN', comment: 'Allow HTTPS' },
      { proto: 'ANY', srcIp: '0.0.0.0/0', dstIp: '0.0.0.0/0', srcPort: '', dstPort: '', action: 'DROP', dir: 'IN', comment: 'Drop all other inbound' }
    ]
  },
  dmz: {
    name: 'DMZ Configuration',
    desc: 'Allow public access to DMZ, restrict DMZ to internal',
    rules: [
      { proto: 'TCP', srcIp: '0.0.0.0/0', dstIp: '10.0.1.0/24', srcPort: '', dstPort: '80', action: 'ALLOW', dir: 'FORWARD', comment: 'Public to DMZ HTTP' },
      { proto: 'TCP', srcIp: '0.0.0.0/0', dstIp: '10.0.1.0/24', srcPort: '', dstPort: '443', action: 'ALLOW', dir: 'FORWARD', comment: 'Public to DMZ HTTPS' },
      { proto: 'ANY', srcIp: '10.0.1.0/24', dstIp: '192.168.1.0/24', srcPort: '', dstPort: '', action: 'DENY', dir: 'FORWARD', comment: 'Block DMZ to internal' },
      { proto: 'TCP', srcIp: '192.168.1.0/24', dstIp: '10.0.1.0/24', srcPort: '', dstPort: '22', action: 'ALLOW', dir: 'FORWARD', comment: 'Admin SSH to DMZ' },
      { proto: 'ANY', srcIp: '0.0.0.0/0', dstIp: '10.0.1.0/24', srcPort: '', dstPort: '', action: 'DROP', dir: 'FORWARD', comment: 'Drop all other to DMZ' }
    ]
  },
  vpn: {
    name: 'VPN Passthrough',
    desc: 'Allow IPsec/IKE and OpenVPN traffic',
    rules: [
      { proto: 'UDP', srcIp: '0.0.0.0/0', dstIp: '0.0.0.0/0', srcPort: '', dstPort: '500', action: 'ALLOW', dir: 'IN', comment: 'IKE (IPsec)' },
      { proto: 'UDP', srcIp: '0.0.0.0/0', dstIp: '0.0.0.0/0', srcPort: '', dstPort: '4500', action: 'ALLOW', dir: 'IN', comment: 'NAT-T (IPsec)' },
      { proto: 'UDP', srcIp: '0.0.0.0/0', dstIp: '0.0.0.0/0', srcPort: '', dstPort: '1194', action: 'ALLOW', dir: 'IN', comment: 'OpenVPN' },
      { proto: 'TCP', srcIp: '0.0.0.0/0', dstIp: '0.0.0.0/0', srcPort: '', dstPort: '1194', action: 'ALLOW', dir: 'IN', comment: 'OpenVPN TCP fallback' }
    ]
  },
  ratelimit: {
    name: 'Rate Limiting (SYN Flood)',
    desc: 'Limit new TCP connections to prevent SYN flood attacks',
    rules: [
      { proto: 'TCP', srcIp: '0.0.0.0/0', dstIp: '0.0.0.0/0', srcPort: '', dstPort: '80', action: 'ALLOW', dir: 'IN', comment: 'Rate limit: 25/sec burst 50 (HTTP)' },
      { proto: 'TCP', srcIp: '0.0.0.0/0', dstIp: '0.0.0.0/0', srcPort: '', dstPort: '443', action: 'ALLOW', dir: 'IN', comment: 'Rate limit: 25/sec burst 50 (HTTPS)' },
      { proto: 'ICMP', srcIp: '0.0.0.0/0', dstIp: '0.0.0.0/0', srcPort: '', dstPort: '', action: 'ALLOW', dir: 'IN', comment: 'Rate limit: 1/sec burst 4 (ping)' }
    ]
  },
  geoblock: {
    name: 'Geo-Blocking Simulation',
    desc: 'Block example CIDR ranges representing geographic regions',
    rules: [
      { proto: 'ANY', srcIp: '5.188.0.0/16', dstIp: '0.0.0.0/0', srcPort: '', dstPort: '', action: 'DROP', dir: 'IN', comment: 'Block region A range' },
      { proto: 'ANY', srcIp: '185.220.0.0/16', dstIp: '0.0.0.0/0', srcPort: '', dstPort: '', action: 'DROP', dir: 'IN', comment: 'Block region B range' },
      { proto: 'ANY', srcIp: '45.155.0.0/16', dstIp: '0.0.0.0/0', srcPort: '', dstPort: '', action: 'DROP', dir: 'IN', comment: 'Block known malicious range' }
    ]
  },
  logging: {
    name: 'Logging Rules',
    desc: 'Log specific traffic for monitoring and auditing',
    rules: [
      { proto: 'TCP', srcIp: '0.0.0.0/0', dstIp: '0.0.0.0/0', srcPort: '', dstPort: '22', action: 'ALLOW', dir: 'IN', comment: 'LOG + Allow SSH' },
      { proto: 'ANY', srcIp: '0.0.0.0/0', dstIp: '0.0.0.0/0', srcPort: '', dstPort: '', action: 'DROP', dir: 'IN', comment: 'LOG + Drop all other inbound' }
    ]
  }
};

let fwRules = [];
let fwNextId = 1;
let fwPlatform = 'iptables';

function fwParseIptables(text) {
  const parsed = [];
  const lines = text.split('\n');
  for (const line of lines) {
    const t = line.trim();
    if (!t || t.startsWith('#') || t.startsWith(':') || t.startsWith('*') || t === 'COMMIT') continue;
    const r = { proto: 'ANY', srcIp: '0.0.0.0/0', dstIp: '0.0.0.0/0', srcPort: '', dstPort: '', action: 'ALLOW', dir: 'IN', comment: '' };
    const pm = t.match(/-p\s+(tcp|udp|icmp)/i);
    if (pm) r.proto = pm[1].toUpperCase();
    const sm = t.match(/-s\s+(\S+)/);
    if (sm) r.srcIp = sm[1];
    const dm = t.match(/-d\s+(\S+)/);
    if (dm) r.dstIp = dm[1];
    const spm = t.match(/--sport\s+(\S+)/);
    if (spm) r.srcPort = spm[1];
    const dpm = t.match(/--dport\s+(\S+)/);
    if (dpm) r.dstPort = dpm[1];
    if (/-j\s+DROP/i.test(t)) r.action = 'DROP';
    else if (/-j\s+REJECT/i.test(t)) r.action = 'REJECT';
    else if (/-j\s+ACCEPT/i.test(t)) r.action = 'ALLOW';
    if (/-A\s+OUTPUT/i.test(t)) r.dir = 'OUT';
    else if (/-A\s+FORWARD/i.test(t)) r.dir = 'FORWARD';
    const cm = t.match(/--comment\s+"([^"]+)"/);
    if (cm) r.comment = cm[1];
    else r.comment = t.substring(0, 60);
    parsed.push(r);
  }
  return parsed;
}

function fwParseNftables(text) {
  const parsed = [];
  const lines = text.split('\n');
  for (const line of lines) {
    const t = line.trim();
    if (!t || t.startsWith('#') || t.startsWith('table') || t.startsWith('chain') || t === '}') continue;
    const r = { proto: 'ANY', srcIp: '0.0.0.0/0', dstIp: '0.0.0.0/0', srcPort: '', dstPort: '', action: 'ALLOW', dir: 'IN', comment: '' };
    const pm = t.match(/\b(tcp|udp|icmp)\b/i);
    if (pm) r.proto = pm[1].toUpperCase();
    const sm = t.match(/ip\s+saddr\s+(\S+)/);
    if (sm) r.srcIp = sm[1];
    const dm = t.match(/ip\s+daddr\s+(\S+)/);
    if (dm) r.dstIp = dm[1];
    const dpm = t.match(/dport\s+(\S+)/);
    if (dpm) r.dstPort = dpm[1];
    if (/\bdrop\b/i.test(t)) r.action = 'DROP';
    else if (/\breject\b/i.test(t)) r.action = 'REJECT';
    else if (/\baccept\b/i.test(t)) r.action = 'ALLOW';
    if (/output/i.test(t)) r.dir = 'OUT';
    else if (/forward/i.test(t)) r.dir = 'FORWARD';
    r.comment = t.substring(0, 60);
    parsed.push(r);
  }
  return parsed;
}

function fwCidrToRange(cidr) {
  if (!cidr || cidr === '0.0.0.0/0') return { start: 0, end: 0xFFFFFFFF };
  const parts = cidr.split('/');
  const ip = parts[0].split('.').reduce((a, b) => (a << 8) | parseInt(b), 0) >>> 0;
  const mask = parts[1] ? (~0 << (32 - parseInt(parts[1]))) >>> 0 : 0xFFFFFFFF;
  return { start: (ip & mask) >>> 0, end: ((ip & mask) | ~mask) >>> 0 };
}

function fwRangesOverlap(a, b) {
  return a.start <= b.end && b.start <= a.end;
}

function fwPortsOverlap(a, b) {
  if (!a || !b) return true;
  const pa = a.includes(':') ? a.split(':').map(Number) : [Number(a), Number(a)];
  const pb = b.includes(':') ? b.split(':').map(Number) : [Number(b), Number(b)];
  return pa[0] <= pb[1] && pb[0] <= pa[1];
}

function fwDetectConflicts(rules) {
  const conflicts = [];
  for (let i = 0; i < rules.length; i++) {
    for (let j = i + 1; j < rules.length; j++) {
      const a = rules[i], b = rules[j];
      if (a.dir !== b.dir) continue;
      if (a.proto !== 'ANY' && b.proto !== 'ANY' && a.proto !== b.proto) continue;
      const srcA = fwCidrToRange(a.srcIp), srcB = fwCidrToRange(b.srcIp);
      const dstA = fwCidrToRange(a.dstIp), dstB = fwCidrToRange(b.dstIp);
      if (!fwRangesOverlap(srcA, srcB) || !fwRangesOverlap(dstA, dstB)) continue;
      if (!fwPortsOverlap(a.dstPort, b.dstPort)) continue;
      let type = 'overlap';
      if (a.action !== b.action) type = 'contradiction';
      const srcAny = a.srcIp === '0.0.0.0/0', srcBany = b.srcIp === '0.0.0.0/0';
      const dstAny = a.dstPort === '' || a.dstPort === '*', dstBany = b.dstPort === '' || b.dstPort === '*';
      if ((srcAny && !srcBany) || (dstAny && !dstBany)) type = 'shadow';
      conflicts.push({ ruleA: i, ruleB: j, type, a, b });
    }
  }
  return conflicts;
}

function fwRuleToIptables(r) {
  const chain = r.dir === 'OUT' ? 'OUTPUT' : r.dir === 'FORWARD' ? 'FORWARD' : 'INPUT';
  const target = r.action === 'ALLOW' ? 'ACCEPT' : r.action;
  let cmd = `iptables -A ${chain}`;
  if (r.proto !== 'ANY') cmd += ` -p ${r.proto.toLowerCase()}`;
  if (r.srcIp && r.srcIp !== '0.0.0.0/0') cmd += ` -s ${r.srcIp}`;
  if (r.dstIp && r.dstIp !== '0.0.0.0/0') cmd += ` -d ${r.dstIp}`;
  if (r.srcPort) cmd += ` --sport ${r.srcPort}`;
  if (r.dstPort) cmd += ` --dport ${r.dstPort}`;
  cmd += ` -j ${target}`;
  if (r.comment) cmd += ` -m comment --comment "${esc(r.comment)}"`;
  return cmd;
}

function fwRuleToNftables(r) {
  const chain = r.dir === 'OUT' ? 'output' : r.dir === 'FORWARD' ? 'forward' : 'input';
  const action = r.action === 'ALLOW' ? 'accept' : r.action.toLowerCase();
  let cmd = `  `;
  if (r.proto !== 'ANY') cmd += `${r.proto.toLowerCase()} `;
  if (r.srcIp && r.srcIp !== '0.0.0.0/0') cmd += `ip saddr ${r.srcIp} `;
  if (r.dstIp && r.dstIp !== '0.0.0.0/0') cmd += `ip daddr ${r.dstIp} `;
  if (r.dstPort) cmd += `dport ${r.dstPort} `;
  cmd += action;
  if (r.comment) cmd += ` comment "${esc(r.comment)}"`;
  return { chain, rule: cmd };
}

function fwRuleToNetsh(r) {
  const dir = r.dir === 'OUT' ? 'out' : 'in';
  const action = r.action === 'ALLOW' ? 'allow' : 'block';
  const name = r.comment || `Rule_${Date.now()}`;
  let cmd = `netsh advfirewall firewall add rule name="${esc(name)}" dir=${dir} action=${action}`;
  if (r.proto !== 'ANY') cmd += ` protocol=${r.proto}`;
  if (r.srcIp && r.srcIp !== '0.0.0.0/0') cmd += ` remoteip=${r.srcIp}`;
  if (r.dstIp && r.dstIp !== '0.0.0.0/0') cmd += ` localip=${r.dstIp}`;
  if (r.dstPort) cmd += ` localport=${r.dstPort}`;
  return cmd;
}

function fwRuleToPf(r) {
  const action = r.action === 'ALLOW' ? 'pass' : 'block';
  const dir = r.dir === 'OUT' ? 'out' : 'in';
  let cmd = `${action} ${dir}`;
  if (r.proto !== 'ANY') cmd += ` proto ${r.proto.toLowerCase()}`;
  if (r.srcIp && r.srcIp !== '0.0.0.0/0') cmd += ` from ${r.srcIp}`;
  else cmd += ` from any`;
  if (r.dstIp && r.dstIp !== '0.0.0.0/0') cmd += ` to ${r.dstIp}`;
  else cmd += ` to any`;
  if (r.dstPort) cmd += ` port ${r.dstPort}`;
  return cmd;
}

function fwRuleToCisco(r, i) {
  const action = r.action === 'ALLOW' ? 'permit' : 'deny';
  const proto = r.proto === 'ANY' ? 'ip' : r.proto.toLowerCase();
  const src = r.srcIp === '0.0.0.0/0' ? 'any' : r.srcIp;
  const dst = r.dstIp === '0.0.0.0/0' ? 'any' : r.dstIp;
  let cmd = `access-list 100 ${action} ${proto} ${src} ${dst}`;
  if (r.dstPort && proto !== 'ip' && proto !== 'icmp') cmd += ` eq ${r.dstPort}`;
  return cmd;
}

function fwGenerateAll(rules, platform) {
  if (platform === 'nftables') {
    const chains = { input: [], output: [], forward: [] };
    rules.forEach(r => {
      const { chain, rule } = fwRuleToNftables(r);
      chains[chain].push(rule);
    });
    let out = '#!/usr/sbin/nft -f\nflush ruleset\n\ntable inet filter {\n';
    for (const [ch, rr] of Object.entries(chains)) {
      if (rr.length === 0) continue;
      out += `  chain ${ch} {\n    type filter hook ${ch} priority 0; policy drop;\n`;
      rr.forEach(r => out += `  ${r}\n`);
      out += `  }\n`;
    }
    out += '}\n';
    return out;
  }
  const gen = { iptables: fwRuleToIptables, netsh: fwRuleToNetsh, pf: fwRuleToPf, cisco: fwRuleToCisco };
  const fn = gen[platform];
  if (!fn) return rules.map((r, i) => fwRuleToIptables(r)).join('\n');
  let header = '';
  if (platform === 'iptables') header = '#!/bin/bash\n# Generated by Darknode Firewall Rule Generator\n# Flush existing rules\niptables -F\niptables -X\n\n# Default policies\niptables -P INPUT DROP\niptables -P FORWARD DROP\niptables -P OUTPUT ACCEPT\n\n# Allow established connections\niptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\niptables -A INPUT -i lo -j ACCEPT\n\n';
  else if (platform === 'pf') header = '# pf.conf — Generated by Darknode Firewall Rule Generator\nset skip on lo0\nblock all\npass out all keep state\n\n';
  else if (platform === 'cisco') header = '! Cisco ACL — Generated by Darknode Firewall Rule Generator\nno access-list 100\n\n';
  else if (platform === 'netsh') header = 'REM Windows Firewall Rules — Generated by Darknode Firewall Rule Generator\nREM Reset firewall\nnetsh advfirewall reset\n\n';
  return header + rules.map((r, i) => fn(r, i)).join('\n') + '\n';
}

function fwRenderBuilder(wrap) {
  const bld = document.createElement('div');
  bld.className = 'fw-builder';
  bld.innerHTML = `
    <div class="fw-form">
      <div class="fw-form-row">
        <label class="fw-label">Protocol<select class="fw-select fw-proto">${FW_PROTOCOLS.map(p => `<option value="${p}">${p}</option>`).join('')}</select></label>
        <label class="fw-label">Direction<select class="fw-select fw-dir">${FW_DIRECTIONS.map(d => `<option value="${d}">${d}</option>`).join('')}</select></label>
        <label class="fw-label">Action<select class="fw-select fw-action">${FW_ACTIONS.map(a => `<option value="${a}">${a}</option>`).join('')}</select></label>
      </div>
      <div class="fw-form-row">
        <label class="fw-label">Source IP/CIDR<input class="fw-input fw-src-ip" placeholder="0.0.0.0/0" value="0.0.0.0/0"></label>
        <label class="fw-label">Source Port<input class="fw-input fw-src-port" placeholder="Any"></label>
      </div>
      <div class="fw-form-row">
        <label class="fw-label">Dest IP/CIDR<input class="fw-input fw-dst-ip" placeholder="0.0.0.0/0" value="0.0.0.0/0"></label>
        <label class="fw-label">Dest Port<input class="fw-input fw-dst-port" placeholder="Any"></label>
      </div>
      <div class="fw-form-row">
        <label class="fw-label" style="flex:1">Comment<input class="fw-input fw-comment" placeholder="Rule description" style="width:100%"></label>
        <button class="fw-btn fw-add-btn">+ Add Rule</button>
      </div>
    </div>
    <div class="fw-platform-bar">
      <span class="fw-plat-label">Output Platform:</span>
      ${Object.entries(FW_PLATFORMS).map(([k, v]) => `<button class="fw-plat-btn${k === fwPlatform ? ' active' : ''}" data-plat="${k}">${v}</button>`).join('')}
    </div>
    <div class="fw-rules-list"></div>
  `;
  bld.querySelector('.fw-add-btn').addEventListener('click', () => {
    const rule = {
      id: fwNextId++,
      proto: bld.querySelector('.fw-proto').value,
      dir: bld.querySelector('.fw-dir').value,
      action: bld.querySelector('.fw-action').value,
      srcIp: bld.querySelector('.fw-src-ip').value || '0.0.0.0/0',
      srcPort: bld.querySelector('.fw-src-port').value,
      dstIp: bld.querySelector('.fw-dst-ip').value || '0.0.0.0/0',
      dstPort: bld.querySelector('.fw-dst-port').value,
      comment: bld.querySelector('.fw-comment').value
    };
    fwRules.push(rule);
    fwRenderRulesList(bld.querySelector('.fw-rules-list'));
    bld.querySelector('.fw-comment').value = '';
    bld.querySelector('.fw-src-port').value = '';
    bld.querySelector('.fw-dst-port').value = '';
  });
  bld.querySelectorAll('.fw-plat-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      fwPlatform = btn.dataset.plat;
      bld.querySelectorAll('.fw-plat-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
    });
  });
  fwRenderRulesList(bld.querySelector('.fw-rules-list'));
  wrap.appendChild(bld);
}

function fwRenderRulesList(el) {
  if (fwRules.length === 0) {
    el.innerHTML = '<div class="fw-empty">No rules added yet. Use the form above or load a template.</div>';
    return;
  }
  el.innerHTML = `<table class="fw-table"><thead><tr><th>#</th><th>Proto</th><th>Source</th><th>Dest</th><th>Port</th><th>Action</th><th>Dir</th><th>Comment</th><th></th></tr></thead><tbody>${
    fwRules.map((r, i) => {
      const actClass = r.action === 'ALLOW' ? 'fw-act-allow' : r.action === 'DROP' ? 'fw-act-drop' : r.action === 'DENY' ? 'fw-act-deny' : 'fw-act-reject';
      return `<tr>
        <td class="fw-num">${i + 1}</td>
        <td><span class="fw-badge fw-badge-proto">${esc(r.proto)}</span></td>
        <td class="fw-mono">${esc(r.srcIp)}${r.srcPort ? ':' + esc(r.srcPort) : ''}</td>
        <td class="fw-mono">${esc(r.dstIp)}</td>
        <td class="fw-mono">${esc(r.dstPort) || '*'}</td>
        <td><span class="fw-badge ${actClass}">${esc(r.action)}</span></td>
        <td><span class="fw-badge fw-badge-dir">${esc(r.dir)}</span></td>
        <td class="fw-comment-cell">${esc(r.comment)}</td>
        <td class="fw-actions">
          <button class="fw-btn-sm fw-move-up" data-i="${i}" title="Move up">&uarr;</button>
          <button class="fw-btn-sm fw-move-dn" data-i="${i}" title="Move down">&darr;</button>
          <button class="fw-btn-sm fw-del-rule" data-i="${i}" title="Delete">&times;</button>
        </td>
      </tr>`;
    }).join('')
  }</tbody></table>`;
  el.querySelectorAll('.fw-del-rule').forEach(b => b.addEventListener('click', () => { fwRules.splice(+b.dataset.i, 1); fwRenderRulesList(el); }));
  el.querySelectorAll('.fw-move-up').forEach(b => b.addEventListener('click', () => { const i = +b.dataset.i; if (i > 0) { [fwRules[i - 1], fwRules[i]] = [fwRules[i], fwRules[i - 1]]; fwRenderRulesList(el); } }));
  el.querySelectorAll('.fw-move-dn').forEach(b => b.addEventListener('click', () => { const i = +b.dataset.i; if (i < fwRules.length - 1) { [fwRules[i], fwRules[i + 1]] = [fwRules[i + 1], fwRules[i]]; fwRenderRulesList(el); } }));
}

function fwRenderTemplates(wrap) {
  const tmpl = document.createElement('div');
  tmpl.className = 'fw-templates';
  tmpl.innerHTML = Object.entries(FW_TEMPLATES).map(([k, t]) => `
    <div class="fw-tmpl-card">
      <div class="fw-tmpl-head">
        <span class="fw-tmpl-name">${esc(t.name)}</span>
        <span class="fw-tmpl-count">${t.rules.length} rules</span>
      </div>
      <div class="fw-tmpl-desc">${esc(t.desc)}</div>
      <div class="fw-tmpl-preview">${t.rules.map(r => `<div class="fw-tmpl-rule"><span class="fw-badge ${r.action === 'ALLOW' ? 'fw-act-allow' : 'fw-act-drop'}">${r.action}</span> ${esc(r.comment)}</div>`).join('')}</div>
      <div class="fw-tmpl-actions">
        <button class="fw-btn fw-load-tmpl" data-k="${k}">Load Template</button>
        <button class="fw-btn fw-append-tmpl" data-k="${k}">Append to Rules</button>
      </div>
    </div>
  `).join('');
  tmpl.querySelectorAll('.fw-load-tmpl').forEach(b => b.addEventListener('click', () => {
    fwRules = FW_TEMPLATES[b.dataset.k].rules.map(r => ({ ...r, id: fwNextId++ }));
    wrap.closest('.fw-wrap').querySelector('.fw-tab[data-tab="builder"]').click();
  }));
  tmpl.querySelectorAll('.fw-append-tmpl').forEach(b => b.addEventListener('click', () => {
    FW_TEMPLATES[b.dataset.k].rules.forEach(r => fwRules.push({ ...r, id: fwNextId++ }));
    wrap.closest('.fw-wrap').querySelector('.fw-tab[data-tab="builder"]').click();
  }));
  wrap.appendChild(tmpl);
}

function fwRenderImport(wrap) {
  const imp = document.createElement('div');
  imp.className = 'fw-import';
  imp.innerHTML = `
    <div class="fw-import-head">Import & Analyze Existing Rules</div>
    <div class="fw-import-format">
      <label><input type="radio" name="fw-import-fmt" value="iptables" checked> iptables</label>
      <label><input type="radio" name="fw-import-fmt" value="nftables"> nftables</label>
    </div>
    <textarea class="fw-import-area" placeholder="Paste your iptables or nftables rules here...\n\nExample:\niptables -A INPUT -p tcp --dport 22 -j ACCEPT\niptables -A INPUT -p tcp --dport 80 -j ACCEPT\niptables -A INPUT -j DROP" rows="12"></textarea>
    <div class="fw-import-actions">
      <button class="fw-btn fw-parse-btn">Parse & Import</button>
      <button class="fw-btn fw-analyze-btn">Analyze Only</button>
    </div>
    <div class="fw-import-result"></div>
  `;
  imp.querySelector('.fw-parse-btn').addEventListener('click', () => {
    const text = imp.querySelector('.fw-import-area').value;
    const fmt = imp.querySelector('input[name="fw-import-fmt"]:checked').value;
    const parsed = fmt === 'nftables' ? fwParseNftables(text) : fwParseIptables(text);
    if (parsed.length === 0) {
      imp.querySelector('.fw-import-result').innerHTML = '<div class="fw-warn">No rules found. Check the format.</div>';
      return;
    }
    parsed.forEach(r => fwRules.push({ ...r, id: fwNextId++ }));
    imp.querySelector('.fw-import-result').innerHTML = `<div class="fw-success">Imported ${parsed.length} rules. Switch to Builder to view.</div>`;
  });
  imp.querySelector('.fw-analyze-btn').addEventListener('click', () => {
    const text = imp.querySelector('.fw-import-area').value;
    const fmt = imp.querySelector('input[name="fw-import-fmt"]:checked').value;
    const parsed = fmt === 'nftables' ? fwParseNftables(text) : fwParseIptables(text);
    const res = imp.querySelector('.fw-import-result');
    if (parsed.length === 0) { res.innerHTML = '<div class="fw-warn">No rules found.</div>'; return; }
    const conflicts = fwDetectConflicts(parsed);
    let html = `<div class="fw-analysis"><div class="fw-analysis-head">Analysis of ${parsed.length} rules</div>`;
    html += `<div class="fw-stat-row">
      <div class="fw-stat"><span class="fw-stat-num">${parsed.length}</span><span class="fw-stat-label">Total Rules</span></div>
      <div class="fw-stat"><span class="fw-stat-num">${parsed.filter(r => r.action === 'ALLOW').length}</span><span class="fw-stat-label">Allow</span></div>
      <div class="fw-stat"><span class="fw-stat-num">${parsed.filter(r => r.action !== 'ALLOW').length}</span><span class="fw-stat-label">Block/Drop</span></div>
      <div class="fw-stat"><span class="fw-stat-num fw-stat-warn">${conflicts.length}</span><span class="fw-stat-label">Conflicts</span></div>
    </div>`;
    if (conflicts.length > 0) {
      html += '<div class="fw-conflict-list">';
      conflicts.forEach(c => {
        const icon = c.type === 'contradiction' ? '!' : c.type === 'shadow' ? '◐' : '⬤';
        html += `<div class="fw-conflict-item fw-conflict-${c.type}"><span class="fw-conflict-icon">${icon}</span><strong>${c.type.toUpperCase()}</strong>: Rule ${c.ruleA + 1} (${esc(c.a.action)} ${esc(c.a.proto)} :${esc(c.a.dstPort) || '*'}) vs Rule ${c.ruleB + 1} (${esc(c.b.action)} ${esc(c.b.proto)} :${esc(c.b.dstPort) || '*'})</div>`;
      });
      html += '</div>';
    } else {
      html += '<div class="fw-success">No conflicts detected in the ruleset.</div>';
    }
    html += '</div>';
    res.innerHTML = html;
  });
  wrap.appendChild(imp);
}

function fwRenderConflicts(wrap) {
  const con = document.createElement('div');
  con.className = 'fw-conflicts';
  if (fwRules.length < 2) {
    con.innerHTML = '<div class="fw-empty">Add at least 2 rules to check for conflicts.</div>';
    wrap.appendChild(con);
    return;
  }
  const conflicts = fwDetectConflicts(fwRules);
  let html = `<div class="fw-conflict-head">Conflict Analysis — ${fwRules.length} rules</div>`;
  if (conflicts.length === 0) {
    html += '<div class="fw-success fw-big-success"><span class="fw-check">OK</span> No conflicts detected. Your ruleset looks clean.</div>';
  } else {
    html += `<div class="fw-warn">${conflicts.length} potential issue(s) found</div>`;
    html += '<div class="fw-conflict-list">';
    conflicts.forEach(c => {
      const typeLabel = { contradiction: 'CONTRADICTING RULES', shadow: 'SHADOWED RULE', overlap: 'OVERLAPPING RULES' };
      const typeClass = `fw-conflict-${c.type}`;
      html += `<div class="fw-conflict-card ${typeClass}">
        <div class="fw-conflict-type">${typeLabel[c.type] || 'ISSUE'}</div>
        <div class="fw-conflict-detail">
          <div class="fw-conflict-rule">Rule #${c.ruleA + 1}: <span class="fw-badge ${c.a.action === 'ALLOW' ? 'fw-act-allow' : 'fw-act-drop'}">${esc(c.a.action)}</span> ${esc(c.a.proto)} ${esc(c.a.srcIp)} → ${esc(c.a.dstIp)}:${esc(c.a.dstPort) || '*'} (${esc(c.a.dir)})</div>
          <div class="fw-conflict-vs">↕ conflicts with ↕</div>
          <div class="fw-conflict-rule">Rule #${c.ruleB + 1}: <span class="fw-badge ${c.b.action === 'ALLOW' ? 'fw-act-allow' : 'fw-act-drop'}">${esc(c.b.action)}</span> ${esc(c.b.proto)} ${esc(c.b.srcIp)} → ${esc(c.b.dstIp)}:${esc(c.b.dstPort) || '*'} (${esc(c.b.dir)})</div>
        </div>
        ${c.type === 'shadow' ? '<div class="fw-conflict-tip">The broader rule shadows the narrower one — reorder or remove.</div>' : ''}
        ${c.type === 'contradiction' ? '<div class="fw-conflict-tip">These rules match similar traffic but take opposite actions.</div>' : ''}
      </div>`;
    });
    html += '</div>';
  }
  con.innerHTML = html;
  wrap.appendChild(con);
}

function fwRenderExport(wrap) {
  const exp = document.createElement('div');
  exp.className = 'fw-export';
  if (fwRules.length === 0) {
    exp.innerHTML = '<div class="fw-empty">No rules to export. Add rules in the Builder tab.</div>';
    wrap.appendChild(exp);
    return;
  }
  const platforms = Object.entries(FW_PLATFORMS);
  exp.innerHTML = `
    <div class="fw-export-head">Export Rules (${fwRules.length} rules)</div>
    <div class="fw-export-tabs">${platforms.map(([k, v]) => `<button class="fw-exp-tab${k === fwPlatform ? ' active' : ''}" data-p="${k}">${v}</button>`).join('')}</div>
    <pre class="fw-export-code">${esc(fwGenerateAll(fwRules, fwPlatform))}</pre>
    <div class="fw-export-actions">
      <button class="fw-btn fw-copy-btn">Copy to Clipboard</button>
      <button class="fw-btn fw-download-btn">Download as File</button>
    </div>
  `;
  exp.querySelectorAll('.fw-exp-tab').forEach(t => t.addEventListener('click', () => {
    exp.querySelectorAll('.fw-exp-tab').forEach(b => b.classList.remove('active'));
    t.classList.add('active');
    fwPlatform = t.dataset.p;
    exp.querySelector('.fw-export-code').textContent = fwGenerateAll(fwRules, fwPlatform);
  }));
  exp.querySelector('.fw-copy-btn').addEventListener('click', () => {
    const code = exp.querySelector('.fw-export-code').textContent;
    navigator.clipboard.writeText(code).then(() => {
      const btn = exp.querySelector('.fw-copy-btn');
      btn.textContent = 'Copied!';
      setTimeout(() => btn.textContent = 'Copy to Clipboard', 1500);
    });
  });
  exp.querySelector('.fw-download-btn').addEventListener('click', () => {
    const code = exp.querySelector('.fw-export-code').textContent;
    const ext = { iptables: 'sh', nftables: 'nft', netsh: 'bat', pf: 'conf', cisco: 'txt' };
    const blob = new Blob([code], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `firewall-rules.${ext[fwPlatform] || 'txt'}`;
    a.click();
    URL.revokeObjectURL(a.href);
  });
  wrap.appendChild(exp);
}

export function renderFirewallRules(container) {
  fwRules = [];
  fwNextId = 1;
  fwPlatform = 'iptables';
  const style = document.createElement('style');
  style.textContent = `
.fw-wrap{font-family:'Courier New',monospace;color:#c8d6e5;max-width:1200px;margin:0 auto;padding:20px}
.fw-header{display:flex;align-items:center;justify-content:space-between;padding:16px 24px;background:linear-gradient(135deg,#0a0e14,#0f172a);border:1px solid #1a2a44;border-radius:10px;margin-bottom:20px}
.fw-title{font-size:1.4em;font-weight:700;color:#00aaff}
.fw-subtitle{font-size:.85em;color:#6a8a9e;margin-top:4px}
.fw-tabs{display:flex;gap:4px;background:#0a0e14;border:1px solid #1a2a44;border-radius:8px;padding:4px;margin-bottom:20px}
.fw-tab{padding:10px 20px;background:transparent;color:#6a8a9e;border:none;border-radius:6px;cursor:pointer;font-family:inherit;font-size:.85em;transition:all .2s}
.fw-tab:hover{color:#c8d6e5;background:rgba(0,170,255,.08)}
.fw-tab.active{background:rgba(0,170,255,.15);color:#00aaff;font-weight:600}
.fw-content{background:#0c1020;border:1px solid #1a2a44;border-radius:10px;padding:24px}
.fw-form{display:flex;flex-direction:column;gap:12px;margin-bottom:20px;padding:20px;background:#0a0e14;border:1px solid #1a2a44;border-radius:8px}
.fw-form-row{display:flex;gap:12px;flex-wrap:wrap}
.fw-label{display:flex;flex-direction:column;gap:4px;font-size:.8em;color:#6a8a9e;flex:1;min-width:140px}
.fw-select,.fw-input{background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:8px 12px;color:#c8d6e5;font-family:inherit;font-size:.9em}
.fw-select:focus,.fw-input:focus{border-color:#00aaff;outline:none;box-shadow:0 0 0 2px rgba(0,170,255,.15)}
.fw-btn{padding:10px 20px;background:#00aaff;color:#0a0e14;border:none;border-radius:6px;cursor:pointer;font-family:inherit;font-weight:600;font-size:.85em;transition:all .2s}
.fw-btn:hover{background:#33bbff;transform:translateY(-1px)}
.fw-add-btn{align-self:flex-end;margin-top:auto}
.fw-platform-bar{display:flex;align-items:center;gap:8px;margin-bottom:16px;flex-wrap:wrap}
.fw-plat-label{font-size:.8em;color:#6a8a9e}
.fw-plat-btn{padding:6px 14px;background:#0a0e14;border:1px solid #1a2a44;border-radius:6px;color:#6a8a9e;cursor:pointer;font-family:inherit;font-size:.78em;transition:all .2s}
.fw-plat-btn:hover{border-color:#00aaff;color:#00aaff}
.fw-plat-btn.active{background:rgba(0,170,255,.12);border-color:#00aaff;color:#00aaff}
.fw-table{width:100%;border-collapse:collapse;font-size:.82em}
.fw-table th{text-align:left;padding:10px 12px;background:#0a0e14;color:#6a8a9e;font-weight:600;border-bottom:2px solid #1a2a44;font-size:.8em;text-transform:uppercase;letter-spacing:.5px}
.fw-table td{padding:8px 12px;border-bottom:1px solid rgba(26,42,68,.5)}
.fw-table tr:hover{background:rgba(0,170,255,.04)}
.fw-num{color:#445;font-weight:600;width:30px}
.fw-mono{font-family:'Courier New',monospace;font-size:.88em}
.fw-badge{display:inline-block;padding:2px 10px;border-radius:4px;font-size:.78em;font-weight:600}
.fw-badge-proto{background:rgba(0,170,255,.12);color:#00aaff}
.fw-badge-dir{background:rgba(200,214,229,.1);color:#8ab4d0}
.fw-act-allow{background:rgba(0,230,136,.12);color:#00e688}
.fw-act-drop{background:rgba(255,68,68,.12);color:#ff4444}
.fw-act-deny{background:rgba(255,145,0,.12);color:#ff9100}
.fw-act-reject{background:rgba(255,215,0,.12);color:#ffd700}
.fw-comment-cell{color:#6a8a9e;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.fw-actions{display:flex;gap:4px;white-space:nowrap}
.fw-btn-sm{width:28px;height:28px;display:flex;align-items:center;justify-content:center;background:#0a0e14;border:1px solid #1a2a44;border-radius:4px;color:#6a8a9e;cursor:pointer;font-size:.9em;transition:all .2s}
.fw-btn-sm:hover{border-color:#00aaff;color:#00aaff}
.fw-empty{text-align:center;padding:40px;color:#445;font-size:.9em}
.fw-templates{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:16px}
.fw-tmpl-card{background:#0a0e14;border:1px solid #1a2a44;border-radius:8px;padding:20px;transition:border-color .2s}
.fw-tmpl-card:hover{border-color:rgba(0,170,255,.3)}
.fw-tmpl-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
.fw-tmpl-name{font-weight:600;color:#00aaff;font-size:.95em}
.fw-tmpl-count{font-size:.75em;color:#445;background:#0c1020;padding:2px 8px;border-radius:4px}
.fw-tmpl-desc{font-size:.82em;color:#6a8a9e;margin-bottom:12px}
.fw-tmpl-preview{display:flex;flex-direction:column;gap:4px;margin-bottom:14px}
.fw-tmpl-rule{font-size:.78em;color:#8ab4d0;padding:4px 0}
.fw-tmpl-actions{display:flex;gap:8px}
.fw-tmpl-actions .fw-btn{flex:1;padding:8px 12px;font-size:.8em}
.fw-tmpl-actions .fw-append-tmpl{background:transparent;border:1px solid #00aaff;color:#00aaff}
.fw-tmpl-actions .fw-append-tmpl:hover{background:rgba(0,170,255,.1)}
.fw-import{display:flex;flex-direction:column;gap:16px}
.fw-import-head{font-size:1.05em;font-weight:600;color:#00aaff}
.fw-import-format{display:flex;gap:16px;font-size:.85em;color:#8ab4d0}
.fw-import-format label{cursor:pointer;display:flex;align-items:center;gap:4px}
.fw-import-area{background:#0a0e14;border:1px solid #1a2a44;border-radius:8px;padding:16px;color:#c8d6e5;font-family:'Courier New',monospace;font-size:.85em;resize:vertical;min-height:200px}
.fw-import-area:focus{border-color:#00aaff;outline:none}
.fw-import-actions{display:flex;gap:8px}
.fw-import-actions .fw-analyze-btn{background:transparent;border:1px solid #00aaff;color:#00aaff}
.fw-warn{color:#ff9100;padding:12px;background:rgba(255,145,0,.08);border-radius:6px;font-size:.85em}
.fw-success{color:#00e688;padding:12px;background:rgba(0,230,136,.08);border-radius:6px;font-size:.85em}
.fw-analysis-head{font-weight:600;color:#c8d6e5;margin-bottom:12px}
.fw-stat-row{display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap}
.fw-stat{background:#0a0e14;border:1px solid #1a2a44;border-radius:8px;padding:14px 20px;flex:1;min-width:100px;text-align:center}
.fw-stat-num{display:block;font-size:1.5em;font-weight:700;color:#00aaff}
.fw-stat-num.fw-stat-warn{color:#ff4444}
.fw-stat-label{font-size:.75em;color:#6a8a9e;margin-top:4px;display:block}
.fw-conflict-list{display:flex;flex-direction:column;gap:10px}
.fw-conflict-item{padding:10px 14px;border-radius:6px;font-size:.83em;display:flex;align-items:center;gap:10px}
.fw-conflict-icon{font-size:1.1em}
.fw-conflict-contradiction{background:rgba(255,68,68,.08);border-left:3px solid #ff4444;color:#ff8a8a}
.fw-conflict-shadow{background:rgba(255,145,0,.08);border-left:3px solid #ff9100;color:#ffb74d}
.fw-conflict-overlap{background:rgba(0,170,255,.08);border-left:3px solid #00aaff;color:#66ccff}
.fw-conflict-head{font-size:1.05em;font-weight:600;color:#00aaff;margin-bottom:16px}
.fw-big-success{text-align:center;padding:30px;font-size:1em}
.fw-check{font-size:2em;display:block;margin-bottom:8px;color:#00e688}
.fw-conflict-card{background:#0a0e14;border:1px solid #1a2a44;border-radius:8px;padding:16px;margin-bottom:10px}
.fw-conflict-type{font-size:.78em;font-weight:700;letter-spacing:.5px;margin-bottom:10px}
.fw-conflict-contradiction .fw-conflict-type{color:#ff4444}
.fw-conflict-shadow .fw-conflict-type{color:#ff9100}
.fw-conflict-overlap .fw-conflict-type{color:#00aaff}
.fw-conflict-detail{display:flex;flex-direction:column;gap:6px}
.fw-conflict-rule{font-size:.85em;color:#c8d6e5}
.fw-conflict-vs{text-align:center;color:#445;font-size:.78em;padding:2px 0}
.fw-conflict-tip{margin-top:10px;font-size:.8em;color:#6a8a9e;font-style:italic}
.fw-export-head{font-size:1.05em;font-weight:600;color:#00aaff;margin-bottom:16px}
.fw-export-tabs{display:flex;gap:4px;flex-wrap:wrap;margin-bottom:16px}
.fw-exp-tab{padding:8px 16px;background:#0a0e14;border:1px solid #1a2a44;border-radius:6px;color:#6a8a9e;cursor:pointer;font-family:inherit;font-size:.78em;transition:all .2s}
.fw-exp-tab:hover{border-color:#00aaff;color:#00aaff}
.fw-exp-tab.active{background:rgba(0,170,255,.12);border-color:#00aaff;color:#00aaff}
.fw-export-code{background:#0a0e14;border:1px solid #1a2a44;border-radius:8px;padding:20px;color:#00e688;font-family:'Courier New',monospace;font-size:.82em;line-height:1.6;overflow-x:auto;white-space:pre;max-height:500px;overflow-y:auto;margin-bottom:16px}
.fw-export-actions{display:flex;gap:8px}
.fw-export-actions .fw-download-btn{background:transparent;border:1px solid #00aaff;color:#00aaff}
@media(max-width:768px){
.fw-form-row{flex-direction:column}
.fw-table{font-size:.75em}
.fw-table th:nth-child(3),.fw-table td:nth-child(3){display:none}
.fw-templates{grid-template-columns:1fr}
.fw-stat-row{flex-direction:column}
.fw-export-tabs{flex-direction:column}
}
  `;
  container.innerHTML = '';
  container.appendChild(style);
  const wrap = document.createElement('div');
  wrap.className = 'fw-wrap';
  wrap.innerHTML = `
    <div class="fw-header">
      <div><div class="fw-title">Firewall Rule Generator</div><div class="fw-subtitle">Multi-platform firewall rule builder, analyzer &amp; exporter</div></div>
    </div>
    <div class="fw-tabs">
      <button class="fw-tab active" data-tab="builder">Builder</button>
      <button class="fw-tab" data-tab="templates">Templates</button>
      <button class="fw-tab" data-tab="import">Import / Analyze</button>
      <button class="fw-tab" data-tab="conflicts">Conflicts</button>
      <button class="fw-tab" data-tab="export">Export</button>
    </div>
    <div class="fw-content"></div>
  `;
  container.appendChild(wrap);
  const content = wrap.querySelector('.fw-content');
  const tabs = wrap.querySelectorAll('.fw-tab');
  function showTab(tab) {
    tabs.forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    content.innerHTML = '';
    const name = tab.dataset.tab;
    if (name === 'builder') fwRenderBuilder(content);
    else if (name === 'templates') fwRenderTemplates(content);
    else if (name === 'import') fwRenderImport(content);
    else if (name === 'conflicts') fwRenderConflicts(content);
    else if (name === 'export') fwRenderExport(content);
  }
  tabs.forEach(t => t.addEventListener('click', () => showTab(t)));
  showTab(tabs[0]);
}
