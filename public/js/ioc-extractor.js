import { esc } from '/js/shared.js';

const IOC_PATTERNS = {
  ipv4: { regex: /(?:^|[\s,;|"'(<\[])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?=[\s,;|"')>\]]|$)/gm, label: 'IPv4 Addresses', icon: 'IP4' },
  ipv6: { regex: /(?:^|[\s,;|])([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7})(?=[\s,;|]|$)/gm, label: 'IPv6 Addresses', icon: 'IP6' },
  domain: { regex: /(?:^|[\s,;|"'(<\[])([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.(?:com|net|org|io|xyz|ru|cn|ir|kp|info|biz|co|uk|de|fr|jp|br|in|au|ca|gov|edu|mil|int|top|tk|ml|ga|cf|gq|cc|tv|us|me|pro|name|club|site|online|store|tech|fun|icu|buzz|space|dev|app|ai))(?=[\s,;|"')>\]]|$)/gim, label: 'Domains', icon: 'DNS' },
  url: { regex: /https?:\/\/[^\s<>"')\]]+/gi, label: 'URLs', icon: 'URL' },
  email: { regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi, label: 'Email Addresses', icon: 'MAIL' },
  md5: { regex: /\b([a-fA-F0-9]{32})\b/g, label: 'MD5 Hashes', icon: 'MD5' },
  sha1: { regex: /\b([a-fA-F0-9]{40})\b/g, label: 'SHA-1 Hashes', icon: 'SHA1' },
  sha256: { regex: /\b([a-fA-F0-9]{64})\b/g, label: 'SHA-256 Hashes', icon: 'SHA256' },
  cve: { regex: /CVE-\d{4}-\d{4,}/gi, label: 'CVE IDs', icon: 'CVE' },
  mac: { regex: /\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g, label: 'MAC Addresses', icon: 'MAC' },
  registry: { regex: /(?:HKLM|HKCU|HKCR|HKU|HKCC)\\[\w\\]+/gi, label: 'Registry Keys', icon: 'REG' },
  filepath: { regex: /(?:[A-Z]:\\(?:[\w.-]+\\)*[\w.-]+|\/(?:[\w.-]+\/)*[\w.-]+\.\w+)/g, label: 'File Paths', icon: 'FILE' },
  btc: { regex: /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g, label: 'Bitcoin Addresses', icon: 'BTC' },
};

const SAMPLE_TEXT = `Incident Report - APT29 Campaign Analysis
Date: 2026-09-18

## Network Indicators

The threat actor established C2 communications with the following infrastructure:
- Primary C2: 185.220.101.34 (resolved from evil-update[.]com)
- Secondary C2: 91.219.237.229
- Backup domain: data-exfil[.]xyz
- Fallback URL: https://cdn-update.suspicious-domain.ru/payload.bin

## Email Indicators
Phishing emails originated from: attacker@evil-update.com
Reply-to address: support@legitimate-lookalike.com

## File Indicators
Dropper hash (MD5): d41d8cd98f00b204e9800998ecf8427e
Payload hash (SHA-256): e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Secondary payload (SHA-1): da39a3ee5e6b4b0d3255bfef95601890afd80709

## Vulnerabilities Exploited
- CVE-2024-21887 (Ivanti Connect Secure)
- CVE-2023-46805 (Ivanti authentication bypass)

## Host Indicators
Registry persistence: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\UpdateService
Dropped file: C:\\Users\\Public\\Downloads\\svchost_update.exe
MAC address of compromised host: AA:BB:CC:DD:EE:FF

## Financial
Bitcoin wallet for ransom: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa`;

function extractIOCs(text) {
  var results = {};
  var seen = {};
  Object.keys(IOC_PATTERNS).forEach(function(type) {
    var p = IOC_PATTERNS[type];
    var matches = [];
    var m;
    var re = new RegExp(p.regex.source, p.regex.flags);
    while ((m = re.exec(text)) !== null) {
      var val = m[1] || m[0];
      val = val.trim().replace(/[,;|"'<>\[\]()]+$/, '');
      if (!seen[type + ':' + val.toLowerCase()]) {
        seen[type + ':' + val.toLowerCase()] = true;
        matches.push(val);
      }
    }
    if (type === 'ipv4') matches = matches.filter(function(ip) { return ip.split('.').every(function(o) { return parseInt(o) <= 255; }); });
    if (type === 'ipv6') matches = matches.filter(function(ip) { return !/^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/.test(ip); });
    if (type === 'sha256') matches = matches.filter(function(h) { return !seen['sha1:' + h.substring(0, 40).toLowerCase()] || h.length === 64; });
    if (matches.length > 0) results[type] = matches;
  });
  return results;
}

// IOC type -> Security Graph entity type
var GRAPH_TYPE = { ipv4: 'IP', ipv6: 'IP', domain: 'DOMAIN', cve: 'VULNERABILITY' };

function iocGraphItems(iocs) {
  var items = [];
  Object.keys(iocs).forEach(function(type) {
    iocs[type].forEach(function(v) {
      items.push({
        type: GRAPH_TYPE[type] || 'INDICATOR',
        name: v,
        data: { iocType: type },
        opts: { tags: ['ioc', type] }
      });
    });
  });
  return items;
}

function defang(val) {
  return val.replace(/\./g, '[.]').replace(/http/gi, 'hxxp').replace(/:\/\//g, '://');
}

function refang(val) {
  return val.replace(/\[\.\]/g, '.').replace(/hxxp/gi, 'http');
}

export function renderIOCExtractor(container) {
  var activeTab = 'extract';
  var rawInput = '';
  var iocs = {};
  var defanged = false;

  var CSS = '<style>' +
    '.ioc-wrap{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#c8d6e5;max-width:1100px}' +
    '.ioc-title{font-size:1.6rem;font-weight:700;margin:0 0 6px;color:var(--txt)}' +
    '.ioc-sub{color:var(--mut);font-size:.85rem;margin-bottom:20px;line-height:1.5}' +
    '.ioc-tabs{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:24px}' +
    '.ioc-tab{background:var(--card);border:1px solid var(--line);color:var(--mut);padding:8px 16px;font-size:.75rem;font-weight:600;letter-spacing:.04em;text-transform:uppercase;cursor:pointer;border-radius:4px;transition:all .15s;font-family:inherit}' +
    '.ioc-tab:hover{background:color-mix(in srgb,var(--acc) 8%,var(--card));color:var(--txt)}' +
    '.ioc-tab.active{background:var(--acc);color:var(--on-acc,#fff);border-color:var(--acc)}' +
    '.ioc-panel{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:20px;margin-bottom:16px}' +
    '.ioc-panel-title{font-size:.8rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--acc);margin-bottom:12px}' +
    '.ioc-textarea{width:100%;min-height:200px;background:var(--card2,#0a0e14);border:1px solid var(--line);color:var(--txt);font-family:ui-monospace,monospace;font-size:.75rem;padding:12px;border-radius:6px;resize:vertical}' +
    '.ioc-textarea:focus{border-color:var(--acc);outline:none}' +
    '.ioc-btn{background:var(--acc);color:var(--on-acc,#fff);border:1px solid var(--acc);padding:8px 16px;border-radius:6px;font-size:.78rem;font-weight:600;cursor:pointer;font-family:inherit;transition:all .15s}' +
    '.ioc-btn:hover{opacity:.9}' +
    '.ioc-btn.ghost{background:transparent;color:var(--acc);border-color:var(--line)}' +
    '.ioc-btn.ghost:hover{border-color:var(--acc);background:color-mix(in srgb,var(--acc) 8%,transparent)}' +
    '.ioc-btn.sm{padding:5px 10px;font-size:.7rem}' +
    '.ioc-row{display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap;align-items:flex-start}' +
    '.ioc-stat{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px;text-align:center;flex:1;min-width:100px}' +
    '.ioc-stat-num{font-size:1.6rem;font-weight:800;color:var(--acc)}' +
    '.ioc-stat-label{font-size:.7rem;color:var(--mut);text-transform:uppercase;letter-spacing:.04em;margin-top:4px}' +
    '.ioc-group{margin-bottom:20px}' +
    '.ioc-group-head{display:flex;align-items:center;gap:8px;margin-bottom:10px;padding-bottom:8px;border-bottom:1px solid var(--line)}' +
    '.ioc-group-icon{font-size:.62rem;font-weight:800;letter-spacing:.05em;padding:2px 6px;border-radius:4px;background:color-mix(in srgb,var(--acc) 14%,transparent);color:var(--acc);font-family:ui-monospace,monospace}' +
    '.ioc-group-label{font-weight:700;font-size:.85rem;color:var(--txt)}' +
    '.ioc-group-count{background:var(--acc);color:#fff;padding:2px 8px;border-radius:10px;font-size:.65rem;font-weight:700}' +
    '.ioc-item{display:flex;align-items:center;gap:8px;padding:6px 10px;border-radius:4px;font-family:ui-monospace,monospace;font-size:.75rem;color:var(--txt);cursor:pointer;transition:background .12s}' +
    '.ioc-item:hover{background:rgba(37,99,235,.08)}' +
    '.ioc-item-val{flex:1;word-break:break-all}' +
    '.ioc-copy{opacity:0;font-size:.65rem;color:var(--acc);transition:opacity .12s}' +
    '.ioc-item:hover .ioc-copy{opacity:1}' +
    '.ioc-export-area{width:100%;min-height:180px;background:var(--card2,#0a0e14);border:1px solid var(--line);color:var(--txt);font-family:ui-monospace,monospace;font-size:.72rem;padding:12px;border-radius:6px;resize:vertical}' +
    '.ioc-toggle{display:flex;align-items:center;gap:8px;font-size:.78rem;color:var(--mut);cursor:pointer;user-select:none}' +
    '.ioc-switch{width:36px;height:20px;border-radius:10px;background:var(--line);position:relative;transition:background .2s;flex-shrink:0}' +
    '.ioc-switch::after{content:"";position:absolute;width:16px;height:16px;border-radius:50%;background:#fff;top:2px;left:2px;transition:transform .2s}' +
    '.ioc-switch.on{background:var(--acc)}' +
    '.ioc-switch.on::after{transform:translateX(16px)}' +
    '.ioc-empty{text-align:center;padding:40px 20px;color:var(--mut);font-size:.85rem}' +
    '[data-style=pro] .ioc-wrap{color:#0f172a}' +
    '[data-style=pro] .ioc-panel{background:#fff;border-color:#e2e8f0}' +
    '[data-style=pro] .ioc-stat{background:#fff;border-color:#e2e8f0}' +
    '[data-style=pro] .ioc-textarea{background:#f8fafc;border-color:#e2e8f0;color:#0f172a}' +
    '[data-style=pro] .ioc-export-area{background:#f8fafc;border-color:#e2e8f0;color:#0f172a}' +
    '[data-style=pro] .ioc-item{color:#334155}' +
    '[data-style=pro] .ioc-item:hover{background:rgba(37,99,235,.05)}' +
    '[data-style=pro] .ioc-group-label{color:#0f172a}' +
    '</style>';

  function totalCount() {
    var n = 0;
    Object.keys(iocs).forEach(function(k) { n += iocs[k].length; });
    return n;
  }

  function exportCSV() {
    var lines = ['type,value'];
    Object.keys(iocs).forEach(function(type) {
      iocs[type].forEach(function(v) {
        var val = defanged ? defang(v) : v;
        lines.push(type + ',"' + val.replace(/"/g, '""') + '"');
      });
    });
    return lines.join('\n');
  }

  function exportJSON() {
    var out = {};
    Object.keys(iocs).forEach(function(type) {
      out[type] = iocs[type].map(function(v) { return defanged ? defang(v) : v; });
    });
    return JSON.stringify(out, null, 2);
  }

  function exportSTIX() {
    var objects = [];
    objects.push({
      type: 'bundle', id: 'bundle--' + crypto.randomUUID(), spec_version: '2.1',
      objects: []
    });
    Object.keys(iocs).forEach(function(type) {
      iocs[type].forEach(function(v) {
        var stixType = '', pattern = '';
        if (type === 'ipv4' || type === 'ipv6') { stixType = 'ipv4-addr'; pattern = "[ipv4-addr:value = '" + v + "']"; }
        else if (type === 'domain') { stixType = 'domain-name'; pattern = "[domain-name:value = '" + v + "']"; }
        else if (type === 'url') { stixType = 'url'; pattern = "[url:value = '" + v + "']"; }
        else if (type === 'email') { stixType = 'email-addr'; pattern = "[email-addr:value = '" + v + "']"; }
        else if (type === 'md5') { pattern = "[file:hashes.MD5 = '" + v + "']"; }
        else if (type === 'sha1') { pattern = "[file:hashes.'SHA-1' = '" + v + "']"; }
        else if (type === 'sha256') { pattern = "[file:hashes.'SHA-256' = '" + v + "']"; }
        else if (type === 'cve') { stixType = 'vulnerability'; }
        else return;
        if (type === 'cve') {
          objects[0].objects.push({
            type: 'vulnerability', id: 'vulnerability--' + crypto.randomUUID(),
            name: v, spec_version: '2.1', created: new Date().toISOString()
          });
        } else {
          objects[0].objects.push({
            type: 'indicator', id: 'indicator--' + crypto.randomUUID(),
            pattern: pattern, pattern_type: 'stix', valid_from: new Date().toISOString(),
            spec_version: '2.1', created: new Date().toISOString()
          });
        }
      });
    });
    return JSON.stringify(objects[0], null, 2);
  }

  function render() {
    var tabDefs = [
      { id: 'extract', label: 'Extract' },
      { id: 'results', label: 'Results (' + totalCount() + ')' },
      { id: 'export', label: 'Export' }
    ];
    var tabsHtml = tabDefs.map(function(t) {
      return '<button class="ioc-tab' + (activeTab === t.id ? ' active' : '') + '" data-tab="' + t.id + '">' + t.label + '</button>';
    }).join('');

    var contentHtml = '';

    if (activeTab === 'extract') {
      contentHtml = '<div class="ioc-panel">' +
        '<div class="ioc-panel-title">Paste Text to Extract IOCs</div>' +
        '<textarea class="ioc-textarea" id="ioc-input" placeholder="Paste threat reports, logs, email headers, OSINT data, or any text containing indicators of compromise...">' + esc(rawInput) + '</textarea>' +
        '<div class="ioc-row" style="margin-top:12px;align-items:center">' +
          '<button class="ioc-btn" id="ioc-extract">Extract IOCs</button>' +
          '<button class="ioc-btn ghost" id="ioc-sample">Load Sample</button>' +
          '<button class="ioc-btn ghost" id="ioc-clear">Clear</button>' +
          '<div style="flex:1"></div>' +
          '<label class="ioc-toggle" id="ioc-defang-toggle">' +
            '<div class="ioc-switch' + (defanged ? ' on' : '') + '"></div>' +
            '<span>Defang output</span>' +
          '</label>' +
        '</div>' +
      '</div>';
      if (totalCount() > 0) {
        contentHtml += '<div class="ioc-row">';
        var types = Object.keys(iocs);
        types.forEach(function(type) {
          contentHtml += '<div class="ioc-stat"><div class="ioc-stat-num">' + iocs[type].length + '</div><div class="ioc-stat-label">' + esc(IOC_PATTERNS[type].label) + '</div></div>';
        });
        contentHtml += '</div>';
      }
    } else if (activeTab === 'results') {
      if (totalCount() === 0) {
        contentHtml = '<div class="ioc-panel"><div class="ioc-empty">No IOCs extracted yet. Paste text and click Extract.</div></div>';
      } else {
        contentHtml += '<div class="ioc-row" style="align-items:center">' +
          '<button class="ioc-btn" id="ioc-to-graph">Send ' + totalCount() + ' IOCs to Security Graph</button>' +
          '<span style="font-size:.75rem;color:var(--mut)">Duplicates are merged. Linked to the active investigation if one is set.</span>' +
        '</div>';
        Object.keys(iocs).forEach(function(type) {
          var p = IOC_PATTERNS[type];
          contentHtml += '<div class="ioc-group">' +
            '<div class="ioc-group-head">' +
              '<span class="ioc-group-icon">' + p.icon + '</span>' +
              '<span class="ioc-group-label">' + esc(p.label) + '</span>' +
              '<span class="ioc-group-count">' + iocs[type].length + '</span>' +
            '</div>';
          iocs[type].forEach(function(v) {
            var display = defanged ? defang(v) : v;
            contentHtml += '<div class="ioc-item" data-val="' + esc(display) + '">' +
              '<span class="ioc-item-val">' + esc(display) + '</span>' +
              '<span class="ioc-copy">COPY</span>' +
            '</div>';
          });
          contentHtml += '</div>';
        });
      }
    } else if (activeTab === 'export') {
      if (totalCount() === 0) {
        contentHtml = '<div class="ioc-panel"><div class="ioc-empty">No IOCs to export. Extract IOCs first.</div></div>';
      } else {
        contentHtml = '<div class="ioc-panel">' +
          '<div class="ioc-panel-title">Export Format</div>' +
          '<div class="ioc-row" style="margin-bottom:16px">' +
            '<button class="ioc-btn sm" data-fmt="csv">CSV</button>' +
            '<button class="ioc-btn sm ghost" data-fmt="json">JSON</button>' +
            '<button class="ioc-btn sm ghost" data-fmt="stix">STIX 2.1</button>' +
            '<button class="ioc-btn sm ghost" data-fmt="plain">Plain List</button>' +
          '</div>' +
          '<textarea class="ioc-export-area" id="ioc-export-out" readonly>' + esc(exportCSV()) + '</textarea>' +
          '<div class="ioc-row" style="margin-top:10px">' +
            '<button class="ioc-btn ghost sm" id="ioc-copy-all">Copy to Clipboard</button>' +
            '<button class="ioc-btn ghost sm" id="ioc-download">Download</button>' +
          '</div>' +
        '</div>';
      }
    }

    container.innerHTML = CSS +
      '<div class="ioc-wrap">' +
        '<h1 class="ioc-title">IOC Extractor</h1>' +
        '<p class="ioc-sub">Extract Indicators of Compromise from unstructured text. Supports IPs, domains, URLs, hashes, CVEs, emails, and more.</p>' +
        '<div class="ioc-tabs">' + tabsHtml + '</div>' +
        contentHtml +
      '</div>';

    container.querySelectorAll('.ioc-tab').forEach(function(btn) {
      btn.onclick = function() { activeTab = btn.dataset.tab; render(); };
    });

    var extractBtn = container.querySelector('#ioc-extract');
    if (extractBtn) extractBtn.onclick = function() {
      rawInput = container.querySelector('#ioc-input').value;
      var processed = rawInput.replace(/\[\.\]/g, '.').replace(/hxxp/gi, 'http');
      iocs = extractIOCs(processed);
      activeTab = 'results';
      render();
    };
    var sampleBtn = container.querySelector('#ioc-sample');
    if (sampleBtn) sampleBtn.onclick = function() {
      rawInput = SAMPLE_TEXT;
      var processed = rawInput.replace(/\[\.\]/g, '.').replace(/hxxp/gi, 'http');
      iocs = extractIOCs(processed);
      activeTab = 'results';
      render();
    };
    var clearBtn = container.querySelector('#ioc-clear');
    if (clearBtn) clearBtn.onclick = function() { rawInput = ''; iocs = {}; render(); };

    var toGraphBtn = container.querySelector('#ioc-to-graph');
    if (toGraphBtn) toGraphBtn.onclick = function() {
      toGraphBtn.disabled = true;
      import('/js/graph-bridge.js?v=20260923c').then(function(gb) {
        var r = gb.sendToGraph('IOC Extractor', iocGraphItems(iocs));
        toGraphBtn.textContent = 'Sent: ' + r.created + ' new, ' + r.updated + ' merged';
      }).catch(function() { toGraphBtn.textContent = 'Security Graph unavailable'; toGraphBtn.disabled = false; });
    };

    var defangToggle = container.querySelector('#ioc-defang-toggle');
    if (defangToggle) defangToggle.onclick = function() { defanged = !defanged; render(); };

    container.querySelectorAll('.ioc-item').forEach(function(item) {
      item.onclick = function() {
        navigator.clipboard.writeText(item.dataset.val);
        var cp = item.querySelector('.ioc-copy');
        if (cp) { cp.textContent = 'COPIED'; setTimeout(function() { cp.textContent = 'COPY'; }, 1200); }
      };
    });

    var fmtBtns = container.querySelectorAll('[data-fmt]');
    fmtBtns.forEach(function(btn) {
      btn.onclick = function() {
        fmtBtns.forEach(function(b) { b.classList.toggle('ghost', b !== btn); b.classList.toggle('active', b === btn); });
        if (btn.classList.contains('ghost')) { btn.classList.remove('ghost'); }
        var out = container.querySelector('#ioc-export-out');
        if (!out) return;
        var fmt = btn.dataset.fmt;
        if (fmt === 'csv') out.value = exportCSV();
        else if (fmt === 'json') out.value = exportJSON();
        else if (fmt === 'stix') out.value = exportSTIX();
        else {
          var lines = [];
          Object.keys(iocs).forEach(function(type) {
            iocs[type].forEach(function(v) { lines.push(defanged ? defang(v) : v); });
          });
          out.value = lines.join('\n');
        }
      };
    });

    var copyAll = container.querySelector('#ioc-copy-all');
    if (copyAll) copyAll.onclick = function() {
      var out = container.querySelector('#ioc-export-out');
      if (out) { navigator.clipboard.writeText(out.value); copyAll.textContent = 'Copied!'; setTimeout(function() { copyAll.textContent = 'Copy to Clipboard'; }, 1500); }
    };
    var downloadBtn = container.querySelector('#ioc-download');
    if (downloadBtn) downloadBtn.onclick = function() {
      var out = container.querySelector('#ioc-export-out');
      if (!out) return;
      var blob = new Blob([out.value], { type: 'text/plain' });
      var a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'iocs-export.txt';
      a.click();
      URL.revokeObjectURL(a.href);
    };
  }

  render();
}
