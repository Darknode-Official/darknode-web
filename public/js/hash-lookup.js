// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Hash Lookup — hash identification, computation, file hashing, comparison

var esc = function(s) { return String(s != null ? s : '').replace(/[&<>"']/g, function(c) {
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); };

var _hlHashTypes = [
  { name: 'MD5', len: 32, pattern: /^[a-f0-9]{32}$/i },
  { name: 'SHA-1', len: 40, pattern: /^[a-f0-9]{40}$/i },
  { name: 'SHA-224', len: 56, pattern: /^[a-f0-9]{56}$/i },
  { name: 'SHA-256', len: 64, pattern: /^[a-f0-9]{64}$/i },
  { name: 'SHA-384', len: 96, pattern: /^[a-f0-9]{96}$/i },
  { name: 'SHA-512', len: 128, pattern: /^[a-f0-9]{128}$/i },
  { name: 'NTLM', len: 32, pattern: /^[a-f0-9]{32}$/i },
  { name: 'CRC32', len: 8, pattern: /^[a-f0-9]{8}$/i },
  { name: 'RIPEMD-160', len: 40, pattern: /^[a-f0-9]{40}$/i },
  { name: 'MySQL 4.1+', len: 40, pattern: /^\*[a-f0-9]{40}$/i },
  { name: 'bcrypt', len: null, pattern: /^\$2[aby]?\$\d{2}\$.{53}$/ },
  { name: 'Argon2', len: null, pattern: /^\$argon2(i|d|id)\$/ },
  { name: 'scrypt', len: null, pattern: /^\$s0\$/ }
];

export function renderHashLookup(container) {
  var h = '';
  h += '<div style="background:#0a0e14;color:#c8d6e5;font-family:\'Courier New\',monospace;padding:20px;min-height:600px;">';
  h += '<h2 style="color:#00ddff;font-size:18px;letter-spacing:2px;margin:0 0 4px;">HASH TOOLKIT</h2>';
  h += '<div style="color:#4a6a8a;font-size:11px;margin-bottom:20px;">Identify, compute, and compare cryptographic hashes — all client-side</div>';

  // Tabs
  h += '<div style="display:flex;gap:4px;margin-bottom:16px;" id="hl-tabs">';
  h += '<button class="hl-tab hl-tab-on" data-tab="identify" style="background:#0a2a44;border:1px solid #00aaff;color:#00ddff;padding:6px 14px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:4px 4px 0 0;">Identify</button>';
  h += '<button class="hl-tab" data-tab="compute" style="background:#111a24;border:1px solid #1a3050;color:#4a6a8a;padding:6px 14px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:4px 4px 0 0;">Compute</button>';
  h += '<button class="hl-tab" data-tab="file" style="background:#111a24;border:1px solid #1a3050;color:#4a6a8a;padding:6px 14px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:4px 4px 0 0;">File Hash</button>';
  h += '<button class="hl-tab" data-tab="compare" style="background:#111a24;border:1px solid #1a3050;color:#4a6a8a;padding:6px 14px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:4px 4px 0 0;">Compare</button>';
  h += '</div>';
  h += '<div id="hl-content"></div>';
  h += '</div>';
  container.innerHTML = h;

  document.getElementById('hl-tabs').addEventListener('click', function(e) {
    var btn = e.target.closest('[data-tab]');
    if (!btn) return;
    var tabs = document.querySelectorAll('.hl-tab');
    for (var i = 0; i < tabs.length; i++) {
      tabs[i].style.background = '#111a24'; tabs[i].style.borderColor = '#1a3050'; tabs[i].style.color = '#4a6a8a'; tabs[i].className = 'hl-tab';
    }
    btn.style.background = '#0a2a44'; btn.style.borderColor = '#00aaff'; btn.style.color = '#00ddff'; btn.className = 'hl-tab hl-tab-on';
    _hlRenderTab(btn.getAttribute('data-tab'));
  });
  _hlRenderTab('identify');
};

function _hlRenderTab(tab) {
  var el = document.getElementById('hl-content');
  if (!el) return;
  if (tab === 'identify') _hlTabIdentify(el);
  else if (tab === 'compute') _hlTabCompute(el);
  else if (tab === 'file') _hlTabFile(el);
  else if (tab === 'compare') _hlTabCompare(el);
}

function _hlTabIdentify(el) {
  el.innerHTML =
    '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:16px;">' +
    '<div style="color:#00aaff;font-size:12px;margin-bottom:8px;">PASTE A HASH TO IDENTIFY</div>' +
    '<div style="display:flex;gap:8px;">' +
    '<input id="hl-hash-input" style="flex:1;background:#080c14;border:1px solid #1a2a44;border-radius:4px;color:#c8d6e5;font-family:monospace;font-size:12px;padding:8px 12px;" placeholder="e.g. 5d41402abc4b2a76b9719d911017c592">' +
    '<button onclick="_hlIdentify()" style="background:#00aaff22;color:#00aaff;border:1px solid #00aaff44;padding:8px 14px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:4px;">IDENTIFY</button>' +
    '</div></div>' +
    '<div id="hl-id-results" style="margin-top:12px;"></div>';
}

window._hlIdentify = function() {
  var input = (document.getElementById('hl-hash-input') || {}).value;
  var results = document.getElementById('hl-id-results');
  if (!input || !results) return;
  input = input.trim();

  var matches = [];
  for (var i = 0; i < _hlHashTypes.length; i++) {
    var ht = _hlHashTypes[i];
    if (ht.pattern.test(input)) matches.push(ht);
  }

  var h = '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:14px;">';
  h += '<div style="color:#4a6a8a;font-size:10px;margin-bottom:6px;">Input: ' + input.length + ' characters</div>';

  if (matches.length === 0) {
    h += '<div style="color:#ff4444;font-size:12px;">No matching hash type identified.</div>';
  } else {
    h += '<div style="color:#00ff88;font-size:12px;font-weight:bold;margin-bottom:8px;">POSSIBLE TYPES (' + matches.length + ')</div>';
    for (var m = 0; m < matches.length; m++) {
      var confidence = matches.length === 1 ? 'HIGH' : 'MEDIUM';
      var confColor = confidence === 'HIGH' ? '#00ff88' : '#ffaa00';
      h += '<div style="display:flex;align-items:center;gap:8px;padding:4px 0;border-bottom:1px solid #0d1525;">';
      h += '<span style="color:#00ddff;font-weight:bold;font-size:13px;width:100px;">' + esc(matches[m].name) + '</span>';
      h += '<span style="color:#4a6a8a;font-size:10px;">Length: ' + (matches[m].len || 'variable') + '</span>';
      h += '<span style="color:' + confColor + ';font-size:9px;padding:1px 6px;background:' + confColor + '15;border:1px solid ' + confColor + '33;border-radius:2px;">' + confidence + '</span>';
      h += '</div>';
    }
  }
  h += '</div>';
  results.innerHTML = h;
};

function _hlTabCompute(el) {
  el.innerHTML =
    '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:16px;">' +
    '<div style="color:#00aaff;font-size:12px;margin-bottom:8px;">COMPUTE HASHES</div>' +
    '<textarea id="hl-text-input" style="width:100%;height:80px;background:#080c14;border:1px solid #1a2a44;border-radius:4px;color:#c8d6e5;font-family:monospace;font-size:12px;padding:10px;resize:vertical;box-sizing:border-box;" placeholder="Enter text to hash..."></textarea>' +
    '<button onclick="_hlComputeAll()" style="background:#00aaff22;color:#00aaff;border:1px solid #00aaff44;padding:8px 14px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:4px;margin-top:6px;">HASH IT</button>' +
    '</div>' +
    '<div id="hl-compute-results" style="margin-top:12px;"></div>';
}

window._hlComputeAll = function() {
  var input = (document.getElementById('hl-text-input') || {}).value;
  var results = document.getElementById('hl-compute-results');
  if (input === undefined || input === null || !results) return;

  var encoder = new TextEncoder();
  var data = encoder.encode(input);

  var algos = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'];
  var hashes = {};
  var done = 0;

  for (var a = 0; a < algos.length; a++) {
    (function(algo) {
      crypto.subtle.digest(algo, data).then(function(buf) {
        var arr = new Uint8Array(buf);
        var hex = '';
        for (var i = 0; i < arr.length; i++) hex += ('0' + arr[i].toString(16)).slice(-2);
        hashes[algo] = hex;
        done++;
        if (done >= algos.length) _hlRenderComputed(results, input, hashes);
      });
    })(algos[a]);
  }
};

function _hlRenderComputed(el, input, hashes) {
  var h = '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:14px;">';
  h += '<div style="color:#4a6a8a;font-size:10px;margin-bottom:8px;">Input: "' + esc(input.substring(0, 50)) + (input.length > 50 ? '...' : '') + '" (' + input.length + ' chars)</div>';

  var keys = Object.keys(hashes);
  for (var i = 0; i < keys.length; i++) {
    h += '<div style="margin:6px 0;">';
    h += '<div style="color:#00aaff;font-size:10px;letter-spacing:1px;margin-bottom:2px;">' + esc(keys[i]) + '</div>';
    h += '<div style="display:flex;gap:6px;align-items:center;">';
    h += '<code style="flex:1;background:#080c14;border:1px solid #1a2a44;border-radius:3px;padding:6px 8px;font-size:11px;color:#00ff88;word-break:break-all;">' + esc(hashes[keys[i]]) + '</code>';
    h += '<button onclick="navigator.clipboard.writeText(\'' + esc(hashes[keys[i]]) + '\')" style="background:#111a24;border:1px solid #1a3050;color:#4a6a8a;padding:4px 8px;font-family:monospace;font-size:9px;cursor:pointer;border-radius:2px;flex-shrink:0;">COPY</button>';
    h += '</div></div>';
  }
  h += '</div>';
  el.innerHTML = h;
}

function _hlTabFile(el) {
  el.innerHTML =
    '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:16px;">' +
    '<div style="color:#00aaff;font-size:12px;margin-bottom:8px;">FILE HASH</div>' +
    '<div id="hl-drop-zone" style="border:2px dashed #1a3050;border-radius:6px;padding:40px;text-align:center;cursor:pointer;transition:border-color 0.2s;" ondragover="event.preventDefault();this.style.borderColor=\'#00aaff\'" ondragleave="this.style.borderColor=\'#1a3050\'" ondrop="_hlHandleDrop(event)">' +
    '<div style="color:#4a6a8a;font-size:12px;">Drop a file here or click to select</div>' +
    '<div style="color:#3a5a7a;font-size:10px;margin-top:4px;">File is hashed locally — never uploaded</div>' +
    '<input type="file" id="hl-file-input" style="display:none;" onchange="_hlHashFile(this.files[0])">' +
    '</div>' +
    '</div>' +
    '<div id="hl-file-results" style="margin-top:12px;"></div>';

  document.getElementById('hl-drop-zone').addEventListener('click', function() {
    document.getElementById('hl-file-input').click();
  });
}

window._hlHandleDrop = function(e) {
  e.preventDefault();
  document.getElementById('hl-drop-zone').style.borderColor = '#1a3050';
  if (e.dataTransfer.files.length > 0) _hlHashFile(e.dataTransfer.files[0]);
};

window._hlHashFile = function(file) {
  var results = document.getElementById('hl-file-results');
  if (!file || !results) return;

  results.innerHTML = '<div style="color:#ffaa00;font-size:11px;">Hashing ' + esc(file.name) + ' (' + (file.size / 1024).toFixed(1) + ' KB)...</div>';

  var reader = new FileReader();
  reader.onload = function() {
    var data = new Uint8Array(reader.result);
    var algos = ['SHA-1', 'SHA-256', 'SHA-512'];
    var hashes = {};
    var done = 0;

    for (var a = 0; a < algos.length; a++) {
      (function(algo) {
        crypto.subtle.digest(algo, data).then(function(buf) {
          var arr = new Uint8Array(buf);
          var hex = '';
          for (var i = 0; i < arr.length; i++) hex += ('0' + arr[i].toString(16)).slice(-2);
          hashes[algo] = hex;
          done++;
          if (done >= algos.length) {
            var h = '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:14px;">';
            h += '<div style="color:#c8d6e5;font-size:12px;font-weight:bold;margin-bottom:4px;">' + esc(file.name) + '</div>';
            h += '<div style="color:#4a6a8a;font-size:10px;margin-bottom:10px;">Size: ' + file.size.toLocaleString() + ' bytes | Type: ' + esc(file.type || 'unknown') + '</div>';
            var keys = Object.keys(hashes);
            for (var i = 0; i < keys.length; i++) {
              h += '<div style="margin:6px 0;">';
              h += '<div style="color:#00aaff;font-size:10px;letter-spacing:1px;margin-bottom:2px;">' + esc(keys[i]) + '</div>';
              h += '<div style="display:flex;gap:6px;align-items:center;">';
              h += '<code style="flex:1;background:#080c14;border:1px solid #1a2a44;border-radius:3px;padding:6px 8px;font-size:10px;color:#00ff88;word-break:break-all;">' + esc(hashes[keys[i]]) + '</code>';
              h += '<button onclick="navigator.clipboard.writeText(\'' + esc(hashes[keys[i]]) + '\')" style="background:#111a24;border:1px solid #1a3050;color:#4a6a8a;padding:4px 8px;font-family:monospace;font-size:9px;cursor:pointer;border-radius:2px;flex-shrink:0;">COPY</button>';
              h += '</div></div>';
            }
            h += '</div>';
            results.innerHTML = h;
          }
        });
      })(algos[a]);
    }
  };
  reader.readAsArrayBuffer(file);
};

function _hlTabCompare(el) {
  el.innerHTML =
    '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:16px;">' +
    '<div style="color:#00aaff;font-size:12px;margin-bottom:8px;">COMPARE HASHES</div>' +
    '<input id="hl-cmp-a" style="width:100%;background:#080c14;border:1px solid #1a2a44;border-radius:4px;color:#c8d6e5;font-family:monospace;font-size:11px;padding:8px 12px;margin-bottom:6px;box-sizing:border-box;" placeholder="Hash A">' +
    '<input id="hl-cmp-b" style="width:100%;background:#080c14;border:1px solid #1a2a44;border-radius:4px;color:#c8d6e5;font-family:monospace;font-size:11px;padding:8px 12px;margin-bottom:6px;box-sizing:border-box;" placeholder="Hash B">' +
    '<button onclick="_hlCompare()" style="background:#00aaff22;color:#00aaff;border:1px solid #00aaff44;padding:8px 14px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:4px;">COMPARE</button>' +
    '</div>' +
    '<div id="hl-cmp-result" style="margin-top:12px;"></div>';
}

window._hlCompare = function() {
  var a = (document.getElementById('hl-cmp-a') || {}).value;
  var b = (document.getElementById('hl-cmp-b') || {}).value;
  var result = document.getElementById('hl-cmp-result');
  if (!a || !b || !result) return;

  a = a.trim().toLowerCase();
  b = b.trim().toLowerCase();
  var match = a === b;

  result.innerHTML =
    '<div style="background:#0c1020;border:2px solid ' + (match ? '#00ff88' : '#ff4444') + ';border-radius:8px;padding:20px;text-align:center;">' +
    '<div style="font-size:36px;font-weight:bold;color:' + (match ? '#00ff88' : '#ff4444') + ';text-shadow:0 0 20px ' + (match ? '#00ff88' : '#ff4444') + '40;">' + (match ? 'MATCH' : 'NO MATCH') + '</div>' +
    '<div style="color:#4a6a8a;font-size:10px;margin-top:6px;">' + (match ? 'Both hashes are identical' : 'Hashes differ — files/data are different') + '</div>' +
    '</div>';
};
