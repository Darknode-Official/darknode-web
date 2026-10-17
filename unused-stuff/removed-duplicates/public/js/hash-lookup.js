// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved.
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
  { name: 'MySQL 4.1+', len: 41, pattern: /^\*[a-f0-9]{40}$/i },
  { name: 'bcrypt', len: null, pattern: /^\$2[abxy]?\$\d{2}\$.{53}$/ },
  { name: 'Argon2', len: null, pattern: /^\$argon2(i|d|id)\$/ },
  { name: 'scrypt', len: null, pattern: /^\$s0\$/ }
];

var HL_CSS = '<style>' +
  '.hl-wrap{color:var(--txt,#e7eefc);background:var(--card,#0b1120);padding:20px;min-height:600px;border-radius:8px}' +
  '.hl-h2{color:var(--txt,#e7eefc);font-size:18px;letter-spacing:2px;margin:0 0 4px;font-weight:700}' +
  '.hl-sub{color:var(--mut,#7a93b8);font-size:11px;margin-bottom:20px}' +
  '.hl-tabs{display:flex;gap:4px;margin-bottom:16px}' +
  '.hl-tab{background:var(--card2,#0f1726);border:1px solid var(--line,#283a5a);color:var(--mut,#7a93b8);padding:6px 14px;font-size:11px;cursor:pointer;border-radius:4px 4px 0 0;font-family:inherit}' +
  '.hl-tab.hl-tab-on{background:color-mix(in srgb,var(--acc,#2563eb) 14%,var(--card2,#0f1726));border-color:var(--acc,#2563eb);color:var(--acc,#2563eb)}' +
  '.hl-card{background:var(--card2,#0f1726);border:1px solid var(--line,#283a5a);border-radius:6px;padding:16px}' +
  '.hl-card2{background:var(--card2,#0f1726);border:1px solid var(--line,#283a5a);border-radius:6px;padding:14px}' +
  '.hl-lbl{color:var(--acc,#2563eb);font-size:12px;margin-bottom:8px}' +
  '.hl-input{flex:1;background:var(--card,#0b1120);border:1px solid var(--line,#283a5a);border-radius:4px;color:var(--txt,#e7eefc);font-family:var(--font-mono);font-size:12px;padding:8px 12px}' +
  '.hl-textarea{width:100%;height:80px;background:var(--card,#0b1120);border:1px solid var(--line,#283a5a);border-radius:4px;color:var(--txt,#e7eefc);font-family:var(--font-mono);font-size:12px;padding:10px;resize:vertical;box-sizing:border-box}' +
  '.hl-btn{background:color-mix(in srgb,var(--acc,#2563eb) 14%,transparent);color:var(--acc,#2563eb);border:1px solid color-mix(in srgb,var(--acc,#2563eb) 40%,transparent);padding:8px 14px;font-size:11px;cursor:pointer;border-radius:4px;font-family:inherit}' +
  '.hl-copy{background:var(--card2,#0f1726);border:1px solid var(--line,#283a5a);color:var(--mut,#7a93b8);padding:4px 8px;font-size:9px;cursor:pointer;border-radius:4px;flex-shrink:0;font-family:inherit}' +
  '.hl-meta{color:var(--mut,#7a93b8);font-size:10px;margin-bottom:6px}' +
  '.hl-hashlbl{color:var(--acc,#2563eb);font-size:10px;letter-spacing:1px;margin-bottom:2px}' +
  '.hl-hashval{flex:1;background:var(--card,#0b1120);border:1px solid var(--line,#283a5a);border-radius:3px;padding:6px 8px;font-size:11px;color:#16a34a;word-break:break-all;font-family:var(--font-mono)}' +
  '.hl-err{color:#dc2626;font-size:12px}' +
  '.hl-oklbl{color:#16a34a;font-size:12px;font-weight:bold;margin-bottom:8px}' +
  '.hl-typerow{display:flex;align-items:center;gap:8px;padding:4px 0;border-bottom:1px solid var(--line,#283a5a)}' +
  '.hl-typename{color:var(--acc,#2563eb);font-weight:bold;font-size:13px;width:100px;font-family:var(--font-mono)}' +
  '.hl-typelen{color:var(--mut,#7a93b8);font-size:10px}' +
  '.hl-conf{font-size:9px;padding:1px 6px;border-radius:2px}' +
  '.hl-conf.high{color:#16a34a;background:rgba(22,163,74,.12);border:1px solid rgba(22,163,74,.3)}' +
  '.hl-conf.med{color:#d97706;background:rgba(217,119,6,.12);border:1px solid rgba(217,119,6,.3)}' +
  '.hl-drop{border:2px dashed var(--line,#283a5a);border-radius:6px;padding:40px;text-align:center;cursor:pointer;transition:border-color .2s}' +
  '.hl-drop-main{color:var(--txt-2,#9fb0cc);font-size:12px}' +
  '.hl-drop-hint{color:var(--mut,#7a93b8);font-size:10px;margin-top:4px}' +
  '.hl-fname{color:var(--txt,#e7eefc);font-size:12px;font-weight:bold;margin-bottom:4px}' +
  '.hl-fmeta{color:var(--mut,#7a93b8);font-size:10px;margin-bottom:10px}' +
  '.hl-busy{color:#d97706;font-size:11px}' +
  '.hl-cmp-input{width:100%;background:var(--card,#0b1120);border:1px solid var(--line,#283a5a);border-radius:4px;color:var(--txt,#e7eefc);font-family:var(--font-mono);font-size:11px;padding:8px 12px;margin-bottom:6px;box-sizing:border-box}' +
  '.hl-cmp-box{border-radius:8px;padding:20px;text-align:center;background:var(--card2,#0f1726);border:2px solid var(--line,#283a5a)}' +
  '.hl-cmp-box.match{border-color:#16a34a}' +
  '.hl-cmp-box.nomatch{border-color:#dc2626}' +
  '.hl-cmp-big{font-size:36px;font-weight:bold}' +
  '.hl-cmp-box.match .hl-cmp-big{color:#16a34a}' +
  '.hl-cmp-box.nomatch .hl-cmp-big{color:#dc2626}' +
  '.hl-cmp-sub{color:var(--mut,#7a93b8);font-size:10px;margin-top:6px}' +
  '</style>';

export function renderHashLookup(container) {
  var h = HL_CSS;
  h += '<div class="hl-wrap">';
  h += '<h2 class="hl-h2">HASH TOOLKIT</h2>';
  h += '<div class="hl-sub">Identify, compute, and compare cryptographic hashes — all client-side</div>';

  // Tabs
  h += '<div class="hl-tabs" id="hl-tabs">';
  h += '<button class="hl-tab hl-tab-on" data-tab="identify">Identify</button>';
  h += '<button class="hl-tab" data-tab="compute">Compute</button>';
  h += '<button class="hl-tab" data-tab="file">File Hash</button>';
  h += '<button class="hl-tab" data-tab="compare">Compare</button>';
  h += '</div>';
  h += '<div id="hl-content"></div>';
  h += '</div>';
  container.innerHTML = h;

  document.getElementById('hl-tabs').addEventListener('click', function(e) {
    var btn = e.target.closest('[data-tab]');
    if (!btn) return;
    var tabs = document.querySelectorAll('.hl-tab');
    for (var i = 0; i < tabs.length; i++) {
      tabs[i].className = 'hl-tab';
    }
    btn.className = 'hl-tab hl-tab-on';
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
    '<div class="hl-card">' +
    '<div class="hl-lbl">PASTE A HASH TO IDENTIFY</div>' +
    '<div style="display:flex;gap:8px;">' +
    '<input id="hl-hash-input" class="hl-input" placeholder="e.g. 5d41402abc4b2a76b9719d911017c592">' +
    '<button onclick="_hlIdentify()" class="hl-btn">Identify</button>' +
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

  var h = '<div class="hl-card2">';
  h += '<div class="hl-meta">Input: ' + input.length + ' characters</div>';

  if (matches.length === 0) {
    h += '<div class="hl-err">No matching hash type identified.</div>';
  } else {
    h += '<div class="hl-oklbl">POSSIBLE TYPES (' + matches.length + ')</div>';
    for (var m = 0; m < matches.length; m++) {
      var confidence = matches.length === 1 ? 'HIGH' : 'MEDIUM';
      var confClass = confidence === 'HIGH' ? 'high' : 'med';
      h += '<div class="hl-typerow">';
      h += '<span class="hl-typename">' + esc(matches[m].name) + '</span>';
      h += '<span class="hl-typelen">Length: ' + (matches[m].len || 'variable') + '</span>';
      h += '<span class="hl-conf ' + confClass + '">' + confidence + '</span>';
      h += '</div>';
    }
  }
  h += '</div>';
  results.innerHTML = h;
};

function _hlTabCompute(el) {
  el.innerHTML =
    '<div class="hl-card">' +
    '<div class="hl-lbl">COMPUTE HASHES</div>' +
    '<textarea id="hl-text-input" class="hl-textarea" placeholder="Enter text to hash..."></textarea>' +
    '<button onclick="_hlComputeAll()" class="hl-btn" style="margin-top:6px;">Hash It</button>' +
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
  var h = '<div class="hl-card2">';
  h += '<div class="hl-meta">Input: "' + esc(input.substring(0, 50)) + (input.length > 50 ? '...' : '') + '" (' + input.length + ' chars)</div>';

  var keys = Object.keys(hashes);
  for (var i = 0; i < keys.length; i++) {
    h += '<div style="margin:6px 0;">';
    h += '<div class="hl-hashlbl">' + esc(keys[i]) + '</div>';
    h += '<div style="display:flex;gap:6px;align-items:center;">';
    h += '<code class="hl-hashval">' + esc(hashes[keys[i]]) + '</code>';
    h += '<button onclick="navigator.clipboard.writeText(\'' + esc(hashes[keys[i]]) + '\')" class="hl-copy">Copy</button>';
    h += '</div></div>';
  }
  h += '</div>';
  el.innerHTML = h;
}

function _hlTabFile(el) {
  el.innerHTML =
    '<div class="hl-card">' +
    '<div class="hl-lbl">FILE HASH</div>' +
    '<div id="hl-drop-zone" class="hl-drop" ondragover="event.preventDefault();this.style.borderColor=\'var(--acc,#2563eb)\'" ondragleave="this.style.borderColor=\'var(--line,#283a5a)\'" ondrop="_hlHandleDrop(event)">' +
    '<div class="hl-drop-main">Drop a file here or click to select</div>' +
    '<div class="hl-drop-hint">File is hashed locally — never uploaded</div>' +
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
  document.getElementById('hl-drop-zone').style.borderColor = 'var(--line,#283a5a)';
  if (e.dataTransfer.files.length > 0) _hlHashFile(e.dataTransfer.files[0]);
};

window._hlHashFile = function(file) {
  var results = document.getElementById('hl-file-results');
  if (!file || !results) return;

  results.innerHTML = '<div class="hl-busy">Hashing ' + esc(file.name) + ' (' + (file.size / 1024).toFixed(1) + ' KB)...</div>';

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
            var h = '<div class="hl-card2">';
            h += '<div class="hl-fname">' + esc(file.name) + '</div>';
            h += '<div class="hl-fmeta">Size: ' + file.size.toLocaleString() + ' bytes | Type: ' + esc(file.type || 'unknown') + '</div>';
            var keys = Object.keys(hashes);
            for (var i = 0; i < keys.length; i++) {
              h += '<div style="margin:6px 0;">';
              h += '<div class="hl-hashlbl">' + esc(keys[i]) + '</div>';
              h += '<div style="display:flex;gap:6px;align-items:center;">';
              h += '<code class="hl-hashval" style="font-size:10px;">' + esc(hashes[keys[i]]) + '</code>';
              h += '<button onclick="navigator.clipboard.writeText(\'' + esc(hashes[keys[i]]) + '\')" class="hl-copy">Copy</button>';
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
    '<div class="hl-card">' +
    '<div class="hl-lbl">COMPARE HASHES</div>' +
    '<input id="hl-cmp-a" class="hl-cmp-input" placeholder="Hash A">' +
    '<input id="hl-cmp-b" class="hl-cmp-input" placeholder="Hash B">' +
    '<button onclick="_hlCompare()" class="hl-btn">Compare</button>' +
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
    '<div class="hl-cmp-box ' + (match ? 'match' : 'nomatch') + '">' +
    '<div class="hl-cmp-big">' + (match ? 'MATCH' : 'NO MATCH') + '</div>' +
    '<div class="hl-cmp-sub">' + (match ? 'Both hashes are identical' : 'Hashes differ — files/data are different') + '</div>' +
    '</div>';
};
