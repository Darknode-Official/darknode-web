/**
 * DARKNODE — Favicon Hash Calculator
 * Threat hunting via favicon fingerprinting (Shodan/Censys compatible)
 * Copyright 2024-2026 Darknode Project. All rights reserved.
 */

export function renderFaviconHasher(container) {
  var esc = function(s) { var d = document.createElement('div'); d.textContent = s; return d.innerHTML; };

  var KNOWN_HASHES = {
    '-1137275908': 'Apache HTTP Server (default)',
    '116323821': 'Apache Tomcat',
    '-297069493': 'Apache (powered by)',
    '81586312': 'Nginx (default)',
    '-1293291324': 'Microsoft IIS 7/8',
    '-1002298449': 'Microsoft IIS 10',
    '247761667': 'Microsoft Exchange OWA',
    '-305179312': 'Microsoft SharePoint',
    '-553691228': 'Grafana',
    '-1395847077': 'Kibana',
    '81462090': 'Jenkins CI',
    '-1032603236': 'Jenkins CI (alternate)',
    '1485257654': 'GitLab',
    '-316785895': 'Atlassian Jira',
    '-1007812832': 'Atlassian Confluence',
    '116070534': 'Spring Boot (leaf)',
    '-1588886052': 'Django (green)',
    '1485832694': 'Laravel',
    '-64644021': 'WordPress',
    '-1840324437': 'phpMyAdmin',
    '-1462811347': 'Webmin',
    '988422585': 'cPanel',
    '-1166125415': 'Plesk',
    '362091310': 'Fortinet FortiGate',
    '1916021449': 'Palo Alto GlobalProtect',
    '-996278746': 'Cisco ASA VPN',
    '-305179312': 'SonicWall',
    '1848946384': 'Sophos UTM',
    '-1214941836': 'Synology DSM',
    '681542341': 'QNAP NAS',
    '-428438895': 'Prometheus',
    '-1950415971': 'RabbitMQ',
    '2026498956': 'Elasticsearch',
    '-752607229': 'Keycloak',
    '774517901': 'Minio',
    '-1003469480': 'Zabbix'
  };

  function murmurHash3(keyBytes) {
    var h = 0;
    var len = keyBytes.length;
    var nblocks = len >> 2;
    var c1 = 0xcc9e2d51;
    var c2 = 0x1b873593;
    for (var i = 0; i < nblocks; i++) {
      var k = (keyBytes[i * 4]) | (keyBytes[i * 4 + 1] << 8) | (keyBytes[i * 4 + 2] << 16) | (keyBytes[i * 4 + 3] << 24);
      k = Math.imul(k, c1); k = (k << 15) | (k >>> 17); k = Math.imul(k, c2);
      h ^= k; h = (h << 13) | (h >>> 19); h = Math.imul(h, 5) + 0xe6546b64;
    }
    var tail = nblocks * 4;
    var k1 = 0;
    switch (len & 3) {
      case 3: k1 ^= keyBytes[tail + 2] << 16;
      case 2: k1 ^= keyBytes[tail + 1] << 8;
      case 1: k1 ^= keyBytes[tail];
        k1 = Math.imul(k1, c1); k1 = (k1 << 15) | (k1 >>> 17); k1 = Math.imul(k1, c2); h ^= k1;
    }
    h ^= len;
    h ^= h >>> 16; h = Math.imul(h, 0x85ebca6b);
    h ^= h >>> 13; h = Math.imul(h, 0xc2b2ae35);
    h ^= h >>> 16;
    return h | 0;
  }

  function arrayBufferToBase64(buf) {
    var bytes = new Uint8Array(buf);
    var bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }

  function textToBytes(str) {
    var enc = new TextEncoder();
    return enc.encode(str);
  }

  async function sha256Hex(buf) {
    var hash = await crypto.subtle.digest('SHA-256', buf);
    var arr = new Uint8Array(hash);
    return Array.from(arr).map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
  }

  async function md5Hex(buf) {
    var bytes = new Uint8Array(buf);
    var msg = Array.from(bytes);
    var origLen = msg.length;
    msg.push(0x80);
    while (msg.length % 64 !== 56) msg.push(0);
    var bitLen = origLen * 8;
    for (var b = 0; b < 8; b++) msg.push((bitLen >>> (b * 8)) & 0xff);

    var S = [7,12,17,22, 5,9,14,20, 4,11,16,23, 6,10,15,21];
    var K = [];
    for (var i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000);

    var a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    for (var off = 0; off < msg.length; off += 64) {
      var M = [];
      for (var j = 0; j < 16; j++) M[j] = msg[off+j*4] | (msg[off+j*4+1]<<8) | (msg[off+j*4+2]<<16) | (msg[off+j*4+3]<<24);
      var A = a0, B = b0, C = c0, D = d0;
      for (var i = 0; i < 64; i++) {
        var F, g;
        if (i < 16) { F = (B & C) | (~B & D); g = i; }
        else if (i < 32) { F = (D & B) | (~D & C); g = (5*i+1) % 16; }
        else if (i < 48) { F = B ^ C ^ D; g = (3*i+5) % 16; }
        else { F = C ^ (B | ~D); g = (7*i) % 16; }
        F = (F + A + K[i] + M[g]) | 0;
        A = D; D = C; C = B;
        var s = S[(Math.floor(i/16))*4 + (i%4)];
        B = (B + ((F << s) | (F >>> (32-s)))) | 0;
      }
      a0 = (a0 + A) | 0; b0 = (b0 + B) | 0; c0 = (c0 + C) | 0; d0 = (d0 + D) | 0;
    }
    function hexLE(v) {
      return ((v & 0xff).toString(16).padStart(2,'0')) +
        (((v>>>8) & 0xff).toString(16).padStart(2,'0')) +
        (((v>>>16) & 0xff).toString(16).padStart(2,'0')) +
        (((v>>>24) & 0xff).toString(16).padStart(2,'0'));
    }
    return hexLE(a0) + hexLE(b0) + hexLE(c0) + hexLE(d0);
  }

  var _fhResults = [];

  async function processFavicon(arrayBuf, name) {
    var b64 = arrayBufferToBase64(arrayBuf);
    var b64Bytes = textToBytes(b64);
    var shodanHash = murmurHash3(b64Bytes);
    var rawHash = murmurHash3(new Uint8Array(arrayBuf));
    var sha = await sha256Hex(arrayBuf);
    var md = await md5Hex(arrayBuf);
    var known = KNOWN_HASHES[String(shodanHash)] || null;

    return {
      name: name,
      size: arrayBuf.byteLength,
      shodanHash: shodanHash,
      rawMurmur: rawHash,
      sha256: sha,
      md5: md,
      base64: b64,
      known: known,
      blobUrl: URL.createObjectURL(new Blob([arrayBuf], { type: 'image/x-icon' }))
    };
  }

  function renderResults() {
    var el = document.getElementById('fh-results');
    if (!el) return;
    if (_fhResults.length === 0) {
      el.innerHTML = '<div style="color:#2a4a6a;text-align:center;padding:30px;font-size:12px;">Upload or fetch a favicon to begin analysis</div>';
      return;
    }
    var h = '';
    _fhResults.forEach(function(r, idx) {
      var matchColor = r.known ? '#00ff88' : '#4a6a8a';
      h += '<div style="background:#080c18;border:1px solid #1a2a44;border-radius:8px;padding:16px;margin-bottom:12px;">';
      h += '<div style="display:flex;gap:16px;align-items:flex-start;">';
      h += '<div style="flex-shrink:0;width:64px;height:64px;background:#060a14;border:1px solid #1a3050;border-radius:6px;display:flex;align-items:center;justify-content:center;overflow:hidden;">';
      h += '<img src="' + r.blobUrl + '" style="max-width:56px;max-height:56px;image-rendering:pixelated;" onerror="this.style.display=\'none\'">';
      h += '</div>';
      h += '<div style="flex:1;min-width:0;">';
      h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">';
      h += '<span style="color:#00ddff;font-size:13px;font-weight:bold;">' + esc(r.name) + '</span>';
      h += '<span style="color:#3a5a7a;font-size:10px;">' + r.size.toLocaleString() + ' bytes</span>';
      h += '</div>';

      if (r.known) {
        h += '<div style="background:#00ff8810;border:1px solid #00ff8833;border-radius:4px;padding:6px 10px;margin-bottom:10px;">';
        h += '<span style="color:#00ff88;font-size:11px;font-weight:bold;">IDENTIFIED: ' + esc(r.known) + '</span>';
        h += '</div>';
      }

      h += '<div style="display:grid;grid-template-columns:140px 1fr;gap:4px 12px;font-size:10px;">';
      h += '<span style="color:#ff6644;font-weight:bold;">SHODAN HASH</span>';
      h += '<span style="color:#ff6644;cursor:pointer;" onclick="navigator.clipboard.writeText(\'' + r.shodanHash + '\')" title="Click to copy">' + r.shodanHash + '</span>';
      h += '<span style="color:#4a6a8a;">RAW MURMUR3</span><span style="color:#8ab4d4;">' + r.rawMurmur + '</span>';
      h += '<span style="color:#4a6a8a;">SHA-256</span><span style="color:#8ab4d4;word-break:break-all;">' + r.sha256 + '</span>';
      h += '<span style="color:#4a6a8a;">MD5</span><span style="color:#8ab4d4;">' + r.md5 + '</span>';
      h += '</div>';

      h += '<div style="margin-top:10px;padding:8px 12px;background:#060a14;border:1px solid #1a3050;border-radius:4px;">';
      h += '<div style="color:#4a6a8a;font-size:9px;letter-spacing:1px;margin-bottom:4px;">SHODAN QUERY</div>';
      h += '<div style="display:flex;gap:8px;align-items:center;">';
      h += '<code style="color:#ffaa00;font-size:12px;flex:1;">http.favicon.hash:' + r.shodanHash + '</code>';
      h += '<button onclick="navigator.clipboard.writeText(\'http.favicon.hash:' + r.shodanHash + '\')" style="background:#ffaa0015;border:1px solid #ffaa0033;color:#ffaa00;font-size:9px;padding:3px 8px;cursor:pointer;border-radius:4px;font-family:monospace;">COPY</button>';
      h += '</div>';
      h += '</div>';

      h += '</div></div></div>';
    });
    el.innerHTML = h;
  }

  container.innerHTML = '<div style="background:#0a0e14;color:#c8d6e5;font-family:\'Courier New\',monospace;padding:20px;min-height:100vh;">'
    + '<div style="text-align:center;margin-bottom:20px;padding-bottom:14px;border-bottom:1px solid #1a2a44;">'
    + '<div style="font-size:24px;font-weight:800;color:#00ddff;letter-spacing:4px;text-shadow:0 0 20px rgba(0,212,255,0.3);">FAVICON HASHER</div>'
    + '<div style="font-size:10px;color:#4a6a8a;letter-spacing:2px;margin-top:4px;">THREAT HUNTING VIA FAVICON FINGERPRINTING</div>'
    + '</div>'

    + '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px;">'

    + '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:8px;padding:16px;">'
    + '<div style="color:#00aaff;font-size:11px;font-weight:bold;letter-spacing:1px;margin-bottom:10px;">FETCH FROM URL</div>'
    + '<div style="display:flex;gap:8px;">'
    + '<input id="fh-url" type="text" placeholder="https://example.com" style="flex:1;background:#060a14;border:1px solid #1a3050;border-radius:4px;color:#00ddff;font-family:monospace;font-size:13px;padding:10px 12px;">'
    + '<button id="fh-fetch-btn" style="background:#00aaff15;border:1px solid #00aaff44;color:#00aaff;padding:10px 16px;cursor:pointer;border-radius:4px;font-family:monospace;font-size:11px;font-weight:bold;white-space:nowrap;">FETCH</button>'
    + '</div>'
    + '<div id="fh-fetch-status" style="margin-top:6px;font-size:10px;color:#3a5a7a;min-height:14px;"></div>'
    + '</div>'

    + '<div id="fh-dropzone" style="background:#0c1020;border:2px dashed #1a3050;border-radius:8px;padding:16px;text-align:center;cursor:pointer;transition:border-color 0.2s;">'
    + '<div style="color:#00aaff;font-size:11px;font-weight:bold;letter-spacing:1px;margin-bottom:8px;">FILE UPLOAD</div>'
    + '<div style="color:#3a5a7a;font-size:11px;">Drop favicon(s) here or click to browse</div>'
    + '<div style="color:#2a4a6a;font-size:9px;margin-top:4px;">Supports .ico, .png, .svg — batch upload enabled</div>'
    + '<input id="fh-file" type="file" multiple accept=".ico,.png,.svg,.jpg,.gif,image/*" style="display:none;">'
    + '</div>'

    + '</div>'

    + '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">'
    + '<div style="color:#00aaff;font-size:12px;font-weight:bold;letter-spacing:1px;">RESULTS</div>'
    + '<button id="fh-clear-btn" style="background:#ff444415;border:1px solid #ff444433;color:#ff4444;font-size:9px;padding:4px 10px;cursor:pointer;border-radius:4px;font-family:monospace;display:none;">CLEAR ALL</button>'
    + '</div>'

    + '<div id="fh-results"><div style="color:#2a4a6a;text-align:center;padding:30px;font-size:12px;">Upload or fetch a favicon to begin analysis</div></div>'

    + '<details style="margin-top:16px;">'
    + '<summary style="color:#aa66ff;font-size:11px;cursor:pointer;padding:6px 0;font-weight:bold;letter-spacing:1px;">KNOWN FAVICON DATABASE (' + Object.keys(KNOWN_HASHES).length + ' signatures)</summary>'
    + '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:8px;padding:12px;margin-top:6px;max-height:300px;overflow-y:auto;">'
    + '<div style="display:grid;grid-template-columns:140px 1fr;gap:3px 12px;font-size:10px;">'
    + Object.keys(KNOWN_HASHES).map(function(k) {
        return '<span style="color:#ffaa00;font-variant-numeric:tabular-nums;">' + esc(k) + '</span><span style="color:#8ab4d4;">' + esc(KNOWN_HASHES[k]) + '</span>';
      }).join('')
    + '</div></div></details>'

    + '</div>';

  var dropzone = document.getElementById('fh-dropzone');
  var fileInput = document.getElementById('fh-file');
  var fetchBtn = document.getElementById('fh-fetch-btn');
  var urlInput = document.getElementById('fh-url');
  var clearBtn = document.getElementById('fh-clear-btn');

  dropzone.addEventListener('click', function() { fileInput.click(); });

  dropzone.addEventListener('dragover', function(e) {
    e.preventDefault();
    dropzone.style.borderColor = '#00aaff';
  });

  dropzone.addEventListener('dragleave', function() {
    dropzone.style.borderColor = '#1a3050';
  });

  dropzone.addEventListener('drop', function(e) {
    e.preventDefault();
    dropzone.style.borderColor = '#1a3050';
    handleFiles(e.dataTransfer.files);
  });

  fileInput.addEventListener('change', function() {
    if (fileInput.files.length > 0) handleFiles(fileInput.files);
  });

  async function handleFiles(files) {
    for (var i = 0; i < files.length; i++) {
      var f = files[i];
      try {
        var buf = await f.arrayBuffer();
        var result = await processFavicon(buf, f.name);
        _fhResults.unshift(result);
      } catch (e) {
        _fhResults.unshift({ name: f.name, size: 0, shodanHash: 'ERROR', rawMurmur: '', sha256: '', md5: '', base64: '', known: null, blobUrl: '', error: e.message });
      }
    }
    clearBtn.style.display = _fhResults.length > 0 ? 'block' : 'none';
    renderResults();
  }

  fetchBtn.addEventListener('click', async function() {
    var url = urlInput.value.trim();
    if (!url) return;
    if (!url.match(/^https?:\/\//)) url = 'https://' + url;
    var statusEl = document.getElementById('fh-fetch-status');
    statusEl.innerHTML = '<span style="color:#ffaa00;">Fetching favicon...</span>';
    fetchBtn.disabled = true;

    var paths = ['/favicon.ico', '/favicon.png', '/apple-touch-icon.png'];
    var baseUrl = url.replace(/\/+$/, '');
    var fetched = false;

    for (var i = 0; i < paths.length; i++) {
      if (fetched) break;
      try {
        var resp = await fetch(baseUrl + paths[i], { mode: 'cors', redirect: 'follow' });
        if (resp.ok) {
          var ct = resp.headers.get('content-type') || '';
          if (ct.indexOf('text/html') !== -1) continue;
          var buf = await resp.arrayBuffer();
          if (buf.byteLength < 10) continue;
          var result = await processFavicon(buf, baseUrl + paths[i]);
          _fhResults.unshift(result);
          fetched = true;
          statusEl.innerHTML = '<span style="color:#00ff88;">Favicon fetched and hashed</span>';
        }
      } catch (e) { /* try next */ }
    }

    if (!fetched) {
      statusEl.innerHTML = '<span style="color:#ff4444;">CORS blocked or no favicon found.</span> <span style="color:#4a6a8a;">Use file upload instead, or download the favicon manually first.</span>';
    }

    fetchBtn.disabled = false;
    clearBtn.style.display = _fhResults.length > 0 ? 'block' : 'none';
    renderResults();
  });

  urlInput.addEventListener('keydown', function(e) { if (e.key === 'Enter') fetchBtn.click(); });

  clearBtn.addEventListener('click', function() {
    _fhResults.forEach(function(r) { if (r.blobUrl) try { URL.revokeObjectURL(r.blobUrl); } catch(e){} });
    _fhResults = [];
    clearBtn.style.display = 'none';
    renderResults();
  });
};
