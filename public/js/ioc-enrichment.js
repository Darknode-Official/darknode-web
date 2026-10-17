import { esc } from '/js/shared.js';

/*
 * IOC Enrichment Pipeline (sec id: iocenrich)
 * Extract -> normalize/defang/refang -> classify -> de-dupe -> heuristic score
 * -> optional live enrichment -> export (CSV / JSON / copy).
 *
 * Offline-first: extraction, defang/refang, classification and heuristic scoring
 * run entirely client-side with no network. Live enrichment is opt-in (a button)
 * and degrades gracefully when offline or when a required key is missing.
 *
 * API keys are read from localStorage as dn_key_<provider> (set via the Deck).
 * Nothing is ever hardcoded. Only CSP-allowlisted hosts are contacted.
 */

/* ---- extraction patterns ------------------------------------------------ */

var PATTERNS = {
  ipv4:   { label: 'IPv4', regex: /(?:^|[^\d.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\d.])/g },
  ipv6:   { label: 'IPv6', regex: /(?:^|[\s,;|"'(<\[])((?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:))(?=[\s,;|"')>\]]|$)/gm },
  url:    { label: 'URL', regex: /\bhttps?:\/\/[^\s<>"'`)\]}]+/gi },
  email:  { label: 'Email', regex: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g },
  domain: { label: 'Domain', regex: /\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:xn--[a-zA-Z0-9-]+|[a-zA-Z]{2,24}))\b/g },
  md5:    { label: 'MD5', regex: /\b([a-fA-F0-9]{32})\b/g },
  sha1:   { label: 'SHA-1', regex: /\b([a-fA-F0-9]{40})\b/g },
  sha256: { label: 'SHA-256', regex: /\b([a-fA-F0-9]{64})\b/g },
  cve:    { label: 'CVE', regex: /\bCVE-\d{4}-\d{4,7}\b/gi },
  btc:    { label: 'Bitcoin', regex: /\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,62})\b/g },
  mac:    { label: 'MAC', regex: /\b((?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})\b/g },
  registry: { label: 'Registry key', regex: /\b((?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)\\[\w\\.{}$-]+)/gi },
  // Windows drive paths, or Unix paths with at least one directory and a file extension. A Unix
  // path must start a token, so the path part of a URL is not taken as a file.
  filepath: { label: 'File path', regex: /(?:^|[\s"'(=,;<\[])([A-Za-z]:\\(?:[\w.$-]+\\)*[\w.$-]+|\/(?:[\w.-]+\/)+[\w.-]+\.\w+)/gm }
};

var TYPE_ORDER = ['ipv4', 'ipv6', 'domain', 'url', 'email', 'md5', 'sha1', 'sha256', 'cve', 'btc', 'mac', 'registry', 'filepath'];
// Host-side artefacts: defanging them would only corrupt the value.
var NO_DEFANG = { mac: true, registry: true, filepath: true };

var ABUSE_TLDS = ['tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'gdn', 'work', 'click', 'link', 'zip', 'mov', 'country', 'kim', 'loan', 'men', 'date', 'review', 'stream'];
var DDNS_HOSTS = ['no-ip', 'noip', 'duckdns', 'dyndns', 'ddns', 'hopto', 'myftp', 'serveftp', 'sytes', 'zapto', 'ngrok', 'firebaseapp', 'herokuapp', 'pagescloud', 'ddnsking', 'freedns', 'afraid'];

var SAMPLE_TEXT = [
  'SOC escalation 2026-10-10 - suspected intrusion chain',
  '',
  'Beaconing observed to hxxps://cdn-sync[.]update-delivery[.]tk/a.bin',
  'C2 hosts: 185.220.101.47 and 91[.]219[.]237[.]229 (dot) also 45.133.1.9',
  'Internal pivot box 10.0.4.15 and gateway 192.168.1.1 (expected / benign)',
  'Loopback probe ::1 and link-local fe80::1ff:fe23:4567:890a',
  'Staging domain: deep.a.b.c.exfil-node.duckdns.org',
  'Phishing sender: billing[at]secure-login-verify[.]xyz',
  'Dropper MD5 d41d8cd98f00b204e9800998ecf8427e',
  'Payload SHA-256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  'Exploited CVE-2024-3400 on the perimeter appliance',
  'Raw-IP lure: hxxp://193.142.58.12:8443/login',
  'Ransom wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
  'Persistence: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\updater',
  'Dropped file C:\\Users\\Public\\updater.exe and /tmp/.cache/kworker.sh',
  'Rogue host MAC 00:1a:2b:3c:4d:5e on the guest VLAN'
].join('\n');

/* ---- defang / refang ---------------------------------------------------- */

function refang(text) {
  return String(text || '')
    .replace(/\(dot\)/gi, '.')
    .replace(/\[dot\]/gi, '.')
    .replace(/\{dot\}/gi, '.')
    .replace(/\[\.\]/g, '.')
    .replace(/\(\.\)/g, '.')
    .replace(/\s+dot\s+/gi, '.')
    .replace(/\[at\]/gi, '@')
    .replace(/\(at\)/gi, '@')
    .replace(/\s+at\s+/gi, '@')
    .replace(/\[@\]/g, '@')
    .replace(/\[:\]/g, ':')
    .replace(/\(:\)/g, ':')
    .replace(/\[:\/\/\]/g, '://')
    .replace(/h[xX]{2}ps/g, 'https')
    .replace(/h[xX]{2}p/g, 'http')
    .replace(/\bfxp\b/gi, 'ftp')
    .replace(/\[\/\]/g, '/');
}

function defang(val) {
  var v = String(val || '');
  v = v.replace(/https:\/\//gi, 'hxxps://').replace(/http:\/\//gi, 'hxxp://');
  v = v.replace(/@/g, '[at]');
  v = v.replace(/\./g, '[.]');
  return v;
}

/* ---- classification helpers -------------------------------------------- */

function ipToLong(ip) {
  var p = ip.split('.');
  if (p.length !== 4) return -1;
  var n = 0;
  for (var i = 0; i < 4; i++) {
    var o = parseInt(p[i], 10);
    if (isNaN(o) || o < 0 || o > 255 || String(o) !== p[i]) return -1;
    n = n * 256 + o;
  }
  return n >>> 0;
}

function validIPv4(ip) { return ipToLong(ip) >= 0; }

function inRange(long, cidr) {
  var parts = cidr.split('/');
  var base = ipToLong(parts[0]);
  var bits = parseInt(parts[1], 10);
  if (base < 0) return false;
  var mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (long & mask) === (base & mask);
}

var RESERVED_V4 = [
  { cidr: '10.0.0.0/8', name: 'RFC1918 private' },
  { cidr: '172.16.0.0/12', name: 'RFC1918 private' },
  { cidr: '192.168.0.0/16', name: 'RFC1918 private' },
  { cidr: '127.0.0.0/8', name: 'loopback' },
  { cidr: '169.254.0.0/16', name: 'link-local' },
  { cidr: '100.64.0.0/10', name: 'CGNAT' },
  { cidr: '0.0.0.0/8', name: 'this-network' },
  { cidr: '192.0.2.0/24', name: 'TEST-NET-1 documentation' },
  { cidr: '198.51.100.0/24', name: 'TEST-NET-2 documentation' },
  { cidr: '203.0.113.0/24', name: 'TEST-NET-3 documentation' },
  { cidr: '224.0.0.0/4', name: 'multicast' },
  { cidr: '240.0.0.0/4', name: 'reserved' },
  { cidr: '255.255.255.255/32', name: 'broadcast' }
];

function hostIsIp(host) { return validIPv4(host) || /^[0-9a-fA-F:]+$/.test(host) && host.indexOf(':') !== -1; }

function tldOf(domain) {
  var parts = String(domain).toLowerCase().split('.');
  return parts.length > 1 ? parts[parts.length - 1] : '';
}

function scoreIOC(type, value) {
  var v = String(value);
  var lv = v.toLowerCase();
  if (type === 'ipv4') {
    var lng = ipToLong(v);
    for (var i = 0; i < RESERVED_V4.length; i++) {
      if (inRange(lng, RESERVED_V4[i].cidr)) return { level: 'Low', reason: 'Private/reserved (' + RESERVED_V4[i].name + ') - not internet-routable' };
    }
    return { level: 'Medium', reason: 'Public address - confirm reputation before action' };
  }
  if (type === 'ipv6') {
    if (lv === '::1') return { level: 'Low', reason: 'IPv6 loopback' };
    if (lv.indexOf('fe80') === 0) return { level: 'Low', reason: 'Link-local' };
    if (/^f[cd][0-9a-f][0-9a-f]:/.test(lv)) return { level: 'Low', reason: 'Unique-local (ULA) - not routable' };
    if (lv === '::') return { level: 'Low', reason: 'Unspecified address' };
    return { level: 'Medium', reason: 'Public IPv6 - confirm reputation' };
  }
  if (type === 'domain' || type === 'email') {
    var host = type === 'email' ? lv.split('@')[1] || '' : lv;
    var labels = host.split('.');
    var tld = labels.length ? labels[labels.length - 1] : '';
    var reasons = [];
    var level = type === 'email' ? 'Low' : 'Medium';
    if (host.indexOf('xn--') !== -1) { level = 'High'; reasons.push('punycode/IDN - possible homograph'); }
    for (var d = 0; d < DDNS_HOSTS.length; d++) {
      if (host.indexOf(DDNS_HOSTS[d]) !== -1) { level = 'High'; reasons.push('dynamic-DNS/free host (' + DDNS_HOSTS[d] + ') - frequently abused'); break; }
    }
    if (level !== 'High' && ABUSE_TLDS.indexOf(tld) !== -1) { level = 'High'; reasons.push('high-abuse TLD (.' + tld + ')'); }
    if (labels.length >= 5) { if (level === 'Low') level = 'Medium'; reasons.push('deeply nested subdomains (' + labels.length + ' labels)'); }
    if (!reasons.length) reasons.push(type === 'email' ? 'Standard address - verify sender' : 'No offline red flags - enrich to confirm');
    return { level: level, reason: reasons.join('; ') };
  }
  if (type === 'url') {
    var host2 = '';
    try { host2 = new URL(v).hostname; } catch (_) { var m = v.match(/^https?:\/\/([^/:?#]+)/i); host2 = m ? m[1] : ''; }
    var port = '';
    var pm = v.match(/^https?:\/\/[^/:?#]+:(\d+)/i); if (pm) port = pm[1];
    var r = [];
    var lvl = 'Medium';
    if (host2 && hostIsIp(host2)) { lvl = 'High'; r.push('raw-IP host (no domain) - common in malware delivery'); }
    var utld = tldOf(host2);
    if (ABUSE_TLDS.indexOf(utld) !== -1) { lvl = 'High'; r.push('high-abuse TLD (.' + utld + ')'); }
    if (port && port !== '80' && port !== '443' && port !== '8080') { if (lvl === 'Medium') lvl = 'Medium'; r.push('non-standard port ' + port); }
    if (/\.(exe|scr|bat|cmd|ps1|hta|vbs|jar|js|dll|bin|iso|lnk|zip|rar|7z)(\?|$)/i.test(v)) { if (lvl !== 'High') lvl = 'High'; r.push('links to an executable/archive payload'); }
    if (!r.length) r.push('URL - confirm destination reputation');
    return { level: lvl, reason: r.join('; ') };
  }
  if (type === 'md5' || type === 'sha1' || type === 'sha256') {
    return { level: 'Medium', reason: 'File hash - enrich against malware feeds to classify' };
  }
  if (type === 'cve') {
    var year = parseInt((v.match(/CVE-(\d{4})/i) || [])[1], 10);
    var now = new Date().getFullYear();
    if (year && now - year <= 1) return { level: 'High', reason: 'Recent CVE (' + year + ') - likely still exploitable' };
    return { level: 'Medium', reason: 'Vulnerability identifier - check patch status' };
  }
  if (type === 'btc') {
    return { level: 'Medium', reason: 'Cryptocurrency wallet - often tied to ransom/extortion' };
  }
  if (type === 'mac') {
    return { level: 'Low', reason: 'Hardware address - correlates hosts on a local network, not internet-routable' };
  }
  if (type === 'registry') {
    if (/\\(Run|RunOnce|RunServices|Winlogon|Image File Execution Options|AppInit_DLLs|Services|Policies\\Explorer\\Run)(\\|$)/i.test(v)) return { level: 'High', reason: 'Autostart/persistence location' };
    return { level: 'Medium', reason: 'Registry key - check for modification on affected hosts' };
  }
  if (type === 'filepath') {
    var exe = /\.(exe|scr|bat|cmd|ps1|hta|vbs|js|jse|dll|sys|lnk|sh|elf|so|bin|py)$/i.test(v);
    if (exe && /(\\temp\\|\\appdata\\|\\users\\public\\|\\programdata\\|^\/tmp\/|^\/var\/tmp\/|^\/dev\/shm\/)/i.test(v)) return { level: 'High', reason: 'Executable or script in a user-writable staging directory' };
    return { level: 'Medium', reason: exe ? 'Executable or script path - hunt for it on endpoints' : 'File path - hunt for it on endpoints' };
  }
  return { level: 'Medium', reason: 'Indicator' };
}

/* ---- normalization + extraction ---------------------------------------- */

function normalize(type, raw) {
  var v = String(raw).trim().replace(/[),.;:'"\]]+$/, '');
  if (type === 'domain' || type === 'email' || type === 'ipv6' || type === 'mac') v = v.toLowerCase();
  if (type === 'md5' || type === 'sha1' || type === 'sha256') v = v.toLowerCase();
  if (type === 'cve') v = v.toUpperCase();
  return v;
}

function extract(text) {
  var refanged = refang(text);
  var records = [];
  var seen = {};
  var claimedHashes = {};

  // Hashes first so longer forms claim their bytes (SHA-256 before SHA-1 before MD5).
  ['sha256', 'sha1', 'md5'].forEach(function (type) {
    runPattern(type, refanged, function (val) {
      var nv = normalize(type, val);
      if (claimedHashes[nv]) return;
      claimedHashes[nv] = true;
      push(type, nv);
    });
  });

  TYPE_ORDER.forEach(function (type) {
    if (type === 'md5' || type === 'sha1' || type === 'sha256') return;
    runPattern(type, refanged, function (val) {
      var nv = normalize(type, val);
      if (type === 'ipv4' && !validIPv4(nv)) return;
      if (type === 'ipv6' && /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(nv)) return; // MAC, not IPv6
      push(type, nv);
    });
  });

  // Drop domains that are really the host portion of an already-captured URL/email,
  // and drop bare-hash-looking domains handled elsewhere.
  var urlHosts = {}, emailDomains = {}, pathParts = {};
  records.forEach(function (r) {
    if (r.type === 'url') { try { urlHosts[new URL(r.value).hostname.toLowerCase()] = true; } catch (_) {} }
    if (r.type === 'email') { var p = r.value.split('@')[1]; if (p) emailDomains[p.toLowerCase()] = true; }
    // A file name such as "svc.exe" also looks like a domain; it belongs to its path.
    if (r.type === 'filepath' || r.type === 'registry') r.value.split(/[\\/]/).forEach(function (seg) { pathParts[seg.toLowerCase()] = true; });
  });
  records = records.filter(function (r) {
    if (r.type !== 'domain') return true;
    if (urlHosts[r.value] || emailDomains[r.value] || pathParts[r.value]) return false;
    if (/^\d+\.\d+\.\d+\.\d+$/.test(r.value)) return false;
    return true;
  });

  function runPattern(type, src, cb) {
    var p = PATTERNS[type];
    var re = new RegExp(p.regex.source, p.regex.flags);
    var m;
    while ((m = re.exec(src)) !== null) {
      if (m.index === re.lastIndex) re.lastIndex++;
      cb(m[1] != null ? m[1] : m[0]);
    }
  }
  function push(type, value) {
    var key = type + '::' + value.toLowerCase();
    if (seen[key]) return;
    seen[key] = true;
    records.push({ type: type, value: value, risk: scoreIOC(type, value), enrich: null, selected: true });
  }

  return records;
}

/* ---- live enrichment (opt-in, graceful) -------------------------------- */

function readKey(provider) {
  try { return (localStorage.getItem('dn_key_' + provider) || '').trim(); } catch (_) { return ''; }
}

function withTimeout(promise, ms) {
  return new Promise(function (resolve, reject) {
    var t = setTimeout(function () { reject(new Error('timeout')); }, ms);
    promise.then(function (v) { clearTimeout(t); resolve(v); }, function (e) { clearTimeout(t); reject(e); });
  });
}

function hostOfUrl(u) { try { return new URL(u).hostname; } catch (_) { var m = String(u).match(/^https?:\/\/([^/:?#]+)/i); return m ? m[1] : ''; } }

// Returns a promise resolving to { notes, flagged, skipped } - never rejects.
function enrichOne(rec) {
  var type = rec.type, value = rec.value;
  var notes = [];
  var flagged = false;
  var jobs = [];

  function abuseIpdb(ip) {
    var key = readKey('abuseipdb');
    if (!key) { notes.push('AbuseIPDB: connect a key in the Deck to enable'); return Promise.resolve(); }
    return withTimeout(fetch('https://api.abuseipdb.com/api/v2/check?ipAddress=' + encodeURIComponent(ip) + '&maxAgeInDays=90', {
      headers: { Key: key, Accept: 'application/json' }
    }), 12000).then(function (r) { return r.json(); }).then(function (j) {
      var d = j && j.data;
      if (!d) { notes.push('AbuseIPDB: no data'); return; }
      var sc = d.abuseConfidenceScore || 0;
      if (sc >= 50) flagged = true;
      notes.push('AbuseIPDB: ' + sc + '% confidence, ' + (d.totalReports || 0) + ' reports' + (d.countryCode ? ', ' + d.countryCode : ''));
    }).catch(function () { notes.push('AbuseIPDB: lookup failed'); });
  }

  function greyNoise(ip) {
    var key = readKey('greynoise');
    if (!key) return Promise.resolve();
    return withTimeout(fetch('https://api.greynoise.io/v3/community/' + encodeURIComponent(ip), {
      headers: { key: key, Accept: 'application/json' }
    }), 12000).then(function (r) { return r.json(); }).then(function (j) {
      if (!j) return;
      if (j.classification) { if (j.classification === 'malicious') flagged = true; notes.push('GreyNoise: ' + j.classification + (j.name ? ' (' + j.name + ')' : '')); }
    }).catch(function () { /* silent - optional */ });
  }

  function threatFox(term) {
    var authKey = readKey('abusech') || readKey('threatfox');
    var headers = { 'Content-Type': 'application/json', Accept: 'application/json' };
    if (authKey) headers['Auth-Key'] = authKey;
    return withTimeout(fetch('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST', headers: headers, body: JSON.stringify({ query: 'search_ioc', search_term: term })
    }), 12000).then(function (r) { return r.json(); }).then(function (j) {
      if (j && j.query_status === 'ok' && j.data && j.data.length) {
        flagged = true;
        var first = j.data[0];
        notes.push('ThreatFox: ' + j.data.length + ' hit(s)' + (first.malware_printable ? ', ' + first.malware_printable : '') + (first.threat_type ? ' [' + first.threat_type + ']' : ''));
      } else if (j && j.query_status === 'no_result') {
        notes.push('ThreatFox: no match');
      } else if (j && j.query_status === 'illegal_search_term') {
        /* ignore */
      } else {
        notes.push('ThreatFox: unavailable (auth may be required)');
      }
    }).catch(function () { notes.push('ThreatFox: lookup failed'); });
  }

  function urlHausHost(host) {
    return withTimeout(fetch('https://urlhaus-api.abuse.ch/v1/host/', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'host=' + encodeURIComponent(host)
    }), 12000).then(function (r) { return r.json(); }).then(function (j) {
      if (j && j.query_status === 'ok') {
        var cnt = (j.urls && j.urls.length) || 0;
        if (cnt) { flagged = true; notes.push('URLhaus: ' + cnt + ' known malicious URL(s) on host'); }
        else notes.push('URLhaus: host listed, 0 active URLs');
      } else if (j && j.query_status === 'no_results') {
        notes.push('URLhaus: no match');
      } else {
        notes.push('URLhaus: unavailable');
      }
    }).catch(function () { notes.push('URLhaus: lookup failed'); });
  }

  function urlHausUrl(u) {
    return withTimeout(fetch('https://urlhaus-api.abuse.ch/v1/url/', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'url=' + encodeURIComponent(u)
    }), 12000).then(function (r) { return r.json(); }).then(function (j) {
      if (j && j.query_status === 'ok') { flagged = true; notes.push('URLhaus: known malicious (' + (j.threat || 'threat') + ', ' + (j.url_status || 'listed') + ')'); }
      else if (j && j.query_status === 'no_results') notes.push('URLhaus: no match');
      else notes.push('URLhaus: unavailable');
    }).catch(function () { notes.push('URLhaus: lookup failed'); });
  }

  if (type === 'ipv4') { jobs.push(abuseIpdb(value)); jobs.push(greyNoise(value)); jobs.push(urlHausHost(value)); }
  else if (type === 'ipv6') { jobs.push(greyNoise(value)); jobs.push(urlHausHost(value)); }
  else if (type === 'domain') { jobs.push(threatFox(value)); jobs.push(urlHausHost(value)); }
  else if (type === 'url') { jobs.push(urlHausUrl(value)); jobs.push(threatFox(value)); var h = hostOfUrl(value); if (h) jobs.push(urlHausHost(h)); }
  else if (type === 'md5' || type === 'sha1' || type === 'sha256') { jobs.push(threatFox(value)); }
  else { return Promise.resolve({ notes: ['No live source for this type - heuristic only'], flagged: false }); }

  return Promise.all(jobs).then(function () {
    if (!notes.length) notes.push('No enrichment data returned');
    return { notes: notes, flagged: flagged };
  });
}

function runPool(items, worker, concurrency, onEach) {
  concurrency = Math.max(1, concurrency || 4);
  var idx = 0, active = 0;
  return new Promise(function (resolve) {
    function next() {
      if (idx >= items.length && active === 0) { resolve(); return; }
      while (active < concurrency && idx < items.length) {
        var i = idx++; active++;
        worker(items[i], i).then(function (res) {
          if (onEach) { try { onEach(res, this.i); } catch (_) {} }
        }.bind({ i: i })).catch(function () {}).then(function () { active--; next(); });
      }
    }
    if (!items.length) { resolve(); return; }
    next();
  });
}

/* ---- rendering ---------------------------------------------------------- */

export function renderIocEnrichment(main) {
  var state = { raw: '', records: [], defangOut: false, enriching: false };

  var CSS = '<style>' +
    '.iocx{color:var(--txt)}' +
    '.iocx .iocx-ta{width:100%;min-height:190px;background:var(--card2);border:1px solid var(--line);color:var(--txt);font-family:var(--font-mono);font-size:.78rem;line-height:1.5;padding:12px;border-radius:6px;resize:vertical;box-sizing:border-box}' +
    '.iocx .iocx-ta:focus{outline:none;border-color:var(--acc)}' +
    '.iocx .iocx-controls{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:12px}' +
    '.iocx .iocx-spacer{flex:1}' +
    '.iocx .iocx-toggle{display:inline-flex;align-items:center;gap:8px;font-size:.78rem;color:var(--txt-2,var(--mut));cursor:pointer;user-select:none}' +
    '.iocx .iocx-sw{width:34px;height:19px;border-radius:10px;background:var(--line);position:relative;transition:background .18s;flex:0 0 auto}' +
    '.iocx .iocx-sw::after{content:"";position:absolute;width:15px;height:15px;border-radius:50%;background:var(--txt);top:2px;left:2px;transition:transform .18s}' +
    '.iocx .iocx-sw.on{background:var(--acc)}' +
    '.iocx .iocx-sw.on::after{transform:translateX(15px);background:var(--on-acc,#fff)}' +
    '.iocx .iocx-stats{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0}' +
    '.iocx .iocx-stat{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px;min-width:92px;flex:1}' +
    '.iocx .iocx-stat b{display:block;font-size:1.4rem;font-weight:800;color:var(--acc);line-height:1.1}' +
    '.iocx .iocx-stat span{font-size:.68rem;text-transform:uppercase;letter-spacing:.05em;color:var(--mut)}' +
    '.iocx .iocx-tblwrap{overflow-x:auto}' +
    '.iocx .iocx-val{font-family:var(--font-mono);font-size:.78rem;word-break:break-all;color:var(--txt)}' +
    '.iocx .iocx-ty{font-family:var(--font-mono);font-size:.66rem;font-weight:700;letter-spacing:.04em;text-transform:uppercase;padding:2px 7px;border-radius:4px;background:var(--acc-soft);color:var(--acc);white-space:nowrap}' +
    '.iocx .iocx-badge{font-size:.64rem;font-weight:800;letter-spacing:.05em;text-transform:uppercase;padding:2px 8px;border-radius:999px;white-space:nowrap;border:1px solid transparent}' +
    '.iocx .iocx-badge.high{color:var(--bad);border-color:color-mix(in srgb,var(--bad) 45%,var(--line));background:color-mix(in srgb,var(--bad) 12%,transparent)}' +
    '.iocx .iocx-badge.medium{color:var(--warn);border-color:color-mix(in srgb,var(--warn) 45%,var(--line));background:color-mix(in srgb,var(--warn) 12%,transparent)}' +
    '.iocx .iocx-badge.low{color:var(--ok);border-color:color-mix(in srgb,var(--ok) 45%,var(--line));background:color-mix(in srgb,var(--ok) 12%,transparent)}' +
    '.iocx .iocx-reason{font-size:.72rem;color:var(--txt-2,var(--mut));line-height:1.45}' +
    '.iocx .iocx-note{font-size:.72rem;color:var(--txt-2,var(--mut));line-height:1.45}' +
    '.iocx .iocx-note.hit{color:var(--bad);font-weight:600}' +
    '.iocx .iocx-empty{padding:34px 16px;text-align:center;color:var(--mut);font-size:.85rem}' +
    '.iocx .iocx-prog{font-size:.75rem;color:var(--mut)}' +
    '.iocx .data-table td{vertical-align:top}' +
    '.iocx .iocx-chk{width:15px;height:15px;accent-color:var(--acc);cursor:pointer}' +
    '</style>';

  function counts() {
    var c = {};
    state.records.forEach(function (r) { c[r.type] = (c[r.type] || 0) + 1; });
    return c;
  }
  function selected() { return state.records.filter(function (r) { return r.selected; }); }

  function rowsFor(list) {
    return list.map(function (r) {
      var display = state.defangOut && !NO_DEFANG[r.type] ? defang(r.value) : r.value;
      return {
        type: PATTERNS[r.type].label,
        value: display,
        risk: r.risk.level,
        reason: r.risk.reason,
        enrichment: r.enrich ? r.enrich.notes.join(' | ') : ''
      };
    });
  }

  function toCSV(list) {
    var rows = rowsFor(list);
    var head = ['type', 'value', 'risk', 'reason', 'enrichment'];
    var out = [head.join(',')];
    rows.forEach(function (r) {
      out.push(head.map(function (k) { return '"' + String(r[k] == null ? '' : r[k]).replace(/"/g, '""') + '"'; }).join(','));
    });
    return out.join('\r\n');
  }
  // STIX 2.1 bundle: one indicator per selectable observable, a vulnerability SDO per CVE.
  function toSTIX(list) {
    var now = new Date().toISOString();
    var uuid = function () {
      if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
      var b = crypto.getRandomValues(new Uint8Array(16)); b[6] = (b[6] & 15) | 64; b[8] = (b[8] & 63) | 128;
      var h = Array.prototype.map.call(b, function (x) { return (x < 16 ? '0' : '') + x.toString(16); }).join('');
      return h.slice(0, 8) + '-' + h.slice(8, 12) + '-' + h.slice(12, 16) + '-' + h.slice(16, 20) + '-' + h.slice(20);
    };
    var q = function (v) { return "'" + String(v).replace(/\\/g, '\\\\').replace(/'/g, "\\'") + "'"; };
    var objects = [];
    list.forEach(function (r) {
      var v = r.value, pattern = '';
      if (r.type === 'cve') {
        objects.push({ type: 'vulnerability', spec_version: '2.1', id: 'vulnerability--' + uuid(), created: now, modified: now, name: v,
          external_references: [{ source_name: 'cve', external_id: v }] });
        return;
      }
      if (r.type === 'ipv4') pattern = '[ipv4-addr:value = ' + q(v) + ']';
      else if (r.type === 'ipv6') pattern = '[ipv6-addr:value = ' + q(v) + ']';
      else if (r.type === 'domain') pattern = '[domain-name:value = ' + q(v) + ']';
      else if (r.type === 'url') pattern = '[url:value = ' + q(v) + ']';
      else if (r.type === 'email') pattern = '[email-addr:value = ' + q(v) + ']';
      else if (r.type === 'md5') pattern = '[file:hashes.MD5 = ' + q(v) + ']';
      else if (r.type === 'sha1') pattern = "[file:hashes.'SHA-1' = " + q(v) + ']';
      else if (r.type === 'sha256') pattern = "[file:hashes.'SHA-256' = " + q(v) + ']';
      else if (r.type === 'mac') pattern = '[mac-addr:value = ' + q(v.replace(/-/g, ':')) + ']';
      else if (r.type === 'registry') pattern = '[windows-registry-key:key = ' + q(v) + ']';
      else if (r.type === 'filepath') {
        var cut = Math.max(v.lastIndexOf('\\'), v.lastIndexOf('/'));
        pattern = '[file:name = ' + q(v.slice(cut + 1)) + (cut > 0 ? ' AND file:parent_directory_ref.path = ' + q(v.slice(0, cut)) : '') + ']';
      }
      else return; // no STIX cyber-observable for this type (e.g. Bitcoin)
      objects.push({ type: 'indicator', spec_version: '2.1', id: 'indicator--' + uuid(), created: now, modified: now, valid_from: now,
        name: PATTERNS[r.type].label + ': ' + v, description: r.risk.level + ' (heuristic): ' + r.risk.reason, pattern: pattern, pattern_type: 'stix' });
    });
    return JSON.stringify({ type: 'bundle', id: 'bundle--' + uuid(), objects: objects }, null, 2);
  }
  var GRAPH_TYPE = { ipv4: 'IP', ipv6: 'IP', domain: 'DOMAIN', cve: 'VULNERABILITY' };
  function graphItems(list) {
    return list.map(function (r) {
      return { type: GRAPH_TYPE[r.type] || 'INDICATOR', name: r.value,
        data: { iocType: r.type, risk: r.risk.level, reason: r.risk.reason, enrichment: r.enrich ? r.enrich.notes.join(' | ') : '' },
        opts: { tags: ['ioc', r.type] } };
    });
  }

  function toJSON(list) {
    return JSON.stringify({ generated: new Date().toISOString(), count: list.length, defanged: state.defangOut, indicators: rowsFor(list) }, null, 2);
  }

  function download(name, text, mime) {
    try {
      var blob = new Blob([text], { type: mime });
      var a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = name;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
    } catch (_) { toast('Download failed', 'error'); }
  }

  function toast(msg, kind) {
    if (typeof window !== 'undefined' && typeof window.showToast === 'function') { try { window.showToast(msg, kind || 'info'); return; } catch (_) {} }
  }

  function render() {
    var c = counts();
    var total = state.records.length;
    var sel = selected().length;

    var html = CSS + '<div class="iocx">';
    html += '<div class="pg-head"><div>' +
      '<h1 class="pg-h1">IOC Enrichment</h1>' +
      '<p class="muted pg-sub">Extract, defang, classify, score and enrich indicators of compromise, then export. Heuristics run offline; live enrichment is opt-in.</p>' +
      '</div></div>';

    // input
    html += '<div class="panel">' +
      '<div class="panel-h"><h2 class="pg-h2">Source Text</h2></div>' +
      '<textarea class="iocx-ta" id="iocx-input" placeholder="Paste logs, email headers, threat reports or OSINT. Defanged indicators (hxxp, 1[.]2[.]3[.]4, evil(dot)com, user[at]domain) are refanged automatically.">' + esc(state.raw) + '</textarea>' +
      '<div class="iocx-controls">' +
        '<button class="btn primary" id="iocx-extract">Extract and Classify</button>' +
        '<button class="btn ghost" id="iocx-sample">Load Sample</button>' +
        '<button class="btn ghost" id="iocx-clear">Clear</button>' +
        '<div class="iocx-spacer"></div>' +
        '<label class="iocx-toggle" id="iocx-defang"><span class="iocx-sw' + (state.defangOut ? ' on' : '') + '"></span><span>Defang output</span></label>' +
      '</div>' +
    '</div>';

    if (total > 0) {
      html += '<div class="iocx-stats">';
      html += '<div class="iocx-stat"><b>' + total + '</b><span>Total IOCs</span></div>';
      TYPE_ORDER.forEach(function (t) { if (c[t]) html += '<div class="iocx-stat"><b>' + c[t] + '</b><span>' + esc(PATTERNS[t].label) + '</span></div>'; });
      html += '</div>';

      html += '<div class="panel">' +
        '<div class="panel-h"><h2 class="pg-h2">Indicators</h2><span class="iocx-prog" id="iocx-prog">' + sel + ' of ' + total + ' selected</span></div>' +
        '<div class="iocx-controls" style="margin:14px 18px 4px">' +
          '<button class="btn" id="iocx-enrich"' + (state.enriching ? ' disabled' : '') + '>' + (state.enriching ? 'Enriching...' : 'Enrich Selected (live sources)') + '</button>' +
          '<button class="btn ghost" id="iocx-selall">Select All</button>' +
          '<button class="btn ghost" id="iocx-selnone">Select None</button>' +
          '<div class="iocx-spacer"></div>' +
          '<button class="btn ghost" id="iocx-csv">Export CSV</button>' +
          '<button class="btn ghost" id="iocx-json">Export JSON</button>' +
          '<button class="btn ghost" id="iocx-stix">Export STIX 2.1</button>' +
          '<button class="btn ghost" id="iocx-graph">Send to Security Graph</button>' +
          '<button class="btn ghost" id="iocx-copy">Copy</button>' +
        '</div>' +
        '<div class="iocx-tblwrap">' +
          '<table class="data-table"><thead><tr>' +
            '<th style="width:28px"><input type="checkbox" class="iocx-chk" id="iocx-head-chk"' + (sel === total && total ? ' checked' : '') + '></th>' +
            '<th>Type</th><th>Indicator</th><th>Risk</th><th>Heuristic Reason</th><th>Enrichment</th>' +
          '</tr></thead><tbody>';

      state.records.forEach(function (r, i) {
        var display = state.defangOut && !NO_DEFANG[r.type] ? defang(r.value) : r.value;
        var lvl = r.risk.level.toLowerCase();
        html += '<tr>' +
          '<td><input type="checkbox" class="iocx-chk iocx-rowchk" data-i="' + i + '"' + (r.selected ? ' checked' : '') + '></td>' +
          '<td><span class="iocx-ty">' + esc(PATTERNS[r.type].label) + '</span></td>' +
          '<td><span class="iocx-val">' + esc(display) + '</span></td>' +
          '<td><span class="iocx-badge ' + lvl + '">' + esc(r.risk.level) + '</span></td>' +
          '<td><span class="iocx-reason">' + esc(r.risk.reason) + '</span></td>' +
          '<td><span class="iocx-note' + (r.enrich && r.enrich.flagged ? ' hit' : '') + '">' + (r.enrich ? esc(r.enrich.notes.join(' | ')) : '<span style="color:var(--mut)">-</span>') + '</span></td>' +
        '</tr>';
      });

      html += '</tbody></table></div></div>';
    } else {
      html += '<div class="panel"><div class="iocx-empty">No indicators yet. Paste text above (or load the sample) and click Extract and Classify.</div></div>';
    }

    html += '</div>';
    main.innerHTML = html;
    bind();
  }

  function bind() {
    var inp = main.querySelector('#iocx-input');

    var ex = main.querySelector('#iocx-extract');
    if (ex) ex.onclick = function () {
      state.raw = inp ? inp.value : state.raw;
      state.records = extract(state.raw);
      render();
      toast(state.records.length ? state.records.length + ' indicators extracted' : 'No indicators found', state.records.length ? 'success' : 'info');
    };

    var sm = main.querySelector('#iocx-sample');
    if (sm) sm.onclick = function () { state.raw = SAMPLE_TEXT; state.records = extract(state.raw); render(); };

    var cl = main.querySelector('#iocx-clear');
    if (cl) cl.onclick = function () { state.raw = ''; state.records = []; render(); };

    var df = main.querySelector('#iocx-defang');
    if (df) df.onclick = function () { if (inp) state.raw = inp.value; state.defangOut = !state.defangOut; render(); };

    var hc = main.querySelector('#iocx-head-chk');
    if (hc) hc.onchange = function () { var v = hc.checked; state.records.forEach(function (r) { r.selected = v; }); render(); };

    main.querySelectorAll('.iocx-rowchk').forEach(function (cb) {
      cb.onchange = function () { var i = parseInt(cb.dataset.i, 10); if (state.records[i]) state.records[i].selected = cb.checked; updateSelCount(); };
    });

    var sa = main.querySelector('#iocx-selall');
    if (sa) sa.onclick = function () { state.records.forEach(function (r) { r.selected = true; }); render(); };
    var sn = main.querySelector('#iocx-selnone');
    if (sn) sn.onclick = function () { state.records.forEach(function (r) { r.selected = false; }); render(); };

    var csv = main.querySelector('#iocx-csv');
    if (csv) csv.onclick = function () { var l = selected(); if (!l.length) return toast('Select at least one indicator', 'info'); download('iocs-' + stamp() + '.csv', toCSV(l), 'text/csv'); };
    var json = main.querySelector('#iocx-json');
    if (json) json.onclick = function () { var l = selected(); if (!l.length) return toast('Select at least one indicator', 'info'); download('iocs-' + stamp() + '.json', toJSON(l), 'application/json'); };
    var stx = main.querySelector('#iocx-stix');
    if (stx) stx.onclick = function () { var l = selected(); if (!l.length) return toast('Select at least one indicator', 'info'); download('iocs-' + stamp() + '.stix.json', toSTIX(l), 'application/json'); };
    var gr = main.querySelector('#iocx-graph');
    if (gr) gr.onclick = function () {
      var l = selected(); if (!l.length) return toast('Select at least one indicator', 'info');
      gr.disabled = true;
      import('/js/graph-bridge.js?v=20261017d').then(function (gb) {
        var r = gb.sendToGraph('IOC Enrichment', graphItems(l));
        gr.textContent = 'Sent: ' + r.created + ' new, ' + r.updated + ' merged';
      }).catch(function () { gr.textContent = 'Security Graph unavailable'; gr.disabled = false; });
    };
    var cp = main.querySelector('#iocx-copy');
    if (cp) cp.onclick = function () {
      var l = selected(); if (!l.length) return toast('Select at least one indicator', 'info');
      var text = toCSV(l);
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(function () { toast('Copied ' + l.length + ' indicators (CSV)', 'success'); }, function () { toast('Copy failed', 'error'); });
      else toast('Clipboard unavailable', 'error');
    };

    var enb = main.querySelector('#iocx-enrich');
    if (enb) enb.onclick = doEnrich;
  }

  function updateSelCount() {
    var prog = main.querySelector('#iocx-prog');
    if (prog) prog.textContent = selected().length + ' of ' + state.records.length + ' selected';
    var hc = main.querySelector('#iocx-head-chk');
    if (hc) hc.checked = state.records.length > 0 && selected().length === state.records.length;
  }

  function doEnrich() {
    if (state.enriching) return;
    var targets = selected();
    if (!targets.length) { toast('Select at least one indicator to enrich', 'info'); return; }
    state.enriching = true;
    var btn = main.querySelector('#iocx-enrich');
    if (btn) { btn.disabled = true; btn.textContent = 'Enriching 0/' + targets.length + '...'; }
    var done = 0;
    runPool(targets, function (rec) {
      return enrichOne(rec).then(function (res) { rec.enrich = res; return rec; });
    }, 4, function () {
      done++;
      if (btn) btn.textContent = 'Enriching ' + done + '/' + targets.length + '...';
    }).then(function () {
      state.enriching = false;
      var hits = targets.filter(function (r) { return r.enrich && r.enrich.flagged; }).length;
      render();
      toast('Enrichment complete - ' + hits + ' flagged by live sources', hits ? 'success' : 'info');
    });
  }

  function stamp() {
    var d = new Date();
    function p(n) { return (n < 10 ? '0' : '') + n; }
    return d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate()) + '-' + p(d.getHours()) + p(d.getMinutes());
  }

  render();
}
