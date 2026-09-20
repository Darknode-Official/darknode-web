// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Threat Intelligence API — shared module for live threat data
// All functions use callbacks: callback(error, data)

var ThreatAPI = (function() {
  var _cache = {};
  var CACHE_TTL = 5 * 60 * 1000;

  function _cacheKey(prefix, args) {
    return prefix + ':' + args;
  }

  function _cacheGet(key) {
    var entry = _cache[key];
    if (!entry) return null;
    if (Date.now() - entry.ts > CACHE_TTL) {
      delete _cache[key];
      return null;
    }
    return entry.data;
  }

  function _cacheSet(key, data) {
    _cache[key] = { data: data, ts: Date.now() };
    var keys = Object.keys(_cache);
    if (keys.length > 200) {
      keys.sort(function(a, b) { return _cache[a].ts - _cache[b].ts; });
      for (var i = 0; i < 50; i++) delete _cache[keys[i]];
    }
  }

  function esc(s) {
    return String(s != null ? s : '').replace(/[&<>"']/g, function(c) {
      return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
    });
  }

  var _defaultKeys = {
    virustotal: '0318a63efb0592db47a2bfbb3a7c16e42a7e1518b997f9ecf844f56c70cf1afd',
    shodan: 'pwcTag6QwGPVBL0F7H8ky5C3c8HaOAim'
  };

  function getKey(service) {
    try {
      var keys = JSON.parse(localStorage.getItem('dn_api_keys') || '{}');
      if (!keys[service] && _defaultKeys[service]) return _defaultKeys[service];
      return keys[service] || '';
    } catch (e) {
      return '';
    }
  }

  function setKey(service, key) {
    try {
      var keys = JSON.parse(localStorage.getItem('dn_api_keys') || '{}');
      keys[service] = key;
      localStorage.setItem('dn_api_keys', JSON.stringify(keys));
    } catch (e) {}
  }

  function getAllKeys() {
    try {
      return JSON.parse(localStorage.getItem('dn_api_keys') || '{}');
    } catch (e) {
      return {};
    }
  }

  function _fetchJSON(url, opts, callback) {
    opts = opts || {};
    var method = opts.method || 'GET';
    var headers = opts.headers || {};
    var body = opts.body || null;
    var timeout = opts.timeout || 15000;

    try {
      var controller = new AbortController();
      var timer = setTimeout(function() { controller.abort(); }, timeout);

      var fetchOpts = {
        method: method,
        headers: headers,
        signal: controller.signal
      };
      if (body) fetchOpts.body = body;

      fetch(url, fetchOpts)
        .then(function(res) {
          clearTimeout(timer);
          if (!res.ok) {
            return res.text().then(function(t) {
              callback({ status: res.status, message: t || ('HTTP ' + res.status) }, null);
            });
          }
          return res.json().then(function(data) {
            callback(null, data);
          });
        })
        .catch(function(err) {
          clearTimeout(timer);
          var msg = err.name === 'AbortError' ? 'Request timed out' : (err.message || 'Network error');
          callback({ message: msg }, null);
        });
    } catch (err) {
      callback({ message: err.message || 'Fetch failed' }, null);
    }
  }

  // =============================================
  // FREE APIs (no key needed)
  // =============================================

  function searchCVE(query, callback) {
    var ckey = _cacheKey('nvd_search', query);
    var cached = _cacheGet(ckey);
    if (cached) return callback(null, cached);

    var url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=' + encodeURIComponent(query) + '&resultsPerPage=20';
    _fetchJSON(url, { timeout: 20000 }, function(err, data) {
      if (err) return callback(err, null);
      _cacheSet(ckey, data);
      callback(null, data);
    });
  }

  function getCVE(cveId, callback) {
    var ckey = _cacheKey('nvd_cve', cveId);
    var cached = _cacheGet(ckey);
    if (cached) return callback(null, cached);

    var url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=' + encodeURIComponent(cveId);
    _fetchJSON(url, { timeout: 20000 }, function(err, data) {
      if (err) return callback(err, null);
      _cacheSet(ckey, data);
      callback(null, data);
    });
  }

  function recentCriticalCVEs(callback) {
    var ckey = _cacheKey('nvd_critical', 'recent');
    var cached = _cacheGet(ckey);
    if (cached) return callback(null, cached);

    var url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=10&cvssV3Severity=CRITICAL';
    _fetchJSON(url, { timeout: 25000 }, function(err, data) {
      if (err) return callback(err, null);
      _cacheSet(ckey, data);
      callback(null, data);
    });
  }

  function searchCerts(domain, callback) {
    var ckey = _cacheKey('crt', domain);
    var cached = _cacheGet(ckey);
    if (cached) return callback(null, cached);

    var url = 'https://crt.sh/?q=' + encodeURIComponent(domain) + '&output=json';
    _fetchJSON(url, { timeout: 20000 }, function(err, data) {
      if (err) return callback(err, null);
      var results = Array.isArray(data) ? data.slice(0, 50) : [];
      _cacheSet(ckey, results);
      callback(null, results);
    });
  }

  function searchURLhaus(query, callback) {
    var ckey = _cacheKey('urlhaus', query);
    var cached = _cacheGet(ckey);
    if (cached) return callback(null, cached);

    _fetchJSON('/data/feeds/malware-urls.json', { timeout: 15000 }, function(err, feed) {
      if (err) return callback(err, null);
      var matches = [];
      var term = String(query).toLowerCase();
      var entries = (feed && feed.data) ? feed.data : [];
      for (var i = 0; i < entries.length; i++) {
        var u = entries[i];
        var uUrl = String(u.url || '').toLowerCase();
        if (uUrl.indexOf(term) !== -1) matches.push(u);
      }
      var result = { query_status: matches.length > 0 ? 'ok' : 'no_result', urls: matches.length > 0 ? matches : [] };
      _cacheSet(ckey, result);
      callback(null, result);
    });
  }

  function recentURLhaus(callback) {
    var ckey = _cacheKey('urlhaus_recent', 'all');
    var cached = _cacheGet(ckey);
    if (cached) return callback(null, cached);

    _fetchJSON('/data/feeds/malware-urls.json', { timeout: 15000 }, function(err, feed) {
      if (err) return callback(err, null);
      var entries = (feed && feed.data) ? feed.data.slice(0, 10) : [];
      var result = { urls: entries };
      _cacheSet(ckey, result);
      callback(null, result);
    });
  }

  function searchMalware(hashOrTag, callback) {
    var ckey = _cacheKey('mbazaar', hashOrTag);
    var cached = _cacheGet(ckey);
    if (cached) return callback(null, cached);

    _fetchJSON('/data/feeds/threat-iocs.json', { timeout: 15000 }, function(err, feed) {
      if (err) return callback(err, null);
      var matches = [];
      var term = String(hashOrTag).toLowerCase();
      var entries = (feed && feed.data) ? feed.data : [];
      for (var i = 0; i < entries.length; i++) {
        var ioc = entries[i];
        var val = String(ioc.ioc_value || ioc.ioc || '').toLowerCase();
        var mal = String(ioc.malware || ioc.malware_printable || '').toLowerCase();
        if (val.indexOf(term) !== -1 || mal.indexOf(term) !== -1) matches.push(ioc);
      }
      var result = { query_status: matches.length > 0 ? 'ok' : 'no_result', data: matches.length > 0 ? matches : [] };
      _cacheSet(ckey, result);
      callback(null, result);
    });
  }

  function searchIOC(ioc, callback) {
    var ckey = _cacheKey('threatfox', ioc);
    var cached = _cacheGet(ckey);
    if (cached) return callback(null, cached);

    _fetchJSON('/data/feeds/threat-iocs.json', { timeout: 15000 }, function(err, feed) {
      if (err) return callback(err, null);
      var matches = [];
      var term = String(ioc).toLowerCase();
      var entries = (feed && feed.data) ? feed.data : [];
      for (var i = 0; i < entries.length; i++) {
        var entry = entries[i];
        var val = String(entry.ioc_value || entry.ioc || '').toLowerCase();
        if (val.indexOf(term) !== -1) matches.push(entry);
      }
      var result = { query_status: matches.length > 0 ? 'ok' : 'no_result', data: matches.length > 0 ? matches : null };
      _cacheSet(ckey, result);
      callback(null, result);
    });
  }

  function recentIOCs(days, callback) {
    if (typeof days === 'function') { callback = days; days = 1; }
    var ckey = _cacheKey('threatfox_recent', String(days));
    var cached = _cacheGet(ckey);
    if (cached) return callback(null, cached);

    _fetchJSON('/data/feeds/threat-iocs.json', { timeout: 15000 }, function(err, feed) {
      if (err) return callback(err, null);
      var entries = (feed && feed.data) ? feed.data : [];
      var result = { query_status: entries.length > 0 ? 'ok' : 'no_result', data: entries.length > 0 ? entries : null };
      _cacheSet(ckey, result);
      callback(null, result);
    });
  }

  function getEPSS(cveId, callback) {
    var ckey = _cacheKey('epss', cveId);
    var cached = _cacheGet(ckey);
    if (cached) return callback(null, cached);

    var url = 'https://api.first.org/data/v1/epss?cve=' + encodeURIComponent(cveId);
    _fetchJSON(url, { timeout: 15000 }, function(err, data) {
      if (err) return callback(err, null);
      _cacheSet(ckey, data);
      callback(null, data);
    });
  }

  function geoIP(ip, callback) {
    var ckey = _cacheKey('geoip', ip);
    var cached = _cacheGet(ckey);
    if (cached) return callback(null, cached);

    var url = 'https://ipapi.co/' + encodeURIComponent(ip) + '/json/';
    _fetchJSON(url, { timeout: 10000 }, function(err, data) {
      if (err) return callback(err, null);
      _cacheSet(ckey, data);
      callback(null, data);
    });
  }

  function dnsLookup(domain, type, callback) {
    if (typeof type === 'function') { callback = type; type = 'A'; }
    var ckey = _cacheKey('dns', domain + '_' + type);
    var cached = _cacheGet(ckey);
    if (cached) return callback(null, cached);

    var url = 'https://dns.google/resolve?name=' + encodeURIComponent(domain) + '&type=' + encodeURIComponent(type);
    _fetchJSON(url, { timeout: 10000 }, function(err, data) {
      if (err) {
        var cfUrl = 'https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent(domain) + '&type=' + encodeURIComponent(type);
        _fetchJSON(cfUrl, {
          headers: { 'Accept': 'application/dns-json' },
          timeout: 10000
        }, function(err2, data2) {
          if (err2) return callback(err2, null);
          _cacheSet(ckey, data2);
          callback(null, data2);
        });
        return;
      }
      _cacheSet(ckey, data);
      callback(null, data);
    });
  }

  function checkNoise(ip, callback) {
    var ckey = _cacheKey('greynoise', ip);
    var cached = _cacheGet(ckey);
    if (cached) return callback(null, cached);

    var url = 'https://api.greynoise.io/v3/community/' + encodeURIComponent(ip);
    _fetchJSON(url, { timeout: 10000 }, function(err, data) {
      if (err) return callback(err, null);
      _cacheSet(ckey, data);
      callback(null, data);
    });
  }

  // =============================================
  // BYOK APIs (user provides key in Settings)
  // =============================================

  function checkIPReputation(ip, callback) {
    var key = getKey('abuseipdb');
    if (!key) return callback({ message: 'No AbuseIPDB API key configured. Add it in Settings > API Keys.' }, null);

    var ckey = _cacheKey('abuseipdb', ip);
    var cached = _cacheGet(ckey);
    if (cached) return callback(null, cached);

    var url = 'https://api.abuseipdb.com/api/v2/check?ipAddress=' + encodeURIComponent(ip) + '&maxAgeInDays=90';
    _fetchJSON(url, {
      headers: { 'Key': key, 'Accept': 'application/json' },
      timeout: 15000
    }, function(err, data) {
      if (err) return callback(err, null);
      _cacheSet(ckey, data);
      callback(null, data);
    });
  }

  function checkVT(resource, type, callback) {
    if (typeof type === 'function') { callback = type; type = 'file'; }
    var key = getKey('virustotal');
    if (!key) return callback({ message: 'No VirusTotal API key configured. Add it in Settings > API Keys.' }, null);

    var ckey = _cacheKey('vt_' + type, resource);
    var cached = _cacheGet(ckey);
    if (cached) return callback(null, cached);

    var endpoint;
    if (type === 'url') {
      endpoint = 'https://www.virustotal.com/api/v3/urls/' + encodeURIComponent(btoa(resource).replace(/=/g, ''));
    } else if (type === 'domain') {
      endpoint = 'https://www.virustotal.com/api/v3/domains/' + encodeURIComponent(resource);
    } else if (type === 'ip') {
      endpoint = 'https://www.virustotal.com/api/v3/ip_addresses/' + encodeURIComponent(resource);
    } else {
      endpoint = 'https://www.virustotal.com/api/v3/files/' + encodeURIComponent(resource);
    }

    _fetchJSON(endpoint, {
      headers: { 'x-apikey': key },
      timeout: 15000
    }, function(err, data) {
      if (err) return callback(err, null);
      _cacheSet(ckey, data);
      callback(null, data);
    });
  }

  function searchShodan(query, callback) {
    var key = getKey('shodan');
    if (!key) return callback({ message: 'No Shodan API key configured. Add it in Settings > API Keys.' }, null);

    var ckey = _cacheKey('shodan', query);
    var cached = _cacheGet(ckey);
    if (cached) return callback(null, cached);

    var url;
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(query)) {
      url = 'https://api.shodan.io/shodan/host/' + encodeURIComponent(query) + '?key=' + encodeURIComponent(key);
    } else {
      url = 'https://api.shodan.io/shodan/host/search?key=' + encodeURIComponent(key) + '&query=' + encodeURIComponent(query);
    }

    _fetchJSON(url, { timeout: 20000 }, function(err, data) {
      if (err) return callback(err, null);
      _cacheSet(ckey, data);
      callback(null, data);
    });
  }

  function getOTXPulses(callback) {
    var key = getKey('otx');
    if (!key) return callback({ message: 'No AlienVault OTX API key configured. Add it in Settings > API Keys.' }, null);

    var ckey = _cacheKey('otx', 'pulses');
    var cached = _cacheGet(ckey);
    if (cached) return callback(null, cached);

    var url = 'https://otx.alienvault.com/api/v1/pulses/subscribed?limit=20';
    _fetchJSON(url, {
      headers: { 'X-OTX-API-KEY': key },
      timeout: 15000
    }, function(err, data) {
      if (err) return callback(err, null);
      _cacheSet(ckey, data);
      callback(null, data);
    });
  }

  function checkOTXIndicator(type, indicator, callback) {
    var key = getKey('otx');
    if (!key) return callback({ message: 'No AlienVault OTX API key configured. Add it in Settings > API Keys.' }, null);

    var ckey = _cacheKey('otx_' + type, indicator);
    var cached = _cacheGet(ckey);
    if (cached) return callback(null, cached);

    var section = 'general';
    var url = 'https://otx.alienvault.com/api/v1/indicators/' + encodeURIComponent(type) + '/' + encodeURIComponent(indicator) + '/' + section;
    _fetchJSON(url, {
      headers: { 'X-OTX-API-KEY': key },
      timeout: 15000
    }, function(err, data) {
      if (err) return callback(err, null);
      _cacheSet(ckey, data);
      callback(null, data);
    });
  }

  function clearCache() {
    _cache = {};
  }

  return {
    searchCVE: searchCVE,
    getCVE: getCVE,
    recentCriticalCVEs: recentCriticalCVEs,
    searchCerts: searchCerts,
    searchURLhaus: searchURLhaus,
    recentURLhaus: recentURLhaus,
    searchMalware: searchMalware,
    searchIOC: searchIOC,
    recentIOCs: recentIOCs,
    getEPSS: getEPSS,
    geoIP: geoIP,
    dnsLookup: dnsLookup,
    checkNoise: checkNoise,
    checkIPReputation: checkIPReputation,
    checkVT: checkVT,
    searchShodan: searchShodan,
    getOTXPulses: getOTXPulses,
    checkOTXIndicator: checkOTXIndicator,
    getKey: getKey,
    setKey: setKey,
    getAllKeys: getAllKeys,
    clearCache: clearCache,
    esc: esc
  };
})();
