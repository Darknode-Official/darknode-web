// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Address Intelligence -- IP, domain, and URL intelligence gathering from real public sources.
// Parallel lookups against GreyNoise, AbuseIPDB, Shodan, VirusTotal, crt.sh, DNS, plus
// saved ThreatFox / URLhaus snapshot files (not live queries)

var esc = function(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, function(c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
  });
};

var HISTORY_KEY = "dn_address_intel_history";
var API_KEYS_KEY = "dn_api_keys";

function getApiKeys() {
  try { return JSON.parse(localStorage.getItem(API_KEYS_KEY) || "{}"); }
  catch(e) { return {}; }
}

function getHistory() {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]"); }
  catch(e) { return []; }
}

function saveHistory(entry) {
  var hist = getHistory();
  hist.unshift(entry);
  if (hist.length > 20) hist = hist.slice(0, 20);
  try { localStorage.setItem(HISTORY_KEY, JSON.stringify(hist)); } catch(e) {}
}

// Dotted-decimal octets are 0–255 (RFC 791); `\d{1,3}` alone accepts 256–999,
// so validate each octet's numeric range as the project's own isValidIPv4 does.
function _validIPv4Octets(s) {
  return s.split(".").every(function(o) { return /^\d{1,3}$/.test(o) && Number(o) <= 255; });
}

function detectInputType(input) {
  if (!input) return null;
  input = input.trim();
  if (/^https?:\/\//i.test(input)) return "URL";
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(input) && _validIPv4Octets(input)) return "IP";
  if (/^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/.test(input)) return "DOMAIN";
  if (/^(\d{1,3}\.){3}\d{1,3}(:\d+)?$/.test(input) && _validIPv4Octets(input.split(":")[0])) return "IP";
  return null;
}

function extractDomain(url) {
  try {
    var a = document.createElement("a");
    a.href = url;
    return a.hostname;
  } catch(e) {
    return url.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
  }
}

function reverseIP(ip) {
  return ip.split(".").reverse().join(".");
}

function riskColor(score) {
  if (score < 20) return "#2ecc71";
  if (score < 40) return "#f1c40f";
  if (score < 60) return "#e67e22";
  if (score < 80) return "#e74c3c";
  return "#c0392b";
}

function riskLabel(score) {
  if (score < 0) return "Unknown";
  if (score < 20) return "Low";
  if (score < 40) return "Moderate";
  if (score < 60) return "Elevated";
  if (score < 80) return "High";
  return "Critical";
}

function formatTimestamp(ts) {
  if (!ts) return "N/A";
  var d = new Date(ts);
  if (isNaN(d.getTime())) return String(ts);
  return d.toLocaleString();
}

function truncate(s, len) {
  s = String(s || "");
  if (s.length <= len) return s;
  return s.substring(0, len) + "...";
}

// ---- API fetchers ----

function fetchJSON(url, opts) {
  return fetch(url, opts || {}).then(function(r) {
    if (!r.ok) throw new Error("HTTP " + r.status);
    return r.json();
  });
}

function fetchGeoIP(ip) {
  return fetchJSON("https://ipapi.co/" + encodeURIComponent(ip) + "/json/");
}

function fetchReverseDNS(ip) {
  var rev = reverseIP(ip) + ".in-addr.arpa";
  return fetchJSON("https://dns.google/resolve?name=" + encodeURIComponent(rev) + "&type=PTR");
}

function fetchGreyNoise(ip) {
  return fetchJSON("https://api.greynoise.io/v3/community/" + encodeURIComponent(ip));
}

function fetchAbuseIPDB(ip, key) {
  return fetch("https://api.abuseipdb.com/api/v2/check?ipAddress=" + encodeURIComponent(ip) + "&maxAgeInDays=90", {
    headers: { "Key": key, "Accept": "application/json" }
  }).then(function(r) {
    if (!r.ok) throw new Error("HTTP " + r.status);
    return r.json();
  });
}

function fetchShodan(ip, key) {
  return fetchJSON("https://api.shodan.io/shodan/host/" + encodeURIComponent(ip) + "?key=" + encodeURIComponent(key));
}

function fetchVirusTotalIP(ip, key) {
  return fetch("https://www.virustotal.com/api/v3/ip_addresses/" + encodeURIComponent(ip), {
    headers: { "x-apikey": key }
  }).then(function(r) {
    if (!r.ok) throw new Error("HTTP " + r.status);
    return r.json();
  });
}

function fetchVirusTotalDomain(domain, key) {
  return fetch("https://www.virustotal.com/api/v3/domains/" + encodeURIComponent(domain), {
    headers: { "x-apikey": key }
  }).then(function(r) {
    if (!r.ok) throw new Error("HTTP " + r.status);
    return r.json();
  });
}

function fetchVirusTotalURL(url, key) {
  // VirusTotal v3 URL id = unpadded base64url of the URL. btoa() emits
  // standard base64, so translate +/ to -_ or the id won't match VT's.
  var urlId = btoa(url).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return fetch("https://www.virustotal.com/api/v3/urls/" + encodeURIComponent(urlId), {
    headers: { "x-apikey": key }
  }).then(function(r) {
    if (!r.ok) throw new Error("HTTP " + r.status);
    return r.json();
  });
}

// ThreatFox and URLhaus are NOT queried live: they read saved snapshot files
// under /data/feeds/ (written by tools/threat-feed-sync.py). The snapshot
// format is { updated, source, count, data: [...] } with camelCase fields
// (iocValue, confidenceLevel, dateAdded, status ...). Entries are normalised
// to the field names the render code uses, and the snapshot date is kept so
// the UI can label the source honestly.
var _aiSnapCache = {};
function loadSnapshot(path) {
  if (!_aiSnapCache[path]) {
    _aiSnapCache[path] = fetch(path).then(function(r) {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    }).then(function(feed) {
      var entries = Array.isArray(feed) ? feed : ((feed && Array.isArray(feed.data)) ? feed.data : []);
      return { entries: entries, updated: (feed && !Array.isArray(feed) && feed.updated) || null };
    });
    _aiSnapCache[path].catch(function() { delete _aiSnapCache[path]; });
  }
  return _aiSnapCache[path];
}

// Host part of an IOC / URL value: strips scheme (incl. defanged hxxp), port, path.
function iocHost(v) {
  var s = String(v || "").toLowerCase().trim().replace(/^hxxp/, "http").replace(/\[\.\]/g, ".");
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
  s = s.split(/[\/?#]/)[0];
  if (s.charAt(0) === "[") return s.slice(1, s.indexOf("]") > 0 ? s.indexOf("]") : undefined);
  if ((s.match(/:/g) || []).length === 1) s = s.split(":")[0];
  return s;
}

function hostMatches(candidate, term) {
  return candidate === term || (candidate.length > term.length && candidate.slice(-(term.length + 1)) === "." + term);
}

function fetchThreatFox(searchTerm) {
  return loadSnapshot("/data/feeds/threat-iocs.json").then(function(snap) {
    var matches = [];
    var term = iocHost(searchTerm);
    for (var i = 0; i < snap.entries.length; i++) {
      var e = snap.entries[i];
      var raw = e.iocValue || e.ioc_value || e.ioc || "";
      if (!raw) continue;
      if (String(raw).toLowerCase() === String(searchTerm).toLowerCase() || hostMatches(iocHost(raw), term)) {
        matches.push({
          ioc: raw,
          threat_type: e.threat_type || e.threatType || e.iocType || "",
          malware: e.malware || "",
          malware_printable: e.malware_printable || e.malwarePrintable || e.malware || "",
          confidence_level: e.confidence_level != null ? e.confidence_level : e.confidenceLevel,
          first_seen: e.first_seen || e.firstSeen || "",
          tags: e.tags || []
        });
      }
    }
    return { query_status: matches.length > 0 ? "ok" : "no_result", data: matches.length > 0 ? matches : null, snapshot: { updated: snap.updated, count: snap.entries.length } };
  });
}

function normURLhaus(u) {
  return {
    url: u.url || "",
    host: u.host || "",
    url_status: u.url_status || u.status || "",
    threat: u.threat || "",
    date_added: u.date_added || u.dateAdded || "",
    tags: u.tags || []
  };
}

function fetchURLhaus(host) {
  return loadSnapshot("/data/feeds/malware-urls.json").then(function(snap) {
    var matches = [];
    var h = iocHost(host);
    for (var i = 0; i < snap.entries.length; i++) {
      var u = snap.entries[i];
      if (hostMatches(iocHost(u.host || u.url), h)) matches.push(normURLhaus(u));
    }
    return { query_status: matches.length > 0 ? "ok" : "no_results", urls: matches.length > 0 ? matches : null, snapshot: { updated: snap.updated, count: snap.entries.length } };
  });
}

function fetchURLhausURL(url) {
  return loadSnapshot("/data/feeds/malware-urls.json").then(function(snap) {
    var matches = [];
    var target = String(url).toLowerCase().replace(/^hxxp/, "http");
    for (var i = 0; i < snap.entries.length; i++) {
      var u = snap.entries[i];
      var uUrl = String(u.url || "").toLowerCase().replace(/^hxxp/, "http");
      if (uUrl && uUrl === target) matches.push(normURLhaus(u));
    }
    return { query_status: matches.length > 0 ? "ok" : "no_results", urls: matches.length > 0 ? matches : null, snapshot: { updated: snap.updated, count: snap.entries.length } };
  });
}

// "snapshot, updated 2026-09-18" label for a snapshot-backed source.
function snapshotLabel(res) {
  var snap = res && res.snapshot;
  var d = snap && snap.updated ? String(snap.updated).slice(0, 10) : "";
  return "snapshot" + (d ? ", updated " + d : "") + ", not live";
}

function fetchDNSRecords(domain, type) {
  return fetchJSON("https://dns.google/resolve?name=" + encodeURIComponent(domain) + "&type=" + encodeURIComponent(type));
}

function fetchCertTransparency(domain) {
  return fetchJSON("https://crt.sh/?q=" + encodeURIComponent(domain) + "&output=json");
}

// ---- Risk score calculation ----

function calculateRisk(results) {
  var score = -1;
  var tags = [];
  var hasData = false;

  if (results.greynoise && results.greynoise.classification) {
    hasData = true;
    var cl = results.greynoise.classification.toLowerCase();
    if (cl === "malicious") { score = Math.max(score, 0) + 40; tags.push("malicious"); }
    else if (cl === "benign") { score = Math.max(score, 0); tags.push("benign"); }
    else { score = Math.max(score, 0) + 10; }
    if (results.greynoise.noise) tags.push("scanner");
    if (results.greynoise.riot) tags.push("known-service");
  }

  if (results.abuseipdb && results.abuseipdb.data) {
    hasData = true;
    var conf = results.abuseipdb.data.abuseConfidenceScore || 0;
    score = Math.max(score, 0) + Math.round(conf * 0.5);
    if (conf > 50) tags.push("reported-abuse");
    if (results.abuseipdb.data.totalReports > 10) tags.push("frequent-reports");
  }

  if (results.threatfox && results.threatfox.query_status === "ok" && results.threatfox.data) {
    hasData = true;
    var tfCount = Array.isArray(results.threatfox.data) ? results.threatfox.data.length : 0;
    if (tfCount > 0) {
      score = Math.max(score, 0) + Math.min(tfCount * 30, 60);
      tags.push("threatfox-hit");
    }
  }

  if (results.urlhaus && results.urlhaus.query_status === "ok" && results.urlhaus.urls) {
    hasData = true;
    var uhCount = Array.isArray(results.urlhaus.urls) ? results.urlhaus.urls.length : 0;
    if (uhCount > 0) {
      score = Math.max(score, 0) + Math.min(uhCount * 30, 60);
      tags.push("urlhaus-hit");
    }
  }

  if (results.virustotal && results.virustotal.data && results.virustotal.data.attributes) {
    hasData = true;
    var stats = results.virustotal.data.attributes.last_analysis_stats;
    if (stats) {
      var vtMal = stats.malicious || 0;
      var vtTotal = (stats.malicious || 0) + (stats.undetected || 0) + (stats.harmless || 0) + (stats.suspicious || 0);
      if (vtTotal > 0) {
        score = Math.max(score, 0) + Math.round((vtMal / vtTotal) * 50);
        if (vtMal > 5) tags.push("vt-detections");
      }
    }
  }

  if (results.shodan && results.shodan.ports) {
    hasData = true;
    if (results.shodan.ports.length > 20) tags.push("many-open-ports");
    if (results.shodan.vulns && results.shodan.vulns.length > 0) {
      score = Math.max(score, 0) + Math.min(results.shodan.vulns.length * 5, 30);
      tags.push("known-vulns");
    }
  }

  if (!hasData) return { score: -1, label: "Unknown", tags: [] };
  score = Math.max(0, Math.min(100, score));
  return { score: score, label: riskLabel(score), tags: tags };
}

// ---- Panel renderers ----

function panelLoading() {
  return '<div class="ai-panel-loading"><span class="ai-dot"></span><span class="ai-dot"></span><span class="ai-dot"></span></div>';
}

function panelUnavailable(reason) {
  return '<div class="ai-panel-unavail">' + esc(reason || "Data unavailable") + '</div>';
}

function panelNeedsKey(service) {
  return '<div class="ai-panel-unavail">Requires API key for ' + esc(service) + '. Add it in API Keys settings.</div>';
}

function renderKV(label, value) {
  return '<div class="ai-kv"><span class="ai-kv-label">' + esc(label) + '</span><span class="ai-kv-value">' + esc(value || "N/A") + '</span></div>';
}

function renderSummaryCard(input, type, risk) {
  var scoreHTML = "";
  if (risk.score >= 0) {
    var col = riskColor(risk.score);
    var deg = Math.round((risk.score / 100) * 360);
    scoreHTML = '<div class="ai-score-gauge" style="background:conic-gradient(' + col + ' 0deg,' + col + ' ' + deg + 'deg,rgba(255,255,255,0.05) ' + deg + 'deg)">' +
      '<div class="ai-score-inner"><span class="ai-score-num" style="color:' + col + '">' + risk.score + '</span><span class="ai-score-of">/100</span></div></div>';
  } else {
    scoreHTML = '<div class="ai-score-gauge ai-score-unknown"><div class="ai-score-inner"><span class="ai-score-num">?</span><span class="ai-score-of">Unknown</span></div></div>';
  }

  var tagsHTML = "";
  if (risk.tags && risk.tags.length > 0) {
    for (var i = 0; i < risk.tags.length; i++) {
      var tagClass = "ai-tag";
      if (risk.tags[i] === "malicious" || risk.tags[i] === "reported-abuse" || risk.tags[i] === "threatfox-hit" || risk.tags[i] === "urlhaus-hit") tagClass += " ai-tag-danger";
      else if (risk.tags[i] === "benign" || risk.tags[i] === "known-service") tagClass += " ai-tag-safe";
      else tagClass += " ai-tag-warn";
      tagsHTML += '<span class="' + tagClass + '">' + esc(risk.tags[i]) + '</span>';
    }
  }

  return '<div class="ai-summary-card">' +
    '<div class="ai-summary-left">' +
      '<div class="ai-summary-address">' + esc(input) + '</div>' +
      '<div class="ai-summary-meta">' +
        '<span class="ai-type-badge ai-type-' + type.toLowerCase() + '">' + esc(type) + '</span>' +
        '<span class="ai-summary-time">Scanned: ' + esc(new Date().toLocaleString()) + '</span>' +
      '</div>' +
      '<div class="ai-summary-risk">Risk: <strong style="color:' + (risk.score >= 0 ? riskColor(risk.score) : "var(--mut)") + '">' + esc(risk.label) + '</strong></div>' +
      (tagsHTML ? '<div class="ai-tags-row">' + tagsHTML + '</div>' : '') +
    '</div>' +
    '<div class="ai-summary-right">' + scoreHTML + '</div>' +
  '</div>';
}

function renderGeoPanel(data) {
  if (!data) return panelUnavailable("Geolocation data unavailable");
  return '<div class="ai-panel-body">' +
    '<div class="ai-kv-grid">' +
      renderKV("Country", (data.country_name || data.country || "N/A") + (data.country_code ? " (" + data.country_code + ")" : "")) +
      renderKV("City", data.city) +
      renderKV("Region", data.region) +
      renderKV("ISP", data.org || data.isp) +
      renderKV("ASN", data.asn) +
      renderKV("Organization", data.org) +
      renderKV("Timezone", data.timezone) +
      renderKV("Latitude", data.latitude) +
      renderKV("Longitude", data.longitude) +
      renderKV("Postal Code", data.postal) +
    '</div>' +
    (data.latitude && data.longitude ?
      '<div class="ai-map-placeholder">' +
        '<div class="ai-map-coords">' + esc(data.latitude) + ', ' + esc(data.longitude) + '</div>' +
        '<div class="ai-map-label">Approximate location</div>' +
      '</div>' : '') +
  '</div>';
}

function renderNetworkPanel(data, shodan, reverseDNS) {
  var html = '<div class="ai-panel-body">';

  // Reverse DNS
  var rdns = "N/A";
  if (reverseDNS && reverseDNS.Answer && reverseDNS.Answer.length > 0) {
    rdns = reverseDNS.Answer.map(function(a) { return a.data; }).join(", ");
  }
  html += '<div class="ai-kv-grid">' +
    renderKV("Reverse DNS", rdns) +
    renderKV("ASN", data ? data.asn : "N/A") +
    renderKV("Organization", data ? (data.org || data.isp) : "N/A") +
    renderKV("Network", data ? data.network : "N/A") +
  '</div>';

  // Shodan ports
  if (shodan && shodan.ports && shodan.ports.length > 0) {
    html += '<div class="ai-subsection-title">Open Ports (' + shodan.ports.length + ')</div>';
    html += '<table class="ai-table"><thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Product</th><th>Banner</th></tr></thead><tbody>';
    var services = shodan.data || [];
    for (var i = 0; i < services.length && i < 50; i++) {
      var svc = services[i];
      html += '<tr>' +
        '<td>' + esc(svc.port) + '</td>' +
        '<td>' + esc(svc.transport || "tcp") + '</td>' +
        '<td>' + esc(svc._shodan && svc._shodan.module ? svc._shodan.module : (svc.product || "unknown")) + '</td>' +
        '<td>' + esc(svc.product || "") + (svc.version ? " " + esc(svc.version) : "") + '</td>' +
        '<td class="ai-banner-cell">' + esc(truncate(svc.data || "", 120)) + '</td>' +
      '</tr>';
    }
    html += '</tbody></table>';

    if (shodan.vulns && shodan.vulns.length > 0) {
      html += '<div class="ai-subsection-title">Known Vulnerabilities (' + shodan.vulns.length + ')</div>';
      html += '<div class="ai-vuln-list">';
      for (var v = 0; v < shodan.vulns.length && v < 30; v++) {
        html += '<span class="ai-vuln-badge">' + esc(shodan.vulns[v]) + '</span>';
      }
      html += '</div>';
    }

    html += '<div class="ai-kv-grid" style="margin-top:12px">' +
      renderKV("OS", shodan.os || "Unknown") +
      renderKV("Last Update", shodan.last_update || "N/A") +
      renderKV("Hostnames", (shodan.hostnames || []).join(", ") || "None") +
    '</div>';
  } else if (shodan === null) {
    html += '<div class="ai-subsection-title">Open Ports</div>' + panelNeedsKey("Shodan");
  } else {
    html += '<div class="ai-subsection-title">Open Ports</div>' + panelUnavailable("No port data available");
  }

  html += '</div>';
  return html;
}

function renderReputationPanel(results) {
  var html = '<div class="ai-panel-body">';

  // GreyNoise
  html += '<div class="ai-subsection-title">GreyNoise</div>';
  if (results.greynoise) {
    var gn = results.greynoise;
    var gnClass = (gn.classification || "unknown").toLowerCase();
    var gnColor = gnClass === "malicious" ? "#e74c3c" : (gnClass === "benign" ? "#2ecc71" : "var(--mut)");
    html += '<div class="ai-kv-grid">' +
      '<div class="ai-kv"><span class="ai-kv-label">Classification</span><span class="ai-kv-value" style="color:' + gnColor + ';font-weight:600">' + esc(gn.classification || "Unknown") + '</span></div>' +
      renderKV("Noise", gn.noise ? "Yes (Internet scanner)" : "No") +
      renderKV("RIOT", gn.riot ? "Yes (Known service)" : "No") +
      renderKV("Name", gn.name || "N/A") +
      renderKV("Last Seen", gn.last_seen || "N/A") +
      renderKV("Message", gn.message || "") +
    '</div>';
  } else if (results.greynoise_err) {
    html += panelUnavailable(results.greynoise_err);
  } else {
    html += panelLoading();
  }

  // AbuseIPDB
  html += '<div class="ai-subsection-title">AbuseIPDB</div>';
  if (results.abuseipdb && results.abuseipdb.data) {
    var ab = results.abuseipdb.data;
    var abColor = ab.abuseConfidenceScore > 50 ? "#e74c3c" : (ab.abuseConfidenceScore > 20 ? "#e67e22" : "#2ecc71");
    html += '<div class="ai-kv-grid">' +
      '<div class="ai-kv"><span class="ai-kv-label">Abuse Confidence</span><span class="ai-kv-value" style="color:' + abColor + ';font-weight:600">' + esc(ab.abuseConfidenceScore) + '%</span></div>' +
      renderKV("Total Reports", ab.totalReports) +
      renderKV("Distinct Users", ab.numDistinctUsers) +
      renderKV("Usage Type", ab.usageType) +
      renderKV("ISP", ab.isp) +
      renderKV("Domain", ab.domain) +
      renderKV("Country", ab.countryCode) +
      renderKV("Last Reported", ab.lastReportedAt || "Never") +
    '</div>';
  } else if (results.abuseipdb_err) {
    html += panelUnavailable(results.abuseipdb_err);
  } else if (results.abuseipdb_nokey) {
    html += panelNeedsKey("AbuseIPDB");
  } else {
    html += panelLoading();
  }

  // VirusTotal
  html += '<div class="ai-subsection-title">VirusTotal</div>';
  if (results.virustotal && results.virustotal.data && results.virustotal.data.attributes) {
    var vt = results.virustotal.data.attributes;
    var vtStats = vt.last_analysis_stats || {};
    var vtMal = vtStats.malicious || 0;
    var vtSus = vtStats.suspicious || 0;
    var vtHarm = vtStats.harmless || 0;
    var vtUnd = vtStats.undetected || 0;
    var vtColor = vtMal > 5 ? "#e74c3c" : (vtMal > 0 ? "#e67e22" : "#2ecc71");
    html += '<div class="ai-kv-grid">' +
      '<div class="ai-kv"><span class="ai-kv-label">Detections</span><span class="ai-kv-value" style="color:' + vtColor + ';font-weight:600">' + vtMal + ' malicious, ' + vtSus + ' suspicious</span></div>' +
      renderKV("Harmless", vtHarm) +
      renderKV("Undetected", vtUnd) +
      renderKV("Reputation", vt.reputation != null ? vt.reputation : "N/A") +
    '</div>';
  } else if (results.virustotal_err) {
    html += panelUnavailable(results.virustotal_err);
  } else if (results.virustotal_nokey) {
    html += panelNeedsKey("VirusTotal");
  } else {
    html += panelLoading();
  }

  // ThreatFox
  html += '<div class="ai-subsection-title">ThreatFox IOC <span class="ai-snap-note">(' + esc(snapshotLabel(results.threatfox)) + ')</span></div>';
  if (results.threatfox) {
    if (results.threatfox.query_status === "ok" && results.threatfox.data && results.threatfox.data.length > 0) {
      html += '<table class="ai-table"><thead><tr><th>IOC</th><th>Threat Type</th><th>Malware</th><th>Confidence</th><th>First Seen</th></tr></thead><tbody>';
      for (var t = 0; t < results.threatfox.data.length && t < 20; t++) {
        var tf = results.threatfox.data[t];
        html += '<tr>' +
          '<td>' + esc(truncate(tf.ioc || "", 60)) + '</td>' +
          '<td>' + esc(tf.threat_type || "") + '</td>' +
          '<td>' + esc(tf.malware_printable || tf.malware || "") + '</td>' +
          '<td>' + esc(tf.confidence_level || "") + '%</td>' +
          '<td>' + esc(tf.first_seen || "") + '</td>' +
        '</tr>';
      }
      html += '</tbody></table>';
    } else {
      html += panelUnavailable("No match in the saved ThreatFox snapshot" + (results.threatfox.snapshot ? " (" + results.threatfox.snapshot.count + " entries)" : ""));
    }
  } else if (results.threatfox_err) {
    html += panelUnavailable(results.threatfox_err);
  } else {
    html += panelLoading();
  }

  // URLhaus
  html += '<div class="ai-subsection-title">URLhaus <span class="ai-snap-note">(' + esc(snapshotLabel(results.urlhaus)) + ')</span></div>';
  if (results.urlhaus) {
    if (results.urlhaus.query_status !== "no_result" && results.urlhaus.urls && results.urlhaus.urls.length > 0) {
      html += '<table class="ai-table"><thead><tr><th>URL</th><th>Status</th><th>Threat</th><th>Date Added</th><th>Tags</th></tr></thead><tbody>';
      for (var u = 0; u < results.urlhaus.urls.length && u < 20; u++) {
        var uh = results.urlhaus.urls[u];
        var uhStatusClass = uh.url_status === "online" ? "color:#e74c3c;font-weight:600" : "";
        html += '<tr>' +
          '<td>' + esc(truncate(uh.url || "", 80)) + '</td>' +
          '<td style="' + uhStatusClass + '">' + esc(uh.url_status || "") + '</td>' +
          '<td>' + esc(uh.threat || "") + '</td>' +
          '<td>' + esc(uh.date_added || "") + '</td>' +
          '<td>' + esc((uh.tags || []).join(", ")) + '</td>' +
        '</tr>';
      }
      html += '</tbody></table>';
    } else {
      html += panelUnavailable("No match in the saved URLhaus snapshot" + (results.urlhaus.snapshot ? " (" + results.urlhaus.snapshot.count + " entries)" : ""));
    }
  } else if (results.urlhaus_err) {
    html += panelUnavailable(results.urlhaus_err);
  } else {
    html += panelLoading();
  }

  html += '</div>';
  return html;
}

function renderDNSPanel(dnsResults) {
  if (!dnsResults) return panelLoading();
  var html = '<div class="ai-panel-body">';
  var types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"];

  for (var i = 0; i < types.length; i++) {
    var t = types[i];
    var data = dnsResults[t];
    html += '<div class="ai-subsection-title">' + esc(t) + ' Records</div>';
    if (data && data.Answer && data.Answer.length > 0) {
      html += '<table class="ai-table"><thead><tr><th>Name</th><th>TTL</th><th>Data</th></tr></thead><tbody>';
      for (var j = 0; j < data.Answer.length; j++) {
        var rec = data.Answer[j];
        html += '<tr>' +
          '<td>' + esc(rec.name || "") + '</td>' +
          '<td>' + esc(rec.TTL || "") + '</td>' +
          '<td>' + esc(rec.data || "") + '</td>' +
        '</tr>';
      }
      html += '</tbody></table>';
    } else {
      html += '<div class="ai-no-records">No ' + esc(t) + ' records found</div>';
    }
  }

  html += '</div>';
  return html;
}

function renderCertsPanel(certs, subdomains) {
  var html = '<div class="ai-panel-body">';

  // Subdomains
  if (subdomains && subdomains.length > 0) {
    html += '<div class="ai-subsection-title">Discovered Subdomains (' + subdomains.length + ')</div>';
    html += '<div class="ai-subdomain-list">';
    for (var s = 0; s < subdomains.length && s < 100; s++) {
      html += '<span class="ai-subdomain-badge">' + esc(subdomains[s]) + '</span>';
    }
    if (subdomains.length > 100) {
      html += '<span class="ai-subdomain-badge ai-subdomain-more">+' + (subdomains.length - 100) + ' more</span>';
    }
    html += '</div>';
  }

  // Certificates
  html += '<div class="ai-subsection-title">Certificate Transparency Logs</div>';
  if (certs && certs.length > 0) {
    html += '<table class="ai-table"><thead><tr><th>Common Name</th><th>Issuer</th><th>Not Before</th><th>Not After</th><th>SAN Entries</th></tr></thead><tbody>';
    var seen = {};
    var count = 0;
    for (var c = 0; c < certs.length && count < 50; c++) {
      var cert = certs[c];
      var key = (cert.common_name || "") + "|" + (cert.serial_number || c);
      if (seen[key]) continue;
      seen[key] = true;
      count++;
      html += '<tr>' +
        '<td>' + esc(cert.common_name || "") + '</td>' +
        '<td>' + esc(cert.issuer_name || "") + '</td>' +
        '<td>' + esc(cert.not_before || "") + '</td>' +
        '<td>' + esc(cert.not_after || "") + '</td>' +
        '<td>' + esc(truncate(cert.name_value || "", 80)) + '</td>' +
      '</tr>';
    }
    html += '</tbody></table>';
    if (certs.length > 50) {
      html += '<div class="ai-more-indicator">' + certs.length + ' total certificates found (showing first 50)</div>';
    }
  } else {
    html += panelUnavailable("No certificate transparency data found");
  }

  html += '</div>';
  return html;
}

function renderThreatIntelPanel(results) {
  var html = '<div class="ai-panel-body">';
  var hasContent = false;

  // ThreatFox malware families
  if (results.threatfox && results.threatfox.query_status === "ok" && results.threatfox.data && results.threatfox.data.length > 0) {
    hasContent = true;
    var families = {};
    for (var i = 0; i < results.threatfox.data.length; i++) {
      var mw = results.threatfox.data[i].malware_printable || results.threatfox.data[i].malware || "Unknown";
      if (!families[mw]) families[mw] = { count: 0, types: {} };
      families[mw].count++;
      var tt = results.threatfox.data[i].threat_type || "unknown";
      families[mw].types[tt] = true;
    }
    html += '<div class="ai-subsection-title">Associated Malware Families</div>';
    html += '<div class="ai-malware-grid">';
    var famKeys = Object.keys(families);
    for (var f = 0; f < famKeys.length; f++) {
      var fam = families[famKeys[f]];
      html += '<div class="ai-malware-card">' +
        '<div class="ai-malware-name">' + esc(famKeys[f]) + '</div>' +
        '<div class="ai-malware-meta">' + fam.count + ' IOC' + (fam.count > 1 ? "s" : "") + ' | ' + esc(Object.keys(fam.types).join(", ")) + '</div>' +
      '</div>';
    }
    html += '</div>';
  }

  // URLhaus threat info
  if (results.urlhaus && results.urlhaus.urls && results.urlhaus.urls.length > 0) {
    hasContent = true;
    html += '<div class="ai-subsection-title">Malware URLs (URLhaus ' + esc(snapshotLabel(results.urlhaus)) + ')</div>';
    var threats = {};
    for (var u = 0; u < results.urlhaus.urls.length; u++) {
      var thr = results.urlhaus.urls[u].threat || "unknown";
      if (!threats[thr]) threats[thr] = 0;
      threats[thr]++;
    }
    html += '<div class="ai-threat-summary">';
    var thrKeys = Object.keys(threats);
    for (var tk = 0; tk < thrKeys.length; tk++) {
      html += '<div class="ai-threat-item"><span class="ai-threat-type">' + esc(thrKeys[tk]) + '</span><span class="ai-threat-count">' + threats[thrKeys[tk]] + ' URL' + (threats[thrKeys[tk]] > 1 ? "s" : "") + '</span></div>';
    }
    html += '</div>';
    html += '<div class="ai-kv-grid" style="margin-top:8px">' +
      renderKV("Total URLs", results.urlhaus.urls.length) +
      renderKV("Online", results.urlhaus.urls.filter(function(x) { return x.url_status === "online"; }).length) +
      renderKV("Offline", results.urlhaus.urls.filter(function(x) { return x.url_status !== "online"; }).length) +
    '</div>';
  }

  // VirusTotal tags
  if (results.virustotal && results.virustotal.data && results.virustotal.data.attributes) {
    var vtAttr = results.virustotal.data.attributes;
    if (vtAttr.tags && vtAttr.tags.length > 0) {
      hasContent = true;
      html += '<div class="ai-subsection-title">VirusTotal Tags</div>';
      html += '<div class="ai-tags-row">';
      for (var vt = 0; vt < vtAttr.tags.length; vt++) {
        html += '<span class="ai-tag ai-tag-warn">' + esc(vtAttr.tags[vt]) + '</span>';
      }
      html += '</div>';
    }
    if (vtAttr.categories) {
      hasContent = true;
      html += '<div class="ai-subsection-title">VirusTotal Categories</div>';
      html += '<div class="ai-kv-grid">';
      var catKeys = Object.keys(vtAttr.categories);
      for (var ck = 0; ck < catKeys.length && ck < 20; ck++) {
        html += renderKV(catKeys[ck], vtAttr.categories[catKeys[ck]]);
      }
      html += '</div>';
    }
  }

  if (!hasContent) {
    html += panelUnavailable("No threat intelligence matches found");
  }

  html += '</div>';
  return html;
}

function renderRawPanel(results) {
  var html = '<div class="ai-panel-body">';
  var sources = ["geoip", "reverseDNS", "greynoise", "abuseipdb", "shodan", "virustotal", "threatfox", "urlhaus", "dns", "certs"];

  for (var i = 0; i < sources.length; i++) {
    var key = sources[i];
    var data = results[key];
    if (!data) continue;
    html += '<div class="ai-raw-section">' +
      '<button class="ai-raw-toggle" data-target="ai-raw-' + key + '">' + esc(key.toUpperCase()) + ' <span class="ai-raw-arrow">+</span></button>' +
      '<pre class="ai-raw-content" id="ai-raw-' + key + '" style="display:none">' + esc(JSON.stringify(data, null, 2)) + '</pre>' +
    '</div>';
  }

  html += '</div>';
  return html;
}

// ---- Main investigation orchestrator ----

function runInvestigation(input, type, container) {
  var results = {};
  var panels = {};
  var ip = null;
  var domain = null;
  var fullURL = null;

  if (type === "IP") {
    ip = input;
  } else if (type === "DOMAIN") {
    domain = input;
  } else if (type === "URL") {
    fullURL = input;
    domain = extractDomain(input);
    // Check if domain is actually an IP
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(domain)) {
      ip = domain;
      domain = null;
    }
  }

  var keys = getApiKeys();

  // Build panels structure
  var panelOrder = [];
  if (ip) {
    panelOrder.push({ id: "geo", title: "Geolocation", border: "#3498db" });
    panelOrder.push({ id: "network", title: "Network & Ports", border: "#9b59b6" });
  }
  panelOrder.push({ id: "reputation", title: "Reputation & Abuse", border: "#e74c3c" });
  if (domain) {
    panelOrder.push({ id: "dns", title: "DNS Records", border: "#2ecc71" });
    panelOrder.push({ id: "certs", title: "Certificates & Subdomains", border: "#f39c12" });
  }
  panelOrder.push({ id: "threat", title: "Threat Intelligence", border: "#e74c3c" });
  panelOrder.push({ id: "raw", title: "Raw API Responses", border: "var(--line)" });

  // Render skeleton
  var html = '<div id="ai-summary-mount"></div>';
  for (var p = 0; p < panelOrder.length; p++) {
    var pn = panelOrder[p];
    html += '<div class="ai-panel" style="border-left-color:' + pn.border + '" id="ai-panel-' + pn.id + '">' +
      '<div class="ai-panel-header">' + esc(pn.title) + '</div>' +
      '<div class="ai-panel-content" id="ai-content-' + pn.id + '">' + panelLoading() + '</div>' +
    '</div>';
  }
  container.innerHTML = html;

  function updatePanel(id, content) {
    var el = document.getElementById("ai-content-" + id);
    if (el) el.innerHTML = content;
  }

  function updateSummary() {
    var risk = calculateRisk(results);
    var el = document.getElementById("ai-summary-mount");
    if (el) el.innerHTML = renderSummaryCard(input, type, risk);
    return risk;
  }

  // Launch all applicable fetches in parallel

  // --- IP lookups ---
  if (ip) {
    fetchGeoIP(ip).then(function(data) {
      results.geoip = data;
      updatePanel("geo", renderGeoPanel(data));
    }).catch(function() {
      updatePanel("geo", panelUnavailable("Geolocation lookup failed"));
    });

    fetchReverseDNS(ip).then(function(data) {
      results.reverseDNS = data;
    }).catch(function() {
      results.reverseDNS = null;
    });

    fetchGreyNoise(ip).then(function(data) {
      results.greynoise = data;
      updatePanel("reputation", renderReputationPanel(results));
      updateSummary();
    }).catch(function(e) {
      results.greynoise_err = "GreyNoise lookup failed";
      updatePanel("reputation", renderReputationPanel(results));
    });

    if (keys.abuseipdb) {
      fetchAbuseIPDB(ip, keys.abuseipdb).then(function(data) {
        results.abuseipdb = data;
        updatePanel("reputation", renderReputationPanel(results));
        updateSummary();
      }).catch(function() {
        results.abuseipdb_err = "AbuseIPDB lookup failed (check API key)";
        updatePanel("reputation", renderReputationPanel(results));
      });
    } else {
      results.abuseipdb_nokey = true;
    }

    if (keys.shodan) {
      fetchShodan(ip, keys.shodan).then(function(data) {
        results.shodan = data;
        updatePanel("network", renderNetworkPanel(results.geoip, results.shodan, results.reverseDNS));
        updateSummary();
      }).catch(function() {
        results.shodan = {};
        updatePanel("network", renderNetworkPanel(results.geoip, results.shodan, results.reverseDNS));
      });
    } else {
      results.shodan = null;
      // Still render network panel once reverse DNS comes back
      setTimeout(function() {
        updatePanel("network", renderNetworkPanel(results.geoip, results.shodan, results.reverseDNS));
      }, 3000);
    }

    if (keys.virustotal) {
      fetchVirusTotalIP(ip, keys.virustotal).then(function(data) {
        results.virustotal = data;
        updatePanel("reputation", renderReputationPanel(results));
        updateSummary();
      }).catch(function() {
        results.virustotal_err = "VirusTotal lookup failed (check API key)";
        updatePanel("reputation", renderReputationPanel(results));
      });
    } else {
      results.virustotal_nokey = true;
    }

    fetchThreatFox(ip).then(function(data) {
      results.threatfox = data;
      updatePanel("reputation", renderReputationPanel(results));
      updatePanel("threat", renderThreatIntelPanel(results));
      updateSummary();
    }).catch(function() {
      results.threatfox_err = "ThreatFox lookup failed";
      updatePanel("reputation", renderReputationPanel(results));
    });

    // URLhaus snapshot entries carry a host field, which is often a bare IP.
    if (!domain) {
      fetchURLhaus(ip).then(function(data) {
        // Keep any rows already merged in by the exact-URL lookup, without duplicates.
        var prev = (results.urlhaus && results.urlhaus.urls) || [];
        var seen = {};
        var merged = prev.concat(data.urls || []).filter(function(u) { if (seen[u.url]) return false; seen[u.url] = true; return true; });
        data.urls = merged.length ? merged : null;
        data.query_status = merged.length ? "ok" : "no_results";
        results.urlhaus = data;
        updatePanel("reputation", renderReputationPanel(results));
        updatePanel("threat", renderThreatIntelPanel(results));
        updateSummary();
      }).catch(function() {
        results.urlhaus_err = "URLhaus lookup failed";
        updatePanel("reputation", renderReputationPanel(results));
      });
    }
  }

  // --- Domain lookups ---
  if (domain) {
    var dnsResults = {};
    var dnsTypes = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"];
    var dnsComplete = 0;
    for (var d = 0; d < dnsTypes.length; d++) {
      (function(dt) {
        fetchDNSRecords(domain, dt).then(function(data) {
          dnsResults[dt] = data;
        }).catch(function() {
          dnsResults[dt] = null;
        }).finally(function() {
          dnsComplete++;
          if (dnsComplete === dnsTypes.length) {
            results.dns = dnsResults;
            updatePanel("dns", renderDNSPanel(dnsResults));
          }
        });
      })(dnsTypes[d]);
    }

    fetchCertTransparency(domain).then(function(data) {
      results.certs = data;
      // Extract subdomains
      var subMap = {};
      if (Array.isArray(data)) {
        for (var i = 0; i < data.length; i++) {
          var names = (data[i].name_value || "").split("\n");
          for (var n = 0; n < names.length; n++) {
            var name = names[n].trim().toLowerCase().replace(/^\*\./, "");
            if (name && name.indexOf(domain) !== -1 && name !== domain) {
              subMap[name] = true;
            }
          }
        }
      }
      var subdomains = Object.keys(subMap).sort();
      results.subdomains = subdomains;
      updatePanel("certs", renderCertsPanel(data, subdomains));
    }).catch(function() {
      updatePanel("certs", panelUnavailable("Certificate transparency lookup failed"));
    });

    fetchURLhaus(domain).then(function(data) {
      results.urlhaus = data;
      updatePanel("reputation", renderReputationPanel(results));
      updatePanel("threat", renderThreatIntelPanel(results));
      updateSummary();
    }).catch(function() {
      results.urlhaus_err = "URLhaus lookup failed";
      updatePanel("reputation", renderReputationPanel(results));
    });

    fetchThreatFox(domain).then(function(data) {
      results.threatfox = data;
      updatePanel("reputation", renderReputationPanel(results));
      updatePanel("threat", renderThreatIntelPanel(results));
      updateSummary();
    }).catch(function() {
      results.threatfox_err = "ThreatFox lookup failed";
      updatePanel("reputation", renderReputationPanel(results));
    });

    if (keys.virustotal) {
      fetchVirusTotalDomain(domain, keys.virustotal).then(function(data) {
        results.virustotal = data;
        updatePanel("reputation", renderReputationPanel(results));
        updateSummary();
      }).catch(function() {
        results.virustotal_err = "VirusTotal lookup failed (check API key)";
        updatePanel("reputation", renderReputationPanel(results));
      });
    } else {
      results.virustotal_nokey = true;
    }
  }

  // --- URL-specific lookups ---
  if (fullURL) {
    fetchURLhausURL(fullURL).then(function(data) {
      if (data && data.query_status !== "no_result") {
        results.urlhaus_url = data;
        // Merge into urlhaus results for display
        if (!results.urlhaus) results.urlhaus = { query_status: "ok", urls: [], snapshot: data.snapshot };
        if (data.urls) {
          results.urlhaus.urls = (results.urlhaus.urls || []).concat(data.urls);
        }
        updatePanel("reputation", renderReputationPanel(results));
        updatePanel("threat", renderThreatIntelPanel(results));
        updateSummary();
      }
    }).catch(function() {});

    if (keys.virustotal) {
      fetchVirusTotalURL(fullURL, keys.virustotal).then(function(data) {
        if (!results.virustotal) {
          results.virustotal = data;
          updatePanel("reputation", renderReputationPanel(results));
          updateSummary();
        }
      }).catch(function() {});
    }
  }

  // Final update after a generous timeout to catch all stragglers
  setTimeout(function() {
    updateSummary();
    if (ip) {
      updatePanel("network", renderNetworkPanel(results.geoip, results.shodan, results.reverseDNS));
    }
    updatePanel("reputation", renderReputationPanel(results));
    updatePanel("threat", renderThreatIntelPanel(results));
    updatePanel("raw", renderRawPanel(results));
  }, 8000);

  // Second raw data refresh after longer APIs
  setTimeout(function() {
    updatePanel("raw", renderRawPanel(results));
    updateSummary();
  }, 15000);

  // Save to history
  saveHistory({
    input: input,
    type: type,
    timestamp: new Date().toISOString()
  });
}

// ---- CSS ----

var STYLE = '<style>' +
  ':root{--ai-bg:#0a0e17;--ai-card:#111827;--ai-card2:#1a2235;--ai-line:#1e293b;--ai-txt:#e2e8f0;--ai-mut:#64748b;--ai-acc:#00d4ff;--ai-acc2:#7c3aed;--ai-mono:"SF Mono","Fira Code","Cascadia Code",monospace}' +

  '.ai-container{max-width:1100px;margin:0 auto;padding:24px 16px;font-family:system-ui,-apple-system,sans-serif;color:var(--ai-txt)}' +

  '.ai-header{text-align:center;margin-bottom:32px}' +
  '.ai-title{font-size:1.6rem;font-weight:700;margin:0 0 6px;color:var(--ai-txt)}' +
  '.ai-subtitle{font-size:.85rem;color:var(--ai-mut);margin:0}' +

  '.ai-input-section{background:var(--ai-card);border:1px solid var(--ai-line);border-radius:12px;padding:24px;margin-bottom:24px}' +
  '.ai-input-row{display:flex;gap:12px;align-items:center}' +
  '.ai-input-wrap{flex:1;position:relative}' +
  '.ai-input{width:100%;padding:12px 16px;padding-right:80px;background:var(--ai-card2);border:1px solid var(--ai-line);border-radius:8px;color:var(--ai-txt);font-size:.95rem;font-family:var(--ai-mono);outline:none;transition:border-color .2s;box-sizing:border-box}' +
  '.ai-input:focus{border-color:var(--ai-acc)}' +
  '.ai-input::placeholder{color:var(--ai-mut)}' +
  '.ai-type-indicator{position:absolute;right:12px;top:50%;transform:translateY(-50%);font-size:.7rem;font-weight:700;padding:3px 8px;border-radius:4px;font-family:var(--ai-mono);text-transform:uppercase;background:rgba(0,212,255,.1);color:var(--ai-acc);display:none}' +
  '.ai-type-indicator.ai-active{display:block}' +
  '.ai-btn-investigate{padding:12px 28px;background:linear-gradient(135deg,var(--ai-acc),var(--ai-acc2));border:none;border-radius:4px;color:#fff;font-size:.9rem;font-weight:600;cursor:pointer;white-space:nowrap;transition:opacity .2s}' +
  '.ai-btn-investigate:hover{opacity:.85}' +
  '.ai-btn-investigate:disabled{opacity:.4;cursor:not-allowed}' +

  '.ai-history-section{margin-top:16px}' +
  '.ai-history-title{font-size:.78rem;color:var(--ai-mut);margin-bottom:8px;text-transform:uppercase;letter-spacing:.5px}' +
  '.ai-history-list{display:flex;flex-wrap:wrap;gap:6px}' +
  '.ai-history-item{padding:4px 10px;background:var(--ai-card2);border:1px solid var(--ai-line);border-radius:4px;font-size:.75rem;color:var(--ai-mut);cursor:pointer;font-family:var(--ai-mono);transition:border-color .2s,color .2s}' +
  '.ai-history-item:hover{border-color:var(--ai-acc);color:var(--ai-acc)}' +
  '.ai-history-type{color:var(--ai-acc);margin-right:4px;font-weight:600}' +
  '.ai-history-clear{padding:4px 10px;background:transparent;border:1px solid var(--ai-line);border-radius:4px;font-size:.72rem;color:var(--ai-mut);cursor:pointer;transition:color .2s}' +
  '.ai-history-clear:hover{color:#e74c3c;border-color:#e74c3c}' +

  '.ai-api-keys-section{margin-top:16px}' +
  '.ai-api-keys-toggle{font-size:.78rem;color:var(--ai-acc);cursor:pointer;background:none;border:none;padding:0;text-decoration:underline;font-family:inherit}' +
  '.ai-api-keys-panel{margin-top:12px;display:none;background:var(--ai-card2);border:1px solid var(--ai-line);border-radius:8px;padding:16px}' +
  '.ai-api-keys-panel.ai-open{display:block}' +
  '.ai-api-key-row{display:flex;gap:8px;align-items:center;margin-bottom:8px}' +
  '.ai-api-key-label{font-size:.78rem;color:var(--ai-mut);min-width:100px;font-weight:600}' +
  '.ai-api-key-input{flex:1;padding:6px 10px;background:var(--ai-bg);border:1px solid var(--ai-line);border-radius:4px;color:var(--ai-txt);font-size:.78rem;font-family:var(--ai-mono)}' +
  '.ai-api-key-save{padding:6px 16px;background:var(--ai-acc);border:none;border-radius:4px;color:#000;font-size:.78rem;font-weight:600;cursor:pointer;margin-top:4px}' +

  '.ai-results{margin-top:8px}' +

  '.ai-summary-card{display:flex;align-items:center;justify-content:space-between;background:var(--ai-card);border:1px solid var(--ai-line);border-radius:12px;padding:24px;margin-bottom:20px;gap:20px}' +
  '.ai-summary-left{flex:1}' +
  '.ai-summary-address{font-size:1.2rem;font-weight:700;font-family:var(--ai-mono);color:var(--ai-txt);word-break:break-all}' +
  '.ai-summary-meta{display:flex;align-items:center;gap:10px;margin-top:8px;flex-wrap:wrap}' +
  '.ai-type-badge{font-size:.68rem;font-weight:700;padding:3px 10px;border-radius:4px;text-transform:uppercase;font-family:var(--ai-mono)}' +
  '.ai-type-ip{background:rgba(52,152,219,.15);color:#3498db}' +
  '.ai-type-domain{background:rgba(46,204,113,.15);color:#2ecc71}' +
  '.ai-type-url{background:rgba(155,89,182,.15);color:#9b59b6}' +
  '.ai-summary-time{font-size:.75rem;color:var(--ai-mut)}' +
  '.ai-summary-risk{margin-top:8px;font-size:.85rem;color:var(--ai-mut)}' +
  '.ai-summary-right{flex-shrink:0}' +

  '.ai-score-gauge{width:100px;height:100px;border-radius:50%;display:flex;align-items:center;justify-content:center;position:relative}' +
  '.ai-score-inner{width:76px;height:76px;border-radius:50%;background:var(--ai-card);display:flex;flex-direction:column;align-items:center;justify-content:center}' +
  '.ai-score-num{font-size:1.6rem;font-weight:800;line-height:1}' +
  '.ai-score-of{font-size:.6rem;color:var(--ai-mut);margin-top:2px}' +
  '.ai-score-unknown .ai-score-num{color:var(--ai-mut);font-size:1.8rem}' +

  '.ai-tags-row{display:flex;flex-wrap:wrap;gap:5px;margin-top:8px}' +
  '.ai-tag{font-size:.68rem;padding:2px 8px;border-radius:3px;font-family:var(--ai-mono);font-weight:600;text-transform:uppercase}' +
  '.ai-tag-danger{background:rgba(231,76,60,.15);color:#e74c3c;border:1px solid rgba(231,76,60,.25)}' +
  '.ai-tag-safe{background:rgba(46,204,113,.15);color:#2ecc71;border:1px solid rgba(46,204,113,.25)}' +
  '.ai-tag-warn{background:rgba(241,196,15,.15);color:#f1c40f;border:1px solid rgba(241,196,15,.25)}' +

  '.ai-panel{background:var(--ai-card);border:1px solid var(--ai-line);border-radius:10px;margin-bottom:16px;overflow:hidden;border-left:3px solid var(--ai-acc)}' +
  '.ai-panel-header{padding:14px 18px;font-size:.88rem;font-weight:700;color:var(--ai-txt);border-bottom:1px solid var(--ai-line);background:rgba(0,0,0,.15)}' +
  '.ai-panel-content{padding:0}' +
  '.ai-panel-body{padding:16px 18px}' +

  '.ai-panel-loading{display:flex;align-items:center;justify-content:center;padding:32px;gap:6px}' +
  '.ai-dot{width:8px;height:8px;border-radius:50%;background:var(--ai-acc);animation:ai-pulse 1.4s infinite ease-in-out both}' +
  '.ai-dot:nth-child(1){animation-delay:-.32s}' +
  '.ai-dot:nth-child(2){animation-delay:-.16s}' +
  '@keyframes ai-pulse{0%,80%,100%{transform:scale(0);opacity:.4}40%{transform:scale(1);opacity:1}}' +

  '.ai-panel-unavail{padding:16px 18px;font-size:.82rem;color:var(--ai-mut);font-style:italic}' +

  '.ai-kv-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:2px}' +
  '.ai-kv{display:flex;justify-content:space-between;padding:6px 10px;border-radius:4px;background:rgba(0,0,0,.12)}' +
  '.ai-kv-label{font-size:.78rem;color:var(--ai-mut);font-weight:500}' +
  '.ai-kv-value{font-size:.78rem;color:var(--ai-txt);font-family:var(--ai-mono);text-align:right;word-break:break-all;max-width:60%}' +

  '.ai-subsection-title{font-size:.8rem;font-weight:700;color:var(--ai-acc);margin:16px 0 8px;padding-bottom:4px;border-bottom:1px solid var(--ai-line);text-transform:uppercase;letter-spacing:.4px}' +
  '.ai-subsection-title:first-child{margin-top:0}' +
  '.ai-snap-note{font-weight:500;text-transform:none;letter-spacing:0;color:var(--ai-mut,#8a8f98);font-size:.72rem}' +

  '.ai-table{width:100%;border-collapse:collapse;font-size:.76rem;margin-bottom:8px}' +
  '.ai-table thead th{text-align:left;padding:8px 10px;color:var(--ai-mut);font-weight:600;border-bottom:1px solid var(--ai-line);font-size:.72rem;text-transform:uppercase;letter-spacing:.3px;white-space:nowrap}' +
  '.ai-table tbody td{padding:6px 10px;border-bottom:1px solid rgba(30,41,59,.5);color:var(--ai-txt);font-family:var(--ai-mono);vertical-align:top}' +
  '.ai-table tbody tr:hover{background:rgba(0,212,255,.03)}' +
  '.ai-banner-cell{max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--ai-mut);font-size:.72rem}' +
  '.ai-table-wrap{overflow-x:auto}' +

  '.ai-vuln-list{display:flex;flex-wrap:wrap;gap:5px}' +
  '.ai-vuln-badge{font-size:.7rem;padding:3px 8px;background:rgba(231,76,60,.12);color:#e74c3c;border:1px solid rgba(231,76,60,.2);border-radius:4px;font-family:var(--ai-mono);font-weight:600}' +

  '.ai-subdomain-list{display:flex;flex-wrap:wrap;gap:5px}' +
  '.ai-subdomain-badge{font-size:.72rem;padding:3px 10px;background:var(--ai-card2);border:1px solid var(--ai-line);border-radius:4px;font-family:var(--ai-mono);color:var(--ai-txt)}' +
  '.ai-subdomain-more{color:var(--ai-mut);font-style:italic}' +

  '.ai-no-records{font-size:.78rem;color:var(--ai-mut);padding:4px 0;font-style:italic}' +
  '.ai-more-indicator{font-size:.75rem;color:var(--ai-mut);margin-top:8px;font-style:italic}' +

  '.ai-map-placeholder{margin-top:12px;background:var(--ai-card2);border:1px solid var(--ai-line);border-radius:8px;padding:20px;text-align:center}' +
  '.ai-map-coords{font-size:1rem;font-family:var(--ai-mono);color:var(--ai-acc);font-weight:600}' +
  '.ai-map-label{font-size:.72rem;color:var(--ai-mut);margin-top:4px}' +

  '.ai-malware-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:8px}' +
  '.ai-malware-card{background:var(--ai-card2);border:1px solid rgba(231,76,60,.2);border-radius:6px;padding:10px 14px}' +
  '.ai-malware-name{font-size:.82rem;font-weight:700;color:#e74c3c;font-family:var(--ai-mono)}' +
  '.ai-malware-meta{font-size:.72rem;color:var(--ai-mut);margin-top:2px}' +

  '.ai-threat-summary{display:flex;flex-wrap:wrap;gap:8px}' +
  '.ai-threat-item{display:flex;align-items:center;gap:8px;background:var(--ai-card2);border:1px solid var(--ai-line);border-radius:6px;padding:6px 12px}' +
  '.ai-threat-type{font-size:.78rem;font-weight:600;color:var(--ai-txt)}' +
  '.ai-threat-count{font-size:.72rem;color:var(--ai-mut)}' +

  '.ai-raw-section{margin-bottom:4px}' +
  '.ai-raw-toggle{display:block;width:100%;text-align:left;padding:8px 12px;background:var(--ai-card2);border:1px solid var(--ai-line);border-radius:4px;color:var(--ai-txt);font-size:.78rem;font-weight:600;font-family:var(--ai-mono);cursor:pointer;transition:background .2s}' +
  '.ai-raw-toggle:hover{background:rgba(0,212,255,.05)}' +
  '.ai-raw-arrow{float:right;color:var(--ai-mut)}' +
  '.ai-raw-content{margin:0;padding:12px;background:var(--ai-bg);border:1px solid var(--ai-line);border-top:none;border-radius:0 0 4px 4px;font-size:.72rem;color:var(--ai-mut);font-family:var(--ai-mono);max-height:300px;overflow:auto;white-space:pre-wrap;word-break:break-all}' +

  '@media(max-width:640px){' +
    '.ai-input-row{flex-direction:column}' +
    '.ai-btn-investigate{width:100%}' +
    '.ai-summary-card{flex-direction:column;text-align:center}' +
    '.ai-summary-meta{justify-content:center}' +
    '.ai-kv-grid{grid-template-columns:1fr}' +
    '.ai-table{font-size:.7rem}' +
  '}' +
'</style>';

// ---- Main entry point ----

export function renderAddressIntel(main) {
  main.innerHTML = STYLE +
    '<div class="ai-container">' +
      '<div class="ai-header">' +
        '<h1 class="ai-title">Address Intelligence</h1>' +
        '<p class="ai-subtitle">Investigate any IP address, domain, or URL against real threat intelligence sources</p>' +
      '</div>' +
      '<div class="ai-input-section">' +
        '<div class="ai-input-row">' +
          '<div class="ai-input-wrap">' +
            '<input class="ai-input" id="ai-input-field" type="text" placeholder="Enter IP address, domain, or URL..." spellcheck="false" autocomplete="off">' +
            '<span class="ai-type-indicator" id="ai-type-indicator"></span>' +
          '</div>' +
          '<button class="ai-btn-investigate" id="ai-btn-go">Investigate</button>' +
        '</div>' +
        '<div id="ai-history-mount"></div>' +
        '<div class="ai-api-keys-section">' +
          '<button class="ai-api-keys-toggle" id="ai-keys-toggle">Configure API Keys (optional, enables more sources)</button>' +
          '<div class="ai-api-keys-panel" id="ai-keys-panel">' +
            '<div class="ai-api-key-row"><span class="ai-api-key-label">AbuseIPDB</span><input class="ai-api-key-input" id="ai-key-abuseipdb" type="password" placeholder="API key"></div>' +
            '<div class="ai-api-key-row"><span class="ai-api-key-label">Shodan</span><input class="ai-api-key-input" id="ai-key-shodan" type="password" placeholder="API key"></div>' +
            '<div class="ai-api-key-row"><span class="ai-api-key-label">VirusTotal</span><input class="ai-api-key-input" id="ai-key-virustotal" type="password" placeholder="API key"></div>' +
            '<button class="ai-api-key-save" id="ai-keys-save">Save Keys</button>' +
          '</div>' +
        '</div>' +
      '</div>' +
      '<div class="ai-results" id="ai-results"></div>' +
    '</div>';

  // Load existing API keys into fields
  var existingKeys = getApiKeys();
  if (existingKeys.abuseipdb) document.getElementById("ai-key-abuseipdb").value = existingKeys.abuseipdb;
  if (existingKeys.shodan) document.getElementById("ai-key-shodan").value = existingKeys.shodan;
  if (existingKeys.virustotal) document.getElementById("ai-key-virustotal").value = existingKeys.virustotal;

  // Type indicator
  var inputField = document.getElementById("ai-input-field");
  var typeInd = document.getElementById("ai-type-indicator");
  inputField.addEventListener("input", function() {
    var val = inputField.value.trim();
    var detected = detectInputType(val);
    if (detected) {
      typeInd.textContent = detected;
      typeInd.className = "ai-type-indicator ai-active";
    } else {
      typeInd.className = "ai-type-indicator";
    }
  });

  // Enter key
  inputField.addEventListener("keydown", function(e) {
    if (e.key === "Enter") {
      document.getElementById("ai-btn-go").click();
    }
  });

  // Investigate button
  document.getElementById("ai-btn-go").addEventListener("click", function() {
    var val = inputField.value.trim();
    if (!val) return;
    var type = detectInputType(val);
    if (!type) {
      document.getElementById("ai-results").innerHTML =
        '<div class="ai-panel" style="border-left-color:#e74c3c"><div class="ai-panel-header">Invalid Input</div>' +
        '<div class="ai-panel-body" style="color:var(--ai-mut)">Could not detect input type. Enter a valid IPv4 address, domain name, or URL (starting with http:// or https://).</div></div>';
      return;
    }
    var btn = document.getElementById("ai-btn-go");
    btn.disabled = true;
    btn.textContent = "Scanning...";
    setTimeout(function() { btn.disabled = false; btn.textContent = "Investigate"; }, 16000);
    runInvestigation(val, type, document.getElementById("ai-results"));
    renderHistory();
  });

  // API keys toggle
  document.getElementById("ai-keys-toggle").addEventListener("click", function() {
    var panel = document.getElementById("ai-keys-panel");
    if (panel.classList.contains("ai-open")) {
      panel.classList.remove("ai-open");
    } else {
      panel.classList.add("ai-open");
    }
  });

  // Save API keys
  document.getElementById("ai-keys-save").addEventListener("click", function() {
    var keys = getApiKeys();
    var ab = document.getElementById("ai-key-abuseipdb").value.trim();
    var sh = document.getElementById("ai-key-shodan").value.trim();
    var vt = document.getElementById("ai-key-virustotal").value.trim();
    if (ab) keys.abuseipdb = ab; else delete keys.abuseipdb;
    if (sh) keys.shodan = sh; else delete keys.shodan;
    if (vt) keys.virustotal = vt; else delete keys.virustotal;
    try { localStorage.setItem(API_KEYS_KEY, JSON.stringify(keys)); } catch(e) {}
    var saveBtn = document.getElementById("ai-keys-save");
    saveBtn.textContent = "Saved";
    setTimeout(function() { saveBtn.textContent = "Save Keys"; }, 1500);
  });

  // Raw data toggle delegation
  document.addEventListener("click", function(e) {
    if (e.target && e.target.classList && e.target.classList.contains("ai-raw-toggle")) {
      var targetId = e.target.getAttribute("data-target");
      if (targetId) {
        var el = document.getElementById(targetId);
        if (el) {
          var visible = el.style.display !== "none";
          el.style.display = visible ? "none" : "block";
          var arrow = e.target.querySelector(".ai-raw-arrow");
          if (arrow) arrow.textContent = visible ? "+" : "-";
        }
      }
    }
  });

  // Render history
  function renderHistory() {
    var hist = getHistory();
    var mount = document.getElementById("ai-history-mount");
    if (!mount) return;
    if (hist.length === 0) {
      mount.innerHTML = "";
      return;
    }
    var html = '<div class="ai-history-section">' +
      '<div class="ai-history-title">Recent Lookups</div>' +
      '<div class="ai-history-list">';
    for (var i = 0; i < hist.length; i++) {
      html += '<span class="ai-history-item" data-input="' + esc(hist[i].input) + '">' +
        '<span class="ai-history-type">' + esc(hist[i].type || "?") + '</span>' +
        esc(truncate(hist[i].input, 40)) +
      '</span>';
    }
    html += '<span class="ai-history-clear" id="ai-history-clear">Clear</span>';
    html += '</div></div>';
    mount.innerHTML = html;

    // History item clicks
    var items = mount.querySelectorAll(".ai-history-item");
    for (var j = 0; j < items.length; j++) {
      items[j].addEventListener("click", function() {
        var inp = this.getAttribute("data-input");
        if (inp) {
          inputField.value = inp;
          inputField.dispatchEvent(new Event("input"));
          document.getElementById("ai-btn-go").click();
        }
      });
    }

    // Clear history
    var clearBtn = document.getElementById("ai-history-clear");
    if (clearBtn) {
      clearBtn.addEventListener("click", function(e) {
        e.stopPropagation();
        try { localStorage.removeItem(HISTORY_KEY); } catch(ex) {}
        renderHistory();
      });
    }
  }

  renderHistory();

  // Auto-focus input
  setTimeout(function() { inputField.focus(); }, 100);
}
