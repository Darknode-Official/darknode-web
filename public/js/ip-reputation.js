import { db, auth } from "/js/firebase.js";
import { collection, addDoc, getDocs, query, where, orderBy, limit, serverTimestamp } from "https://www.gstatic.com/firebasejs/12.17.0/firebase-firestore.js";

var esc = function(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function(c) { return ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[c]; }); };

var _feedCache = { maliciousIps: null, botnetC2: null, threatIocs: null, malwareUrls: null, ts: 0 };
var CACHE_TTL = 5 * 60 * 1000;
var REPORT_CATEGORIES = ["Scanner", "Brute Force", "Malware", "Phishing", "Spam", "C2", "Other"];

function _loadFeed(path, cb) {
  fetch(path).then(function(r) {
    if (!r.ok) throw new Error("HTTP " + r.status);
    return r.json();
  }).then(function(d) { cb(null, d); }).catch(function(e) { cb(e, null); });
}

function _ensureFeeds(cb) {
  if (_feedCache.ts && Date.now() - _feedCache.ts < CACHE_TTL && _feedCache.maliciousIps) {
    return cb();
  }
  var done = 0;
  var total = 4;
  var check = function() { done++; if (done >= total) { _feedCache.ts = Date.now(); cb(); } };

  _loadFeed("/data/feeds/malicious-ips.json", function(err, d) {
    _feedCache.maliciousIps = err ? null : d;
    check();
  });
  _loadFeed("/data/feeds/botnet-c2.json", function(err, d) {
    _feedCache.botnetC2 = err ? null : d;
    check();
  });
  _loadFeed("/data/feeds/threat-iocs.json", function(err, d) {
    _feedCache.threatIocs = err ? null : d;
    check();
  });
  _loadFeed("/data/feeds/malware-urls.json", function(err, d) {
    _feedCache.malwareUrls = err ? null : d;
    check();
  });
}

function _checkIP(ip) {
  var results = { found: false, score: 0, feeds: [], malware: [], details: [] };
  var ipTrimmed = ip.trim();

  if (_feedCache.maliciousIps && _feedCache.maliciousIps.data) {
    for (var i = 0; i < _feedCache.maliciousIps.data.length; i++) {
      var entry = _feedCache.maliciousIps.data[i];
      var entryIp = typeof entry === "string" ? entry : (entry.ip || entry.ip_address || "");
      if (entryIp === ipTrimmed) {
        results.found = true;
        var entryScore = entry.score || entry.threat_score || 0;
        if (entryScore > results.score) results.score = entryScore;
        results.feeds.push("Malicious IPs (FireHOL/stamparm)");
        results.details.push({ source: "FireHOL/stamparm", ip: ipTrimmed, score: entryScore });
        break;
      }
    }
  }

  if (_feedCache.botnetC2 && _feedCache.botnetC2.data) {
    for (var b = 0; b < _feedCache.botnetC2.data.length; b++) {
      var bot = _feedCache.botnetC2.data[b];
      if ((bot.ip_address || bot.ip || "") === ipTrimmed) {
        results.found = true;
        if (8 > results.score) results.score = 8;
        results.feeds.push("Botnet C2 (Feodo Tracker)");
        var mw = bot.malware || bot.malware_printable || "unknown";
        if (results.malware.indexOf(mw) === -1) results.malware.push(mw);
        results.details.push({
          source: "Feodo Tracker",
          ip: ipTrimmed,
          port: bot.port || "N/A",
          malware: mw,
          firstSeen: bot.first_seen || bot.first_seen_utc || "",
          lastOnline: bot.last_online || ""
        });
        break;
      }
    }
  }

  if (_feedCache.threatIocs && _feedCache.threatIocs.data) {
    for (var t = 0; t < _feedCache.threatIocs.data.length; t++) {
      var ioc = _feedCache.threatIocs.data[t];
      var iocVal = ioc.ioc_value || ioc.ioc || "";
      if (iocVal === ipTrimmed || iocVal.indexOf(ipTrimmed + ":") === 0) {
        results.found = true;
        if (7 > results.score) results.score = 7;
        results.feeds.push("Threat IOCs (ThreatFox)");
        var tfMw = ioc.malware_printable || ioc.malware || "unknown";
        if (results.malware.indexOf(tfMw) === -1) results.malware.push(tfMw);
        results.details.push({
          source: "ThreatFox",
          ioc: iocVal,
          type: ioc.threat_type || ioc.ioc_type || "",
          malware: tfMw,
          firstSeen: ioc.first_seen || ioc.first_seen_utc || ""
        });
        break;
      }
    }
  }

  if (results.found && results.score < 3) results.score = 3;
  return results;
}

function _getReports(ip, cb) {
  try {
    var q = query(collection(db, "ip_reports"), where("ip", "==", ip), orderBy("timestamp", "desc"), limit(50));
    getDocs(q).then(function(snap) {
      var reports = [];
      snap.forEach(function(d) { var r = d.data(); r.id = d.id; reports.push(r); });
      cb(null, reports);
    }).catch(function(e) { cb(e, []); });
  } catch (e) { cb(e, []); }
}

function _scoreColor(score) {
  if (score >= 8) return "#ff3333";
  if (score >= 5) return "#ff6600";
  if (score >= 3) return "#ffaa00";
  return "#00ff88";
}

function _scoreLabel(score) {
  if (score >= 8) return "CRITICAL";
  if (score >= 5) return "HIGH";
  if (score >= 3) return "MEDIUM";
  if (score > 0) return "LOW";
  return "CLEAN";
}

function _isValidIP(ip) {
  var parts = ip.split(".");
  if (parts.length !== 4) return false;
  for (var i = 0; i < 4; i++) {
    var n = parseInt(parts[i], 10);
    if (isNaN(n) || n < 0 || n > 255 || String(n) !== parts[i]) return false;
  }
  return true;
}

export function renderIPReputation(main) {
  var h = "";
  h += '<div style="max-width:1100px;margin:0 auto;padding:24px 16px;">';

  h += '<div style="margin-bottom:24px;">';
  h += '<div style="font-size:22px;font-weight:700;color:#00d4ff;font-family:monospace;letter-spacing:1px;">IP REPUTATION DATABASE</div>';
  h += '<div style="font-size:13px;color:#888;margin-top:4px;">Check IPs against aggregated threat feeds and community reports</div>';
  h += '</div>';

  h += '<div id="ipr-tabs" style="display:flex;gap:8px;margin-bottom:20px;flex-wrap:wrap;">';
  h += '<button class="ipr-tab chip on" data-tab="lookup" style="cursor:pointer;">Lookup</button>';
  h += '<button class="ipr-tab chip" data-tab="bulk" style="cursor:pointer;">Bulk Check</button>';
  h += '<button class="ipr-tab chip" data-tab="dashboard" style="cursor:pointer;">Feed Dashboard</button>';
  h += '<button class="ipr-tab chip" data-tab="report" style="cursor:pointer;">Report IP</button>';
  h += '</div>';

  h += '<div id="ipr-content" style="min-height:400px;"></div>';
  h += '</div>';

  main.innerHTML = h;

  var content = main.querySelector("#ipr-content");
  var activeTab = "lookup";

  function switchTab(id) {
    activeTab = id;
    main.querySelectorAll(".ipr-tab").forEach(function(b) { b.classList.toggle("on", b.dataset.tab === id); });
    if (id === "lookup") renderLookup();
    else if (id === "bulk") renderBulk();
    else if (id === "dashboard") renderDashboard();
    else if (id === "report") renderReport();
  }

  main.querySelector("#ipr-tabs").onclick = function(e) {
    var btn = e.target.closest(".ipr-tab");
    if (btn && btn.dataset.tab) switchTab(btn.dataset.tab);
  };

  function renderLookup() {
    var lh = "";
    lh += '<div style="background:#12121a;border:1px solid #1a1a2e;border-radius:8px;padding:20px;margin-bottom:16px;">';
    lh += '<div style="font-size:14px;font-weight:600;color:#ccc;margin-bottom:12px;">IP Address Lookup</div>';
    lh += '<div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">';
    lh += '<input id="ipr-ip-input" type="text" placeholder="e.g. 192.168.1.1" style="flex:1;min-width:200px;padding:10px 14px;background:#0d0d15;border:1px solid #1a1a2e;border-radius:6px;color:#e0e0e0;font-family:monospace;font-size:14px;outline:none;" />';
    lh += '<button id="ipr-lookup-btn" style="padding:10px 24px;background:#00d4ff;color:#000;border:none;border-radius:6px;font-weight:700;cursor:pointer;font-size:14px;">Check IP</button>';
    lh += '</div>';
    lh += '</div>';
    lh += '<div id="ipr-lookup-result"></div>';
    content.innerHTML = lh;

    var input = content.querySelector("#ipr-ip-input");
    input.addEventListener("focus", function() { this.style.borderColor = "#00d4ff"; });
    input.addEventListener("blur", function() { this.style.borderColor = "#1a1a2e"; });

    content.querySelector("#ipr-lookup-btn").onclick = function() {
      var ip = input.value.trim();
      if (!ip || !_isValidIP(ip)) {
        content.querySelector("#ipr-lookup-result").innerHTML = '<div style="color:#ff6600;padding:12px;">Enter a valid IPv4 address.</div>';
        return;
      }
      content.querySelector("#ipr-lookup-result").innerHTML = '<div style="color:#888;padding:12px;">Checking feeds...</div>';
      _ensureFeeds(function() {
        var res = _checkIP(ip);
        _getReports(ip, function(err, reports) {
          var communityCount = reports ? reports.length : 0;
          if (communityCount > 0 && !res.found) { res.found = true; res.score = Math.max(res.score, 2); }
          if (communityCount >= 3) res.score = Math.max(res.score, 5);
          _renderLookupResult(ip, res, reports || []);
        });
      });
    };

    input.addEventListener("keydown", function(e) {
      if (e.key === "Enter") content.querySelector("#ipr-lookup-btn").click();
    });
  }

  function _renderLookupResult(ip, res, reports) {
    var rh = "";
    var color = _scoreColor(res.score);
    var label = _scoreLabel(res.score);

    rh += '<div style="background:#12121a;border:1px solid #1a1a2e;border-radius:8px;padding:20px;margin-bottom:16px;">';
    rh += '<div style="display:flex;align-items:center;gap:16px;margin-bottom:16px;flex-wrap:wrap;">';
    rh += '<div style="font-family:monospace;font-size:18px;color:#e0e0e0;font-weight:700;">' + esc(ip) + '</div>';
    rh += '<div style="display:flex;align-items:center;gap:8px;">';
    rh += '<div style="width:48px;height:48px;border-radius:50%;border:3px solid ' + color + ';display:flex;align-items:center;justify-content:center;font-size:18px;font-weight:900;color:' + color + ';font-family:monospace;">' + res.score + '</div>';
    rh += '<div style="font-size:13px;font-weight:700;color:' + color + ';letter-spacing:1px;">' + label + '</div>';
    rh += '</div>';
    rh += '</div>';

    if (!res.found) {
      rh += '<div style="color:#00ff88;font-size:14px;padding:12px;background:#0d1a12;border:1px solid #0a2e14;border-radius:6px;">This IP was not found in any threat feed or community reports. It appears clean.</div>';
    } else {
      if (res.feeds.length > 0) {
        rh += '<div style="margin-bottom:14px;">';
        rh += '<div style="font-size:12px;color:#888;margin-bottom:6px;text-transform:uppercase;letter-spacing:1px;">Found In</div>';
        for (var f = 0; f < res.feeds.length; f++) {
          rh += '<div style="display:inline-block;padding:4px 10px;background:#1a0a0a;border:1px solid #ff3333;border-radius:4px;color:#ff6666;font-size:12px;margin:2px 4px 2px 0;font-family:monospace;">' + esc(res.feeds[f]) + '</div>';
        }
        rh += '</div>';
      }

      if (res.malware.length > 0) {
        rh += '<div style="margin-bottom:14px;">';
        rh += '<div style="font-size:12px;color:#888;margin-bottom:6px;text-transform:uppercase;letter-spacing:1px;">Malware Families</div>';
        for (var m = 0; m < res.malware.length; m++) {
          rh += '<div style="display:inline-block;padding:4px 10px;background:#1a1a0a;border:1px solid #ffaa00;border-radius:4px;color:#ffcc00;font-size:12px;margin:2px 4px 2px 0;font-family:monospace;">' + esc(res.malware[m]) + '</div>';
        }
        rh += '</div>';
      }

      if (res.details.length > 0) {
        rh += '<div style="margin-bottom:14px;">';
        rh += '<div style="font-size:12px;color:#888;margin-bottom:6px;text-transform:uppercase;letter-spacing:1px;">Details</div>';
        rh += '<div style="overflow-x:auto;">';
        rh += '<table style="width:100%;border-collapse:collapse;font-size:12px;font-family:monospace;">';
        rh += '<tr style="border-bottom:1px solid #1a1a2e;">';
        rh += '<th style="text-align:left;padding:6px 8px;color:#00d4ff;">Source</th>';
        rh += '<th style="text-align:left;padding:6px 8px;color:#00d4ff;">Type/Port</th>';
        rh += '<th style="text-align:left;padding:6px 8px;color:#00d4ff;">Malware</th>';
        rh += '<th style="text-align:left;padding:6px 8px;color:#00d4ff;">First Seen</th>';
        rh += '</tr>';
        for (var d = 0; d < res.details.length; d++) {
          var det = res.details[d];
          rh += '<tr style="border-bottom:1px solid #111;">';
          rh += '<td style="padding:6px 8px;color:#ccc;">' + esc(det.source) + '</td>';
          rh += '<td style="padding:6px 8px;color:#ccc;">' + esc(det.type || det.port || "N/A") + '</td>';
          rh += '<td style="padding:6px 8px;color:#ffaa00;">' + esc(det.malware || "N/A") + '</td>';
          rh += '<td style="padding:6px 8px;color:#888;">' + esc(det.firstSeen || det.lastOnline || "N/A") + '</td>';
          rh += '</tr>';
        }
        rh += '</table></div></div>';
      }
    }

    if (reports.length > 0) {
      rh += '<div style="margin-top:14px;">';
      rh += '<div style="font-size:12px;color:#888;margin-bottom:6px;text-transform:uppercase;letter-spacing:1px;">Community Reports (' + reports.length + ')</div>';
      var catCounts = {};
      for (var r = 0; r < reports.length; r++) {
        var cat = reports[r].category || "Other";
        catCounts[cat] = (catCounts[cat] || 0) + 1;
      }
      var catKeys = Object.keys(catCounts);
      for (var ck = 0; ck < catKeys.length; ck++) {
        rh += '<div style="display:inline-block;padding:4px 10px;background:#0d0d1a;border:1px solid #4444ff;border-radius:4px;color:#8888ff;font-size:12px;margin:2px 4px 2px 0;">' + esc(catKeys[ck]) + ': ' + catCounts[catKeys[ck]] + '</div>';
      }
      rh += '<div style="margin-top:10px;max-height:200px;overflow-y:auto;">';
      for (var rr = 0; rr < reports.length && rr < 10; rr++) {
        var rep = reports[rr];
        var ts = rep.timestamp ? (rep.timestamp.toDate ? rep.timestamp.toDate().toISOString() : String(rep.timestamp)) : "unknown";
        rh += '<div style="padding:6px 8px;border-bottom:1px solid #111;font-size:12px;">';
        rh += '<span style="color:#00d4ff;">' + esc(rep.category || "Other") + '</span>';
        rh += ' <span style="color:#555;">|</span> ';
        rh += '<span style="color:#888;">' + esc(ts.substring(0, 19)) + '</span>';
        if (rep.description) rh += ' <span style="color:#555;">-</span> <span style="color:#aaa;">' + esc(rep.description) + '</span>';
        rh += '</div>';
      }
      rh += '</div></div>';
    }

    rh += '</div>';
    content.querySelector("#ipr-lookup-result").innerHTML = rh;
  }

  function renderBulk() {
    var bh = "";
    bh += '<div style="background:#12121a;border:1px solid #1a1a2e;border-radius:8px;padding:20px;margin-bottom:16px;">';
    bh += '<div style="font-size:14px;font-weight:600;color:#ccc;margin-bottom:12px;">Bulk IP Check</div>';
    bh += '<div style="font-size:12px;color:#888;margin-bottom:10px;">Enter one IP per line (max 100)</div>';
    bh += '<textarea id="ipr-bulk-input" rows="8" placeholder="192.168.1.1\n10.0.0.1\n..." style="width:100%;padding:10px 14px;background:#0d0d15;border:1px solid #1a1a2e;border-radius:6px;color:#e0e0e0;font-family:monospace;font-size:13px;outline:none;resize:vertical;box-sizing:border-box;"></textarea>';
    bh += '<button id="ipr-bulk-btn" style="margin-top:10px;padding:10px 24px;background:#00d4ff;color:#000;border:none;border-radius:6px;font-weight:700;cursor:pointer;font-size:14px;">Check All</button>';
    bh += '</div>';
    bh += '<div id="ipr-bulk-result"></div>';
    content.innerHTML = bh;

    var textarea = content.querySelector("#ipr-bulk-input");
    textarea.addEventListener("focus", function() { this.style.borderColor = "#00d4ff"; });
    textarea.addEventListener("blur", function() { this.style.borderColor = "#1a1a2e"; });

    content.querySelector("#ipr-bulk-btn").onclick = function() {
      var raw = textarea.value.trim();
      if (!raw) { content.querySelector("#ipr-bulk-result").innerHTML = '<div style="color:#ff6600;padding:12px;">Enter at least one IP address.</div>'; return; }
      var lines = raw.split("\n");
      var ips = [];
      for (var i = 0; i < lines.length && i < 100; i++) {
        var ip = lines[i].trim();
        if (ip && _isValidIP(ip)) ips.push(ip);
      }
      if (ips.length === 0) { content.querySelector("#ipr-bulk-result").innerHTML = '<div style="color:#ff6600;padding:12px;">No valid IPs found.</div>'; return; }
      content.querySelector("#ipr-bulk-result").innerHTML = '<div style="color:#888;padding:12px;">Checking ' + ips.length + ' IPs against feeds...</div>';
      _ensureFeeds(function() {
        var rows = [];
        for (var j = 0; j < ips.length; j++) {
          var r = _checkIP(ips[j]);
          rows.push({ ip: ips[j], score: r.score, found: r.found, feeds: r.feeds, malware: r.malware });
        }
        rows.sort(function(a, b) { return b.score - a.score; });
        _renderBulkResult(rows);
      });
    };
  }

  function _renderBulkResult(rows) {
    var rh = '';
    var threats = 0;
    for (var c = 0; c < rows.length; c++) { if (rows[c].found) threats++; }
    rh += '<div style="background:#12121a;border:1px solid #1a1a2e;border-radius:8px;padding:20px;">';
    rh += '<div style="font-size:14px;font-weight:600;color:#ccc;margin-bottom:4px;">Results: ' + rows.length + ' IPs checked</div>';
    rh += '<div style="font-size:12px;color:#888;margin-bottom:14px;">' + threats + ' flagged as malicious</div>';
    rh += '<div style="overflow-x:auto;">';
    rh += '<table style="width:100%;border-collapse:collapse;font-size:12px;font-family:monospace;">';
    rh += '<tr style="border-bottom:1px solid #1a1a2e;">';
    rh += '<th style="text-align:left;padding:8px;color:#00d4ff;">IP Address</th>';
    rh += '<th style="text-align:center;padding:8px;color:#00d4ff;">Score</th>';
    rh += '<th style="text-align:left;padding:8px;color:#00d4ff;">Status</th>';
    rh += '<th style="text-align:left;padding:8px;color:#00d4ff;">Feeds</th>';
    rh += '<th style="text-align:left;padding:8px;color:#00d4ff;">Malware</th>';
    rh += '</tr>';
    for (var i = 0; i < rows.length; i++) {
      var row = rows[i];
      var sc = _scoreColor(row.score);
      rh += '<tr style="border-bottom:1px solid #111;">';
      rh += '<td style="padding:8px;color:#e0e0e0;">' + esc(row.ip) + '</td>';
      rh += '<td style="padding:8px;text-align:center;color:' + sc + ';font-weight:700;">' + row.score + '</td>';
      rh += '<td style="padding:8px;color:' + (row.found ? "#ff3333" : "#00ff88") + ';">' + (row.found ? "THREAT" : "CLEAN") + '</td>';
      rh += '<td style="padding:8px;color:#aaa;">' + (row.feeds.length > 0 ? esc(row.feeds.join(", ")) : "-") + '</td>';
      rh += '<td style="padding:8px;color:#ffaa00;">' + (row.malware.length > 0 ? esc(row.malware.join(", ")) : "-") + '</td>';
      rh += '</tr>';
    }
    rh += '</table></div></div>';
    content.querySelector("#ipr-bulk-result").innerHTML = rh;
  }

  function renderDashboard() {
    content.innerHTML = '<div style="color:#888;padding:20px;">Loading feed data...</div>';
    _ensureFeeds(function() {
      var dh = "";
      var malCount = (_feedCache.maliciousIps && _feedCache.maliciousIps.data) ? _feedCache.maliciousIps.data.length : 0;
      var botCount = (_feedCache.botnetC2 && _feedCache.botnetC2.data) ? _feedCache.botnetC2.data.length : 0;
      var urlCount = (_feedCache.malwareUrls && _feedCache.malwareUrls.data) ? _feedCache.malwareUrls.data.length : 0;
      var iocCount = (_feedCache.threatIocs && _feedCache.threatIocs.data) ? _feedCache.threatIocs.data.length : 0;

      var lastUpdate = "N/A";
      if (_feedCache.maliciousIps && _feedCache.maliciousIps.updated) lastUpdate = _feedCache.maliciousIps.updated;
      else if (_feedCache.botnetC2 && _feedCache.botnetC2.updated) lastUpdate = _feedCache.botnetC2.updated;

      dh += '<div style="font-size:12px;color:#888;margin-bottom:16px;">Last synced: <span style="color:#00d4ff;">' + esc(lastUpdate) + '</span></div>';

      dh += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:24px;">';

      dh += '<div style="background:#12121a;border:1px solid #1a1a2e;border-radius:8px;padding:16px;text-align:center;">';
      dh += '<div style="font-size:28px;font-weight:900;color:#ff3333;font-family:monospace;">' + malCount.toLocaleString() + '</div>';
      dh += '<div style="font-size:11px;color:#888;margin-top:4px;text-transform:uppercase;letter-spacing:1px;">Malicious IPs</div>';
      dh += '</div>';

      dh += '<div style="background:#12121a;border:1px solid #1a1a2e;border-radius:8px;padding:16px;text-align:center;">';
      dh += '<div style="font-size:28px;font-weight:900;color:#ff6600;font-family:monospace;">' + botCount.toLocaleString() + '</div>';
      dh += '<div style="font-size:11px;color:#888;margin-top:4px;text-transform:uppercase;letter-spacing:1px;">Botnet C2 Servers</div>';
      dh += '</div>';

      dh += '<div style="background:#12121a;border:1px solid #1a1a2e;border-radius:8px;padding:16px;text-align:center;">';
      dh += '<div style="font-size:28px;font-weight:900;color:#ffaa00;font-family:monospace;">' + urlCount.toLocaleString() + '</div>';
      dh += '<div style="font-size:11px;color:#888;margin-top:4px;text-transform:uppercase;letter-spacing:1px;">Malware URLs</div>';
      dh += '</div>';

      dh += '<div style="background:#12121a;border:1px solid #1a1a2e;border-radius:8px;padding:16px;text-align:center;">';
      dh += '<div style="font-size:28px;font-weight:900;color:#00d4ff;font-family:monospace;">' + iocCount.toLocaleString() + '</div>';
      dh += '<div style="font-size:11px;color:#888;margin-top:4px;text-transform:uppercase;letter-spacing:1px;">Threat IOCs</div>';
      dh += '</div>';

      dh += '</div>';

      dh += _renderFeedPreview("Botnet C2 Servers", _feedCache.botnetC2, function(e) {
        return esc(e.ip_address || e.ip || "?") + ":" + esc(e.port || "?") + " - " + esc(e.malware || e.malware_printable || "unknown");
      }, "#ff6600");

      dh += _renderFeedPreview("Threat IOCs", _feedCache.threatIocs, function(e) {
        var val = e.ioc_value || e.ioc || "?";
        if (val.length > 60) val = val.substring(0, 57) + "...";
        return esc(val) + " (" + esc(e.threat_type || e.ioc_type || "unknown") + ")";
      }, "#00d4ff");

      dh += _renderFeedPreview("Malware URLs", _feedCache.malwareUrls, function(e) {
        var u = e.url || "?";
        if (u.length > 70) u = u.substring(0, 67) + "...";
        return esc(u) + " [" + esc(e.threat || e.url_status || "active") + "]";
      }, "#ffaa00");

      dh += _renderFeedPreview("Malicious IPs", _feedCache.maliciousIps, function(e) {
        if (typeof e === "string") return esc(e);
        return esc(e.ip || e.ip_address || "?") + (e.score ? " (score: " + e.score + ")" : "");
      }, "#ff3333");

      content.innerHTML = dh;
    });
  }

  function _renderFeedPreview(title, feed, formatter, color) {
    var ph = "";
    ph += '<div style="background:#12121a;border:1px solid #1a1a2e;border-radius:8px;padding:16px;margin-bottom:12px;">';
    ph += '<div style="font-size:13px;font-weight:700;color:' + color + ';margin-bottom:10px;letter-spacing:1px;">' + esc(title) + '</div>';
    if (!feed || !feed.data || feed.data.length === 0) {
      ph += '<div style="font-size:12px;color:#555;">No data available - run the sync script to populate feeds.</div>';
    } else {
      ph += '<div style="font-family:monospace;font-size:11px;">';
      var count = Math.min(feed.data.length, 5);
      for (var i = 0; i < count; i++) {
        ph += '<div style="padding:4px 0;border-bottom:1px solid #111;color:#aaa;">' + formatter(feed.data[i]) + '</div>';
      }
      ph += '</div>';
    }
    ph += '</div>';
    return ph;
  }

  function renderReport() {
    var user = auth.currentUser;
    var rh = "";
    rh += '<div style="background:#12121a;border:1px solid #1a1a2e;border-radius:8px;padding:20px;">';
    rh += '<div style="font-size:14px;font-weight:600;color:#ccc;margin-bottom:4px;">Report Malicious IP</div>';
    rh += '<div style="font-size:12px;color:#888;margin-bottom:16px;">Submit an IP to the community reputation database</div>';

    if (!user) {
      rh += '<div style="color:#ff6600;padding:12px;background:#1a1008;border:1px solid #332200;border-radius:6px;">You must be signed in to submit reports.</div>';
      rh += '</div>';
      content.innerHTML = rh;
      return;
    }

    rh += '<div style="margin-bottom:12px;">';
    rh += '<label style="font-size:12px;color:#888;display:block;margin-bottom:4px;">IP Address</label>';
    rh += '<input id="ipr-report-ip" type="text" placeholder="e.g. 45.33.32.156" style="width:100%;padding:10px 14px;background:#0d0d15;border:1px solid #1a1a2e;border-radius:6px;color:#e0e0e0;font-family:monospace;font-size:14px;outline:none;box-sizing:border-box;" />';
    rh += '</div>';

    rh += '<div style="margin-bottom:12px;">';
    rh += '<label style="font-size:12px;color:#888;display:block;margin-bottom:4px;">Category</label>';
    rh += '<select id="ipr-report-cat" style="width:100%;padding:10px 14px;background:#0d0d15;border:1px solid #1a1a2e;border-radius:6px;color:#e0e0e0;font-size:14px;outline:none;box-sizing:border-box;">';
    for (var ci = 0; ci < REPORT_CATEGORIES.length; ci++) {
      rh += '<option value="' + esc(REPORT_CATEGORIES[ci]) + '">' + esc(REPORT_CATEGORIES[ci]) + '</option>';
    }
    rh += '</select></div>';

    rh += '<div style="margin-bottom:16px;">';
    rh += '<label style="font-size:12px;color:#888;display:block;margin-bottom:4px;">Description (optional)</label>';
    rh += '<textarea id="ipr-report-desc" rows="3" placeholder="Additional details about the threat..." style="width:100%;padding:10px 14px;background:#0d0d15;border:1px solid #1a1a2e;border-radius:6px;color:#e0e0e0;font-size:13px;outline:none;resize:vertical;box-sizing:border-box;"></textarea>';
    rh += '</div>';

    rh += '<button id="ipr-report-btn" style="padding:10px 24px;background:#00d4ff;color:#000;border:none;border-radius:6px;font-weight:700;cursor:pointer;font-size:14px;">Submit Report</button>';
    rh += '<div id="ipr-report-msg" style="margin-top:10px;font-size:13px;"></div>';
    rh += '</div>';

    rh += '<div style="background:#12121a;border:1px solid #1a1a2e;border-radius:8px;padding:20px;margin-top:16px;">';
    rh += '<div style="font-size:14px;font-weight:600;color:#ccc;margin-bottom:12px;">Recent Community Reports</div>';
    rh += '<div id="ipr-recent-reports" style="color:#888;font-size:12px;">Loading...</div>';
    rh += '</div>';

    content.innerHTML = rh;

    var ipInput = content.querySelector("#ipr-report-ip");
    ipInput.addEventListener("focus", function() { this.style.borderColor = "#00d4ff"; });
    ipInput.addEventListener("blur", function() { this.style.borderColor = "#1a1a2e"; });

    content.querySelector("#ipr-report-btn").onclick = function() {
      var ip = content.querySelector("#ipr-report-ip").value.trim();
      var cat = content.querySelector("#ipr-report-cat").value;
      var desc = content.querySelector("#ipr-report-desc").value.trim();
      var msg = content.querySelector("#ipr-report-msg");

      if (!ip || !_isValidIP(ip)) {
        msg.style.color = "#ff6600";
        msg.textContent = "Enter a valid IPv4 address.";
        return;
      }

      var currentUser = auth.currentUser;
      if (!currentUser) {
        msg.style.color = "#ff6600";
        msg.textContent = "You must be signed in.";
        return;
      }

      msg.style.color = "#888";
      msg.textContent = "Submitting...";

      addDoc(collection(db, "ip_reports"), {
        ip: ip,
        reporter_uid: currentUser.uid,
        category: cat,
        description: desc,
        timestamp: serverTimestamp()
      }).then(function() {
        msg.style.color = "#00ff88";
        msg.textContent = "Report submitted successfully for " + ip + ".";
        content.querySelector("#ipr-report-ip").value = "";
        content.querySelector("#ipr-report-desc").value = "";
        _loadRecentReports();
      }).catch(function(e) {
        msg.style.color = "#ff3333";
        msg.textContent = "Error: " + (e.message || String(e));
      });
    };

    _loadRecentReports();
  }

  function _loadRecentReports() {
    var container = content.querySelector("#ipr-recent-reports");
    if (!container) return;
    try {
      var q = query(collection(db, "ip_reports"), orderBy("timestamp", "desc"), limit(20));
      getDocs(q).then(function(snap) {
        var reports = [];
        snap.forEach(function(d) { var r = d.data(); r.id = d.id; reports.push(r); });
        if (reports.length === 0) {
          container.innerHTML = '<div style="color:#555;">No community reports yet.</div>';
          return;
        }
        var rh = "";
        for (var i = 0; i < reports.length; i++) {
          var rep = reports[i];
          var ts = rep.timestamp ? (rep.timestamp.toDate ? rep.timestamp.toDate().toISOString().substring(0, 19) : String(rep.timestamp).substring(0, 19)) : "pending";
          rh += '<div style="padding:6px 0;border-bottom:1px solid #111;display:flex;gap:12px;align-items:center;flex-wrap:wrap;">';
          rh += '<span style="color:#e0e0e0;font-family:monospace;min-width:120px;">' + esc(rep.ip) + '</span>';
          rh += '<span style="color:#00d4ff;font-size:11px;min-width:80px;">' + esc(rep.category || "Other") + '</span>';
          rh += '<span style="color:#555;font-size:11px;">' + esc(ts) + '</span>';
          if (rep.description) rh += '<span style="color:#888;font-size:11px;flex:1;">' + esc(rep.description.length > 80 ? rep.description.substring(0, 77) + "..." : rep.description) + '</span>';
          rh += '</div>';
        }
        container.innerHTML = rh;
      }).catch(function() {
        container.innerHTML = '<div style="color:#ff6600;">Could not load reports.</div>';
      });
    } catch (e) {
      container.innerHTML = '<div style="color:#ff6600;">Firestore error: ' + esc(e.message || String(e)) + '</div>';
    }
  }

  switchTab("lookup");
}
