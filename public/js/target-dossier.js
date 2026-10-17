// Target Dossier — One-shot recon aggregator.
// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved.
//
// Enter a domain (or IP) and the tool runs several real, independent lookups in
// parallel and assembles a single, exportable intelligence report:
//   - Subdomains via crt.sh certificate transparency
//   - DNS records via DNS-over-HTTPS (dns.google)
//   - ASN / network via api.bgpview.io (resolves the A record first)
//   - Registration (RDAP / WHOIS) via rdap.org
//   - A computed risk / summary panel
// Every lookup is caught per-section — one failure never breaks the others.
// Results render progressively (each panel shows a spinner, then fills).
//   - Geolocation of the primary IP (ipapi.co) + reverse DNS with forward confirmation
// Nothing is fabricated; failures are reported as "unavailable".

import { dnFetch, proxyConfigured } from "/js/net.js";

const esc = (s) => String(s != null ? s : "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// Module-level store of the most recent assembled dossier (for export).
let DOSSIER = null;

const IP_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const IP6_RE = /^[0-9a-fA-F:]+:[0-9a-fA-F:]+$/;

function isIP(s) { return IP_RE.test(s) || IP6_RE.test(s); }

function normalizeTarget(raw) {
  return String(raw || "")
    .trim()
    .replace(/^[a-z]+:\/\//i, "")   // strip scheme
    .replace(/\/.*$/, "")            // strip path
    .replace(/:\d+$/, "")            // strip :port
    .toLowerCase();
}

function toast(msg, kind) {
  try { if (typeof window !== "undefined" && window.showToast) window.showToast(msg, kind || "success"); }
  catch (_) {}
}

// ── Fetch helpers (CSP-allowlisted hosts only) ──────────────────────────────

function fetchJSON(url, opts) {
  return fetch(url, opts).then(function (r) {
    if (!r.ok && r.status !== 404) throw new Error("HTTP " + r.status);
    return r.json().then(function (j) { return { status: r.status, json: j }; });
  });
}

// DNS-over-HTTPS (dns.google). Returns the Answer[] array (possibly empty).
function dohQuery(name, type) {
  return fetch("https://dns.google/resolve?name=" + encodeURIComponent(name) + "&type=" + encodeURIComponent(type))
    .then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
    .then(function (d) { return Array.isArray(d.Answer) ? d.Answer : []; });
}

// Certificate transparency (crt.sh). Returns a de-duplicated, sorted name list.
// crt.sh rarely sends CORS headers, so go through the Darknode proxy when it is configured.
function certSubdomains(domain) {
  var url = "https://crt.sh/?q=%25." + encodeURIComponent(domain) + "&output=json";
  var get = proxyConfigured()
    ? dnFetch(url, { raw: true, timeout: 20000 }).then(function (r) {
        if (r.status && r.status !== 200) throw new Error("crt.sh returned HTTP " + r.status);
        try { return JSON.parse(r.body); } catch (_) { throw new Error(r.truncated ? "crt.sh returned more data than the proxy size limit allows" : "crt.sh did not return valid JSON"); }
      })
    : fetch(url, { headers: { Accept: "application/json" } })
        .then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); });
  return get
    .then(function (rows) {
      if (!Array.isArray(rows)) return { names: [], wildcard: false, total: 0 };
      var set = {};
      var wildcard = false;
      for (var i = 0; i < rows.length; i++) {
        var nv = String(rows[i].name_value || "");
        var parts = nv.split(/\n/);
        for (var p = 0; p < parts.length; p++) {
          var n = parts[p].trim().toLowerCase();
          if (!n) continue;
          if (n.indexOf("*") === 0) { wildcard = true; n = n.replace(/^\*\./, ""); }
          if (n === domain || n.slice(-(domain.length + 1)) === "." + domain) set[n] = true;
        }
      }
      var names = Object.keys(set).sort();
      return { names: names, wildcard: wildcard, total: rows.length };
    });
}

// ASN / network via BGPView. Needs an IPv4/IPv6 address.
function bgpLookup(ip) {
  return fetchJSON("https://api.bgpview.io/ip/" + encodeURIComponent(ip)).then(function (res) {
    var d = (res.json && res.json.data) || {};
    var pref = (Array.isArray(d.prefixes) && d.prefixes[0]) || null;
    var asn = pref && pref.asn ? pref.asn : null;
    return {
      ip: d.ip || ip,
      ptr: d.ptr_record || "",
      prefix: pref ? pref.prefix : "",
      prefixName: pref ? (pref.name || "") : "",
      prefixDesc: pref ? (pref.description || "") : "",
      asn: asn ? asn.asn : "",
      asnName: asn ? (asn.name || "") : "",
      asnDesc: asn ? (asn.description || "") : "",
      country: asn ? (asn.country_code || "") : (pref ? (pref.country_code || "") : ""),
      rir: (d.rir_allocation && d.rir_allocation.rir_name) || "",
      allPrefixes: Array.isArray(d.prefixes) ? d.prefixes.map(function (x) { return x.prefix; }) : []
    };
  });
}

// RDAP (modern WHOIS) via rdap.org. Parses the common registration fields.
function rdapLookup(target, ip) {
  var url = "https://rdap.org/" + (ip ? "ip/" : "domain/") + encodeURIComponent(target);
  return fetch(url, { headers: { Accept: "application/rdap+json, application/json" } })
    .then(function (r) {
      if (r.status === 404) throw new Error("No RDAP record (404) — name may be unregistered or has no RDAP.");
      if (!r.ok) throw new Error("RDAP server returned HTTP " + r.status);
      return r.json();
    })
    .then(function (d) {
      var out = { raw: d, name: d.ldhName || d.handle || target, registrar: "", status: [], nameservers: [], events: {}, dnssec: null };
      // registrar = entity with registrar role
      var ents = d.entities || [];
      for (var i = 0; i < ents.length; i++) {
        var roles = ents[i].roles || [];
        if (roles.indexOf("registrar") >= 0) {
          out.registrar = vcardName(ents[i]) || ents[i].handle || "";
          break;
        }
      }
      if (Array.isArray(d.status)) out.status = d.status.slice();
      var ev = d.events || [];
      for (var e = 0; e < ev.length; e++) {
        if (ev[e].eventAction && ev[e].eventDate) out.events[ev[e].eventAction] = ev[e].eventDate;
      }
      var ns = d.nameservers || [];
      out.nameservers = ns.map(function (n) { return String(n.ldhName || "").toLowerCase(); }).filter(Boolean);
      if (d.secureDNS && typeof d.secureDNS.delegationSigned === "boolean") out.dnssec = d.secureDNS.delegationSigned;
      return out;
    });
}

// Geolocation (ipapi.co) of an address. ipapi returns {error:true, reason} on failure.
function geoLookup(ip) {
  return fetchJSON("https://ipapi.co/" + encodeURIComponent(ip) + "/json/").then(function (res) {
    var g = res.json || {};
    if (g.error) throw new Error(g.reason || "ipapi.co refused the lookup");
    return { ip: g.ip || ip, country: g.country_name || "", countryCode: g.country_code || "", region: g.region || "", city: g.city || "", org: g.org || "", asn: g.asn || "", timezone: g.timezone || "", latitude: g.latitude, longitude: g.longitude };
  });
}

// Reverse DNS (PTR, IPv4) and forward confirmation: does the PTR name resolve back to the IP?
function reverseLookup(ip) {
  if (!IP_RE.test(ip)) return Promise.resolve({ ptr: [], supported: false });
  var rev = ip.split(".").reverse().join(".") + ".in-addr.arpa";
  return dohQuery(rev, "PTR").then(function (ans) {
    var ptr = ans.filter(function (a) { return a.type === 12; }).map(function (a) { return String(a.data || "").replace(/\.$/, ""); }).filter(Boolean);
    if (!ptr.length) return { ptr: [], supported: true };
    return dohQuery(ptr[0], "A").then(function (fwd) {
      var addrs = fwd.filter(function (a) { return a.type === 1; }).map(function (a) { return a.data; });
      return { ptr: ptr, supported: true, forward: addrs, confirmed: addrs.indexOf(ip) >= 0 };
    }).catch(function () { return { ptr: ptr, supported: true, forward: null, confirmed: null }; });
  });
}

// Lookup history (most recent first, capped).
var HIST_KEY = "dn_dossier_history", HIST_MAX = 20;
function loadHistory() {
  try {
    var h = JSON.parse(localStorage.getItem(HIST_KEY) || "null");
    // One-time carry-over from the retired WHOIS Recon tool's history.
    if (!Array.isArray(h)) h = (JSON.parse(localStorage.getItem("dn_whois_history") || "[]") || []).map(function (x) { return x && x.query; });
    return h.filter(function (x) { return typeof x === "string" && x; }).slice(0, HIST_MAX);
  } catch (_) { return []; }
}
function saveHistory(list) { try { localStorage.setItem(HIST_KEY, JSON.stringify(list.slice(0, HIST_MAX))); } catch (_) {} }

function vcardName(entity) {
  var v = entity && entity.vcardArray && entity.vcardArray[1];
  if (!Array.isArray(v)) return "";
  for (var i = 0; i < v.length; i++) { if (v[i][0] === "fn" && v[i][3]) return String(v[i][3]); }
  for (var j = 0; j < v.length; j++) { if (v[j][0] === "org" && v[j][3]) return String(v[j][3]); }
  return "";
}

// ── Small render helpers ────────────────────────────────────────────────────

var SPINNER = '<div class="dsr-spin"><span class="dsr-dot"></span><span class="dsr-dot"></span><span class="dsr-dot"></span> Querying…</div>';

function unavailable(msg) {
  return '<div class="dsr-note dsr-warn">Unavailable — ' + esc(msg) + "</div>";
}

function kvTable(rows) {
  if (!rows.length) return '<div class="dsr-note muted">No data.</div>';
  var h = '<table class="data-table dsr-kv"><tbody>';
  for (var i = 0; i < rows.length; i++) {
    h += '<tr><td class="dsr-k">' + esc(rows[i][0]) + '</td><td class="dsr-v">' + esc(rows[i][1]) + "</td></tr>";
  }
  return h + "</tbody></table>";
}

function daysUntil(dateStr) {
  var t = Date.parse(dateStr);
  if (isNaN(t)) return null;
  return Math.round((t - Date.now()) / 86400000);
}

// ── Main render ─────────────────────────────────────────────────────────────

export function renderDossier(main) {
  main.innerHTML =
    '<style>' +
    '.dsr-wrap{color:var(--txt)}' +
    '.dsr-bar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:0 0 14px}' +
    '.dsr-bar input{flex:1;min-width:220px}' +
    '.dsr-ex{display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin:0 0 18px}' +
    '.dsr-ex .muted{font-size:.74rem}' +
    '.dsr-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:14px}' +
    '.dsr-grid .panel{min-width:0}' +
    '.dsr-body{padding:14px 18px}' +
    '.dsr-note{font-size:.82rem;padding:4px 0}' +
    '.dsr-warn{color:var(--warn,#e0a030)}' +
    '.dsr-kv td{vertical-align:top;word-break:break-word}' +
    '.dsr-k{color:var(--mut);white-space:nowrap;width:1%;padding-right:16px;font-size:.78rem}' +
    '.dsr-v{font-family:var(--font-mono)}' +
    '.dsr-sublist{max-height:340px;overflow:auto;font-family:var(--font-mono);font-size:.8rem;line-height:1.7}' +
    '.dsr-sublist div{border-bottom:1px solid color-mix(in srgb,var(--line) 55%,transparent);padding:2px 0;word-break:break-all}' +
    '.dsr-count{color:var(--mut);font-size:.72rem;font-weight:600;text-transform:uppercase;letter-spacing:.05em}' +
    '.dsr-spin{display:flex;align-items:center;gap:6px;color:var(--mut);font-size:.82rem}' +
    '.dsr-dot{width:6px;height:6px;border-radius:50%;background:var(--acc);display:inline-block;animation:dsrPulse 1s ease-in-out infinite}' +
    '.dsr-dot:nth-child(2){animation-delay:.15s}.dsr-dot:nth-child(3){animation-delay:.3s}' +
    '@keyframes dsrPulse{0%,100%{opacity:.25}50%{opacity:1}}' +
    '.dsr-finding{display:flex;gap:8px;align-items:flex-start;padding:5px 0;font-size:.82rem;border-bottom:1px solid color-mix(in srgb,var(--line) 50%,transparent)}' +
    '.dsr-finding:last-child{border-bottom:none}' +
    '.dsr-stat-row{display:flex;flex-wrap:wrap;gap:16px;margin-bottom:10px}' +
    '.dsr-stat{min-width:70px}' +
    '.dsr-stat b{display:block;font-size:1.4rem;font-family:var(--font-mono);color:var(--txt)}' +
    '.dsr-stat span{font-size:.68rem;text-transform:uppercase;letter-spacing:.05em;color:var(--mut)}' +
    '@media (max-width:640px){.dsr-grid{grid-template-columns:1fr}}' +
    '</style>' +
    '<div class="dsr-wrap">' +
    '<div class="pg-head"><div>' +
    '<h1 class="pg-h1">Target Dossier</h1>' +
    '<p class="muted pg-sub">One-shot recon dossier — subdomains, DNS, certificates, ASN, geolocation, reverse DNS and WHOIS assembled into a single exportable report. Lookups run live; the certificate search goes through the Darknode proxy when available.</p>' +
    "</div></div>" +
    '<div class="dsr-bar">' +
    '<input id="dsr-input" type="text" placeholder="Domain or IP address" autocomplete="off" spellcheck="false">' +
    '<button class="btn primary" id="dsr-run">Build Dossier</button>' +
    '<button class="btn ghost" id="dsr-json" disabled>Export JSON</button>' +
    '<button class="btn ghost" id="dsr-md" disabled>Export Markdown</button>' +
    "</div>" +
    '<div class="dsr-ex" id="dsr-hist"></div>' +
    '<div class="dsr-grid" id="dsr-grid"></div>' +
    "</div>";

  var input = main.querySelector("#dsr-input");
  var runBtn = main.querySelector("#dsr-run");
  var jsonBtn = main.querySelector("#dsr-json");
  var mdBtn = main.querySelector("#dsr-md");
  var grid = main.querySelector("#dsr-grid");

  runBtn.addEventListener("click", function () { run(input.value); });
  input.addEventListener("keydown", function (e) { if (e.key === "Enter") run(input.value); });
  var histEl = main.querySelector("#dsr-hist");
  function renderHistory() {
    var h = loadHistory();
    histEl.hidden = !h.length;
    histEl.innerHTML = h.length ? '<span class="muted">Recent:</span>' + h.map(function (d) {
      return '<button class="btn ghost sm dsr-eg" data-t="' + esc(d) + '">' + esc(d) + "</button>";
    }).join("") + '<button class="btn ghost sm" id="dsr-hist-clear">Clear</button>' : "";
  }
  histEl.addEventListener("click", function (e) {
    var b = e.target.closest("button");
    if (!b) return;
    if (b.id === "dsr-hist-clear") { saveHistory([]); renderHistory(); return; }
    input.value = b.dataset.t; run(b.dataset.t);
  });
  renderHistory();
  jsonBtn.addEventListener("click", function () { exportDossier("json"); });
  mdBtn.addEventListener("click", function () { exportDossier("md"); });

  // Panel scaffolding — each panel owns a body element we fill as data arrives.
  function panel(id, title) {
    return '<div class="panel"><div class="panel-h"><span class="pg-h2">' + esc(title) +
      '</span><span class="dsr-count" id="dsr-c-' + id + '"></span></div>' +
      '<div class="dsr-body" id="dsr-' + id + '">' + SPINNER + "</div></div>";
  }
  function body(id) { return main.querySelector("#dsr-" + id); }
  function count(id, txt) { var el = main.querySelector("#dsr-c-" + id); if (el) el.textContent = txt || ""; }

  function run(raw) {
    var target = normalizeTarget(raw);
    if (!target) { toast("Enter a domain or IP address.", "error"); return; }
    var targetIsIP = isIP(target);
    saveHistory([target].concat(loadHistory().filter(function (x) { return x !== target; })));
    renderHistory();

    jsonBtn.disabled = true;
    mdBtn.disabled = true;
    runBtn.disabled = true;
    runBtn.textContent = "Working…";

    DOSSIER = {
      target: target,
      kind: targetIsIP ? "ip" : "domain",
      generatedAt: new Date().toISOString(),
      dns: null,
      subdomains: null,
      network: null,
      geo: null,
      reverse: null,
      registration: null,
      summary: null
    };

    grid.innerHTML =
      panel("summary", "Risk & Summary") +
      panel("subs", "Subdomains — crt.sh") +
      panel("dns", "DNS Records — dns.google") +
      panel("net", "Network / ASN — BGPView") +
      panel("geo", "Geolocation & Reverse DNS") +
      panel("reg", "Registration — RDAP / WHOIS");

    var pending = { dns: true, subs: true, net: true, geo: true, reg: true };
    function done(key) { pending[key] = false; if (!pending.dns && !pending.subs && !pending.net && !pending.geo && !pending.reg) finish(); }

    var primaryIP = targetIsIP ? target : null;

    // ── DNS (and derive the primary A record for the network lookup) ──
    var dnsReady;
    if (targetIsIP) {
      body("dns").innerHTML = '<div class="dsr-note muted">Target is an IP address — DNS record lookup skipped.</div>';
      dnsReady = Promise.resolve();
      done("dns");
    } else {
      var types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"];
      dnsReady = Promise.all(types.map(function (t) {
        return dohQuery(target, t).then(function (ans) { return { t: t, ans: ans }; })
          .catch(function () { return { t: t, ans: null }; });
      })).then(function (results) {
        var byType = {};
        var any = false, failed = 0;
        results.forEach(function (r) {
          if (r.ans === null) { failed++; return; }
          byType[r.t] = r.ans;
          if (r.ans.length) any = true;
          if (r.t === "A" && r.ans.length && !primaryIP) primaryIP = r.ans[0].data;
        });
        DOSSIER.dns = byType;
        renderDNS(byType, any, failed === types.length);
        count("dns", any ? Object.keys(byType).reduce(function (n, k) { return n + byType[k].length; }, 0) + " records" : "");
      }).catch(function (e) {
        body("dns").innerHTML = unavailable((e && e.message) || "DNS lookup failed.");
      }).then(function () { done("dns"); });
    }

    // ── Subdomains (crt.sh) — independent ──
    if (targetIsIP) {
      body("subs").innerHTML = '<div class="dsr-note muted">Certificate transparency search needs a domain — skipped for IP targets.</div>';
      done("subs");
    } else {
      certSubdomains(target).then(function (res) {
        DOSSIER.subdomains = res;
        renderSubs(res);
        count("subs", res.names.length + " found");
      }).catch(function (e) {
        body("subs").innerHTML = unavailable(((e && e.message) || "crt.sh unreachable") +
          " (crt.sh often blocks cross-origin requests or times out).");
      }).then(function () { done("subs"); });
    }

    // ── Network / ASN (BGPView) — waits for the A record if we have a domain ──
    dnsReady.then(function () {
      if (!primaryIP) {
        body("net").innerHTML = '<div class="dsr-note muted">No A record resolved — network lookup skipped.</div>';
        done("net");
        return;
      }
      return bgpLookup(primaryIP).then(function (net) {
        DOSSIER.network = net;
        renderNet(net);
        count("net", net.asn ? "AS" + net.asn : "");
      }).catch(function (e) {
        body("net").innerHTML = unavailable((e && e.message) || "BGPView unreachable.");
      }).then(function () { done("net"); });
    });

    // ── Geolocation + reverse DNS of the primary address — waits for the A record ──
    dnsReady.then(function () {
      if (!primaryIP) {
        body("geo").innerHTML = '<div class="dsr-note muted">No A record resolved — geolocation and reverse DNS skipped.</div>';
        done("geo");
        return;
      }
      return Promise.all([
        geoLookup(primaryIP).catch(function (e) { return { error: (e && e.message) || "ipapi.co unreachable" }; }),
        reverseLookup(primaryIP).catch(function (e) { return { error: (e && e.message) || "PTR lookup failed" }; })
      ]).then(function (r) {
        DOSSIER.geo = r[0].error ? null : r[0];
        DOSSIER.reverse = r[1].error ? null : r[1];
        renderGeo(primaryIP, r[0], r[1]);
        count("geo", DOSSIER.geo && DOSSIER.geo.countryCode ? DOSSIER.geo.countryCode : "");
      }).then(function () { done("geo"); });
    });

    // ── Registration (RDAP) — independent ──
    rdapLookup(target, targetIsIP).then(function (reg) {
      DOSSIER.registration = reg;
      renderReg(reg, targetIsIP);
      count("reg", reg.registrar ? "" : "");
    }).catch(function (e) {
      body("reg").innerHTML = unavailable((e && e.message) || "RDAP lookup failed.");
    }).then(function () { done("reg"); });

    // ── Finalize: compute the summary once everything settled ──
    function finish() {
      var summary = computeSummary(DOSSIER, primaryIP);
      DOSSIER.summary = summary;
      renderSummary(summary);
      runBtn.disabled = false;
      runBtn.textContent = "Build Dossier";
      jsonBtn.disabled = false;
      mdBtn.disabled = false;
      toast("Dossier assembled for " + target, "success");
    }
  }

  // ── Section renderers ──

  function renderDNS(byType, any, allFailed) {
    if (allFailed) { body("dns").innerHTML = unavailable("DNS-over-HTTPS requests failed (network or CORS)."); return; }
    if (!any) { body("dns").innerHTML = '<div class="dsr-note muted">No DNS records returned.</div>'; return; }
    var html = "";
    var order = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"];
    order.forEach(function (t) {
      var ans = byType[t];
      if (!ans || !ans.length) return;
      html += '<div class="dsr-count" style="margin:8px 0 2px">' + esc(t) + "</div>";
      html += '<div class="dsr-sublist">' + ans.map(function (a) {
        return "<div>" + esc(String(a.data || "")) + (a.TTL != null ? ' <span class="muted">(TTL ' + esc(a.TTL) + ")</span>" : "") + "</div>";
      }).join("") + "</div>";
    });
    body("dns").innerHTML = html || '<div class="dsr-note muted">No DNS records returned.</div>';
  }

  function renderSubs(res) {
    if (!res.names.length) { body("subs").innerHTML = '<div class="dsr-note muted">No subdomains found in certificate transparency logs.</div>'; return; }
    var head = '<div class="dsr-note">' + res.names.length + " unique name" + (res.names.length === 1 ? "" : "s") +
      " across " + res.total + " certificate record" + (res.total === 1 ? "" : "s") +
      (res.wildcard ? ' &middot; <span class="dsr-warn">wildcard certificate present</span>' : "") + "</div>";
    body("subs").innerHTML = head + '<div class="dsr-sublist">' +
      res.names.map(function (n) { return "<div>" + esc(n) + "</div>"; }).join("") + "</div>";
  }

  function renderNet(net) {
    var rows = [];
    if (net.ip) rows.push(["IP", net.ip]);
    if (net.asn) rows.push(["ASN", "AS" + net.asn + (net.asnName ? " (" + net.asnName + ")" : "")]);
    if (net.asnDesc) rows.push(["Operator", net.asnDesc]);
    if (net.prefix) rows.push(["Prefix", net.prefix + (net.prefixDesc ? " — " + net.prefixDesc : "")]);
    if (net.country) rows.push(["Country", net.country]);
    if (net.rir) rows.push(["RIR", net.rir]);
    if (net.ptr) rows.push(["PTR", net.ptr]);
    if (net.allPrefixes && net.allPrefixes.length > 1) rows.push(["Announced prefixes", String(net.allPrefixes.length)]);
    body("net").innerHTML = rows.length ? kvTable(rows) : '<div class="dsr-note muted">No ASN / network data returned.</div>';
  }

  function renderGeo(ip, geo, rev) {
    var html = "";
    if (geo.error) html += unavailable("Geolocation: " + geo.error);
    else {
      var rows = [["IP", geo.ip]];
      var place = [geo.city, geo.region, geo.country].filter(Boolean).join(", ");
      if (place) rows.push(["Location", place + (geo.countryCode ? " (" + geo.countryCode + ")" : "")]);
      if (geo.org) rows.push(["ISP / Org", geo.org]);
      if (geo.asn) rows.push(["ASN", geo.asn]);
      if (geo.timezone) rows.push(["Timezone", geo.timezone]);
      if (geo.latitude != null && geo.longitude != null) rows.push(["Coordinates", geo.latitude + ", " + geo.longitude]);
      html += kvTable(rows);
    }
    if (rev.error) html += unavailable("Reverse DNS: " + rev.error);
    else if (!rev.supported) html += '<div class="dsr-note muted">Reverse DNS lookup here supports IPv4 addresses only.</div>';
    else if (!rev.ptr.length) html += '<div class="dsr-note muted">No PTR (reverse DNS) record for ' + esc(ip) + ".</div>";
    else {
      var fc = rev.confirmed === true ? "yes — the name resolves back to " + ip : rev.confirmed === false ? "no — " + rev.ptr[0] + " resolves to " + ((rev.forward || []).join(", ") || "nothing") : "could not be checked";
      html += kvTable([["PTR", rev.ptr.join(", ")], ["Forward-confirmed", fc]]);
    }
    html += '<div class="dsr-note muted" style="margin-top:6px">Sources: ipapi.co geolocation (approximate) and dns.google PTR lookup.</div>';
    body("geo").innerHTML = html;
  }

  function renderReg(reg, targetIsIP) {
    var rows = [];
    if (reg.name) rows.push(["Name", reg.name]);
    if (reg.registrar) rows.push(["Registrar", reg.registrar]);
    var evLabels = { registration: "Created", "last changed": "Updated", expiration: "Expires", "last update of RDAP database": "RDAP updated" };
    Object.keys(reg.events).forEach(function (k) {
      var label = evLabels[k] || k;
      var val = reg.events[k];
      if (k === "expiration") {
        var d = daysUntil(val);
        if (d != null) val += (d < 0 ? " (expired)" : " (" + d + " days)");
      }
      rows.push([label, val]);
    });
    if (reg.status && reg.status.length) rows.push(["Status", reg.status.join(", ")]);
    if (reg.nameservers && reg.nameservers.length) rows.push(["Nameservers", reg.nameservers.join(", ")]);
    if (reg.dnssec != null) rows.push(["DNSSEC", reg.dnssec ? "signed" : "unsigned"]);
    body("reg").innerHTML = rows.length
      ? kvTable(rows) + '<div class="dsr-note muted" style="margin-top:6px">Source: RDAP via rdap.org. Registries commonly redact personal contact details.</div>'
      : '<div class="dsr-note muted">RDAP responded but returned no registration fields.</div>';
  }

  function renderSummary(summary) {
    var statHtml = '<div class="dsr-stat-row">' +
      '<div class="dsr-stat"><b>' + summary.stats.subdomains + '</b><span>Subdomains</span></div>' +
      '<div class="dsr-stat"><b>' + summary.stats.dnsRecords + '</b><span>DNS records</span></div>' +
      '<div class="dsr-stat"><b>' + summary.stats.nameservers + '</b><span>Nameservers</span></div>' +
      '<div class="dsr-stat"><b>' + (summary.stats.asn || "—") + '</b><span>ASN</span></div>' +
      "</div>";
    var findHtml = summary.findings.length
      ? summary.findings.map(function (f) {
          var cls = f.level === "warn" ? "badge-warn" : (f.level === "bad" ? "badge-bad" : (f.level === "ok" ? "badge-ok" : "badge-info"));
          var tag = f.level === "warn" ? "NOTE" : (f.level === "bad" ? "RISK" : (f.level === "ok" ? "OK" : "INFO"));
          return '<div class="dsr-finding"><span class="badge ' + cls + '">' + tag + "</span><span>" + esc(f.text) + "</span></div>";
        }).join("")
      : '<div class="dsr-note muted">No notable findings.</div>';
    body("summary").innerHTML = statHtml + findHtml;
    count("summary", summary.findings.length + " finding" + (summary.findings.length === 1 ? "" : "s"));
  }
}

// ── Summary / risk computation ──────────────────────────────────────────────

function computeSummary(d, primaryIP) {
  var findings = [];
  var dnsCount = 0;
  if (d.dns) Object.keys(d.dns).forEach(function (k) { dnsCount += d.dns[k].length; });
  var subCount = d.subdomains ? d.subdomains.names.length : 0;
  var nsCount = d.registration && d.registration.nameservers ? d.registration.nameservers.length : 0;

  if (subCount >= 100) findings.push({ level: "warn", text: "Large attack surface: " + subCount + " subdomains observed in certificate transparency logs." });
  else if (subCount > 0) findings.push({ level: "info", text: subCount + " subdomain(s) discovered via certificate transparency." });

  if (d.subdomains && d.subdomains.wildcard) findings.push({ level: "warn", text: "Wildcard certificate present — a single cert covers arbitrary subdomains." });

  if (d.dns && d.dns.MX && d.dns.MX.length) findings.push({ level: "info", text: "Mail exchangers configured (" + d.dns.MX.length + " MX record(s))." });
  if (d.dns && d.dns.TXT) {
    var txts = d.dns.TXT.map(function (a) { return String(a.data || ""); });
    var hasSPF = txts.some(function (t) { return /v=spf1/i.test(t); });
    var hasDMARC = txts.some(function (t) { return /v=DMARC1/i.test(t); });
    if (hasSPF) findings.push({ level: "ok", text: "SPF record published." });
    else if (d.dns.MX && d.dns.MX.length) findings.push({ level: "warn", text: "Mail is configured but no SPF record was found in TXT records." });
    if (hasDMARC) findings.push({ level: "ok", text: "DMARC record published." });
  }

  if (d.registration) {
    var reg = d.registration;
    if (reg.events && reg.events.expiration) {
      var days = daysUntil(reg.events.expiration);
      if (days != null && days < 0) findings.push({ level: "bad", text: "Registration appears EXPIRED (expiry " + reg.events.expiration + ")." });
      else if (days != null && days <= 30) findings.push({ level: "warn", text: "Domain expires in " + days + " day(s) — renewal window." });
    }
    if (reg.dnssec === false) findings.push({ level: "warn", text: "DNSSEC is not enabled for this domain." });
    else if (reg.dnssec === true) findings.push({ level: "ok", text: "DNSSEC delegation is signed." });
    var statuses = (reg.status || []).map(function (s) { return String(s).toLowerCase(); });
    if (statuses.some(function (s) { return s.indexOf("hold") >= 0; })) findings.push({ level: "bad", text: "Domain has a hold status: " + reg.status.join(", ") + "." });
    if (statuses.some(function (s) { return s.indexOf("pending delete") >= 0 || s.indexOf("redemption") >= 0; })) findings.push({ level: "bad", text: "Domain is in a delete/redemption lifecycle state." });
  }

  if (d.network && d.network.asn) findings.push({ level: "info", text: "Hosted on AS" + d.network.asn + (d.network.asnName ? " (" + d.network.asnName + ")" : "") + (d.network.country ? ", " + d.network.country : "") + "." });

  else if (d.geo && d.geo.asn) findings.push({ level: "info", text: "Hosted on " + d.geo.asn + (d.geo.org ? " (" + d.geo.org + ")" : "") + (d.geo.countryCode ? ", " + d.geo.countryCode : "") + " (ipapi.co)." });

  if (primaryIP) findings.push({ level: "info", text: "Primary address resolved: " + primaryIP + "." });
  if (d.reverse && d.reverse.ptr && d.reverse.ptr.length && d.reverse.confirmed === false) findings.push({ level: "warn", text: "Reverse DNS " + d.reverse.ptr[0] + " does not resolve back to " + primaryIP + " (not forward-confirmed)." });

  return {
    stats: { subdomains: subCount, dnsRecords: dnsCount, nameservers: nsCount, asn: d.network && d.network.asn ? "AS" + d.network.asn : (d.geo && d.geo.asn) || "" },
    findings: findings
  };
}

// ── Export ──────────────────────────────────────────────────────────────────

function download(filename, text, mime) {
  try {
    var blob = new Blob([text], { type: mime });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 2000);
  } catch (e) {
    toast("Export failed: " + ((e && e.message) || "unknown error"), "error");
  }
}

function exportDossier(fmt) {
  if (!DOSSIER) { toast("Run a dossier first.", "error"); return; }
  var base = "dossier-" + DOSSIER.target.replace(/[^a-z0-9.\-]/gi, "_") + "-" + DOSSIER.generatedAt.slice(0, 10);
  if (fmt === "json") {
    download(base + ".json", JSON.stringify(DOSSIER, null, 2), "application/json");
    toast("Exported JSON dossier.", "success");
  } else {
    download(base + ".md", toMarkdown(DOSSIER), "text/markdown");
    toast("Exported Markdown dossier.", "success");
  }
}

function toMarkdown(d) {
  var L = [];
  L.push("# Target Dossier: " + d.target);
  L.push("");
  L.push("- Target type: " + d.kind);
  L.push("- Generated: " + d.generatedAt);
  L.push("");

  L.push("## Risk & Summary");
  if (d.summary) {
    L.push("");
    L.push("| Metric | Value |");
    L.push("| --- | --- |");
    L.push("| Subdomains | " + d.summary.stats.subdomains + " |");
    L.push("| DNS records | " + d.summary.stats.dnsRecords + " |");
    L.push("| Nameservers | " + d.summary.stats.nameservers + " |");
    L.push("| ASN | " + (d.summary.stats.asn || "n/a") + " |");
    L.push("");
    if (d.summary.findings.length) {
      d.summary.findings.forEach(function (f) { L.push("- [" + f.level.toUpperCase() + "] " + f.text); });
    } else { L.push("- No notable findings."); }
  } else { L.push("", "_Not computed._"); }
  L.push("");

  L.push("## DNS Records");
  if (d.dns && Object.keys(d.dns).length) {
    ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"].forEach(function (t) {
      var ans = d.dns[t];
      if (!ans || !ans.length) return;
      L.push("");
      L.push("### " + t);
      ans.forEach(function (a) { L.push("- `" + String(a.data || "") + "`" + (a.TTL != null ? " (TTL " + a.TTL + ")" : "")); });
    });
  } else { L.push("", "_Unavailable or no records._"); }
  L.push("");

  L.push("## Subdomains (crt.sh)");
  if (d.subdomains && d.subdomains.names.length) {
    L.push("");
    L.push(d.subdomains.names.length + " unique names" + (d.subdomains.wildcard ? " (wildcard certificate present)" : "") + ":");
    L.push("");
    d.subdomains.names.forEach(function (n) { L.push("- " + n); });
  } else { L.push("", "_None found or unavailable._"); }
  L.push("");

  L.push("## Network / ASN (BGPView)");
  if (d.network) {
    var n = d.network;
    L.push("");
    if (n.ip) L.push("- IP: `" + n.ip + "`");
    if (n.asn) L.push("- ASN: AS" + n.asn + (n.asnName ? " (" + n.asnName + ")" : ""));
    if (n.asnDesc) L.push("- Operator: " + n.asnDesc);
    if (n.prefix) L.push("- Prefix: `" + n.prefix + "`" + (n.prefixDesc ? " — " + n.prefixDesc : ""));
    if (n.country) L.push("- Country: " + n.country);
    if (n.rir) L.push("- RIR: " + n.rir);
    if (n.ptr) L.push("- PTR: " + n.ptr);
  } else { L.push("", "_Unavailable._"); }
  L.push("");

  L.push("## Geolocation & Reverse DNS");
  if (d.geo || d.reverse) {
    L.push("");
    var g = d.geo;
    if (g) {
      L.push("- IP: `" + g.ip + "`");
      var place = [g.city, g.region, g.country].filter(Boolean).join(", ");
      if (place) L.push("- Location: " + place);
      if (g.org) L.push("- ISP / Org: " + g.org);
      if (g.asn) L.push("- ASN: " + g.asn);
    }
    if (d.reverse && d.reverse.ptr && d.reverse.ptr.length) {
      L.push("- PTR: " + d.reverse.ptr.join(", "));
      L.push("- Forward-confirmed: " + (d.reverse.confirmed === true ? "yes" : d.reverse.confirmed === false ? "no" : "unknown"));
    } else if (d.reverse) L.push("- PTR: none");
  } else { L.push("", "_Unavailable._"); }
  L.push("");

  L.push("## Registration (RDAP / WHOIS)");
  if (d.registration) {
    var r = d.registration;
    L.push("");
    if (r.name) L.push("- Name: " + r.name);
    if (r.registrar) L.push("- Registrar: " + r.registrar);
    Object.keys(r.events || {}).forEach(function (k) { L.push("- " + k + ": " + r.events[k]); });
    if (r.status && r.status.length) L.push("- Status: " + r.status.join(", "));
    if (r.nameservers && r.nameservers.length) L.push("- Nameservers: " + r.nameservers.join(", "));
    if (r.dnssec != null) L.push("- DNSSEC: " + (r.dnssec ? "signed" : "unsigned"));
    L.push("");
    L.push("_Source: RDAP via rdap.org. Registries commonly redact personal contact details._");
  } else { L.push("", "_Unavailable._"); }
  L.push("");
  L.push("---");
  L.push("Generated by Darknode Target Dossier.");
  return L.join("\n");
}
