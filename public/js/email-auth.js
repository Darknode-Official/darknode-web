// Email Authentication Analyzer — SPF / DMARC / DKIM auditor for the Darknode web app.
// Checks a domain's email-authentication DNS records live via DNS-over-HTTPS (Cloudflare, Google fallback).
// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Fully client-side. No external libraries. All records shown are the real DNS answers, never fabricated.
//
// Architecture
//   transport  : dohTXT(name, signal)  — Cloudflare primary → Google fallback, AbortController (external
//                signal + internal 8s timeout, combined and cleaned up), joins split TXT chunks.
//                Module-level in-flight de-dupe so a name is never fetched twice concurrently.
//   parsers    : analyzeSPF / analyzeDMARC / analyzeDKIM — PURE (DNS text in → {status,record,findings} out),
//                no DOM, independently testable.
//   render     : fires the three lookups concurrently and fills each card progressively as its data
//                resolves (never blocks on the slowest). Per-domain in-memory cache makes re-analysis
//                instant. Outstanding requests are aborted when a new analysis starts or the tool is torn
//                down (MutationObserver on the mount, since this tool has no auth.js cleanup hook).

const esc = (s) => String(s != null ? s : "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// ── palette (status pills only; everything else uses theme tokens) ──
var C_PASS = "#38d99a";
var C_WARN = "#f5b544";
var C_FAIL = "#f0484a";

// common DKIM selectors to probe when the user does not supply one
var DEFAULT_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "dkim", "s1", "mail"];
var EXAMPLE_DOMAINS = ["google.com", "github.com", "paypal.com", "microsoft.com"];

function toast(msg) {
  if (typeof window.showToast === "function") window.showToast(msg);
}

// ── sanitize a user-entered domain: strip scheme, path, user@, port, lowercase ──
function cleanDomain(raw) {
  var d = String(raw == null ? "" : raw).trim().toLowerCase();
  d = d.replace(/^[a-z][a-z0-9+.-]*:\/\//, ""); // scheme://
  d = d.replace(/^.*@/, "");                     // user@ (email address)
  d = d.split("/")[0];                           // path
  d = d.split("?")[0];                           // query
  d = d.split("#")[0];                           // fragment
  d = d.split(":")[0];                           // port
  d = d.replace(/\.+$/, "").replace(/^\.+/, ""); // stray dots
  return d.trim();
}

function validDomain(d) {
  return /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(d);
}

// ────────────────────────────────────────────────────────────────────────────
// TRANSPORT — DNS-over-HTTPS TXT lookup (pure of DOM)
// ────────────────────────────────────────────────────────────────────────────

// De-dupe identical in-flight lookups so a name is never fetched twice at once.
var INFLIGHT = new Map();

// Single HTTP fetch of one DoH endpoint. Combines an optional external abort signal
// (new analysis / teardown) with an internal 8s timeout, and cleans both up on settle.
function fetchDoH(url, signal) {
  var ctrl = typeof AbortController !== "undefined" ? new AbortController() : null;
  var timer = null, onAbort = null;
  function cleanup() {
    if (timer) { clearTimeout(timer); timer = null; }
    if (onAbort && signal) { try { signal.removeEventListener("abort", onAbort); } catch (e) {} onAbort = null; }
  }
  if (ctrl) {
    timer = setTimeout(function () { try { ctrl.abort(); } catch (e) {} }, 8000);
    if (signal) {
      if (signal.aborted) { try { ctrl.abort(); } catch (e) {} }
      else { onAbort = function () { try { ctrl.abort(); } catch (e) {} }; try { signal.addEventListener("abort", onAbort); } catch (e) {} }
    }
  }
  var opts = { headers: { Accept: "application/dns-json" } };
  if (ctrl) opts.signal = ctrl.signal;
  return fetch(url, opts).then(function (res) {
    cleanup();
    if (!res.ok) throw new Error("HTTP " + res.status);
    return res.json();
  }, function (err) {
    cleanup();
    throw err;
  });
}

// Status 0 = NOERROR, 3 = NXDOMAIN. Answer entries carry the TXT in .data.
function parseDoH(json) {
  var out = [];
  var answers = (json && json.Answer) || [];
  answers.forEach(function (a) {
    if (a && (a.type === 16 || a.type === "TXT")) out.push(decodeTXT(a.data));
  });
  return { ok: true, status: json ? json.Status : -1, txt: out };
}

// Public transport: Cloudflare primary, Google fallback. Never rejects — resolves
// { ok:true, status, txt:[...] } or { ok:false, error }. In-flight de-duped by name.
function dohTXT(name, signal) {
  if (signal && signal.aborted) return Promise.resolve({ ok: false, error: "aborted" });
  var shared = INFLIGHT.get(name);
  if (shared) return shared;

  var CF = "https://cloudflare-dns.com/dns-query?name=" + encodeURIComponent(name) + "&type=TXT";
  var GOOG = "https://dns.google/resolve?name=" + encodeURIComponent(name) + "&type=TXT";

  var p = fetchDoH(CF, signal).then(parseDoH).catch(function (err) {
    if (signal && signal.aborted) return { ok: false, error: "aborted" };
    return fetchDoH(GOOG, signal).then(parseDoH).catch(function (e) {
      return { ok: false, error: (e && e.message) ? e.message : "DNS query failed" };
    });
  }).then(function (r) {
    INFLIGHT.delete(name);
    return r;
  }, function (e) {
    INFLIGHT.delete(name);
    return { ok: false, error: (e && e.message) ? e.message : "DNS query failed" };
  });

  INFLIGHT.set(name, p);
  return p;
}

// TXT records arrive as one or more double-quoted chunks; join and unquote them.
function decodeTXT(data) {
  var s = String(data == null ? "" : data);
  var chunks = s.match(/"(?:[^"\\]|\\.)*"/g);
  if (chunks && chunks.length) {
    return chunks.map(function (c) {
      return c.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, "\\");
    }).join("");
  }
  // already unquoted (some resolvers)
  return s.replace(/^"|"$/g, "");
}

// ────────────────────────────────────────────────────────────────────────────
// PARSERS / GRADERS — pure functions, DNS text in → { status, record, findings } out
// ────────────────────────────────────────────────────────────────────────────

// ── SPF analysis ──
function analyzeSPF(txts) {
  var rec = null;
  (txts || []).forEach(function (t) { if (/^v=spf1(\s|$)/i.test(t.trim())) rec = t.trim(); });
  if (!rec) {
    return { status: "FAIL", record: null, findings: [
      { kind: "bad", text: "No SPF record (v=spf1) found at the domain root. Receivers cannot verify which servers may send mail for this domain." },
      { kind: "tip", text: "Publish a TXT record such as: v=spf1 include:_spf.example.com -all" }
    ] };
  }
  var findings = [];
  var nSpf = (txts || []).filter(function (t) { return /^v=spf1(\s|$)/i.test(String(t).trim()); }).length;
  var tokens = rec.split(/\s+/).slice(1).filter(Boolean);
  var allPolicy = null, includes = 0, lookups = 0, worst = "PASS";

  tokens.forEach(function (tok) {
    var m = /^([+\-~?]?)(all|include|a|mx|ptr|exists|ip4|ip6|redirect|exp)([:=].*)?$/i.exec(tok);
    if (!m && !/^redirect=|^exp=/i.test(tok)) {
      findings.push({ kind: "warn", text: "Unrecognised mechanism/term: " + tok });
      if (worst === "PASS") worst = "WARN";
      return;
    }
    var qual = m ? m[1] : "";
    var mech = m ? m[2].toLowerCase() : tok.split(/[:=]/)[0].toLowerCase();
    if (mech === "all") allPolicy = (qual || "+") + "all";
    if (mech === "include") { includes++; lookups++; }
    // Each of a/mx/ptr/exists/redirect causes a DNS lookup toward the RFC 7208 limit of 10.
    if (mech === "a" || mech === "mx" || mech === "ptr" || mech === "exists" || mech === "redirect") lookups++;
    if (mech === "ptr") {
      findings.push({ kind: "warn", text: "Uses the deprecated 'ptr' mechanism, which is slow and discouraged (RFC 7208)." });
      if (worst === "PASS") worst = "WARN";
    }
  });

  if (allPolicy === "-all") {
    findings.push({ kind: "good", text: "Ends with -all (fail / hard reject) — strongest SPF posture." });
  } else if (allPolicy === "~all") {
    findings.push({ kind: "warn", text: "Ends with ~all (softfail). Mail from unlisted servers is accepted but marked. Consider -all once confident." });
    if (worst === "PASS") worst = "WARN";
  } else if (allPolicy === "?all") {
    findings.push({ kind: "warn", text: "Ends with ?all (neutral) — provides effectively no protection." });
    if (worst === "PASS") worst = "WARN";
  } else if (allPolicy === "+all") {
    findings.push({ kind: "bad", text: "Ends with +all (pass all) — DANGEROUS. Any server on the internet may send as this domain. Remove immediately." });
    worst = "FAIL";
  } else {
    findings.push({ kind: "warn", text: "No explicit 'all' mechanism. Default handling is neutral; add -all or ~all." });
    if (worst === "PASS") worst = "WARN";
  }

  findings.push({ kind: "info", text: "include: count = " + includes + (lookups ? " · approx. DNS-lookup mechanisms = " + lookups : "") });
  if (lookups > 10) {
    findings.push({ kind: "bad", text: "SPF allows a maximum of 10 DNS-lookup mechanisms (include/a/mx/ptr/exists/redirect). This record has about " + lookups + " and may 'permerror'. Flatten or consolidate includes." });
    worst = "FAIL";
  } else if (lookups >= 8) {
    findings.push({ kind: "warn", text: "Close to the SPF 10 DNS-lookup limit (about " + lookups + "). Watch for growth." });
    if (worst === "PASS") worst = "WARN";
  }
  if (nSpf > 1) {
    findings.unshift({ kind: "bad", text: nSpf + " SPF records (v=spf1) are published. RFC 7208 4.5 makes that a permerror: SPF fails for all mail. Merge them into one record." });
    worst = "FAIL";
  }

  return { status: worst, record: rec, findings: findings };
}

// ── DMARC analysis ──
function analyzeDMARC(txts) {
  var rec = null;
  (txts || []).forEach(function (t) { if (/^v=DMARC1\s*;?/i.test(t.trim())) rec = t.trim(); });
  if (!rec) {
    return { status: "FAIL", record: null, findings: [
      { kind: "bad", text: "No DMARC record found at _dmarc. The domain has no published policy telling receivers how to handle SPF/DKIM failures." },
      { kind: "tip", text: "Start in monitor mode: v=DMARC1; p=none; rua=mailto:dmarc@example.com — then tighten to quarantine, then reject." }
    ] };
  }
  var tags = {};
  rec.split(";").forEach(function (pair) {
    var kv = pair.split("=");
    if (kv.length >= 2) {
      var k = kv[0].trim().toLowerCase();
      var v = kv.slice(1).join("=").trim();
      if (k) tags[k] = v;
    }
  });

  var findings = [];
  var nDmarc = (txts || []).filter(function (t) { return /^v=DMARC1\s*;?/i.test(String(t).trim()); }).length;
  var p = (tags.p || "").toLowerCase();
  var status;
  if (p === "reject") {
    status = "PASS";
    findings.push({ kind: "good", text: "Policy p=reject — strongest enforcement. Spoofed mail is rejected outright." });
  } else if (p === "quarantine") {
    status = "WARN";
    findings.push({ kind: "warn", text: "Policy p=quarantine — failing mail is sent to spam. Good, but p=reject is the end goal." });
  } else if (p === "none") {
    status = "WARN";
    findings.push({ kind: "warn", text: "Policy p=none — monitoring only. No spoofing protection is enforced; this is a reporting posture, not defence." });
  } else {
    status = "FAIL";
    findings.push({ kind: "bad", text: "DMARC record present but missing or invalid 'p=' tag. The policy is effectively undefined." });
  }

  if (tags.sp) findings.push({ kind: "info", text: "Subdomain policy sp=" + tags.sp });
  if (tags.pct && tags.pct !== "100") {
    findings.push({ kind: "warn", text: "pct=" + tags.pct + " — policy applies to only " + tags.pct + "% of mail. Full coverage needs pct=100." });
    if (status === "PASS") status = "WARN";
  }
  if (tags.rua) {
    findings.push({ kind: "good", text: "Aggregate reports (rua) sent to: " + tags.rua });
  } else {
    findings.push({ kind: "warn", text: "No rua= tag. Aggregate reports are off, so you are flying blind on auth results and sources." });
    if (status === "PASS") status = "WARN";
  }
  if (tags.ruf) findings.push({ kind: "info", text: "Forensic reports (ruf) to: " + tags.ruf });
  if (tags.adkim) findings.push({ kind: "info", text: "DKIM alignment adkim=" + tags.adkim + (tags.adkim.toLowerCase() === "s" ? " (strict)" : " (relaxed)") });
  if (tags.aspf) findings.push({ kind: "info", text: "SPF alignment aspf=" + tags.aspf + (tags.aspf.toLowerCase() === "s" ? " (strict)" : " (relaxed)") });
  if (tags.fo) findings.push({ kind: "info", text: "Failure reporting options fo=" + tags.fo });
  if (nDmarc > 1) {
    findings.unshift({ kind: "bad", text: nDmarc + " DMARC records are published at _dmarc. RFC 7489 6.6.3: receivers then apply no DMARC policy at all. Keep exactly one." });
    status = "FAIL";
  }

  return { status: status, record: rec, findings: findings };
}

// ── DKIM analysis across probed selectors ──
// results: [{ selector, found, record, error }]
function analyzeDKIM(results) {
  results = results || [];
  var hits = results.filter(function (r) { return r.found; });
  var findings = [];
  var status;
  if (!hits.length) {
    status = "NOT FOUND";
    findings.push({ kind: "warn", text: "No DKIM record found for the common selectors tried (" +
      results.map(function (r) { return r.selector; }).join(", ") + ")." });
    findings.push({ kind: "tip", text: "This does not mean DKIM is missing — many providers use a custom selector. Check a signed message's DKIM-Signature header for its s= value and enter it above." });
    return { status: status, records: [], findings: findings };
  }
  status = "PASS";
  hits.forEach(function (h) {
    var revoked = /p=\s*(;|$)/i.test(h.record);
    if (!revoked) findings.push({ kind: "good", text: "Selector '" + h.selector + "' publishes a DKIM key." });
    if (/t=y/i.test(h.record)) {
      findings.push({ kind: "warn", text: "Selector '" + h.selector + "' is in test mode (t=y); receivers may ignore failures." });
      if (status === "PASS") status = "WARN";
    }
    if (revoked) {
      findings.push({ kind: "warn", text: "Selector '" + h.selector + "' has an empty public key (p=) — the key is revoked/disabled." });
      if (status === "PASS") status = "WARN";
    }
  });
  var errored = results.filter(function (r) { return r.error; });
  if (errored.length) {
    findings.push({ kind: "info", text: errored.length + " selector lookup(s) failed to resolve and were skipped." });
  }
  return { status: status, records: hits, findings: findings };
}

// ── LOOKUP JOBS — glue transport to parsers; resolve { net, result } ──
// net=false means the lookup failed at the transport level (not cached, so a retry can succeed).
function spfJob(domain, signal) {
  return dohTXT(domain, signal).then(function (r) {
    return r.ok
      ? { net: true, result: analyzeSPF(r.txt) }
      : { net: false, result: { status: "FAIL", record: null, findings: [{ kind: "bad", text: "SPF lookup failed: " + r.error }] } };
  });
}
function dmarcJob(domain, signal) {
  return dohTXT("_dmarc." + domain, signal).then(function (r) {
    return r.ok
      ? { net: true, result: analyzeDMARC(r.txt) }
      : { net: false, result: { status: "FAIL", record: null, findings: [{ kind: "bad", text: "DMARC lookup failed: " + r.error }] } };
  });
}
function dkimJob(domain, selectors, signal) {
  // allSettled so one failed selector lookup never fails the others.
  return Promise.allSettled(selectors.map(function (sel) {
    return dohTXT(sel + "._domainkey." + domain, signal);
  })).then(function (settled) {
    var results = settled.map(function (s, i) {
      var sel = selectors[i];
      if (s.status === "fulfilled" && s.value && s.value.ok) {
        var dkim = null;
        (s.value.txt || []).forEach(function (t) {
          if (/(^|;)\s*(v=DKIM1|k=|p=)/i.test(t)) dkim = t.trim();
        });
        return { selector: sel, found: !!dkim, record: dkim, error: null };
      }
      var err = (s.status === "fulfilled" && s.value) ? s.value.error
        : (s.reason && s.reason.message) ? s.reason.message : "lookup failed";
      return { selector: sel, found: false, record: null, error: err };
    });
    var net = results.some(function (r) { return r.error === null; });
    return { net: net, result: analyzeDKIM(results) };
  });
}

// ── per-domain in-memory cache of finished analyses (keyed by domain + selectors) ──
var CACHE = new Map();
function cacheKey(domain, selectors) { return domain + "\u0000" + selectors.join(","); }

// ────────────────────────────────────────────────────────────────────────────
// PRESENTATION
// ────────────────────────────────────────────────────────────────────────────
var EA_CSS =
  '<style>' +
  '.ea-wrap{color:var(--txt)}' +
  '.ea-bar{display:flex;flex-wrap:wrap;gap:10px;align-items:flex-end}' +
  '.ea-bar .ea-field{flex:1 1 260px;min-width:0}' +
  '.ea-bar .ea-field.ea-narrow{flex:0 1 220px}' +
  '.ea-lbl{display:block;font-size:.74rem;color:var(--mut);margin-bottom:4px;text-transform:uppercase;letter-spacing:.04em}' +
  '.ea-in{width:100%;box-sizing:border-box;background:var(--card2);border:1px solid var(--line);color:var(--txt);border-radius:4px;padding:9px 11px;font-size:.9rem;font-family:inherit}' +
  '.ea-in:focus{outline:none;border-color:var(--acc);box-shadow:0 0 0 3px color-mix(in srgb,var(--acc) 15%,transparent)}' +
  '.ea-chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px}' +
  '.ea-chip{background:var(--card2);border:1px solid var(--line);color:var(--txt-2);border-radius:999px;padding:4px 11px;font-size:.78rem;cursor:pointer;font-family:var(--font-mono)}' +
  '.ea-chip:hover{border-color:var(--acc);color:var(--acc)}' +
  '.ea-hint{font-size:.74rem;color:var(--mut);margin-top:6px}' +
  '.ea-summary{margin:16px 0 4px;padding:12px 14px;border:1px solid var(--line);border-radius:6px;background:color-mix(in srgb,var(--card2) 50%,var(--card));display:flex;align-items:center;gap:14px;flex-wrap:wrap}' +
  '.ea-score{font-family:var(--font-mono);font-size:1.6rem;font-weight:700;line-height:1}' +
  '.ea-score small{display:block;font-size:.66rem;color:var(--mut);font-weight:400;letter-spacing:.05em;text-transform:uppercase;margin-top:3px}' +
  '.ea-summary-txt{color:var(--txt-2);font-size:.86rem;flex:1 1 240px;min-width:0}' +
  '.ea-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:14px;margin-top:14px;align-items:start}' +
  '.ea-card{border:1px solid var(--line);border-radius:8px;background:var(--card);overflow:hidden}' +
  '.ea-card-h{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:12px 14px;border-bottom:1px solid var(--line);background:var(--card2)}' +
  '.ea-card-h h3{margin:0;font-size:.95rem;color:var(--txt)}' +
  '.ea-card-h .ea-sub{font-size:.72rem;color:var(--mut);font-family:var(--font-mono);display:block;margin-top:2px}' +
  '.ea-pill{font-size:.68rem;font-weight:700;letter-spacing:.06em;padding:4px 9px;border-radius:999px;white-space:nowrap;border:1px solid;text-transform:uppercase}' +
  '.ea-body{padding:12px 14px}' +
  '.ea-rec{font-family:var(--font-mono);font-size:.76rem;line-height:1.5;white-space:pre-wrap;word-break:break-all;background:var(--card2);border:1px solid var(--line);border-radius:5px;padding:10px;color:var(--txt);max-height:210px;overflow:auto;margin-bottom:12px}' +
  '.ea-rec.ea-empty{color:var(--mut);font-style:italic;word-break:normal}' +
  '.ea-list{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:7px}' +
  '.ea-list li{display:flex;gap:8px;font-size:.8rem;line-height:1.45;color:var(--txt-2)}' +
  '.ea-dot{flex:0 0 auto;width:7px;height:7px;border-radius:50%;margin-top:6px}' +
  '.ea-loading{display:flex;align-items:center;gap:10px;color:var(--mut);font-size:.88rem}' +
  '.ea-body .ea-loading{margin:0}' +
  '.ea-spin{width:16px;height:16px;border:2px solid var(--line);border-top-color:var(--acc);border-radius:50%;animation:ea-rot .7s linear infinite}' +
  '@keyframes ea-rot{to{transform:rotate(360deg)}}' +
  '.ea-err{margin-top:16px;padding:10px 12px;border-radius:5px;border:1px solid color-mix(in srgb,var(--bad) 45%,var(--line));background:color-mix(in srgb,var(--bad) 10%,transparent);color:var(--txt);font-size:.85rem}' +
  '.ea-go{white-space:nowrap}' +
  '</style>';

// pill colour + status helpers
function pillCss(status) {
  var color = C_PASS;
  if (status === "WARN") color = C_WARN;
  else if (status === "FAIL") color = C_FAIL;
  else if (status === "NOT FOUND") color = "var(--mut)";
  return "color:" + color + ";border-color:" + color + ";background:color-mix(in srgb," + color + " 14%,transparent)";
}
function pillStyle(status) { return 'style="' + pillCss(status) + '"'; }
function dotColor(kind) {
  if (kind === "good") return C_PASS;
  if (kind === "warn") return C_WARN;
  if (kind === "bad") return C_FAIL;
  if (kind === "tip") return "var(--acc)";
  return "var(--mut)";
}
function renderFindings(findings) {
  return '<ul class="ea-list">' + (findings || []).map(function (f) {
    return '<li><span class="ea-dot" style="background:' + dotColor(f.kind) + '"></span><span>' + esc(f.text) + '</span></li>';
  }).join("") + '</ul>';
}
function recordBox(rec, emptyMsg) {
  if (rec) return '<div class="ea-rec">' + esc(rec) + '</div>';
  return '<div class="ea-rec ea-empty">' + esc(emptyMsg) + '</div>';
}
// truncate a long DKIM key for display, preserving tags
function truncRec(rec) {
  if (!rec) return rec;
  return rec.replace(/(p=)([A-Za-z0-9+/=]{40,})/g, function (_, pre, key) {
    return pre + key.slice(0, 32) + "… [" + key.length + " chars]";
  });
}
// record block for a given card (DKIM lists every resolved selector)
function recordHtml(key, analysis, emptyMsg) {
  if (key === "dkim") {
    if (analysis.records && analysis.records.length) {
      return analysis.records.map(function (h) {
        return '<div class="ea-rec"><span style="color:var(--acc)">' + esc(h.selector) + '._domainkey:</span>\n' + esc(truncRec(h.record)) + '</div>';
      }).join("");
    }
    return recordBox(null, emptyMsg);
  }
  return recordBox(analysis.record, emptyMsg);
}

function scoreFor(status) {
  if (status === "PASS") return 2;
  if (status === "WARN") return 1;
  return 0; // FAIL / NOT FOUND
}

// ── render ──
export { analyzeSPF, analyzeDMARC, analyzeDKIM };

export function renderEmailAuth(main) {
  main.innerHTML = EA_CSS +
    '<div class="ea-wrap">' +
    '<div class="pg-head"><div>' +
    '<h1 class="pg-h1">Email Authentication Analyzer</h1>' +
    '<p class="muted pg-sub">Audit a domain\'s SPF, DMARC and DKIM records live over DNS-over-HTTPS. All results are the real DNS answers, resolved in your browser.</p>' +
    '</div></div>' +

    '<div class="panel">' +
    '<div class="ea-bar">' +
    '<div class="ea-field"><label class="ea-lbl" for="ea-domain">Domain</label>' +
    '<input class="ea-in" id="ea-domain" placeholder="example.com" autocomplete="off" spellcheck="false"></div>' +
    '<div class="ea-field ea-narrow"><label class="ea-lbl" for="ea-selector">DKIM selector (optional)</label>' +
    '<input class="ea-in" id="ea-selector" placeholder="e.g. google, selector1" autocomplete="off" spellcheck="false"></div>' +
    '<div class="ea-field" style="flex:0 0 auto"><button class="btn primary ea-go" id="ea-run" type="button">Analyze</button></div>' +
    '</div>' +
    '<div class="ea-chips" id="ea-chips">' +
    EXAMPLE_DOMAINS.map(function (d) { return '<button class="ea-chip" type="button" data-d="' + esc(d) + '">' + esc(d) + '</button>'; }).join("") +
    '</div>' +
    '<p class="ea-hint">Leave the selector blank to probe common ones: ' + DEFAULT_SELECTORS.join(", ") + '. SPF and DMARC are always checked at the root and _dmarc.</p>' +
    '</div>' +

    '<div id="ea-out"></div>' +
    '</div>';

  var $ = function (id) { return main.querySelector("#" + id); };
  var domainIn = $("ea-domain");
  var selIn = $("ea-selector");
  var out = $("ea-out");
  var runBtn = $("ea-run");
  var busy = false;

  // ── lifecycle: abort outstanding requests on new analysis or teardown ──
  var curCtrl = null;   // AbortController for the in-flight analysis
  var runSeq = 0;       // bumped per run; stale handlers bail
  var torn = false;

  function abortCurrent() {
    if (curCtrl) { try { curCtrl.abort(); } catch (e) {} curCtrl = null; }
  }

  // This tool has no auth.js cleanup hook, so detect teardown ourselves: when auth.js
  // replaces main's children for the next tool, abort outstanding DNS requests.
  var wrapRoot = main.querySelector(".ea-wrap");
  var observer = null;
  if (typeof MutationObserver !== "undefined") {
    observer = new MutationObserver(function () {
      if (torn) return;
      if (!wrapRoot || !main.contains(wrapRoot)) {
        torn = true;
        abortCurrent();
        if (observer) { observer.disconnect(); observer = null; }
      }
    });
    try { observer.observe(main, { childList: true }); } catch (e) {}
  }

  $("ea-chips").addEventListener("click", function (e) {
    var b = e.target.closest(".ea-chip");
    if (!b) return;
    domainIn.value = b.dataset.d;
    run();
  });

  runBtn.onclick = run;
  domainIn.addEventListener("keydown", function (e) { if (e.key === "Enter") run(); });
  selIn.addEventListener("keydown", function (e) { if (e.key === "Enter") run(); });

  // card titles/subs; sub is refined for DKIM once results land
  function cardsMeta(domain) {
    return {
      spf: { title: "SPF", sub: domain + " (TXT)", empty: "No v=spf1 record found." },
      dmarc: { title: "DMARC", sub: "_dmarc." + domain, empty: "No v=DMARC1 record found." },
      dkim: { title: "DKIM", sub: "common selectors", empty: "No DKIM record for the selectors tried." }
    };
  }

  function cardShell(key, meta, analysis) {
    var body = analysis
      ? (recordHtml(key, analysis, meta.empty) + renderFindings(analysis.findings))
      : '<div class="ea-loading"><span class="ea-spin"></span><span>Resolving…</span></div>';
    var pill = analysis
      ? '<span class="ea-pill" ' + pillStyle(analysis.status) + '>' + esc(analysis.status) + '</span>'
      : '<span class="ea-pill" style="color:var(--mut);border-color:var(--line)">…</span>';
    return '<div class="ea-card" id="ea-c-' + key + '">' +
      '<div class="ea-card-h"><div><h3>' + esc(meta.title) + '</h3><span class="ea-sub">' + esc(meta.sub) + '</span></div>' +
      pill + '</div>' +
      '<div class="ea-body">' + body + '</div>' +
      '</div>';
  }

  // fill one card in place as its lookup resolves (progressive rendering)
  function fillCard(key, meta, analysis) {
    var card = out.querySelector("#ea-c-" + key);
    if (!card) return;
    if (key === "dkim") {
      var sub = card.querySelector(".ea-sub");
      if (sub) sub.textContent = analysis.records && analysis.records.length
        ? analysis.records.length + " selector(s)" : "common selectors";
    }
    var pill = card.querySelector(".ea-pill");
    if (pill) { pill.textContent = analysis.status; pill.setAttribute("style", pillCss(analysis.status)); }
    var body = card.querySelector(".ea-body");
    if (body) body.innerHTML = recordHtml(key, analysis, meta.empty) + renderFindings(analysis.findings);
  }

  function renderSummary(domain, spf, dmarc, dkim) {
    var el = out.querySelector("#ea-summary");
    if (!el) return;
    var total = scoreFor(spf.status) + scoreFor(dmarc.status) + scoreFor(dkim.status);
    var pct = Math.round((total / 6) * 100);
    var grade, gColor, line;
    if (pct >= 85) { grade = "A"; gColor = C_PASS; line = "Strong email-authentication posture."; }
    else if (pct >= 60) { grade = "B"; gColor = C_PASS; line = "Good, with room to tighten enforcement."; }
    else if (pct >= 35) { grade = "C"; gColor = C_WARN; line = "Partial protection — gaps leave the domain spoofable."; }
    else { grade = "D"; gColor = C_FAIL; line = "Weak or missing authentication — high spoofing risk."; }

    el.innerHTML =
      '<div class="ea-score" style="color:' + gColor + '">' + grade + '<small>' + pct + ' / 100</small></div>' +
      '<div class="ea-summary-txt"><strong>' + esc(domain) + '</strong> — ' + esc(line) +
      ' SPF ' + esc(spf.status) + ' · DMARC ' + esc(dmarc.status) + ' · DKIM ' + esc(dkim.status) + '.</div>';
  }

  function run() {
    if (busy) return;
    var domain = cleanDomain(domainIn.value);
    if (!domain) { toast("Enter a domain to analyze"); domainIn.focus(); return; }
    if (!validDomain(domain)) {
      out.innerHTML = '<div class="ea-err">\"' + esc(domain) + '\" does not look like a valid domain. Use a bare domain such as example.com.</div>';
      return;
    }
    domainIn.value = domain;

    // abort any outstanding analysis before starting a new one
    abortCurrent();
    curCtrl = typeof AbortController !== "undefined" ? new AbortController() : null;
    var signal = curCtrl ? curCtrl.signal : undefined;
    var myRun = ++runSeq;
    var stale = function () { return torn || myRun !== runSeq; };

    var selectorRaw = (selIn.value || "").trim().toLowerCase().replace(/[^a-z0-9._-]/g, "");
    var selectors = selectorRaw ? [selectorRaw] : DEFAULT_SELECTORS.slice();
    var meta = cardsMeta(domain);
    var key = cacheKey(domain, selectors);

    // cache hit → render everything instantly, no network
    var cached = CACHE.get(key);
    if (cached) {
      out.innerHTML =
        '<div class="ea-summary" id="ea-summary"></div>' +
        '<div class="ea-cards">' +
        cardShell("spf", meta, cached.spf) +
        cardShell("dmarc", meta, cached.dmarc) +
        cardShell("dkim", meta, cached.dkim) +
        '</div>';
      renderSummary(domain, cached.spf, cached.dmarc, cached.dkim);
      toast("Analyzed " + domain + " (cached)");
      return;
    }

    busy = true;
    runBtn.disabled = true;

    // progressive shell — three card skeletons + summary placeholder, rendered immediately
    out.innerHTML =
      '<div class="ea-summary" id="ea-summary"><div class="ea-loading"><span class="ea-spin"></span><span>Querying DNS for ' + esc(domain) + ' …</span></div></div>' +
      '<div class="ea-cards">' +
      cardShell("spf", meta, null) +
      cardShell("dmarc", meta, null) +
      cardShell("dkim", meta, null) +
      '</div>';

    // fire all three concurrently; fill each card as soon as it resolves
    var spfP = spfJob(domain, signal).then(function (o) { if (!stale()) fillCard("spf", meta, o.result); return o; });
    var dmarcP = dmarcJob(domain, signal).then(function (o) { if (!stale()) fillCard("dmarc", meta, o.result); return o; });
    var dkimP = dkimJob(domain, selectors, signal).then(function (o) { if (!stale()) fillCard("dkim", meta, o.result); return o; });

    Promise.allSettled([spfP, dmarcP, dkimP]).then(function (settled) {
      // a newer run (or teardown) owns the UI now — leave busy/button to it
      if (stale()) return;
      busy = false;
      if (!torn) runBtn.disabled = false;

      var spf = settled[0].status === "fulfilled" ? settled[0].value
        : { net: false, result: { status: "FAIL", record: null, findings: [{ kind: "bad", text: "SPF lookup error." }] } };
      var dmarc = settled[1].status === "fulfilled" ? settled[1].value
        : { net: false, result: { status: "FAIL", record: null, findings: [{ kind: "bad", text: "DMARC lookup error." }] } };
      var dkim = settled[2].status === "fulfilled" ? settled[2].value
        : { net: false, result: { status: "NOT FOUND", records: [], findings: [{ kind: "warn", text: "DKIM lookup error." }] } };

      renderSummary(domain, spf.result, dmarc.result, dkim.result);

      // only cache a clean run (no transport failures) so a retry can still succeed
      if (spf.net && dmarc.net && dkim.net) {
        CACHE.set(key, { spf: spf.result, dmarc: dmarc.result, dkim: dkim.result });
      }
      toast("Analyzed " + domain);
    });
  }
}
