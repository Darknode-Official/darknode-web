// security.txt Studio — generate and validate an RFC 9116 security.txt file.
// Author, preview, download and audit the standardized vulnerability-disclosure
// contact file that belongs at /.well-known/security.txt on a web host.
// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Generation and validation are client-side. Fetch uses the Darknode proxy when configured, else a direct (CORS-limited) request.
//
// Architecture: the RFC 9116 field set is expressed once as a declarative table
// (FIELD_SPECS). That single table drives both generation (field order + emission)
// and validation (which fields are known, required, single-valued, and how their
// values are checked). Two pure, DOM-free functions sit at the core —
// generateSecurityTxt(model) and validateSecurityTxt(text) — and the two render
// modes are thin layers that feed/consume them. __selftest() exercises the pair.

const esc = (s) => String(s != null ? s : "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// ── RFC 9116 declarative field table ──
// One row per field. This is the single source of truth for field ORDER (generation),
// which names are KNOWN, which are REQUIRED, which may appear MULTIPLE times, the
// value KIND (how to validate it), and whether mailto:/tel: are acceptable.
//   kind: 'uri'       → must be an absolute URI; https preferred, http warns
//         'timestamp' → ISO 8601; past = fail, >1yr = warn
//         'langs'     → comma-separated BCP 47 tags
var FIELD_SPECS = [
  { name: "Contact", required: true, multiple: true, kind: "uri", allowMailtoTel: true },
  { name: "Expires", required: true, multiple: false, kind: "timestamp" },
  { name: "Encryption", required: false, multiple: true, kind: "uri" },
  { name: "Acknowledgments", required: false, multiple: true, kind: "uri" },
  { name: "Preferred-Languages", required: false, multiple: false, kind: "langs" },
  { name: "Canonical", required: false, multiple: true, kind: "uri" },
  { name: "Policy", required: false, multiple: true, kind: "uri" },
  { name: "Hiring", required: false, multiple: true, kind: "uri" }
];
// lower-case field name → spec, for O(1) validator lookups.
var SPEC_BY_NAME = Object.create(null);
FIELD_SPECS.forEach(function (s) { SPEC_BY_NAME[s.name.toLowerCase()] = s; });

function toast(msg) {
  if (typeof window !== "undefined" && typeof window.showToast === "function") {
    try { window.showToast(msg); } catch (e) { /* ignore */ }
  }
}

// ── helpers ──
function oneYearOut() {
  var d = new Date();
  d.setUTCFullYear(d.getUTCFullYear() + 1);
  return d;
}
// value for <input type="datetime-local"> in local time, minute precision
function toLocalInputValue(d) {
  var p = function (n) { return (n < 10 ? "0" : "") + n; };
  return d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate()) +
    "T" + p(d.getHours()) + ":" + p(d.getMinutes());
}
function msPerYear() { return 365 * 24 * 3600 * 1000; }

// Coerce a Date or any parseable string to an ISO 8601 UTC string, or "" if blank/invalid.
function toIsoUtc(v) {
  if (v == null || v === "") return "";
  var d = (v instanceof Date) ? v : new Date(v);
  if (isNaN(d.getTime())) return "";
  return d.toISOString();
}

function isHttpsLike(v) { return /^https:\/\//i.test(v); }
function isHttpInsecure(v) { return /^http:\/\//i.test(v); }
function isMailtoOrTel(v) { return /^(mailto:|tel:)/i.test(v); }
function looksLikeUri(v) { return /^[a-z][a-z0-9+.-]*:/i.test(String(v || "").trim()); }
function endsWithWellKnown(v) {
  return /\/\.well-known\/security\.txt\/?$/i.test(String(v || "").trim());
}

// ── pure generator ──
// generateSecurityTxt(model) -> string
// model is keyed by lower-case field name (e.g. { contact:[...], expires:Date|iso,
// "preferred-languages":"en, fr", ... }). Deterministic field order from FIELD_SPECS,
// leading "# security.txt — RFC 9116" comment block, Expires emitted as ISO 8601 UTC.
function generateSecurityTxt(model) {
  model = model || {};
  var L = [];
  L.push("# security.txt — RFC 9116");
  L.push("# Place this file at https://<your-domain>/.well-known/security.txt");
  L.push("# Recommended: PGP-sign this document (clear-signed) so visitors can verify its authenticity.");
  L.push("");

  FIELD_SPECS.forEach(function (spec) {
    var raw = model[spec.name.toLowerCase()];
    var values;
    if (spec.multiple) {
      values = Array.isArray(raw) ? raw : (raw != null ? [raw] : []);
    } else {
      values = (raw != null && raw !== "") ? [raw] : [];
    }
    values.forEach(function (v) {
      if (spec.kind === "timestamp") {
        var iso = toIsoUtc(v);
        if (iso) L.push(spec.name + ": " + iso);
      } else {
        var s = String(v == null ? "" : v).trim();
        if (s) L.push(spec.name + ": " + s);
      }
    });
  });

  return L.join("\n") + "\n";
}

// Per-field value validation, driven by the spec. Pushes findings for one line.
function checkFieldValue(findings, spec, name, value, lineNo) {
  var lower = spec.name.toLowerCase();
  if (value === "") return; // empty-value already reported by the caller

  if (spec.kind === "timestamp") {
    // RFC 9116 §2.5.5: the value MUST be an RFC 3339 date-time (Date() alone also
    // accepts RFC 2822 / US-style / date-only strings, which are not compliant).
    var rfc3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/i.test(value);
    var d = rfc3339 ? new Date(value.toUpperCase()) : new Date(NaN);
    if (isNaN(d.getTime())) {
      findings.push({ level: "error", msg: spec.name + " value '" + value + "' is not an RFC 3339 date-time (e.g. 2027-01-01T00:00:00Z).", line: lineNo });
      return;
    }
    var now = Date.now();
    if (d.getTime() < now) {
      findings.push({ level: "error", msg: spec.name + " is in the past (" + value + ") — this file is EXPIRED and should be refreshed.", line: lineNo });
    } else if (d.getTime() - now > msPerYear()) {
      findings.push({ level: "warn", msg: spec.name + " is more than a year away. RFC 9116 recommends a value less than a year in the future.", line: lineNo });
    }
    return;
  }

  if (spec.kind === "langs") {
    var tags = value.split(",").map(function (x) { return x.trim(); }).filter(Boolean);
    if (!tags.length) {
      findings.push({ level: "error", msg: spec.name + " has no language tags.", line: lineNo });
    }
    tags.forEach(function (t) {
      if (!/^[a-zA-Z]{1,8}(-[a-zA-Z0-9]{1,8})*$/.test(t)) {
        findings.push({ level: "warn", msg: "Language tag '" + t + "' does not look like a valid BCP 47 tag (e.g. en, en-US, fr).", line: lineNo });
      }
    });
    return;
  }

  // kind === 'uri'
  if (spec.allowMailtoTel && isMailtoOrTel(value)) return; // mailto:/tel: are fine for these
  if (looksLikeUri(value)) {
    if (isHttpInsecure(value)) {
      findings.push({ level: "warn", msg: "'" + name + "' uses http:// — RFC 9116 requires https for web URIs.", line: lineNo });
    } else if (!isHttpsLike(value)) {
      findings.push({ level: "info", msg: "'" + name + "' uses a non-https scheme. Web resources should use https.", line: lineNo });
    }
    if (lower === "canonical" && !endsWithWellKnown(value)) {
      findings.push({ level: "warn", msg: "Canonical should point to the file's own location, ending in /.well-known/security.txt.", line: lineNo });
    }
  } else {
    var extra = spec.allowMailtoTel ? " (use a URI such as https://, mailto:, or tel:)" : " (use an absolute URI, e.g. https://…)";
    findings.push({ level: "error", msg: "'" + name + "' value is not a URI" + extra + ".", line: lineNo });
  }
}

// ── pure validator ──
// validateSecurityTxt(text) -> { ok, fields:[{name,value,line}], findings:[{level,msg,line}], signed }
// Full RFC 9116 parse: ignores blank lines and '#' comments, field names are
// case-insensitive, handles CRLF and trailing whitespace, understands a PGP
// clear-signed document (notes it is signed but not cryptographically verified,
// skips the Hash: armor header, undoes '- ' dash-escaping, parses only the signed body).
export function validateSecurityTxt(text) {
  var findings = [];
  var fields = [];
  var signed = false;

  var raw = String(text == null ? "" : text);
  if (!raw.trim()) {
    findings.push({ level: "error", msg: "The document is empty. Paste a security.txt or load the example.", line: 0 });
    return { ok: false, fields: fields, findings: findings, signed: false };
  }

  var lines = raw.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");

  // Detect a PGP clear-signed document and restrict parsing to the signed body.
  var startIdx = 0, endIdx = lines.length;
  if (raw.indexOf("-----BEGIN PGP SIGNED MESSAGE-----") >= 0) {
    signed = true;
    for (var a = 0; a < lines.length; a++) {
      if (lines[a].indexOf("-----BEGIN PGP SIGNED MESSAGE-----") >= 0) { startIdx = a + 1; break; }
    }
    // skip any Hash: armor header(s) that follow the marker
    while (startIdx < lines.length && lines[startIdx].trim() !== "" &&
      /^hash\s*:/i.test(lines[startIdx])) startIdx++;
    // skip the blank line separating armor headers from the signed body
    if (startIdx < lines.length && lines[startIdx].trim() === "") startIdx++;
    for (var b = startIdx; b < lines.length; b++) {
      if (lines[b].indexOf("-----BEGIN PGP SIGNATURE-----") >= 0) { endIdx = b; break; }
    }
    findings.push({ level: "info", msg: "Document is PGP clear-signed. The signature is not verified here, but RFC 9116 recommends signing — good.", line: 0 });
  }

  var counts = Object.create(null);
  for (var i = startIdx; i < endIdx; i++) {
    var lineNo = i + 1;
    var trimmed = lines[i].trimEnd().replace(/^\s+/, "");
    // In a clear-signed body, '- ' is dash-escaping; undo it before any other check.
    if (signed && trimmed.indexOf("- ") === 0) trimmed = trimmed.slice(2);
    if (trimmed === "") continue;
    if (trimmed.charAt(0) === "#") continue;

    var ci = trimmed.indexOf(":");
    if (ci < 0) {
      findings.push({ level: "error", msg: "Line is not a comment and has no 'Name: value' field.", line: lineNo });
      continue;
    }
    var name = trimmed.slice(0, ci).trim();
    var value = trimmed.slice(ci + 1).trim();
    var lower = name.toLowerCase();

    if (!/^[a-zA-Z][a-zA-Z0-9-]*$/.test(name)) {
      findings.push({ level: "error", msg: "Field name '" + name + "' is not a valid token.", line: lineNo });
      continue;
    }
    if (value === "") {
      findings.push({ level: "error", msg: "Field '" + name + "' has an empty value.", line: lineNo });
    }

    counts[lower] = (counts[lower] || 0) + 1;
    fields.push({ name: name, value: value, line: lineNo });

    var spec = SPEC_BY_NAME[lower];
    if (!spec) {
      findings.push({ level: "info", msg: "Unknown field '" + name + "' — not defined by RFC 9116 (allowed as an extension, but double-check the spelling).", line: lineNo });
      continue;
    }
    checkFieldValue(findings, spec, name, value, lineNo);
  }

  // Required-presence and single-value checks — both driven by the table.
  FIELD_SPECS.forEach(function (spec) {
    var lower = spec.name.toLowerCase();
    var c = counts[lower] || 0;
    if (spec.required && c === 0) {
      findings.push({ level: "error", msg: spec.name === "Contact"
        ? "Missing required field: at least one Contact is mandatory."
        : "Missing required field: " + spec.name + " is mandatory.", line: 0 });
    }
    if (!spec.multiple && c > 1) {
      findings.push({ level: "error", msg: "Multiple " + spec.name + " fields found — only one is allowed.", line: 0 });
    }
  });

  var hasError = findings.some(function (x) { return x.level === "error"; });
  return { ok: !hasError, fields: fields, findings: findings, signed: signed };
}

// ── self-check ──
// Lightweight assertions over the pure pair. Returns [{name,pass}]; also console.asserts.
export function __selftest() {
  var results = [];
  function assert(name, cond) {
    results.push({ name: name, pass: !!cond });
    if (typeof console !== "undefined" && console.assert) console.assert(!!cond, "security-txt selftest failed: " + name);
  }
  var future = new Date(Date.now() + 200 * 24 * 3600 * 1000).toISOString();
  var validSample = { contact: ["mailto:security@example.com"], expires: future };

  assert("valid sample validates ok",
    validateSecurityTxt("Contact: mailto:a@b.com\nExpires: " + future + "\n").ok === true);
  assert("past Expires FAILs",
    validateSecurityTxt("Contact: mailto:a@b.com\nExpires: 2000-01-01T00:00:00.000Z\n").ok === false);
  assert("missing Contact FAILs",
    validateSecurityTxt("Expires: " + future + "\n").ok === false);
  assert("round-trip generate→validate ok",
    validateSecurityTxt(generateSecurityTxt(validSample)).ok === true);

  return results;
}
// Run the self-check once at module load (dev signal only; never throws into the UI).
try { __selftest(); } catch (e) { /* ignore */ }

function exampleText() {
  return generateSecurityTxt({
    contact: [
      "mailto:security@example.com",
      "https://example.com/security-report",
      "tel:+1-201-555-0123"
    ],
    expires: oneYearOut(),
    encryption: ["https://example.com/pgp-key.txt"],
    acknowledgments: ["https://example.com/hall-of-fame"],
    "preferred-languages": "en, fr",
    canonical: ["https://example.com/.well-known/security.txt"],
    policy: ["https://example.com/security-policy"],
    hiring: ["https://example.com/jobs"]
  });
}

// ── CSS ──
var ST_CSS =
  '<style>' +
  '.st-wrap{color:var(--txt)}' +
  '.st-grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:16px;align-items:start}' +
  '@media(max-width:860px){.st-grid{grid-template-columns:minmax(0,1fr)}}' +
  '.st-col{display:flex;flex-direction:column;gap:14px;min-width:0}' +
  '.st-field{margin-bottom:12px}' +
  '.st-field:last-child{margin-bottom:0}' +
  '.st-lbl{display:block;font-size:.8rem;color:var(--mut);margin-bottom:4px}' +
  '.st-req{color:var(--bad);font-weight:600}' +
  '.st-in,.st-ta{width:100%;box-sizing:border-box;background:var(--card2);border:1px solid var(--line);color:var(--txt);border-radius:4px;padding:8px 10px;font-size:.85rem;font-family:inherit}' +
  '.st-in[type=datetime-local]{width:auto;min-width:min(100%,240px)}' +
  '.st-in:focus,.st-ta:focus{outline:none;border-color:var(--acc);box-shadow:0 0 0 3px color-mix(in srgb,var(--acc) 15%,transparent)}' +
  '.st-ta{resize:vertical;min-height:120px;line-height:1.5;font-family:var(--font-mono);font-size:.8rem}' +
  '.st-multi-row{display:grid;grid-template-columns:1fr auto;gap:8px;margin-bottom:6px}' +
  '.st-iconbtn{background:var(--card2);border:1px solid var(--line);color:var(--mut);border-radius:4px;padding:6px 10px;cursor:pointer;font-size:.8rem;line-height:1;white-space:nowrap}' +
  '.st-iconbtn:hover{border-color:var(--bad);color:var(--bad)}' +
  '.st-mini{font-size:.8rem;padding:5px 11px}' +
  '.st-hint{font-size:.75rem;color:var(--mut);margin-top:5px}' +
  '.st-warnrow{font-size:.75rem;color:var(--bad);margin-top:5px;display:none}' +
  '.st-warnrow.show{display:block}' +
  '.st-pre{font-family:var(--font-mono);font-size:.8rem;line-height:1.6;white-space:pre;overflow:auto;background:var(--card2);border:1px solid var(--line);border-radius:6px;padding:14px;max-height:560px;color:var(--txt);tab-size:4}' +
  '.st-actions{display:flex;flex-wrap:wrap;gap:8px}' +
  '.st-sticky{position:sticky;top:12px}' +
  '.st-verdict{padding:12px 14px;border-radius:6px;margin-bottom:12px;font-size:.92rem;font-weight:600}' +
  '.st-verdict.pass{border:1px solid color-mix(in srgb,var(--acc) 50%,var(--line));background:color-mix(in srgb,var(--acc) 12%,transparent);color:var(--txt)}' +
  '.st-verdict.fail{border:1px solid color-mix(in srgb,var(--bad) 55%,var(--line));background:color-mix(in srgb,var(--bad) 12%,transparent);color:var(--txt)}' +
  '.st-issue{padding:7px 11px;border-radius:4px;margin-bottom:6px;font-size:.82rem;border:1px solid var(--line);background:var(--card2);display:flex;gap:9px;align-items:baseline}' +
  '.st-issue .st-badge{flex:0 0 auto;font-size:.75rem;font-weight:600;padding:2px 7px;border-radius:3px}' +
  '.st-issue.error{border-color:color-mix(in srgb,var(--bad) 50%,var(--line))}' +
  '.st-issue.error .st-badge{background:color-mix(in srgb,var(--bad) 20%,transparent);color:var(--bad)}' +
  '.st-issue.warn .st-badge{background:color-mix(in srgb,var(--acc) 18%,transparent);color:var(--acc)}' +
  '.st-issue.info .st-badge{background:color-mix(in srgb,var(--mut) 22%,transparent);color:var(--txt-2)}' +
  '.st-issue .st-ln{color:var(--mut);font-family:var(--font-mono);font-size:.75rem;flex:0 0 auto}' +
  '.st-tbl{width:100%;border-collapse:collapse;font-size:.8rem;margin-top:8px}' +
  '.st-tbl th,.st-tbl td{text-align:left;padding:6px 9px;border-bottom:1px solid var(--line);vertical-align:top}' +
  '.st-tbl th{color:var(--mut);font-size:.75rem}' +
  '.st-tbl td.k{font-family:var(--font-mono);color:var(--acc);white-space:nowrap}' +
  '.st-tbl td.v{font-family:var(--font-mono);color:var(--txt-2);word-break:break-all}' +
  '.st-fetchrow{display:grid;grid-template-columns:1fr auto;gap:8px;margin-bottom:10px}' +
  '@media(max-width:520px){.st-fetchrow{grid-template-columns:1fr}}' +
  '.st-note{font-size:.78rem;color:var(--txt-2);background:color-mix(in srgb,var(--card2) 60%,var(--card));border:1px solid var(--line);border-radius:6px;padding:10px 12px;line-height:1.5}' +
  '</style>';

// ── render ──
export function renderSecurityTxt(main) {
  var state = {
    mode: "generate",
    contact: [],
    expires: toIsoUtc(toLocalInputValue(oneYearOut())),
    encryption: [],
    acknowledgments: [],
    languages: "",
    canonical: [],
    policy: [],
    hiring: []
  };

  // Map the UI state onto the canonical model keys that generateSecurityTxt expects.
  function modelFromState(st) {
    return {
      contact: st.contact,
      expires: st.expires,
      encryption: st.encryption,
      acknowledgments: st.acknowledgments,
      "preferred-languages": st.languages,
      canonical: st.canonical,
      policy: st.policy,
      hiring: st.hiring
    };
  }

  main.innerHTML = ST_CSS +
    '<div class="st-wrap">' +
    '<div class="pg-head"><div>' +
    '<h1 class="pg-h1">security.txt Studio</h1>' +
    '<p class="muted pg-sub">Generate and validate an RFC 9116 <code>security.txt</code> — the standardized file that tells researchers how to report vulnerabilities. Generation and validation run in your browser.</p>' +
    '</div></div>' +
    '<div class="seg" id="st-tabs" style="margin-bottom:16px">' +
    '<button class="st-tab on" data-mode="generate" type="button">Generate</button>' +
    '<button class="st-tab" data-mode="validate" type="button">Validate</button>' +
    '</div>' +
    '<div id="st-body"></div>' +
    '</div>';

  var body = main.querySelector("#st-body");

  // ───────────────────────── GENERATE ─────────────────────────
  function multiFieldHtml(key, label, placeholder, hint) {
    return '<div class="st-field" data-multi="' + key + '">' +
      '<label class="st-lbl">' + esc(label) + '</label>' +
      '<div class="st-multi-list"></div>' +
      '<button class="btn ghost st-mini st-add" type="button" data-key="' + key + '">Add</button>' +
      (hint ? '<p class="st-hint">' + esc(hint) + '</p>' : '') +
      '</div>';
  }

  function renderGenerate() {
    body.innerHTML =
      '<div class="st-grid">' +
      '<div class="st-col">' +

      '<div class="panel">' +
      '<div class="panel-h"><h2 class="pg-h2">Required</h2></div>' +
      multiFieldHtml("contact", "Contact (one or more)", "mailto:security@example.com",
        "A URL the way to reach you: mailto:, https:// or tel:. At least one is required.") +
      '<div class="st-field">' +
      '<label class="st-lbl" for="st-expires">Expires <span class="st-req">*</span></label>' +
      '<input class="st-in" id="st-expires" type="datetime-local">' +
      '<p class="st-hint">Output as ISO 8601 UTC. After this date the file is considered stale. Keep it under a year out.</p>' +
      '<p class="st-warnrow" id="st-expires-warn">This is more than a year away — RFC 9116 recommends less than a year.</p>' +
      '</div>' +
      '</div>' +

      '<div class="panel">' +
      '<div class="panel-h"><h2 class="pg-h2">Optional</h2></div>' +
      multiFieldHtml("encryption", "Encryption (key URLs)", "https://example.com/pgp-key.txt",
        "URL to a PGP key researchers can use to encrypt their report.") +
      multiFieldHtml("acknowledgments", "Acknowledgments", "https://example.com/hall-of-fame",
        "URL to a page thanking researchers who reported issues.") +
      '<div class="st-field">' +
      '<label class="st-lbl" for="st-languages">Preferred-Languages</label>' +
      '<input class="st-in" id="st-languages" placeholder="en, fr, de">' +
      '<p class="st-hint">Comma-separated BCP 47 language tags, in order of preference.</p>' +
      '</div>' +
      multiFieldHtml("canonical", "Canonical", "https://example.com/.well-known/security.txt",
        "The https URL(s) where this very file lives, ending in /.well-known/security.txt.") +
      multiFieldHtml("policy", "Policy", "https://example.com/security-policy",
        "URL to your vulnerability-disclosure policy.") +
      multiFieldHtml("hiring", "Hiring", "https://example.com/jobs",
        "URL to security-related job openings.") +
      '</div>' +

      '</div>' +

      '<div class="st-col">' +
      '<div class="panel st-sticky">' +
      '<div class="panel-h"><h2 class="pg-h2">security.txt preview</h2>' +
      '<div class="st-actions">' +
      '<button class="btn ghost st-mini" id="st-copy" type="button">Copy</button>' +
      '<button class="btn primary st-mini" id="st-download" type="button">Download security.txt</button>' +
      '</div></div>' +
      '<pre class="st-pre" id="st-preview"></pre>' +
      '<p class="st-note" style="margin-top:12px">Host this file at <code>https://&lt;your-domain&gt;/.well-known/security.txt</code> (served as <code>text/plain</code> over https). For authenticity, PGP clear-sign it and publish your key via the <code>Encryption</code> field.</p>' +
      '</div>' +
      '</div>' +
      '</div>';

    var preview = body.querySelector("#st-preview");
    function refresh() { preview.textContent = generateSecurityTxt(modelFromState(state)); }

    // multi-value lists
    var MULTI = ["contact", "encryption", "acknowledgments", "canonical", "policy", "hiring"];
    MULTI.forEach(function (key) {
      var block = body.querySelector('[data-multi="' + key + '"]');
      var list = block.querySelector(".st-multi-list");
      var ph = ({
        contact: "mailto:security@example.com", encryption: "https://example.com/pgp-key.txt",
        acknowledgments: "https://example.com/hall-of-fame", canonical: "Canonical URL",
        policy: "Policy URL", hiring: "https://example.com/jobs"
      })[key];

      function renderList() {
        if (!state[key].length) state[key] = [""];
        list.innerHTML = state[key].map(function (val, i) {
          return '<div class="st-multi-row" data-i="' + i + '">' +
            '<input class="st-in st-mval" value="' + esc(val) + '" placeholder="' + esc(ph) + '">' +
            '<button class="st-iconbtn st-mdel" type="button" title="Remove">Remove</button>' +
            '</div>';
        }).join("");
        list.querySelectorAll(".st-multi-row").forEach(function (row) {
          var i = +row.dataset.i;
          row.querySelector(".st-mval").oninput = function (e) { state[key][i] = e.target.value; refresh(); };
          row.querySelector(".st-mdel").onclick = function () {
            state[key].splice(i, 1);
            if (!state[key].length) state[key] = [""];
            renderList(); refresh();
          };
        });
      }
      block.querySelector(".st-add").onclick = function () { state[key].push(""); renderList(); refresh(); };
      renderList();
    });

    // expires
    var expEl = body.querySelector("#st-expires");
    var expWarn = body.querySelector("#st-expires-warn");
    // seed the picker from the stored ISO value (shown in local time)
    if (state.expires) {
      var seed = new Date(state.expires);
      if (!isNaN(seed.getTime())) expEl.value = toLocalInputValue(seed);
    }
    function syncExpires() {
      state.expires = toIsoUtc(expEl.value);
      var d = state.expires ? new Date(state.expires) : null;
      var far = d && !isNaN(d.getTime()) && (d.getTime() - Date.now() > msPerYear());
      expWarn.classList.toggle("show", !!far);
      refresh();
    }
    expEl.oninput = syncExpires;
    expEl.onchange = syncExpires;

    // languages
    var langEl = body.querySelector("#st-languages");
    langEl.value = state.languages;
    langEl.oninput = function () { state.languages = langEl.value; refresh(); };

    // actions
    body.querySelector("#st-copy").onclick = function () {
      var text = generateSecurityTxt(modelFromState(state));
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(
          function () { toast("security.txt copied to clipboard"); },
          function () { toast("Copy failed — select the text manually"); });
      } else { toast("Clipboard unavailable — select the text manually"); }
    };
    body.querySelector("#st-download").onclick = function () {
      var text = generateSecurityTxt(modelFromState(state));
      var blob = new Blob([text], { type: "text/plain" });
      var url = URL.createObjectURL(blob);
      var a = document.createElement("a");
      a.href = url; a.download = "security.txt";
      document.body.appendChild(a); a.click();
      document.body.removeChild(a);
      setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
      toast("Downloaded security.txt");
    };

    // initial warn state + paint
    syncExpires();
  }

  // ───────────────────────── VALIDATE ─────────────────────────
  function renderValidate() {
    body.innerHTML =
      '<div class="st-grid">' +
      '<div class="st-col">' +
      '<div class="panel">' +
      '<div class="panel-h"><h2 class="pg-h2">Input</h2>' +
      '<div class="st-actions">' +
      '<button class="btn ghost st-mini" id="st-example" type="button">Load example</button>' +
      '<button class="btn primary st-mini" id="st-check" type="button">Validate</button>' +
      '</div></div>' +
      '<p class="st-note" style="margin-bottom:10px">Fetch requests https://&lt;domain&gt;/.well-known/security.txt through the Darknode proxy when it is available, otherwise directly from the browser (which CORS may block). If it fails, open the file and paste it below.</p>' +
      '<div class="st-fetchrow">' +
      '<input class="st-in" id="st-domain" placeholder="example.com">' +
      '<button class="btn ghost st-mini" id="st-fetch" type="button">Fetch from domain</button>' +
      '</div>' +
      '<div class="st-field">' +
      '<label class="st-lbl" for="st-input">Paste security.txt</label>' +
      '<textarea class="st-ta" id="st-input" style="min-height:360px" placeholder="Contact: mailto:security@example.com&#10;Expires: 2027-01-01T00:00:00.000Z"></textarea>' +
      '</div>' +
      '</div>' +
      '</div>' +

      '<div class="st-col">' +
      '<div class="panel st-sticky">' +
      '<div class="panel-h"><h2 class="pg-h2">Validation report</h2></div>' +
      '<div id="st-report"><p class="st-note">Paste a security.txt and press Validate, or load the example.</p></div>' +
      '</div>' +
      '</div>' +
      '</div>';

    var input = body.querySelector("#st-input");
    var report = body.querySelector("#st-report");

    function runReport() {
      var res = validateSecurityTxt(input.value);
      var html = "";
      html += '<div class="st-verdict ' + (res.ok ? "pass" : "fail") + '">' +
        (res.ok ? "Pass: valid per RFC 9116" : "Fail: the file does not meet RFC 9116") +
        (res.signed ? " (PGP-signed)" : "") + '</div>';

      var errs = res.findings.filter(function (x) { return x.level === "error"; });
      var warns = res.findings.filter(function (x) { return x.level === "warn"; });
      var infos = res.findings.filter(function (x) { return x.level === "info"; });

      function issueHtml(x) {
        return '<div class="st-issue ' + x.level + '">' +
          '<span class="st-badge">' + x.level + '</span>' +
          '<span>' + esc(x.msg) + '</span>' +
          (x.line ? '<span class="st-ln">line ' + x.line + '</span>' : '') +
          '</div>';
      }

      if (!res.findings.length) {
        html += '<div class="st-note">No issues found.</div>';
      } else {
        html += errs.map(issueHtml).join("") + warns.map(issueHtml).join("") + infos.map(issueHtml).join("");
      }

      if (res.fields.length) {
        html += '<table class="st-tbl"><thead><tr><th>Field</th><th>Value</th><th>Line</th></tr></thead><tbody>' +
          res.fields.map(function (f) {
            return '<tr><td class="k">' + esc(f.name) + '</td><td class="v">' + esc(f.value) + '</td><td class="st-ln">' + f.line + '</td></tr>';
          }).join("") + '</tbody></table>';
      }
      report.innerHTML = html;
    }

    body.querySelector("#st-check").onclick = runReport;
    body.querySelector("#st-example").onclick = function () {
      input.value = exampleText();
      runReport();
      toast("Loaded example security.txt");
    };

    body.querySelector("#st-fetch").onclick = function () {
      var btn = body.querySelector("#st-fetch");
      var domain = (body.querySelector("#st-domain").value || "").trim()
        .replace(/^https?:\/\//i, "").replace(/[\/?#].*$/, "");
      if (!domain) { toast("Enter a domain first"); return; }
      var target = "https://" + domain + "/.well-known/security.txt";
      btn.disabled = true;
      report.innerHTML = '<p class="st-note">Fetching ' + esc(target) + ' …</p>';

      var ctrl = typeof AbortController !== "undefined" ? new AbortController() : null;
      var timer = setTimeout(function () { if (ctrl) ctrl.abort(); }, 8000);

      // Prefer the Darknode proxy (real server-side request, no CORS); fall back to a direct browser fetch.
      function direct() {
        return fetch(target, ctrl ? { signal: ctrl.signal } : {}).then(function (r) {
          return r.text().then(function (t) { return { ok: r.ok, status: r.status, text: t }; });
        });
      }
      import("/js/net.js").then(function (net) {
        if (!net.proxyConfigured()) return direct();
        return net.dnFetch(target, { raw: true, timeout: 8000 }).then(function (d) {
          return { ok: d.status >= 200 && d.status < 300, status: d.status, text: String(d.body || "") };
        });
      }, direct).then(function (out) {
        clearTimeout(timer);
        btn.disabled = false;
        if (!out.ok) {
          report.innerHTML = '<div class="st-note">Server returned HTTP ' + out.status +
            '. The file may not exist at that location. Paste it manually if you have it.</div>';
          return;
        }
        input.value = out.text;
        runReport();
        toast("Fetched security.txt from " + domain);
      }).catch(function (err) {
        clearTimeout(timer);
        btn.disabled = false;
        var why = (err && err.name === "AbortError")
          ? "the request timed out after 8 seconds"
          : (err && err.message) ? err.message : "the browser blocked it (most likely CORS) or the host is unreachable";
        report.innerHTML = '<div class="st-note">Could not fetch ' + esc(target) + ' — ' + why +
          '. This is expected for many hosts: open the URL in a new tab and paste the contents into the box on the left.</div>';
      });
    };
  }

  // ── tab switching ──
  function setMode(mode) {
    state.mode = mode;
    main.querySelectorAll(".st-tab").forEach(function (t) {
      t.classList.toggle("on", t.dataset.mode === mode);
    });
    if (mode === "generate") renderGenerate(); else renderValidate();
  }
  main.querySelector("#st-tabs").onclick = function (e) {
    var b = e.target.closest(".st-tab");
    if (b && b.dataset.mode !== state.mode) setMode(b.dataset.mode);
  };

  setMode("generate");
}
