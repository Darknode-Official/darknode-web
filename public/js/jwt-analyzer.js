// Copyright (c) 2026 Darknode-Official. All rights reserved.
// JWT Analyzer — decode, inspect, audit, compare, and build JSON Web Tokens
// FOR AUTHORIZED SECURITY TESTING ONLY.

var esc = function(s) { return String(s != null ? s : '').replace(/[&<>"']/g, function(c) {
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); };

var _jwtState = { tab: 'decode' };

function _jwtB64Decode(str) {
  try {
    var pad = str.replace(/-/g, '+').replace(/_/g, '/');
    while (pad.length % 4) pad += '=';
    // atob yields a Latin-1 byte string; JWT segments are UTF-8, so decode the
    // raw bytes as UTF-8 before parsing or non-ASCII claims get mangled
    // (e.g. "José" -> "JosÃ©").
    var bin = atob(pad);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return JSON.parse(new TextDecoder('utf-8').decode(bytes));
  } catch (e) { return null; }
}

function _jwtB64Encode(obj) {
  try {
    var json = JSON.stringify(obj);
    // UTF-8 encode before btoa: btoa throws on code points > 0xFF, so a claim
    // with any non-ASCII character would otherwise silently produce an empty
    // (invalid) segment. Build a byte string the encoder can consume.
    var utf8 = new TextEncoder().encode(json);
    var bin = '';
    for (var i = 0; i < utf8.length; i++) bin += String.fromCharCode(utf8[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  } catch (e) { return ''; }
}

function _jwtSplit(token) {
  var t = (token || '').trim();
  var parts = t.split('.');
  if (parts.length < 2 || parts.length > 3) return null;
  var header = _jwtB64Decode(parts[0]);
  var payload = _jwtB64Decode(parts[1]);
  if (!header) return null;
  return { header: header, payload: payload, signature: parts[2] || '', raw: parts };
}

function _jwtPretty(obj) {
  if (!obj) return '<span style="color:#ff4444;">INVALID</span>';
  var json = JSON.stringify(obj, null, 2);
  return json.replace(/(".*?")(\s*:\s*)/g, '<span style="color:#00ddff;">$1</span>$2')
    .replace(/:\s*(".*?")/g, ': <span style="color:#00ff88;">$1</span>')
    .replace(/:\s*(\d+\.?\d*)/g, ': <span style="color:#ffaa00;">$1</span>')
    .replace(/:\s*(true|false|null)/g, ': <span style="color:#aa66ff;">$1</span>');
}

function _jwtTimeFmt(ts) {
  if (!ts || typeof ts !== 'number') return null;
  try { return new Date(ts * 1000).toISOString().replace('T', ' ').replace('.000Z', ' UTC'); }
  catch (e) { return null; }
}

function _jwtTimeLeft(ts) {
  if (!ts) return '';
  var now = Math.floor(Date.now() / 1000);
  var diff = ts - now;
  var abs = Math.abs(diff);
  var h = Math.floor(abs / 3600);
  var m = Math.floor((abs % 3600) / 60);
  var s = abs % 60;
  var str = (h > 0 ? h + 'h ' : '') + (m > 0 ? m + 'm ' : '') + s + 's';
  return diff > 0 ? str + ' remaining' : str + ' ago';
}

var _jwtAlgRisk = {
  'none': { level: 'CRITICAL', color: '#ff2222', note: 'No signature — token can be forged by anyone' },
  'HS256': { level: 'MEDIUM', color: '#ffaa00', note: 'HMAC-SHA256 — vulnerable to brute force if secret is weak; RS256→HS256 confusion attack possible' },
  'HS384': { level: 'MEDIUM', color: '#ffaa00', note: 'HMAC-SHA384 — symmetric key; check for key confusion attacks' },
  'HS512': { level: 'LOW', color: '#00cc88', note: 'HMAC-SHA512 — strong if secret is long (>32 bytes)' },
  'RS256': { level: 'LOW', color: '#00cc88', note: 'RSA-SHA256 — asymmetric, standard choice' },
  'RS384': { level: 'LOW', color: '#00cc88', note: 'RSA-SHA384 — asymmetric, strong' },
  'RS512': { level: 'LOW', color: '#00cc88', note: 'RSA-SHA512 — asymmetric, strongest RSA variant' },
  'ES256': { level: 'LOW', color: '#00ff88', note: 'ECDSA P-256 — compact, modern, recommended' },
  'ES384': { level: 'LOW', color: '#00ff88', note: 'ECDSA P-384 — strong elliptic curve' },
  'ES512': { level: 'LOW', color: '#00ff88', note: 'ECDSA P-521 — strongest ECDSA variant' },
  'PS256': { level: 'LOW', color: '#00ff88', note: 'RSASSA-PSS SHA-256 — modern RSA padding' },
  'EdDSA': { level: 'LOW', color: '#00ff88', note: 'Edwards-curve DSA — Ed25519/Ed448, best modern choice' }
};

var _jwtStdClaims = [
  { key: 'iss', name: 'Issuer', desc: 'Who issued this token' },
  { key: 'sub', name: 'Subject', desc: 'Who/what the token is about' },
  { key: 'aud', name: 'Audience', desc: 'Intended recipient(s)' },
  { key: 'exp', name: 'Expiration', desc: 'Token expiry (Unix timestamp)', isTime: true },
  { key: 'nbf', name: 'Not Before', desc: 'Token not valid before (Unix timestamp)', isTime: true },
  { key: 'iat', name: 'Issued At', desc: 'When the token was issued (Unix timestamp)', isTime: true },
  { key: 'jti', name: 'JWT ID', desc: 'Unique token identifier' }
];

var _jwtAttacks = [
  { name: 'Algorithm None', severity: 'CRITICAL', desc: 'Set alg to "none" and remove signature. If server accepts unsigned tokens, full auth bypass.', payload: '{"alg":"none","typ":"JWT"}.{claims}.', color: '#ff2222' },
  { name: 'RS256 → HS256 Confusion', severity: 'CRITICAL', desc: 'Change alg from RS256 to HS256, sign with the public key as HMAC secret. Server may verify with public key as symmetric key.', payload: 'Change alg: RS256 → HS256, sign with PEM public key', color: '#ff2222' },
  { name: 'Weak Secret Brute Force', severity: 'HIGH', desc: 'HS256 tokens with weak secrets can be cracked offline. Tools: hashcat -m 16500, jwt-cracker, jwt_tool.', payload: 'hashcat -m 16500 jwt.txt wordlist.txt', color: '#ff6600' },
  { name: 'JWK Header Injection', severity: 'CRITICAL', desc: 'Inject your own public key in the JWT header via the jwk field. Server fetches key from header instead of its own store.', payload: 'Add "jwk":{...your RSA key...} to header', color: '#ff2222' },
  { name: 'JKU/x5u URL Injection', severity: 'CRITICAL', desc: 'Point jku (JWK Set URL) or x5u (X.509 URL) to attacker-controlled server hosting your signing keys.', payload: '"jku":"https://evil.com/.well-known/jwks.json"', color: '#ff2222' },
  { name: 'KID Injection', severity: 'HIGH', desc: 'The kid (Key ID) field may be used in file paths or SQL queries. Try path traversal or SQL injection.', payload: '"kid":"../../dev/null" or "kid":"\' UNION SELECT \'secret\' --"', color: '#ff6600' },
  { name: 'Expired Token Replay', severity: 'MEDIUM', desc: 'Send expired tokens to test if server validates exp claim. Many implementations skip expiration checks.', payload: 'Use token with past exp value', color: '#ffaa00' },
  { name: 'Claim Tampering', severity: 'HIGH', desc: 'Modify role/admin/group claims in the payload. If signature is not verified, privilege escalation is possible.', payload: '"role":"user" → "role":"admin"', color: '#ff6600' }
];

function _jwtGrade(parsed) {
  if (!parsed) return { grade: 'F', color: '#ff2222', reasons: ['Invalid token'] };
  var score = 100;
  var reasons = [];
  var alg = (parsed.header.alg || '').toUpperCase();
  if (alg === 'NONE' || !alg) { score -= 40; reasons.push('No algorithm / alg:none — token is unsigned'); }
  else if (alg.startsWith('HS')) { score -= 10; reasons.push('Symmetric algorithm — vulnerable if secret is weak'); }
  if (parsed.header.jwk) { score -= 15; reasons.push('JWK embedded in header — potential key injection'); }
  if (parsed.header.jku) { score -= 15; reasons.push('JKU URL in header — potential SSRF/key injection'); }
  if (parsed.header.x5u) { score -= 10; reasons.push('x5u URL in header — potential certificate injection'); }
  if (!parsed.payload) { score -= 30; reasons.push('Payload cannot be decoded'); }
  else {
    if (!parsed.payload.exp) { score -= 15; reasons.push('No expiration claim (exp) — token never expires'); }
    else {
      var now = Math.floor(Date.now() / 1000);
      if (parsed.payload.exp < now) { score -= 5; reasons.push('Token is expired'); }
      var window = parsed.payload.exp - (parsed.payload.iat || now);
      if (window > 86400 * 30) { score -= 10; reasons.push('Expiration window > 30 days — very long-lived token'); }
      else if (window > 86400 * 7) { score -= 5; reasons.push('Expiration window > 7 days'); }
    }
    if (!parsed.payload.iss) { score -= 5; reasons.push('No issuer claim (iss)'); }
    if (!parsed.payload.sub) { score -= 5; reasons.push('No subject claim (sub)'); }
    if (!parsed.payload.iat) { score -= 5; reasons.push('No issued-at claim (iat)'); }
    if (!parsed.payload.jti) { score -= 3; reasons.push('No JWT ID (jti) — replay protection missing'); }
  }
  if (!parsed.signature || parsed.signature.length === 0) { score -= 20; reasons.push('No signature present'); }
  else if (parsed.signature.length < 20) { score -= 10; reasons.push('Signature suspiciously short'); }
  if (score < 0) score = 0;
  var grade, color;
  if (score >= 85) { grade = 'A'; color = '#00ff88'; }
  else if (score >= 70) { grade = 'B'; color = '#44cc44'; }
  else if (score >= 55) { grade = 'C'; color = '#ffaa00'; }
  else if (score >= 35) { grade = 'D'; color = '#ff6600'; }
  else { grade = 'F'; color = '#ff2222'; }
  return { grade: grade, color: color, score: score, reasons: reasons };
}

function _jwtBtn(label, tab) {
  var active = _jwtState.tab === tab;
  return '<button onclick="_jwtSetTab(\'' + tab + '\')" style="padding:8px 14px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:4px;border:1px solid ' + (active ? '#00aaff' : '#1a2a44') + ';background:' + (active ? '#00aaff18' : '#080c18') + ';color:' + (active ? '#00ddff' : '#4a6a8a') + ';letter-spacing:1px;">' + label + '</button>';
}

export function renderJwtAnalyzer(container) {
  var h = '';
  h += '<div style="background:#0a0e14;color:#c8d6e5;font-family:\'Courier New\',monospace;padding:20px;min-height:600px;" id="jwt-root">';
  h += '<h2 style="color:#00ddff;font-size:18px;letter-spacing:2px;margin:0 0 4px;">JWT ANALYZER</h2>';
  h += '<div style="color:#4a6a8a;font-size:11px;margin-bottom:4px;">Decode, inspect, audit, compare, and build JSON Web Tokens</div>';
  h += '<div style="color:#ff4444;font-size:9px;margin-bottom:16px;padding:3px 8px;background:#ff444408;border:1px solid #ff444420;border-radius:3px;display:inline-block;">FOR AUTHORIZED SECURITY TESTING ONLY</div>';

  // Tabs
  h += '<div style="display:flex;gap:4px;margin-bottom:16px;flex-wrap:wrap;">';
  h += _jwtBtn('DECODE', 'decode');
  h += _jwtBtn('COMPARE', 'compare');
  h += _jwtBtn('BUILDER', 'builder');
  h += _jwtBtn('ATTACKS', 'attacks');
  h += '</div>';

  // Tab content
  if (_jwtState.tab === 'decode') {
    h += '<div style="margin-bottom:12px;">';
    h += '<textarea id="jwt-input" placeholder="Paste JWT token here (eyJ...)" style="width:100%;height:80px;background:#060a14;color:#00ddff;border:2px solid #1a3050;border-radius:6px;padding:10px;font-family:monospace;font-size:13px;resize:vertical;box-sizing:border-box;" oninput="_jwtDecode()"></textarea>';
    h += '</div>';
    h += '<div id="jwt-decode-output"></div>';
  }
  else if (_jwtState.tab === 'compare') {
    h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px;">';
    h += '<div><div style="color:#00aaff;font-size:10px;letter-spacing:1px;margin-bottom:4px;">TOKEN A</div>';
    h += '<textarea id="jwt-cmp-a" placeholder="Paste first JWT..." style="width:100%;height:70px;background:#060a14;color:#00ddff;border:1px solid #1a3050;border-radius:4px;padding:8px;font-family:monospace;font-size:11px;resize:vertical;box-sizing:border-box;"></textarea></div>';
    h += '<div><div style="color:#aa66ff;font-size:10px;letter-spacing:1px;margin-bottom:4px;">TOKEN B</div>';
    h += '<textarea id="jwt-cmp-b" placeholder="Paste second JWT..." style="width:100%;height:70px;background:#060a14;color:#aa66ff;border:1px solid #1a3050;border-radius:4px;padding:8px;font-family:monospace;font-size:11px;resize:vertical;box-sizing:border-box;"></textarea></div>';
    h += '</div>';
    h += '<button onclick="_jwtCompare()" style="background:#00aaff15;color:#00aaff;border:1px solid #00aaff33;padding:8px 20px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:4px;margin-bottom:12px;">COMPARE TOKENS</button>';
    h += '<div id="jwt-cmp-output"></div>';
  }
  else if (_jwtState.tab === 'builder') {
    h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:8px;padding:16px;margin-bottom:12px;">';
    h += '<div style="color:#00aaff;font-size:11px;letter-spacing:1px;margin-bottom:10px;font-weight:bold;">TOKEN BUILDER (unsigned, alg:none)</div>';
    h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:12px;">';
    var bFields = [
      { id: 'iss', label: 'Issuer (iss)', ph: 'darknode.ai' },
      { id: 'sub', label: 'Subject (sub)', ph: 'user@example.com' },
      { id: 'aud', label: 'Audience (aud)', ph: 'api.example.com' },
      { id: 'jti', label: 'JWT ID (jti)', ph: 'unique-id-123' }
    ];
    bFields.forEach(function(f) {
      h += '<div><div style="color:#4a6a8a;font-size:9px;letter-spacing:1px;margin-bottom:2px;">' + f.label + '</div>';
      h += '<input id="jwt-b-' + f.id + '" placeholder="' + f.ph + '" style="width:100%;background:#060a14;color:#c8d6e5;border:1px solid #1a3050;border-radius:3px;padding:6px 8px;font-family:monospace;font-size:11px;box-sizing:border-box;"/></div>';
    });
    h += '</div>';
    h += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:12px;">';
    h += '<div><div style="color:#4a6a8a;font-size:9px;letter-spacing:1px;margin-bottom:2px;">EXPIRES IN</div>';
    h += '<select id="jwt-b-exp" style="width:100%;background:#060a14;color:#c8d6e5;border:1px solid #1a3050;border-radius:3px;padding:6px;font-family:monospace;font-size:11px;">';
    h += '<option value="3600">1 hour</option><option value="86400">24 hours</option><option value="604800">7 days</option><option value="2592000">30 days</option><option value="31536000">1 year</option><option value="0">No expiration</option>';
    h += '</select></div>';
    h += '<div><div style="color:#4a6a8a;font-size:9px;letter-spacing:1px;margin-bottom:2px;">CUSTOM CLAIMS (JSON)</div>';
    h += '<input id="jwt-b-custom" placeholder=\'{"role":"admin","level":5}\' style="width:100%;background:#060a14;color:#c8d6e5;border:1px solid #1a3050;border-radius:3px;padding:6px 8px;font-family:monospace;font-size:11px;box-sizing:border-box;"/></div>';
    h += '</div>';
    h += '<button onclick="_jwtBuild()" style="background:#ff660015;color:#ff6600;border:1px solid #ff660033;padding:8px 20px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:4px;">BUILD UNSIGNED TOKEN</button>';
    h += '<div style="color:#ff4444;font-size:9px;margin-top:6px;">Warning: This generates unsigned tokens (alg:none) for testing only. Never use in production.</div>';
    h += '</div>';
    h += '<div id="jwt-build-output"></div>';
  }
  else if (_jwtState.tab === 'attacks') {
    h += '<div style="color:#ff4444;font-size:10px;margin-bottom:12px;padding:6px 10px;background:#ff444408;border:1px solid #ff444420;border-radius:4px;">Reference material for authorized penetration testing. Do not use without explicit permission from the token issuer.</div>';
    _jwtAttacks.forEach(function(a) {
      h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-left:3px solid ' + a.color + ';border-radius:6px;padding:12px 14px;margin-bottom:8px;">';
      h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">';
      h += '<span style="color:#c8d6e5;font-size:12px;font-weight:bold;">' + esc(a.name) + '</span>';
      h += '<span style="color:' + a.color + ';font-size:9px;font-weight:bold;letter-spacing:1px;padding:2px 8px;background:' + a.color + '15;border:1px solid ' + a.color + '33;border-radius:2px;">' + a.severity + '</span>';
      h += '</div>';
      h += '<div style="color:#6a8aaa;font-size:10px;line-height:1.5;margin-bottom:6px;">' + esc(a.desc) + '</div>';
      h += '<div style="color:#ffaa00;font-size:10px;background:#060a14;padding:6px 8px;border-radius:3px;font-family:monospace;word-break:break-all;">' + esc(a.payload) + '</div>';
      h += '</div>';
    });
  }

  h += '</div>';
  container.innerHTML = h;
};

window._jwtSetTab = function(tab) {
  _jwtState.tab = tab;
  var root = document.getElementById('jwt-root');
  if (root) renderJwtAnalyzer(root.parentElement);
};

window._jwtDecode = function() {
  var el = document.getElementById('jwt-input');
  var out = document.getElementById('jwt-decode-output');
  if (!el || !out) return;
  var token = el.value.trim();
  if (!token) { out.innerHTML = ''; return; }
  var parsed = _jwtSplit(token);
  if (!parsed) { out.innerHTML = '<div style="color:#ff4444;font-size:11px;padding:8px;">Invalid JWT format — expected 2 or 3 dot-separated Base64url segments</div>'; return; }

  var h = '';
  // Header
  h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:8px;padding:14px;margin-bottom:10px;">';
  h += '<div style="color:#ff6644;font-size:11px;letter-spacing:1px;font-weight:bold;margin-bottom:8px;">HEADER</div>';
  h += '<pre style="margin:0;font-size:11px;line-height:1.6;overflow-x:auto;">' + _jwtPretty(parsed.header) + '</pre>';
  // Algorithm analysis
  var alg = parsed.header.alg || 'none';
  var risk = _jwtAlgRisk[alg] || _jwtAlgRisk[alg.toUpperCase()] || { level: 'UNKNOWN', color: '#ffaa00', note: 'Unrecognized algorithm' };
  h += '<div style="margin-top:8px;padding:6px 10px;background:' + risk.color + '10;border:1px solid ' + risk.color + '33;border-radius:4px;display:flex;gap:8px;align-items:center;">';
  h += '<span style="color:' + risk.color + ';font-size:9px;font-weight:bold;letter-spacing:1px;">' + risk.level + '</span>';
  h += '<span style="color:#6a8aaa;font-size:10px;">' + esc(risk.note) + '</span>';
  h += '</div>';
  // Dangerous header fields
  if (parsed.header.jwk) h += '<div style="color:#ff4444;font-size:10px;margin-top:4px;">JWK found in header — possible key injection vector</div>';
  if (parsed.header.jku) h += '<div style="color:#ff4444;font-size:10px;margin-top:4px;">JKU URL: ' + esc(parsed.header.jku) + ' — possible SSRF</div>';
  if (parsed.header.x5u) h += '<div style="color:#ff4444;font-size:10px;margin-top:4px;">x5u URL: ' + esc(parsed.header.x5u) + ' — possible cert injection</div>';
  if (parsed.header.kid) h += '<div style="color:#ffaa00;font-size:10px;margin-top:4px;">KID: ' + esc(parsed.header.kid) + ' — test for path traversal / SQLi</div>';
  h += '</div>';

  // Payload
  h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:8px;padding:14px;margin-bottom:10px;">';
  h += '<div style="color:#00ff88;font-size:11px;letter-spacing:1px;font-weight:bold;margin-bottom:8px;">PAYLOAD</div>';
  if (parsed.payload) {
    h += '<pre style="margin:0 0 10px;font-size:11px;line-height:1.6;overflow-x:auto;">' + _jwtPretty(parsed.payload) + '</pre>';
    // Claims inspector
    h += '<div style="border-top:1px solid #1a2a44;padding-top:8px;">';
    h += '<div style="color:#4a6a8a;font-size:9px;letter-spacing:1px;margin-bottom:6px;">STANDARD CLAIMS</div>';
    var now = Math.floor(Date.now() / 1000);
    _jwtStdClaims.forEach(function(c) {
      var val = parsed.payload[c.key];
      var present = val !== undefined;
      h += '<div style="display:flex;gap:8px;align-items:center;margin:3px 0;font-size:10px;">';
      h += '<span style="color:' + (present ? '#00aaff' : '#2a3a4a') + ';min-width:30px;font-weight:bold;">' + c.key + '</span>';
      h += '<span style="color:#4a6a8a;min-width:80px;">' + c.name + '</span>';
      if (present) {
        if (c.isTime && typeof val === 'number') {
          var tFmt = _jwtTimeFmt(val);
          var tLeft = _jwtTimeLeft(val);
          var isExp = c.key === 'exp';
          var isNbf = c.key === 'nbf';
          var statusColor = '#6a8aaa';
          var statusText = '';
          if (isExp) {
            if (val < now) { statusColor = '#ff4444'; statusText = 'EXPIRED'; }
            else { statusColor = '#00ff88'; statusText = 'VALID'; }
          } else if (isNbf) {
            if (val > now) { statusColor = '#ffaa00'; statusText = 'NOT YET VALID'; }
            else { statusColor = '#00ff88'; statusText = 'ACTIVE'; }
          }
          h += '<span style="color:#8ab4d4;">' + esc(tFmt) + '</span>';
          if (statusText) h += '<span style="color:' + statusColor + ';font-size:9px;font-weight:bold;padding:1px 6px;background:' + statusColor + '15;border:1px solid ' + statusColor + '33;border-radius:2px;">' + statusText + '</span>';
          h += '<span style="color:#4a6a8a;font-size:9px;">' + esc(tLeft) + '</span>';
        } else {
          h += '<span style="color:#8ab4d4;">' + esc(typeof val === 'object' ? JSON.stringify(val) : String(val)) + '</span>';
        }
      } else {
        h += '<span style="color:#2a3a4a;font-style:italic;">not set</span>';
      }
      h += '</div>';
    });
    // Custom claims
    var customKeys = Object.keys(parsed.payload).filter(function(k) {
      return !_jwtStdClaims.some(function(c) { return c.key === k; });
    });
    if (customKeys.length > 0) {
      h += '<div style="color:#4a6a8a;font-size:9px;letter-spacing:1px;margin:8px 0 6px;">CUSTOM CLAIMS (' + customKeys.length + ')</div>';
      customKeys.forEach(function(k) {
        var v = parsed.payload[k];
        h += '<div style="display:flex;gap:8px;margin:3px 0;font-size:10px;">';
        h += '<span style="color:#aa66ff;min-width:80px;font-weight:bold;">' + esc(k) + '</span>';
        h += '<span style="color:#8ab4d4;">' + esc(typeof v === 'object' ? JSON.stringify(v) : String(v)) + '</span>';
        h += '</div>';
      });
    }
    h += '</div>';
  } else {
    h += '<div style="color:#ff4444;">Could not decode payload</div>';
  }
  h += '</div>';

  // Signature
  h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:8px;padding:14px;margin-bottom:10px;">';
  h += '<div style="color:#aa66ff;font-size:11px;letter-spacing:1px;font-weight:bold;margin-bottom:6px;">SIGNATURE</div>';
  if (parsed.signature) {
    h += '<div style="font-size:10px;color:#6a8aaa;word-break:break-all;">' + esc(parsed.signature) + '</div>';
    h += '<div style="color:#4a6a8a;font-size:9px;margin-top:4px;">' + parsed.signature.length + ' chars (Base64url encoded)</div>';
  } else {
    h += '<div style="color:#ff4444;font-size:10px;">No signature — token is unsigned</div>';
  }
  h += '</div>';

  // Security grade
  var grade = _jwtGrade(parsed);
  h += '<div style="background:' + grade.color + '08;border:2px solid ' + grade.color + '44;border-radius:8px;padding:16px;text-align:center;margin-bottom:10px;">';
  h += '<div style="font-size:48px;font-weight:bold;color:' + grade.color + ';text-shadow:0 0 20px ' + grade.color + '40;">' + grade.grade + '</div>';
  h += '<div style="color:' + grade.color + ';font-size:10px;letter-spacing:2px;">SECURITY GRADE (' + grade.score + '/100)</div>';
  if (grade.reasons.length > 0) {
    h += '<div style="text-align:left;margin-top:10px;">';
    grade.reasons.forEach(function(r) {
      h += '<div style="color:#6a8aaa;font-size:10px;margin:2px 0;">- ' + esc(r) + '</div>';
    });
    h += '</div>';
  }
  h += '</div>';

  out.innerHTML = h;
};

window._jwtCompare = function() {
  var elA = document.getElementById('jwt-cmp-a');
  var elB = document.getElementById('jwt-cmp-b');
  var out = document.getElementById('jwt-cmp-output');
  if (!elA || !elB || !out) return;
  var a = _jwtSplit(elA.value);
  var b = _jwtSplit(elB.value);
  if (!a || !b) { out.innerHTML = '<div style="color:#ff4444;font-size:11px;">Both fields must contain valid JWTs</div>'; return; }

  var h = '';
  // Header diff
  h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:8px;padding:14px;margin-bottom:10px;">';
  h += '<div style="color:#ff6644;font-size:11px;letter-spacing:1px;font-weight:bold;margin-bottom:8px;">HEADER COMPARISON</div>';
  var allHKeys = {};
  Object.keys(a.header).forEach(function(k) { allHKeys[k] = true; });
  Object.keys(b.header).forEach(function(k) { allHKeys[k] = true; });
  Object.keys(allHKeys).forEach(function(k) {
    var va = a.header[k], vb = b.header[k];
    var match = JSON.stringify(va) === JSON.stringify(vb);
    h += '<div style="display:flex;gap:8px;font-size:10px;margin:2px 0;align-items:center;">';
    h += '<span style="color:#4a6a8a;min-width:50px;">' + esc(k) + '</span>';
    h += '<span style="color:#00aaff;flex:1;">' + esc(va !== undefined ? (typeof va === 'object' ? JSON.stringify(va) : String(va)) : '—') + '</span>';
    h += '<span style="color:' + (match ? '#00ff88' : '#ff4444') + ';font-size:9px;">' + (match ? '=' : '!=') + '</span>';
    h += '<span style="color:#aa66ff;flex:1;">' + esc(vb !== undefined ? (typeof vb === 'object' ? JSON.stringify(vb) : String(vb)) : '—') + '</span>';
    h += '</div>';
  });
  h += '</div>';

  // Payload diff
  if (a.payload && b.payload) {
    h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:8px;padding:14px;margin-bottom:10px;">';
    h += '<div style="color:#00ff88;font-size:11px;letter-spacing:1px;font-weight:bold;margin-bottom:8px;">PAYLOAD COMPARISON</div>';
    var allPKeys = {};
    Object.keys(a.payload).forEach(function(k) { allPKeys[k] = true; });
    Object.keys(b.payload).forEach(function(k) { allPKeys[k] = true; });
    Object.keys(allPKeys).forEach(function(k) {
      var va = a.payload[k], vb = b.payload[k];
      var match = JSON.stringify(va) === JSON.stringify(vb);
      var isTime = (k === 'exp' || k === 'iat' || k === 'nbf');
      h += '<div style="display:flex;gap:8px;font-size:10px;margin:2px 0;align-items:center;background:' + (match ? 'transparent' : '#ff444408') + ';padding:2px 4px;border-radius:3px;">';
      h += '<span style="color:#4a6a8a;min-width:60px;font-weight:bold;">' + esc(k) + '</span>';
      var dispA = va !== undefined ? (isTime && typeof va === 'number' ? _jwtTimeFmt(va) || String(va) : (typeof va === 'object' ? JSON.stringify(va) : String(va))) : '—';
      var dispB = vb !== undefined ? (isTime && typeof vb === 'number' ? _jwtTimeFmt(vb) || String(vb) : (typeof vb === 'object' ? JSON.stringify(vb) : String(vb))) : '—';
      h += '<span style="color:#00aaff;flex:1;word-break:break-all;">' + esc(dispA) + '</span>';
      h += '<span style="color:' + (match ? '#00ff88' : '#ff4444') + ';font-size:9px;font-weight:bold;">' + (match ? '=' : '!=') + '</span>';
      h += '<span style="color:#aa66ff;flex:1;word-break:break-all;">' + esc(dispB) + '</span>';
      h += '</div>';
    });
    h += '</div>';
  }

  // Signature comparison
  h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:8px;padding:14px;">';
  h += '<div style="color:#aa66ff;font-size:11px;letter-spacing:1px;font-weight:bold;margin-bottom:6px;">SIGNATURE</div>';
  var sigMatch = a.signature === b.signature;
  h += '<div style="font-size:10px;color:' + (sigMatch ? '#00ff88' : '#ff4444') + ';">' + (sigMatch ? 'Signatures match' : 'Signatures differ') + '</div>';
  h += '</div>';

  out.innerHTML = h;
};

window._jwtBuild = function() {
  var out = document.getElementById('jwt-build-output');
  if (!out) return;
  var payload = {};
  var now = Math.floor(Date.now() / 1000);
  payload.iat = now;

  var iss = (document.getElementById('jwt-b-iss') || {}).value;
  var sub = (document.getElementById('jwt-b-sub') || {}).value;
  var aud = (document.getElementById('jwt-b-aud') || {}).value;
  var jti = (document.getElementById('jwt-b-jti') || {}).value;
  var expSel = (document.getElementById('jwt-b-exp') || {}).value;
  var customStr = (document.getElementById('jwt-b-custom') || {}).value;

  if (iss) payload.iss = iss;
  if (sub) payload.sub = sub;
  if (aud) payload.aud = aud;
  if (jti) payload.jti = jti;
  var expVal = parseInt(expSel, 10);
  if (expVal > 0) payload.exp = now + expVal;
  if (customStr) {
    try {
      var custom = JSON.parse(customStr);
      Object.keys(custom).forEach(function(k) { payload[k] = custom[k]; });
    } catch (e) {
      out.innerHTML = '<div style="color:#ff4444;font-size:11px;">Invalid custom claims JSON: ' + esc(e.message) + '</div>';
      return;
    }
  }

  var header = { alg: 'none', typ: 'JWT' };
  var token = _jwtB64Encode(header) + '.' + _jwtB64Encode(payload) + '.';

  var h = '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:8px;padding:14px;margin-top:12px;">';
  h += '<div style="color:#ff6600;font-size:11px;letter-spacing:1px;font-weight:bold;margin-bottom:8px;">GENERATED TOKEN (UNSIGNED)</div>';
  h += '<div style="background:#060a14;padding:10px;border-radius:4px;font-size:11px;color:#ffaa00;word-break:break-all;cursor:pointer;" onclick="navigator.clipboard.writeText(this.textContent)" title="Click to copy">' + esc(token) + '</div>';
  h += '<div style="color:#4a6a8a;font-size:9px;margin-top:6px;">Click token to copy. This is an unsigned (alg:none) token for testing.</div>';
  h += '<div style="margin-top:8px;"><div style="color:#4a6a8a;font-size:9px;letter-spacing:1px;margin-bottom:4px;">PAYLOAD PREVIEW</div>';
  h += '<pre style="margin:0;font-size:10px;line-height:1.5;overflow-x:auto;">' + _jwtPretty(payload) + '</pre>';
  h += '</div></div>';
  out.innerHTML = h;
};
