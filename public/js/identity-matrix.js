// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Identity Matrix — IAM analyzer, JWT debugger, RBAC builder, session entropy
// All analysis runs client-side. Nothing leaves the browser.

var esc = function(s) {
  return String(s != null ? s : '').replace(/[&<>"']/g, function(c) {
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
  });
};

// ── JWT Decoder ─────────────────────────────────────────────────────────────

function _imDecodeBase64Url(str) {
  var s = str.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  try { return JSON.parse(atob(s)); } catch (e) { return null; }
}

function _imDecodeJWT(token) {
  var parts = token.split('.');
  if (parts.length !== 3) return { error: 'Invalid JWT: expected 3 parts, got ' + parts.length };
  var header = _imDecodeBase64Url(parts[0]);
  var payload = _imDecodeBase64Url(parts[1]);
  if (!header) return { error: 'Failed to decode JWT header' };
  if (!payload) return { error: 'Failed to decode JWT payload' };
  var isExpired = false;
  var expiresIn = null;
  if (payload.exp) {
    var now = Math.floor(Date.now() / 1000);
    isExpired = payload.exp < now;
    expiresIn = isExpired ? 'EXPIRED ' + (now - payload.exp) + 's ago' : 'Expires in ' + (payload.exp - now) + 's';
  }
  return { header: header, payload: payload, signature: parts[2], isExpired: isExpired, expiresIn: expiresIn };
}

// ── Entropy Calculator ──────────────────────────────────────────────────────

function _imEntropy(str) {
  if (!str || str.length === 0) return 0;
  var freq = {};
  for (var i = 0; i < str.length; i++) {
    var c = str[i];
    freq[c] = (freq[c] || 0) + 1;
  }
  var entropy = 0;
  var len = str.length;
  var keys = Object.keys(freq);
  for (var j = 0; j < keys.length; j++) {
    var p = freq[keys[j]] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function _imEntropyRating(bits) {
  if (bits >= 5.5) return { label: 'EXCELLENT', color: '#00cc66' };
  if (bits >= 4.5) return { label: 'GOOD', color: '#44aaff' };
  if (bits >= 3.5) return { label: 'FAIR', color: '#ffaa22' };
  if (bits >= 2.5) return { label: 'WEAK', color: '#ff6644' };
  return { label: 'INSECURE', color: '#ff2244' };
}

// ── RBAC Model Data ─────────────────────────────────────────────────────────

var _imRoles = [
  { name: 'super_admin', level: 100, permissions: ['*'], inherits: [], description: 'Full system access — unrestricted' },
  { name: 'admin', level: 80, permissions: ['users:*', 'config:*', 'logs:read', 'reports:*', 'audit:read'], inherits: ['moderator'], description: 'Administrative access — user and config management' },
  { name: 'moderator', level: 60, permissions: ['content:*', 'users:read', 'users:suspend', 'reports:read'], inherits: ['editor'], description: 'Content moderation and user oversight' },
  { name: 'editor', level: 40, permissions: ['content:create', 'content:edit', 'content:delete', 'media:upload'], inherits: ['viewer'], description: 'Content creation and editing' },
  { name: 'viewer', level: 20, permissions: ['content:read', 'media:read', 'profile:read'], inherits: ['guest'], description: 'Read-only access to content' },
  { name: 'guest', level: 0, permissions: ['content:read:public'], inherits: [], description: 'Public content only — unauthenticated' },
  { name: 'api_service', level: 50, permissions: ['api:*', 'data:read', 'data:write', 'webhooks:manage'], inherits: [], description: 'Service account for API integrations' },
  { name: 'auditor', level: 70, permissions: ['audit:*', 'logs:*', 'users:read', 'config:read', 'reports:*'], inherits: ['viewer'], description: 'Compliance and audit access — read + audit trails' },
  { name: 'security_analyst', level: 75, permissions: ['security:*', 'logs:*', 'audit:*', 'users:read', 'config:read', 'incidents:*'], inherits: ['auditor'], description: 'Security operations — incident response and threat hunting' }
];

// ── Privilege Escalation Paths ──────────────────────────────────────────────

var _imEscPaths = [
  { from: 'viewer', to: 'editor', vector: 'IDOR on content:edit endpoint — /api/content/{id}/edit does not check ownership', severity: 'high', mitre: 'T1068' },
  { from: 'editor', to: 'moderator', vector: 'Mass assignment on role update — POST /api/profile accepts role field in body', severity: 'critical', mitre: 'T1068' },
  { from: 'moderator', to: 'admin', vector: 'JWT claim manipulation — alg:none accepted, role claim editable client-side', severity: 'critical', mitre: 'T1134.005' },
  { from: 'api_service', to: 'admin', vector: 'Service account token reuse — API key grants access to /admin/users endpoint', severity: 'high', mitre: 'T1078.004' },
  { from: 'guest', to: 'viewer', vector: 'Forced browsing — /internal/dashboard accessible without authentication', severity: 'medium', mitre: 'T1190' },
  { from: 'editor', to: 'admin', vector: 'File upload RCE — SVG with embedded JavaScript, no sanitization on media:upload', severity: 'critical', mitre: 'T1203' },
  { from: 'auditor', to: 'super_admin', vector: 'Log injection + deserialization — crafted log entry triggers pickle.loads in log viewer', severity: 'critical', mitre: 'T1059' }
];

// ── OAuth 2.0 Flows ─────────────────────────────────────────────────────────

var _imOAuthFlows = [
  { name: 'Authorization Code', grantType: 'authorization_code', steps: ['1. Client redirects user to /authorize', '2. User authenticates and consents', '3. Auth server redirects back with ?code=...', '4. Client exchanges code for token at /token', '5. Auth server returns access_token + refresh_token'], bestFor: 'Server-side web apps', pkce: 'Recommended', security: 'Most secure — code exchange is server-to-server' },
  { name: 'Auth Code + PKCE', grantType: 'authorization_code', steps: ['1. Client generates code_verifier + code_challenge', '2. Redirect to /authorize with code_challenge', '3. User authenticates', '4. Client exchanges code + code_verifier for token', '5. Server verifies SHA256(verifier) == challenge'], bestFor: 'SPAs, mobile apps, public clients', pkce: 'Required', security: 'Prevents authorization code interception attacks' },
  { name: 'Client Credentials', grantType: 'client_credentials', steps: ['1. Client sends client_id + client_secret to /token', '2. Auth server validates credentials', '3. Returns access_token (no refresh token)'], bestFor: 'Machine-to-machine / service accounts', pkce: 'N/A', security: 'No user context — client authenticates as itself' },
  { name: 'Device Code', grantType: 'urn:ietf:params:oauth:grant-type:device_code', steps: ['1. Client requests device code from /device/code', '2. User visits verification URL on another device', '3. User enters the displayed code and authenticates', '4. Client polls /token until user completes auth', '5. Returns access_token + refresh_token'], bestFor: 'Smart TVs, IoT, CLI tools', pkce: 'N/A', security: 'User authenticates on a trusted device with full browser' },
  { name: 'Implicit (DEPRECATED)', grantType: 'implicit', steps: ['1. Client redirects to /authorize with response_type=token', '2. User authenticates', '3. Token returned in URL fragment #access_token=...'], bestFor: 'NONE — deprecated in OAuth 2.1', pkce: 'N/A', security: 'INSECURE — token exposed in URL, no refresh token, no code exchange' }
];

// ── Main Render ─────────────────────────────────────────────────────────────

window.renderIdentityMatrix = function(container) {
  var el = typeof container === 'string' ? document.getElementById(container) : container;
  if (!el) return;

  var h = '';
  h += '<div style="background:#0a0e16;color:#c8d6e5;font-family:\'Courier New\',monospace;padding:24px;min-height:100%;">';

  // Header
  h += '<h2 style="margin:0 0 4px;color:#7c5cff;letter-spacing:2px;font-size:18px;">IDENTITY MATRIX</h2>';
  h += '<div style="color:#4a6a8a;font-size:11px;margin-bottom:20px;">Identity & Access Management Analyzer | JWT Debugger | RBAC Builder</div>';

  // Tabs
  h += '<div id="im-tabs" style="display:flex;gap:4px;margin-bottom:16px;flex-wrap:wrap;">';
  var tabs = ['JWT Decoder', 'RBAC Model', 'Priv Escalation', 'OAuth Flows', 'Token Entropy'];
  for (var ti = 0; ti < tabs.length; ti++) {
    var isActive = ti === 0;
    h += '<button class="im-tab" data-im-tab="' + ti + '" style="background:' + (isActive ? '#1a1a3a' : '#0f1218') + ';border:1px solid ' + (isActive ? '#7c5cff' : '#1a2a3a') + ';color:' + (isActive ? '#7c5cff' : '#5a7a9a') + ';padding:6px 14px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:3px;letter-spacing:1px;">' + esc(tabs[ti]) + '</button>';
  }
  h += '</div>';

  // ── Tab 0: JWT Decoder ──
  h += '<div id="im-panel-0" class="im-panel">';
  h += '<div style="margin-bottom:12px;">';
  h += '<label style="color:#5a8aaa;font-size:11px;display:block;margin-bottom:4px;">PASTE JWT TOKEN:</label>';
  h += '<textarea id="im-jwt-input" rows="4" style="width:100%;background:#0f1218;border:1px solid #1a2a3a;color:#c8d6e5;padding:10px;font-family:monospace;font-size:11px;border-radius:3px;resize:vertical;box-sizing:border-box;" placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"></textarea>';
  h += '<button id="im-jwt-decode" style="background:#1a1a3a;border:1px solid #7c5cff;color:#7c5cff;padding:6px 16px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:3px;margin-top:6px;">DECODE</button>';
  h += '</div>';
  h += '<div id="im-jwt-result" style="min-height:80px;"></div>';
  h += '</div>';

  // ── Tab 1: RBAC Model ──
  h += '<div id="im-panel-1" class="im-panel" style="display:none;">';
  h += '<h3 style="color:#5a9abb;font-size:13px;letter-spacing:2px;margin:0 0 10px;">ROLE-BASED ACCESS CONTROL MODEL</h3>';
  h += '<table style="width:100%;border-collapse:collapse;font-size:11px;">';
  h += '<tr style="color:#4a6a8a;text-align:left;"><th style="padding:6px 8px;">ROLE</th><th style="padding:6px 8px;">LEVEL</th><th style="padding:6px 8px;">INHERITS</th><th style="padding:6px 8px;">PERMISSIONS</th></tr>';
  for (var ri = 0; ri < _imRoles.length; ri++) {
    var r = _imRoles[ri];
    var levelColor = r.level >= 80 ? '#ff4444' : (r.level >= 50 ? '#ffaa22' : '#44aaff');
    h += '<tr style="border-bottom:1px solid #0f1a24;">';
    h += '<td style="padding:6px 8px;"><span style="color:' + levelColor + ';font-weight:bold;">' + esc(r.name) + '</span><br><span style="color:#4a6a8a;font-size:9px;">' + esc(r.description) + '</span></td>';
    h += '<td style="padding:6px 8px;color:' + levelColor + ';">' + r.level + '</td>';
    h += '<td style="padding:6px 8px;color:#5a8aaa;">' + (r.inherits.length ? esc(r.inherits.join(', ')) : '—') + '</td>';
    h += '<td style="padding:6px 8px;color:#8ab4d4;font-size:10px;max-width:300px;word-wrap:break-word;">' + esc(r.permissions.join(', ')) + '</td>';
    h += '</tr>';
  }
  h += '</table></div>';

  // ── Tab 2: Privilege Escalation ──
  h += '<div id="im-panel-2" class="im-panel" style="display:none;">';
  h += '<h3 style="color:#ff4444;font-size:13px;letter-spacing:2px;margin:0 0 10px;">PRIVILEGE ESCALATION PATHS</h3>';
  for (var ei = 0; ei < _imEscPaths.length; ei++) {
    var ep = _imEscPaths[ei];
    var epColor = ep.severity === 'critical' ? '#ff2244' : (ep.severity === 'high' ? '#ff6644' : '#ffaa22');
    h += '<div style="background:#0f1218;border-left:3px solid ' + epColor + ';padding:10px 14px;margin-bottom:8px;border-radius:0 4px 4px 0;">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">';
    h += '<span style="color:#c8d6e5;font-size:12px;">' + esc(ep.from) + ' <span style="color:' + epColor + ';">&rarr;</span> ' + esc(ep.to) + '</span>';
    h += '<span style="color:' + epColor + ';font-size:10px;border:1px solid ' + epColor + ';padding:1px 6px;border-radius:2px;">' + esc(ep.severity.toUpperCase()) + '</span>';
    h += '</div>';
    h += '<div style="font-size:11px;color:#8aa0b8;line-height:1.5;">' + esc(ep.vector) + '</div>';
    h += '<div style="font-size:9px;color:#4a6a8a;margin-top:4px;">MITRE ATT&CK: ' + esc(ep.mitre) + '</div>';
    h += '</div>';
  }
  h += '</div>';

  // ── Tab 3: OAuth Flows ──
  h += '<div id="im-panel-3" class="im-panel" style="display:none;">';
  h += '<h3 style="color:#5a9abb;font-size:13px;letter-spacing:2px;margin:0 0 10px;">OAUTH 2.0 / 2.1 GRANT FLOWS</h3>';
  for (var oi = 0; oi < _imOAuthFlows.length; oi++) {
    var of_ = _imOAuthFlows[oi];
    var deprecated = of_.name.indexOf('DEPRECATED') > -1;
    h += '<div style="background:#0f1218;padding:12px 16px;margin-bottom:10px;border-radius:4px;border:1px solid ' + (deprecated ? '#3a1a1a' : '#1a2a3a') + ';">';
    h += '<div style="color:' + (deprecated ? '#ff4444' : '#00d4ff') + ';font-size:14px;font-weight:bold;margin-bottom:6px;">' + esc(of_.name) + '</div>';
    h += '<div style="font-size:10px;color:#4a6a8a;margin-bottom:6px;">grant_type: ' + esc(of_.grantType) + ' | PKCE: ' + esc(of_.pkce) + ' | Best for: ' + esc(of_.bestFor) + '</div>';
    h += '<div style="font-size:11px;color:#8ab4d4;margin-bottom:4px;">Security: ' + esc(of_.security) + '</div>';
    h += '<div style="font-size:10px;color:#6a8aaa;line-height:1.7;margin-top:6px;">';
    for (var si = 0; si < of_.steps.length; si++) {
      h += esc(of_.steps[si]) + '<br>';
    }
    h += '</div></div>';
  }
  h += '</div>';

  // ── Tab 4: Token Entropy ──
  h += '<div id="im-panel-4" class="im-panel" style="display:none;">';
  h += '<h3 style="color:#5a9abb;font-size:13px;letter-spacing:2px;margin:0 0 10px;">SESSION TOKEN ENTROPY ANALYZER</h3>';
  h += '<div style="margin-bottom:12px;">';
  h += '<label style="color:#5a8aaa;font-size:11px;display:block;margin-bottom:4px;">PASTE SESSION TOKEN / API KEY / COOKIE VALUE:</label>';
  h += '<textarea id="im-entropy-input" rows="3" style="width:100%;background:#0f1218;border:1px solid #1a2a3a;color:#c8d6e5;padding:10px;font-family:monospace;font-size:11px;border-radius:3px;resize:vertical;box-sizing:border-box;" placeholder="eyJhbGciOiJSUzI1NiIs..."></textarea>';
  h += '<button id="im-entropy-calc" style="background:#0a2a3a;border:1px solid #1a4a6a;color:#00d4ff;padding:6px 16px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:3px;margin-top:6px;">ANALYZE</button>';
  h += '</div>';
  h += '<div id="im-entropy-result"></div>';
  h += '</div>';

  h += '</div>';
  el.innerHTML = h;

  // ── Wire tab switching ──
  el.addEventListener('click', function(e) {
    var tabBtn = e.target.closest('.im-tab');
    if (!tabBtn) return;
    var idx = tabBtn.getAttribute('data-im-tab');
    var allTabs = el.querySelectorAll('.im-tab');
    var allPanels = el.querySelectorAll('.im-panel');
    for (var a = 0; a < allTabs.length; a++) {
      allTabs[a].style.background = '#0f1218';
      allTabs[a].style.borderColor = '#1a2a3a';
      allTabs[a].style.color = '#5a7a9a';
    }
    tabBtn.style.background = '#1a1a3a';
    tabBtn.style.borderColor = '#7c5cff';
    tabBtn.style.color = '#7c5cff';
    for (var b = 0; b < allPanels.length; b++) {
      allPanels[b].style.display = 'none';
    }
    var panel = document.getElementById('im-panel-' + idx);
    if (panel) panel.style.display = 'block';
  });

  // ── Wire JWT decoder ──
  var jwtBtn = document.getElementById('im-jwt-decode');
  if (jwtBtn) {
    jwtBtn.addEventListener('click', function() {
      var input = document.getElementById('im-jwt-input');
      var result = document.getElementById('im-jwt-result');
      if (!input || !result) return;
      var token = input.value.trim();
      if (!token) { result.innerHTML = '<div style="color:#ff4444;">No token provided.</div>'; return; }
      var decoded = _imDecodeJWT(token);
      if (decoded.error) { result.innerHTML = '<div style="color:#ff4444;">' + esc(decoded.error) + '</div>'; return; }
      var rh = '';
      rh += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:8px;">';
      rh += '<div style="background:#0f1218;padding:12px;border-radius:4px;border:1px solid #1a2a3a;">';
      rh += '<div style="color:#7c5cff;font-size:12px;font-weight:bold;margin-bottom:6px;">HEADER</div>';
      rh += '<pre style="margin:0;font-size:10px;color:#8ab4d4;white-space:pre-wrap;word-break:break-all;">' + esc(JSON.stringify(decoded.header, null, 2)) + '</pre>';
      rh += '</div>';
      rh += '<div style="background:#0f1218;padding:12px;border-radius:4px;border:1px solid #1a2a3a;">';
      rh += '<div style="color:#00d4ff;font-size:12px;font-weight:bold;margin-bottom:6px;">PAYLOAD</div>';
      rh += '<pre style="margin:0;font-size:10px;color:#8ab4d4;white-space:pre-wrap;word-break:break-all;">' + esc(JSON.stringify(decoded.payload, null, 2)) + '</pre>';
      rh += '</div>';
      rh += '</div>';
      if (decoded.expiresIn) {
        var expColor = decoded.isExpired ? '#ff2244' : '#00cc66';
        rh += '<div style="margin-top:8px;padding:8px 12px;background:#0f1218;border:1px solid ' + expColor + ';border-radius:4px;font-size:11px;color:' + expColor + ';">';
        rh += (decoded.isExpired ? 'TOKEN EXPIRED' : 'TOKEN VALID') + ' | ' + esc(decoded.expiresIn);
        rh += '</div>';
      }
      rh += '<div style="margin-top:8px;padding:8px 12px;background:#0f1218;border:1px solid #1a2a3a;border-radius:4px;font-size:10px;color:#4a6a8a;">';
      rh += 'Signature (base64url): ' + esc(decoded.signature.substring(0, 50)) + '...';
      rh += '</div>';
      result.innerHTML = rh;
    });
  }

  // ── Wire Entropy Analyzer ──
  var entBtn = document.getElementById('im-entropy-calc');
  if (entBtn) {
    entBtn.addEventListener('click', function() {
      var input = document.getElementById('im-entropy-input');
      var result = document.getElementById('im-entropy-result');
      if (!input || !result) return;
      var token = input.value.trim();
      if (!token) { result.innerHTML = '<div style="color:#ff4444;">No token provided.</div>'; return; }
      var entropy = _imEntropy(token);
      var rating = _imEntropyRating(entropy);
      var uniqueChars = Object.keys(token.split('').reduce(function(a, c) { a[c] = 1; return a; }, {})).length;
      var totalEntropy = entropy * token.length;
      var rh = '';
      rh += '<div style="background:#0f1218;padding:14px;border-radius:4px;border:1px solid #1a2a3a;margin-top:8px;">';
      rh += '<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-bottom:12px;">';
      rh += '<div style="text-align:center;"><div style="color:' + rating.color + ';font-size:28px;font-weight:bold;">' + entropy.toFixed(3) + '</div><div style="color:#4a6a8a;font-size:10px;">BITS / CHAR</div></div>';
      rh += '<div style="text-align:center;"><div style="color:#00d4ff;font-size:28px;font-weight:bold;">' + totalEntropy.toFixed(0) + '</div><div style="color:#4a6a8a;font-size:10px;">TOTAL BITS</div></div>';
      rh += '<div style="text-align:center;"><div style="color:' + rating.color + ';font-size:28px;font-weight:bold;">' + esc(rating.label) + '</div><div style="color:#4a6a8a;font-size:10px;">RATING</div></div>';
      rh += '</div>';
      rh += '<div style="font-size:11px;color:#8ab4d4;line-height:1.8;">';
      rh += 'Token length: <span style="color:#00d4ff;">' + token.length + ' chars</span><br>';
      rh += 'Unique characters: <span style="color:#00d4ff;">' + uniqueChars + '</span><br>';
      rh += 'Character space: <span style="color:#00d4ff;">' + (uniqueChars <= 16 ? 'Hex' : (uniqueChars <= 36 ? 'Alphanumeric' : (uniqueChars <= 64 ? 'Base64' : 'Extended'))) + '</span><br>';
      rh += 'Brute force complexity: <span style="color:#00d4ff;">2^' + totalEntropy.toFixed(0) + ' ≈ 10^' + (totalEntropy * 0.301).toFixed(0) + '</span><br>';
      var bruteTime = totalEntropy > 128 ? 'Heat death of universe' : (totalEntropy > 80 ? 'Billions of years' : (totalEntropy > 64 ? 'Centuries' : (totalEntropy > 48 ? 'Years' : (totalEntropy > 32 ? 'Days' : 'Seconds'))));
      rh += 'Time to brute-force (1B/s): <span style="color:' + (totalEntropy > 64 ? '#00cc66' : '#ff4444') + ';">' + bruteTime + '</span>';
      rh += '</div></div>';
      result.innerHTML = rh;
    });
  }
};
