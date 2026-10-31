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
  try {
    var bin = atob(s);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return JSON.parse(new TextDecoder('utf-8').decode(bytes));
  } catch (e) { return null; }
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
  if (bits >= 5.5) return { label: 'Excellent', color: 'var(--ok)' };
  if (bits >= 4.5) return { label: 'Good', color: 'var(--acc)' };
  if (bits >= 3.5) return { label: 'Fair', color: 'var(--warn)' };
  if (bits >= 2.5) return { label: 'Weak', color: 'var(--bad)' };
  return { label: 'Insecure', color: 'var(--bad)' };
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

export function renderIdentityMatrix(container) {
  var el = typeof container === 'string' ? document.getElementById(container) : container;
  if (!el) return;

  var h = '';
  h += '<div>';

  // Header
  h += '<div class="pg-head"><div><h1 class="pg-h1">Identity Matrix</h1>';
  h += '<p class="muted pg-sub">Identity and access management analyzer: Decode JWTs and estimate token entropy locally in your browser, with reference material on RBAC, privilege escalation patterns and OAuth flows.</p></div></div>';

  // Tabs
  h += '<div id="im-tabs" class="seg" style="margin-bottom:16px;flex-wrap:wrap;">';
  var tabs = ['JWT decoder', 'RBAC reference', 'Escalation patterns', 'OAuth flows', 'Token entropy'];
  for (var ti = 0; ti < tabs.length; ti++) {
    var isActive = ti === 0;
    h += '<button class="im-tab' + (isActive ? ' on' : '') + '" data-im-tab="' + ti + '">' + esc(tabs[ti]) + '</button>';
  }
  h += '</div>';

  // ── Tab 0: JWT Decoder ──
  h += '<div id="im-panel-0" class="im-panel">';
  h += '<div style="margin-bottom:12px;">';
  h += '<label style="color:var(--mut);font-size:12px;display:block;margin-bottom:4px;">Paste a JWT</label>';
  h += '<textarea id="im-jwt-input" rows="4" style="width:100%;font-family:monospace;font-size:12px;resize:vertical;box-sizing:border-box;" placeholder="eyJhbGciOi..."></textarea>';
  h += '<button class="btn" id="im-jwt-decode" style="margin-top:6px;">Decode</button>';
  h += '</div>';
  h += '<div id="im-jwt-result" style="min-height:80px;"></div>';
  h += '</div>';

  // ── Tab 1: RBAC Model ──
  h += '<div id="im-panel-1" class="im-panel" style="display:none;">';
  h += '<h3 style="color:var(--txt);font-size:14px;margin:0 0 4px;">Example role-based access control model</h3><p class="muted" style="font-size:12px;margin:0 0 10px;">A reference role hierarchy for a typical web application. It is an example, not read from your systems.</p>';
  h += '<table style="width:100%;border-collapse:collapse;font-size:12px;">';
  h += '<tr style="color:var(--mut);text-align:left;"><th style="padding:6px 8px;">Role</th><th style="padding:6px 8px;">Level</th><th style="padding:6px 8px;">Inherits</th><th style="padding:6px 8px;">Permissions</th></tr>';
  for (var ri = 0; ri < _imRoles.length; ri++) {
    var r = _imRoles[ri];
    var levelColor = r.level >= 80 ? 'var(--bad)' : (r.level >= 50 ? 'var(--warn)' : 'var(--acc)');
    h += '<tr style="border-bottom:1px solid var(--line);">';
    h += '<td style="padding:6px 8px;"><span style="color:' + levelColor + ';font-weight:bold;">' + esc(r.name) + '</span><br><span style="color:var(--mut);font-size:12px;">' + esc(r.description) + '</span></td>';
    h += '<td style="padding:6px 8px;color:' + levelColor + ';">' + r.level + '</td>';
    h += '<td style="padding:6px 8px;color:var(--mut);">' + (r.inherits.length ? esc(r.inherits.join(', ')) : '—') + '</td>';
    h += '<td style="padding:6px 8px;color:var(--txt-2);font-size:12px;max-width:300px;word-wrap:break-word;">' + esc(r.permissions.join(', ')) + '</td>';
    h += '</tr>';
  }
  h += '</table></div>';

  // ── Tab 2: Privilege Escalation ──
  h += '<div id="im-panel-2" class="im-panel" style="display:none;">';
  h += '<h3 style="color:var(--txt);font-size:14px;margin:0 0 4px;">Common privilege escalation patterns</h3><p class="muted" style="font-size:12px;margin:0 0 10px;">Reference examples mapped to the example roles above and to MITRE ATT&amp;CK. They are not findings about your systems.</p>';
  for (var ei = 0; ei < _imEscPaths.length; ei++) {
    var ep = _imEscPaths[ei];
    var epColor = ep.severity === 'medium' ? 'var(--warn)' : 'var(--bad)';
    h += '<div style="background:var(--card2);border-left:3px solid ' + epColor + ';padding:10px 14px;margin-bottom:8px;border-radius:0 4px 4px 0;">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">';
    h += '<span style="color:var(--txt);font-size:12px;">' + esc(ep.from) + ' <span style="color:' + epColor + ';">&rarr;</span> ' + esc(ep.to) + '</span>';
    h += '<span style="color:' + epColor + ';font-size:12px;border:1px solid ' + epColor + ';padding:1px 6px;border-radius:2px;">' + esc(ep.severity) + '</span>';
    h += '</div>';
    h += '<div style="font-size:12px;color:var(--txt-2);line-height:1.5;">' + esc(ep.vector) + '</div>';
    h += '<div style="font-size:12px;color:var(--mut);margin-top:4px;">MITRE ATT&CK: ' + esc(ep.mitre) + '</div>';
    h += '</div>';
  }
  h += '</div>';

  // ── Tab 3: OAuth Flows ──
  h += '<div id="im-panel-3" class="im-panel" style="display:none;">';
  h += '<h3 style="color:var(--txt);font-size:14px;margin:0 0 10px;">OAuth 2.0 / 2.1 grant flows</h3>';
  for (var oi = 0; oi < _imOAuthFlows.length; oi++) {
    var of_ = _imOAuthFlows[oi];
    var deprecated = of_.name.indexOf('DEPRECATED') > -1;
    h += '<div style="background:var(--card2);padding:12px 16px;margin-bottom:10px;border-radius:4px;border:1px solid ' + (deprecated ? 'var(--bad)' : 'var(--line)') + ';">';
    h += '<div style="color:' + (deprecated ? 'var(--bad)' : 'var(--txt)') + ';font-size:14px;font-weight:bold;margin-bottom:6px;">' + esc(of_.name) + '</div>';
    h += '<div style="font-size:12px;color:var(--mut);margin-bottom:6px;">grant_type: ' + esc(of_.grantType) + ' | PKCE: ' + esc(of_.pkce) + ' | Best for: ' + esc(of_.bestFor) + '</div>';
    h += '<div style="font-size:12px;color:var(--txt-2);margin-bottom:4px;">Security: ' + esc(of_.security) + '</div>';
    h += '<div style="font-size:12px;color:var(--mut);line-height:1.7;margin-top:6px;">';
    for (var si = 0; si < of_.steps.length; si++) {
      h += esc(of_.steps[si]) + '<br>';
    }
    h += '</div></div>';
  }
  h += '</div>';

  // ── Tab 4: Token Entropy ──
  h += '<div id="im-panel-4" class="im-panel" style="display:none;">';
  h += '<h3 style="color:var(--txt);font-size:14px;margin:0 0 4px;">Session token entropy analyzer</h3><p class="muted" style="font-size:12px;margin:0 0 10px;">Shannon entropy of the characters in the value you paste. It is an estimate: a token from a weak generator can still look random.</p>';
  h += '<div style="margin-bottom:12px;">';
  h += '<label style="color:var(--mut);font-size:12px;display:block;margin-bottom:4px;">Paste a session token, API key or cookie value</label>';
  h += '<textarea id="im-entropy-input" rows="3" style="width:100%;font-family:monospace;font-size:12px;resize:vertical;box-sizing:border-box;" placeholder="eyJhbGciOiJSUzI1NiIs..."></textarea>';
  h += '<button class="btn" id="im-entropy-calc" style="margin-top:6px;">Analyze</button>';
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
    for (var a = 0; a < allTabs.length; a++) allTabs[a].classList.remove('on');
    tabBtn.classList.add('on');
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
      if (!token) { result.innerHTML = '<div style="color:var(--bad);">No token provided.</div>'; return; }
      var decoded = _imDecodeJWT(token);
      if (decoded.error) { result.innerHTML = '<div style="color:var(--bad);">' + esc(decoded.error) + '</div>'; return; }
      var rh = '';
      rh += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:8px;">';
      rh += '<div style="background:var(--card2);padding:12px;border-radius:4px;border:1px solid var(--line);">';
      rh += '<div style="color:var(--acc-2);font-size:12px;font-weight:bold;margin-bottom:6px;">Header</div>';
      rh += '<pre style="margin:0;font-size:12px;color:var(--txt-2);white-space:pre-wrap;word-break:break-all;">' + esc(JSON.stringify(decoded.header, null, 2)) + '</pre>';
      rh += '</div>';
      rh += '<div style="background:var(--card2);padding:12px;border-radius:4px;border:1px solid var(--line);">';
      rh += '<div style="color:var(--acc);font-size:12px;font-weight:bold;margin-bottom:6px;">Payload</div>';
      rh += '<pre style="margin:0;font-size:12px;color:var(--txt-2);white-space:pre-wrap;word-break:break-all;">' + esc(JSON.stringify(decoded.payload, null, 2)) + '</pre>';
      rh += '</div>';
      rh += '</div>';
      if (decoded.expiresIn) {
        var expColor = decoded.isExpired ? 'var(--bad)' : 'var(--ok)';
        rh += '<div style="margin-top:8px;padding:8px 12px;background:var(--card2);border:1px solid ' + expColor + ';border-radius:4px;font-size:12px;color:' + expColor + ';">';
        rh += (decoded.isExpired ? 'Token expired' : 'Token valid') + ' | ' + esc(decoded.expiresIn);
        rh += '</div>';
      }
      rh += '<div style="margin-top:8px;padding:8px 12px;background:var(--card2);border:1px solid var(--line);border-radius:4px;font-size:12px;color:var(--mut);">';
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
      if (!token) { result.innerHTML = '<div style="color:var(--bad);">No token provided.</div>'; return; }
      var entropy = _imEntropy(token);
      var rating = _imEntropyRating(entropy);
      var uniqueChars = Object.keys(token.split('').reduce(function(a, c) { a[c] = 1; return a; }, {})).length;
      var totalEntropy = entropy * token.length;
      var rh = '';
      rh += '<div style="background:var(--card2);padding:14px;border-radius:4px;border:1px solid var(--line);margin-top:8px;">';
      rh += '<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-bottom:12px;">';
      rh += '<div style="text-align:center;"><div style="color:' + rating.color + ';font-size:28px;font-weight:bold;">' + entropy.toFixed(3) + '</div><div style="color:var(--mut);font-size:12px;">Bits / char</div></div>';
      rh += '<div style="text-align:center;"><div style="color:var(--acc);font-size:28px;font-weight:bold;">' + totalEntropy.toFixed(0) + '</div><div style="color:var(--mut);font-size:12px;">Total bits</div></div>';
      rh += '<div style="text-align:center;"><div style="color:' + rating.color + ';font-size:28px;font-weight:bold;">' + esc(rating.label) + '</div><div style="color:var(--mut);font-size:12px;">Rating</div></div>';
      rh += '</div>';
      rh += '<div style="font-size:12px;color:var(--txt-2);line-height:1.8;">';
      rh += 'Token length: <span style="color:var(--acc);">' + token.length + ' chars</span><br>';
      rh += 'Unique characters: <span style="color:var(--acc);">' + uniqueChars + '</span><br>';
      rh += 'Character space: <span style="color:var(--acc);">' + (uniqueChars <= 16 ? 'Hex' : (uniqueChars <= 36 ? 'Alphanumeric' : (uniqueChars <= 64 ? 'Base64' : 'Extended'))) + '</span><br>';
      rh += 'Estimated brute-force complexity: <span style="color:var(--acc);">2^' + totalEntropy.toFixed(0) + ' ≈ 10^' + (totalEntropy * 0.301).toFixed(0) + '</span><br>';
      var bruteTime = totalEntropy > 128 ? 'Longer than the age of the universe' : (totalEntropy > 80 ? 'Billions of years' : (totalEntropy > 64 ? 'Centuries' : (totalEntropy > 48 ? 'Years' : (totalEntropy > 32 ? 'Days' : 'Seconds'))));
      rh += 'Estimated time to brute-force (1B/s): <span style="color:' + (totalEntropy > 64 ? 'var(--ok)' : 'var(--bad)') + ';">' + bruteTime + '</span>';
      rh += '</div></div>';
      result.innerHTML = rh;
    });
  }
};
