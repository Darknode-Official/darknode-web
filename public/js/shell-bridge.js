// Shell Bridge — shared WebSocket shell connection for all tools
// Any tool can import this to run real commands on the user's machine

var _shellWs = null;
var _shellStatus = 'disconnected';
var _shellCallbacks = {};
var _shellCmdId = 0;
var _shellHost = 'localhost';
var _shellPort = '8765';
var _shellReconnectTimer = null;
var _shellListeners = [];
var _shellEverConnected = false;
var _shellReconnectAttempts = 0;
var _shellMaxReconnectAttempts = 3;
var _shellAutoConnect = false;

function _shellLoadSettings() {
  try {
    var s = JSON.parse(localStorage.getItem('dn_shell_bridge') || '{}');
    if (s.host) _shellHost = s.host;
    if (s.port) _shellPort = s.port;
  } catch (_) {}
}

function _shellSaveSettings() {
  try { localStorage.setItem('dn_shell_bridge', JSON.stringify({ host: _shellHost, port: _shellPort })); } catch (_) {}
}

function _shellNotify() {
  for (var i = 0; i < _shellListeners.length; i++) {
    try { _shellListeners[i](_shellStatus); } catch (_) {}
  }
}

export function shellOnStatus(fn) {
  _shellListeners.push(fn);
}

export function shellStatus() {
  return _shellStatus;
}

export function shellConnect(host, port) {
  if (host) _shellHost = host;
  if (port) _shellPort = port;
  _shellSaveSettings();
  if (_shellWs && _shellWs.readyState <= 1) _shellWs.close();
  _shellStatus = 'connecting';
  _shellNotify();
  try {
    _shellWs = new WebSocket('ws://' + _shellHost + ':' + _shellPort);
    _shellWs.onopen = function() {
      _shellStatus = 'connected';
      _shellEverConnected = true;
      _shellReconnectAttempts = 0;
      _shellNotify();
      if (_shellReconnectTimer) { clearTimeout(_shellReconnectTimer); _shellReconnectTimer = null; }
    };
    _shellWs.onclose = function() {
      _shellStatus = 'disconnected';
      _shellNotify();
      if (_shellEverConnected && _shellReconnectAttempts < _shellMaxReconnectAttempts) {
        _shellReconnectAttempts++;
        if (!_shellReconnectTimer) _shellReconnectTimer = setTimeout(function() { _shellReconnectTimer = null; shellConnect(); }, 30000);
      }
    };
    _shellWs.onerror = function() {
      _shellStatus = 'disconnected';
      _shellNotify();
    };
    _shellWs.onmessage = function(e) {
      try {
        var msg = JSON.parse(e.data);
        if (msg.type === 'info') return;
        var id = msg.id || msg.cmdId;
        if (id && _shellCallbacks[id]) {
          _shellCallbacks[id](msg);
          delete _shellCallbacks[id];
        } else if (!id && (msg.type === 'output' || msg.type === 'error')) {
          var keys = Object.keys(_shellCallbacks);
          if (keys.length > 0) {
            _shellCallbacks[keys[0]](msg);
            delete _shellCallbacks[keys[0]];
          }
        }
      } catch (_) {}
    };
  } catch (_) {
    _shellStatus = 'disconnected';
    _shellNotify();
  }
}

export function shellDisconnect() {
  if (_shellReconnectTimer) { clearTimeout(_shellReconnectTimer); _shellReconnectTimer = null; }
  if (_shellWs) _shellWs.close();
  _shellStatus = 'disconnected';
  _shellNotify();
}

export function shellExec(cmd, callback, timeout) {
  if (_shellStatus !== 'connected' || !_shellWs) {
    if (callback) callback({ type: 'error', data: 'Not connected to shell server.' });
    return false;
  }
  var id = 'cmd_' + (++_shellCmdId) + '_' + Date.now();
  var to = timeout || 30000;
  _shellCallbacks[id] = callback;
  setTimeout(function() {
    if (_shellCallbacks[id]) {
      _shellCallbacks[id]({ type: 'error', data: 'Command timed out after ' + (to / 1000) + 's' });
      delete _shellCallbacks[id];
    }
  }, to);
  _shellWs.send(JSON.stringify({ type: 'exec', cmd: cmd, id: id }));
  return true;
}

export function shellIsConnected() {
  return _shellStatus === 'connected';
}

var _esc = function(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function(c) { return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); };

export function shellRunUI(cmd, container, options) {
  var opts = options || {};
  var label = opts.label || cmd.split(' ')[0];

  if (_shellStatus !== 'connected') {
    container.innerHTML =
      '<div class="sb-disconnected">' +
      '<div class="sb-title">Shell Server Required</div>' +
      '<p class="sb-desc">This action runs <code>' + _esc(cmd) + '</code> on your machine. Start the shell server to enable it.</p>' +
      '<div class="sb-steps">' +
      '<div class="sb-step">1. Open a terminal on your machine</div>' +
      '' +
      '<div class="sb-step">2. Run: <code>darknode-serve</code></div>' +
      '<div class="sb-step">3. <button class="sb-connect-btn" id="sb-connect-' + _shellCmdId + '">Connect</button></div>' +
      '</div>' +
      '<a class="sb-download" href="/tools/darknode-shell-server.py" download>Download Shell Server</a>' +
      '</div>';
    var connectBtn = container.querySelector('#sb-connect-' + _shellCmdId);
    if (connectBtn) {
      connectBtn.onclick = function() {
        shellConnect();
        container.innerHTML = '<div class="sb-loading">Connecting...</div>';
        var checkInterval = setInterval(function() {
          if (_shellStatus === 'connected') {
            clearInterval(checkInterval);
            shellRunUI(cmd, container, options);
          } else if (_shellStatus === 'disconnected') {
            clearInterval(checkInterval);
            container.innerHTML = '<div class="sb-error">Connection failed. Make sure the shell server is running.</div>';
          }
        }, 500);
        setTimeout(function() { clearInterval(checkInterval); }, 10000);
      };
    }
    return;
  }

  container.innerHTML =
    '<div class="sb-running">' +
    '<div class="sb-cmd-label">Running: <code>' + _esc(cmd) + '</code></div>' +
    '<div class="sb-spinner"></div>' +
    '</div>';

  shellExec(cmd, function(result) {
    var output = (result.data || result.output || result.error || 'No output');
    var isError = result.type === 'error';
    container.innerHTML =
      '<div class="sb-result ' + (isError ? 'sb-result-error' : 'sb-result-ok') + '">' +
      '<div class="sb-cmd-label">' + _esc(label) + ' ' + (isError ? 'failed' : 'complete') + '</div>' +
      '<pre class="sb-output">' + _esc(output) + '</pre>' +
      '</div>';
  }, opts.timeout || 60000);
}

export function shellAI(prompt, callback, model) {
  var m = model || 'llama3.2';
  if (_shellStatus !== 'connected') {
    // Fallback: try direct Ollama HTTP
    try {
      var xhr = new XMLHttpRequest();
      xhr.open('POST', 'http://127.0.0.1:11434/api/generate', true);
      xhr.setRequestHeader('Content-Type', 'application/json');
      xhr.timeout = 120000;
      xhr.onload = function() {
        try {
          var resp = JSON.parse(xhr.responseText);
          callback(null, resp.response || resp.message || xhr.responseText);
        } catch (e) { callback(null, xhr.responseText); }
      };
      xhr.onerror = function() { callback('AI unavailable. Start the shell server or run: ollama serve'); };
      xhr.ontimeout = function() { callback('AI request timed out'); };
      xhr.send(JSON.stringify({ model: m, prompt: prompt, stream: false }));
    } catch (e) { callback('AI unavailable. Start the shell server or run: ollama serve'); }
    return;
  }
  // Use shell to run ollama
  var safePrompt = prompt.replace(/'/g, "'\\''");
  var cmd = "ollama run " + m + " '" + safePrompt + "' 2>&1";
  shellExec(cmd, function(result) {
    if (result.type === 'error') { callback(result.data || 'AI error'); }
    else { callback(null, result.data || result.output || ''); }
  }, 120000);
}

export function shellAIAvailable(callback) {
  if (_shellStatus === 'connected') {
    shellExec('ollama list 2>&1 | head -5', function(result) {
      var output = result.data || result.output || '';
      callback(output.indexOf('NAME') !== -1 || output.indexOf('llama') !== -1 || output.indexOf(':') !== -1);
    }, 5000);
    return;
  }
  // Try direct HTTP
  try {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'http://127.0.0.1:11434/api/tags', true);
    xhr.timeout = 3000;
    xhr.onload = function() { callback(true); };
    xhr.onerror = function() { callback(false); };
    xhr.ontimeout = function() { callback(false); };
    xhr.send();
  } catch (e) { callback(false); }
}

export function shellAIUI(prompt, container, options) {
  var opts = options || {};
  var model = opts.model || 'llama3.2';
  container.innerHTML = '<div class="sb-running"><div class="sb-cmd-label">AI analyzing...</div><div class="sb-spinner"></div></div>';
  shellAI(prompt, function(err, response) {
    if (err) {
      container.innerHTML =
        '<div class="sb-disconnected">' +
        '<div class="sb-title">AI Analysis Requires Ollama</div>' +
        '<div class="sb-steps">' +
        '<div class="sb-step">1. Install: <code>curl -fsSL https://ollama.com/install.sh | sh</code></div>' +
        '<div class="sb-step">2. Pull a model: <code>ollama pull llama3.2</code></div>' +
        '<div class="sb-step">3. It connects automatically via the shell server</div>' +
        '</div></div>';
    } else {
      container.innerHTML =
        '<div class="sb-result sb-result-ok">' +
        '<div class="sb-cmd-label">AI Analysis Complete</div>' +
        '<pre class="sb-output" style="white-space:pre-wrap;word-wrap:break-word">' + _esc(response) + '</pre>' +
        '</div>';
    }
  }, model);
}

_shellLoadSettings();

// Do NOT auto-connect on page load — wait for explicit user action
// This prevents WebSocket spam in console on every page load
_shellLoadSettings();
