// Copyright (c) 2026 Darknode-Official. All rights reserved.
// WebSocket Tester — test WebSocket connections, send messages, monitor frames

var esc = function(s) { return String(s != null ? s : '').replace(/[&<>"']/g, function(c) {
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); };

var _wsConnection = null;
var _wsLog = [];
var _wsTotal = 0;
var WS_KEEP = 1000; // a busy stream (dozens of frames a second) would otherwise grow the page until the tab stalls

export function renderWebSocketTester(container) {
  var h = '';
  h += '<div>';
  h += '<div class="pg-head"><div><h1 class="pg-h1">WebSocket Tester</h1>';
  h += '<p class="muted pg-sub">Connect to any WebSocket endpoint, send messages and monitor traffic.</p></div></div>';

  // Connection
  h += '<div class="card">';
  h += '<div style="display:flex;gap:8px;margin-bottom:8px;">';
  h += '<input id="ws-url" style="flex:1;" placeholder="wss://echo.websocket.org">';
  h += '<button class="btn" id="ws-connect-btn" onclick="_wsConnect()">Connect</button>';
  h += '<button class="btn ghost" onclick="_wsDisconnect()">Close</button>';
  h += '</div>';
  h += '<div id="ws-status" style="font-size:12px;color:var(--bad);">DISCONNECTED</div>';
  h += '</div>';

  // Send
  h += '<div class="card">';
  h += '<div style="display:flex;gap:8px;">';
  h += '<textarea id="ws-message" style="flex:1;font-family:monospace;font-size:12px;resize:vertical;height:60px;" placeholder="Message to send..."></textarea>';
  h += '<div style="display:flex;flex-direction:column;gap:4px;">';
  h += '<button class="btn sm" onclick="_wsSend()">Send</button>';
  h += '<button class="btn ghost sm" onclick="_wsSendJSON()">JSON</button>';
  h += '<button class="btn ghost sm" onclick="_wsClear()">Clear</button>';
  h += '</div></div></div>';

  // Log
  h += '<div class="card">';
  h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">';
  h += '<div style="color:var(--txt);font-size:14px;font-weight:600;">Message log</div>';
  h += '<div id="ws-frame-count" style="color:var(--mut);font-size:12px;">0 frames</div>';
  h += '</div>';
  h += '<div id="ws-log" style="background:var(--card2);border:1px solid var(--line);border-radius:4px;padding:8px;max-height:400px;overflow-y:auto;font-size:12px;line-height:1.6;"></div>';
  h += '</div>';

  // Quick test endpoints
  h += '<div class="card">';
  h += '<div style="color:var(--mut);font-size:12px;margin-bottom:6px;">Quick connect</div>';
  h += '<div style="display:flex;gap:4px;flex-wrap:wrap;">';
  var endpoints = [
    { url: 'wss://echo.websocket.org', label: 'Echo Server' },
    { url: 'wss://ws.postman-echo.com/raw', label: 'Postman Echo' },
    { url: 'wss://stream.binance.com:9443/ws/btcusdt@trade', label: 'Binance BTC' },
    { url: 'wss://stream.binance.com:9443/ws/ethusdt@trade', label: 'Binance ETH' }
  ];
  for (var ep = 0; ep < endpoints.length; ep++) {
    h += '<button onclick="document.getElementById(\'ws-url\').value=\'' + esc(endpoints[ep].url) + '\'" class="btn ghost sm">' + esc(endpoints[ep].label) + '</button>';
  }
  h += '</div></div>';

  h += '</div>';
  container.innerHTML = h;
};

function _wsAddLog(type, data) {
  var log = document.getElementById('ws-log');
  var count = document.getElementById('ws-frame-count');
  if (!log) return;

  var time = new Date().toISOString().substring(11, 23);
  var color = type === 'sent' ? '#00aaff' : type === 'received' ? '#00ff88' : type === 'error' ? '#ff4444' : '#ffaa00';
  var icon = type === 'sent' ? '&#8593;' : type === 'received' ? '&#8595;' : type === 'error' ? '&#9888;' : '&#9679;';

  var truncated = data.length > 2000 ? data.substring(0, 2000) + '... (' + data.length + ' chars)' : data;
  var isJSON = false;
  try { JSON.parse(data); isJSON = true; } catch (e) {}

  var entry = document.createElement('div');
  entry.style.cssText = 'margin:2px 0;padding:3px 6px;border-left:2px solid ' + color + ';background:' + color + '08;border-radius:0 3px 3px 0;cursor:pointer;';
  entry.innerHTML = '<span style="color:var(--mut);margin-right:6px;">' + time + '</span>' +
    '<span style="color:' + color + ';margin-right:6px;">' + icon + ' ' + type.toUpperCase() + '</span>' +
    '<span style="color:var(--txt);word-break:break-all;' + (isJSON ? 'font-style:italic;' : '') + '">' + esc(truncated) + '</span>';
  entry.onclick = function() {
    try { navigator.clipboard.writeText(data); entry.style.borderLeftColor = '#ffaa00'; setTimeout(function() { entry.style.borderLeftColor = color; }, 500); } catch (e) {}
  };
  var atBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 40; // don't yank the view while someone reads older frames
  log.appendChild(entry);
  if (atBottom) log.scrollTop = log.scrollHeight;

  _wsLog.push({ type: type, data: data, time: time });
  _wsTotal++;
  while (_wsLog.length > WS_KEEP) { _wsLog.shift(); if (log.firstChild) log.removeChild(log.firstChild); }
  if (count) count.textContent = _wsTotal + ' frames' + (_wsTotal > WS_KEEP ? ' (last ' + WS_KEEP + ' shown)' : '');
}

window._wsConnect = function() {
  var url = (document.getElementById('ws-url') || {}).value;
  var status = document.getElementById('ws-status');
  if (!url) return;

  if (_wsConnection) {
    // Detach first: the old socket's late onclose would otherwise null out
    // the new connection and mark it DISCONNECTED.
    _wsConnection.onopen = _wsConnection.onmessage = _wsConnection.onclose = _wsConnection.onerror = null;
    try { _wsConnection.close(); } catch (e) {}
  }

  if (status) { status.textContent = 'CONNECTING...'; status.style.color = '#ffaa00'; }
  _wsAddLog('info', 'Connecting to ' + url + '...');

  try {
    _wsConnection = new WebSocket(url);

    _wsConnection.onopen = function() {
      if (status) { status.textContent = 'CONNECTED'; status.style.color = '#00ff88'; }
      _wsAddLog('info', 'Connection established');
    };

    _wsConnection.onmessage = function(e) {
      _wsAddLog('received', typeof e.data === 'string' ? e.data : '[Binary: ' + e.data.size + ' bytes]');
    };

    _wsConnection.onclose = function(e) {
      if (status) { status.textContent = 'DISCONNECTED (code: ' + e.code + ')'; status.style.color = '#ff4444'; }
      _wsAddLog('info', 'Connection closed — code: ' + e.code + (e.reason ? ' reason: ' + e.reason : ''));
      _wsConnection = null;
    };

    _wsConnection.onerror = function() {
      if (status) { status.textContent = 'ERROR'; status.style.color = '#ff4444'; }
      _wsAddLog('error', 'WebSocket error — connection failed or was rejected');
    };
  } catch (err) {
    if (status) { status.textContent = 'FAILED'; status.style.color = '#ff4444'; }
    _wsAddLog('error', 'Failed to create WebSocket: ' + String(err.message || err));
  }
};

window._wsDisconnect = function() {
  if (_wsConnection) {
    _wsConnection.close();
    _wsConnection = null;
  }
};

window._wsSend = function() {
  var msg = (document.getElementById('ws-message') || {}).value;
  if (!msg) return;
  if (!_wsConnection || _wsConnection.readyState !== 1) {
    _wsAddLog('error', _wsConnection ? 'WebSocket not ready (state: ' + _wsConnection.readyState + ')' : 'Not connected');
    return;
  }
  _wsConnection.send(msg);
  _wsAddLog('sent', msg);
};

window._wsSendJSON = function() {
  var msg = (document.getElementById('ws-message') || {}).value;
  if (!msg) return;
  try {
    var obj = JSON.parse(msg);
    var formatted = JSON.stringify(obj);
    if (_wsConnection && _wsConnection.readyState === 1) {
      _wsConnection.send(formatted);
      _wsAddLog('sent', formatted);
    } else {
      _wsAddLog('error', 'Not connected');
    }
  } catch (e) {
    _wsAddLog('error', 'Invalid JSON: ' + e.message);
  }
};

window._wsClear = function() {
  var log = document.getElementById('ws-log');
  if (log) log.innerHTML = '';
  _wsLog = [];
  _wsTotal = 0;
  var count = document.getElementById('ws-frame-count');
  if (count) count.textContent = '0 frames';
};
