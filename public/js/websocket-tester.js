// Copyright (c) 2026 Darknode-Official. All rights reserved.
// WebSocket Tester — test WebSocket connections, send messages, monitor frames

var esc = function(s) { return String(s != null ? s : '').replace(/[&<>"']/g, function(c) {
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); };

var _wsConnection = null;
var _wsLog = [];

window.renderWebSocketTester = function(container) {
  var h = '';
  h += '<div style="background:#0a0e14;color:#c8d6e5;font-family:\'Courier New\',monospace;padding:20px;min-height:500px;">';
  h += '<h2 style="color:#00ddff;font-size:18px;letter-spacing:2px;margin:0 0 4px;">WEBSOCKET TESTER</h2>';
  h += '<div style="color:#4a6a8a;font-size:11px;margin-bottom:20px;">Connect to any WebSocket endpoint, send messages, and monitor traffic</div>';

  // Connection
  h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:16px;margin-bottom:12px;">';
  h += '<div style="display:flex;gap:8px;margin-bottom:8px;">';
  h += '<input id="ws-url" style="flex:1;background:#080c14;border:1px solid #1a2a44;border-radius:4px;color:#c8d6e5;font-family:monospace;font-size:12px;padding:8px 12px;" placeholder="wss://echo.websocket.org" value="wss://echo.websocket.org">';
  h += '<button id="ws-connect-btn" onclick="_wsConnect()" style="background:#00ff8822;color:#00ff88;border:1px solid #00ff8844;padding:8px 16px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:4px;">CONNECT</button>';
  h += '<button onclick="_wsDisconnect()" style="background:#ff444422;color:#ff4444;border:1px solid #ff444444;padding:8px 12px;font-family:monospace;font-size:11px;cursor:pointer;border-radius:4px;">CLOSE</button>';
  h += '</div>';
  h += '<div id="ws-status" style="font-size:10px;color:#ff4444;">DISCONNECTED</div>';
  h += '</div>';

  // Send
  h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:16px;margin-bottom:12px;">';
  h += '<div style="display:flex;gap:8px;">';
  h += '<textarea id="ws-message" style="flex:1;background:#080c14;border:1px solid #1a2a44;border-radius:4px;color:#c8d6e5;font-family:monospace;font-size:11px;padding:8px 10px;resize:vertical;height:60px;" placeholder="Message to send..."></textarea>';
  h += '<div style="display:flex;flex-direction:column;gap:4px;">';
  h += '<button onclick="_wsSend()" style="background:#00aaff22;color:#00aaff;border:1px solid #00aaff44;padding:6px 14px;font-family:monospace;font-size:10px;cursor:pointer;border-radius:4px;">SEND</button>';
  h += '<button onclick="_wsSendJSON()" style="background:#aa66ff22;color:#aa66ff;border:1px solid #aa66ff44;padding:6px 14px;font-family:monospace;font-size:10px;cursor:pointer;border-radius:4px;">JSON</button>';
  h += '<button onclick="_wsClear()" style="background:#1a1a2a;color:#4a6a8a;border:1px solid #1a2a44;padding:6px 14px;font-family:monospace;font-size:10px;cursor:pointer;border-radius:4px;">CLEAR</button>';
  h += '</div></div></div>';

  // Log
  h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:14px;">';
  h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">';
  h += '<div style="color:#00aaff;font-size:12px;font-weight:bold;">MESSAGE LOG</div>';
  h += '<div id="ws-frame-count" style="color:#4a6a8a;font-size:10px;">0 frames</div>';
  h += '</div>';
  h += '<div id="ws-log" style="background:#060a10;border:1px solid #0d1525;border-radius:4px;padding:8px;max-height:400px;overflow-y:auto;font-size:10px;line-height:1.6;"></div>';
  h += '</div>';

  // Quick test endpoints
  h += '<div style="background:#0c1020;border:1px solid #1a2a44;border-radius:6px;padding:12px;margin-top:12px;">';
  h += '<div style="color:#4a6a8a;font-size:10px;margin-bottom:6px;">QUICK CONNECT:</div>';
  h += '<div style="display:flex;gap:4px;flex-wrap:wrap;">';
  var endpoints = [
    { url: 'wss://echo.websocket.org', label: 'Echo Server' },
    { url: 'wss://ws.postman-echo.com/raw', label: 'Postman Echo' },
    { url: 'wss://stream.binance.com:9443/ws/btcusdt@trade', label: 'Binance BTC' },
    { url: 'wss://stream.binance.com:9443/ws/ethusdt@trade', label: 'Binance ETH' }
  ];
  for (var ep = 0; ep < endpoints.length; ep++) {
    h += '<button onclick="document.getElementById(\'ws-url\').value=\'' + esc(endpoints[ep].url) + '\'" style="background:#0a1a28;border:1px solid #1a3050;color:#5a8aaa;padding:3px 8px;font-family:monospace;font-size:9px;cursor:pointer;border-radius:3px;">' + esc(endpoints[ep].label) + '</button>';
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
  entry.innerHTML = '<span style="color:#3a5a7a;margin-right:6px;">' + time + '</span>' +
    '<span style="color:' + color + ';margin-right:6px;">' + icon + ' ' + type.toUpperCase() + '</span>' +
    '<span style="color:#c8d6e5;word-break:break-all;' + (isJSON ? 'font-style:italic;' : '') + '">' + esc(truncated) + '</span>';
  entry.onclick = function() {
    try { navigator.clipboard.writeText(data); entry.style.borderLeftColor = '#ffaa00'; setTimeout(function() { entry.style.borderLeftColor = color; }, 500); } catch (e) {}
  };
  log.appendChild(entry);
  log.scrollTop = log.scrollHeight;

  _wsLog.push({ type: type, data: data, time: time });
  if (count) count.textContent = _wsLog.length + ' frames';
}

window._wsConnect = function() {
  var url = (document.getElementById('ws-url') || {}).value;
  var status = document.getElementById('ws-status');
  if (!url) return;

  if (_wsConnection) {
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
  if (!msg || !_wsConnection || _wsConnection.readyState !== 1) {
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
    }
  } catch (e) {
    _wsAddLog('error', 'Invalid JSON: ' + e.message);
  }
};

window._wsClear = function() {
  var log = document.getElementById('ws-log');
  if (log) log.innerHTML = '';
  _wsLog = [];
  var count = document.getElementById('ws-frame-count');
  if (count) count.textContent = '0 frames';
};
