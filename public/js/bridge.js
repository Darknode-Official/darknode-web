// Darknode Bridge — connects to the local Darknode CLI
// Usage: import { bridge } from '/js/bridge.js';

class DarknodeBridge extends EventTarget {
  #ws = null;
  #authed = false;
  #queue = new Map();
  #counter = 0;
  #tools = [];
  #ollama = [];
  #hostname = '';

  get connected() { return this.#authed && this.#ws && this.#ws.readyState === WebSocket.OPEN; }
  get tools() { return this.#tools; }
  get ollamaModels() { return this.#ollama; }
  get hostname() { return this.#hostname; }

  probe(port) {
    port = port || 13337;
    return new Promise(function(resolve) {
      try {
        var ctrl = new AbortController();
        var timer = setTimeout(function() { ctrl.abort(); resolve(false); }, 1500);
        fetch('http://127.0.0.1:' + port + '/health', { signal: ctrl.signal })
          .then(function(r) { return r.json(); })
          .then(function(j) { clearTimeout(timer); resolve(j && j.status === 'ok'); })
          .catch(function() { clearTimeout(timer); resolve(false); });
      } catch (e) { resolve(false); }
    });
  }

  connect(token, port) {
    var self = this;
    port = port || 13337;
    return new Promise(function(resolve, reject) {
      if (self.#ws) try { self.#ws.close(); } catch (_) {}
      self.#authed = false;
      var ws = new WebSocket('ws://localhost:' + port);
      self.#ws = ws;
      var timeout = setTimeout(function() { ws.close(); reject(new Error('Connection timeout')); }, 5000);

      ws.onopen = function() {
        ws.send(JSON.stringify({ type: 'auth', token: token }));
      };

      ws.onmessage = function(e) {
        var msg;
        try { msg = JSON.parse(e.data); } catch (_) { return; }
        if (msg.type === 'auth_ok') {
          clearTimeout(timeout);
          self.#authed = true;
          self.#tools = msg.tools || [];
          self.#ollama = msg.ollama || [];
          self.#hostname = msg.hostname || '';
          self.dispatchEvent(new CustomEvent('connect', { detail: msg }));
          resolve(msg);
          return;
        }
        if (msg.type === 'auth_fail') {
          clearTimeout(timeout);
          ws.close();
          reject(new Error('Invalid token'));
          return;
        }
        if (msg.id && self.#queue.has(msg.id)) {
          self.#queue.get(msg.id)(msg);
        }
      };

      ws.onclose = function() {
        self.#authed = false;
        self.dispatchEvent(new Event('disconnect'));
      };

      ws.onerror = function() {
        clearTimeout(timeout);
        reject(new Error('Connection failed — is Darknode CLI running?'));
      };
    });
  }

  disconnect() {
    if (this.#ws) try { this.#ws.close(); } catch (_) {}
    this.#ws = null;
    this.#authed = false;
  }

  exec(cmd) {
    var self = this;
    return new Promise(function(resolve, reject) {
      if (!self.connected) return reject(new Error('CLI not connected'));
      var id = 'e' + (++self.#counter);
      var stdout = '', stderr = '';
      self.#queue.set(id, function(msg) {
        if (msg.type === 'stdout') stdout += msg.data;
        else if (msg.type === 'stderr') stderr += msg.data;
        else if (msg.type === 'exit') { self.#queue.delete(id); resolve({ stdout: stdout, stderr: stderr, code: msg.code }); }
        else if (msg.type === 'error') { self.#queue.delete(id); reject(new Error(msg.data)); }
      });
      self.#ws.send(JSON.stringify({ id: id, type: 'exec', cmd: cmd }));
    });
  }

  execStream(cmd, onData) {
    var self = this;
    return new Promise(function(resolve, reject) {
      if (!self.connected) return reject(new Error('CLI not connected'));
      var id = 'e' + (++self.#counter);
      self.#queue.set(id, function(msg) {
        if (msg.type === 'stdout' || msg.type === 'stderr') onData(msg.data, msg.type);
        else if (msg.type === 'exit') { self.#queue.delete(id); resolve(msg.code); }
        else if (msg.type === 'error') { self.#queue.delete(id); reject(new Error(msg.data)); }
      });
      self.#ws.send(JSON.stringify({ id: id, type: 'exec', cmd: cmd }));
    });
  }

  kill(id) {
    if (this.connected) this.#ws.send(JSON.stringify({ type: 'kill', id: id }));
  }

  streamAI(model, messages, onToken) {
    var self = this;
    return new Promise(function(resolve, reject) {
      if (!self.connected) return reject(new Error('CLI not connected'));
      var id = 'a' + (++self.#counter);
      self.#queue.set(id, function(msg) {
        if (msg.type === 'token') onToken(msg.data);
        else if (msg.type === 'done') { self.#queue.delete(id); resolve(); }
        else if (msg.type === 'error') { self.#queue.delete(id); reject(new Error(msg.data)); }
      });
      self.#ws.send(JSON.stringify({ id: id, type: 'ai', model: model, messages: messages }));
    });
  }

  hasTool(name) { return this.#tools.includes(name); }
}

export const bridge = new DarknodeBridge();
