#!/usr/bin/env node
'use strict';

// Darknode CLI — Local security operations server for darknode.ai
// Zero dependencies. Run: node darknode-cli.js
// Users download this and run it to unlock shell features + free local AI.

const http = require('http');
const crypto = require('crypto');
const { spawn, execSync } = require('child_process');
const os = require('os');

const PORT = parseInt(process.argv.find((_, i, a) => a[i - 1] === '--port') || '13337', 10);
const VERSION = '1.0.0';
const OLLAMA = 'http://127.0.0.1:11434';
const TOKEN = crypto.randomBytes(3).toString('hex').toUpperCase();

if (process.argv.includes('--help') || process.argv.includes('-h')) {
  console.log(`\n  Darknode CLI v${VERSION} — Local security operations server\n\n  Usage: node darknode-cli.js [--port <port>]\n\n  Starts a local server that darknode.ai connects to,\n  enabling real command execution and free AI via Ollama.\n\n  1. Run this script\n  2. Open darknode.ai → Settings → CLI\n  3. Enter the auth token shown in your terminal\n`);
  process.exit(0);
}

// ─── ANSI ──────────────────────────────────────────
const C = { r: '\x1b[0m', b: '\x1b[1m', dim: '\x1b[2m', red: '\x1b[91m', grn: '\x1b[92m', ylw: '\x1b[93m', blu: '\x1b[94m', mag: '\x1b[95m', cyn: '\x1b[96m', gry: '\x1b[90m', wht: '\x1b[97m' };
const ts = () => new Date().toLocaleTimeString('en-US', { hour12: false });
const info = (m) => console.log(`  ${C.gry}${ts()}${C.r}  ${C.cyn}[*]${C.r}  ${m}`);
const ok   = (m) => console.log(`  ${C.gry}${ts()}${C.r}  ${C.grn}[+]${C.r}  ${m}`);
const warn = (m) => console.log(`  ${C.gry}${ts()}${C.r}  ${C.ylw}[!]${C.r}  ${m}`);
const err  = (m) => console.log(`  ${C.gry}${ts()}${C.r}  ${C.red}[-]${C.r}  ${m}`);

// ─── Allowed Origins ───────────────────────────────
const ORIGINS = new Set([
  'https://darknode.ai', 'https://www.darknode.ai',
  'https://sentinel-b4194.web.app', 'https://sentinel-b4194-6173e.web.app',
  'http://localhost:5000', 'http://localhost:3000', 'http://127.0.0.1:5000', 'null'
]);

// ─── WebSocket Helpers ─────────────────────────────
function wsAccept(key) {
  return crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-5AB5DC587610').digest('base64');
}

function wsSend(sock, obj) {
  if (!sock || sock.destroyed) return;
  const buf = Buffer.from(typeof obj === 'string' ? obj : JSON.stringify(obj));
  let header;
  if (buf.length < 126) {
    header = Buffer.alloc(2); header[0] = 0x81; header[1] = buf.length;
  } else if (buf.length < 65536) {
    header = Buffer.alloc(4); header[0] = 0x81; header[1] = 126; header.writeUInt16BE(buf.length, 2);
  } else {
    header = Buffer.alloc(10); header[0] = 0x81; header[1] = 127; header.writeUInt32BE(0, 2); header.writeUInt32BE(buf.length, 6);
  }
  sock.write(Buffer.concat([header, buf]));
}

function wsParse(buffer) {
  if (buffer.length < 2) return null;
  const opcode = buffer[0] & 0x0f;
  const masked = (buffer[1] & 0x80) !== 0;
  let len = buffer[1] & 0x7f, off = 2;
  if (len === 126) { if (buffer.length < 4) return null; len = buffer.readUInt16BE(2); off = 4; }
  else if (len === 127) { if (buffer.length < 10) return null; len = Number(buffer.readUInt32BE(6)); off = 10; }
  const need = off + (masked ? 4 : 0) + len;
  if (buffer.length < need) return null;
  let payload;
  if (masked) {
    const mask = buffer.slice(off, off + 4); off += 4;
    payload = Buffer.alloc(len);
    for (let i = 0; i < len; i++) payload[i] = buffer[off + i] ^ mask[i & 3];
  } else { payload = buffer.slice(off, off + len); }
  return { opcode, payload, consumed: off + len };
}

// ─── Tool Detection ────────────────────────────────
const DETECT = [
  'nmap','masscan','sqlmap','hydra','john','hashcat','gobuster','dirb','nikto',
  'nuclei','subfinder','amass','dnsrecon','fierce','searchsploit','tcpdump',
  'tshark','msfconsole','msfvenom','aircrack-ng','responder','crackmapexec',
  'volatility','binwalk','foremost','exiftool','steghide','gdb','radare2',
  'ffuf','feroxbuster','wpscan','whatweb','python3','ruby','perl','docker',
  'git','curl','wget','openssl','ollama','ncat','socat','smbclient','wfuzz',
  'wafw00f','hashid','dig','whois','host','traceroute','nc'
];

function detectTools() {
  const found = [];
  const cmd = process.platform === 'win32' ? 'where' : 'which';
  for (const t of DETECT) {
    try { execSync(`${cmd} ${t} 2>/dev/null`, { stdio: 'pipe', timeout: 2000 }); found.push(t); } catch {}
  }
  return found;
}

// ─── Ollama Detection ──────────────────────────────
function fetchOllamaModels() {
  return new Promise((resolve) => {
    const req = http.get(OLLAMA + '/api/tags', { timeout: 3000 }, (res) => {
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => {
        try { resolve((JSON.parse(body).models || []).map(m => ({ name: m.name, size: m.size }))); }
        catch { resolve([]); }
      });
    });
    req.on('error', () => resolve([]));
    req.on('timeout', () => { req.destroy(); resolve([]); });
  });
}

// ─── Command Execution ────────────────────────────
const activeProcs = new Map();

function execCommand(id, cmd, sock) {
  console.log(`  ${C.gry}${ts()}${C.r}  ${C.blu}[>]${C.r}  ${C.b}${cmd}${C.r}`);
  const proc = spawn(cmd, { shell: true, cwd: os.homedir(), env: { ...process.env, TERM: 'xterm-256color' } });
  if (!activeProcs.has(sock)) activeProcs.set(sock, new Map());
  activeProcs.get(sock).set(id, proc);
  proc.stdout.on('data', (d) => wsSend(sock, { id, type: 'stdout', data: d.toString() }));
  proc.stderr.on('data', (d) => wsSend(sock, { id, type: 'stderr', data: d.toString() }));
  proc.on('close', (code) => {
    wsSend(sock, { id, type: 'exit', code: code || 0 });
    if (activeProcs.has(sock)) activeProcs.get(sock).delete(id);
    console.log(`  ${C.gry}${ts()}${C.r}  ${C.blu}[>]${C.r}  ${C.dim}exit ${code || 0}${C.r}`);
  });
  proc.on('error', (e) => {
    wsSend(sock, { id, type: 'error', data: e.message });
    if (activeProcs.has(sock)) activeProcs.get(sock).delete(id);
    err(e.message);
  });
}

// ─── AI Streaming (Ollama) ─────────────────────────
function streamAI(id, model, messages, sock) {
  console.log(`  ${C.gry}${ts()}${C.r}  ${C.mag}[~]${C.r}  ${model} ${C.dim}(${messages.length} msgs)${C.r}`);
  const body = JSON.stringify({ model, messages, stream: true });
  const url = new URL(OLLAMA + '/api/chat');
  const req = http.request({ hostname: url.hostname, port: url.port, path: url.pathname, method: 'POST', headers: { 'Content-Type': 'application/json' } }, (res) => {
    let buf = '';
    res.on('data', (chunk) => {
      buf += chunk.toString();
      let nl;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl).trim(); buf = buf.slice(nl + 1);
        if (!line) continue;
        try {
          const j = JSON.parse(line);
          if (j.message && j.message.content) wsSend(sock, { id, type: 'token', data: j.message.content });
          if (j.done) wsSend(sock, { id, type: 'done' });
        } catch {}
      }
    });
    res.on('end', () => wsSend(sock, { id, type: 'done' }));
  });
  req.on('error', (e) => { wsSend(sock, { id, type: 'error', data: 'Ollama: ' + e.message }); err('Ollama: ' + e.message); });
  req.write(body); req.end();
}

// ─── Server ────────────────────────────────────────
const clients = new Set();
let detectedTools = [];
let ollamaModels = [];

const server = http.createServer((req, res) => {
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    res.end(JSON.stringify({ status: 'ok', version: VERSION }));
    return;
  }
  if (req.method === 'OPTIONS') {
    res.writeHead(204, { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET', 'Access-Control-Allow-Headers': 'Content-Type' });
    res.end(); return;
  }
  res.writeHead(426); res.end('WebSocket required');
});

server.on('upgrade', (req, socket) => {
  const origin = req.headers.origin || '';
  if (!ORIGINS.has(origin) && !origin.startsWith('http://localhost:') && !origin.startsWith('http://127.0.0.1:')) {
    warn('Rejected origin: ' + origin); socket.destroy(); return;
  }
  const key = req.headers['sec-websocket-key'];
  if (!key) { socket.destroy(); return; }
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + wsAccept(key) + '\r\n\r\n');

  let authed = false, buf = Buffer.alloc(0);

  socket.on('data', (data) => {
    buf = Buffer.concat([buf, data]);
    while (buf.length > 0) {
      const frame = wsParse(buf);
      if (!frame) break;
      buf = buf.slice(frame.consumed);
      if (frame.opcode === 0x8) { socket.end(); return; }
      if (frame.opcode === 0x9) { const p = Buffer.alloc(2); p[0] = 0x8a; p[1] = 0; socket.write(p); continue; }
      if (frame.opcode !== 0x1) continue;
      let msg;
      try { msg = JSON.parse(frame.payload.toString()); } catch { continue; }

      if (!authed) {
        if (msg.type === 'auth' && msg.token === TOKEN) {
          authed = true; clients.add(socket);
          ok('Browser connected ' + C.dim + '(' + origin + ')' + C.r);
          wsSend(socket, { type: 'auth_ok', tools: detectedTools, ollama: ollamaModels, platform: process.platform, hostname: os.hostname() });
        } else { wsSend(socket, { type: 'auth_fail' }); warn('Bad auth token'); }
        continue;
      }

      switch (msg.type) {
        case 'exec': if (msg.cmd) execCommand(msg.id, msg.cmd, socket); break;
        case 'kill': {
          const procs = activeProcs.get(socket);
          if (procs && procs.has(msg.id)) { procs.get(msg.id).kill('SIGTERM'); procs.delete(msg.id); }
          break;
        }
        case 'ai': if (msg.model && msg.messages) streamAI(msg.id, msg.model, msg.messages, socket); break;
        case 'ping': wsSend(socket, { id: msg.id, type: 'pong' }); break;
        case 'tools': wsSend(socket, { type: 'tools', tools: detectedTools, ollama: ollamaModels }); break;
      }
    }
  });

  socket.on('close', () => {
    if (authed) {
      clients.delete(socket);
      const procs = activeProcs.get(socket);
      if (procs) { procs.forEach(p => { try { p.kill('SIGTERM'); } catch {} }); activeProcs.delete(socket); }
      warn('Browser disconnected');
    }
  });
  socket.on('error', () => { clients.delete(socket); activeProcs.delete(socket); });
});

// ─── Startup ───────────────────────────────────────
async function start() {
  console.log(`\n  ${C.b}${C.cyn}┌──────────────────────────────────────────┐${C.r}`);
  console.log(`  ${C.b}${C.cyn}│${C.r}  ${C.b}${C.wht}D A R K N O D E${C.r}   ${C.dim}CLI v${VERSION}${C.r}              ${C.b}${C.cyn}│${C.r}`);
  console.log(`  ${C.b}${C.cyn}│${C.r}  ${C.dim}Local Security Operations Server${C.r}         ${C.b}${C.cyn}│${C.r}`);
  console.log(`  ${C.b}${C.cyn}└──────────────────────────────────────────┘${C.r}\n`);

  info('Scanning for security tools...');
  detectedTools = detectTools();
  ok(`${detectedTools.length} tools: ${C.dim}${detectedTools.slice(0, 8).join(', ')}${detectedTools.length > 8 ? ' +' + (detectedTools.length - 8) + ' more' : ''}${C.r}`);

  info('Checking Ollama...');
  ollamaModels = await fetchOllamaModels();
  if (ollamaModels.length) ok(`Ollama: ${ollamaModels.map(m => m.name).join(', ')}`);
  else warn('Ollama not detected — install from ollama.com for free local AI');

  server.listen(PORT, '127.0.0.1', () => {
    ok(`WebSocket: ${C.b}ws://localhost:${PORT}${C.r}`);
    console.log();
    console.log(`  ${C.b}${C.ylw}  Auth Token: ${TOKEN}${C.r}`);
    console.log(`  ${C.dim}  Enter this in Darknode → Settings → CLI Connect${C.r}`);
    console.log();
    info('Waiting for browser connection...\n');
  });

  server.on('error', (e) => {
    if (e.code === 'EADDRINUSE') { err(`Port ${PORT} in use. Try: node darknode-cli.js --port ${PORT + 1}`); }
    else err(e.message);
    process.exit(1);
  });
}

process.on('SIGINT', () => {
  console.log(); warn('Shutting down...');
  clients.forEach(s => { try { s.end(); } catch {} });
  activeProcs.forEach(procs => procs.forEach(p => { try { p.kill('SIGTERM'); } catch {} }));
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 1000);
});

start();
