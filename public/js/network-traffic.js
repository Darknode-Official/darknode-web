import { esc } from '/js/shared.js';

const NT_PROTOCOLS = ['TCP','UDP','ICMP','DNS','HTTP','HTTPS','SSH','FTP','SMTP','TELNET'];
const NT_FLAGS = ['SYN','ACK','FIN','RST','PSH','URG'];
const NT_STATES = ['ESTABLISHED','SYN_SENT','SYN_RECEIVED','FIN_WAIT_1','FIN_WAIT_2','TIME_WAIT','CLOSE_WAIT','LAST_ACK','CLOSING','CLOSED'];

function _randIP(internal){
  if(internal) return `192.168.${Math.floor(Math.random()*5)}.${Math.floor(Math.random()*254)+1}`;
  const o = [Math.floor(Math.random()*223)+1,Math.floor(Math.random()*256),Math.floor(Math.random()*256),Math.floor(Math.random()*254)+1];
  return o.join('.');
}
function _randPort(proto){
  const well = {HTTP:80,HTTPS:443,SSH:22,FTP:21,SMTP:25,DNS:53,TELNET:23};
  if(well[proto] && Math.random()>0.3) return well[proto];
  return Math.floor(Math.random()*64511)+1025;
}
function _randSize(proto){
  const bases = {DNS:[40,120],ICMP:[56,128],TCP:[40,1460],UDP:[28,512],HTTP:[200,4096],HTTPS:[200,8192],SSH:[80,600],FTP:[60,2048],SMTP:[100,3000],TELNET:[20,200]};
  const [lo,hi] = bases[proto]||[40,1460];
  return Math.floor(Math.random()*(hi-lo))+lo;
}
function _randFlags(proto){
  if(proto==='ICMP'||proto==='UDP'||proto==='DNS') return [];
  const n = Math.floor(Math.random()*3)+1;
  const f = [];
  const pool = [...NT_FLAGS];
  for(let i=0;i<n;i++){const idx=Math.floor(Math.random()*pool.length);f.push(pool.splice(idx,1)[0]);}
  return f;
}
function _randPayload(proto){
  const payloads = {
    HTTP:['GET / HTTP/1.1\\r\\nHost: example.com','POST /api/data HTTP/1.1\\r\\nContent-Type: application/json','HTTP/1.1 200 OK\\r\\nContent-Length: 1024','GET /login?user=admin HTTP/1.1'],
    HTTPS:['[TLS 1.3 Client Hello]','[TLS 1.3 Application Data]','[TLS 1.2 Change Cipher Spec]','[TLS Encrypted Alert]'],
    DNS:['Standard query A example.com','Standard query response CNAME cdn.example.com','Standard query AAAA api.internal','Standard query PTR 1.168.192.in-addr.arpa'],
    SSH:['SSH-2.0-OpenSSH_9.6','[SSH Encrypted Packet]','[Key Exchange Init]','[Diffie-Hellman Key Exchange]'],
    ICMP:['Echo (ping) request','Echo (ping) reply','Destination unreachable','Time exceeded'],
    FTP:['220 FTP server ready','USER anonymous','PASS guest@','LIST','RETR secret.zip'],
    SMTP:['EHLO mail.example.com','MAIL FROM:<admin@corp.com>','RCPT TO:<user@target.com>','DATA'],
    TELNET:['login: ','Password: ','$ whoami','$ cat /etc/passwd'],
    TCP:['[TCP segment of reassembled PDU]','[TCP Keep-Alive]','[TCP Retransmission]','[TCP Window Update]'],
    UDP:['[UDP Datagram]','[QUIC Initial]','[NTP Time Request]','[SNMP GetRequest]']
  };
  const list = payloads[proto]||payloads.TCP;
  return list[Math.floor(Math.random()*list.length)];
}

function _genPacket(){
  const proto = NT_PROTOCOLS[Math.floor(Math.random()*NT_PROTOCOLS.length)];
  const inbound = Math.random()>0.5;
  return {
    ts: new Date(),
    src: inbound ? _randIP(false) : _randIP(true),
    srcPort: _randPort(proto==='DNS'&&!inbound?'TCP':proto),
    dst: inbound ? _randIP(true) : _randIP(false),
    dstPort: _randPort(proto),
    proto,
    size: _randSize(proto),
    flags: _randFlags(proto),
    payload: _randPayload(proto),
    id: Math.random().toString(36).slice(2,10)
  };
}

function _fmtTime(d){ return d.toLocaleTimeString('en-US',{hour12:false})+'.'+String(d.getMilliseconds()).padStart(3,'0'); }

export function renderNetworkTraffic(container){
  const packets = [];
  let feedInterval = null;
  let paused = false;
  let maxPackets = 500;
  let activeTab = 'feed';
  let filterProto = '';
  let filterIP = '';
  let anomalies = [];

  const s = document.createElement('style');
  s.textContent = `
.nt-wrap{background:#080c14;color:#c8d6e5;font-family:'Courier New',monospace;min-height:100vh;padding:0;}
.nt-header{background:linear-gradient(135deg,#0a1628,#0f1f3a);padding:16px 24px;border-bottom:1px solid #1a2a44;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;}
.nt-header h2{margin:0;font-size:20px;color:#00aaff;letter-spacing:2px;text-transform:uppercase;}
.nt-header-stats{display:flex;gap:16px;font-size:12px;color:#6a8a9e;}
.nt-header-stats span{color:#00ff88;}
.nt-tabs{display:flex;background:#0a1020;border-bottom:1px solid #1a2a44;overflow-x:auto;}
.nt-tab{padding:10px 18px;background:none;border:none;color:#6a8a9e;cursor:pointer;font-family:inherit;font-size:12px;text-transform:uppercase;letter-spacing:1px;border-bottom:2px solid transparent;white-space:nowrap;transition:all .2s;}
.nt-tab:hover{color:#c8d6e5;background:#0d1520;}
.nt-tab.active{color:#00aaff;border-bottom-color:#00aaff;}
.nt-content{padding:16px 20px;}
.nt-controls{display:flex;gap:10px;margin-bottom:14px;flex-wrap:wrap;align-items:center;}
.nt-btn{background:#1a2a44;color:#c8d6e5;border:1px solid #2a3a54;padding:6px 14px;border-radius:4px;cursor:pointer;font-family:inherit;font-size:12px;transition:all .2s;}
.nt-btn:hover{background:#2a3a54;border-color:#00aaff;}
.nt-btn.active{background:#00aaff;color:#080c14;border-color:#00aaff;}
.nt-btn.danger{border-color:#ff4444;}
.nt-btn.danger:hover{background:#ff4444;color:#fff;}
.nt-input,.nt-select{background:#0a1020;color:#c8d6e5;border:1px solid #1a2a44;padding:6px 10px;border-radius:4px;font-family:inherit;font-size:12px;}
.nt-input:focus,.nt-select:focus{border-color:#00aaff;outline:none;}
.nt-feed{max-height:60vh;overflow-y:auto;border:1px solid #1a2a44;border-radius:4px;background:#060a10;}
.nt-feed::-webkit-scrollbar{width:6px;}
.nt-feed::-webkit-scrollbar-thumb{background:#1a2a44;border-radius:3px;}
.nt-pkt{display:grid;grid-template-columns:90px 160px 160px 60px 55px 90px 1fr;gap:4px;padding:5px 10px;border-bottom:1px solid #0d1520;font-size:11px;align-items:center;transition:background .15s;}
.nt-pkt:hover{background:#0d1828;}
.nt-pkt-head{background:#0a1020;color:#6a8a9e;font-weight:bold;text-transform:uppercase;letter-spacing:1px;position:sticky;top:0;z-index:2;border-bottom:2px solid #1a2a44;}
.nt-proto{padding:2px 6px;border-radius:3px;font-size:10px;font-weight:bold;text-align:center;display:inline-block;}
.nt-proto-TCP{background:#1a3a5c;color:#00aaff;}
.nt-proto-UDP{background:#2a1a4c;color:#bb86fc;}
.nt-proto-ICMP{background:#3a2a1a;color:#ffa726;}
.nt-proto-DNS{background:#1a3a2a;color:#00ff88;}
.nt-proto-HTTP{background:#3a1a1a;color:#ff4444;}
.nt-proto-HTTPS{background:#1a2a1a;color:#66bb6a;}
.nt-proto-SSH{background:#1a1a3a;color:#7c8fff;}
.nt-proto-FTP{background:#3a3a1a;color:#ffd600;}
.nt-proto-SMTP{background:#2a1a3a;color:#ce93d8;}
.nt-proto-TELNET{background:#3a1a2a;color:#ef5350;}
.nt-flags{font-size:10px;color:#8ab4c8;}
.nt-flag{background:#1a2a3a;padding:1px 4px;border-radius:2px;margin-right:2px;display:inline-block;}
.nt-flag-SYN{color:#00ff88;}
.nt-flag-ACK{color:#00aaff;}
.nt-flag-FIN{color:#ffa726;}
.nt-flag-RST{color:#ff4444;}
.nt-flag-PSH{color:#bb86fc;}
.nt-flag-URG{color:#ffd600;}
.nt-payload{color:#6a8a9e;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.nt-panel{background:#0a1020;border:1px solid #1a2a44;border-radius:6px;padding:16px;margin-bottom:16px;}
.nt-panel h3{margin:0 0 12px;font-size:14px;color:#00aaff;text-transform:uppercase;letter-spacing:1px;}
.nt-stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px;}
.nt-stat{background:#0d1520;border:1px solid #1a2a44;border-radius:6px;padding:14px;text-align:center;}
.nt-stat-val{font-size:28px;font-weight:bold;color:#00ff88;}
.nt-stat-label{font-size:11px;color:#6a8a9e;text-transform:uppercase;margin-top:4px;}
.nt-bar-chart{margin-top:12px;}
.nt-bar-row{display:flex;align-items:center;margin-bottom:6px;gap:8px;}
.nt-bar-label{width:60px;font-size:11px;color:#8ab4c8;text-align:right;}
.nt-bar-track{flex:1;height:18px;background:#0d1520;border-radius:3px;overflow:hidden;position:relative;}
.nt-bar-fill{height:100%;border-radius:3px;transition:width .4s;}
.nt-bar-pct{position:absolute;right:6px;top:1px;font-size:10px;color:#c8d6e5;}
.nt-talker-table{width:100%;border-collapse:collapse;font-size:12px;}
.nt-talker-table th{background:#0d1520;color:#6a8a9e;text-align:left;padding:8px 12px;border-bottom:2px solid #1a2a44;text-transform:uppercase;font-size:10px;letter-spacing:1px;}
.nt-talker-table td{padding:8px 12px;border-bottom:1px solid #0d1520;color:#c8d6e5;}
.nt-talker-table tr:hover td{background:#0d1828;}
.nt-anomaly{background:#1a0a0a;border:1px solid #3a1a1a;border-left:3px solid #ff4444;border-radius:4px;padding:12px 16px;margin-bottom:10px;}
.nt-anomaly-type{font-size:11px;text-transform:uppercase;color:#ff4444;font-weight:bold;letter-spacing:1px;margin-bottom:4px;}
.nt-anomaly-desc{font-size:12px;color:#c8d6e5;}
.nt-anomaly-meta{font-size:10px;color:#6a8a9e;margin-top:6px;}
.nt-anomaly.warn{border-left-color:#ffa726;background:#1a1a0a;}
.nt-anomaly.warn .nt-anomaly-type{color:#ffa726;}
.nt-filter-builder{display:flex;flex-direction:column;gap:12px;}
.nt-filter-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap;}
.nt-filter-row label{font-size:12px;color:#6a8a9e;min-width:80px;}
.nt-bpf-preview{background:#060a10;border:1px solid #1a2a44;border-radius:4px;padding:12px;font-size:13px;color:#00ff88;min-height:40px;margin-top:10px;}
.nt-bpf-ref{margin-top:16px;}
.nt-bpf-ref table{width:100%;border-collapse:collapse;font-size:12px;}
.nt-bpf-ref th{background:#0d1520;color:#6a8a9e;text-align:left;padding:6px 10px;border-bottom:1px solid #1a2a44;}
.nt-bpf-ref td{padding:6px 10px;border-bottom:1px solid #0d1520;color:#c8d6e5;}
.nt-bpf-ref code{background:#1a2a3a;padding:2px 6px;border-radius:3px;color:#00aaff;font-size:11px;}
.nt-export-area{background:#060a10;border:1px solid #1a2a44;border-radius:4px;padding:12px;font-size:11px;color:#8ab4c8;min-height:200px;max-height:50vh;overflow-y:auto;white-space:pre;font-family:inherit;}
.nt-live-dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:#00ff88;margin-right:6px;animation:nt-pulse 1.5s infinite;}
.nt-live-dot.paused{background:#ffa726;animation:none;}
@keyframes nt-pulse{0%,100%{opacity:1;}50%{opacity:.3;}}
.nt-conn-table{width:100%;border-collapse:collapse;font-size:12px;margin-top:12px;}
.nt-conn-table th{background:#0d1520;color:#6a8a9e;text-align:left;padding:6px 10px;border-bottom:2px solid #1a2a44;text-transform:uppercase;font-size:10px;}
.nt-conn-table td{padding:6px 10px;border-bottom:1px solid #0d1520;color:#c8d6e5;}
.nt-state{padding:2px 6px;border-radius:3px;font-size:10px;font-weight:bold;}
.nt-state-ESTABLISHED{background:#1a3a2a;color:#00ff88;}
.nt-state-SYN_SENT,.nt-state-SYN_RECEIVED{background:#1a2a3a;color:#00aaff;}
.nt-state-TIME_WAIT,.nt-state-FIN_WAIT_1,.nt-state-FIN_WAIT_2{background:#2a2a1a;color:#ffa726;}
.nt-state-CLOSE_WAIT,.nt-state-LAST_ACK,.nt-state-CLOSING{background:#2a1a1a;color:#ff4444;}
.nt-state-CLOSED{background:#1a1a1a;color:#6a8a9e;}
.nt-empty{text-align:center;padding:40px;color:#4a5a6a;font-size:13px;}
@media(max-width:900px){
  .nt-pkt{grid-template-columns:80px 1fr 1fr 50px 45px 70px;font-size:10px;}
  .nt-pkt .nt-payload{display:none;}
  .nt-stats-grid{grid-template-columns:1fr 1fr;}
}
@media(max-width:600px){
  .nt-pkt{grid-template-columns:70px 1fr 1fr 45px;font-size:10px;}
  .nt-pkt .nt-flags,.nt-pkt .nt-payload{display:none;}
  .nt-header{padding:12px 16px;}
  .nt-content{padding:12px;}
  .nt-stats-grid{grid-template-columns:1fr;}
}
`;
  container.innerHTML = '';
  container.appendChild(s);

  const wrap = document.createElement('div');
  wrap.className = 'nt-wrap';
  container.appendChild(wrap);

  function getProtoCounts(){
    const c = {};
    packets.forEach(p => { c[p.proto] = (c[p.proto]||0)+1; });
    return c;
  }
  function getTotalBytes(){ return packets.reduce((s,p) => s+p.size, 0); }

  function getTopTalkers(){
    const ips = {};
    packets.forEach(p => {
      [p.src,p.dst].forEach(ip => {
        if(!ips[ip]) ips[ip] = {ip, pkts:0, bytes:0, protos:new Set()};
        ips[ip].pkts++;
        ips[ip].bytes += p.size;
        ips[ip].protos.add(p.proto);
      });
    });
    return Object.values(ips).sort((a,b) => b.pkts - a.pkts).slice(0,20);
  }

  function detectAnomalies(){
    const results = [];
    const srcPorts = {};
    packets.forEach(p => {
      const k = p.src;
      if(!srcPorts[k]) srcPorts[k] = new Set();
      srcPorts[k].add(p.dstPort);
    });
    Object.entries(srcPorts).forEach(([ip,ports]) => {
      if(ports.size > 15){
        results.push({type:'Port Scan Detected',severity:'high',desc:`${esc(ip)} connected to ${ports.size} distinct destination ports`,meta:`Ports: ${[...ports].slice(0,10).join(', ')}${ports.size>10?'...':''}`});
      }
    });

    const dnsPkts = packets.filter(p => p.proto === 'DNS');
    const dnsBySrc = {};
    dnsPkts.forEach(p => { dnsBySrc[p.src] = (dnsBySrc[p.src]||0)+1; });
    Object.entries(dnsBySrc).forEach(([ip,cnt]) => {
      if(cnt > 30){
        results.push({type:'DNS Tunneling Indicator',severity:'high',desc:`${esc(ip)} made ${cnt} DNS queries — possible DNS tunneling or data exfiltration`,meta:'High volume DNS activity from single source'});
      }
    });

    const outbound = {};
    packets.forEach(p => {
      if(p.src.startsWith('192.168.')){
        if(!outbound[p.src]) outbound[p.src] = 0;
        outbound[p.src] += p.size;
      }
    });
    Object.entries(outbound).forEach(([ip,bytes]) => {
      if(bytes > 50000){
        results.push({type:'Large Data Exfiltration',severity:'warn',desc:`${esc(ip)} sent ${(bytes/1024).toFixed(1)} KB outbound — above normal threshold`,meta:'Potential data exfiltration or large file transfer'});
      }
    });

    const intervals = {};
    const sorted = [...packets].sort((a,b) => a.ts - b.ts);
    for(let i=1;i<sorted.length;i++){
      const k = sorted[i].src+'->'+sorted[i].dst;
      if(!intervals[k]) intervals[k] = [];
      intervals[k].push(sorted[i].ts - sorted[i-1].ts);
    }
    Object.entries(intervals).forEach(([pair,gaps]) => {
      if(gaps.length >= 8){
        const avg = gaps.reduce((s,g)=>s+g,0)/gaps.length;
        const variance = gaps.reduce((s,g)=>s+(g-avg)**2,0)/gaps.length;
        const stddev = Math.sqrt(variance);
        if(avg > 0 && stddev/avg < 0.2){
          results.push({type:'Beaconing Detected',severity:'high',desc:`${esc(pair)} shows regular interval communication (~${(avg/1000).toFixed(1)}s)`,meta:`${gaps.length} intervals, std dev ratio: ${(stddev/avg).toFixed(3)}`});
        }
      }
    });

    return results;
  }

  function getConnections(){
    const conns = {};
    packets.forEach(p => {
      if(p.proto==='ICMP'||p.proto==='DNS') return;
      const k = [p.src,p.srcPort,p.dst,p.dstPort,p.proto].join(':');
      if(!conns[k]) conns[k] = {src:p.src,srcPort:p.srcPort,dst:p.dst,dstPort:p.dstPort,proto:p.proto,pkts:0,bytes:0,lastSeen:p.ts,state:NT_STATES[Math.floor(Math.random()*NT_STATES.length)]};
      conns[k].pkts++;
      conns[k].bytes += p.size;
      conns[k].lastSeen = p.ts;
    });
    return Object.values(conns).sort((a,b)=>b.pkts-a.pkts).slice(0,30);
  }

  function _ntEsc(s){return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}

  function renderHeader(){
    const total = packets.length;
    const bytes = getTotalBytes();
    const cliReady = window._bridge && window._bridge.connected;
    return `<div class="nt-header">
      <h2><span class="nt-live-dot ${paused?'paused':''}"></span>Network Traffic Analyzer <span style="font-size:11px;font-weight:700;margin-left:8px;padding:1px 7px;border:1px solid #ffa726;color:#ffa726;border-radius:3px">SAMPLE TRAFFIC</span> ${cliReady?'<span style="color:#22c55e;font-size:11px;font-weight:700;margin-left:8px">[CLI CONNECTED]</span>':''}</h2>
      <div style="font-size:11px;color:#8a9bb0;margin:4px 0 6px">The packets below are simulated in your browser for learning. They are not captured from your network.${cliReady?' Use Show Live Ports for real data from your local agent.':''}</div>
      <div class="nt-header-stats">
        <div>Packets: <span>${total.toLocaleString()}</span></div>
        <div>Bytes: <span>${(bytes/1024).toFixed(1)} KB</span></div>
        <div>Protocols: <span>${new Set(packets.map(p=>p.proto)).size}</span></div>
        ${cliReady?'<div><button class="nt-tab" id="nt-live-ports" style="font-size:11px;padding:4px 10px">Show Live Ports</button></div>':''}
      </div>
    </div>`;
  }

  function renderTabs(){
    const tabs = [{id:'feed',label:'Sample Feed'},{id:'stats',label:'Statistics'},{id:'talkers',label:'Top Talkers'},{id:'anomalies',label:'Anomalies'},{id:'filters',label:'Filters'},{id:'export',label:'Export'}];
    return `<div class="nt-tabs">${tabs.map(t=>`<button class="nt-tab ${activeTab===t.id?'active':''}" data-tab="${t.id}">${t.label}</button>`).join('')}</div>`;
  }

  function renderFeed(){
    const filtered = packets.filter(p => {
      if(filterProto && p.proto !== filterProto) return false;
      if(filterIP && !p.src.includes(filterIP) && !p.dst.includes(filterIP)) return false;
      return true;
    }).slice(-200);

    return `<div class="nt-content">
      <div class="nt-controls">
        <button class="nt-btn ${paused?'':'active'}" id="nt-toggle">${paused?'▶ Resume':'Pause'}</button>
        <button class="nt-btn danger" id="nt-clear">Clear</button>
        <select class="nt-select" id="nt-proto-filter"><option value="">All Protocols</option>${NT_PROTOCOLS.map(p=>`<option value="${p}" ${filterProto===p?'selected':''}>${p}</option>`).join('')}</select>
        <input class="nt-input" id="nt-ip-filter" placeholder="Filter by IP..." value="${esc(filterIP)}" style="width:140px;">
        <span style="font-size:11px;color:#6a8a9e;">${filtered.length} packets shown</span>
      </div>
      <div class="nt-feed" id="nt-feed-list">
        <div class="nt-pkt nt-pkt-head"><span>Time</span><span>Source</span><span>Destination</span><span>Proto</span><span>Size</span><span>Flags</span><span>Info</span></div>
        ${filtered.map(p=>`<div class="nt-pkt">
          <span>${_fmtTime(p.ts)}</span>
          <span>${esc(p.src)}:${p.srcPort}</span>
          <span>${esc(p.dst)}:${p.dstPort}</span>
          <span><span class="nt-proto nt-proto-${p.proto}">${p.proto}</span></span>
          <span>${p.size}</span>
          <span class="nt-flags">${p.flags.map(f=>`<span class="nt-flag nt-flag-${f}">${f}</span>`).join('')}</span>
          <span class="nt-payload">${esc(p.payload)}</span>
        </div>`).join('')}
      </div>
    </div>`;
  }

  function renderStats(){
    const counts = getProtoCounts();
    const total = packets.length || 1;
    const bytes = getTotalBytes();
    const conns = getConnections();
    const protoColors = {TCP:'#00aaff',UDP:'#bb86fc',ICMP:'#ffa726',DNS:'#00ff88',HTTP:'#ff4444',HTTPS:'#66bb6a',SSH:'#7c8fff',FTP:'#ffd600',SMTP:'#ce93d8',TELNET:'#ef5350'};

    return `<div class="nt-content">
      <div class="nt-stats-grid">
        <div class="nt-stat"><div class="nt-stat-val">${packets.length.toLocaleString()}</div><div class="nt-stat-label">Total Packets</div></div>
        <div class="nt-stat"><div class="nt-stat-val">${(bytes/1024).toFixed(1)}</div><div class="nt-stat-label">Total KB</div></div>
        <div class="nt-stat"><div class="nt-stat-val">${Object.keys(counts).length}</div><div class="nt-stat-label">Protocols Seen</div></div>
        <div class="nt-stat"><div class="nt-stat-val">${conns.length}</div><div class="nt-stat-label">Active Connections</div></div>
      </div>
      <div class="nt-panel" style="margin-top:16px;">
        <h3>Protocol Distribution</h3>
        <div class="nt-bar-chart">
          ${Object.entries(counts).sort((a,b)=>b[1]-a[1]).map(([proto,cnt])=>{
            const pct = (cnt/total*100).toFixed(1);
            return `<div class="nt-bar-row">
              <span class="nt-bar-label">${proto}</span>
              <div class="nt-bar-track"><div class="nt-bar-fill" style="width:${pct}%;background:${protoColors[proto]||'#6a8a9e'}"></div><span class="nt-bar-pct">${pct}% (${cnt})</span></div>
            </div>`;
          }).join('')}
        </div>
      </div>
      <div class="nt-panel">
        <h3>Connection States</h3>
        ${conns.length?`<table class="nt-conn-table">
          <thead><tr><th>Source</th><th>Destination</th><th>Proto</th><th>Pkts</th><th>Bytes</th><th>State</th></tr></thead>
          <tbody>${conns.slice(0,15).map(c=>`<tr>
            <td>${esc(c.src)}:${c.srcPort}</td>
            <td>${esc(c.dst)}:${c.dstPort}</td>
            <td><span class="nt-proto nt-proto-${c.proto}">${c.proto}</span></td>
            <td>${c.pkts}</td>
            <td>${c.bytes.toLocaleString()}</td>
            <td><span class="nt-state nt-state-${c.state}">${c.state}</span></td>
          </tr>`).join('')}</tbody>
        </table>`:'<div class="nt-empty">No connections yet</div>'}
      </div>
    </div>`;
  }

  function renderTalkers(){
    const talkers = getTopTalkers();
    const maxPkts = talkers.length ? talkers[0].pkts : 1;
    return `<div class="nt-content">
      <div class="nt-panel">
        <h3>Top Talkers by Packet Count</h3>
        ${talkers.length?`<table class="nt-talker-table">
          <thead><tr><th>#</th><th>IP Address</th><th>Packets</th><th>Bandwidth</th><th>Protocols</th><th>Activity</th></tr></thead>
          <tbody>${talkers.map((t,i)=>`<tr>
            <td>${i+1}</td>
            <td style="color:#00aaff;">${esc(t.ip)}</td>
            <td>${t.pkts.toLocaleString()}</td>
            <td>${(t.bytes/1024).toFixed(1)} KB</td>
            <td>${[...t.protos].map(p=>`<span class="nt-proto nt-proto-${p}" style="margin-right:3px;">${p}</span>`).join('')}</td>
            <td><div class="nt-bar-track" style="width:120px;display:inline-block;"><div class="nt-bar-fill" style="width:${(t.pkts/maxPkts*100).toFixed(0)}%;background:${t.ip.startsWith('192.168.')?'#00aaff':'#00ff88'}"></div></div></td>
          </tr>`).join('')}</tbody>
        </table>`:'<div class="nt-empty">No traffic data yet — start capture to see top talkers</div>'}
      </div>
    </div>`;
  }

  function renderAnomalies(){
    anomalies = detectAnomalies();
    return `<div class="nt-content">
      <div class="nt-controls">
        <button class="nt-btn" id="nt-refresh-anomalies">Refresh Analysis</button>
        <span style="font-size:11px;color:#6a8a9e;">${anomalies.length} anomalies detected</span>
      </div>
      ${anomalies.length ? anomalies.map(a => `<div class="nt-anomaly ${a.severity}">
        <div class="nt-anomaly-type">${a.severity === 'high' ? '[!]' : '[~]'} ${esc(a.type)}</div>
        <div class="nt-anomaly-desc">${a.desc}</div>
        <div class="nt-anomaly-meta">${esc(a.meta)}</div>
      </div>`).join('') : '<div class="nt-empty">No anomalies detected — collect more packets for analysis</div>'}
    </div>`;
  }

  function renderFilters(){
    return `<div class="nt-content">
      <div class="nt-panel">
        <h3>BPF Filter Builder</h3>
        <div class="nt-filter-builder">
          <div class="nt-filter-row">
            <label>Protocol:</label>
            <select class="nt-select" id="nt-bpf-proto"><option value="">Any</option><option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option><option value="arp">ARP</option></select>
          </div>
          <div class="nt-filter-row">
            <label>Source Host:</label>
            <input class="nt-input" id="nt-bpf-src" placeholder="e.g. 192.168.1.1" style="width:160px;">
          </div>
          <div class="nt-filter-row">
            <label>Dest Host:</label>
            <input class="nt-input" id="nt-bpf-dst" placeholder="e.g. 10.0.0.1" style="width:160px;">
          </div>
          <div class="nt-filter-row">
            <label>Port:</label>
            <input class="nt-input" id="nt-bpf-port" placeholder="e.g. 80" style="width:100px;" type="number">
          </div>
          <div class="nt-filter-row">
            <label>Direction:</label>
            <select class="nt-select" id="nt-bpf-dir"><option value="">Any</option><option value="src">Source only</option><option value="dst">Destination only</option></select>
          </div>
          <div class="nt-filter-row">
            <label>Negate:</label>
            <select class="nt-select" id="nt-bpf-neg"><option value="">No</option><option value="not">Negate (NOT)</option></select>
          </div>
          <button class="nt-btn active" id="nt-bpf-gen">Generate Filter</button>
        </div>
        <div class="nt-bpf-preview" id="nt-bpf-out">Click "Generate Filter" to build BPF expression</div>
      </div>
      <div class="nt-panel nt-bpf-ref">
        <h3>BPF Quick Reference</h3>
        <table>
          <thead><tr><th>Expression</th><th>Description</th></tr></thead>
          <tbody>
            <tr><td><code>tcp port 80</code></td><td>Capture HTTP traffic</td></tr>
            <tr><td><code>host 192.168.1.1</code></td><td>All traffic to/from a host</td></tr>
            <tr><td><code>src net 10.0.0.0/8</code></td><td>Traffic from 10.x.x.x subnet</td></tr>
            <tr><td><code>dst port 443</code></td><td>Traffic to HTTPS port</td></tr>
            <tr><td><code>not arp</code></td><td>Exclude ARP packets</td></tr>
            <tr><td><code>tcp[tcpflags] & tcp-syn != 0</code></td><td>TCP SYN packets only</td></tr>
            <tr><td><code>udp and port 53</code></td><td>DNS traffic over UDP</td></tr>
            <tr><td><code>icmp[icmptype] == 8</code></td><td>ICMP echo requests (ping)</td></tr>
            <tr><td><code>len > 1000</code></td><td>Packets larger than 1000 bytes</td></tr>
            <tr><td><code>ether broadcast</code></td><td>Broadcast frames</td></tr>
          </tbody>
        </table>
      </div>
    </div>`;
  }

  function renderExport(){
    const lines = packets.slice(-100).map(p => {
      return `${_fmtTime(p.ts)}  ${p.src}:${p.srcPort} -> ${p.dst}:${p.dstPort}  ${p.proto}  ${p.size}B  [${p.flags.join(',')}]  ${p.payload}`;
    });
    return `<div class="nt-content">
      <div class="nt-controls">
        <button class="nt-btn" id="nt-export-copy">Copy to Clipboard</button>
        <button class="nt-btn" id="nt-export-dl">Download as .log</button>
        <button class="nt-btn" id="nt-export-json">Export JSON</button>
        <span style="font-size:11px;color:#6a8a9e;">Last 100 sample packets (simulated, not a real capture)</span>
      </div>
      <div class="nt-export-area" id="nt-export-text">${lines.length ? esc(lines.join('\n')) : 'No sample packets generated yet.'}</div>
    </div>`;
  }

  function render(){
    const contentMap = {feed:renderFeed, stats:renderStats, talkers:renderTalkers, anomalies:renderAnomalies, filters:renderFilters, export:renderExport};
    wrap.innerHTML = renderHeader() + renderTabs() + (contentMap[activeTab]||renderFeed)();
    bindEvents();
  }

  function bindEvents(){
    wrap.querySelectorAll('.nt-tab').forEach(t => {
      t.addEventListener('click', () => { activeTab = t.dataset.tab; render(); });
    });

    const toggleBtn = wrap.querySelector('#nt-toggle');
    if(toggleBtn) toggleBtn.addEventListener('click', () => { paused = !paused; if(!paused) startFeed(); else stopFeed(); render(); });

    const clearBtn = wrap.querySelector('#nt-clear');
    if(clearBtn) clearBtn.addEventListener('click', () => { packets.length = 0; render(); });

    const protoFilter = wrap.querySelector('#nt-proto-filter');
    if(protoFilter) protoFilter.addEventListener('change', e => { filterProto = e.target.value; render(); });

    const ipFilter = wrap.querySelector('#nt-ip-filter');
    if(ipFilter){
      let debounce;
      ipFilter.addEventListener('input', e => { clearTimeout(debounce); debounce = setTimeout(() => { filterIP = e.target.value.trim(); render(); }, 300); });
    }

    const livePorts = wrap.querySelector('#nt-live-ports');
    if(livePorts) livePorts.addEventListener('click', async () => {
      livePorts.textContent = 'Loading...';
      try {
        const r = await window._bridge.exec('ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null');
        const modal = document.createElement('div');
        modal.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.7);z-index:9999;display:flex;align-items:center;justify-content:center';
        modal.innerHTML = '<div style="background:#0f172a;border:1px solid #1e293b;border-radius:12px;padding:24px;max-width:700px;width:90%;max-height:80vh;overflow:auto"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px"><h3 style="margin:0;color:#e2e8f0">Live Listening Ports <span style="color:#22c55e;font-size:11px">[LIVE]</span></h3><button id="nt-close-modal" style="background:none;border:none;color:#e2e8f0;font-size:20px;cursor:pointer">&times;</button></div><pre style="font-size:11px;overflow:auto;color:#c8d6e5;line-height:1.5">' + _ntEsc(r.stdout||'No data') + '</pre></div>';
        document.body.appendChild(modal);
        modal.querySelector('#nt-close-modal').onclick = () => modal.remove();
        modal.onclick = e => { if(e.target === modal) modal.remove(); };
      } catch(e) { livePorts.textContent = 'Error'; }
      livePorts.textContent = 'Show Live Ports';
    });

    const refreshAnom = wrap.querySelector('#nt-refresh-anomalies');
    if(refreshAnom) refreshAnom.addEventListener('click', () => render());

    const bpfGen = wrap.querySelector('#nt-bpf-gen');
    if(bpfGen) bpfGen.addEventListener('click', () => {
      const proto = wrap.querySelector('#nt-bpf-proto')?.value || '';
      const src = wrap.querySelector('#nt-bpf-src')?.value.trim() || '';
      const dst = wrap.querySelector('#nt-bpf-dst')?.value.trim() || '';
      const port = wrap.querySelector('#nt-bpf-port')?.value.trim() || '';
      const dir = wrap.querySelector('#nt-bpf-dir')?.value || '';
      const neg = wrap.querySelector('#nt-bpf-neg')?.value || '';
      const parts = [];
      if(neg) parts.push('not');
      if(proto) parts.push(proto);
      if(src) parts.push(`${dir==='src'||!dir?'src':''} host ${src}`.trim());
      if(dst) parts.push(`${dir==='dst'||!dir?'dst':''} host ${dst}`.trim());
      if(port){
        if(dir==='src') parts.push(`src port ${port}`);
        else if(dir==='dst') parts.push(`dst port ${port}`);
        else parts.push(`port ${port}`);
      }
      const out = wrap.querySelector('#nt-bpf-out');
      if(out) out.textContent = parts.length ? parts.join(' and ') : '(empty filter — captures all traffic)';
    });

    const copyBtn = wrap.querySelector('#nt-export-copy');
    if(copyBtn) copyBtn.addEventListener('click', () => {
      const txt = wrap.querySelector('#nt-export-text')?.textContent || '';
      navigator.clipboard.writeText(txt).then(() => { copyBtn.textContent = 'Copied!'; setTimeout(() => { copyBtn.textContent = 'Copy to Clipboard'; }, 1500); });
    });

    const dlBtn = wrap.querySelector('#nt-export-dl');
    if(dlBtn) dlBtn.addEventListener('click', () => {
      const txt = wrap.querySelector('#nt-export-text')?.textContent || '';
      const blob = new Blob([txt], {type:'text/plain'});
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `network-capture-${Date.now()}.log`;
      a.click();
      URL.revokeObjectURL(a.href);
    });

    const jsonBtn = wrap.querySelector('#nt-export-json');
    if(jsonBtn) jsonBtn.addEventListener('click', () => {
      const data = packets.slice(-100).map(p => ({
        timestamp: p.ts.toISOString(),
        source: `${p.src}:${p.srcPort}`,
        destination: `${p.dst}:${p.dstPort}`,
        protocol: p.proto,
        size: p.size,
        flags: p.flags,
        info: p.payload
      }));
      const blob = new Blob([JSON.stringify(data,null,2)], {type:'application/json'});
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `network-capture-${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(a.href);
    });

    if(activeTab === 'feed'){
      const feedList = wrap.querySelector('#nt-feed-list');
      if(feedList) feedList.scrollTop = feedList.scrollHeight;
    }
  }

  function addPacket(){
    const pkt = _genPacket();
    packets.push(pkt);
    if(packets.length > maxPackets) packets.splice(0, packets.length - maxPackets);

    if(activeTab === 'feed'){
      const feedList = wrap.querySelector('#nt-feed-list');
      if(feedList){
        if(filterProto && pkt.proto !== filterProto) return;
        if(filterIP && !pkt.src.includes(filterIP) && !pkt.dst.includes(filterIP)) return;
        const row = document.createElement('div');
        row.className = 'nt-pkt';
        row.innerHTML = `
          <span>${_fmtTime(pkt.ts)}</span>
          <span>${esc(pkt.src)}:${pkt.srcPort}</span>
          <span>${esc(pkt.dst)}:${pkt.dstPort}</span>
          <span><span class="nt-proto nt-proto-${pkt.proto}">${pkt.proto}</span></span>
          <span>${pkt.size}</span>
          <span class="nt-flags">${pkt.flags.map(f=>`<span class="nt-flag nt-flag-${f}">${f}</span>`).join('')}</span>
          <span class="nt-payload">${esc(pkt.payload)}</span>`;
        feedList.appendChild(row);
        const rows = feedList.querySelectorAll('.nt-pkt:not(.nt-pkt-head)');
        if(rows.length > 200) rows[0].remove();
        feedList.scrollTop = feedList.scrollHeight;

        const statsEl = wrap.querySelector('.nt-header-stats');
        if(statsEl){
          const bytes = getTotalBytes();
          statsEl.innerHTML = `<div>Packets: <span>${packets.length.toLocaleString()}</span></div><div>Bytes: <span>${(bytes/1024).toFixed(1)} KB</span></div><div>Protocols: <span>${new Set(packets.map(p=>p.proto)).size}</span></div>`;
        }
      }
    }
  }

  function startFeed(){
    if(feedInterval) return;
    feedInterval = setInterval(() => {
      const burst = Math.floor(Math.random()*3)+1;
      for(let i=0;i<burst;i++) addPacket();
    }, 400 + Math.floor(Math.random()*300));
  }

  function stopFeed(){
    if(feedInterval){ clearInterval(feedInterval); feedInterval = null; }
  }

  render();
  startFeed();

  const cleanup = () => { stopFeed(); };
  const observer = new MutationObserver(() => {
    if(!document.contains(wrap)){ cleanup(); observer.disconnect(); }
  });
  observer.observe(container.parentNode || document.body, {childList:true,subtree:true});
}
