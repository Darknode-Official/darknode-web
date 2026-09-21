import { esc } from '/js/shared.js';

/* ── Sample Packet Hex Dumps ─────────────────────────────────────── */
const SAMPLES = {
  http: {
    name: 'HTTP GET Request',
    hex: 'aabbccddeeff0011223344550800450000730000400040067cc00a0001010a000102' +
         'c3500050000000010000000050021000ffff000047455420' +
         '2f696e6465782e68746d6c20485454502f312e310d0a486f73743a2065786' +
         '16d706c652e636f6d0d0a557365722d4167656e743a206375726c2f372e38' +
         '382e310d0a4163636570743a202a2f2a0d0a0d0a'
  },
  dns: {
    name: 'DNS Query (A Record)',
    hex: 'ffeeddccbbaa6655443322110800450000440000400040110000c0a80101c0a80' +
         '1fe00350035003000001234010000010000000000000765' +
         '78616d706c6503636f6d0000010001'
  },
  tcpsyn: {
    name: 'TCP SYN',
    hex: '0011223344556677889900aa08004500002c000040004006b1c6c0a80164' +
         'ac100a01d431005000000000000000006002ffff9a5f0000020405b4'
  },
  arp: {
    name: 'ARP Request',
    hex: 'ffffffffffff0011223344550806000108000604000100112233445' +
         '5c0a8010100000000000000000000c0a80102'
  }
};

/* ── Hex / Parse Utilities ───────────────────────────────────────── */
function hexToBytes(hex) {
  const clean = hex.replace(/[\s\n\r]/g, '');
  const bytes = [];
  for (let i = 0; i < clean.length; i += 2) bytes.push(parseInt(clean.substr(i, 2), 16));
  return bytes;
}

function fmtMAC(b, o) {
  return [b[o],b[o+1],b[o+2],b[o+3],b[o+4],b[o+5]].map(x => x.toString(16).padStart(2,'0')).join(':');
}

function fmtIP(b, o) { return `${b[o]}.${b[o+1]}.${b[o+2]}.${b[o+3]}`; }

function rd16(b, o) { return (b[o] << 8) | b[o+1]; }
function rd32(b, o) { return ((b[o] << 24) | (b[o+1] << 16) | (b[o+2] << 8) | b[o+3]) >>> 0; }

function tcpFlags(flagByte) {
  const names = ['FIN','SYN','RST','PSH','ACK','URG'];
  return names.filter((_, i) => flagByte & (1 << i)).reverse().join(', ') || 'None';
}

function protocolName(num) {
  const map = { 1:'ICMP', 6:'TCP', 17:'UDP', 2:'IGMP' };
  return map[num] || `Proto(${num})`;
}

/* ── Protocol Dissector ──────────────────────────────────────────── */
function dissect(bytes) {
  const layers = [];
  if (bytes.length < 14) return layers;

  /* Ethernet */
  const ethType = rd16(bytes, 12);
  layers.push({
    name: 'Ethernet II', layer: 'eth', start: 0, end: 14,
    fields: [
      { label: 'Destination MAC', value: fmtMAC(bytes, 0), start: 0, end: 6 },
      { label: 'Source MAC', value: fmtMAC(bytes, 6), start: 6, end: 12 },
      { label: 'EtherType', value: '0x' + ethType.toString(16).padStart(4,'0') +
        (ethType === 0x0800 ? ' (IPv4)' : ethType === 0x0806 ? ' (ARP)' : ethType === 0x86dd ? ' (IPv6)' : ''), start: 12, end: 14 }
    ]
  });

  if (ethType === 0x0806) {
    /* ARP */
    if (bytes.length >= 42) {
      const op = rd16(bytes, 20);
      layers.push({
        name: 'ARP', layer: 'arp', start: 14, end: 42,
        fields: [
          { label: 'Hardware Type', value: rd16(bytes,14) === 1 ? 'Ethernet (1)' : String(rd16(bytes,14)), start: 14, end: 16 },
          { label: 'Protocol Type', value: '0x' + rd16(bytes,16).toString(16).padStart(4,'0'), start: 16, end: 18 },
          { label: 'Operation', value: op === 1 ? 'Request (1)' : op === 2 ? 'Reply (2)' : String(op), start: 20, end: 22 },
          { label: 'Sender MAC', value: fmtMAC(bytes, 22), start: 22, end: 28 },
          { label: 'Sender IP', value: fmtIP(bytes, 28), start: 28, end: 32 },
          { label: 'Target MAC', value: fmtMAC(bytes, 32), start: 32, end: 38 },
          { label: 'Target IP', value: fmtIP(bytes, 38), start: 38, end: 42 }
        ]
      });
    }
    return layers;
  }

  if (ethType !== 0x0800) return layers;

  /* IPv4 */
  const ipOff = 14;
  if (bytes.length < ipOff + 20) return layers;
  const ihl = (bytes[ipOff] & 0x0f) * 4;
  const totalLen = rd16(bytes, ipOff + 2);
  const proto = bytes[ipOff + 9];
  layers.push({
    name: 'IPv4', layer: 'ip', start: ipOff, end: ipOff + ihl,
    fields: [
      { label: 'Version', value: '4', start: ipOff, end: ipOff + 1 },
      { label: 'Header Length', value: ihl + ' bytes', start: ipOff, end: ipOff + 1 },
      { label: 'Total Length', value: String(totalLen), start: ipOff + 2, end: ipOff + 4 },
      { label: 'TTL', value: String(bytes[ipOff + 8]), start: ipOff + 8, end: ipOff + 9 },
      { label: 'Protocol', value: protocolName(proto), start: ipOff + 9, end: ipOff + 10 },
      { label: 'Header Checksum', value: '0x' + rd16(bytes, ipOff + 10).toString(16).padStart(4,'0'), start: ipOff + 10, end: ipOff + 12 },
      { label: 'Source IP', value: fmtIP(bytes, ipOff + 12), start: ipOff + 12, end: ipOff + 16 },
      { label: 'Destination IP', value: fmtIP(bytes, ipOff + 16), start: ipOff + 16, end: ipOff + 20 }
    ]
  });

  const tOff = ipOff + ihl;

  if (proto === 6 && bytes.length >= tOff + 20) {
    /* TCP */
    const dataOff = ((bytes[tOff + 12] >> 4) & 0x0f) * 4;
    const flags = bytes[tOff + 13];
    layers.push({
      name: 'TCP', layer: 'tcp', start: tOff, end: tOff + dataOff,
      fields: [
        { label: 'Source Port', value: String(rd16(bytes, tOff)), start: tOff, end: tOff + 2 },
        { label: 'Destination Port', value: String(rd16(bytes, tOff + 2)), start: tOff + 2, end: tOff + 4 },
        { label: 'Sequence Number', value: String(rd32(bytes, tOff + 4)), start: tOff + 4, end: tOff + 8 },
        { label: 'Acknowledgment', value: String(rd32(bytes, tOff + 8)), start: tOff + 8, end: tOff + 12 },
        { label: 'Data Offset', value: dataOff + ' bytes', start: tOff + 12, end: tOff + 13 },
        { label: 'Flags', value: tcpFlags(flags), start: tOff + 13, end: tOff + 14 },
        { label: 'Window Size', value: String(rd16(bytes, tOff + 14)), start: tOff + 14, end: tOff + 16 },
        { label: 'Checksum', value: '0x' + rd16(bytes, tOff + 16).toString(16).padStart(4,'0'), start: tOff + 16, end: tOff + 18 }
      ]
    });
    const payOff = tOff + dataOff;
    if (payOff < bytes.length) {
      const payload = bytes.slice(payOff);
      const ascii = payload.map(b => b >= 32 && b < 127 ? String.fromCharCode(b) : '.').join('');
      let appName = 'Application Data';
      if (ascii.startsWith('GET ') || ascii.startsWith('POST ') || ascii.startsWith('HTTP/')) appName = 'HTTP';
      layers.push({
        name: appName, layer: 'app', start: payOff, end: bytes.length,
        fields: [
          { label: 'Payload Length', value: payload.length + ' bytes', start: payOff, end: bytes.length },
          { label: 'ASCII Preview', value: ascii.substring(0, 120) + (ascii.length > 120 ? '...' : ''), start: payOff, end: Math.min(payOff + 120, bytes.length) }
        ]
      });
    }
  } else if (proto === 17 && bytes.length >= tOff + 8) {
    /* UDP */
    const udpLen = rd16(bytes, tOff + 4);
    layers.push({
      name: 'UDP', layer: 'udp', start: tOff, end: tOff + 8,
      fields: [
        { label: 'Source Port', value: String(rd16(bytes, tOff)), start: tOff, end: tOff + 2 },
        { label: 'Destination Port', value: String(rd16(bytes, tOff + 2)), start: tOff + 2, end: tOff + 4 },
        { label: 'Length', value: String(udpLen), start: tOff + 4, end: tOff + 6 },
        { label: 'Checksum', value: '0x' + rd16(bytes, tOff + 6).toString(16).padStart(4,'0'), start: tOff + 6, end: tOff + 8 }
      ]
    });
    const payOff = tOff + 8;
    if (payOff < bytes.length) {
      const payload = bytes.slice(payOff);
      let appName = 'Application Data';
      const srcPort = rd16(bytes, tOff), dstPort = rd16(bytes, tOff + 2);
      if (srcPort === 53 || dstPort === 53) appName = 'DNS';
      layers.push({
        name: appName, layer: 'app', start: payOff, end: bytes.length,
        fields: [
          { label: 'Payload Length', value: payload.length + ' bytes', start: payOff, end: bytes.length }
        ]
      });
    }
  }
  return layers;
}

/* ── Main Renderer ───────────────────────────────────────────────── */
export function renderPacketInspector(container) {
  let state = { tab: 'input', packets: [], hexInput: '', selected: null, selField: null };

  const LAYER_COLORS = {
    eth: { bg: '#7c3aed22', border: '#7c3aed', label: '#a78bfa' },
    arp: { bg: '#7c3aed22', border: '#7c3aed', label: '#a78bfa' },
    ip:  { bg: '#2563eb22', border: '#2563eb', label: '#60a5fa' },
    tcp: { bg: '#16a34a22', border: '#16a34a', label: '#4ade80' },
    udp: { bg: '#ea580c22', border: '#ea580c', label: '#fb923c' },
    app: { bg: '#ca8a0422', border: '#ca8a04', label: '#facc15' }
  };

  function render() {
    container.innerHTML = `<style>
.pi-wrap{font-family:'Inter',system-ui,sans-serif;color:var(--txt,#c8d6e5);max-width:1100px;margin:0 auto;padding:28px 16px}
.pi-title{font-size:1.45rem;font-weight:700;margin-bottom:4px;letter-spacing:-.02em}
.pi-sub{color:var(--mut,#64748b);font-size:.85rem;margin-bottom:20px}
.pi-tabs{display:flex;gap:4px;border-bottom:1px solid var(--line,#1e293b);margin-bottom:20px;flex-wrap:wrap}
.pi-tab{background:none;border:none;color:var(--mut,#64748b);padding:9px 18px;cursor:pointer;font-size:.82rem;font-weight:500;border-bottom:2px solid transparent;transition:color .15s,border-color .15s}
.pi-tab:hover{color:var(--txt,#c8d6e5)}
.pi-tab.active{color:var(--acc,#2563eb);border-bottom-color:var(--acc,#2563eb)}
.pi-card{background:var(--card,#0d1117);border:1px solid var(--line,#1e293b);border-radius:10px;padding:18px;margin-bottom:14px}
.pi-card2{background:var(--card2,#080c14);border:1px solid var(--line,#1e293b);border-radius:8px;padding:14px;margin-bottom:10px}
.pi-label{font-size:.72rem;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--mut,#64748b);margin-bottom:8px}
.pi-textarea{width:100%;min-height:140px;background:var(--card2,#080c14);border:1px solid var(--line,#1e293b);border-radius:6px;color:var(--txt,#c8d6e5);font-family:'JetBrains Mono',monospace;font-size:.78rem;padding:12px;resize:vertical;box-sizing:border-box}
.pi-textarea:focus{outline:none;border-color:var(--acc,#2563eb)}
.pi-btn{background:var(--acc,#2563eb);color:#fff;border:none;padding:8px 18px;border-radius:6px;font-size:.8rem;font-weight:600;cursor:pointer;transition:opacity .15s}
.pi-btn:hover{opacity:.85}
.pi-btn-sm{background:var(--card2,#080c14);color:var(--txt,#c8d6e5);border:1px solid var(--line,#1e293b);padding:6px 14px;border-radius:5px;font-size:.75rem;cursor:pointer;transition:border-color .15s}
.pi-btn-sm:hover{border-color:var(--acc,#2563eb)}
.pi-samples{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}
.pi-tree-layer{border-left:3px solid;border-radius:6px;padding:10px 14px;margin-bottom:8px}
.pi-tree-head{font-size:.82rem;font-weight:700;cursor:pointer;display:flex;align-items:center;gap:8px}
.pi-tree-arrow{transition:transform .2s;font-size:.65rem}
.pi-tree-arrow.open{transform:rotate(90deg)}
.pi-tree-fields{margin-top:8px;padding-left:12px}
.pi-field{display:flex;justify-content:space-between;padding:4px 8px;font-size:.76rem;border-radius:4px;cursor:pointer;transition:background .12s}
.pi-field:hover{background:rgba(255,255,255,.04)}
.pi-field.sel{background:var(--acc,#2563eb);color:#fff}
.pi-field-label{color:var(--mut,#64748b)}
.pi-field.sel .pi-field-label{color:rgba(255,255,255,.7)}
.pi-hex-wrap{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.pi-hex-block{font-family:'JetBrains Mono',monospace;font-size:.72rem;line-height:1.8;white-space:pre;overflow-x:auto;background:var(--card2,#080c14);border:1px solid var(--line,#1e293b);border-radius:8px;padding:14px}
.pi-hex-off{color:var(--mut,#64748b);user-select:none}
.pi-hex-hl{background:var(--acc,#2563eb);color:#fff;border-radius:2px;padding:0 1px}
.pi-conv-row{display:grid;grid-template-columns:1fr 60px 1fr auto;gap:10px;align-items:center;padding:10px 14px;border-bottom:1px solid var(--line,#1e293b);font-size:.78rem}
.pi-conv-row:last-child{border-bottom:none}
.pi-conv-arrow{text-align:center;color:var(--acc,#2563eb);font-weight:700}
.pi-stat-bar{display:flex;align-items:center;gap:10px;margin-bottom:10px}
.pi-stat-name{width:90px;font-size:.76rem;text-align:right;color:var(--mut,#64748b)}
.pi-stat-track{flex:1;height:20px;background:var(--card2,#080c14);border-radius:4px;overflow:hidden;border:1px solid var(--line,#1e293b)}
.pi-stat-fill{height:100%;border-radius:3px;transition:width .3s}
.pi-stat-val{width:50px;font-size:.75rem;font-weight:600}
.pi-badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.68rem;font-weight:600}
.pi-empty{text-align:center;padding:50px 20px;color:var(--mut,#64748b)}
.pi-empty-icon{font-size:2.4rem;margin-bottom:10px;opacity:.3}
.pi-grid-stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:18px}
.pi-stat-card{background:var(--card2,#080c14);border:1px solid var(--line,#1e293b);border-radius:8px;padding:14px;text-align:center}
.pi-stat-card-val{font-size:1.5rem;font-weight:700;color:var(--acc,#2563eb)}
.pi-stat-card-label{font-size:.72rem;color:var(--mut,#64748b);margin-top:4px}
.pi-pkt-select{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px}
.pi-pkt-chip{padding:5px 12px;border-radius:5px;font-size:.74rem;cursor:pointer;border:1px solid var(--line,#1e293b);background:var(--card2,#080c14);transition:border-color .15s}
.pi-pkt-chip.active{border-color:var(--acc,#2563eb);color:var(--acc,#2563eb)}
@media(max-width:700px){.pi-hex-wrap{grid-template-columns:1fr}.pi-conv-row{grid-template-columns:1fr;gap:4px}}
[data-style=pro] .pi-wrap{color:#1e293b}
[data-style=pro] .pi-sub{color:#64748b}
[data-style=pro] .pi-tab{color:#64748b}
[data-style=pro] .pi-tab:hover{color:#1e293b}
[data-style=pro] .pi-tab.active{color:#2563eb;border-bottom-color:#2563eb}
[data-style=pro] .pi-card{background:#fff;border-color:#e2e8f0}
[data-style=pro] .pi-card2{background:#f8fafc;border-color:#e2e8f0}
[data-style=pro] .pi-textarea{background:#f8fafc;border-color:#e2e8f0;color:#1e293b}
[data-style=pro] .pi-textarea:focus{border-color:#2563eb}
[data-style=pro] .pi-btn-sm{background:#f8fafc;color:#1e293b;border-color:#e2e8f0}
[data-style=pro] .pi-btn-sm:hover{border-color:#2563eb}
[data-style=pro] .pi-field-label{color:#64748b}
[data-style=pro] .pi-field:hover{background:rgba(0,0,0,.03)}
[data-style=pro] .pi-hex-block{background:#f8fafc;border-color:#e2e8f0;color:#1e293b}
[data-style=pro] .pi-hex-off{color:#94a3b8}
[data-style=pro] .pi-conv-row{border-color:#e2e8f0}
[data-style=pro] .pi-stat-track{background:#f1f5f9;border-color:#e2e8f0}
[data-style=pro] .pi-stat-name{color:#64748b}
[data-style=pro] .pi-pkt-chip{background:#f8fafc;border-color:#e2e8f0;color:#1e293b}
[data-style=pro] .pi-pkt-chip.active{border-color:#2563eb;color:#2563eb}
[data-style=pro] .pi-stat-card{background:#fff;border-color:#e2e8f0}
[data-style=pro] .pi-empty{color:#94a3b8}
</style>
<div class="pi-wrap">
  <div class="pi-title">Packet Inspector</div>
  <div class="pi-sub">Network packet analysis and protocol dissection</div>
  <div class="pi-tabs">${['input','dissection','hexview','conversations','statistics'].map(t => {
    const labels = { input:'Input', dissection:'Dissection', hexview:'Hex View', conversations:'Conversations', statistics:'Statistics' };
    return `<button class="pi-tab${state.tab===t?' active':''}" data-tab="${t}">${esc(labels[t])}</button>`;
  }).join('')}</div>
  <div class="pi-body">${renderTab()}</div>
</div>`;
    bind();
  }

  function renderTab() {
    if (state.tab === 'input') return renderInput();
    if (state.packets.length === 0) return `<div class="pi-empty"><div class="pi-empty-icon">&#x1F4E6;</div>No packets loaded.<br><span style="font-size:.78rem">Go to the Input tab and load or paste packet data.</span></div>`;
    if (state.tab === 'dissection') return renderDissection();
    if (state.tab === 'hexview') return renderHexView();
    if (state.tab === 'conversations') return renderConversations();
    if (state.tab === 'statistics') return renderStatistics();
    return '';
  }

  /* ── Input Tab ────────────────────────────────────── */
  function renderInput() {
    return `<div class="pi-card">
      <div class="pi-label">Paste Hex Dump</div>
      <textarea class="pi-textarea" id="piHexIn" placeholder="Paste raw hex bytes (e.g. aabbccddeeff0800450000...)">${esc(state.hexInput)}</textarea>
      <div style="display:flex;gap:10px;margin-top:12px;align-items:center;flex-wrap:wrap">
        <button class="pi-btn" id="piParse">Parse Packet</button>
        <button class="pi-btn-sm" id="piClear">Clear All</button>
        <span style="font-size:.72rem;color:var(--mut,#64748b)">${state.packets.length} packet(s) loaded</span>
      </div>
    </div>
    <div class="pi-card">
      <div class="pi-label">Sample Captures</div>
      <div class="pi-samples">
        ${Object.entries(SAMPLES).map(([k,v]) => `<button class="pi-btn-sm" data-sample="${k}">${esc(v.name)}</button>`).join('')}
      </div>
      <div style="margin-top:8px"><button class="pi-btn-sm" id="piLoadAll">Load All Samples</button></div>
    </div>`;
  }

  /* ── Dissection Tab ───────────────────────────────── */
  function renderDissection() {
    const idx = state.selected ?? 0;
    const pkt = state.packets[idx];
    if (!pkt) return '';
    const layers = dissect(pkt.bytes);
    return `${pktSelector(idx)}
    <div class="pi-card">
      ${layers.map((l,li) => {
        const c = LAYER_COLORS[l.layer] || LAYER_COLORS.app;
        return `<div class="pi-tree-layer" style="border-color:${c.border};background:${c.bg}">
          <div class="pi-tree-head" data-toggle="${li}">
            <span class="pi-tree-arrow open">&#9654;</span>
            <span class="pi-badge" style="background:${c.border};color:#fff">${esc(l.name)}</span>
            <span style="font-size:.72rem;color:${c.label}">Bytes ${l.start}-${l.end} (${l.end - l.start} bytes)</span>
          </div>
          <div class="pi-tree-fields" id="piFields${li}">
            ${l.fields.map(f => {
              const sel = state.selField && state.selField.start === f.start && state.selField.end === f.end;
              return `<div class="pi-field${sel?' sel':''}" data-fs="${f.start}" data-fe="${f.end}">
                <span class="pi-field-label">${esc(f.label)}</span>
                <span>${esc(f.value)}</span>
              </div>`;
            }).join('')}
          </div>
        </div>`;
      }).join('')}
    </div>`;
  }

  /* ── Hex View Tab ─────────────────────────────────── */
  function renderHexView() {
    const idx = state.selected ?? 0;
    const pkt = state.packets[idx];
    if (!pkt) return '';
    const b = pkt.bytes;
    const sf = state.selField;
    let hexLines = '', asciiLines = '';
    for (let row = 0; row < b.length; row += 16) {
      const off = row.toString(16).padStart(6, '0');
      let hParts = [], aParts = [];
      for (let col = 0; col < 16; col++) {
        const i = row + col;
        if (i >= b.length) { hParts.push('  '); aParts.push(' '); continue; }
        const hl = sf && i >= sf.start && i < sf.end;
        const hx = b[i].toString(16).padStart(2, '0');
        const ch = (b[i] >= 32 && b[i] < 127) ? String.fromCharCode(b[i]) : '.';
        hParts.push(hl ? `<span class="pi-hex-hl">${hx}</span>` : hx);
        aParts.push(hl ? `<span class="pi-hex-hl">${esc(ch)}</span>` : esc(ch));
      }
      hexLines += `<span class="pi-hex-off">${off}</span>  ${hParts.join(' ')}${row + 16 < b.length ? '\n' : ''}`;
      asciiLines += `${aParts.join('')}${row + 16 < b.length ? '\n' : ''}`;
    }
    return `${pktSelector(idx)}
    <div class="pi-card">
      <div class="pi-hex-wrap">
        <div><div class="pi-label">Hex Dump</div><div class="pi-hex-block">${hexLines}</div></div>
        <div><div class="pi-label">ASCII</div><div class="pi-hex-block">${asciiLines}</div></div>
      </div>
      ${sf ? `<div style="margin-top:10px;font-size:.74rem;color:var(--acc,#2563eb)">Highlighting bytes ${sf.start} - ${sf.end} (${sf.end - sf.start} bytes)</div>` : `<div style="margin-top:10px;font-size:.74rem;color:var(--mut,#64748b)">Select a field in Dissection tab to highlight bytes here.</div>`}
    </div>`;
  }

  /* ── Conversations Tab ────────────────────────────── */
  function renderConversations() {
    const convMap = {};
    state.packets.forEach((pkt, pi) => {
      const layers = dissect(pkt.bytes);
      const ipL = layers.find(l => l.layer === 'ip');
      if (!ipL) return;
      const srcF = ipL.fields.find(f => f.label === 'Source IP');
      const dstF = ipL.fields.find(f => f.label === 'Destination IP');
      if (!srcF || !dstF) return;
      const key = [srcF.value, dstF.value].sort().join(' <-> ');
      if (!convMap[key]) convMap[key] = { src: srcF.value, dst: dstF.value, count: 0, bytes: 0, protos: new Set() };
      convMap[key].count++;
      convMap[key].bytes += pkt.bytes.length;
      const transL = layers.find(l => l.layer === 'tcp' || l.layer === 'udp');
      if (transL) convMap[key].protos.add(transL.name);
      const appL = layers.find(l => l.layer === 'app');
      if (appL) convMap[key].protos.add(appL.name);
    });
    const convs = Object.values(convMap);
    if (convs.length === 0) return `<div class="pi-empty"><div class="pi-empty-icon">&#x1F517;</div>No IP conversations found in loaded packets.</div>`;
    return `<div class="pi-card">
      <div class="pi-label">IP Conversations (${convs.length})</div>
      ${convs.map(c => `<div class="pi-conv-row">
        <span>${esc(c.src)}</span>
        <span class="pi-conv-arrow">&harr;</span>
        <span>${esc(c.dst)}</span>
        <span style="text-align:right">
          <span class="pi-badge" style="background:var(--acc,#2563eb);color:#fff">${c.count} pkt${c.count > 1 ? 's' : ''}</span>
          <span style="font-size:.72rem;color:var(--mut,#64748b);margin-left:6px">${c.bytes} B</span>
          <span style="font-size:.72rem;color:var(--mut,#64748b);margin-left:6px">${[...c.protos].join(', ')}</span>
        </span>
      </div>`).join('')}
    </div>`;
  }

  /* ── Statistics Tab ───────────────────────────────── */
  function renderStatistics() {
    const protoCounts = {};
    let totalBytes = 0, minSize = Infinity, maxSize = 0;
    const talkers = {};

    state.packets.forEach(pkt => {
      const b = pkt.bytes;
      totalBytes += b.length;
      if (b.length < minSize) minSize = b.length;
      if (b.length > maxSize) maxSize = b.length;
      const layers = dissect(b);
      layers.forEach(l => { protoCounts[l.name] = (protoCounts[l.name] || 0) + 1; });
      const ipL = layers.find(l => l.layer === 'ip');
      if (ipL) {
        const src = ipL.fields.find(f => f.label === 'Source IP');
        const dst = ipL.fields.find(f => f.label === 'Destination IP');
        if (src) talkers[src.value] = (talkers[src.value] || 0) + b.length;
        if (dst) talkers[dst.value] = (talkers[dst.value] || 0) + b.length;
      }
    });

    const maxProto = Math.max(...Object.values(protoCounts), 1);
    const barColors = { 'Ethernet II':'#7c3aed', 'ARP':'#a78bfa', 'IPv4':'#2563eb', 'TCP':'#16a34a', 'UDP':'#ea580c', 'HTTP':'#eab308', 'DNS':'#eab308' };
    const topTalkers = Object.entries(talkers).sort((a,b) => b[1] - a[1]).slice(0, 5);
    const maxTalk = topTalkers.length ? topTalkers[0][1] : 1;
    const avg = state.packets.length ? Math.round(totalBytes / state.packets.length) : 0;

    return `<div class="pi-grid-stats">
      <div class="pi-stat-card"><div class="pi-stat-card-val">${state.packets.length}</div><div class="pi-stat-card-label">Total Packets</div></div>
      <div class="pi-stat-card"><div class="pi-stat-card-val">${totalBytes}</div><div class="pi-stat-card-label">Total Bytes</div></div>
      <div class="pi-stat-card"><div class="pi-stat-card-val">${avg}</div><div class="pi-stat-card-label">Avg Size (B)</div></div>
      <div class="pi-stat-card"><div class="pi-stat-card-val">${minSize === Infinity ? 0 : minSize} / ${maxSize}</div><div class="pi-stat-card-label">Min / Max Size</div></div>
    </div>
    <div class="pi-card">
      <div class="pi-label">Protocol Distribution</div>
      ${Object.entries(protoCounts).map(([name, cnt]) => {
        const pct = Math.round((cnt / maxProto) * 100);
        const col = barColors[name] || '#64748b';
        return `<div class="pi-stat-bar">
          <span class="pi-stat-name">${esc(name)}</span>
          <div class="pi-stat-track"><div class="pi-stat-fill" style="width:${pct}%;background:${col}"></div></div>
          <span class="pi-stat-val">${cnt}</span>
        </div>`;
      }).join('')}
    </div>
    <div class="pi-card">
      <div class="pi-label">Top Talkers (by bytes)</div>
      ${topTalkers.length === 0 ? '<div style="font-size:.78rem;color:var(--mut,#64748b)">No IP traffic detected.</div>' :
      topTalkers.map(([ip, bytes]) => {
        const pct = Math.round((bytes / maxTalk) * 100);
        return `<div class="pi-stat-bar">
          <span class="pi-stat-name">${esc(ip)}</span>
          <div class="pi-stat-track"><div class="pi-stat-fill" style="width:${pct}%;background:var(--acc,#2563eb)"></div></div>
          <span class="pi-stat-val">${bytes} B</span>
        </div>`;
      }).join('')}
    </div>`;
  }

  /* ── Packet selector chips ────────────────────────── */
  function pktSelector(active) {
    if (state.packets.length < 2) return '';
    return `<div class="pi-pkt-select">${state.packets.map((p,i) =>
      `<span class="pi-pkt-chip${i===active?' active':''}" data-pktidx="${i}">#${i+1} ${esc(p.label)}</span>`
    ).join('')}</div>`;
  }

  /* ── Event Bindings ───────────────────────────────── */
  function bind() {
    container.querySelectorAll('.pi-tab').forEach(btn => {
      btn.addEventListener('click', () => { state.tab = btn.dataset.tab; render(); });
    });
    const parseBtn = container.querySelector('#piParse');
    if (parseBtn) parseBtn.addEventListener('click', () => {
      const ta = container.querySelector('#piHexIn');
      if (!ta) return;
      const raw = ta.value.trim();
      if (!raw) return;
      state.hexInput = raw;
      const bytes = hexToBytes(raw);
      if (bytes.length < 14) return;
      const layers = dissect(bytes);
      const topProto = layers.length > 1 ? layers[layers.length - 1].name : 'Unknown';
      state.packets.push({ bytes, label: topProto, hex: raw });
      state.selected = state.packets.length - 1;
      state.selField = null;
      state.hexInput = '';
      state.tab = 'dissection';
      render();
    });
    const clearBtn = container.querySelector('#piClear');
    if (clearBtn) clearBtn.addEventListener('click', () => {
      state.packets = []; state.selected = null; state.selField = null; state.hexInput = '';
      render();
    });
    container.querySelectorAll('[data-sample]').forEach(btn => {
      btn.addEventListener('click', () => {
        const s = SAMPLES[btn.dataset.sample];
        if (!s) return;
        const bytes = hexToBytes(s.hex);
        const layers = dissect(bytes);
        const topProto = layers.length > 1 ? layers[layers.length - 1].name : s.name;
        state.packets.push({ bytes, label: topProto, hex: s.hex });
        state.selected = state.packets.length - 1;
        state.selField = null;
        state.tab = 'dissection';
        render();
      });
    });
    const loadAll = container.querySelector('#piLoadAll');
    if (loadAll) loadAll.addEventListener('click', () => {
      Object.values(SAMPLES).forEach(s => {
        const bytes = hexToBytes(s.hex);
        const layers = dissect(bytes);
        const topProto = layers.length > 1 ? layers[layers.length - 1].name : s.name;
        state.packets.push({ bytes, label: topProto, hex: s.hex });
      });
      state.selected = 0;
      state.tab = 'dissection';
      render();
    });
    container.querySelectorAll('.pi-tree-head').forEach(hd => {
      hd.addEventListener('click', () => {
        const fields = container.querySelector('#piFields' + hd.dataset.toggle);
        const arrow = hd.querySelector('.pi-tree-arrow');
        if (fields) fields.style.display = fields.style.display === 'none' ? '' : 'none';
        if (arrow) arrow.classList.toggle('open');
      });
    });
    container.querySelectorAll('.pi-field').forEach(f => {
      f.addEventListener('click', () => {
        state.selField = { start: +f.dataset.fs, end: +f.dataset.fe };
        render();
      });
    });
    container.querySelectorAll('.pi-pkt-chip').forEach(chip => {
      chip.addEventListener('click', () => {
        state.selected = +chip.dataset.pktidx;
        state.selField = null;
        render();
      });
    });
  }

  render();
}
