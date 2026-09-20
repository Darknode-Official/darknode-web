// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Subnet Visualizer — interactive CIDR subnet calculator, VLSM planner, and visual network mapper.

export function renderSubnetVisualizer(container) {
  const PRIVATE_RANGES = [
    { name: "Class A Private", cidr: "10.0.0.0/8", desc: "10.0.0.0 – 10.255.255.255 (16,777,216 hosts)" },
    { name: "Class B Private", cidr: "172.16.0.0/12", desc: "172.16.0.0 – 172.31.255.255 (1,048,576 hosts)" },
    { name: "Class C Private", cidr: "192.168.0.0/16", desc: "192.168.0.0 – 192.168.255.255 (65,536 hosts)" },
    { name: "Loopback", cidr: "127.0.0.0/8", desc: "127.0.0.0 – 127.255.255.255" },
    { name: "Link-Local", cidr: "169.254.0.0/16", desc: "169.254.0.0 – 169.254.255.255 (APIPA)" },
    { name: "Multicast", cidr: "224.0.0.0/4", desc: "224.0.0.0 – 239.255.255.255" },
    { name: "Documentation", cidr: "192.0.2.0/24", desc: "TEST-NET-1 (RFC 5737)" },
    { name: "Documentation", cidr: "198.51.100.0/24", desc: "TEST-NET-2 (RFC 5737)" },
    { name: "Documentation", cidr: "203.0.113.0/24", desc: "TEST-NET-3 (RFC 5737)" },
  ];

  const USAGE_COLORS = {
    available: { bg: "#0d4f2b", border: "#17a34a", label: "Available" },
    used:      { bg: "#0c3a5f", border: "#2196f3", label: "Used" },
    reserved:  { bg: "#2a2a2a", border: "#666", label: "Reserved" },
    dmz:       { bg: "#5c3d0e", border: "#f59e0b", label: "DMZ" },
    server:    { bg: "#3b1f6e", border: "#9333ea", label: "Server" },
    guest:     { bg: "#5c1e1e", border: "#ef4444", label: "Guest" },
  };

  function ipToInt(ip) {
    const p = ip.split(".").map(Number);
    return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
  }

  function intToIp(n) {
    return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
  }

  function parseCidr(cidr) {
    const m = cidr.trim().match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/);
    if (!m) return null;
    const prefix = parseInt(m[2], 10);
    if (prefix < 0 || prefix > 32) return null;
    const ip = ipToInt(m[1]);
    const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
    const network = (ip & mask) >>> 0;
    const broadcast = (network | (~mask >>> 0)) >>> 0;
    const totalHosts = Math.pow(2, 32 - prefix);
    const usableHosts = prefix <= 30 ? totalHosts - 2 : (prefix === 31 ? 2 : 1);
    const wildcard = (~mask) >>> 0;
    return { ip: m[1], prefix, mask, network, broadcast, totalHosts, usableHosts, wildcard,
      networkIp: intToIp(network), broadcastIp: intToIp(broadcast),
      maskIp: intToIp(mask), wildcardIp: intToIp(wildcard),
      firstUsable: prefix <= 30 ? intToIp(network + 1) : intToIp(network),
      lastUsable: prefix <= 30 ? intToIp(broadcast - 1) : intToIp(broadcast),
      cidr: intToIp(network) + "/" + prefix };
  }

  function subnetContains(subnet, ip) {
    const n = ipToInt(ip);
    return n >= subnet.network && n <= subnet.broadcast;
  }

  function splitSubnet(cidr) {
    const s = parseCidr(cidr);
    if (!s || s.prefix >= 32) return null;
    const newPrefix = s.prefix + 1;
    const half = Math.pow(2, 32 - newPrefix);
    return [
      intToIp(s.network) + "/" + newPrefix,
      intToIp(s.network + half) + "/" + newPrefix
    ];
  }

  function mergeSubnets(cidr1, cidr2) {
    const s1 = parseCidr(cidr1), s2 = parseCidr(cidr2);
    if (!s1 || !s2 || s1.prefix !== s2.prefix || s1.prefix === 0) return null;
    const newPrefix = s1.prefix - 1;
    const parentMask = newPrefix === 0 ? 0 : (0xFFFFFFFF << (32 - newPrefix)) >>> 0;
    const parent1 = (s1.network & parentMask) >>> 0;
    const parent2 = (s2.network & parentMask) >>> 0;
    if (parent1 !== parent2) return null;
    return intToIp(parent1) + "/" + newPrefix;
  }

  // VLSM calculator
  function vlsmCalculate(baseCidr, requirements) {
    const base = parseCidr(baseCidr);
    if (!base) return { error: "Invalid base CIDR" };
    const sorted = requirements.map((r, i) => ({ ...r, index: i })).sort((a, b) => b.hosts - a.hosts);
    const results = [];
    let currentAddr = base.network;
    for (const req of sorted) {
      let bits = 0;
      while (Math.pow(2, bits) - 2 < req.hosts && bits < 32) bits++;
      const prefix = 32 - bits;
      const size = Math.pow(2, bits);
      const aligned = (Math.ceil(currentAddr / size) * size) >>> 0;
      if (aligned + size - 1 > base.broadcast) {
        return { error: "Not enough address space for '" + req.name + "' (" + req.hosts + " hosts)" };
      }
      const subnet = parseCidr(intToIp(aligned) + "/" + prefix);
      results.push({ name: req.name, requested: req.hosts, allocated: Math.pow(2, bits) - 2, ...subnet, index: req.index });
      currentAddr = aligned + size;
    }
    const wasted = base.totalHosts - (currentAddr - base.network);
    return { results: results.sort((a, b) => a.index - b.index), wasted, total: base.totalHosts };
  }

  // Supernetting
  function supernet(cidrs) {
    if (cidrs.length < 2) return { error: "Need at least 2 subnets" };
    const parsed = cidrs.map(parseCidr).filter(Boolean);
    if (parsed.length < 2) return { error: "Invalid CIDR(s)" };
    let minNet = parsed[0].network, maxBcast = parsed[0].broadcast;
    for (const s of parsed) {
      if (s.network < minNet) minNet = s.network;
      if (s.broadcast > maxBcast) maxBcast = s.broadcast;
    }
    let bits = 0;
    while (Math.pow(2, bits) <= (maxBcast - minNet)) bits++;
    const prefix = 32 - bits;
    const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
    const network = (minNet & mask) >>> 0;
    return { supernet: parseCidr(intToIp(network) + "/" + prefix), inputs: parsed };
  }

  // State
  let currentCidr = "192.168.1.0/24";
  let subnets = [];
  let selectedSubnet = null;
  let vlsmReqs = [{ name: "LAN", hosts: 50 }, { name: "Servers", hosts: 10 }, { name: "DMZ", hosts: 5 }];
  let activeTab = "calculator";

  function initSubnets() {
    const s = parseCidr(currentCidr);
    if (!s) return;
    subnets = [{ cidr: s.cidr, usage: "available", label: "" }];
    selectedSubnet = null;
  }
  initSubnets();

  function formatNumber(n) {
    return n.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  }

  function render() {
    const s = parseCidr(currentCidr);
    container.innerHTML = `
      <style>
        .sv-wrap{font-family:system-ui,-apple-system,sans-serif;color:#e0e0e0;max-width:1200px;margin:0 auto;padding:20px}
        .sv-h1{font-size:1.6rem;font-weight:700;color:#00d4ff;margin:0 0 6px}
        .sv-sub{color:#888;font-size:.85rem;margin:0 0 20px}
        .sv-tabs{display:flex;gap:4px;margin-bottom:20px;border-bottom:1px solid #333}
        .sv-tab{padding:8px 16px;cursor:pointer;color:#888;border:none;background:none;font-size:.85rem;border-bottom:2px solid transparent;transition:all .2s}
        .sv-tab:hover{color:#ccc}
        .sv-tab.active{color:#00d4ff;border-bottom-color:#00d4ff}
        .sv-card{background:#111;border:1px solid #222;border-radius:8px;padding:16px;margin-bottom:16px}
        .sv-card h3{margin:0 0 12px;font-size:1rem;color:#00d4ff}
        .sv-input{background:#0a0a0a;border:1px solid #333;color:#e0e0e0;padding:8px 12px;border-radius:4px;font-family:monospace;font-size:.9rem;width:100%}
        .sv-input:focus{outline:none;border-color:#00d4ff}
        .sv-btn{background:#00d4ff;color:#000;border:none;padding:6px 14px;border-radius:4px;cursor:pointer;font-size:.8rem;font-weight:600;transition:opacity .2s}
        .sv-btn:hover{opacity:.85}
        .sv-btn-sm{padding:4px 10px;font-size:.75rem}
        .sv-btn-ghost{background:none;border:1px solid #444;color:#ccc}
        .sv-btn-ghost:hover{border-color:#00d4ff;color:#00d4ff}
        .sv-btn-danger{background:#ef4444}
        .sv-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px}
        .sv-row{display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid #1a1a1a}
        .sv-label{color:#888;font-size:.82rem}
        .sv-val{font-family:monospace;color:#e0e0e0;font-size:.85rem}
        .sv-val.accent{color:#00d4ff}
        .sv-map{display:grid;gap:3px;margin:12px 0}
        .sv-cell{padding:6px 4px;border-radius:4px;font-size:.65rem;font-family:monospace;text-align:center;cursor:pointer;border:1px solid transparent;transition:all .15s;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
        .sv-cell:hover{transform:scale(1.05);z-index:1;box-shadow:0 2px 8px rgba(0,0,0,.5)}
        .sv-cell.selected{border-color:#fff!important;box-shadow:0 0 0 1px #fff}
        .sv-legend{display:flex;gap:12px;flex-wrap:wrap;margin:8px 0}
        .sv-legend-item{display:flex;align-items:center;gap:4px;font-size:.75rem;color:#888}
        .sv-legend-dot{width:12px;height:12px;border-radius:2px;border:1px solid}
        .sv-detail{background:#0a0f14;border:1px solid #00d4ff33;border-radius:8px;padding:16px;margin-top:12px}
        .sv-presets{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0}
        .sv-preset{padding:4px 10px;border:1px solid #333;border-radius:12px;font-size:.75rem;cursor:pointer;background:none;color:#888;transition:all .2s}
        .sv-preset:hover{border-color:#00d4ff;color:#00d4ff}
        .sv-vlsm-row{display:grid;grid-template-columns:1fr 80px 40px;gap:8px;align-items:center;margin:4px 0}
        .sv-vlsm-input{background:#0a0a0a;border:1px solid #333;color:#e0e0e0;padding:6px 8px;border-radius:4px;font-size:.8rem}
        .sv-result-bar{height:20px;border-radius:3px;position:relative;overflow:hidden;margin:4px 0}
        .sv-result-fill{height:100%;border-radius:3px;display:flex;align-items:center;padding:0 6px;font-size:.65rem;font-weight:600;white-space:nowrap}
        .sv-export{background:#0a0a0a;border:1px solid #333;border-radius:4px;padding:12px;font-family:monospace;font-size:.75rem;white-space:pre;overflow-x:auto;color:#aaa;max-height:300px;overflow-y:auto}
        .sv-table{width:100%;border-collapse:collapse;font-size:.82rem}
        .sv-table th{text-align:left;padding:6px 8px;border-bottom:1px solid #333;color:#888;font-weight:600}
        .sv-table td{padding:6px 8px;border-bottom:1px solid #1a1a1a;font-family:monospace}
        .sv-2col{display:grid;grid-template-columns:1fr 1fr;gap:16px}
        @media(max-width:768px){.sv-2col{grid-template-columns:1fr}}
      </style>
      <div class="sv-wrap">
        <h1 class="sv-h1">Subnet Visualizer</h1>
        <p class="sv-sub">Interactive CIDR calculator, visual subnet mapper, and VLSM planner</p>
        <div class="sv-tabs">
          ${["calculator", "visual map", "VLSM", "supernet", "reference"].map(t =>
            `<button class="sv-tab ${activeTab === t ? "active" : ""}" onclick="this.closest('.sv-wrap').__setTab('${t}')">${t.charAt(0).toUpperCase() + t.slice(1)}</button>`
          ).join("")}
        </div>
        ${activeTab === "calculator" ? renderCalculator(s) : ""}
        ${activeTab === "visual map" ? renderVisualMap(s) : ""}
        ${activeTab === "VLSM" ? renderVLSM(s) : ""}
        ${activeTab === "supernet" ? renderSupernet() : ""}
        ${activeTab === "reference" ? renderReference() : ""}
      </div>`;
    const wrap = container.querySelector(".sv-wrap");
    wrap.__setTab = (t) => { activeTab = t; render(); };
    wrap.__setCidr = (c) => { currentCidr = c; initSubnets(); render(); };
    wrap.__splitSubnet = (idx) => {
      const sub = subnets[idx];
      const halves = splitSubnet(sub.cidr);
      if (halves) {
        subnets.splice(idx, 1, { cidr: halves[0], usage: sub.usage, label: "" }, { cidr: halves[1], usage: "available", label: "" });
        render();
      }
    };
    wrap.__mergeSubnets = (i, j) => {
      const merged = mergeSubnets(subnets[i].cidr, subnets[j].cidr);
      if (merged) {
        const minIdx = Math.min(i, j), maxIdx = Math.max(i, j);
        subnets.splice(maxIdx, 1);
        subnets.splice(minIdx, 1, { cidr: merged, usage: "available", label: "" });
        render();
      }
    };
    wrap.__selectSubnet = (idx) => { selectedSubnet = idx === selectedSubnet ? null : idx; render(); };
    wrap.__setUsage = (idx, usage) => { subnets[idx].usage = usage; render(); };
    wrap.__setLabel = (idx, label) => { subnets[idx].label = label; render(); };
    wrap.__addVlsm = () => { vlsmReqs.push({ name: "Subnet " + (vlsmReqs.length + 1), hosts: 10 }); render(); };
    wrap.__rmVlsm = (i) => { vlsmReqs.splice(i, 1); render(); };
    wrap.__setVlsmName = (i, v) => { vlsmReqs[i].name = v; };
    wrap.__setVlsmHosts = (i, v) => { vlsmReqs[i].hosts = parseInt(v, 10) || 1; };
  }

  function renderCalculator(s) {
    if (!s) return `<div class="sv-card"><p style="color:#ef4444">Invalid CIDR notation. Use format: 192.168.1.0/24</p></div>`;
    const binaryMask = s.mask.toString(2).padStart(32, "0").replace(/(.{8})/g, "$1.").slice(0, -1);
    const binaryNet = s.network.toString(2).padStart(32, "0").replace(/(.{8})/g, "$1.").slice(0, -1);
    const ipClass = s.network < 0x80000000 ? "A" : s.network < 0xC0000000 ? "B" : s.network < 0xE0000000 ? "C" : s.network < 0xF0000000 ? "D" : "E";
    const isPrivate = PRIVATE_RANGES.some(r => { const p = parseCidr(r.cidr); return p && s.network >= p.network && s.broadcast <= p.broadcast; });
    return `
      <div class="sv-card">
        <h3>CIDR Input</h3>
        <div style="display:flex;gap:8px;align-items:center">
          <input class="sv-input" style="max-width:280px" value="${currentCidr}" onchange="this.closest('.sv-wrap').__setCidr(this.value)" placeholder="e.g. 192.168.1.0/24">
        </div>
        <div class="sv-presets" style="margin-top:8px">
          <span style="color:#666;font-size:.75rem;margin-right:4px">Quick:</span>
          ${PRIVATE_RANGES.slice(0, 5).map(r => `<button class="sv-preset" onclick="this.closest('.sv-wrap').__setCidr('${r.cidr}')">${r.cidr}</button>`).join("")}
          <button class="sv-preset" onclick="this.closest('.sv-wrap').__setCidr('192.168.1.0/24')">192.168.1.0/24</button>
          <button class="sv-preset" onclick="this.closest('.sv-wrap').__setCidr('10.0.0.0/16')">10.0.0.0/16</button>
        </div>
      </div>
      <div class="sv-2col">
        <div class="sv-card">
          <h3>Network Details</h3>
          ${[
            ["Network Address", s.networkIp, true],
            ["Broadcast Address", s.broadcastIp, false],
            ["Subnet Mask", s.maskIp, false],
            ["Wildcard Mask", s.wildcardIp, false],
            ["CIDR Notation", "/" + s.prefix, true],
            ["First Usable", s.firstUsable, false],
            ["Last Usable", s.lastUsable, false],
            ["Total Addresses", formatNumber(s.totalHosts), true],
            ["Usable Hosts", formatNumber(s.usableHosts), true],
            ["IP Class", ipClass, false],
            ["Type", isPrivate ? "Private (RFC 1918)" : "Public", false],
          ].map(([l, v, a]) => `<div class="sv-row"><span class="sv-label">${l}</span><span class="sv-val${a ? " accent" : ""}">${v}</span></div>`).join("")}
        </div>
        <div class="sv-card">
          <h3>Binary Representation</h3>
          <div class="sv-row"><span class="sv-label">Network</span><span class="sv-val" style="font-size:.75rem">${binaryNet}</span></div>
          <div class="sv-row"><span class="sv-label">Mask</span><span class="sv-val" style="font-size:.75rem">${binaryMask}</span></div>
          <h3 style="margin-top:16px">Subnet Sizes</h3>
          <div style="max-height:200px;overflow-y:auto">
            <table class="sv-table">
              <tr><th>CIDR</th><th>Mask</th><th>Hosts</th></tr>
              ${[8,12,16,20,21,22,23,24,25,26,27,28,29,30,31,32].map(p => {
                const m = p === 0 ? 0 : (0xFFFFFFFF << (32 - p)) >>> 0;
                const hosts = p <= 30 ? Math.pow(2, 32 - p) - 2 : p === 31 ? 2 : 1;
                const active = p === s.prefix;
                return `<tr style="${active ? "background:#00d4ff15;color:#00d4ff" : ""}"><td>/${p}</td><td>${intToIp(m)}</td><td>${formatNumber(hosts)}</td></tr>`;
              }).join("")}
            </table>
          </div>
        </div>
      </div>
      <div class="sv-card">
        <h3>Export</h3>
        <div class="sv-export">Network:     ${s.networkIp}/${s.prefix}
Mask:        ${s.maskIp}
Wildcard:    ${s.wildcardIp}
Broadcast:   ${s.broadcastIp}
Usable:      ${s.firstUsable} – ${s.lastUsable}
Hosts:       ${formatNumber(s.usableHosts)}
Class:       ${ipClass} (${isPrivate ? "Private" : "Public"})</div>
      </div>`;
  }

  function renderVisualMap(s) {
    if (!s) return `<div class="sv-card"><p style="color:#ef4444">Invalid CIDR</p></div>`;
    const maxCells = 256;
    const cols = s.prefix >= 24 ? Math.min(16, s.totalHosts) : 16;
    return `
      <div class="sv-card">
        <h3>Subnet Map — ${currentCidr}</h3>
        <div class="sv-legend">
          ${Object.entries(USAGE_COLORS).map(([k, v]) =>
            `<span class="sv-legend-item"><span class="sv-legend-dot" style="background:${v.bg};border-color:${v.border}"></span>${v.label}</span>`
          ).join("")}
        </div>
        <div class="sv-map" style="grid-template-columns:repeat(${cols},1fr)">
          ${subnets.map((sub, i) => {
            const p = parseCidr(sub.cidr);
            const c = USAGE_COLORS[sub.usage] || USAGE_COLORS.available;
            const span = Math.max(1, Math.min(cols, Math.ceil(p.totalHosts / (s.totalHosts / maxCells))));
            return `<div class="sv-cell ${i === selectedSubnet ? "selected" : ""}"
              style="background:${c.bg};border-color:${c.border};grid-column:span ${Math.min(span, cols)}"
              onclick="this.closest('.sv-wrap').__selectSubnet(${i})"
              title="${sub.cidr} (${sub.usage})">${sub.label || sub.cidr}</div>`;
          }).join("")}
        </div>
        ${selectedSubnet !== null && subnets[selectedSubnet] ? renderSelectedDetail(selectedSubnet) : ""}
        <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap">
          <button class="sv-btn sv-btn-sm" onclick="this.closest('.sv-wrap').__setCidr(prompt('Enter CIDR:') || '${currentCidr}')">Change Network</button>
        </div>
      </div>`;
  }

  function renderSelectedDetail(idx) {
    const sub = subnets[idx];
    const p = parseCidr(sub.cidr);
    if (!p) return "";
    return `
      <div class="sv-detail">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
          <strong style="color:#00d4ff">${sub.cidr}</strong>
          <div style="display:flex;gap:6px">
            ${p.prefix < 32 ? `<button class="sv-btn sv-btn-sm" onclick="this.closest('.sv-wrap').__splitSubnet(${idx})">Split /${p.prefix + 1}</button>` : ""}
            ${idx > 0 ? `<button class="sv-btn sv-btn-sm sv-btn-ghost" onclick="this.closest('.sv-wrap').__mergeSubnets(${idx - 1},${idx})">Merge ↑</button>` : ""}
          </div>
        </div>
        ${[
          ["Network", p.networkIp], ["Broadcast", p.broadcastIp], ["Usable", p.firstUsable + " – " + p.lastUsable], ["Hosts", formatNumber(p.usableHosts)]
        ].map(([l, v]) => `<div class="sv-row"><span class="sv-label">${l}</span><span class="sv-val">${v}</span></div>`).join("")}
        <div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap">
          <span style="color:#888;font-size:.75rem">Usage:</span>
          ${Object.entries(USAGE_COLORS).map(([k, v]) =>
            `<button class="sv-preset" style="${sub.usage === k ? "border-color:#00d4ff;color:#00d4ff" : ""}" onclick="this.closest('.sv-wrap').__setUsage(${idx},'${k}')">${v.label}</button>`
          ).join("")}
        </div>
        <div style="margin-top:6px"><input class="sv-vlsm-input" style="width:200px" placeholder="Label (e.g. Office LAN)" value="${sub.label}" onchange="this.closest('.sv-wrap').__setLabel(${idx},this.value)"></div>
      </div>`;
  }

  function renderVLSM(s) {
    if (!s) return `<div class="sv-card"><p style="color:#ef4444">Invalid CIDR</p></div>`;
    const result = vlsmCalculate(currentCidr, vlsmReqs);
    return `
      <div class="sv-card">
        <h3>VLSM Calculator — ${currentCidr}</h3>
        <p style="color:#888;font-size:.8rem;margin:0 0 12px">Enter subnet names and required host counts. The calculator finds the optimal CIDR split.</p>
        ${vlsmReqs.map((r, i) => `
          <div class="sv-vlsm-row">
            <input class="sv-vlsm-input" value="${r.name}" onchange="this.closest('.sv-wrap').__setVlsmName(${i},this.value)" placeholder="Subnet name">
            <input class="sv-vlsm-input" type="number" min="1" value="${r.hosts}" onchange="this.closest('.sv-wrap').__setVlsmHosts(${i},this.value)" placeholder="Hosts">
            <button class="sv-btn sv-btn-sm sv-btn-danger" onclick="this.closest('.sv-wrap').__rmVlsm(${i})">×</button>
          </div>`).join("")}
        <button class="sv-btn sv-btn-sm sv-btn-ghost" style="margin-top:8px" onclick="this.closest('.sv-wrap').__addVlsm()">+ Add Subnet</button>
      </div>
      <div class="sv-card">
        <h3>Results</h3>
        ${result.error ? `<p style="color:#ef4444">${result.error}</p>` : `
          <table class="sv-table">
            <tr><th>Name</th><th>Network</th><th>Mask</th><th>Requested</th><th>Allocated</th><th>Usable Range</th></tr>
            ${result.results.map(r => `
              <tr>
                <td style="color:#00d4ff">${r.name}</td>
                <td>${r.networkIp}/${r.prefix}</td>
                <td>${r.maskIp}</td>
                <td>${r.requested}</td>
                <td>${r.allocated}</td>
                <td style="font-size:.75rem">${r.firstUsable} – ${r.lastUsable}</td>
              </tr>`).join("")}
          </table>
          <div style="margin-top:12px;display:flex;gap:16px;font-size:.8rem;color:#888">
            <span>Total: ${formatNumber(result.total)} addresses</span>
            <span>Wasted: ${formatNumber(result.wasted)} (${(result.wasted / result.total * 100).toFixed(1)}%)</span>
          </div>
          ${result.results.map(r => {
            const pct = (r.totalHosts / result.total * 100).toFixed(1);
            const c = USAGE_COLORS[Object.keys(USAGE_COLORS)[r.index % Object.keys(USAGE_COLORS).length]];
            return `<div class="sv-result-bar"><div class="sv-result-fill" style="width:${Math.max(2, pct)}%;background:${c.bg};border:1px solid ${c.border}">${r.name} (/${r.prefix})</div></div>`;
          }).join("")}
        `}
      </div>`;
  }

  function renderSupernet() {
    return `
      <div class="sv-card">
        <h3>Supernetting / Aggregation</h3>
        <p style="color:#888;font-size:.8rem;margin:0 0 12px">Enter multiple CIDR ranges (one per line) to find the smallest supernet that covers all of them.</p>
        <textarea class="sv-input" id="sv-supernet-input" rows="4" placeholder="192.168.1.0/24&#10;192.168.2.0/24&#10;192.168.3.0/24">192.168.0.0/24\n192.168.1.0/24</textarea>
        <button class="sv-btn" style="margin-top:8px" onclick="(function(){
          const ta = document.getElementById('sv-supernet-input');
          const cidrs = ta.value.split(/[\\n,]+/).map(s=>s.trim()).filter(Boolean);
          const r = (${supernet.toString()})(cidrs);
          const out = document.getElementById('sv-supernet-result');
          if (r.error) { out.innerHTML = '<p style=color:#ef4444>'+r.error+'</p>'; return; }
          const s = r.supernet;
          out.innerHTML = '<strong style=color:#00d4ff>Supernet: '+s.cidr+'</strong><br>Mask: '+s.maskIp+'<br>Hosts: '+(s.usableHosts)+'<br>Range: '+s.networkIp+' – '+s.broadcastIp;
        })()">Calculate Supernet</button>
        <div id="sv-supernet-result" style="margin-top:12px;font-size:.85rem"></div>
      </div>`;
  }

  function renderReference() {
    return `
      <div class="sv-card">
        <h3>Private Address Ranges (RFC 1918 + Special)</h3>
        <table class="sv-table">
          <tr><th>Name</th><th>CIDR</th><th>Range</th></tr>
          ${PRIVATE_RANGES.map(r => `<tr><td>${r.name}</td><td style="color:#00d4ff;cursor:pointer" onclick="this.closest('.sv-wrap').__setCidr('${r.cidr}')">${r.cidr}</td><td style="font-size:.75rem">${r.desc}</td></tr>`).join("")}
        </table>
      </div>
      <div class="sv-card">
        <h3>Subnet Cheat Sheet</h3>
        <table class="sv-table">
          <tr><th>CIDR</th><th>Subnet Mask</th><th>Wildcard</th><th>Addresses</th><th>Usable</th><th>Typical Use</th></tr>
          ${[
            ["/8", "255.0.0.0", "0.255.255.255", "16,777,216", "16,777,214", "Class A network"],
            ["/12", "255.240.0.0", "0.15.255.255", "1,048,576", "1,048,574", "172.16.0.0 private"],
            ["/16", "255.255.0.0", "0.0.255.255", "65,536", "65,534", "Large campus"],
            ["/20", "255.255.240.0", "0.0.15.255", "4,096", "4,094", "Large department"],
            ["/22", "255.255.252.0", "0.0.3.255", "1,024", "1,022", "Building floor"],
            ["/24", "255.255.255.0", "0.0.0.255", "256", "254", "Standard LAN"],
            ["/25", "255.255.255.128", "0.0.0.127", "128", "126", "Half subnet"],
            ["/26", "255.255.255.192", "0.0.0.63", "64", "62", "Small office"],
            ["/27", "255.255.255.224", "0.0.0.31", "32", "30", "Conference room"],
            ["/28", "255.255.255.240", "0.0.0.15", "16", "14", "DMZ / servers"],
            ["/29", "255.255.255.248", "0.0.0.7", "8", "6", "Point-to-point link"],
            ["/30", "255.255.255.252", "0.0.0.3", "4", "2", "WAN link"],
            ["/31", "255.255.255.254", "0.0.0.1", "2", "2", "P2P (RFC 3021)"],
            ["/32", "255.255.255.255", "0.0.0.0", "1", "1", "Host route"],
          ].map(r => `<tr><td style="color:#00d4ff">${r[0]}</td><td>${r[1]}</td><td>${r[2]}</td><td>${r[3]}</td><td>${r[4]}</td><td style="color:#888;font-size:.75rem">${r[5]}</td></tr>`).join("")}
        </table>
      </div>`;
  }

  render();
}
