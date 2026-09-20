// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Source-available for learning only. Redistribution prohibited. See LICENSE.
(function(){var _h=location.hostname,_a=["darknode.ai","www.darknode.ai","localhost","127.0.0.1"];if(!_a.some(function(d){return _h===d}))throw document.body.innerHTML="",new Error("unlicensed")}());

// Timeline Viz — interactive security timeline and attack chain visualization.
// Renders kill chains, topology diagrams, attack trees, risk heat maps, and incident timelines.

const KILL_CHAIN_PHASES = [
  { id: "recon", name: "Reconnaissance", color: "#64b5f6",
    desc: "Harvesting information: email addresses, network ranges, public-facing services.",
    techniques: ["OSINT gathering", "Port scanning (Nmap)", "DNS enumeration", "Social media profiling", "Google dorking", "Whois lookup", "Shodan/Censys search", "Technology fingerprinting"] },
  { id: "weaponize", name: "Weaponization", color: "#7986cb",
    desc: "Coupling an exploit with a backdoor into a deliverable payload.",
    techniques: ["Malware development", "Document exploit embedding", "Macro payload creation", "Custom C2 implant", "Payload obfuscation", "Dropper creation", "Watering hole setup", "Supply chain compromise"] },
  { id: "deliver", name: "Delivery", color: "#9575cd",
    desc: "Transmitting the weaponized payload to the target environment.",
    techniques: ["Spear phishing email", "USB drop", "Watering hole", "Drive-by download", "Third-party compromise", "Social engineering call", "Malicious ad (malvertising)", "Physical access"] },
  { id: "exploit", name: "Exploitation", color: "#f06292",
    desc: "Triggering the exploit to gain initial code execution.",
    techniques: ["Buffer overflow", "SQL injection", "Command injection", "Deserialization exploit", "Zero-day exploit", "Macro execution", "Browser exploit", "Privilege escalation"] },
  { id: "install", name: "Installation", color: "#ef5350",
    desc: "Installing persistent access mechanism on the target system.",
    techniques: ["Web shell", "RAT installation", "Registry persistence", "Scheduled task", "Service creation", "DLL side-loading", "Bootkit/rootkit", "Cron job"] },
  { id: "c2", name: "Command & Control", color: "#ff7043",
    desc: "Establishing a command channel for remote control of the implant.",
    techniques: ["HTTPS C2 beacon", "DNS tunneling", "Domain fronting", "Social media C2", "Encrypted channel", "Legitimate cloud services", "Custom protocol", "Steganography"] },
  { id: "actions", name: "Actions on Objectives", color: "#ffa726",
    desc: "Accomplishing the original goal: data theft, disruption, or destruction.",
    techniques: ["Data exfiltration", "Lateral movement", "Credential harvesting", "Ransomware deployment", "Data destruction", "Espionage", "Cryptocurrency mining", "Supply chain attack"] },
];

const MITRE_TACTICS = [
  { id: "TA0043", name: "Reconnaissance", color: "#78909c", count: 10 },
  { id: "TA0042", name: "Resource Development", color: "#90a4ae", count: 8 },
  { id: "TA0001", name: "Initial Access", color: "#64b5f6", count: 9 },
  { id: "TA0002", name: "Execution", color: "#7986cb", count: 14 },
  { id: "TA0003", name: "Persistence", color: "#9575cd", count: 19 },
  { id: "TA0004", name: "Privilege Escalation", color: "#ce93d8", count: 13 },
  { id: "TA0005", name: "Defense Evasion", color: "#f48fb1", count: 42 },
  { id: "TA0006", name: "Credential Access", color: "#ef9a9a", count: 17 },
  { id: "TA0007", name: "Discovery", color: "#ffab91", count: 31 },
  { id: "TA0008", name: "Lateral Movement", color: "#ffcc80", count: 9 },
  { id: "TA0009", name: "Collection", color: "#ffe082", count: 17 },
  { id: "TA0011", name: "Command and Control", color: "#fff59d", count: 16 },
  { id: "TA0010", name: "Exfiltration", color: "#c5e1a5", count: 9 },
  { id: "TA0040", name: "Impact", color: "#80cbc4", count: 14 },
];

const RISK_MATRIX = {
  labels: { likelihood: ["Rare", "Unlikely", "Possible", "Likely", "Almost Certain"], impact: ["Negligible", "Minor", "Moderate", "Major", "Severe"] },
  cells: [
    [1,2,3,4,5],
    [2,4,6,8,10],
    [3,6,9,12,15],
    [4,8,12,16,20],
    [5,10,15,20,25]
  ],
  colors: { 1: "#1b5e20", 2: "#2e7d32", 3: "#388e3c", 4: "#43a047", 5: "#66bb6a",
    6: "#fdd835", 8: "#fbc02d", 9: "#f9a825", 10: "#f57f17",
    12: "#ef6c00", 15: "#e65100", 16: "#d84315", 20: "#c62828", 25: "#b71c1c" }
};

const SAMPLE_INCIDENT = [
  { time: "2026-03-15 02:14:33", event: "Anomalous DNS query to c2.evil.xyz from 10.0.5.22", severity: "medium", phase: "c2" },
  { time: "2026-03-15 02:14:35", event: "IDS alert: Cobalt Strike beacon pattern detected", severity: "high", phase: "c2" },
  { time: "2026-03-15 02:15:01", event: "Process notepad.exe spawned cmd.exe on 10.0.5.22", severity: "high", phase: "exploit" },
  { time: "2026-03-15 02:15:12", event: "Lateral movement: SMB connection from 10.0.5.22 to 10.0.5.50", severity: "critical", phase: "actions" },
  { time: "2026-03-15 02:15:30", event: "Credential dump: lsass.exe memory access on 10.0.5.50", severity: "critical", phase: "actions" },
  { time: "2026-03-15 02:16:00", event: "New admin account 'svc_backup' created on DC01", severity: "critical", phase: "install" },
  { time: "2026-03-15 02:17:22", event: "Large data transfer (2.3 GB) to external IP 185.x.x.x", severity: "critical", phase: "actions" },
  { time: "2026-03-15 02:18:00", event: "Scheduled task created for persistence on DC01", severity: "high", phase: "install" },
  { time: "2026-03-15 02:20:00", event: "SOC analyst acknowledged alert, began investigation", severity: "info", phase: "response" },
  { time: "2026-03-15 02:25:00", event: "Network segment 10.0.5.0/24 isolated", severity: "info", phase: "response" },
  { time: "2026-03-15 02:30:00", event: "Forensic image capture initiated on 10.0.5.22", severity: "info", phase: "response" },
  { time: "2026-03-15 03:00:00", event: "C2 domain sinkholed via DNS", severity: "info", phase: "response" },
];

const SEV_COLORS = { critical: "#ff1744", high: "#ff6d00", medium: "#ffd600", low: "#00e676", info: "#448aff" };

function drawTopology(canvas, width, height) {
  const ctx = canvas.getContext("2d");
  canvas.width = width; canvas.height = height;
  const nodes = [
    { x: width/2, y: 40, label: "Internet", type: "cloud", color: "#64b5f6" },
    { x: width/2, y: 120, label: "Firewall", type: "firewall", color: "#ef5350" },
    { x: width/2, y: 200, label: "DMZ Switch", type: "switch", color: "#ffa726" },
    { x: width/4, y: 280, label: "Web Server", type: "server", color: "#66bb6a" },
    { x: width*3/4, y: 280, label: "Mail Server", type: "server", color: "#66bb6a" },
    { x: width/2, y: 340, label: "Internal FW", type: "firewall", color: "#ef5350" },
    { x: width/4, y: 420, label: "Workstations", type: "pc", color: "#90caf9" },
    { x: width/2, y: 420, label: "Domain Controller", type: "server", color: "#ce93d8" },
    { x: width*3/4, y: 420, label: "File Server", type: "server", color: "#66bb6a" },
    { x: width/2, y: 500, label: "Database", type: "database", color: "#ffb74d" },
  ];
  const edges = [[0,1],[1,2],[2,3],[2,4],[2,5],[5,6],[5,7],[5,8],[7,9]];
  ctx.strokeStyle = "rgba(255,255,255,0.15)"; ctx.lineWidth = 2;
  edges.forEach(([a,b]) => {
    ctx.beginPath(); ctx.moveTo(nodes[a].x, nodes[a].y); ctx.lineTo(nodes[b].x, nodes[b].y); ctx.stroke();
  });
  nodes.forEach(n => {
    ctx.fillStyle = n.color + "22"; ctx.strokeStyle = n.color;
    ctx.beginPath(); ctx.arc(n.x, n.y, 20, 0, Math.PI*2); ctx.fill(); ctx.stroke();
    ctx.fillStyle = n.color; ctx.font = "bold 10px system-ui"; ctx.textAlign = "center";
    ctx.fillText(n.label, n.x, n.y + 34);
  });
}

export function renderTimelineViz(container) {
  container.innerHTML = `
    <div style="max-width:1100px;margin:0 auto;padding:24px;">
      <h2 style="font-size:1.6rem;font-weight:700;margin:0 0 6px;">Security Visualization</h2>
      <p style="color:var(--txt-dim,#888);margin:0 0 20px;font-size:.9rem;">Interactive kill chains, topology diagrams, risk matrices, and incident timelines.</p>

      <div style="display:flex;gap:8px;margin-bottom:24px;flex-wrap:wrap;">
        <button class="viz-tab active" data-tab="killchain" style="padding:8px 16px;border-radius:6px;border:1px solid var(--border,#333);background:var(--acc,#00d4ff);color:#000;cursor:pointer;font-weight:600;font-size:.82rem;">Kill Chain</button>
        <button class="viz-tab" data-tab="mitre" style="padding:8px 16px;border-radius:6px;border:1px solid var(--border,#333);background:var(--bg-alt,#111);color:var(--txt,#fff);cursor:pointer;font-weight:600;font-size:.82rem;">MITRE ATT&CK</button>
        <button class="viz-tab" data-tab="topology" style="padding:8px 16px;border-radius:6px;border:1px solid var(--border,#333);background:var(--bg-alt,#111);color:var(--txt,#fff);cursor:pointer;font-weight:600;font-size:.82rem;">Network Topology</button>
        <button class="viz-tab" data-tab="risk" style="padding:8px 16px;border-radius:6px;border:1px solid var(--border,#333);background:var(--bg-alt,#111);color:var(--txt,#fff);cursor:pointer;font-weight:600;font-size:.82rem;">Risk Matrix</button>
        <button class="viz-tab" data-tab="timeline" style="padding:8px 16px;border-radius:6px;border:1px solid var(--border,#333);background:var(--bg-alt,#111);color:var(--txt,#fff);cursor:pointer;font-weight:600;font-size:.82rem;">Incident Timeline</button>
      </div>

      <div id="viz-panel"></div>
    </div>
  `;

  const panel = container.querySelector("#viz-panel");
  const tabs = container.querySelectorAll(".viz-tab");

  function showTab(tab) {
    tabs.forEach(t => { t.style.background = "var(--bg-alt,#111)"; t.style.color = "var(--txt,#fff)"; t.classList.remove("active"); });
    const active = container.querySelector(\`[data-tab="\${tab}"]\`);
    if (active) { active.style.background = "var(--acc,#00d4ff)"; active.style.color = "#000"; active.classList.add("active"); }

    if (tab === "killchain") {
      panel.innerHTML = \`
        <h3 style="font-size:1.1rem;font-weight:600;margin:0 0 16px;">Lockheed Martin Cyber Kill Chain</h3>
        <div style="display:flex;overflow-x:auto;gap:0;padding-bottom:12px;">
          \${KILL_CHAIN_PHASES.map((p, i) => \`
            <div style="flex:0 0 150px;position:relative;">
              <div style="background:\${p.color}22;border:2px solid \${p.color};border-radius:10px;padding:12px;text-align:center;position:relative;z-index:1;">
                <div style="font-size:.72rem;color:\${p.color};font-weight:700;text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px;">Phase \${i+1}</div>
                <div style="font-size:.88rem;font-weight:700;color:var(--txt,#fff);margin-bottom:6px;">\${p.name}</div>
                <div style="font-size:.7rem;color:var(--txt-dim,#999);line-height:1.4;">\${p.desc.substring(0, 80)}...</div>
              </div>
              \${i < KILL_CHAIN_PHASES.length - 1 ? '<div style="position:absolute;right:-12px;top:50%;transform:translateY(-50%);font-size:1.2rem;color:var(--txt-dim,#555);z-index:2;">&rarr;</div>' : ''}
            </div>
          \`).join("")}
        </div>
        <div style="margin-top:20px;display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px;">
          \${KILL_CHAIN_PHASES.map(p => \`
            <div style="background:var(--bg-alt,#111);border:1px solid var(--border,#222);border-radius:8px;padding:14px;border-top:3px solid \${p.color};">
              <h4 style="font-size:.9rem;margin:0 0 8px;color:\${p.color};">\${p.name}</h4>
              <p style="font-size:.78rem;color:var(--txt-dim,#888);margin:0 0 8px;">\${p.desc}</p>
              <ul style="list-style:none;padding:0;margin:0;">
                \${p.techniques.map(t => \`<li style="font-size:.75rem;color:var(--txt-dim,#ccc);padding:2px 0;border-bottom:1px solid var(--border,#1a1a1a);">&#8226; \${t}</li>\`).join("")}
              </ul>
            </div>
          \`).join("")}
        </div>
      \`;
    } else if (tab === "mitre") {
      panel.innerHTML = \`
        <h3 style="font-size:1.1rem;font-weight:600;margin:0 0 16px;">MITRE ATT&CK Tactics</h3>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:8px;">
          \${MITRE_TACTICS.map(t => \`
            <div style="background:\${t.color}15;border:1px solid \${t.color}44;border-radius:8px;padding:12px;text-align:center;cursor:pointer;transition:transform .15s ease,box-shadow .15s ease;" onmouseover="this.style.transform='translateY(-2px)';this.style.boxShadow='0 4px 12px rgba(0,0,0,.3)'" onmouseout="this.style.transform='none';this.style.boxShadow='none'">
              <div style="font-size:.65rem;color:\${t.color};font-family:monospace;margin-bottom:4px;">\${t.id}</div>
              <div style="font-size:.82rem;font-weight:600;color:var(--txt,#fff);margin-bottom:6px;">\${t.name}</div>
              <div style="font-size:1.4rem;font-weight:800;color:\${t.color};">\${t.count}</div>
              <div style="font-size:.65rem;color:var(--txt-dim,#888);">techniques</div>
            </div>
          \`).join("")}
        </div>
      \`;
    } else if (tab === "topology") {
      panel.innerHTML = \`
        <h3 style="font-size:1.1rem;font-weight:600;margin:0 0 16px;">Network Topology</h3>
        <canvas id="topo-canvas" style="width:100%;max-width:800px;display:block;margin:0 auto;background:var(--bg-alt,#0a0a1a);border-radius:12px;border:1px solid var(--border,#222);"></canvas>
        <div style="display:flex;justify-content:center;gap:16px;margin-top:12px;flex-wrap:wrap;">
          <span style="font-size:.72rem;display:flex;align-items:center;gap:4px;"><span style="width:10px;height:10px;border-radius:50%;background:#64b5f6;display:inline-block;"></span> Cloud</span>
          <span style="font-size:.72rem;display:flex;align-items:center;gap:4px;"><span style="width:10px;height:10px;border-radius:50%;background:#ef5350;display:inline-block;"></span> Firewall</span>
          <span style="font-size:.72rem;display:flex;align-items:center;gap:4px;"><span style="width:10px;height:10px;border-radius:50%;background:#ffa726;display:inline-block;"></span> Switch</span>
          <span style="font-size:.72rem;display:flex;align-items:center;gap:4px;"><span style="width:10px;height:10px;border-radius:50%;background:#66bb6a;display:inline-block;"></span> Server</span>
          <span style="font-size:.72rem;display:flex;align-items:center;gap:4px;"><span style="width:10px;height:10px;border-radius:50%;background:#90caf9;display:inline-block;"></span> Workstation</span>
          <span style="font-size:.72rem;display:flex;align-items:center;gap:4px;"><span style="width:10px;height:10px;border-radius:50%;background:#ffb74d;display:inline-block;"></span> Database</span>
        </div>
      \`;
      const c = container.querySelector("#topo-canvas");
      if (c) drawTopology(c, 800, 560);
    } else if (tab === "risk") {
      const M = RISK_MATRIX;
      panel.innerHTML = \`
        <h3 style="font-size:1.1rem;font-weight:600;margin:0 0 16px;">Risk Assessment Matrix</h3>
        <div style="overflow-x:auto;">
          <table style="border-collapse:collapse;min-width:500px;margin:0 auto;">
            <thead>
              <tr>
                <th style="padding:8px;border:1px solid var(--border,#333);background:var(--bg-alt,#111);font-size:.72rem;color:var(--txt-dim,#888);">Likelihood / Impact</th>
                \${M.labels.impact.map(l => \`<th style="padding:8px 12px;border:1px solid var(--border,#333);background:var(--bg-alt,#111);font-size:.75rem;text-align:center;">\${l}</th>\`).join("")}
              </tr>
            </thead>
            <tbody>
              \${M.labels.likelihood.slice().reverse().map((l, ri) => {
                const row = M.cells[4 - ri];
                return \`<tr>
                  <td style="padding:8px 12px;border:1px solid var(--border,#333);background:var(--bg-alt,#111);font-weight:600;font-size:.78rem;">\${l}</td>
                  \${row.map(v => {
                    const c = M.colors[v] || "#666";
                    const label = v <= 3 ? "Low" : v <= 6 ? "Medium" : v <= 12 ? "High" : v <= 16 ? "Very High" : "Critical";
                    return \`<td style="padding:12px;border:1px solid var(--border,#333);background:\${c}33;text-align:center;cursor:pointer;" title="\${label} (\${v})">
                      <div style="font-size:1.1rem;font-weight:800;color:\${c};">\${v}</div>
                      <div style="font-size:.62rem;color:var(--txt-dim,#999);">\${label}</div>
                    </td>\`;
                  }).join("")}
                </tr>\`;
              }).join("")}
            </tbody>
          </table>
        </div>
        <div style="display:flex;justify-content:center;gap:16px;margin-top:16px;flex-wrap:wrap;">
          <span style="font-size:.72rem;display:flex;align-items:center;gap:4px;"><span style="width:14px;height:14px;border-radius:3px;background:#388e3c;display:inline-block;"></span> Low (1-3)</span>
          <span style="font-size:.72rem;display:flex;align-items:center;gap:4px;"><span style="width:14px;height:14px;border-radius:3px;background:#f9a825;display:inline-block;"></span> Medium (4-6)</span>
          <span style="font-size:.72rem;display:flex;align-items:center;gap:4px;"><span style="width:14px;height:14px;border-radius:3px;background:#ef6c00;display:inline-block;"></span> High (8-12)</span>
          <span style="font-size:.72rem;display:flex;align-items:center;gap:4px;"><span style="width:14px;height:14px;border-radius:3px;background:#d84315;display:inline-block;"></span> Very High (15-16)</span>
          <span style="font-size:.72rem;display:flex;align-items:center;gap:4px;"><span style="width:14px;height:14px;border-radius:3px;background:#b71c1c;display:inline-block;"></span> Critical (20-25)</span>
        </div>
      \`;
    } else if (tab === "timeline") {
      panel.innerHTML = \`
        <h3 style="font-size:1.1rem;font-weight:600;margin:0 0 4px;">Incident Timeline</h3>
        <p style="font-size:.78rem;color:var(--txt-dim,#888);margin:0 0 16px;">Sample incident: Cobalt Strike intrusion with lateral movement and data exfiltration.</p>
        <div style="display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap;">
          <span style="font-size:.68rem;display:flex;align-items:center;gap:4px;"><span style="width:8px;height:8px;border-radius:50%;background:#ff1744;"></span> Critical</span>
          <span style="font-size:.68rem;display:flex;align-items:center;gap:4px;"><span style="width:8px;height:8px;border-radius:50%;background:#ff6d00;"></span> High</span>
          <span style="font-size:.68rem;display:flex;align-items:center;gap:4px;"><span style="width:8px;height:8px;border-radius:50%;background:#ffd600;"></span> Medium</span>
          <span style="font-size:.68rem;display:flex;align-items:center;gap:4px;"><span style="width:8px;height:8px;border-radius:50%;background:#448aff;"></span> Info</span>
        </div>
        <div style="position:relative;padding-left:40px;">
          <div style="position:absolute;left:19px;top:0;bottom:0;width:2px;background:var(--border,#333);"></div>
          \${SAMPLE_INCIDENT.map((e, i) => \`
            <div style="position:relative;margin-bottom:16px;animation:fadeInUp .3s ease \${i * 0.05}s both;">
              <div style="position:absolute;left:-29px;top:4px;width:12px;height:12px;border-radius:50%;background:\${SEV_COLORS[e.severity]};border:2px solid var(--bg,#0a0e16);z-index:1;"></div>
              <div style="background:var(--bg-alt,#111);border:1px solid var(--border,#222);border-radius:8px;padding:10px 14px;border-left:3px solid \${SEV_COLORS[e.severity]};">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
                  <code style="font-size:.72rem;color:var(--txt-dim,#888);">\${e.time}</code>
                  <span style="font-size:.65rem;padding:2px 6px;border-radius:4px;background:\${SEV_COLORS[e.severity]}22;color:\${SEV_COLORS[e.severity]};text-transform:uppercase;font-weight:600;">\${e.severity}</span>
                </div>
                <p style="font-size:.82rem;color:var(--txt,#fff);margin:0;">\${e.event}</p>
                <span style="font-size:.65rem;color:var(--txt-dim,#666);margin-top:4px;display:inline-block;">Phase: \${e.phase}</span>
              </div>
            </div>
          \`).join("")}
        </div>
      \`;
    }
  }

  showTab("killchain");
  tabs.forEach(t => t.addEventListener("click", () => showTab(t.dataset.tab)));
}
