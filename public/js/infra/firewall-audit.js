// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// Firewall Rule Audit: paste an on-prem / edge firewall rule-base export
// (iptables, nftables, Cisco ASA/IOS ACL, pfSense/OPNsense, FortiGate, Windows
// Firewall) and get a deterministic analysis: shadowed and redundant rules by
// real address/port containment, any-to-any permits, admin services open to any
// source, missing default deny, logging gaps, broad egress. Each finding carries
// the exact rule, a fix, and the control reference. Everything runs in the browser.
//
//   renderFirewallAudit(main) -> void

import {
  detectFormat, parseConfig, analyze, FORMATS, DEFAULT_INTERNAL, describeAddr, describePorts,
  findingsToCsv, resultToJson, remediationText, summaryText, SEVERITY_ORDER, toSinkFindings,
} from "./firewall-audit-engine.js?v=20261017d";
import { sampleShare, SAMPLE_SHARE } from "../core/sink-map.js";
import { attachSinkButton } from "../core/sink.js";

const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const toast = (m) => { try { (window.showToast || (() => {}))(m); } catch (_) {} };

const SEV = {
  critical: { c: "#b00020", t: "Critical" }, high: { c: "#c0501b", t: "High" }, medium: { c: "#8a6d00", t: "Medium" },
  low: { c: "var(--mut,#667085)", t: "Low" }, info: { c: "var(--mut,#667085)", t: "Info" }, good: { c: "#1b7f4d", t: "Good" },
};
const GRADE_C = { A: "#1b7f4d", B: "#1b7f4d", C: "#8a6d00", D: "#c0501b", F: "#b00020" };

let injected = false;
function injectStyle() {
  if (injected || document.getElementById("fwa-css")) { injected = true; return; }
  injected = true;
  const st = document.createElement("style"); st.id = "fwa-css";
  st.textContent = `
  .fwa{font-size:14px;line-height:1.5;color:var(--txt,var(--tx,#1a2230))}
  .fwa .fwa-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .fwa h1{font-size:1.6rem;margin:0;letter-spacing:-.01em}
  .fwa .fwa-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--mut,#667085);border:1px solid var(--line,#e6e8ee);padding:2px 9px;border-radius:999px}
  .fwa .fwa-sub{color:var(--mut,#667085);margin:6px 0 14px;max-width:78ch}
  .fwa .fwa-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:14px 16px;margin-bottom:14px}
  .fwa h3{font-size:.95rem;margin:0 0 6px}
  .fwa .fwa-note{color:var(--mut,#667085);font-size:.82rem;margin:0 0 10px;overflow-wrap:anywhere}
  .fwa .fwa-grid{display:grid;grid-template-columns:minmax(0,2fr) minmax(0,1fr);gap:14px}
  @media(max-width:900px){.fwa .fwa-grid{grid-template-columns:1fr}}
  .fwa textarea{width:100%;resize:vertical;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;line-height:1.5;padding:10px 12px;border:1px solid var(--line,#d7dbe3);border-radius:8px;background:var(--bg,#fbfcfe);color:var(--txt,var(--tx,#1a2230));box-sizing:border-box}
  .fwa .fwa-in{min-height:260px}
  .fwa .fwa-set{min-height:120px}
  .fwa input[type=text]{width:100%;font:inherit;font-size:13px;padding:8px 10px;border:1px solid var(--line,#d7dbe3);border-radius:8px;background:var(--bg,#fbfcfe);color:var(--txt,var(--tx,#1a2230));box-sizing:border-box}
  .fwa .fwa-row{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-top:10px}
  .fwa .fwa-btn{appearance:none;font:inherit;font-size:.83rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--txt,var(--tx,#1a2230));padding:7px 13px;border-radius:7px;cursor:pointer}
  .fwa .fwa-btn:hover{border-color:var(--acc,#2552c6)}
  .fwa .fwa-btn.pri{background:var(--acc,#2552c6);border-color:var(--acc,#2552c6);color:#fff}
  .fwa .fwa-btn.sm{font-size:.76rem;padding:5px 10px;font-weight:500}
  .fwa .fwa-btn:disabled{opacity:.55;cursor:default}
  .fwa .fwa-badge{font-size:.76rem;font-weight:600;border:1px solid var(--line,#e6e8ee);border-radius:999px;padding:3px 10px;color:var(--mut,#667085)}
  .fwa .fwa-badge.on{color:var(--txt,var(--tx,#1a2230));border-color:var(--acc,#2552c6)}
  .fwa .fwa-lbl{display:block;font-size:.76rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--mut,#667085);margin:10px 0 4px}
  .fwa .fwa-ex{display:flex;gap:6px;flex-wrap:wrap;margin-top:6px}
  .fwa .fwa-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:14px}
  .fwa .fwa-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:10px 14px}
  .fwa .fwa-kpi b{display:block;font-size:1.45rem;line-height:1.2;font-variant-numeric:tabular-nums}
  .fwa .fwa-kpi span{font-size:.72rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.05em}
  .fwa .fwa-score{display:flex;gap:18px;align-items:center;flex-wrap:wrap}
  .fwa .fwa-score .fwa-big{font-size:2.6rem;font-weight:700;line-height:1;font-variant-numeric:tabular-nums;color:var(--c)}
  .fwa .fwa-score .fwa-grade{font-size:1.2rem;font-weight:700;color:var(--c)}
  .fwa .fwa-sev{font-weight:700;color:var(--c);white-space:nowrap}
  .fwa .fwa-c{color:var(--c)}
  .fwa .fwa-tbl{border:1px solid var(--line,#e6e8ee);border-radius:10px;overflow:auto}
  .fwa table{width:100%;border-collapse:collapse;font-size:.84rem}
  .fwa th{text-align:left;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:8px 12px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee);white-space:nowrap;cursor:pointer;user-select:none}
  .fwa th.nosort{cursor:default}
  .fwa td{padding:8px 12px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:anywhere}
  .fwa tr:last-child td{border-bottom:0}
  .fwa tr.fwa-f{cursor:pointer}
  .fwa tr.fwa-f:hover td{background:var(--bg,#f7f8fb)}
  .fwa tr.fwa-x td{background:var(--bg,#fbfcfe);padding:12px 14px 14px}
  .fwa .fwa-mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
  .fwa pre{margin:6px 0 0;padding:10px 12px;border:1px solid var(--line,#e6e8ee);border-radius:8px;background:var(--card,#fff);font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;line-height:1.5;white-space:pre-wrap;overflow-wrap:anywhere;max-height:280px;overflow:auto}
  .fwa .fwa-x h4{font-size:.78rem;text-transform:uppercase;letter-spacing:.05em;color:var(--mut,#667085);margin:12px 0 4px}
  .fwa .fwa-x h4:first-child{margin-top:0}
  .fwa .fwa-x p{margin:0;white-space:pre-line}
  .fwa .fwa-flag{display:inline-block;font-size:.68rem;font-weight:700;letter-spacing:.04em;text-transform:uppercase;border:1px solid currentColor;border-radius:4px;padding:0 5px;margin-right:4px;color:var(--c)}
  .fwa .fwa-dim{color:var(--mut,#667085)}
  .fwa .fwa-off td{color:var(--mut,#667085);text-decoration:line-through}
  .fwa .fwa-off td.fwa-keep{text-decoration:none}
  .fwa .fwa-empty{padding:26px;text-align:center;color:var(--mut,#667085)}
  .fwa .fwa-tabs{display:flex;gap:4px;flex-wrap:wrap;margin:14px 0 10px;border-bottom:1px solid var(--line,#e6e8ee)}
  .fwa .fwa-tab{appearance:none;font:inherit;font-size:.84rem;font-weight:600;background:none;border:0;border-bottom:2px solid transparent;padding:8px 12px;color:var(--mut,#667085);cursor:pointer;margin-bottom:-1px}
  .fwa .fwa-tab.on{color:var(--txt,var(--tx,#1a2230));border-bottom-color:var(--acc,#2552c6)}
  .fwa .fwa-notes{font-size:.8rem;color:var(--mut,#667085);margin:8px 0 0;padding-left:18px}
  .fwa .fwa-notes li{margin:2px 0}
  .fwa details{margin-top:8px}
  .fwa summary{cursor:pointer;font-size:.82rem;color:var(--mut,#667085)}
  `;
  document.head.appendChild(st);
}

function download(name, text, type) {
  const b = new Blob([text], { type: type || "text/plain" });
  const u = URL.createObjectURL(b); const a = document.createElement("a");
  a.href = u; a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(u), 1000);
}
async function copyText(t) {
  try { await navigator.clipboard.writeText(t); toast("Copied"); }
  catch (_) { toast("Copy failed; select the text manually"); }
}

// Synthetic example configs (clearly labelled in the UI). Each one contains a mix
// of issues so the analyses have something to show.
const EXAMPLES = {
  iptables: `# Generated by iptables-save (example, synthetic)
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -s 10.0.0.0/8 -p tcp -m tcp --dport 3306 -j ACCEPT
-A INPUT -s 10.1.0.0/16 -p tcp -m tcp --dport 3306 -j ACCEPT
-A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 3389 -j ACCEPT
-A INPUT -s 192.168.1.0/24 -p tcp --dport 22 -j DROP
-A INPUT -s 10.0.0.0/8 -p tcp --dport 8080 -j ACCEPT
-A INPUT -p tcp --dport 9000 -m comment --comment "temp test rule" -j ACCEPT
-A FORWARD -s 10.0.0.0/8 -j ACCEPT
COMMIT
`,
  nft: `table inet filter {
	chain input {
		type filter hook input priority 0; policy accept;
		iif "lo" accept
		ct state established,related accept
		tcp dport 22 accept
		ip saddr 10.0.0.0/8 tcp dport { 80, 443 } accept
		tcp dport 5432 log prefix "pg " accept
		drop
	}
	chain forward {
		type filter hook forward priority 0; policy drop;
	}
}
`,
  cisco: `object-group network ADMIN_HOSTS
 network-object host 10.10.1.5
 network-object 10.10.2.0 255.255.255.0
object-group service WEB tcp
 port-object eq www
 port-object eq https
access-list OUTSIDE_IN remark Public web
access-list OUTSIDE_IN extended permit object-group WEB any host 203.0.113.10
access-list OUTSIDE_IN extended permit tcp any host 203.0.113.11 eq 3389
access-list OUTSIDE_IN extended permit tcp object-group ADMIN_HOSTS host 203.0.113.11 eq ssh
access-list OUTSIDE_IN extended permit tcp host 10.10.1.5 host 203.0.113.11 eq ssh log
access-list OUTSIDE_IN extended deny tcp any host 203.0.113.11 eq 3389 log
access-list OUTSIDE_IN extended permit tcp object-group PARTNER_NET any eq 445
access-list OUTSIDE_IN extended permit tcp any host 203.0.113.12 range 8000 8100 inactive
access-list OUTSIDE_IN extended permit ip any any
access-group OUTSIDE_IN in interface outside
ip access-list extended LAN_IN
 10 permit tcp 192.168.10.0 0.0.0.255 any eq 443
 20 permit ip 192.168.10.0 0.0.0.255 any
 30 deny ip any any log
interface GigabitEthernet0/1
 ip access-group LAN_IN in
`,
  "pfsense-csv": `Action,Interface,Protocol,Source,Port,Destination,Port,Gateway,Description
Pass,WAN,IPv4 TCP,*,*,192.168.1.10,3389,*,RDP to file server
Pass,WAN,IPv4 TCP,*,*,192.168.1.20,443,*,Web
Block,WAN,IPv4 *,! 198.51.100.0/24,*,*,*,*,Block others
Pass,LAN,IPv4 *,LAN net,*,*,*,*,Default allow LAN to any
Pass,LAN,IPv4 TCP,LAN net,*,*,443,*,redundant https
`,
  "pfsense-xml": `<pfsense>
  <aliases>
    <alias><name>AdminHosts</name><type>network</type><address>10.0.0.0/24 10.0.1.5</address></alias>
  </aliases>
  <filter>
    <rule><type>pass</type><interface>wan</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
      <source><any/></source><destination><address>192.168.1.10</address><port>22</port></destination><descr>SSH in</descr><log/></rule>
    <rule><type>pass</type><interface>wan</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
      <source><address>AdminHosts</address></source><destination><address>192.168.1.10</address><port>22</port></destination><descr>SSH admins</descr></rule>
    <rule><type>pass</type><interface>lan</interface><ipprotocol>inet</ipprotocol>
      <source><network>lan</network></source><destination><any/></destination><descr>Default allow LAN to any rule</descr></rule>
    <rule><type>block</type><interface>wan</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
      <source><address>OldVendor</address></source><destination><any/></destination><disabled/><descr>old</descr></rule>
  </filter>
</pfsense>
`,
  fortigate: `config firewall address
    edit "LAN_NET"
        set subnet 192.168.1.0 255.255.255.0
    next
    edit "DB_SERVER"
        set subnet 192.168.1.50/32
    next
end
config firewall service custom
    edit "MYSQL-CUSTOM"
        set tcp-portrange 3306
    next
end
config firewall policy
    edit 1
        set name "Allow all in"
        set srcintf "wan1"
        set dstintf "internal"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set logtraffic disable
    next
    edit 2
        set name "DB from internet"
        set srcintf "wan1"
        set dstintf "internal"
        set srcaddr "all"
        set dstaddr "DB_SERVER"
        set action accept
        set schedule "always"
        set service "MYSQL-CUSTOM" "SSH"
        set logtraffic utm
    next
    edit 3
        set name "LAN out"
        set srcintf "internal"
        set dstintf "wan1"
        set srcaddr "LAN_NET"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set logtraffic all
    next
    edit 4
        set name "temp test"
        set srcintf "internal"
        set dstintf "wan1"
        set srcaddr "LAN_NET"
        set dstaddr "all"
        set action accept
        set status disable
        set schedule "always"
        set service "HTTPS" "VENDOR_PORTAL"
    next
end
`,
  "windows-netsh": `
Rule Name:                            Remote Desktop - User Mode (TCP-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:                             Remote Desktop
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            3389
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            SQL Server (TCP-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             TCP
LocalPort:                            1433
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            File and Printer Sharing (SMB-In)
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private
LocalIP:                              Any
RemoteIP:                             LocalSubnet
Protocol:                             TCP
LocalPort:                            445
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            temp allow all
----------------------------------------------------------------------
Enabled:                              No
Direction:                            In
Profiles:                             Domain,Private,Public
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             Any
LocalPort:                            Any
RemotePort:                           Any
Edge traversal:                       No
Action:                               Allow
Ok.
`,
};
const EXAMPLE_LABELS = { iptables: "iptables", nft: "nftables", cisco: "Cisco ASA/IOS", "pfsense-csv": "pfSense CSV", "pfsense-xml": "pfSense XML", fortigate: "FortiGate", "windows-netsh": "Windows netsh" };

export function renderFirewallAudit(main) {
  injectStyle();
  main.innerHTML = `
  <div class="fwa">
    <div class="fwa-hd"><h1>Firewall Rule Audit</h1><span class="fwa-tag">Infrastructure</span></div>
    <p class="fwa-sub">Paste a firewall rule-base export and get a deterministic review: shadowed and redundant rules (by real
      address and port containment, not text matching), any-to-any permits, admin services open to any source, missing default deny,
      logging gaps and broad egress. Each finding names the rule, the fix, and the control it maps to.
      The configuration is analysed in your browser and is not uploaded.</p>

    <div class="fwa-grid">
      <div class="fwa-card">
        <h3>Rule base</h3>
        <p class="fwa-note">Supported: <b>iptables-save</b> / <b>iptables -S</b>, <b>nft list ruleset</b> (partial), <b>Cisco ASA/IOS</b> access-lists
          with object-groups and access-group bindings, <b>pfSense/OPNsense</b> rules CSV or config.xml, <b>FortiGate</b> CLI
          (firewall policy + address + service), <b>Windows Firewall</b> netsh show rule output or Get-NetFirewallRule CSV.
          Include object / address / alias definitions when you have them; unresolved names are listed, never guessed.</p>
        <textarea id="fwaIn" class="fwa-in" placeholder="Paste the export here" spellcheck="false"></textarea>
        <div class="fwa-row">
          <button class="fwa-btn pri" id="fwaRun">Analyse</button>
          <label class="fwa-btn">Load file<input type="file" id="fwaFile" accept=".txt,.conf,.rules,.csv,.xml,.cfg,.log,text/plain,text/csv,text/xml" hidden></label>
          <span class="fwa-badge" id="fwaFmt">Format: waiting for input</span>
          <button class="fwa-btn" id="fwaClear">Clear</button>
        </div>
        <span class="fwa-lbl">Load example (synthetic config, for a quick look)</span>
        <div class="fwa-ex" id="fwaEx">${Object.keys(EXAMPLES).map((k) => `<button class="fwa-btn sm" data-ex="${k}">${esc(EXAMPLE_LABELS[k])}</button>`).join("")}</div>
      </div>
      <div class="fwa-card">
        <h3>Settings</h3>
        <span class="fwa-lbl">Internal networks</span>
        <p class="fwa-note">One CIDR per line. Sources inside these are treated as internal; anything else is external. Default is RFC 1918 plus IPv6 ULA, loopback and link-local.</p>
        <textarea id="fwaInternal" class="fwa-set" aria-label="Internal networks" spellcheck="false">${esc(DEFAULT_INTERNAL.join("\n"))}</textarea>
        <span class="fwa-lbl">Trusted admin source (optional)</span>
        <p class="fwa-note">Used only to fill in the fix snippets, for example a jump host or VPN pool.</p>
        <input type="text" id="fwaTrusted" placeholder="10.20.0.0/24">
        <span class="fwa-lbl">Device name (optional)</span>
        <p class="fwa-note">Names this firewall in the Security Graph so its findings link to one asset. A loaded file's name is used when left empty.</p>
        <input type="text" id="fwaDevice" placeholder="Firewall hostname" maxlength="80">
      </div>
    </div>

    <div id="fwaOut"></div>
  </div>`;

  const $ = (id) => main.querySelector("#" + id);
  const inTA = $("fwaIn"), out = $("fwaOut"), fmtBadge = $("fwaFmt");
  let result = null, sortKey = "severity", sortDir = 1, openIds = new Set(), tab = "findings", ruleSort = "idx";
  let example = null, srcName = ""; // last loaded synthetic example / file name (for the graph sink)

  function updateBadge() {
    const d = detectFormat(inTA.value);
    if (!inTA.value.trim()) { fmtBadge.textContent = "Format: waiting for input"; fmtBadge.classList.remove("on"); return; }
    if (!d) { fmtBadge.textContent = "Format: not recognised"; fmtBadge.classList.remove("on"); return; }
    fmtBadge.textContent = `Format: ${d.label}` + (d.confidence !== "high" ? ` (${d.confidence} confidence)` : "");
    fmtBadge.classList.add("on");
  }
  let tmr = null;
  inTA.addEventListener("input", () => { clearTimeout(tmr); tmr = setTimeout(updateBadge, 150); });
  inTA.addEventListener("keydown", (e) => { if ((e.ctrlKey || e.metaKey) && e.key === "Enter") run(); });

  $("fwaFile").addEventListener("change", (e) => {
    const f = e.target.files && e.target.files[0]; if (!f) return;
    if (f.size > 8 * 1024 * 1024) { toast("File is larger than 8 MB; paste the relevant section instead"); return; }
    const fr = new FileReader();
    fr.onload = () => { inTA.value = String(fr.result || ""); srcName = f.name; updateBadge(); toast(`Loaded ${f.name}`); };
    fr.onerror = () => toast("Could not read file");
    fr.readAsText(f);
  });
  $("fwaEx").addEventListener("click", (e) => {
    const b = e.target.closest("[data-ex]"); if (!b) return;
    inTA.value = example = EXAMPLES[b.dataset.ex]; srcName = ""; updateBadge(); run();
  });
  $("fwaClear").addEventListener("click", async () => {
    if (inTA.value.trim() && window.dnConfirm) { const ok = await window.dnConfirm("Clear the rule base?", "The pasted configuration and the results will be removed.", { confirm: "Clear" }); if (!ok) return; }
    inTA.value = ""; out.innerHTML = ""; result = null; example = null; srcName = ""; updateBadge();
  });
  $("fwaRun").addEventListener("click", run);

  function run() {
    const text = inTA.value;
    if (!text.trim()) { out.innerHTML = `<div class="fwa-card fwa-empty">Paste a firewall export or load an example first.</div>`; return; }
    const btn = $("fwaRun"); btn.disabled = true;
    try {
      const parsed = parseConfig(text);
      if (!parsed.format) {
        out.innerHTML = `<div class="fwa-card fwa-empty">Format not recognised.<br><span class="fwa-note">${esc(parsed.notes[0] || "")}</span></div>`;
        return;
      }
      result = analyze(parsed, { internal: $("fwaInternal").value, trusted: $("fwaTrusted").value.trim() });
      result.sample = sampleShare(text, example) >= SAMPLE_SHARE;
      result.device = $("fwaDevice").value.trim() || srcName;
      openIds = new Set(); tab = "findings";
      render();
      if (!parsed.rules.length) toast("Recognised the format but found no rules");
    } catch (err) {
      out.innerHTML = `<div class="fwa-card fwa-empty">The analysis stopped with an error.<br><span class="fwa-note fwa-mono">${esc(err && err.message || err)}</span></div>`;
    } finally { btn.disabled = false; }
  }

  function sevSpan(sev) { const s = SEV[sev] || SEV.info; return `<span class="fwa-sev" style="--c:${s.c}">${s.t}</span>`; }

  function render() {
    const r = result; const c = r.stats.counts;
    const gc = GRADE_C[r.score.grade] || SEV.info.c;
    out.innerHTML = `
      <div class="fwa-card">
        <div class="fwa-score">
          <div><span class="fwa-big" style="--c:${gc}">${r.score.value}</span><div class="fwa-dim" style="font-size:.74rem;text-transform:uppercase;letter-spacing:.05em">posture score</div></div>
          <div><span class="fwa-grade" style="--c:${gc}">Grade ${r.score.grade}</span><div class="fwa-dim" style="font-size:.8rem">${esc(r.label)}${r.partial ? " (partial parse)" : ""} · ${r.stats.rules} rules</div></div>
          <div class="fwa-dim" style="font-size:.8rem;flex:1;min-width:220px">${esc(r.score.explanation)}</div>
        </div>
        <div class="fwa-row">
          <button class="fwa-btn sm" id="fwaCsv">Export findings CSV</button>
          <button class="fwa-btn sm" id="fwaJson">Export JSON</button>
          <button class="fwa-btn sm" id="fwaRem">Remediation list (txt)</button>
          <button class="fwa-btn sm" id="fwaCopy">Copy summary</button>
          <span id="fwaSink"></span>
        </div>
        ${r.notes.length ? `<details><summary>Parser notes (${r.notes.length})</summary><ul class="fwa-notes">${r.notes.map((n) => `<li>${esc(n)}</li>`).join("")}</ul></details>` : ""}
      </div>
      <div class="fwa-kpis">
        <div class="fwa-kpi"><b class="fwa-c" style="--c:${c.critical ? SEV.critical.c : "inherit"}">${c.critical}</b><span>Critical</span></div>
        <div class="fwa-kpi"><b class="fwa-c" style="--c:${c.high ? SEV.high.c : "inherit"}">${c.high}</b><span>High</span></div>
        <div class="fwa-kpi"><b class="fwa-c" style="--c:${c.medium ? SEV.medium.c : "inherit"}">${c.medium}</b><span>Medium</span></div>
        <div class="fwa-kpi"><b>${c.low + c.info}</b><span>Low / info</span></div>
        <div class="fwa-kpi"><b>${r.stats.anySrcAllows}<span class="fwa-dim" style="font-size:.9rem;text-transform:none;letter-spacing:0"> / ${r.stats.allows} (${r.stats.pctAnySrcAllows}%)</span></b><span>Allows from any source</span></div>
        <div class="fwa-kpi"><b class="fwa-c" style="--c:${r.stats.exposedServices ? SEV.high.c : SEV.good.c}">${r.stats.exposedServices}</b><span>Risky services open to any</span></div>
        <div class="fwa-kpi"><b>${r.stats.shadowed}<span class="fwa-dim" style="font-size:.9rem;text-transform:none;letter-spacing:0"> + ${r.stats.redundant}</span></b><span>Shadowed + redundant</span></div>
        <div class="fwa-kpi"><b>${r.stats.disabled}</b><span>Disabled rules</span></div>
      </div>
      <div class="fwa-tabs">
        <button class="fwa-tab ${tab === "findings" ? "on" : ""}" data-tab="findings">Findings (${r.findings.length})</button>
        <button class="fwa-tab ${tab === "rules" ? "on" : ""}" data-tab="rules">Normalised rules (${r.rules.length})</button>
        <button class="fwa-tab ${tab === "matrix" ? "on" : ""}" data-tab="matrix">Exposure matrix</button>
      </div>
      <div id="fwaPanel"></div>`;
    out.querySelector("#fwaCsv").addEventListener("click", () => download("firewall-audit-findings.csv", findingsToCsv(r.findings), "text/csv"));
    out.querySelector("#fwaJson").addEventListener("click", () => download("firewall-audit.json", resultToJson(r), "application/json"));
    out.querySelector("#fwaRem").addEventListener("click", () => download("firewall-audit-remediation.txt", remediationText(r)));
    out.querySelector("#fwaCopy").addEventListener("click", () => copyText(summaryText(r)));
    const sinkFindings = toSinkFindings(r, { device: r.device });
    attachSinkButton(out.querySelector("#fwaSink"), () => ({ findings: sinkFindings, sample: !!r.sample }), "fwaudit", { dataset: r.device || r.label });
    out.querySelector(".fwa-tabs").addEventListener("click", (e) => { const b = e.target.closest("[data-tab]"); if (!b) return; tab = b.dataset.tab; out.querySelectorAll(".fwa-tab").forEach((x) => x.classList.toggle("on", x === b)); renderPanel(); });
    renderPanel();
  }

  function renderPanel() {
    const p = out.querySelector("#fwaPanel"); if (!p) return;
    if (tab === "findings") renderFindings(p); else if (tab === "rules") renderRules(p); else renderMatrix(p);
  }

  function sortedFindings() {
    const f = result.findings.slice();
    const cmp = {
      severity: (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
      type: (a, b) => a.type.localeCompare(b.type),
      title: (a, b) => a.title.localeCompare(b.title),
      rules: (a, b) => (a.evidence[0] ? a.evidence[0].idx : 1e9) - (b.evidence[0] ? b.evidence[0].idx : 1e9),
      confidence: (a, b) => a.confidence.localeCompare(b.confidence),
    }[sortKey] || (() => 0);
    f.sort((a, b) => sortDir * cmp(a, b) || a.id.localeCompare(b.id));
    return f;
  }

  function renderFindings(p) {
    const f = sortedFindings();
    if (!f.length) { p.innerHTML = `<div class="fwa-card fwa-empty"><span class="fwa-sev" style="--c:${SEV.good.c}">No findings.</span> The rule base passed every check this tool runs. That is not the same as a secure network; review the normalised rules too.</div>`; return; }
    const th = (k, label) => `<th data-k="${k}">${label}${sortKey === k ? (sortDir > 0 ? " ▴" : " ▾") : ""}</th>`;
    p.innerHTML = `<div class="fwa-tbl"><table>
      <thead><tr>${th("severity", "Severity")}${th("title", "Finding")}${th("type", "Type")}${th("rules", "Rules")}${th("confidence", "Confidence")}</tr></thead>
      <tbody>${f.map((x) => `
        <tr class="fwa-f" data-id="${x.id}">
          <td>${sevSpan(x.severity)}</td>
          <td><b>${esc(x.title)}</b><div class="fwa-dim fwa-mono">${x.id}</div></td>
          <td class="fwa-dim">${esc(x.type)}</td>
          <td class="fwa-mono">${x.evidence.length ? x.evidence.slice(0, 6).map((e) => "#" + e.idx).join(", ") + (x.evidence.length > 6 ? ` +${x.evidence.length - 6}` : "") : "<span class='fwa-dim'>policy</span>"}</td>
          <td class="fwa-dim">${esc(x.confidence)}</td>
        </tr>
        ${openIds.has(x.id) ? `<tr class="fwa-x"><td colspan="5">${detailHtml(x)}</td></tr>` : ""}`).join("")}
      </tbody></table></div>`;
    p.querySelector("thead").addEventListener("click", (e) => { const h = e.target.closest("th[data-k]"); if (!h) return; if (sortKey === h.dataset.k) sortDir = -sortDir; else { sortKey = h.dataset.k; sortDir = 1; } renderFindings(p); });
    p.querySelector("tbody").addEventListener("click", (e) => {
      const row = e.target.closest("tr.fwa-f"); if (!row) return;
      if (e.target.closest("button")) return;
      const id = row.dataset.id; if (openIds.has(id)) openIds.delete(id); else openIds.add(id); renderFindings(p);
    });
    p.querySelectorAll("[data-copy]").forEach((b) => b.addEventListener("click", () => copyText(b.dataset.copy)));
  }

  function detailHtml(x) {
    return `
      <h4>What this means</h4><p>${esc(x.detail)}</p>
      ${x.evidence.length ? `<h4>Evidence</h4><pre>${x.evidence.map((e) => `#${e.idx}${e.lineNo ? " line " + e.lineNo : ""}${e.name ? " [" + esc(e.name) + "]" : ""}\n${esc(e.raw)}`).join("\n\n")}</pre>` : ""}
      <h4>Fix</h4><p>${esc(x.fix)}</p>
      ${x.snippet ? `<pre>${esc(x.snippet)}</pre><div class="fwa-row" style="margin-top:6px"><button class="fwa-btn sm" data-copy="${esc(x.snippet)}">Copy snippet</button></div>` : ""}
      ${x.refs.length ? `<h4>References</h4><p>${x.refs.map(esc).join("\n")}</p>` : ""}
      ${x.attack ? `<h4>ATT&amp;CK</h4><p>${esc(x.attack)}</p>` : ""}`;
  }

  function renderRules(p) {
    const rules = result.rules.slice();
    if (ruleSort === "flags") rules.sort((a, b) => (b.flags.length - a.flags.length) || a.idx - b.idx);
    const flagC = { "any-any": SEV.critical.c, exposed: SEV.high.c, shadowed: SEV.high.c, overridden: SEV.medium.c, redundant: SEV.low.c, "broad-egress": SEV.medium.c };
    p.innerHTML = `<p class="fwa-note">Every rule normalised to one shape so that different vendors compare the same way. Struck-through rows are disabled. Shadow and redundancy markers point at the earlier rule that decides first.</p>
      <div class="fwa-tbl"><table>
      <thead><tr><th data-k="idx">#</th><th class="nosort">Scope</th><th class="nosort">Action</th><th class="nosort">Dir</th><th class="nosort">Proto</th><th class="nosort">Source</th><th class="nosort">Src ports</th><th class="nosort">Destination</th><th class="nosort">Dst ports</th><th class="nosort">Log</th><th data-k="flags">Markers</th><th class="nosort">Name</th></tr></thead>
      <tbody>${rules.map((r) => `<tr class="${r.enabled ? "" : "fwa-off"}" title="${esc(r.raw.slice(0, 300))}">
        <td class="fwa-mono fwa-keep">${r.idx}${r.lineNo ? `<div class="fwa-dim">L${r.lineNo}</div>` : ""}</td>
        <td class="fwa-dim">${esc(r.scope)}${r.iface && r.format !== "fortigate" ? `<div>${esc(r.iface)}</div>` : r.format === "fortigate" ? `<div>${esc(r.iface)}</div>` : ""}</td>
        <td><b>${esc(r.action)}</b>${r.target && r.action === "jump" ? ` <span class="fwa-dim">${esc(r.target)}</span>` : ""}${r.state ? `<div class="fwa-dim">${esc(r.state)}</div>` : ""}</td>
        <td>${esc(r.direction)}</td>
        <td>${esc(r.proto)}</td>
        <td class="fwa-mono">${esc(r.src.text || describeAddr(r.src))}</td>
        <td class="fwa-mono">${esc(describePorts(r.srcPorts))}</td>
        <td class="fwa-mono">${esc(r.dst.text || describeAddr(r.dst))}</td>
        <td class="fwa-mono">${esc(describePorts(r.dstPorts))}</td>
        <td class="fwa-dim">${r.log === null ? "n/a" : r.log ? "yes" : "no"}</td>
        <td class="fwa-keep">${r.flags.map((f) => `<span class="fwa-flag" style="--c:${flagC[f] || SEV.info.c}">${esc(f)}${f === "shadowed" || f === "overridden" ? " by #" + r.shadowedBy : f === "redundant" ? " of #" + r.redundantOf : ""}</span>`).join("")}${r.restricted ? `<span class="fwa-flag" style="--c:${SEV.info.c}">extra match</span>` : ""}${r.unresolved.length ? `<span class="fwa-flag" style="--c:${SEV.info.c}">unresolved</span>` : ""}</td>
        <td>${esc(r.name)}${r.notes.length ? `<div class="fwa-dim">${esc(r.notes.join(" "))}</div>` : ""}</td>
      </tr>`).join("")}</tbody></table></div>`;
    p.querySelector("thead").addEventListener("click", (e) => { const h = e.target.closest("th[data-k]"); if (!h) return; ruleSort = h.dataset.k; renderRules(p); });
  }

  function renderMatrix(p) {
    const ex = result.exposure.slice().sort((a, b) => (b.fromAny.length + b.fromBroad.length) - (a.fromAny.length + a.fromBroad.length) || SEVERITY_ORDER[a.sev] - SEVERITY_ORDER[b.sev]);
    const openCount = ex.filter((e) => e.fromAny.length).length;
    p.innerHTML = `<p class="fwa-note">Which risky services an enabled allow rule makes reachable from any source (0.0.0.0/0, ::/0, "any", "all") or from a broad non-internal range (a /16 or wider outside your internal list). Rules shadowed by an earlier rule are not counted.
      ${openCount ? `<b class="fwa-c" style="--c:${SEV.high.c}">${openCount} service(s) open to any.</b>` : `<b class="fwa-c" style="--c:${SEV.good.c}">No risky service is open to any source.</b>`}</p>
      <div class="fwa-tbl"><table>
      <thead><tr><th class="nosort">Service</th><th class="nosort">Ports</th><th class="nosort">If exposed</th><th class="nosort">From any</th><th class="nosort">From broad external</th></tr></thead>
      <tbody>${ex.map((e) => {
        const open = e.fromAny.length > 0, broad = e.fromBroad.length > 0;
        return `<tr>
          <td><b>${esc(e.label)}</b></td>
          <td class="fwa-mono">${esc(e.proto === "any" ? "" : e.proto + "/")}${esc(e.ports)}</td>
          <td>${sevSpan(e.sev)}</td>
          <td class="fwa-mono">${open ? `<span class="fwa-c" style="--c:${SEV[e.sev].c}">open</span> via ${e.fromAny.map((i) => "#" + i).join(", ")}` : `<span class="fwa-c" style="--c:${SEV.good.c}">closed</span>`}</td>
          <td class="fwa-mono">${broad ? `via ${e.fromBroad.map((i) => "#" + i).join(", ")}` : `<span class="fwa-dim">no</span>`}</td>
        </tr>`; }).join("")}</tbody></table></div>`;
  }
}
