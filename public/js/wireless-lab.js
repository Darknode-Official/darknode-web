const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const WIFI_NETWORKS = [
  { ssid: "CorpNet-5G", bssid: "AA:BB:CC:11:22:33", channel: 6, signal: -42, encryption: "WPA3-SAE", vendor: "Cisco", clients: 23, hidden: false },
  { ssid: "GuestWiFi", bssid: "AA:BB:CC:11:22:34", channel: 1, signal: -55, encryption: "WPA2-PSK", vendor: "Ubiquiti", clients: 8, hidden: false },
  { ssid: "", bssid: "DE:AD:BE:EF:00:01", channel: 11, signal: -67, encryption: "WPA2-Enterprise", vendor: "Aruba", clients: 2, hidden: true },
  { ssid: "IoT-Devices", bssid: "11:22:33:44:55:66", channel: 36, signal: -48, encryption: "WPA2-PSK", vendor: "TP-Link", clients: 41, hidden: false },
  { ssid: "OldPrinter", bssid: "77:88:99:AA:BB:CC", channel: 6, signal: -73, encryption: "WEP", vendor: "HP", clients: 1, hidden: false },
  { ssid: "DIRECT-xY", bssid: "FF:EE:DD:CC:BB:AA", channel: 149, signal: -60, encryption: "WPA2-PSK", vendor: "Samsung", clients: 0, hidden: false },
  { ssid: "FreeAirport", bssid: "00:11:22:33:44:55", channel: 1, signal: -38, encryption: "Open", vendor: "Ruckus", clients: 67, hidden: false },
  { ssid: "SecureVault", bssid: "AB:CD:EF:12:34:56", channel: 44, signal: -51, encryption: "WPA3-Enterprise", vendor: "Fortinet", clients: 5, hidden: false },
  { ssid: "SmartHome", bssid: "98:76:54:32:10:FE", channel: 6, signal: -62, encryption: "WPA2-PSK", vendor: "Netgear", clients: 14, hidden: false },
  { ssid: "Neighbor_Net", bssid: "12:34:56:78:9A:BC", channel: 11, signal: -80, encryption: "WPA2-PSK", vendor: "ASUS", clients: 3, hidden: false },
];

const ATTACK_TYPES = [
  { id: "deauth", name: "Deauthentication", desc: "Send deauth frames to disconnect clients from AP", tools: ["aireplay-ng", "mdk4"], risk: "Medium", mitre: "T1498.001" },
  { id: "evil-twin", name: "Evil Twin AP", desc: "Clone target AP to intercept traffic", tools: ["hostapd", "dnsmasq", "airbase-ng"], risk: "High", mitre: "T1557.002" },
  { id: "handshake", name: "WPA Handshake Capture", desc: "Capture 4-way handshake for offline cracking", tools: ["airodump-ng", "aireplay-ng"], risk: "Low", mitre: "T1040" },
  { id: "pmkid", name: "PMKID Attack", desc: "Extract PMKID from AP without client deauth", tools: ["hcxdumptool", "hcxtools"], risk: "Low", mitre: "T1040" },
  { id: "wps-pin", name: "WPS PIN Brute Force", desc: "Brute force WPS PIN to recover WPA key", tools: ["reaver", "bully"], risk: "Medium", mitre: "T1110.001" },
  { id: "karma", name: "KARMA Attack", desc: "Respond to all probe requests to capture clients", tools: ["hostapd-mana", "wifiphisher"], risk: "High", mitre: "T1557" },
  { id: "krack", name: "KRACK (Key Reinstallation)", desc: "Exploit WPA2 key reinstallation vulnerability", tools: ["krackattacks-scripts"], risk: "Critical", mitre: "T1557.002" },
  { id: "dragonblood", name: "Dragonblood (WPA3)", desc: "Side-channel and downgrade attacks on WPA3-SAE", tools: ["dragonslayer", "dragondrain"], risk: "High", mitre: "T1557" },
  { id: "beacon-flood", name: "Beacon Flood", desc: "Flood area with fake APs to cause confusion", tools: ["mdk4"], risk: "Medium", mitre: "T1498" },
  { id: "wep-crack", name: "WEP Cracking", desc: "Statistical attack to recover WEP key", tools: ["aircrack-ng", "besside-ng"], risk: "Low", mitre: "T1040" },
];

const WIFI_VULNS = [
  { id: "wep-usage", name: "WEP Encryption", severity: "Critical", desc: "WEP is fundamentally broken. Key recovery takes minutes.", fix: "Upgrade to WPA3-SAE or WPA2-Enterprise", cve: "N/A (protocol flaw)" },
  { id: "open-network", name: "Open Network (No Encryption)", severity: "Critical", desc: "All traffic visible to anyone in range. Trivial MITM.", fix: "Enable WPA3-SAE with strong passphrase", cve: "N/A" },
  { id: "wps-enabled", name: "WPS Enabled", severity: "High", desc: "WPS PIN is brute-forceable in hours. Bypasses WPA2.", fix: "Disable WPS entirely in AP settings", cve: "CVE-2011-5053" },
  { id: "weak-psk", name: "Weak Pre-Shared Key", severity: "High", desc: "Short or dictionary PSK crackable via captured handshake.", fix: "Use 20+ char random passphrase or Enterprise auth", cve: "N/A" },
  { id: "mgmt-unprotected", name: "Unprotected Management Frames", severity: "Medium", desc: "Deauth/disassoc frames not authenticated. Enables DoS.", fix: "Enable 802.11w (PMF) — mandatory in WPA3", cve: "N/A (protocol gap)" },
  { id: "pmf-optional", name: "PMF Optional (Not Required)", severity: "Medium", desc: "Clients can negotiate no PMF, leaving them vulnerable.", fix: "Set PMF to Required, not Optional", cve: "N/A" },
  { id: "krack-vuln", name: "KRACK Vulnerability", severity: "High", desc: "Key reinstallation in WPA2 4-way handshake.", fix: "Patch AP and client firmware; upgrade to WPA3", cve: "CVE-2017-13077" },
  { id: "fragattacks", name: "FragAttacks", severity: "Medium", desc: "Frame aggregation and fragmentation flaws in all Wi-Fi.", fix: "Apply vendor patches; use HTTPS for sensitive traffic", cve: "CVE-2020-24586" },
  { id: "default-creds", name: "Default AP Credentials", severity: "High", desc: "Admin panel accessible with factory username/password.", fix: "Change default credentials immediately on deployment", cve: "N/A" },
  { id: "hidden-ssid", name: "Hidden SSID (False Security)", severity: "Low", desc: "SSID broadcast disabled but trivially discovered in probe responses.", fix: "Not a security control — use proper encryption instead", cve: "N/A" },
];

const BT_DEVICES = [
  { name: "Galaxy Buds Pro", mac: "A0:B1:C2:D3:E4:F5", type: "Audio", rssi: -45, version: "5.0", vulnerable: false },
  { name: "Fitbit Charge 5", mac: "F5:E4:D3:C2:B1:A0", type: "Wearable", rssi: -52, version: "5.0", vulnerable: true },
  { name: "Smart Lock v2", mac: "12:34:56:78:9A:BC", type: "IoT Lock", rssi: -38, version: "4.2", vulnerable: true },
  { name: "OBD-II Scanner", mac: "DE:AD:BE:EF:CA:FE", type: "Automotive", rssi: -61, version: "4.0", vulnerable: true },
  { name: "Logitech K380", mac: "AA:BB:CC:DD:EE:FF", type: "Keyboard", rssi: -55, version: "3.0", vulnerable: true },
  { name: "AirTag", mac: "11:22:33:44:55:66", type: "Tracker", rssi: -70, version: "5.0", vulnerable: false },
  { name: "Tesla Model 3 BLE", mac: "CA:FE:BA:BE:00:01", type: "Automotive", rssi: -48, version: "5.0", vulnerable: true },
  { name: "Ring Doorbell", mac: "BE:EF:CA:FE:12:34", type: "IoT Camera", rssi: -56, version: "4.2", vulnerable: true },
];

const BT_ATTACKS = [
  { id: "blueborne", name: "BlueBorne", desc: "RCE via Bluetooth without pairing — spreads like a worm", cve: "CVE-2017-0781", severity: "Critical" },
  { id: "blesa", name: "BLESA", desc: "BLE spoofing attack during reconnection", cve: "CVE-2020-9770", severity: "High" },
  { id: "knob", name: "KNOB Attack", desc: "Key negotiation reduced to 1 byte of entropy", cve: "CVE-2019-9506", severity: "High" },
  { id: "bias", name: "BIAS Attack", desc: "Impersonate previously paired device", cve: "CVE-2020-10135", severity: "High" },
  { id: "braktooth", name: "BrakTooth", desc: "Family of 16 vulnerabilities in BT Classic", cve: "Multiple", severity: "Critical" },
  { id: "sweyntooth", name: "SweynTooth", desc: "BLE vulnerabilities affecting medical and IoT devices", cve: "Multiple", severity: "High" },
  { id: "blurtooth", name: "BLURtooth", desc: "CTKD flaw allows key overwrite across BT profiles", cve: "CVE-2020-15802", severity: "Medium" },
  { id: "mousejack", name: "MouseJack", desc: "Inject keystrokes via vulnerable wireless peripherals", cve: "CVE-2016-10761", severity: "Critical" },
];

const TABS = [
  { id: "scan", label: "Wi-Fi Scanner" },
  { id: "attacks", label: "Attack Lab" },
  { id: "vulns", label: "Vulnerability Audit" },
  { id: "bluetooth", label: "Bluetooth Recon" },
  { id: "spectrum", label: "Spectrum Analyzer" },
  { id: "deauth", label: "Deauth Simulator" },
  { id: "handshake", label: "Handshake Cracker" },
  { id: "rogue-ap", label: "Rogue AP Builder" },
];

export function renderWirelessLab(main) {
  var tab = "scan";

  function render() {
    var tabsHTML = "";
    for (var i = 0; i < TABS.length; i++) {
      tabsHTML += '<button class="wl-tab' + (TABS[i].id === tab ? " active" : "") + '" data-tab="' + esc(TABS[i].id) + '">' + esc(TABS[i].label) + '</button>';
    }

    var body = "";
    if (tab === "scan") body = renderScan();
    else if (tab === "attacks") body = renderAttacks();
    else if (tab === "vulns") body = renderVulns();
    else if (tab === "bluetooth") body = renderBluetooth();
    else if (tab === "spectrum") body = renderSpectrum();
    else if (tab === "deauth") body = renderDeauth();
    else if (tab === "handshake") body = renderHandshake();
    else if (tab === "rogue-ap") body = renderRogueAP();

    main.innerHTML =
      '<h1 class="pg-h1">Wireless Pentesting Lab</h1>' +
      '<p class="muted pg-sub">802.11 and Bluetooth security analysis, attack simulation, and defense testing.</p>' +
      '<div class="wl-tabs">' + tabsHTML + '</div>' +
      '<div class="wl-body">' + body + '</div>' +
      '<div class="wl-footer muted">Darknode Wireless Lab v1.0 &mdash; Use only on networks you own or are authorized to test.</div>';

    main.querySelectorAll(".wl-tab").forEach(function(btn) {
      btn.onclick = function() { tab = btn.dataset.tab; render(); };
    });

    bindEvents();
  }

  function signalBar(dbm) {
    var strength = dbm > -50 ? 4 : dbm > -60 ? 3 : dbm > -70 ? 2 : 1;
    var bars = "";
    for (var b = 1; b <= 4; b++) {
      bars += '<div class="wl-bar' + (b <= strength ? " active" : "") + '" style="height:' + (b * 5 + 4) + 'px"></div>';
    }
    return '<div class="wl-signal">' + bars + '</div>';
  }

  function encBadge(enc) {
    var cls = "wl-enc-badge ";
    if (enc === "Open" || enc === "WEP") cls += "wl-enc-bad";
    else if (enc.indexOf("WPA3") !== -1) cls += "wl-enc-good";
    else cls += "wl-enc-ok";
    return '<span class="' + cls + '">' + esc(enc) + '</span>';
  }

  function sevBadge(sev) {
    var cls = "wl-sev ";
    if (sev === "Critical") cls += "wl-sev-crit";
    else if (sev === "High") cls += "wl-sev-high";
    else if (sev === "Medium") cls += "wl-sev-med";
    else cls += "wl-sev-low";
    return '<span class="' + cls + '">' + esc(sev) + '</span>';
  }

  function renderScan() {
    var rows = "";
    for (var i = 0; i < WIFI_NETWORKS.length; i++) {
      var n = WIFI_NETWORKS[i];
      var ssidDisplay = n.hidden ? '<span class="wl-hidden">[Hidden Network]</span>' : esc(n.ssid);
      var band = n.channel > 14 ? "5 GHz" : "2.4 GHz";
      rows +=
        '<tr class="wl-net-row">' +
        '<td>' + signalBar(n.signal) + '</td>' +
        '<td><div class="wl-ssid">' + ssidDisplay + '</div><div class="wl-bssid">' + esc(n.bssid) + '</div></td>' +
        '<td>' + encBadge(n.encryption) + '</td>' +
        '<td class="wl-ch">' + n.channel + ' <span class="muted">(' + band + ')</span></td>' +
        '<td>' + n.signal + ' dBm</td>' +
        '<td>' + esc(n.vendor) + '</td>' +
        '<td>' + n.clients + '</td>' +
        '</tr>';
    }
    return '<div class="wl-scan-bar">' +
      '<span class="wl-scan-status"><span class="wl-pulse"></span> Scanning &mdash; ' + WIFI_NETWORKS.length + ' networks found</span>' +
      '<select class="wl-select" id="wl-iface"><option>wlan0mon</option><option>wlan1mon</option></select>' +
      '<select class="wl-select" id="wl-band"><option>All Bands</option><option>2.4 GHz</option><option>5 GHz</option></select>' +
      '</div>' +
      '<div class="wl-table-wrap"><table class="wl-table">' +
      '<thead><tr><th></th><th>SSID / BSSID</th><th>Security</th><th>Channel</th><th>Signal</th><th>Vendor</th><th>Clients</th></tr></thead>' +
      '<tbody>' + rows + '</tbody>' +
      '</table></div>' +
      '<div class="wl-cmd-box">' +
      '<div class="wl-cmd-label">Equivalent Command</div>' +
      '<pre class="wl-cmd">sudo airodump-ng wlan0mon --band abg --output-format csv -w scan_results</pre>' +
      '</div>';
  }

  function renderAttacks() {
    var cards = "";
    for (var i = 0; i < ATTACK_TYPES.length; i++) {
      var a = ATTACK_TYPES[i];
      var toolTags = "";
      for (var t = 0; t < a.tools.length; t++) {
        toolTags += '<span class="wl-tool-tag">' + esc(a.tools[t]) + '</span>';
      }
      cards +=
        '<div class="wl-atk-card">' +
        '<div class="wl-atk-header">' +
        '<span class="wl-atk-name">' + esc(a.name) + '</span>' +
        sevBadge(a.risk) +
        '</div>' +
        '<p class="wl-atk-desc">' + esc(a.desc) + '</p>' +
        '<div class="wl-atk-meta">' +
        '<div class="wl-atk-tools">' + toolTags + '</div>' +
        '<span class="wl-mitre-tag">' + esc(a.mitre) + '</span>' +
        '</div>' +
        '</div>';
    }
    return '<div class="wl-atk-grid">' + cards + '</div>';
  }

  function renderVulns() {
    var items = "";
    for (var i = 0; i < WIFI_VULNS.length; i++) {
      var v = WIFI_VULNS[i];
      var detected = [];
      if (v.id === "wep-usage") {
        for (var n = 0; n < WIFI_NETWORKS.length; n++) { if (WIFI_NETWORKS[n].encryption === "WEP") detected.push(WIFI_NETWORKS[n]); }
      } else if (v.id === "open-network") {
        for (var n = 0; n < WIFI_NETWORKS.length; n++) { if (WIFI_NETWORKS[n].encryption === "Open") detected.push(WIFI_NETWORKS[n]); }
      } else if (v.id === "hidden-ssid") {
        for (var n = 0; n < WIFI_NETWORKS.length; n++) { if (WIFI_NETWORKS[n].hidden) detected.push(WIFI_NETWORKS[n]); }
      }
      var detectedHTML = "";
      if (detected.length > 0) {
        detectedHTML = '<div class="wl-vuln-detected">Detected on: ';
        for (var d = 0; d < detected.length; d++) {
          detectedHTML += '<span class="wl-vuln-net">' + esc(detected[d].ssid || detected[d].bssid) + '</span>';
        }
        detectedHTML += '</div>';
      }
      items +=
        '<div class="wl-vuln-card">' +
        '<div class="wl-vuln-header">' + sevBadge(v.severity) + ' <strong>' + esc(v.name) + '</strong></div>' +
        '<p class="wl-vuln-desc">' + esc(v.desc) + '</p>' +
        '<div class="wl-vuln-fix"><strong>Fix:</strong> ' + esc(v.fix) + '</div>' +
        '<div class="wl-vuln-cve">' + esc(v.cve) + '</div>' +
        detectedHTML +
        '</div>';
    }
    return '<div class="wl-vuln-list">' + items + '</div>';
  }

  function renderBluetooth() {
    var devRows = "";
    for (var i = 0; i < BT_DEVICES.length; i++) {
      var d = BT_DEVICES[i];
      devRows +=
        '<tr>' +
        '<td><strong>' + esc(d.name) + '</strong></td>' +
        '<td class="mono">' + esc(d.mac) + '</td>' +
        '<td>' + esc(d.type) + '</td>' +
        '<td>' + d.rssi + ' dBm</td>' +
        '<td>BT ' + esc(d.version) + '</td>' +
        '<td>' + (d.vulnerable ? '<span class="wl-sev wl-sev-high">Vulnerable</span>' : '<span class="wl-sev wl-sev-low">Secure</span>') + '</td>' +
        '</tr>';
    }
    var atkCards = "";
    for (var i = 0; i < BT_ATTACKS.length; i++) {
      var a = BT_ATTACKS[i];
      atkCards +=
        '<div class="wl-bt-card">' +
        '<div class="wl-bt-header">' + sevBadge(a.severity) + ' <strong>' + esc(a.name) + '</strong></div>' +
        '<p class="wl-atk-desc">' + esc(a.desc) + '</p>' +
        '<div class="wl-vuln-cve">' + esc(a.cve) + '</div>' +
        '</div>';
    }
    return '<h2 class="wl-sec-title">Discovered Devices</h2>' +
      '<div class="wl-table-wrap"><table class="wl-table">' +
      '<thead><tr><th>Name</th><th>MAC</th><th>Type</th><th>RSSI</th><th>Version</th><th>Status</th></tr></thead>' +
      '<tbody>' + devRows + '</tbody>' +
      '</table></div>' +
      '<h2 class="wl-sec-title">Bluetooth Attack Vectors</h2>' +
      '<div class="wl-bt-grid">' + atkCards + '</div>' +
      '<div class="wl-cmd-box">' +
      '<div class="wl-cmd-label">Bluetooth Scanning Commands</div>' +
      '<pre class="wl-cmd">sudo hcitool scan                    # Classic BT discovery\nsudo hcitool lescan                  # BLE discovery\nsudo btmon                            # HCI monitor\nredfang -r 00:00:00:00:00:00-FF:FF:FF:FF:FF:FF  # Find hidden BT</pre>' +
      '</div>';
  }

  function renderSpectrum() {
    return '<h2 class="wl-sec-title">2.4 GHz Spectrum</h2>' +
      '<div class="wl-spectrum-info">Channels 1, 6, 11 are the only non-overlapping channels in 2.4 GHz.</div>' +
      '<canvas id="wl-spectrum-canvas" class="wl-canvas" width="800" height="300"></canvas>' +
      '<h2 class="wl-sec-title">5 GHz Spectrum</h2>' +
      '<canvas id="wl-spectrum-5g" class="wl-canvas" width="800" height="250"></canvas>' +
      '<div class="wl-spectrum-legend">' +
      '<span class="wl-legend-item"><span class="wl-legend-dot" style="background:var(--acc)"></span> Your Networks</span>' +
      '<span class="wl-legend-item"><span class="wl-legend-dot" style="background:var(--warn)"></span> Neighboring</span>' +
      '<span class="wl-legend-item"><span class="wl-legend-dot" style="background:var(--bad)"></span> Interference</span>' +
      '</div>';
  }

  function renderDeauth() {
    return '<div class="wl-sim-panel">' +
      '<h2 class="wl-sec-title">Deauthentication Attack Simulator</h2>' +
      '<p class="muted">Simulates IEEE 802.11 deauthentication frame injection. Educational only.</p>' +
      '<div class="wl-form-grid">' +
      '<div class="wl-form-group"><label class="wl-label">Target AP (BSSID)</label>' +
      '<select class="wl-select" id="wl-deauth-target">' +
      WIFI_NETWORKS.map(function(n) { return '<option value="' + esc(n.bssid) + '">' + esc(n.ssid || n.bssid) + ' (' + esc(n.bssid) + ')</option>'; }).join("") +
      '</select></div>' +
      '<div class="wl-form-group"><label class="wl-label">Target Client</label>' +
      '<select class="wl-select" id="wl-deauth-client"><option value="FF:FF:FF:FF:FF:FF">Broadcast (all clients)</option><option value="specific">Specific client MAC</option></select></div>' +
      '<div class="wl-form-group"><label class="wl-label">Reason Code</label>' +
      '<select class="wl-select" id="wl-deauth-reason"><option value="7">7 - Class 3 frame from nonassociated STA</option><option value="1">1 - Unspecified reason</option><option value="4">4 - Disassociated due to inactivity</option><option value="5">5 - AP unable to handle all STAs</option></select></div>' +
      '<div class="wl-form-group"><label class="wl-label">Frame Count</label>' +
      '<input type="number" class="wl-input" id="wl-deauth-count" value="10" min="1" max="100"></div>' +
      '</div>' +
      '<button class="wl-btn" id="wl-deauth-run">Simulate Deauth</button>' +
      '<div class="wl-output" id="wl-deauth-output"></div>' +
      '<div class="wl-cmd-box"><div class="wl-cmd-label">Real Command</div>' +
      '<pre class="wl-cmd">sudo aireplay-ng -0 10 -a AA:BB:CC:11:22:33 -c FF:FF:FF:FF:FF:FF wlan0mon</pre></div>' +
      '<div class="wl-defense-box">' +
      '<h3>Defense: 802.11w (PMF)</h3>' +
      '<p>Protected Management Frames (PMF / 802.11w) cryptographically authenticates management frames including deauth and disassociation. Mandatory in WPA3, optional in WPA2. Enable PMF on your AP to mitigate deauth attacks.</p>' +
      '</div>' +
      '</div>';
  }

  function renderHandshake() {
    return '<div class="wl-sim-panel">' +
      '<h2 class="wl-sec-title">WPA Handshake Capture &amp; Crack Simulator</h2>' +
      '<p class="muted">Simulates the 4-way handshake capture and dictionary attack process.</p>' +
      '<div class="wl-form-grid">' +
      '<div class="wl-form-group"><label class="wl-label">Target Network</label>' +
      '<select class="wl-select" id="wl-hs-target">' +
      WIFI_NETWORKS.filter(function(n) { return n.encryption.indexOf("WPA") !== -1; }).map(function(n) {
        return '<option value="' + esc(n.bssid) + '">' + esc(n.ssid || n.bssid) + ' (' + esc(n.encryption) + ')</option>';
      }).join("") +
      '</select></div>' +
      '<div class="wl-form-group"><label class="wl-label">Wordlist</label>' +
      '<select class="wl-select" id="wl-hs-wordlist"><option>rockyou.txt (14M words)</option><option>darkc0de.lst (1.7M)</option><option>fasttrack.txt (222 words)</option><option>Custom wordlist</option></select></div>' +
      '<div class="wl-form-group"><label class="wl-label">Hash Mode</label>' +
      '<select class="wl-select" id="wl-hs-mode"><option>WPA-PBKDF2 (CPU)</option><option>WPA-PBKDF2 (GPU - hashcat)</option><option>PMKID (hashcat 22000)</option></select></div>' +
      '</div>' +
      '<button class="wl-btn" id="wl-hs-capture">1. Capture Handshake</button> ' +
      '<button class="wl-btn wl-btn-sec" id="wl-hs-crack" disabled>2. Crack Hash</button>' +
      '<div class="wl-output" id="wl-hs-output"></div>' +
      '<div class="wl-hs-4way">' +
      '<h3>The 4-Way Handshake</h3>' +
      '<div class="wl-hs-steps">' +
      '<div class="wl-hs-step"><span class="wl-hs-arrow">AP &#8594; Client</span> ANonce (AP random nonce)</div>' +
      '<div class="wl-hs-step"><span class="wl-hs-arrow">Client &#8594; AP</span> SNonce + MIC (client derives PTK)</div>' +
      '<div class="wl-hs-step"><span class="wl-hs-arrow">AP &#8594; Client</span> GTK + MIC (AP confirms PTK)</div>' +
      '<div class="wl-hs-step"><span class="wl-hs-arrow">Client &#8594; AP</span> ACK (handshake complete)</div>' +
      '</div>' +
      '</div>' +
      '<div class="wl-cmd-box"><div class="wl-cmd-label">Real Commands</div>' +
      '<pre class="wl-cmd"># Capture handshake\nsudo airodump-ng -c 6 --bssid AA:BB:CC:11:22:33 -w capture wlan0mon\n\n# Force handshake with deauth\nsudo aireplay-ng -0 1 -a AA:BB:CC:11:22:33 wlan0mon\n\n# Crack with aircrack-ng\naircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap\n\n# Crack with hashcat (GPU)\nhashcat -m 22000 capture.hc22000 rockyou.txt</pre></div>' +
      '</div>';
  }

  function renderRogueAP() {
    return '<div class="wl-sim-panel">' +
      '<h2 class="wl-sec-title">Rogue AP / Evil Twin Builder</h2>' +
      '<p class="muted">Configure an evil twin access point for authorized security testing.</p>' +
      '<div class="wl-form-grid">' +
      '<div class="wl-form-group"><label class="wl-label">Clone Target</label>' +
      '<select class="wl-select" id="wl-rogue-target">' +
      '<option value="">-- Select AP to clone --</option>' +
      WIFI_NETWORKS.map(function(n) { return '<option value="' + esc(n.bssid) + '">' + esc(n.ssid || n.bssid) + '</option>'; }).join("") +
      '</select></div>' +
      '<div class="wl-form-group"><label class="wl-label">SSID Override</label>' +
      '<input class="wl-input" id="wl-rogue-ssid" placeholder="Leave blank to clone SSID"></div>' +
      '<div class="wl-form-group"><label class="wl-label">Channel</label>' +
      '<input type="number" class="wl-input" id="wl-rogue-ch" value="6" min="1" max="165"></div>' +
      '<div class="wl-form-group"><label class="wl-label">Captive Portal</label>' +
      '<select class="wl-select" id="wl-rogue-portal"><option>None</option><option>Login page clone</option><option>Firmware update</option><option>Terms of service</option><option>OAuth phishing</option></select></div>' +
      '<div class="wl-form-group"><label class="wl-label">DHCP Range</label>' +
      '<input class="wl-input" id="wl-rogue-dhcp" value="192.168.1.100-200"></div>' +
      '<div class="wl-form-group"><label class="wl-label">DNS Spoofing</label>' +
      '<select class="wl-select" id="wl-rogue-dns"><option>Off</option><option>Redirect all to captive portal</option><option>Selective domain spoofing</option></select></div>' +
      '</div>' +
      '<button class="wl-btn" id="wl-rogue-gen">Generate Config</button>' +
      '<div class="wl-output" id="wl-rogue-output"></div>' +
      '<div class="wl-defense-box">' +
      '<h3>Detecting Rogue APs</h3>' +
      '<ul class="wl-defense-list">' +
      '<li>Wireless IDS (WIDS) monitors for duplicate SSIDs on different BSSIDs</li>' +
      '<li>802.1X / RADIUS prevents association with unauthorized APs</li>' +
      '<li>Client certificate pinning detects MITM on TLS connections</li>' +
      '<li>MDM policies restrict auto-connecting to open networks</li>' +
      '<li>DNSSEC validates DNS responses end-to-end</li>' +
      '</ul></div>' +
      '</div>';
  }

  function drawSpectrum(canvasId, networks, startCh, endCh, label) {
    var canvas = main.querySelector("#" + canvasId);
    if (!canvas) return;
    var ctx = canvas.getContext("2d");
    var W = canvas.width, H = canvas.height;
    ctx.clearRect(0, 0, W, H);

    ctx.fillStyle = "rgba(0,0,0,0.3)";
    ctx.fillRect(0, 0, W, H);

    var chCount = endCh - startCh + 1;
    var chW = (W - 80) / chCount;
    var ox = 50, oy = H - 40;

    ctx.strokeStyle = "rgba(255,255,255,0.1)";
    ctx.lineWidth = 1;
    for (var g = 0; g <= 5; g++) {
      var gy = oy - (oy - 20) * g / 5;
      ctx.beginPath(); ctx.moveTo(ox, gy); ctx.lineTo(W - 30, gy); ctx.stroke();
      ctx.fillStyle = "rgba(255,255,255,0.3)";
      ctx.font = "10px monospace";
      ctx.textAlign = "right";
      ctx.fillText("-" + (g * 20) + " dBm", ox - 6, gy + 4);
    }

    ctx.fillStyle = "rgba(255,255,255,0.4)";
    ctx.font = "10px monospace";
    ctx.textAlign = "center";
    for (var c = startCh; c <= endCh; c++) {
      var cx = ox + (c - startCh + 0.5) * chW;
      ctx.fillText("" + c, cx, oy + 16);
    }

    for (var i = 0; i < networks.length; i++) {
      var n = networks[i];
      var ch = n.channel;
      if (ch < startCh || ch > endCh) continue;
      var cx = ox + (ch - startCh + 0.5) * chW;
      var strength = Math.max(0, 100 + n.signal) / 100;
      var peakY = oy - (oy - 20) * strength;
      var spread = chW * 2.5;

      var color = n.encryption === "Open" || n.encryption === "WEP"
        ? "rgba(255,92,108," : "rgba(0,255,200,";

      var grad = ctx.createLinearGradient(0, peakY, 0, oy);
      grad.addColorStop(0, color + "0.6)");
      grad.addColorStop(1, color + "0.05)");
      ctx.fillStyle = grad;
      ctx.beginPath();
      ctx.moveTo(cx - spread, oy);
      ctx.quadraticCurveTo(cx - spread * 0.3, peakY, cx, peakY);
      ctx.quadraticCurveTo(cx + spread * 0.3, peakY, cx + spread, oy);
      ctx.closePath();
      ctx.fill();

      ctx.strokeStyle = color + "0.8)";
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.moveTo(cx - spread, oy);
      ctx.quadraticCurveTo(cx - spread * 0.3, peakY, cx, peakY);
      ctx.quadraticCurveTo(cx + spread * 0.3, peakY, cx + spread, oy);
      ctx.stroke();

      ctx.fillStyle = "rgba(255,255,255,0.7)";
      ctx.font = "9px monospace";
      ctx.textAlign = "center";
      ctx.fillText(n.ssid || "Hidden", cx, peakY - 6);
    }
  }

  function simulateDeauth() {
    var out = main.querySelector("#wl-deauth-output");
    if (!out) return;
    var target = main.querySelector("#wl-deauth-target").value;
    var count = parseInt(main.querySelector("#wl-deauth-count").value) || 10;
    var reason = main.querySelector("#wl-deauth-reason").value;
    var net = WIFI_NETWORKS.find(function(n) { return n.bssid === target; });
    var lines = [];
    lines.push("[*] Interface: wlan0mon");
    lines.push("[*] Target AP: " + (net ? net.ssid || net.bssid : target) + " (" + target + ")");
    lines.push("[*] Reason code: " + reason);
    lines.push("[*] Sending " + count + " deauthentication frames...");
    lines.push("");
    var sent = 0;
    out.innerHTML = '<pre class="wl-pre">' + esc(lines.join("\n")) + '</pre>';
    var iv = setInterval(function() {
      sent++;
      if (sent > count) { clearInterval(iv); lines.push("\n[+] Deauth simulation complete. " + count + " frames sent."); }
      else { lines.push("[" + sent + "/" + count + "] Deauth frame sent to " + target + " (reason=" + reason + ")"); }
      out.innerHTML = '<pre class="wl-pre">' + esc(lines.join("\n")) + '</pre>';
      out.querySelector("pre").scrollTop = out.querySelector("pre").scrollHeight;
    }, 200);
  }

  function simulateHandshakeCapture() {
    var out = main.querySelector("#wl-hs-output");
    var crackBtn = main.querySelector("#wl-hs-crack");
    if (!out) return;
    var target = main.querySelector("#wl-hs-target").value;
    var net = WIFI_NETWORKS.find(function(n) { return n.bssid === target; });
    var lines = [];
    lines.push("[*] Starting handshake capture on channel " + (net ? net.channel : "6"));
    lines.push("[*] Target: " + (net ? net.ssid : target) + " (" + target + ")");
    lines.push("[*] Waiting for client association...");
    out.innerHTML = '<pre class="wl-pre">' + esc(lines.join("\n")) + '</pre>';

    setTimeout(function() {
      lines.push("[*] Client detected: C0:FF:EE:00:11:22");
      lines.push("[*] Sending deauth to force reconnection...");
      out.innerHTML = '<pre class="wl-pre">' + esc(lines.join("\n")) + '</pre>';
    }, 1500);
    setTimeout(function() {
      lines.push("[+] EAPOL Message 1/4 captured (ANonce)");
      out.innerHTML = '<pre class="wl-pre">' + esc(lines.join("\n")) + '</pre>';
    }, 2500);
    setTimeout(function() {
      lines.push("[+] EAPOL Message 2/4 captured (SNonce + MIC)");
      out.innerHTML = '<pre class="wl-pre">' + esc(lines.join("\n")) + '</pre>';
    }, 3200);
    setTimeout(function() {
      lines.push("[+] EAPOL Message 3/4 captured (GTK + MIC)");
      out.innerHTML = '<pre class="wl-pre">' + esc(lines.join("\n")) + '</pre>';
    }, 3800);
    setTimeout(function() {
      lines.push("[+] EAPOL Message 4/4 captured (ACK)");
      lines.push("");
      lines.push("[+] WPA handshake captured successfully!");
      lines.push("[+] Saved to: capture-" + target.replace(/:/g, "") + ".cap");
      out.innerHTML = '<pre class="wl-pre">' + esc(lines.join("\n")) + '</pre>';
      if (crackBtn) crackBtn.disabled = false;
    }, 4500);
  }

  function simulateCrack() {
    var out = main.querySelector("#wl-hs-output");
    if (!out) return;
    var wordlist = main.querySelector("#wl-hs-wordlist").value;
    var lines = [];
    lines.push("[*] Starting dictionary attack...");
    lines.push("[*] Wordlist: " + wordlist);
    lines.push("[*] Hash type: WPA-PBKDF2-PMKID+EAPOL");
    lines.push("");
    out.innerHTML = '<pre class="wl-pre">' + esc(lines.join("\n")) + '</pre>';
    var tested = 0;
    var total = wordlist.indexOf("14M") !== -1 ? 14344391 : wordlist.indexOf("1.7M") !== -1 ? 1726000 : 222;
    var rate = wordlist.indexOf("GPU") !== -1 ? 450000 : 2800;
    var found = false;
    var iv = setInterval(function() {
      tested += rate;
      if (tested > total * 0.6 && !found) {
        found = true;
        clearInterval(iv);
        lines.push("[+] KEY FOUND: p@ssw0rd123!");
        lines.push("[+] Master Key: 8A:2C:E1:... (truncated)");
        lines.push("[+] Tested " + tested.toLocaleString() + " / " + total.toLocaleString() + " keys");
        lines.push("[+] Speed: " + rate.toLocaleString() + " keys/sec");
      } else if (tested >= total) {
        clearInterval(iv);
        lines.push("[-] Exhausted wordlist. Key not found.");
        lines.push("[*] Try a larger wordlist or rules-based attack.");
      } else {
        lines.push("[" + Math.floor(tested/total*100) + "%] Tested: " + tested.toLocaleString() + " / " + total.toLocaleString() + " (" + rate.toLocaleString() + " keys/s)");
      }
      out.innerHTML = '<pre class="wl-pre">' + esc(lines.join("\n")) + '</pre>';
      out.querySelector("pre").scrollTop = out.querySelector("pre").scrollHeight;
    }, 400);
  }

  function generateRogueConfig() {
    var out = main.querySelector("#wl-rogue-output");
    if (!out) return;
    var target = main.querySelector("#wl-rogue-target").value;
    var ssid = main.querySelector("#wl-rogue-ssid").value;
    var ch = main.querySelector("#wl-rogue-ch").value;
    var portal = main.querySelector("#wl-rogue-portal").value;
    var dhcp = main.querySelector("#wl-rogue-dhcp").value;
    var dns = main.querySelector("#wl-rogue-dns").value;

    var net = target ? WIFI_NETWORKS.find(function(n) { return n.bssid === target; }) : null;
    if (!ssid && net) ssid = net.ssid;
    if (!ssid) ssid = "FreeWiFi";

    var config = "# hostapd.conf - Evil Twin AP\n";
    config += "interface=wlan0\n";
    config += "driver=nl80211\n";
    config += "ssid=" + ssid + "\n";
    config += "hw_mode=" + (parseInt(ch) > 14 ? "a" : "g") + "\n";
    config += "channel=" + ch + "\n";
    config += "wmm_enabled=0\n";
    config += "macaddr_acl=0\n";
    config += "auth_algs=1\n";
    config += "ignore_broadcast_ssid=0\n";

    config += "\n# dnsmasq.conf\n";
    config += "interface=wlan0\n";
    config += "dhcp-range=" + dhcp.replace("-", ",") + ",12h\n";
    config += "dhcp-option=3,192.168.1.1\n";
    config += "dhcp-option=6,192.168.1.1\n";

    if (dns !== "Off") {
      config += "\n# DNS spoofing\n";
      config += "address=/#/192.168.1.1\n";
    }

    if (portal !== "None") {
      config += "\n# iptables - redirect HTTP to captive portal\n";
      config += "iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 192.168.1.1:80\n";
      config += "iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination 192.168.1.1:443\n";
    }

    config += "\n# Launch sequence:\n";
    config += "# 1. sudo airmon-ng start wlan0\n";
    config += "# 2. sudo hostapd hostapd.conf &\n";
    config += "# 3. sudo dnsmasq -C dnsmasq.conf &\n";
    config += "# 4. sudo python3 captive_portal.py  # if using portal\n";

    out.innerHTML = '<pre class="wl-pre">' + esc(config) + '</pre>';
  }

  function bindEvents() {
    var deauthBtn = main.querySelector("#wl-deauth-run");
    if (deauthBtn) deauthBtn.onclick = simulateDeauth;

    var hsCapture = main.querySelector("#wl-hs-capture");
    if (hsCapture) hsCapture.onclick = simulateHandshakeCapture;

    var hsCrack = main.querySelector("#wl-hs-crack");
    if (hsCrack) hsCrack.onclick = simulateCrack;

    var rogueGen = main.querySelector("#wl-rogue-gen");
    if (rogueGen) rogueGen.onclick = generateRogueConfig;

    if (tab === "spectrum") {
      var nets24 = WIFI_NETWORKS.filter(function(n) { return n.channel <= 14; });
      var nets5 = WIFI_NETWORKS.filter(function(n) { return n.channel > 14; });
      drawSpectrum("wl-spectrum-canvas", nets24, 1, 14, "2.4 GHz");
      drawSpectrum("wl-spectrum-5g", nets5, 36, 165, "5 GHz");
    }
  }

  render();
}
