var esc = function(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function(c) { return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]; }); };

var ONION_SERVICES = [
  { url: "dread...onion", name: "Dread Forum", category: "Forum", description: "Reddit-like darknet forum for market discussions and security" },
  { url: "breach...onion", name: "BreachForums Mirror", category: "Forum", description: "Database leak sharing and trading platform" },
  { url: "paste...onion", name: "DeepPaste", category: "Paste", description: "Anonymous paste service for sensitive data" },
  { url: "market...onion", name: "AlphaBay Market", category: "Market", description: "Former largest darknet marketplace (seized by LE)" },
  { url: "wiki...onion", name: "Hidden Wiki", category: "Directory", description: "Directory of .onion services and links" },
  { url: "mail...onion", name: "ProtonMail Onion", category: "Email", description: "Encrypted email accessible over Tor" },
  { url: "search...onion", name: "Ahmia", category: "Search", description: "Clearnet search engine for .onion sites" },
  { url: "leak...onion", name: "RansomWatch", category: "Leak Site", description: "Ransomware group data leak aggregator" }
];

var THREAT_ACTORS = [
  { name: "LockBit 3.0", type: "Ransomware", origin: "Russia", targets: "Enterprise, Healthcare, Gov", ttps: "Double extortion, affiliate model", status: "Active", victims2024: 312 },
  { name: "BlackCat/ALPHV", type: "Ransomware", origin: "Russia", targets: "Critical Infrastructure", ttps: "Rust-based, triple extortion", status: "Disrupted", victims2024: 89 },
  { name: "Cl0p", type: "Ransomware", origin: "Russia", targets: "File Transfer (MOVEit)", ttps: "Zero-day exploitation, data theft only", status: "Active", victims2024: 267 },
  { name: "Scattered Spider", type: "Access Broker", origin: "US/UK", targets: "Telecom, Casino, Tech", ttps: "Social engineering, SIM swap, Okta abuse", status: "Active", victims2024: 45 },
  { name: "ShinyHunters", type: "Data Breach", origin: "France", targets: "SaaS, Cloud Services", ttps: "API exploitation, credential stuffing", status: "Active", victims2024: 128 },
  { name: "IntelBroker", type: "Data Broker", origin: "Unknown", targets: "Government, Defense", ttps: "Insider access, third-party compromises", status: "Active", victims2024: 73 },
  { name: "Lazarus Group", type: "Nation-State (APT38)", origin: "North Korea", targets: "Crypto, Finance, Defense", ttps: "Supply chain, social engineering", status: "Active", victims2024: 31 },
  { name: "APT29 (Cozy Bear)", type: "Nation-State", origin: "Russia (SVR)", targets: "Government, Diplomatic", ttps: "Cloud exploitation, phishing", status: "Active", victims2024: 18 },
  { name: "APT28 (Fancy Bear)", type: "Nation-State", origin: "Russia (GRU)", targets: "Government, Military, Media", ttps: "Spear phishing, zero-days, credential harvesting", status: "Active", victims2024: 24 },
  { name: "APT41 (Double Dragon)", type: "Nation-State / Criminal", origin: "China", targets: "Tech, Healthcare, Telecom", ttps: "Supply chain, rootkits, dual espionage/financial", status: "Active", victims2024: 37 },
  { name: "Rhysida", type: "Ransomware", origin: "Unknown", targets: "Healthcare, Education, Gov", ttps: "Double extortion, Cobalt Strike, PhishingKit", status: "Active", victims2024: 78 },
  { name: "Play Ransomware", type: "Ransomware", origin: "Unknown", targets: "MSPs, IT Services, Gov", ttps: "ProxyNotShell, FortiOS exploits, intermittent encryption", status: "Active", victims2024: 94 },
  { name: "Akira", type: "Ransomware", origin: "Unknown", targets: "SMBs, VPN-connected orgs", ttps: "Cisco VPN exploitation, Linux ESXi targeting", status: "Active", victims2024: 142 },
  { name: "Medusa", type: "Ransomware", origin: "Unknown", targets: "Education, Healthcare", ttps: "RDP brute force, living off the land, triple extortion", status: "Active", victims2024: 63 },
  { name: "BlackBasta", type: "Ransomware", origin: "Russia (ex-Conti)", targets: "Manufacturing, Finance", ttps: "QakBot delivery, AD enumeration, ESXi encryption", status: "Active", victims2024: 108 },
  { name: "Turla (Snake)", type: "Nation-State", origin: "Russia (FSB)", targets: "Government, Diplomatic", ttps: "Watering holes, satellite C2, custom malware", status: "Active", victims2024: 11 },
  { name: "Kimsuky", type: "Nation-State", origin: "North Korea", targets: "Think Tanks, Academia, Media", ttps: "Spear phishing, credential theft, BabyShark malware", status: "Active", victims2024: 22 },
  { name: "FIN7", type: "Cybercrime", origin: "Russia", targets: "Retail, Hospitality, Finance", ttps: "Carbanak malware, POS attacks, fake companies for recruitment", status: "Active", victims2024: 41 }
];

var BREACH_DB = [
  { name: "National Public Data", records: "2.9B", date: "2024-08", type: "PII (SSN, DOB, Address)", source: "Unsecured database", industry: "Data Broker" },
  { name: "MOVEit Transfer", records: "77M+", date: "2023-06", type: "Employee/Financial data", source: "Zero-day (CVE-2023-34362)", industry: "Multiple" },
  { name: "AT&T", records: "73M", date: "2024-03", type: "Customer PII, SSN", source: "Third-party breach", industry: "Telecom" },
  { name: "Ticketmaster", records: "560M", date: "2024-05", type: "Payment, PII", source: "Snowflake credential theft", industry: "Entertainment" },
  { name: "Change Healthcare", records: "100M+", date: "2024-02", type: "Medical, Insurance, PII", source: "Ransomware (BlackCat)", industry: "Healthcare" },
  { name: "Dell", records: "49M", date: "2024-05", type: "Customer names, addresses", source: "API abuse", industry: "Technology" },
  { name: "23andMe", records: "6.9M", date: "2023-10", type: "Genetic, ancestry data", source: "Credential stuffing", industry: "Biotech" },
  { name: "Snowflake Customers", records: "500M+", date: "2024-06", type: "Various enterprise data", source: "Stolen credentials (no MFA)", industry: "Cloud/SaaS" },
  { name: "T-Mobile", records: "37M", date: "2023-01", type: "Customer PII, account data", source: "API abuse", industry: "Telecom" },
  { name: "MGM Resorts", records: "10M+", date: "2023-09", type: "PII, loyalty data", source: "Social engineering (Scattered Spider)", industry: "Hospitality" },
  { name: "Caesars Entertainment", records: "65M", date: "2023-09", type: "Loyalty program data, SSN", source: "Social engineering", industry: "Hospitality" },
  { name: "Latitude Financial", records: "14M", date: "2023-03", type: "ID documents, financial", source: "Credential theft", industry: "Finance" },
  { name: "ICMR India", records: "815M", date: "2023-10", type: "PII (Aadhaar, passport)", source: "Unsecured database", industry: "Government" },
  { name: "Real Estate Wealth Network", records: "1.5B", date: "2023-12", type: "Property, owner data", source: "Misconfiguration", industry: "Real Estate" },
  { name: "Infosys McCamish", records: "6M", date: "2024-01", type: "Insurance, financial PII", source: "Ransomware (LockBit)", industry: "Insurance" },
  { name: "loanDepot", records: "16.6M", date: "2024-01", type: "Financial, SSN, PII", source: "Ransomware", industry: "Finance" },
  { name: "Hathaway Corp", records: "100M", date: "2024-04", type: "Enterprise data", source: "Supply chain compromise", industry: "Technology" },
  { name: "UnitedHealth/Optum", records: "100M+", date: "2024-02", type: "Medical, claims, PII", source: "Ransomware (BlackCat)", industry: "Healthcare" }
];

var TIMELINE_EVENTS = [
  { date: "2017-05", name: "WannaCry", type: "ransomware", impact: "300,000+ systems in 150 countries", desc: "EternalBlue SMB exploit spread globally in hours, crippling NHS hospitals and major enterprises. Kill switch discovered by MalwareTech." },
  { date: "2017-06", name: "NotPetya", type: "nation-state", impact: "$10B+ in damages worldwide", desc: "Russian GRU disguised destructive wiper as ransomware. Spread via MeDoc tax software update in Ukraine, hit Maersk, Merck, FedEx globally." },
  { date: "2017-09", name: "Equifax Breach", type: "breach", impact: "147M records (SSN, DOB, addresses)", desc: "Apache Struts vulnerability (CVE-2017-5638) left unpatched for months. Exposed half of all Americans' personal data." },
  { date: "2018-03", name: "Cambridge Analytica", type: "breach", impact: "87M Facebook profiles harvested", desc: "Political consulting firm harvested Facebook data via quiz app, used for voter micro-targeting in US 2016 election and Brexit." },
  { date: "2018-11", name: "Marriott/Starwood Breach", type: "breach", impact: "500M guest records exposed", desc: "Attackers lurked inside Starwood network since 2014, undiscovered through Marriott acquisition. Attributed to Chinese MSS." },
  { date: "2019-07", name: "Capital One Breach", type: "breach", impact: "106M customer records", desc: "Former AWS employee exploited misconfigured WAF and SSRF to access S3 buckets containing credit applications and SSNs." },
  { date: "2020-07", name: "Twitter VIP Hack", type: "breach", impact: "130 high-profile accounts compromised", desc: "Social engineering of Twitter employees gave attackers internal admin tools. Bitcoin scam tweets posted from Obama, Musk, Apple accounts." },
  { date: "2020-12", name: "SolarWinds (SUNBURST)", type: "nation-state", impact: "18,000 orgs, US gov agencies", desc: "Russian SVR (APT29) compromised SolarWinds Orion build system. Trojanized updates delivered to Fortune 500 and US government networks." },
  { date: "2021-03", name: "Microsoft Exchange (ProxyLogon)", type: "vulnerability", impact: "250,000+ servers exploited globally", desc: "Four zero-days (CVE-2021-26855 etc.) exploited by Hafnium (China) before patch. Mass exploitation by multiple groups followed disclosure." },
  { date: "2021-05", name: "Colonial Pipeline", type: "ransomware", impact: "US East Coast fuel supply disrupted", desc: "DarkSide ransomware shut down largest US fuel pipeline for 6 days. $4.4M ransom paid (partially recovered). Led to executive order on cybersecurity." },
  { date: "2021-07", name: "Kaseya VSA Attack", type: "ransomware", impact: "1,500+ businesses via MSPs", desc: "REvil exploited zero-day in Kaseya VSA remote management. Supply chain attack hit MSPs, cascading to their clients. $70M ransom demanded." },
  { date: "2021-12", name: "Log4Shell (Log4j)", type: "vulnerability", impact: "Billions of devices running Java", desc: "CVE-2021-44228 in Apache Log4j allowed RCE via JNDI injection. Trivially exploitable, ubiquitous library. Mass scanning within hours of disclosure." },
  { date: "2022-02", name: "Ukraine Cyber Offensive", type: "nation-state", impact: "Ukrainian infrastructure targeted", desc: "Russia launched coordinated cyber attacks alongside military invasion: HermeticWiper, WhisperGate, Industroyer2 targeting energy grid." },
  { date: "2022-03", name: "Lapsus$ Spree", type: "breach", impact: "Microsoft, Nvidia, Samsung, Okta breached", desc: "Teen-led group used social engineering and SIM swapping to breach major tech companies. Stole source code and internal data." },
  { date: "2022-03", name: "Dirty Pipe (Linux)", type: "vulnerability", impact: "Linux kernel 5.8+ systems vulnerable", desc: "CVE-2022-0847 allowed overwriting read-only files via pipe buffer flag manipulation. Easy privilege escalation on unpatched Linux." },
  { date: "2022-09", name: "Uber Breach", type: "breach", impact: "Internal systems fully compromised", desc: "Scattered Spider member used MFA fatigue bombing to access Uber employee VPN, then pivoted to Slack, AWS, and GDrive." },
  { date: "2023-01", name: "ESXiArgs Ransomware", type: "ransomware", impact: "3,800+ VMware ESXi servers encrypted", desc: "Mass exploitation of CVE-2021-21974 in VMware ESXi. Automated ransomware targeted unpatched hypervisors across Europe." },
  { date: "2023-05", name: "MOVEit Zero-Day (Cl0p)", type: "vulnerability", impact: "2,600+ organizations, 77M+ individuals", desc: "Cl0p exploited CVE-2023-34362 SQLi in MOVEit Transfer. Mass data theft without deploying ransomware. Largest single campaign by victim count." },
  { date: "2023-09", name: "MGM/Caesars Attacks", type: "ransomware", impact: "$100M+ combined losses", desc: "Scattered Spider social-engineered IT helpdesks at both casino giants. MGM operations crippled for 10 days; Caesars paid $15M ransom." },
  { date: "2023-10", name: "Citrix Bleed", type: "vulnerability", impact: "Thousands of NetScaler devices", desc: "CVE-2023-4966 allowed session token theft from Citrix NetScaler. LockBit and others mass-exploited for initial access." },
  { date: "2024-01", name: "Microsoft Exec Email Hack", type: "nation-state", impact: "Senior Microsoft leadership emails", desc: "APT29 (Midnight Blizzard) accessed Microsoft exec emails via legacy test OAuth app. Password spray on non-MFA account." },
  { date: "2024-02", name: "Change Healthcare Attack", type: "ransomware", impact: "US healthcare payments halted for weeks", desc: "BlackCat/ALPHV encrypted Change Healthcare, disrupting pharmacy claims for 100M+ patients. $22M ransom paid; affiliate dispute followed." },
  { date: "2024-07", name: "CrowdStrike Outage", type: "vulnerability", impact: "8.5M Windows systems crashed globally", desc: "Faulty CrowdStrike Falcon sensor update caused worldwide BSOD. Airlines, hospitals, banks disrupted. Not a cyberattack but exposed single-vendor risk." }
];

var TABS = [
  { id: "monitor", label: "Overview" },
  { id: "actors", label: "Threat Actors" },
  { id: "breaches", label: "Breach Database" },
  { id: "onion", label: "Onion Directory" },
  { id: "timeline", label: "Threat Timeline" }
];

export function renderDarkwebOsint(main) {
  var tab = "monitor";

  function render() {
    var tabsHTML = "";
    for (var i = 0; i < TABS.length; i++) {
      tabsHTML += '<button class="dw-tab' + (TABS[i].id === tab ? " active" : "") + '" data-tab="' + esc(TABS[i].id) + '">' + esc(TABS[i].label) + '</button>';
    }

    var body = "";
    if (tab === "monitor") body = renderMonitor();
    else if (tab === "actors") body = renderActors();
    else if (tab === "breaches") body = renderBreaches();
    else if (tab === "onion") body = renderOnion();
    else if (tab === "timeline") body = renderTimeline();

    main.innerHTML =
      '<h1 class="pg-h1">Dark Web OSINT</h1>' +
      '<p class="muted pg-sub">Reference profiles of threat actors, public data breaches and known .onion services.</p>' +
      '<div class="dw-tabs">' + tabsHTML + '</div>' +
      '<div class="dw-body">' + body + '</div>' +
      '<div class="dw-footer muted">Reference data compiled from public reporting; it is not a live feed. No dark web connections are made.</div>';

    main.querySelectorAll(".dw-tab").forEach(function(btn) {
      btn.onclick = function() { tab = btn.dataset.tab; render(); };
    });

    bindEvents();
  }

  function renderMonitor() {
    return '<div class="dw-stats">' +
      '<div class="dw-stat"><div class="dw-stat-v">' + BREACH_DB.length + '</div><div class="dw-stat-l">Reference Breaches</div></div>' +
      '<div class="dw-stat"><div class="dw-stat-v">' + THREAT_ACTORS.length + '</div><div class="dw-stat-l">Profiled Actors</div></div>' +
      '<div class="dw-stat"><div class="dw-stat-v">' + ONION_SERVICES.length + '</div><div class="dw-stat-l">Directory Entries</div></div>' +
      '</div>' +
      '<div class="dw-panel">' +
      '<h3 class="dw-panel-h">Live Threat Feed</h3>' +
      '<p class="muted">No live feed is connected. This tool does not monitor dark web sources in real time; the tabs above are reference directories built from public reporting.</p>' +
      '</div>';
  }

  function renderActors() {
    var cards = "";
    for (var i = 0; i < THREAT_ACTORS.length; i++) {
      var a = THREAT_ACTORS[i];
      var statusClass = a.status === "Active" ? "dw-status-active" : "dw-status-disrupted";
      cards +=
        '<div class="dw-actor-card">' +
        '<div class="dw-actor-header">' +
        '<strong class="dw-actor-name">' + esc(a.name) + '</strong>' +
        '<span class="dw-actor-status ' + statusClass + '">' + esc(a.status) + '</span>' +
        '</div>' +
        '<div class="dw-actor-meta">' +
        '<span class="dw-actor-type">' + esc(a.type) + '</span>' +
        '<span class="dw-actor-origin">' + esc(a.origin) + '</span>' +
        '</div>' +
        '<div class="dw-kv"><span>Targets</span><span>' + esc(a.targets) + '</span></div>' +
        '<div class="dw-kv"><span>TTPs</span><span>' + esc(a.ttps) + '</span></div>' +
        '<div class="dw-kv"><span>2024 Victims</span><span class="dw-bad">' + a.victims2024 + '</span></div>' +
        '</div>';
    }
    return '<div class="dw-actor-grid">' + cards + '</div>';
  }

  function renderBreaches() {
    var rows = "";
    for (var i = 0; i < BREACH_DB.length; i++) {
      var b = BREACH_DB[i];
      rows +=
        '<tr>' +
        '<td><strong>' + esc(b.name) + '</strong></td>' +
        '<td class="dw-bad mono">' + esc(b.records) + '</td>' +
        '<td class="mono">' + esc(b.date) + '</td>' +
        '<td>' + esc(b.type) + '</td>' +
        '<td>' + esc(b.source) + '</td>' +
        '<td>' + esc(b.industry) + '</td>' +
        '</tr>';
    }
    return '<div class="dw-table-wrap"><table class="dw-table">' +
      '<thead><tr><th>Organization</th><th>Records</th><th>Date</th><th>Data Type</th><th>Attack Vector</th><th>Industry</th></tr></thead>' +
      '<tbody>' + rows + '</tbody>' +
      '</table></div>';
  }

  function renderOnion() {
    var rows = "";
    for (var i = 0; i < ONION_SERVICES.length; i++) {
      var s = ONION_SERVICES[i];
      rows +=
        '<tr class="dw-onion-row" data-cat="' + esc(s.category) + '">' +
        '<td><strong>' + esc(s.name) + '</strong><div class="dw-onion-url mono">' + esc(s.url) + '</div></td>' +
        '<td>' + esc(s.category) + '</td>' +
        '<td>' + esc(s.description) + '</td>' +
        '</tr>';
    }
    return '<p class="muted">Reference directory of well-known services. Reachability is not checked; addresses are truncated.</p>' +
      '<div class="dw-onion-controls">' +
      '<input class="dw-input" id="dw-onion-q" placeholder="Search services...">' +
      '<select class="dw-select" id="dw-onion-cat"><option>All Categories</option><option>Forum</option><option>Market</option><option>Paste</option><option>Search</option><option>Leak Site</option></select>' +
      '</div>' +
      '<div class="dw-table-wrap"><table class="dw-table">' +
      '<thead><tr><th>Service</th><th>Category</th><th>Description</th></tr></thead>' +
      '<tbody>' + rows + '</tbody>' +
      '</table></div>';
  }

  function renderTimeline() {
    var typeColors = {
      ransomware: "#ef4444",
      "nation-state": "#8b5cf6",
      breach: "#f59e0b",
      vulnerability: "#3b82f6"
    };
    var html = '<div class="dw-timeline-wrap">';
    html += '<div class="dw-timeline-legend">';
    html += '<span style="color:' + typeColors.ransomware + '">Ransomware</span>';
    html += '<span style="color:' + typeColors["nation-state"] + '">Nation-State</span>';
    html += '<span style="color:' + typeColors.breach + '">Breach</span>';
    html += '<span style="color:' + typeColors.vulnerability + '">Vulnerability</span>';
    html += '</div>';
    html += '<div class="dw-timeline">';
    for (var i = 0; i < TIMELINE_EVENTS.length; i++) {
      var ev = TIMELINE_EVENTS[i];
      var side = i % 2 === 0 ? "left" : "right";
      var color = typeColors[ev.type] || "#6b7280";
      html += '<div class="dw-tl-item dw-tl-' + side + '">' +
        '<div class="dw-tl-dot" style="background:' + color + '"></div>' +
        '<div class="dw-tl-card">' +
          '<div class="dw-tl-date" style="color:' + color + '">' + esc(ev.date) + '</div>' +
          '<div class="dw-tl-name">' + esc(ev.name) + '</div>' +
          '<div class="dw-tl-type" style="background:' + color + '22;color:' + color + ';border:1px solid ' + color + '44">' + esc(ev.type) + '</div>' +
          '<div class="dw-tl-impact"><strong>Impact:</strong> ' + esc(ev.impact) + '</div>' +
          '<div class="dw-tl-desc">' + esc(ev.desc) + '</div>' +
        '</div>' +
      '</div>';
    }
    html += '</div></div>';
    html += '<style>' +
      '.dw-timeline-wrap{max-width:900px;margin:0 auto}' +
      '.dw-timeline-legend{display:flex;gap:16px;justify-content:center;margin-bottom:20px;font-size:.78rem;font-weight:600}' +
      '.dw-timeline-legend span::before{content:"";display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:5px;background:currentColor}' +
      '.dw-timeline{position:relative;padding:10px 0}' +
      '.dw-timeline::before{content:"";position:absolute;left:50%;top:0;bottom:0;width:2px;background:var(--line,#283a5a);transform:translateX(-1px)}' +
      '.dw-tl-item{position:relative;width:50%;padding:0 30px 24px}' +
      '.dw-tl-left{left:0;text-align:right}' +
      '.dw-tl-right{left:50%;text-align:left}' +
      '.dw-tl-dot{position:absolute;top:4px;width:14px;height:14px;border-radius:50%;border:2px solid var(--bg,#0b1120);z-index:2}' +
      '.dw-tl-left .dw-tl-dot{right:-7px}' +
      '.dw-tl-right .dw-tl-dot{left:-7px}' +
      '.dw-tl-card{background:var(--card,#0f1726);border:1px solid var(--line,#283a5a);border-radius:8px;padding:14px;text-align:left}' +
      '.dw-tl-date{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;margin-bottom:2px}' +
      '.dw-tl-name{font-size:.95rem;font-weight:700;margin-bottom:6px}' +
      '.dw-tl-type{display:inline-block;font-size:.65rem;font-weight:600;padding:2px 8px;border-radius:4px;text-transform:uppercase;letter-spacing:.03em;margin-bottom:8px}' +
      '.dw-tl-impact{font-size:.78rem;color:var(--txt,#e7eefc);margin-bottom:6px;line-height:1.4}' +
      '.dw-tl-desc{font-size:.78rem;color:var(--mut,#7a93b8);line-height:1.5}' +
      '@media(max-width:700px){.dw-timeline::before{left:20px}.dw-tl-item{width:100%;left:0;padding-left:50px;padding-right:10px;text-align:left}.dw-tl-left .dw-tl-dot,.dw-tl-right .dw-tl-dot{left:13px;right:auto}}' +
      '</style>';
    return html;
  }

  function bindEvents() {
    // Onion Scanner: live-filter the service rows by keyword + category.
    var oq = main.querySelector("#dw-onion-q"), oc = main.querySelector("#dw-onion-cat");
    if (oq || oc) {
      var filterOnion = function() {
        var q = (oq && oq.value || "").toLowerCase().trim();
        var cat = (oc && oc.value) || "All Categories";
        main.querySelectorAll(".dw-onion-row").forEach(function(row) {
          var matchQ = !q || row.textContent.toLowerCase().indexOf(q) >= 0;
          var matchCat = cat === "All Categories" || (row.getAttribute("data-cat") === cat);
          row.style.display = (matchQ && matchCat) ? "" : "none";
        });
      };
      if (oq) oq.oninput = filterOnion;
      if (oc) oc.onchange = filterOnion;
    }
  }

  render();
}
