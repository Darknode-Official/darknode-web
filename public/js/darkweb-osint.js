var esc = function(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function(c) { return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]; }); };

var ONION_SERVICES = [
  { url: "dread...onion", name: "Dread Forum", category: "Forum", status: "Online", lastSeen: "2 min ago", description: "Reddit-like darknet forum for market discussions and security" },
  { url: "breach...onion", name: "BreachForums Mirror", category: "Forum", status: "Online", lastSeen: "5 min ago", description: "Database leak sharing and trading platform" },
  { url: "paste...onion", name: "DeepPaste", category: "Paste", status: "Online", lastSeen: "1 min ago", description: "Anonymous paste service for sensitive data" },
  { url: "market...onion", name: "AlphaBay Market", category: "Market", status: "Offline", lastSeen: "3 days ago", description: "Former largest darknet marketplace (seized by LE)" },
  { url: "wiki...onion", name: "Hidden Wiki", category: "Directory", status: "Online", lastSeen: "8 min ago", description: "Directory of .onion services and links" },
  { url: "mail...onion", name: "ProtonMail Onion", category: "Email", status: "Online", lastSeen: "1 min ago", description: "Encrypted email accessible over Tor" },
  { url: "search...onion", name: "Ahmia", category: "Search", status: "Online", lastSeen: "3 min ago", description: "Clearnet search engine for .onion sites" },
  { url: "leak...onion", name: "RansomWatch", category: "Leak Site", status: "Online", lastSeen: "12 min ago", description: "Ransomware group data leak aggregator" }
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

var PASTE_SAMPLES = [
  { title: "Database dump - users table", site: "DeepPaste", time: "14 min ago", tags: ["database", "credentials"], preview: "id,email,password_hash,created_at\n1,admin@corp.com,$2b$12$...,2024-01-15\n2,user@example.com,$2b$12$...,2024-02-03" },
  { title: "AWS Access Keys (exposed)", site: "PrivBin", time: "28 min ago", tags: ["cloud", "credentials", "aws"], preview: "AKIA[REDACTED]\naws_secret_access_key = [REDACTED]\nregion = us-east-1" },
  { title: "Internal network diagram", site: "ZeroPaste", time: "1 hr ago", tags: ["network", "recon"], preview: "10.0.0.0/8 - Corporate\n172.16.0.0/12 - DMZ\n192.168.1.0/24 - Management" },
  { title: "Combolists - email:pass 500K", site: "DeepPaste", time: "3 hrs ago", tags: ["credentials", "combo"], preview: "user1@gmail.com:p@ssw0rd\nuser2@yahoo.com:123456\n[497,998 more entries...]" },
  { title: "Ransomware negotiation chat log", site: "OnionPaste", time: "5 hrs ago", tags: ["ransomware", "negotiation"], preview: "[Operator]: Your files have been encrypted.\n[Victim]: How much?\n[Operator]: 2.5 BTC within 72 hours." },
  { title: "Zero-day exploit - RCE in [product]", site: "PrivBin", time: "8 hrs ago", tags: ["exploit", "0day"], preview: "# Remote Code Execution\n# Affects: [PRODUCT] < v4.2.1\n# Type: Deserialization\ncurl -X POST ..." }
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

var EMAIL_BREACH_DATA = [
  { name: "LinkedIn (2021)", exposed: ["Email", "Password hash (SHA1)", "Full name", "Phone"], severity: "high", date: "2021-06", records: "700M" },
  { name: "Adobe (2013)", exposed: ["Email", "Encrypted password", "Username", "Password hint"], severity: "high", date: "2013-10", records: "153M" },
  { name: "Dropbox (2016)", exposed: ["Email", "Password hash (bcrypt)"], severity: "medium", date: "2016-08", records: "68M" },
  { name: "MyFitnessPal (2018)", exposed: ["Email", "Username", "Password hash (SHA1)"], severity: "high", date: "2018-02", records: "150M" },
  { name: "Canva (2019)", exposed: ["Email", "Username", "Full name", "Location"], severity: "medium", date: "2019-05", records: "137M" },
  { name: "Zynga (2019)", exposed: ["Email", "Username", "Password hash (SHA1)", "Phone"], severity: "high", date: "2019-09", records: "170M" },
  { name: "Exactis (2018)", exposed: ["Email", "Phone", "Address", "Personal interests", "Household data"], severity: "critical", date: "2018-06", records: "340M" },
  { name: "Apollo (2018)", exposed: ["Email", "Employer", "Job title", "Phone", "Location"], severity: "medium", date: "2018-07", records: "200M" },
  { name: "Wattpad (2020)", exposed: ["Email", "Username", "Password hash (bcrypt)", "DOB", "IP"], severity: "high", date: "2020-06", records: "271M" },
  { name: "Dubsmash (2019)", exposed: ["Email", "Username", "Password hash (SHA256)"], severity: "medium", date: "2019-02", records: "162M" },
  { name: "Cit0day Collection (2020)", exposed: ["Email", "Plaintext password"], severity: "critical", date: "2020-11", records: "226M" },
  { name: "Gravatar (2020)", exposed: ["Email", "Username", "Password hash (MD5/phpass)"], severity: "medium", date: "2020-10", records: "114M" },
  { name: "Verifications.io (2019)", exposed: ["Email", "Full name", "Phone", "Address", "DOB", "IP"], severity: "critical", date: "2019-02", records: "763M" },
  { name: "MGM Resorts (2020)", exposed: ["Email", "Full name", "Phone", "Address", "DOB"], severity: "high", date: "2020-02", records: "142M" },
  { name: "Twitter/X (2023)", exposed: ["Email", "Phone", "Username", "Account metadata"], severity: "medium", date: "2023-01", records: "200M" }
];

var TABS = [
  { id: "monitor", label: "Live Monitor" },
  { id: "actors", label: "Threat Actors" },
  { id: "breaches", label: "Breach Database" },
  { id: "paste", label: "Paste Monitor" },
  { id: "onion", label: "Onion Scanner" },
  { id: "email", label: "Email Lookup" },
  { id: "crypto", label: "Crypto Tracing" },
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
    else if (tab === "paste") body = renderPaste();
    else if (tab === "onion") body = renderOnion();
    else if (tab === "email") body = renderEmail();
    else if (tab === "crypto") body = renderCrypto();
    else if (tab === "timeline") body = renderTimeline();

    main.innerHTML =
      '<h1 class="pg-h1">Dark Web OSINT</h1>' +
      '<p class="muted pg-sub">Monitor threat actors, data breaches, paste sites, and .onion services.</p>' +
      '<div class="dw-tabs">' + tabsHTML + '</div>' +
      '<div class="dw-body">' + body + '</div>' +
      '<div class="dw-footer muted">All data is simulated for educational purposes. No real dark web connections are made.</div>';

    main.querySelectorAll(".dw-tab").forEach(function(btn) {
      btn.onclick = function() { tab = btn.dataset.tab; render(); };
    });

    bindEvents();
  }

  function renderMonitor() {
    var feedItems = "";
    var feed = [
      { time: "2 min ago", type: "breach", text: "New data dump posted on BreachForums -- 2.3M records from fintech company" },
      { time: "8 min ago", type: "ransomware", text: "LockBit claims attack on European logistics firm -- 72hr deadline" },
      { time: "15 min ago", type: "paste", text: "AWS credentials exposed on DeepPaste -- IAM keys with admin privileges" },
      { time: "22 min ago", type: "market", text: "New initial access listing -- RDP to US hospital network ($5,000)" },
      { time: "34 min ago", type: "exploit", text: "PoC exploit for CVE-2024-XXXX shared on underground forum" },
      { time: "41 min ago", type: "actor", text: "Scattered Spider member claims successful SIM swap of telecom exec" },
      { time: "55 min ago", type: "breach", text: "ShinyHunters selling 40M user records from gaming platform" },
      { time: "1 hr ago", type: "ransomware", text: "BlackBasta leak site updated -- 3 new victims added" }
    ];
    for (var i = 0; i < feed.length; i++) {
      var f = feed[i];
      var typeClass = "dw-feed-" + f.type;
      feedItems += '<div class="dw-feed-item">' +
        '<span class="dw-feed-type ' + typeClass + '">' + esc(f.type) + '</span>' +
        '<span class="dw-feed-text">' + esc(f.text) + '</span>' +
        '<span class="dw-feed-time">' + esc(f.time) + '</span>' +
        '</div>';
    }

    return '<div class="dw-stats">' +
      '<div class="dw-stat"><div class="dw-stat-v dw-bad">' + BREACH_DB.length + '</div><div class="dw-stat-l">Major Breaches</div></div>' +
      '<div class="dw-stat"><div class="dw-stat-v dw-warn">' + THREAT_ACTORS.length + '</div><div class="dw-stat-l">Tracked Actors</div></div>' +
      '<div class="dw-stat"><div class="dw-stat-v">' + ONION_SERVICES.filter(function(s) { return s.status === "Online"; }).length + '</div><div class="dw-stat-l">Active Services</div></div>' +
      '<div class="dw-stat"><div class="dw-stat-v">' + PASTE_SAMPLES.length + '</div><div class="dw-stat-l">New Pastes</div></div>' +
      '</div>' +
      '<div class="dw-panel">' +
      '<h3 class="dw-panel-h"><span class="dw-pulse"></span> Live Threat Feed</h3>' +
      '<div class="dw-feed">' + feedItems + '</div>' +
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

  function renderPaste() {
    var items = "";
    for (var i = 0; i < PASTE_SAMPLES.length; i++) {
      var p = PASTE_SAMPLES[i];
      var tags = "";
      for (var t = 0; t < p.tags.length; t++) {
        tags += '<span class="dw-tag">' + esc(p.tags[t]) + '</span>';
      }
      items +=
        '<div class="dw-paste-card">' +
        '<div class="dw-paste-header">' +
        '<strong>' + esc(p.title) + '</strong>' +
        '<span class="dw-paste-time">' + esc(p.time) + '</span>' +
        '</div>' +
        '<div class="dw-paste-meta">' +
        '<span class="dw-paste-site">' + esc(p.site) + '</span>' +
        tags +
        '</div>' +
        '<pre class="dw-paste-preview">' + esc(p.preview) + '</pre>' +
        '</div>';
    }
    return '<div class="dw-paste-controls">' +
      '<input class="dw-input" placeholder="Search pastes (keyword, email, domain...)">' +
      '<select class="dw-select"><option>All Sites</option><option>DeepPaste</option><option>PrivBin</option><option>ZeroPaste</option><option>OnionPaste</option></select>' +
      '</div>' +
      '<div class="dw-paste-list">' + items + '</div>';
  }

  function renderOnion() {
    var rows = "";
    for (var i = 0; i < ONION_SERVICES.length; i++) {
      var s = ONION_SERVICES[i];
      var statusCls = s.status === "Online" ? "dw-online" : "dw-offline";
      rows +=
        '<tr>' +
        '<td><strong>' + esc(s.name) + '</strong><div class="dw-onion-url mono">' + esc(s.url) + '</div></td>' +
        '<td>' + esc(s.category) + '</td>' +
        '<td><span class="' + statusCls + '">' + esc(s.status) + '</span></td>' +
        '<td>' + esc(s.lastSeen) + '</td>' +
        '<td>' + esc(s.description) + '</td>' +
        '</tr>';
    }
    return '<div class="dw-onion-controls">' +
      '<input class="dw-input" placeholder="Search .onion services...">' +
      '<select class="dw-select"><option>All Categories</option><option>Forum</option><option>Market</option><option>Paste</option><option>Search</option><option>Leak Site</option></select>' +
      '</div>' +
      '<div class="dw-table-wrap"><table class="dw-table">' +
      '<thead><tr><th>Service</th><th>Category</th><th>Status</th><th>Last Seen</th><th>Description</th></tr></thead>' +
      '<tbody>' + rows + '</tbody>' +
      '</table></div>';
  }

  function renderEmail() {
    return '<div class="dw-panel">' +
      '<h3 class="dw-panel-h">Email Breach Lookup</h3>' +
      '<p class="muted">Check if an email address appears in known data breaches. Educational simulation.</p>' +
      '<div class="dw-email-form">' +
      '<input class="dw-input dw-input-lg" id="dw-email-input" placeholder="Enter email address...">' +
      '<button class="dw-btn" id="dw-email-check">Check Breaches</button>' +
      '</div>' +
      '<div id="dw-email-result"></div>' +
      '</div>';
  }

  function renderCrypto() {
    return '<div class="dw-panel">' +
      '<h3 class="dw-panel-h">Cryptocurrency Address Analyzer</h3>' +
      '<p class="muted">Trace cryptocurrency transactions and identify suspicious activity patterns. Simulated analysis.</p>' +
      '<div class="dw-crypto-form">' +
      '<select class="dw-select" id="dw-crypto-chain"><option>Bitcoin (BTC)</option><option>Ethereum (ETH)</option><option>Monero (XMR)</option></select>' +
      '<input class="dw-input dw-input-lg" id="dw-crypto-addr" placeholder="Enter wallet address...">' +
      '<button class="dw-btn" id="dw-crypto-trace">Trace Address</button>' +
      '</div>' +
      '<div id="dw-crypto-result"></div>' +
      '</div>' +
      '<div class="dw-panel">' +
      '<h3 class="dw-panel-h">Known Ransomware Wallets</h3>' +
      '<div class="dw-table-wrap"><table class="dw-table">' +
      '<thead><tr><th>Group</th><th>Address (truncated)</th><th>Total Received</th><th>Status</th></tr></thead>' +
      '<tbody>' +
      '<tr><td>LockBit 3.0</td><td class="mono">bc1q...7x4m</td><td class="dw-bad">$91.2M</td><td>Active</td></tr>' +
      '<tr><td>BlackCat</td><td class="mono">bc1q...f2ka</td><td class="dw-bad">$42.8M</td><td>Seized</td></tr>' +
      '<tr><td>Cl0p</td><td class="mono">bc1q...9p3n</td><td class="dw-bad">$67.5M</td><td>Active</td></tr>' +
      '<tr><td>Conti (defunct)</td><td class="mono">bc1q...m8zr</td><td class="dw-bad">$180M+</td><td>Defunct</td></tr>' +
      '<tr><td>REvil</td><td class="mono">bc1q...k4wn</td><td class="dw-bad">$123M</td><td>Arrested</td></tr>' +
      '</tbody></table></div></div>';
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
      '.dw-timeline::before{content:"";position:absolute;left:50%;top:0;bottom:0;width:2px;background:var(--line,#21262d);transform:translateX(-1px)}' +
      '.dw-tl-item{position:relative;width:50%;padding:0 30px 24px}' +
      '.dw-tl-left{left:0;text-align:right}' +
      '.dw-tl-right{left:50%;text-align:left}' +
      '.dw-tl-dot{position:absolute;top:4px;width:14px;height:14px;border-radius:50%;border:2px solid var(--bg,#0a0e1a);z-index:2}' +
      '.dw-tl-left .dw-tl-dot{right:-7px}' +
      '.dw-tl-right .dw-tl-dot{left:-7px}' +
      '.dw-tl-card{background:var(--card,#0d1117);border:1px solid var(--line,#21262d);border-radius:8px;padding:14px;text-align:left}' +
      '.dw-tl-date{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;margin-bottom:2px}' +
      '.dw-tl-name{font-size:.95rem;font-weight:700;margin-bottom:6px}' +
      '.dw-tl-type{display:inline-block;font-size:.65rem;font-weight:600;padding:2px 8px;border-radius:4px;text-transform:uppercase;letter-spacing:.03em;margin-bottom:8px}' +
      '.dw-tl-impact{font-size:.78rem;color:var(--txt,#c8d6e5);margin-bottom:6px;line-height:1.4}' +
      '.dw-tl-desc{font-size:.78rem;color:var(--mut,#6b7280);line-height:1.5}' +
      '@media(max-width:700px){.dw-timeline::before{left:20px}.dw-tl-item{width:100%;left:0;padding-left:50px;padding-right:10px;text-align:left}.dw-tl-left .dw-tl-dot,.dw-tl-right .dw-tl-dot{left:13px;right:auto}}' +
      '</style>';
    return html;
  }

  function checkEmail() {
    var emailInput = main.querySelector("#dw-email-input");
    var resultDiv = main.querySelector("#dw-email-result");
    if (!emailInput || !resultDiv) return;
    var email = emailInput.value.trim();
    if (!email || email.indexOf("@") === -1) {
      resultDiv.innerHTML = '<div class="dw-warn-box">Enter a valid email address.</div>';
      return;
    }

    var hash = 0;
    for (var i = 0; i < email.length; i++) { hash = ((hash << 5) - hash) + email.charCodeAt(i); hash |= 0; }
    var breachCount = (Math.abs(hash) % 10) + 1;
    if (breachCount > EMAIL_BREACH_DATA.length) breachCount = EMAIL_BREACH_DATA.length;

    var shuffled = EMAIL_BREACH_DATA.slice();
    var seed = Math.abs(hash);
    for (var j = shuffled.length - 1; j > 0; j--) {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      var k = seed % (j + 1);
      var tmp = shuffled[j];
      shuffled[j] = shuffled[k];
      shuffled[k] = tmp;
    }
    var found = shuffled.slice(0, breachCount);

    var sevColors = { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e" };
    var summaryHtml = '<div class="dw-result-bad" style="margin-bottom:16px">' +
      '<strong>' + esc(email) + '</strong> found in <strong>' + found.length + '</strong> known breaches' +
      '</div>';

    var listHtml = '';
    for (var m = 0; m < found.length; m++) {
      var br = found[m];
      var sevColor = sevColors[br.severity] || "#6b7280";
      var exposedHtml = '';
      for (var e = 0; e < br.exposed.length; e++) {
        exposedHtml += '<span style="display:inline-block;padding:2px 6px;margin:2px;font-size:.68rem;background:var(--line,#21262d);border-radius:3px">' + esc(br.exposed[e]) + '</span>';
      }
      listHtml += '<div style="background:var(--card,#0d1117);border:1px solid var(--line,#21262d);border-left:3px solid ' + sevColor + ';border-radius:6px;padding:14px;margin-bottom:8px">' +
        '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">' +
          '<strong style="font-size:.88rem">' + esc(br.name) + '</strong>' +
          '<span style="font-size:.65rem;font-weight:700;padding:2px 8px;border-radius:3px;text-transform:uppercase;background:' + sevColor + '22;color:' + sevColor + '">' + esc(br.severity) + '</span>' +
        '</div>' +
        '<div class="dw-kv" style="margin-bottom:4px"><span>Date</span><span class="mono">' + esc(br.date) + '</span></div>' +
        '<div class="dw-kv" style="margin-bottom:4px"><span>Records Affected</span><span class="dw-bad mono">' + esc(br.records) + '</span></div>' +
        '<div style="margin-top:6px"><div style="font-size:.72rem;color:var(--mut,#6b7280);margin-bottom:4px;font-weight:600">Data Exposed:</div>' + exposedHtml + '</div>' +
      '</div>';
    }

    var totalExposed = {};
    for (var n = 0; n < found.length; n++) {
      for (var p = 0; p < found[n].exposed.length; p++) {
        totalExposed[found[n].exposed[p]] = true;
      }
    }
    var exposedKeys = Object.keys(totalExposed);
    var exposedSummary = '';
    for (var q = 0; q < exposedKeys.length; q++) {
      exposedSummary += '<span style="display:inline-block;padding:3px 8px;margin:2px;font-size:.72rem;background:#ef444422;color:#ef4444;border:1px solid #ef444444;border-radius:4px">' + esc(exposedKeys[q]) + '</span>';
    }

    resultDiv.innerHTML = summaryHtml +
      '<div style="background:var(--card,#0d1117);border:1px solid var(--line,#21262d);border-radius:8px;padding:16px;margin-bottom:16px">' +
        '<div style="font-size:.82rem;font-weight:600;margin-bottom:8px">Aggregate Exposure Summary</div>' +
        '<div style="margin-bottom:8px">' + exposedSummary + '</div>' +
        '<div class="muted" style="font-size:.72rem">Your data types above were found across ' + found.length + ' separate incidents</div>' +
      '</div>' +
      '<div style="font-size:.82rem;font-weight:600;margin-bottom:8px">Breach Details</div>' +
      listHtml;
  }

  function traceCrypto() {
    var addrInput = main.querySelector("#dw-crypto-addr");
    var resultDiv = main.querySelector("#dw-crypto-result");
    if (!addrInput || !resultDiv) return;
    var addr = addrInput.value.trim();
    if (!addr || addr.length < 10) {
      resultDiv.innerHTML = '<div class="dw-warn-box">Enter a valid cryptocurrency address.</div>';
      return;
    }
    var hash = 0;
    for (var i = 0; i < addr.length; i++) { hash = ((hash << 5) - hash) + addr.charCodeAt(i); hash |= 0; }
    var bal = (Math.abs(hash) % 10000) / 100;
    var txCount = Math.abs(hash) % 200 + 5;
    var risk = Math.abs(hash) % 100;
    var riskLevel = risk > 70 ? "High Risk" : risk > 40 ? "Medium Risk" : "Low Risk";
    var riskClass = risk > 70 ? "dw-bad" : risk > 40 ? "dw-warn" : "dw-ok";
    var isMixer = risk > 60;
    var isExchange = risk < 35;

    var addrShort = addr.length > 12 ? addr.substring(0, 6) + "..." + addr.substring(addr.length - 4) : addr;

    var incomingSources = [
      { label: "Exchange (Binance)", amount: (bal * 0.4).toFixed(3), risk: "low" },
      { label: "Unknown Wallet", amount: (bal * 0.25).toFixed(3), risk: "medium" },
      { label: isMixer ? "Mixing Service" : "Mining Pool", amount: (bal * 0.2).toFixed(3), risk: isMixer ? "high" : "low" },
      { label: "P2P Transfer", amount: (bal * 0.15).toFixed(3), risk: "medium" }
    ];
    var outgoingSinks = [
      { label: isExchange ? "Exchange (Kraken)" : "Unknown Wallet", amount: (bal * 0.35).toFixed(3), risk: isExchange ? "low" : "medium" },
      { label: risk > 50 ? "Darknet Market" : "DeFi Protocol", amount: (bal * 0.3).toFixed(3), risk: risk > 50 ? "high" : "low" },
      { label: "Cold Storage", amount: (bal * 0.2).toFixed(3), risk: "low" },
      { label: "Unspent", amount: (bal * 0.15).toFixed(3), risk: "none" }
    ];

    var riskColors = { high: "#ef4444", medium: "#f59e0b", low: "#22c55e", none: "#6b7280" };

    var flowHtml = '<div style="display:flex;align-items:center;gap:0;margin:20px 0;overflow-x:auto;padding:10px 0">';
    // Incoming column
    flowHtml += '<div style="display:flex;flex-direction:column;gap:6px;min-width:160px">';
    for (var s = 0; s < incomingSources.length; s++) {
      var src = incomingSources[s];
      flowHtml += '<div style="background:var(--card,#0d1117);border:1px solid ' + riskColors[src.risk] + '44;border-radius:6px;padding:8px 10px;font-size:.72rem">' +
        '<div style="font-weight:600;color:' + riskColors[src.risk] + '">' + esc(src.label) + '</div>' +
        '<div class="mono" style="margin-top:2px">' + esc(src.amount) + ' BTC</div>' +
      '</div>';
    }
    flowHtml += '</div>';
    // Arrows in
    flowHtml += '<div style="display:flex;flex-direction:column;align-items:center;justify-content:center;padding:0 8px;min-width:40px">';
    for (var ai = 0; ai < 4; ai++) {
      flowHtml += '<div style="color:var(--mut,#6b7280);font-size:.8rem;margin:8px 0">--&gt;</div>';
    }
    flowHtml += '</div>';
    // Center node
    flowHtml += '<div style="background:var(--card,#0d1117);border:2px solid ' + (risk > 70 ? '#ef4444' : risk > 40 ? '#f59e0b' : '#22c55e') + ';border-radius:10px;padding:16px;min-width:140px;text-align:center">' +
      '<div style="font-size:.68rem;color:var(--mut,#6b7280);text-transform:uppercase;font-weight:600;margin-bottom:4px">Target Address</div>' +
      '<div class="mono" style="font-size:.82rem;font-weight:700;margin-bottom:6px">' + esc(addrShort) + '</div>' +
      '<div style="font-size:1.1rem;font-weight:800">' + bal.toFixed(2) + ' BTC</div>' +
      '<div style="font-size:.68rem;margin-top:4px;color:' + (risk > 70 ? '#ef4444' : risk > 40 ? '#f59e0b' : '#22c55e') + ';font-weight:600">' + esc(riskLevel) + '</div>' +
    '</div>';
    // Arrows out
    flowHtml += '<div style="display:flex;flex-direction:column;align-items:center;justify-content:center;padding:0 8px;min-width:40px">';
    for (var ao = 0; ao < 4; ao++) {
      flowHtml += '<div style="color:var(--mut,#6b7280);font-size:.8rem;margin:8px 0">--&gt;</div>';
    }
    flowHtml += '</div>';
    // Outgoing column
    flowHtml += '<div style="display:flex;flex-direction:column;gap:6px;min-width:160px">';
    for (var d = 0; d < outgoingSinks.length; d++) {
      var sink = outgoingSinks[d];
      flowHtml += '<div style="background:var(--card,#0d1117);border:1px solid ' + riskColors[sink.risk] + '44;border-radius:6px;padding:8px 10px;font-size:.72rem">' +
        '<div style="font-weight:600;color:' + riskColors[sink.risk] + '">' + esc(sink.label) + '</div>' +
        '<div class="mono" style="margin-top:2px">' + esc(sink.amount) + ' BTC</div>' +
      '</div>';
    }
    flowHtml += '</div>';
    flowHtml += '</div>';

    var flagsHtml = '';
    if (isMixer) {
      flagsHtml += '<div style="background:#ef444418;border:1px solid #ef444444;border-radius:6px;padding:10px 14px;margin-bottom:6px;font-size:.78rem">' +
        '<strong style="color:#ef4444">Mixing Service Detected</strong> -- Funds passed through a tumbling/mixing service to obscure transaction trail.' +
        '</div>';
    }
    if (risk > 50) {
      flagsHtml += '<div style="background:#f59e0b18;border:1px solid #f59e0b44;border-radius:6px;padding:10px 14px;margin-bottom:6px;font-size:.78rem">' +
        '<strong style="color:#f59e0b">Darknet Market Exposure</strong> -- Address has transacted with known darknet market wallets.' +
        '</div>';
    }
    if (risk > 70) {
      flagsHtml += '<div style="background:#ef444418;border:1px solid #ef444444;border-radius:6px;padding:10px 14px;margin-bottom:6px;font-size:.78rem">' +
        '<strong style="color:#ef4444">OFAC Sanctions Match</strong> -- This address appears on the OFAC SDN list. Transacting with this address may violate US sanctions.' +
        '</div>';
    }

    resultDiv.innerHTML =
      '<div class="dw-crypto-result">' +
      '<div class="dw-crypto-stats">' +
      '<div class="dw-stat"><div class="dw-stat-v">' + bal.toFixed(2) + ' BTC</div><div class="dw-stat-l">Balance</div></div>' +
      '<div class="dw-stat"><div class="dw-stat-v">' + txCount + '</div><div class="dw-stat-l">Transactions</div></div>' +
      '<div class="dw-stat"><div class="dw-stat-v ' + riskClass + '">' + esc(riskLevel) + '</div><div class="dw-stat-l">Risk Score</div></div>' +
      '<div class="dw-stat"><div class="dw-stat-v">' + (isMixer ? '<span class="dw-bad">Yes</span>' : 'No') + '</div><div class="dw-stat-l">Mixer Used</div></div>' +
      '</div>' +
      '<div class="dw-kv"><span>First seen</span><span>2023-04-12</span></div>' +
      '<div class="dw-kv"><span>Last activity</span><span>2024-11-28</span></div>' +
      '<div class="dw-kv"><span>Cluster</span><span>' + (isExchange ? 'Exchange (Binance-linked)' : 'Unknown / Private') + '</span></div>' +
      '<div class="dw-kv"><span>Sanctions</span><span>' + (risk > 70 ? '<span class="dw-bad">OFAC Listed</span>' : 'Not listed') + '</span></div>' +
      '<div class="dw-kv"><span>Attribution</span><span>' + (risk > 60 ? '<span class="dw-warn">Possible ransomware proceeds</span>' : 'No known attribution') + '</span></div>' +
      '</div>' +
      '<div style="margin-top:16px"><div style="font-size:.88rem;font-weight:600;margin-bottom:4px">Transaction Flow Analysis</div>' +
      '<div class="muted" style="font-size:.72rem;margin-bottom:8px">Visualizing fund sources (left) and destinations (right) for this address</div>' +
      flowHtml + '</div>' +
      (flagsHtml ? '<div style="margin-top:12px"><div style="font-size:.82rem;font-weight:600;margin-bottom:6px">Risk Flags</div>' + flagsHtml + '</div>' : '');
  }

  function bindEvents() {
    var emailBtn = main.querySelector("#dw-email-check");
    if (emailBtn) emailBtn.onclick = checkEmail;
    var cryptoBtn = main.querySelector("#dw-crypto-trace");
    if (cryptoBtn) cryptoBtn.onclick = traceCrypto;
  }

  render();
}
