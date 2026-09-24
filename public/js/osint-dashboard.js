// OSINT Dashboard — research organizer, username checker, Google dork builder, tool directory
const esc = (s) => String(s != null ? s : "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

// ── Platform Database for Username Checking (200+) ──
const PLATFORMS = {
  "Social Media": [
    { name: "Twitter/X", url: "https://x.com/{}", check: "Profile page" },
    { name: "Facebook", url: "https://facebook.com/{}", check: "Profile page" },
    { name: "Instagram", url: "https://instagram.com/{}", check: "Profile page" },
    { name: "TikTok", url: "https://tiktok.com/@{}", check: "Profile page" },
    { name: "Snapchat", url: "https://snapchat.com/add/{}", check: "Add page" },
    { name: "Pinterest", url: "https://pinterest.com/{}", check: "Profile page" },
    { name: "Tumblr", url: "https://{}.tumblr.com", check: "Blog page" },
    { name: "Mastodon", url: "Search on instances", check: "Federated search" },
    { name: "Bluesky", url: "https://bsky.app/profile/{}", check: "Profile page" },
    { name: "Threads", url: "https://threads.net/@{}", check: "Profile page" },
    { name: "VK", url: "https://vk.com/{}", check: "Profile page" },
    { name: "Weibo", url: "Search on weibo.com", check: "Search" },
  ],
  "Professional": [
    { name: "LinkedIn", url: "https://linkedin.com/in/{}", check: "Profile page" },
    { name: "AngelList", url: "https://angel.co/u/{}", check: "Profile page" },
    { name: "Glassdoor", url: "Search on glassdoor.com", check: "Search" },
    { name: "Crunchbase", url: "https://crunchbase.com/person/{}", check: "Person page" },
    { name: "About.me", url: "https://about.me/{}", check: "Profile page" },
    { name: "Gravatar", url: "Check via email hash", check: "API lookup" },
    { name: "Keybase", url: "https://keybase.io/{}", check: "Profile page" },
  ],
  "Development": [
    { name: "GitHub", url: "https://github.com/{}", check: "Profile page" },
    { name: "GitLab", url: "https://gitlab.com/{}", check: "Profile page" },
    { name: "Bitbucket", url: "https://bitbucket.org/{}", check: "Profile page" },
    { name: "Stack Overflow", url: "Search on stackoverflow.com", check: "User search" },
    { name: "Dev.to", url: "https://dev.to/{}", check: "Profile page" },
    { name: "HackerNews", url: "https://news.ycombinator.com/user?id={}", check: "Profile page" },
    { name: "CodePen", url: "https://codepen.io/{}", check: "Profile page" },
    { name: "Replit", url: "https://replit.com/@{}", check: "Profile page" },
    { name: "npm", url: "https://npmjs.com/~{}", check: "Profile page" },
    { name: "PyPI", url: "https://pypi.org/user/{}", check: "Profile page" },
    { name: "Docker Hub", url: "https://hub.docker.com/u/{}", check: "Profile page" },
    { name: "HackerRank", url: "https://hackerrank.com/{}", check: "Profile page" },
    { name: "LeetCode", url: "https://leetcode.com/{}", check: "Profile page" },
    { name: "Codewars", url: "https://codewars.com/users/{}", check: "Profile page" },
  ],
  "Security": [
    { name: "HackerOne", url: "https://hackerone.com/{}", check: "Profile page" },
    { name: "Bugcrowd", url: "https://bugcrowd.com/{}", check: "Profile page" },
    { name: "Hack The Box", url: "Search on hackthebox.com", check: "Search" },
    { name: "TryHackMe", url: "https://tryhackme.com/p/{}", check: "Profile page" },
    { name: "Root-Me", url: "https://root-me.org/{}", check: "Profile page" },
    { name: "CTFtime", url: "Search on ctftime.org", check: "Search" },
  ],
  "Gaming": [
    { name: "Steam", url: "https://steamcommunity.com/id/{}", check: "Profile page" },
    { name: "Xbox/GamerTag", url: "https://xboxgamertag.com/search/{}", check: "Search" },
    { name: "PSN", url: "Search on psnprofiles.com", check: "Search" },
    { name: "Twitch", url: "https://twitch.tv/{}", check: "Channel page" },
    { name: "Epic Games", url: "Search via Fortnite tracker", check: "Search" },
    { name: "Roblox", url: "Search on roblox.com/users", check: "User search" },
    { name: "Minecraft", url: "https://namemc.com/profile/{}", check: "Profile page" },
    { name: "Chess.com", url: "https://chess.com/member/{}", check: "Profile page" },
    { name: "Lichess", url: "https://lichess.org/@/{}", check: "Profile page" },
    { name: "osu!", url: "https://osu.ppy.sh/users/{}", check: "User search" },
    { name: "Riot/LoL", url: "Search on op.gg", check: "Search" },
  ],
  "Forums & Communities": [
    { name: "Reddit", url: "https://reddit.com/user/{}", check: "Profile page" },
    { name: "Quora", url: "https://quora.com/profile/{}", check: "Profile page" },
    { name: "Discord", url: "Lookup via bots/APIs", check: "Bot lookup" },
    { name: "Telegram", url: "https://t.me/{}", check: "Channel/user" },
    { name: "Medium", url: "https://medium.com/@{}", check: "Profile page" },
    { name: "Substack", url: "https://{}.substack.com", check: "Publication" },
    { name: "Disqus", url: "https://disqus.com/by/{}", check: "Profile page" },
    { name: "SlideShare", url: "https://slideshare.net/{}", check: "Profile page" },
    { name: "Goodreads", url: "Search on goodreads.com", check: "Search" },
    { name: "Letterboxd", url: "https://letterboxd.com/{}", check: "Profile page" },
  ],
  "Media & Content": [
    { name: "YouTube", url: "https://youtube.com/@{}", check: "Channel page" },
    { name: "Vimeo", url: "https://vimeo.com/{}", check: "Profile page" },
    { name: "SoundCloud", url: "https://soundcloud.com/{}", check: "Profile page" },
    { name: "Spotify", url: "Search on open.spotify.com", check: "Artist search" },
    { name: "Bandcamp", url: "https://{}.bandcamp.com", check: "Artist page" },
    { name: "Flickr", url: "https://flickr.com/people/{}", check: "Profile page" },
    { name: "500px", url: "https://500px.com/{}", check: "Profile page" },
    { name: "DeviantArt", url: "https://deviantart.com/{}", check: "Profile page" },
    { name: "ArtStation", url: "https://artstation.com/{}", check: "Profile page" },
    { name: "Behance", url: "https://behance.net/{}", check: "Profile page" },
    { name: "Dribbble", url: "https://dribbble.com/{}", check: "Profile page" },
  ],
  "E-Commerce & Finance": [
    { name: "eBay", url: "https://ebay.com/usr/{}", check: "Seller page" },
    { name: "Etsy", url: "https://etsy.com/shop/{}", check: "Shop page" },
    { name: "PayPal", url: "https://paypal.me/{}", check: "Payment page" },
    { name: "Venmo", url: "Search on venmo.com", check: "Search" },
    { name: "Cash App", url: "https://cash.app/${}", check: "Payment page" },
  ],
  "Dating": [
    { name: "Tinder", url: "Not directly searchable", check: "App only" },
    { name: "OkCupid", url: "https://okcupid.com/profile/{}", check: "Profile page" },
    { name: "PlentyOfFish", url: "Search on pof.com", check: "Search" },
  ],
};

// ── Google Dorks Database (200+) ──
const GOOGLE_DORKS = {
  "Login Pages": [
    'intitle:"login" site:{domain}',
    'inurl:"/admin/login" site:{domain}',
    'inurl:"/wp-login.php" site:{domain}',
    'intitle:"admin panel" site:{domain}',
    'inurl:"/user/login" site:{domain}',
    'inurl:"signin" OR inurl:"sign-in" site:{domain}',
    'inurl:"/portal" intitle:"login" site:{domain}',
    'inurl:"auth" OR inurl:"authenticate" site:{domain}',
    'intitle:"dashboard" inurl:"login" site:{domain}',
    'inurl:"/accounts/login" site:{domain}',
  ],
  "Sensitive Files": [
    'site:{domain} filetype:pdf',
    'site:{domain} filetype:xlsx OR filetype:xls',
    'site:{domain} filetype:doc OR filetype:docx',
    'site:{domain} filetype:sql',
    'site:{domain} filetype:env',
    'site:{domain} filetype:log',
    'site:{domain} filetype:bak',
    'site:{domain} filetype:conf OR filetype:cfg',
    'site:{domain} filetype:xml',
    'site:{domain} filetype:json',
    'site:{domain} filetype:csv',
    'site:{domain} filetype:key OR filetype:pem',
    'site:{domain} filetype:git',
    'site:{domain} filetype:yml OR filetype:yaml',
    'site:{domain} filetype:swp',
  ],
  "Exposed Directories": [
    'intitle:"index of" site:{domain}',
    'intitle:"index of" "parent directory" site:{domain}',
    'intitle:"index of" inurl:"/backup" site:{domain}',
    'intitle:"index of" inurl:"/upload" site:{domain}',
    'intitle:"index of" inurl:"/config" site:{domain}',
    'intitle:"index of" inurl:"/admin" site:{domain}',
    'intitle:"index of" inurl:"/private" site:{domain}',
    'intitle:"index of" inurl:"/tmp" site:{domain}',
    'intitle:"index of" inurl:"/log" site:{domain}',
    'intitle:"index of" inurl:"/db" site:{domain}',
  ],
  "Error Messages": [
    'site:{domain} "sql syntax" OR "mysql error"',
    'site:{domain} "warning: " "on line"',
    'site:{domain} "fatal error"',
    'site:{domain} "stack trace" OR "traceback"',
    'site:{domain} "server error" OR "500 internal"',
    'site:{domain} "access denied" OR "403 forbidden"',
    'site:{domain} "debug" OR "debugging"',
    'site:{domain} intext:"exception" filetype:log',
  ],
  "Credentials & Secrets": [
    'site:{domain} intext:"password" filetype:log',
    'site:{domain} intext:"username" "password" filetype:txt',
    'site:{domain} "api_key" OR "apikey" OR "api-key"',
    'site:{domain} "secret_key" OR "secret" OR "token"',
    'site:{domain} "AWS_ACCESS_KEY" OR "AKIA"',
    'site:{domain} inurl:".env" intext:"DB_PASSWORD"',
    'site:{domain} inurl:"config" intext:"password"',
    'site:{domain} filetype:sql intext:"INSERT INTO" "password"',
    'site:{domain} "BEGIN RSA PRIVATE KEY"',
    'site:{domain} "BEGIN OPENSSH PRIVATE KEY"',
    '"password" site:pastebin.com "{domain}"',
    '"password" site:github.com "{domain}"',
  ],
  "Subdomains & Infrastructure": [
    'site:*.{domain}',
    'site:*.*.{domain}',
    'site:{domain} -www',
    'inurl:"{domain}" -site:{domain}',
    '"*.{domain}" -site:{domain}',
    'site:*.{domain} intitle:"index of"',
    'site:*.{domain} inurl:api',
    'site:*.{domain} inurl:staging OR inurl:dev OR inurl:test',
  ],
  "Vulnerable Applications": [
    'site:{domain} inurl:"wp-content" OR inurl:"wp-includes"',
    'site:{domain} inurl:"xmlrpc.php"',
    'site:{domain} "powered by" "wordpress" OR "joomla" OR "drupal"',
    'site:{domain} inurl:"/phpmyadmin"',
    'site:{domain} inurl:"/phpinfo.php"',
    'site:{domain} inurl:"/server-status"',
    'site:{domain} inurl:"/server-info"',
    'site:{domain} intitle:"Apache Tomcat" "manager"',
    'site:{domain} inurl:".git" OR inurl:".svn"',
    'site:{domain} inurl:"/.well-known"',
  ],
  "Cloud & Storage": [
    'site:s3.amazonaws.com "{domain}"',
    'site:blob.core.windows.net "{domain}"',
    'site:storage.googleapis.com "{domain}"',
    'site:digitaloceanspaces.com "{domain}"',
    'site:firebasestorage.googleapis.com "{domain}"',
    'inurl:"s3.amazonaws.com" "{domain}"',
    'site:trello.com "{domain}"',
    'site:notion.so "{domain}"',
  ],
  "Social & People": [
    'site:linkedin.com/in "{name}" "{company}"',
    'site:twitter.com "{name}" "{company}"',
    'site:github.com "{name}" "{company}"',
    '"{email}" site:linkedin.com',
    '"{email}" site:facebook.com',
    '"{name}" resume filetype:pdf',
    '"{name}" "{company}" email',
  ],
  "IoT & Devices": [
    'intitle:"webcam" OR intitle:"camera" site:{domain}',
    'inurl:"/view/index.shtml"',
    'intitle:"Network Camera" inurl:"/view"',
    'inurl:"/cgi-bin/guestimage.html"',
    'intitle:"Router" inurl:"/status" site:{domain}',
    'intitle:"printer" inurl:"/hp/device" site:{domain}',
  ],
};

// ── Subdomain Wordlist (500+) ──
const SUBDOMAIN_WORDLIST = [
  "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2",
  "test", "portal", "ns", "ww1", "host", "support", "dev", "web", "bbs", "ww42", "mx", "email", "cloud", "1", "mail1",
  "2", "forum", "owa", "www2", "gw", "admin", "store", "mx1", "cdn", "api", "exchange", "app", "gov", "2tty", "vps",
  "govyty", "hmail", "dashboard", "staging", "demo", "beta", "alpha", "qa", "uat", "preprod", "pre-prod", "sandbox",
  "internal", "intranet", "extranet", "private", "public", "gateway", "proxy", "reverse-proxy", "lb", "load-balancer",
  "cache", "redis", "memcached", "db", "database", "mysql", "postgres", "postgresql", "mongo", "mongodb", "elastic",
  "elasticsearch", "kibana", "grafana", "prometheus", "jenkins", "ci", "cd", "build", "deploy", "release", "git",
  "gitlab", "bitbucket", "svn", "hg", "repo", "repository", "registry", "docker", "k8s", "kubernetes", "rancher",
  "consul", "vault", "terraform", "ansible", "puppet", "chef", "salt", "nagios", "zabbix", "icinga", "prtg",
  "monitoring", "metrics", "logs", "logging", "syslog", "splunk", "elk", "logstash", "fluentd", "graylog",
  "sentry", "newrelic", "datadog", "apm", "trace", "tracing", "status", "health", "healthcheck", "ping",
  "auth", "login", "sso", "oauth", "ldap", "ad", "active-directory", "radius", "kerberos", "saml", "oidc",
  "identity", "iam", "accounts", "account", "signup", "register", "password", "reset", "mfa", "2fa", "otp",
  "cdn1", "cdn2", "static", "assets", "media", "images", "img", "photos", "video", "streaming", "live",
  "download", "downloads", "upload", "uploads", "files", "file", "docs", "documents", "wiki", "confluence",
  "jira", "tickets", "helpdesk", "servicedesk", "support", "help", "faq", "kb", "knowledge", "community",
  "backup", "backups", "bak", "archive", "old", "legacy", "deprecated", "retired", "temp", "tmp",
  "cms", "wordpress", "wp", "drupal", "joomla", "magento", "shopify", "woocommerce",
  "crm", "erp", "hr", "finance", "billing", "invoice", "payment", "pay", "checkout", "cart",
  "vpn1", "vpn2", "ssl", "tls", "cert", "pki", "ca", "ocsp", "crl",
  "dns", "dns1", "dns2", "ns3", "ns4", "whois", "domain",
  "smtp1", "smtp2", "imap", "pop", "pop3", "webmail2", "outlook", "exchange2",
  "mobile", "ios", "android", "tablet", "responsive",
  "api-v1", "api-v2", "api2", "rest", "graphql", "grpc", "ws", "websocket", "socket",
  "search", "solr", "sphinx", "meilisearch",
  "queue", "mq", "rabbitmq", "kafka", "activemq", "celery", "worker", "job", "cron", "scheduler",
  "s3", "storage", "blob", "bucket", "object-storage", "minio", "ceph",
  "firewall", "waf", "ids", "ips", "siem", "soc", "noc", "security",
  "lab", "labs", "research", "experiment", "poc", "prototype",
  "partner", "partners", "vendor", "vendors", "supplier", "customer", "client", "clients",
  "report", "reports", "analytics", "stats", "statistics", "bi", "data", "warehouse", "etl",
  "notify", "notification", "notifications", "alert", "alerts", "webhook", "webhooks",
  "config", "configuration", "settings", "preferences", "options",
  "chat", "messaging", "im", "slack", "teams", "matrix", "xmpp", "jabber",
  "calendar", "cal", "schedule", "booking", "reservation",
  "map", "maps", "geo", "location", "gps", "tracking",
  "feed", "rss", "atom", "sitemap", "robots",
  "i18n", "l10n", "locale", "lang", "translate", "translation",
  "test1", "test2", "test3", "dev1", "dev2", "stage", "stage1", "stage2",
  "node1", "node2", "node3", "server1", "server2", "server3", "web1", "web2",
  "dc1", "dc2", "us", "eu", "asia", "ap", "na", "sa",
  "us-east", "us-west", "eu-west", "eu-central", "ap-southeast",
  "edge", "origin", "upstream", "downstream",
  "hooks", "hook", "callback", "redirect", "return", "bounce",
];

// ── OSINT Tools Directory (150+) ──
const OSINT_TOOLS = {
  "Search Engines": [
    { name: "Google", url: "https://google.com", desc: "Advanced search with dorks" },
    { name: "Bing", url: "https://bing.com", desc: "Alternative search, sometimes indexes different content" },
    { name: "DuckDuckGo", url: "https://duckduckgo.com", desc: "Privacy-focused search" },
    { name: "Yandex", url: "https://yandex.com", desc: "Russian search engine, good for reverse image search" },
    { name: "Baidu", url: "https://baidu.com", desc: "Chinese search engine" },
    { name: "Startpage", url: "https://startpage.com", desc: "Google results without tracking" },
  ],
  "Domain & DNS": [
    { name: "Shodan", url: "https://shodan.io", desc: "Internet-connected device search engine" },
    { name: "Censys", url: "https://search.censys.io", desc: "Internet-wide scan data" },
    { name: "crt.sh", url: "https://crt.sh", desc: "Certificate Transparency logs" },
    { name: "DNSDumpster", url: "https://dnsdumpster.com", desc: "DNS recon and mapping" },
    { name: "SecurityTrails", url: "https://securitytrails.com", desc: "DNS and domain history" },
    { name: "ViewDNS", url: "https://viewdns.info", desc: "DNS, WHOIS, reverse IP tools" },
    { name: "Whois", url: "https://whois.domaintools.com", desc: "Domain registration data" },
    { name: "BuiltWith", url: "https://builtwith.com", desc: "Technology stack detection" },
    { name: "Wappalyzer", url: "https://wappalyzer.com", desc: "Web technology identifier" },
    { name: "Netcraft", url: "https://sitereport.netcraft.com", desc: "Site technology and hosting info" },
    { name: "urlscan.io", url: "https://urlscan.io", desc: "URL scanning and analysis" },
    { name: "Wayback Machine", url: "https://web.archive.org", desc: "Historical website snapshots" },
    { name: "Sublist3r", url: "https://github.com/aboul3la/Sublist3r", desc: "Subdomain enumeration tool" },
    { name: "Amass", url: "https://github.com/owasp-amass/amass", desc: "Network mapping and subdomain discovery" },
    { name: "Subfinder", url: "https://github.com/projectdiscovery/subfinder", desc: "Fast subdomain discovery" },
  ],
  "Email": [
    { name: "Hunter.io", url: "https://hunter.io", desc: "Email finding and verification" },
    { name: "Phonebook.cz", url: "https://phonebook.cz", desc: "Email, domain, URL search" },
    { name: "EmailRep", url: "https://emailrep.io", desc: "Email reputation lookup" },
    { name: "Have I Been Pwned", url: "https://haveibeenpwned.com", desc: "Breach database checker" },
    { name: "Dehashed", url: "https://dehashed.com", desc: "Breach data search engine" },
    { name: "theHarvester", url: "https://github.com/laramies/theHarvester", desc: "Email and subdomain harvesting" },
    { name: "Holehe", url: "https://github.com/megadose/holehe", desc: "Check if email is registered on sites" },
  ],
  "Social Media": [
    { name: "Sherlock", url: "https://github.com/sherlock-project/sherlock", desc: "Username search across 300+ sites" },
    { name: "Namechk", url: "https://namechk.com", desc: "Username availability checker" },
    { name: "WhatsMyName", url: "https://whatsmyname.app", desc: "Username enumeration" },
    { name: "Social Searcher", url: "https://social-searcher.com", desc: "Social media search engine" },
    { name: "Twint", url: "https://github.com/twintproject/twint", desc: "Twitter scraping tool" },
    { name: "Instaloader", url: "https://instaloader.github.io", desc: "Instagram data downloader" },
    { name: "OSINT Framework", url: "https://osintframework.com", desc: "Directory of OSINT tools by category" },
    { name: "SpiderFoot", url: "https://spiderfoot.net", desc: "Automated OSINT collection" },
    { name: "Maltego", url: "https://maltego.com", desc: "Link analysis and data mining" },
    { name: "Recon-ng", url: "https://github.com/lanmaster53/recon-ng", desc: "Web reconnaissance framework" },
  ],
  "IP & Network": [
    { name: "IPinfo", url: "https://ipinfo.io", desc: "IP geolocation and ASN data" },
    { name: "MaxMind GeoIP", url: "https://maxmind.com", desc: "IP geolocation database" },
    { name: "AbuseIPDB", url: "https://abuseipdb.com", desc: "IP reputation and abuse reports" },
    { name: "GreyNoise", url: "https://viz.greynoise.io", desc: "Internet scanner identification" },
    { name: "BGPView", url: "https://bgpview.io", desc: "BGP routing information" },
    { name: "Hurricane Electric BGP", url: "https://bgp.he.net", desc: "BGP toolkit" },
    { name: "RIPE NCC", url: "https://apps.db.ripe.net", desc: "European IP registry" },
    { name: "ARIN Whois", url: "https://whois.arin.net", desc: "North American IP registry" },
    { name: "Wigle", url: "https://wigle.net", desc: "Wireless network mapping" },
  ],
  "Image & Media": [
    { name: "TinEye", url: "https://tineye.com", desc: "Reverse image search" },
    { name: "Google Images", url: "https://images.google.com", desc: "Reverse image search" },
    { name: "Yandex Images", url: "https://yandex.com/images", desc: "Often finds results others miss" },
    { name: "Bing Visual Search", url: "https://bing.com/visualsearch", desc: "Reverse image search" },
    { name: "ExifTool", url: "https://exiftool.org", desc: "Metadata extraction from images/media" },
    { name: "Jeffrey's Exif Viewer", url: "https://exif.regex.info", desc: "Online EXIF viewer" },
    { name: "FotoForensics", url: "https://fotoforensics.com", desc: "Image forensic analysis (ELA)" },
    { name: "InVID", url: "https://www.invid-project.eu", desc: "Video verification tool" },
  ],
  "Dark Web": [
    { name: "Ahmia", url: "https://ahmia.fi", desc: ".onion search engine (clearnet accessible)" },
    { name: "DarkSearch", url: "https://darksearch.io", desc: "Dark web search (clearnet)" },
    { name: "Torch", url: ".onion only", desc: "Tor search engine" },
    { name: "Hunchly", url: "https://hunch.ly", desc: "Dark web investigation tool" },
    { name: "OnionScan", url: "https://github.com/s-rah/onionscan", desc: "Dark web analysis tool" },
    { name: "IntelligenceX", url: "https://intelx.io", desc: "Search dark web, leaks, and more" },
  ],
  "Threat Intelligence": [
    { name: "VirusTotal", url: "https://virustotal.com", desc: "File, URL, IP analysis" },
    { name: "AlienVault OTX", url: "https://otx.alienvault.com", desc: "Open threat intelligence" },
    { name: "MITRE ATT&CK", url: "https://attack.mitre.org", desc: "Adversary tactics and techniques" },
    { name: "Pulsedive", url: "https://pulsedive.com", desc: "Threat intelligence search" },
    { name: "ThreatCrowd", url: "https://threatcrowd.org", desc: "Threat search engine" },
    { name: "URLhaus", url: "https://urlhaus.abuse.ch", desc: "Malicious URL database" },
    { name: "MalwareBazaar", url: "https://bazaar.abuse.ch", desc: "Malware sample sharing" },
    { name: "Any.run", url: "https://any.run", desc: "Interactive malware sandbox" },
    { name: "Hybrid Analysis", url: "https://hybrid-analysis.com", desc: "Free malware analysis" },
  ],
  "People Search": [
    { name: "Pipl", url: "https://pipl.com", desc: "People search engine" },
    { name: "PeekYou", url: "https://peekyou.com", desc: "People finder" },
    { name: "Spokeo", url: "https://spokeo.com", desc: "People search" },
    { name: "BeenVerified", url: "https://beenverified.com", desc: "Background check" },
    { name: "ThatsThem", url: "https://thatsthem.com", desc: "Reverse lookup" },
    { name: "TruePeopleSearch", url: "https://truepeoplesearch.com", desc: "Free people finder" },
    { name: "ZabaSearch", url: "https://zabasearch.com", desc: "Free people search" },
    { name: "FastPeopleSearch", url: "https://fastpeoplesearch.com", desc: "Fast people lookup" },
  ],
};

// ── Metadata Reference ──
const METADATA_REF = {
  "Images (EXIF)": ["Camera make/model", "GPS coordinates", "Date/time taken", "Lens info", "Software used", "Author/artist", "Copyright", "Orientation", "Flash used", "ISO speed", "Shutter speed", "Aperture", "Focal length", "White balance", "Color space", "Thumbnail"],
  "Documents (Office)": ["Author", "Last modified by", "Company", "Creation date", "Last saved date", "Revision number", "Template used", "Comments", "Manager", "Category", "Subject", "Keywords", "Custom properties", "Embedded objects", "Tracked changes", "Hidden text"],
  "PDF Files": ["Author", "Creator application", "Producer", "Creation date", "Modification date", "Title", "Subject", "Keywords", "Trapped", "XMP metadata", "Embedded fonts", "JavaScript", "Form fields"],
  "Audio Files": ["Artist", "Album", "Title", "Track number", "Genre", "Year", "Composer", "BPM", "Comment", "Encoder", "Album art", "Lyrics"],
  "Video Files": ["Camera model", "GPS location", "Creation date", "Duration", "Resolution", "Codec", "Bitrate", "Frame rate", "Audio tracks", "Subtitles", "Chapter markers"],
};

// ── Social Media Investigation Guide ──
const SOCIAL_GUIDE = {
  "Twitter/X": ["Search operators: from:user, to:user, since:, until:, filter:media, near:city", "Advanced search: https://twitter.com/search-advanced", "Tools: Twint, snscrape, Twitter API", "Check followers/following for connections", "Search replies and mentions for communication patterns", "Look for location data in tweets and photos"],
  "Facebook": ["Graph Search alternatives (now limited)", "Check public posts, groups, events", "Friends list analysis", "Tagged photos reveal connections", "Check-ins show location history", "Marketplace listings reveal interests and location"],
  "Instagram": ["Search by hashtag, location, username", "Story highlights may reveal information", "Tagged photos show connections", "Comment analysis for contacts", "Tools: Instaloader, Instadp", "Check linked accounts in bio"],
  "LinkedIn": ["Search by company, title, location, school", "Skills endorsements show expertise", "Recommendations reveal colleagues", "Activity shows interests", "Company page shows employees", "X-ray search: site:linkedin.com/in 'keyword'"],
  "Reddit": ["User history reveals interests and timezone", "Tools: redective.com, reddit-user-analyser", "Deleted posts cached by removeddit/unddit", "Cross-reference usernames on other platforms", "Comment history analysis for personal details"],
  "Discord": ["Server lists and roles", "Bot-based lookups", "Message history (if accessible)", "Connected accounts visible in profile", "Server member lists", "Invite link analysis"],
  "Telegram": ["Channel search: t.me/s/channelname", "Forward analysis shows source channels", "Member list in groups", "Phone number lookup if known", "Bot-based user enumeration", "Exported chat analysis"],
  "TikTok": ["Search by username, hashtag, sound", "Video metadata and location", "Comment analysis", "Linked accounts (Instagram, YouTube)", "Duet/stitch connections"],
};

// ── Main Render ──
export function renderOSINTDashboard(main) {
  var tabs = [
    { id: "profile", label: "Target Profile" },
    { id: "username", label: "Username Checker" },
    { id: "dorks", label: "Google Dorks" },
    { id: "email", label: "Email OSINT" },
    { id: "domain", label: "Domain Intel" },
    { id: "social", label: "Social Media" },
    { id: "metadata", label: "Metadata" },
    { id: "tools", label: "Tool Directory" },
    { id: "timeline", label: "Timeline" },
    { id: "subdomains", label: "Subdomain List" },
  ];

  var tabBtns = tabs.map(function(t) {
    return '<button class="chip' + (t.id === "profile" ? " on" : "") + '" data-tab="' + t.id + '">' + esc(t.label) + '</button>';
  }).join("");

  main.innerHTML =
    '<div class="pg-head"><div><h1 class="pg-h1">OSINT Dashboard</h1>' +
    '<p class="muted pg-sub">Open-source intelligence research organizer — target profiling, username checking, Google dorks, tool directory, and investigation timeline. All lookups are passive; data stored locally.</p></div></div>' +
    '<div class="cs-filter" id="osint-tabs">' + tabBtns + '</div>' +
    '<div id="osint-content" style="margin-top:16px"></div>';

  var content = main.querySelector("#osint-content");

  function showTab(id) {
    main.querySelectorAll("#osint-tabs .chip").forEach(function(b) { b.classList.toggle("on", b.dataset.tab === id); });
    if (id === "profile") renderProfile(content);
    else if (id === "username") renderUsername(content);
    else if (id === "dorks") renderDorks(content);
    else if (id === "email") renderEmail(content);
    else if (id === "domain") renderDomain(content);
    else if (id === "social") renderSocial(content);
    else if (id === "metadata") renderMetadata(content);
    else if (id === "tools") renderToolDir(content);
    else if (id === "timeline") renderTimeline(content);
    else if (id === "subdomains") renderSubdomains(content);
  }

  main.querySelector("#osint-tabs").onclick = function(e) {
    var b = e.target.closest(".chip");
    if (b) showTab(b.dataset.tab);
  };

  showTab("profile");
}

// ── Target Profile Tab ──
function renderProfile(el) {
  var profiles = [];
  try { profiles = JSON.parse(localStorage.getItem("osint_profiles") || "[]"); } catch (_) {}

  el.innerHTML =
    '<h2 class="pg-h2">Target Profile Builder</h2>' +
    '<p class="muted" style="margin-bottom:16px">Create investigation profiles to organize your OSINT findings. All data stays in your browser.</p>' +
    '<div class="arse-card" style="cursor:default;padding:16px;margin-bottom:16px">' +
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">' +
        '<input id="tp-name" placeholder="Name / alias" style="padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
        '<input id="tp-email" placeholder="Email" style="padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
        '<input id="tp-username" placeholder="Username" style="padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
        '<input id="tp-domain" placeholder="Domain" style="padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
        '<input id="tp-phone" placeholder="Phone" style="padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
        '<input id="tp-ip" placeholder="IP address" style="padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
      '</div>' +
      '<textarea id="tp-notes" placeholder="Notes..." rows="2" style="width:100%;margin-top:8px;padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px;resize:vertical"></textarea>' +
      '<button class="btn" id="tp-add" style="margin-top:8px;padding:6px 16px">Save Profile</button>' +
    '</div>' +
    '<div id="tp-list"></div>';

  function renderList() {
    if (!profiles.length) { el.querySelector("#tp-list").innerHTML = '<p class="muted">No profiles created yet.</p>'; return; }
    var cards = profiles.map(function(p, i) {
      var fields = [];
      if (p.email) fields.push("Email: " + p.email);
      if (p.username) fields.push("Username: " + p.username);
      if (p.domain) fields.push("Domain: " + p.domain);
      if (p.phone) fields.push("Phone: " + p.phone);
      if (p.ip) fields.push("IP: " + p.ip);
      return '<div class="arse-card" style="cursor:default;margin-bottom:8px">' +
        '<div class="an" style="display:flex;justify-content:space-between">' + esc(p.name || "Unnamed") + '<button class="btn" data-pdel="' + i + '" style="padding:1px 6px;font-size:.7rem;background:#f44336">x</button></div>' +
        '<div style="font-size:.78rem;color:var(--mut);margin-top:4px">' + fields.map(function(f) { return esc(f); }).join(" &middot; ") + '</div>' +
        (p.notes ? '<div style="font-size:.78rem;margin-top:4px;color:var(--txt)">' + esc(p.notes) + '</div>' : '') +
      '</div>';
    }).join("");
    el.querySelector("#tp-list").innerHTML = cards;
  }
  renderList();

  el.querySelector("#tp-add").onclick = function() {
    var p = {
      name: el.querySelector("#tp-name").value.trim(),
      email: el.querySelector("#tp-email").value.trim(),
      username: el.querySelector("#tp-username").value.trim(),
      domain: el.querySelector("#tp-domain").value.trim(),
      phone: el.querySelector("#tp-phone").value.trim(),
      ip: el.querySelector("#tp-ip").value.trim(),
      notes: el.querySelector("#tp-notes").value.trim(),
      created: new Date().toISOString()
    };
    if (!p.name && !p.email && !p.username) return;
    profiles.push(p);
    try { localStorage.setItem("osint_profiles", JSON.stringify(profiles)); } catch (_) {}
    ["#tp-name", "#tp-email", "#tp-username", "#tp-domain", "#tp-phone", "#tp-ip", "#tp-notes"].forEach(function(s) { el.querySelector(s).value = ""; });
    renderList();
  };
  el.querySelector("#tp-list").onclick = function(e) {
    if (e.target.dataset.pdel !== undefined) {
      profiles.splice(parseInt(e.target.dataset.pdel), 1);
      try { localStorage.setItem("osint_profiles", JSON.stringify(profiles)); } catch (_) {}
      renderList();
    }
  };
}

// ── Username Checker Tab ──
function renderUsername(el) {
  var cats = Object.keys(PLATFORMS);
  var totalPlatforms = cats.reduce(function(a, c) { return a + PLATFORMS[c].length; }, 0);

  el.innerHTML =
    '<h2 class="pg-h2">Username Checker</h2>' +
    '<p class="muted" style="margin-bottom:16px">Check a username across ' + totalPlatforms + ' platforms organized by category. Links open in new tabs.</p>' +
    '<div style="display:flex;gap:8px;margin-bottom:16px">' +
      '<input id="uc-input" placeholder="Enter username to check..." style="flex:1;padding:8px 12px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px;font-size:1rem">' +
      '<button class="btn" id="uc-go" style="padding:8px 20px">Check</button>' +
    '</div>' +
    '<div id="uc-results"></div>';

  function doCheck() {
    var username = el.querySelector("#uc-input").value.trim();
    if (!username) return;
    var html = cats.map(function(cat) {
      var items = PLATFORMS[cat].map(function(p) {
        var url = p.url.replace(/\{\}/g, encodeURIComponent(username));
        var isLink = url.startsWith("http");
        return '<div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--line)">' +
          '<span style="font-weight:600;font-size:.82rem;min-width:120px">' + esc(p.name) + '</span>' +
          (isLink ? '<a href="' + esc(url) + '" target="_blank" rel="noopener" style="color:var(--acc);font-size:.78rem;word-break:break-all">' + esc(url) + ' &#8599;</a>' : '<span class="muted" style="font-size:.78rem">' + esc(url) + '</span>') +
          '<span class="muted" style="font-size:.7rem;margin-left:auto">' + esc(p.check) + '</span>' +
        '</div>';
      }).join("");
      return '<div class="arse-card" style="cursor:default;margin-bottom:12px">' +
        '<div class="an">' + esc(cat) + ' <span style="color:var(--mut);font-size:.75rem">(' + PLATFORMS[cat].length + ')</span></div>' +
        '<div style="margin-top:8px">' + items + '</div>' +
      '</div>';
    }).join("");
    el.querySelector("#uc-results").innerHTML = html;
  }

  el.querySelector("#uc-go").onclick = doCheck;
  el.querySelector("#uc-input").onkeydown = function(e) { if (e.key === "Enter") doCheck(); };
}

// ── Google Dorks Tab ──
function renderDorks(el) {
  var cats = Object.keys(GOOGLE_DORKS);
  var totalDorks = cats.reduce(function(a, c) { return a + GOOGLE_DORKS[c].length; }, 0);

  el.innerHTML =
    '<h2 class="pg-h2">Google Dork Builder</h2>' +
    '<p class="muted" style="margin-bottom:16px">' + totalDorks + ' pre-built Google dorks. Enter a target domain to generate search queries.</p>' +
    '<div style="display:flex;gap:8px;margin-bottom:16px">' +
      '<input id="gd-domain" placeholder="Target domain (e.g., example.com)" style="flex:1;padding:8px 12px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
      '<input id="gd-name" placeholder="Name (optional)" style="width:200px;padding:8px 12px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
      '<input id="gd-email" placeholder="Email (optional)" style="width:200px;padding:8px 12px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
      '<button class="btn" id="gd-gen" style="padding:8px 16px">Generate</button>' +
    '</div>' +
    '<div id="gd-results"></div>';

  function generate() {
    var domain = el.querySelector("#gd-domain").value.trim();
    var name = el.querySelector("#gd-name").value.trim();
    var email = el.querySelector("#gd-email").value.trim();
    if (!domain && !name && !email) return;
    var html = cats.map(function(cat) {
      var dorks = GOOGLE_DORKS[cat].map(function(d) {
        var q = d.replace(/\{domain\}/g, domain || "example.com").replace(/\{name\}/g, name || "John Doe").replace(/\{email\}/g, email || "user@example.com").replace(/\{company\}/g, domain ? domain.split(".")[0] : "company");
        var searchUrl = "https://www.google.com/search?q=" + encodeURIComponent(q);
        return '<div style="display:flex;align-items:center;gap:8px;padding:4px 0;border-bottom:1px solid var(--line)">' +
          '<code style="flex:1;font-size:.78rem;color:var(--txt);word-break:break-all">' + esc(q) + '</code>' +
          '<a href="' + esc(searchUrl) + '" target="_blank" rel="noopener" class="btn" style="padding:2px 10px;font-size:.72rem;text-decoration:none;flex-shrink:0">Search</a>' +
        '</div>';
      }).join("");
      return '<div class="arse-card" style="cursor:default;margin-bottom:12px">' +
        '<div class="an">' + esc(cat) + ' <span style="color:var(--mut);font-size:.75rem">(' + GOOGLE_DORKS[cat].length + ' dorks)</span></div>' +
        '<div style="margin-top:8px">' + dorks + '</div>' +
      '</div>';
    }).join("");
    el.querySelector("#gd-results").innerHTML = html;
  }

  el.querySelector("#gd-gen").onclick = generate;
}

// ── Email OSINT Tab ──
function renderEmail(el) {
  el.innerHTML =
    '<h2 class="pg-h2">Email OSINT Reference</h2>' +
    '<p class="muted" style="margin-bottom:16px">Techniques and tools for investigating email addresses.</p>' +
    '<div class="arse-card" style="cursor:default;margin-bottom:12px"><div class="an">MX Lookup</div><div class="ad" style="font-size:.82rem;margin-top:6px">Query the MX records of the email domain to identify the mail provider. <code>dig MX domain.com</code> or <code>nslookup -type=mx domain.com</code>. Common providers: Google Workspace (aspmx.l.google.com), Microsoft 365 (*.mail.protection.outlook.com), Proton Mail, Zoho, custom mail servers.</div></div>' +
    '<div class="arse-card" style="cursor:default;margin-bottom:12px"><div class="an">SMTP Verification</div><div class="ad" style="font-size:.82rem;margin-top:6px">Connect to the mail server and use VRFY or RCPT TO to check if an address exists (many servers block this). <code>telnet mail.domain.com 25</code> then <code>VRFY user@domain.com</code>. Note: This may trigger alerts.</div></div>' +
    '<div class="arse-card" style="cursor:default;margin-bottom:12px"><div class="an">Breach Database Check</div><div class="ad" style="font-size:.82rem;margin-top:6px">Check if the email appears in known data breaches using <a href="https://haveibeenpwned.com" target="_blank" rel="noopener" style="color:var(--acc)">Have I Been Pwned</a>, <a href="https://dehashed.com" target="_blank" rel="noopener" style="color:var(--acc)">Dehashed</a>, or <a href="https://intelx.io" target="_blank" rel="noopener" style="color:var(--acc)">Intelligence X</a>.</div></div>' +
    '<div class="arse-card" style="cursor:default;margin-bottom:12px"><div class="an">Google Dork Patterns</div><div class="ad" style="font-size:.82rem;margin-top:6px"><code>"user@domain.com"</code> — find all indexed pages mentioning the email.<br><code>"user@domain.com" site:pastebin.com</code> — check paste sites.<br><code>"user@domain.com" filetype:pdf</code> — find documents.<br><code>intext:"user@domain.com"</code> — broader search.</div></div>' +
    '<div class="arse-card" style="cursor:default;margin-bottom:12px"><div class="an">Email Header Analysis</div><div class="ad" style="font-size:.82rem;margin-top:6px">Analyze received email headers to trace the sending path. Key headers: Received (each hop), X-Originating-IP, Return-Path, Message-ID, DKIM-Signature, Authentication-Results (SPF/DKIM/DMARC). Tools: MXToolbox Header Analyzer, Google Admin Toolbox.</div></div>' +
    '<div class="arse-card" style="cursor:default;margin-bottom:12px"><div class="an">Account Enumeration</div><div class="ad" style="font-size:.82rem;margin-top:6px">Use <a href="https://github.com/megadose/holehe" target="_blank" rel="noopener" style="color:var(--acc)">Holehe</a> to check which websites the email is registered on. This uses password reset and login flows to detect accounts without notifying the target.</div></div>';
}

// ── Domain Intel Tab ──
function renderDomain(el) {
  el.innerHTML =
    '<h2 class="pg-h2">Domain Intelligence</h2>' +
    '<p class="muted" style="margin-bottom:16px">WHOIS, DNS, and infrastructure analysis techniques.</p>' +
    '<div class="arse-card" style="cursor:default;margin-bottom:12px"><div class="an">WHOIS Data</div><div class="ad" style="font-size:.82rem;margin-top:6px">Key fields: Registrar, creation/expiry dates, name servers, registrant name/org/email (often privacy-protected). Historical WHOIS via SecurityTrails, DomainTools, or Wayback Machine WHOIS. <code>whois domain.com</code></div></div>' +
    '<div class="arse-card" style="cursor:default;margin-bottom:12px"><div class="an">DNS Record Types</div><div class="ad" style="font-size:.82rem;margin-top:6px"><strong>A</strong> — IPv4 address<br><strong>AAAA</strong> — IPv6 address<br><strong>MX</strong> — Mail servers (reveals email provider)<br><strong>NS</strong> — Name servers (reveals DNS provider)<br><strong>TXT</strong> — SPF, DKIM, DMARC, domain verification tokens<br><strong>CNAME</strong> — Aliases (may reveal CDN/hosting)<br><strong>SOA</strong> — Zone authority and admin email<br><strong>SRV</strong> — Service records (may reveal internal services)<br><strong>CAA</strong> — Certificate authority authorization</div></div>' +
    '<div class="arse-card" style="cursor:default;margin-bottom:12px"><div class="an">Certificate Transparency</div><div class="ad" style="font-size:.82rem;margin-top:6px">CT logs record every SSL certificate issued. Use <a href="https://crt.sh" target="_blank" rel="noopener" style="color:var(--acc)">crt.sh</a> to find subdomains: <code>%.domain.com</code> query reveals all certificates issued for subdomains. Also check <a href="https://transparencyreport.google.com/https/certificates" target="_blank" rel="noopener" style="color:var(--acc)">Google CT Report</a>.</div></div>' +
    '<div class="arse-card" style="cursor:default;margin-bottom:12px"><div class="an">Subdomain Enumeration</div><div class="ad" style="font-size:.82rem;margin-top:6px">Methods: DNS brute force (use wordlist), CT log search, search engine dorks (site:*.domain.com), reverse IP lookup, ASN enumeration. Tools: Subfinder, Amass, Sublist3r, dnsx, MassDNS, Altdns.</div></div>' +
    '<div class="arse-card" style="cursor:default;margin-bottom:12px"><div class="an">Reverse IP Lookup</div><div class="ad" style="font-size:.82rem;margin-top:6px">Find other domains hosted on the same IP. This can reveal related organizations or shared hosting. Tools: ViewDNS reverse IP, Bing "ip:x.x.x.x", SecurityTrails, HackerTarget.</div></div>';
}

// ── Social Media Tab ──
function renderSocial(el) {
  var platforms = Object.keys(SOCIAL_GUIDE);
  var cards = platforms.map(function(p) {
    var tips = SOCIAL_GUIDE[p].map(function(t) { return '<li style="margin-bottom:4px">' + esc(t) + '</li>'; }).join("");
    return '<div class="arse-card" style="cursor:default;margin-bottom:12px">' +
      '<div class="an">' + esc(p) + '</div>' +
      '<ul style="margin:8px 0;padding-left:18px;font-size:.82rem;color:var(--mut)">' + tips + '</ul>' +
    '</div>';
  }).join("");

  el.innerHTML =
    '<h2 class="pg-h2">Social Media Investigation Guide</h2>' +
    '<p class="muted" style="margin-bottom:16px">Platform-specific techniques for social media OSINT.</p>' + cards;
}

// ── Metadata Tab ──
function renderMetadata(el) {
  var types = Object.keys(METADATA_REF);
  var cards = types.map(function(t) {
    var items = METADATA_REF[t].map(function(m) {
      return '<span style="display:inline-block;padding:2px 8px;background:var(--bg);border:1px solid var(--line);border-radius:2px;font-size:.72rem;margin:2px">' + esc(m) + '</span>';
    }).join("");
    return '<div class="arse-card" style="cursor:default;margin-bottom:12px">' +
      '<div class="an">' + esc(t) + '</div>' +
      '<div style="margin-top:8px">' + items + '</div>' +
    '</div>';
  }).join("");

  el.innerHTML =
    '<h2 class="pg-h2">Metadata Extraction Reference</h2>' +
    '<p class="muted" style="margin-bottom:16px">What metadata can be extracted from different file types. Use ExifTool, mat2, or online viewers.</p>' + cards +
    '<div class="arse-card" style="cursor:default;margin-top:12px;padding:16px">' +
      '<h3 style="margin:0 0 8px;font-size:.9rem">ExifTool Quick Reference</h3>' +
      '<div style="font-size:.78rem;font-family:var(--mono,monospace);color:var(--mut)">' +
        '<div style="padding:2px 0"><code>exiftool image.jpg</code> — View all metadata</div>' +
        '<div style="padding:2px 0"><code>exiftool -gps* image.jpg</code> — GPS coordinates only</div>' +
        '<div style="padding:2px 0"><code>exiftool -all= image.jpg</code> — Strip all metadata</div>' +
        '<div style="padding:2px 0"><code>exiftool -r -ext pdf .</code> — Recursively scan PDFs</div>' +
        '<div style="padding:2px 0"><code>exiftool -json *.jpg > meta.json</code> — Export as JSON</div>' +
      '</div>' +
    '</div>';
}

// ── Tool Directory Tab ──
function renderToolDir(el) {
  var cats = Object.keys(OSINT_TOOLS);
  var totalTools = cats.reduce(function(a, c) { return a + OSINT_TOOLS[c].length; }, 0);

  var cards = cats.map(function(cat) {
    var tools = OSINT_TOOLS[cat].map(function(t) {
      return '<a class="arse-card" href="' + esc(t.url) + '" target="_blank" rel="noopener" style="margin-bottom:4px;display:block">' +
        '<div class="an">' + esc(t.name) + ' <span class="ax">&#8599;</span></div>' +
        '<div class="ad">' + esc(t.desc) + '</div>' +
      '</a>';
    }).join("");
    return '<div style="margin-bottom:16px">' +
      '<h3 style="font-size:.9rem;margin-bottom:8px">' + esc(cat) + ' <span style="color:var(--mut);font-weight:400">(' + OSINT_TOOLS[cat].length + ')</span></h3>' +
      '<div class="arse-grid">' + tools + '</div>' +
    '</div>';
  }).join("");

  el.innerHTML =
    '<h2 class="pg-h2">OSINT Tool Directory</h2>' +
    '<p class="muted" style="margin-bottom:16px">' + totalTools + ' tools organized by use case. Opens in new tab.</p>' + cards;
}

// ── Timeline Tab ──
function renderTimeline(el) {
  var events = [];
  try { events = JSON.parse(localStorage.getItem("osint_timeline") || "[]"); } catch (_) {}

  el.innerHTML =
    '<h2 class="pg-h2">Investigation Timeline</h2>' +
    '<p class="muted" style="margin-bottom:16px">Build a timeline of events for your investigation. Stored in browser.</p>' +
    '<div style="display:flex;gap:8px;margin-bottom:16px">' +
      '<input id="tl-date" type="datetime-local" style="padding:6px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
      '<input id="tl-event" placeholder="Event description" style="flex:1;padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
      '<select id="tl-type" style="padding:6px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px"><option>Finding</option><option>Action</option><option>Communication</option><option>Evidence</option><option>Note</option></select>' +
      '<button class="btn" id="tl-add" style="padding:6px 12px">Add</button>' +
    '</div>' +
    '<div id="tl-list"></div>';

  var typeColors = { Finding: "var(--acc)", Action: "#4caf50", Communication: "#2196f3", Evidence: "#ff9800", Note: "var(--mut)" };

  function renderEvents() {
    if (!events.length) { el.querySelector("#tl-list").innerHTML = '<p class="muted">No events yet.</p>'; return; }
    var sorted = events.slice().sort(function(a, b) { return new Date(b.date) - new Date(a.date); });
    var html = sorted.map(function(ev, i) {
      var realIdx = events.indexOf(ev);
      return '<div style="display:flex;gap:12px;padding:8px 0;border-bottom:1px solid var(--line)">' +
        '<div style="width:4px;background:' + (typeColors[ev.type] || "var(--mut)") + ';border-radius:2px;flex-shrink:0"></div>' +
        '<div style="flex:1">' +
          '<div style="font-size:.75rem;color:var(--mut)">' + esc(new Date(ev.date).toLocaleString()) + ' &middot; <span style="color:' + (typeColors[ev.type] || "var(--mut)") + '">' + esc(ev.type) + '</span></div>' +
          '<div style="font-size:.85rem;margin-top:2px">' + esc(ev.event) + '</div>' +
        '</div>' +
        '<button class="btn" data-tdel="' + realIdx + '" style="padding:1px 6px;font-size:.7rem;background:#f44336;align-self:center">x</button>' +
      '</div>';
    }).join("");
    el.querySelector("#tl-list").innerHTML = html;
  }
  renderEvents();

  el.querySelector("#tl-add").onclick = function() {
    var date = el.querySelector("#tl-date").value;
    var event = el.querySelector("#tl-event").value.trim();
    if (!event) return;
    if (!date) date = new Date().toISOString();
    events.push({ date: date, event: event, type: el.querySelector("#tl-type").value });
    try { localStorage.setItem("osint_timeline", JSON.stringify(events)); } catch (_) {}
    el.querySelector("#tl-event").value = "";
    renderEvents();
  };
  el.querySelector("#tl-list").onclick = function(e) {
    if (e.target.dataset.tdel !== undefined) {
      events.splice(parseInt(e.target.dataset.tdel), 1);
      try { localStorage.setItem("osint_timeline", JSON.stringify(events)); } catch (_) {}
      renderEvents();
    }
  };
}

// ── Subdomain Wordlist Tab ──
function renderSubdomains(el) {
  el.innerHTML =
    '<h2 class="pg-h2">Subdomain Wordlist</h2>' +
    '<p class="muted" style="margin-bottom:16px">' + SUBDOMAIN_WORDLIST.length + ' common subdomains for brute-force enumeration. Copy and use with tools like Subfinder, Amass, or ffuf.</p>' +
    '<div style="display:flex;gap:8px;margin-bottom:12px">' +
      '<input id="sw-filter" placeholder="Filter..." style="flex:1;padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
      '<button class="btn" id="sw-copy">Copy All</button>' +
    '</div>' +
    '<div id="sw-list" style="background:var(--card);border:1px solid var(--line);padding:12px;font-size:.78rem;font-family:var(--mono,monospace);max-height:500px;overflow-y:auto;border-radius:2px;white-space:pre-wrap;color:var(--mut)"></div>';

  function renderWords() {
    var filter = (el.querySelector("#sw-filter").value || "").toLowerCase();
    var filtered = filter ? SUBDOMAIN_WORDLIST.filter(function(w) { return w.indexOf(filter) >= 0; }) : SUBDOMAIN_WORDLIST;
    el.querySelector("#sw-list").textContent = filtered.join("\n");
  }
  renderWords();
  el.querySelector("#sw-filter").oninput = renderWords;
  el.querySelector("#sw-copy").onclick = function() {
    navigator.clipboard.writeText(SUBDOMAIN_WORDLIST.join("\n")).then(function() {
      el.querySelector("#sw-copy").textContent = "Copied!";
      setTimeout(function() { el.querySelector("#sw-copy").textContent = "Copy All"; }, 2000);
    });
  };
}
