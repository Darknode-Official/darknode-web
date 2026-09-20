// Copyright (c) 2026 SpartanKing18. All rights reserved.
// Source-available for learning only. Redistribution prohibited. See LICENSE.
//
// OSINT (Open Source Intelligence) Techniques Reference Database
// Google dorks, Shodan queries, social media OSINT, domain recon, and more

// ============================================================================
// GOOGLE DORKS
// ============================================================================
export const GOOGLE_DORKS = [
  // --- Exposed Files ---
  { dork: 'filetype:pdf "confidential"', category: "files", description: "Find PDFs marked confidential" },
  { dork: 'filetype:xls "password"', category: "files", description: "Spreadsheets containing passwords" },
  { dork: 'filetype:doc "internal use only"', category: "files", description: "Internal documents leaked online" },
  { dork: 'filetype:sql "INSERT INTO"', category: "files", description: "Exposed SQL database dumps" },
  { dork: 'filetype:log "error" "password"', category: "files", description: "Log files with credentials" },
  { dork: 'filetype:env "DB_PASSWORD"', category: "files", description: "Exposed .env files with secrets" },
  { dork: 'filetype:cfg "password"', category: "files", description: "Config files with credentials" },
  { dork: 'filetype:bak "password"', category: "files", description: "Backup files containing passwords" },
  { dork: 'filetype:pem "PRIVATE KEY"', category: "files", description: "Exposed private key files" },
  { dork: 'filetype:ppk "PuTTY"', category: "files", description: "PuTTY private key files" },
  { dork: 'filetype:key "PRIVATE"', category: "files", description: "Private key files" },
  { dork: 'filetype:csv "email" "password"', category: "files", description: "CSV files with credentials" },
  { dork: 'filetype:json "api_key"', category: "files", description: "JSON files with API keys" },
  { dork: 'filetype:yml "password:"', category: "files", description: "YAML config with passwords" },
  { dork: 'filetype:xml "password"', category: "files", description: "XML files containing passwords" },
  { dork: 'filetype:conf "password"', category: "files", description: "Config files with passwords" },
  { dork: 'filetype:ini "[database]" "password"', category: "files", description: "INI files with DB credentials" },
  { dork: 'filetype:rdp "full address"', category: "files", description: "RDP connection files" },
  { dork: 'filetype:ovpn', category: "files", description: "OpenVPN configuration files" },
  { dork: 'filetype:pcap', category: "files", description: "Packet capture files" },
  { dork: 'ext:sql | ext:dbf | ext:mdb "password"', category: "files", description: "Database files with passwords" },
  { dork: '"index of" "*.sql.gz"', category: "files", description: "Compressed SQL backups in open directories" },
  { dork: '"index of" "backup" filetype:zip', category: "files", description: "Backup archives in open directories" },
  { dork: 'filetype:reg "HKEY_CURRENT_USER" "password"', category: "files", description: "Registry exports with passwords" },
  { dork: 'filetype:htpasswd', category: "files", description: "Apache password files" },

  // --- Login Pages ---
  { dork: 'intitle:"login" inurl:"/admin"', category: "login", description: "Admin login pages" },
  { dork: 'intitle:"admin panel" "login"', category: "login", description: "Admin panel login" },
  { dork: 'inurl:"/wp-login.php"', category: "login", description: "WordPress login pages" },
  { dork: 'inurl:"/administrator" intitle:"login"', category: "login", description: "Joomla admin login" },
  { dork: 'inurl:"/user/login" "drupal"', category: "login", description: "Drupal login pages" },
  { dork: 'inurl:"/phpmyadmin" intitle:"phpMyAdmin"', category: "login", description: "phpMyAdmin interfaces" },
  { dork: 'inurl:"/pgadmin" intitle:"pgAdmin"', category: "login", description: "pgAdmin database admin" },
  { dork: 'intitle:"Grafana" inurl:"/login"', category: "login", description: "Grafana dashboards" },
  { dork: 'intitle:"Kibana" inurl:"/app"', category: "login", description: "Kibana ELK dashboards" },
  { dork: 'intitle:"Jenkins" inurl:"/login"', category: "login", description: "Jenkins CI servers" },
  { dork: 'inurl:"/manager/html" intitle:"Tomcat"', category: "login", description: "Apache Tomcat manager" },
  { dork: 'inurl:"/admin" intitle:"Django" "Log in"', category: "login", description: "Django admin login" },
  { dork: 'intitle:"Sign In" "Outlook Web App"', category: "login", description: "Outlook Web Access" },
  { dork: 'intitle:"Sign in" inurl:"/owa"', category: "login", description: "Exchange OWA login" },
  { dork: 'inurl:"/remote/login" intitle:"FortiGate"', category: "login", description: "FortiGate VPN login" },
  { dork: 'intitle:"VPN" "SSL" inurl:"/dana-na/auth"', category: "login", description: "Pulse Secure VPN" },
  { dork: 'intitle:"Citrix" inurl:"/vpn/index.html"', category: "login", description: "Citrix Gateway login" },
  { dork: 'intitle:"webmin" inurl:":10000"', category: "login", description: "Webmin admin panels" },
  { dork: 'intitle:"Zabbix" inurl:"/index.php"', category: "login", description: "Zabbix monitoring login" },

  // --- Directory Listings ---
  { dork: 'intitle:"Index of /" "Parent Directory"', category: "directories", description: "Open directory listings" },
  { dork: '"index of" "backup"', category: "directories", description: "Backup directories" },
  { dork: '"index of" ".git"', category: "directories", description: "Exposed .git repositories" },
  { dork: '"index of" ".svn"', category: "directories", description: "Exposed SVN repositories" },
  { dork: '"index of" "wp-content/uploads"', category: "directories", description: "WordPress upload directories" },
  { dork: '"index of" "private"', category: "directories", description: "Directories named private" },
  { dork: '"index of" "config"', category: "directories", description: "Config directories" },
  { dork: '"index of" "phpmyadmin"', category: "directories", description: "phpMyAdmin directory" },
  { dork: '"index of" "cgi-bin"', category: "directories", description: "CGI script directories" },
  { dork: '"index of" "secret"', category: "directories", description: "Secret directories" },
  { dork: '"index of" ".env"', category: "directories", description: "Exposed environment files" },
  { dork: '"index of" "db" ext:sql', category: "directories", description: "Database dump directories" },

  // --- Vulnerable Pages ---
  { dork: 'inurl:".php?id="', category: "vulnerabilities", description: "Potential SQL injection targets" },
  { dork: 'inurl:".php?page="', category: "vulnerabilities", description: "Potential LFI targets" },
  { dork: 'inurl:".php?file="', category: "vulnerabilities", description: "Potential file inclusion" },
  { dork: 'inurl:".php?url="', category: "vulnerabilities", description: "Potential SSRF targets" },
  { dork: 'inurl:".php?redirect="', category: "vulnerabilities", description: "Open redirect targets" },
  { dork: 'inurl:"wp-content/plugins" "index of"', category: "vulnerabilities", description: "WordPress plugin directory listing" },
  { dork: 'inurl:"xmlrpc.php" "XML-RPC"', category: "vulnerabilities", description: "WordPress XML-RPC (brute force vector)" },
  { dork: '"Powered by" "Joomla" inurl:"/index.php/component"', category: "vulnerabilities", description: "Joomla components (often vulnerable)" },
  { dork: 'inurl:"server-status" "Apache Server Status"', category: "vulnerabilities", description: "Apache server status page" },
  { dork: 'inurl:"server-info" "Apache Server Information"', category: "vulnerabilities", description: "Apache server info page" },
  { dork: 'intitle:"phpinfo()" "PHP Version"', category: "vulnerabilities", description: "Exposed PHP info pages" },
  { dork: '"error" "warning" "mysql" filetype:php', category: "vulnerabilities", description: "PHP errors revealing paths/queries" },
  { dork: '"Fatal error" "Call to undefined function" filetype:php', category: "vulnerabilities", description: "PHP fatal errors" },
  { dork: '"ORA-00921" "SQL command"', category: "vulnerabilities", description: "Oracle SQL errors" },
  { dork: '"syntax error" "mysql" "query"', category: "vulnerabilities", description: "MySQL syntax errors" },
  { dork: '"ODBC" "error" "SQL Server"', category: "vulnerabilities", description: "MSSQL ODBC errors" },
  { dork: 'inurl:"/debug" intitle:"debug"', category: "vulnerabilities", description: "Debug pages" },
  { dork: 'inurl:"/actuator" intitle:"Whitelabel Error"', category: "vulnerabilities", description: "Spring Boot actuator endpoints" },
  { dork: 'inurl:"/.well-known/security.txt"', category: "vulnerabilities", description: "Security contact info" },

  // --- Cameras / IoT ---
  { dork: 'intitle:"Live View / - AXIS"', category: "cameras", description: "AXIS network cameras" },
  { dork: 'inurl:"view/index.shtml"', category: "cameras", description: "Generic IP cameras" },
  { dork: 'intitle:"IP CAMERA Viewer"', category: "cameras", description: "IP camera viewer pages" },
  { dork: 'inurl:"/cgi-bin/viewer/video.jpg"', category: "cameras", description: "Camera MJPEG streams" },
  { dork: 'intitle:"webcamXP 5" "chat"', category: "cameras", description: "webcamXP cameras" },
  { dork: 'inurl:"lvappl.htm"', category: "cameras", description: "Canon network cameras" },
  { dork: 'intitle:"Network Camera" "NetworkCamera"', category: "cameras", description: "Generic network cameras" },
  { dork: 'inurl:"ViewerFrame?Mode="', category: "cameras", description: "Panasonic cameras" },
  { dork: 'intitle:"Hikvision" "Web Client"', category: "cameras", description: "Hikvision DVR/NVR" },
  { dork: 'intitle:"DVR" "login" inurl:"/web/"', category: "cameras", description: "DVR login pages" },

  // --- Exposed Databases ---
  { dork: 'intitle:"Elasticsearch" inurl:":9200"', category: "databases", description: "Exposed Elasticsearch instances" },
  { dork: 'intitle:"MongoDB" inurl:":27017"', category: "databases", description: "Exposed MongoDB instances" },
  { dork: 'intitle:"CouchDB" "Welcome"', category: "databases", description: "Exposed CouchDB" },
  { dork: 'inurl:":5984/_utils"', category: "databases", description: "CouchDB Fauxton admin" },
  { dork: '"redis_version" "used_memory"', category: "databases", description: "Exposed Redis instances" },
  { dork: 'intitle:"Solr Admin" inurl:"/solr"', category: "databases", description: "Apache Solr admin" },
  { dork: '"cassandra" "cluster_name" "native_transport"', category: "databases", description: "Exposed Cassandra" },

  // --- Cloud Services ---
  { dork: 'site:s3.amazonaws.com "index of"', category: "cloud", description: "Open S3 buckets with listing" },
  { dork: 'site:blob.core.windows.net "index of"', category: "cloud", description: "Open Azure Blob storage" },
  { dork: 'site:storage.googleapis.com "index of"', category: "cloud", description: "Open GCS buckets" },
  { dork: 'site:trello.com "password"', category: "cloud", description: "Trello boards with passwords" },
  { dork: 'site:pastebin.com "password" "email"', category: "cloud", description: "Pastebin password dumps" },
  { dork: 'site:docs.google.com "confidential"', category: "cloud", description: "Google Docs with sensitive data" },
  { dork: '"amazonaws.com" "AccessDenied" "key"', category: "cloud", description: "S3 buckets with access errors" },
  { dork: 'site:github.com "api_key" "password" filetype:env', category: "cloud", description: "GitHub repos with secrets" },
  { dork: 'site:gitlab.com "private_key"', category: "cloud", description: "GitLab repos with private keys" },
  { dork: 'site:herokuapp.com inurl:"admin"', category: "cloud", description: "Heroku apps with admin pages" },
  { dork: '"firebase" "apiKey" site:github.com', category: "cloud", description: "Firebase keys on GitHub" },

  // --- Error Messages ---
  { dork: '"Internal Server Error" "server at"', category: "errors", description: "500 error pages revealing server info" },
  { dork: '"Warning: mysql_" "on line"', category: "errors", description: "PHP MySQL warnings" },
  { dork: '"Warning: pg_" "on line"', category: "errors", description: "PHP PostgreSQL warnings" },
  { dork: '"Microsoft OLE DB Provider" "error"', category: "errors", description: "ASP/MSSQL errors" },
  { dork: '"Traceback (most recent call last)"', category: "errors", description: "Python traceback errors" },
  { dork: '"Exception in thread" "java.lang"', category: "errors", description: "Java exceptions" },
  { dork: '"stack trace" "at" ".java:"', category: "errors", description: "Java stack traces" },
  { dork: '"Unhandled Exception" "ASP.NET"', category: "errors", description: "ASP.NET unhandled exceptions" },

  // --- Version Detection ---
  { dork: '"Apache" "Server at" intitle:"Index of"', category: "versions", description: "Apache version in directory listings" },
  { dork: '"nginx" "server" intitle:"Welcome to nginx"', category: "versions", description: "nginx default pages" },
  { dork: '"Microsoft-IIS" "server at"', category: "versions", description: "IIS version info" },
  { dork: '"X-Powered-By" "PHP"', category: "versions", description: "PHP version in headers" },
  { dork: '"WordPress" "version" "readme.html"', category: "versions", description: "WordPress version in readme" },

  // --- Government / Education ---
  { dork: 'site:gov filetype:pdf "for official use only"', category: "government", description: "Government FOUO documents" },
  { dork: 'site:edu filetype:xls "ssn" OR "social security"', category: "government", description: "Educational institution PII" },
  { dork: 'site:mil "not for public release"', category: "government", description: "Military restricted documents" },

  // --- Network Devices ---
  { dork: 'intitle:"RouterOS" "MikroTik"', category: "devices", description: "MikroTik router admin pages" },
  { dork: 'intitle:"Cisco" "login" inurl:"/admin"', category: "devices", description: "Cisco device admin" },
  { dork: 'intitle:"NETGEAR" "password" "login"', category: "devices", description: "NETGEAR router admin" },
  { dork: '"Powered by" "DD-WRT"', category: "devices", description: "DD-WRT router firmware" },
  { dork: 'intitle:"SonicWall" "login"', category: "devices", description: "SonicWall firewall admin" },
  { dork: 'intitle:"UniFi" "login"', category: "devices", description: "Ubiquiti UniFi controllers" },
  { dork: 'inurl:"/cgi-bin/luci" intitle:"OpenWrt"', category: "devices", description: "OpenWrt routers" },

  // --- Specific Technologies ---
  { dork: 'intitle:"Swagger UI" "api"', category: "tech", description: "Swagger API documentation" },
  { dork: 'intitle:"GraphQL Playground"', category: "tech", description: "GraphQL Playground interfaces" },
  { dork: '"graphiql" intitle:"GraphiQL"', category: "tech", description: "GraphiQL interfaces" },
  { dork: 'inurl:"/api/v1" inurl:"docs" intitle:"API"', category: "tech", description: "API documentation pages" },
  { dork: 'intitle:"RabbitMQ Management" inurl:":15672"', category: "tech", description: "RabbitMQ management" },
  { dork: 'intitle:"Docker" "Container" inurl:":2375"', category: "tech", description: "Exposed Docker API" },
  { dork: 'intitle:"Kubernetes Dashboard"', category: "tech", description: "Kubernetes dashboards" },
  { dork: 'intitle:"Portainer" inurl:"/api"', category: "tech", description: "Portainer container management" },
  { dork: 'intitle:"Prometheus" inurl:"/graph"', category: "tech", description: "Prometheus monitoring" },
  { dork: 'intitle:"ArgoCD" "Applications"', category: "tech", description: "ArgoCD deployment dashboards" },
  { dork: 'intitle:"Jupyter Notebook" "New" "Upload"', category: "tech", description: "Exposed Jupyter notebooks" },
  { dork: 'intitle:"MinIO" "Browser"', category: "tech", description: "MinIO object storage" },
  { dork: 'intitle:"Vault" "Sign in" "Hashicorp"', category: "tech", description: "HashiCorp Vault" },
  { dork: 'intitle:"Consul" "Services" "Nodes"', category: "tech", description: "HashiCorp Consul" },

  // --- Targeting (site-specific) ---
  { dork: 'site:TARGET.com filetype:pdf', category: "targeting", description: "PDF documents on target domain" },
  { dork: 'site:TARGET.com filetype:doc OR filetype:docx', category: "targeting", description: "Word documents on target" },
  { dork: 'site:TARGET.com inurl:"/api/"', category: "targeting", description: "API endpoints on target" },
  { dork: 'site:TARGET.com inurl:"admin"', category: "targeting", description: "Admin pages on target" },
  { dork: 'site:TARGET.com inurl:"login"', category: "targeting", description: "Login pages on target" },
  { dork: 'site:TARGET.com "powered by"', category: "targeting", description: "Technology stack on target" },
  { dork: 'site:TARGET.com "error" "warning"', category: "targeting", description: "Error pages on target" },
  { dork: 'site:TARGET.com ext:php | ext:asp | ext:jsp', category: "targeting", description: "Server-side scripts on target" },
  { dork: '"@TARGET.com" email', category: "targeting", description: "Email addresses for target domain" },
  { dork: 'intext:"@TARGET.com" site:linkedin.com', category: "targeting", description: "LinkedIn profiles at target" },
  { dork: '"TARGET" site:github.com', category: "targeting", description: "Target code on GitHub" },
  { dork: 'site:TARGET.com -www', category: "targeting", description: "Subdomains of target" },
];

// ============================================================================
// SHODAN QUERIES
// ============================================================================
export const SHODAN_QUERIES = [
  // --- Databases ---
  { query: 'port:27017 "MongoDB Server Information"', category: "databases", description: "Open MongoDB instances" },
  { query: 'port:9200 "elasticsearch"', category: "databases", description: "Open Elasticsearch clusters" },
  { query: 'port:6379 "redis_version"', category: "databases", description: "Open Redis instances" },
  { query: 'port:5432 "PostgreSQL"', category: "databases", description: "PostgreSQL servers" },
  { query: 'port:3306 "mysql"', category: "databases", description: "MySQL servers" },
  { query: 'port:1433 "Microsoft SQL Server"', category: "databases", description: "MSSQL servers" },
  { query: 'port:5984 "couchdb"', category: "databases", description: "CouchDB instances" },
  { query: '"cassandra" port:9042', category: "databases", description: "Cassandra instances" },
  { query: 'port:11211 "STAT"', category: "databases", description: "Memcached servers" },
  { query: 'port:8086 "InfluxDB"', category: "databases", description: "InfluxDB time-series databases" },

  // --- Web Servers ---
  { query: 'http.title:"Dashboard" http.component:"grafana"', category: "web", description: "Grafana dashboards" },
  { query: 'http.title:"Kibana"', category: "web", description: "Kibana dashboards" },
  { query: 'http.title:"Jenkins"', category: "web", description: "Jenkins CI servers" },
  { query: 'http.title:"Kubernetes Dashboard"', category: "web", description: "Kubernetes dashboards" },
  { query: '"default password" http.title:"login"', category: "web", description: "Devices with default credentials" },
  { query: 'http.favicon.hash:116323821', category: "web", description: "Spring Boot default favicon" },
  { query: 'http.favicon.hash:-1293762044', category: "web", description: "Atlassian Jira" },
  { query: 'http.component:"wordpress"', category: "web", description: "WordPress sites" },
  { query: '"X-Powered-By: Express" port:3000', category: "web", description: "Express.js applications" },
  { query: 'http.title:"phpMyAdmin"', category: "web", description: "phpMyAdmin panels" },
  { query: 'http.title:"Apache Tomcat"', category: "web", description: "Apache Tomcat servers" },

  // --- Industrial / ICS ---
  { query: 'port:502 "Modbus"', category: "ics", description: "Modbus SCADA/ICS devices" },
  { query: 'port:47808 "BACnet"', category: "ics", description: "BACnet building automation" },
  { query: 'port:20000 "DNP3"', category: "ics", description: "DNP3 SCADA protocol" },
  { query: '"Siemens" "S7" port:102', category: "ics", description: "Siemens S7 PLCs" },
  { query: '"Schneider Electric"', category: "ics", description: "Schneider Electric devices" },
  { query: '"Allen-Bradley"', category: "ics", description: "Rockwell Allen-Bradley PLCs" },
  { query: 'port:44818 "EtherNet/IP"', category: "ics", description: "EtherNet/IP industrial devices" },
  { query: '"Niagara Fox" port:1911', category: "ics", description: "Niagara building management" },

  // --- Cameras ---
  { query: '"Server: yawcam" "Mime-Type: text/html"', category: "cameras", description: "Yawcam webcams" },
  { query: 'http.title:"DVR" http.html:"login"', category: "cameras", description: "DVR login pages" },
  { query: '"Hikvision" port:80', category: "cameras", description: "Hikvision cameras" },
  { query: '"Dahua" port:80', category: "cameras", description: "Dahua cameras" },
  { query: '"Server: DNVRS" "RTSP"', category: "cameras", description: "RTSP video streams" },
  { query: '"IP Camera" has_screenshot:true', category: "cameras", description: "IP cameras with screenshots" },
  { query: 'port:554 "RTSP"', category: "cameras", description: "RTSP streaming devices" },

  // --- Network Devices ---
  { query: '"MikroTik" port:8291', category: "network", description: "MikroTik routers (Winbox)" },
  { query: '"Cisco" "last-modified"', category: "network", description: "Cisco devices" },
  { query: 'http.title:"RouterOS"', category: "network", description: "MikroTik RouterOS web UI" },
  { query: '"Fortinet" "FortiGate"', category: "network", description: "FortiGate firewalls" },
  { query: '"SonicWall" port:443', category: "network", description: "SonicWall firewalls" },
  { query: '"Palo Alto" "GlobalProtect"', category: "network", description: "Palo Alto GlobalProtect VPN" },
  { query: '"OpenVPN" port:1194', category: "network", description: "OpenVPN servers" },
  { query: '"WireGuard" port:51820', category: "network", description: "WireGuard VPN servers" },

  // --- Exposed Services ---
  { query: 'port:2375 "Docker"', category: "services", description: "Exposed Docker API (unauthenticated)" },
  { query: 'port:5900 "RFB" "Authentication"', category: "services", description: "VNC servers" },
  { query: 'port:3389 "Remote Desktop"', category: "services", description: "RDP servers" },
  { query: '"X-Jenkins" "Set-Cookie"', category: "services", description: "Jenkins with no auth" },
  { query: 'port:9090 "Prometheus"', category: "services", description: "Prometheus monitoring" },
  { query: 'port:15672 "RabbitMQ"', category: "services", description: "RabbitMQ management" },
  { query: 'port:8500 "consul"', category: "services", description: "HashiCorp Consul" },
  { query: 'port:4040 "Spark"', category: "services", description: "Apache Spark Web UI" },
  { query: 'port:8888 "Jupyter"', category: "services", description: "Jupyter notebooks" },
  { query: 'port:9000 "MinIO"', category: "services", description: "MinIO object storage" },
  { query: '"ETH - Node" port:8545', category: "services", description: "Ethereum RPC nodes" },
  { query: 'port:11211 "memcached"', category: "services", description: "Memcached (DDoS amplification)" },
  { query: 'port:161 "SNMP" "public"', category: "services", description: "SNMP with public community string" },
  { query: 'port:389 "LDAP"', category: "services", description: "LDAP directory servers" },

  // --- Country/Org Targeting ---
  { query: 'country:"US" port:22 "OpenSSH"', category: "targeting", description: "SSH servers in US" },
  { query: 'org:"TARGET" port:443', category: "targeting", description: "HTTPS servers belonging to organization" },
  { query: 'hostname:"TARGET.com"', category: "targeting", description: "All devices for hostname" },
  { query: 'net:"192.168.0.0/16"', category: "targeting", description: "Devices in IP range" },
  { query: 'asn:"AS15169"', category: "targeting", description: "All Google AS devices" },
  { query: 'ssl.cert.subject.cn:"TARGET.com"', category: "targeting", description: "SSL certificates for domain" },
  { query: 'ssl.cert.issuer.cn:"Let\'s Encrypt"', category: "targeting", description: "Sites using Let's Encrypt" },
  { query: 'ssl.cert.expired:true', category: "targeting", description: "Expired SSL certificates" },
];

// ============================================================================
// USERNAME ENUMERATION
// ============================================================================
export const USERNAME_ENUMERATION = {
  description: "Techniques and platforms for discovering usernames across services",
  tools: [
    { name: "Sherlock", description: "Hunt usernames across 400+ social networks", command: "sherlock USERNAME", url: "github.com/sherlock-project/sherlock" },
    { name: "Maigret", description: "Sherlock fork with 2,500+ sites", command: "maigret USERNAME", url: "github.com/soxoj/maigret" },
    { name: "WhatsMyName", description: "Username enumeration on 600+ sites", command: "python wmn.py -u USERNAME", url: "github.com/WebBreacher/WhatsMyName" },
    { name: "Namechk", description: "Check username availability across domains and social media", url: "namechk.com" },
    { name: "KnowEm", description: "Check 500+ social networks", url: "knowem.com" },
    { name: "Instant Username Search", description: "Real-time username availability", url: "instantusername.com" },
  ],
  techniques: [
    { method: "Registration check", description: "Attempt to register with the username — 'username taken' reveals existence" },
    { method: "Password reset", description: "Try password reset — different error for existing vs non-existing accounts" },
    { method: "Login error messages", description: "Compare error messages: 'user not found' vs 'wrong password'" },
    { method: "Timing attack", description: "Measure response time — existing users may take longer (password hash check)" },
    { method: "API enumeration", description: "Check API endpoints like /api/users/USERNAME or /api/check-username" },
    { method: "Response size", description: "Different response sizes for valid vs invalid usernames" },
  ]
};

// ============================================================================
// EMAIL DISCOVERY
// ============================================================================
export const EMAIL_DISCOVERY = {
  tools: [
    { name: "theHarvester", description: "Gather emails, subdomains, hosts, employee names", command: "theHarvester -d TARGET.com -b all", url: "github.com/laramies/theHarvester" },
    { name: "Hunter.io", description: "Find email addresses associated with a domain", url: "hunter.io", note: "API-based, freemium" },
    { name: "Phonebook.cz", description: "Email address discovery via IntelX", url: "phonebook.cz" },
    { name: "Skymem", description: "Find email addresses for a domain", url: "skymem.info" },
    { name: "Snov.io", description: "Email finder and verifier", url: "snov.io" },
    { name: "Clearbit Connect", description: "Find company emails from LinkedIn", url: "clearbit.com" },
  ],
  patterns: [
    { format: "first.last@domain.com", example: "john.smith@company.com", prevalence: "Very common" },
    { format: "firstlast@domain.com", example: "johnsmith@company.com", prevalence: "Common" },
    { format: "first@domain.com", example: "john@company.com", prevalence: "Common (small companies)" },
    { format: "flast@domain.com", example: "jsmith@company.com", prevalence: "Common" },
    { format: "first_last@domain.com", example: "john_smith@company.com", prevalence: "Moderate" },
    { format: "firstl@domain.com", example: "johns@company.com", prevalence: "Moderate" },
    { format: "last.first@domain.com", example: "smith.john@company.com", prevalence: "Less common" },
    { format: "f.last@domain.com", example: "j.smith@company.com", prevalence: "Moderate" },
  ],
  verification: [
    { method: "SMTP VRFY", description: "VRFY command to check if mailbox exists (often disabled)", command: "telnet TARGET-MX 25 → VRFY user@domain.com" },
    { method: "SMTP RCPT TO", description: "RCPT TO with invalid MAIL FROM to check recipient validity", command: "MAIL FROM:<test@test.com> → RCPT TO:<target@domain.com>" },
    { method: "MX record lookup", description: "Find mail servers for domain", command: "dig MX domain.com" },
    { method: "SPF record check", description: "SPF record reveals authorized mail sources", command: "dig TXT domain.com | grep spf" },
    { method: "DMARC record", description: "DMARC policy reveals email infrastructure", command: "dig TXT _dmarc.domain.com" },
  ]
};

// ============================================================================
// SOCIAL MEDIA OSINT
// ============================================================================
export const SOCIAL_MEDIA_OSINT = {
  twitter_x: {
    techniques: [
      { name: "Advanced search operators", examples: ["from:USER since:2024-01-01 until:2024-12-31", "from:USER filter:links", "from:USER filter:images", "to:USER", '"exact phrase" from:USER', "from:USER lang:en"] },
      { name: "Cached/deleted tweets", tools: ["Wayback Machine (web.archive.org)", "Google cache: cache:twitter.com/USER", "Politwoops (for politicians)"] },
      { name: "Geolocation", description: "geocode:LAT,LONG,RADIUS near:CITY within:DISTANCE" },
      { name: "Network mapping", description: "Analyze followers, following, lists, mutual connections" },
      { name: "API analysis", description: "Twitter API v2 for programmatic timeline/follower analysis" },
    ]
  },
  linkedin: {
    techniques: [
      { name: "Google dorking", example: 'site:linkedin.com/in "TARGET NAME" "COMPANY"' },
      { name: "Company page", description: "Browse employees, tech stack, recent hires" },
      { name: "Job postings", description: "Reveal tech stack, internal tools, security posture" },
      { name: "Skills & endorsements", description: "Map employee skill sets and roles" },
      { name: "Group memberships", description: "Identify interests and professional circles" },
      { name: "InMail phishing", description: "Social engineering via professional context" },
    ]
  },
  facebook: {
    techniques: [
      { name: "Profile search", example: "facebook.com/search/people/?q=NAME" },
      { name: "Graph search", description: "People who work at X and live in Y (limited)" },
      { name: "Photo tags", description: "Find tagged photos and connected people" },
      { name: "Check-ins", description: "Location history from public check-ins" },
      { name: "Groups", description: "Public group memberships reveal interests" },
      { name: "Events", description: "Event attendance reveals schedule and interests" },
    ]
  },
  instagram: {
    techniques: [
      { name: "Photo EXIF/location", description: "Geotagged photos reveal physical locations" },
      { name: "Story highlights", description: "Archived stories may reveal personal info" },
      { name: "Tagged photos", description: "Photos others tagged them in" },
      { name: "Following list", description: "Analyze who they follow for interests/connections" },
      { name: "Comment analysis", description: "Frequent commenters reveal social circle" },
    ]
  },
  reddit: {
    techniques: [
      { name: "Comment history", description: "u/USERNAME/comments reveals posting history" },
      { name: "Subreddit activity", description: "Subscribed/active subreddits reveal interests" },
      { name: "Pushshift/Arctic", description: "Historical Reddit data (deleted comments)" },
      { name: "Reddit investigator", description: "Tools to analyze posting patterns and times" },
      { name: "Cross-referencing", description: "Username may be same across platforms" },
    ]
  },
  discord: {
    techniques: [
      { name: "Server search", description: "Find public servers user is active in" },
      { name: "Discriminator", description: "Username#discriminator for unique identification" },
      { name: "Linked accounts", description: "Profile may show linked GitHub, Spotify, etc." },
      { name: "Message history", description: "Search messages in shared servers" },
    ]
  },
  telegram: {
    techniques: [
      { name: "Username search", description: "t.me/USERNAME for public profiles" },
      { name: "Phone number search", description: "Add phone to contacts to find Telegram account" },
      { name: "Public channels", description: "Search public channels for mentions" },
      { name: "Bot API", description: "Use bots for automated searches" },
    ]
  }
};

// ============================================================================
// DOMAIN RECONNAISSANCE
// ============================================================================
export const DOMAIN_RECON = {
  dns_records: [
    { type: "A", description: "IPv4 address mapping", command: "dig A domain.com", osint_value: "Reveals hosting provider, geographic location" },
    { type: "AAAA", description: "IPv6 address mapping", command: "dig AAAA domain.com", osint_value: "Additional IP addresses" },
    { type: "MX", description: "Mail exchange servers", command: "dig MX domain.com", osint_value: "Email provider (Google Workspace, O365, self-hosted)" },
    { type: "NS", description: "Name servers", command: "dig NS domain.com", osint_value: "DNS provider, infrastructure" },
    { type: "TXT", description: "Text records (SPF, DKIM, DMARC, verification)", command: "dig TXT domain.com", osint_value: "SPF reveals mail infrastructure, verification records reveal SaaS usage" },
    { type: "CNAME", description: "Canonical name (alias)", command: "dig CNAME subdomain.domain.com", osint_value: "Reveals third-party services" },
    { type: "SOA", description: "Start of Authority", command: "dig SOA domain.com", osint_value: "Admin email, DNS provider" },
    { type: "SRV", description: "Service records", command: "dig SRV _sip._tcp.domain.com", osint_value: "Services running (SIP, XMPP, LDAP)" },
    { type: "CAA", description: "Certificate Authority Authorization", command: "dig CAA domain.com", osint_value: "Allowed CAs for SSL certs" },
    { type: "PTR", description: "Reverse DNS", command: "dig -x IP_ADDRESS", osint_value: "Hostname from IP; reveals hosting" },
  ],
  subdomain_enumeration: {
    passive: [
      { tool: "crt.sh", description: "Certificate Transparency log search", command: "curl 'https://crt.sh/?q=%25.TARGET.com&output=json'" },
      { tool: "SecurityTrails", description: "DNS history and subdomain search", url: "securitytrails.com" },
      { tool: "VirusTotal", description: "Subdomain data from passive DNS", url: "virustotal.com" },
      { tool: "Shodan", description: "ssl.cert.subject.cn:TARGET.com", url: "shodan.io" },
      { tool: "DNSdumpster", description: "Free DNS recon and research", url: "dnsdumpster.com" },
      { tool: "Amass (passive)", description: "OWASP subdomain enumeration", command: "amass enum -passive -d TARGET.com" },
      { tool: "Subfinder", description: "Fast passive subdomain discovery", command: "subfinder -d TARGET.com" },
      { tool: "Sublist3r", description: "Python subdomain enumeration", command: "sublist3r -d TARGET.com" },
    ],
    active: [
      { tool: "Amass (active)", description: "DNS brute-force + permutations", command: "amass enum -active -d TARGET.com" },
      { tool: "Gobuster DNS", description: "DNS subdomain brute force", command: "gobuster dns -d TARGET.com -w wordlist.txt" },
      { tool: "MassDNS", description: "High-performance DNS resolution", command: "massdns -r resolvers.txt -t A subdomains.txt" },
      { tool: "dnsrecon", description: "DNS enumeration with zone transfer attempts", command: "dnsrecon -d TARGET.com -a" },
      { tool: "Zone transfer", description: "Attempt AXFR transfer (misconfiguration)", command: "dig AXFR TARGET.com @ns1.TARGET.com" },
    ]
  },
  whois_data: {
    description: "Domain registration information",
    tools: [
      { name: "whois CLI", command: "whois TARGET.com" },
      { name: "DomainTools", url: "whois.domaintools.com" },
      { name: "who.is", url: "who.is" },
    ],
    useful_fields: [
      "Registrant Name/Organization/Email",
      "Admin/Tech Contact",
      "Creation/Expiration/Update dates",
      "Name Servers",
      "Registrar",
      "DNSSEC status"
    ],
    historical: [
      { tool: "DomainTools WHOIS History", description: "Historical WHOIS records showing previous owners" },
      { tool: "WhoisXML API", description: "Historical and reverse WHOIS lookups" },
    ]
  },
  certificate_transparency: {
    description: "All publicly trusted CAs must log certificates to CT logs",
    tools: [
      { name: "crt.sh", url: "crt.sh", description: "Search CT logs by domain" },
      { name: "Google CT", url: "transparencyreport.google.com/https/certificates", description: "Google's CT log viewer" },
      { name: "Censys", url: "censys.io", description: "Internet-wide certificate search" },
    ],
    osint_value: "Reveals subdomains, internal hostnames, staging/dev environments, email addresses in cert fields"
  }
};

// ============================================================================
// IMAGE OSINT
// ============================================================================
export const IMAGE_OSINT = {
  exif_data: {
    description: "Metadata embedded in images by cameras and phones",
    fields: [
      { field: "GPS Latitude/Longitude", description: "Exact location where photo was taken" },
      { field: "DateTimeOriginal", description: "When the photo was taken" },
      { field: "Make/Model", description: "Camera or phone model" },
      { field: "Software", description: "Editing software used" },
      { field: "Author/Artist", description: "Photographer name" },
      { field: "Copyright", description: "Copyright information" },
      { field: "Lens", description: "Camera lens used" },
      { field: "Serial Number", description: "Camera serial (unique identifier)" },
      { field: "Thumbnail", description: "Embedded thumbnail (may show uncropped original)" },
    ],
    tools: [
      { name: "exiftool", command: "exiftool image.jpg", description: "Read/write metadata (most comprehensive)" },
      { name: "exiv2", command: "exiv2 image.jpg", description: "Read EXIF data" },
      { name: "Jeffrey's Exif Viewer", url: "exif.regex.info/exif.cgi", description: "Online EXIF viewer" },
      { name: "FotoForensics", url: "fotoforensics.com", description: "ELA and metadata analysis" },
    ]
  },
  reverse_image_search: [
    { name: "Google Images", url: "images.google.com", description: "Largest index; drag-and-drop or paste URL" },
    { name: "Yandex Images", url: "yandex.com/images", description: "Often finds results Google misses, especially faces" },
    { name: "TinEye", url: "tineye.com", description: "Specialized reverse image search; finds oldest known copy" },
    { name: "Bing Visual Search", url: "bing.com/visualsearch", description: "Microsoft's reverse image search" },
    { name: "Baidu Image Search", url: "image.baidu.com", description: "Best for images from Chinese internet" },
    { name: "SauceNAO", url: "saucenao.com", description: "Anime/illustration source finder" },
    { name: "PimEyes", url: "pimeyes.com", description: "Face recognition search engine (paid)" },
    { name: "Social Catfish", url: "socialcatfish.com", description: "Search by image across social media" },
  ],
  geolocation_from_images: {
    description: "Determining location from visual clues in images",
    techniques: [
      { clue: "Street signs", description: "Language, format, and style indicate country/region" },
      { clue: "License plates", description: "Country, state/province identification" },
      { clue: "Architecture", description: "Building styles indicate culture and era" },
      { clue: "Vegetation", description: "Plant species indicate climate zone" },
      { clue: "Sun position/shadows", description: "Shadow direction + time = approximate latitude" },
      { clue: "Power lines/poles", description: "Pole style varies by country" },
      { clue: "Road markings", description: "Lane markings, drive side indicate country" },
      { clue: "Store signs/brands", description: "Local businesses and chains narrow location" },
      { clue: "Language on signs", description: "Script identifies country or region" },
      { clue: "Phone country code", description: "Phone numbers on signs reveal country" },
      { clue: "Satellite imagery comparison", description: "Match terrain features to Google Earth" },
    ],
    tools: [
      { name: "GeoGuessr", description: "Game that trains geolocation skills" },
      { name: "Google Street View", description: "Compare photos to street-level imagery" },
      { name: "Google Earth", description: "Satellite imagery for terrain matching" },
      { name: "SunCalc", description: "Calculate sun position from shadows + date/time", url: "suncalc.org" },
    ]
  }
};

// ============================================================================
// CORPORATE INTELLIGENCE
// ============================================================================
export const CORPORATE_INTEL = {
  techniques: [
    {
      name: "Technology stack detection",
      tools: [
        { name: "BuiltWith", url: "builtwith.com", description: "Detect web technologies used" },
        { name: "Wappalyzer", url: "wappalyzer.com", description: "Browser extension for tech detection" },
        { name: "WhatRuns", url: "whatruns.com", description: "Discover technologies on websites" },
        { name: "Netcraft", url: "netcraft.com", description: "Web server and hosting info" },
      ]
    },
    {
      name: "Job posting analysis",
      description: "Job listings reveal tech stack, security tools, team size, and org structure",
      sources: ["LinkedIn Jobs", "Indeed", "Glassdoor", "company careers page"],
      indicators: ["Required technologies/tools", "Team size mentions", "Security certifications required", "Cloud provider (AWS/Azure/GCP)"]
    },
    {
      name: "Financial records",
      sources: [
        { name: "SEC EDGAR", description: "US public company filings (10-K, 10-Q, 8-K)", url: "sec.gov/edgar" },
        { name: "Companies House", description: "UK company registrations", url: "companieshouse.gov.uk" },
        { name: "OpenCorporates", description: "Global corporate registry search", url: "opencorporates.com" },
        { name: "Crunchbase", description: "Startup funding and company info", url: "crunchbase.com" },
      ]
    },
    {
      name: "Employee enumeration",
      techniques: [
        "LinkedIn company page → employees list",
        "GitHub organization members",
        "Conference speaker bios",
        "Patent filings (USPTO, Google Patents)",
        "Academic paper co-authors",
        "Press releases and quotes",
      ]
    },
    {
      name: "Infrastructure mapping",
      techniques: [
        "BGP/ASN lookup (bgp.he.net)",
        "IP range WHOIS (ARIN, RIPE, APNIC)",
        "Reverse DNS on IP ranges",
        "SSL certificate analysis",
        "Cloud asset discovery (S3 buckets, Azure blobs)",
        "Shodan org: search",
      ]
    },
    {
      name: "Breach data analysis",
      tools: [
        { name: "Have I Been Pwned", url: "haveibeenpwned.com", description: "Check if email appears in known breaches" },
        { name: "DeHashed", url: "dehashed.com", description: "Search breached databases (paid)" },
        { name: "Intelligence X", url: "intelx.io", description: "Search engine for OSINT (darknet, leaks, paste sites)" },
        { name: "Leak-Lookup", url: "leak-lookup.com", description: "Database breach search" },
      ],
      ethical_note: "Only search for your own credentials or with explicit authorization during assessments"
    },
  ]
};

// ============================================================================
// METADATA EXTRACTION
// ============================================================================
export const METADATA_EXTRACTION = {
  document_metadata: {
    description: "Extract metadata from Office documents, PDFs, and other files",
    tools: [
      { name: "exiftool", command: "exiftool document.pdf", description: "Read all metadata from any file type" },
      { name: "FOCA", description: "Fingerprinting Organizations with Collected Archives", platform: "Windows", notes: "Downloads documents from target domain, extracts metadata (usernames, paths, software)" },
      { name: "Metagoofil", command: "metagoofil -d TARGET.com -t pdf,doc,xls -o output/", description: "Download and extract metadata from public documents" },
      { name: "pdfinfo", command: "pdfinfo file.pdf", description: "PDF metadata viewer" },
      { name: "mat2", command: "mat2 --show file.pdf", description: "Metadata anonymization toolkit (view and strip)" },
    ],
    common_fields: [
      { field: "Author", description: "Document creator (often employee username or full name)" },
      { field: "Creator/Producer", description: "Software used to create (reveals internal tools)" },
      { field: "Company", description: "Organization name" },
      { field: "Last Modified By", description: "Last editor" },
      { field: "Creation/Modification Date", description: "Timeline information" },
      { field: "Internal paths", description: "File paths in metadata reveal directory structure (C:\\Users\\jsmith\\...)" },
      { field: "Printer name", description: "Network printer names reveal internal naming conventions" },
      { field: "Email addresses", description: "Sometimes embedded in document properties" },
      { field: "Template paths", description: "Corporate template paths reveal internal servers" },
      { field: "GPS data (images)", description: "Location where document images were taken" },
    ]
  }
};

// ============================================================================
// WAYBACK MACHINE TECHNIQUES
// ============================================================================
export const WAYBACK_TECHNIQUES = [
  { technique: "Historical snapshots", url: "web.archive.org/web/*/TARGET.com", description: "Browse all archived versions of a site" },
  { technique: "robots.txt history", url: "web.archive.org/web/*/TARGET.com/robots.txt", description: "Old robots.txt may reveal hidden paths" },
  { technique: "Old technologies", description: "Previous site versions may reveal old software, frameworks, or APIs still running" },
  { technique: "Removed pages", description: "Pages that were taken down but still exist in the archive" },
  { technique: "Old credentials", description: "Configuration pages or comments from older versions may contain secrets" },
  { technique: "Employee names", description: "Old about/team pages may reveal former employees" },
  { technique: "API discovery", url: "web.archive.org/cdx/search/cdx?url=TARGET.com/*&output=text&fl=original&collapse=urlkey", description: "CDX API to list all archived URLs for a domain" },
  { technique: "JavaScript analysis", description: "Old JS files may contain API keys, endpoints, or debug code" },
  { technique: "Subdomain discovery", description: "Archived subdomains that may still be active" },
  { technique: "waybackurls tool", command: "waybackurls TARGET.com | sort -u", description: "Extract all URLs from Wayback Machine for a domain" },
  { technique: "GAU (Get All URLs)", command: "gau TARGET.com", description: "Fetch URLs from Wayback, Common Crawl, OTX, URLScan" },
];

// ============================================================================
// PHONE NUMBER OSINT
// ============================================================================
export const PHONE_OSINT = {
  tools: [
    { name: "PhoneInfoga", description: "Advanced phone number lookup", command: "phoneinfoga scan -n +1234567890", url: "github.com/sundowndev/phoneinfoga" },
    { name: "Truecaller", description: "Caller ID and spam blocking; reveals name", url: "truecaller.com" },
    { name: "NumVerify", description: "Phone number validation and carrier lookup", url: "numverify.com" },
    { name: "CallerID Test", description: "Reverse phone lookup", url: "calleridtest.com" },
    { name: "SpyDialer", description: "Free reverse phone lookup", url: "spydialer.com" },
  ],
  techniques: [
    { method: "Carrier lookup", description: "HLR lookup reveals mobile carrier, roaming status" },
    { method: "Format analysis", description: "Country code + number format reveals location" },
    { method: "Social media search", description: "Search phone number on Facebook, Google, WhatsApp" },
    { method: "Messenger check", description: "Check if number is registered on WhatsApp, Telegram, Signal, Viber" },
    { method: "Reverse lookup", description: "White/yellow pages, Spokeo, WhitePages" },
    { method: "Google dorking", description: '"TARGET_PHONE_NUMBER" to find associated accounts' },
  ]
};

// ============================================================================
// OSINT FRAMEWORKS AND METHODOLOGY
// ============================================================================
export const OSINT_METHODOLOGY = {
  phases: [
    { phase: 1, name: "Define Requirements", description: "What do you need to find? Set clear objectives and scope." },
    { phase: 2, name: "Source Identification", description: "Identify relevant data sources (social media, public records, technical)" },
    { phase: 3, name: "Data Collection", description: "Gather raw data from identified sources using tools and manual techniques" },
    { phase: 4, name: "Data Processing", description: "Clean, deduplicate, and normalize collected data" },
    { phase: 5, name: "Analysis", description: "Cross-reference data points, identify patterns, verify findings" },
    { phase: 6, name: "Reporting", description: "Document findings with sources, confidence levels, and recommendations" },
  ],
  opsec_for_researchers: [
    "Use a dedicated research machine or VM",
    "Use VPN or Tor for searches",
    "Create sock puppet accounts (not linked to real identity)",
    "Don't log into personal accounts during research",
    "Clear cookies and use private/incognito mode",
    "Be aware that some platforms log who views profiles (LinkedIn)",
    "Use browser extensions to control fingerprinting",
    "Document your methodology for legal defensibility",
    "Know and follow local laws regarding OSINT collection",
  ],
  frameworks: [
    { name: "OSINT Framework", url: "osintframework.com", description: "Categorized collection of OSINT tools and resources" },
    { name: "IntelTechniques", url: "inteltechniques.com", description: "Michael Bazzell's OSINT tools and training" },
    { name: "Maltego", description: "Visual link analysis and data mining platform", url: "maltego.com" },
    { name: "SpiderFoot", description: "Automated OSINT collection", command: "spiderfoot -s TARGET.com", url: "spiderfoot.net" },
    { name: "Recon-ng", description: "Full-featured web reconnaissance framework", command: "recon-ng", url: "github.com/lanmaster53/recon-ng" },
  ]
};
