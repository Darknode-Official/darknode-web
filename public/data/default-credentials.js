// Copyright (c) 2026 SpartanKing18. All rights reserved.
// Default credentials database for network devices, IoT, software, databases, web applications.
// For authorized security testing and auditing only.

export const CREDENTIAL_CATEGORIES = [
  "routers", "switches", "firewalls", "access-points", "printers",
  "cameras", "databases", "web-apps", "industrial", "iot",
  "bmc-ipmi", "vpn", "voip", "network-management"
];

export const DEFAULT_CREDENTIALS = [
  // ============================================================================
  // ROUTERS
  // ============================================================================
  { vendor: "Cisco", product: "IOS Router", category: "routers", username: "admin", password: "admin", port: 23, protocol: "telnet/ssh", notes: "Default on many consumer/SMB Cisco routers", cve: null },
  { vendor: "Cisco", product: "IOS Router (enable)", category: "routers", username: "enable", password: "cisco", port: 23, protocol: "telnet", notes: "Default enable password on older IOS", cve: null },
  { vendor: "Cisco", product: "RV Series", category: "routers", username: "cisco", password: "cisco", port: 443, protocol: "https", notes: "RV110W, RV120W, RV215W web interface", cve: null },
  { vendor: "Cisco", product: "Meraki MX", category: "routers", username: "", password: "", port: 443, protocol: "https", notes: "Managed via dashboard.meraki.com — no local default", cve: null },
  { vendor: "Juniper", product: "SRX/EX", category: "routers", username: "root", password: "(none)", port: 22, protocol: "ssh", notes: "Factory default has no password — commit required", cve: null },
  { vendor: "Juniper", product: "Junos (console)", category: "routers", username: "root", password: "root123", port: 0, protocol: "console", notes: "Some lab/evaluation images", cve: null },
  { vendor: "MikroTik", product: "RouterOS", category: "routers", username: "admin", password: "", port: 8291, protocol: "winbox", notes: "Empty password by default — Winbox port 8291, SSH 22, HTTP 80", cve: null },
  { vendor: "MikroTik", product: "RouterOS v6.43+", category: "routers", username: "admin", password: "(serial number)", port: 8291, protocol: "winbox", notes: "Newer versions use serial number as default password", cve: null },
  { vendor: "Ubiquiti", product: "EdgeRouter", category: "routers", username: "ubnt", password: "ubnt", port: 22, protocol: "ssh", notes: "Factory default on all EdgeRouter models", cve: null },
  { vendor: "Ubiquiti", product: "UniFi Security Gateway", category: "routers", username: "ubnt", password: "ubnt", port: 22, protocol: "ssh", notes: "Before adoption by UniFi Controller", cve: null },
  { vendor: "Netgear", product: "Nighthawk", category: "routers", username: "admin", password: "password", port: 80, protocol: "http", notes: "Default on most Netgear consumer routers", cve: null },
  { vendor: "Netgear", product: "Orbi", category: "routers", username: "admin", password: "password", port: 80, protocol: "http", notes: "Orbi mesh router system", cve: null },
  { vendor: "TP-Link", product: "Archer Series", category: "routers", username: "admin", password: "admin", port: 80, protocol: "http", notes: "Older firmware — newer requires setup", cve: null },
  { vendor: "D-Link", product: "DIR Series", category: "routers", username: "admin", password: "", port: 80, protocol: "http", notes: "Empty password on older D-Link routers", cve: null },
  { vendor: "D-Link", product: "DIR-615", category: "routers", username: "admin", password: "admin", port: 80, protocol: "http", notes: "Some firmware versions", cve: null },
  { vendor: "Asus", product: "RT Series", category: "routers", username: "admin", password: "admin", port: 80, protocol: "http", notes: "RT-AC66U, RT-AC68U, RT-AX88U etc.", cve: null },
  { vendor: "Linksys", product: "EA Series", category: "routers", username: "admin", password: "admin", port: 80, protocol: "http", notes: "Older Linksys Smart Wi-Fi routers", cve: null },
  { vendor: "Linksys", product: "WRT54G", category: "routers", username: "", password: "admin", port: 80, protocol: "http", notes: "Classic — blank username, admin password", cve: null },
  { vendor: "Huawei", product: "HG Series", category: "routers", username: "admin", password: "admin", port: 80, protocol: "http", notes: "ISP-provided home gateways", cve: null },
  { vendor: "ZTE", product: "ZXHN", category: "routers", username: "admin", password: "admin", port: 80, protocol: "http", notes: "ISP CPE devices", cve: null },
  { vendor: "Zyxel", product: "VMG Series", category: "routers", username: "admin", password: "1234", port: 80, protocol: "http", notes: "DSL/fiber gateways", cve: null },
  { vendor: "pfSense", product: "pfSense CE", category: "routers", username: "admin", password: "pfsense", port: 443, protocol: "https", notes: "Open-source firewall/router", cve: null },
  { vendor: "OPNsense", product: "OPNsense", category: "routers", username: "root", password: "opnsense", port: 443, protocol: "https", notes: "Fork of pfSense", cve: null },
  { vendor: "OpenWrt", product: "OpenWrt", category: "routers", username: "root", password: "(none)", port: 22, protocol: "ssh", notes: "No password set by default — telnet only until set", cve: null },
  { vendor: "DD-WRT", product: "DD-WRT", category: "routers", username: "root", password: "admin", port: 80, protocol: "http", notes: "Open-source router firmware", cve: null },

  // ============================================================================
  // SWITCHES
  // ============================================================================
  { vendor: "Cisco", product: "Catalyst Switch", category: "switches", username: "admin", password: "admin", port: 22, protocol: "ssh", notes: "Varies by model — some have no default", cve: null },
  { vendor: "Cisco", product: "SG Series (SMB)", category: "switches", username: "cisco", password: "cisco", port: 443, protocol: "https", notes: "SG200, SG300, SG350, SG500 managed switches", cve: null },
  { vendor: "HP/Aruba", product: "ProCurve", category: "switches", username: "admin", password: "(none)", port: 23, protocol: "telnet", notes: "No default password — set on first login", cve: null },
  { vendor: "HP/Aruba", product: "Aruba Switch", category: "switches", username: "admin", password: "", port: 22, protocol: "ssh", notes: "ArubaOS switches", cve: null },
  { vendor: "Juniper", product: "EX Series", category: "switches", username: "root", password: "(none)", port: 0, protocol: "console", notes: "Factory default — requires console setup", cve: null },
  { vendor: "Netgear", product: "GS Series", category: "switches", username: "admin", password: "password", port: 80, protocol: "http", notes: "GS108T, GS110TP, GS724T managed switches", cve: null },
  { vendor: "D-Link", product: "DGS Series", category: "switches", username: "admin", password: "admin", port: 80, protocol: "http", notes: "DGS-1100, DGS-1210 series", cve: null },
  { vendor: "TP-Link", product: "T1600G/T2600G", category: "switches", username: "admin", password: "admin", port: 80, protocol: "http", notes: "JetStream managed switches", cve: null },
  { vendor: "Ubiquiti", product: "UniFi Switch", category: "switches", username: "ubnt", password: "ubnt", port: 22, protocol: "ssh", notes: "Before controller adoption", cve: null },
  { vendor: "Dell", product: "PowerConnect", category: "switches", username: "admin", password: "", port: 22, protocol: "ssh", notes: "No default password — serial console setup", cve: null },

  // ============================================================================
  // FIREWALLS
  // ============================================================================
  { vendor: "Fortinet", product: "FortiGate", category: "firewalls", username: "admin", password: "", port: 443, protocol: "https", notes: "Blank password by default — change on first login", cve: null },
  { vendor: "Palo Alto", product: "PAN-OS", category: "firewalls", username: "admin", password: "admin", port: 443, protocol: "https", notes: "Default on all PAN-OS firewalls", cve: null },
  { vendor: "SonicWall", product: "TZ/NSa Series", category: "firewalls", username: "admin", password: "password", port: 443, protocol: "https", notes: "Default management credentials", cve: null },
  { vendor: "Check Point", product: "Gaia", category: "firewalls", username: "admin", password: "admin", port: 443, protocol: "https", notes: "SmartConsole / Gaia portal", cve: null },
  { vendor: "WatchGuard", product: "Firebox", category: "firewalls", username: "admin", password: "readwrite", port: 8080, protocol: "https", notes: "Read-write admin access", cve: null },
  { vendor: "WatchGuard", product: "Firebox (status)", category: "firewalls", username: "status", password: "readonly", port: 8080, protocol: "https", notes: "Read-only monitoring access", cve: null },
  { vendor: "Sophos", product: "XG Firewall", category: "firewalls", username: "admin", password: "admin", port: 4444, protocol: "https", notes: "Web admin on port 4444", cve: null },
  { vendor: "Barracuda", product: "CloudGen Firewall", category: "firewalls", username: "root", password: "", port: 22, protocol: "ssh", notes: "Root SSH — no default password", cve: null },

  // ============================================================================
  // CAMERAS / DVRs
  // ============================================================================
  { vendor: "Hikvision", product: "IP Camera", category: "cameras", username: "admin", password: "12345", port: 80, protocol: "http", notes: "Older firmware — newer requires activation", cve: "CVE-2017-7921" },
  { vendor: "Hikvision", product: "NVR/DVR", category: "cameras", username: "admin", password: "12345", port: 80, protocol: "http", notes: "Network video recorders", cve: null },
  { vendor: "Dahua", product: "IP Camera", category: "cameras", username: "admin", password: "admin", port: 80, protocol: "http", notes: "Older firmware default", cve: "CVE-2021-36260" },
  { vendor: "Axis", product: "IP Camera", category: "cameras", username: "root", password: "pass", port: 80, protocol: "http", notes: "Axis Communications default", cve: null },
  { vendor: "Reolink", product: "IP Camera", category: "cameras", username: "admin", password: "", port: 80, protocol: "http", notes: "Blank password — set on first access", cve: null },
  { vendor: "Amcrest", product: "IP Camera", category: "cameras", username: "admin", password: "admin", port: 80, protocol: "http", notes: "Amcrest/Dahua OEM", cve: null },
  { vendor: "Foscam", product: "IP Camera", category: "cameras", username: "admin", password: "", port: 88, protocol: "http", notes: "Web interface on port 88", cve: null },
  { vendor: "Wyze", product: "Cam v2/v3", category: "cameras", username: "", password: "", port: 0, protocol: "app", notes: "Cloud-only — no local credentials", cve: null },
  { vendor: "Ring", product: "Doorbell/Cam", category: "cameras", username: "", password: "", port: 0, protocol: "app", notes: "Amazon Ring — cloud-managed via app", cve: null },
  { vendor: "Uniview", product: "IP Camera", category: "cameras", username: "admin", password: "123456", port: 80, protocol: "http", notes: "Uniview NVR/camera default", cve: null },

  // ============================================================================
  // DATABASES
  // ============================================================================
  { vendor: "MySQL", product: "MySQL Server", category: "databases", username: "root", password: "", port: 3306, protocol: "mysql", notes: "Empty root password on many default installs", cve: null },
  { vendor: "MySQL", product: "MySQL (XAMPP)", category: "databases", username: "root", password: "", port: 3306, protocol: "mysql", notes: "XAMPP default — no root password", cve: null },
  { vendor: "MariaDB", product: "MariaDB Server", category: "databases", username: "root", password: "", port: 3306, protocol: "mysql", notes: "Unix socket auth or empty password", cve: null },
  { vendor: "PostgreSQL", product: "PostgreSQL", category: "databases", username: "postgres", password: "postgres", port: 5432, protocol: "postgresql", notes: "Common default — some installs use peer auth", cve: null },
  { vendor: "MongoDB", product: "MongoDB", category: "databases", username: "", password: "", port: 27017, protocol: "mongodb", notes: "No auth by default — bindIp 0.0.0.0 is critical", cve: null },
  { vendor: "Redis", product: "Redis Server", category: "databases", username: "", password: "", port: 6379, protocol: "redis", notes: "No authentication by default", cve: null },
  { vendor: "Elasticsearch", product: "Elasticsearch", category: "databases", username: "", password: "", port: 9200, protocol: "http", notes: "No auth pre-8.0 — open by default", cve: null },
  { vendor: "Elasticsearch", product: "Elasticsearch 8+", category: "databases", username: "elastic", password: "(auto-generated)", port: 9200, protocol: "https", notes: "Security enabled by default in 8.x", cve: null },
  { vendor: "CouchDB", product: "CouchDB", category: "databases", username: "admin", password: "password", port: 5984, protocol: "http", notes: "Admin party mode if not configured", cve: null },
  { vendor: "Microsoft", product: "SQL Server (sa)", category: "databases", username: "sa", password: "sa", port: 1433, protocol: "tds", notes: "Common weak sa password", cve: null },
  { vendor: "Oracle", product: "Oracle DB", category: "databases", username: "system", password: "oracle", port: 1521, protocol: "oracle", notes: "Common default for development instances", cve: null },
  { vendor: "Oracle", product: "Oracle DB (scott)", category: "databases", username: "scott", password: "tiger", port: 1521, protocol: "oracle", notes: "Classic demo account since Oracle 7", cve: null },
  { vendor: "Cassandra", product: "Apache Cassandra", category: "databases", username: "cassandra", password: "cassandra", port: 9042, protocol: "cql", notes: "Default superuser when auth enabled", cve: null },
  { vendor: "InfluxDB", product: "InfluxDB 1.x", category: "databases", username: "admin", password: "", port: 8086, protocol: "http", notes: "No auth by default in 1.x", cve: null },
  { vendor: "Memcached", product: "Memcached", category: "databases", username: "", password: "", port: 11211, protocol: "memcached", notes: "No authentication mechanism", cve: null },

  // ============================================================================
  // WEB APPLICATIONS
  // ============================================================================
  { vendor: "WordPress", product: "WordPress", category: "web-apps", username: "admin", password: "admin", port: 80, protocol: "http", notes: "Common weak setup — not a true default", cve: null },
  { vendor: "Joomla", product: "Joomla CMS", category: "web-apps", username: "admin", password: "admin", port: 80, protocol: "http", notes: "Set during installation wizard", cve: null },
  { vendor: "Drupal", product: "Drupal", category: "web-apps", username: "admin", password: "admin", port: 80, protocol: "http", notes: "Set during install — this is common weak choice", cve: null },
  { vendor: "phpMyAdmin", product: "phpMyAdmin", category: "web-apps", username: "root", password: "", port: 80, protocol: "http", notes: "Uses MySQL root credentials — often empty", cve: null },
  { vendor: "Apache", product: "Tomcat", category: "web-apps", username: "tomcat", password: "tomcat", port: 8080, protocol: "http", notes: "Manager app — /manager/html", cve: null },
  { vendor: "Apache", product: "Tomcat (admin)", category: "web-apps", username: "admin", password: "admin", port: 8080, protocol: "http", notes: "Host Manager app", cve: null },
  { vendor: "Jenkins", product: "Jenkins", category: "web-apps", username: "admin", password: "(initial admin password)", port: 8080, protocol: "http", notes: "Password in /var/lib/jenkins/secrets/initialAdminPassword", cve: null },
  { vendor: "Grafana", product: "Grafana", category: "web-apps", username: "admin", password: "admin", port: 3000, protocol: "http", notes: "Prompts password change on first login", cve: null },
  { vendor: "Kibana", product: "Kibana", category: "web-apps", username: "elastic", password: "changeme", port: 5601, protocol: "http", notes: "Pre-8.0 default", cve: null },
  { vendor: "Nagios", product: "Nagios XI", category: "web-apps", username: "nagiosadmin", password: "nagiosadmin", port: 80, protocol: "http", notes: "Nagios web interface", cve: null },
  { vendor: "Zabbix", product: "Zabbix", category: "web-apps", username: "Admin", password: "zabbix", port: 80, protocol: "http", notes: "Case-sensitive username (capital A)", cve: null },
  { vendor: "PRTG", product: "PRTG Network Monitor", category: "web-apps", username: "prtgadmin", password: "prtgadmin", port: 443, protocol: "https", notes: "Paessler PRTG monitoring", cve: null },
  { vendor: "SonarQube", product: "SonarQube", category: "web-apps", username: "admin", password: "admin", port: 9000, protocol: "http", notes: "Code quality platform", cve: null },
  { vendor: "Portainer", product: "Portainer", category: "web-apps", username: "admin", password: "(set on first use)", port: 9443, protocol: "https", notes: "Docker management UI", cve: null },
  { vendor: "GitLab", product: "GitLab CE", category: "web-apps", username: "root", password: "(initial_root_password file)", port: 80, protocol: "http", notes: "Password in /etc/gitlab/initial_root_password", cve: null },
  { vendor: "Gogs", product: "Gogs", category: "web-apps", username: "admin", password: "(set on install)", port: 3000, protocol: "http", notes: "Self-hosted Git service", cve: null },
  { vendor: "Gitea", product: "Gitea", category: "web-apps", username: "admin", password: "(set on install)", port: 3000, protocol: "http", notes: "Lightweight Git service (Gogs fork)", cve: null },
  { vendor: "Minio", product: "MinIO", category: "web-apps", username: "minioadmin", password: "minioadmin", port: 9000, protocol: "http", notes: "S3-compatible object storage", cve: null },
  { vendor: "RabbitMQ", product: "RabbitMQ", category: "web-apps", username: "guest", password: "guest", port: 15672, protocol: "http", notes: "Management UI — only allows localhost by default", cve: null },
  { vendor: "Apache", product: "ActiveMQ", category: "web-apps", username: "admin", password: "admin", port: 8161, protocol: "http", notes: "Web console", cve: "CVE-2023-46604" },

  // ============================================================================
  // PRINTERS
  // ============================================================================
  { vendor: "HP", product: "LaserJet", category: "printers", username: "admin", password: "", port: 80, protocol: "http", notes: "Embedded Web Server — often no password", cve: null },
  { vendor: "HP", product: "OfficeJet Pro", category: "printers", username: "admin", password: "admin", port: 80, protocol: "http", notes: "Varies by model", cve: null },
  { vendor: "Canon", product: "imageRUNNER", category: "printers", username: "7654321", password: "7654321", port: 80, protocol: "http", notes: "Default system manager ID and PIN", cve: null },
  { vendor: "Epson", product: "WorkForce", category: "printers", username: "EPSONWEB", password: "admin", port: 80, protocol: "http", notes: "EpsonNet web config", cve: null },
  { vendor: "Brother", product: "HL/MFC Series", category: "printers", username: "admin", password: "access", port: 80, protocol: "http", notes: "Brother web interface default", cve: null },
  { vendor: "Xerox", product: "WorkCentre", category: "printers", username: "admin", password: "1111", port: 80, protocol: "http", notes: "Xerox multifunction printer", cve: null },
  { vendor: "Lexmark", product: "Laser Printers", category: "printers", username: "", password: "", port: 80, protocol: "http", notes: "No default credentials — set on first access", cve: null },
  { vendor: "Samsung", product: "Xpress Series", category: "printers", username: "admin", password: "sec00000", port: 80, protocol: "http", notes: "Samsung/HP printer firmware", cve: null },
  { vendor: "Ricoh", product: "MP Series", category: "printers", username: "admin", password: "", port: 80, protocol: "http", notes: "Blank password default", cve: null },
  { vendor: "Konica Minolta", product: "bizhub", category: "printers", username: "admin", password: "12345678", port: 80, protocol: "http", notes: "Admin password for web interface", cve: null },

  // ============================================================================
  // BMC / IPMI / iLO / iDRAC
  // ============================================================================
  { vendor: "HP", product: "iLO (Integrated Lights-Out)", category: "bmc-ipmi", username: "Administrator", password: "(on tag)", port: 443, protocol: "https", notes: "Default password printed on server pull tag", cve: null },
  { vendor: "Dell", product: "iDRAC", category: "bmc-ipmi", username: "root", password: "calvin", port: 443, protocol: "https", notes: "iDRAC 6/7/8/9 default", cve: null },
  { vendor: "Lenovo", product: "IMM/XCC", category: "bmc-ipmi", username: "USERID", password: "PASSW0RD", port: 443, protocol: "https", notes: "Lenovo Integrated Management Module / XClarity", cve: null },
  { vendor: "Supermicro", product: "IPMI BMC", category: "bmc-ipmi", username: "ADMIN", password: "ADMIN", port: 623, protocol: "ipmi", notes: "Supermicro baseboard management", cve: "CVE-2013-3619" },
  { vendor: "IPMI", product: "Generic IPMI", category: "bmc-ipmi", username: "admin", password: "admin", port: 623, protocol: "ipmi", notes: "Many IPMI implementations use this default", cve: null },
  { vendor: "Cisco", product: "CIMC", category: "bmc-ipmi", username: "admin", password: "password", port: 443, protocol: "https", notes: "Cisco Integrated Management Controller", cve: null },

  // ============================================================================
  // INDUSTRIAL / SCADA / ICS
  // ============================================================================
  { vendor: "Siemens", product: "S7 PLC", category: "industrial", username: "", password: "", port: 102, protocol: "s7comm", notes: "No authentication by default — S7-300/400/1200/1500", cve: null },
  { vendor: "Siemens", product: "SCALANCE", category: "industrial", username: "admin", password: "admin", port: 443, protocol: "https", notes: "Industrial network switch", cve: null },
  { vendor: "Schneider Electric", product: "Modicon PLC", category: "industrial", username: "USER", password: "USER", port: 502, protocol: "modbus", notes: "Modicon M340/M580 — Modbus TCP", cve: null },
  { vendor: "Allen-Bradley", product: "ControlLogix", category: "industrial", username: "", password: "", port: 44818, protocol: "ethernet/ip", notes: "No auth by default — CIP protocol", cve: null },
  { vendor: "ABB", product: "AC500 PLC", category: "industrial", username: "admin", password: "admin", port: 80, protocol: "http", notes: "ABB Automation Builder web interface", cve: null },
  { vendor: "GE", product: "GE Fanuc", category: "industrial", username: "", password: "", port: 18245, protocol: "srtp", notes: "GE SRTP protocol — no auth", cve: null },
  { vendor: "Mitsubishi", product: "MELSEC", category: "industrial", username: "", password: "", port: 5007, protocol: "melsec", notes: "MELSEC communication — no auth", cve: null },
  { vendor: "Omron", product: "CJ/NJ PLC", category: "industrial", username: "", password: "", port: 9600, protocol: "fins", notes: "FINS/TCP protocol — no auth by default", cve: null },
  { vendor: "Beckhoff", product: "TwinCAT", category: "industrial", username: "Administrator", password: "1", port: 48898, protocol: "ads", notes: "TwinCAT ADS route — Windows login", cve: null },
  { vendor: "Rockwell", product: "FactoryTalk", category: "industrial", username: "admin", password: "admin", port: 80, protocol: "http", notes: "FactoryTalk administration", cve: null },

  // ============================================================================
  // IoT DEVICES
  // ============================================================================
  { vendor: "Samsung", product: "SmartThings Hub", category: "iot", username: "", password: "", port: 0, protocol: "app", notes: "Cloud-managed via SmartThings app", cve: null },
  { vendor: "Philips", product: "Hue Bridge", category: "iot", username: "", password: "", port: 80, protocol: "http", notes: "Physical button pairing — API key from /api", cve: null },
  { vendor: "TP-Link", product: "Kasa Smart Plug", category: "iot", username: "", password: "", port: 9999, protocol: "proprietary", notes: "Cloud-bound — local control via port 9999", cve: null },
  { vendor: "Sonoff", product: "Smart Switch", category: "iot", username: "admin", password: "admin", port: 80, protocol: "http", notes: "Tasmota/custom firmware web interface", cve: null },
  { vendor: "Synology", product: "DiskStation NAS", category: "iot", username: "admin", password: "(set on install)", port: 5000, protocol: "http", notes: "DSM web interface — forced password on setup", cve: null },
  { vendor: "QNAP", product: "QTS NAS", category: "iot", username: "admin", password: "admin", port: 8080, protocol: "http", notes: "QNAP NAS default", cve: "CVE-2021-28799" },
  { vendor: "Western Digital", product: "My Cloud", category: "iot", username: "admin", password: "", port: 80, protocol: "http", notes: "WD My Cloud NAS — blank password", cve: "CVE-2018-17153" },
  { vendor: "Raspberry Pi", product: "Raspberry Pi OS", category: "iot", username: "pi", password: "raspberry", port: 22, protocol: "ssh", notes: "Default until 2022 — now requires setup", cve: null },
  { vendor: "Arduino", product: "Arduino IoT Cloud", category: "iot", username: "", password: "", port: 0, protocol: "cloud", notes: "Managed via Arduino Cloud", cve: null },
  { vendor: "Espressif", product: "ESP32/ESP8266", category: "iot", username: "", password: "", port: 80, protocol: "http", notes: "No default — depends on firmware flashed", cve: null },

  // ============================================================================
  // VPN APPLIANCES
  // ============================================================================
  { vendor: "OpenVPN", product: "OpenVPN Access Server", category: "vpn", username: "openvpn", password: "(set on install)", port: 943, protocol: "https", notes: "Admin UI on port 943", cve: null },
  { vendor: "Fortinet", product: "FortiClient EMS", category: "vpn", username: "admin", password: "", port: 443, protocol: "https", notes: "Endpoint management server", cve: null },
  { vendor: "Pulse Secure", product: "Pulse Connect Secure", category: "vpn", username: "admin", password: "", port: 443, protocol: "https", notes: "No default — set during initial config", cve: "CVE-2021-22893" },
  { vendor: "Cisco", product: "AnyConnect/ASA", category: "vpn", username: "admin", password: "admin", port: 443, protocol: "https", notes: "ASA ASDM interface", cve: null },
  { vendor: "WireGuard", product: "WireGuard", category: "vpn", username: "", password: "", port: 51820, protocol: "udp", notes: "Key-based auth only — no usernames/passwords", cve: null },

  // ============================================================================
  // VoIP SYSTEMS
  // ============================================================================
  { vendor: "Asterisk", product: "Asterisk PBX", category: "voip", username: "admin", password: "amp111", port: 80, protocol: "http", notes: "FreePBX web interface default", cve: null },
  { vendor: "3CX", product: "3CX Phone System", category: "voip", username: "admin", password: "(set on install)", port: 5001, protocol: "https", notes: "3CX management console", cve: "CVE-2023-29059" },
  { vendor: "Cisco", product: "CUCM", category: "voip", username: "admin", password: "admin", port: 443, protocol: "https", notes: "Cisco Unified Communications Manager", cve: null },
  { vendor: "Yealink", product: "IP Phone", category: "voip", username: "admin", password: "admin", port: 80, protocol: "http", notes: "Yealink T-series desk phones", cve: null },
  { vendor: "Polycom", product: "VVX Phone", category: "voip", username: "Polycom", password: "456", port: 80, protocol: "http", notes: "Polycom VVX series — user password is 123", cve: null },
  { vendor: "Grandstream", product: "GXP Phone", category: "voip", username: "admin", password: "admin", port: 80, protocol: "http", notes: "Grandstream IP phones", cve: null },

  // ============================================================================
  // NETWORK MANAGEMENT / SNMP
  // ============================================================================
  { vendor: "SNMP", product: "SNMP v1/v2c", category: "network-management", username: "", password: "public", port: 161, protocol: "snmp", notes: "Default read community string", cve: null },
  { vendor: "SNMP", product: "SNMP v1/v2c (write)", category: "network-management", username: "", password: "private", port: 161, protocol: "snmp", notes: "Default write community string", cve: null },
  { vendor: "Cacti", product: "Cacti", category: "network-management", username: "admin", password: "admin", port: 80, protocol: "http", notes: "Network monitoring/graphing", cve: null },
  { vendor: "LibreNMS", product: "LibreNMS", category: "network-management", username: "admin", password: "(set on install)", port: 80, protocol: "http", notes: "Auto-discovery network monitoring", cve: null },
  { vendor: "Observium", product: "Observium", category: "network-management", username: "admin", password: "(set on install)", port: 80, protocol: "http", notes: "Network monitoring platform", cve: null },
  { vendor: "Netbox", product: "NetBox", category: "network-management", username: "admin", password: "admin", port: 80, protocol: "http", notes: "IPAM/DCIM tool by NetBox Labs", cve: null },
  { vendor: "ManageEngine", product: "OpManager", category: "network-management", username: "admin", password: "admin", port: 8060, protocol: "http", notes: "ManageEngine network monitoring", cve: null },
  { vendor: "Splunk", product: "Splunk Enterprise", category: "network-management", username: "admin", password: "changeme", port: 8000, protocol: "http", notes: "Splunk web interface default", cve: null },
];

export const CREDENTIAL_STATS = {
  total: DEFAULT_CREDENTIALS.length,
  by_category: CREDENTIAL_CATEGORIES.reduce((acc, cat) => {
    acc[cat] = DEFAULT_CREDENTIALS.filter(c => c.category === cat).length;
    return acc;
  }, {}),
};
