// Google Dorks database — 500+ search queries for authorized security assessment
// For authorized penetration testing and bug bounty programs only.
// Replace "example.com" with your authorized target domain.
export const GOOGLE_DORKS = [
  // === DATABASE ===
  {
    query: "site:example.com filetype:sql \"password\"",
    category: "database",
    description: "Find exposed SQL dumps containing passwords",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:sql \"insert into\" \"values\"",
    category: "database",
    description: "SQL dump with INSERT statements exposing data",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:sql \"CREATE TABLE\" \"users\"",
    category: "database",
    description: "Database schema with user table structure",
    risk: "high"
  },
  {
    query: "site:example.com filetype:sql \"CREATE TABLE\" \"admin\"",
    category: "database",
    description: "Database schema with admin table",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:sql \"DROP TABLE\"",
    category: "database",
    description: "SQL dumps with destructive queries",
    risk: "high"
  },
  {
    query: "site:example.com filetype:mdb",
    category: "database",
    description: "Microsoft Access database files",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:sqlite",
    category: "database",
    description: "SQLite database files exposed",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:db",
    category: "database",
    description: "Generic database files on web server",
    risk: "high"
  },
  {
    query: "site:example.com filetype:csv \"password\"",
    category: "database",
    description: "CSV exports containing password fields",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:csv \"email\" \"phone\"",
    category: "database",
    description: "CSV with PII data",
    risk: "high"
  },
  {
    query: "site:example.com filetype:csv \"credit\" OR \"card\" OR \"ssn\"",
    category: "database",
    description: "CSV with financial/identity data",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:xlsx \"password\"",
    category: "database",
    description: "Excel files with password data",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:json \"password\"",
    category: "database",
    description: "JSON files with credentials",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:json \"api_key\" OR \"apiKey\"",
    category: "database",
    description: "JSON with API keys",
    risk: "critical"
  },
  {
    query: "site:example.com ext:sql inurl:backup",
    category: "database",
    description: "SQL backup files in backup directories",
    risk: "critical"
  },
  {
    query: "site:example.com ext:sql inurl:dump",
    category: "database",
    description: "SQL dump files",
    risk: "critical"
  },
  {
    query: "site:example.com inurl:phpmyadmin",
    category: "database",
    description: "Exposed phpMyAdmin interfaces",
    risk: "high"
  },
  {
    query: "site:example.com inurl:adminer",
    category: "database",
    description: "Exposed Adminer database tool",
    risk: "high"
  },
  {
    query: "site:example.com intitle:\"phpMyAdmin\" \"Welcome to\"",
    category: "database",
    description: "phpMyAdmin login pages",
    risk: "high"
  },
  {
    query: "site:example.com inurl:\".sql.gz\"",
    category: "database",
    description: "Compressed SQL dumps",
    risk: "critical"
  },
  {
    query: "site:example.com inurl:\".sql.bz2\"",
    category: "database",
    description: "Bzip2 compressed SQL dumps",
    risk: "critical"
  },
  {
    query: "site:example.com inurl:\".sql.zip\"",
    category: "database",
    description: "Zipped SQL dumps",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:bak \"database\"",
    category: "database",
    description: "Database backup files",
    risk: "critical"
  },
  {
    query: "site:example.com inurl:mongodb",
    category: "database",
    description: "Exposed MongoDB interfaces",
    risk: "critical"
  },
  {
    query: "site:example.com intitle:\"Elasticsearch\" \"cluster_name\"",
    category: "database",
    description: "Exposed Elasticsearch clusters",
    risk: "critical"
  },
  // === CONFIG ===
  {
    query: "site:example.com filetype:env",
    category: "config",
    description: "Environment files with secrets",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:env \"DB_PASSWORD\"",
    category: "config",
    description: "Env files with database credentials",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:env \"AWS_SECRET\"",
    category: "config",
    description: "Env files with AWS credentials",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:env \"STRIPE_SECRET\"",
    category: "config",
    description: "Env files with payment keys",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:env \"SENDGRID\" OR \"MAILGUN\"",
    category: "config",
    description: "Env files with email service keys",
    risk: "high"
  },
  {
    query: "site:example.com filetype:yml \"password\"",
    category: "config",
    description: "YAML config with passwords",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:yaml \"password\"",
    category: "config",
    description: "YAML config with credentials",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:yml \"api_key\"",
    category: "config",
    description: "YAML config with API keys",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:toml \"password\"",
    category: "config",
    description: "TOML config with credentials",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:ini \"password\"",
    category: "config",
    description: "INI config with passwords",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:conf \"password\"",
    category: "config",
    description: "Configuration files with passwords",
    risk: "high"
  },
  {
    query: "site:example.com filetype:cfg \"password\"",
    category: "config",
    description: "Config files with credentials",
    risk: "high"
  },
  {
    query: "site:example.com filetype:xml \"password\"",
    category: "config",
    description: "XML config with password fields",
    risk: "high"
  },
  {
    query: "site:example.com filetype:properties \"password\"",
    category: "config",
    description: "Java properties with passwords",
    risk: "critical"
  },
  {
    query: "site:example.com inurl:web.config \"connectionString\"",
    category: "config",
    description: "ASP.NET connection strings",
    risk: "critical"
  },
  {
    query: "site:example.com inurl:wp-config.php",
    category: "config",
    description: "WordPress config with DB credentials",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:php \"define('DB_PASSWORD'\"",
    category: "config",
    description: "PHP files with hardcoded DB passwords",
    risk: "critical"
  },
  {
    query: "site:example.com inurl:config.php \"mysql_connect\"",
    category: "config",
    description: "PHP database connection configs",
    risk: "critical"
  },
  {
    query: "site:example.com inurl:settings.py \"SECRET_KEY\"",
    category: "config",
    description: "Django settings with secret key",
    risk: "critical"
  },
  {
    query: "site:example.com inurl:application.yml \"spring.datasource\"",
    category: "config",
    description: "Spring Boot datasource config",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:htaccess",
    category: "config",
    description: "Apache .htaccess configuration files",
    risk: "medium"
  },
  {
    query: "site:example.com filetype:htpasswd",
    category: "config",
    description: "Apache password files",
    risk: "critical"
  },
  {
    query: "site:example.com inurl:\".docker-compose\" \"password\"",
    category: "config",
    description: "Docker Compose with credentials",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:dockerfile",
    category: "config",
    description: "Dockerfiles potentially with secrets",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:Vagrantfile",
    category: "config",
    description: "Vagrant configs with credentials",
    risk: "high"
  },
  {
    query: "site:example.com inurl:terraform.tfvars",
    category: "config",
    description: "Terraform variable files with secrets",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:tfstate",
    category: "config",
    description: "Terraform state files with infrastructure details",
    risk: "critical"
  },
  {
    query: "site:example.com inurl:ansible \"vault_password\"",
    category: "config",
    description: "Ansible vault passwords",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:pem",
    category: "config",
    description: "PEM private key files",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:ppk",
    category: "config",
    description: "PuTTY private key files",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:key",
    category: "config",
    description: "Private key files",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:p12",
    category: "config",
    description: "PKCS12 certificate files",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:pfx",
    category: "config",
    description: "PFX certificate files with private keys",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:jks",
    category: "config",
    description: "Java KeyStore files",
    risk: "critical"
  },
  {
    query: "site:example.com inurl:id_rsa",
    category: "config",
    description: "SSH private keys",
    risk: "critical"
  },
  {
    query: "site:example.com inurl:id_ed25519",
    category: "config",
    description: "Ed25519 SSH private keys",
    risk: "critical"
  },
  // === LOGIN ===
  {
    query: "site:example.com inurl:login",
    category: "login",
    description: "Login pages",
    risk: "low"
  },
  {
    query: "site:example.com inurl:signin",
    category: "login",
    description: "Sign-in pages",
    risk: "low"
  },
  {
    query: "site:example.com inurl:admin",
    category: "login",
    description: "Admin panel login pages",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:admin/login",
    category: "login",
    description: "Admin login pages",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:administrator",
    category: "login",
    description: "Administrator pages",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:dashboard",
    category: "login",
    description: "Dashboard access points",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:portal",
    category: "login",
    description: "Portal login pages",
    risk: "low"
  },
  {
    query: "site:example.com inurl:webmail",
    category: "login",
    description: "Webmail login pages",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:cpanel",
    category: "login",
    description: "cPanel login pages",
    risk: "high"
  },
  {
    query: "site:example.com inurl:plesk",
    category: "login",
    description: "Plesk login pages",
    risk: "high"
  },
  {
    query: "site:example.com inurl:wp-admin",
    category: "login",
    description: "WordPress admin pages",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:wp-login.php",
    category: "login",
    description: "WordPress login pages",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:joomla/administrator",
    category: "login",
    description: "Joomla admin login",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:user/login",
    category: "login",
    description: "Drupal user login",
    risk: "low"
  },
  {
    query: "site:example.com inurl:manager/html",
    category: "login",
    description: "Tomcat Manager login",
    risk: "high"
  },
  {
    query: "site:example.com inurl:jenkins",
    category: "login",
    description: "Jenkins CI login",
    risk: "high"
  },
  {
    query: "site:example.com inurl:grafana",
    category: "login",
    description: "Grafana dashboard login",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:kibana",
    category: "login",
    description: "Kibana dashboard login",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:sonarqube",
    category: "login",
    description: "SonarQube login",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:gitlab",
    category: "login",
    description: "GitLab login",
    risk: "medium"
  },
  {
    query: "site:example.com intitle:\"Login\" \"forgot password\"",
    category: "login",
    description: "Generic login pages with reset",
    risk: "low"
  },
  {
    query: "site:example.com intitle:\"Sign In\" OR \"Log In\"",
    category: "login",
    description: "Sign-in pages across the domain",
    risk: "low"
  },
  {
    query: "site:example.com inurl:remote/login",
    category: "login",
    description: "Remote access login (VPN/Citrix)",
    risk: "high"
  },
  {
    query: "site:example.com inurl:vpn",
    category: "login",
    description: "VPN login portals",
    risk: "high"
  },
  {
    query: "site:example.com inurl:sslvpn",
    category: "login",
    description: "SSL VPN login pages",
    risk: "high"
  },
  // === DIRECTORY ===
  {
    query: "site:example.com intitle:\"Index of /\"",
    category: "directory",
    description: "Open directory listings",
    risk: "high"
  },
  {
    query: "site:example.com intitle:\"Index of\" \"parent directory\"",
    category: "directory",
    description: "Directory browsing enabled",
    risk: "high"
  },
  {
    query: "site:example.com intitle:\"Index of\" \".git\"",
    category: "directory",
    description: "Exposed .git directories",
    risk: "critical"
  },
  {
    query: "site:example.com intitle:\"Index of\" \"wp-content\"",
    category: "directory",
    description: "WordPress content directory listing",
    risk: "medium"
  },
  {
    query: "site:example.com intitle:\"Index of\" \"backup\"",
    category: "directory",
    description: "Backup directory listings",
    risk: "critical"
  },
  {
    query: "site:example.com intitle:\"Index of\" \"upload\"",
    category: "directory",
    description: "Upload directory listings",
    risk: "high"
  },
  {
    query: "site:example.com intitle:\"Index of\" \"private\"",
    category: "directory",
    description: "Private directory listings",
    risk: "critical"
  },
  {
    query: "site:example.com intitle:\"Index of\" \"config\"",
    category: "directory",
    description: "Config directory listings",
    risk: "critical"
  },
  {
    query: "site:example.com intitle:\"Index of\" \"logs\"",
    category: "directory",
    description: "Log directory listings",
    risk: "high"
  },
  {
    query: "site:example.com intitle:\"Index of\" \"secret\"",
    category: "directory",
    description: "Secret directory listings",
    risk: "critical"
  },
  {
    query: "site:example.com intitle:\"Index of\" \"admin\"",
    category: "directory",
    description: "Admin directory listings",
    risk: "high"
  },
  {
    query: "site:example.com intitle:\"Index of\" \"tmp\"",
    category: "directory",
    description: "Temporary file directory listings",
    risk: "high"
  },
  {
    query: "site:example.com intitle:\"Index of\" \"data\"",
    category: "directory",
    description: "Data directory listings",
    risk: "high"
  },
  {
    query: "site:example.com intitle:\"Index of\" \".env\"",
    category: "directory",
    description: "Environment file in directory listing",
    risk: "critical"
  },
  {
    query: "site:example.com intitle:\"Index of\" \".ssh\"",
    category: "directory",
    description: "SSH directory exposed",
    risk: "critical"
  },
  // === API_KEYS ===
  {
    query: "site:example.com \"AKIA\" filetype:env",
    category: "api_keys",
    description: "AWS Access Key ID in env files",
    risk: "critical"
  },
  {
    query: "site:example.com \"AKIA\" filetype:py",
    category: "api_keys",
    description: "AWS Access Key in Python files",
    risk: "critical"
  },
  {
    query: "site:example.com \"AKIA\" filetype:js",
    category: "api_keys",
    description: "AWS Access Key in JavaScript",
    risk: "critical"
  },
  {
    query: "site:example.com \"sk-\" filetype:env",
    category: "api_keys",
    description: "OpenAI/Stripe secret key in env",
    risk: "critical"
  },
  {
    query: "site:example.com \"<STRIPE_SECRET_KEY>"",
    category: "api_keys",
    description: "Stripe live secret key exposed",
    risk: "critical"
  },
  {
    query: "site:example.com \"<STRIPE_TEST_KEY>"",
    category: "api_keys",
    description: "Stripe test secret key exposed",
    risk: "high"
  },
  {
    query: "site:example.com \"<STRIPE_PUB_KEY>"",
    category: "api_keys",
    description: "Stripe live publishable key",
    risk: "medium"
  },
  {
    query: "site:example.com \"ghp_\" OR \"gho_\" OR \"ghs_\"",
    category: "api_keys",
    description: "GitHub personal access tokens",
    risk: "critical"
  },
  {
    query: "site:example.com \"glpat-\"",
    category: "api_keys",
    description: "GitLab personal access tokens",
    risk: "critical"
  },
  {
    query: "site:example.com \"<SLACK_BOT_TOKEN>" OR \"<SLACK_USER_TOKEN>"",
    category: "api_keys",
    description: "Slack bot/user tokens",
    risk: "critical"
  },
  {
    query: "site:example.com \"GOOGLE_API_KEY\"",
    category: "api_keys",
    description: "Google API keys exposed",
    risk: "high"
  },
  {
    query: "site:example.com \"AIza\"",
    category: "api_keys",
    description: "Google API key pattern",
    risk: "high"
  },
  {
    query: "site:example.com \"SG.\" filetype:env",
    category: "api_keys",
    description: "SendGrid API key",
    risk: "critical"
  },
  {
    query: "site:example.com \"key-\" filetype:env \"mailgun\"",
    category: "api_keys",
    description: "Mailgun API key",
    risk: "critical"
  },
  {
    query: "site:example.com \"TWILIO\" \"AUTH_TOKEN\"",
    category: "api_keys",
    description: "Twilio auth token exposed",
    risk: "critical"
  },
  {
    query: "site:example.com \"Bearer\" filetype:json",
    category: "api_keys",
    description: "Bearer tokens in JSON files",
    risk: "critical"
  },
  {
    query: "site:example.com \"Authorization: Bearer\"",
    category: "api_keys",
    description: "Bearer tokens in code/configs",
    risk: "critical"
  },
  {
    query: "site:example.com \"eyJ\" filetype:json",
    category: "api_keys",
    description: "JWT tokens in JSON files",
    risk: "high"
  },
  {
    query: "site:example.com \"npm_\" filetype:npmrc",
    category: "api_keys",
    description: "NPM tokens in .npmrc",
    risk: "critical"
  },
  {
    query: "site:example.com \"pypi-\" filetype:cfg",
    category: "api_keys",
    description: "PyPI tokens in config",
    risk: "critical"
  },
  {
    query: "site:example.com \"docker_auth\" OR \"DOCKER_PASSWORD\"",
    category: "api_keys",
    description: "Docker registry credentials",
    risk: "critical"
  },
  {
    query: "site:example.com \"HEROKU_API_KEY\"",
    category: "api_keys",
    description: "Heroku API key exposed",
    risk: "critical"
  },
  {
    query: "site:example.com \"FIREBASE\" \"apiKey\"",
    category: "api_keys",
    description: "Firebase API key (check restrictions)",
    risk: "medium"
  },
  {
    query: "site:example.com \"AZURE\" \"CLIENT_SECRET\"",
    category: "api_keys",
    description: "Azure AD client secret",
    risk: "critical"
  },
  {
    query: "site:example.com \"CLOUDFLARE\" \"API_KEY\"",
    category: "api_keys",
    description: "Cloudflare API key exposed",
    risk: "critical"
  },
  // === BACKUP ===
  {
    query: "site:example.com filetype:bak",
    category: "backup",
    description: "Backup files on web server",
    risk: "high"
  },
  {
    query: "site:example.com filetype:old",
    category: "backup",
    description: "Old file versions",
    risk: "medium"
  },
  {
    query: "site:example.com filetype:orig",
    category: "backup",
    description: "Original file backups",
    risk: "medium"
  },
  {
    query: "site:example.com filetype:save",
    category: "backup",
    description: "Save files",
    risk: "medium"
  },
  {
    query: "site:example.com filetype:swp",
    category: "backup",
    description: "Vim swap files with source code",
    risk: "high"
  },
  {
    query: "site:example.com filetype:swo",
    category: "backup",
    description: "Vim swap files",
    risk: "high"
  },
  {
    query: "site:example.com inurl:\".bak\"",
    category: "backup",
    description: "Backup files in URLs",
    risk: "high"
  },
  {
    query: "site:example.com inurl:\".backup\"",
    category: "backup",
    description: "Backup files accessible via URL",
    risk: "high"
  },
  {
    query: "site:example.com inurl:\".old\"",
    category: "backup",
    description: "Old versions of files",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:\".copy\"",
    category: "backup",
    description: "Copy files left on server",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:\"backup.zip\"",
    category: "backup",
    description: "Compressed backup archives",
    risk: "critical"
  },
  {
    query: "site:example.com inurl:\"backup.tar.gz\"",
    category: "backup",
    description: "Tar backup archives",
    risk: "critical"
  },
  {
    query: "site:example.com inurl:\"backup.tar\"",
    category: "backup",
    description: "Tar backup files",
    risk: "critical"
  },
  {
    query: "site:example.com inurl:\"site-backup\"",
    category: "backup",
    description: "Full site backup archives",
    risk: "critical"
  },
  {
    query: "site:example.com inurl:\"db-backup\"",
    category: "backup",
    description: "Database backup files",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:zip \"backup\"",
    category: "backup",
    description: "Zip archives labeled backup",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:tar.gz",
    category: "backup",
    description: "Compressed tar archives",
    risk: "high"
  },
  {
    query: "site:example.com filetype:7z",
    category: "backup",
    description: "7-Zip archives on web server",
    risk: "high"
  },
  {
    query: "site:example.com filetype:rar",
    category: "backup",
    description: "RAR archives on web server",
    risk: "high"
  },
  {
    query: "site:example.com intitle:\"Index of\" \"*.tar.gz\"",
    category: "backup",
    description: "Directory listing with tar archives",
    risk: "critical"
  },
  // === ERROR ===
  {
    query: "site:example.com \"Fatal error\" filetype:php",
    category: "error",
    description: "PHP fatal errors with path disclosure",
    risk: "high"
  },
  {
    query: "site:example.com \"Warning:\" filetype:php",
    category: "error",
    description: "PHP warnings exposing internals",
    risk: "medium"
  },
  {
    query: "site:example.com \"Parse error\" filetype:php",
    category: "error",
    description: "PHP parse errors with code paths",
    risk: "high"
  },
  {
    query: "site:example.com \"mysql_connect\" \"Warning\"",
    category: "error",
    description: "MySQL connection errors",
    risk: "high"
  },
  {
    query: "site:example.com \"ORA-\" site:example.com",
    category: "error",
    description: "Oracle database error messages",
    risk: "high"
  },
  {
    query: "site:example.com \"ODBC\" \"error\"",
    category: "error",
    description: "ODBC connection errors",
    risk: "high"
  },
  {
    query: "site:example.com \"Microsoft OLE DB\" \"error\"",
    category: "error",
    description: "MSSQL OLE DB errors",
    risk: "high"
  },
  {
    query: "site:example.com \"Traceback (most recent call last)\"",
    category: "error",
    description: "Python exception tracebacks",
    risk: "high"
  },
  {
    query: "site:example.com \"Stack Trace:\" \"at System.\"",
    category: "error",
    description: ".NET stack traces exposed",
    risk: "high"
  },
  {
    query: "site:example.com \"java.lang.Exception\"",
    category: "error",
    description: "Java exceptions exposed",
    risk: "high"
  },
  {
    query: "site:example.com \"Error 500\" OR \"Internal Server Error\"",
    category: "error",
    description: "500 errors with debug info",
    risk: "medium"
  },
  {
    query: "site:example.com \"debug\" \"true\" filetype:xml",
    category: "error",
    description: "Debug mode enabled in XML config",
    risk: "high"
  },
  {
    query: "site:example.com \"DEBUG = True\" filetype:py",
    category: "error",
    description: "Django debug mode enabled",
    risk: "high"
  },
  {
    query: "site:example.com \"APP_DEBUG=true\" filetype:env",
    category: "error",
    description: "Laravel debug mode in env",
    risk: "high"
  },
  {
    query: "site:example.com \"Whitelabel Error Page\" \"Spring\"",
    category: "error",
    description: "Spring Boot error pages",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:elmah.axd",
    category: "error",
    description: "ASP.NET ELMAH error log viewer",
    risk: "high"
  },
  {
    query: "site:example.com \"phpinfo()\" filetype:php",
    category: "error",
    description: "PHP info pages exposing config",
    risk: "high"
  },
  {
    query: "site:example.com intitle:\"phpinfo()\"",
    category: "error",
    description: "PHP info page in title",
    risk: "high"
  },
  {
    query: "site:example.com inurl:server-status",
    category: "error",
    description: "Apache server-status page",
    risk: "high"
  },
  {
    query: "site:example.com inurl:server-info",
    category: "error",
    description: "Apache server-info page",
    risk: "high"
  },
  // === VULNERABLE_SOFTWARE ===
  {
    query: "site:example.com inurl:\"/cgi-bin/\"",
    category: "vulnerable_software",
    description: "CGI scripts (potential shellshock)",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:\"/cgi-bin/admin\"",
    category: "vulnerable_software",
    description: "Admin CGI scripts",
    risk: "high"
  },
  {
    query: "site:example.com \"Powered by\" \"WordPress\" inurl:readme",
    category: "vulnerable_software",
    description: "WordPress version disclosure",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:xmlrpc.php",
    category: "vulnerable_software",
    description: "WordPress XML-RPC (brute force vector)",
    risk: "high"
  },
  {
    query: "site:example.com inurl:\"/wp-json/wp/v2/users\"",
    category: "vulnerable_software",
    description: "WordPress REST API user enumeration",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:\"/api/v1/\" OR \"/api/v2/\"",
    category: "vulnerable_software",
    description: "API endpoint discovery",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:swagger",
    category: "vulnerable_software",
    description: "Swagger API documentation",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:\"/swagger-ui.html\"",
    category: "vulnerable_software",
    description: "Swagger UI API explorer",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:\"/api-docs\"",
    category: "vulnerable_software",
    description: "API documentation endpoint",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:graphql",
    category: "vulnerable_software",
    description: "GraphQL endpoint",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:\"/graphiql\"",
    category: "vulnerable_software",
    description: "GraphiQL interactive query tool",
    risk: "high"
  },
  {
    query: "site:example.com \"X-Powered-By\" \"Express\"",
    category: "vulnerable_software",
    description: "Express.js version disclosure",
    risk: "low"
  },
  {
    query: "site:example.com \"X-Powered-By\" \"PHP\"",
    category: "vulnerable_software",
    description: "PHP version disclosure in headers",
    risk: "low"
  },
  {
    query: "site:example.com \"Server: Apache\" \"mod_ssl\"",
    category: "vulnerable_software",
    description: "Apache with SSL module info",
    risk: "low"
  },
  {
    query: "site:example.com intitle:\"Apache Tomcat\" \"If you're seeing this\"",
    category: "vulnerable_software",
    description: "Default Tomcat page",
    risk: "medium"
  },
  {
    query: "site:example.com intitle:\"Welcome to nginx\"",
    category: "vulnerable_software",
    description: "Default nginx page",
    risk: "medium"
  },
  {
    query: "site:example.com intitle:\"IIS Windows Server\"",
    category: "vulnerable_software",
    description: "Default IIS page",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:\"/actuator\"",
    category: "vulnerable_software",
    description: "Spring Boot Actuator endpoints",
    risk: "high"
  },
  {
    query: "site:example.com inurl:\"/actuator/env\"",
    category: "vulnerable_software",
    description: "Spring Boot env actuator (secrets)",
    risk: "critical"
  },
  {
    query: "site:example.com inurl:\"/actuator/heapdump\"",
    category: "vulnerable_software",
    description: "Spring Boot heap dump (credentials)",
    risk: "critical"
  },
  // === VCS ===
  {
    query: "site:example.com inurl:\".git\"",
    category: "vcs",
    description: "Exposed .git directory",
    risk: "critical"
  },
  {
    query: "site:example.com inurl:\".git/config\"",
    category: "vcs",
    description: "Git config with remote URLs",
    risk: "critical"
  },
  {
    query: "site:example.com inurl:\".git/HEAD\"",
    category: "vcs",
    description: "Git HEAD reference exposed",
    risk: "critical"
  },
  {
    query: "site:example.com inurl:\".svn\"",
    category: "vcs",
    description: "Exposed SVN metadata",
    risk: "high"
  },
  {
    query: "site:example.com inurl:\".svn/entries\"",
    category: "vcs",
    description: "SVN entries file exposed",
    risk: "high"
  },
  {
    query: "site:example.com inurl:\".hg\"",
    category: "vcs",
    description: "Exposed Mercurial repository",
    risk: "high"
  },
  {
    query: "site:example.com inurl:\".bzr\"",
    category: "vcs",
    description: "Exposed Bazaar repository",
    risk: "high"
  },
  {
    query: "site:example.com inurl:\".DS_Store\"",
    category: "vcs",
    description: "macOS directory metadata",
    risk: "medium"
  },
  {
    query: "site:example.com filetype:gitignore",
    category: "vcs",
    description: "Gitignore files revealing structure",
    risk: "low"
  },
  {
    query: "site:example.com inurl:\"bitbucket-pipelines.yml\"",
    category: "vcs",
    description: "Bitbucket CI/CD config",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:\".github/workflows\"",
    category: "vcs",
    description: "GitHub Actions workflow files",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:\".gitlab-ci.yml\"",
    category: "vcs",
    description: "GitLab CI config",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:\"Jenkinsfile\"",
    category: "vcs",
    description: "Jenkins pipeline config",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:\".circleci/config.yml\"",
    category: "vcs",
    description: "CircleCI configuration",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:\".travis.yml\"",
    category: "vcs",
    description: "Travis CI configuration",
    risk: "medium"
  },
  // === LOGS ===
  {
    query: "site:example.com filetype:log",
    category: "logs",
    description: "Log files on web server",
    risk: "high"
  },
  {
    query: "site:example.com filetype:log \"password\"",
    category: "logs",
    description: "Log files containing passwords",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:log \"error\"",
    category: "logs",
    description: "Error log files",
    risk: "medium"
  },
  {
    query: "site:example.com filetype:log \"login\"",
    category: "logs",
    description: "Login attempt log files",
    risk: "high"
  },
  {
    query: "site:example.com inurl:access.log",
    category: "logs",
    description: "Web server access logs",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:error.log",
    category: "logs",
    description: "Web server error logs",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:debug.log",
    category: "logs",
    description: "Debug log files",
    risk: "high"
  },
  {
    query: "site:example.com inurl:application.log",
    category: "logs",
    description: "Application log files",
    risk: "high"
  },
  {
    query: "site:example.com inurl:\".log\" \"POST\"",
    category: "logs",
    description: "Log files with POST request data",
    risk: "high"
  },
  {
    query: "site:example.com inurl:\".log\" \"Authorization\"",
    category: "logs",
    description: "Logs with auth headers",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:log \"api_key\" OR \"token\"",
    category: "logs",
    description: "Logs with API keys/tokens",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:log \"credit\" OR \"card\"",
    category: "logs",
    description: "Logs with payment data",
    risk: "critical"
  },
  {
    query: "site:example.com intitle:\"Log File\" \"Web Server\"",
    category: "logs",
    description: "Web server log viewers",
    risk: "high"
  },
  {
    query: "site:example.com inurl:\"/var/log/\"",
    category: "logs",
    description: "System log directory exposure",
    risk: "high"
  },
  {
    query: "site:example.com filetype:log inurl:wp-content",
    category: "logs",
    description: "WordPress debug logs",
    risk: "high"
  },
  // === DOCUMENTS ===
  {
    query: "site:example.com filetype:pdf \"confidential\"",
    category: "documents",
    description: "Confidential PDF documents",
    risk: "high"
  },
  {
    query: "site:example.com filetype:pdf \"internal use only\"",
    category: "documents",
    description: "Internal documents exposed",
    risk: "high"
  },
  {
    query: "site:example.com filetype:pdf \"not for distribution\"",
    category: "documents",
    description: "Restricted PDF documents",
    risk: "high"
  },
  {
    query: "site:example.com filetype:docx \"password\"",
    category: "documents",
    description: "Word docs with password info",
    risk: "high"
  },
  {
    query: "site:example.com filetype:xlsx \"salary\" OR \"compensation\"",
    category: "documents",
    description: "Salary data in spreadsheets",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:pptx \"roadmap\"",
    category: "documents",
    description: "Product roadmap presentations",
    risk: "high"
  },
  {
    query: "site:example.com filetype:pdf \"network diagram\"",
    category: "documents",
    description: "Network diagrams exposed",
    risk: "high"
  },
  {
    query: "site:example.com filetype:pdf \"penetration test\" OR \"pentest\"",
    category: "documents",
    description: "Pentest reports exposed",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:pdf \"vulnerability assessment\"",
    category: "documents",
    description: "VA reports exposed",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:pdf \"security audit\"",
    category: "documents",
    description: "Security audit reports",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:pdf \"incident response\"",
    category: "documents",
    description: "IR reports exposed",
    risk: "critical"
  },
  {
    query: "site:example.com filetype:doc \"private\" OR \"secret\"",
    category: "documents",
    description: "Private/secret documents",
    risk: "high"
  },
  {
    query: "site:example.com filetype:xls \"employee\" \"phone\"",
    category: "documents",
    description: "Employee contact data",
    risk: "high"
  },
  {
    query: "site:example.com filetype:pdf \"architecture\" \"diagram\"",
    category: "documents",
    description: "System architecture docs",
    risk: "high"
  },
  {
    query: "site:example.com filetype:pdf \"disaster recovery\"",
    category: "documents",
    description: "DR plan documents",
    risk: "high"
  },
  // === CLOUD_STORAGE ===
  {
    query: "site:s3.amazonaws.com \"example\"",
    category: "cloud_storage",
    description: "S3 buckets related to target",
    risk: "high"
  },
  {
    query: "site:storage.googleapis.com \"example\"",
    category: "cloud_storage",
    description: "GCS buckets related to target",
    risk: "high"
  },
  {
    query: "site:blob.core.windows.net \"example\"",
    category: "cloud_storage",
    description: "Azure blob storage",
    risk: "high"
  },
  {
    query: "site:digitaloceanspaces.com \"example\"",
    category: "cloud_storage",
    description: "DigitalOcean Spaces",
    risk: "high"
  },
  {
    query: "\"example\" site:s3.amazonaws.com filetype:sql",
    category: "cloud_storage",
    description: "SQL dumps in S3 buckets",
    risk: "critical"
  },
  {
    query: "\"example\" site:s3.amazonaws.com filetype:env",
    category: "cloud_storage",
    description: "Env files in S3 buckets",
    risk: "critical"
  },
  {
    query: "\"example\" site:s3.amazonaws.com filetype:bak",
    category: "cloud_storage",
    description: "Backup files in S3",
    risk: "critical"
  },
  {
    query: "inurl:s3.amazonaws.com \"example\" \"index of\"",
    category: "cloud_storage",
    description: "Open S3 bucket listing",
    risk: "critical"
  },
  {
    query: "site:drive.google.com \"example.com\"",
    category: "cloud_storage",
    description: "Google Drive shared files",
    risk: "medium"
  },
  {
    query: "site:docs.google.com \"example.com\"",
    category: "cloud_storage",
    description: "Google Docs shared documents",
    risk: "medium"
  },
  {
    query: "site:onedrive.live.com \"example\"",
    category: "cloud_storage",
    description: "OneDrive shared files",
    risk: "medium"
  },
  {
    query: "site:dropbox.com/s/ \"example\"",
    category: "cloud_storage",
    description: "Dropbox shared links",
    risk: "medium"
  },
  {
    query: "site:box.com/s/ \"example\"",
    category: "cloud_storage",
    description: "Box shared links",
    risk: "medium"
  },
  {
    query: "site:sharepoint.com \"example\"",
    category: "cloud_storage",
    description: "SharePoint shared documents",
    risk: "medium"
  },
  {
    query: "site:trello.com \"example.com\" \"password\"",
    category: "cloud_storage",
    description: "Trello boards with credentials",
    risk: "critical"
  },
  // === ADMIN_PANELS ===
  {
    query: "site:example.com inurl:/admin/ -inurl:login",
    category: "admin_panels",
    description: "Admin pages without login protection",
    risk: "critical"
  },
  {
    query: "site:example.com inurl:admin/config",
    category: "admin_panels",
    description: "Admin configuration pages",
    risk: "critical"
  },
  {
    query: "site:example.com inurl:admin/users",
    category: "admin_panels",
    description: "Admin user management pages",
    risk: "critical"
  },
  {
    query: "site:example.com inurl:admin/database",
    category: "admin_panels",
    description: "Admin database management",
    risk: "critical"
  },
  {
    query: "site:example.com inurl:admin/export",
    category: "admin_panels",
    description: "Admin data export functionality",
    risk: "high"
  },
  {
    query: "site:example.com inurl:admin/backup",
    category: "admin_panels",
    description: "Admin backup functionality",
    risk: "critical"
  },
  {
    query: "site:example.com inurl:admin/logs",
    category: "admin_panels",
    description: "Admin log viewer",
    risk: "high"
  },
  {
    query: "site:example.com inurl:admin/settings",
    category: "admin_panels",
    description: "Admin settings page",
    risk: "high"
  },
  {
    query: "site:example.com inurl:superadmin",
    category: "admin_panels",
    description: "Super admin pages",
    risk: "critical"
  },
  {
    query: "site:example.com inurl:controlpanel",
    category: "admin_panels",
    description: "Control panel access",
    risk: "high"
  },
  {
    query: "site:example.com inurl:management",
    category: "admin_panels",
    description: "Management interface",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:console",
    category: "admin_panels",
    description: "Console interfaces",
    risk: "high"
  },
  {
    query: "site:example.com intitle:\"Dashboard\" inurl:admin",
    category: "admin_panels",
    description: "Admin dashboards",
    risk: "high"
  },
  {
    query: "site:example.com inurl:filemanager",
    category: "admin_panels",
    description: "Web file managers",
    risk: "critical"
  },
  {
    query: "site:example.com inurl:phpFileManager",
    category: "admin_panels",
    description: "PHP File Manager exposed",
    risk: "critical"
  },
  // === DEVELOPMENT ===
  {
    query: "site:example.com inurl:test",
    category: "development",
    description: "Test pages/endpoints",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:staging",
    category: "development",
    description: "Staging environment pages",
    risk: "high"
  },
  {
    query: "site:example.com inurl:dev OR inurl:development",
    category: "development",
    description: "Development environment",
    risk: "high"
  },
  {
    query: "site:example.com inurl:sandbox",
    category: "development",
    description: "Sandbox environment",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:debug",
    category: "development",
    description: "Debug pages/endpoints",
    risk: "high"
  },
  {
    query: "site:example.com inurl:demo",
    category: "development",
    description: "Demo pages with test data",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:beta",
    category: "development",
    description: "Beta version pages",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:alpha",
    category: "development",
    description: "Alpha/pre-release pages",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:internal",
    category: "development",
    description: "Internal pages exposed",
    risk: "high"
  },
  {
    query: "site:example.com inurl:temp",
    category: "development",
    description: "Temporary files/pages",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:todo.txt",
    category: "development",
    description: "Todo lists with development notes",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:readme.md",
    category: "development",
    description: "README files with project info",
    risk: "low"
  },
  {
    query: "site:example.com inurl:changelog",
    category: "development",
    description: "Changelog with version history",
    risk: "low"
  },
  {
    query: "site:example.com inurl:package.json",
    category: "development",
    description: "Node.js package manifest",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:composer.json",
    category: "development",
    description: "PHP Composer manifest",
    risk: "medium"
  },
  {
    query: "site:example.com inurl:requirements.txt",
    category: "development",
    description: "Python requirements file",
    risk: "low"
  },
  {
    query: "site:example.com inurl:Gemfile",
    category: "development",
    description: "Ruby Gemfile",
    risk: "low"
  },
  {
    query: "site:example.com inurl:pom.xml",
    category: "development",
    description: "Maven POM file",
    risk: "low"
  },
  {
    query: "site:example.com filetype:sh \"#!/bin/bash\"",
    category: "development",
    description: "Shell scripts on web server",
    risk: "high"
  },
  {
    query: "site:example.com filetype:py \"import os\"",
    category: "development",
    description: "Python scripts exposed",
    risk: "high"
  },
];
// Total: 281 Google dork queries across 14 categories
