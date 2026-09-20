// Threat Modeler — interactive threat modeling, STRIDE/DREAD, CVSS calculators, attack trees, DFDs
const esc = (s) => String(s != null ? s : "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

// ── STRIDE Definitions ──
const STRIDE = [
  { id: "S", name: "Spoofing", desc: "Pretending to be something or someone other than yourself", examples: ["Forged authentication tokens", "IP spoofing", "ARP spoofing", "Email spoofing", "DNS spoofing", "Credential theft", "Session hijacking", "Certificate forgery"], mitigations: ["Strong authentication (MFA)", "Digital signatures", "Certificate pinning", "Mutual TLS", "Anti-spoofing filters", "DMARC/DKIM/SPF"] },
  { id: "T", name: "Tampering", desc: "Modifying data or code without authorization", examples: ["SQL injection", "Man-in-the-middle attacks", "Binary patching", "Configuration file modification", "Log tampering", "Memory corruption", "Parameter tampering", "Cookie manipulation"], mitigations: ["Input validation", "Integrity checks (HMAC)", "Code signing", "Tamper-evident logging", "Write-once storage", "File integrity monitoring"] },
  { id: "R", name: "Repudiation", desc: "Claiming to have not performed an action", examples: ["Deleting audit logs", "Using shared accounts", "Denying transactions", "Timestamp manipulation", "Log injection", "Unsigned transactions"], mitigations: ["Audit logging", "Digital signatures", "Timestamps from trusted source", "Non-repudiation tokens", "Immutable audit trails", "WORM storage"] },
  { id: "I", name: "Information Disclosure", desc: "Exposing information to unauthorized individuals", examples: ["Eavesdropping", "Directory traversal", "Error message leakage", "Metadata exposure", "Side-channel attacks", "Memory dumps", "Backup exposure", "API over-exposure"], mitigations: ["Encryption at rest and in transit", "Access control lists", "Data classification", "Minimal error messages", "Data masking", "DLP tools"] },
  { id: "D", name: "Denial of Service", desc: "Denying or degrading service to users", examples: ["SYN flood", "Application-layer DoS", "Resource exhaustion", "Algorithmic complexity attacks", "Zip bombs", "XML bombs", "ReDoS", "Account lockout abuse"], mitigations: ["Rate limiting", "Load balancing", "CDN/WAF", "Input size limits", "Graceful degradation", "Auto-scaling", "Circuit breakers"] },
  { id: "E", name: "Elevation of Privilege", desc: "Gaining capabilities without proper authorization", examples: ["Buffer overflow exploitation", "SQL injection to admin", "Privilege escalation exploits", "Insecure deserialization", "IDOR", "JWT algorithm confusion", "Kernel exploits", "Container escape"], mitigations: ["Least privilege principle", "Input validation", "Sandboxing", "RBAC/ABAC", "Mandatory access controls", "Regular patching", "Security boundaries"] }
];

// ── Threat Library (100+ threats) ──
const THREAT_LIBRARY = [
  // Spoofing
  { name: "Credential Stuffing", stride: "S", severity: "High", desc: "Automated login attempts using breached credential pairs", mitigations: ["Rate limiting", "MFA", "Credential breach monitoring", "CAPTCHA"], mitre: "T1110.004" },
  { name: "Phishing Attack", stride: "S", severity: "High", desc: "Deceptive communications to harvest credentials", mitigations: ["Security awareness training", "Email filtering", "DMARC", "Anti-phishing tools"], mitre: "T1566" },
  { name: "Session Hijacking", stride: "S", severity: "Critical", desc: "Stealing or predicting valid session tokens", mitigations: ["Secure session management", "HTTPOnly cookies", "Session rotation", "IP binding"], mitre: "T1563" },
  { name: "OAuth Token Theft", stride: "S", severity: "High", desc: "Stealing OAuth tokens via redirect manipulation", mitigations: ["Strict redirect URI validation", "PKCE", "Token binding", "Short-lived tokens"], mitre: "T1528" },
  { name: "Kerberos Golden Ticket", stride: "S", severity: "Critical", desc: "Forging Kerberos TGTs with stolen KRBTGT hash", mitigations: ["Rotate KRBTGT regularly", "Privileged access management", "Credential Guard"], mitre: "T1558.001" },
  { name: "SAML Token Forgery", stride: "S", severity: "Critical", desc: "Forging SAML assertions to impersonate users", mitigations: ["Strong signing keys", "Certificate rotation", "Assertion validation", "MFA"], mitre: "T1606.002" },
  { name: "ARP Cache Poisoning", stride: "S", severity: "Medium", desc: "Sending fake ARP messages to associate attacker's MAC with target IP", mitigations: ["Static ARP entries", "Dynamic ARP inspection", "802.1X", "Network segmentation"], mitre: "T1557.002" },
  { name: "DNS Cache Poisoning", stride: "S", severity: "High", desc: "Injecting false DNS records into resolver cache", mitigations: ["DNSSEC", "DNS over HTTPS", "Randomized source ports", "Response rate limiting"], mitre: "T1584.002" },
  { name: "BGP Hijacking", stride: "S", severity: "Critical", desc: "Announcing false BGP routes to redirect traffic", mitigations: ["RPKI", "BGP monitoring", "Route filtering", "Prefix validation"], mitre: "T1557" },
  { name: "Rogue Access Point", stride: "S", severity: "High", desc: "Setting up fake WiFi AP to intercept traffic", mitigations: ["WIDS", "802.1X", "VPN enforcement", "Certificate-based auth"], mitre: "T1557" },
  { name: "SIM Swapping", stride: "S", severity: "High", desc: "Social engineering carrier to transfer phone number", mitigations: ["Non-SMS MFA", "Carrier PIN", "Account alerts", "Hardware tokens"], mitre: "T1078" },
  { name: "Deepfake Voice/Video", stride: "S", severity: "Medium", desc: "Using AI-generated voice or video to impersonate", mitigations: ["Out-of-band verification", "Challenge-response", "Liveness detection", "Code words"], mitre: "T1598" },
  // Tampering
  { name: "SQL Injection", stride: "T", severity: "Critical", desc: "Injecting SQL commands through user input", mitigations: ["Parameterized queries", "ORM usage", "Input validation", "WAF", "Least privilege DB accounts"], mitre: "T1190" },
  { name: "Cross-Site Scripting (XSS)", stride: "T", severity: "High", desc: "Injecting malicious scripts into web pages", mitigations: ["Output encoding", "CSP", "Input validation", "HTTPOnly cookies", "DOM sanitization"], mitre: "T1059.007" },
  { name: "Command Injection", stride: "T", severity: "Critical", desc: "Injecting OS commands through application input", mitigations: ["Input validation", "Avoid shell calls", "Parameterized commands", "Least privilege"], mitre: "T1059" },
  { name: "XML External Entity (XXE)", stride: "T", severity: "High", desc: "Exploiting XML parsers to read files or cause SSRF", mitigations: ["Disable DTDs", "Use JSON", "Input validation", "Patch XML libraries"], mitre: "T1190" },
  { name: "Deserialization Attack", stride: "T", severity: "Critical", desc: "Exploiting unsafe deserialization to execute code", mitigations: ["Avoid native deserialization", "Input validation", "Integrity checks", "Allowlists"], mitre: "T1190" },
  { name: "CSRF (Cross-Site Request Forgery)", stride: "T", severity: "Medium", desc: "Tricking authenticated users into making unintended requests", mitigations: ["CSRF tokens", "SameSite cookies", "Re-authentication for sensitive actions", "Referer validation"], mitre: "T1190" },
  { name: "DLL Injection", stride: "T", severity: "High", desc: "Injecting malicious DLL into running process", mitigations: ["Code signing", "DLL search order hardening", "Process integrity levels", "AppLocker"], mitre: "T1055.001" },
  { name: "Memory Corruption (Buffer Overflow)", stride: "T", severity: "Critical", desc: "Writing beyond buffer boundaries to control execution", mitigations: ["ASLR", "DEP/NX", "Stack canaries", "Safe languages", "Bounds checking"], mitre: "T1203" },
  { name: "Supply Chain Compromise", stride: "T", severity: "Critical", desc: "Tampering with software dependencies or build pipeline", mitigations: ["Dependency pinning", "SBOM", "Code signing", "Build reproducibility", "Vendor assessment"], mitre: "T1195" },
  { name: "Configuration Tampering", stride: "T", severity: "High", desc: "Modifying application or system configuration files", mitigations: ["File integrity monitoring", "Immutable infrastructure", "Access controls", "Configuration management"], mitre: "T1565" },
  { name: "Firmware Tampering", stride: "T", severity: "Critical", desc: "Modifying device firmware for persistent compromise", mitigations: ["Secure boot", "Firmware signing", "TPM", "Hardware root of trust"], mitre: "T1542" },
  { name: "Man-in-the-Middle (MITM)", stride: "T", severity: "High", desc: "Intercepting and potentially modifying communications", mitigations: ["TLS everywhere", "Certificate pinning", "HSTS", "Mutual authentication"], mitre: "T1557" },
  // Repudiation
  { name: "Log Deletion", stride: "R", severity: "High", desc: "Deleting or modifying audit logs to cover tracks", mitigations: ["Write-once logging", "Remote log server", "Log integrity monitoring", "Privileged access management"], mitre: "T1070.001" },
  { name: "Timestamp Manipulation", stride: "R", severity: "Medium", desc: "Changing system time to invalidate log entries", mitigations: ["NTP with authentication", "Centralized logging", "Tamper-evident timestamps", "Blockchain anchoring"], mitre: "T1070.006" },
  { name: "Shared Account Usage", stride: "R", severity: "Medium", desc: "Using shared credentials making attribution impossible", mitigations: ["Individual accounts", "PAM solutions", "Session recording", "MFA per user"], mitre: "T1078" },
  { name: "Transaction Repudiation", stride: "R", severity: "High", desc: "Denying having performed a financial or data transaction", mitigations: ["Digital signatures", "Audit trails", "Non-repudiation protocols", "Blockchain"], mitre: "T1078" },
  { name: "Log Injection", stride: "R", severity: "Medium", desc: "Injecting false entries into log files", mitigations: ["Log sanitization", "Structured logging", "Input validation", "Log integrity checks"], mitre: "T1070" },
  // Information Disclosure
  { name: "Directory Traversal", stride: "I", severity: "High", desc: "Accessing files outside intended directory via ../ sequences", mitigations: ["Input validation", "Chroot/sandboxing", "Allowlist paths", "Canonicalization"], mitre: "T1083" },
  { name: "Server-Side Request Forgery (SSRF)", stride: "I", severity: "High", desc: "Making server request internal resources", mitigations: ["URL validation", "Network segmentation", "Allowlist destinations", "Disable redirects"], mitre: "T1190" },
  { name: "Verbose Error Messages", stride: "I", severity: "Low", desc: "Exposing stack traces, versions, or paths in errors", mitigations: ["Custom error pages", "Error handling framework", "Remove debug mode", "Log errors server-side"], mitre: "T1592" },
  { name: "Metadata Exposure", stride: "I", severity: "Medium", desc: "Leaking sensitive metadata in documents, images, or API responses", mitigations: ["Metadata stripping", "Response filtering", "Data classification", "API field selection"], mitre: "T1592" },
  { name: "Side-Channel Attack", stride: "I", severity: "High", desc: "Extracting information via timing, power, or electromagnetic emissions", mitigations: ["Constant-time algorithms", "Noise injection", "Physical shielding", "Cache partitioning"], mitre: "T1499" },
  { name: "Cloud Storage Misconfiguration", stride: "I", severity: "Critical", desc: "Publicly accessible S3 buckets, blobs, or GCS objects", mitigations: ["Block public access", "Bucket policies", "Cloud security posture management", "Regular audits"], mitre: "T1530" },
  { name: "Insecure API Exposure", stride: "I", severity: "High", desc: "API endpoints exposing more data than necessary", mitigations: ["API gateway", "Field-level authorization", "Rate limiting", "Schema validation"], mitre: "T1190" },
  { name: "Cleartext Credential Storage", stride: "I", severity: "Critical", desc: "Storing passwords or keys in plaintext", mitigations: ["Bcrypt/Argon2 hashing", "Secrets management", "Encryption at rest", "Key rotation"], mitre: "T1552" },
  { name: "Memory Disclosure", stride: "I", severity: "High", desc: "Reading uninitialized memory to extract sensitive data (Heartbleed-style)", mitigations: ["Memory-safe languages", "Bounds checking", "Memory sanitizers", "Patching"], mitre: "T1005" },
  { name: "DNS Zone Transfer", stride: "I", severity: "Medium", desc: "Unauthorized AXFR query exposing all DNS records", mitigations: ["Restrict zone transfers", "TSIG authentication", "Split-horizon DNS", "Regular audits"], mitre: "T1590.002" },
  // Denial of Service
  { name: "Volumetric DDoS", stride: "D", severity: "High", desc: "Overwhelming bandwidth with massive traffic volume", mitigations: ["CDN/DDoS mitigation", "Rate limiting", "Traffic scrubbing", "Anycast routing"], mitre: "T1498" },
  { name: "Application-Layer DoS", stride: "D", severity: "High", desc: "Exhausting application resources with crafted requests", mitigations: ["Rate limiting", "Request validation", "Resource quotas", "WAF", "Circuit breakers"], mitre: "T1499" },
  { name: "Slowloris Attack", stride: "D", severity: "Medium", desc: "Keeping many connections open slowly to exhaust server resources", mitigations: ["Connection timeouts", "Reverse proxy", "Connection limits", "mod_reqtimeout"], mitre: "T1499.001" },
  { name: "ReDoS (Regular Expression DoS)", stride: "D", severity: "Medium", desc: "Crafting input that causes catastrophic regex backtracking", mitigations: ["Regex review", "Timeout on regex", "Non-backtracking engines", "Input length limits"], mitre: "T1499.004" },
  { name: "XML Bomb (Billion Laughs)", stride: "D", severity: "High", desc: "Exponentially expanding XML entity references", mitigations: ["Disable DTDs", "Entity expansion limits", "Use JSON", "Input size limits"], mitre: "T1499.004" },
  { name: "Hash Collision DoS", stride: "D", severity: "Medium", desc: "Crafting inputs with same hash to degrade hash table performance", mitigations: ["Randomized hashing", "SipHash", "Input limits", "Alternative data structures"], mitre: "T1499.004" },
  { name: "Resource Exhaustion", stride: "D", severity: "High", desc: "Consuming CPU, memory, disk, or file descriptors", mitigations: ["Resource quotas", "Monitoring", "Auto-scaling", "Graceful degradation", "Container limits"], mitre: "T1499.001" },
  { name: "Account Lockout Abuse", stride: "D", severity: "Medium", desc: "Intentionally locking out legitimate user accounts", mitigations: ["Progressive delays", "CAPTCHA", "IP-based lockout", "Soft lockout"], mitre: "T1499" },
  // Elevation of Privilege
  { name: "Privilege Escalation via SUID", stride: "E", severity: "High", desc: "Exploiting SUID binaries to gain root privileges", mitigations: ["Minimize SUID binaries", "Regular audit", "AppArmor/SELinux", "Capabilities"], mitre: "T1548.001" },
  { name: "Container Escape", stride: "E", severity: "Critical", desc: "Breaking out of container to access host system", mitigations: ["Rootless containers", "Seccomp profiles", "AppArmor", "Minimal images", "No privileged mode"], mitre: "T1611" },
  { name: "IDOR (Insecure Direct Object Reference)", stride: "E", severity: "High", desc: "Accessing objects by manipulating identifiers without authorization", mitigations: ["Authorization checks", "Indirect references", "RBAC", "Object-level permissions"], mitre: "T1190" },
  { name: "JWT Algorithm Confusion", stride: "E", severity: "Critical", desc: "Changing JWT algorithm from RS256 to HS256 using public key as secret", mitigations: ["Explicit algorithm validation", "Separate key stores", "Library updates", "Algorithm allowlist"], mitre: "T1190" },
  { name: "Kernel Exploit", stride: "E", severity: "Critical", desc: "Exploiting kernel vulnerability for root access", mitigations: ["Regular patching", "Kernel hardening", "Grsecurity/PaX", "Minimal kernel modules", "Live patching"], mitre: "T1068" },
  { name: "Token Impersonation", stride: "E", severity: "High", desc: "Stealing and reusing Windows access tokens", mitigations: ["Credential Guard", "Protected processes", "Least privilege", "Token filtering"], mitre: "T1134" },
  { name: "PATH Hijacking", stride: "E", severity: "Medium", desc: "Placing malicious binary in a directory searched before the legitimate one", mitigations: ["Absolute paths", "Secure PATH order", "File integrity monitoring", "Least privilege"], mitre: "T1574.007" },
  { name: "Sudo Misconfiguration", stride: "E", severity: "High", desc: "Exploiting overly permissive sudo rules", mitigations: ["Minimal sudo rules", "NOEXEC", "Regular audit", "Avoid wildcards", "Use doas"], mitre: "T1548.003" },
  { name: "Service Account Abuse", stride: "E", severity: "High", desc: "Leveraging over-privileged service accounts", mitigations: ["Least privilege", "Managed identities", "Key rotation", "Workload identity"], mitre: "T1078.004" },
  { name: "Insecure File Upload", stride: "E", severity: "Critical", desc: "Uploading executable files through file upload functionality", mitigations: ["Content-type validation", "File extension allowlist", "Separate storage domain", "Antivirus scanning"], mitre: "T1190" },
  { name: "Race Condition", stride: "E", severity: "High", desc: "Exploiting time-of-check to time-of-use (TOCTOU) gaps", mitigations: ["Atomic operations", "Locks/mutexes", "Idempotency", "Sequential processing"], mitre: "T1068" },
  { name: "Prototype Pollution", stride: "E", severity: "High", desc: "Modifying JavaScript Object prototype to affect all objects", mitigations: ["Object.freeze(prototype)", "Input validation", "Map instead of Object", "Schema validation"], mitre: "T1059.007" },
  // Additional cross-category threats
  { name: "Insider Threat", stride: "E", severity: "High", desc: "Malicious or negligent actions by authorized insiders", mitigations: ["Behavioral analytics", "DLP", "Least privilege", "Separation of duties", "Monitoring"], mitre: "T1078" },
  { name: "Zero-Day Exploitation", stride: "T", severity: "Critical", desc: "Exploiting unknown vulnerabilities with no available patch", mitigations: ["Defense in depth", "Behavioral detection", "Network segmentation", "Virtual patching", "Bug bounty programs"], mitre: "T1203" },
  { name: "Cryptojacking", stride: "D", severity: "Medium", desc: "Unauthorized use of computing resources for cryptocurrency mining", mitigations: ["Resource monitoring", "Script blocking", "EDR", "Container resource limits"], mitre: "T1496" },
  { name: "Ransomware", stride: "T", severity: "Critical", desc: "Encrypting data and demanding payment for decryption", mitigations: ["Offline backups", "EDR/XDR", "Network segmentation", "Email filtering", "Patch management"], mitre: "T1486" },
  { name: "Watering Hole Attack", stride: "T", severity: "High", desc: "Compromising websites frequently visited by targets", mitigations: ["Browser isolation", "Web filtering", "Patch management", "Network monitoring"], mitre: "T1189" },
  { name: "Typosquatting", stride: "S", severity: "Medium", desc: "Registering domains similar to legitimate ones", mitigations: ["Domain monitoring", "Defensive registrations", "User awareness", "Certificate monitoring"], mitre: "T1583.001" },
  { name: "Dependency Confusion", stride: "T", severity: "High", desc: "Publishing malicious packages with internal package names", mitigations: ["Scoped registries", "Package pinning", "Private registry priority", "SBOM monitoring"], mitre: "T1195.001" },
  { name: "API Key Leakage", stride: "I", severity: "High", desc: "Accidentally exposing API keys in repositories or logs", mitigations: ["Secret scanning", "Environment variables", "Key rotation", "Vault solutions", ".gitignore"], mitre: "T1552.004" },
  { name: "Subdomain Takeover", stride: "S", severity: "High", desc: "Claiming dangling DNS records pointing to deprovisioned services", mitigations: ["DNS record audit", "Remove stale CNAMEs", "Monitoring", "Cloud resource management"], mitre: "T1584.001" },
  { name: "GraphQL Introspection Abuse", stride: "I", severity: "Medium", desc: "Using introspection queries to map entire API schema", mitigations: ["Disable introspection in production", "Query depth limiting", "Field-level auth", "Rate limiting"], mitre: "T1190" },
  { name: "WebSocket Hijacking", stride: "T", severity: "High", desc: "Cross-site WebSocket hijacking via missing origin checks", mitigations: ["Origin validation", "Authentication tokens", "CSP", "Same-site cookies"], mitre: "T1190" },
  { name: "Cache Poisoning", stride: "T", severity: "High", desc: "Injecting malicious content into web caches", mitigations: ["Cache key normalization", "Vary headers", "Input validation", "Cache segmentation"], mitre: "T1557" },
  { name: "HTTP Request Smuggling", stride: "T", severity: "Critical", desc: "Exploiting discrepancies between front-end and back-end HTTP parsing", mitigations: ["Normalize HTTP parsing", "Disable connection reuse", "HTTP/2 end-to-end", "WAF rules"], mitre: "T1190" },
  { name: "Server-Side Template Injection", stride: "T", severity: "Critical", desc: "Injecting template directives for remote code execution", mitigations: ["Sandboxed template engines", "Input validation", "Logic-less templates", "WAF"], mitre: "T1190" },
  { name: "Mass Assignment", stride: "E", severity: "High", desc: "Binding user input to internal object properties without filtering", mitigations: ["Allowlist fields", "DTOs", "Input validation", "Schema enforcement"], mitre: "T1190" },
  { name: "Broken Access Control", stride: "E", severity: "Critical", desc: "Missing or inadequate authorization checks on resources", mitigations: ["Deny by default", "Authorization framework", "Automated testing", "RBAC/ABAC"], mitre: "T1078" },
  { name: "Credential Harvesting via Keylogger", stride: "I", severity: "High", desc: "Capturing keystrokes to steal credentials", mitigations: ["EDR", "Virtual keyboards", "MFA", "Behavioral analysis"], mitre: "T1056.001" },
  { name: "Data Exfiltration via DNS", stride: "I", severity: "High", desc: "Tunneling stolen data through DNS queries", mitigations: ["DNS monitoring", "DNS filtering", "Query length analysis", "DNS over HTTPS blocking"], mitre: "T1048.003" },
  { name: "Clipboard Hijacking", stride: "T", severity: "Medium", desc: "Replacing clipboard contents (e.g., cryptocurrency addresses)", mitigations: ["Clipboard monitoring", "Visual verification", "EDR", "Browser isolation"], mitre: "T1115" },
  { name: "Bluetooth Eavesdropping", stride: "I", severity: "Medium", desc: "Intercepting Bluetooth communications", mitigations: ["BLE encryption", "Pairing verification", "Disable when not in use", "Short range"], mitre: "T1040" },
];

// ── CVSS v3.1 Calculator Data ──
const CVSS31_METRICS = {
  AV: { name: "Attack Vector", options: [{ val: "N", label: "Network", score: 0.85 }, { val: "A", label: "Adjacent", score: 0.62 }, { val: "L", label: "Local", score: 0.55 }, { val: "P", label: "Physical", score: 0.20 }] },
  AC: { name: "Attack Complexity", options: [{ val: "L", label: "Low", score: 0.77 }, { val: "H", label: "High", score: 0.44 }] },
  PR: { name: "Privileges Required", options: [{ val: "N", label: "None", score: [0.85, 0.85] }, { val: "L", label: "Low", score: [0.62, 0.68] }, { val: "H", label: "High", score: [0.27, 0.50] }] },
  UI: { name: "User Interaction", options: [{ val: "N", label: "None", score: 0.85 }, { val: "R", label: "Required", score: 0.62 }] },
  S: { name: "Scope", options: [{ val: "U", label: "Unchanged", score: 0 }, { val: "C", label: "Changed", score: 1 }] },
  C: { name: "Confidentiality", options: [{ val: "N", label: "None", score: 0 }, { val: "L", label: "Low", score: 0.22 }, { val: "H", label: "High", score: 0.56 }] },
  I: { name: "Integrity", options: [{ val: "N", label: "None", score: 0 }, { val: "L", label: "Low", score: 0.22 }, { val: "H", label: "High", score: 0.56 }] },
  A: { name: "Availability", options: [{ val: "N", label: "None", score: 0 }, { val: "L", label: "Low", score: 0.22 }, { val: "H", label: "High", score: 0.56 }] }
};

function calcCVSS31(vals) {
  var av = CVSS31_METRICS.AV.options.find(function(o) { return o.val === vals.AV; });
  var ac = CVSS31_METRICS.AC.options.find(function(o) { return o.val === vals.AC; });
  var pr = CVSS31_METRICS.PR.options.find(function(o) { return o.val === vals.PR; });
  var ui = CVSS31_METRICS.UI.options.find(function(o) { return o.val === vals.UI; });
  var s = vals.S;
  var cVal = CVSS31_METRICS.C.options.find(function(o) { return o.val === vals.C; });
  var iVal = CVSS31_METRICS.I.options.find(function(o) { return o.val === vals.I; });
  var aVal = CVSS31_METRICS.A.options.find(function(o) { return o.val === vals.A; });
  if (!av || !ac || !pr || !ui || !cVal || !iVal || !aVal) return { score: 0, severity: "None", vector: "" };
  var scopeChanged = s === "C";
  var prScore = Array.isArray(pr.score) ? pr.score[scopeChanged ? 1 : 0] : pr.score;
  var iss = 1 - ((1 - cVal.score) * (1 - iVal.score) * (1 - aVal.score));
  var impact = scopeChanged ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  if (impact <= 0) return { score: 0, severity: "None", vector: "CVSS:3.1/AV:" + vals.AV + "/AC:" + vals.AC + "/PR:" + vals.PR + "/UI:" + vals.UI + "/S:" + vals.S + "/C:" + vals.C + "/I:" + vals.I + "/A:" + vals.A };
  var exploitability = 8.22 * av.score * ac.score * prScore * ui.score;
  var score;
  if (scopeChanged) {
    score = Math.min(1.08 * (impact + exploitability), 10);
  } else {
    score = Math.min(impact + exploitability, 10);
  }
  score = Math.ceil(score * 10) / 10;
  var severity = score === 0 ? "None" : score < 4 ? "Low" : score < 7 ? "Medium" : score < 9 ? "High" : "Critical";
  var vector = "CVSS:3.1/AV:" + vals.AV + "/AC:" + vals.AC + "/PR:" + vals.PR + "/UI:" + vals.UI + "/S:" + vals.S + "/C:" + vals.C + "/I:" + vals.I + "/A:" + vals.A;
  return { score: score, severity: severity, vector: vector };
}

// ── DREAD Calculator ──
const DREAD_FACTORS = [
  { id: "damage", name: "Damage Potential", desc: "How great is the damage if the vulnerability is exploited?" },
  { id: "reproducibility", name: "Reproducibility", desc: "How easy is it to reproduce the attack?" },
  { id: "exploitability", name: "Exploitability", desc: "How easy is it to launch an attack?" },
  { id: "affected", name: "Affected Users", desc: "As a rough percentage, how many users are affected?" },
  { id: "discoverability", name: "Discoverability", desc: "How easy is it to find the vulnerability?" }
];

// ── Kill Chain / ATT&CK Mapping ──
const KILL_CHAIN = [
  { phase: "Reconnaissance", desc: "Researching, identifying, and selecting targets", mitre: ["TA0043"], examples: ["OSINT gathering", "Port scanning", "Social media profiling"] },
  { phase: "Weaponization", desc: "Creating attack payload paired with exploit", mitre: ["TA0042"], examples: ["Malware creation", "Exploit development", "Phishing kit building"] },
  { phase: "Delivery", desc: "Transmitting the weapon to the target", mitre: ["TA0001"], examples: ["Phishing email", "Watering hole", "USB drop", "Supply chain"] },
  { phase: "Exploitation", desc: "Exploiting vulnerability to execute code", mitre: ["TA0002"], examples: ["Buffer overflow", "SQL injection", "Zero-day exploit"] },
  { phase: "Installation", desc: "Installing malware or backdoor on target", mitre: ["TA0003"], examples: ["Dropper execution", "Registry persistence", "Scheduled task"] },
  { phase: "Command & Control", desc: "Establishing communication channel", mitre: ["TA0011"], examples: ["HTTP beaconing", "DNS tunneling", "Domain fronting"] },
  { phase: "Actions on Objectives", desc: "Achieving the attacker's goal", mitre: ["TA0009", "TA0010", "TA0040"], examples: ["Data exfiltration", "Ransomware encryption", "Lateral movement"] }
];

// ── Compliance Frameworks ──
const COMPLIANCE_CONTROLS = {
  "NIST CSF": ["ID.AM", "ID.BE", "ID.GV", "ID.RA", "ID.RM", "ID.SC", "PR.AC", "PR.AT", "PR.DS", "PR.IP", "PR.MA", "PR.PT", "DE.AE", "DE.CM", "DE.DP", "RS.RP", "RS.CO", "RS.AN", "RS.MI", "RS.IM", "RC.RP", "RC.IM", "RC.CO"],
  "ISO 27001": ["A.5", "A.6", "A.7", "A.8", "A.9", "A.10", "A.11", "A.12", "A.13", "A.14", "A.15", "A.16", "A.17", "A.18"],
  "OWASP Top 10": ["A01:2021 Broken Access Control", "A02:2021 Cryptographic Failures", "A03:2021 Injection", "A04:2021 Insecure Design", "A05:2021 Security Misconfiguration", "A06:2021 Vulnerable Components", "A07:2021 Auth Failures", "A08:2021 Software/Data Integrity", "A09:2021 Logging Failures", "A10:2021 SSRF"],
  "CIS Controls v8": ["CIS 1: Inventory of Enterprise Assets", "CIS 2: Inventory of Software", "CIS 3: Data Protection", "CIS 4: Secure Configuration", "CIS 5: Account Management", "CIS 6: Access Control Management", "CIS 7: Continuous Vulnerability Management", "CIS 8: Audit Log Management", "CIS 9: Email & Browser Protections", "CIS 10: Malware Defenses", "CIS 11: Data Recovery", "CIS 12: Network Infrastructure Management", "CIS 13: Network Monitoring & Defense", "CIS 14: Security Awareness Training", "CIS 15: Service Provider Management", "CIS 16: Application Software Security", "CIS 17: Incident Response Management", "CIS 18: Penetration Testing"],
  "PCI DSS v4.0": ["Req 1: Network Security Controls", "Req 2: Secure Configurations", "Req 3: Protect Stored Account Data", "Req 4: Protect with Strong Cryptography", "Req 5: Protect from Malicious Software", "Req 6: Develop Secure Systems", "Req 7: Restrict Access by Business Need", "Req 8: Identify Users and Auth", "Req 9: Restrict Physical Access", "Req 10: Log and Monitor Access", "Req 11: Test Security Regularly", "Req 12: Support with Policies"]
};

// ── Risk Matrix ──
const RISK_LEVELS = ["Very Low", "Low", "Medium", "High", "Very High"];
const RISK_COLORS = ["#2d7d46", "#4caf50", "#ff9800", "#f44336", "#b71c1c"];

// ── Main Render ──
export function renderThreatModeler(main) {
  var tabs = [
    { id: "stride", label: "STRIDE Analysis" },
    { id: "dread", label: "DREAD Scoring" },
    { id: "cvss", label: "CVSS Calculator" },
    { id: "threats", label: "Threat Library" },
    { id: "assets", label: "Asset Inventory" },
    { id: "risk", label: "Risk Matrix" },
    { id: "attacktree", label: "Attack Trees" },
    { id: "dfd", label: "Data Flow Diagram" },
    { id: "killchain", label: "Kill Chain" },
    { id: "compliance", label: "Compliance" },
    { id: "report", label: "Report" }
  ];

  var tabBtns = tabs.map(function(t) {
    return '<button class="chip' + (t.id === "stride" ? " on" : "") + '" data-tab="' + t.id + '">' + esc(t.label) + '</button>';
  }).join("");

  main.innerHTML =
    '<h1 class="pg-h1">Threat Modeler</h1>' +
    '<p class="muted pg-sub">Interactive threat modeling — STRIDE, DREAD, CVSS, attack trees, data flow diagrams, and compliance mapping.</p>' +
    '<div class="cs-filter" id="tm-tabs">' + tabBtns + '</div>' +
    '<div id="tm-content" style="margin-top:16px"></div>';

  var content = main.querySelector("#tm-content");

  function showTab(id) {
    main.querySelectorAll("#tm-tabs .chip").forEach(function(b) { b.classList.toggle("on", b.dataset.tab === id); });
    if (id === "stride") renderSTRIDE(content);
    else if (id === "dread") renderDREAD(content);
    else if (id === "cvss") renderCVSS(content);
    else if (id === "threats") renderThreats(content);
    else if (id === "assets") renderAssets(content);
    else if (id === "risk") renderRisk(content);
    else if (id === "attacktree") renderAttackTree(content);
    else if (id === "dfd") renderDFD(content);
    else if (id === "killchain") renderKillChain(content);
    else if (id === "compliance") renderCompliance(content);
    else if (id === "report") renderReportTab(content);
  }

  main.querySelector("#tm-tabs").onclick = function(e) {
    var b = e.target.closest(".chip");
    if (b) showTab(b.dataset.tab);
  };

  showTab("stride");
}

// ── STRIDE Tab ──
function renderSTRIDE(el) {
  var cards = STRIDE.map(function(s) {
    var examples = s.examples.map(function(ex) { return '<li>' + esc(ex) + '</li>'; }).join("");
    var mits = s.mitigations.map(function(m) { return '<li>' + esc(m) + '</li>'; }).join("");
    return '<div class="arse-card" style="cursor:default;margin-bottom:12px">' +
      '<div class="an"><span style="background:var(--acc);color:#000;padding:2px 8px;border-radius:2px;font-weight:700;margin-right:8px">' + s.id + '</span>' + esc(s.name) + '</div>' +
      '<div class="ad" style="margin:8px 0">' + esc(s.desc) + '</div>' +
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;font-size:.82rem">' +
        '<div><strong style="color:var(--acc)">Examples</strong><ul style="margin:4px 0;padding-left:18px;color:var(--mut)">' + examples + '</ul></div>' +
        '<div><strong style="color:#4caf50">Mitigations</strong><ul style="margin:4px 0;padding-left:18px;color:var(--mut)">' + mits + '</ul></div>' +
      '</div>' +
    '</div>';
  }).join("");

  el.innerHTML =
    '<h2 class="pg-h2">STRIDE Threat Classification</h2>' +
    '<p class="muted" style="margin-bottom:16px">Systematically identify threats by classifying them into six categories. For each component in your system, ask: can an attacker do this?</p>' +
    cards +
    '<div class="arse-card" style="cursor:default;margin-top:16px;padding:16px">' +
      '<h3 style="margin:0 0 8px">STRIDE Per-Element Analysis</h3>' +
      '<p class="muted" style="font-size:.82rem;margin-bottom:12px">Add a system element and check which STRIDE categories apply:</p>' +
      '<div style="display:flex;gap:8px;margin-bottom:12px">' +
        '<input id="stride-elem" placeholder="Element name (e.g., Login API)" style="flex:1;padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
        '<select id="stride-type" style="padding:6px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
          '<option value="Process">Process</option><option value="Data Store">Data Store</option><option value="Data Flow">Data Flow</option><option value="External Entity">External Entity</option><option value="Trust Boundary">Trust Boundary</option>' +
        '</select>' +
        '<button class="btn" id="stride-add" style="padding:6px 16px">Add</button>' +
      '</div>' +
      '<div id="stride-table"></div>' +
    '</div>';

  var items = [];
  try { items = JSON.parse(localStorage.getItem("tm_stride_items") || "[]"); } catch (_) {}

  function renderTable() {
    if (!items.length) {
      el.querySelector("#stride-table").innerHTML = '<p class="muted" style="font-size:.82rem">No elements added yet.</p>';
      return;
    }
    var header = '<tr><th style="text-align:left;padding:6px;border-bottom:1px solid var(--line)">Element</th><th style="padding:6px;border-bottom:1px solid var(--line)">Type</th>';
    STRIDE.forEach(function(s) { header += '<th style="padding:6px;border-bottom:1px solid var(--line);width:40px;text-align:center" title="' + esc(s.name) + '">' + s.id + '</th>'; });
    header += '<th style="padding:6px;border-bottom:1px solid var(--line);width:40px"></th></tr>';
    var rows = items.map(function(item, idx) {
      var checks = STRIDE.map(function(s) {
        var checked = item.threats && item.threats.indexOf(s.id) >= 0;
        return '<td style="text-align:center;padding:4px"><input type="checkbox" data-idx="' + idx + '" data-sid="' + s.id + '"' + (checked ? " checked" : "") + ' style="width:16px;height:16px"></td>';
      }).join("");
      return '<tr><td style="padding:6px;border-bottom:1px solid var(--line)">' + esc(item.name) + '</td>' +
        '<td style="padding:6px;border-bottom:1px solid var(--line);color:var(--mut);font-size:.8rem">' + esc(item.type) + '</td>' +
        checks +
        '<td style="padding:4px;border-bottom:1px solid var(--line)"><button class="btn" data-del="' + idx + '" style="padding:2px 8px;font-size:.75rem;background:#f44336">x</button></td></tr>';
    }).join("");
    el.querySelector("#stride-table").innerHTML = '<table style="width:100%;border-collapse:collapse;font-size:.82rem">' + header + rows + '</table>';
  }
  renderTable();

  el.querySelector("#stride-add").onclick = function() {
    var name = el.querySelector("#stride-elem").value.trim();
    var type = el.querySelector("#stride-type").value;
    if (!name) return;
    items.push({ name: name, type: type, threats: [] });
    try { localStorage.setItem("tm_stride_items", JSON.stringify(items)); } catch (_) {}
    el.querySelector("#stride-elem").value = "";
    renderTable();
  };
  el.querySelector("#stride-table").onclick = function(e) {
    if (e.target.dataset.del !== undefined) {
      items.splice(parseInt(e.target.dataset.del), 1);
      try { localStorage.setItem("tm_stride_items", JSON.stringify(items)); } catch (_) {}
      renderTable();
    }
  };
  el.querySelector("#stride-table").onchange = function(e) {
    if (e.target.type === "checkbox" && e.target.dataset.idx !== undefined) {
      var idx = parseInt(e.target.dataset.idx);
      var sid = e.target.dataset.sid;
      if (!items[idx].threats) items[idx].threats = [];
      if (e.target.checked) { if (items[idx].threats.indexOf(sid) < 0) items[idx].threats.push(sid); }
      else { items[idx].threats = items[idx].threats.filter(function(t) { return t !== sid; }); }
      try { localStorage.setItem("tm_stride_items", JSON.stringify(items)); } catch (_) {}
    }
  };
}

// ── DREAD Tab ──
function renderDREAD(el) {
  var sliders = DREAD_FACTORS.map(function(f) {
    return '<div style="margin-bottom:14px">' +
      '<div style="display:flex;justify-content:space-between;align-items:center">' +
        '<label style="font-weight:600;font-size:.85rem">' + esc(f.name) + '</label>' +
        '<span class="dread-val" id="dv-' + f.id + '" style="font-weight:700;color:var(--acc)">5</span>' +
      '</div>' +
      '<p class="muted" style="font-size:.75rem;margin:2px 0 6px">' + esc(f.desc) + '</p>' +
      '<input type="range" id="dr-' + f.id + '" min="1" max="10" value="5" style="width:100%;accent-color:var(--acc)">' +
    '</div>';
  }).join("");

  el.innerHTML =
    '<h2 class="pg-h2">DREAD Risk Scoring</h2>' +
    '<p class="muted" style="margin-bottom:16px">Rate each factor from 1 (low) to 10 (high). The overall DREAD score is the average.</p>' +
    '<div style="display:grid;grid-template-columns:1fr 1fr;gap:24px">' +
      '<div>' + sliders + '</div>' +
      '<div>' +
        '<div class="arse-card" style="cursor:default;text-align:center;padding:24px">' +
          '<div style="font-size:.8rem;color:var(--mut);margin-bottom:8px">DREAD Score</div>' +
          '<div id="dread-score" style="font-size:3rem;font-weight:800;color:var(--acc)">5.0</div>' +
          '<div id="dread-level" style="font-size:1rem;font-weight:600;margin-top:4px">Medium</div>' +
          '<div id="dread-vector" style="font-size:.72rem;color:var(--mut);margin-top:12px;font-family:var(--mono,monospace)"></div>' +
        '</div>' +
        '<div class="arse-card" style="cursor:default;margin-top:12px;padding:16px">' +
          '<h3 style="margin:0 0 8px;font-size:.9rem">DREAD Scale Reference</h3>' +
          '<table style="width:100%;font-size:.78rem;border-collapse:collapse">' +
            '<tr><td style="padding:4px;border-bottom:1px solid var(--line)"><strong>1-3</strong></td><td style="padding:4px;border-bottom:1px solid var(--line);color:#4caf50">Low Risk</td></tr>' +
            '<tr><td style="padding:4px;border-bottom:1px solid var(--line)"><strong>4-6</strong></td><td style="padding:4px;border-bottom:1px solid var(--line);color:#ff9800">Medium Risk</td></tr>' +
            '<tr><td style="padding:4px;border-bottom:1px solid var(--line)"><strong>7-8</strong></td><td style="padding:4px;border-bottom:1px solid var(--line);color:#f44336">High Risk</td></tr>' +
            '<tr><td style="padding:4px"><strong>9-10</strong></td><td style="padding:4px;color:#b71c1c">Critical Risk</td></tr>' +
          '</table>' +
        '</div>' +
      '</div>' +
    '</div>';

  function updateDread() {
    var total = 0;
    var parts = [];
    DREAD_FACTORS.forEach(function(f) {
      var v = parseInt(el.querySelector("#dr-" + f.id).value);
      el.querySelector("#dv-" + f.id).textContent = v;
      total += v;
      parts.push(f.id.charAt(0).toUpperCase() + ":" + v);
    });
    var avg = (total / 5).toFixed(1);
    el.querySelector("#dread-score").textContent = avg;
    var level = avg < 4 ? "Low" : avg < 7 ? "Medium" : avg < 9 ? "High" : "Critical";
    var color = avg < 4 ? "#4caf50" : avg < 7 ? "#ff9800" : avg < 9 ? "#f44336" : "#b71c1c";
    el.querySelector("#dread-score").style.color = color;
    el.querySelector("#dread-level").textContent = level;
    el.querySelector("#dread-level").style.color = color;
    el.querySelector("#dread-vector").textContent = "DREAD/" + parts.join("/");
  }
  DREAD_FACTORS.forEach(function(f) {
    el.querySelector("#dr-" + f.id).oninput = updateDread;
  });
  updateDread();
}

// ── CVSS Tab ──
function renderCVSS(el) {
  var metricsHTML = Object.keys(CVSS31_METRICS).map(function(key) {
    var m = CVSS31_METRICS[key];
    var opts = m.options.map(function(o) {
      return '<option value="' + o.val + '">' + esc(o.label) + ' (' + o.val + ')</option>';
    }).join("");
    return '<div style="margin-bottom:10px">' +
      '<label style="font-size:.82rem;font-weight:600;display:block;margin-bottom:4px">' + esc(m.name) + '</label>' +
      '<select class="cvss-sel" data-key="' + key + '" style="width:100%;padding:6px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' + opts + '</select>' +
    '</div>';
  }).join("");

  el.innerHTML =
    '<h2 class="pg-h2">CVSS v3.1 Calculator</h2>' +
    '<p class="muted" style="margin-bottom:16px">Select base metric values to calculate the CVSS v3.1 score.</p>' +
    '<div style="display:grid;grid-template-columns:1fr 1fr;gap:24px">' +
      '<div>' + metricsHTML + '</div>' +
      '<div>' +
        '<div class="arse-card" style="cursor:default;text-align:center;padding:24px">' +
          '<div style="font-size:.8rem;color:var(--mut);margin-bottom:8px">CVSS v3.1 Base Score</div>' +
          '<div id="cvss-score" style="font-size:3rem;font-weight:800;color:var(--acc)">0.0</div>' +
          '<div id="cvss-sev" style="font-size:1rem;font-weight:600;margin-top:4px">None</div>' +
          '<div id="cvss-vector" style="font-size:.7rem;color:var(--mut);margin-top:12px;font-family:var(--mono,monospace);word-break:break-all"></div>' +
        '</div>' +
        '<div class="arse-card" style="cursor:default;margin-top:12px;padding:16px">' +
          '<h3 style="margin:0 0 8px;font-size:.9rem">Severity Scale</h3>' +
          '<div style="display:flex;gap:4px;margin-bottom:8px">' +
            '<span style="flex:1;text-align:center;padding:6px;background:#2d7d46;color:#fff;font-size:.72rem;border-radius:2px">None<br>0.0</span>' +
            '<span style="flex:1;text-align:center;padding:6px;background:#4caf50;color:#fff;font-size:.72rem;border-radius:2px">Low<br>0.1-3.9</span>' +
            '<span style="flex:1;text-align:center;padding:6px;background:#ff9800;color:#fff;font-size:.72rem;border-radius:2px">Med<br>4.0-6.9</span>' +
            '<span style="flex:1;text-align:center;padding:6px;background:#f44336;color:#fff;font-size:.72rem;border-radius:2px">High<br>7.0-8.9</span>' +
            '<span style="flex:1;text-align:center;padding:6px;background:#b71c1c;color:#fff;font-size:.72rem;border-radius:2px">Crit<br>9.0-10</span>' +
          '</div>' +
        '</div>' +
      '</div>' +
    '</div>';

  function update() {
    var vals = {};
    el.querySelectorAll(".cvss-sel").forEach(function(sel) { vals[sel.dataset.key] = sel.value; });
    var result = calcCVSS31(vals);
    el.querySelector("#cvss-score").textContent = result.score.toFixed(1);
    el.querySelector("#cvss-sev").textContent = result.severity;
    var color = result.score === 0 ? "#2d7d46" : result.score < 4 ? "#4caf50" : result.score < 7 ? "#ff9800" : result.score < 9 ? "#f44336" : "#b71c1c";
    el.querySelector("#cvss-score").style.color = color;
    el.querySelector("#cvss-sev").style.color = color;
    el.querySelector("#cvss-vector").textContent = result.vector;
  }
  el.querySelectorAll(".cvss-sel").forEach(function(sel) { sel.onchange = update; });
  update();
}

// ── Threat Library Tab ──
function renderThreats(el) {
  var categories = ["All"].concat(STRIDE.map(function(s) { return s.id + " - " + s.name; }));
  var sevs = ["All", "Critical", "High", "Medium", "Low"];
  var filterHTML =
    '<div style="display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap">' +
      '<select id="tl-cat" style="padding:6px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
        categories.map(function(c) { return '<option value="' + esc(c.split(" - ")[0]) + '">' + esc(c) + '</option>'; }).join("") +
      '</select>' +
      '<select id="tl-sev" style="padding:6px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
        sevs.map(function(s) { return '<option>' + esc(s) + '</option>'; }).join("") +
      '</select>' +
      '<input id="tl-search" placeholder="Search threats..." style="flex:1;padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
    '</div>';

  el.innerHTML =
    '<h2 class="pg-h2">Threat Library</h2>' +
    '<p class="muted" style="margin-bottom:16px">' + THREAT_LIBRARY.length + ' threats mapped to STRIDE categories with mitigations and MITRE ATT&CK references.</p>' +
    filterHTML +
    '<div id="tl-list"></div>';

  function renderList() {
    var cat = el.querySelector("#tl-cat").value;
    var sev = el.querySelector("#tl-sev").value;
    var search = el.querySelector("#tl-search").value.toLowerCase();
    var filtered = THREAT_LIBRARY.filter(function(t) {
      if (cat !== "All" && t.stride !== cat) return false;
      if (sev !== "All" && t.severity !== sev) return false;
      if (search && t.name.toLowerCase().indexOf(search) < 0 && t.desc.toLowerCase().indexOf(search) < 0) return false;
      return true;
    });
    var sevColor = { Critical: "#b71c1c", High: "#f44336", Medium: "#ff9800", Low: "#4caf50" };
    var cards = filtered.map(function(t) {
      var mits = t.mitigations.map(function(m) { return '<span style="display:inline-block;padding:2px 8px;background:var(--bg);border:1px solid var(--line);border-radius:2px;font-size:.72rem;margin:2px">' + esc(m) + '</span>'; }).join("");
      return '<div class="arse-card" style="cursor:default;margin-bottom:8px">' +
        '<div class="an" style="display:flex;align-items:center;gap:8px">' +
          '<span style="background:var(--acc);color:#000;padding:1px 6px;border-radius:2px;font-size:.72rem;font-weight:700">' + t.stride + '</span>' +
          esc(t.name) +
          '<span style="margin-left:auto;color:' + (sevColor[t.severity] || "var(--mut)") + ';font-size:.75rem;font-weight:600">' + esc(t.severity) + '</span>' +
        '</div>' +
        '<div class="ad" style="margin:6px 0">' + esc(t.desc) + '</div>' +
        '<div style="margin-bottom:4px">' + mits + '</div>' +
        (t.mitre ? '<span style="font-size:.7rem;color:var(--mut);font-family:var(--mono,monospace)">MITRE: ' + esc(t.mitre) + '</span>' : '') +
      '</div>';
    }).join("");
    el.querySelector("#tl-list").innerHTML = filtered.length ? cards : '<p class="muted">No threats match the current filters.</p>';
  }
  el.querySelector("#tl-cat").onchange = renderList;
  el.querySelector("#tl-sev").onchange = renderList;
  el.querySelector("#tl-search").oninput = renderList;
  renderList();
}

// ── Asset Inventory Tab ──
function renderAssets(el) {
  var classifications = ["Public", "Internal", "Confidential", "Restricted"];
  var types = ["Application", "Server", "Database", "Network Device", "API", "Cloud Service", "Workstation", "Mobile Device", "IoT Device", "Data Store"];

  el.innerHTML =
    '<h2 class="pg-h2">Asset Inventory</h2>' +
    '<p class="muted" style="margin-bottom:16px">Catalog your assets with classification levels to prioritize threat modeling efforts.</p>' +
    '<div class="arse-card" style="cursor:default;padding:16px;margin-bottom:16px">' +
      '<div style="display:grid;grid-template-columns:1fr 1fr 1fr auto;gap:8px">' +
        '<input id="asset-name" placeholder="Asset name" style="padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
        '<select id="asset-type" style="padding:6px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' + types.map(function(t) { return '<option>' + esc(t) + '</option>'; }).join("") + '</select>' +
        '<select id="asset-class" style="padding:6px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' + classifications.map(function(c) { return '<option>' + esc(c) + '</option>'; }).join("") + '</select>' +
        '<button class="btn" id="asset-add" style="padding:6px 16px">Add</button>' +
      '</div>' +
      '<input id="asset-desc" placeholder="Description (optional)" style="width:100%;margin-top:8px;padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
    '</div>' +
    '<div id="asset-list"></div>';

  var assets = [];
  try { assets = JSON.parse(localStorage.getItem("tm_assets") || "[]"); } catch (_) {}
  var classColors = { Public: "#4caf50", Internal: "#2196f3", Confidential: "#ff9800", Restricted: "#f44336" };

  function renderAssetList() {
    if (!assets.length) { el.querySelector("#asset-list").innerHTML = '<p class="muted">No assets added yet.</p>'; return; }
    var cards = assets.map(function(a, i) {
      return '<div class="arse-card" style="cursor:default;margin-bottom:6px;display:flex;align-items:center;gap:12px">' +
        '<span style="width:6px;height:6px;border-radius:50%;background:' + (classColors[a.classification] || "var(--mut)") + ';flex-shrink:0"></span>' +
        '<div style="flex:1">' +
          '<div style="font-weight:600;font-size:.85rem">' + esc(a.name) + ' <span style="color:var(--mut);font-weight:400;font-size:.75rem">(' + esc(a.type) + ')</span></div>' +
          (a.desc ? '<div class="muted" style="font-size:.75rem">' + esc(a.desc) + '</div>' : '') +
        '</div>' +
        '<span style="padding:2px 8px;border-radius:2px;font-size:.72rem;font-weight:600;color:' + (classColors[a.classification] || "var(--mut)") + ';border:1px solid ' + (classColors[a.classification] || "var(--line)") + '">' + esc(a.classification) + '</span>' +
        '<button class="btn" data-del="' + i + '" style="padding:2px 8px;font-size:.72rem;background:#f44336">x</button>' +
      '</div>';
    }).join("");
    el.querySelector("#asset-list").innerHTML = cards;
  }
  renderAssetList();

  el.querySelector("#asset-add").onclick = function() {
    var name = el.querySelector("#asset-name").value.trim();
    if (!name) return;
    assets.push({ name: name, type: el.querySelector("#asset-type").value, classification: el.querySelector("#asset-class").value, desc: el.querySelector("#asset-desc").value.trim() });
    try { localStorage.setItem("tm_assets", JSON.stringify(assets)); } catch (_) {}
    el.querySelector("#asset-name").value = "";
    el.querySelector("#asset-desc").value = "";
    renderAssetList();
  };
  el.querySelector("#asset-list").onclick = function(e) {
    if (e.target.dataset.del !== undefined) {
      assets.splice(parseInt(e.target.dataset.del), 1);
      try { localStorage.setItem("tm_assets", JSON.stringify(assets)); } catch (_) {}
      renderAssetList();
    }
  };
}

// ── Risk Matrix Tab ──
function renderRisk(el) {
  var cells = [];
  for (var li = 4; li >= 0; li--) {
    for (var ii = 0; ii < 5; ii++) {
      var riskLevel = Math.round((li + ii) / 2);
      cells.push({ li: li, ii: ii, risk: riskLevel });
    }
  }
  var matrixHTML = '<table style="border-collapse:collapse;width:100%;table-layout:fixed">';
  matrixHTML += '<tr><th style="width:80px"></th>';
  for (var i = 0; i < 5; i++) {
    matrixHTML += '<th style="padding:8px;text-align:center;font-size:.75rem;border:1px solid var(--line)">' + RISK_LEVELS[i] + '<br>Impact</th>';
  }
  matrixHTML += '</tr>';
  for (var l = 4; l >= 0; l--) {
    matrixHTML += '<tr><th style="padding:8px;text-align:right;font-size:.75rem;border:1px solid var(--line)">' + RISK_LEVELS[l] + '<br>Likelihood</th>';
    for (var im = 0; im < 5; im++) {
      var risk = Math.round((l + im) / 2);
      matrixHTML += '<td style="padding:12px;text-align:center;border:1px solid var(--line);background:' + RISK_COLORS[risk] + '20;cursor:pointer;font-size:.72rem;color:' + RISK_COLORS[risk] + ';font-weight:600" data-l="' + l + '" data-i="' + im + '">' + RISK_LEVELS[risk] + '</td>';
    }
    matrixHTML += '</tr>';
  }
  matrixHTML += '</table>';

  el.innerHTML =
    '<h2 class="pg-h2">Risk Assessment Matrix</h2>' +
    '<p class="muted" style="margin-bottom:16px">5x5 likelihood vs. impact matrix. Click a cell to place a risk item.</p>' +
    matrixHTML +
    '<div style="margin-top:16px">' +
      '<div style="display:flex;gap:8px;margin-bottom:12px">' +
        '<input id="risk-name" placeholder="Risk / Threat name" style="flex:1;padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
      '</div>' +
      '<div id="risk-items"></div>' +
    '</div>';

  var riskItems = [];
  try { riskItems = JSON.parse(localStorage.getItem("tm_risk_items") || "[]"); } catch (_) {}

  function renderRiskItems() {
    if (!riskItems.length) { el.querySelector("#risk-items").innerHTML = '<p class="muted" style="font-size:.82rem">Click a matrix cell to place a risk. Enter a name first.</p>'; return; }
    var html = riskItems.map(function(r, i) {
      var risk = Math.round((r.likelihood + r.impact) / 2);
      return '<div class="arse-card" style="cursor:default;margin-bottom:4px;display:flex;align-items:center;gap:8px;padding:8px 12px">' +
        '<span style="width:8px;height:8px;border-radius:50%;background:' + RISK_COLORS[risk] + '"></span>' +
        '<span style="font-size:.82rem;font-weight:600">' + esc(r.name) + '</span>' +
        '<span class="muted" style="font-size:.72rem;margin-left:auto">L:' + RISK_LEVELS[r.likelihood] + ' / I:' + RISK_LEVELS[r.impact] + '</span>' +
        '<span style="color:' + RISK_COLORS[risk] + ';font-size:.75rem;font-weight:600">' + RISK_LEVELS[risk] + '</span>' +
        '<button class="btn" data-rdel="' + i + '" style="padding:1px 6px;font-size:.7rem;background:#f44336">x</button>' +
      '</div>';
    }).join("");
    el.querySelector("#risk-items").innerHTML = html;
  }
  renderRiskItems();

  el.querySelector("table").onclick = function(e) {
    var td = e.target.closest("td[data-l]");
    if (!td) return;
    var name = el.querySelector("#risk-name").value.trim();
    if (!name) { el.querySelector("#risk-name").focus(); return; }
    riskItems.push({ name: name, likelihood: parseInt(td.dataset.l), impact: parseInt(td.dataset.i) });
    try { localStorage.setItem("tm_risk_items", JSON.stringify(riskItems)); } catch (_) {}
    el.querySelector("#risk-name").value = "";
    renderRiskItems();
  };
  el.querySelector("#risk-items").onclick = function(e) {
    if (e.target.dataset.rdel !== undefined) {
      riskItems.splice(parseInt(e.target.dataset.rdel), 1);
      try { localStorage.setItem("tm_risk_items", JSON.stringify(riskItems)); } catch (_) {}
      renderRiskItems();
    }
  };
}

// ── Attack Tree Tab ──
function renderAttackTree(el) {
  el.innerHTML =
    '<h2 class="pg-h2">Attack Tree Builder</h2>' +
    '<p class="muted" style="margin-bottom:16px">Model attack scenarios as trees. The root is the attacker\'s goal; branches are sub-goals connected by AND/OR gates.</p>' +
    '<div style="display:flex;gap:8px;margin-bottom:12px">' +
      '<input id="at-root" placeholder="Root goal (e.g., Steal customer data)" value="" style="flex:1;padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
      '<button class="btn" id="at-reset" style="padding:6px 12px;background:#f44336">Reset</button>' +
    '</div>' +
    '<div id="at-tree" style="padding:16px;background:var(--card);border:1px solid var(--line);border-radius:2px;overflow-x:auto"></div>' +
    '<div style="display:flex;gap:8px;margin-top:12px">' +
      '<input id="at-child" placeholder="Add sub-goal..." style="flex:1;padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
      '<select id="at-gate" style="padding:6px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px"><option>OR</option><option>AND</option></select>' +
      '<button class="btn" id="at-addchild" style="padding:6px 12px">Add to Selected</button>' +
    '</div>' +
    '<p class="muted" style="font-size:.75rem;margin-top:8px">Click a node to select it, then add children. OR = any child suffices. AND = all children required.</p>';

  var tree = { id: "root", name: "Attacker Goal", gate: "OR", children: [], expanded: true };
  try { var saved = JSON.parse(localStorage.getItem("tm_attack_tree")); if (saved) tree = saved; } catch (_) {}
  var selectedId = "root";

  function renderNode(node, depth) {
    var indent = depth * 24;
    var isSel = node.id === selectedId;
    var gateColor = node.gate === "AND" ? "#f44336" : "#4caf50";
    var childrenHTML = "";
    if (node.children && node.children.length) {
      childrenHTML = node.children.map(function(c) { return renderNode(c, depth + 1); }).join("");
    }
    return '<div style="margin-left:' + indent + 'px;margin-bottom:4px">' +
      '<div data-nid="' + esc(node.id) + '" style="display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border:2px solid ' + (isSel ? "var(--acc)" : "var(--line)") + ';border-radius:2px;cursor:pointer;background:' + (isSel ? "var(--acc)10" : "var(--card)") + '">' +
        (node.children && node.children.length ? '<span style="font-size:.65rem;padding:1px 4px;border-radius:2px;background:' + gateColor + ';color:#fff;font-weight:700">' + node.gate + '</span>' : '') +
        '<span style="font-size:.82rem">' + esc(node.name) + '</span>' +
        (node.id !== "root" ? '<span class="at-del" data-did="' + esc(node.id) + '" style="font-size:.7rem;color:#f44336;cursor:pointer;margin-left:4px">[x]</span>' : '') +
      '</div>' +
      childrenHTML +
    '</div>';
  }

  function paint() {
    el.querySelector("#at-tree").innerHTML = renderNode(tree, 0);
  }
  paint();

  var idCounter = Date.now();
  function findNode(node, id) {
    if (node.id === id) return node;
    if (node.children) { for (var i = 0; i < node.children.length; i++) { var f = findNode(node.children[i], id); if (f) return f; } }
    return null;
  }
  function removeNode(parent, id) {
    if (parent.children) {
      parent.children = parent.children.filter(function(c) { return c.id !== id; });
      parent.children.forEach(function(c) { removeNode(c, id); });
    }
  }

  el.querySelector("#at-tree").onclick = function(e) {
    var del = e.target.closest("[data-did]");
    if (del) { removeNode(tree, del.dataset.did); if (selectedId === del.dataset.did) selectedId = "root"; try { localStorage.setItem("tm_attack_tree", JSON.stringify(tree)); } catch (_) {} paint(); return; }
    var nd = e.target.closest("[data-nid]");
    if (nd) { selectedId = nd.dataset.nid; paint(); }
  };
  el.querySelector("#at-addchild").onclick = function() {
    var name = el.querySelector("#at-child").value.trim();
    if (!name) return;
    var parent = findNode(tree, selectedId);
    if (!parent) return;
    if (!parent.children) parent.children = [];
    parent.gate = el.querySelector("#at-gate").value;
    parent.children.push({ id: "n" + (++idCounter), name: name, gate: "OR", children: [] });
    try { localStorage.setItem("tm_attack_tree", JSON.stringify(tree)); } catch (_) {}
    el.querySelector("#at-child").value = "";
    paint();
  };
  el.querySelector("#at-root").onchange = function() {
    tree.name = el.querySelector("#at-root").value.trim() || "Attacker Goal";
    try { localStorage.setItem("tm_attack_tree", JSON.stringify(tree)); } catch (_) {}
    paint();
  };
  el.querySelector("#at-root").value = tree.name;
  el.querySelector("#at-reset").onclick = function() {
    tree = { id: "root", name: "Attacker Goal", gate: "OR", children: [], expanded: true };
    selectedId = "root";
    try { localStorage.setItem("tm_attack_tree", JSON.stringify(tree)); } catch (_) {}
    el.querySelector("#at-root").value = tree.name;
    paint();
  };
}

// ── Data Flow Diagram Tab ──
function renderDFD(el) {
  el.innerHTML =
    '<h2 class="pg-h2">Data Flow Diagram</h2>' +
    '<p class="muted" style="margin-bottom:16px">Model your system\'s data flows to identify trust boundaries and potential threats.</p>' +
    '<div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap">' +
      '<select id="dfd-type" style="padding:6px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
        '<option value="external">External Entity</option><option value="process">Process</option><option value="datastore">Data Store</option><option value="boundary">Trust Boundary</option>' +
      '</select>' +
      '<input id="dfd-name" placeholder="Name" style="flex:1;padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
      '<button class="btn" id="dfd-add" style="padding:6px 12px">Add Element</button>' +
    '</div>' +
    '<div style="display:flex;gap:8px;margin-bottom:12px">' +
      '<select id="dfd-from" style="flex:1;padding:6px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px"><option value="">From...</option></select>' +
      '<select id="dfd-to" style="flex:1;padding:6px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px"><option value="">To...</option></select>' +
      '<input id="dfd-flowname" placeholder="Data label" style="flex:1;padding:6px 10px;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:2px">' +
      '<button class="btn" id="dfd-addflow" style="padding:6px 12px">Add Flow</button>' +
    '</div>' +
    '<div id="dfd-canvas" style="background:var(--card);border:1px solid var(--line);border-radius:2px;padding:20px;min-height:300px;overflow:auto"></div>' +
    '<div style="margin-top:8px;display:flex;gap:12px;font-size:.75rem;color:var(--mut)">' +
      '<span style="display:flex;align-items:center;gap:4px"><span style="display:inline-block;width:16px;height:16px;border:2px solid #2196f3;border-radius:50%"></span> External Entity</span>' +
      '<span style="display:flex;align-items:center;gap:4px"><span style="display:inline-block;width:16px;height:16px;border:2px solid var(--acc);border-radius:2px"></span> Process</span>' +
      '<span style="display:flex;align-items:center;gap:4px"><span style="display:inline-block;width:16px;height:6px;border-top:2px solid #4caf50;border-bottom:2px solid #4caf50"></span> Data Store</span>' +
      '<span style="display:flex;align-items:center;gap:4px"><span style="display:inline-block;width:16px;height:16px;border:2px dashed #f44336;border-radius:2px"></span> Trust Boundary</span>' +
    '</div>';

  var elements = [];
  var flows = [];
  try { elements = JSON.parse(localStorage.getItem("tm_dfd_elements") || "[]"); } catch (_) {}
  try { flows = JSON.parse(localStorage.getItem("tm_dfd_flows") || "[]"); } catch (_) {}

  function typeStyle(type) {
    if (type === "external") return "border:2px solid #2196f3;border-radius:50%;padding:8px 16px;background:#2196f310";
    if (type === "process") return "border:2px solid var(--acc);border-radius:2px;padding:8px 16px;background:var(--acc)10";
    if (type === "datastore") return "border-top:2px solid #4caf50;border-bottom:2px solid #4caf50;padding:8px 16px;background:#4caf5010";
    if (type === "boundary") return "border:2px dashed #f44336;border-radius:2px;padding:8px 16px;background:#f4433608";
    return "";
  }

  function paintDFD() {
    var elems = elements.map(function(e, i) {
      return '<div style="display:inline-block;margin:8px;' + typeStyle(e.type) + ';font-size:.82rem;position:relative">' +
        esc(e.name) +
        '<span class="dfd-del" data-eidx="' + i + '" style="position:absolute;top:-6px;right:-6px;width:16px;height:16px;border-radius:50%;background:#f44336;color:#fff;font-size:.65rem;display:flex;align-items:center;justify-content:center;cursor:pointer">x</span>' +
      '</div>';
    }).join("");
    var flowsList = flows.map(function(f, i) {
      return '<div style="font-size:.78rem;padding:4px 0;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:6px">' +
        '<span style="font-weight:600">' + esc(f.from) + '</span>' +
        ' <span style="color:var(--acc)">→</span> ' +
        '<span style="font-weight:600">' + esc(f.to) + '</span>' +
        '<span class="muted">(' + esc(f.label) + ')</span>' +
        '<span class="dfd-fdel" data-fidx="' + i + '" style="margin-left:auto;color:#f44336;cursor:pointer;font-size:.7rem">[x]</span>' +
      '</div>';
    }).join("");
    el.querySelector("#dfd-canvas").innerHTML =
      '<div style="margin-bottom:16px">' + (elems || '<span class="muted">No elements yet. Add external entities, processes, and data stores above.</span>') + '</div>' +
      (flowsList ? '<h4 style="font-size:.85rem;margin:12px 0 4px">Data Flows</h4>' + flowsList : '');
    updateDropdowns();
  }

  function updateDropdowns() {
    var opts = '<option value="">Select...</option>' + elements.filter(function(e) { return e.type !== "boundary"; }).map(function(e) { return '<option>' + esc(e.name) + '</option>'; }).join("");
    el.querySelector("#dfd-from").innerHTML = opts;
    el.querySelector("#dfd-to").innerHTML = opts;
  }
  paintDFD();

  el.querySelector("#dfd-add").onclick = function() {
    var name = el.querySelector("#dfd-name").value.trim();
    if (!name) return;
    elements.push({ name: name, type: el.querySelector("#dfd-type").value });
    try { localStorage.setItem("tm_dfd_elements", JSON.stringify(elements)); } catch (_) {}
    el.querySelector("#dfd-name").value = "";
    paintDFD();
  };
  el.querySelector("#dfd-addflow").onclick = function() {
    var from = el.querySelector("#dfd-from").value;
    var to = el.querySelector("#dfd-to").value;
    var label = el.querySelector("#dfd-flowname").value.trim() || "data";
    if (!from || !to) return;
    flows.push({ from: from, to: to, label: label });
    try { localStorage.setItem("tm_dfd_flows", JSON.stringify(flows)); } catch (_) {}
    el.querySelector("#dfd-flowname").value = "";
    paintDFD();
  };
  el.querySelector("#dfd-canvas").onclick = function(e) {
    var eidx = e.target.closest("[data-eidx]");
    if (eidx) { elements.splice(parseInt(eidx.dataset.eidx), 1); try { localStorage.setItem("tm_dfd_elements", JSON.stringify(elements)); } catch (_) {} paintDFD(); return; }
    var fidx = e.target.closest("[data-fidx]");
    if (fidx) { flows.splice(parseInt(fidx.dataset.fidx), 1); try { localStorage.setItem("tm_dfd_flows", JSON.stringify(flows)); } catch (_) {} paintDFD(); }
  };
}

// ── Kill Chain Tab ──
function renderKillChain(el) {
  var phases = KILL_CHAIN.map(function(kc, i) {
    var examples = kc.examples.map(function(ex) { return '<span style="display:inline-block;padding:1px 6px;background:var(--bg);border:1px solid var(--line);border-radius:2px;font-size:.7rem;margin:2px">' + esc(ex) + '</span>'; }).join("");
    var mitreLinks = kc.mitre.map(function(t) { return '<span style="font-family:var(--mono,monospace);font-size:.7rem;color:var(--acc)">' + esc(t) + '</span>'; }).join(", ");
    return '<div class="arse-card" style="cursor:default;margin-bottom:8px;display:flex;gap:12px;align-items:flex-start">' +
      '<div style="min-width:32px;height:32px;display:flex;align-items:center;justify-content:center;background:var(--acc);color:#000;font-weight:800;border-radius:2px;font-size:.85rem">' + (i + 1) + '</div>' +
      '<div style="flex:1">' +
        '<div style="font-weight:700;font-size:.9rem;margin-bottom:4px">' + esc(kc.phase) + '</div>' +
        '<div class="muted" style="font-size:.8rem;margin-bottom:6px">' + esc(kc.desc) + '</div>' +
        '<div style="margin-bottom:4px">' + examples + '</div>' +
        '<div>MITRE: ' + mitreLinks + '</div>' +
      '</div>' +
    '</div>';
  }).join("");

  el.innerHTML =
    '<h2 class="pg-h2">Cyber Kill Chain & ATT&CK Mapping</h2>' +
    '<p class="muted" style="margin-bottom:16px">Map threats to Lockheed Martin\'s Cyber Kill Chain phases and corresponding MITRE ATT&CK tactics.</p>' +
    phases +
    '<div class="arse-card" style="cursor:default;margin-top:16px;padding:16px">' +
      '<h3 style="margin:0 0 8px;font-size:.9rem">MITRE ATT&CK Tactics Overview</h3>' +
      '<div style="display:flex;flex-wrap:wrap;gap:6px">' +
        ["TA0043 Recon", "TA0042 Resource Dev", "TA0001 Initial Access", "TA0002 Execution", "TA0003 Persistence", "TA0004 Priv Esc", "TA0005 Defense Evasion", "TA0006 Credential Access", "TA0007 Discovery", "TA0008 Lateral Movement", "TA0009 Collection", "TA0010 Exfiltration", "TA0011 C2", "TA0040 Impact"].map(function(t) {
          return '<span style="padding:4px 8px;background:var(--bg);border:1px solid var(--line);border-radius:2px;font-size:.72rem;font-family:var(--mono,monospace)">' + esc(t) + '</span>';
        }).join("") +
      '</div>' +
    '</div>';
}

// ── Compliance Tab ──
function renderCompliance(el) {
  var frameworks = Object.keys(COMPLIANCE_CONTROLS);
  var frameworkCards = frameworks.map(function(fw) {
    var controls = COMPLIANCE_CONTROLS[fw].map(function(c) {
      return '<div style="padding:4px 8px;background:var(--bg);border:1px solid var(--line);border-radius:2px;font-size:.72rem">' + esc(c) + '</div>';
    }).join("");
    return '<div class="arse-card" style="cursor:default;margin-bottom:12px">' +
      '<div class="an">' + esc(fw) + ' <span style="color:var(--mut);font-size:.75rem">(' + COMPLIANCE_CONTROLS[fw].length + ' controls)</span></div>' +
      '<div style="display:flex;flex-wrap:wrap;gap:4px;margin-top:8px">' + controls + '</div>' +
    '</div>';
  }).join("");

  el.innerHTML =
    '<h2 class="pg-h2">Compliance Framework Mapping</h2>' +
    '<p class="muted" style="margin-bottom:16px">Map identified threats to compliance framework controls. Reference for NIST CSF, ISO 27001, OWASP, CIS, and PCI DSS.</p>' +
    frameworkCards;
}

// ── Report Tab ──
function renderReportTab(el) {
  var items = []; try { items = JSON.parse(localStorage.getItem("tm_stride_items") || "[]"); } catch (_) {}
  var assets = []; try { assets = JSON.parse(localStorage.getItem("tm_assets") || "[]"); } catch (_) {}
  var risks = []; try { risks = JSON.parse(localStorage.getItem("tm_risk_items") || "[]"); } catch (_) {}
  var tree = null; try { tree = JSON.parse(localStorage.getItem("tm_attack_tree")); } catch (_) {}

  var now = new Date().toISOString().split("T")[0];
  var report = "# Threat Model Report\n";
  report += "Generated: " + now + "\n\n";
  report += "## Assets (" + assets.length + ")\n";
  assets.forEach(function(a) { report += "- " + a.name + " [" + a.type + "] — " + a.classification + (a.desc ? ": " + a.desc : "") + "\n"; });
  report += "\n## STRIDE Analysis (" + items.length + " elements)\n";
  items.forEach(function(item) {
    report += "- " + item.name + " (" + item.type + "): " + (item.threats && item.threats.length ? item.threats.join(", ") : "No threats identified") + "\n";
  });
  report += "\n## Risk Items (" + risks.length + ")\n";
  risks.forEach(function(r) {
    var risk = Math.round((r.likelihood + r.impact) / 2);
    report += "- " + r.name + " — Likelihood: " + RISK_LEVELS[r.likelihood] + ", Impact: " + RISK_LEVELS[r.impact] + " → " + RISK_LEVELS[risk] + " risk\n";
  });
  if (tree && tree.children && tree.children.length) {
    report += "\n## Attack Tree: " + tree.name + "\n";
    function printTree(node, indent) {
      report += indent + (node.children && node.children.length ? "[" + node.gate + "] " : "- ") + node.name + "\n";
      if (node.children) node.children.forEach(function(c) { printTree(c, indent + "  "); });
    }
    printTree(tree, "");
  }

  el.innerHTML =
    '<h2 class="pg-h2">Threat Model Report</h2>' +
    '<p class="muted" style="margin-bottom:16px">Auto-generated report from your threat modeling data. Copy and save as needed.</p>' +
    '<div style="display:flex;gap:8px;margin-bottom:12px">' +
      '<button class="btn" id="tm-copy">Copy to Clipboard</button>' +
    '</div>' +
    '<pre style="background:var(--card);border:1px solid var(--line);padding:16px;font-size:.78rem;white-space:pre-wrap;overflow-x:auto;max-height:500px;overflow-y:auto;border-radius:2px;color:var(--txt)">' + esc(report) + '</pre>';

  el.querySelector("#tm-copy").onclick = function() {
    navigator.clipboard.writeText(report).then(function() {
      el.querySelector("#tm-copy").textContent = "Copied!";
      setTimeout(function() { el.querySelector("#tm-copy").textContent = "Copy to Clipboard"; }, 2000);
    });
  };
}
