// =============================================================================
// Digital Forensics & Incident Response (DFIR) Reference
// Comprehensive procedures, artifacts, memory analysis, timeline techniques,
// IR playbooks, and log analysis patterns.
// =============================================================================

// -----------------------------------------------------------------------------
// 1. FORENSIC PROCEDURES
// -----------------------------------------------------------------------------
export const FORENSICS_PROCEDURES = [
  // -- Disk Forensics --
  {
    name: "Disk Image Acquisition (dd)",
    category: "disk",
    description: "Create a bit-for-bit forensic image of a suspect drive using dd or dc3dd, preserving all data including deleted files, slack space, and unallocated clusters.",
    steps: [
      "Document the drive: serial number, model, capacity, interface type",
      "Write-protect the source drive using a hardware write blocker",
      "Connect the destination media (must be equal or larger capacity)",
      "Run dd: dd if=/dev/sdX of=/path/to/image.dd bs=4096 conv=noerror,sync status=progress",
      "Calculate and record MD5 and SHA-256 hashes of both source and image",
      "Verify hashes match to confirm forensic integrity",
      "Store the image on encrypted, tamper-evident media",
      "Complete chain-of-custody documentation"
    ],
    tools: ["dd", "dc3dd", "dcfldd", "FTK Imager", "Guymager", "ewfacquire"],
    artifacts: ["Raw disk image (.dd/.raw)", "E01 (Expert Witness Format)", "AFF4", "Hash verification logs"]
  },
  {
    name: "EWF Image Acquisition",
    category: "disk",
    description: "Create a forensic image in Expert Witness Format (E01) which supports compression, case metadata, and built-in hash verification.",
    steps: [
      "Attach write blocker to suspect drive",
      "Launch ewfacquire or FTK Imager",
      "Enter case metadata: examiner, case number, evidence number, description",
      "Select compression level and segment size",
      "Begin acquisition and monitor progress",
      "Verify embedded hash matches source hash",
      "Document acquisition log and any errors"
    ],
    tools: ["ewfacquire", "FTK Imager", "EnCase", "Guymager"],
    artifacts: ["E01 image segments", "Acquisition log", "Hash verification report"]
  },
  {
    name: "File System Analysis",
    category: "disk",
    description: "Examine the file system structure, metadata, and content to identify evidence, recover deleted files, and build timelines.",
    steps: [
      "Mount the forensic image read-only or use forensic tool",
      "Identify the file system type (NTFS, ext4, APFS, FAT32, exFAT)",
      "Parse the Master File Table ($MFT) or equivalent metadata structure",
      "Enumerate all files including hidden and system files",
      "Recover deleted files from unallocated space",
      "Extract file metadata: timestamps (MACB), permissions, ownership",
      "Identify alternate data streams (NTFS ADS)",
      "Search for known-bad files using hash sets (NSRL, HashKeeper)",
      "Carve files from unallocated space using file signatures",
      "Document all findings with screenshots and hash values"
    ],
    tools: ["Autopsy", "Sleuth Kit (fls, icat, ifind)", "X-Ways Forensics", "EnCase", "FTK"],
    artifacts: ["File listings", "Deleted file recovery", "ADS contents", "Carved files", "Timeline data"]
  },
  {
    name: "Registry Analysis",
    category: "disk",
    description: "Extract and analyze Windows registry hives to determine user activity, system configuration, installed software, network connections, and evidence of execution.",
    steps: [
      "Extract registry hive files: SAM, SYSTEM, SOFTWARE, SECURITY, NTUSER.DAT, UsrClass.dat",
      "Parse hives with RegRipper or Registry Explorer",
      "Extract user accounts and password hashes from SAM",
      "Determine system name, timezone, and last shutdown from SYSTEM",
      "Identify installed software and services from SOFTWARE",
      "Analyze UserAssist entries for program execution evidence",
      "Check ShimCache/AppCompatCache for execution artifacts",
      "Examine MRU lists, typed URLs, and recent documents",
      "Parse shellbags for folder access history",
      "Correlate findings with other artifact sources"
    ],
    tools: ["RegRipper", "Registry Explorer (Eric Zimmerman)", "RECmd", "yarp", "python-registry"],
    artifacts: ["SAM hive", "SYSTEM hive", "SOFTWARE hive", "NTUSER.DAT", "UsrClass.dat", "AmCache.hve"]
  },
  {
    name: "File Carving and Recovery",
    category: "disk",
    description: "Recover files from unallocated disk space, damaged media, or areas where file system metadata has been destroyed, using file signature-based carving.",
    steps: [
      "Identify target file types and their magic byte signatures",
      "Select carving tool appropriate for the media and file types",
      "Configure carving parameters: block size, max file size, target types",
      "Run carving against unallocated space or full disk image",
      "Review carved files for relevance and integrity",
      "Hash and catalog all recovered files",
      "Validate recovered files by opening and inspecting content",
      "Document recovery statistics and any corrupted files"
    ],
    tools: ["Scalpel", "Foremost", "PhotoRec", "Bulk Extractor", "Magnet AXIOM"],
    artifacts: ["Carved files", "Recovery log", "File signature matches"]
  },
  {
    name: "Encrypted Volume Analysis",
    category: "disk",
    description: "Detect, identify, and attempt to access encrypted volumes and containers including BitLocker, LUKS, FileVault, VeraCrypt, and full-disk encryption.",
    steps: [
      "Scan for encrypted volume indicators (BitLocker metadata, LUKS header, etc.)",
      "Identify encryption type and algorithm used",
      "Check for recovery keys in Active Directory, Microsoft account, or backup",
      "Attempt known passwords and passphrases",
      "Check for key material in memory dumps",
      "Use Elcomsoft or Passware for key recovery if applicable",
      "Mount decrypted volume read-only for analysis",
      "Document encryption type, key source, and decryption method"
    ],
    tools: ["Elcomsoft Forensic Disk Decryptor", "Passware Kit Forensic", "dislocker", "cryptsetup", "Arsenal Image Mounter"],
    artifacts: ["Recovery keys", "Encryption metadata", "Decrypted volume image"]
  },
  {
    name: "USB Device Forensics",
    category: "disk",
    description: "Analyze artifacts related to USB device connections to determine which devices were connected, when they were used, and what data may have been transferred.",
    steps: [
      "Extract USB device entries from SYSTEM registry hive (USBSTOR)",
      "Parse SetupAPI logs for device installation timestamps",
      "Check USB device entries in SYSTEM\\Enum\\USB",
      "Analyze drive letter assignments in MountedDevices",
      "Cross-reference with user-specific MountPoints2 entries",
      "Check Event Logs for storage device events",
      "Analyze link files (.lnk) for references to removable drives",
      "Check jump lists for recently accessed files on USB drives",
      "Parse Volume Shadow Copies for historical USB artifacts",
      "Timeline all USB device activity"
    ],
    tools: ["USBDeview", "USB Forensic Tracker", "Registry Explorer", "RegRipper", "Autopsy"],
    artifacts: ["USBSTOR registry entries", "SetupAPI logs", "MountPoints2", "Link files referencing USB"]
  },
  {
    name: "Browser Forensics",
    category: "disk",
    description: "Extract and analyze web browser artifacts including history, cookies, cache, downloads, bookmarks, saved passwords, and session data from all major browsers.",
    steps: [
      "Identify installed browsers and their profile locations",
      "Extract SQLite databases for history, cookies, downloads, bookmarks",
      "Parse browser cache for cached web content and images",
      "Analyze session restore data for tab history",
      "Extract saved passwords and autofill data",
      "Parse extension/add-on data and settings",
      "Analyze IndexedDB and Local Storage for web app data",
      "Check for private/incognito browsing artifacts",
      "Extract favicon database for site visit evidence",
      "Parse typed URL history from browser and registry",
      "Create timeline of browsing activity",
      "Document findings with screenshots of relevant content"
    ],
    tools: ["Hindsight (Chrome)", "KAPE", "DB Browser for SQLite", "NirSoft BrowsingHistoryView", "Autopsy"],
    artifacts: ["History database", "Cookies database", "Cache files", "Session data", "Saved passwords"]
  },
  {
    name: "Email Forensics (Mailbox Analysis)",
    category: "disk",
    description: "Analyze email mailbox files (PST, OST, MBOX, EML) to investigate phishing, business email compromise, data leakage, and insider threats.",
    steps: [
      "Identify mailbox format and location (PST, OST, MBOX, EDB)",
      "Create forensic copy of mailbox files",
      "Parse mailbox contents with appropriate tool",
      "Search for emails matching investigation keywords",
      "Analyze email attachments for malware",
      "Check for auto-forwarding rules and delegates",
      "Identify deleted emails and recover if possible",
      "Analyze email headers for spoofing and impersonation",
      "Search for data exfiltration via email attachments",
      "Create timeline of relevant email communications",
      "Export relevant emails preserving metadata"
    ],
    tools: ["Kernel PST Viewer", "pffexport", "munpack", "Autopsy Email Parser", "MailXaminer", "Aid4Mail"],
    artifacts: ["Parsed emails", "Attachments", "Forwarding rules", "Deleted email recovery"]
  },

  // -- Memory Forensics --
  {
    name: "Live Memory Acquisition",
    category: "memory",
    description: "Capture a forensic copy of volatile memory (RAM) from a running system for analysis of processes, network connections, loaded modules, and in-memory artifacts.",
    steps: [
      "Select memory acquisition tool appropriate for OS",
      "Ensure sufficient storage for full RAM dump",
      "Run acquisition tool with administrator/root privileges",
      "For Windows: use WinPmem, DumpIt, or Magnet RAM Capture",
      "For Linux: use LiME (Loadable Kernel Module) or /proc/kcore",
      "For macOS: use osxpmem or MacQuisition",
      "Calculate hash of memory dump immediately after acquisition",
      "Document acquisition time, tool version, and system state",
      "Collect additional volatile data: processes, netstat, routing table",
      "Secure memory dump with chain-of-custody documentation"
    ],
    tools: ["WinPmem", "DumpIt", "Magnet RAM Capture", "LiME", "osxpmem", "FTK Imager (RAM capture)"],
    artifacts: ["Raw memory dump (.raw/.mem)", "Crash dump (.dmp)", "Hibernation file (hiberfil.sys)", "Pagefile (pagefile.sys)"]
  },
  {
    name: "Process Analysis",
    category: "memory",
    description: "Analyze running processes in a memory dump to identify malicious executables, injected code, hollow processes, and suspicious parent-child relationships.",
    steps: [
      "List all processes with PID, PPID, creation time, and exit time",
      "Identify process tree and parent-child relationships",
      "Look for suspicious process names mimicking system processes",
      "Check for processes spawned from unusual paths",
      "Identify processes with unexpected parent processes",
      "Scan for injected code and hollowed processes",
      "Extract process command-line arguments",
      "Dump suspicious process executables for static analysis",
      "Check process privileges and security tokens",
      "Correlate with known-good baseline process list"
    ],
    tools: ["Volatility (pslist, pstree, psscan, psxview)", "Rekall", "MemProcFS"],
    artifacts: ["Process listings", "Process tree", "Dumped executables", "Command-line arguments"]
  },
  {
    name: "Memory Malware Detection",
    category: "memory",
    description: "Scan memory for indicators of malware including injected DLLs, rootkit hooks, API hooking, code injection, and process manipulation techniques.",
    steps: [
      "Run malfind to detect injected code segments",
      "Scan for SSDT hooks and IDT modifications",
      "Check for inline API hooks in critical DLLs",
      "Detect hidden processes using cross-view detection (psxview)",
      "Scan for known malware signatures with YARA rules",
      "Analyze loaded drivers for unsigned or suspicious modules",
      "Check for privilege escalation artifacts",
      "Extract and analyze suspicious memory regions",
      "Dump injected code for reverse engineering",
      "Cross-reference IOCs with threat intelligence"
    ],
    tools: ["Volatility (malfind, ssdt, apihooks, driverirp)", "YARA", "MemProcFS", "Rekall"],
    artifacts: ["Injected code dumps", "YARA matches", "Hook detection results", "Hidden process list"]
  },
  {
    name: "Network Connection Analysis (Memory)",
    category: "memory",
    description: "Extract and analyze active and recently closed network connections from memory to identify command-and-control channels, data exfiltration, and lateral movement.",
    steps: [
      "Extract active TCP/UDP connections with process associations",
      "Identify listening ports and bound services",
      "Recover recently closed connections from connection pools",
      "Check for connections to known-bad IPs and domains",
      "Identify unusual ports and protocol usage",
      "Correlate connections with process analysis findings",
      "Extract DNS cache entries from memory",
      "Look for raw socket usage indicating tunneling",
      "Document source/destination IP, port, PID, and process name",
      "Cross-reference with network logs and firewall data"
    ],
    tools: ["Volatility (netscan, connscan, sockets)", "Rekall", "MemProcFS"],
    artifacts: ["Active connection table", "DNS cache", "Socket information"]
  },
  {
    name: "Credential Extraction from Memory",
    category: "memory",
    description: "Extract authentication credentials, tokens, and hashes from memory for use in determining compromised accounts and lateral movement paths.",
    steps: [
      "Extract LSASS process memory for credential harvesting",
      "Parse Kerberos tickets (TGT and service tickets)",
      "Extract NTLM hashes from cached logon sessions",
      "Recover plaintext passwords from WDigest (if enabled)",
      "Extract cached domain credentials",
      "Parse LSA secrets from memory",
      "Identify credential guards and protections in place",
      "Document all recovered credentials with timestamps",
      "Determine accounts at risk and scope of compromise",
      "Recommend password resets for compromised accounts"
    ],
    tools: ["Volatility (hashdump, cachedump, lsadump)", "Mimikatz (offline mode)", "pypykatz"],
    artifacts: ["NTLM hashes", "Kerberos tickets", "Cached credentials", "LSA secrets"]
  },

  // -- Network Forensics --
  {
    name: "Full Packet Capture Analysis",
    category: "network",
    description: "Capture and analyze complete network traffic to reconstruct communications, identify malicious activity, and extract transferred data.",
    steps: [
      "Set up capture point: span port, network tap, or inline device",
      "Configure capture filters to focus on relevant traffic",
      "Start packet capture with appropriate ring buffer settings",
      "Analyze captured traffic for anomalies and IOCs",
      "Reconstruct TCP streams and sessions",
      "Extract files transferred via HTTP, FTP, SMB, and email",
      "Identify DNS queries to suspicious domains",
      "Detect encrypted tunnels and covert channels",
      "Analyze TLS certificates and handshakes",
      "Generate statistics: top talkers, protocols, data volume",
      "Document findings with packet-level evidence"
    ],
    tools: ["Wireshark", "tcpdump", "tshark", "NetworkMiner", "Zeek (Bro)", "Moloch/Arkime"],
    artifacts: ["PCAP files", "Extracted files", "TCP stream reconstructions", "Protocol statistics"]
  },
  {
    name: "NetFlow and Traffic Analysis",
    category: "network",
    description: "Analyze network flow data (NetFlow, sFlow, IPFIX) to identify communication patterns, data exfiltration, lateral movement, and beaconing behavior.",
    steps: [
      "Collect flow data from routers, switches, and flow sensors",
      "Normalize data across different flow formats",
      "Establish baseline traffic patterns",
      "Identify high-volume data transfers (potential exfiltration)",
      "Detect periodic beaconing patterns (C2 communication)",
      "Map lateral movement between internal hosts",
      "Identify connections to known-bad IP addresses",
      "Analyze traffic at unusual times (off-hours activity)",
      "Generate flow visualizations and reports",
      "Correlate with PCAP data for deep-dive analysis"
    ],
    tools: ["nfdump", "SiLK", "Zeek", "Argus", "Elastic (Filebeat/Packetbeat)", "Plixer Scrutinizer"],
    artifacts: ["Flow records", "Traffic profiles", "Beaconing detection results", "Lateral movement maps"]
  },
  {
    name: "DNS Log Analysis",
    category: "network",
    description: "Analyze DNS query and response logs to detect data exfiltration via DNS tunneling, domain generation algorithms (DGA), fast-flux domains, and C2 communication.",
    steps: [
      "Collect DNS logs from recursive resolvers, DNS servers, and passive DNS",
      "Identify queries to newly registered domains (NRDs)",
      "Detect domain generation algorithm (DGA) patterns",
      "Analyze query frequency for beaconing patterns",
      "Check for DNS tunneling indicators: long subdomain names, TXT records",
      "Identify fast-flux domains with rapidly changing IP resolutions",
      "Cross-reference domains with threat intelligence feeds",
      "Check for DNS rebinding attacks",
      "Analyze NXDOMAIN responses for reconnaissance indicators",
      "Document IOC domains and associated timestamps"
    ],
    tools: ["Zeek", "PassiveDNS", "DNSdist", "Splunk DNS app", "RITA", "Freq.py"],
    artifacts: ["DNS query logs", "Suspicious domain list", "Tunneling indicators", "DGA detections"]
  },
  {
    name: "Firewall and IDS Log Analysis",
    category: "network",
    description: "Analyze firewall rules, connection logs, and intrusion detection/prevention system alerts to identify attack patterns and policy violations.",
    steps: [
      "Collect logs from firewalls, IDS/IPS, and UTM devices",
      "Parse and normalize log formats across vendors",
      "Identify blocked and allowed connections to/from IOC addresses",
      "Analyze IDS/IPS alerts for true positives vs false positives",
      "Detect port scanning and reconnaissance activity",
      "Identify policy violations and unauthorized access attempts",
      "Correlate alerts across multiple sensors for attack patterns",
      "Check for rule bypasses and evasion attempts",
      "Generate timeline of network-based attack events",
      "Document findings with raw log evidence"
    ],
    tools: ["Splunk", "ELK Stack", "Suricata", "Snort", "pfSense", "Palo Alto Cortex"],
    artifacts: ["Firewall logs", "IDS/IPS alerts", "Connection logs", "Rule hit counts"]
  },
  {
    name: "Wireless Network Forensics",
    category: "network",
    description: "Investigate wireless network attacks including rogue access points, evil twin attacks, deauthentication attacks, and unauthorized wireless access.",
    steps: [
      "Survey wireless environment for authorized and rogue APs",
      "Capture wireless frames in monitor mode",
      "Identify deauthentication and disassociation attacks",
      "Detect evil twin and rogue access points by BSSID and SSID",
      "Analyze probe requests for client device enumeration",
      "Check for WPA handshake captures indicating cracking attempts",
      "Review wireless controller logs for unauthorized associations",
      "Analyze RADIUS/authentication logs for wireless access",
      "Map physical locations of rogue devices",
      "Document wireless attack indicators and timeline"
    ],
    tools: ["Aircrack-ng", "Kismet", "Wireshark", "WiFi Pineapple detection", "Ekahau"],
    artifacts: ["Wireless capture files", "Rogue AP list", "Deauth attack evidence", "RADIUS logs"]
  },
  {
    name: "Email Header Analysis",
    category: "network",
    description: "Analyze email headers to trace message origin, identify spoofing attempts, and determine the authentication status of suspicious emails.",
    steps: [
      "Extract full email headers from the suspicious message",
      "Parse Received headers to trace the message path (bottom-up)",
      "Identify the originating IP address from the earliest Received header",
      "Check SPF, DKIM, and DMARC authentication results",
      "Verify Return-Path and envelope sender alignment",
      "Analyze Message-ID for anomalies",
      "Check X-Originating-IP and X-Mailer headers",
      "Perform WHOIS and geolocation on originating IP",
      "Compare timestamps across Received headers for inconsistencies",
      "Check for header injection and spoofing indicators",
      "Document findings with annotated header analysis"
    ],
    tools: ["MXToolbox Header Analyzer", "Google Admin Toolbox", "PhishTool", "email-header-analyzer"],
    artifacts: ["Parsed headers", "Authentication results", "IP geolocation", "Spoofing indicators"]
  },

  // -- Mobile Forensics --
  {
    name: "iOS Device Acquisition",
    category: "mobile",
    description: "Acquire forensic data from Apple iOS devices including logical, file system, and physical extractions depending on device state and security configuration.",
    steps: [
      "Document device state: locked/unlocked, passcode known, iOS version",
      "Enable airplane mode to prevent remote wipe",
      "Attempt logical acquisition via iTunes/Finder backup",
      "Try advanced logical acquisition with forensic tool",
      "Attempt file system extraction if jailbreak is feasible",
      "For locked devices: check for known exploits (checkm8, etc.)",
      "Extract keychain data if passcode is known",
      "Parse backup files for messages, call logs, photos, app data",
      "Extract cloud data from iCloud if credentials available",
      "Document extraction method, tool version, and data obtained"
    ],
    tools: ["Cellebrite UFED", "GrayKey", "Magnet AXIOM", "iLEAPP", "libimobiledevice", "checkra1n"],
    artifacts: ["iTunes backup", "File system extraction", "Keychain data", "iCloud data"]
  },
  {
    name: "Android Device Acquisition",
    category: "mobile",
    description: "Acquire forensic data from Android devices using logical, file system, and physical extraction methods based on device model, OS version, and security state.",
    steps: [
      "Document device: model, Android version, security patch level, encryption status",
      "Enable airplane mode, disable Wi-Fi and Bluetooth",
      "Check if USB debugging is enabled",
      "Attempt ADB logical extraction if USB debugging is on",
      "Try advanced extraction with forensic tool (Cellebrite, MSAB)",
      "For rooted devices: perform file system extraction via ADB",
      "Attempt chip-off or JTAG for physically damaged devices",
      "Parse extracted data for communications, app data, location",
      "Extract cloud data from Google account if available",
      "Document extraction method and data scope"
    ],
    tools: ["Cellebrite UFED", "MSAB XRY", "Magnet AXIOM", "ALEAPP", "ADB", "Andriller"],
    artifacts: ["ADB backup", "File system dump", "App databases", "Google account data"]
  },
  {
    name: "Mobile App Data Analysis",
    category: "mobile",
    description: "Analyze application data from mobile devices including messaging apps, social media, location services, and installed app artifacts.",
    steps: [
      "Inventory all installed applications with versions",
      "Extract SQLite databases from app sandboxed storage",
      "Parse messaging app databases (WhatsApp, Signal, Telegram, etc.)",
      "Extract and reconstruct media files from app caches",
      "Analyze location data from mapping and fitness apps",
      "Parse social media app data and cached content",
      "Extract browser history from mobile browsers",
      "Analyze financial and payment app data",
      "Check app permissions and access logs",
      "Correlate app data with timeline events"
    ],
    tools: ["ALEAPP", "iLEAPP", "Autopsy", "DB Browser for SQLite", "Magnet AXIOM"],
    artifacts: ["SQLite databases", "App caches", "Media files", "Chat logs", "Location data"]
  },

  // -- Cloud Forensics --
  {
    name: "AWS Cloud Forensics",
    category: "cloud",
    description: "Investigate security incidents in Amazon Web Services environments including unauthorized access, resource abuse, and data exfiltration from cloud infrastructure.",
    steps: [
      "Preserve CloudTrail logs and ensure logging is enabled",
      "Collect VPC Flow Logs for network activity",
      "Review IAM access and credential reports",
      "Check GuardDuty findings for detected threats",
      "Snapshot affected EC2 instances for disk forensics",
      "Capture EC2 instance memory if possible",
      "Analyze S3 access logs for data access patterns",
      "Review Lambda function invocations and logs",
      "Check for IAM key usage and credential compromise",
      "Examine security group changes and network modifications",
      "Review AWS Config changes for resource modifications",
      "Preserve and analyze CloudWatch logs and metrics"
    ],
    tools: ["AWS CLI", "CloudTrail", "GuardDuty", "Athena", "CloudWatch", "Prowler", "ScoutSuite"],
    artifacts: ["CloudTrail logs", "VPC Flow Logs", "EC2 snapshots", "S3 access logs", "IAM reports"]
  },
  {
    name: "Azure Cloud Forensics",
    category: "cloud",
    description: "Investigate incidents in Microsoft Azure environments including identity compromise, resource abuse, and data breach scenarios.",
    steps: [
      "Collect Azure Activity Logs and sign-in logs",
      "Review Azure AD audit logs for identity events",
      "Analyze Azure Security Center alerts and recommendations",
      "Snapshot affected VMs for disk analysis",
      "Collect NSG Flow Logs for network activity",
      "Review Azure Key Vault access logs",
      "Examine storage account access logs",
      "Check for risky sign-in events in Azure AD",
      "Review conditional access policy evaluations",
      "Analyze Azure Sentinel incidents if configured",
      "Examine resource creation and modification history",
      "Document and preserve all collected logs"
    ],
    tools: ["Azure CLI", "Azure Portal", "Azure Sentinel", "Microsoft Defender for Cloud", "Az PowerShell"],
    artifacts: ["Activity logs", "Sign-in logs", "NSG Flow Logs", "VM snapshots", "Azure AD audit logs"]
  },
  {
    name: "GCP Cloud Forensics",
    category: "cloud",
    description: "Investigate incidents in Google Cloud Platform environments including unauthorized access, resource abuse, and data exfiltration.",
    steps: [
      "Collect Cloud Audit Logs (Admin Activity, Data Access, System Event)",
      "Review VPC Flow Logs for network activity",
      "Analyze Cloud Security Command Center findings",
      "Snapshot affected Compute Engine instances",
      "Collect Cloud Storage access logs",
      "Review IAM policy changes and bindings",
      "Analyze GKE audit logs if Kubernetes is in use",
      "Check for service account key misuse",
      "Review Cloud Functions and Cloud Run invocation logs",
      "Examine BigQuery query logs for data access",
      "Preserve and export logs to Cloud Storage for analysis"
    ],
    tools: ["gcloud CLI", "Cloud Logging", "Security Command Center", "Chronicle", "BigQuery"],
    artifacts: ["Audit logs", "VPC Flow Logs", "Compute snapshots", "IAM reports", "Access logs"]
  },
  {
    name: "Microsoft 365 Forensics",
    category: "cloud",
    description: "Investigate compromised Microsoft 365 accounts, email-based attacks, data exfiltration via SharePoint/OneDrive, and Teams-based incidents.",
    steps: [
      "Collect Unified Audit Log (UAL) entries for target accounts",
      "Review Azure AD sign-in logs for suspicious authentication",
      "Analyze mailbox audit logs for email access and forwarding rules",
      "Check for inbox rules created by attackers (auto-forward, auto-delete)",
      "Examine eDiscovery for relevant email content",
      "Review SharePoint/OneDrive access and sharing logs",
      "Check for OAuth app consent grants (illicit consent attacks)",
      "Analyze Teams chat logs and file sharing activity",
      "Review Power Automate flows for automated exfiltration",
      "Check for admin role assignments and privilege escalation",
      "Document timeline of compromise indicators"
    ],
    tools: ["Microsoft Purview", "Azure AD Portal", "Exchange Online PowerShell", "Graph API", "Hawk"],
    artifacts: ["Unified Audit Logs", "Mailbox audit logs", "Sign-in logs", "Inbox rules", "OAuth grants"]
  },
  {
    name: "Container and Kubernetes Forensics",
    category: "cloud",
    description: "Investigate security incidents in containerized environments including container escapes, compromised pods, and supply chain attacks on container images.",
    steps: [
      "Collect Kubernetes audit logs for API server events",
      "Identify affected pods, containers, and nodes",
      "Capture container filesystem state before termination",
      "Analyze container image layers for malicious modifications",
      "Review Kubernetes RBAC configurations for privilege escalation",
      "Check for privileged containers and host mounts",
      "Analyze network policies and pod-to-pod communications",
      "Review container registry logs for image push/pull activity",
      "Examine init containers and sidecars for injected components",
      "Check for secrets exposure and service account token misuse",
      "Preserve etcd data for cluster state analysis"
    ],
    tools: ["kubectl", "crictl", "Falco", "Sysdig", "Trivy", "kube-hunter", "docker inspect"],
    artifacts: ["Kubernetes audit logs", "Container filesystem snapshots", "Image manifests", "Pod specs", "Network policies"]
  },

  // -- Malware Analysis --
  {
    name: "Static Malware Analysis",
    category: "malware",
    description: "Analyze malware samples without execution, examining file properties, embedded strings, imports, exports, and code structures to understand capabilities.",
    steps: [
      "Calculate file hashes (MD5, SHA-1, SHA-256) and check VirusTotal",
      "Identify file type using magic bytes and file command",
      "Extract embedded strings (ASCII and Unicode) with strings/FLOSS",
      "Analyze PE headers: imports, exports, sections, timestamps",
      "Check digital signature validity and signer information",
      "Identify packing or obfuscation using PEiD or Detect It Easy",
      "Unpack if packed (UPX, Themida, custom packers)",
      "Analyze import address table for API calls indicating behavior",
      "Extract embedded resources, configurations, and certificates",
      "Perform YARA rule matching against known malware families",
      "Disassemble with IDA Pro or Ghidra for code analysis",
      "Document IOCs, capabilities, and classification"
    ],
    tools: ["IDA Pro", "Ghidra", "PE-bear", "PEStudio", "FLOSS", "Detect It Easy", "YARA", "CFF Explorer"],
    artifacts: ["File hashes", "Embedded strings", "PE metadata", "YARA matches", "Disassembly"]
  },
  {
    name: "Dynamic Malware Analysis",
    category: "malware",
    description: "Execute malware in a controlled sandbox environment to observe runtime behavior including file system changes, registry modifications, network communications, and process activity.",
    steps: [
      "Prepare isolated analysis environment (VM or sandbox)",
      "Take a clean snapshot before execution",
      "Set up monitoring tools: Process Monitor, Wireshark, Regshot",
      "Configure network simulation (INetSim, FakeNet-NG)",
      "Execute the malware sample in the sandbox",
      "Monitor file system changes in real-time",
      "Capture registry modifications",
      "Record network traffic and DNS queries",
      "Track process creation and injection",
      "Observe persistence mechanisms installed",
      "Collect behavioral IOCs from monitoring tools",
      "Revert to clean snapshot after analysis"
    ],
    tools: ["Cuckoo Sandbox", "CAPE Sandbox", "ANY.RUN", "Joe Sandbox", "Process Monitor", "Wireshark", "FakeNet-NG", "INetSim"],
    artifacts: ["Behavioral report", "Network PCAP", "Dropped files", "Registry changes", "Process tree"]
  },
  {
    name: "Malware Reverse Engineering",
    category: "malware",
    description: "Perform deep code-level analysis of malware through disassembly and decompilation to understand algorithms, encryption, C2 protocols, and evasion techniques.",
    steps: [
      "Load binary into disassembler (IDA Pro, Ghidra)",
      "Identify the entry point and main function",
      "Analyze control flow and function call graph",
      "Identify encryption/encoding algorithms",
      "Reverse engineer C2 communication protocol",
      "Extract configuration data (C2 URLs, encryption keys, etc.)",
      "Identify anti-analysis techniques (anti-debug, anti-VM, anti-sandbox)",
      "Analyze privilege escalation and persistence mechanisms",
      "Document data exfiltration methods",
      "Write YARA rules based on unique code patterns",
      "Create decryption tools if applicable",
      "Produce detailed technical analysis report"
    ],
    tools: ["IDA Pro", "Ghidra", "x64dbg", "Binary Ninja", "Radare2", "dnSpy (.NET)", "jadx (Android)"],
    artifacts: ["Annotated disassembly", "Decompiled source", "Extracted configs", "YARA rules", "Decryption tools"]
  },
  {
    name: "Firmware Analysis",
    category: "malware",
    description: "Extract and analyze firmware images from IoT devices, routers, and embedded systems to identify backdoors, vulnerabilities, and malicious modifications.",
    steps: [
      "Obtain firmware image via download, extraction, or JTAG/SPI dump",
      "Identify firmware format and extract file system (binwalk)",
      "Analyze file system contents for configuration and binaries",
      "Search for hardcoded credentials and API keys",
      "Identify web server components and CGI scripts",
      "Analyze init scripts and startup services",
      "Check for known vulnerable library versions",
      "Look for backdoor accounts and unauthorized services",
      "Emulate firmware with QEMU for dynamic analysis",
      "Compare against known-good firmware versions",
      "Document vulnerabilities and IOCs"
    ],
    tools: ["binwalk", "firmware-mod-kit", "QEMU", "Ghidra", "firmwalker", "EMBA", "FAT (Firmware Analysis Toolkit)"],
    artifacts: ["Extracted file system", "Binary analysis", "Credential findings", "Vulnerability list"]
  }
];

// -----------------------------------------------------------------------------
// 2. FORENSIC ARTIFACTS
// -----------------------------------------------------------------------------
export const ARTIFACTS = [
  // =========================================================================
  // WINDOWS ARTIFACTS (85+)
  // =========================================================================

  // -- Registry Hives --
  {
    os: "Windows",
    name: "SAM Registry Hive",
    location: "C:\\Windows\\System32\\config\\SAM",
    description: "Contains local user account information, password hashes (LM/NTLM), account creation dates, last login times, and group memberships.",
    tool: "RegRipper, Registry Explorer, Mimikatz",
    significance: "Critical for identifying local accounts, determining last logon times, and extracting password hashes for credential analysis."
  },
  {
    os: "Windows",
    name: "SYSTEM Registry Hive",
    location: "C:\\Windows\\System32\\config\\SYSTEM",
    description: "Stores hardware configuration, services, drivers, mounted devices, timezone settings, computer name, and last shutdown time.",
    tool: "RegRipper, Registry Explorer",
    significance: "Essential for determining system timezone (critical for timeline accuracy), computer name, services configured to run, and last known shutdown."
  },
  {
    os: "Windows",
    name: "SOFTWARE Registry Hive",
    location: "C:\\Windows\\System32\\config\\SOFTWARE",
    description: "Contains installed software, OS version, network configuration, Windows Firewall settings, and system-wide application settings.",
    tool: "RegRipper, Registry Explorer",
    significance: "Reveals installed programs, network interfaces, firewall rules, and system-wide configuration changes."
  },
  {
    os: "Windows",
    name: "SECURITY Registry Hive",
    location: "C:\\Windows\\System32\\config\\SECURITY",
    description: "Contains security policy settings, cached domain logon credentials, LSA secrets, and audit policy configuration.",
    tool: "RegRipper, secretsdump.py",
    significance: "Stores cached domain credentials and LSA secrets that may contain service account passwords."
  },
  {
    os: "Windows",
    name: "NTUSER.DAT",
    location: "C:\\Users\\<username>\\NTUSER.DAT",
    description: "Per-user registry hive containing user preferences, recently accessed files, typed URLs, search history, UserAssist, and application settings.",
    tool: "RegRipper, Registry Explorer, RECmd",
    significance: "Primary source for user-specific activity including program execution (UserAssist), recent files, typed paths, and application usage."
  },
  {
    os: "Windows",
    name: "UsrClass.dat",
    location: "C:\\Users\\<username>\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat",
    description: "Contains shellbag data documenting folder access including folders on removable media, network shares, and zip archives.",
    tool: "ShellBags Explorer, RegRipper",
    significance: "Proves a user accessed specific folders even after deletion, including on USB drives and network shares."
  },
  {
    os: "Windows",
    name: "AmCache.hve",
    location: "C:\\Windows\\AppCompat\\Programs\\Amcache.hve",
    description: "Tracks application compatibility data including file paths, SHA-1 hashes, file sizes, publisher information, and timestamps of execution.",
    tool: "AmcacheParser (Eric Zimmerman), RegRipper",
    significance: "Provides evidence of program execution with SHA-1 hashes, useful for confirming malware execution even after deletion."
  },

  // -- Event Logs --
  {
    os: "Windows",
    name: "Security Event Log",
    location: "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
    description: "Records security-related events including logon/logoff (4624/4634), failed logons (4625), account management (4720-4738), privilege use (4672), and audit policy changes.",
    tool: "Event Viewer, EvtxECmd, hayabusa, Chainsaw",
    significance: "Primary source for authentication events, detecting brute force, pass-the-hash, lateral movement, and privilege escalation."
  },
  {
    os: "Windows",
    name: "System Event Log",
    location: "C:\\Windows\\System32\\winevt\\Logs\\System.evtx",
    description: "Records system events including service start/stop, driver loading, system time changes, and unexpected shutdowns.",
    tool: "Event Viewer, EvtxECmd, hayabusa",
    significance: "Shows service installations (Event ID 7045), driver loads, and system state changes relevant to persistence and anti-forensics."
  },
  {
    os: "Windows",
    name: "Application Event Log",
    location: "C:\\Windows\\System32\\winevt\\Logs\\Application.evtx",
    description: "Records application-level events including crashes, errors, and application-specific audit events.",
    tool: "Event Viewer, EvtxECmd",
    significance: "Application crashes may indicate exploitation attempts; application audit events provide usage evidence."
  },
  {
    os: "Windows",
    name: "PowerShell Operational Log",
    location: "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx",
    description: "Records PowerShell engine start/stop events, module loading, and script block logging if enabled.",
    tool: "Event Viewer, EvtxECmd, hayabusa",
    significance: "Critical for detecting PowerShell-based attacks, fileless malware, and post-exploitation activities."
  },
  {
    os: "Windows",
    name: "PowerShell Script Block Log",
    location: "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx (Event ID 4104)",
    description: "Contains the full text of executed PowerShell scripts and commands when script block logging is enabled.",
    tool: "Event Viewer, EvtxECmd, Get-WinEvent",
    significance: "Captures deobfuscated PowerShell code, revealing actual malicious commands even when heavily encoded."
  },
  {
    os: "Windows",
    name: "Sysmon Event Log",
    location: "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx",
    description: "Sysmon provides detailed process creation (Event ID 1), network connections (3), file creation (11), registry changes (12-14), and more.",
    tool: "Event Viewer, EvtxECmd, hayabusa, Chainsaw",
    significance: "Gold standard for endpoint detection: captures process command lines, parent processes, network connections, and file hashes."
  },
  {
    os: "Windows",
    name: "Windows Defender Log",
    location: "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Windows Defender%4Operational.evtx",
    description: "Records Windows Defender detections (1116/1117), exclusions added, real-time protection status changes, and scan results.",
    tool: "Event Viewer, EvtxECmd",
    significance: "Shows malware detections, quarantine actions, and importantly exclusions added by attackers to evade detection."
  },
  {
    os: "Windows",
    name: "Task Scheduler Log",
    location: "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-TaskScheduler%4Operational.evtx",
    description: "Records scheduled task creation, modification, execution, and deletion events.",
    tool: "Event Viewer, EvtxECmd",
    significance: "Scheduled tasks are a common persistence mechanism; this log reveals task creation and execution history."
  },
  {
    os: "Windows",
    name: "Terminal Services / RDP Log",
    location: "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
    description: "Records RDP session events: logon (21), reconnection (25), disconnection (24), logoff (23) with source IP addresses.",
    tool: "Event Viewer, EvtxECmd",
    significance: "Critical for tracking lateral movement via RDP, showing source IPs and session durations."
  },
  {
    os: "Windows",
    name: "WMI Activity Log",
    location: "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-WMI-Activity%4Operational.evtx",
    description: "Records WMI query execution, event subscription creation, and provider loading.",
    tool: "Event Viewer, EvtxECmd",
    significance: "WMI is used for lateral movement and persistence; this log captures WMI event subscriptions and remote WMI execution."
  },
  {
    os: "Windows",
    name: "Bits-Client Log",
    location: "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Bits-Client%4Operational.evtx",
    description: "Records BITS (Background Intelligent Transfer Service) job creation, progress, and completion.",
    tool: "Event Viewer, EvtxECmd",
    significance: "BITS is abused by attackers for stealthy file downloads and persistence; this log captures transfer details."
  },
  {
    os: "Windows",
    name: "Windows Firewall Log",
    location: "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx",
    description: "Records Windows Firewall rule changes, including rules added, modified, or deleted, and connection filtering events.",
    tool: "Event Viewer, EvtxECmd",
    significance: "Attackers add firewall rules to allow C2 traffic or disable host-based firewall protections."
  },
  {
    os: "Windows",
    name: "SMB Client/Server Logs",
    location: "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-SMBClient%4Security.evtx, Microsoft-Windows-SMBServer%4Security.evtx",
    description: "Records SMB file sharing access events including share access, authentication, and errors.",
    tool: "Event Viewer, EvtxECmd",
    significance: "SMB is used for lateral movement (PsExec, file shares); these logs track share access and failed authentication."
  },

  // -- Prefetch --
  {
    os: "Windows",
    name: "Prefetch Files",
    location: "C:\\Windows\\Prefetch\\*.pf",
    description: "Created when an application is executed, storing the executable name, run count, last 8 run times (Win10+), and files/directories referenced during the first 10 seconds.",
    tool: "PECmd (Eric Zimmerman), WinPrefetchView",
    significance: "Proves program execution with timestamps even after the executable is deleted. Run count shows frequency of use."
  },

  // -- ShimCache / AppCompatCache --
  {
    os: "Windows",
    name: "ShimCache (AppCompatCache)",
    location: "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache",
    description: "Application Compatibility Cache tracking executables the OS has seen, storing file path, size, and last modified timestamp. Insertion-ordered.",
    tool: "AppCompatCacheParser (Eric Zimmerman), ShimCacheParser",
    significance: "Shows evidence of file existence and potential execution. Survives file deletion and is useful for timeline analysis."
  },

  // -- SRUM --
  {
    os: "Windows",
    name: "SRUM Database",
    location: "C:\\Windows\\System32\\sru\\SRUDB.dat",
    description: "System Resource Usage Monitor tracking application resource usage: network data sent/received per app, CPU time, energy usage, for up to 30-60 days.",
    tool: "SrumECmd (Eric Zimmerman), srum-dump",
    significance: "Provides network usage per application over time, proving data transfer volumes and application activity even after deletion."
  },

  // -- Jump Lists --
  {
    os: "Windows",
    name: "Jump Lists (AutomaticDestinations)",
    location: "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\",
    description: "Stores recently and frequently accessed files per application with timestamps, file paths, and volume information.",
    tool: "JLECmd (Eric Zimmerman), JumpListExplorer",
    significance: "Reveals files opened by specific applications, including files on removable media and network shares."
  },
  {
    os: "Windows",
    name: "Jump Lists (CustomDestinations)",
    location: "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations\\",
    description: "Application-pinned items and custom entries in taskbar jump lists.",
    tool: "JLECmd (Eric Zimmerman)",
    significance: "Shows deliberately pinned items and application-specific recent file lists."
  },

  // -- LNK Files --
  {
    os: "Windows",
    name: "LNK (Shortcut) Files",
    location: "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\",
    description: "Windows shortcut files created when files are opened, containing target path, timestamps (MAC), volume serial number, MAC address, and file size.",
    tool: "LECmd (Eric Zimmerman), lnk_parser",
    significance: "Provides evidence of file access with timestamps, even referencing files on disconnected drives or deleted files."
  },

  // -- Shellbags --
  {
    os: "Windows",
    name: "Shellbags",
    location: "UsrClass.dat\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU and Bags",
    description: "Records folder access in Windows Explorer, including folder paths, view settings, and access timestamps for local, network, and removable folders.",
    tool: "ShellBags Explorer (Eric Zimmerman), RegRipper",
    significance: "Proves user navigated to specific folders, persists even after folder deletion or drive disconnection."
  },

  // -- USN Journal --
  {
    os: "Windows",
    name: "USN Journal ($UsnJrnl)",
    location: "C:\\$Extend\\$UsnJrnl:$J",
    description: "NTFS change journal recording file system changes: creation, deletion, rename, data modification, with timestamps and reason codes.",
    tool: "MFTECmd (Eric Zimmerman), ANJP",
    significance: "Massive source of file system activity. Shows file renames, deletions, and modifications even if files are gone."
  },

  // -- $MFT --
  {
    os: "Windows",
    name: "Master File Table ($MFT)",
    location: "C:\\$MFT",
    description: "NTFS metadata file containing an entry for every file and directory with timestamps (Created, Modified, Accessed, Entry Modified), file sizes, and parent directory references.",
    tool: "MFTECmd (Eric Zimmerman), analyzeMFT, Sleuth Kit (istat)",
    significance: "Definitive source for file existence, timestamps, and metadata. Resident files (small) have content stored directly in the MFT."
  },
  {
    os: "Windows",
    name: "$MFT $STANDARD_INFORMATION",
    location: "C:\\$MFT (attribute 0x10)",
    description: "Standard timestamp attribute showing Created, Modified, Accessed, and MFT Entry Modified timestamps. These can be modified by user-space tools (timestomping).",
    tool: "MFTECmd, analyzeMFT",
    significance: "Compare with $FILE_NAME timestamps to detect timestomping. $SI timestamps are easily modified; $FN timestamps are not."
  },
  {
    os: "Windows",
    name: "$MFT $FILE_NAME",
    location: "C:\\$MFT (attribute 0x30)",
    description: "File name attribute with its own set of MACB timestamps that are harder to modify than $STANDARD_INFORMATION timestamps.",
    tool: "MFTECmd, analyzeMFT",
    significance: "Used to detect timestomping: if $FN created time is after $SI created time, the $SI timestamp was likely manipulated."
  },
  {
    os: "Windows",
    name: "$LogFile (NTFS Journal)",
    location: "C:\\$LogFile",
    description: "NTFS transaction log recording metadata changes to the file system for recovery purposes. Contains recent file operations.",
    tool: "LogFileParser, NTFS Log Tracker",
    significance: "Contains detailed file system operations from recent activity, useful for recovering short-term historical actions."
  },

  // -- Browser Artifacts (Windows) --
  {
    os: "Windows",
    name: "Chrome History",
    location: "C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History",
    description: "SQLite database containing URL visits, search terms, page titles, visit counts, and transition types with timestamps.",
    tool: "Hindsight, DB Browser for SQLite, BrowsingHistoryView",
    significance: "Shows browsing activity, search queries, and download sources with precise timestamps."
  },
  {
    os: "Windows",
    name: "Chrome Downloads",
    location: "C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History (downloads table)",
    description: "Records all file downloads including URL, file path, start/end times, file size, and mime type.",
    tool: "Hindsight, DB Browser for SQLite",
    significance: "Tracks malware delivery, tool downloads, and data staging for exfiltration."
  },
  {
    os: "Windows",
    name: "Chrome Cookies",
    location: "C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies",
    description: "SQLite database of browser cookies with domain, name, value, creation and expiry times, and security flags.",
    tool: "Hindsight, DB Browser for SQLite",
    significance: "Reveals authenticated sessions and site access. Cookie theft is a common post-exploitation technique."
  },
  {
    os: "Windows",
    name: "Chrome Login Data",
    location: "C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
    description: "Stores saved website credentials encrypted with DPAPI (Windows) including URLs, usernames, and encrypted passwords.",
    tool: "Hindsight, ChromePass",
    significance: "Attackers frequently harvest browser-saved credentials for further access."
  },
  {
    os: "Windows",
    name: "Chrome Cache",
    location: "C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache\\Cache_Data\\",
    description: "Browser cache storing web content: HTML pages, images, scripts, and other resources with HTTP headers.",
    tool: "ChromeCacheView, Hindsight",
    significance: "May contain cached copies of accessed web pages, images, and scripts including malicious content."
  },

  // -- Scheduled Tasks --
  {
    os: "Windows",
    name: "Scheduled Tasks (XML)",
    location: "C:\\Windows\\System32\\Tasks\\",
    description: "XML files defining scheduled tasks including triggers, actions, principals, and creation metadata. Each file represents one task.",
    tool: "Autoruns, Task Scheduler, KAPE",
    significance: "Common persistence mechanism. Malware creates scheduled tasks to survive reboots and maintain access."
  },
  {
    os: "Windows",
    name: "Scheduled Tasks (Registry)",
    location: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree",
    description: "Registry entries for scheduled tasks containing task GUID, path, hash, and dynamic info including last run time.",
    tool: "Registry Explorer, RegRipper",
    significance: "Registry task entries persist even after XML task files are deleted, providing evidence of historical tasks."
  },

  // -- Services --
  {
    os: "Windows",
    name: "Windows Services",
    location: "SYSTEM\\CurrentControlSet\\Services\\",
    description: "Registry entries for all Windows services including service binary path, start type, display name, and dependencies.",
    tool: "Registry Explorer, RegRipper, Autoruns",
    significance: "Service creation is a common persistence and privilege escalation technique (Event ID 7045 in System log)."
  },

  // -- WMI Persistence --
  {
    os: "Windows",
    name: "WMI Event Subscriptions",
    location: "C:\\Windows\\System32\\wbem\\Repository\\",
    description: "WMI repository (OBJECTS.DATA, INDEX.BTR, MAPPING*.MAP) containing permanent WMI event subscriptions used for persistence.",
    tool: "PyWMIPersistenceFinder, WMI Explorer",
    significance: "WMI event subscriptions are a stealthy persistence mechanism that can execute commands on system events."
  },

  // -- PowerShell --
  {
    os: "Windows",
    name: "PowerShell Console History",
    location: "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
    description: "PSReadLine history file containing all PowerShell commands typed by the user in console sessions.",
    tool: "Text editor, KAPE",
    significance: "Contains raw PowerShell commands executed interactively, often revealing attacker actions in post-exploitation."
  },
  {
    os: "Windows",
    name: "PowerShell Transcription Logs",
    location: "Configured via Group Policy or registry",
    description: "Full transcripts of PowerShell sessions including input, output, and timestamps when transcription logging is enabled.",
    tool: "Text editor, KAPE",
    significance: "Captures complete PowerShell sessions with output, providing detailed evidence of attacker activity."
  },

  // -- Startup and Persistence --
  {
    os: "Windows",
    name: "Run/RunOnce Keys",
    location: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run, NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    description: "Registry keys specifying programs to execute at startup for all users (HKLM) or specific users (HKCU).",
    tool: "RegRipper, Autoruns, Registry Explorer",
    significance: "Extremely common malware persistence location. Check both HKLM and HKCU, Run and RunOnce variants."
  },
  {
    os: "Windows",
    name: "Startup Folder",
    location: "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",
    description: "Programs and shortcuts placed here execute automatically when the user logs on.",
    tool: "File explorer, Autoruns",
    significance: "Simple but effective persistence mechanism; look for unexpected executables, scripts, or shortcut files."
  },
  {
    os: "Windows",
    name: "Winlogon Registry Entries",
    location: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    description: "Winlogon configuration including Shell, Userinit, and Notify values that specify programs to load during login.",
    tool: "RegRipper, Autoruns",
    significance: "Modifications to Shell or Userinit values can execute malware at every login before the user desktop loads."
  },

  // -- Recent Activity --
  {
    os: "Windows",
    name: "UserAssist",
    location: "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
    description: "Records GUI program execution with run count, last run time, and focus time. Values are ROT-13 encoded.",
    tool: "UserAssist (Didier Stevens), Registry Explorer",
    significance: "Tracks programs launched via Explorer/desktop with execution counts and timestamps."
  },
  {
    os: "Windows",
    name: "RecentDocs MRU",
    location: "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
    description: "Tracks recently opened documents organized by file extension, with MRU ordering.",
    tool: "Registry Explorer, RegRipper",
    significance: "Shows what documents a user opened recently, organized by file type."
  },
  {
    os: "Windows",
    name: "TypedPaths",
    location: "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths",
    description: "Records paths manually typed into Windows Explorer address bar.",
    tool: "Registry Explorer, RegRipper",
    significance: "Shows paths the user deliberately navigated to, including UNC paths to network shares."
  },
  {
    os: "Windows",
    name: "WordWheelQuery",
    location: "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery",
    description: "Records searches performed in Windows Explorer search bar.",
    tool: "Registry Explorer, RegRipper",
    significance: "Reveals what a user was searching for on the local system."
  },
  {
    os: "Windows",
    name: "LastVisitedPidlMRU",
    location: "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU",
    description: "Records the application and directory location for the last files opened via common Open/Save dialogs.",
    tool: "Registry Explorer, RegRipper",
    significance: "Shows which applications were used to open/save files and from which directories."
  },
  {
    os: "Windows",
    name: "OpenSavePidlMRU",
    location: "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU",
    description: "Records files accessed through Open/Save dialog boxes organized by file extension.",
    tool: "Registry Explorer, RegRipper",
    significance: "Tracks specific files opened or saved through standard Windows dialogs."
  },

  // -- Network Artifacts --
  {
    os: "Windows",
    name: "Network Profiles",
    location: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles",
    description: "Records network connections with profile name, first/last connect timestamps, and network category (public/private/domain).",
    tool: "Registry Explorer, RegRipper",
    significance: "Shows networks the system connected to with timestamps, useful for placing a device at a location."
  },
  {
    os: "Windows",
    name: "Network Signatures",
    location: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures",
    description: "Maps network profiles to their MAC addresses (gateway) and DNS suffixes for identifying specific networks.",
    tool: "Registry Explorer",
    significance: "Links network profile names to specific physical networks via gateway MAC addresses."
  },
  {
    os: "Windows",
    name: "WLAN AutoConfig Log",
    location: "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-WLAN-AutoConfig%4Operational.evtx",
    description: "Records wireless network connections, disconnections, and authentication events.",
    tool: "Event Viewer, EvtxECmd",
    significance: "Tracks Wi-Fi network connections with timestamps and SSIDs."
  },
  {
    os: "Windows",
    name: "DNS Client Cache",
    location: "In memory (ipconfig /displaydns) or ETL logs",
    description: "Cached DNS resolution results showing domains recently resolved by the system.",
    tool: "ipconfig /displaydns, Volatility (dnsresolver)",
    significance: "Shows recently resolved domain names, potentially revealing C2 communication or malicious site access."
  },

  // -- Recycle Bin --
  {
    os: "Windows",
    name: "Recycle Bin ($I files)",
    location: "C:\\$Recycle.Bin\\<SID>\\$I*",
    description: "Metadata files for each recycled item containing original path, deletion timestamp, and file size.",
    tool: "RBCmd (Eric Zimmerman), Rifiuti2",
    significance: "Reveals deleted file paths and timestamps, potentially recovering evidence of anti-forensic file deletion."
  },
  {
    os: "Windows",
    name: "Recycle Bin ($R files)",
    location: "C:\\$Recycle.Bin\\<SID>\\$R*",
    description: "Actual content of recycled files, recoverable unless the recycle bin has been emptied.",
    tool: "RBCmd, file copy",
    significance: "May contain recoverable copies of deleted evidence files."
  },

  // -- Volume Shadow Copies --
  {
    os: "Windows",
    name: "Volume Shadow Copies",
    location: "System Volume Information",
    description: "Point-in-time snapshots of the volume allowing recovery of previous versions of files, registry hives, and system state.",
    tool: "vssadmin, vshadowinfo, Arsenal Image Mounter",
    significance: "Can recover previous versions of modified or deleted files, including registry hives from before an incident."
  },

  // -- Windows Search --
  {
    os: "Windows",
    name: "Windows Search Index",
    location: "C:\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Windows.edb",
    description: "Extensible Storage Engine (ESE) database containing indexed file metadata, partial content, and email data for Windows Search.",
    tool: "ESEDatabaseView, WinSearchDBAnalyzer",
    significance: "Contains metadata and snippets of file content even for deleted files, including emails indexed from Outlook."
  },

  // -- Thumbcache --
  {
    os: "Windows",
    name: "Thumbcache",
    location: "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Windows\\Explorer\\thumbcache_*.db",
    description: "Thumbnail database containing cached image thumbnails for files viewed in Explorer, even after original files are deleted.",
    tool: "Thumbcache Viewer, thumbs_viewer",
    significance: "May contain thumbnail images of deleted photos/documents proving their prior existence."
  },

  // -- RDP --
  {
    os: "Windows",
    name: "RDP Bitmap Cache",
    location: "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Terminal Server Client\\Cache\\",
    description: "Cached screen fragments (tiles) from outbound RDP sessions stored as BMP bitmap data.",
    tool: "bmc-tools, RDP Bitmap Cache Parser",
    significance: "Allows partial visual reconstruction of what the user saw during RDP sessions to remote systems."
  },
  {
    os: "Windows",
    name: "Default.rdp",
    location: "C:\\Users\\<user>\\Documents\\Default.rdp",
    description: "Default RDP connection settings including last server connected to.",
    tool: "Text editor",
    significance: "May reveal the last RDP destination server address."
  },
  {
    os: "Windows",
    name: "RDP Connection History",
    location: "NTUSER.DAT\\Software\\Microsoft\\Terminal Server Client\\Servers",
    description: "Registry entries recording RDP target servers with username hints.",
    tool: "Registry Explorer, RegRipper",
    significance: "Lists servers the user connected to via RDP with associated usernames."
  },

  // -- BITS --
  {
    os: "Windows",
    name: "BITS Queue Database",
    location: "C:\\ProgramData\\Microsoft\\Network\\Downloader\\qmgr.db",
    description: "Background Intelligent Transfer Service database containing pending and recent file transfers with URLs and file paths.",
    tool: "BitsParser, KAPE",
    significance: "BITS jobs can be used by malware for stealthy downloads; the queue database reveals transfer details."
  },

  // -- ETW / ETL --
  {
    os: "Windows",
    name: "ETW Trace Logs",
    location: "C:\\Windows\\System32\\LogFiles\\WMI\\",
    description: "Event Tracing for Windows log files capturing detailed system events from various providers.",
    tool: "tracerpt, PerfView, ETW Explorer",
    significance: "Contains detailed performance and diagnostic data that may capture evidence not in standard event logs."
  },

  // -- Group Policy --
  {
    os: "Windows",
    name: "Group Policy History",
    location: "C:\\Windows\\System32\\GroupPolicy\\",
    description: "Local Group Policy configuration including security settings, software restrictions, and script assignments.",
    tool: "Text editor (for registry.pol), LGPO",
    significance: "Attackers may modify GPO to weaken security settings or establish persistence via logon scripts."
  },

  // -- WER --
  {
    os: "Windows",
    name: "WER Reports",
    location: "C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive\\",
    description: "Windows Error Reporting crash dumps and metadata for application crashes.",
    tool: "File explorer, WER analysis tools",
    significance: "Application crashes during exploitation attempts leave WER reports with crash details and mini-dumps."
  },

  // -- Autoruns --
  {
    os: "Windows",
    name: "AppInit_DLLs",
    location: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs",
    description: "DLLs loaded into every user-mode process that loads user32.dll, used as a DLL injection persistence technique.",
    tool: "Autoruns, Registry Explorer",
    significance: "Classic DLL injection persistence mechanism; any DLL listed here loads into most processes."
  },
  {
    os: "Windows",
    name: "Image File Execution Options (IFEO)",
    location: "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\",
    description: "Debugger attachment settings per executable. Can be abused to redirect execution of legitimate programs to malicious ones.",
    tool: "Autoruns, Registry Explorer",
    significance: "IFEO debugger persistence: sets a 'debugger' for a system binary that actually runs malware instead."
  },
  {
    os: "Windows",
    name: "COM Object Hijacking",
    location: "HKCU\\Software\\Classes\\CLSID\\",
    description: "User-level COM object registrations that override system-level COM objects, enabling DLL loading persistence.",
    tool: "Autoruns, Registry Explorer",
    significance: "COM hijacking is a stealthy persistence technique that loads attacker DLLs when COM objects are instantiated."
  },

  // -- Additional Windows --
  {
    os: "Windows",
    name: "BAM/DAM (Background Activity Moderator)",
    location: "SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\<SID>",
    description: "Tracks application execution with full paths and last execution timestamps on Windows 10 1709+.",
    tool: "Registry Explorer, RegRipper",
    significance: "Provides evidence of program execution with paths and timestamps, useful for execution timeline."
  },
  {
    os: "Windows",
    name: "ActivitiesCache.db",
    location: "C:\\Users\\<user>\\AppData\\Local\\ConnectedDevicesPlatform\\<id>\\ActivitiesCache.db",
    description: "Windows Timeline/Activity History database tracking application usage, file opens, and web browsing across devices.",
    tool: "WxTCmd (Eric Zimmerman)",
    significance: "Rich source of user activity including app usage durations and clipboard data if synced."
  },
  {
    os: "Windows",
    name: "NTFS $I30 (Index Attributes)",
    location: "NTFS directory index entries",
    description: "NTFS directory index entries containing file names and timestamps for files that existed in a directory, including deleted entries in slack space.",
    tool: "INDXParse, Sleuth Kit",
    significance: "Recovers evidence of deleted file names from directory index slack space."
  },
  {
    os: "Windows",
    name: "SetupAPI Logs",
    location: "C:\\Windows\\INF\\setupapi.dev.log",
    description: "Records device driver installation events including timestamps, device IDs, and driver details for all Plug and Play devices.",
    tool: "Text editor, KAPE",
    significance: "Provides first-connected timestamps for USB and other removable devices."
  },
  {
    os: "Windows",
    name: "MountPoints2",
    location: "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2",
    description: "Per-user registry key tracking mounted volumes and network shares the user has accessed.",
    tool: "Registry Explorer, RegRipper",
    significance: "Links specific users to USB device usage and network share access."
  },
  {
    os: "Windows",
    name: "Pagefile.sys",
    location: "C:\\pagefile.sys",
    description: "Windows virtual memory paging file that may contain fragments of process memory, including passwords, documents, and malware artifacts.",
    tool: "strings, Bulk Extractor, page_brute",
    significance: "Contains memory fragments that may include sensitive data from processes that were paged to disk."
  },
  {
    os: "Windows",
    name: "Hiberfil.sys",
    location: "C:\\hiberfil.sys",
    description: "Hibernation file containing a compressed copy of the entire system memory at the time of hibernation.",
    tool: "Volatility (hibinfo), Arsenal Hibernation Recon",
    significance: "Full memory image from last hibernation; can be analyzed with memory forensics tools."
  },
  {
    os: "Windows",
    name: "Credential Manager Vault",
    location: "C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Vault\\",
    description: "Windows Credential Manager storage containing saved web and Windows credentials in encrypted vault files.",
    tool: "vaultcmd, Mimikatz, NirSoft CredentialsFileView",
    significance: "Stored credentials can be decrypted with user context; attackers harvest these for lateral movement."
  },
  {
    os: "Windows",
    name: "DPAPI Master Keys",
    location: "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Protect\\<SID>\\",
    description: "Data Protection API master key files used to encrypt/decrypt user secrets including browser passwords, credential manager entries, and certificates.",
    tool: "Mimikatz (dpapi::masterkey), SharpDPAPI",
    significance: "DPAPI master keys are needed to decrypt browser passwords, credential manager entries, and other user secrets."
  },

  // =========================================================================
  // LINUX ARTIFACTS (65+)
  // =========================================================================
  {
    os: "Linux",
    name: "auth.log / secure",
    location: "/var/log/auth.log (Debian) or /var/log/secure (RHEL)",
    description: "Authentication events including SSH logins, sudo usage, PAM module activity, user additions, and password changes.",
    tool: "grep, awk, Splunk, ELK",
    significance: "Primary source for login activity, brute force detection, privilege escalation, and unauthorized access attempts."
  },
  {
    os: "Linux",
    name: "syslog / messages",
    location: "/var/log/syslog (Debian) or /var/log/messages (RHEL)",
    description: "General system messages from various services and the kernel, including hardware events, service status, and errors.",
    tool: "grep, awk, journalctl, Splunk",
    significance: "Broad system activity log useful for correlating events across services."
  },
  {
    os: "Linux",
    name: "wtmp",
    location: "/var/log/wtmp",
    description: "Binary log of all login and logout events including user, terminal, source IP, and timestamps.",
    tool: "last, utmpdump",
    significance: "Definitive record of user login sessions with source addresses and durations."
  },
  {
    os: "Linux",
    name: "btmp",
    location: "/var/log/btmp",
    description: "Binary log of failed login attempts including username tried, source address, and timestamp.",
    tool: "lastb, utmpdump",
    significance: "Reveals brute force attacks, password spraying, and failed access attempts."
  },
  {
    os: "Linux",
    name: "utmp",
    location: "/var/run/utmp",
    description: "Binary file tracking currently logged-in users, their terminals, and login times.",
    tool: "who, w, utmpdump",
    significance: "Shows current active sessions at the time of acquisition."
  },
  {
    os: "Linux",
    name: "lastlog",
    location: "/var/log/lastlog",
    description: "Records the last login time and source for each user account on the system.",
    tool: "lastlog command",
    significance: "Quick reference for when each account was last used and from where."
  },
  {
    os: "Linux",
    name: "kern.log",
    location: "/var/log/kern.log",
    description: "Kernel messages including hardware events, driver issues, SELinux/AppArmor denials, and kernel module loading.",
    tool: "grep, dmesg",
    significance: "Shows kernel module loading (rootkit detection), hardware changes, and security module denials."
  },
  {
    os: "Linux",
    name: "cron.log",
    location: "/var/log/cron or /var/log/syslog (cron entries)",
    description: "Log of cron job executions, modifications, and errors.",
    tool: "grep, journalctl",
    significance: "Cron jobs are a common persistence mechanism; this log shows when cron jobs executed."
  },
  {
    os: "Linux",
    name: "User Crontab Files",
    location: "/var/spool/cron/crontabs/<user>",
    description: "Per-user crontab files defining scheduled tasks.",
    tool: "crontab -l, cat",
    significance: "Attackers often install cron jobs for persistence; check all user crontabs."
  },
  {
    os: "Linux",
    name: "System Crontab",
    location: "/etc/crontab, /etc/cron.d/, /etc/cron.daily/, etc.",
    description: "System-wide cron configuration files and directories for periodic task execution.",
    tool: "cat, ls",
    significance: "System cron directories can hide persistent malicious tasks among legitimate ones."
  },
  {
    os: "Linux",
    name: "bash_history",
    location: "/home/<user>/.bash_history or ~/.bash_history",
    description: "Command history for bash shell sessions containing all commands typed by the user.",
    tool: "cat, grep",
    significance: "Critical evidence of user/attacker activity. Check for data exfiltration, tool usage, and reconnaissance commands."
  },
  {
    os: "Linux",
    name: "zsh_history",
    location: "/home/<user>/.zsh_history",
    description: "Command history for zsh shell sessions, often includes timestamps if EXTENDED_HISTORY is set.",
    tool: "cat, grep",
    significance: "Same significance as bash_history; zsh may include timestamps for each command."
  },
  {
    os: "Linux",
    name: ".bash_profile / .bashrc",
    location: "/home/<user>/.bash_profile, /home/<user>/.bashrc",
    description: "Shell initialization scripts executed on login (profile) or shell start (rc). Can be backdoored for persistence.",
    tool: "cat, diff against known-good",
    significance: "Attackers insert backdoor commands in shell profiles for persistence on login."
  },
  {
    os: "Linux",
    name: "/etc/passwd",
    location: "/etc/passwd",
    description: "User account database containing username, UID, GID, home directory, and login shell for all accounts.",
    tool: "cat, getent passwd",
    significance: "Check for unauthorized accounts, UID 0 accounts (root equivalents), and unusual shells."
  },
  {
    os: "Linux",
    name: "/etc/shadow",
    location: "/etc/shadow",
    description: "Password hash file containing encrypted passwords, password change dates, and account expiration settings.",
    tool: "cat (as root), john, hashcat",
    significance: "Contains password hashes; check for recently changed passwords and accounts with no password set."
  },
  {
    os: "Linux",
    name: "/etc/group",
    location: "/etc/group",
    description: "Group membership database listing all groups and their member users.",
    tool: "cat, getent group",
    significance: "Check for unauthorized additions to privileged groups (sudo, wheel, docker, adm)."
  },
  {
    os: "Linux",
    name: "/etc/sudoers",
    location: "/etc/sudoers, /etc/sudoers.d/",
    description: "Sudo configuration defining which users can execute commands as root or other users.",
    tool: "visudo, cat",
    significance: "Attackers modify sudoers for privilege escalation; check for NOPASSWD entries and unusual rules."
  },
  {
    os: "Linux",
    name: "SSH Authorized Keys",
    location: "/home/<user>/.ssh/authorized_keys",
    description: "Public keys authorized for SSH login without password for each user account.",
    tool: "cat, ssh-keygen -l",
    significance: "Attackers add their public keys for persistent passwordless SSH access."
  },
  {
    os: "Linux",
    name: "SSH Known Hosts",
    location: "/home/<user>/.ssh/known_hosts",
    description: "SSH server fingerprints for previously connected hosts.",
    tool: "cat, ssh-keygen -l",
    significance: "Reveals SSH destinations the user connected to, indicating lateral movement targets."
  },
  {
    os: "Linux",
    name: "SSH Config",
    location: "/home/<user>/.ssh/config, /etc/ssh/sshd_config",
    description: "SSH client and server configuration including host aliases, key settings, and access controls.",
    tool: "cat",
    significance: "Client config reveals connection shortcuts and tunnels; server config shows access controls and logging settings."
  },
  {
    os: "Linux",
    name: "SSH Private Keys",
    location: "/home/<user>/.ssh/id_rsa, id_ed25519, id_ecdsa",
    description: "SSH private keys that can be used to authenticate to remote systems.",
    tool: "ls -la, ssh-keygen -l",
    significance: "Stolen private keys enable lateral movement to any system with corresponding authorized_keys entry."
  },
  {
    os: "Linux",
    name: "/proc filesystem",
    location: "/proc/",
    description: "Virtual filesystem exposing kernel and process information including running processes, network connections, loaded modules, and system configuration.",
    tool: "ls, cat (various /proc entries)",
    significance: "Live system state: processes (/proc/PID/), network (/proc/net/), modules (/proc/modules), mounts (/proc/mounts)."
  },
  {
    os: "Linux",
    name: "/proc/PID/cmdline",
    location: "/proc/<PID>/cmdline",
    description: "Command line arguments used to start a process.",
    tool: "cat, strings",
    significance: "Reveals full command lines of running processes including potentially malicious arguments."
  },
  {
    os: "Linux",
    name: "/proc/PID/exe",
    location: "/proc/<PID>/exe",
    description: "Symbolic link to the actual executable file for a running process.",
    tool: "ls -la, readlink",
    significance: "Can identify deleted executables still running in memory (shows '(deleted)' suffix)."
  },
  {
    os: "Linux",
    name: "/proc/PID/fd",
    location: "/proc/<PID>/fd/",
    description: "Directory containing symbolic links to all open file descriptors for a process.",
    tool: "ls -la",
    significance: "Shows all files, sockets, and pipes open by a process, revealing data access and network connections."
  },
  {
    os: "Linux",
    name: "/proc/PID/maps",
    location: "/proc/<PID>/maps",
    description: "Memory map of a process showing all mapped regions, permissions, and backing files.",
    tool: "cat",
    significance: "Reveals loaded libraries and injected memory regions; useful for detecting process injection."
  },
  {
    os: "Linux",
    name: "/proc/PID/environ",
    location: "/proc/<PID>/environ",
    description: "Environment variables for a running process, null-byte separated.",
    tool: "cat, strings, tr '\\0' '\\n'",
    significance: "May contain credentials passed via environment variables, API keys, or paths to attacker tools."
  },
  {
    os: "Linux",
    name: "Systemd Journal",
    location: "/var/log/journal/ or /run/log/journal/",
    description: "Structured binary log from systemd-journald containing all system and service logs with rich metadata.",
    tool: "journalctl",
    significance: "Comprehensive structured log source; can filter by service, priority, time range, and boot."
  },
  {
    os: "Linux",
    name: "Systemd Service Files",
    location: "/etc/systemd/system/, /usr/lib/systemd/system/, ~/.config/systemd/user/",
    description: "Service unit files defining system services, their dependencies, and execution parameters.",
    tool: "systemctl, cat",
    significance: "Attackers create or modify service files for persistence. Check for new or recently modified unit files."
  },
  {
    os: "Linux",
    name: "Systemd Timers",
    location: "/etc/systemd/system/*.timer",
    description: "Systemd timer units that schedule periodic execution of associated service units.",
    tool: "systemctl list-timers",
    significance: "Modern replacement for cron; can be used as a persistence mechanism."
  },
  {
    os: "Linux",
    name: "apt History Log",
    location: "/var/log/apt/history.log",
    description: "Records package installation, removal, and upgrade history on Debian-based systems.",
    tool: "cat, grep",
    significance: "Shows software installed by attackers or removed as anti-forensics."
  },
  {
    os: "Linux",
    name: "dpkg Log",
    location: "/var/log/dpkg.log",
    description: "Detailed package manager log for Debian-based systems showing individual package operations.",
    tool: "cat, grep",
    significance: "More detailed than apt history; shows exact package operations with timestamps."
  },
  {
    os: "Linux",
    name: "yum/dnf History",
    location: "/var/log/yum.log or dnf history",
    description: "Package management history on RHEL-based systems.",
    tool: "cat, yum history, dnf history",
    significance: "Shows package installations on RedHat/CentOS systems."
  },
  {
    os: "Linux",
    name: "Network Interfaces Config",
    location: "/etc/network/interfaces, /etc/sysconfig/network-scripts/, /etc/netplan/",
    description: "Network interface configuration files defining IP addresses, routes, DNS, and network parameters.",
    tool: "cat, ip addr",
    significance: "Check for unauthorized network changes, additional IPs, or promiscuous mode configurations."
  },
  {
    os: "Linux",
    name: "/etc/hosts",
    location: "/etc/hosts",
    description: "Static hostname resolution file mapping IP addresses to hostnames.",
    tool: "cat",
    significance: "Attackers modify /etc/hosts to redirect DNS, block security updates, or facilitate internal pivoting."
  },
  {
    os: "Linux",
    name: "/etc/resolv.conf",
    location: "/etc/resolv.conf",
    description: "DNS resolver configuration specifying nameservers and search domains.",
    tool: "cat",
    significance: "DNS poisoning attacks may modify resolv.conf to redirect DNS queries to attacker-controlled servers."
  },
  {
    os: "Linux",
    name: "iptables/nftables Rules",
    location: "/etc/iptables/rules.v4, nft list ruleset",
    description: "Firewall rules defining allowed and blocked network traffic.",
    tool: "iptables -L, nft list ruleset",
    significance: "Attackers may modify firewall rules to allow C2 traffic or block security tools."
  },
  {
    os: "Linux",
    name: "/etc/rc.local",
    location: "/etc/rc.local",
    description: "Script executed at the end of the boot process on systems that support it.",
    tool: "cat",
    significance: "Legacy persistence mechanism; check for unauthorized commands."
  },
  {
    os: "Linux",
    name: "init.d Scripts",
    location: "/etc/init.d/",
    description: "SysV init scripts for system services.",
    tool: "ls, cat",
    significance: "Legacy persistence location; check for new or modified service scripts."
  },
  {
    os: "Linux",
    name: "Loaded Kernel Modules",
    location: "/proc/modules, /lib/modules/",
    description: "Currently loaded kernel modules and available module files.",
    tool: "lsmod, modinfo",
    significance: "Rootkits load malicious kernel modules; compare with known-good baseline."
  },
  {
    os: "Linux",
    name: "/tmp and /var/tmp",
    location: "/tmp/, /var/tmp/, /dev/shm/",
    description: "Temporary directories often used by attackers to stage tools, store exfiltrated data, and execute payloads.",
    tool: "ls -la, find",
    significance: "Common staging areas for attacker tools and malware; /dev/shm is RAM-backed and favored for fileless attacks."
  },
  {
    os: "Linux",
    name: "at Jobs",
    location: "/var/spool/at/",
    description: "Scheduled one-time job files created with the 'at' command.",
    tool: "atq, ls",
    significance: "One-time scheduled tasks can be used for delayed execution of malicious commands."
  },
  {
    os: "Linux",
    name: "Mail Spool",
    location: "/var/mail/<user> or /var/spool/mail/<user>",
    description: "Local mailbox files containing system-generated emails for user accounts.",
    tool: "cat, mail",
    significance: "May contain cron job output, system alerts, and error messages revealing attacker activity."
  },
  {
    os: "Linux",
    name: "Audit Log (auditd)",
    location: "/var/log/audit/audit.log",
    description: "Linux Audit Framework log containing detailed system call auditing, file access, and security events.",
    tool: "ausearch, aureport, Splunk",
    significance: "Most detailed Linux logging when configured; captures syscalls, file access, network connections, and commands."
  },
  {
    os: "Linux",
    name: "SELinux/AppArmor Logs",
    location: "/var/log/audit/audit.log (SELinux), /var/log/kern.log (AppArmor)",
    description: "Mandatory access control denials and policy violations from SELinux or AppArmor.",
    tool: "ausearch -m AVC, aa-status",
    significance: "MAC denials may indicate exploitation attempts that violate security policies."
  },
  {
    os: "Linux",
    name: "Docker Logs",
    location: "/var/lib/docker/containers/<id>/<id>-json.log",
    description: "Container stdout/stderr logs and Docker daemon logs.",
    tool: "docker logs, journalctl -u docker",
    significance: "Container activity logs; check for container escapes and unauthorized container creation."
  },
  {
    os: "Linux",
    name: "Docker Configuration",
    location: "/var/lib/docker/, /etc/docker/daemon.json",
    description: "Docker daemon configuration, image layers, volumes, and network settings.",
    tool: "docker inspect, ls",
    significance: "Check for privileged containers, host mounts, and modified images."
  },
  {
    os: "Linux",
    name: ".profile / .login",
    location: "/home/<user>/.profile",
    description: "Login profile scripts executed on user login, varying by shell.",
    tool: "cat",
    significance: "Shell profile backdoors execute on each login."
  },
  {
    os: "Linux",
    name: "PAM Configuration",
    location: "/etc/pam.d/",
    description: "Pluggable Authentication Module configuration for various services.",
    tool: "cat, diff",
    significance: "PAM backdoors can enable authentication bypass or credential harvesting."
  },
  {
    os: "Linux",
    name: "/etc/ld.so.preload",
    location: "/etc/ld.so.preload",
    description: "Specifies shared libraries to preload before all others for every dynamically linked program.",
    tool: "cat",
    significance: "Classic library injection persistence; listed libraries load into every process."
  },
  {
    os: "Linux",
    name: "Webserver Access Logs",
    location: "/var/log/apache2/access.log, /var/log/nginx/access.log, /var/log/httpd/access_log",
    description: "HTTP request logs including client IP, request method, URL, status code, user agent, and referrer.",
    tool: "grep, awk, GoAccess, Splunk",
    significance: "Critical for web compromise investigations: shows exploitation attempts, web shells, and data access."
  },
  {
    os: "Linux",
    name: "Webserver Error Logs",
    location: "/var/log/apache2/error.log, /var/log/nginx/error.log",
    description: "HTTP server error logs including application errors, configuration issues, and failed requests.",
    tool: "grep, tail",
    significance: "Exploitation attempts often generate errors; error logs complement access logs."
  },
  {
    os: "Linux",
    name: "MySQL/MariaDB Logs",
    location: "/var/log/mysql/, /var/log/mariadb/",
    description: "Database query logs, error logs, slow query logs, and binary logs.",
    tool: "cat, mysqlbinlog",
    significance: "SQL injection evidence, unauthorized data access, and database manipulation."
  },
  {
    os: "Linux",
    name: "/proc/net/tcp and /proc/net/udp",
    location: "/proc/net/tcp, /proc/net/udp",
    description: "Kernel tables listing all active TCP and UDP connections with local/remote addresses, state, and owning inode.",
    tool: "cat, ss, netstat",
    significance: "Live network connection state showing active connections and listening ports."
  },
  {
    os: "Linux",
    name: "Swap Partition/File",
    location: "/dev/sdXN (swap partition) or /swapfile",
    description: "Linux swap space containing paged-out memory fragments that may include credentials, keys, and process data.",
    tool: "strings, Bulk Extractor, swap_digger",
    significance: "Swap may contain sensitive data paged out of RAM including passwords and encryption keys."
  },
  {
    os: "Linux",
    name: "Core Dumps",
    location: "/var/crash/, /var/lib/systemd/coredump/, core files",
    description: "Process memory dumps generated on crash, containing full process state at time of failure.",
    tool: "gdb, coredumpctl",
    significance: "Core dumps from exploited processes contain exploitation evidence and may include injected payloads."
  },
  {
    os: "Linux",
    name: "/etc/environment",
    location: "/etc/environment",
    description: "System-wide environment variable definitions applied to all users and sessions.",
    tool: "cat",
    significance: "Attackers can set malicious environment variables (LD_PRELOAD, PATH manipulation) for persistence."
  },

  // =========================================================================
  // macOS ARTIFACTS (35+)
  // =========================================================================
  {
    os: "macOS",
    name: "Unified Logs",
    location: "/var/db/diagnostics/, /var/db/uuidtext/",
    description: "Apple's unified logging system capturing all system, application, and kernel messages with structured metadata.",
    tool: "log show, log collect, mac_apt, UnifiedLogReader",
    significance: "Primary macOS log source; contains process execution, network activity, user actions, and security events."
  },
  {
    os: "macOS",
    name: "FSEvents",
    location: "/.fseventsd/",
    description: "File System Events log tracking all file and directory changes (create, delete, rename, modify) across all volumes.",
    tool: "FSEventsParser, mac_apt",
    significance: "Comprehensive file system change history; reveals file creation, deletion, and modifications over time."
  },
  {
    os: "macOS",
    name: "Spotlight Metadata",
    location: "/.Spotlight-V100/",
    description: "Spotlight search index containing file metadata, content excerpts, and attributes for all indexed files.",
    tool: "mdls, mdfind, Spotlight_parser",
    significance: "Contains metadata for files even after deletion if the index hasn't been updated."
  },
  {
    os: "macOS",
    name: "Quarantine Events Database",
    location: "~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2",
    description: "Tracks files downloaded from the internet with source URL, download timestamp, and application that downloaded them.",
    tool: "sqlite3, mac_apt",
    significance: "Proves file downloads with source URLs and timestamps, critical for malware delivery tracking."
  },
  {
    os: "macOS",
    name: "TCC.db (Privacy Database)",
    location: "~/Library/Application Support/com.apple.TCC/TCC.db, /Library/Application Support/com.apple.TCC/TCC.db",
    description: "Transparency, Consent, and Control database recording application permission grants for camera, microphone, screen recording, accessibility, and more.",
    tool: "sqlite3, TCC_parser",
    significance: "Shows which applications have been granted sensitive permissions; malware often requires TCC bypass."
  },
  {
    os: "macOS",
    name: "Launch Agents (User)",
    location: "~/Library/LaunchAgents/",
    description: "Per-user launch agent plist files that run programs when the user logs in.",
    tool: "plutil, launchctl list, KnockKnock",
    significance: "Common persistence mechanism; check for unfamiliar plist files with suspicious program arguments."
  },
  {
    os: "macOS",
    name: "Launch Agents (System)",
    location: "/Library/LaunchAgents/",
    description: "System-wide launch agent plist files running for all users at login.",
    tool: "plutil, launchctl list, KnockKnock",
    significance: "System-level persistence; requires admin privileges to install."
  },
  {
    os: "macOS",
    name: "Launch Daemons",
    location: "/Library/LaunchDaemons/, /System/Library/LaunchDaemons/",
    description: "System daemon plist files that run at boot with root privileges regardless of user login.",
    tool: "plutil, launchctl list, KnockKnock",
    significance: "Highest privilege persistence; daemons run as root at system startup."
  },
  {
    os: "macOS",
    name: "Keychain",
    location: "~/Library/Keychains/login.keychain-db, /Library/Keychains/System.keychain",
    description: "Encrypted credential store containing saved passwords, certificates, encryption keys, and secure notes.",
    tool: "security (command line), Keychain Access.app",
    significance: "Attackers target keychain for credential harvesting; shows stored passwords and certificates."
  },
  {
    os: "macOS",
    name: "KnowledgeC.db",
    location: "~/Library/Application Support/Knowledge/knowledgeC.db",
    description: "Tracks application usage, device activity, media playback, Safari history, and Siri interactions with timestamps.",
    tool: "sqlite3, mac_apt",
    significance: "Rich timeline of user activity including application focus time and device usage patterns."
  },
  {
    os: "macOS",
    name: "ASL (Apple System Log)",
    location: "/var/log/asl/",
    description: "Legacy Apple System Log files (pre-unified logging) containing system and application messages.",
    tool: "syslog, mac_apt",
    significance: "Historical log data on older macOS versions."
  },
  {
    os: "macOS",
    name: "Install.log",
    location: "/var/log/install.log",
    description: "Records software installations via the macOS installer framework.",
    tool: "cat, grep",
    significance: "Shows software installations with timestamps, including potentially malicious packages."
  },
  {
    os: "macOS",
    name: "system.log",
    location: "/var/log/system.log",
    description: "General system messages (deprecated in favor of unified logs but still present).",
    tool: "cat, grep",
    significance: "System events and errors from various services."
  },
  {
    os: "macOS",
    name: "Login Items",
    location: "~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm",
    description: "Applications configured to launch at user login via System Preferences.",
    tool: "sfltool, BTM parser",
    significance: "Persistence mechanism; check for unknown items in login items."
  },
  {
    os: "macOS",
    name: "Bash/Zsh History",
    location: "~/.bash_history, ~/.zsh_history, ~/.bash_sessions/",
    description: "Shell command history and bash session transcripts.",
    tool: "cat, grep",
    significance: "Same as Linux; macOS also stores per-session bash history in .bash_sessions/."
  },
  {
    os: "macOS",
    name: "Safari History",
    location: "~/Library/Safari/History.db",
    description: "Safari browser history SQLite database with URLs, titles, visit counts, and timestamps.",
    tool: "sqlite3, mac_apt, Autopsy",
    significance: "Safari browsing activity including malware delivery and C2 panel access."
  },
  {
    os: "macOS",
    name: "Safari Downloads",
    location: "~/Library/Safari/Downloads.plist",
    description: "Record of files downloaded through Safari with source URLs and local file paths.",
    tool: "plutil, mac_apt",
    significance: "Tracks downloaded files with source URLs."
  },
  {
    os: "macOS",
    name: "Dock plist",
    location: "~/Library/Preferences/com.apple.dock.plist",
    description: "Dock configuration including persistent and recent application entries.",
    tool: "plutil, defaults read",
    significance: "Shows recently used and pinned applications."
  },
  {
    os: "macOS",
    name: "Finder Preferences",
    location: "~/Library/Preferences/com.apple.finder.plist",
    description: "Finder settings including recent folders, sidebar items, and view preferences.",
    tool: "plutil, defaults read",
    significance: "Recent folder access and Finder usage patterns."
  },
  {
    os: "macOS",
    name: "Network Preferences",
    location: "/Library/Preferences/SystemConfiguration/preferences.plist",
    description: "Network interface configurations, Wi-Fi settings, VPN configurations, and proxy settings.",
    tool: "plutil, networksetup",
    significance: "Shows network configurations and connected networks."
  },
  {
    os: "macOS",
    name: "Wi-Fi Connection Log",
    location: "/var/log/wifi.log, /Library/Preferences/com.apple.wifi.known-networks.plist",
    description: "Wi-Fi connection history including network names, connection times, and security types.",
    tool: "cat, plutil",
    significance: "Places the device at specific wireless networks at specific times."
  },
  {
    os: "macOS",
    name: "Airport Preferences",
    location: "/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist",
    description: "Detailed Wi-Fi network history with connection timestamps and BSSID information.",
    tool: "plutil",
    significance: "Historical Wi-Fi network connections with BSSIDs for location correlation."
  },
  {
    os: "macOS",
    name: "Gatekeeper and XProtect",
    location: "/var/db/gkopaque.bundle/, /Library/Apple/System/Library/CoreServices/XProtect.bundle/",
    description: "macOS malware protection databases and quarantine assessment results.",
    tool: "spctl, xprotect_parser",
    significance: "Shows Gatekeeper assessment results and XProtect malware detections."
  },
  {
    os: "macOS",
    name: "CrashReporter Logs",
    location: "~/Library/Logs/DiagnosticReports/, /Library/Logs/DiagnosticReports/",
    description: "Application crash reports with stack traces, thread states, and binary images.",
    tool: "Console.app, cat",
    significance: "Crash reports from exploitation attempts contain valuable technical details."
  },
  {
    os: "macOS",
    name: "MRT (Malware Removal Tool) Log",
    location: "/var/log/MRT.log",
    description: "Malware Removal Tool scan results and remediation actions.",
    tool: "cat",
    significance: "Shows if Apple's MRT detected and removed known malware."
  },
  {
    os: "macOS",
    name: "Cups Logs",
    location: "/var/log/cups/",
    description: "Printing service logs showing print jobs, printers used, and documents printed.",
    tool: "cat, grep",
    significance: "Print logs can reveal data exfiltration via printing."
  },
  {
    os: "macOS",
    name: "iCloud Data",
    location: "~/Library/Mobile Documents/",
    description: "Locally synced iCloud Drive files and application data.",
    tool: "ls, find",
    significance: "Synced data may include files also accessible from other Apple devices."
  },
  {
    os: "macOS",
    name: "Authorization Database",
    location: "/var/db/auth.db",
    description: "Database controlling which applications and processes are granted specific system privileges and authorization rights.",
    tool: "sqlite3, security authorizationdb",
    significance: "Modifications to authorization rights can weaken system security or grant elevated privileges to malware."
  },
  {
    os: "macOS",
    name: "Notification Center Database",
    location: "~/Library/Group Containers/group.com.apple.usernoted/db2/db",
    description: "Stores notification history including content, timestamps, and source applications.",
    tool: "sqlite3",
    significance: "May contain message previews, alert content, and application notification history."
  },
  {
    os: "macOS",
    name: "Kernel Extensions (kext)",
    location: "/Library/Extensions/, /System/Library/Extensions/",
    description: "Loadable kernel extensions that run in kernel space with full system access.",
    tool: "kextstat, KnockKnock",
    significance: "Malicious kexts provide rootkit-level access; newer macOS versions restrict kext loading."
  },
  {
    os: "macOS",
    name: "System Extensions",
    location: "/Library/SystemExtensions/",
    description: "Modern replacement for kernel extensions running in user space with specific system capabilities.",
    tool: "systemextensionsctl list",
    significance: "Network extensions, endpoint security extensions, and driver extensions that can intercept system activity."
  },

  // =========================================================================
  // BROWSER ARTIFACTS (30+)
  // =========================================================================
  {
    os: "Browser",
    name: "Chrome History",
    location: "Default/History (SQLite: urls, visits, keyword_search_terms tables)",
    description: "Complete browsing history with URLs, page titles, visit counts, typed counts, transition types, and timestamps in Chrome epoch format.",
    tool: "Hindsight, DB Browser for SQLite",
    significance: "Primary web activity timeline with visit frequency and navigation method."
  },
  {
    os: "Browser",
    name: "Chrome Cookies",
    location: "Default/Cookies (SQLite, now Default/Network/Cookies)",
    description: "Cookie storage with domain, name, value (encrypted on disk), creation time, expiry, last access, and security flags.",
    tool: "Hindsight, DB Browser for SQLite, ChromeCookiesView",
    significance: "Reveals authenticated sessions, tracking data, and site-specific preferences."
  },
  {
    os: "Browser",
    name: "Chrome Cache",
    location: "Default/Cache/Cache_Data/ (index, data_0-3, f_xxxxxx files)",
    description: "Cached web resources including HTML, JavaScript, CSS, images, and API responses with HTTP headers.",
    tool: "ChromeCacheView, Hindsight",
    significance: "Contains cached copies of web content including potentially malicious scripts and accessed data."
  },
  {
    os: "Browser",
    name: "Chrome Downloads",
    location: "Default/History (SQLite: downloads, downloads_url_chains tables)",
    description: "File download records including URL, referrer, file path, total bytes, start/end time, state, danger type, and MIME type.",
    tool: "Hindsight, DB Browser for SQLite",
    significance: "Tracks all file downloads with source URLs and local save paths."
  },
  {
    os: "Browser",
    name: "Chrome Bookmarks",
    location: "Default/Bookmarks (JSON file)",
    description: "Bookmark tree structure with URLs, names, creation dates, and folder hierarchy.",
    tool: "JSON viewer, Hindsight",
    significance: "Bookmarked sites may include C2 panels, data staging sites, or target research."
  },
  {
    os: "Browser",
    name: "Chrome Session Data",
    location: "Default/Sessions/Session_*, Default/Sessions/Tabs_*",
    description: "Current and last session tab data including URLs, navigation history per tab, and window layout.",
    tool: "Hindsight, SNSS parser",
    significance: "Shows what tabs were open at browser close, revealing active browsing context."
  },
  {
    os: "Browser",
    name: "Chrome Extensions",
    location: "Default/Extensions/<extension-id>/",
    description: "Installed browser extensions with manifest, scripts, permissions, and version information.",
    tool: "File browser, manifest.json analysis",
    significance: "Malicious extensions can steal credentials, inject content, and exfiltrate data."
  },
  {
    os: "Browser",
    name: "Chrome Autofill",
    location: "Default/Web Data (SQLite: autofill, autofill_profiles tables)",
    description: "Form autofill data including names, addresses, phone numbers, and field-value pairs.",
    tool: "DB Browser for SQLite, Hindsight",
    significance: "Contains personal information entered into web forms."
  },
  {
    os: "Browser",
    name: "Chrome Login Data",
    location: "Default/Login Data (SQLite: logins table)",
    description: "Saved website credentials with origin URL, username, and encrypted password (DPAPI on Windows, Keychain on macOS).",
    tool: "Hindsight, ChromePass",
    significance: "Stored credentials are a high-value target for attackers."
  },
  {
    os: "Browser",
    name: "Chrome IndexedDB",
    location: "Default/IndexedDB/<origin>.indexeddb.leveldb/",
    description: "Client-side structured data storage for web applications, stored in LevelDB format per origin.",
    tool: "LevelDB viewer, Hindsight",
    significance: "Web application data including cached messages, offline data, and app state."
  },
  {
    os: "Browser",
    name: "Chrome Local Storage",
    location: "Default/Local Storage/leveldb/",
    description: "Key-value storage for web applications persisted in LevelDB format.",
    tool: "LevelDB viewer, Hindsight",
    significance: "May contain authentication tokens, user preferences, and application data."
  },
  {
    os: "Browser",
    name: "Chrome Favicons",
    location: "Default/Favicons (SQLite)",
    description: "Favicon images and URL mappings for visited websites.",
    tool: "DB Browser for SQLite, Hindsight",
    significance: "Favicon entries prove a site was visited even if history entries are cleared."
  },
  {
    os: "Browser",
    name: "Chrome Media History",
    location: "Default/Media History (SQLite)",
    description: "Records media playback events including URLs, watch time, and playback positions.",
    tool: "DB Browser for SQLite",
    significance: "Shows media consumption activity."
  },
  {
    os: "Browser",
    name: "Chrome Preferences",
    location: "Default/Preferences (JSON)",
    description: "Browser settings including homepage, search engine, download path, proxy settings, and feature flags.",
    tool: "JSON viewer",
    significance: "Modified preferences may indicate browser hijacking or proxy redirection."
  },
  {
    os: "Browser",
    name: "Chrome Sync Data",
    location: "Default/Sync Data/SyncData.sqlite3",
    description: "Chrome sync state including synced tabs, bookmarks, and history from other devices.",
    tool: "DB Browser for SQLite",
    significance: "May reveal activity from other synced devices."
  },
  {
    os: "Browser",
    name: "Firefox History",
    location: "profiles/<profile>/places.sqlite (moz_places, moz_historyvisits)",
    description: "Browsing history, bookmarks, and visit metadata in SQLite format.",
    tool: "DB Browser for SQLite, Hindsight",
    significance: "Firefox browsing activity with different schema from Chrome."
  },
  {
    os: "Browser",
    name: "Firefox Cookies",
    location: "profiles/<profile>/cookies.sqlite",
    description: "Firefox cookie storage in SQLite format.",
    tool: "DB Browser for SQLite",
    significance: "Same significance as Chrome cookies for Firefox browser."
  },
  {
    os: "Browser",
    name: "Firefox Downloads",
    location: "profiles/<profile>/places.sqlite (moz_annos, moz_places)",
    description: "Download history stored as annotations on places entries.",
    tool: "DB Browser for SQLite",
    significance: "Firefox download records with source URLs."
  },
  {
    os: "Browser",
    name: "Firefox Form History",
    location: "profiles/<profile>/formhistory.sqlite",
    description: "Form field autofill data recording field names and entered values.",
    tool: "DB Browser for SQLite",
    significance: "Contains data entered into web forms including search queries and usernames."
  },
  {
    os: "Browser",
    name: "Firefox Logins",
    location: "profiles/<profile>/logins.json, key4.db",
    description: "Saved credentials encrypted with the master password (or default if none set).",
    tool: "firefox_decrypt, DB Browser for SQLite",
    significance: "Stored Firefox credentials; can be decrypted with master password or key4.db."
  },
  {
    os: "Browser",
    name: "Firefox Session Store",
    location: "profiles/<profile>/sessionstore.jsonlz4",
    description: "Compressed JSON containing all open tabs, their history, form data, and scroll positions.",
    tool: "lz4jsoncat, sessionstore parser",
    significance: "Complete snapshot of all open Firefox tabs and their states."
  },
  {
    os: "Browser",
    name: "Firefox Extensions",
    location: "profiles/<profile>/extensions/, extensions.json",
    description: "Installed Firefox add-ons/extensions.",
    tool: "File browser, JSON viewer",
    significance: "Malicious add-ons can intercept and modify all browser traffic."
  },
  {
    os: "Browser",
    name: "Firefox Cache",
    location: "profiles/<profile>/cache2/entries/",
    description: "Firefox cache stored in individual files with metadata.",
    tool: "MozillaCacheView, cache2 parser",
    significance: "Cached web content from Firefox browsing."
  },
  {
    os: "Browser",
    name: "Edge History",
    location: "Default/History (same format as Chrome, Chromium-based Edge)",
    description: "Microsoft Edge (Chromium) browsing history in identical format to Chrome.",
    tool: "Hindsight, DB Browser for SQLite",
    significance: "Edge uses the same SQLite schema as Chrome; same tools apply."
  },
  {
    os: "Browser",
    name: "Edge Collections",
    location: "Default/Collections/collectionsSQLite",
    description: "Edge Collections feature storing curated groups of web pages and notes.",
    tool: "DB Browser for SQLite",
    significance: "May contain research collections relevant to investigation."
  },
  {
    os: "Browser",
    name: "Safari Web Data",
    location: "~/Library/Safari/History.db, ~/Library/Safari/Bookmarks.plist",
    description: "Safari browsing history in SQLite and bookmarks in plist format.",
    tool: "sqlite3, plutil, mac_apt",
    significance: "Safari-specific artifacts on macOS."
  },
  {
    os: "Browser",
    name: "Browser Profile Metadata",
    location: "Local State (Chrome), profiles.ini (Firefox)",
    description: "Browser profile listing and metadata including creation time and last used time.",
    tool: "JSON viewer, INI parser",
    significance: "Identifies all browser profiles and when they were last active."
  },
  {
    os: "Browser",
    name: "Web Notifications",
    location: "Default/Platform Notifications/ (Chrome)",
    description: "Push notification data received by the browser from web applications.",
    tool: "LevelDB viewer",
    significance: "May contain notification content from web applications."
  },
  {
    os: "Browser",
    name: "Service Workers",
    location: "Default/Service Worker/Database/ (Chrome)",
    description: "Registered service workers and their cached data for progressive web apps.",
    tool: "LevelDB viewer, SQLite browser",
    significance: "Service workers can intercept network requests; malicious ones could modify traffic."
  },
  {
    os: "Browser",
    name: "WebRTC Logs",
    location: "chrome://webrtc-internals/ (live), WebRTC event logs",
    description: "WebRTC peer connection data including ICE candidates, STUN/TURN servers, and media statistics.",
    tool: "Browser developer tools",
    significance: "WebRTC connections can reveal real IP addresses even behind VPNs."
  }
];

// -----------------------------------------------------------------------------
// 3. MEMORY ANALYSIS (Volatility Plugins and Techniques)
// -----------------------------------------------------------------------------
export const MEMORY_ANALYSIS = [
  // -- Process Analysis --
  {
    plugin: "pslist",
    description: "List running processes from the EPROCESS linked list with PID, PPID, threads, handles, and start time.",
    usage: "vol.py -f memory.raw windows.pslist",
    output: "PID, PPID, ImageFileName, Offset, Threads, Handles, SessionId, CreateTime, ExitTime",
    significance: "Basic process enumeration; hidden processes will be missing from this list."
  },
  {
    plugin: "psscan",
    description: "Scan for EPROCESS structures in physical memory, finding processes unlinked from the active list (hidden/terminated).",
    usage: "vol.py -f memory.raw windows.psscan",
    output: "PID, PPID, ImageFileName, Offset, Threads, Handles, CreateTime, ExitTime",
    significance: "Finds hidden processes that rootkits have unlinked from the process list."
  },
  {
    plugin: "pstree",
    description: "Display process tree showing parent-child relationships between all running processes.",
    usage: "vol.py -f memory.raw windows.pstree",
    output: "Hierarchical process tree with PID, PPID, ImageFileName",
    significance: "Visualizes process hierarchy; unusual parent-child relationships indicate injection or exploitation."
  },
  {
    plugin: "psxview",
    description: "Cross-reference multiple process listing methods (pslist, psscan, thrdproc, etc.) to detect hidden processes.",
    usage: "vol.py -f memory.raw windows.psxview",
    output: "Process visibility across different detection methods",
    significance: "Gold standard for process hiding detection; a process visible in psscan but not pslist is suspicious."
  },
  {
    plugin: "cmdline",
    description: "Extract command-line arguments for each process from the PEB (Process Environment Block).",
    usage: "vol.py -f memory.raw windows.cmdline",
    output: "PID, Process, Args (full command line)",
    significance: "Reveals exact commands used to launch processes, including encoded PowerShell commands and tool arguments."
  },
  {
    plugin: "consoles",
    description: "Extract command history from console host (conhost.exe) processes showing interactive command sessions.",
    usage: "vol.py -f memory.raw windows.consoles",
    output: "Console input/output history, command text",
    significance: "Recovers interactive shell sessions including commands typed and their output."
  },
  {
    plugin: "envars",
    description: "Display environment variables for each process.",
    usage: "vol.py -f memory.raw windows.envars",
    output: "PID, Process, Variable, Value",
    significance: "May reveal custom variables set by malware, paths to tools, or C2 configuration."
  },
  {
    plugin: "privileges",
    description: "List security privileges for each process token.",
    usage: "vol.py -f memory.raw windows.privileges",
    output: "PID, Process, Privilege, Attributes, Description",
    significance: "Identifies processes with elevated privileges; SeDebugPrivilege enables process injection."
  },
  {
    plugin: "getsids",
    description: "Extract SIDs associated with each process, showing the security context.",
    usage: "vol.py -f memory.raw windows.getsids",
    output: "PID, Process, SID, Name",
    significance: "Shows which user context each process runs under; unusual SIDs indicate privilege escalation."
  },
  {
    plugin: "handles",
    description: "List open handles for processes, showing accessed files, registry keys, events, and other kernel objects.",
    usage: "vol.py -f memory.raw windows.handles --pid <PID>",
    output: "PID, Process, Offset, HandleValue, Type, GrantedAccess, Name",
    significance: "Reveals files, registry keys, and mutexes opened by a process."
  },

  // -- DLL and Module Analysis --
  {
    plugin: "dlllist",
    description: "List loaded DLLs for each process from the PEB InLoadOrderModuleList.",
    usage: "vol.py -f memory.raw windows.dlllist --pid <PID>",
    output: "PID, Process, Base, Size, Name, Path, LoadTime",
    significance: "Shows all loaded DLLs; look for unusual DLLs or DLLs loaded from unexpected paths."
  },
  {
    plugin: "ldrmodules",
    description: "Cross-reference the three PEB module lists (InLoad, InInit, InMem) to find injected or unlinked DLLs.",
    usage: "vol.py -f memory.raw windows.ldrmodules --pid <PID>",
    output: "PID, Process, Base, InLoad, InInit, InMem, MappedPath",
    significance: "DLLs missing from one or more lists indicate injection; False/False/True is a strong indicator."
  },
  {
    plugin: "modules",
    description: "List loaded kernel modules/drivers from the module linked list.",
    usage: "vol.py -f memory.raw windows.modules",
    output: "Offset, Base, Size, Name, Path",
    significance: "Identifies loaded drivers; rootkit drivers may be present in this list."
  },
  {
    plugin: "modscan",
    description: "Scan for kernel module structures in physical memory to find unlinked/hidden drivers.",
    usage: "vol.py -f memory.raw windows.modscan",
    output: "Offset, Base, Size, Name, Path",
    significance: "Finds kernel modules hidden from the standard module list by rootkits."
  },
  {
    plugin: "driverscan",
    description: "Scan for DRIVER_OBJECT structures to enumerate all drivers.",
    usage: "vol.py -f memory.raw windows.driverscan",
    output: "Offset, Start, Size, ServiceKey, Name, DriverName",
    significance: "Enumerates all driver objects including those hidden from module lists."
  },

  // -- Malware Detection --
  {
    plugin: "malfind",
    description: "Detect injected code by finding memory regions with PAGE_EXECUTE_READWRITE protection and no mapped file (VAD-based detection).",
    usage: "vol.py -f memory.raw windows.malfind --pid <PID>",
    output: "PID, Process, Start VPN, End VPN, Tag, Protection, Hexdump, Disassembly",
    significance: "Primary injection detection; executable memory with no backing file typically indicates code injection."
  },
  {
    plugin: "yarascan",
    description: "Scan process or kernel memory with YARA rules to detect known malware patterns.",
    usage: "vol.py -f memory.raw windows.yarascan --yara-rules 'rule test { strings: $a = \"malware\" condition: $a }'",
    output: "Owner, Rule, Offset, HexDump",
    significance: "Pattern-based malware detection in memory; use with comprehensive YARA rule sets."
  },
  {
    plugin: "ssdt",
    description: "Display the System Service Descriptor Table (SSDT) to detect hooked system calls.",
    usage: "vol.py -f memory.raw windows.ssdt",
    output: "Index, Address, Module, Symbol",
    significance: "SSDT hooks redirect system calls to rootkit code; entries pointing outside ntoskrnl are suspicious."
  },
  {
    plugin: "idt",
    description: "Display the Interrupt Descriptor Table (IDT) to detect hooked interrupt handlers.",
    usage: "vol.py -f memory.raw windows.idt",
    output: "CPU, Index, Selector, Address, Module, Section",
    significance: "IDT hooks can intercept hardware interrupts and software exceptions for rootkit purposes."
  },
  {
    plugin: "callbacks",
    description: "List kernel notification callbacks for process creation, thread creation, image loading, and registry operations.",
    usage: "vol.py -f memory.raw windows.callbacks",
    output: "Type, Callback, Module, Detail",
    significance: "Rootkits register callbacks to monitor and intercept system events."
  },
  {
    plugin: "driverirp",
    description: "List IRP (I/O Request Packet) handlers for a driver, detecting IRP hooking.",
    usage: "vol.py -f memory.raw windows.driverirp",
    output: "Offset, DriverName, IRP, Address, Module, Symbol",
    significance: "IRP hooks can filter or modify I/O requests, used by rootkits to hide files and registry entries."
  },
  {
    plugin: "timers",
    description: "List kernel timer DPCs (Deferred Procedure Calls) to find periodic callback routines.",
    usage: "vol.py -f memory.raw windows.timers",
    output: "Offset, DueTime, Period, Signaled, Routine, Module",
    significance: "Malware uses kernel timers for periodic execution and maintaining persistence."
  },

  // -- Network Analysis --
  {
    plugin: "netscan",
    description: "Scan for network connection structures (TCP endpoints, UDP endpoints, listeners) in memory.",
    usage: "vol.py -f memory.raw windows.netscan",
    output: "Offset, Proto, LocalAddr, LocalPort, ForeignAddr, ForeignPort, State, PID, Owner, Created",
    significance: "Reveals active and recently closed network connections with associated processes."
  },
  {
    plugin: "netstat",
    description: "List active network connections from the kernel connection table.",
    usage: "vol.py -f memory.raw windows.netstat",
    output: "Offset, Proto, LocalAddr, LocalPort, ForeignAddr, ForeignPort, State, PID, Owner, Created",
    significance: "Complementary to netscan; uses different detection method for cross-validation."
  },

  // -- Registry Analysis --
  {
    plugin: "hivelist",
    description: "List registry hive file objects in memory with their virtual and physical offsets.",
    usage: "vol.py -f memory.raw windows.registry.hivelist",
    output: "Offset, FileFullPath, LastWriteTime",
    significance: "Identifies registry hives loaded in memory for further analysis."
  },
  {
    plugin: "printkey",
    description: "Print a specific registry key and its values from a memory-resident hive.",
    usage: "vol.py -f memory.raw windows.registry.printkey --key 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'",
    output: "Last Write Time, Key, Subkeys, Values with Type and Data",
    significance: "Extracts registry values directly from memory, reflecting live state including in-memory modifications."
  },
  {
    plugin: "userassist",
    description: "Extract UserAssist entries from memory-resident NTUSER.DAT showing GUI program execution.",
    usage: "vol.py -f memory.raw windows.registry.userassist",
    output: "Hive, Key, Name, Count, FocusCount, TimeFocused, LastUpdated",
    significance: "Program execution evidence from memory, may include entries not yet flushed to disk."
  },
  {
    plugin: "hashdump",
    description: "Extract password hashes from the SAM registry hive in memory.",
    usage: "vol.py -f memory.raw windows.hashdump",
    output: "User, RID, LMHASH, NTHASH",
    significance: "Extracts local account password hashes for offline cracking or pass-the-hash analysis."
  },
  {
    plugin: "cachedump",
    description: "Extract cached domain logon credentials from the SECURITY hive in memory.",
    usage: "vol.py -f memory.raw windows.cachedump",
    output: "Username, Domain, DomainName, Hash",
    significance: "Recovers cached domain credentials that may reveal compromised domain accounts."
  },
  {
    plugin: "lsadump",
    description: "Extract LSA secrets from the SECURITY registry hive in memory.",
    usage: "vol.py -f memory.raw windows.lsadump",
    output: "Secret name, Hex data, Text representation",
    significance: "LSA secrets may contain service account passwords, VPN credentials, and other sensitive data."
  },

  // -- File and Dump Operations --
  {
    plugin: "filescan",
    description: "Scan for FILE_OBJECT structures in memory, finding all open files across all processes.",
    usage: "vol.py -f memory.raw windows.filescan",
    output: "Offset, Ptr, Hnd, Access, Name",
    significance: "Lists all files referenced in memory including deleted files with handles still open."
  },
  {
    plugin: "dumpfiles",
    description: "Extract file content from memory based on file object virtual addresses.",
    usage: "vol.py -f memory.raw windows.dumpfiles --virtaddr <offset>",
    output: "Extracted file on disk",
    significance: "Recovers file content from memory including malware dropped files and documents."
  },
  {
    plugin: "procdump",
    description: "Dump a process executable from memory to disk for static analysis.",
    usage: "vol.py -f memory.raw windows.procdump --pid <PID> --dump-dir ./output/",
    output: "Reconstructed PE executable file",
    significance: "Extracts running executables for malware analysis even if deleted from disk."
  },
  {
    plugin: "memmap",
    description: "Display the memory map for a process showing all mapped memory regions.",
    usage: "vol.py -f memory.raw windows.memmap --pid <PID> --dump",
    output: "Virtual address, Physical address, Size, mapping details",
    significance: "Full memory layout of a process; --dump option extracts all addressable memory."
  },
  {
    plugin: "vadinfo",
    description: "Display Virtual Address Descriptor (VAD) tree for a process detailing memory region properties.",
    usage: "vol.py -f memory.raw windows.vadinfo --pid <PID>",
    output: "VAD node details: start, end, tag, protection, flags, file mapping",
    significance: "Detailed memory region analysis showing protections, types, and backing files for each region."
  },

  // -- Windows Internals --
  {
    plugin: "svcscan",
    description: "Scan for Windows service records in memory.",
    usage: "vol.py -f memory.raw windows.svcscan",
    output: "Offset, Order, PID, Start, State, Type, Name, Display, Binary",
    significance: "Lists all Windows services with their state and binary path, including services hidden from the registry."
  },
  {
    plugin: "symlinkscan",
    description: "Scan for symbolic link objects in kernel memory.",
    usage: "vol.py -f memory.raw windows.symlinkscan",
    output: "Offset, CreateTime, From, To",
    significance: "Symbolic links can be used to redirect file or object access; check for malicious redirections."
  },
  {
    plugin: "mutantscan",
    description: "Scan for mutex/mutant objects in kernel memory.",
    usage: "vol.py -f memory.raw windows.mutantscan",
    output: "Offset, CID, Name, Path",
    significance: "Malware often creates unique mutexes to prevent multiple instances; known mutex names are IOCs."
  },
  {
    plugin: "devicetree",
    description: "Display the device object tree showing device driver relationships.",
    usage: "vol.py -f memory.raw windows.devicetree",
    output: "Hierarchical device tree with driver associations",
    significance: "Reveals driver stack and device attachments; filter drivers indicate rootkit interception."
  },

  // -- Crash Dump and Hiberfil --
  {
    plugin: "crashinfo",
    description: "Extract crash dump header information from a Windows crash dump file.",
    usage: "vol.py -f memory.dmp windows.crashinfo",
    output: "Crash dump header: MajorVersion, MinorVersion, MachineType, BugCheckCode",
    significance: "Provides system version information from crash dumps for profile identification."
  },
  {
    plugin: "hibinfo",
    description: "Parse Windows hibernation file (hiberfil.sys) to extract memory image.",
    usage: "vol.py -f hiberfil.sys windows.hibinfo",
    output: "Hibernation file metadata and decompressed memory image",
    significance: "Hibernation files contain a compressed memory dump from when the system hibernated."
  },

  // -- Linux Memory Analysis --
  {
    plugin: "linux.pslist",
    description: "List processes from the Linux task_struct linked list.",
    usage: "vol.py -f memory.raw linux.pslist",
    output: "OFFSET, PID, TID, PPID, COMM",
    significance: "Basic Linux process enumeration from memory."
  },
  {
    plugin: "linux.pstree",
    description: "Display Linux process tree with parent-child relationships.",
    usage: "vol.py -f memory.raw linux.pstree",
    output: "Hierarchical process tree",
    significance: "Visualizes Linux process hierarchy for anomaly detection."
  },
  {
    plugin: "linux.bash",
    description: "Extract bash command history from process memory.",
    usage: "vol.py -f memory.raw linux.bash",
    output: "PID, Process, CommandTime, Command",
    significance: "Recovers bash history from memory including commands from sessions where history was disabled."
  },
  {
    plugin: "linux.check_afinfo",
    description: "Verify network protocol operation function pointers for rootkit hooks.",
    usage: "vol.py -f memory.raw linux.check_afinfo",
    output: "Symbol name, Member, Address, Module",
    significance: "Detects rootkit hooks on network protocol handlers."
  },
  {
    plugin: "linux.check_syscall",
    description: "Check the system call table for hooked entries.",
    usage: "vol.py -f memory.raw linux.check_syscall",
    output: "Table index, Address, Symbol, Module",
    significance: "Detects rootkit system call table modifications."
  },
  {
    plugin: "linux.lsmod",
    description: "List loaded Linux kernel modules.",
    usage: "vol.py -f memory.raw linux.lsmod",
    output: "Address, Core Size, Name",
    significance: "Identifies loaded kernel modules; compare with known-good list for rootkit detection."
  },
  {
    plugin: "linux.lsof",
    description: "List open files for Linux processes from memory.",
    usage: "vol.py -f memory.raw linux.lsof",
    output: "PID, FD, Path",
    significance: "Shows all files opened by each process."
  },
  {
    plugin: "linux.mount",
    description: "List mounted filesystems from memory.",
    usage: "vol.py -f memory.raw linux.mount",
    output: "Device, Mount Point, Filesystem Type",
    significance: "Reveals mounted filesystems including hidden or overlay mounts."
  },
  {
    plugin: "linux.sockstat",
    description: "List network connections from Linux kernel memory.",
    usage: "vol.py -f memory.raw linux.sockstat",
    output: "Netfilter connection tracking entries",
    significance: "Network connections from Linux memory."
  }
];

// -----------------------------------------------------------------------------
// 4. TIMELINE ANALYSIS
// -----------------------------------------------------------------------------
export const TIMELINE_ANALYSIS = [
  {
    source: "NTFS $MFT",
    tool: "MFTECmd (Eric Zimmerman)",
    command: "MFTECmd.exe -f $MFT --csv output/ --csvf mft_timeline.csv",
    format: "CSV with columns: EntryNumber, SequenceNumber, ParentEntryNumber, ParentPath, FileName, Extension, IsDirectory, SICreated, SIModified, SIAccessed, SIEntryModified, FNCreated, FNModified, FNAccessed, FNEntryModified, FileSize"
  },
  {
    source: "NTFS USN Journal",
    tool: "MFTECmd (Eric Zimmerman)",
    command: "MFTECmd.exe -f $UsnJrnl:$J --csv output/ --csvf usn_timeline.csv",
    format: "CSV with columns: EntryNumber, ParentEntryNumber, ParentPath, FileName, Extension, UpdateTimestamp, UpdateReasons, UpdateSourceFlags, FileAttributes"
  },
  {
    source: "Windows Event Logs",
    tool: "EvtxECmd (Eric Zimmerman)",
    command: "EvtxECmd.exe -d C:\\Windows\\System32\\winevt\\Logs\\ --csv output/ --csvf evtx_timeline.csv",
    format: "CSV with normalized timestamp, event ID, channel, provider, user, computer, and payload data"
  },
  {
    source: "Windows Prefetch",
    tool: "PECmd (Eric Zimmerman)",
    command: "PECmd.exe -d C:\\Windows\\Prefetch\\ --csv output/ --csvf prefetch_timeline.csv",
    format: "CSV with executable name, run count, last run times (up to 8), and referenced files/directories"
  },
  {
    source: "Windows Registry (All Hives)",
    tool: "RECmd (Eric Zimmerman)",
    command: "RECmd.exe --bn BatchExamples\\RECmd_Batch_MC.reb -d C:\\registry_hives\\ --csv output/",
    format: "CSV with key path, value name, value data, last write timestamp, and plugin-specific parsed data"
  },
  {
    source: "Windows Shellbags",
    tool: "SBECmd (Eric Zimmerman)",
    command: "SBECmd.exe -d C:\\Users\\ --csv output/ --csvf shellbags_timeline.csv",
    format: "CSV with bag path, created, modified, accessed, last write, MFT entry, and slot modified dates"
  },
  {
    source: "Windows LNK Files",
    tool: "LECmd (Eric Zimmerman)",
    command: "LECmd.exe -d C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\ --csv output/",
    format: "CSV with source file, target path, creation, modified, accessed, target MAC times, volume serial, and drive type"
  },
  {
    source: "Windows Jump Lists",
    tool: "JLECmd (Eric Zimmerman)",
    command: "JLECmd.exe -d C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\ --csv output/",
    format: "CSV with source file, AppId, target path, timestamps, and interaction count"
  },
  {
    source: "Windows Recycle Bin",
    tool: "RBCmd (Eric Zimmerman)",
    command: "RBCmd.exe -d C:\\$Recycle.Bin\\ --csv output/ --csvf recyclebin_timeline.csv",
    format: "CSV with source, file name, file size, deleted timestamp, and original path"
  },
  {
    source: "Windows SRUM",
    tool: "SrumECmd (Eric Zimmerman)",
    command: "SrumECmd.exe -f SRUDB.dat -r SOFTWARE --csv output/",
    format: "CSV with timestamp, application, user, bytes sent/received, foreground time, and resource usage"
  },
  {
    source: "Windows AmCache",
    tool: "AmcacheParser (Eric Zimmerman)",
    command: "AmcacheParser.exe -f Amcache.hve --csv output/ --csvf amcache_timeline.csv",
    format: "CSV with SHA1, full path, file size, publisher, version, compile time, and install date"
  },
  {
    source: "Browser History (Chrome/Edge)",
    tool: "Hindsight",
    command: "hindsight.py -i \"C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\User Data\\Default\" -o output/",
    format: "Excel/SQLite with URL, title, visit time, visit type, transition, and from_visit for all Chromium artifacts"
  },
  {
    source: "Full Disk Image (Plaso)",
    tool: "log2timeline (Plaso)",
    command: "log2timeline.py --storage-file timeline.plaso disk_image.E01",
    format: "Plaso storage file containing events from all parsers; convert with psort.py to CSV, JSON, or Elasticsearch"
  },
  {
    source: "Plaso Output Processing",
    tool: "psort (Plaso)",
    command: "psort.py -o l2tcsv -w timeline.csv timeline.plaso \"date > '2024-01-01' AND date < '2024-12-31'\"",
    format: "CSV (l2tcsv format): date, time, timezone, MACB, source, sourcetype, type, user, host, short, desc, version, filename, inode, notes, format, extra"
  },
  {
    source: "Plaso to Timesketch",
    tool: "psort (Plaso) + Timesketch",
    command: "psort.py -o timesketch -w timeline.jsonl timeline.plaso",
    format: "JSONL for import into Timesketch for collaborative timeline analysis"
  },
  {
    source: "macOS FSEvents",
    tool: "FSEventsParser",
    command: "FSEventsParser -s /.fseventsd/ -o csv -t folder_timeline.csv",
    format: "CSV with event ID, timestamp, full path, flags (created, removed, renamed, modified), and node ID"
  },
  {
    source: "macOS Unified Logs",
    tool: "UnifiedLogReader / log show",
    command: "log show --archive system_logs.logarchive --style ndjson --predicate 'process == \"loginwindow\"' > timeline.jsonl",
    format: "NDJSON with timestamp, subsystem, category, process, PID, message, activity, and trace ID"
  },
  {
    source: "Linux Logs (auth+syslog)",
    tool: "log2timeline (Plaso)",
    command: "log2timeline.py --parsers 'syslog,utmp,selinux' --storage-file linux_timeline.plaso /var/log/",
    format: "Plaso storage with parsed Linux log events"
  },
  {
    source: "Supertimeline (All Sources)",
    tool: "KAPE + log2timeline",
    command: "kape.exe --tsource C: --tdest output\\triage --target KapeTriage --msource output\\triage --mdest output\\modules --module !EZParser",
    format: "Complete supertimeline combining all available evidence sources into a unified chronological view"
  },
  {
    source: "Network PCAP",
    tool: "tshark",
    command: "tshark -r capture.pcap -T fields -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e http.host -e dns.qry.name -E separator=, > network_timeline.csv",
    format: "CSV with timestamp, source/destination IP and port, HTTP host, and DNS query fields"
  },
  {
    source: "Memory Processes",
    tool: "Volatility 3",
    command: "vol.py -f memory.raw windows.pslist | sort -t ',' -k8 > process_timeline.csv",
    format: "Process list sorted by creation time to timeline process execution order"
  },
  {
    source: "Cloud (AWS CloudTrail)",
    tool: "AWS CLI + jq",
    command: "aws cloudtrail lookup-events --start-time 2024-01-01 --end-time 2024-01-31 --output json | jq -r '.Events[] | [.EventTime, .EventName, .Username, .EventSource] | @csv' > cloudtrail_timeline.csv",
    format: "CSV with event time, event name, username, and event source for AWS API activity timeline"
  }
];

// -----------------------------------------------------------------------------
// 5. INCIDENT RESPONSE PLAYBOOKS
// -----------------------------------------------------------------------------
export const IR_PLAYBOOKS = [
  {
    incident: "Ransomware",
    severity: "Critical",
    steps: [
      "Activate the incident response team and establish communication channels",
      "Identify the ransomware variant from ransom note, file extensions, and IOCs",
      "Determine the scope: which systems, users, and data are affected",
      "Assess backup availability, integrity, and last successful backup date",
      "Check for decryptors (NoMoreRansom.org, vendor-specific decryption tools)"
    ],
    containment: [
      "Immediately isolate affected systems from the network (disable network adapters, block at switch/firewall)",
      "Disable any remote access services (RDP, VPN, SSH) to affected segments",
      "Block known C2 IP addresses and domains at perimeter firewall and DNS",
      "Disable compromised user accounts and reset credentials",
      "Preserve at least one encrypted system for forensic analysis before remediation",
      "Power off systems that are actively encrypting if live encryption is observed",
      "Segment the network to prevent lateral movement to unaffected areas",
      "Disable shared drives and mapped network folders to prevent further encryption",
      "Alert cloud providers if cloud resources are affected"
    ],
    eradication: [
      "Identify the initial access vector (phishing email, RDP brute force, vulnerability exploitation)",
      "Remove ransomware binaries, scripts, and persistence mechanisms from all affected systems",
      "Patch the vulnerability or close the access vector used for initial compromise",
      "Scan all systems with updated AV/EDR signatures for the identified ransomware family",
      "Remove any backdoors, web shells, or additional access tools deployed by the attacker",
      "Verify no scheduled tasks, services, or registry entries maintain persistence",
      "Reset all credentials for affected accounts and service accounts",
      "If Active Directory is compromised, perform KRBTGT password reset (twice, 12 hours apart)"
    ],
    recovery: [
      "Restore systems from verified clean backups (test backup integrity first)",
      "Rebuild systems that cannot be cleaned from gold images",
      "Restore data from backups in priority order based on business criticality",
      "Verify restored systems are patched and hardened before reconnecting to network",
      "Monitor restored systems intensively for signs of re-infection for 30-90 days",
      "Gradually restore network connectivity in phases with enhanced monitoring",
      "Validate business applications and services are functioning correctly",
      "Communicate restoration progress to stakeholders and management"
    ],
    lessons: [
      "Document the complete timeline from initial access to detection and containment",
      "Identify gaps in detection that allowed the attack to progress",
      "Review and improve backup strategy: 3-2-1 rule, offline/immutable backups",
      "Assess and improve network segmentation to limit blast radius",
      "Evaluate endpoint detection and response (EDR) coverage and configuration",
      "Implement or improve email security controls (anti-phishing, sandboxing)",
      "Review and restrict RDP access, enforce MFA on all remote access",
      "Conduct tabletop exercise to practice revised response procedures",
      "Report to law enforcement and relevant regulatory bodies as required"
    ]
  },
  {
    incident: "Phishing",
    severity: "High",
    steps: [
      "Receive and triage the phishing report from user or automated detection",
      "Analyze the phishing email: headers, URLs, attachments, sender spoofing",
      "Determine if the email is credential harvesting, malware delivery, or BEC",
      "Check email gateway logs for delivery scope (how many users received it)",
      "Identify users who interacted with the phishing email (clicked, submitted credentials, opened attachments)"
    ],
    containment: [
      "Quarantine the phishing email from all mailboxes using admin purge/search-and-destroy",
      "Block the sender domain and any spoofed addresses at the email gateway",
      "Block phishing URLs at web proxy, DNS, and firewall",
      "If credentials were submitted: immediately reset affected user passwords and revoke sessions",
      "Enable MFA for compromised accounts if not already enabled",
      "Check for inbox rules created by attackers (auto-forward, auto-delete)",
      "Block any malicious attachment hashes at endpoint protection",
      "If malware was delivered: isolate affected endpoints and begin malware response",
      "Notify users who received the email to delete and not interact with it"
    ],
    eradication: [
      "Confirm all instances of the phishing email are removed from mailboxes",
      "Remove any malware delivered via the phishing email from affected endpoints",
      "Revoke any OAuth app consent grants created during the attack",
      "Remove attacker-created inbox rules and email forwarding configurations",
      "Verify no additional persistence was established on compromised endpoints",
      "Check for lateral movement from compromised accounts",
      "Update email filtering rules to detect similar phishing patterns"
    ],
    recovery: [
      "Restore normal email delivery once blocking rules are in place",
      "Monitor compromised accounts for suspicious activity for 30 days",
      "Re-enable any disabled services or accounts after verification",
      "Conduct password resets for any accounts where credential reuse is suspected",
      "Verify no data was exfiltrated during the compromise window"
    ],
    lessons: [
      "Analyze why the phishing email bypassed existing email security controls",
      "Update email security rules and filters based on the attack techniques",
      "Conduct targeted phishing awareness training for affected users",
      "Review and improve phishing reporting process for faster triage",
      "Evaluate DMARC, SPF, and DKIM configuration for the organization",
      "Consider implementing URL rewriting and time-of-click analysis",
      "Update threat intelligence with IOCs from the phishing campaign"
    ]
  },
  {
    incident: "Data Breach",
    severity: "Critical",
    steps: [
      "Confirm the data breach: validate the report, check for false positives",
      "Classify the type and sensitivity of data exposed (PII, PHI, financial, IP)",
      "Determine the volume of records affected",
      "Identify the breach method: exfiltration, accidental exposure, insider, or third-party",
      "Assess regulatory requirements based on data type and jurisdiction (GDPR, HIPAA, PCI-DSS, state laws)"
    ],
    containment: [
      "Stop ongoing data exfiltration by isolating affected systems",
      "Revoke access credentials used for unauthorized data access",
      "Block exfiltration channels (IPs, domains, cloud storage services, email addresses)",
      "If cloud storage is exposed: immediately restrict access and change credentials",
      "Preserve forensic evidence before making changes to affected systems",
      "Engage legal counsel for regulatory notification requirements",
      "Activate breach notification process if required by regulation",
      "Disable any APIs or services involved in the data exposure"
    ],
    eradication: [
      "Identify and close the vulnerability or access path used for the breach",
      "Remove any unauthorized access mechanisms (backdoors, compromised accounts)",
      "Patch systems and applications involved in the breach",
      "Review and restrict access controls on affected data stores",
      "Implement additional monitoring on affected data repositories",
      "If data was posted publicly: initiate takedown requests"
    ],
    recovery: [
      "Restore affected systems from secure backups if integrity is compromised",
      "Implement enhanced access controls and monitoring on affected data",
      "Issue breach notifications to affected individuals as required by law",
      "Provide credit monitoring or identity protection services if PII was exposed",
      "Re-enable services with enhanced security controls in place",
      "Report to regulatory bodies within required timeframes"
    ],
    lessons: [
      "Conduct thorough root cause analysis of the breach",
      "Review data classification and protection policies",
      "Implement or improve Data Loss Prevention (DLP) controls",
      "Review and minimize data retention to reduce future breach impact",
      "Evaluate encryption of data at rest and in transit",
      "Review third-party access and vendor security requirements",
      "Update incident response plan based on lessons learned",
      "Conduct organization-wide data handling training"
    ]
  },
  {
    incident: "Insider Threat",
    severity: "High",
    steps: [
      "Receive alert from DLP, UEBA, HR, or management regarding suspicious insider activity",
      "Determine the type: malicious insider, negligent insider, or compromised credentials",
      "Identify the scope of access the insider has to sensitive systems and data",
      "Coordinate with HR, Legal, and management before taking technical actions",
      "Preserve evidence while maintaining operational security (do not alert the insider if malicious)"
    ],
    containment: [
      "Increase monitoring on the insider's accounts and systems without alerting (if investigation is ongoing)",
      "Enable detailed audit logging on all systems the insider accesses",
      "If imminent threat: disable access and collect corporate devices",
      "Implement DLP rules to detect and block data exfiltration attempts",
      "Monitor for use of personal devices, cloud storage, USB drives, and personal email",
      "Coordinate with physical security if on-premises threat is identified",
      "Preserve mailbox content and file access logs for forensic analysis"
    ],
    eradication: [
      "Disable all user accounts and access upon confirmed threat and HR/Legal approval",
      "Revoke VPN, remote access, and cloud service access",
      "Change shared credentials and service account passwords the insider had access to",
      "Remove the insider from all distribution groups and shared mailboxes",
      "Collect and forensically image corporate devices",
      "Review and revoke any personal device enrollments (BYOD)",
      "Audit all data the insider accessed in the past 90-180 days"
    ],
    recovery: [
      "Reassign the insider's responsibilities and access to appropriate personnel",
      "Restore any data that was modified or deleted by the insider",
      "Review and update access controls based on least privilege principles",
      "Verify no backdoor accounts or access mechanisms remain",
      "Monitor systems previously accessed by the insider for anomalies"
    ],
    lessons: [
      "Review and improve insider threat detection capabilities (UEBA, DLP)",
      "Implement or enhance the insider threat program",
      "Review offboarding procedures and access revocation timelines",
      "Evaluate separation of duties and least privilege implementation",
      "Conduct background check review for sensitive positions",
      "Implement mandatory access reviews and certification campaigns",
      "Review data handling agreements and acceptable use policies"
    ]
  },
  {
    incident: "DDoS Attack",
    severity: "High",
    steps: [
      "Confirm DDoS attack: differentiate from legitimate traffic surge or infrastructure failure",
      "Classify the attack type: volumetric (UDP flood, amplification), protocol (SYN flood), or application layer (HTTP flood, Slowloris)",
      "Identify target: specific IP, service, application, or DNS",
      "Determine attack volume and compare against available bandwidth and mitigation capacity",
      "Activate DDoS response procedures and notify relevant teams"
    ],
    containment: [
      "Activate DDoS mitigation service (Cloudflare, AWS Shield, Akamai) if available",
      "Enable rate limiting on affected services and load balancers",
      "Apply ACLs at upstream routers to block attack traffic if source is identifiable",
      "Enable SYN cookies and TCP connection limits if SYN flood is detected",
      "Null-route the targeted IP as a last resort if single-IP attack is saturating links",
      "Contact ISP for upstream filtering and black hole routing assistance",
      "Scale infrastructure horizontally if possible (auto-scaling, CDN)",
      "Implement geographic blocking if attack originates from specific regions",
      "Enable CAPTCHA or JavaScript challenges for application-layer attacks"
    ],
    eradication: [
      "Analyze attack traffic to identify patterns, source IPs, and amplification vectors",
      "Block identified attack source ranges at perimeter firewalls",
      "Patch any services being used as amplification reflectors",
      "Update WAF rules to block application-layer attack patterns",
      "Report abuse to ISPs hosting attack infrastructure",
      "If botnet-driven: share IOCs with relevant ISACs and law enforcement"
    ],
    recovery: [
      "Gradually remove emergency mitigation rules while monitoring traffic",
      "Verify all services are functioning normally post-attack",
      "Scale infrastructure back to normal levels when attack subsides",
      "Re-enable any services that were taken offline during mitigation",
      "Monitor for follow-up attacks (DDoS is often a distraction for other attacks)"
    ],
    lessons: [
      "Evaluate and improve DDoS mitigation capacity and provider agreements",
      "Document attack patterns for future mitigation rule creation",
      "Review architecture for DDoS resilience (CDN, anycast, geo-distribution)",
      "Implement always-on DDoS protection for critical services",
      "Test DDoS response procedures regularly with tabletop exercises",
      "Consider DDoS insurance and business continuity implications",
      "Investigate if DDoS was a diversionary tactic for another attack"
    ]
  },
  {
    incident: "Web Application Compromise",
    severity: "High",
    steps: [
      "Identify the compromised web application and determine the attack vector",
      "Check for web shells, defacement, injected content, or data theft",
      "Review web server access and error logs for exploitation activity",
      "Determine if the database was accessed (SQL injection) or the server was compromised",
      "Assess the data exposure: user credentials, personal data, payment information"
    ],
    containment: [
      "Take the compromised application offline or put it behind a maintenance page",
      "Block the attacker's IP addresses at the WAF and firewall",
      "If web shell is found: do not delete it yet; preserve for forensic analysis",
      "Isolate the web server from internal network to prevent lateral movement",
      "Revoke database credentials used by the application",
      "Invalidate all user sessions and API tokens",
      "Enable enhanced WAF rules for the identified attack vector",
      "Block outbound connections from the web server to the internet"
    ],
    eradication: [
      "Remove all web shells, backdoors, and injected code from the application",
      "Patch the vulnerability that was exploited (SQL injection, RFI, deserialization, etc.)",
      "Update the application framework and all dependencies to latest versions",
      "Reset all application credentials: database passwords, API keys, encryption keys",
      "Review application code for additional vulnerabilities",
      "Check for attacker modifications to configuration files and .htaccess",
      "Scan the server for rootkits and additional compromise indicators",
      "Review database for injected content, new admin accounts, or stored procedures"
    ],
    recovery: [
      "Deploy the cleaned and patched application from verified source code",
      "Restore database from clean backup if data integrity is compromised",
      "Force password resets for all application user accounts",
      "Re-enable the application with enhanced monitoring and WAF protection",
      "Conduct vulnerability scan and penetration test before going live",
      "Monitor for re-exploitation attempts on the patched vulnerability"
    ],
    lessons: [
      "Conduct a thorough code review and security audit of the application",
      "Implement a Web Application Firewall (WAF) with tuned rulesets",
      "Establish a vulnerability management program for web applications",
      "Implement automated dependency scanning in CI/CD pipeline",
      "Review and improve input validation and output encoding",
      "Implement Content Security Policy (CSP) headers",
      "Set up file integrity monitoring for web application files",
      "Schedule regular penetration testing and security assessments"
    ]
  },
  {
    incident: "Supply Chain Attack",
    severity: "Critical",
    steps: [
      "Identify the compromised component: software library, update mechanism, hardware, or service provider",
      "Determine which versions or builds are affected",
      "Assess the scope: how many systems or customers are impacted",
      "Evaluate the type of compromise: backdoor, trojanized update, dependency confusion, typosquatting",
      "Coordinate with the affected vendor or maintainer if known"
    ],
    containment: [
      "Block or quarantine the compromised component across all systems",
      "Prevent further downloads/installations of the affected version",
      "Isolate systems running the compromised component from sensitive resources",
      "Revoke any certificates or signing keys associated with the compromise",
      "Block known C2 infrastructure associated with the supply chain attack",
      "Notify downstream customers or users if your organization distributes the component",
      "Preserve the compromised component for analysis (do not delete yet)",
      "Assess if the attacker leveraged the supply chain access for further compromise"
    ],
    eradication: [
      "Remove or downgrade the compromised component to a known-clean version",
      "Scan all systems for IOCs associated with the supply chain attack",
      "Check for persistence mechanisms installed via the compromised component",
      "Audit all code or configuration changes made through the compromised supply chain",
      "Rebuild systems that ran the compromised component from trusted images",
      "Rotate all credentials that may have been accessible to the compromised component",
      "Review CI/CD pipeline for compromise (build servers, artifact repositories)"
    ],
    recovery: [
      "Deploy clean versions of the affected component after thorough verification",
      "Verify software integrity using independent hash verification or signing",
      "Implement enhanced monitoring for supply chain indicators",
      "Restore any systems rebuilt from clean images to operational state",
      "Validate business operations are functioning correctly with clean components"
    ],
    lessons: [
      "Implement Software Bill of Materials (SBOM) for all applications",
      "Establish software composition analysis (SCA) in the development pipeline",
      "Review vendor security assessment and third-party risk management processes",
      "Implement dependency pinning and hash verification for all components",
      "Set up alerts for unusual package updates, new maintainers, or dependency changes",
      "Consider using private package repositories with curated, verified components",
      "Evaluate code signing and build provenance verification (SLSA framework)",
      "Review and restrict CI/CD pipeline access and permissions"
    ]
  },
  {
    incident: "Account Compromise",
    severity: "High",
    steps: [
      "Identify the compromised account(s) from alerts, user reports, or anomalous behavior",
      "Determine the compromise method: credential stuffing, phishing, password spray, token theft",
      "Assess the privileges of the compromised account (regular user, admin, service account)",
      "Check for signs of account abuse: data access, email forwarding, privilege escalation",
      "Determine if the compromise has spread to other accounts or systems"
    ],
    containment: [
      "Reset the password for the compromised account immediately",
      "Revoke all active sessions and refresh tokens for the account",
      "Disable the account temporarily if the scope of compromise is unclear",
      "Enable MFA if not already configured on the compromised account",
      "Block the source IPs used for unauthorized access",
      "Check for and remove any persistent access mechanisms (SSH keys, API tokens, OAuth apps)",
      "If a service account: rotate the credentials and update all dependent services",
      "If privileged account: assess and contain potential lateral movement"
    ],
    eradication: [
      "Identify and close the initial compromise vector",
      "Remove any attacker-created accounts or access mechanisms",
      "Revoke all OAuth and API tokens generated during the compromise period",
      "Remove inbox rules, delegates, and forwarding created by the attacker",
      "Check for and remove any privilege escalation (group memberships, role assignments)",
      "Scan endpoints used by the compromised account for malware",
      "Review and remove any VPN or remote access configurations added by the attacker"
    ],
    recovery: [
      "Re-enable the account with a new strong password and MFA enabled",
      "Restore any data modified or deleted during the compromise",
      "Notify the account owner of the compromise and provide guidance",
      "Re-grant appropriate access permissions (do not simply restore old permissions)",
      "Monitor the account and associated systems for 30 days post-recovery"
    ],
    lessons: [
      "Enforce MFA on all accounts, especially privileged accounts",
      "Implement password complexity requirements and breach-password checking",
      "Deploy conditional access policies (location, device, risk-based)",
      "Set up anomalous login detection and impossible travel alerts",
      "Review and implement least privilege access principles",
      "Evaluate Privileged Access Management (PAM) solutions for admin accounts",
      "Implement regular access reviews and certification campaigns",
      "Educate users on password hygiene and phishing recognition"
    ]
  },
  {
    incident: "Malware Infection",
    severity: "Medium to High",
    steps: [
      "Receive alert from AV/EDR, user report, or anomalous system behavior",
      "Identify the malware: name, type (trojan, worm, RAT, cryptominer, spyware), and capabilities",
      "Determine the infection vector: email attachment, drive-by download, USB, lateral movement",
      "Assess the scope: number of infected systems and network segments affected",
      "Classify the malware severity based on capabilities and data access"
    ],
    containment: [
      "Isolate infected systems from the network immediately",
      "Block malware C2 domains and IPs at DNS and firewall",
      "Block malware file hashes at endpoint protection across the organization",
      "Disable network shares accessible from infected systems",
      "Capture memory dump from infected system before remediation",
      "Quarantine the malware sample for analysis",
      "Scan all systems with updated signatures for the identified malware",
      "Block lateral movement by segmenting affected network areas"
    ],
    eradication: [
      "Remove the malware from all infected systems using AV/EDR or manual removal",
      "Remove all persistence mechanisms (registry keys, scheduled tasks, services, startup items)",
      "Patch the vulnerability exploited for initial infection",
      "Clean or reimage systems that cannot be reliably cleaned",
      "Reset credentials for accounts accessed from infected systems",
      "Check for secondary payloads or additional malware families",
      "Update AV/EDR signatures and detection rules organization-wide"
    ],
    recovery: [
      "Restore cleaned systems to the network in a monitored state",
      "Verify system integrity and application functionality",
      "Restore any files encrypted, deleted, or corrupted by the malware",
      "Monitor recovered systems for re-infection for 14-30 days",
      "Validate that all malware IOCs are blocked at perimeter controls"
    ],
    lessons: [
      "Analyze the infection vector and improve defenses at that point",
      "Review and enhance endpoint protection configuration and coverage",
      "Implement application whitelisting on critical systems",
      "Review and improve email filtering for malware delivery",
      "Evaluate network segmentation to limit malware spread",
      "Update detection rules and YARA signatures based on the malware analysis",
      "Conduct user awareness training on the infection vector",
      "Share IOCs with relevant ISACs and threat intelligence platforms"
    ]
  },
  {
    incident: "Advanced Persistent Threat (APT)",
    severity: "Critical",
    steps: [
      "Identify APT indicators: custom malware, zero-day exploits, long dwell time, targeted data access",
      "Determine the suspected threat actor group based on TTPs and IOCs",
      "Map the attack to the MITRE ATT&CK framework to understand the full kill chain",
      "Assess the scope: all compromised systems, accounts, and data accessed",
      "Engage specialized incident response firm and/or notify relevant government agencies"
    ],
    containment: [
      "DO NOT immediately remove the threat; plan a coordinated eviction to prevent the actor from going deeper",
      "Increase monitoring across all systems, not just known-compromised ones",
      "Deploy additional network monitoring at key chokepoints",
      "Silently block C2 communication at the firewall (do not alert the attacker)",
      "Prepare for coordinated credential reset across the entire environment",
      "Stage clean infrastructure for migration (new domain controllers, etc.)",
      "Identify and protect the attacker's likely objectives (intellectual property, credentials)",
      "Plan the containment and eviction for simultaneous execution across all affected systems"
    ],
    eradication: [
      "Execute coordinated eviction: simultaneously remove all attacker access across all systems",
      "Reset ALL domain credentials including KRBTGT (twice, 12 hours apart)",
      "Reset all service account passwords",
      "Rebuild compromised domain controllers from clean media",
      "Remove all identified backdoors, web shells, implants, and C2 infrastructure",
      "Re-key all certificates and cryptographic material that may be compromised",
      "Rebuild or reimage all confirmed and suspected compromised systems",
      "Deploy new endpoint detection with APT-specific detection rules",
      "Block all identified IOCs at every layer (network, endpoint, email, DNS)"
    ],
    recovery: [
      "Bring systems back online in phases with intensive monitoring",
      "Implement network segmentation to limit future lateral movement",
      "Deploy enhanced detection for the specific APT group's known TTPs",
      "Establish 24/7 monitoring for at least 90 days post-eviction",
      "Validate that business-critical applications are functioning correctly",
      "Restore data from verified clean backups where needed",
      "Engage ongoing threat hunting to detect any remaining access"
    ],
    lessons: [
      "Conduct comprehensive lessons-learned review with all stakeholders",
      "Document the complete attack timeline, TTPs, and IOCs in detail",
      "Share threat intelligence with relevant ISACs, CERT, and intelligence agencies",
      "Implement a continuous threat hunting program",
      "Evaluate and implement zero-trust architecture",
      "Enhance detection capabilities for the specific APT TTPs observed",
      "Review and improve security monitoring coverage and alert fidelity",
      "Implement deception technology (honeypots, honeytokens) for early detection",
      "Evaluate network segmentation and microsegmentation strategies",
      "Conduct red team exercises simulating the APT's observed TTPs"
    ]
  }
];

// -----------------------------------------------------------------------------
// 6. LOG ANALYSIS (Queries and Patterns)
// -----------------------------------------------------------------------------
export const LOG_ANALYSIS = [
  // =========================================================================
  // SPLUNK QUERIES
  // =========================================================================
  {
    source: "Splunk",
    query: "index=wineventlog EventCode=4625 | stats count by src_ip, user | where count > 10 | sort -count",
    description: "Detect brute force login attempts by identifying source IPs with more than 10 failed login events.",
    ioc: "Multiple failed login attempts from a single source IP indicating credential brute force or password spraying."
  },
  {
    source: "Splunk",
    query: "index=wineventlog EventCode=4624 LogonType=10 | stats count by src_ip, user, dest | sort -count",
    description: "Track Remote Desktop (RDP) logins (LogonType 10) showing source IPs, users, and destination systems.",
    ioc: "RDP logins from unexpected sources or at unusual times indicating lateral movement."
  },
  {
    source: "Splunk",
    query: "index=wineventlog EventCode=4720 OR EventCode=4726 | table _time, user, TargetUserName, EventCode | sort _time",
    description: "Detect user account creation (4720) and deletion (4726) events for unauthorized account management.",
    ioc: "Unauthorized account creation is a common persistence technique; rapid creation and deletion indicates covering tracks."
  },
  {
    source: "Splunk",
    query: "index=wineventlog EventCode=4672 | stats count by user | where count > 5 | sort -count",
    description: "Identify users assigned special privileges (admin logon) and detect privilege escalation.",
    ioc: "Unexpected privilege assignments to non-admin accounts indicating privilege escalation."
  },
  {
    source: "Splunk",
    query: "index=wineventlog EventCode=7045 | table _time, ServiceName, ImagePath, ServiceType, StartType | sort _time",
    description: "Detect new Windows service installations which may indicate persistence or privilege escalation.",
    ioc: "New services with suspicious binary paths, encoded commands, or running as SYSTEM."
  },
  {
    source: "Splunk",
    query: "index=wineventlog EventCode=4688 OR (source=\"*Sysmon*\" EventCode=1) | search (CommandLine=\"*powershell*\" OR CommandLine=\"*cmd*\" OR CommandLine=\"*wscript*\" OR CommandLine=\"*cscript*\" OR CommandLine=\"*mshta*\" OR CommandLine=\"*rundll32*\" OR CommandLine=\"*regsvr32*\") | table _time, user, ParentImage, Image, CommandLine",
    description: "Monitor process creation events for common LOLBin (Living off the Land Binary) execution.",
    ioc: "LOLBin abuse: legitimate Windows binaries used for malicious purposes (execution, download, proxy)."
  },
  {
    source: "Splunk",
    query: "index=wineventlog source=\"*PowerShell*\" EventCode=4104 | search ScriptBlockText=\"*-enc*\" OR ScriptBlockText=\"*downloadstring*\" OR ScriptBlockText=\"*invoke-expression*\" OR ScriptBlockText=\"*iex*\" OR ScriptBlockText=\"*webclient*\" OR ScriptBlockText=\"*bypass*\" | table _time, ComputerName, ScriptBlockText",
    description: "Detect suspicious PowerShell script blocks containing encoded commands, download cradles, or execution bypass.",
    ioc: "PowerShell-based attack techniques: encoded commands, download cradles, and AMSI/execution policy bypass."
  },
  {
    source: "Splunk",
    query: "index=wineventlog EventCode=4624 LogonType=3 | stats dc(dest) as unique_dests by src_ip, user | where unique_dests > 5 | sort -unique_dests",
    description: "Detect potential lateral movement by finding accounts authenticating to many systems via network logon.",
    ioc: "Single account authenticating to many systems in a short time indicating lateral movement or reconnaissance."
  },
  {
    source: "Splunk",
    query: "index=wineventlog EventCode=1102 OR EventCode=104 | table _time, ComputerName, EventCode, user",
    description: "Detect security log clearing (1102) and system log clearing (104) indicating anti-forensic activity.",
    ioc: "Event log clearing is a strong indicator of attacker activity to cover tracks."
  },
  {
    source: "Splunk",
    query: "index=wineventlog source=\"*Sysmon*\" EventCode=3 | search NOT (DestinationIp=\"10.*\" OR DestinationIp=\"172.16.*\" OR DestinationIp=\"192.168.*\" OR DestinationIp=\"127.*\") | stats count by Image, DestinationIp, DestinationPort | where count > 50 | sort -count",
    description: "Identify processes making frequent outbound connections to external IPs, potential C2 beaconing.",
    ioc: "Periodic outbound connections to external IPs from non-browser processes suggesting C2 communication."
  },
  {
    source: "Splunk",
    query: "index=wineventlog source=\"*Sysmon*\" EventCode=11 TargetFilename=\"*.exe\" OR TargetFilename=\"*.dll\" OR TargetFilename=\"*.ps1\" OR TargetFilename=\"*.bat\" OR TargetFilename=\"*.vbs\" | search TargetFilename=\"*\\Temp\\*\" OR TargetFilename=\"*\\AppData\\*\" OR TargetFilename=\"*\\ProgramData\\*\" | table _time, Image, TargetFilename",
    description: "Detect executable and script files created in suspicious directories (Temp, AppData, ProgramData).",
    ioc: "Malware drops and staging in temporary/user-writable directories."
  },
  {
    source: "Splunk",
    query: "index=wineventlog source=\"*Sysmon*\" EventCode=1 ParentImage=\"*\\winword.exe\" OR ParentImage=\"*\\excel.exe\" OR ParentImage=\"*\\powerpnt.exe\" OR ParentImage=\"*\\outlook.exe\" | table _time, ParentImage, Image, CommandLine, User",
    description: "Detect child processes spawned by Office applications indicating macro-based malware execution.",
    ioc: "Office applications spawning cmd.exe, PowerShell, or other executables indicates macro-based attack."
  },
  {
    source: "Splunk",
    query: "index=wineventlog EventCode=4698 | table _time, SubjectUserName, TaskName, TaskContent | sort _time",
    description: "Detect new scheduled task creation (Event ID 4698) for persistence analysis.",
    ioc: "Scheduled task creation is a top persistence mechanism; check for tasks running suspicious binaries."
  },
  {
    source: "Splunk",
    query: "index=proxy OR index=web | stats sum(bytes_out) as total_bytes by src_ip, dest_host | where total_bytes > 104857600 | sort -total_bytes",
    description: "Detect large data transfers (over 100MB) to external destinations indicating potential data exfiltration.",
    ioc: "Unusually large outbound data transfers to external hosts suggesting data exfiltration."
  },
  {
    source: "Splunk",
    query: "index=dns | stats count by query | where count > 1000 OR len(query) > 50 | sort -count",
    description: "Detect DNS tunneling and DGA by finding high-frequency DNS queries or queries with unusually long domain names.",
    ioc: "DNS tunneling uses long subdomain names and high query frequency; DGA domains are algorithmically generated."
  },
  {
    source: "Splunk",
    query: "index=wineventlog source=\"*Sysmon*\" EventCode=8 | table _time, SourceImage, TargetImage, StartModule, StartFunction | sort _time",
    description: "Detect remote thread creation (CreateRemoteThread) indicating process injection.",
    ioc: "Remote thread injection is used for code injection and defense evasion."
  },
  {
    source: "Splunk",
    query: "index=wineventlog source=\"*Sysmon*\" EventCode=10 TargetImage=\"*\\lsass.exe\" | table _time, SourceImage, GrantedAccess, CallTrace | sort _time",
    description: "Detect processes accessing LSASS memory (credential dumping).",
    ioc: "LSASS memory access is the primary indicator of credential dumping (Mimikatz, etc.)."
  },
  {
    source: "Splunk",
    query: "index=wineventlog source=\"*WinDefend*\" EventCode=1116 OR EventCode=1117 | table _time, ComputerName, ThreatName, Severity, Path, Action | sort _time",
    description: "Track Windows Defender malware detections and remediation actions.",
    ioc: "AV detections with paths and threat names; check for repeated detections indicating persistent threat."
  },
  {
    source: "Splunk",
    query: "index=wineventlog source=\"*WinDefend*\" EventCode=5007 | search Value=\"*ExclusionPath*\" OR Value=\"*ExclusionProcess*\" OR Value=\"*ExclusionExtension*\" | table _time, ComputerName, Value",
    description: "Detect Windows Defender exclusion additions that may be used to evade antivirus detection.",
    ioc: "Adding AV exclusions is a common technique to prevent detection of dropped malware."
  },

  // =========================================================================
  // ELK / ELASTICSEARCH QUERIES
  // =========================================================================
  {
    source: "ELK",
    query: "event.code:4625 | aggregate by source.ip, user.name with count > 10",
    description: "Detect brute force attempts in ELK/Elastic Security by finding repeated failed logins per source.",
    ioc: "Brute force credential attacks from identified source IPs."
  },
  {
    source: "ELK",
    query: "event.code:4624 AND winlog.event_data.LogonType:\"10\" | aggregate by source.ip, user.name, host.name",
    description: "Track RDP sessions in ELK environment.",
    ioc: "RDP lateral movement tracking."
  },
  {
    source: "ELK",
    query: "event.code:1 AND process.parent.name:(\"winword.exe\" OR \"excel.exe\" OR \"powerpnt.exe\") AND process.name:(\"cmd.exe\" OR \"powershell.exe\" OR \"wscript.exe\" OR \"mshta.exe\")",
    description: "Detect Office macro execution spawning suspicious child processes in Elastic.",
    ioc: "Macro-based malware execution from Office documents."
  },
  {
    source: "ELK",
    query: "event.code:4104 AND powershell.script_block_text:(*downloadstring* OR *invoke-expression* OR *encodedcommand* OR *bypass*)",
    description: "Detect suspicious PowerShell script blocks in Elastic SIEM.",
    ioc: "PowerShell-based attack techniques captured by script block logging."
  },
  {
    source: "ELK",
    query: "event.code:7045 AND NOT winlog.event_data.ServiceName:(\"Microsoft*\" OR \"Windows*\")",
    description: "Detect non-Microsoft service installations for persistence analysis in Elastic.",
    ioc: "New service creation from non-standard sources."
  },
  {
    source: "ELK",
    query: "event.code:3 AND NOT destination.ip:(10.0.0.0/8 OR 172.16.0.0/12 OR 192.168.0.0/16 OR 127.0.0.0/8) | aggregate by process.name, destination.ip, destination.port with count | sort count desc",
    description: "Identify processes with frequent outbound connections to external IPs in Elastic.",
    ioc: "Potential C2 beaconing detected by outbound connection frequency analysis."
  },
  {
    source: "ELK",
    query: "event.code:1102 OR event.code:104",
    description: "Detect event log clearing in Elastic Security.",
    ioc: "Anti-forensic log clearing activity."
  },
  {
    source: "ELK",
    query: "event.code:10 AND winlog.event_data.TargetImage:\"*lsass.exe\" AND NOT winlog.event_data.SourceImage:(\"*csrss.exe\" OR \"*lsm.exe\" OR \"*wmiprvse.exe\")",
    description: "Detect credential dumping by monitoring LSASS access in Elastic, filtering known legitimate accessors.",
    ioc: "LSASS memory access for credential harvesting."
  },
  {
    source: "ELK",
    query: "dns.question.name:* | aggregate by dns.question.name with count | filter count > 500 or dns.question.name length > 40",
    description: "Detect DNS tunneling and DGA domains in Elastic using query frequency and name length.",
    ioc: "DNS-based data exfiltration or command-and-control."
  },
  {
    source: "ELK",
    query: "http.response.status_code:200 AND url.path:(\"/cmd\" OR \"/shell\" OR \"/exec\" OR \"/eval\" OR \"/upload\") AND source.ip:(10.0.0.0/8 OR 172.16.0.0/12 OR 192.168.0.0/16)",
    description: "Detect potential web shell access by monitoring HTTP requests to suspicious URL paths.",
    ioc: "Web shell interaction patterns with command execution paths."
  },

  // =========================================================================
  // GREP / AWK / COMMAND LINE PATTERNS
  // =========================================================================
  {
    source: "grep/awk",
    query: "grep -i 'failed password' /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -20",
    description: "Extract and count failed SSH password attempts by source IP from auth.log.",
    ioc: "SSH brute force attacks showing most active attacker IPs."
  },
  {
    source: "grep/awk",
    query: "grep 'Accepted password\\|Accepted publickey' /var/log/auth.log | awk '{print $1,$2,$3,$9,$11}' | sort",
    description: "List all successful SSH logins with timestamps, usernames, and source IPs.",
    ioc: "Successful logins from unexpected IPs or during unusual hours."
  },
  {
    source: "grep/awk",
    query: "grep -i 'session opened for user root' /var/log/auth.log | grep -v 'cron'",
    description: "Identify root sessions opened excluding cron, focusing on interactive root access.",
    ioc: "Direct root access or privilege escalation to root."
  },
  {
    source: "grep/awk",
    query: "awk '/sshd.*Did not receive identification string/ {print $NF}' /var/log/auth.log | sort | uniq -c | sort -rn",
    description: "Identify SSH scanning activity from hosts that connect but don't complete authentication.",
    ioc: "SSH port scanning and reconnaissance activity."
  },
  {
    source: "grep/awk",
    query: "grep -E 'useradd|userdel|usermod|groupadd|passwd' /var/log/auth.log | grep -v 'pam_unix'",
    description: "Detect user account modifications: creation, deletion, modification, and password changes.",
    ioc: "Unauthorized account management activity for persistence or privilege escalation."
  },
  {
    source: "grep/awk",
    query: "last -f /var/log/wtmp | head -50",
    description: "Display the 50 most recent login sessions from wtmp binary log.",
    ioc: "Login session history with source addresses and durations."
  },
  {
    source: "grep/awk",
    query: "lastb -f /var/log/btmp | awk '{print $3}' | sort | uniq -c | sort -rn | head -20",
    description: "Count failed login attempts by source IP from btmp.",
    ioc: "Top attacking IPs from failed login data."
  },
  {
    source: "grep/awk",
    query: "grep -rn 'COMMAND=' /var/log/auth.log | grep -i sudo | awk -F'COMMAND=' '{print $2}' | sort | uniq -c | sort -rn | head -30",
    description: "List the most frequently used sudo commands, showing privilege escalation patterns.",
    ioc: "Unusual sudo commands indicating post-exploitation activity."
  },
  {
    source: "grep/awk",
    query: "find / -name '*.php' -newer /var/log/syslog -mtime -7 2>/dev/null | head -50",
    description: "Find PHP files modified in the last 7 days that may be web shells or backdoors.",
    ioc: "Recently modified or created PHP files in web directories suggesting web shell deployment."
  },
  {
    source: "grep/awk",
    query: "find / -perm -4000 -type f 2>/dev/null | xargs ls -la",
    description: "Find all SUID binaries on the system that could be exploited for privilege escalation.",
    ioc: "Unexpected SUID binaries indicating privilege escalation backdoors."
  },
  {
    source: "grep/awk",
    query: "find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null | xargs ls -la",
    description: "Find executable files in temporary directories commonly used for malware staging.",
    ioc: "Executables in /tmp, /var/tmp, or /dev/shm indicating active compromise."
  },
  {
    source: "grep/awk",
    query: "netstat -tlnp 2>/dev/null || ss -tlnp",
    description: "List all listening TCP ports with associated processes.",
    ioc: "Unexpected listening ports indicating backdoors or unauthorized services."
  },
  {
    source: "grep/awk",
    query: "netstat -tnp 2>/dev/null | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -20",
    description: "List top destination IPs for established outbound TCP connections.",
    ioc: "Active outbound connections to potentially malicious C2 servers."
  },
  {
    source: "grep/awk",
    query: "ps auxf | grep -v '\\[' | awk '$3 > 50 || $4 > 50'",
    description: "Find processes consuming excessive CPU or memory resources.",
    ioc: "Cryptominers and resource-intensive malware consuming excessive system resources."
  },
  {
    source: "grep/awk",
    query: "for user in $(cut -d: -f1 /etc/passwd); do crontab -l -u $user 2>/dev/null && echo \"--- $user ---\"; done",
    description: "List crontab entries for all users on the system.",
    ioc: "Unauthorized cron jobs used for persistence or periodic data exfiltration."
  },
  {
    source: "grep/awk",
    query: "grep -rn 'curl\\|wget\\|python.*http\\|nc\\s\\+-e\\|bash\\s\\+-i' /var/log/ 2>/dev/null | head -30",
    description: "Search logs for evidence of reverse shell commands and download activity.",
    ioc: "Reverse shell and malware download commands in log files."
  },
  {
    source: "grep/awk",
    query: "awk '$3 == 0 && $1 != \"root\"' /etc/passwd",
    description: "Find non-root accounts with UID 0 (root equivalent privileges).",
    ioc: "Backdoor accounts with root-level access via UID 0."
  },
  {
    source: "grep/awk",
    query: "diff <(grep -E '^[^#]' /etc/passwd | cut -d: -f7 | sort | uniq -c | sort -rn) /dev/null",
    description: "Count login shells assigned to users to identify unusual shell assignments.",
    ioc: "Accounts with unusual shells (e.g., /bin/bash on service accounts that should have /sbin/nologin)."
  },
  {
    source: "grep/awk",
    query: "grep -rn 'POST.*\\(200\\|302\\)' /var/log/apache2/access.log | awk '{print $7}' | sort | uniq -c | sort -rn | head -20",
    description: "Find the most frequently accessed POST endpoints that returned success, potential web shell activity.",
    ioc: "Frequent POST requests to unusual endpoints suggesting web shell command execution."
  },
  {
    source: "grep/awk",
    query: "awk '/select.*from|union.*select|insert.*into|drop.*table|exec.*xp_|script>|<\\?php/i' /var/log/apache2/access.log | head -30",
    description: "Detect SQL injection and XSS attempts in web server access logs.",
    ioc: "Web application attack attempts: SQL injection, cross-site scripting, PHP injection."
  },
  {
    source: "grep/awk",
    query: "grep -E '\\.(php|asp|aspx|jsp|cgi)\\?' /var/log/apache2/access.log | grep -E '(cmd=|exec=|shell=|eval=|system=|passthru=)' | head -20",
    description: "Detect web shell command execution patterns in web server logs.",
    ioc: "Web shell command execution via URL parameters."
  },
  {
    source: "grep/awk",
    query: "find / -name authorized_keys -exec ls -la {} \\; 2>/dev/null",
    description: "Find all authorized_keys files on the system and list their details.",
    ioc: "Unauthorized SSH keys added for persistent access."
  },
  {
    source: "grep/awk",
    query: "find /etc/systemd/system /usr/lib/systemd/system -name '*.service' -mtime -30 | xargs ls -la 2>/dev/null",
    description: "Find systemd service files modified in the last 30 days.",
    ioc: "Recently created or modified services indicating persistence mechanisms."
  },
  {
    source: "grep/awk",
    query: "journalctl --since '7 days ago' -p err | grep -i 'segfault\\|denied\\|error\\|fail' | head -50",
    description: "Search systemd journal for error-level messages from the past week.",
    ioc: "System errors, access denials, and segfaults that may indicate exploitation or compromise."
  },
  {
    source: "grep/awk",
    query: "cat /proc/*/cmdline 2>/dev/null | tr '\\0' ' ' | grep -iE 'nc |ncat |socat |python.*pty|bash.*-i|php.*-r' | head -20",
    description: "Check running process command lines for reverse shell and bind shell patterns.",
    ioc: "Active reverse shells or bind shells running on the system."
  },
  {
    source: "grep/awk",
    query: "ls -la /etc/ld.so.preload 2>/dev/null; cat /etc/ld.so.preload 2>/dev/null; ldd /bin/ls 2>/dev/null | grep -v '=>'",
    description: "Check for library preloading attacks and verify linked libraries of common binaries.",
    ioc: "LD_PRELOAD rootkit or shared library injection for process hooking."
  },
  {
    source: "grep/awk",
    query: "rpm -Va 2>/dev/null | grep -E '^..5' || dpkg --verify 2>/dev/null | grep -v '^$'",
    description: "Verify package integrity by checking installed package file checksums.",
    ioc: "Modified system files indicating trojanized binaries or rootkit activity."
  },
  {
    source: "grep/awk",
    query: "dmesg | grep -i 'oom\\|killed\\|segfault\\|error\\|usb' | tail -30",
    description: "Check kernel ring buffer for out-of-memory kills, segfaults, and USB device events.",
    ioc: "OOM kills from resource exhaustion, segfaults from exploitation, and USB device connections."
  },
  {
    source: "grep/awk",
    query: "grep -rn 'ProxyCommand\\|LocalForward\\|RemoteForward\\|DynamicForward' /home/*/.ssh/config /root/.ssh/config 2>/dev/null",
    description: "Detect SSH tunnel and proxy configurations in SSH client configs.",
    ioc: "SSH tunneling configured for network pivoting and covert channels."
  }
];
