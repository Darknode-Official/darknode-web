// Darknode -- MITRE ATT&CK Framework Reference
// Copyright (c) 2026 SpartanKing18. All rights reserved.

// Copyright (c) 2026 SpartanKing18. All rights reserved.
// MITRE ATT&CK Framework -- Complete Reference Data
// Covers Enterprise ATT&CK tactics, techniques, groups, software, mitigations, and data sources

// =============================================================================
// MITRE ATT&CK TACTICS
// =============================================================================

const MITRE_TACTICS = [
  {
    id: "TA0043",
    name: "Reconnaissance",
    shortName: "reconnaissance",
    description: "The adversary is trying to gather information they can use to plan future operations. Reconnaissance consists of techniques that involve adversaries actively or passively gathering information that can be used to support targeting. Such information may include details of the victim organization, infrastructure, or staff. This information can be leveraged by the adversary to aid in other phases of the adversary lifecycle, such as using gathered information to plan and execute Initial Access or to scope and prioritize post-compromise objectives.",
    techniques: 10,
    url: "https://attack.mitre.org/tactics/TA0043/"
  },
  {
    id: "TA0042",
    name: "Resource Development",
    shortName: "resource-development",
    description: "The adversary is trying to establish resources they can use to support operations. Resource Development consists of techniques that involve adversaries creating, purchasing, or compromising resources that can be used to support targeting. Such resources include infrastructure, accounts, or capabilities. These resources can be leveraged by the adversary to aid in other phases of the adversary lifecycle, such as using purchased domains to support Command and Control or compromised email accounts for phishing during Initial Access.",
    techniques: 8,
    url: "https://attack.mitre.org/tactics/TA0042/"
  },
  {
    id: "TA0001",
    name: "Initial Access",
    shortName: "initial-access",
    description: "The adversary is trying to get into your network. Initial Access consists of techniques that use various entry vectors to gain their initial foothold within a network. Techniques used to gain a foothold include targeted spearphishing and exploiting weaknesses on public-facing web servers. Footholds gained through Initial Access may allow for continued access, like valid accounts and use of external remote services, or may be limited-use due to changing passwords.",
    techniques: 10,
    url: "https://attack.mitre.org/tactics/TA0001/"
  },
  {
    id: "TA0002",
    name: "Execution",
    shortName: "execution",
    description: "The adversary is trying to run malicious code. Execution consists of techniques that result in adversary-controlled code running on a local or remote system. Techniques that run malicious code are often paired with techniques from all other tactics to achieve broader goals, like exploring the network or stealing data. For example, an adversary might use a remote access tool to run a PowerShell script that does Remote System Discovery.",
    techniques: 14,
    url: "https://attack.mitre.org/tactics/TA0002/"
  },
  {
    id: "TA0003",
    name: "Persistence",
    shortName: "persistence",
    description: "The adversary is trying to maintain their foothold. Persistence consists of techniques that adversaries use to keep access to systems across restarts, changed credentials, and other interruptions that could cut off their access. Techniques used for persistence include any access, action, or configuration changes that let them maintain their foothold on systems, such as replacing or hijacking legitimate code or adding startup code.",
    techniques: 20,
    url: "https://attack.mitre.org/tactics/TA0003/"
  },
  {
    id: "TA0004",
    name: "Privilege Escalation",
    shortName: "privilege-escalation",
    description: "The adversary is trying to gain higher-level permissions. Privilege Escalation consists of techniques that adversaries use to gain higher-level permissions on a system or network. Adversaries can often enter and explore a network with unprivileged access but require elevated permissions to follow through on their objectives. Common approaches are to take advantage of system weaknesses, misconfigurations, and vulnerabilities. These techniques often overlap with Persistence techniques, as OS features that let an adversary persist can execute in an elevated context.",
    techniques: 14,
    url: "https://attack.mitre.org/tactics/TA0004/"
  },
  {
    id: "TA0005",
    name: "Defense Evasion",
    shortName: "defense-evasion",
    description: "The adversary is trying to avoid being detected. Defense Evasion consists of techniques that adversaries use to avoid detection throughout their compromise. Techniques used for defense evasion include uninstalling or disabling security software, obfuscating or encrypting data and scripts, abusing trusted processes to hide and masquerade their malware, and exploiting trusted certificates. These techniques are particularly dangerous because they undermine the defensive measures organizations rely upon.",
    techniques: 42,
    url: "https://attack.mitre.org/tactics/TA0005/"
  },
  {
    id: "TA0006",
    name: "Credential Access",
    shortName: "credential-access",
    description: "The adversary is trying to steal account names and passwords. Credential Access consists of techniques for stealing credentials like account names and passwords. Techniques used to get credentials include keylogging, credential dumping, and brute force attacks. Using legitimate credentials can give adversaries access to systems, make them harder to detect, and provide the opportunity to create more accounts to help achieve their goals.",
    techniques: 17,
    url: "https://attack.mitre.org/tactics/TA0006/"
  },
  {
    id: "TA0007",
    name: "Discovery",
    shortName: "discovery",
    description: "The adversary is trying to figure out your environment. Discovery consists of techniques an adversary may use to gain knowledge about the system and internal network. These techniques help adversaries observe the environment and orient themselves before deciding how to act. They also allow adversaries to explore what they can control and what is around their entry point in order to discover how it could benefit their current objective.",
    techniques: 32,
    url: "https://attack.mitre.org/tactics/TA0007/"
  },
  {
    id: "TA0008",
    name: "Lateral Movement",
    shortName: "lateral-movement",
    description: "The adversary is trying to move through your environment. Lateral Movement consists of techniques that adversaries use to enter and control remote systems on a network. Following through on their primary objective often requires exploring the network to find their target and subsequently gaining access to it. Reaching their objective often involves pivoting through multiple systems and accounts. Adversaries might install their own remote access tools to accomplish Lateral Movement or use legitimate credentials with native network and operating system tools, which may be stealthier.",
    techniques: 9,
    url: "https://attack.mitre.org/tactics/TA0008/"
  },
  {
    id: "TA0009",
    name: "Collection",
    shortName: "collection",
    description: "The adversary is trying to gather data of interest to their goal. Collection consists of techniques adversaries may use to gather information relevant to their objectives. Frequently, the next goal after collecting data is to steal (exfiltrate) the data. Common target sources include various drive types, browsers, audio, video, and email. Common collection methods include capturing screenshots and keyboard input.",
    techniques: 17,
    url: "https://attack.mitre.org/tactics/TA0009/"
  },
  {
    id: "TA0011",
    name: "Command and Control",
    shortName: "command-and-control",
    description: "The adversary is trying to communicate with compromised systems to control them. Command and Control consists of techniques that adversaries may use to communicate with systems under their control within a victim network. Adversaries commonly attempt to mimic normal, expected traffic to avoid detection. There are many ways an adversary can establish command and control with various levels of stealth depending on the victim network structure and defenses.",
    techniques: 16,
    url: "https://attack.mitre.org/tactics/TA0011/"
  },
  {
    id: "TA0010",
    name: "Exfiltration",
    shortName: "exfiltration",
    description: "The adversary is trying to steal data. Exfiltration consists of techniques that adversaries may use to steal data from your network. Once they have collected data, adversaries often package it to avoid detection while removing it. This can include compression and encryption. Techniques for getting data out of a target network typically include transferring it over their command and control channel or an alternate channel and may also include putting size limits on the transmission.",
    techniques: 9,
    url: "https://attack.mitre.org/tactics/TA0010/"
  },
  {
    id: "TA0013",
    name: "Impact",
    shortName: "impact",
    description: "The adversary is trying to manipulate, interrupt, or destroy your systems and data. Impact consists of techniques that adversaries use to disrupt availability or compromise integrity by manipulating business and operational processes. Techniques used for impact can include destroying or tampering with data. In some cases, business processes can look fine, but may have been altered to benefit the adversary. These techniques might be used by adversaries to follow through on their end goal or to provide cover for a confidentiality breach.",
    techniques: 14,
    url: "https://attack.mitre.org/tactics/TA0013/"
  }
];

// =============================================================================
// MITRE ATT&CK DATA SOURCES
// =============================================================================

const MITRE_DATASOURCES = [
  {
    id: "DS0029",
    name: "Network Traffic",
    description: "Network traffic data captured from network interfaces, taps, or inline devices. This includes packet captures, flow records, and protocol metadata that can reveal adversary communication patterns, data exfiltration, and lateral movement.",
    components: [
      "Network Traffic Content",
      "Network Traffic Flow",
      "Network Connection Creation"
    ],
    techniques: ["T1071", "T1572", "T1573", "T1095", "T1571", "T1132", "T1001", "T1048", "T1041", "T1568", "T1102", "T1090", "T1219", "T1105", "T1557"]
  },
  {
    id: "DS0009",
    name: "Process",
    description: "Information about running processes on a system, including process creation events, command-line arguments, and parent-child relationships. Process monitoring is foundational for detecting execution of malicious code and suspicious process behavior.",
    components: [
      "Process Creation",
      "Process Termination",
      "Process Access",
      "Process Modification",
      "OS API Execution"
    ],
    techniques: ["T1059", "T1053", "T1055", "T1106", "T1569", "T1204", "T1203", "T1218", "T1036", "T1027", "T1140", "T1622", "T1057", "T1518"]
  },
  {
    id: "DS0022",
    name: "File",
    description: "Information about files on disk including creation, modification, deletion, and access events. File monitoring is critical for detecting malware drops, configuration changes, and data staging activities by adversaries.",
    components: [
      "File Creation",
      "File Modification",
      "File Deletion",
      "File Access",
      "File Metadata"
    ],
    techniques: ["T1105", "T1560", "T1074", "T1036", "T1070", "T1027", "T1547", "T1546", "T1564", "T1055", "T1204", "T1080", "T1505"]
  },
  {
    id: "DS0017",
    name: "Command",
    description: "Information about commands executed on a system through command-line interfaces, scripting interpreters, or remote execution mechanisms. Command monitoring captures the exact instructions adversaries issue during an intrusion.",
    components: [
      "Command Execution"
    ],
    techniques: ["T1059", "T1053", "T1047", "T1569", "T1218", "T1216", "T1220", "T1127", "T1072", "T1651"]
  },
  {
    id: "DS0024",
    name: "Windows Registry",
    description: "Information about changes to the Windows Registry, which stores configuration data for the operating system and applications. Adversaries frequently modify registry keys for persistence, privilege escalation, and defense evasion.",
    components: [
      "Windows Registry Key Creation",
      "Windows Registry Key Modification",
      "Windows Registry Key Deletion",
      "Windows Registry Key Access"
    ],
    techniques: ["T1547", "T1546", "T1112", "T1562", "T1564", "T1574", "T1012", "T1552", "T1036", "T1218"]
  },
  {
    id: "DS0015",
    name: "Application Log",
    description: "Logs generated by applications and services running on a system, including web server logs, database logs, authentication logs, and application-specific event logs. These provide context about how services are being used or abused.",
    components: [
      "Application Log Content"
    ],
    techniques: ["T1190", "T1133", "T1505", "T1210", "T1213", "T1530", "T1114", "T1098", "T1110", "T1078"]
  },
  {
    id: "DS0028",
    name: "Logon Session",
    description: "Information about user authentication sessions on a system, including login events, session creation, and metadata about authentication type. Logon session data reveals unauthorized access attempts and credential misuse.",
    components: [
      "Logon Session Creation",
      "Logon Session Metadata"
    ],
    techniques: ["T1078", "T1021", "T1110", "T1550", "T1558", "T1134", "T1563", "T1534"]
  },
  {
    id: "DS0002",
    name: "User Account",
    description: "Information about user accounts on a system or domain, including creation, modification, deletion, and authentication events. Monitoring user account activity helps detect unauthorized access, privilege escalation, and account manipulation.",
    components: [
      "User Account Creation",
      "User Account Modification",
      "User Account Deletion",
      "User Account Authentication",
      "User Account Metadata"
    ],
    techniques: ["T1136", "T1098", "T1078", "T1087", "T1110", "T1531", "T1070", "T1134"]
  },
  {
    id: "DS0026",
    name: "Active Directory",
    description: "Information about Active Directory objects and operations, including changes to directory services, schema modifications, and replication events. Monitoring AD is essential for detecting domain-level attacks and privilege escalation.",
    components: [
      "Active Directory Object Creation",
      "Active Directory Object Modification",
      "Active Directory Object Deletion",
      "Active Directory Object Access",
      "Active Directory Credential Request"
    ],
    techniques: ["T1558", "T1207", "T1484", "T1098", "T1069", "T1482", "T1087", "T1615", "T1003"]
  },
  {
    id: "DS0019",
    name: "Service",
    description: "Information about system services, daemons, and background processes, including service creation, modification, and status changes. Service monitoring detects adversaries installing persistent backdoors or modifying legitimate services.",
    components: [
      "Service Creation",
      "Service Modification"
    ],
    techniques: ["T1543", "T1569", "T1574", "T1489", "T1505"]
  },
  {
    id: "DS0005",
    name: "WMI",
    description: "Information about Windows Management Instrumentation activity, including WMI queries, event subscriptions, and remote execution. WMI is frequently abused by adversaries for execution, persistence, and lateral movement on Windows systems.",
    components: [
      "WMI Creation"
    ],
    techniques: ["T1047", "T1546", "T1059"]
  },
  {
    id: "DS0025",
    name: "Cloud Service",
    description: "Information about cloud platform services and API activity, including service enumeration, configuration changes, and access patterns. Monitoring cloud services is critical for detecting adversary activity in hybrid and cloud-native environments.",
    components: [
      "Cloud Service Disable",
      "Cloud Service Enumeration",
      "Cloud Service Metadata",
      "Cloud Service Modification"
    ],
    techniques: ["T1078", "T1098", "T1580", "T1538", "T1526", "T1562", "T1537", "T1530", "T1610"]
  },
  {
    id: "DS0030",
    name: "Instance",
    description: "Information about virtual machine instances in cloud environments, including instance creation, modification, start, stop, and deletion events. Instance monitoring reveals unauthorized compute resource usage and infrastructure manipulation.",
    components: [
      "Instance Creation",
      "Instance Modification",
      "Instance Start",
      "Instance Stop",
      "Instance Deletion",
      "Instance Enumeration",
      "Instance Metadata"
    ],
    techniques: ["T1578", "T1580", "T1610", "T1537", "T1106"]
  },
  {
    id: "DS0020",
    name: "Snapshot",
    description: "Information about storage snapshots in cloud environments, including creation, modification, and sharing events. Adversaries may create or modify snapshots to exfiltrate data or access sensitive information from disk images.",
    components: [
      "Snapshot Creation",
      "Snapshot Modification",
      "Snapshot Deletion",
      "Snapshot Enumeration",
      "Snapshot Metadata"
    ],
    techniques: ["T1578", "T1537", "T1580"]
  },
  {
    id: "DS0034",
    name: "Volume",
    description: "Information about storage volumes in cloud environments, including creation, attachment, detachment, and modification events. Volume monitoring detects unauthorized data access through volume cloning or cross-account sharing.",
    components: [
      "Volume Creation",
      "Volume Modification",
      "Volume Deletion",
      "Volume Enumeration",
      "Volume Metadata"
    ],
    techniques: ["T1578", "T1537", "T1580"]
  },
  {
    id: "DS0018",
    name: "Firewall",
    description: "Information about firewall configuration and traffic filtering events, including rule modifications, blocked connections, and allowed traffic. Firewall data helps detect adversaries manipulating network controls to enable their operations.",
    components: [
      "Firewall Disable",
      "Firewall Enumeration",
      "Firewall Metadata",
      "Firewall Rule Modification"
    ],
    techniques: ["T1562", "T1016", "T1049", "T1048", "T1572", "T1090"]
  },
  {
    id: "DS0016",
    name: "Drive",
    description: "Information about logical and physical drive access, including drive mounting, removable media insertion, and disk-level operations. Drive monitoring detects data staging to removable media and destructive disk operations.",
    components: [
      "Drive Access",
      "Drive Creation",
      "Drive Modification"
    ],
    techniques: ["T1091", "T1025", "T1052", "T1561", "T1092", "T1200"]
  },
  {
    id: "DS0006",
    name: "Web Credential",
    description: "Information about web-based authentication credentials, including browser cookies, session tokens, and web application credentials. Monitoring web credentials helps detect credential theft through session hijacking and cookie stealing.",
    components: [
      "Web Credential Creation",
      "Web Credential Usage"
    ],
    techniques: ["T1539", "T1550", "T1606", "T1528", "T1185"]
  },
  {
    id: "DS0010",
    name: "Cloud Storage",
    description: "Information about cloud storage service activity, including object creation, modification, deletion, and access events in services like S3, Azure Blob Storage, and GCS. Monitors for unauthorized data access and exfiltration via cloud storage.",
    components: [
      "Cloud Storage Access",
      "Cloud Storage Creation",
      "Cloud Storage Deletion",
      "Cloud Storage Enumeration",
      "Cloud Storage Metadata",
      "Cloud Storage Modification"
    ],
    techniques: ["T1530", "T1537", "T1567", "T1074"]
  },
  {
    id: "DS0031",
    name: "Cluster",
    description: "Information about container orchestration cluster activity, including Kubernetes or similar platform events for cluster-level operations. Cluster monitoring detects unauthorized access to orchestration APIs and manipulation of cluster resources.",
    components: [
      "Cluster Metadata"
    ],
    techniques: ["T1610", "T1613", "T1609"]
  },
  {
    id: "DS0014",
    name: "Pod",
    description: "Information about container pod lifecycle events in orchestration platforms, including pod creation, modification, and deletion. Pod monitoring detects adversaries deploying malicious containers or escaping pod sandboxes.",
    components: [
      "Pod Creation",
      "Pod Modification",
      "Pod Enumeration",
      "Pod Metadata"
    ],
    techniques: ["T1610", "T1613", "T1611", "T1053"]
  },
  {
    id: "DS0032",
    name: "Container",
    description: "Information about individual container lifecycle and runtime events, including container creation, start, stop, and execution activity. Container monitoring detects escape attempts and execution of unauthorized payloads within containerized environments.",
    components: [
      "Container Creation",
      "Container Start",
      "Container Enumeration",
      "Container Metadata"
    ],
    techniques: ["T1610", "T1613", "T1611", "T1612"]
  },
  {
    id: "DS0013",
    name: "Sensor Health",
    description: "Information about the operational status and health of security sensors and monitoring tools. Adversaries may attempt to disable or degrade sensor capabilities to avoid detection, making sensor health monitoring a critical meta-detection mechanism.",
    components: [
      "Host Status"
    ],
    techniques: ["T1562", "T1070", "T1489"]
  },
  {
    id: "DS0033",
    name: "Network Share",
    description: "Information about shared network resources, including SMB shares, NFS exports, and similar network file sharing mechanisms. Network share monitoring detects adversaries accessing sensitive data or using shares for lateral movement.",
    components: [
      "Network Share Access"
    ],
    techniques: ["T1021", "T1080", "T1039", "T1135", "T1570"]
  },
  {
    id: "DS0027",
    name: "Driver",
    description: "Information about kernel-mode and user-mode driver loading events on a system. Driver monitoring is essential for detecting rootkits and adversaries loading malicious drivers to gain kernel-level access and bypass security controls.",
    components: [
      "Driver Load",
      "Driver Metadata"
    ],
    techniques: ["T1014", "T1068", "T1543", "T1547", "T1562"]
  },
  {
    id: "DS0012",
    name: "Script",
    description: "Information about script execution events, including PowerShell, VBScript, JavaScript, and Python script activity. Script monitoring captures the content and context of interpreted language execution commonly used by adversaries for automation.",
    components: [
      "Script Execution"
    ],
    techniques: ["T1059", "T1204", "T1027", "T1140", "T1220"]
  },
  {
    id: "DS0011",
    name: "Module",
    description: "Information about dynamic library and module loading events, including DLL loads on Windows, shared object loads on Linux, and dylib loads on macOS. Module monitoring detects DLL side-loading, injection, and other library-based attacks.",
    components: [
      "Module Load"
    ],
    techniques: ["T1574", "T1055", "T1129", "T1553"]
  },
  {
    id: "DS0001",
    name: "Firmware",
    description: "Information about system firmware including BIOS, UEFI, and device firmware. Firmware monitoring detects unauthorized modifications that could provide adversaries with persistent access below the operating system level that survives reimaging.",
    components: [
      "Firmware Modification"
    ],
    techniques: ["T1542", "T1495", "T1601"]
  },
  {
    id: "DS0007",
    name: "Image",
    description: "Information about virtual machine images and container images used in cloud and containerized environments. Image monitoring detects adversaries injecting malicious code into golden images or deploying unauthorized machine images.",
    components: [
      "Image Creation",
      "Image Modification",
      "Image Deletion",
      "Image Metadata"
    ],
    techniques: ["T1578", "T1525", "T1610", "T1204"]
  },
  {
    id: "DS0008",
    name: "Kernel",
    description: "Information about kernel-level operations and modifications, including system call activity, kernel module loading, and kernel memory access. Kernel monitoring detects rootkits and adversaries operating at the highest privilege level of the OS.",
    components: [
      "Kernel Module Load"
    ],
    techniques: ["T1014", "T1547", "T1068", "T1215"]
  },
  {
    id: "DS0004",
    name: "Malware Repository",
    description: "Information from malware analysis repositories and sandboxes, including file hashes, behavioral signatures, and threat intelligence indicators. This data source supports proactive threat hunting and attribution of adversary tooling.",
    components: [
      "Malware Content",
      "Malware Metadata"
    ],
    techniques: ["T1587", "T1588", "T1608", "T1583"]
  },
  {
    id: "DS0003",
    name: "Scheduled Job",
    description: "Information about scheduled tasks, cron jobs, and other time-based execution mechanisms. Monitoring scheduled jobs detects adversaries establishing persistence through scheduled execution of malicious payloads at defined intervals.",
    components: [
      "Scheduled Job Creation",
      "Scheduled Job Modification",
      "Scheduled Job Metadata"
    ],
    techniques: ["T1053", "T1546"]
  },
  {
    id: "DS0021",
    name: "Persona",
    description: "Information about online personas and social media profiles used by adversaries for social engineering. Persona data supports detection of adversary reconnaissance and influence operations targeting organizational personnel.",
    components: [
      "Social Media"
    ],
    techniques: ["T1585", "T1586", "T1593", "T1589", "T1598"]
  },
  {
    id: "DS0035",
    name: "Internet Scan",
    description: "Information from active and passive internet scanning, including port scans, service fingerprinting, and vulnerability scanning directed at organizational assets. Internet scan data reveals adversary reconnaissance and infrastructure mapping activity.",
    components: [
      "Response Content",
      "Response Metadata"
    ],
    techniques: ["T1595", "T1592", "T1590", "T1591"]
  },
  {
    id: "DS0036",
    name: "Group",
    description: "Information about security groups and group membership changes in on-premises and cloud environments. Group monitoring detects adversaries adding accounts to privileged groups to escalate privileges or maintain persistent access.",
    components: [
      "Group Enumeration",
      "Group Metadata",
      "Group Modification"
    ],
    techniques: ["T1069", "T1098", "T1136", "T1484"]
  },
  {
    id: "DS0037",
    name: "Certificate",
    description: "Information about digital certificates, including certificate creation, modification, and usage events. Certificate monitoring detects adversaries creating unauthorized certificates for code signing, HTTPS interception, or authentication bypass.",
    components: [
      "Certificate Registration"
    ],
    techniques: ["T1587", "T1588", "T1553", "T1606"]
  },
  {
    id: "DS0038",
    name: "Domain Name",
    description: "Information about domain name registrations, DNS resolution patterns, and domain metadata. Domain name monitoring detects adversaries establishing infrastructure through new domain registrations, DNS hijacking, and typosquatting campaigns.",
    components: [
      "Active DNS",
      "Passive DNS",
      "Domain Registration"
    ],
    techniques: ["T1583", "T1584", "T1568", "T1071", "T1102"]
  },
  {
    id: "DS0023",
    name: "Named Pipe",
    description: "Information about named pipe creation and access events on Windows systems. Named pipes are inter-process communication mechanisms frequently used by adversaries for local privilege escalation, lateral movement via SMB, and covert data channels.",
    components: [
      "Named Pipe Metadata"
    ],
    techniques: ["T1055", "T1570", "T1021", "T1559"]
  }
];

// =============================================================================
// MITRE ATT&CK MITIGATIONS
// =============================================================================

const MITRE_MITIGATIONS = [
  {
    id: "M1036",
    name: "Account Use Policies",
    description: "Configure features related to account use like login attempt lockouts, specific login times, and other policies that enforce secure account usage. Account use policies reduce the effectiveness of brute force attacks and limit the window of opportunity for compromised credential abuse. Implement lockout thresholds, session timeouts, and restrictions on concurrent sessions to limit adversary access.",
    techniques: ["T1078", "T1110", "T1021", "T1563"]
  },
  {
    id: "M1015",
    name: "Active Directory Configuration",
    description: "Configure Active Directory to prevent abuse of features that adversaries may leverage for privilege escalation and persistence. This includes securing Group Policy Objects, limiting delegation rights, protecting the AdminSDHolder container, and enforcing proper LDAP signing and channel binding. Properly hardened AD configurations significantly reduce the attack surface for domain-level compromises.",
    techniques: ["T1484", "T1558", "T1207", "T1003", "T1098", "T1069"]
  },
  {
    id: "M1049",
    name: "Antivirus/Antimalware",
    description: "Use signatures or heuristics to detect malicious software. Deploy endpoint protection platforms with real-time scanning, behavioral analysis, and cloud-based threat intelligence integration. Keep signature databases current and configure scan schedules for both on-access and periodic full-system scans to maximize detection coverage against known and emerging threats.",
    techniques: ["T1059", "T1204", "T1027", "T1055", "T1105", "T1566", "T1203", "T1547"]
  },
  {
    id: "M1048",
    name: "Application Isolation and Sandboxing",
    description: "Restrict execution of code to a virtual environment on or in transit to an endpoint system. Application sandboxing uses hardware or software-based isolation to contain potentially malicious code within a controlled environment, preventing it from accessing critical system resources. Technologies include browser sandboxes, application containers, and virtualization-based isolation for high-risk applications.",
    techniques: ["T1203", "T1559", "T1189", "T1566", "T1204", "T1218", "T1137"]
  },
  {
    id: "M1047",
    name: "Audit",
    description: "Perform audits or scans of systems, permissions, insecure software, insecure configurations, and other activities to identify potential weaknesses. Regular auditing of system configurations, file permissions, registry settings, and account privileges enables organizations to identify and remediate security gaps before adversaries can exploit them. Automated audit tools should be supplemented with periodic manual reviews of critical systems.",
    techniques: ["T1053", "T1098", "T1136", "T1543", "T1547", "T1546", "T1574", "T1078", "T1552"]
  },
  {
    id: "M1040",
    name: "Behavior Prevention on Endpoint",
    description: "Use capabilities to prevent suspicious behavior patterns on endpoint systems. This includes process behavior monitoring, memory protection, API call monitoring, and machine learning-based detection of anomalous activity. Endpoint behavioral prevention goes beyond signature-based detection to identify novel threats based on their actions rather than their identity, blocking suspicious process trees, injection attempts, and credential access patterns.",
    techniques: ["T1055", "T1059", "T1106", "T1204", "T1547", "T1218", "T1003", "T1546"]
  },
  {
    id: "M1046",
    name: "Boot Integrity",
    description: "Use secure boot and integrity verification mechanisms to ensure the boot process has not been tampered with. Secure Boot validates firmware and bootloader signatures using a chain of trust anchored in hardware, while Measured Boot records component hashes in the TPM for remote attestation. These mechanisms prevent bootkits and firmware-level rootkits from persisting below the operating system.",
    techniques: ["T1542", "T1495", "T1014"]
  },
  {
    id: "M1045",
    name: "Code Signing",
    description: "Enforce binary and application integrity with digital signature verification. Code signing ensures that only software from trusted publishers can execute, preventing adversaries from running unsigned or tampered binaries. Implement certificate pinning for critical applications, maintain a revocation list for compromised certificates, and enforce signature validation on drivers, scripts, and executables across all endpoints.",
    techniques: ["T1204", "T1036", "T1574", "T1553", "T1059", "T1547", "T1543"]
  },
  {
    id: "M1043",
    name: "Credential Access Protection",
    description: "Use capabilities to prevent successful credential access by adversaries, including blocking forms of credential dumping. Enable Windows Credential Guard to protect LSASS secrets using virtualization-based security, configure additional LSA protections, and deploy credential theft prevention tools. These mechanisms make it significantly harder for adversaries to extract password hashes, Kerberos tickets, and other authentication material from memory.",
    techniques: ["T1003", "T1558", "T1552", "T1539", "T1556"]
  },
  {
    id: "M1053",
    name: "Data Loss Prevention",
    description: "Use a data loss prevention strategy to identify and restrict exfiltration of sensitive data. DLP solutions monitor data in motion, at rest, and in use across endpoints, network boundaries, and cloud services. Configure policies to detect and block transmission of classified documents, personally identifiable information, source code, and other sensitive data through unauthorized channels including email, web uploads, and removable media.",
    techniques: ["T1048", "T1041", "T1567", "T1052", "T1537", "T1030"]
  },
  {
    id: "M1042",
    name: "Disable or Remove Feature or Program",
    description: "Remove or deny access to unnecessary and potentially vulnerable software to prevent abuse by adversaries. Uninstall unused applications, disable unnecessary services and features, remove legacy protocols, and limit the availability of scripting interpreters. Reducing the software footprint of systems directly shrinks the attack surface and eliminates potential tools that adversaries could leverage for execution or persistence.",
    techniques: ["T1047", "T1059", "T1218", "T1127", "T1137", "T1221", "T1080", "T1021", "T1219", "T1543"]
  },
  {
    id: "M1055",
    name: "Do Not Mitigate",
    description: "This category is used for techniques that should not be mitigated with preventive controls, either because they represent benign behaviors that cannot be distinguished from malicious activity, or because mitigation would cause more disruption than the technique itself. In these cases, organizations should focus on detection and response capabilities rather than attempting to prevent the behavior entirely.",
    techniques: ["T1014", "T1480", "T1622"]
  },
  {
    id: "M1041",
    name: "Encrypt Sensitive Information",
    description: "Protect sensitive information with strong encryption to minimize the impact of data theft. Implement encryption at rest using AES-256 or equivalent for stored data, enforce TLS 1.2 or higher for data in transit, and use end-to-end encryption for particularly sensitive communications. Proper key management through HSMs or cloud KMS services ensures that encryption cannot be trivially bypassed by adversaries who gain system access.",
    techniques: ["T1557", "T1040", "T1114", "T1005", "T1039", "T1025", "T1552", "T1602"]
  },
  {
    id: "M1039",
    name: "Environment Variable Permissions",
    description: "Prevent modification of environment variables by unauthorized users and applications. Restrict write access to system-level environment variables and PATH entries that could be manipulated by adversaries to hijack execution flow. On Windows, protect registry keys storing environment variables; on Unix systems, restrict write access to profile scripts and environment configuration files.",
    techniques: ["T1574", "T1059"]
  },
  {
    id: "M1038",
    name: "Execution Prevention",
    description: "Block execution of code on a system through application control and allowlisting. Deploy application control solutions such as AppLocker, WDAC, or third-party allowlisting tools to restrict executable code to an approved set of applications. Execution prevention is one of the most effective mitigations against adversary tooling, preventing the running of unapproved binaries, scripts, and installers regardless of their origin.",
    techniques: ["T1059", "T1204", "T1218", "T1127", "T1106", "T1203", "T1047", "T1220", "T1072"]
  },
  {
    id: "M1050",
    name: "Exploit Protection",
    description: "Use exploit protection features to prevent memory corruption-based exploitation techniques. Enable DEP, ASLR, CFG, and other exploit mitigations at both the OS and application level. Deploy EMET or Windows Defender Exploit Guard to enforce additional protections such as export address filtering, heap spray allocation, and stack pivot detection against sophisticated exploitation attempts.",
    techniques: ["T1203", "T1068", "T1189", "T1211", "T1210", "T1190"]
  },
  {
    id: "M1037",
    name: "Filter Network Traffic",
    description: "Use network appliances to filter ingress or egress traffic and perform protocol-level filtering. Configure firewalls, proxies, and intrusion prevention systems to enforce network policies that restrict adversary communication channels. Implement egress filtering to block unauthorized outbound connections, protocol allowlisting to prevent protocol tunneling, and deep packet inspection to identify malicious content within permitted traffic.",
    techniques: ["T1071", "T1572", "T1090", "T1219", "T1048", "T1095", "T1571", "T1102", "T1568"]
  },
  {
    id: "M1035",
    name: "Limit Access to Resource Over Network",
    description: "Prevent access to file shares, remote access to systems, unnecessary services, and other network-accessible resources. Implement network-level access controls to restrict which systems and users can reach sensitive services. Use host-based firewalls, VPN requirements, jump boxes, and zero-trust network access to ensure that only authorized personnel and systems can access critical infrastructure and data resources.",
    techniques: ["T1021", "T1210", "T1080", "T1135", "T1570", "T1133", "T1219", "T1190"]
  },
  {
    id: "M1034",
    name: "Limit Hardware Installation",
    description: "Prevent the installation of unauthorized hardware devices. Block the use of removable media, unauthorized USB devices, and rogue network equipment through Group Policy, device control software, and endpoint management solutions. Hardware installation restrictions prevent adversaries from introducing malicious devices for data exfiltration, keystroke capture, or network bridging.",
    techniques: ["T1200", "T1091", "T1052", "T1025"]
  },
  {
    id: "M1033",
    name: "Limit Software Installation",
    description: "Block users or groups from installing unapproved software. Use application control policies, MDM solutions, and software restriction policies to limit software installation to authorized packages from trusted sources. This prevents adversaries from installing remote access tools, hacking utilities, and other malicious software even after gaining initial access to a system.",
    techniques: ["T1204", "T1072", "T1219", "T1137"]
  },
  {
    id: "M1032",
    name: "Multi-factor Authentication",
    description: "Use two or more pieces of evidence to authenticate to a system rather than relying solely on passwords. Implement MFA using a combination of something you know (password), something you have (hardware token or mobile device), and something you are (biometrics). Phishing-resistant MFA methods such as FIDO2/WebAuthn hardware tokens provide the strongest protection against credential theft, replay attacks, and adversary-in-the-middle attacks.",
    techniques: ["T1078", "T1110", "T1556", "T1021", "T1133", "T1550", "T1528", "T1566", "T1621"]
  },
  {
    id: "M1031",
    name: "Network Intrusion Prevention",
    description: "Use intrusion detection and prevention signatures to identify traffic patterns indicative of malicious network activity. Deploy network IDS/IPS sensors at key network boundaries and internal segments to detect command and control traffic, exploitation attempts, and lateral movement. Regularly update signature databases and tune detection rules to minimize false positives while maintaining coverage against current threat actor TTPs.",
    techniques: ["T1071", "T1572", "T1573", "T1095", "T1571", "T1568", "T1090", "T1132", "T1001", "T1102"]
  },
  {
    id: "M1030",
    name: "Network Segmentation",
    description: "Architect sections of the network to isolate critical systems, functions, or resources. Use physical and logical segmentation through VLANs, subnets, micro-segmentation, and software-defined networking to contain adversary lateral movement. Network segmentation limits blast radius by ensuring that compromise of one segment does not automatically grant access to other segments, particularly between user workstations and sensitive server environments.",
    techniques: ["T1021", "T1210", "T1570", "T1080", "T1557", "T1048", "T1090", "T1133"]
  },
  {
    id: "M1028",
    name: "Operating System Configuration",
    description: "Make configuration changes related to the operating system or a common feature of the OS that result in system hardening against techniques. Apply CIS benchmarks, DISA STIGs, or vendor-specific hardening guides to reduce the attack surface. This includes configuring secure defaults, disabling unnecessary features, enabling security logging, restricting privileged operations, and implementing host-based firewall rules to limit network exposure.",
    techniques: ["T1053", "T1547", "T1546", "T1562", "T1003", "T1556", "T1112", "T1564"]
  },
  {
    id: "M1027",
    name: "Password Policies",
    description: "Set and enforce secure password policies for accounts. Implement minimum length requirements of at least 14 characters, prohibit commonly used passwords, enforce password history to prevent reuse, and consider passphrase-based policies. Integrate password policies with breach databases to reject known-compromised credentials. Password policies reduce the effectiveness of brute force, password spraying, and credential stuffing attacks.",
    techniques: ["T1078", "T1110", "T1021", "T1552"]
  },
  {
    id: "M1026",
    name: "Privileged Account Management",
    description: "Manage the creation, modification, use, and permissions associated with privileged accounts, including SYSTEM and root. Implement just-in-time privilege access, enforce separation of duties, use privileged access workstations for administrative tasks, and maintain an inventory of all privileged accounts. Deploy privileged access management solutions to vault credentials, rotate passwords automatically, and audit all privileged session activity.",
    techniques: ["T1078", "T1098", "T1134", "T1003", "T1136", "T1543", "T1547", "T1021", "T1053"]
  },
  {
    id: "M1025",
    name: "Privileged Process Integrity",
    description: "Protect processes with high privileges that can be used to interact with critical system components through use of protected process light, anti-process injection defenses, or other integrity mechanisms. On Windows, enable Protected Process Light for LSASS and other critical processes. These protections prevent adversaries from injecting code into high-privilege processes to steal credentials or manipulate system security functions.",
    techniques: ["T1055", "T1003", "T1134"]
  },
  {
    id: "M1024",
    name: "Restrict Library Loading",
    description: "Prevent abuse of library loading mechanisms in the operating system and software by configuring appropriate library loading mechanisms and investigations. On Windows, enable Safe DLL Search Mode, configure CWDIllegalInDllSearch, and implement DLL allowlisting. On Linux, restrict LD_PRELOAD and LD_LIBRARY_PATH usage. These controls prevent DLL side-loading, search order hijacking, and library injection attacks.",
    techniques: ["T1574", "T1055", "T1129"]
  },
  {
    id: "M1022",
    name: "Restrict File and Directory Permissions",
    description: "Restrict access by setting directory and file permissions that are not specific to users or privileged accounts. Apply the principle of least privilege to file system permissions, ensuring that users and processes can only access files required for their function. Protect sensitive directories including system folders, configuration files, credential stores, and log directories from unauthorized modification or access.",
    techniques: ["T1574", "T1547", "T1546", "T1543", "T1036", "T1070", "T1552", "T1505", "T1564"]
  },
  {
    id: "M1021",
    name: "Restrict Web-Based Content",
    description: "Restrict use of certain websites, block downloads and attachments, block JavaScript, restrict browser extensions, and implement web content filtering. Deploy web proxy solutions with URL categorization, SSL inspection, and content filtering to prevent users from accessing malicious sites. Block potentially dangerous file types at the web gateway and restrict access to personal cloud storage services that could be used for exfiltration.",
    techniques: ["T1189", "T1566", "T1204", "T1102", "T1567", "T1219", "T1071"]
  },
  {
    id: "M1020",
    name: "SSL/TLS Inspection",
    description: "Break and inspect SSL/TLS sessions to look at encrypted web traffic for adversary activity. Deploy TLS inspection proxies at network boundaries to decrypt, inspect, and re-encrypt traffic, enabling detection of command and control channels, data exfiltration, and malware delivery hidden within encrypted connections. Ensure proper certificate management and configure exemptions for sensitive services like banking and healthcare to balance security with privacy.",
    techniques: ["T1071", "T1573", "T1572", "T1132", "T1001", "T1041", "T1102"]
  },
  {
    id: "M1019",
    name: "Threat Intelligence Program",
    description: "Establish a threat intelligence program to track and analyze adversary behavior, tactics, techniques, and procedures relevant to the organization. Consume and operationalize threat intelligence feeds, participate in information sharing communities (ISACs), and integrate threat data into detection and response workflows. A mature threat intelligence program enables proactive defense by anticipating adversary actions based on observed patterns and indicators.",
    techniques: ["T1583", "T1584", "T1585", "T1586", "T1587", "T1588", "T1608", "T1595"]
  },
  {
    id: "M1018",
    name: "User Account Management",
    description: "Manage the creation, modification, use, and permissions associated with user accounts. Implement least privilege access, disable inactive accounts, enforce account expiration policies, and regularly review account permissions. User account management reduces the attack surface by ensuring that accounts exist only for legitimate users and possess only the minimum privileges required for their roles.",
    techniques: ["T1078", "T1136", "T1098", "T1087", "T1021", "T1053", "T1059"]
  },
  {
    id: "M1017",
    name: "User Training",
    description: "Train users to be aware of access or manipulation attempts by an adversary to reduce the risk of successful spearphishing, social engineering, and other user-targeted techniques. Implement regular security awareness programs covering phishing identification, safe browsing practices, password hygiene, social engineering recognition, and incident reporting procedures. Conduct simulated phishing exercises to measure effectiveness and reinforce training.",
    techniques: ["T1566", "T1204", "T1189", "T1598", "T1534", "T1091", "T1080"]
  },
  {
    id: "M1016",
    name: "Vulnerability Scanning",
    description: "Scan systems for known vulnerabilities to identify potential attack vectors before adversaries can exploit them. Implement continuous vulnerability management with authenticated scanning, risk-based prioritization, and integration with patch management workflows. Regular vulnerability assessments of both internal and external-facing assets help organizations maintain visibility into their exposure and prioritize remediation efforts effectively.",
    techniques: ["T1190", "T1210", "T1211", "T1068", "T1189"]
  },
  {
    id: "M1054",
    name: "Software Configuration",
    description: "Implement configuration changes to software including the operating system that may be used to restrict adversary behavior. This includes hardening application settings, restricting macro execution in Office documents, configuring browser security settings, and tightening default configurations of commonly abused software. Software configuration changes can neutralize many adversary techniques without requiring additional security tools.",
    techniques: ["T1137", "T1221", "T1218", "T1059", "T1566", "T1204", "T1562"]
  },
  {
    id: "M1056",
    name: "Pre-compromise",
    description: "This mitigation addresses techniques that occur before an adversary gains access to the target environment, during the reconnaissance and resource development phases. Pre-compromise mitigations include reducing the public attack surface, limiting information exposure, and monitoring for adversary infrastructure development. These controls aim to make targeting more difficult and increase adversary cost during the planning phase.",
    techniques: ["T1595", "T1592", "T1590", "T1591", "T1589", "T1593", "T1594", "T1583", "T1584", "T1585", "T1586", "T1587", "T1588", "T1608"]
  },
  {
    id: "M1051",
    name: "Update Software",
    description: "Perform regular software updates to mitigate exploitation risk. Implement a comprehensive patch management program with defined SLAs for critical, high, medium, and low severity vulnerabilities. Prioritize patching of internet-facing systems and known-exploited vulnerabilities. Use automated patch deployment tools, maintain a software inventory, and test patches in staging environments before production deployment to balance security with stability.",
    techniques: ["T1190", "T1210", "T1211", "T1068", "T1189", "T1203", "T1212"]
  },
  {
    id: "M1052",
    name: "User Account Control",
    description: "Configure Windows User Account Control to mitigate risk of adversaries obtaining elevated process access. Set UAC to the highest enforcement level, requiring explicit consent for all administrative operations. Configure UAC to prompt on the secure desktop, prevent auto-elevation of built-in administrator accounts, and ensure that standard users cannot bypass UAC prompts. This limits the effectiveness of privilege escalation techniques on Windows systems.",
    techniques: ["T1548", "T1134", "T1055", "T1218", "T1547"]
  },
  {
    id: "M1044",
    name: "Restrict Registry Permissions",
    description: "Restrict the ability to modify certain hives or keys in the Windows Registry. Apply access control lists to protect registry keys used for persistence, privilege escalation, and security configuration. Critical keys to protect include Run/RunOnce entries, service configurations, AppInit_DLLs, Image File Execution Options, and security policy settings. Auditing registry access provides additional visibility into attempted modifications.",
    techniques: ["T1547", "T1546", "T1112", "T1574", "T1562"]
  },
  {
    id: "M1057",
    name: "Data Backup",
    description: "Maintain and test regular data backups to ensure organizational resilience against destructive attacks. Implement the 3-2-1 backup strategy: three copies of data, on two different media types, with one copy stored offsite or in the cloud. Ensure backups are immutable or air-gapped to prevent adversaries from encrypting or destroying them during ransomware attacks. Regularly test restoration procedures to verify backup integrity and recovery time objectives.",
    techniques: ["T1485", "T1486", "T1491", "T1561", "T1490"]
  },
  {
    id: "M1058",
    name: "Network Denial of Service Mitigation",
    description: "Implement defenses against network denial of service attacks to maintain availability of critical services. Deploy DDoS mitigation services, configure rate limiting, implement traffic scrubbing, and use content delivery networks to absorb volumetric attacks. Configure network infrastructure with redundancy and failover capabilities, and establish incident response playbooks specific to denial of service scenarios to enable rapid response and recovery.",
    techniques: ["T1498", "T1499"]
  },
  {
    id: "M1059",
    name: "Disk Wipe Mitigation",
    description: "Implement safeguards to prevent or recover from disk wipe attacks that destroy data and disrupt operations. Deploy endpoint protection with behavioral detection of mass file deletion and MBR modification attempts. Restrict access to low-level disk utilities and administrative tools that can perform destructive operations. Combine with robust backup strategies and system imaging to enable rapid recovery of wiped systems.",
    techniques: ["T1561", "T1485"]
  }
];

const MITRE_TECHNIQUES = [
  {
    id: "T1595",
    name: "Active Scanning",
    tactic: "reconnaissance",
    description: "Adversaries may execute active reconnaissance scans to gather information that can be used during targeting. Active scans involve probing victim infrastructure directly, as opposed to passive collection techniques. This scanning activity may include port scans, vulnerability scans, and banner grabbing to enumerate services running on target hosts.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Monitor for suspicious network traffic that could indicate active scanning activity. Look for high volumes of connection attempts across multiple ports or hosts from a single source IP. Network intrusion detection systems can flag sequential port scanning patterns, SYN scans, and other reconnaissance signatures. Analyze firewall logs for denied connection attempts that follow scanning patterns.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "This technique cannot easily be mitigated with preventive controls since it is based on behaviors performed outside of the scope of enterprise defenses and controls. Efforts should focus on minimizing the amount and sensitivity of data available to external parties." }
    ],
    examples: [
      { group: "APT28", description: "APT28 has performed large-scale scanning of target networks to identify open ports and vulnerable services prior to intrusion operations." },
      { group: "APT41", description: "APT41 has conducted reconnaissance scanning against target organizations to identify externally facing infrastructure and exploitable services." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1595"
    ]
  },
  {
    id: "T1595.001",
    name: "Active Scanning: Scanning IP Blocks",
    tactic: "reconnaissance",
    description: "Adversaries may scan victim IP blocks to gather information that can be used during targeting. Scanning IP blocks involves sending network traffic to a range of IP addresses to identify live hosts and active services. This can reveal the scope of a target's internet-facing infrastructure and identify potential entry points for further exploitation.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Monitor network traffic for patterns indicative of IP block scanning, such as sequential connection attempts across contiguous IP ranges. Firewall and IDS logs may show rapid connection attempts to multiple addresses within a subnet. Rate-based detection rules can flag sources that attempt connections to an abnormal number of destination IPs within a short time window.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "This technique cannot easily be mitigated with preventive controls since it is based on behaviors performed outside of the scope of enterprise defenses. Organizations can reduce their attack surface by limiting externally accessible services and implementing proper network segmentation." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has performed broad IP block scanning to map out victim network infrastructure before launching targeted operations." },
      { group: "Lazarus Group", description: "Lazarus Group has scanned IP ranges belonging to target organizations to identify internet-facing systems for initial compromise." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1595/001"
    ]
  },
  {
    id: "T1595.002",
    name: "Active Scanning: Vulnerability Scanning",
    tactic: "reconnaissance",
    description: "Adversaries may scan victims for vulnerabilities that can be used during targeting. Vulnerability scans typically check configurations of target hosts and software versions against databases of known vulnerabilities. These scans may leverage commercial or open-source scanning tools such as Nessus, OpenVAS, or custom scripts to identify exploitable weaknesses in target infrastructure.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Monitor for network traffic patterns associated with vulnerability scanning tools. These tools often generate distinctive traffic signatures, including specific HTTP request patterns, unusual User-Agent strings, and known exploit check payloads. Web application firewalls and intrusion detection systems can identify and log these scanning attempts based on signature matching and behavioral analysis.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "This technique cannot easily be mitigated with preventive controls since it occurs outside enterprise defenses. Organizations should maintain up-to-date patching and configuration management to reduce the number of discoverable vulnerabilities." }
    ],
    examples: [
      { group: "APT41", description: "APT41 has used vulnerability scanning tools including Acunetix against target web applications to identify SQL injection and other exploitable vulnerabilities." },
      { group: "Sandworm Team", description: "Sandworm Team has conducted vulnerability scans against critical infrastructure targets to identify exploitable services including Exchange and VPN appliances." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1595/002"
    ]
  },
  {
    id: "T1595.003",
    name: "Active Scanning: Wordlist Scanning",
    tactic: "reconnaissance",
    description: "Adversaries may iteratively probe infrastructure using brute-force and crawling techniques to discover hidden content and resources. This involves using wordlists to enumerate valid directories, pages, files, and other resources on web servers. Tools like DirBuster, Gobuster, and ffuf are commonly used to discover content that is not linked publicly but is accessible on web servers.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Monitor web server logs for high volumes of HTTP requests targeting non-existent resources, which is indicative of directory brute-forcing. Look for sequential requests following common wordlist patterns such as admin, backup, config, and other well-known directory names. Web application firewalls can detect and block automated enumeration attempts based on request rate and pattern matching.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "This technique cannot easily be mitigated since it targets publicly accessible infrastructure. Organizations should ensure sensitive directories are properly access-controlled and remove unnecessary files from web servers." }
    ],
    examples: [
      { group: "APT28", description: "APT28 has used directory brute-forcing techniques to discover hidden login portals and administrative interfaces on target web infrastructure." },
      { group: "Turla", description: "Turla has performed wordlist-based scanning against target web servers to enumerate accessible resources and identify potential upload points." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1595/003"
    ]
  },
  {
    id: "T1592",
    name: "Gather Victim Host Information",
    tactic: "reconnaissance",
    description: "Adversaries may gather information about the victim's hosts that can be used during targeting. Information about hosts may include hardware specifications, installed software, security configurations, and identifiers such as hostnames. This information can be gathered through active scanning, phishing, or by leveraging publicly available data to inform follow-on targeting decisions.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Detection of this technique is difficult as it typically occurs outside the visibility of enterprise defenses. Monitor for unusual information-gathering requests from external sources. Analyze web server logs for automated user-agent enumeration or requests targeting system information disclosure endpoints. Information gathered through social engineering is particularly difficult to detect through technical controls.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "This technique cannot easily be mitigated with preventive controls since it is based on behaviors performed outside the scope of enterprise defenses. Organizations should limit the exposure of host information through proper configuration of public-facing services." }
    ],
    examples: [
      { group: "Lazarus Group", description: "Lazarus Group has gathered detailed host information about target systems including operating system versions and installed security products to tailor their malware payloads." },
      { group: "APT32", description: "APT32 has collected host configuration information from targets through watering hole attacks that profiled visiting systems." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1592"
    ]
  },
  {
    id: "T1592.001",
    name: "Gather Victim Host Information: Hardware",
    tactic: "reconnaissance",
    description: "Adversaries may gather information about the victim's host hardware that can be used during targeting. Hardware details may include processor types, memory configurations, peripheral devices, and network interface information. Understanding hardware configurations helps adversaries determine the compatibility of their tools and the feasibility of certain attack vectors against target systems.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Detection is challenging as hardware enumeration often occurs through legitimate channels. Monitor for suspicious queries or scanning that attempts to fingerprint hardware configurations. Web analytics and JavaScript-based profiling embedded in phishing pages can collect hardware details; monitoring for unusual outbound data from browser sessions may provide indicators.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "This technique cannot easily be mitigated with preventive controls. Organizations should limit hardware information exposure in public procurement records, IT job postings, and support forum discussions." }
    ],
    examples: [
      { group: "Equation Group", description: "Equation Group has gathered detailed hardware information about target systems including hard drive models to deploy firmware-level implants targeting specific manufacturers." },
      { group: "APT28", description: "APT28 has profiled target hardware through browser-based reconnaissance to determine system capabilities and tailor payloads accordingly." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1592/001"
    ]
  },
  {
    id: "T1592.002",
    name: "Gather Victim Host Information: Software",
    tactic: "reconnaissance",
    description: "Adversaries may gather information about the victim's host software that can be used during targeting. Software information includes installed applications, versions, patch levels, and security products. This information helps adversaries select appropriate exploits, craft compatible payloads, and identify security products they need to evade during the intrusion.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Monitor for indicators of software enumeration such as targeted probes for specific application version headers, error page analysis, and banner grabbing attempts. Browser fingerprinting scripts delivered via phishing or watering holes can enumerate installed plugins and software; endpoint detection can flag suspicious JavaScript executing enumeration routines.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "This technique cannot easily be mitigated with preventive controls. Organizations should configure web servers and applications to suppress detailed version information in headers and error messages." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has used browser fingerprinting techniques to identify installed software and browser plugins on target systems visiting compromised websites." },
      { group: "Kimsuky", description: "Kimsuky has collected software inventory information from targets using reconnaissance scripts embedded in phishing documents to identify security products." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1592/002"
    ]
  },
  {
    id: "T1592.003",
    name: "Gather Victim Host Information: Firmware",
    tactic: "reconnaissance",
    description: "Adversaries may gather information about the victim's host firmware that can be used during targeting. Firmware information includes BIOS versions, UEFI configurations, and embedded device firmware versions. This intelligence enables adversaries to identify targets vulnerable to firmware-level attacks that can provide persistent, low-level access that survives operating system reinstallation.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Detection of firmware reconnaissance is particularly difficult as it often occurs through indirect channels. Monitor for unusual queries targeting firmware update portals or known firmware vulnerability databases that could indicate adversary research into target firmware configurations. Phishing documents designed to extract system management information may also provide firmware details.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "This technique cannot easily be mitigated with preventive controls. Organizations should limit disclosure of firmware versions in public documentation and ensure firmware updates are applied promptly to reduce the window of exploitability." }
    ],
    examples: [
      { group: "Equation Group", description: "Equation Group gathered firmware information to develop hard drive firmware implants targeting specific manufacturer models, enabling persistent access that survived disk formatting." },
      { group: "APT28", description: "APT28 has targeted UEFI firmware, gathering information about target firmware configurations to develop bootkits like LoJax." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1592/003"
    ]
  },
  {
    id: "T1592.004",
    name: "Gather Victim Host Information: Client Configurations",
    tactic: "reconnaissance",
    description: "Adversaries may gather information about the victim's client configurations that can be used during targeting. Client configuration details include operating system settings, browser configurations, language preferences, and timezone settings. This information helps adversaries customize social engineering lures, determine the locale of targets, and tailor their malware to match victim system configurations.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Monitor for web-based profiling activity that collects client configuration details through JavaScript or similar technologies. Browser fingerprinting techniques can harvest timezone, language, screen resolution, and installed fonts. Network monitoring for exfiltration of configuration data to suspicious domains may reveal this collection activity.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "This technique cannot easily be mitigated with preventive controls. Browser privacy extensions and standardized configurations can reduce the uniqueness of client fingerprints exposed to external sites." }
    ],
    examples: [
      { group: "APT32", description: "APT32 has used profiling scripts on compromised websites to collect browser configuration details including language settings, plugins, and timezone from visiting targets." },
      { group: "Turla", description: "Turla has employed watering hole attacks with embedded scripts that fingerprint visitor client configurations to selectively deliver exploits to targets of interest." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1592/004"
    ]
  },
  {
    id: "T1589",
    name: "Gather Victim Identity Information",
    tactic: "reconnaissance",
    description: "Adversaries may gather information about the victim's identity that can be used during targeting. Identity information may include personal details, credentials, email addresses, and employee roles. This data can be used for social engineering, credential stuffing, targeted phishing campaigns, or to impersonate legitimate users during an intrusion.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Detection of identity information gathering is difficult because much of it occurs through publicly available sources or social engineering. Monitor for signs of credential testing against externally facing services. Track data broker sites and paste sites for organizational credential dumps. Implement monitoring for social engineering attempts targeting employees through phone, email, or social media channels.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "This technique cannot easily be mitigated with preventive controls since it is based on behaviors performed outside the enterprise environment. Organizations should conduct security awareness training and limit the amount of personal information employees share publicly." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has collected identity information about target personnel through social media profiling and open-source intelligence to craft convincing spearphishing campaigns." },
      { group: "Kimsuky", description: "Kimsuky has gathered identity information about journalists, think tank members, and government officials to support their social engineering operations targeting South Korean organizations." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1589"
    ]
  },
  {
    id: "T1589.001",
    name: "Gather Victim Identity Information: Credentials",
    tactic: "reconnaissance",
    description: "Adversaries may gather credentials that can be used during targeting. Credential information may include usernames and passwords, API keys, or authentication tokens obtained from breach dumps, phishing, or underground markets. These credentials can enable initial access through credential stuffing, password spraying, or direct login to target services.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Monitor for credential stuffing and password spraying attacks against externally facing authentication endpoints. Track known breach databases for organizational email domains appearing in new credential dumps. Implement anomaly detection on authentication systems to identify login attempts using credentials from known breaches.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should enforce multi-factor authentication to reduce the impact of compromised credentials. Regular credential rotation and monitoring of breach notification services can help identify exposed credentials before they are exploited." }
    ],
    examples: [
      { group: "APT28", description: "APT28 has harvested credentials from previous data breaches and used them in credential stuffing attacks against government and military email systems." },
      { group: "APT33", description: "APT33 has collected credentials through phishing campaigns and purchased credential dumps from underground forums to support password spraying operations against energy sector targets." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1589/001"
    ]
  },
  {
    id: "T1589.002",
    name: "Gather Victim Identity Information: Email Addresses",
    tactic: "reconnaissance",
    description: "Adversaries may gather email addresses that can be used during targeting. Email addresses can be obtained from corporate websites, social media, data breaches, or through email harvesting tools. These addresses enable targeted phishing campaigns, can reveal organizational email naming conventions, and may be used to enumerate valid user accounts on target systems.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Detection of email harvesting is difficult as it often involves scraping publicly available information. Monitor for automated scraping of organizational web pages, particularly staff directories and contact pages. Track social engineering attempts that try to elicit email address formats from employees. Monitor for email enumeration attacks against mail servers and web applications.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should limit the exposure of email addresses on public websites and consider using contact forms instead of listing direct email addresses. Configure mail servers to prevent email address enumeration through SMTP VRFY and RCPT TO probing." }
    ],
    examples: [
      { group: "Lazarus Group", description: "Lazarus Group has harvested email addresses from LinkedIn and corporate websites to build target lists for spearphishing campaigns against cryptocurrency exchanges." },
      { group: "APT34", description: "APT34 has used tools like theHarvester to collect email addresses from search engine results and public data sources to compile target lists for phishing operations." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1589/002"
    ]
  },
  {
    id: "T1589.003",
    name: "Gather Victim Identity Information: Employee Names",
    tactic: "reconnaissance",
    description: "Adversaries may gather employee names that can be used during targeting. Employee names can be obtained from organizational websites, LinkedIn profiles, conference presentations, and published research. This information aids in crafting convincing social engineering lures, generating potential usernames based on naming conventions, and identifying key personnel for targeted attacks.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Detection is challenging as employee name gathering primarily involves collecting publicly available information. Monitor for suspicious LinkedIn activity such as fake profiles connecting with employees or bulk profile viewing. Track unusual access patterns to employee directory pages on corporate websites that may indicate automated scraping.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should provide guidance to employees about limiting personal information exposure on social media and professional networking sites. Consider limiting the detail of publicly accessible staff directories." }
    ],
    examples: [
      { group: "Kimsuky", description: "Kimsuky has gathered employee names from academic and government organizations through LinkedIn and institutional websites to identify targets for spearphishing campaigns." },
      { group: "APT29", description: "APT29 has collected employee names and roles from target organizations to craft highly targeted spearphishing emails that appeared to come from known colleagues." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1589/003"
    ]
  },
  {
    id: "T1590",
    name: "Gather Victim Network Information",
    tactic: "reconnaissance",
    description: "Adversaries may gather information about the victim's networks that can be used during targeting. Network information includes details about IP address ranges, domain registrations, network topology, DNS records, and security appliances. This intelligence helps adversaries understand the target's network architecture and identify potential attack vectors for initial access.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Monitor for DNS enumeration attempts, WHOIS lookups, and network scanning targeting organizational infrastructure. Track unusual queries to DNS servers that may indicate zone transfer attempts or subdomain brute-forcing. Network-based sensors can detect reconnaissance probes targeting perimeter devices and security appliances.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "This technique cannot easily be mitigated with preventive controls. Organizations should minimize unnecessary information in DNS records, WHOIS registrations, and other publicly accessible network data sources. Implement DNS zone transfer restrictions and use privacy protection for domain registrations." }
    ],
    examples: [
      { group: "APT41", description: "APT41 has performed extensive network reconnaissance including DNS enumeration and network mapping of target organizations prior to intrusion operations." },
      { group: "Sandworm Team", description: "Sandworm Team has gathered detailed network information about Ukrainian critical infrastructure targets including IP ranges and network topology to plan destructive attacks." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1590"
    ]
  },
  {
    id: "T1590.001",
    name: "Gather Victim Network Information: Domain Properties",
    tactic: "reconnaissance",
    description: "Adversaries may gather information about the victim's network domain properties to use during targeting. Domain properties include registration details, expiration dates, registrar information, and name server configurations. This data can reveal organizational ownership, infrastructure hosting patterns, and potential targets for domain hijacking or typosquatting attacks.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Monitor for excessive WHOIS lookups targeting organizational domains from single sources. Track domain monitoring services for alerts about typosquatting or look-alike domain registrations that may indicate adversary preparation for impersonation attacks. Analyze DNS query logs for enumeration patterns targeting domain infrastructure.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should use WHOIS privacy protection services to limit the exposure of domain registration details. Implement domain monitoring to detect adversary registration of similar domains that could be used in phishing campaigns." }
    ],
    examples: [
      { group: "APT28", description: "APT28 has researched domain registration details of target organizations to identify hosting infrastructure and plan domain spoofing for credential harvesting campaigns." },
      { group: "Turla", description: "Turla has gathered domain property information to understand target infrastructure and identify domains suitable for watering hole compromises." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1590/001"
    ]
  },
  {
    id: "T1590.002",
    name: "Gather Victim Network Information: DNS",
    tactic: "reconnaissance",
    description: "Adversaries may gather the victim's DNS information to use during targeting. DNS records can reveal subdomains, mail servers, name servers, service records, and other infrastructure details. Adversaries may query DNS directly, attempt zone transfers, or use passive DNS databases to build a comprehensive map of the target's internet-facing infrastructure without direct interaction.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Monitor DNS servers for zone transfer requests from unauthorized sources. Track DNS query logs for patterns indicative of subdomain enumeration or brute-forcing. Implement rate limiting on DNS queries and alert on abnormal query volumes targeting organizational domains from single sources.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should restrict DNS zone transfers to authorized secondary name servers only. Minimize information leakage through DNS by removing unnecessary records and using split-horizon DNS where appropriate." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has performed DNS reconnaissance to enumerate subdomains and identify internal naming conventions of target organizations to support further intrusion planning." },
      { group: "APT34", description: "APT34 has conducted DNS enumeration against target organizations to map infrastructure and identify services such as VPN endpoints, mail servers, and web applications." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1590/002"
    ]
  },
  {
    id: "T1590.003",
    name: "Gather Victim Network Information: Network Trust Dependencies",
    tactic: "reconnaissance",
    description: "Adversaries may gather information about the victim's network trust dependencies to use during targeting. Trust dependencies include relationships between organizations such as managed service providers, IT contractors, and business partners with network access. Understanding these relationships can help adversaries identify weaker third-party targets that provide a pathway into the primary target's network.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Detection of trust dependency research is extremely difficult as it typically involves analyzing publicly available business relationship information. Monitor for social engineering attempts targeting employees to learn about third-party vendor relationships and network access arrangements. Track for reconnaissance against known partner organizations that could precede a supply chain attack.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should limit public disclosure of third-party network trust relationships and vendor partnerships. Implement network segmentation and zero-trust principles to reduce the impact of compromised trust relationships." }
    ],
    examples: [
      { group: "APT29", description: "APT29 compromised SolarWinds by first understanding the trust relationship between the software vendor and its customers, then leveraging the software supply chain to gain access to thousands of organizations." },
      { group: "Hafnium", description: "Hafnium has researched managed service provider relationships to identify targets that share network trust with high-value organizations." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1590/003"
    ]
  },
  {
    id: "T1590.004",
    name: "Gather Victim Network Information: Network Topology",
    tactic: "reconnaissance",
    description: "Adversaries may gather information about the victim's network topology to use during targeting. Network topology details include the layout of network segments, routing configurations, and the placement of critical infrastructure components. This knowledge helps adversaries plan lateral movement paths and identify high-value targets such as domain controllers and database servers within the network.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Monitor for traceroute and network mapping activities targeting organizational infrastructure. Detect attempts to probe internal network boundaries through VPN or external service endpoints. Watch for social engineering attempts aimed at extracting network architecture details from IT personnel.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should avoid exposing detailed network topology information in public documentation, job postings, or vendor RFPs. Implement network segmentation to limit the value of topology information if obtained by adversaries." }
    ],
    examples: [
      { group: "Sandworm Team", description: "Sandworm Team has gathered detailed network topology information about Ukrainian power grid infrastructure to plan attacks that targeted specific network segments controlling industrial systems." },
      { group: "APT41", description: "APT41 has mapped target network topologies through initial reconnaissance to identify optimal paths for lateral movement during intrusion operations." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1590/004"
    ]
  },
  {
    id: "T1590.005",
    name: "Gather Victim Network Information: IP Addresses",
    tactic: "reconnaissance",
    description: "Adversaries may gather the victim's IP addresses to use during targeting. IP address information can be obtained through DNS lookups, network scanning, CDN enumeration, and analysis of email headers. Knowledge of IP addresses enables adversaries to identify hosting providers, map organizational network ranges, and target specific systems for exploitation or denial of service attacks.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Monitor for unusual volumes of DNS queries resolving organizational domains. Track reverse DNS lookups targeting organizational IP ranges. Analyze email header exposure that may leak internal IP addressing information. Monitor for scanning activity targeting discovered IP addresses after initial DNS reconnaissance.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should use CDN services and reverse proxies to mask origin server IP addresses. Configure email systems to strip internal IP addresses from outgoing message headers. Implement proper DNS configurations to minimize unnecessary IP address exposure." }
    ],
    examples: [
      { group: "APT28", description: "APT28 has gathered IP address information about target organizations through DNS enumeration and email header analysis to identify externally accessible systems." },
      { group: "Lazarus Group", description: "Lazarus Group has collected IP address ranges of financial institutions to identify internet-facing systems for targeted attacks against banking infrastructure." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1590/005"
    ]
  },
  {
    id: "T1590.006",
    name: "Gather Victim Network Information: Network Security Appliances",
    tactic: "reconnaissance",
    description: "Adversaries may gather information about the victim's network security appliances to use during targeting. Security appliance information includes details about firewalls, intrusion detection systems, VPN concentrators, and web application firewalls. Understanding the security stack helps adversaries develop evasion techniques and identify known vulnerabilities in specific security products deployed by the target.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Monitor for probing activity that attempts to fingerprint security appliance types and versions. Detect scanning patterns targeting common management ports for security devices. Track SSL certificate details and HTTP response headers that may reveal security appliance vendor information. Watch for CVE research patterns correlated with the organization's known security stack.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should configure security appliances to suppress vendor and version information in banners and error messages. Remove references to specific security products from public job postings and procurement documents." }
    ],
    examples: [
      { group: "APT41", description: "APT41 has identified and targeted specific VPN appliances including Citrix NetScaler and Pulse Secure VPNs by first gathering information about which security products target organizations deployed." },
      { group: "APT29", description: "APT29 has researched target security appliance configurations to develop techniques for bypassing specific firewall and IDS products during intrusion operations." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1590/006"
    ]
  },
  {
    id: "T1591",
    name: "Gather Victim Org Information",
    tactic: "reconnaissance",
    description: "Adversaries may gather information about the victim's organization that can be used during targeting. Organizational information includes business structure, physical locations, key personnel, business partnerships, and operational tempo. This intelligence helps adversaries craft more effective social engineering campaigns and understand the best timing and approach for attacks.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Detection of organizational information gathering is inherently difficult because much of this data is publicly available through corporate websites, SEC filings, press releases, and social media. Monitor for social engineering attempts targeting employees to extract sensitive organizational details. Track unusual interest in organizational structure from unknown entities.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should review and limit the organizational information shared publicly. Conduct security awareness training to help employees recognize social engineering attempts designed to extract sensitive organizational details." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has extensively researched target organizations to understand their structure, key decision-makers, and business relationships before launching spearphishing campaigns." },
      { group: "Kimsuky", description: "Kimsuky has gathered organizational information about South Korean government agencies and research institutions to support highly targeted social engineering operations." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1591"
    ]
  },
  {
    id: "T1591.001",
    name: "Gather Victim Org Information: Determine Physical Locations",
    tactic: "reconnaissance",
    description: "Adversaries may gather information about the victim's physical locations to use during targeting. Physical location details include office addresses, data center locations, remote office sites, and employee home office regions. This information can support physical access attacks, help determine time zones for social engineering timing, and enable geographic correlation with observed network activity.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Detection of physical location reconnaissance is very difficult as this information is typically publicly available. Monitor for unusual interest in facility locations through corporate website analytics. Track social engineering attempts that probe employees about office locations, work schedules, and physical security measures.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should be cautious about the level of physical location detail shared publicly. Avoid disclosing data center locations and detailed floor plans in public-facing materials." }
    ],
    examples: [
      { group: "APT38", description: "APT38 has researched the physical locations of financial institutions including branch offices and data centers to plan cyber operations targeting SWIFT payment systems." },
      { group: "Lazarus Group", description: "Lazarus Group has gathered physical location information about target organizations to understand timezone-based operational windows for conducting attacks." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1591/001"
    ]
  },
  {
    id: "T1591.002",
    name: "Gather Victim Org Information: Business Relationships",
    tactic: "reconnaissance",
    description: "Adversaries may gather information about the victim's business relationships to use during targeting. Business relationship details include vendors, contractors, supply chain partners, and technology providers. Understanding these relationships enables adversaries to conduct supply chain attacks, craft pretext for social engineering based on known partnerships, or identify weaker organizations that provide network access to the primary target.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Detection is challenging as business relationship information is largely public. Monitor for phishing attempts impersonating known business partners. Track for social engineering attempts that reference specific vendor relationships to establish credibility. Watch for compromises of known partner organizations that could indicate preparation for a supply chain attack.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should be selective about publicly disclosing business partnerships and vendor relationships. Implement verification procedures for communications claiming to originate from business partners." }
    ],
    examples: [
      { group: "APT29", description: "APT29 researched SolarWinds' customer relationships as part of the supply chain compromise, understanding which organizations would be affected by a trojanized software update." },
      { group: "Turla", description: "Turla has identified IT vendors servicing government organizations and targeted these relationships to gain indirect access to their ultimate targets." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1591/002"
    ]
  },
  {
    id: "T1591.003",
    name: "Gather Victim Org Information: Identify Business Tempo",
    tactic: "reconnaissance",
    description: "Adversaries may gather information about the victim's business tempo to use during targeting. Business tempo includes operational schedules, fiscal year timing, merger activities, product launch dates, and holiday schedules. Understanding business tempo helps adversaries time attacks for maximum impact or minimum detection, such as launching attacks during off-hours or major organizational transitions.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Detection of business tempo research is extremely difficult as this information is largely public. Monitor for correlation between organizational events and increased reconnaissance or attack activity. Track for social engineering attempts that probe employees about upcoming organizational changes, staffing levels, or operational schedules.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should maintain heightened security awareness during known high-risk periods such as mergers, acquisitions, major product launches, and holidays when security staffing may be reduced." }
    ],
    examples: [
      { group: "APT38", description: "APT38 has timed attacks against financial institutions to coincide with periods of high transaction volume and reduced staffing to maximize the window for fraudulent SWIFT transfers." },
      { group: "Sandworm Team", description: "Sandworm Team has timed destructive attacks against Ukrainian infrastructure to coincide with holidays and political events for maximum impact." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1591/003"
    ]
  },
  {
    id: "T1591.004",
    name: "Gather Victim Org Information: Identify Roles",
    tactic: "reconnaissance",
    description: "Adversaries may gather information about the victim's organizational roles to use during targeting. Role identification includes mapping key personnel such as executives, IT administrators, security staff, and finance department employees. This information helps adversaries identify high-value targets for spearphishing, determine who has access to critical systems, and craft role-appropriate social engineering lures.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Monitor for social media scraping and LinkedIn enumeration targeting organizational personnel. Track unusual access to staff directory pages on corporate websites. Watch for social engineering attempts that try to identify personnel in specific roles through phone calls or emails to the organization.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should limit detailed role information in public directories and advise employees to be cautious about role-specific details shared on professional networking platforms." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has specifically targeted IT administrators and security personnel identified through LinkedIn and organizational charts to gain access to privileged accounts." },
      { group: "Kimsuky", description: "Kimsuky has identified researchers and policy advisors at think tanks through public bios and used this role information to craft highly targeted spearphishing emails with relevant policy topic lures." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1591/004"
    ]
  },
  {
    id: "T1598",
    name: "Phishing for Information",
    tactic: "reconnaissance",
    description: "Adversaries may send phishing messages to elicit sensitive information that can be used during targeting. Phishing for information differs from phishing as an initial access technique in that the objective is intelligence gathering rather than gaining code execution on the victim system. These campaigns attempt to harvest credentials, system information, or organizational details through deceptive communications.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Monitor email gateways for phishing indicators such as spoofed sender addresses, suspicious attachments, and links to credential harvesting pages. Implement DMARC, DKIM, and SPF email authentication to detect domain spoofing. User reporting of suspicious emails provides valuable detection data. Monitor for newly registered domains that closely resemble organizational domains being used in phishing infrastructure.",
    mitigations: [
      { id: "M1017", name: "User Training", description: "Train users to identify and report phishing attempts. Conduct regular phishing awareness exercises to improve organizational resilience against social engineering campaigns." },
      { id: "M1054", name: "Software Configuration", description: "Configure email clients to display full sender addresses and implement warning banners for external emails. Enable link protection features in email security gateways." }
    ],
    examples: [
      { group: "APT28", description: "APT28 has conducted extensive phishing campaigns to harvest credentials from government and military personnel using fake login pages mimicking legitimate services." },
      { group: "Lazarus Group", description: "Lazarus Group has sent phishing emails to cryptocurrency exchange employees designed to elicit credentials and system information for subsequent intrusion operations." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1598"
    ]
  },
  {
    id: "T1598.001",
    name: "Phishing for Information: Spearphishing Service",
    tactic: "reconnaissance",
    description: "Adversaries may send spearphishing messages via third-party services to elicit sensitive information. Rather than using email, adversaries leverage social media platforms, messaging services, and professional networking sites to contact targets. These services may bypass email security controls and appear more trustworthy to targets who regularly use these platforms for professional communication.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Monitor for reports from employees about suspicious messages received through social media and messaging platforms. Track creation of fake profiles on professional networking sites that impersonate legitimate individuals or organizations. Implement policies requiring verification of contacts through alternative channels before sharing sensitive information via social platforms.",
    mitigations: [
      { id: "M1017", name: "User Training", description: "Train employees to be suspicious of unsolicited messages on social media and professional networking platforms, especially those requesting sensitive information or credentials." },
      { id: "M1056", name: "Pre-compromise", description: "Organizations cannot directly prevent the use of third-party services for spearphishing but can limit the exposure of employee profiles and implement policies governing information sharing through these platforms." }
    ],
    examples: [
      { group: "Lazarus Group", description: "Lazarus Group has used LinkedIn to contact targets with fake job offers, using the spearphishing conversation to gather information about target organizations' technology stacks and security measures." },
      { group: "Kimsuky", description: "Kimsuky has used social media messaging to contact researchers and journalists, gradually building rapport before requesting sensitive information about their organizations." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1598/001"
    ]
  },
  {
    id: "T1598.002",
    name: "Phishing for Information: Spearphishing Attachment",
    tactic: "reconnaissance",
    description: "Adversaries may send spearphishing emails with a malicious attachment to elicit sensitive information. The attachment may contain forms requesting credentials, tracking pixels to capture IP addresses and email client details, or documents that exploit vulnerabilities to collect system information. Unlike initial access phishing, the primary goal is information gathering rather than code execution.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Monitor inbound emails for suspicious attachments, particularly those containing forms, macros, or embedded objects that collect information. Email security solutions can scan attachments for known phishing templates and credential harvesting forms. Sandbox analysis of attachments can detect tracking mechanisms and information-gathering scripts before delivery to end users.",
    mitigations: [
      { id: "M1017", name: "User Training", description: "Train users to avoid opening attachments from untrusted or unexpected sources and to report suspicious emails to security teams for analysis." },
      { id: "M1054", name: "Software Configuration", description: "Configure email gateways to quarantine attachments with potentially malicious content. Implement policies to strip active content from incoming attachments where possible." }
    ],
    examples: [
      { group: "APT28", description: "APT28 has sent spearphishing emails with malicious documents containing tracking pixels to identify when targets opened the email and gather system information from the victim environment." },
      { group: "Turla", description: "Turla has sent documents with embedded forms designed to harvest credentials from targeted diplomatic personnel." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1598/002"
    ]
  },
  {
    id: "T1598.003",
    name: "Phishing for Information: Spearphishing Link",
    tactic: "reconnaissance",
    description: "Adversaries may send spearphishing messages with a malicious link to elicit sensitive information. The link typically directs victims to credential harvesting pages that mimic legitimate login portals for services such as email, VPN, or cloud applications. These pages capture entered credentials and may also fingerprint the victim's browser, operating system, and network information.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Monitor email traffic for messages containing links to known phishing infrastructure or recently registered domains. URL rewriting and scanning services can analyze links at click time to detect credential harvesting pages. Monitor for DNS queries to domains that closely mimic legitimate organizational services. Browser isolation can prevent credential capture even if users click malicious links.",
    mitigations: [
      { id: "M1017", name: "User Training", description: "Train users to verify URLs before entering credentials and to be suspicious of login pages reached through email links. Encourage the use of bookmarks for frequently accessed services." },
      { id: "M1054", name: "Software Configuration", description: "Implement email link scanning and URL rewriting to provide real-time protection against malicious links. Deploy multi-factor authentication to limit the impact of harvested credentials." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has used spearphishing emails with links to credential harvesting pages designed to mimic Microsoft 365 and other cloud service login portals to capture victim credentials." },
      { group: "APT33", description: "APT33 has sent targeted emails with links to fake login pages mimicking corporate VPN portals to harvest credentials from energy sector employees." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1598/003"
    ]
  },
  {
    id: "T1597",
    name: "Search Closed Sources",
    tactic: "reconnaissance",
    description: "Adversaries may search and gather information from closed sources that can be used during targeting. Closed sources include paid threat intelligence feeds, commercial data brokers, dark web forums, and other non-public information repositories. These sources may contain detailed technical information about target organizations including leaked credentials, vulnerability assessments, and internal documents.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Direct detection of adversaries searching closed sources is generally not possible for the target organization. Monitor for the operational use of information that could only have been obtained from closed sources, such as references to non-public vulnerabilities or internal documentation in phishing lures. Track dark web monitoring services for organizational data appearing in underground markets.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should subscribe to dark web monitoring services to detect when their data appears in underground markets. Implement breach response procedures to mitigate the impact of leaked information." }
    ],
    examples: [
      { group: "APT28", description: "APT28 has used information obtained from underground forums and dark web sources to support targeting of government and military organizations." },
      { group: "FIN7", description: "FIN7 has purchased stolen credentials and access from initial access brokers on dark web marketplaces to gain entry into target organizations." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1597"
    ]
  },
  {
    id: "T1597.001",
    name: "Search Closed Sources: Threat Intel Vendors",
    tactic: "reconnaissance",
    description: "Adversaries may search private threat intelligence vendor data to gather information for targeting. Threat intelligence reports often contain detailed analysis of organizational security postures, incident response capabilities, and known vulnerabilities. Adversaries with access to these services, whether through legitimate purchase or compromise, can use this intelligence to understand and evade a target's defensive capabilities.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Detection of this activity is extremely difficult as it occurs on third-party platforms outside organizational visibility. Monitor for indicators that adversaries have knowledge of internal security capabilities that would typically only be described in threat intelligence reports. Track for unauthorized access to threat intelligence platforms used by the organization.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should use access controls and monitoring for their threat intelligence platform accounts. Be aware that threat intelligence shared with vendors may be accessible to adversaries who compromise those vendors." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has reportedly researched threat intelligence publications to understand which of their tools and techniques have been publicly documented, adapting their tradecraft accordingly." },
      { group: "Turla", description: "Turla has monitored threat intelligence reports about their operations to modify techniques and avoid documented detection methods." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1597/001"
    ]
  },
  {
    id: "T1597.002",
    name: "Search Closed Sources: Purchase Technical Data",
    tactic: "reconnaissance",
    description: "Adversaries may purchase technical data from closed sources to gather information for targeting. Technical data available for purchase includes network scan results, vulnerability assessments, breached database contents, and initial access brokerage offerings. This data can provide adversaries with detailed technical intelligence about targets without requiring direct reconnaissance that might trigger detection.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Direct detection is extremely difficult as purchases occur on external platforms. Monitor for the use of credentials or technical details that appear in known breach databases against organizational systems. Track dark web monitoring services for offerings related to organizational data or access. Watch for attacks that demonstrate prior knowledge of internal configurations consistent with purchased intelligence.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should engage dark web monitoring services to detect when their data is being sold. Implement proactive credential rotation following known breaches and monitor for unauthorized access using potentially compromised credentials." }
    ],
    examples: [
      { group: "FIN7", description: "FIN7 has purchased network access and credentials from initial access brokers on underground forums to streamline their intrusion operations against retail and hospitality targets." },
      { group: "Conti", description: "Conti ransomware operators have purchased initial access to target organizations from access brokers operating on dark web marketplaces." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1597/002"
    ]
  },
  {
    id: "T1596",
    name: "Search Open Technical Databases",
    tactic: "reconnaissance",
    description: "Adversaries may search freely available technical databases for information about victims that can be used during targeting. These databases include DNS registries, WHOIS databases, certificate transparency logs, internet scanning repositories like Shodan and Censys, and passive DNS services. Information gathered from these sources helps adversaries map target infrastructure without direct interaction.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Detection of searches against open technical databases is generally not possible for the target organization as these are third-party services. Monitor for follow-up activities that leverage information obtained from these databases, such as targeted scans of specific services discovered through Shodan or exploitation attempts against certificates identified through transparency logs.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should regularly audit their exposure in open technical databases and remove unnecessary entries. Monitor certificate transparency logs for unauthorized certificate issuance and review Shodan and similar databases for exposed services." }
    ],
    examples: [
      { group: "APT41", description: "APT41 has used Shodan and other internet scanning databases to identify vulnerable services and exposed management interfaces belonging to target organizations." },
      { group: "APT28", description: "APT28 has leveraged open technical databases to gather information about target infrastructure including exposed services and SSL certificate details." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1596"
    ]
  },
  {
    id: "T1596.001",
    name: "Search Open Technical Databases: DNS/Passive DNS",
    tactic: "reconnaissance",
    description: "Adversaries may search DNS and passive DNS data for information about victims. DNS records reveal subdomains, mail servers, and service endpoints, while passive DNS databases provide historical DNS resolution data showing how domains have been configured over time. This information helps adversaries map infrastructure, identify hosting changes, and discover previously used but potentially still accessible services.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Direct detection of passive DNS lookups is not possible as these occur on third-party platforms. Monitor for reconnaissance activities that follow passive DNS research, such as targeted scans of previously active subdomains or services discovered through historical DNS data. Track for enumeration of subdomains revealed by passive DNS that are not publicly linked.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should promptly remove DNS records for decommissioned services and monitor passive DNS databases for historical records that may reveal sensitive infrastructure information." }
    ],
    examples: [
      { group: "APT34", description: "APT34 has used passive DNS services to map target DNS infrastructure and identify subdomains hosting web applications and remote access services." },
      { group: "Turla", description: "Turla has queried passive DNS databases to research target infrastructure history and identify services that may have been exposed in the past." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1596/001"
    ]
  },
  {
    id: "T1596.002",
    name: "Search Open Technical Databases: WHOIS",
    tactic: "reconnaissance",
    description: "Adversaries may search public WHOIS data for information about victims. WHOIS records contain domain registration details including registrant names, email addresses, phone numbers, and associated IP address ranges. This information can reveal organizational structure, identify related domains and infrastructure, and provide contact information useful for social engineering campaigns.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Detection of WHOIS lookups against organizational domains is generally not feasible as these are public queries. Monitor for follow-up activities such as phishing emails sent to addresses discovered through WHOIS or scanning of IP ranges identified through registration records.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should use WHOIS privacy protection services offered by domain registrars to mask registration details. Consider using a dedicated registration entity to prevent linkage between domains through shared registrant information." }
    ],
    examples: [
      { group: "APT28", description: "APT28 has used WHOIS data to identify domain ownership, associated IP ranges, and registrant contact information for target organizations." },
      { group: "APT29", description: "APT29 has queried WHOIS databases to map relationships between domains owned by target organizations and identify infrastructure suitable for impersonation." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1596/002"
    ]
  },
  {
    id: "T1596.003",
    name: "Search Open Technical Databases: Digital Certificates",
    tactic: "reconnaissance",
    description: "Adversaries may search certificate transparency logs and other digital certificate databases for information about victims. Certificate transparency logs record all publicly issued SSL/TLS certificates, revealing domain names, subdomains, and organizational details. Analysis of certificate data can expose internal hostnames, development environments, and infrastructure that organizations may not intend to be publicly discoverable.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Detection of certificate database searches is not directly possible. Monitor certificate transparency logs for unexpected certificate issuance that could indicate adversary preparation of look-alike infrastructure. Track for reconnaissance against services discovered through certificate transparency that are not intended to be publicly accessible.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should be aware that certificate transparency logs expose domain information and should use wildcard certificates where appropriate to minimize subdomain disclosure. Monitor CT logs for unauthorized certificate issuance." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has analyzed certificate transparency logs to discover internal subdomains and staging environments belonging to target organizations." },
      { group: "APT41", description: "APT41 has used digital certificate data to identify target web infrastructure and plan attacks against specific services." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1596/003"
    ]
  },
  {
    id: "T1596.004",
    name: "Search Open Technical Databases: CDNs",
    tactic: "reconnaissance",
    description: "Adversaries may search content delivery network data for information about victims. CDN configurations can reveal origin server IP addresses, caching behaviors, and the geographic distribution of content delivery. By analyzing CDN relationships, adversaries may identify the true origin servers behind CDN protections, which can then be targeted directly to bypass CDN-based security controls.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Detection of CDN enumeration is generally not possible as it involves querying third-party services. Monitor for direct access attempts to origin server IP addresses that should only be accessed through CDN infrastructure, which may indicate an adversary has successfully identified origin servers behind CDN protection.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should configure CDN settings to prevent origin IP disclosure and implement origin server access controls that only allow connections from CDN edge nodes. Ensure historical DNS records that predate CDN implementation do not expose origin IPs." }
    ],
    examples: [
      { group: "APT41", description: "APT41 has investigated CDN configurations to identify origin server IP addresses of target web applications hidden behind CDN protection." },
      { group: "Turla", description: "Turla has analyzed CDN relationships of target organizations to understand content delivery architecture and identify potential bypass methods." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1596/004"
    ]
  },
  {
    id: "T1596.005",
    name: "Search Open Technical Databases: Scan Databases",
    tactic: "reconnaissance",
    description: "Adversaries may search internet-wide scan databases for information about victims. Services like Shodan, Censys, and BinaryEdge continuously scan the internet and catalog discovered services, banners, and configurations. Adversaries can query these databases to identify exposed services, vulnerable software versions, and misconfigured systems belonging to target organizations without performing any direct scanning.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Direct detection of scan database queries is not possible. Monitor for exploitation attempts that target services or vulnerabilities that match the organization's exposure as recorded in scan databases. Regular self-auditing through these same databases can help organizations understand what adversaries can discover about their infrastructure.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should regularly search scan databases for their own assets to identify and remediate exposed services. Configure services to minimize information disclosure in banners and implement proper network segmentation to reduce the attack surface visible to internet scanning services." }
    ],
    examples: [
      { group: "APT41", description: "APT41 has used Shodan to identify Citrix ADC, Cisco routers, and other vulnerable network devices belonging to target organizations." },
      { group: "Sandworm Team", description: "Sandworm Team has leveraged internet scan databases to identify exposed industrial control system interfaces and vulnerable VPN appliances at critical infrastructure targets." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1596/005"
    ]
  },
  {
    id: "T1593",
    name: "Search Open Websites/Domains",
    tactic: "reconnaissance",
    description: "Adversaries may search freely available websites and domains for information about victims. This includes searching social media platforms, search engines, code repositories, and other open websites for organizational data. Information gathered can include employee details, technical infrastructure data, code repositories, and other intelligence useful for targeting and initial access planning.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Detection of open website searches is extremely difficult as these activities use legitimate services. Monitor for the operational use of information that could have been gathered from public web searches, such as spearphishing emails referencing publicly available organizational details. Implement alerts for when organizational data appears on paste sites or is referenced in unexpected contexts online.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should regularly audit their web presence and minimize the exposure of sensitive information across public websites, social media, and other online platforms." }
    ],
    examples: [
      { group: "Kimsuky", description: "Kimsuky has extensively searched open websites including academic institutions and think tank sites to identify targets and gather information for social engineering operations." },
      { group: "APT32", description: "APT32 has searched social media and public websites to identify and profile potential targets within Vietnamese dissident communities and foreign corporations." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1593"
    ]
  },
  {
    id: "T1593.001",
    name: "Search Open Websites/Domains: Social Media",
    tactic: "reconnaissance",
    description: "Adversaries may search social media platforms for information about victims. Social media profiles on LinkedIn, Twitter, Facebook, and other platforms can reveal employee roles, technical expertise, organizational relationships, and personal details. This information supports targeted social engineering, helps identify high-value targets, and can reveal technology stacks used within the organization based on employee skill profiles.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Detection is very difficult as social media searching is a normal activity. Monitor for fake profiles or unusual connection requests targeting organizational personnel on professional networks. Track employee reports of suspicious social media interactions. Implement social media monitoring to detect impersonation of the organization or key personnel.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should develop social media policies that guide employees on appropriate information sharing. Conduct awareness training about the risks of oversharing technical and organizational details on social platforms." }
    ],
    examples: [
      { group: "Lazarus Group", description: "Lazarus Group has used LinkedIn to identify and profile potential targets including security researchers, then used the gathered information to craft convincing recruitment-themed social engineering campaigns." },
      { group: "APT34", description: "APT34 has created fake social media personas on LinkedIn and other platforms to build relationships with target personnel and gather organizational intelligence." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1593/001"
    ]
  },
  {
    id: "T1593.002",
    name: "Search Open Websites/Domains: Search Engines",
    tactic: "reconnaissance",
    description: "Adversaries may use search engines to gather information about victims. Advanced search operators (Google dorking) can reveal exposed files, login portals, error messages with sensitive details, and misconfigured web applications. Search engines index vast amounts of content that organizations may not realize is publicly accessible, including internal documents, configuration files, and database backups.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Detection of search engine queries targeting organizational data is generally not possible. Conduct regular Google dorking assessments against your own organization to identify and remediate exposed sensitive content. Monitor web server logs for Googlebot and other search engine crawler access to sensitive directories that should be restricted via robots.txt or access controls.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should conduct regular search engine audits to identify exposed sensitive content. Implement proper robots.txt configurations, configure web servers to prevent directory listing, and ensure sensitive files are protected by authentication rather than relying on obscurity." }
    ],
    examples: [
      { group: "APT28", description: "APT28 has used search engine queries to identify exposed Outlook Web Access portals, VPN login pages, and other externally facing authentication endpoints belonging to target organizations." },
      { group: "APT41", description: "APT41 has leveraged advanced search engine operators to discover exposed configuration files and administrative interfaces on target web infrastructure." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1593/002"
    ]
  },
  {
    id: "T1593.003",
    name: "Search Open Websites/Domains: Code Repositories",
    tactic: "reconnaissance",
    description: "Adversaries may search public code repositories for information about victims. Platforms like GitHub, GitLab, and Bitbucket may contain organizational source code, configuration files, API keys, internal documentation, and infrastructure-as-code templates. Employees may inadvertently commit sensitive data including credentials, internal URLs, and network configurations to public repositories.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Monitor public code repositories for accidental commits of organizational data using automated secret scanning tools. Track for organizational keywords, domain names, and internal IP ranges appearing in public repositories. Implement pre-commit hooks to prevent accidental credential and configuration leakage.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should implement secret scanning on repositories, enforce pre-commit hooks that detect credentials and sensitive data, and regularly audit public repositories for organizational data exposure. Train developers on proper handling of secrets and configuration data." }
    ],
    examples: [
      { group: "APT41", description: "APT41 has searched public GitHub repositories for exposed credentials and API keys belonging to target organizations that could provide initial access." },
      { group: "Lazarus Group", description: "Lazarus Group has examined open-source projects and code repositories used by target organizations to identify vulnerabilities in their software supply chain." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1593/003"
    ]
  },
  {
    id: "T1594",
    name: "Search Victim-Owned Websites",
    tactic: "reconnaissance",
    description: "Adversaries may search websites owned by the victim for information that can be used during targeting. Victim-owned websites such as corporate portals, career pages, product documentation, and investor relations pages contain detailed organizational information. This data can reveal technology stacks, organizational structure, job openings indicating security gaps, and technical details about products and services.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Monitor web server logs for automated scraping patterns targeting organizational websites, particularly career pages, staff directories, and technical documentation. Implement rate limiting and bot detection on public-facing websites. Track for unusual access patterns that suggest systematic information gathering across multiple pages.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should review the information published on their websites and limit technical details that could aid adversary reconnaissance. Implement web application firewalls with bot detection capabilities to identify and limit automated scraping." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has systematically analyzed target organizations' websites to gather information about technology stacks, personnel, and organizational structure for planning intrusion operations." },
      { group: "Kimsuky", description: "Kimsuky has scraped victim organizational websites including university department pages and research center sites to identify targets and gather contextual information for social engineering." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1594"
    ]
  },
  {
    id: "T1583",
    name: "Acquire Infrastructure",
    tactic: "resource-development",
    description: "Adversaries may buy, lease, or rent infrastructure that can be used during targeting. This includes acquiring domains, DNS servers, virtual private servers, physical servers, botnets, and web services. Using acquired infrastructure provides adversaries with staging points for attacks, command and control channels, and platforms for hosting malicious content that are not directly linked to their identity.",
    platforms: ["PRE"],
    dataSources: ["DS0038"],
    detection: "Monitor for newly registered domains that closely resemble organizational domains or brands. Track domain registration patterns associated with known threat actors. Analyze passive DNS data for new infrastructure that resolves to IP ranges associated with previous adversary operations. OSINT monitoring of hosting providers and domain registrars can identify suspicious infrastructure acquisition patterns.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "This technique cannot easily be mitigated with preventive controls as it occurs outside the scope of enterprise defenses. Organizations can monitor for infrastructure that mimics their brand and pursue takedown actions against impersonating domains and services." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has acquired infrastructure including domains and VPS instances across multiple cloud providers to support their operations, frequently rotating infrastructure to evade detection." },
      { group: "APT28", description: "APT28 has registered domains mimicking legitimate government and military services across multiple registrars to host credential harvesting pages and command and control infrastructure." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1583"
    ]
  },
  {
    id: "T1583.001",
    name: "Acquire Infrastructure: Domains",
    tactic: "resource-development",
    description: "Adversaries may acquire domains that can be used during targeting. Domain names are purchased from registrars and may use typosquatting, homoglyph substitution, or keyword-based naming to impersonate legitimate organizations. Acquired domains serve as foundations for phishing campaigns, watering hole attacks, and command and control infrastructure that appears trustworthy to victims and security tools.",
    platforms: ["PRE"],
    dataSources: ["DS0038"],
    detection: "Monitor newly registered domains for patterns resembling organizational domains using automated tools. Track WHOIS registration data for domains registered with details matching known adversary patterns. Monitor certificate transparency logs for SSL certificates issued to suspicious domains that mimic legitimate organizational services.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should implement brand monitoring services to detect look-alike domain registrations. Pre-register common typosquatting variants of organizational domains and implement DMARC policies to prevent domain spoofing in email." }
    ],
    examples: [
      { group: "APT28", description: "APT28 has registered domains mimicking legitimate organizations including accounts-google.com and login-microsoftonline.com to host credential phishing pages." },
      { group: "APT29", description: "APT29 has acquired domains that closely resembled legitimate cloud service providers and government portals for use in phishing and command and control operations." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1583/001"
    ]
  },
  {
    id: "T1583.002",
    name: "Acquire Infrastructure: DNS Server",
    tactic: "resource-development",
    description: "Adversaries may set up their own DNS servers that can be used during targeting. Dedicated DNS servers provide adversaries with full control over DNS resolution, enabling techniques like DNS-based command and control, data exfiltration through DNS queries, and dynamic traffic redirection. Custom DNS servers can also support fast-flux operations that rapidly change IP resolutions to evade blocking.",
    platforms: ["PRE"],
    dataSources: ["DS0038"],
    detection: "Monitor for organizational DNS queries being directed to suspicious or newly observed DNS servers. Track for DNS traffic patterns consistent with tunneling or command and control communications. Analyze DNS server configurations in domain registrations for known adversary infrastructure patterns.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "This technique cannot easily be mitigated with preventive controls. Organizations should implement DNS monitoring to detect queries to malicious nameservers and block known-bad DNS servers at the network perimeter." }
    ],
    examples: [
      { group: "APT34", description: "APT34 has configured custom DNS servers to support their DNS tunneling command and control communications used in operations against Middle Eastern government and financial targets." },
      { group: "Turla", description: "Turla has established DNS servers to support sophisticated DNS-based command and control channels that blend with legitimate DNS traffic." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1583/002"
    ]
  },
  {
    id: "T1583.003",
    name: "Acquire Infrastructure: Virtual Private Server",
    tactic: "resource-development",
    description: "Adversaries may rent virtual private servers that can be used during targeting. VPS providers offer easily provisioned and disposable infrastructure that can be quickly deployed across multiple geographic regions. Adversaries select VPS providers based on factors including payment anonymity, jurisdictional protections, and resistance to law enforcement takedown requests to maintain operational security.",
    platforms: ["PRE"],
    dataSources: ["DS0038"],
    detection: "Monitor for command and control traffic directed to VPS providers commonly associated with adversary operations. Track newly provisioned VPS instances communicating with organizational infrastructure. Correlate VPS IP ranges with threat intelligence feeds that catalog known adversary infrastructure.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "This technique cannot easily be mitigated with preventive controls. Organizations can maintain threat intelligence on VPS providers frequently used by adversaries and implement detection for communications with suspicious VPS infrastructure." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has used VPS providers across multiple countries including the United States and Europe to host command and control infrastructure, frequently rotating servers to evade detection." },
      { group: "Lazarus Group", description: "Lazarus Group has rented VPS instances from providers that accept cryptocurrency payments to host command and control infrastructure for financial theft operations." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1583/003"
    ]
  },
  {
    id: "T1583.004",
    name: "Acquire Infrastructure: Server",
    tactic: "resource-development",
    description: "Adversaries may buy or lease physical servers that can be used during targeting. Dedicated physical servers provide adversaries with full hardware control, higher performance, and greater operational security compared to shared hosting. These servers can be provisioned in colocation facilities or through dedicated hosting providers to support resource-intensive operations including large-scale scanning, exploit hosting, and data staging.",
    platforms: ["PRE"],
    dataSources: ["DS0038"],
    detection: "Detection of physical server acquisition is difficult as it occurs through legitimate commercial transactions. Monitor for command and control traffic directed to dedicated hosting providers. Track threat intelligence for known adversary server procurement patterns and hosting preferences.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "This technique cannot easily be mitigated with preventive controls. Organizations should maintain awareness of hosting providers frequently used by adversaries and implement detection for suspicious traffic to dedicated server infrastructure." }
    ],
    examples: [
      { group: "APT28", description: "APT28 has leased dedicated servers in multiple countries to host phishing infrastructure and command and control services with greater reliability than shared hosting." },
      { group: "Equation Group", description: "Equation Group has maintained dedicated server infrastructure across multiple hosting providers globally to support long-term intelligence collection operations." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1583/004"
    ]
  },
  {
    id: "T1583.005",
    name: "Acquire Infrastructure: Botnet",
    tactic: "resource-development",
    description: "Adversaries may buy, lease, or rent a botnet that can be used during targeting. Botnets are networks of compromised systems that can be directed to perform tasks such as distributed denial of service attacks, credential stuffing, and proxy-based traffic routing. Renting botnet access provides adversaries with distributed infrastructure that obscures their true origin and provides resilience against takedown efforts.",
    platforms: ["PRE"],
    dataSources: ["DS0038"],
    detection: "Monitor for traffic patterns consistent with botnet-driven attacks such as distributed credential stuffing or DDoS traffic. Track underground marketplace offerings for botnet rental services targeting organizational infrastructure. Implement behavioral analysis to detect coordinated activity from distributed compromised hosts.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "This technique cannot easily be mitigated with preventive controls. Organizations should implement DDoS protection services and rate limiting to mitigate the impact of botnet-driven attacks. Monitor for credential stuffing patterns from distributed IP addresses." }
    ],
    examples: [
      { group: "Sandworm Team", description: "Sandworm Team has used botnets including VPNFilter to establish distributed infrastructure for attacks against critical infrastructure targets." },
      { group: "APT28", description: "APT28 has leveraged botnet infrastructure for distributed credential brute-forcing campaigns against government and military email systems." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1583/005"
    ]
  },
  {
    id: "T1583.006",
    name: "Acquire Infrastructure: Web Services",
    tactic: "resource-development",
    description: "Adversaries may register accounts with web services that can be used during targeting. Legitimate web services including cloud storage providers, social media platforms, code repositories, and collaboration tools can be used for command and control, data exfiltration, and payload hosting. Using popular web services helps adversaries blend malicious traffic with legitimate usage and complicates blocking efforts.",
    platforms: ["PRE"],
    dataSources: ["DS0038"],
    detection: "Monitor for suspicious use of legitimate web services including unusual data volumes to cloud storage providers, communications with social media APIs from non-browser processes, and file hosting on platforms not typically used by the organization. Implement SSL inspection where feasible to analyze encrypted traffic to popular web services.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "This technique cannot easily be mitigated without impacting legitimate business operations. Organizations should implement CASB solutions to monitor and control the use of cloud services and detect anomalous patterns that may indicate adversary abuse of web services." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has used legitimate web services including Dropbox and Google Drive for command and control communications and data exfiltration, blending malicious traffic with normal cloud service usage." },
      { group: "APT41", description: "APT41 has leveraged GitHub and other code hosting platforms to host malware payloads and manage command and control infrastructure." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1583/006"
    ]
  },
  {
    id: "T1583.007",
    name: "Acquire Infrastructure: Serverless",
    tactic: "resource-development",
    description: "Adversaries may acquire serverless cloud infrastructure that can be used during targeting. Serverless computing platforms such as AWS Lambda, Azure Functions, and Google Cloud Functions allow adversaries to execute code without managing servers, providing ephemeral and scalable infrastructure. Serverless functions can be used for redirectors, payload staging, and command and control with minimal cost and configuration overhead.",
    platforms: ["PRE"],
    dataSources: ["DS0038"],
    detection: "Monitor for command and control traffic directed to serverless platform endpoints. Track for unusual API Gateway or cloud function URLs communicating with organizational infrastructure. Analyze DNS queries for patterns associated with serverless platform domains used by cloud providers.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "This technique is difficult to mitigate because serverless functions run on major cloud provider infrastructure that cannot be broadly blocked. Organizations should implement network monitoring for suspicious traffic to cloud function endpoints." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has used cloud-based serverless infrastructure to host redirectors and command and control endpoints that benefit from the trust associated with major cloud provider domains." },
      { group: "APT41", description: "APT41 has leveraged serverless cloud functions as part of their infrastructure to provide scalable and disposable command and control endpoints." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1583/007"
    ]
  },
  {
    id: "T1583.008",
    name: "Acquire Infrastructure: Malvertising",
    tactic: "resource-development",
    description: "Adversaries may purchase online advertisements that can be used to distribute malware to specific target audiences. Malvertising leverages legitimate advertising networks to deliver malicious content through ad placements on trusted websites. Adversaries can use targeting capabilities of ad platforms to deliver malicious ads to users based on geographic location, interests, browsing history, or organizational affiliation.",
    platforms: ["PRE"],
    dataSources: ["DS0038"],
    detection: "Monitor for users being redirected from legitimate websites to suspicious download pages through advertising networks. Track endpoint telemetry for malware delivery following web browsing sessions with heavy ad content. Implement ad-blocking at the network level and monitor for suspicious redirects originating from advertising CDNs.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should deploy network-level ad blocking and endpoint browser extensions that filter advertisements. Implement web content filtering to block access to known malvertising infrastructure." }
    ],
    examples: [
      { group: "FIN7", description: "FIN7 has purchased Google Ads to display malicious search advertisements that mimicked legitimate software download pages, redirecting victims to trojanized installer packages." },
      { group: "DEV-0569", description: "DEV-0569 has used malvertising campaigns through Google Ads to distribute trojanized software installers disguised as legitimate applications like TeamViewer and AnyDesk." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1583/008"
    ]
  },
  {
    id: "T1584",
    name: "Compromise Infrastructure",
    tactic: "resource-development",
    description: "Adversaries may compromise third-party infrastructure that can be used during targeting. Rather than acquiring their own infrastructure, adversaries may hack into existing servers, domains, and web services belonging to other parties. Compromised infrastructure provides operational advantages including pre-existing trust relationships, established domain reputation, and attribution challenges for defenders investigating the attack.",
    platforms: ["PRE"],
    dataSources: ["DS0038"],
    detection: "Monitor for organizational infrastructure being used in attacks against third parties, which may indicate compromise. Track for unusual traffic patterns or configuration changes on organizational servers. Implement integrity monitoring on web-facing infrastructure to detect unauthorized modifications. Correlate threat intelligence about compromised infrastructure with organizational asset inventories.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "This technique cannot easily be mitigated as it targets third-party infrastructure. Organizations should ensure their own infrastructure is hardened to prevent it from being compromised and used as attack infrastructure against others." }
    ],
    examples: [
      { group: "Turla", description: "Turla has compromised web servers belonging to other organizations and governments to use as command and control infrastructure, leveraging the legitimate reputation of compromised domains." },
      { group: "APT28", description: "APT28 has compromised legitimate websites to serve as watering holes and to redirect victims to credential harvesting infrastructure." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1584"
    ]
  },
  {
    id: "T1584.001",
    name: "Compromise Infrastructure: Domains",
    tactic: "resource-development",
    description: "Adversaries may hijack domains that can be used during targeting. Domain hijacking involves taking control of a domain through compromising registrar accounts, exploiting expired domain registrations, or leveraging DNS misconfigurations. Hijacked domains benefit from pre-existing trust, domain age, and reputation that can bypass security controls that flag newly registered domains.",
    platforms: ["PRE"],
    dataSources: ["DS0038"],
    detection: "Monitor for unexpected changes to organizational domain DNS records or registrar account settings. Implement domain registry lock features to prevent unauthorized transfers. Track for domains previously associated with legitimate organizations that begin exhibiting malicious behavior patterns.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should enable registrar lock on domains, implement multi-factor authentication on registrar accounts, and monitor for unauthorized DNS record modifications." }
    ],
    examples: [
      { group: "Sea Turtle", description: "Sea Turtle has hijacked DNS records and domain registrations of government organizations and telecommunications companies in the Middle East and North Africa to redirect traffic for credential theft." },
      { group: "APT28", description: "APT28 has taken control of expired domains previously associated with legitimate organizations to leverage their established reputation in phishing campaigns." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1584/001"
    ]
  },
  {
    id: "T1584.002",
    name: "Compromise Infrastructure: DNS Server",
    tactic: "resource-development",
    description: "Adversaries may compromise third-party DNS servers that can be used during targeting. By gaining control of DNS servers, adversaries can redirect traffic, intercept communications, and establish man-in-the-middle positions. Compromised DNS infrastructure can affect many downstream victims and provides the ability to selectively redirect specific targets while allowing normal resolution for others to avoid detection.",
    platforms: ["PRE"],
    dataSources: ["DS0038"],
    detection: "Monitor for unexpected DNS resolution changes for organizational domains. Implement DNSSEC to detect unauthorized DNS record modifications. Track for DNS responses that differ from expected authoritative answers, which may indicate DNS server compromise or manipulation.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should implement DNSSEC validation, monitor DNS resolution consistency, and use DNS monitoring services that detect unauthorized changes to zone files and DNS configurations." }
    ],
    examples: [
      { group: "Sea Turtle", description: "Sea Turtle has compromised DNS registrars and DNS management infrastructure to redirect traffic for espionage operations against government and telecommunications targets." },
      { group: "APT34", description: "APT34 has compromised DNS servers to redirect victim traffic through adversary-controlled infrastructure for credential interception." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1584/002"
    ]
  },
  {
    id: "T1584.003",
    name: "Compromise Infrastructure: Virtual Private Server",
    tactic: "resource-development",
    description: "Adversaries may compromise virtual private servers that can be used during targeting. Rather than renting VPS instances, adversaries may exploit vulnerabilities in existing VPS to gain unauthorized access. Compromised VPS instances provide command and control infrastructure that is attributed to the legitimate owner rather than the adversary, complicating incident response and attribution efforts.",
    platforms: ["PRE"],
    dataSources: ["DS0038"],
    detection: "Monitor organizational VPS instances for indicators of compromise including unauthorized user accounts, unexpected processes, and configuration changes. Implement host-based monitoring on VPS instances. Track threat intelligence for reports of compromised VPS infrastructure being used in attacks.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should harden VPS instances with current patches, strong authentication, and minimal attack surface. Implement monitoring to detect unauthorized access to cloud infrastructure." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has compromised VPS instances belonging to other organizations to use as intermediate hops in their command and control infrastructure, adding attribution complexity." },
      { group: "Turla", description: "Turla has compromised poorly secured VPS instances to establish relay nodes for routing command and control traffic through legitimate-appearing infrastructure." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1584/003"
    ]
  },
  {
    id: "T1584.004",
    name: "Compromise Infrastructure: Server",
    tactic: "resource-development",
    description: "Adversaries may compromise third-party servers that can be used during targeting. Adversaries may exploit vulnerabilities in web servers, application servers, or other internet-facing services to gain access for use as attack infrastructure. Compromised servers provide adversaries with computing resources, network positions, and legitimate reputations that support various phases of attack operations.",
    platforms: ["PRE"],
    dataSources: ["DS0038"],
    detection: "Monitor organizational servers for indicators of compromise including unexpected file modifications, new scheduled tasks, and unauthorized network connections. Implement web application firewalls and file integrity monitoring on public-facing servers. Track threat intelligence for reports of organizational infrastructure being used in attacks.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should maintain current patches on all internet-facing servers, implement web application firewalls, and deploy file integrity monitoring to detect unauthorized modifications that could indicate server compromise." }
    ],
    examples: [
      { group: "Turla", description: "Turla has compromised web servers in over 45 countries to build a distributed network of command and control nodes, using the compromised servers to relay communications and host payloads." },
      { group: "APT28", description: "APT28 has compromised web servers to host phishing pages and serve as redirect points in multi-stage attack infrastructure." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1584/004"
    ]
  },
  {
    id: "T1584.005",
    name: "Compromise Infrastructure: Botnet",
    tactic: "resource-development",
    description: "Adversaries may compromise existing botnets that can be used during targeting. Rather than building their own botnet, adversaries may hijack control of an existing botnet by compromising its command and control infrastructure or exploiting vulnerabilities in the botnet's management systems. This provides instant access to a large network of compromised hosts without the effort of initial infection campaigns.",
    platforms: ["PRE"],
    dataSources: ["DS0038"],
    detection: "Detection of botnet compromise by other adversaries is extremely difficult for organizations not directly involved. Monitor for changes in botnet behavior patterns that may indicate a change in operator. Track threat intelligence for reports of botnet infrastructure being repurposed for different attack campaigns.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "This technique cannot easily be mitigated by target organizations. Focus on detecting botnet-driven activities such as DDoS attacks, credential stuffing, and proxy traffic regardless of who operates the botnet." }
    ],
    examples: [
      { group: "Sandworm Team", description: "Sandworm Team took control of the VPNFilter botnet consisting of over 500,000 compromised network devices to establish distributed attack infrastructure." },
      { group: "Turla", description: "Turla has hijacked command and control infrastructure of other threat groups, including taking over Iranian APT34 infrastructure to conduct their own espionage operations." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1584/005"
    ]
  },
  {
    id: "T1584.006",
    name: "Compromise Infrastructure: Web Services",
    tactic: "resource-development",
    description: "Adversaries may compromise access to third-party web services that can be used during targeting. This includes taking over social media accounts, cloud storage accounts, code repositories, and other web-based platforms. Compromised web service accounts inherit the reputation and trust of the original owner, making malicious content hosted on these services more likely to bypass security controls.",
    platforms: ["PRE"],
    dataSources: ["DS0038"],
    detection: "Monitor for unauthorized access to organizational web service accounts. Track for content modifications on organizational social media accounts or code repositories that could indicate compromise. Implement multi-factor authentication and access alerts on all web service accounts.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should implement multi-factor authentication on all web service accounts. Monitor for unauthorized logins and content changes. Use access logging and alerting to detect compromised web service accounts." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has compromised legitimate web services to use for command and control and data staging, leveraging the trust associated with well-known platforms." },
      { group: "Lazarus Group", description: "Lazarus Group has compromised social media accounts and cloud storage services to distribute malware and host command and control content." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1584/006"
    ]
  },
  {
    id: "T1584.007",
    name: "Compromise Infrastructure: Serverless",
    tactic: "resource-development",
    description: "Adversaries may compromise serverless cloud infrastructure that can be used during targeting. By gaining access to existing cloud function accounts or exploiting misconfigured serverless applications, adversaries can leverage these resources without provisioning their own infrastructure. Compromised serverless functions execute on trusted cloud provider infrastructure and may be difficult to distinguish from legitimate usage.",
    platforms: ["PRE"],
    dataSources: ["DS0038"],
    detection: "Monitor serverless function execution logs for unauthorized invocations or code modifications. Track for changes to function configurations, environment variables, or IAM permissions that may indicate compromise. Implement alerting on unusual function execution patterns including unexpected execution times and invocation sources.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should implement least-privilege IAM policies for serverless functions, enable execution logging, and monitor for unauthorized modifications to function code and configurations." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has leveraged compromised cloud infrastructure including serverless functions as part of their operations targeting cloud-hosted environments." },
      { group: "APT41", description: "APT41 has exploited misconfigured cloud functions to establish persistence and command and control channels within compromised cloud environments." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1584/007"
    ]
  },
  {
    id: "T1587",
    name: "Develop Capabilities",
    tactic: "resource-development",
    description: "Adversaries may build capabilities that can be used during targeting. Rather than purchasing or stealing tools, sophisticated adversaries develop custom malware, exploits, and certificates tailored to their specific operational requirements. Custom capabilities are less likely to be detected by signature-based security tools and can be designed to evade specific defensive measures deployed by target organizations.",
    platforms: ["PRE"],
    dataSources: ["DS0004"],
    detection: "Detection of capability development is extremely difficult as it occurs in adversary-controlled environments. Monitor for the deployment of custom tools and malware not seen in commodity threat landscapes. Track for the use of custom exploits targeting specific software in organizational environments. Analyze malware samples for development artifacts that may provide attribution intelligence.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "This technique cannot be directly mitigated as it occurs outside the enterprise environment. Organizations should focus on detecting the deployment and execution of custom adversary capabilities within their networks." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has developed sophisticated custom malware families including SUNBURST, EnvyScout, and numerous backdoors specifically designed for their espionage operations." },
      { group: "Equation Group", description: "Equation Group developed highly advanced custom capabilities including firmware implants and zero-day exploits tailored for specific hardware and software targets." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1587"
    ]
  },
  {
    id: "T1587.001",
    name: "Develop Capabilities: Malware",
    tactic: "resource-development",
    description: "Adversaries may develop malware that can be used during targeting. Custom malware development allows adversaries to create backdoors, RATs, ransomware, and other tools tailored to specific operational needs. Custom malware can incorporate anti-analysis features, specific communication protocols, and targeted evasion capabilities designed to bypass the defensive measures of intended targets.",
    platforms: ["PRE"],
    dataSources: ["DS0004"],
    detection: "Monitor for execution of unknown malware that does not match known commodity threat signatures. Implement behavioral detection rules that can identify custom malware based on actions rather than signatures. Submit suspicious samples to sandbox environments for dynamic analysis. Track malware development trends associated with known threat actors through threat intelligence services.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "This technique cannot be directly prevented. Organizations should deploy defense-in-depth security that includes behavioral analysis, endpoint detection and response, and sandboxing to detect custom malware that evades signature-based detection." }
    ],
    examples: [
      { group: "APT28", description: "APT28 has developed numerous custom malware families including X-Agent, Zebrocy, and Drovorub specifically designed for their espionage operations across multiple platforms." },
      { group: "Lazarus Group", description: "Lazarus Group has developed custom malware families including HOPLIGHT and ELECTRICFISH for targeting financial institutions and cryptocurrency exchanges." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1587/001"
    ]
  },
  {
    id: "T1587.002",
    name: "Develop Capabilities: Code Signing Certificates",
    tactic: "resource-development",
    description: "Adversaries may create self-signed code signing certificates that can be used during targeting. Code signing certificates allow adversaries to sign their malware, making it appear legitimate and potentially bypassing security controls that require signed code. Self-signed certificates may be installed on compromised systems to establish trust, or adversaries may create certificates that impersonate legitimate software vendors.",
    platforms: ["PRE"],
    dataSources: ["DS0004"],
    detection: "Monitor for execution of code signed by untrusted or self-signed certificates. Implement certificate pinning for critical applications and track the certificate trust store for unauthorized additions. Alert on binaries signed with certificates not in the organizational approved certificate authority list.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should enforce code signing policies that require trusted certificate authorities. Monitor certificate trust stores for unauthorized additions and implement application whitelisting that validates certificate chains." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has created self-signed certificates to sign malware and authenticate command and control communications, lending apparent legitimacy to their tools." },
      { group: "APT41", description: "APT41 has developed code signing certificates to sign their custom malware, enabling it to bypass security controls that check for signed executables." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1587/002"
    ]
  },
  {
    id: "T1587.003",
    name: "Develop Capabilities: Digital Certificates",
    tactic: "resource-development",
    description: "Adversaries may create SSL/TLS certificates that can be used during targeting. These digital certificates can encrypt command and control traffic, authenticate phishing websites, and provide HTTPS connections that appear legitimate to both users and security tools. Adversaries may generate certificates through free certificate authorities or create self-signed certificates for their operational infrastructure.",
    platforms: ["PRE"],
    dataSources: ["DS0004"],
    detection: "Monitor certificate transparency logs for certificates issued to domains resembling organizational infrastructure. Track for self-signed certificates used in connections to organizational systems. Implement TLS inspection to analyze encrypted traffic and detect the use of fraudulent or suspicious certificates.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should monitor certificate transparency logs for unauthorized certificate issuance on organizational domains. Implement certificate pinning for critical services and deploy TLS inspection capabilities to detect suspicious certificates." }
    ],
    examples: [
      { group: "APT28", description: "APT28 has created SSL certificates for phishing domains designed to mimic legitimate Microsoft and Google login pages to capture credentials over encrypted connections." },
      { group: "Turla", description: "Turla has generated digital certificates for their command and control infrastructure to encrypt communications and avoid detection by network monitoring tools." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1587/003"
    ]
  },
  {
    id: "T1587.004",
    name: "Develop Capabilities: Exploits",
    tactic: "resource-development",
    description: "Adversaries may develop exploits that can be used during targeting. Custom exploit development enables adversaries to target specific vulnerabilities in software used by their intended victims. This includes developing zero-day exploits for previously unknown vulnerabilities as well as creating reliable exploit code for known but unpatched vulnerabilities. Exploit development requires significant technical expertise and resources.",
    platforms: ["PRE"],
    dataSources: ["DS0004"],
    detection: "Detection of exploit development is not directly possible as it occurs in adversary environments. Monitor for exploitation attempts using unknown techniques or targeting zero-day vulnerabilities. Implement exploit mitigation technologies such as ASLR, DEP, and control flow integrity. Conduct regular vulnerability assessments to identify and patch known vulnerabilities before they can be exploited.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations cannot prevent exploit development but can reduce their exposure by maintaining aggressive patch management, deploying exploit mitigation technologies, and implementing defense-in-depth strategies." }
    ],
    examples: [
      { group: "Equation Group", description: "Equation Group developed sophisticated zero-day exploits including EternalBlue targeting the Windows SMB protocol, which was later leaked and widely exploited." },
      { group: "APT29", description: "APT29 has developed custom exploits for zero-day vulnerabilities in products including Microsoft Exchange, iOS, and various web browsers to support their espionage operations." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1587/004"
    ]
  },
  {
    id: "T1588",
    name: "Obtain Capabilities",
    tactic: "resource-development",
    description: "Adversaries may buy, steal, or download capabilities that can be used during targeting. Rather than developing capabilities in-house, adversaries may obtain tools, malware, exploits, and certificates from external sources. This includes purchasing from underground markets, downloading open-source offensive tools, stealing from other threat actors, and acquiring through vulnerability brokers.",
    platforms: ["PRE"],
    dataSources: ["DS0004"],
    detection: "Monitor for the use of known publicly available attack tools and malware families within organizational networks. Track threat intelligence for new tools and exploits being traded in underground markets. Implement detection for common offensive tools such as Cobalt Strike, Mimikatz, and Metasploit that are frequently obtained and used by adversaries.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations cannot directly prevent adversaries from obtaining capabilities but should deploy detection for commonly used offensive tools and maintain awareness of the threat landscape through threat intelligence services." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has obtained and used Cobalt Strike for post-exploitation activities alongside their custom malware toolkit." },
      { group: "FIN7", description: "FIN7 has purchased and used various commercial and open-source tools including Cobalt Strike, Carbanak, and legitimate penetration testing tools for their financially motivated operations." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1588"
    ]
  },
  {
    id: "T1588.001",
    name: "Obtain Capabilities: Malware",
    tactic: "resource-development",
    description: "Adversaries may buy, steal, or download malware that can be used during targeting. Obtained malware includes commodity malware available on underground forums, leaked tools from other threat actors, and cracked versions of commercial exploitation frameworks. Using obtained malware reduces development time but may increase the risk of detection due to existing signatures and behavioral indicators.",
    platforms: ["PRE"],
    dataSources: ["DS0004"],
    detection: "Monitor for execution of known malware families and commodity tools. Implement signature-based detection for well-known malware families frequently traded on underground forums. Track threat intelligence for new malware offerings in underground markets and develop detection rules proactively.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should maintain up-to-date antivirus signatures and EDR detection rules for known malware families. Deploy behavioral analysis capabilities to detect variants of obtained malware that may differ from known samples." }
    ],
    examples: [
      { group: "FIN7", description: "FIN7 has obtained and deployed various commodity malware including banking trojans and remote access tools purchased from underground markets to supplement their custom toolset." },
      { group: "Wizard Spider", description: "Wizard Spider has obtained and deployed TrickBot and other commodity malware for initial access and reconnaissance before deploying Ryuk and Conti ransomware." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1588/001"
    ]
  },
  {
    id: "T1588.002",
    name: "Obtain Capabilities: Tool",
    tactic: "resource-development",
    description: "Adversaries may buy, steal, or download tools that can be used during targeting. Tools obtained by adversaries include both offensive security tools and dual-use utilities. Common examples include Cobalt Strike, Metasploit, Mimikatz, BloodHound, and various network scanning utilities. These tools provide tested capabilities that can be deployed quickly without custom development effort.",
    platforms: ["PRE"],
    dataSources: ["DS0004"],
    detection: "Monitor for execution of known offensive tools using both signature and behavioral detection. Implement detection for common tool indicators including named pipes, process injection patterns, and network signatures associated with popular offensive frameworks. Track for obfuscated versions of common tools designed to evade signature detection.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should deploy detection for commonly used offensive tools and maintain current signatures for known variants. Implement application whitelisting to prevent unauthorized tool execution." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has obtained and used Cobalt Strike extensively as their primary post-exploitation framework alongside custom tooling in numerous intrusion operations." },
      { group: "APT41", description: "APT41 has obtained and used a wide range of publicly available tools including Cobalt Strike, Mimikatz, and various web shells for their dual espionage and financial crime operations." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1588/002"
    ]
  },
  {
    id: "T1588.003",
    name: "Obtain Capabilities: Code Signing Certificates",
    tactic: "resource-development",
    description: "Adversaries may buy or steal code signing certificates that can be used during targeting. Unlike self-signed certificates, obtained code signing certificates from legitimate certificate authorities provide a higher degree of trust. Stolen certificates from software vendors are particularly valuable as they allow adversaries to sign malware that appears to originate from trusted software publishers.",
    platforms: ["PRE"],
    dataSources: ["DS0004"],
    detection: "Monitor for code execution signed by certificates associated with compromised or revoked certificate authorities. Track certificate revocation lists for certificates that were compromised. Implement detection for binaries signed with certificates from unexpected publishers or geographic regions.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should implement strict code signing verification policies and monitor for revoked certificates. Hardware security modules should be used to protect private keys of organizational code signing certificates." }
    ],
    examples: [
      { group: "APT41", description: "APT41 has stolen code signing certificates from video game and software companies to sign their malware, enabling it to bypass security controls that verify code signatures." },
      { group: "Stuxnet", description: "The Stuxnet worm used stolen code signing certificates from Realtek Semiconductor and JMicron Technology to sign its drivers, allowing it to appear as legitimate software." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1588/003"
    ]
  },
  {
    id: "T1588.004",
    name: "Obtain Capabilities: Digital Certificates",
    tactic: "resource-development",
    description: "Adversaries may buy or steal SSL/TLS and other digital certificates that can be used during targeting. Obtained digital certificates can be used to encrypt command and control traffic, authenticate to web services, and provide HTTPS for phishing sites. Legitimate certificates from trusted certificate authorities are more effective than self-signed certificates at bypassing security controls and avoiding user warnings.",
    platforms: ["PRE"],
    dataSources: ["DS0004"],
    detection: "Monitor certificate transparency logs for unauthorized certificates issued for organizational domains. Track for SSL/TLS certificates used by adversary infrastructure that were issued by legitimate certificate authorities. Implement certificate monitoring to detect when organizational domains appear in certificates not authorized by IT.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should implement certificate transparency monitoring for their domains. Use CAA DNS records to restrict which certificate authorities can issue certificates for organizational domains." }
    ],
    examples: [
      { group: "APT28", description: "APT28 has obtained SSL certificates from Let's Encrypt and other free certificate authorities for their phishing infrastructure to provide HTTPS connections that appear legitimate." },
      { group: "APT29", description: "APT29 has obtained digital certificates for command and control infrastructure to encrypt communications and appear as legitimate HTTPS traffic." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1588/004"
    ]
  },
  {
    id: "T1588.005",
    name: "Obtain Capabilities: Exploits",
    tactic: "resource-development",
    description: "Adversaries may buy, steal, or download exploits that can be used during targeting. Exploits may be obtained from vulnerability brokers, underground markets, leaked exploit kits, or public proof-of-concept code. Obtaining pre-built exploits significantly reduces the technical barrier to exploitation and allows adversaries to quickly weaponize known vulnerabilities against target systems.",
    platforms: ["PRE"],
    dataSources: ["DS0004"],
    detection: "Monitor for exploitation attempts using known public exploits and recently disclosed vulnerabilities. Track threat intelligence for exploit availability in underground markets and public repositories. Implement virtual patching through WAF and IPS rules when patches are not immediately available.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should maintain aggressive patch management programs to reduce the window of exposure to obtained exploits. Deploy intrusion prevention systems with virtual patching capabilities for rapid mitigation of newly disclosed vulnerabilities." }
    ],
    examples: [
      { group: "APT28", description: "APT28 has obtained and weaponized exploits for vulnerabilities in Flash, Java, and various Microsoft products, deploying them through phishing campaigns and watering hole attacks." },
      { group: "APT41", description: "APT41 has rapidly obtained and deployed exploits for newly disclosed vulnerabilities in Citrix NetScaler, Cisco routers, and Microsoft Exchange to gain initial access to target organizations." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1588/005"
    ]
  },
  {
    id: "T1588.006",
    name: "Obtain Capabilities: Vulnerabilities",
    tactic: "resource-development",
    description: "Adversaries may acquire information about vulnerabilities that can be used during targeting. Vulnerability information may be obtained from vulnerability brokers, dark web markets, public disclosure databases, or through collaboration with other threat actors. Knowledge of unpatched vulnerabilities in target software provides adversaries with a strategic advantage for planning exploitation campaigns.",
    platforms: ["PRE"],
    dataSources: ["DS0004"],
    detection: "Detection of vulnerability information acquisition is not directly possible. Monitor for exploitation attempts targeting recently disclosed or zero-day vulnerabilities. Track threat intelligence for vulnerability information being sold in underground markets that targets software used by the organization.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should participate in vulnerability disclosure programs and maintain awareness of vulnerabilities affecting their technology stack. Implement rapid patch deployment processes and maintain threat intelligence coverage for vulnerability trading activity." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has obtained vulnerability information about zero-day flaws in popular software to develop exploitation capabilities for their espionage operations." },
      { group: "NSO Group", description: "NSO Group has obtained and stockpiled zero-day vulnerability information for mobile operating systems to develop the Pegasus spyware platform." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1588/006"
    ]
  },
  {
    id: "T1585",
    name: "Establish Accounts",
    tactic: "resource-development",
    description: "Adversaries may create and cultivate accounts with services that can be used during targeting. Established accounts on social media, email providers, and cloud services provide adversaries with personas for social engineering, infrastructure for staging attacks, and channels for command and control communications. Account creation may occur well in advance of operations to build credibility and history.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Monitor for social media accounts impersonating organizational personnel or brand. Track for newly created email accounts sending messages to organizational addresses. Implement reporting mechanisms for employees to flag suspicious social media contacts and email communications from unknown accounts.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should monitor social media platforms for fake accounts impersonating their brand or personnel. Implement email authentication standards including SPF, DKIM, and DMARC to detect communications from fraudulent accounts." }
    ],
    examples: [
      { group: "Lazarus Group", description: "Lazarus Group has created elaborate fake LinkedIn personas posing as recruiters to build trust with targets before deploying social engineering attacks against security researchers and cryptocurrency professionals." },
      { group: "Kimsuky", description: "Kimsuky has established email accounts and social media profiles to impersonate journalists and academics for use in prolonged social engineering campaigns against Korean peninsula researchers." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1585"
    ]
  },
  {
    id: "T1585.001",
    name: "Establish Accounts: Social Media Accounts",
    tactic: "resource-development",
    description: "Adversaries may create social media accounts that can be used during targeting. Social media accounts on platforms like LinkedIn, Twitter, and Facebook allow adversaries to build personas, conduct social engineering, and gather intelligence through direct interaction with targets. These accounts may be cultivated over time with posted content and connections to establish credibility before being used in attack operations.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Monitor for social media accounts impersonating organizational personnel or known industry figures. Track for fake profiles attempting to connect with employees. Implement social media monitoring tools that detect brand impersonation and fake account creation on major platforms.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should implement social media monitoring to detect impersonation accounts. Train employees to verify the identity of social media contacts through alternative channels before sharing sensitive information." }
    ],
    examples: [
      { group: "Lazarus Group", description: "Lazarus Group has created numerous fake LinkedIn profiles impersonating recruiters from major technology companies to target security researchers and cryptocurrency developers." },
      { group: "APT34", description: "APT34 has created fake social media personas on LinkedIn and other platforms with detailed backgrounds to build trust with targets before initiating spearphishing through direct messages." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1585/001"
    ]
  },
  {
    id: "T1585.002",
    name: "Establish Accounts: Email Accounts",
    tactic: "resource-development",
    description: "Adversaries may create email accounts that can be used during targeting. Email accounts with free providers like Gmail, Outlook, and ProtonMail provide adversaries with communication channels for phishing, social engineering, and account registration on other services. Adversaries may create accounts with names designed to impersonate legitimate individuals or organizations to increase the effectiveness of their campaigns.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Monitor inbound email for messages from recently created accounts that attempt to impersonate known contacts or organizational brands. Implement email authentication checks to detect spoofing. Track for patterns of emails from new accounts targeting multiple employees within the organization.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should implement email security gateways that flag messages from recently created accounts. Deploy DMARC policies to prevent domain spoofing and train employees to verify unexpected email communications through alternative channels." }
    ],
    examples: [
      { group: "APT28", description: "APT28 has created Gmail and other email accounts impersonating government officials and journalists to send spearphishing emails to targets." },
      { group: "Kimsuky", description: "Kimsuky has established email accounts on various providers to impersonate journalists, academics, and think tank researchers for use in social engineering campaigns." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1585/002"
    ]
  },
  {
    id: "T1585.003",
    name: "Establish Accounts: Cloud Accounts",
    tactic: "resource-development",
    description: "Adversaries may create accounts with cloud providers that can be used during targeting. Cloud accounts on platforms like AWS, Azure, and GCP provide adversaries with infrastructure for hosting payloads, staging data, and establishing command and control channels. Cloud accounts can be created with minimal verification and provide access to a wide range of services that blend with legitimate cloud usage.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Monitor for communications with cloud infrastructure not associated with organizational accounts. Track for new cloud account creation using organizational email addresses or domains. Implement network monitoring for traffic to cloud provider endpoints that are not part of approved organizational cloud usage.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should monitor for unauthorized cloud account creation using organizational identities. Implement cloud access security brokers to control and monitor cloud service usage across the organization." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has created cloud accounts on Azure and AWS to host infrastructure for operations, leveraging the trust associated with major cloud providers." },
      { group: "APT41", description: "APT41 has established cloud accounts for use as command and control infrastructure and to host payloads on legitimate cloud storage services." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1585/003"
    ]
  },
  {
    id: "T1586",
    name: "Compromise Accounts",
    tactic: "resource-development",
    description: "Adversaries may compromise accounts with services that can be used during targeting. Rather than creating new accounts, adversaries may take over existing legitimate accounts through credential theft, brute force, or social engineering. Compromised accounts inherit the reputation, history, and trust relationships of the original owner, making them more effective for social engineering and harder to detect as malicious.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Monitor for unauthorized access to organizational accounts including login anomalies, geographic impossibilities, and credential sharing indicators. Implement multi-factor authentication to prevent unauthorized account access. Track for accounts exhibiting behavior changes that may indicate compromise, such as unusual posting patterns on social media or unexpected email activity.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should enforce multi-factor authentication on all accounts. Implement anomaly detection for account access patterns and conduct regular credential audits to identify compromised accounts." }
    ],
    examples: [
      { group: "APT28", description: "APT28 has compromised email accounts of government officials and journalists to use as launch points for further spearphishing campaigns targeting their contacts." },
      { group: "Turla", description: "Turla has compromised social media accounts and email accounts belonging to government personnel to leverage established trust relationships for espionage operations." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1586"
    ]
  },
  {
    id: "T1586.001",
    name: "Compromise Accounts: Social Media Accounts",
    tactic: "resource-development",
    description: "Adversaries may compromise social media accounts that can be used during targeting. Compromised social media accounts on platforms like LinkedIn, Twitter, and Facebook provide adversaries with established personas that have existing connections and credibility. These accounts can be used to send malicious links, gather information from connected contacts, and spread disinformation that appears to originate from trusted sources.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Monitor for unusual activity on organizational social media accounts including unexpected posts, connection requests, or direct messages. Implement multi-factor authentication on social media accounts and track for account access from unusual locations or devices. Encourage employees to report suspicious messages from known contacts.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should enforce multi-factor authentication on all organizational social media accounts. Implement monitoring for account compromise indicators such as unusual posting times, content changes, and geographic access anomalies." }
    ],
    examples: [
      { group: "APT28", description: "APT28 has compromised social media accounts of journalists and government officials to distribute malicious content and gather intelligence from their contacts." },
      { group: "Lazarus Group", description: "Lazarus Group has compromised legitimate LinkedIn accounts to leverage existing professional connections when targeting individuals in the cryptocurrency and technology sectors." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1586/001"
    ]
  },
  {
    id: "T1586.002",
    name: "Compromise Accounts: Email Accounts",
    tactic: "resource-development",
    description: "Adversaries may compromise email accounts that can be used during targeting. Compromised email accounts provide adversaries with trusted communication channels that bypass many email security controls. Messages sent from compromised accounts benefit from existing sender reputation, established communication history, and may be automatically trusted by recipients who recognize the sender address.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Monitor email accounts for indicators of compromise including login from unusual locations, email forwarding rule changes, and unexpected sent messages. Implement email security policies that detect compromised account behavior such as mass mailing, unusual recipient patterns, and messages containing suspicious attachments or links from typically low-volume senders.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should enforce multi-factor authentication on all email accounts. Implement impossible travel detection and monitor for unauthorized email forwarding rules and delegates that may indicate account compromise." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has compromised email accounts to send phishing emails to targets that trust the compromised sender, including leveraging compromised accounts within the SolarWinds supply chain attack." },
      { group: "Kimsuky", description: "Kimsuky has compromised email accounts of academics and journalists to send spearphishing emails to targets who would trust communications from the compromised individual." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1586/002"
    ]
  },
  {
    id: "T1586.003",
    name: "Compromise Accounts: Cloud Accounts",
    tactic: "resource-development",
    description: "Adversaries may compromise cloud accounts that can be used during targeting. Compromised cloud accounts on platforms like AWS, Azure, or GCP provide adversaries with legitimate infrastructure for hosting malicious content, command and control, and data exfiltration. These compromised accounts leverage existing trust and billing relationships, making malicious activity harder to distinguish from legitimate usage.",
    platforms: ["PRE"],
    dataSources: ["DS0029"],
    detection: "Monitor cloud account access for anomalous login patterns, unusual API calls, and resource provisioning that deviates from baseline behavior. Implement cloud security posture management tools to detect configuration changes indicative of account compromise. Track for unauthorized IAM role modifications and new service activations.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should enforce multi-factor authentication on all cloud accounts. Implement cloud security monitoring to detect unauthorized access and unusual resource utilization that may indicate account compromise." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has compromised cloud accounts to leverage existing infrastructure for command and control and to access data stored in cloud environments." },
      { group: "APT41", description: "APT41 has compromised cloud accounts to gain access to target cloud environments and leverage the compromised infrastructure for further operations." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1586/003"
    ]
  },
  {
    id: "T1608",
    name: "Stage Capabilities",
    tactic: "resource-development",
    description: "Adversaries may upload, install, or otherwise set up capabilities that can be used during targeting. Staging capabilities involves preparing infrastructure with the tools, malware, certificates, and web content needed for attack operations. This includes uploading malware to download servers, installing SSL certificates on phishing sites, and configuring web infrastructure to serve exploits or redirect victims.",
    platforms: ["PRE"],
    dataSources: ["DS0038"],
    detection: "Monitor for newly observed domains hosting suspicious content including login pages mimicking organizational services, exploit kits, and malware download pages. Track certificate transparency logs for new certificates issued to suspicious domains. Implement web reputation services to detect newly established infrastructure hosting malicious content.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "This technique cannot easily be mitigated with preventive controls as staging occurs on adversary-controlled infrastructure. Organizations should implement proactive monitoring for staged capabilities targeting their users and brand." }
    ],
    examples: [
      { group: "APT28", description: "APT28 has staged phishing infrastructure with credential harvesting pages, installing SSL certificates and configuring web servers to closely mimic legitimate Microsoft and Google services." },
      { group: "APT29", description: "APT29 has staged malware, tools, and web content on compromised servers and legitimate cloud services in preparation for intrusion operations." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1608"
    ]
  },
  {
    id: "T1608.001",
    name: "Stage Capabilities: Upload Malware",
    tactic: "resource-development",
    description: "Adversaries may upload malware to third-party or adversary-controlled infrastructure to make it available during targeting. Malware may be uploaded to file hosting services, compromised websites, cloud storage, or dedicated command and control servers. Staging malware on legitimate services helps evade URL-based blocking and benefits from the reputation of trusted hosting platforms.",
    platforms: ["PRE"],
    dataSources: ["DS0038"],
    detection: "Monitor for downloads from unusual file hosting services or recently created cloud storage locations. Implement URL reputation checking to detect downloads from newly staged infrastructure. Track for organizational domains appearing in malware distribution infrastructure through abuse notification services.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should implement web content filtering and URL reputation checking to block access to known malware hosting infrastructure. Monitor for abuse of organizational web infrastructure that may be used to stage malware." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has uploaded malware to legitimate cloud storage services including Dropbox and Google Drive to distribute payloads to targets, leveraging the trusted reputation of these platforms." },
      { group: "Lazarus Group", description: "Lazarus Group has staged malware on compromised websites and cloud hosting platforms for distribution through spearphishing campaigns targeting cryptocurrency organizations." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1608/001"
    ]
  },
  {
    id: "T1608.002",
    name: "Stage Capabilities: Upload Tool",
    tactic: "resource-development",
    description: "Adversaries may upload tools to third-party or adversary-controlled infrastructure to make them available during targeting. Tools may include penetration testing utilities, remote access software, or system administration tools that will be downloaded and executed on compromised systems. Staging tools on accessible infrastructure allows adversaries to quickly deploy additional capabilities during an operation.",
    platforms: ["PRE"],
    dataSources: ["DS0038"],
    detection: "Monitor for downloads of known offensive tools from unusual sources. Implement application whitelisting to prevent execution of unauthorized tools. Track for staging of tools on organizational web infrastructure through file integrity monitoring.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should implement application control policies that prevent execution of unauthorized tools. Monitor for downloads of known offensive utilities from external hosting infrastructure." }
    ],
    examples: [
      { group: "APT41", description: "APT41 has staged penetration testing tools and custom utilities on cloud hosting platforms for download during intrusion operations." },
      { group: "FIN7", description: "FIN7 has uploaded Cobalt Strike and other post-exploitation tools to cloud storage and file sharing services for distribution to compromised endpoints." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1608/002"
    ]
  },
  {
    id: "T1608.003",
    name: "Stage Capabilities: Install Digital Certificate",
    tactic: "resource-development",
    description: "Adversaries may install SSL/TLS certificates on adversary-controlled infrastructure to support targeting operations. Installing digital certificates on web servers enables HTTPS connections that appear legitimate to both users and security tools. Certificates may be installed on phishing sites to display the lock icon, on command and control servers to encrypt traffic, or on redirector infrastructure to maintain encrypted communication chains.",
    platforms: ["PRE"],
    dataSources: ["DS0038"],
    detection: "Monitor certificate transparency logs for certificates issued to domains associated with phishing or adversary infrastructure. Track for newly installed certificates on organizational web servers that were not authorized by IT. Implement network monitoring to detect encrypted communications to suspicious infrastructure using recently issued certificates.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should monitor certificate transparency logs for certificates issued to domains resembling organizational branding. Implement TLS inspection where feasible to analyze encrypted communications." }
    ],
    examples: [
      { group: "APT28", description: "APT28 has installed Let's Encrypt certificates on phishing infrastructure to provide HTTPS connections that display the browser lock icon for credential harvesting pages." },
      { group: "Turla", description: "Turla has installed digital certificates on command and control servers to encrypt communications and evade detection by network monitoring tools." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1608/003"
    ]
  },
  {
    id: "T1608.004",
    name: "Stage Capabilities: Drive-by Target",
    tactic: "resource-development",
    description: "Adversaries may prepare an operational environment to infect systems that browse to a compromised website. This involves staging exploit code, malicious scripts, and browser profiling tools on web infrastructure that will be visited by target users. Drive-by targeting may include selective delivery of exploits based on victim browser fingerprinting to target specific organizations or user profiles while avoiding security researcher systems.",
    platforms: ["PRE"],
    dataSources: ["DS0038"],
    detection: "Monitor web infrastructure for unauthorized modifications that could indicate staging of drive-by exploit content. Implement web application firewalls and file integrity monitoring to detect injected malicious scripts. Track for JavaScript-based browser profiling code and exploit delivery frameworks staged on organizational or frequently visited websites.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should implement web content integrity monitoring on their own web properties. Keep browsers and plugins updated to reduce vulnerability to drive-by exploits. Deploy browser isolation technologies for high-risk browsing activities." }
    ],
    examples: [
      { group: "APT32", description: "APT32 has staged drive-by exploit content on compromised websites frequented by Vietnamese dissident communities, using browser fingerprinting to selectively deliver exploits." },
      { group: "Turla", description: "Turla has staged watering hole attack infrastructure on government and embassy websites, profiling visitors and selectively delivering exploits to targets matching their intelligence collection requirements." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1608/004"
    ]
  },
  {
    id: "T1608.005",
    name: "Stage Capabilities: Link Target",
    tactic: "resource-development",
    description: "Adversaries may put in place resources that are referenced by a link that can be used during targeting. Link targets include web pages for credential harvesting, malware download sites, and exploit delivery infrastructure. Adversaries stage these resources and then distribute links through phishing emails, social media, or other communication channels to drive targets to the prepared infrastructure.",
    platforms: ["PRE"],
    dataSources: ["DS0038"],
    detection: "Monitor for links in inbound communications pointing to newly created or recently modified web infrastructure. Implement URL scanning and reputation checking for links in emails and messages. Track for phishing pages mimicking organizational login portals through brand monitoring services.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should implement link scanning in email gateways and instant messaging platforms. Deploy brand monitoring to detect credential harvesting pages impersonating organizational services." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has staged credential harvesting pages and then distributed links to these pages through spearphishing emails targeting government and diplomatic personnel." },
      { group: "APT33", description: "APT33 has set up fake corporate login portals and distributed links through targeted phishing campaigns against energy sector organizations." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1608/005"
    ]
  },
  {
    id: "T1608.006",
    name: "Stage Capabilities: SEO Poisoning",
    tactic: "resource-development",
    description: "Adversaries may poison mechanisms used by search engines to influence search result rankings for malicious content. SEO poisoning involves creating or compromising web content designed to rank highly in search results for terms likely searched by targets. This can drive victims to malicious download pages, watering hole sites, or credential harvesting infrastructure that appears in legitimate search results.",
    platforms: ["PRE"],
    dataSources: ["DS0038"],
    detection: "Monitor for organizational brand terms and related keywords appearing in search results that link to suspicious or unauthorized websites. Track for SEO spam targeting organizational domains through search engine alerts. Implement web filtering to block access to known SEO poisoning infrastructure identified through threat intelligence.",
    mitigations: [
      { id: "M1056", name: "Pre-compromise", description: "Organizations should monitor search engine results for brand-related terms to detect SEO poisoning targeting their users. Implement web content filtering and educate users about the risks of downloading software from search results rather than official sources." }
    ],
    examples: [
      { group: "FIN7", description: "FIN7 has used SEO poisoning to promote malicious websites disguised as legitimate software download pages, targeting users searching for popular business applications." },
      { group: "Gootkit", description: "Gootkit operators have used SEO poisoning to drive traffic to compromised websites hosting the Gootloader malware, targeting searches for legal documents and business templates." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1608/006"
    ]
  },
  {
    id: "T1189",
    name: "Drive-by Compromise",
    tactic: "initial-access",
    description: "Adversaries may gain access to a system through a user visiting a website over the normal course of browsing. The user's web browser is typically targeted for exploitation, but adversaries may also use compromised websites for non-exploitation behavior such as acquiring application access tokens. Multiple techniques may be used including exploiting browser vulnerabilities, delivering malicious scripts, and leveraging compromised legitimate websites frequented by target users.",
    platforms: ["Windows", "Linux", "macOS", "SaaS"],
    dataSources: ["DS0015", "DS0029"],
    detection: "Monitor network traffic for unusual patterns such as connections to known exploit kit domains or downloads of suspicious content following web browsing. Implement browser-level protections and monitor for exploit attempts targeting browser vulnerabilities. Endpoint detection tools can identify exploitation behavior including unexpected child processes spawned by browser applications and memory corruption indicators.",
    mitigations: [
      { id: "M1048", name: "Application Isolation and Sandboxing", description: "Use browser sandboxing and isolation technologies to limit the impact of browser exploitation. Application containers can prevent exploits from escaping the browser process." },
      { id: "M1050", name: "Exploit Protection", description: "Deploy exploit protection mechanisms such as Windows Defender Exploit Guard or similar endpoint protections that can detect and block common exploitation techniques." },
      { id: "M1051", name: "Update Software", description: "Keep web browsers and all browser plugins updated to the latest versions to remediate known vulnerabilities that could be exploited through drive-by attacks." }
    ],
    examples: [
      { group: "APT32", description: "APT32 has compromised legitimate websites to serve as watering holes, using browser exploits to target visitors from specific organizations and geographic regions." },
      { group: "Turla", description: "Turla has used strategic web compromises on government and embassy websites to deliver exploits to diplomatic and government targets visiting these sites." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1189"
    ]
  },
  {
    id: "T1190",
    name: "Exploit Public-Facing Application",
    tactic: "initial-access",
    description: "Adversaries may attempt to exploit a weakness in an internet-facing host or service to initially access a network. Common targets include web servers, email servers, VPN appliances, firewalls, and other services accessible from the internet. Exploitation may target software bugs, misconfigurations, or known vulnerabilities in applications that have not been patched. This technique often provides adversaries with initial foothold access to the internal network.",
    platforms: ["Windows", "Linux", "macOS", "Containers", "Network"],
    dataSources: ["DS0015", "DS0029"],
    detection: "Monitor public-facing applications for exploitation attempts including unusual HTTP requests, unexpected errors, and anomalous application behavior. Web application firewalls can detect and block known exploit patterns. Analyze application logs for signs of exploitation such as SQL injection, command injection, and path traversal attempts. Monitor for unexpected process creation or network connections from public-facing service accounts.",
    mitigations: [
      { id: "M1048", name: "Application Isolation and Sandboxing", description: "Isolate public-facing applications in segmented network zones with minimal access to internal resources. Use containerization and application sandboxing to limit the impact of successful exploitation." },
      { id: "M1030", name: "Network Segmentation", description: "Segment networks so that compromised public-facing applications cannot directly access sensitive internal resources. Implement micro-segmentation around critical assets." },
      { id: "M1051", name: "Update Software", description: "Apply security patches promptly for all public-facing applications. Implement virtual patching through web application firewalls when immediate patching is not feasible." }
    ],
    examples: [
      { group: "APT41", description: "APT41 has exploited vulnerabilities in Citrix NetScaler, Cisco routers, and Zoho ManageEngine to gain initial access to target organizations." },
      { group: "Hafnium", description: "Hafnium exploited multiple zero-day vulnerabilities in Microsoft Exchange Server (ProxyLogon) to gain initial access to thousands of organizations worldwide." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1190"
    ]
  },
  {
    id: "T1133",
    name: "External Remote Services",
    tactic: "initial-access",
    description: "Adversaries may leverage external-facing remote services to initially access or persist within a network. Remote services such as VPNs, Citrix, RDP, SSH, and other access mechanisms allow users to connect to internal enterprise network resources from external locations. Adversaries may use valid accounts obtained through credential theft, brute force, or purchase to authenticate to these services and gain network access.",
    platforms: ["Windows", "Linux", "macOS", "Containers"],
    dataSources: ["DS0028", "DS0029"],
    detection: "Monitor remote access service logs for anomalous authentication patterns including login attempts from unusual geographic locations, impossible travel scenarios, and access during abnormal hours. Implement multi-factor authentication monitoring to detect bypass attempts. Track for brute force and credential stuffing attacks against remote access endpoints.",
    mitigations: [
      { id: "M1035", name: "Limit Access to Resource Over Network", description: "Limit access to remote services to only necessary users and source IP ranges. Implement network-level access controls and VPN split tunneling policies." },
      { id: "M1032", name: "Multi-factor Authentication", description: "Require multi-factor authentication for all remote access services to prevent unauthorized access using stolen credentials." },
      { id: "M1030", name: "Network Segmentation", description: "Segment networks so that remote access provides access only to necessary resources rather than the entire internal network." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has used compromised VPN credentials to gain initial access to target networks, leveraging stolen credentials obtained through previous phishing campaigns." },
      { group: "APT28", description: "APT28 has used compromised credentials to access external-facing services including Outlook Web Access and VPN gateways for initial access to government networks." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1133"
    ]
  },
  {
    id: "T1200",
    name: "Hardware Additions",
    tactic: "initial-access",
    description: "Adversaries may introduce computer accessories, networking hardware, or other computing devices to gain access to target systems or networks. Hardware additions can include USB devices, network implants, wireless access points, and other physical devices that provide a backdoor into the network. These devices can be placed by insiders, social engineers, or through physical access to target facilities.",
    platforms: ["Windows", "Linux", "macOS"],
    dataSources: ["DS0015", "DS0029"],
    detection: "Monitor for unauthorized hardware devices connecting to the network through 802.1X network access control and DHCP monitoring. Implement USB device control policies that alert on unauthorized device connections. Conduct regular physical security audits of networking equipment and server rooms. Monitor for unexpected wireless access points through wireless intrusion detection systems.",
    mitigations: [
      { id: "M1035", name: "Limit Access to Resource Over Network", description: "Implement 802.1X network access control to prevent unauthorized devices from connecting to the network. Require device authentication before granting network access." },
      { id: "M1034", name: "Limit Hardware Installation", description: "Restrict USB and removable media device installation through group policy and endpoint management. Implement device whitelisting to prevent unauthorized hardware connections." }
    ],
    examples: [
      { group: "DarkVishnya", description: "DarkVishnya threat actors physically planted small computing devices including Bash Bunnies and Raspberry Pis in bank branches to gain direct network access for financially motivated attacks." },
      { group: "APT28", description: "APT28 has reportedly used close-access operations involving hardware devices to compromise air-gapped networks and Wi-Fi networks of target organizations." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1200"
    ]
  },
  {
    id: "T1566",
    name: "Phishing",
    tactic: "initial-access",
    description: "Adversaries may send phishing messages to gain access to victim systems. Phishing is the most common initial access vector, using social engineering to trick users into executing malicious code, providing credentials, or taking other actions that benefit the adversary. Phishing campaigns may use email attachments, malicious links, or voice calls to deliver their payload and can range from mass campaigns to highly targeted spearphishing operations.",
    platforms: ["Windows", "Linux", "macOS", "SaaS", "Office 365", "Google Workspace"],
    dataSources: ["DS0015", "DS0029"],
    detection: "Monitor email gateways for phishing indicators including suspicious attachments, malicious URLs, and spoofed sender addresses. Implement sandboxing for email attachments and URL detonation for links in messages. Monitor endpoint telemetry for suspicious processes spawned from email client or office applications. Track user-reported phishing attempts as a valuable detection data source.",
    mitigations: [
      { id: "M1017", name: "User Training", description: "Conduct regular security awareness training and phishing simulations to help employees recognize and report phishing attempts." },
      { id: "M1054", name: "Software Configuration", description: "Configure email security gateways to filter suspicious messages. Implement SPF, DKIM, and DMARC email authentication to reduce spoofing. Enable safe links and safe attachments features." },
      { id: "M1049", name: "Antivirus/Antimalware", description: "Deploy antivirus solutions that can scan email attachments and downloads for malicious content." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has used spearphishing with malicious attachments and links as a primary initial access vector, including the use of HTML smuggling to deliver ISO files containing malware." },
      { group: "Lazarus Group", description: "Lazarus Group has conducted extensive phishing campaigns against cryptocurrency exchanges and financial institutions using job recruitment and industry conference themes." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1566"
    ]
  },
  {
    id: "T1566.001",
    name: "Phishing: Spearphishing Attachment",
    tactic: "initial-access",
    description: "Adversaries may send spearphishing emails with a malicious attachment to gain access to victim systems. Malicious attachments may include weaponized Office documents with macros, PDF files with embedded scripts, archive files containing executables, or disk image files. The attachment exploits vulnerabilities or relies on social engineering to convince the user to open the file and enable malicious content execution.",
    platforms: ["Windows", "Linux", "macOS"],
    dataSources: ["DS0015", "DS0029"],
    detection: "Monitor email gateways for attachments with known malicious characteristics including macro-enabled documents, executable content in archives, and files with mismatched extensions. Implement sandbox detonation of email attachments to detect malicious behavior. Monitor endpoints for suspicious process execution chains originating from document applications such as Word or Excel spawning PowerShell or cmd.exe.",
    mitigations: [
      { id: "M1017", name: "User Training", description: "Train users to be suspicious of unexpected email attachments and to verify the sender through alternative channels before opening attachments." },
      { id: "M1049", name: "Antivirus/Antimalware", description: "Deploy antivirus scanning on email gateways and endpoints to detect malicious attachments before and after delivery." },
      { id: "M1054", name: "Software Configuration", description: "Disable macro execution in Office applications or require macro signing. Configure email gateways to block dangerous attachment types." }
    ],
    examples: [
      { group: "APT28", description: "APT28 has sent spearphishing emails with malicious Word documents containing macros that download and execute the Zebrocy and X-Agent malware families." },
      { group: "Kimsuky", description: "Kimsuky has distributed spearphishing emails with malicious HWP documents exploiting vulnerabilities in the Hangul Word Processor to target South Korean government officials." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1566/001"
    ]
  },
  {
    id: "T1566.002",
    name: "Phishing: Spearphishing Link",
    tactic: "initial-access",
    description: "Adversaries may send spearphishing emails with a malicious link to gain access to victim systems. Links may point to credential harvesting pages, drive-by exploit sites, or direct malware downloads. Spearphishing links are often more difficult for email security to detect than attachments because the malicious content is hosted externally and the link itself may appear benign or use URL shortening services.",
    platforms: ["Windows", "Linux", "macOS", "SaaS", "Office 365", "Google Workspace"],
    dataSources: ["DS0015", "DS0029"],
    detection: "Monitor email traffic for messages containing links to recently registered domains, URL shorteners, or known phishing infrastructure. Implement URL rewriting and time-of-click analysis to evaluate link safety. Monitor web proxy logs for connections to credential harvesting pages following email link clicks. Track for users submitting credentials to non-organizational login pages.",
    mitigations: [
      { id: "M1017", name: "User Training", description: "Train users to verify URLs before clicking and to navigate directly to services rather than following email links. Conduct regular phishing simulations with link-based scenarios." },
      { id: "M1054", name: "Software Configuration", description: "Implement email link scanning and URL rewriting to provide real-time protection. Enable web content filtering to block access to known phishing domains." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has used spearphishing emails with links to credential harvesting pages mimicking Microsoft 365 authentication to capture victim credentials for initial access." },
      { group: "APT33", description: "APT33 has sent targeted emails with links to fake login portals for corporate VPN and webmail services to harvest credentials from energy sector employees." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1566/002"
    ]
  },
  {
    id: "T1566.003",
    name: "Phishing: Spearphishing via Service",
    tactic: "initial-access",
    description: "Adversaries may send spearphishing messages via third-party services to gain access to victim systems. Rather than using email, adversaries leverage social media direct messages, messaging applications, and professional networking platforms to deliver malicious links or attachments. These channels may bypass traditional email security controls and appear more personal and trustworthy to targets.",
    platforms: ["Windows", "Linux", "macOS"],
    dataSources: ["DS0015", "DS0029"],
    detection: "Monitor for downloads and file execution following interactions with social media and messaging platforms. Implement endpoint monitoring for suspicious process chains originating from browser sessions on social media sites. Track for unusual outbound connections following social media usage that may indicate successful payload delivery.",
    mitigations: [
      { id: "M1017", name: "User Training", description: "Train employees to be cautious of unsolicited messages on social media and messaging platforms, especially those containing links or file attachments." },
      { id: "M1021", name: "Restrict Web-Based Content", description: "Implement web content policies that restrict access to non-business social media platforms on corporate devices where appropriate." }
    ],
    examples: [
      { group: "Lazarus Group", description: "Lazarus Group has used LinkedIn to deliver malicious attachments disguised as job descriptions to security researchers and cryptocurrency professionals." },
      { group: "APT34", description: "APT34 has used LinkedIn direct messages with fake job opportunities to deliver malware to targets in the technology and government sectors." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1566/003"
    ]
  },
  {
    id: "T1566.004",
    name: "Phishing: Spearphishing Voice",
    tactic: "initial-access",
    description: "Adversaries may use voice communications to trick users into performing actions that grant access to systems. Voice phishing (vishing) involves phone calls where adversaries impersonate IT support, executives, or other trusted entities to convince targets to provide credentials, install remote access software, or perform other actions. Vishing can bypass email security controls entirely and leverages the urgency and authority conveyed through live conversation.",
    platforms: ["Windows", "Linux", "macOS"],
    dataSources: ["DS0015"],
    detection: "Detection of vishing attacks relies primarily on user awareness and reporting. Monitor for remote access tool installations following reported suspicious phone calls. Track for unusual help desk or IT support call patterns. Implement callback verification procedures for sensitive requests received via phone.",
    mitigations: [
      { id: "M1017", name: "User Training", description: "Train employees to be suspicious of unsolicited phone calls requesting credentials or asking them to install software. Implement verification procedures requiring callback through known numbers for sensitive requests." },
      { id: "M1056", name: "Pre-compromise", description: "Establish clear policies that IT support will never request passwords over the phone. Implement callback verification procedures for all sensitive requests received via voice communication." }
    ],
    examples: [
      { group: "LAPSUS$", description: "LAPSUS$ has used social engineering phone calls to IT help desks to reset credentials and bypass multi-factor authentication for high-profile target accounts." },
      { group: "Scattered Spider", description: "Scattered Spider has extensively used vishing attacks targeting IT help desks to gain initial access through SIM swapping and MFA reset social engineering." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1566/004"
    ]
  },
  {
    id: "T1091",
    name: "Replication Through Removable Media",
    tactic: "initial-access",
    description: "Adversaries may move onto systems by copying malware to removable media and using autoplay or social engineering to trick users into executing it. This technique is particularly useful for targeting air-gapped networks that are not directly connected to the internet. Malware designed for removable media propagation may include worm functionality to spread to additional systems when the infected media is connected.",
    platforms: ["Windows"],
    dataSources: ["DS0016", "DS0009"],
    detection: "Monitor for new files created on removable media devices and autorun execution from USB drives. Implement USB device monitoring to track device connections and file transfers. Endpoint detection tools can alert on suspicious executable files or autorun configurations on removable media. Monitor for process execution originating from removable drive paths.",
    mitigations: [
      { id: "M1034", name: "Limit Hardware Installation", description: "Restrict USB device connections through group policy and endpoint management solutions. Implement USB device whitelisting to allow only authorized devices." },
      { id: "M1042", name: "Disable or Remove Feature or Program", description: "Disable autorun and autoplay for removable media devices through group policy to prevent automatic execution of content on USB devices." }
    ],
    examples: [
      { group: "Stuxnet", description: "Stuxnet propagated through infected USB drives to cross air-gapped networks and reach Iranian nuclear facility control systems, using multiple zero-day exploits for LNK file handling." },
      { group: "Agent.BTZ", description: "Agent.BTZ spread through infected USB drives to compromise US military classified networks, leading to the creation of US Cyber Command in response to the breach." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1091"
    ]
  },
  {
    id: "T1195",
    name: "Supply Chain Compromise",
    tactic: "initial-access",
    description: "Adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer to enable data or system compromise. Supply chain compromise involves targeting the less-secure elements in the supply chain including software vendors, hardware manufacturers, and managed service providers. This technique can provide broad access to many organizations through a single compromise of a trusted vendor.",
    platforms: ["Windows", "Linux", "macOS"],
    dataSources: ["DS0022"],
    detection: "Monitor for unexpected changes to installed software including unauthorized updates, modified binaries, and altered checksums. Implement software bill of materials tracking and verify software signatures and hashes against vendor-provided values. Monitor for anomalous behavior from legitimate software that may indicate supply chain compromise.",
    mitigations: [
      { id: "M1051", name: "Update Software", description: "Keep software updated but verify update integrity through hash validation and code signing verification before deployment." },
      { id: "M1016", name: "Vulnerability Scanning", description: "Conduct regular vulnerability scanning of third-party software and monitor vendor security advisories for supply chain compromise indicators." }
    ],
    examples: [
      { group: "APT29", description: "APT29 compromised SolarWinds Orion software build process to distribute the SUNBURST backdoor to approximately 18,000 organizations through trojanized software updates." },
      { group: "APT41", description: "APT41 has compromised multiple software vendors to distribute trojanized software updates as a means of gaining initial access to their ultimate targets." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1195"
    ]
  },
  {
    id: "T1195.001",
    name: "Supply Chain Compromise: Compromise Software Dependencies and Development Tools",
    tactic: "initial-access",
    description: "Adversaries may manipulate software dependencies and development tools to gain access to victim systems. This includes compromising package repositories, injecting malicious code into open-source libraries, and trojanizing development tools used by software engineers. Compromised dependencies can be widely distributed through package managers, affecting many downstream applications and organizations that rely on the poisoned components.",
    platforms: ["Windows", "Linux", "macOS"],
    dataSources: ["DS0022"],
    detection: "Monitor software dependency management systems for unexpected package additions or version changes. Implement software composition analysis to track third-party libraries and detect known compromised packages. Verify checksums and signatures of development tools and dependencies. Monitor build environments for unauthorized modifications.",
    mitigations: [
      { id: "M1051", name: "Update Software", description: "Maintain awareness of security advisories for all software dependencies. Implement automated dependency scanning to detect known vulnerable or compromised packages." },
      { id: "M1016", name: "Vulnerability Scanning", description: "Regularly scan software dependencies for known vulnerabilities and monitor package registries for reports of compromised packages." }
    ],
    examples: [
      { group: "Lazarus Group", description: "Lazarus Group has compromised npm and PyPI packages to distribute malware through popular open-source package repositories targeting developers." },
      { group: "APT29", description: "APT29 has targeted software build systems and development tools to inject malicious code into the software supply chain." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1195/001"
    ]
  },
  {
    id: "T1195.002",
    name: "Supply Chain Compromise: Compromise Software Supply Chain",
    tactic: "initial-access",
    description: "Adversaries may manipulate application software prior to receipt by the end user to establish access to victim systems. This involves compromising the software vendor's development, build, or distribution infrastructure to inject malicious code into otherwise legitimate software. The resulting trojanized software is then distributed to victims through normal update channels, bypassing security controls that trust signed vendor software.",
    platforms: ["Windows", "Linux", "macOS"],
    dataSources: ["DS0022"],
    detection: "Monitor for anomalous behavior from trusted software following updates. Implement binary analysis and comparison tools to detect unauthorized modifications to signed software. Track software vendor security advisories and breach notifications. Monitor for network communications from legitimate software to unexpected destinations.",
    mitigations: [
      { id: "M1051", name: "Update Software", description: "Verify software update integrity through multiple channels before deployment. Implement staged rollout of updates to detect anomalies before enterprise-wide deployment." },
      { id: "M1016", name: "Vulnerability Scanning", description: "Conduct regular integrity verification of installed software against known-good baselines." }
    ],
    examples: [
      { group: "APT29", description: "APT29 compromised the SolarWinds Orion build system to inject the SUNBURST backdoor into legitimate software updates, affecting approximately 18,000 organizations globally." },
      { group: "APT41", description: "APT41 has compromised software vendors including Netsarang and ASUS to distribute trojanized software updates to their customers." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1195/002"
    ]
  },
  {
    id: "T1195.003",
    name: "Supply Chain Compromise: Compromise Hardware Supply Chain",
    tactic: "initial-access",
    description: "Adversaries may manipulate hardware components in products prior to receipt by the end consumer to establish access. Hardware supply chain compromise involves modifying firmware, adding covert hardware components, or replacing legitimate components with compromised versions during manufacturing or distribution. These modifications can provide persistent access that is extremely difficult to detect through software-based security controls.",
    platforms: ["Windows", "Linux", "macOS"],
    dataSources: ["DS0022"],
    detection: "Detection of hardware supply chain compromise is extremely challenging. Implement hardware integrity verification including visual inspection of critical components, firmware hash verification, and hardware attestation mechanisms. Monitor for unexpected firmware modifications and conduct periodic hardware audits of critical infrastructure.",
    mitigations: [
      { id: "M1046", name: "Boot Integrity", description: "Implement secure boot and measured boot to detect unauthorized firmware modifications. Use TPM-based attestation to verify hardware and firmware integrity." },
      { id: "M1051", name: "Update Software", description: "Keep firmware updated and verify firmware images against vendor-provided hashes. Implement UEFI Secure Boot to prevent unauthorized firmware execution." }
    ],
    examples: [
      { group: "Equation Group", description: "Equation Group reportedly intercepted hardware shipments to install firmware implants on hard drives and network equipment destined for target organizations." },
      { group: "APT28", description: "APT28 has been associated with operations that involved hardware supply chain manipulation including modified network equipment." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1195/003"
    ]
  },
  {
    id: "T1199",
    name: "Trusted Relationship",
    tactic: "initial-access",
    description: "Adversaries may breach or leverage organizations that have access to intended victims. Trusted relationships include managed service providers, IT contractors, and business partners with network access or shared credentials. Access through trusted third parties exploits the implicit trust between organizations and can bypass security controls focused on external threats while appearing as legitimate partner activity.",
    platforms: ["Windows", "Linux", "macOS", "SaaS", "Office 365", "IaaS"],
    dataSources: ["DS0028", "DS0029"],
    detection: "Monitor network connections from trusted partners for anomalous behavior including unusual access patterns, off-hours activity, and access to resources outside normal scope. Implement behavioral baselines for third-party access and alert on deviations. Track for lateral movement originating from partner VPN connections or jump hosts.",
    mitigations: [
      { id: "M1030", name: "Network Segmentation", description: "Segment networks to limit the scope of access granted to trusted partners. Implement zero-trust network architecture that does not grant blanket access based on network origin." },
      { id: "M1032", name: "Multi-factor Authentication", description: "Require multi-factor authentication for all third-party access to organizational resources." }
    ],
    examples: [
      { group: "APT29", description: "APT29 leveraged the SolarWinds supply chain compromise to abuse trusted relationships between SolarWinds and its customers, gaining access through legitimate software update channels." },
      { group: "APT41", description: "APT41 has targeted managed service providers and IT vendors to leverage their trusted access to downstream customer organizations." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1199"
    ]
  },
  {
    id: "T1078",
    name: "Valid Accounts",
    tactic: "initial-access",
    description: "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining initial access, persistence, privilege escalation, or defense evasion. Compromised credentials may be used to bypass access controls on resources and systems and may even be used for persistent access to remote systems. Valid accounts are one of the most effective initial access methods because they generate minimal anomalous activity compared to exploit-based techniques.",
    platforms: ["Windows", "Linux", "macOS", "SaaS", "Office 365", "Azure AD", "IaaS", "GCP", "Containers"],
    dataSources: ["DS0028", "DS0002"],
    detection: "Monitor authentication logs for anomalous login activity including impossible travel, unusual source IPs, and off-hours access. Implement user and entity behavior analytics to detect credential abuse. Track for password spraying, credential stuffing, and brute force attempts. Monitor for use of dormant accounts and service accounts for interactive logins.",
    mitigations: [
      { id: "M1032", name: "Multi-factor Authentication", description: "Implement multi-factor authentication for all user accounts, especially privileged accounts and remote access. Use phishing-resistant MFA methods where possible." },
      { id: "M1027", name: "Password Policies", description: "Enforce strong password policies including complexity requirements, rotation schedules, and prohibitions against password reuse. Implement credential screening against known breach databases." },
      { id: "M1026", name: "Privileged Account Management", description: "Implement least-privilege access controls and regularly audit account permissions. Disable dormant accounts and remove unnecessary service accounts." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has extensively used valid credentials obtained through phishing and credential theft to access target networks, including using compromised credentials for lateral movement within the SolarWinds campaign." },
      { group: "APT28", description: "APT28 has used credentials obtained through phishing and brute force attacks to access government email systems and VPN services." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1078"
    ]
  },
  {
    id: "T1078.001",
    name: "Valid Accounts: Default Accounts",
    tactic: "initial-access",
    description: "Adversaries may obtain and abuse credentials of default accounts as a means of gaining initial access. Default accounts include built-in accounts with preset usernames and passwords that are enabled by default in operating systems, network devices, and applications. These accounts are well-documented and widely known, making them prime targets for adversaries scanning for systems where default credentials have not been changed.",
    platforms: ["Windows", "Linux", "macOS", "Azure AD", "Office 365", "SaaS", "IaaS", "GCP", "Containers", "Network"],
    dataSources: ["DS0028", "DS0002"],
    detection: "Monitor for authentication using default account credentials. Implement detection rules for login attempts using well-known default usernames and passwords. Track for access to network devices and applications using factory default credentials. Conduct regular audits to identify systems where default accounts remain enabled with unchanged passwords.",
    mitigations: [
      { id: "M1027", name: "Password Policies", description: "Change or disable all default account credentials during system provisioning. Implement automated compliance checks to detect default credentials that have not been changed." },
      { id: "M1026", name: "Privileged Account Management", description: "Disable default accounts where possible. Where default accounts cannot be disabled, change passwords to strong unique values and implement monitoring." }
    ],
    examples: [
      { group: "Mirai", description: "The Mirai botnet scanned for IoT devices using a list of over 60 common default username and password combinations to compromise and recruit devices." },
      { group: "APT41", description: "APT41 has used default credentials on network devices and applications to gain initial access where administrators failed to change factory-set passwords." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1078/001"
    ]
  },
  {
    id: "T1078.002",
    name: "Valid Accounts: Domain Accounts",
    tactic: "initial-access",
    description: "Adversaries may obtain and abuse credentials of domain accounts as a means of gaining initial access. Domain accounts are managed by Active Directory Domain Services and provide access to resources across the domain. Compromised domain credentials can provide broad access to organizational resources and enable lateral movement across the enterprise network.",
    platforms: ["Windows", "Linux", "macOS"],
    dataSources: ["DS0028", "DS0002"],
    detection: "Monitor Active Directory authentication logs for anomalous login patterns. Implement detection for Kerberos ticket anomalies including golden and silver ticket attacks. Track for password spraying attempts targeting domain accounts. Monitor for service account credentials being used for interactive logins.",
    mitigations: [
      { id: "M1032", name: "Multi-factor Authentication", description: "Implement multi-factor authentication for domain account access, particularly for privileged accounts and remote access scenarios." },
      { id: "M1026", name: "Privileged Account Management", description: "Implement tiered administration models and privileged access workstations. Use managed service accounts and group managed service accounts to reduce credential exposure." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has obtained and used domain account credentials through various means including NTLM hash harvesting and Kerberos ticket theft to move laterally within compromised networks." },
      { group: "Wizard Spider", description: "Wizard Spider has used compromised domain credentials obtained through tools like Mimikatz to authenticate to domain resources and deploy ransomware across enterprise networks." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1078/002"
    ]
  },
  {
    id: "T1078.003",
    name: "Valid Accounts: Local Accounts",
    tactic: "initial-access",
    description: "Adversaries may obtain and abuse credentials of local accounts as a means of gaining initial access. Local accounts are configured on individual systems and may include the built-in administrator account as well as user-created local accounts. Local account credentials may be reused across multiple systems, meaning compromise of credentials on one system can provide access to additional systems where the same credentials are used.",
    platforms: ["Windows", "Linux", "macOS", "Containers", "Network"],
    dataSources: ["DS0028", "DS0002"],
    detection: "Monitor for local account authentication from unusual sources. Track for brute force and password spraying attempts against local accounts. Implement detection for local administrator account usage that deviates from normal administrative patterns. Monitor for the creation of new local accounts on systems.",
    mitigations: [
      { id: "M1027", name: "Password Policies", description: "Enforce unique passwords for local accounts across systems using LAPS (Local Administrator Password Solution) or similar tools. Prevent local credential reuse across systems." },
      { id: "M1026", name: "Privileged Account Management", description: "Implement Microsoft LAPS to manage and rotate local administrator passwords. Disable the built-in administrator account where feasible." }
    ],
    examples: [
      { group: "APT28", description: "APT28 has used compromised local account credentials to access systems where password reuse allowed lateral movement using credentials obtained from a single compromised host." },
      { group: "FIN7", description: "FIN7 has used local account credentials harvested through Mimikatz and other credential dumping tools to access additional systems within compromised networks." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1078/003"
    ]
  },
  {
    id: "T1078.004",
    name: "Valid Accounts: Cloud Accounts",
    tactic: "initial-access",
    description: "Adversaries may obtain and abuse credentials of cloud accounts as a means of gaining initial access. Cloud accounts include accounts for SaaS applications, IaaS/PaaS platforms, and identity providers like Azure AD and Okta. Compromised cloud credentials can provide access to cloud-hosted data, services, and infrastructure. Cloud account compromise is particularly impactful because it can provide access to resources across multiple services and environments.",
    platforms: ["Azure AD", "Office 365", "SaaS", "IaaS", "GCP"],
    dataSources: ["DS0028", "DS0002"],
    detection: "Monitor cloud authentication logs for anomalous sign-in activity including unusual locations, impossible travel, and unfamiliar devices. Track for changes to MFA configurations that may indicate attempts to bypass authentication controls. Monitor for OAuth application consent grants and API key usage from unexpected sources.",
    mitigations: [
      { id: "M1032", name: "Multi-factor Authentication", description: "Enforce multi-factor authentication for all cloud account access. Implement conditional access policies that evaluate sign-in risk and device compliance." },
      { id: "M1026", name: "Privileged Account Management", description: "Implement just-in-time access and privileged identity management for cloud administrative accounts. Monitor and restrict OAuth application registrations." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has compromised cloud accounts including Azure AD credentials to access cloud-hosted email, SharePoint, and other organizational resources in numerous espionage campaigns." },
      { group: "LAPSUS$", description: "LAPSUS$ has compromised cloud accounts through social engineering and SIM swapping to gain access to cloud-hosted source code repositories and internal systems at major technology companies." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1078/004"
    ]
  },
  {
    id: "T1059",
    name: "Command and Scripting Interpreter",
    tactic: "execution",
    description: "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are a common feature across many platforms. Most systems come with some built-in command-line interface and scripting capabilities such as PowerShell, Unix shells, Windows Command Shell, and various scripting languages that adversaries can leverage to execute arbitrary code.",
    platforms: ["Windows", "Linux", "macOS", "Network"],
    dataSources: ["DS0009", "DS0012"],
    detection: "Monitor command-line activity for suspicious patterns including encoded commands, unusual parameter combinations, and execution of uncommon interpreters. Log and analyze script execution events through script block logging, command-line auditing, and process creation monitoring. Implement behavioral rules to detect execution chains commonly used in attacks such as office applications spawning shell interpreters.",
    mitigations: [
      { id: "M1049", name: "Antivirus/Antimalware", description: "Deploy endpoint protection that can detect and block malicious scripts and command execution. Enable AMSI integration for script-based threat detection." },
      { id: "M1038", name: "Execution Prevention", description: "Implement application whitelisting to restrict script interpreter execution to authorized contexts. Use constrained language mode for PowerShell where possible." },
      { id: "M1042", name: "Disable or Remove Feature or Program", description: "Remove or restrict access to unnecessary scripting interpreters and language runtimes on systems where they are not required." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has used PowerShell extensively for execution, including encoded commands for downloading payloads, executing in-memory malware, and performing reconnaissance." },
      { group: "APT41", description: "APT41 has used various command interpreters including PowerShell, Python, and Windows Command Shell during their intrusion operations for both initial execution and post-exploitation." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1059"
    ]
  },
  {
    id: "T1059.001",
    name: "Command and Scripting Interpreter: PowerShell",
    tactic: "execution",
    description: "Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. Adversaries use PowerShell to perform discovery, download and execute payloads, create reverse shells, and bypass security controls. PowerShell can execute .NET code in memory without writing to disk, making it a preferred tool for fileless malware.",
    platforms: ["Windows"],
    dataSources: ["DS0009", "DS0012"],
    detection: "Enable PowerShell script block logging and module logging to capture executed commands and scripts. Monitor for encoded command-line arguments using the -EncodedCommand parameter. Track PowerShell execution policy bypasses and invocation of suspicious cmdlets such as Invoke-Expression, Invoke-WebRequest, and New-Object Net.WebClient. Implement AMSI to detect obfuscated and in-memory malicious scripts.",
    mitigations: [
      { id: "M1049", name: "Antivirus/Antimalware", description: "Enable AMSI integration with endpoint protection to detect malicious PowerShell execution. Deploy solutions that can analyze PowerShell content at runtime." },
      { id: "M1045", name: "Code Signing", description: "Require signed scripts through PowerShell execution policy. Implement Constrained Language Mode to restrict access to sensitive .NET types and methods." },
      { id: "M1042", name: "Disable or Remove Feature or Program", description: "Remove PowerShell v2 which lacks modern logging and security controls. Restrict PowerShell access to only users and service accounts that require it." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has extensively used PowerShell for execution including encoded commands, in-memory payload execution, and leveraging PowerShell to invoke .NET assemblies for credential theft." },
      { group: "FIN7", description: "FIN7 has used PowerShell scripts to download and execute Carbanak payloads, perform reconnaissance, and establish persistence on compromised systems." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1059/001"
    ]
  },
  {
    id: "T1059.002",
    name: "Command and Scripting Interpreter: AppleScript",
    tactic: "execution",
    description: "Adversaries may abuse AppleScript for execution. AppleScript is a macOS scripting language designed to control applications and parts of the operating system through Apple Events. Adversaries can use AppleScript to perform various actions including executing shell commands, controlling applications, collecting system information, and interacting with other macOS scripting frameworks like JavaScript for Automation (JXA).",
    platforms: ["macOS"],
    dataSources: ["DS0009", "DS0012"],
    detection: "Monitor for execution of osascript and osacompile processes which are used to run AppleScript. Track for AppleScript execution that invokes shell commands or performs unusual system operations. Monitor for compiled AppleScript files appearing in unexpected locations and AppleScript usage by non-standard applications.",
    mitigations: [
      { id: "M1038", name: "Execution Prevention", description: "Restrict access to osascript through application control policies. Implement endpoint detection rules for suspicious AppleScript execution patterns." },
      { id: "M1042", name: "Disable or Remove Feature or Program", description: "Consider restricting AppleScript execution capabilities through MDM profiles on managed macOS systems where scripting is not required for business operations." }
    ],
    examples: [
      { group: "Lazarus Group", description: "Lazarus Group has used AppleScript to execute payloads and perform system reconnaissance on compromised macOS systems as part of their cross-platform malware campaigns." },
      { group: "OceanLotus", description: "OceanLotus has used AppleScript to execute malicious commands and interact with the macOS operating system on compromised systems." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1059/002"
    ]
  },
  {
    id: "T1059.003",
    name: "Command and Scripting Interpreter: Windows Command Shell",
    tactic: "execution",
    description: "Adversaries may abuse the Windows command shell (cmd.exe) for execution. The command shell is the default command-line interpreter for Windows and is used extensively for executing programs, batch scripts, and system commands. Adversaries leverage cmd.exe to run built-in commands for discovery, execute downloaded payloads, chain commands together, and interact with the operating system. Batch files provide a simple scripting mechanism for automating multi-step attack sequences.",
    platforms: ["Windows"],
    dataSources: ["DS0009", "DS0012"],
    detection: "Monitor process creation events for cmd.exe execution, particularly when spawned by unusual parent processes such as Office applications, web browsers, or script interpreters. Track for suspicious command-line arguments including use of /c for command execution, file redirection operators for data exfiltration, and chained commands using && or | operators. Implement detection for obfuscated batch file execution.",
    mitigations: [
      { id: "M1038", name: "Execution Prevention", description: "Implement application whitelisting to control which processes can spawn cmd.exe. Configure endpoint detection rules for suspicious cmd.exe execution chains." }
    ],
    examples: [
      { group: "APT28", description: "APT28 has used cmd.exe to execute commands for reconnaissance, file manipulation, and lateral movement on compromised Windows systems." },
      { group: "APT41", description: "APT41 has used the Windows command shell extensively for executing commands, running batch scripts, and managing compromised systems during their intrusion operations." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1059/003"
    ]
  },
  {
    id: "T1059.004",
    name: "Command and Scripting Interpreter: Unix Shell",
    tactic: "execution",
    description: "Adversaries may abuse Unix shell commands and scripts for execution. Unix shells such as bash, sh, zsh, and others provide a command-line interface to Unix-based operating systems. Adversaries can use Unix shells to execute commands, run scripts, download payloads, create reverse shells, and automate attack operations on Linux and macOS systems.",
    platforms: ["Linux", "macOS"],
    dataSources: ["DS0009", "DS0012"],
    detection: "Monitor for shell process creation, particularly bash or sh spawned by unusual parent processes such as web server processes (apache, nginx) or application servers. Track for suspicious command execution including reverse shell one-liners, base64 encoded commands, and commands downloading content from external sources. Implement auditd logging on Linux systems to capture command execution.",
    mitigations: [
      { id: "M1038", name: "Execution Prevention", description: "Restrict shell access to only authorized users and service accounts. Implement SELinux or AppArmor policies to confine shell execution from application contexts." },
      { id: "M1026", name: "Privileged Account Management", description: "Limit interactive shell access for service accounts. Configure restricted shells for users who do not require full shell capabilities." }
    ],
    examples: [
      { group: "APT28", description: "APT28 has used bash scripts on compromised Linux systems for execution of payloads, persistence mechanisms, and data collection operations." },
      { group: "APT32", description: "APT32 has used Unix shell commands on compromised Linux servers to execute backdoors, collect system information, and establish persistent access." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1059/004"
    ]
  },
  {
    id: "T1059.005",
    name: "Command and Scripting Interpreter: Visual Basic",
    tactic: "execution",
    description: "Adversaries may abuse Visual Basic (VB) for execution. Visual Basic includes VBScript (VBS), Visual Basic for Applications (VBA) in Office documents, and VB.NET. VBA macros in Office documents remain one of the most common malware delivery mechanisms, as adversaries craft documents with embedded macros that download and execute payloads when the document is opened and macros are enabled.",
    platforms: ["Windows", "Linux", "macOS"],
    dataSources: ["DS0009", "DS0012"],
    detection: "Monitor for execution of wscript.exe and cscript.exe processes which execute VBScript files. Track for Office applications spawning child processes such as cmd.exe, PowerShell, or other interpreters that may indicate macro execution. Enable Office macro logging and monitor for VBA macro execution events. Implement AMSI for VBScript detection.",
    mitigations: [
      { id: "M1038", name: "Execution Prevention", description: "Disable Office macros for users who do not require them. Implement macro execution policies that allow only digitally signed macros from trusted publishers." },
      { id: "M1042", name: "Disable or Remove Feature or Program", description: "Disable VBScript execution through group policy by removing the Windows Script Host or restricting WSH file associations. Block macro execution in Office through GPO." },
      { id: "M1049", name: "Antivirus/Antimalware", description: "Enable AMSI integration for VBScript detection. Deploy endpoint protection that can analyze macro content in Office documents." }
    ],
    examples: [
      { group: "APT28", description: "APT28 has used VBA macros in weaponized Office documents to download and execute the Zebrocy and Sofacy malware families through macro-enabled phishing attachments." },
      { group: "FIN7", description: "FIN7 has extensively used VBA macros in malicious documents as their primary delivery mechanism, often employing elaborate social engineering to convince victims to enable macros." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1059/005"
    ]
  },
  {
    id: "T1059.006",
    name: "Command and Scripting Interpreter: Python",
    tactic: "execution",
    description: "Adversaries may abuse Python commands and scripts for execution. Python is a widely available programming language installed on many operating systems by default, particularly Linux and macOS. Adversaries use Python for in-memory execution, cross-platform compatibility, and its extensive standard library that provides capabilities for networking, file operations, and process management without requiring additional tools.",
    platforms: ["Windows", "Linux", "macOS"],
    dataSources: ["DS0009", "DS0012"],
    detection: "Monitor for Python process execution, particularly when spawned by unusual parent processes or executed with inline code via the -c flag. Track for Python scripts downloading content from external sources or establishing network connections. Monitor for Python execution in environments where Python is not typically used for business operations.",
    mitigations: [
      { id: "M1038", name: "Execution Prevention", description: "Restrict Python installation and execution to systems and users that require it for legitimate purposes. Implement application whitelisting to control Python interpreter execution." },
      { id: "M1049", name: "Antivirus/Antimalware", description: "Deploy endpoint protection that can monitor Python script execution and detect malicious Python code patterns." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has used Python scripts for various stages of their operations including payload execution, data collection, and command and control communications." },
      { group: "Turla", description: "Turla has deployed Python-based backdoors on compromised systems, leveraging Python's cross-platform capabilities for operations across Windows and Linux environments." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1059/006"
    ]
  },
  {
    id: "T1059.007",
    name: "Command and Scripting Interpreter: JavaScript",
    tactic: "execution",
    description: "Adversaries may abuse JavaScript for execution. JavaScript can be executed through Windows Script Host (wscript.exe/cscript.exe) as JScript files, through web browsers, and through Node.js on servers. Adversaries use JavaScript for payload delivery through malicious .js and .jse files, HTML Application (HTA) files with embedded scripts, and Node.js-based malware. JavaScript for Automation (JXA) provides similar capabilities on macOS.",
    platforms: ["Windows", "Linux", "macOS"],
    dataSources: ["DS0009", "DS0012"],
    detection: "Monitor for execution of wscript.exe and cscript.exe with .js or .jse file arguments. Track for mshta.exe execution which may process HTA files containing JavaScript. Monitor Node.js process execution on systems where it is not expected. Detect JavaScript execution through unusual parent processes and monitor for obfuscated JavaScript files.",
    mitigations: [
      { id: "M1038", name: "Execution Prevention", description: "Remove default file associations for .js and .jse files or associate them with a text editor instead of Windows Script Host. Block HTA file execution through application control policies." },
      { id: "M1042", name: "Disable or Remove Feature or Program", description: "Disable Windows Script Host for users who do not require it. Remove Node.js from systems where it is not needed for business operations." }
    ],
    examples: [
      { group: "FIN7", description: "FIN7 has used JavaScript-based backdoors and JScript files as initial payloads delivered through phishing emails, often using elaborate obfuscation to evade detection." },
      { group: "APT29", description: "APT29 has used HTML smuggling to deliver JavaScript-based droppers that extract and execute malicious payloads from within the browser session." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1059/007"
    ]
  },
  {
    id: "T1059.008",
    name: "Command and Scripting Interpreter: Network Device CLI",
    tactic: "execution",
    description: "Adversaries may abuse scripting or built-in command line interpreters on network devices to execute malicious commands. Network device CLIs such as Cisco IOS, Juniper JunOS, and others provide powerful management interfaces that can be abused by adversaries who gain access. Commands executed through network device CLIs can modify device configurations, establish persistent access, redirect network traffic, and disable security features.",
    platforms: ["Network"],
    dataSources: ["DS0009", "DS0029"],
    detection: "Monitor network device command logs and AAA (Authentication, Authorization, and Accounting) logs for unusual command execution. Track for configuration changes made through CLI sessions, particularly those modifying access control lists, routing tables, or creating new user accounts. Implement change management controls and alerts for network device configuration modifications.",
    mitigations: [
      { id: "M1038", name: "Execution Prevention", description: "Implement role-based access control on network devices to limit which commands can be executed by different user levels. Use command authorization to restrict dangerous commands." },
      { id: "M1026", name: "Privileged Account Management", description: "Restrict CLI access to network devices to authorized administrators only. Implement centralized authentication and authorization through TACACS+ or RADIUS with command accounting." }
    ],
    examples: [
      { group: "APT28", description: "APT28 has accessed network device CLIs to modify configurations and establish persistence on compromised routers and firewalls." },
      { group: "APT41", description: "APT41 has used Cisco IOS CLI commands on compromised routers to modify configurations and install implants for persistent network-level access." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1059/008"
    ]
  },
  {
    id: "T1059.009",
    name: "Command and Scripting Interpreter: Cloud API",
    tactic: "execution",
    description: "Adversaries may abuse cloud management APIs and CLIs to execute commands within cloud environments. Cloud APIs such as AWS CLI, Azure PowerShell, and gcloud provide interfaces for managing cloud resources that adversaries can leverage with stolen credentials. These tools can be used to provision resources, modify configurations, access data, and maintain persistence within cloud environments while appearing as legitimate administrative activity.",
    platforms: ["IaaS", "Azure AD", "Office 365", "SaaS", "GCP"],
    dataSources: ["DS0009", "DS0029"],
    detection: "Monitor cloud API call logs (CloudTrail, Azure Activity Log, GCP Audit Logs) for unusual commands and access patterns. Track for API calls from unexpected source IP addresses or geographic locations. Implement detection for sensitive API operations including instance creation, permission modifications, and data access from service accounts or users that do not typically perform these actions.",
    mitigations: [
      { id: "M1026", name: "Privileged Account Management", description: "Implement least-privilege access for cloud API permissions. Use conditional access policies to restrict API access based on device compliance, location, and risk level." },
      { id: "M1032", name: "Multi-factor Authentication", description: "Require multi-factor authentication for cloud API access, particularly for administrative operations and access from new devices or locations." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has used cloud APIs extensively in their operations, including Azure AD and Microsoft Graph API calls to access email, manage permissions, and maintain persistence in compromised cloud tenants." },
      { group: "LAPSUS$", description: "LAPSUS$ has used cloud management APIs and CLIs after compromising cloud accounts to access data, create additional accounts, and exfiltrate information from cloud environments." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1059/009"
    ]
  },
  {
    id: "T1609",
    name: "Container Administration Command",
    tactic: "execution",
    description: "Adversaries may abuse a container administration service to execute commands within a container. Container administration services such as Docker daemon, Kubernetes API server, and container runtime interfaces allow management of containers and can be abused for code execution. If adversaries gain access to container management interfaces, they can execute commands within running containers, deploy new containers with malicious images, or escape container isolation.",
    platforms: ["Containers"],
    dataSources: ["DS0009", "DS0032"],
    detection: "Monitor container administration API calls for unusual command execution requests. Track for docker exec, kubectl exec, and similar container command execution events. Implement audit logging for container orchestration platforms and alert on command execution in production containers. Monitor for new container deployments from unrecognized images.",
    mitigations: [
      { id: "M1026", name: "Privileged Account Management", description: "Restrict access to container administration interfaces using RBAC. Limit which users and service accounts can execute commands within containers." },
      { id: "M1035", name: "Limit Access to Resource Over Network", description: "Restrict network access to container administration APIs. Use admission controllers to prevent unauthorized container operations." }
    ],
    examples: [
      { group: "TeamTNT", description: "TeamTNT has used Docker API access to execute commands within running containers for cryptocurrency mining and lateral movement in cloud container environments." },
      { group: "Hildegard", description: "Hildegard malware has abused Kubernetes kubelet API to execute commands within containers in compromised Kubernetes clusters." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1609"
    ]
  },
  {
    id: "T1610",
    name: "Deploy Container",
    tactic: "execution",
    description: "Adversaries may deploy a container into a victim environment to facilitate execution or evade defenses. Containers provide isolated execution environments that can be rapidly deployed with preconfigured tools and malware. Adversaries may deploy containers with mining software, backdoors, or other malicious tooling using compromised container orchestration platforms or exposed Docker APIs.",
    platforms: ["Containers"],
    dataSources: ["DS0032"],
    detection: "Monitor container orchestration platforms for unexpected container deployments. Track for containers launched from unrecognized or untrusted images. Implement image scanning and admission control policies to prevent deployment of unauthorized container images. Monitor for containers with excessive privileges or host mount points.",
    mitigations: [
      { id: "M1035", name: "Limit Access to Resource Over Network", description: "Restrict access to container deployment APIs and ensure Docker daemons are not exposed on the network without proper authentication." },
      { id: "M1047", name: "Audit", description: "Implement container image scanning and signing requirements. Use admission controllers to enforce policies about which images can be deployed in the environment." }
    ],
    examples: [
      { group: "TeamTNT", description: "TeamTNT has deployed cryptocurrency mining containers on compromised Docker and Kubernetes environments, using the container deployment mechanism for both execution and evasion." },
      { group: "Kinsing", description: "Kinsing malware has deployed containers with cryptomining software by exploiting exposed Docker API endpoints and misconfigured Kubernetes clusters." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1610"
    ]
  },
  {
    id: "T1203",
    name: "Exploitation for Client Execution",
    tactic: "execution",
    description: "Adversaries may exploit software vulnerabilities in client applications to execute code. Vulnerabilities can exist in web browsers, office productivity suites, PDF readers, and other commonly used applications. Exploitation typically requires the victim to open a specially crafted file or visit a malicious website. Successful exploitation can result in arbitrary code execution with the privileges of the vulnerable application, providing a foothold for further attack activities.",
    platforms: ["Windows", "Linux", "macOS"],
    dataSources: ["DS0009", "DS0015"],
    detection: "Monitor for abnormal behavior from client applications including unexpected child process creation, unusual memory access patterns, and anomalous network connections. Endpoint detection tools can identify exploitation indicators such as ROP chains, heap sprays, and shellcode execution. Track for crash reports and application errors that may indicate failed exploitation attempts.",
    mitigations: [
      { id: "M1048", name: "Application Isolation and Sandboxing", description: "Enable application sandboxing features in browsers and PDF readers. Use browser isolation technologies for high-risk web browsing." },
      { id: "M1050", name: "Exploit Protection", description: "Deploy exploit protection mechanisms such as Windows Defender Exploit Guard with Attack Surface Reduction rules to block common exploitation techniques." },
      { id: "M1051", name: "Update Software", description: "Keep all client applications updated to the latest versions to remediate known vulnerabilities." }
    ],
    examples: [
      { group: "APT28", description: "APT28 has exploited vulnerabilities in Microsoft Office, Adobe Flash, and web browsers to achieve code execution through malicious documents and websites." },
      { group: "APT32", description: "APT32 has exploited vulnerabilities in Microsoft Office to execute malicious code through phishing documents targeting Vietnamese organizations and dissidents." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1203"
    ]
  },
  {
    id: "T1559",
    name: "Inter-Process Communication",
    tactic: "execution",
    description: "Adversaries may abuse inter-process communication (IPC) mechanisms for local code execution. IPC methods allow processes to share data and communicate, and adversaries can exploit these mechanisms to execute code in the context of other processes. Common IPC mechanisms abused include Component Object Model (COM), Dynamic Data Exchange (DDE), and XPC Services, each providing different execution capabilities across platforms.",
    platforms: ["Windows", "macOS"],
    dataSources: ["DS0009", "DS0012"],
    detection: "Monitor for IPC-related activity including COM object instantiation, DDE communications between applications, and unusual process relationships that may indicate IPC-based execution. Track for unexpected DCOM network traffic and monitor for script execution triggered through IPC mechanisms. Implement process monitoring for unusual child process creation from applications involved in IPC.",
    mitigations: [
      { id: "M1048", name: "Application Isolation and Sandboxing", description: "Isolate applications that are frequent targets of IPC-based attacks. Configure application sandboxing to restrict IPC capabilities." },
      { id: "M1042", name: "Disable or Remove Feature or Program", description: "Disable DDE in Microsoft Office applications through registry settings and group policy where it is not required for business operations." }
    ],
    examples: [
      { group: "APT28", description: "APT28 has used DDE and COM-based execution techniques to run malicious code through Microsoft Office applications without relying on traditional macro-based attacks." },
      { group: "FIN7", description: "FIN7 has leveraged COM objects and DDE to execute malicious code in victim environments as alternatives to macro-based execution." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1559"
    ]
  },
  {
    id: "T1559.001",
    name: "Inter-Process Communication: Component Object Model",
    tactic: "execution",
    description: "Adversaries may use the Windows Component Object Model (COM) for local code execution. COM is a system for creating software components that interact with each other through standardized interfaces. Adversaries can abuse COM to execute code through COM scriptlets (SCT files), COM hijacking, and DCOM for remote execution. COM objects can be instantiated from various languages and can execute arbitrary code with the privileges of the hosting process.",
    platforms: ["Windows"],
    dataSources: ["DS0009", "DS0012"],
    detection: "Monitor for unusual COM object instantiation through registry monitoring and process creation events. Track for svchost.exe and dllhost.exe processes loading unusual DLLs or spawning unexpected child processes. Monitor registry modifications to COM-related keys that may indicate COM hijacking. Detect DCOM lateral movement through monitoring of port 135/TCP and dynamic RPC ports.",
    mitigations: [
      { id: "M1048", name: "Application Isolation and Sandboxing", description: "Configure DCOM permissions to restrict remote COM object access. Implement application-level COM security to prevent unauthorized COM object usage." },
      { id: "M1026", name: "Privileged Account Management", description: "Restrict DCOM permissions to limit which users can instantiate COM objects remotely. Audit and restrict COM object access through DCOMCNFG security settings." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has used COM objects for code execution and lateral movement, including abusing DCOM to execute commands on remote systems." },
      { group: "Turla", description: "Turla has abused COM objects to achieve execution and maintain persistence through COM hijacking techniques on compromised Windows systems." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1559/001"
    ]
  },
  {
    id: "T1559.002",
    name: "Inter-Process Communication: Dynamic Data Exchange",
    tactic: "execution",
    description: "Adversaries may use Windows Dynamic Data Exchange (DDE) to execute arbitrary commands. DDE is a protocol for communication between applications and can be abused to execute commands through Microsoft Office documents without requiring macros. DDE execution in Office documents triggers through specially crafted field codes that instruct the application to launch external programs when the document is opened.",
    platforms: ["Windows"],
    dataSources: ["DS0009", "DS0012"],
    detection: "Monitor for Office applications spawning unexpected child processes such as cmd.exe, PowerShell, or other interpreters. Track for DDE-related process creation events and monitor for unusual DDEAUTO and DDE field codes in Office documents. Implement endpoint detection rules for DDE execution patterns and monitor for network connections from Office applications following DDE-triggered execution.",
    mitigations: [
      { id: "M1042", name: "Disable or Remove Feature or Program", description: "Disable DDE in Microsoft Office applications through registry settings. Set DisableEmbeddedFiles and related DDE registry values to prevent DDE execution from documents." },
      { id: "M1054", name: "Software Configuration", description: "Configure Office applications to disable automatic DDE link updates. Deploy group policy settings that prevent DDE code execution from Office documents." }
    ],
    examples: [
      { group: "APT28", description: "APT28 has used DDE execution in Office documents as an alternative to macros for delivering payloads through spearphishing campaigns." },
      { group: "FIN7", description: "FIN7 has employed DDE-based execution in Microsoft Word documents to execute PowerShell commands that download and install their backdoors." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1559/002"
    ]
  },
  {
    id: "T1559.003",
    name: "Inter-Process Communication: XPC Services",
    tactic: "execution",
    description: "Adversaries may abuse XPC services for execution on macOS. XPC is an inter-process communication framework used by macOS for communication between processes, particularly between applications and their helper tools. Adversaries may abuse XPC services to execute code with elevated privileges if they can interact with privileged XPC services that have improper access controls or vulnerable message handling implementations.",
    platforms: ["macOS"],
    dataSources: ["DS0009", "DS0012"],
    detection: "Monitor for unusual XPC service connections and message passing between processes. Track for processes communicating with system XPC services that do not normally interact with those services. Implement endpoint monitoring for privilege escalation attempts through XPC service exploitation.",
    mitigations: [
      { id: "M1051", name: "Update Software", description: "Keep macOS and applications updated to patch known XPC service vulnerabilities. Apple regularly addresses XPC-related privilege escalation issues in security updates." },
      { id: "M1038", name: "Execution Prevention", description: "Implement endpoint protection that can monitor XPC service interactions and detect unusual privilege escalation patterns." }
    ],
    examples: [
      { group: "OceanLotus", description: "OceanLotus has exploited XPC service vulnerabilities on macOS to escalate privileges and execute code in the context of privileged system services." },
      { group: "Lazarus Group", description: "Lazarus Group has targeted macOS XPC services in their cross-platform malware campaigns to achieve execution with elevated privileges." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1559/003"
    ]
  },
  {
    id: "T1106",
    name: "Native API",
    tactic: "execution",
    description: "Adversaries may interact with the native OS application programming interface to execute behaviors. Native APIs provide the lowest-level access to operating system functions and are used for process creation, memory management, file operations, and network communication. Adversaries frequently use native APIs such as Windows API functions (CreateProcess, VirtualAlloc, WriteProcessMemory) and POSIX system calls to perform actions that may evade higher-level monitoring.",
    platforms: ["Windows", "Linux", "macOS"],
    dataSources: ["DS0009", "DS0012"],
    detection: "Monitor for suspicious API calls through endpoint telemetry and ETW (Event Tracing for Windows). Track for common malicious API call sequences such as VirtualAlloc followed by WriteProcessMemory and CreateRemoteThread which indicate process injection. Implement API monitoring to detect unusual syscall patterns on Linux and macOS. Monitor for direct NT API calls that bypass higher-level Windows API functions.",
    mitigations: [
      { id: "M1038", name: "Execution Prevention", description: "Implement application whitelisting and code integrity policies to restrict which processes can call sensitive native APIs." },
      { id: "M1040", name: "Behavior Prevention on Endpoint", description: "Deploy endpoint protection that monitors native API calls for suspicious patterns and can block known malicious API call sequences." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has used native Windows API calls for process injection, credential dumping, and defense evasion, often calling NT-level APIs directly to bypass user-mode API hooks." },
      { group: "Lazarus Group", description: "Lazarus Group has extensively used Windows native APIs for memory allocation, process injection, and anti-analysis techniques in their custom malware families." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1106"
    ]
  },
  {
    id: "T1053",
    name: "Scheduled Task/Job",
    tactic: "execution",
    description: "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Utilities such as at, cron, schtasks, and systemd timers exist on all major operating systems to schedule programs or scripts for execution at specified dates and times. Adversaries use scheduled tasks for persistence, privilege escalation, and execution of payloads at predetermined intervals to maintain access and automate attack operations.",
    platforms: ["Windows", "Linux", "macOS", "Containers"],
    dataSources: ["DS0009", "DS0003"],
    detection: "Monitor for the creation of scheduled tasks through command-line utilities and APIs. Track for schtasks.exe, at.exe, and crontab modifications. Implement detection for scheduled tasks executing suspicious binaries, scripts, or commands. Monitor scheduled task creation events in Windows Event Logs (Event ID 4698) and crontab modifications on Linux systems.",
    mitigations: [
      { id: "M1026", name: "Privileged Account Management", description: "Restrict the ability to create scheduled tasks to authorized administrators. Implement access controls on task scheduler interfaces and crontab access." },
      { id: "M1028", name: "Operating System Configuration", description: "Configure task scheduler permissions to prevent unauthorized users from creating or modifying scheduled tasks. Audit existing scheduled tasks regularly." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has created scheduled tasks for persistence and execution of malicious payloads on compromised Windows systems, using schtasks.exe and the Task Scheduler COM interface." },
      { group: "APT28", description: "APT28 has used scheduled tasks to maintain persistence and execute payloads at regular intervals on compromised systems." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1053"
    ]
  },
  {
    id: "T1053.002",
    name: "Scheduled Task/Job: At",
    tactic: "execution",
    description: "Adversaries may abuse the at utility to schedule tasks for execution. The at command schedules commands or programs to run at a specified time and date on Windows and Unix systems. Adversaries can use at to execute malicious payloads, maintain persistence through recurring executions, and perform actions at times when security monitoring may be reduced. On Windows, the at command can also be used to schedule tasks on remote systems for lateral movement.",
    platforms: ["Windows", "Linux"],
    dataSources: ["DS0009", "DS0003"],
    detection: "Monitor for at command execution and creation of scheduled jobs. On Windows, track for at.exe process creation and associated command-line arguments. Monitor Windows Event Log for task creation events. On Linux, monitor the at daemon queue for new job submissions and track atd log files for job execution.",
    mitigations: [
      { id: "M1026", name: "Privileged Account Management", description: "Restrict at command access to authorized administrators. On Linux, use at.allow and at.deny files to control which users can submit at jobs." },
      { id: "M1028", name: "Operating System Configuration", description: "Disable the at service if it is not required for business operations. Configure access controls to prevent unauthorized at job creation." }
    ],
    examples: [
      { group: "APT28", description: "APT28 has used the at command to schedule execution of malicious payloads on compromised systems and to execute commands on remote systems during lateral movement." },
      { group: "APT41", description: "APT41 has used at commands to schedule execution of tools and payloads on compromised Windows systems." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1053/002"
    ]
  },
  {
    id: "T1053.003",
    name: "Scheduled Task/Job: Cron",
    tactic: "execution",
    description: "Adversaries may abuse the cron utility to schedule tasks for recurring execution on Unix-based systems. Cron is a time-based job scheduler that executes commands at specified intervals defined in crontab files. Adversaries can create cron jobs to maintain persistence, periodically execute malicious scripts, beacon to command and control servers, and automate data exfiltration at regular intervals.",
    platforms: ["Linux", "macOS"],
    dataSources: ["DS0009", "DS0003"],
    detection: "Monitor for modifications to crontab files in /var/spool/cron/, /etc/crontab, and /etc/cron.d/ directories. Track for crontab command usage that adds new scheduled jobs. Implement file integrity monitoring on cron directories. Monitor cron daemon logs for execution of unexpected or suspicious commands.",
    mitigations: [
      { id: "M1026", name: "Privileged Account Management", description: "Restrict crontab access through cron.allow and cron.deny files. Limit which users can create and modify cron jobs to authorized administrators." },
      { id: "M1018", name: "User Account Management", description: "Audit cron jobs regularly and remove unauthorized entries. Monitor for cron job creation by non-administrative users." }
    ],
    examples: [
      { group: "APT32", description: "APT32 has used cron jobs to maintain persistence on compromised Linux servers, scheduling periodic execution of backdoor scripts." },
      { group: "TeamTNT", description: "TeamTNT has installed cron jobs on compromised Linux systems to maintain persistence for cryptocurrency mining operations and periodically download updated mining configurations." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1053/003"
    ]
  },
  {
    id: "T1053.005",
    name: "Scheduled Task/Job: Scheduled Task",
    tactic: "execution",
    description: "Adversaries may abuse the Windows Task Scheduler to schedule execution of malicious payloads. The Task Scheduler allows programs to be executed at specified times, at logon, at system startup, or in response to specific events. Adversaries can create scheduled tasks through schtasks.exe, the Task Scheduler COM interface, or PowerShell cmdlets to achieve persistence, privilege escalation, and remote execution.",
    platforms: ["Windows"],
    dataSources: ["DS0009", "DS0003"],
    detection: "Monitor Windows Event Log for task creation (Event ID 4698), modification (Event ID 4702), and execution events. Track schtasks.exe and taskeng.exe process creation with associated command-line arguments. Monitor for scheduled task creation through COM interfaces and PowerShell cmdlets. Implement detection for tasks executing suspicious binaries from temporary or user-writable directories.",
    mitigations: [
      { id: "M1026", name: "Privileged Account Management", description: "Restrict scheduled task creation permissions through group policy. Configure task scheduler to require elevated privileges for task creation." },
      { id: "M1028", name: "Operating System Configuration", description: "Configure audit policies to log scheduled task creation and modification events. Regularly audit existing scheduled tasks for unauthorized entries." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has used scheduled tasks extensively for persistence on compromised Windows systems, creating tasks that execute malware at system startup and at regular intervals." },
      { group: "Wizard Spider", description: "Wizard Spider has created scheduled tasks on compromised systems to execute Cobalt Strike beacons and maintain persistent access for ransomware deployment." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1053/005"
    ]
  },
  {
    id: "T1053.006",
    name: "Scheduled Task/Job: Systemd Timers",
    tactic: "execution",
    description: "Adversaries may abuse systemd timers to schedule execution of malicious payloads on Linux systems. Systemd timers are unit files that can activate services at specified times or intervals, providing functionality similar to cron but with additional features including dependency management and resource controls. Adversaries can create timer units to achieve persistence and execute malicious commands with systemd service integration.",
    platforms: ["Linux"],
    dataSources: ["DS0009", "DS0003"],
    detection: "Monitor for creation and modification of systemd timer and service unit files in /etc/systemd/system/ and user-level systemd directories. Track systemctl commands that create or enable timer units. Monitor journald logs for timer activation and associated service execution events. Implement file integrity monitoring on systemd configuration directories.",
    mitigations: [
      { id: "M1026", name: "Privileged Account Management", description: "Restrict the ability to create systemd timer units to authorized administrators. Limit write access to systemd configuration directories." },
      { id: "M1018", name: "User Account Management", description: "Audit systemd timer units regularly for unauthorized entries. Monitor for user-level systemd timers that may be used for persistence." }
    ],
    examples: [
      { group: "APT28", description: "APT28 has used systemd timers on compromised Linux systems to establish persistence and periodically execute reconnaissance and communication scripts." },
      { group: "TeamTNT", description: "TeamTNT has created systemd timer units on compromised Linux servers to ensure persistent execution of cryptocurrency mining processes." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1053/006"
    ]
  },
  {
    id: "T1053.007",
    name: "Scheduled Task/Job: Container Orchestration Job",
    tactic: "execution",
    description: "Adversaries may abuse container orchestration jobs to schedule execution of malicious code. Kubernetes CronJobs and similar container orchestration scheduling features allow containers to be executed on recurring schedules. Adversaries with access to container orchestration platforms can create scheduled jobs that deploy malicious containers, execute commands within existing containers, or perform data exfiltration at regular intervals.",
    platforms: ["Containers"],
    dataSources: ["DS0009", "DS0032"],
    detection: "Monitor Kubernetes API server audit logs for creation of CronJob and Job resources. Track for CronJobs deploying containers from unrecognized or untrusted images. Implement admission controllers that validate job specifications against security policies. Monitor for unusual scheduling patterns and container orchestration jobs created by service accounts that do not typically manage scheduled workloads.",
    mitigations: [
      { id: "M1026", name: "Privileged Account Management", description: "Restrict the ability to create CronJobs and Jobs in container orchestration platforms through RBAC policies. Limit scheduling permissions to authorized administrators." },
      { id: "M1035", name: "Limit Access to Resource Over Network", description: "Restrict network access to container orchestration APIs. Implement network policies that limit container communication to authorized endpoints." }
    ],
    examples: [
      { group: "TeamTNT", description: "TeamTNT has created Kubernetes CronJobs to maintain persistent cryptocurrency mining operations in compromised container environments." },
      { group: "Hildegard", description: "Hildegard malware has created scheduled container jobs in compromised Kubernetes clusters to ensure persistent execution of cryptomining and backdoor containers." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1053/007"
    ]
  },
  {
    id: "T1129",
    name: "Shared Modules",
    tactic: "execution",
    description: "Adversaries may execute malicious payloads via loading shared modules. Shared modules are dynamically loaded libraries (DLLs on Windows, shared objects on Linux) that can be loaded by programs at runtime. Adversaries can abuse the shared module loading mechanism to execute malicious code by placing malicious libraries in locations where they will be loaded by legitimate applications, or by using API functions to explicitly load attacker-controlled modules.",
    platforms: ["Windows", "macOS", "Linux"],
    dataSources: ["DS0009", "DS0011"],
    detection: "Monitor for unusual DLL loading events including libraries loaded from temporary directories, user-writable locations, or unexpected file paths. Track for use of LoadLibrary and dlopen API calls that load modules from suspicious locations. Implement detection for unsigned or modified DLLs being loaded by legitimate applications.",
    mitigations: [
      { id: "M1038", name: "Execution Prevention", description: "Implement application whitelisting that validates the integrity and source of loaded modules. Enable Windows Defender Application Control or similar solutions to restrict DLL loading." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has used DLL side-loading techniques to execute malicious shared modules in the context of legitimate applications to evade detection." },
      { group: "APT41", description: "APT41 has loaded malicious DLLs through legitimate applications using shared module loading mechanisms to execute their payloads." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1129"
    ]
  },
  {
    id: "T1072",
    name: "Software Deployment Tools",
    tactic: "execution",
    description: "Adversaries may gain access to and use third-party software suites installed within an enterprise network to move laterally and execute code. Software deployment tools such as SCCM, Ansible, Chef, Puppet, and similar systems have access to large numbers of endpoints and can execute code with elevated privileges. Adversaries who compromise these tools can leverage their existing trust and distribution mechanisms to deploy malicious payloads across the enterprise.",
    platforms: ["Windows", "Linux", "macOS"],
    dataSources: ["DS0009", "DS0029"],
    detection: "Monitor software deployment tool activity for unexpected deployments and policy changes. Track for deployment of unsigned or unrecognized software through enterprise management tools. Implement change management controls and approval workflows for software deployments. Monitor deployment tool administrative accounts for unauthorized access.",
    mitigations: [
      { id: "M1026", name: "Privileged Account Management", description: "Restrict administrative access to software deployment tools to authorized personnel only. Implement multi-factor authentication for deployment tool administrative consoles." },
      { id: "M1030", name: "Network Segmentation", description: "Segment management networks used by software deployment tools from user networks. Restrict communication paths for deployment infrastructure." },
      { id: "M1032", name: "Multi-factor Authentication", description: "Require multi-factor authentication for access to software deployment management interfaces." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has abused software deployment tools within compromised networks to distribute malware to endpoints, leveraging existing enterprise management infrastructure." },
      { group: "Sandworm Team", description: "Sandworm Team has used enterprise software deployment mechanisms to distribute the NotPetya wiper across victim networks." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1072"
    ]
  },
  {
    id: "T1569",
    name: "System Services",
    tactic: "execution",
    description: "Adversaries may abuse system services or daemons to execute commands or programs. Operating system services run in the background with elevated privileges and can be created or modified by adversaries to execute malicious code. Service execution provides persistence, privilege escalation, and a way to execute payloads that appear as legitimate system processes. Both Windows services and Unix daemons provide this capability.",
    platforms: ["Windows", "macOS", "Linux"],
    dataSources: ["DS0009", "DS0019"],
    detection: "Monitor for new service creation and modification of existing service configurations. Track for services executing unusual binaries or scripts. On Windows, monitor for service creation events (Event ID 7045) and service configuration changes. On Linux and macOS, monitor for new daemon configurations in systemd unit files and launchd plist files.",
    mitigations: [
      { id: "M1026", name: "Privileged Account Management", description: "Restrict service creation and modification permissions to authorized administrators. Implement access controls on service management interfaces." },
      { id: "M1022", name: "Restrict File and Directory Permissions", description: "Restrict write access to service binary directories and configuration files to prevent modification of existing services." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has created and modified Windows services to execute malicious payloads and maintain persistence on compromised systems." },
      { group: "APT41", description: "APT41 has installed Windows services to execute malware and maintain persistent access, using service creation for both execution and privilege escalation." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1569"
    ]
  },
  {
    id: "T1569.001",
    name: "System Services: Launchctl",
    tactic: "execution",
    description: "Adversaries may abuse launchctl to execute commands or programs on macOS. Launchctl interfaces with launchd, the service management framework for macOS, to load, unload, and manage services and daemons. Adversaries can use launchctl to execute malicious programs as launch agents or launch daemons, providing persistent execution with various privilege levels depending on the plist configuration and installation location.",
    platforms: ["macOS"],
    dataSources: ["DS0009", "DS0019"],
    detection: "Monitor for launchctl command execution and creation of new plist files in LaunchAgent and LaunchDaemon directories. Track for launchctl commands that load new services or modify existing ones. Monitor /Library/LaunchAgents, /Library/LaunchDaemons, and user-level ~/Library/LaunchAgents directories for new or modified plist files.",
    mitigations: [
      { id: "M1022", name: "Restrict File and Directory Permissions", description: "Restrict write access to LaunchDaemon directories to prevent unauthorized service installation. Monitor LaunchAgent directories for unauthorized additions." },
      { id: "M1026", name: "Privileged Account Management", description: "Restrict the ability to create system-level Launch Daemons to authorized administrators." }
    ],
    examples: [
      { group: "Lazarus Group", description: "Lazarus Group has used launchctl to install and manage persistent backdoors on compromised macOS systems through Launch Agent plists." },
      { group: "OceanLotus", description: "OceanLotus has installed persistent backdoors through launchctl and Launch Agent plist files on compromised macOS systems targeting Vietnamese organizations." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1569/001"
    ]
  },
  {
    id: "T1569.002",
    name: "System Services: Service Execution",
    tactic: "execution",
    description: "Adversaries may abuse the Windows service control manager to execute malicious commands or payloads. The Service Control Manager (SCM) manages Windows services and can be interacted with through sc.exe, the Services MMC snap-in, or programmatically through the Windows API. Adversaries can create new services or modify existing ones to execute malicious binaries, and services can also be used for remote execution through the Service Control Manager Remote Protocol.",
    platforms: ["Windows"],
    dataSources: ["DS0009", "DS0019"],
    detection: "Monitor for new Windows service creation events (Event ID 7045) and changes to existing service configurations. Track sc.exe command execution and service creation through the SCM API. Monitor for services configured to execute binaries from temporary or user-writable directories. Detect remote service creation through monitoring of SMB and RPC traffic associated with the SCM Remote Protocol.",
    mitigations: [
      { id: "M1026", name: "Privileged Account Management", description: "Restrict service creation and modification permissions through group policy and ACLs on the Service Control Manager." },
      { id: "M1022", name: "Restrict File and Directory Permissions", description: "Restrict write permissions on service binary paths to prevent adversaries from replacing legitimate service executables." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has created Windows services for execution of malicious payloads and has used PsExec to execute commands through remote service creation on target systems." },
      { group: "Wizard Spider", description: "Wizard Spider has used Windows service creation through PsExec and WMI to remotely execute Cobalt Strike beacons and deploy Ryuk ransomware across enterprise networks." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1569/002"
    ]
  },
  {
    id: "T1204",
    name: "User Execution",
    tactic: "execution",
    description: "Adversaries may rely upon specific actions by a user in order to gain execution. Users may be subjected to social engineering to get them to execute malicious code by opening a malicious document, clicking a malicious link, or running a malicious program. User execution requires the attacker to craft convincing social engineering lures that motivate the target to take the desired action, making it one of the most common initial execution methods in real-world attacks.",
    platforms: ["Windows", "Linux", "macOS", "IaaS", "Containers"],
    dataSources: ["DS0009", "DS0015"],
    detection: "Monitor for execution of programs from user-writable directories, temporary folders, and download directories. Track for file execution following email attachment opening or web downloads. Implement detection for common social engineering execution patterns such as double-extension files, icon-spoofed executables, and documents triggering script execution.",
    mitigations: [
      { id: "M1017", name: "User Training", description: "Conduct regular security awareness training to help users recognize social engineering attempts. Perform phishing simulations to assess and improve organizational resilience." },
      { id: "M1038", name: "Execution Prevention", description: "Implement application whitelisting to restrict execution of unauthorized programs. Configure mark-of-the-web and SmartScreen warnings for files downloaded from the internet." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has relied on user execution of malicious files including ISO images, LNK files, and HTML smuggling payloads to gain initial code execution on target systems." },
      { group: "FIN7", description: "FIN7 has heavily relied on social engineering to convince users to open malicious documents and enable macros, using elaborate lures themed around invoices, delivery notifications, and industry-specific content." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1204"
    ]
  },
  {
    id: "T1204.001",
    name: "User Execution: Malicious Link",
    tactic: "execution",
    description: "Adversaries may rely upon a user clicking a malicious link in order to gain execution. Users may be subjected to social engineering to get them to click on a link that will lead to code execution. Clicking on a link may involve visiting a website that exploits browser vulnerabilities, downloading and executing a malicious file, or submitting credentials to a phishing page that subsequently deploys malware.",
    platforms: ["Windows", "Linux", "macOS"],
    dataSources: ["DS0015", "DS0029"],
    detection: "Monitor for web browsing activity that leads to downloads from suspicious domains or recently registered websites. Track for file execution following web downloads through browser processes. Implement URL filtering and reputation checking to detect clicks on known malicious links. Monitor DNS queries following email link clicks for connections to suspicious infrastructure.",
    mitigations: [
      { id: "M1017", name: "User Training", description: "Train users to hover over links before clicking to verify the destination URL. Educate users about the risks of clicking links in unsolicited emails and messages." },
      { id: "M1021", name: "Restrict Web-Based Content", description: "Implement web content filtering to block access to known malicious and suspicious websites. Deploy URL rewriting and time-of-click analysis in email security solutions." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has distributed spearphishing emails containing links that led to credential harvesting pages and malware download sites for initial compromise." },
      { group: "Lazarus Group", description: "Lazarus Group has used social media messages and emails containing malicious links to direct targets to fake job application sites that deliver malware." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1204/001"
    ]
  },
  {
    id: "T1204.002",
    name: "User Execution: Malicious File",
    tactic: "execution",
    description: "Adversaries may rely upon a user opening a malicious file to gain execution. Users may be subjected to social engineering to get them to open a file that will lead to code execution. This file may be delivered as an email attachment, downloaded from a website, or shared through messaging platforms. Common malicious file types include Office documents with macros, executable files disguised with document icons, and archive files containing malicious content.",
    platforms: ["Windows", "Linux", "macOS"],
    dataSources: ["DS0009", "DS0022"],
    detection: "Monitor for execution of files from download directories, email attachment temporary folders, and other common delivery locations. Track for process creation chains that indicate document-based execution such as Word or Excel spawning cmd.exe or PowerShell. Implement mark-of-the-web tracking and monitor for execution of files flagged as downloaded from the internet.",
    mitigations: [
      { id: "M1017", name: "User Training", description: "Train users to be suspicious of unexpected file attachments and to verify the legitimacy of files before opening them. Educate users about common file-based attack techniques including macro-enabled documents." },
      { id: "M1038", name: "Execution Prevention", description: "Implement application whitelisting and SmartScreen to warn users about or block execution of files from untrusted sources." },
      { id: "M1049", name: "Antivirus/Antimalware", description: "Deploy antivirus solutions that scan files on write and on execution to detect known malicious content before it can be executed by users." }
    ],
    examples: [
      { group: "APT28", description: "APT28 has distributed malicious documents with embedded macros through phishing emails, relying on users to open the documents and enable macro execution." },
      { group: "Kimsuky", description: "Kimsuky has delivered malicious HWP and DOCX files through targeted emails, using social engineering themes related to North Korean policy and academic research to convince targets to open the files." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1204/002"
    ]
  },
  {
    id: "T1204.003",
    name: "User Execution: Malicious Image",
    tactic: "execution",
    description: "Adversaries may rely on a user running a malicious container image to gain execution. Users may be convinced to download and run container images from public registries that contain malicious code, cryptocurrency miners, or backdoors. Malicious images may be disguised as legitimate software or popular applications to encourage download and deployment in container environments.",
    platforms: ["Containers", "IaaS"],
    dataSources: ["DS0032"],
    detection: "Monitor container registries for pulls of untrusted or suspicious images. Implement image scanning to detect malware, vulnerabilities, and malicious configurations in container images before deployment. Track for containers running images not from approved registries. Monitor runtime container behavior for indicators of malicious activity.",
    mitigations: [
      { id: "M1047", name: "Audit", description: "Implement container image scanning and vulnerability assessment as part of the CI/CD pipeline. Require image signing and verification before deployment." },
      { id: "M1017", name: "User Training", description: "Train developers and operations staff to only use container images from trusted registries and to verify image integrity before deployment." }
    ],
    examples: [
      { group: "TeamTNT", description: "TeamTNT has uploaded malicious Docker images to Docker Hub that contained cryptocurrency mining software and worm capabilities to spread to other container environments." },
      { group: "Kinsing", description: "Kinsing operators have distributed malicious container images through public registries that deploy cryptomining software when run in target container environments." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1204/003"
    ]
  },
  {
    id: "T1047",
    name: "Windows Management Instrumentation",
    tactic: "execution",
    description: "Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious commands and payloads. WMI is a Windows administration feature that provides a uniform environment for local and remote access to Windows system components. Adversaries can use WMI to interact with local and remote systems for execution, lateral movement, persistence through event subscriptions, and reconnaissance. WMI queries and method invocations can be performed through the wmic.exe command-line tool, PowerShell, or programmatically through the WMI API.",
    platforms: ["Windows"],
    dataSources: ["DS0009", "DS0005"],
    detection: "Monitor for WMI activity including process creation through Win32_Process Create method, WMI event subscription creation, and WMI command-line tool usage. Track wmic.exe process execution and associated command-line arguments. Monitor for WMI-based lateral movement through detection of DCOM network traffic on port 135/TCP. Implement WMI event logging through ETW and monitor for suspicious WMI queries.",
    mitigations: [
      { id: "M1026", name: "Privileged Account Management", description: "Restrict remote WMI access through DCOM permissions and WMI namespace security. Implement least-privilege access for WMI operations." },
      { id: "M1042", name: "Disable or Remove Feature or Program", description: "Disable the WMI service on systems where it is not required. Restrict wmic.exe and PowerShell WMI cmdlet access through application control." },
      { id: "M1038", name: "Execution Prevention", description: "Implement application whitelisting to restrict unauthorized use of WMI tools and scripts." }
    ],
    examples: [
      { group: "APT29", description: "APT29 has used WMI for remote execution during lateral movement, using Win32_Process Create to execute commands and payloads on remote systems within compromised networks." },
      { group: "Wizard Spider", description: "Wizard Spider has extensively used WMI for remote execution during ransomware deployment, leveraging WMI to execute Cobalt Strike and ransomware payloads across enterprise networks." }
    ],
    references: [
      "https://attack.mitre.org/techniques/T1047"
    ]
  },
];
