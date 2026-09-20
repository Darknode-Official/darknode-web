// Copyright (c) 2026 SpartanKing18. All rights reserved.
// Cybersecurity interview questions with detailed answers for education and career preparation.

export const INTERVIEW_CATEGORIES = [
  "Network Security", "Application Security", "Cloud Security", "Cryptography",
  "Incident Response", "Penetration Testing", "Compliance & GRC",
  "Identity & Access Management", "Security Operations", "Malware Analysis"
];

export const INTERVIEW_QUESTIONS = [
  // =====================================================================
  // NETWORK SECURITY
  // =====================================================================
  { id: 1, question: "What is the difference between TCP and UDP?", category: "Network Security", difficulty: "easy",
    answer: "TCP (Transmission Control Protocol) is connection-oriented, providing reliable, ordered delivery through a three-way handshake (SYN, SYN-ACK, ACK), sequence numbers, and acknowledgments. UDP (User Datagram Protocol) is connectionless and does not guarantee delivery, ordering, or duplicate protection. TCP is used for HTTP, SSH, FTP, and email where reliability matters. UDP is used for DNS, VoIP, streaming, and gaming where speed matters more than reliability. TCP has higher overhead due to connection management and flow control, while UDP has minimal overhead with just an 8-byte header.",
    follow_ups: ["When would you choose UDP over TCP in a security tool?", "How does TCP's three-way handshake relate to SYN flood attacks?"],
    key_terms: ["TCP", "UDP", "three-way handshake", "connection-oriented", "connectionless"]
  },
  { id: 2, question: "Explain the OSI model and its seven layers.", category: "Network Security", difficulty: "easy",
    answer: "The OSI (Open Systems Interconnection) model is a conceptual framework with 7 layers: Layer 1 (Physical) handles raw bit transmission over physical media. Layer 2 (Data Link) provides node-to-node data transfer and MAC addressing. Layer 3 (Network) handles routing and IP addressing. Layer 4 (Transport) provides end-to-end communication via TCP/UDP. Layer 5 (Session) manages connections between applications. Layer 6 (Presentation) handles data formatting, encryption, and compression. Layer 7 (Application) is the user-facing layer with protocols like HTTP, FTP, and SMTP. In practice, the TCP/IP model collapses this into 4 layers. Security controls exist at every layer — from physical locks to application firewalls.",
    follow_ups: ["At which OSI layer does a firewall operate?", "Where does TLS fit in the OSI model?"],
    key_terms: ["OSI model", "Physical", "Data Link", "Network", "Transport", "Session", "Presentation", "Application"]
  },
  { id: 3, question: "What is ARP poisoning and how do you prevent it?", category: "Network Security", difficulty: "medium",
    answer: "ARP (Address Resolution Protocol) poisoning is an attack where an attacker sends falsified ARP messages to link their MAC address with the IP address of a legitimate host (like the gateway). This causes traffic meant for that IP to be sent to the attacker instead, enabling man-in-the-middle attacks, session hijacking, and data interception. Prevention methods include: Dynamic ARP Inspection (DAI) on managed switches, static ARP entries for critical infrastructure, VLAN segmentation to limit broadcast domains, using encrypted protocols (HTTPS, SSH) so intercepted traffic is useless, and deploying tools like arpwatch to detect ARP table changes. 802.1X port-based authentication also helps by ensuring only authorized devices connect to the network.",
    follow_ups: ["How would you detect ARP poisoning in progress?", "What tool would you use to perform ARP poisoning in a pentest?"],
    key_terms: ["ARP", "MAC address", "man-in-the-middle", "DAI", "VLAN"]
  },
  { id: 4, question: "What is a VLAN and how does it improve security?", category: "Network Security", difficulty: "easy",
    answer: "A VLAN (Virtual Local Area Network) is a logical grouping of devices on one or more LANs that communicate as if they were on the same physical network segment, regardless of physical location. VLANs improve security by segmenting the network — devices on different VLANs cannot communicate without going through a Layer 3 device (router or L3 switch), which can enforce access control lists (ACLs). This limits the blast radius of a breach, prevents lateral movement, and isolates sensitive systems (e.g., PCI-scoped cardholder data environment). VLANs also reduce broadcast storm scope and allow applying different security policies to different segments.",
    follow_ups: ["What is VLAN hopping and how do you prevent it?", "How does 802.1Q tagging work?"],
    key_terms: ["VLAN", "network segmentation", "802.1Q", "ACL", "broadcast domain"]
  },
  { id: 5, question: "Explain DNS and common DNS-based attacks.", category: "Network Security", difficulty: "medium",
    answer: "DNS (Domain Name System) translates domain names to IP addresses. It uses a hierarchical system of root servers, TLD servers, and authoritative nameservers. Common DNS attacks include: DNS cache poisoning (injecting false records into a resolver's cache to redirect traffic), DNS tunneling (encoding data in DNS queries to exfiltrate data or bypass firewalls), DNS amplification (using open resolvers with spoofed source IPs for DDoS), DNS hijacking (changing DNS records to redirect a domain), DNS rebinding (manipulating TTL to bypass same-origin policy), and zone transfer attacks (requesting AXFR to dump all DNS records). DNSSEC adds cryptographic signatures to prevent poisoning but is not widely adopted.",
    follow_ups: ["How would you detect DNS tunneling?", "What is the difference between authoritative and recursive DNS?"],
    key_terms: ["DNS", "cache poisoning", "DNS tunneling", "amplification", "DNSSEC", "zone transfer"]
  },
  { id: 6, question: "What is the difference between IDS and IPS?", category: "Network Security", difficulty: "easy",
    answer: "An IDS (Intrusion Detection System) passively monitors network traffic or system activity for suspicious patterns and alerts administrators but does not block traffic. An IPS (Intrusion Prevention System) sits inline in the network path and can actively block or drop malicious traffic in real-time. IDS is deployed as a passive tap or span port; IPS is deployed inline between network segments. Both use signature-based detection (known attack patterns) and anomaly-based detection (deviations from baseline). IDS has no risk of false-positive disruption since it only alerts, while IPS can accidentally block legitimate traffic. Many modern solutions combine both capabilities (IDPS) and integrate with SIEM for correlation.",
    follow_ups: ["What is the difference between signature-based and anomaly-based detection?", "Where would you deploy an IPS in a network?"],
    key_terms: ["IDS", "IPS", "signature-based", "anomaly-based", "inline", "passive"]
  },
  { id: 7, question: "What is a firewall and what are the different types?", category: "Network Security", difficulty: "easy",
    answer: "A firewall is a security device that monitors and filters incoming and outgoing network traffic based on predetermined rules. Types include: Packet filtering firewalls (inspect individual packets based on IP, port, protocol — stateless, fast but limited), Stateful inspection firewalls (track connection state, understanding that a response packet relates to an earlier request), Application-layer firewalls/WAFs (inspect application data like HTTP headers and payloads for attacks), Next-Generation Firewalls (NGFW) (combine traditional firewall with IPS, application awareness, user identity, SSL inspection, and threat intelligence), and Cloud firewalls (FWaaS) (firewall capabilities delivered as a cloud service). Each type operates at different OSI layers and provides different levels of inspection depth.",
    follow_ups: ["What is a WAF and how does it differ from a network firewall?", "What is deep packet inspection?"],
    key_terms: ["firewall", "stateful", "stateless", "NGFW", "WAF", "packet filtering"]
  },
  { id: 8, question: "Explain the concept of Zero Trust Architecture.", category: "Network Security", difficulty: "medium",
    answer: "Zero Trust is a security framework based on the principle 'never trust, always verify.' Unlike traditional perimeter-based security that trusts everything inside the network, Zero Trust treats every access request as potentially hostile regardless of source. Key principles: verify explicitly (authenticate and authorize every request), least privilege access (grant minimum permissions needed), assume breach (segment networks, encrypt data, monitor continuously). Implementation involves micro-segmentation, identity-based access control (beyond just IP), multi-factor authentication, continuous monitoring and validation, and encryption of all data in transit and at rest. Technologies enabling Zero Trust include SDP (Software Defined Perimeter), ZTNA (Zero Trust Network Access), and identity-aware proxies.",
    follow_ups: ["How do you implement Zero Trust in a legacy environment?", "What is the difference between Zero Trust and VPN?"],
    key_terms: ["Zero Trust", "micro-segmentation", "least privilege", "ZTNA", "MFA", "assume breach"]
  },
  { id: 9, question: "What is BGP hijacking and why is it dangerous?", category: "Network Security", difficulty: "hard",
    answer: "BGP (Border Gateway Protocol) hijacking occurs when an attacker announces ownership of IP address blocks they don't actually own, causing routers across the internet to redirect traffic through the attacker's network. BGP is inherently trust-based — routers accept route announcements from peers without cryptographic verification. This allows traffic interception (man-in-the-middle on a global scale), blackholing (directing traffic to a dead end for DoS), and credential harvesting (serving fake websites to redirected traffic). Notable incidents include Pakistan Telecom accidentally hijacking YouTube in 2008 and various state-level interceptions. Defenses include RPKI (Resource Public Key Infrastructure) for route origin validation, BGP monitoring services, and route filtering, but adoption remains incomplete.",
    follow_ups: ["What is RPKI and how does it help?", "How would you detect if your organization's IP space was being hijacked?"],
    key_terms: ["BGP", "route hijacking", "RPKI", "AS", "prefix announcement"]
  },
  { id: 10, question: "What is a DDoS attack and how do you mitigate it?", category: "Network Security", difficulty: "medium",
    answer: "A DDoS (Distributed Denial of Service) attack floods a target with traffic from many sources to overwhelm its resources and make it unavailable. Types include: volumetric attacks (UDP flood, DNS amplification — overwhelm bandwidth), protocol attacks (SYN flood, Ping of Death — exhaust server resources), and application-layer attacks (HTTP flood, Slowloris — target specific services). Mitigation strategies include: CDN and DDoS protection services (Cloudflare, AWS Shield, Akamai), rate limiting and connection throttling, anycast routing to distribute traffic globally, blackhole routing for sacrificial IP absorption, scrubbing centers that filter malicious traffic, and having an incident response plan with ISP coordination. The key is having more capacity than the attacker and filtering bad traffic before it reaches your servers.",
    follow_ups: ["What is the difference between a DoS and DDoS attack?", "How does SYN flood work at the TCP level?"],
    key_terms: ["DDoS", "volumetric", "SYN flood", "amplification", "Slowloris", "scrubbing"]
  },
  // =====================================================================
  // APPLICATION SECURITY
  // =====================================================================
  { id: 11, question: "What is SQL injection and how do you prevent it?", category: "Application Security", difficulty: "easy",
    answer: "SQL injection is an attack where malicious SQL statements are inserted into application queries through user input. For example, entering ' OR '1'='1 in a login field can bypass authentication. Types include: in-band (error-based, UNION-based), blind (boolean-based, time-based), and out-of-band (DNS, HTTP exfiltration). Prevention methods: parameterized queries/prepared statements (the most effective defense — separate SQL code from data), input validation and sanitization, stored procedures (with parameterized calls), ORM frameworks that abstract SQL, least privilege database accounts, and WAF rules as a defense-in-depth layer. Never concatenate user input directly into SQL queries.",
    follow_ups: ["What is the difference between UNION-based and blind SQL injection?", "Can stored procedures prevent SQL injection?"],
    key_terms: ["SQL injection", "prepared statements", "parameterized queries", "UNION", "blind SQLi"]
  },
  { id: 12, question: "Explain Cross-Site Scripting (XSS) and its types.", category: "Application Security", difficulty: "medium",
    answer: "XSS is a vulnerability where an attacker injects malicious scripts into web pages viewed by other users. Three types: Reflected XSS (payload is in the URL/request and reflected back in the response — requires social engineering to send the malicious link), Stored XSS (payload is saved in the database and served to every user who views the page — most dangerous), DOM-based XSS (payload is processed by client-side JavaScript, never sent to the server). Impact includes cookie theft, session hijacking, keylogging, defacement, and phishing. Prevention: output encoding/escaping for the correct context (HTML, JavaScript, URL, CSS), Content Security Policy (CSP) headers, HttpOnly cookie flag, input validation, and using modern frameworks that auto-escape output (React, Angular).",
    follow_ups: ["How does CSP prevent XSS?", "What is the difference between encoding and validation?"],
    key_terms: ["XSS", "reflected", "stored", "DOM-based", "CSP", "output encoding"]
  },
  { id: 13, question: "What is CSRF and how does it differ from XSS?", category: "Application Security", difficulty: "medium",
    answer: "CSRF (Cross-Site Request Forgery) tricks an authenticated user's browser into sending unauthorized requests to a web application. Unlike XSS which executes scripts in the victim's browser context, CSRF exploits the browser's automatic inclusion of credentials (cookies) in requests. For example, if a user is logged into their bank, a malicious page can trigger a money transfer request. Prevention: anti-CSRF tokens (unique per-session or per-request tokens that must accompany state-changing requests), SameSite cookie attribute (Lax or Strict), checking the Origin/Referer headers, requiring re-authentication for sensitive actions, and using custom request headers (which require CORS preflight). Modern frameworks like Django and Rails include CSRF protection by default.",
    follow_ups: ["How does the SameSite cookie attribute prevent CSRF?", "Can CSRF work with JSON APIs?"],
    key_terms: ["CSRF", "anti-CSRF token", "SameSite", "same-origin policy", "state-changing"]
  },
  { id: 14, question: "What is the OWASP Top 10?", category: "Application Security", difficulty: "easy",
    answer: "The OWASP Top 10 is a standard awareness document listing the ten most critical web application security risks, updated periodically (latest: 2021). The current list: A01 Broken Access Control (most prevalent — IDOR, privilege escalation), A02 Cryptographic Failures (sensitive data exposure, weak encryption), A03 Injection (SQL, NoSQL, OS, LDAP injection), A04 Insecure Design (missing security controls at the design level), A05 Security Misconfiguration (default configs, unnecessary features, verbose errors), A06 Vulnerable and Outdated Components (known CVEs in dependencies), A07 Identification and Authentication Failures (weak passwords, broken session management), A08 Software and Data Integrity Failures (insecure CI/CD, unsigned updates), A09 Security Logging and Monitoring Failures (insufficient detection capability), A10 Server-Side Request Forgery (SSRF).",
    follow_ups: ["How has the OWASP Top 10 changed from 2017 to 2021?", "What is OWASP ASVS?"],
    key_terms: ["OWASP", "Top 10", "Broken Access Control", "Injection", "Security Misconfiguration"]
  },
  { id: 15, question: "What is a Content Security Policy (CSP)?", category: "Application Security", difficulty: "medium",
    answer: "CSP is an HTTP response header that allows website owners to control which resources the browser is allowed to load, significantly reducing XSS and data injection attacks. A CSP policy specifies allowed sources for scripts, styles, images, fonts, frames, and other resource types. Example: Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self' 'unsafe-inline'. Key directives: default-src (fallback), script-src (JavaScript sources), style-src (CSS sources), img-src (images), connect-src (AJAX/fetch), frame-src (iframes), report-uri/report-to (violation reporting). Best practices: avoid 'unsafe-inline' and 'unsafe-eval', use nonces or hashes for inline scripts, deploy in report-only mode first, then enforce.",
    follow_ups: ["What is the difference between CSP report-only and enforce mode?", "How do nonces work with CSP?"],
    key_terms: ["CSP", "script-src", "default-src", "nonce", "unsafe-inline", "report-only"]
  },
  // =====================================================================
  // CLOUD SECURITY
  // =====================================================================
  { id: 16, question: "What is the shared responsibility model in cloud security?", category: "Cloud Security", difficulty: "easy",
    answer: "The shared responsibility model defines what security obligations belong to the cloud provider vs the customer. The provider is responsible for security 'of' the cloud — physical infrastructure, hypervisor, networking hardware, and the foundational services. The customer is responsible for security 'in' the cloud — data, access management, application configuration, network controls, and OS patching (in IaaS). The boundary shifts by service model: in IaaS (EC2), the customer manages everything above the hypervisor. In PaaS (Lambda), the provider also handles the OS and runtime. In SaaS (Office 365), the provider handles almost everything except data and access. A common mistake is assuming the provider handles all security — misconfigured S3 buckets and IAM are customer responsibilities.",
    follow_ups: ["How does the shared responsibility differ between IaaS, PaaS, and SaaS?", "What are the most common cloud security misconfigurations?"],
    key_terms: ["shared responsibility", "IaaS", "PaaS", "SaaS", "cloud provider", "customer responsibility"]
  },
  { id: 17, question: "What is an IAM policy in AWS and how do you write a secure one?", category: "Cloud Security", difficulty: "medium",
    answer: "An IAM (Identity and Access Management) policy is a JSON document that defines permissions in AWS. It specifies who (Principal) can do what (Action) on which resources (Resource) under what conditions (Condition). Policies follow the principle of least privilege — grant only the minimum permissions required. Key security practices: never use wildcard (*) actions or resources in production, use conditions to restrict access (e.g., MFA required, source IP), prefer managed policies over inline policies, use IAM roles instead of long-term access keys, enable CloudTrail to audit IAM activity, regularly review and remove unused permissions with IAM Access Analyzer, and implement permission boundaries to cap maximum permissions.",
    follow_ups: ["What is the difference between identity-based and resource-based policies?", "How do you implement least privilege in AWS?"],
    key_terms: ["IAM", "policy", "least privilege", "Principal", "Action", "Resource", "Condition"]
  },
  // =====================================================================
  // CRYPTOGRAPHY
  // =====================================================================
  { id: 18, question: "What is the difference between symmetric and asymmetric encryption?", category: "Cryptography", difficulty: "easy",
    answer: "Symmetric encryption uses a single shared key for both encryption and decryption (AES, ChaCha20, 3DES). It's fast and efficient for large data but requires secure key distribution — both parties must have the same secret key. Asymmetric encryption uses a key pair — a public key for encryption and a private key for decryption (RSA, ECC, Ed25519). It solves the key distribution problem but is much slower (100-1000x). In practice, hybrid encryption combines both: asymmetric encryption exchanges a session key, then symmetric encryption handles the bulk data (this is how TLS works). Key sizes differ: AES-256 provides 256-bit security, while RSA needs 3072+ bits for equivalent strength. ECC provides similar security to RSA with much smaller keys.",
    follow_ups: ["Why is AES-GCM preferred over AES-CBC?", "What is the key exchange problem?"],
    key_terms: ["symmetric", "asymmetric", "AES", "RSA", "ECC", "hybrid encryption", "key exchange"]
  },
  { id: 19, question: "What is a hash function and what properties should it have?", category: "Cryptography", difficulty: "easy",
    answer: "A cryptographic hash function takes an input of any size and produces a fixed-size output (digest). Essential properties: deterministic (same input always produces same output), pre-image resistance (infeasible to find input from hash), second pre-image resistance (given input x, infeasible to find different input y with same hash), collision resistance (infeasible to find any two inputs with same hash), and avalanche effect (small input change dramatically changes output). Common algorithms: SHA-256 (256-bit, widely used), SHA-3 (newest standard, sponge construction), BLAKE2/BLAKE3 (faster than SHA), and MD5/SHA-1 (broken for collisions, avoid for security). Hashes are used for integrity verification, digital signatures, password storage (with salting and key derivation like bcrypt/Argon2), and proof-of-work.",
    follow_ups: ["Why is MD5 still used in some contexts despite being broken?", "What is a rainbow table and how does salting prevent it?"],
    key_terms: ["hash function", "collision resistance", "pre-image", "SHA-256", "salt", "bcrypt"]
  },
  // =====================================================================
  // INCIDENT RESPONSE
  // =====================================================================
  { id: 20, question: "What are the phases of incident response?", category: "Incident Response", difficulty: "easy",
    answer: "The NIST Incident Response framework defines four main phases: 1) Preparation — establishing IR policies, building the CSIRT team, deploying detection tools, conducting tabletop exercises, and creating playbooks. 2) Detection and Analysis — identifying indicators of compromise through SIEM alerts, IDS/IPS, endpoint detection, user reports, and threat intelligence; then triaging, scoping, and classifying the incident severity. 3) Containment, Eradication, and Recovery — short-term containment (isolate affected systems), evidence preservation, removing the threat (malware, backdoors, compromised accounts), patching vulnerabilities, and restoring systems from clean backups. 4) Post-Incident Activity — lessons learned meeting, updating IR plans, improving detection, documenting timeline, and reporting to stakeholders/regulators if required.",
    follow_ups: ["How do you prioritize multiple simultaneous incidents?", "What information should be included in an incident report?"],
    key_terms: ["NIST", "CSIRT", "preparation", "detection", "containment", "eradication", "lessons learned"]
  },
  { id: 21, question: "What is chain of custody and why is it important?", category: "Incident Response", difficulty: "medium",
    answer: "Chain of custody is a documented chronological record of the seizure, custody, control, transfer, analysis, and disposition of evidence. It tracks who handled evidence, when, where, and what they did with it. It's critical because it ensures evidence integrity and admissibility in legal proceedings — if the chain is broken (gaps in documentation, unauthorized access, improper storage), evidence can be challenged or deemed inadmissible in court. Key practices: document every evidence handoff with signatures, timestamps, and purpose; use tamper-evident bags/containers; create forensic images (bit-for-bit copies) instead of working on originals; hash evidence at every transfer point to verify integrity; maintain a secure evidence storage area with access logs; and use write-blockers when imaging storage media.",
    follow_ups: ["What tools do you use for forensic imaging?", "How do you handle volatile evidence?"],
    key_terms: ["chain of custody", "evidence integrity", "forensic imaging", "write-blocker", "hash verification"]
  },
  // =====================================================================
  // PENETRATION TESTING
  // =====================================================================
  { id: 22, question: "What is the difference between black box, white box, and gray box testing?", category: "Penetration Testing", difficulty: "easy",
    answer: "Black box testing simulates an external attacker with no prior knowledge of the target — no source code, network diagrams, or credentials. The tester discovers everything through reconnaissance. White box (or crystal box) testing provides full access to source code, architecture documentation, credentials, and network diagrams — mimicking an insider threat or comprehensive audit. Gray box testing is a hybrid where the tester has partial information, such as user-level credentials or limited documentation — simulating a compromised employee or partner. Black box is most realistic but time-consuming and may miss internal vulnerabilities. White box is most thorough but less realistic. Gray box balances coverage and realism. Most real-world engagements are gray box with clearly defined scope and rules of engagement.",
    follow_ups: ["Which type do you recommend for a first-time pentest?", "What should be included in rules of engagement?"],
    key_terms: ["black box", "white box", "gray box", "rules of engagement", "scope"]
  },
  { id: 23, question: "Explain the penetration testing methodology.", category: "Penetration Testing", difficulty: "medium",
    answer: "A standard pentest methodology follows these phases: 1) Planning and Scoping — define objectives, scope (in-scope IPs, domains, applications), rules of engagement, timeline, communication channels, and get written authorization. 2) Reconnaissance — passive (OSINT, DNS, WHOIS, social media) and active (port scanning, service enumeration) information gathering. 3) Vulnerability Analysis — identify vulnerabilities through automated scanning (Nessus, Nuclei), manual testing, and configuration review. 4) Exploitation — attempt to exploit discovered vulnerabilities to demonstrate impact (gaining access, escalating privileges). 5) Post-Exploitation — assess the value of compromised systems, pivot to other targets, maintain access, and determine data exposure. 6) Reporting — document all findings with severity ratings, evidence (screenshots, logs), reproduction steps, and remediation recommendations. 7) Remediation Verification — retest after fixes are applied.",
    follow_ups: ["What is the most important deliverable of a pentest?", "How do you handle a critical vulnerability discovered during a test?"],
    key_terms: ["methodology", "reconnaissance", "exploitation", "post-exploitation", "reporting"]
  },
  // =====================================================================
  // COMPLIANCE & GRC
  // =====================================================================
  { id: 24, question: "What is the difference between a vulnerability, a threat, and a risk?", category: "Compliance & GRC", difficulty: "easy",
    answer: "A vulnerability is a weakness in a system that could be exploited (e.g., unpatched software, weak password policy, misconfigured firewall). A threat is any potential danger that could exploit a vulnerability (e.g., malware, hackers, natural disasters, insider threats). A risk is the potential for loss or damage when a threat exploits a vulnerability — it combines the likelihood of exploitation with the impact if it occurs. Risk = Threat × Vulnerability × Impact. Risk management involves identifying assets, assessing threats and vulnerabilities, calculating risk levels, and implementing controls to reduce risk to an acceptable level. Controls can mitigate, transfer (insurance), avoid (removing the asset/activity), or accept the risk.",
    follow_ups: ["How do you calculate risk quantitatively?", "What is a risk register?"],
    key_terms: ["vulnerability", "threat", "risk", "impact", "likelihood", "risk management"]
  },
  { id: 25, question: "What is PCI DSS and what are its key requirements?", category: "Compliance & GRC", difficulty: "medium",
    answer: "PCI DSS (Payment Card Industry Data Security Standard) is a set of security requirements for organizations that handle credit card data. It has 12 main requirements grouped into 6 goals: Build and maintain a secure network (1. Install firewalls, 2. Change default passwords), Protect cardholder data (3. Protect stored data, 4. Encrypt transmission), Maintain a vulnerability management program (5. Use antivirus, 6. Develop secure systems), Implement access controls (7. Restrict access by need-to-know, 8. Unique IDs for each person, 9. Restrict physical access), Monitor and test networks (10. Track all access, 11. Regular security testing), and Maintain an information security policy (12. Security policy for all personnel). Compliance levels depend on transaction volume, with Level 1 merchants requiring an on-site audit by a QSA.",
    follow_ups: ["What is the cardholder data environment (CDE)?", "What is the difference between PCI compliance and PCI certification?"],
    key_terms: ["PCI DSS", "cardholder data", "QSA", "CDE", "SAQ", "compliance levels"]
  },
  // =====================================================================
  // IDENTITY & ACCESS MANAGEMENT
  // =====================================================================
  { id: 26, question: "What is Multi-Factor Authentication and what are the factors?", category: "Identity & Access Management", difficulty: "easy",
    answer: "MFA requires two or more independent authentication factors to verify identity. The three factor categories are: Something you know (password, PIN, security question), Something you have (hardware token, smart card, phone with authenticator app, SMS code), and Something you are (biometrics — fingerprint, face recognition, iris scan, voice). A strong MFA implementation uses factors from different categories — two passwords would not count as MFA. TOTP-based authenticator apps (Google Authenticator, Authy) are preferred over SMS due to SIM-swapping attacks. Hardware security keys (FIDO2/WebAuthn like YubiKey) provide the strongest protection as they're phishing-resistant — they verify the website's origin during authentication. Modern passwordless authentication (passkeys) combines 'something you have' with 'something you are' to eliminate passwords entirely.",
    follow_ups: ["Why is SMS-based 2FA considered weak?", "What is FIDO2/WebAuthn?"],
    key_terms: ["MFA", "2FA", "TOTP", "FIDO2", "WebAuthn", "biometrics", "authentication factors"]
  },
  // =====================================================================
  // SECURITY OPERATIONS
  // =====================================================================
  { id: 27, question: "What is a SIEM and how does it work?", category: "Security Operations", difficulty: "medium",
    answer: "A SIEM (Security Information and Event Management) system aggregates, correlates, and analyzes security data from across an organization's IT infrastructure in real-time. It collects logs from firewalls, servers, endpoints, applications, cloud services, and network devices, then normalizes them into a common format. Key capabilities: log aggregation and storage, real-time event correlation (matching patterns across multiple sources), alerting on suspicious activity, dashboards and visualization, compliance reporting, forensic investigation support, and threat intelligence integration. SIEM correlation rules detect complex attack patterns that individual devices can't — for example, correlating a failed VPN login from Russia with a successful login from the same account in the US minutes later. Popular SIEMs include Splunk, Microsoft Sentinel, Elastic Security, IBM QRadar, and the open-source Wazuh.",
    follow_ups: ["What is the difference between SIEM and SOAR?", "How do you write effective SIEM correlation rules?"],
    key_terms: ["SIEM", "log aggregation", "correlation", "normalization", "Splunk", "SOAR"]
  },
  // =====================================================================
  // MALWARE ANALYSIS
  // =====================================================================
  { id: 28, question: "What is the difference between static and dynamic malware analysis?", category: "Malware Analysis", difficulty: "easy",
    answer: "Static analysis examines malware without executing it — inspecting the file structure, strings, imports, embedded resources, packer detection, and disassembly/decompilation. Tools include strings, file, PEiD, IDA Pro, Ghidra, and YARA rules. It's safe (no execution risk) but can be defeated by obfuscation and packing. Dynamic analysis involves executing the malware in a controlled environment (sandbox) and observing its behavior — file system changes, registry modifications, network connections, process creation, and API calls. Tools include Cuckoo Sandbox, ANY.RUN, Process Monitor, Wireshark, and Regshot. Dynamic analysis reveals actual behavior but may miss code paths not triggered during analysis (time bombs, environment checks). A comprehensive analysis combines both approaches: static analysis first to understand structure, then dynamic analysis to observe behavior.",
    follow_ups: ["How do you set up a safe malware analysis environment?", "What is sandbox evasion?"],
    key_terms: ["static analysis", "dynamic analysis", "sandbox", "strings", "disassembly", "behavioral analysis"]
  },
  { id: 29, question: "What are indicators of compromise (IOCs)?", category: "Malware Analysis", difficulty: "easy",
    answer: "IOCs are forensic artifacts that indicate a potential security breach. They are observable evidence that an attack has occurred or is in progress. Types include: network IOCs (malicious IP addresses, domains, URLs, unusual DNS queries, C2 traffic patterns), host-based IOCs (malicious file hashes, suspicious file paths, registry modifications, scheduled tasks, service installations), email IOCs (sender addresses, subject lines, attachment hashes, embedded URLs), and behavioral IOCs (unusual process execution chains, abnormal login patterns, data exfiltration volumes, lateral movement). IOCs are shared through threat intelligence feeds in formats like STIX/TAXII, OpenIOC, and YARA rules. They're used for detection (SIEM/IDS rules), incident response (scoping a breach), and threat hunting (proactively searching for compromise). The Pyramid of Pain ranks IOCs by how difficult they are for attackers to change.",
    follow_ups: ["What is the Pyramid of Pain?", "How do you operationalize threat intelligence IOCs?"],
    key_terms: ["IOC", "hash", "C2", "STIX", "TAXII", "YARA", "threat intelligence"]
  },
  { id: 30, question: "What is ransomware and how do you respond to an attack?", category: "Malware Analysis", difficulty: "medium",
    answer: "Ransomware is malware that encrypts files or locks systems and demands payment (usually cryptocurrency) for the decryption key. Modern ransomware often includes double extortion (threatening to leak stolen data) and sometimes triple extortion (DDoSing the victim). Response steps: immediately isolate affected systems from the network to prevent spread, preserve evidence (memory dumps, logs, encrypted file samples), identify the ransomware variant (ID Ransomware, ransom note analysis), check for available decryptors (NoMoreRansom project), assess the scope of encryption and data exfiltration, notify law enforcement and legal counsel, activate your incident response plan, restore from clean offline backups, and conduct a post-incident review. Prevention: regular tested backups (3-2-1 rule), endpoint detection, email filtering, patch management, network segmentation, and least privilege access. The FBI recommends against paying the ransom.",
    follow_ups: ["Should you ever pay a ransomware demand?", "How does ransomware typically gain initial access?"],
    key_terms: ["ransomware", "double extortion", "decryptor", "NoMoreRansom", "3-2-1 backup"]
  }
];
